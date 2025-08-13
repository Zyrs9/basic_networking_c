#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>          // getpid
#include <sys/socket.h>
#include <netinet/ip.h>      // iphdr
#include <netinet/ip_icmp.h> // icmphdr
#include <sys/time.h>        // gettimeofday
#include <arpa/inet.h>
#include "ping.h"

// 16-bit 1's complement checksum (fold carries)
uint16_t icmp_checksum(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t*)data;
    uint32_t sum = 0;

    // add 16-bit words (big-endian)
    while (len > 1) {
        uint16_t w = ((uint16_t)p[0] << 8) | (uint16_t)p[1];
        sum += w;
        p   += 2;
        len -= 2;
    }
    if (len == 1) { // last odd byte
        sum += ((uint16_t)p[0] << 8);
    }

    // fold to 16 bits
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)~sum;
}

// build ICMP Echo (hdr + payload) and write checksum
size_t build_icmp_echo(uint16_t id, uint16_t seq,
                       const uint8_t *payload, size_t payload_len,
                       uint8_t *out, size_t out_cap)
{
    const size_t hdr_len = sizeof(icmp_echo_hdr);
    const size_t total   = hdr_len + payload_len;
    assert(out != NULL);
    if (out_cap < total) {
        fprintf(stderr, "build_icmp_echo: buf too small (need=%zu, cap=%zu)\n",
                total, out_cap);
        exit(EXIT_FAILURE);
    }

    icmp_echo_hdr hdr;
    hdr.type     = ICMP_ECHO;
    hdr.code     = 0;
    hdr.checksum = 0;            // must be 0 before calc
    hdr.id       = htons(id);    // host->net
    hdr.seq      = htons(seq);   // host->net

    // write hdr + payload
    memcpy(out, &hdr, hdr_len);
    if (payload_len && payload) memcpy(out + hdr_len, payload, payload_len);

    // calc checksum over whole ICMP (hdr+payload)
    ((icmp_echo_hdr*)out)->checksum = icmp_checksum(out, total);
    return total;
}

// simple hex dump (16 bytes per line)
void hex_dump(const void *buf, size_t len) {
    const unsigned char *p = (const unsigned char*)buf;
    for (size_t i = 0; i < len; i += 16) {
        printf("%04zx  ", i);
        size_t j = 0;
        for (; j < 16 && i + j < len; ++j) printf("%02x ", p[i + j]);
        for (; j < 16; ++j) printf("   ");
        printf(" |");
        for (j = 0; j < 16 && i + j < len; ++j) {
            unsigned char c = p[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        printf("|\n");
    }
}

// send one Echo and read one Reply, print RTT
void send_icmp_echo(const char *target_ip, const uint8_t *packet, size_t pkt_len) {
    int sockfd;
    struct sockaddr_in addr;
    struct timeval start, end;
    char recvbuf[2048];
    struct sockaddr_in r_addr;
    socklen_t r_addr_len = sizeof(r_addr);

    // raw socket (need root)
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) { perror("socket"); exit(EXIT_FAILURE); }

    // dst addr
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, target_ip, &addr.sin_addr) <= 0) {
        perror("inet_pton"); close(sockfd); exit(EXIT_FAILURE);
    }

    // send
    gettimeofday(&start, NULL);
    if (sendto(sockfd, packet, pkt_len, 0,
               (struct sockaddr*)&addr, sizeof(addr)) <= 0) {
        perror("sendto"); close(sockfd); exit(EXIT_FAILURE);
    }

    // recv (1 pkt)
    ssize_t len = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0,
                           (struct sockaddr*)&r_addr, &r_addr_len);
    if (len <= 0) { perror("recvfrom"); close(sockfd); exit(EXIT_FAILURE); }
    gettimeofday(&end, NULL);

    // rtt (ms)
    double rtt = (end.tv_sec - start.tv_sec) * 1000.0 +
                 (end.tv_usec - start.tv_usec) / 1000.0;

    // parse IP + ICMP
    struct iphdr   *ip_hdr   = (struct iphdr *)recvbuf;
    struct icmphdr *icmp_hdr = (struct icmphdr *)(recvbuf + ip_hdr->ihl * 4);

    if (icmp_hdr->type == ICMP_ECHOREPLY) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_hdr->saddr, ip_str, sizeof(ip_str));
        printf("%zd bytes from %s: icmp_seq=%d ttl=%d time=%.2f ms\n",
               len - ip_hdr->ihl * 4,
               ip_str,
               ntohs(icmp_hdr->un.echo.sequence),
               ip_hdr->ttl,
               rtt);
    } else {
        printf("unexpected ICMP type=%d\n", icmp_hdr->type);
    }

    close(sockfd);
}

int main(int argc, char **argv) {
    // payload
    const char *msg = "Hello";
    uint8_t packet[128];
    uint16_t id  = (uint16_t)(getpid() & 0xFFFF);
    uint16_t seq = 1;

    // build ICMP
    size_t pkt_len = build_icmp_echo(id, seq,
                                     (const uint8_t*)msg, strlen(msg),
                                     packet, sizeof(packet));

    // show packet bytes
    printf("ICMP Echo built: type=%u code=%u id=0x%04x seq=%u payload=%zu total=%zu\n",
           ((icmp_echo_hdr*)packet)->type,
           ((icmp_echo_hdr*)packet)->code,
           ntohs(((icmp_echo_hdr*)packet)->id),
           ntohs(((icmp_echo_hdr*)packet)->seq),
           strlen(msg), pkt_len);
    puts("\nhex dump:");
    hex_dump(packet, pkt_len);

    // target (arg or default 8.8.8.8)
    const char *target = (argc >= 2) ? argv[1] : "8.8.8.8";
    // send once, wait reply (need sudo/root)
    send_icmp_echo(target, packet, pkt_len);

    return 0;
}

