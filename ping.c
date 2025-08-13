// feature-test macros (must be first)
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>          // getpid
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>           // getaddrinfo, addrinfo
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
        sum += w; p += 2; len -= 2;
    }
    if (len == 1) sum += ((uint16_t)p[0] << 8);

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

    memcpy(out, &hdr, hdr_len);
    if (payload_len && payload) memcpy(out + hdr_len, payload, payload_len);

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

// resolve host -> IPv4. try inet_pton first, else getaddrinfo
static int resolve_ipv4(const char *host, struct in_addr *out_addr) {
    if (inet_pton(AF_INET, host, out_addr) == 1) return 0; // dotted IP

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // v4 only

    int rc = getaddrinfo(host, NULL, &hints, &res);
    if (rc != 0 || !res) return -1;

    struct sockaddr_in *sa = (struct sockaddr_in*)res->ai_addr;
    *out_addr = sa->sin_addr;
    freeaddrinfo(res);
    return 0;
}

// send 1 echo, wait for our reply (id/seq), print RTT.
// returns 0 on success, -1 on timeout/error.
int send_icmp_echo(const char *target_host,
                   const uint8_t *packet, size_t pkt_len)
{
    int sockfd = -1;
    struct sockaddr_in addr;
    struct timeval start, now;
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 }; // 2s recv timeout
    char recvbuf[2048];
    socklen_t r_addr_len = sizeof(struct sockaddr_in);
    int rc = -1;

    // resolve host -> IPv4
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (resolve_ipv4(target_host, &addr.sin_addr) != 0) {
        fprintf(stderr, "resolve error for '%s'\n", target_host);
        return -1;
    }

    // raw socket (need root)
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) { perror("socket"); return -1; }

    // set recv timeout (avoid hang)
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt(SO_RCVTIMEO)"); close(sockfd); return -1;
    }

    // id/seq we expect
    const icmp_echo_hdr *out_hdr = (const icmp_echo_hdr*)packet;
    uint16_t want_id  = ntohs(out_hdr->id);
    uint16_t want_seq = ntohs(out_hdr->seq);
    uint32_t want_ip  = addr.sin_addr.s_addr;

    // send
    gettimeofday(&start, NULL);
    if (sendto(sockfd, packet, pkt_len, 0,
               (struct sockaddr*)&addr, sizeof(addr)) <= 0) {
        perror("sendto"); close(sockfd); return -1;
    }

    // recv loop
    for (;;) {
        struct sockaddr_in src = {0};
        ssize_t len = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0,
                               (struct sockaddr*)&src, &r_addr_len);
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                gettimeofday(&now, NULL);
                double ms = (now.tv_sec - start.tv_sec) * 1000.0 +
                            (now.tv_usec - start.tv_usec) / 1000.0;
                printf("request timeout for %s (%.0f ms)\n", target_host, ms);
                rc = -1; break;
            }
            if (errno == EINTR) continue;
            perror("recvfrom"); rc = -1; break;
        }

        if ((size_t)len < sizeof(struct iphdr) + sizeof(struct icmphdr)) continue;
        struct iphdr *ip_hdr = (struct iphdr *)recvbuf;
        size_t ip_len = ip_hdr->ihl * 4;
        if ((size_t)len < ip_len + sizeof(struct icmphdr)) continue;

        struct icmphdr *icmp_hdr = (struct icmphdr *)(recvbuf + ip_len);

        // match our reply
        if (icmp_hdr->type == ICMP_ECHOREPLY &&
            ntohs(icmp_hdr->un.echo.id) == want_id &&
            ntohs(icmp_hdr->un.echo.sequence) == want_seq &&
            ip_hdr->saddr == want_ip)
        {
            struct timeval end; gettimeofday(&end, NULL);
            double rtt = (end.tv_sec - start.tv_sec) * 1000.0 +
                         (end.tv_usec - start.tv_usec) / 1000.0;

            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip_hdr->saddr, ip_str, sizeof(ip_str));
            printf("%zd bytes from %s: icmp_seq=%u ttl=%d time=%.2f ms\n",
                   len - ip_len, ip_str, want_seq, ip_hdr->ttl, rtt);
            rc = 0; break;
        }

        // common ICMP errors -> print and stop
        if (icmp_hdr->type == ICMP_DEST_UNREACH) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip_hdr->saddr, ip_str, sizeof(ip_str));
            printf("dest unreachable from %s (code=%d)\n", ip_str, icmp_hdr->code);
            rc = -1; break;
        }
        if (icmp_hdr->type == ICMP_TIME_EXCEEDED) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip_hdr->saddr, ip_str, sizeof(ip_str));
            printf("time exceeded from %s\n", ip_str);
            rc = -1; break;
        }

        // else: not ours -> keep looping until timeout
    }

    close(sockfd);
    return rc;
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

    // show bytes
    printf("ICMP Echo built: type=%u code=%u id=0x%04x seq=%u payload=%zu total=%zu\n",
           ((icmp_echo_hdr*)packet)->type,
           ((icmp_echo_hdr*)packet)->code,
           ntohs(((icmp_echo_hdr*)packet)->id),
           ntohs(((icmp_echo_hdr*)packet)->seq),
           strlen(msg), pkt_len);
    puts("\nhex dump:");
    hex_dump(packet, pkt_len);

    // target (arg or default)
    const char *target = (argc >= 2) ? argv[1] : "8.8.8.8";

    // send once, wait reply (sudo/root)
    (void)send_icmp_echo(target, packet, pkt_len);
    return 0;
}

