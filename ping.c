// feature-test (must be first)
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>          // getpid, getopt
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>           // getaddrinfo
#include <netinet/ip.h>      // iphdr
#include <netinet/ip_icmp.h> // icmphdr
#include <sys/time.h>        // gettimeofday
#include <time.h>            // nanosleep
#include <arpa/inet.h>
#include <math.h>            // sqrt
#include "ping.h"

// 16-bit 1's complement checksum
uint16_t icmp_checksum(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t*)data;
    uint32_t sum = 0;
    while (len > 1) { uint16_t w = ((uint16_t)p[0] << 8) | p[1]; sum += w; p += 2; len -= 2; }
    if (len == 1) sum += ((uint16_t)p[0] << 8);
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)~sum;
}

// build ICMP Echo and write checksum
size_t build_icmp_echo(uint16_t id, uint16_t seq,
                       const uint8_t *payload, size_t payload_len,
                       uint8_t *out, size_t out_cap) {
    const size_t hdr_len = sizeof(icmp_echo_hdr);
    const size_t total   = hdr_len + payload_len;
    assert(out);
    if (out_cap < total) {
        fprintf(stderr, "buf too small (need=%zu, cap=%zu)\n", total, out_cap);
        exit(EXIT_FAILURE);
    }
    icmp_echo_hdr hdr = (icmp_echo_hdr){0};
    hdr.type = ICMP_ECHO; hdr.code = 0; hdr.id = htons(id); hdr.seq = htons(seq);
    memcpy(out, &hdr, hdr_len);
    if (payload_len && payload) memcpy(out + hdr_len, payload, payload_len);
    ((icmp_echo_hdr*)out)->checksum = icmp_checksum(out, total);
    return total;
}

// simple hex dump (16 bytes/line)
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

// resolve host -> IPv4 (try inet_pton first)
static int resolve_ipv4(const char *host, struct in_addr *out_addr) {
    if (inet_pton(AF_INET, host, out_addr) == 1) return 0;
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    int rc = getaddrinfo(host, NULL, &hints, &res);
    if (rc != 0 || !res) return -1;
    struct sockaddr_in *sa = (struct sockaddr_in*)res->ai_addr;
    *out_addr = sa->sin_addr;
    freeaddrinfo(res);
    return 0;
}

// recv one reply; returns 0 ok, -1 timeout/err
static int recv_match(int sockfd, uint16_t want_id, uint16_t want_seq,
                      int timeout_ms, int loose_id, int verbose,
                      double *out_rtt_ms, char *out_ip, int out_ip_sz, int *out_ttl)
{
    struct timeval tv = { .tv_sec = timeout_ms / 1000,
                          .tv_usec = (timeout_ms % 1000) * 1000 };
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt(SO_RCVTIMEO)"); return -1;
    }

    struct timeval start; gettimeofday(&start, NULL);
    char recvbuf[4096];
    socklen_t alen = sizeof(struct sockaddr_in);

    for (;;) {
        struct sockaddr_in src = {0};
        ssize_t len = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0,
                               (struct sockaddr*)&src, &alen);
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return -1; // timeout
            if (errno == EINTR) continue;
            perror("recvfrom"); return -1;
        }
        if ((size_t)len < sizeof(struct iphdr) + sizeof(struct icmphdr)) continue;

        struct iphdr *ip_hdr = (struct iphdr *)recvbuf;
        size_t ip_len = (size_t)ip_hdr->ihl * 4;
        if ((size_t)len < ip_len + sizeof(struct icmphdr)) continue;

        struct icmphdr *icmp_hdr = (struct icmphdr *)(recvbuf + ip_len);
        uint8_t  t  = icmp_hdr->type;
        uint8_t  c  = icmp_hdr->code;
        uint16_t id = ntohs(icmp_hdr->un.echo.id);
        uint16_t sq = ntohs(icmp_hdr->un.echo.sequence);

        if (verbose) {
            char sip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &ip_hdr->saddr, sip, sizeof(sip));
            printf("[dbg] icmp t=%u c=%u id=0x%04x seq=%u from %s\n", t, c, id, sq, sip);
        }

        if (t == ICMP_ECHOREPLY &&
            (loose_id || id == want_id) &&
            sq == want_seq) {
            struct timeval end; gettimeofday(&end, NULL);
            double rtt = (end.tv_sec - start.tv_sec) * 1000.0 +
                         (end.tv_usec - start.tv_usec) / 1000.0;
            if (out_rtt_ms) *out_rtt_ms = rtt;
            if (out_ip && out_ip_sz > 0) inet_ntop(AF_INET, &ip_hdr->saddr, out_ip, out_ip_sz);
            if (out_ttl) *out_ttl = ip_hdr->ttl;
            return 0;
        }

        if (t == ICMP_DEST_UNREACH) {
            char sip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &ip_hdr->saddr, sip, sizeof(sip));
            printf("dest unreachable from %s (code=%u)\n", sip, c);
            return -1;
        }
        if (t == ICMP_TIME_EXCEEDED) {
            char sip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &ip_hdr->saddr, sip, sizeof(sip));
            printf("time exceeded from %s\n", sip);
            return -1;
        }
        // else: not our reply -> loop
    }
}

static int parse_int(const char *s, int *out) {
    char *end = NULL; long v = strtol(s, &end, 10);
    if (!s || *s == '\0' || !end || *end != '\0') return -1;
    if (v < 0 || v > 1000000) return -1;
    *out = (int)v; return 0;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s [-c count] [-i ms] [-W ms] [-t ttl] [-A] [-v] host\n"
        "  -c N   count (def 4)\n"
        "  -i MS  interval (ms, def 1000)\n"
        "  -W MS  timeout  (ms, def 5000)\n"
        "  -t N   TTL/hops (opt)\n"
        "  -A     loose id match (ignore ICMP id)\n"
        "  -v     verbose (print all ICMP seen)\n", argv0);
}

int main(int argc, char **argv) {
    int count = 4, interval_ms = 1000, timeout_ms = 5000, ttl_opt = -1;
    int loose_id = 0, verbose = 0;

    int opt;
    while ((opt = getopt(argc, argv, "c:i:W:t:Av")) != -1) {
        switch (opt) {
            case 'c': if (parse_int(optarg, &count)) { usage(argv[0]); return 1; } break;
            case 'i': if (parse_int(optarg, &interval_ms)) { usage(argv[0]); return 1; } break;
            case 'W': if (parse_int(optarg, &timeout_ms)) { usage(argv[0]); return 1; } break;
            case 't': if (parse_int(optarg, &ttl_opt)) { usage(argv[0]); return 1; } break;
            case 'A': loose_id = 1; break;
            case 'v': verbose  = 1; break;
            default: usage(argv[0]); return 1;
        }
    }
    if (optind >= argc) { usage(argv[0]); return 1; }
    const char *target = argv[optind];

    // resolve
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    if (resolve_ipv4(target, &dst.sin_addr) != 0) {
        fprintf(stderr, "resolve error for '%s'\n", target);
        return 1;
    }

    // raw socket (need sudo/root)
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) { perror("socket"); return 1; }

    // TTL
    if (ttl_opt > 0) {
        if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl_opt, sizeof(ttl_opt)) < 0)
            perror("setsockopt(IP_TTL)");
    }

    // payload
    const char *msg = "Hello";
    const uint8_t *payload = (const uint8_t*)msg;
    size_t pay_len = strlen(msg);

    // show 1st packet bytes (debug)
    {
        uint8_t pkt[128];
        size_t len = build_icmp_echo((uint16_t)(getpid() & 0xFFFF), 1, payload, pay_len, pkt, sizeof(pkt));
        printf("ICMP Echo built: type=%u code=%u id=0x%04x seq=%u payload=%zu total=%zu\n",
            ((icmp_echo_hdr*)pkt)->type,
            ((icmp_echo_hdr*)pkt)->code,
            ntohs(((icmp_echo_hdr*)pkt)->id),
            ntohs(((icmp_echo_hdr*)pkt)->seq),
            pay_len, len);
        puts("\nhex dump:");
        hex_dump(pkt, len);
    }

    // loop
    uint16_t id = (uint16_t)(getpid() & 0xFFFF);
    int sent = 0, recv_ok = 0;
    double min_ms = 0.0, max_ms = 0.0, sum_ms = 0.0, sumsq_ms = 0.0;

    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dst.sin_addr, dst_ip, sizeof(dst_ip));
    printf("\nPING %s (%s): %zu data bytes\n", target, dst_ip, pay_len);

    for (int i = 0; i < count; ++i) {
        uint16_t seq = (uint16_t)(i + 1);
        ++sent;

        // send pkt
        uint8_t pkt[1500];
        size_t pkt_len = build_icmp_echo(id, seq, payload, pay_len, pkt, sizeof(pkt));
        if (sendto(sockfd, pkt, pkt_len, 0, (const struct sockaddr*)&dst, sizeof(dst)) <= 0) {
            perror("sendto");
            printf("request timeout for icmp_seq %u\n", seq);
        } else {
            double rtt = 0.0; char src_ip[INET_ADDRSTRLEN] = "?.?.?.?"; int ttl = -1;
            int ok = recv_match(sockfd, id, seq, timeout_ms, loose_id, verbose,
                                &rtt, src_ip, sizeof(src_ip), &ttl);
            if (ok == 0) {
                ++recv_ok;
                if (recv_ok == 1) { min_ms = max_ms = rtt; }
                else {
                    if (rtt < min_ms) min_ms = rtt;
                    if (rtt > max_ms) max_ms = rtt;
                }
                sum_ms += rtt; sumsq_ms += rtt * rtt;
                printf("%zu bytes from %s: icmp_seq=%u ttl=%d time=%.2f ms\n",
                       sizeof(icmp_echo_hdr) + pay_len, src_ip, seq, ttl, rtt);
            } else {
                printf("request timeout for icmp_seq %u\n", seq);
            }
        }

        if (i + 1 < count) {
            struct timespec ts; ts.tv_sec = interval_ms / 1000; ts.tv_nsec = (interval_ms % 1000) * 1000000L;
            nanosleep(&ts, NULL);
        }
    }

    // stats
    double loss = (sent == 0) ? 0.0 : (100.0 * (sent - recv_ok) / sent);
    double avg  = (recv_ok == 0) ? 0.0 : (sum_ms / recv_ok);
    double mdev = 0.0;
    if (recv_ok > 1) {
        double var = (sumsq_ms / recv_ok) - (avg * avg);
        if (var < 0) { var = 0; }
        mdev = sqrt(var);
    }

    printf("\n--- %s ping statistics ---\n", target);
    printf("%d packets transmitted, %d received, %.0f%% packet loss\n", sent, recv_ok, loss);
    if (recv_ok > 0)
        printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", min_ms, avg, max_ms, mdev);

    close(sockfd);
    return 0;
}

