#ifndef PING_H
#define PING_H

#include <stdint.h>
#include <stddef.h>
#include <arpa/inet.h>

#define ICMP_ECHO      8
#define ICMP_ECHOREPLY 0

// ICMP Echo header (RFC 792)
#if defined(__GNUC__)
#define PACKED __attribute__((packed))
#else
#define PACKED
#endif

typedef struct PACKED {
    uint8_t  type;      // 8: Echo, 0: Echo Reply
    uint8_t  code;      // Echo/Echo Reply 0
    uint16_t checksum;  // 16-bit one's complement
    uint16_t id;
    uint16_t seq;
} icmp_echo_hdr;

uint16_t icmp_checksum(const void *data, size_t len);
size_t   build_icmp_echo(uint16_t id, uint16_t seq,
                         const uint8_t *payload, size_t payload_len,
                         uint8_t *out, size_t out_cap);
void     hex_dump(const void *buf, size_t len);

#endif // PING_H

