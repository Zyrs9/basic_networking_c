#ifndef PING_H
#define PING_H

#include <stdint.h>
#include <stddef.h>
#include <arpa/inet.h>

// ICMP type codes
#define ICMP_ECHO      8
#define ICMP_ECHOREPLY 0

#if defined(__GNUC__)
#define PACKED __attribute__((packed))
#else
#define PACKED
#endif

// ICMP Echo hdr (RFC 792)
typedef struct PACKED {
    uint8_t  type;     // 8=req, 0=reply
    uint8_t  code;     // 0
    uint16_t checksum; // 1's comp
    uint16_t id;       // net order
    uint16_t seq;      // net order
} icmp_echo_hdr;

// build + checksum + dump
uint16_t icmp_checksum(const void *data, size_t len);
size_t   build_icmp_echo(uint16_t id, uint16_t seq,
                         const uint8_t *payload, size_t payload_len,
                         uint8_t *out, size_t out_cap);
void     hex_dump(const void *buf, size_t len);

#endif // PING_H

