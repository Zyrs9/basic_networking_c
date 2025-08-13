#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>   // getpid
#include "ping.h"

// 16-bit one's complement checksum 
uint16_t icmp_checksum(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t*)data;
    uint32_t sum = 0;

    // 16-bit to big-endian
    while (len > 1) {
        uint16_t w = ((uint16_t)p[0] << 8) | (uint16_t)p[1];
        sum += w;
        p += 2;
        len -= 2;
    }
    if (len == 1) {
        uint16_t w = ((uint16_t)p[0] << 8);
        sum += w;
    }

    // multiplying the carry
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

// Verilen id/seq ve payload ile ICMP Echo paketi kurar.
// out: çıktının yazılacağı buffer, out_cap: kapasite
// dönüş: yazılan gerçek paket uzunluğu (başlık+payload)
size_t build_icmp_echo(uint16_t id, uint16_t seq,
                       const uint8_t *payload, size_t payload_len,
                       uint8_t *out, size_t out_cap)
{
    const size_t hdr_len = sizeof(icmp_echo_hdr);
    const size_t total   = hdr_len + payload_len;
    assert(out != NULL);
    if (out_cap < total) {
        fprintf(stderr, "build_icmp_echo: buffer yetersiz (gerekli=%zu, var=%zu)\n",
                total, out_cap);
        exit(EXIT_FAILURE);
    }

    icmp_echo_hdr hdr;
    hdr.type = ICMP_ECHO;
    hdr.code = 0;
    hdr.checksum = 0; // checksum = 0 before all calculations.
    hdr.id  = htons(id);
    hdr.seq = htons(seq);

    memcpy(out, &hdr, hdr_len);
    if (payload_len && payload) {
        memcpy(out + hdr_len, payload, payload_len);
    }

    // checksum from ICMP total -> header + payload
    uint16_t csum = icmp_checksum(out, total);

    // checksum2header
    ((icmp_echo_hdr*)out)->checksum = csum;

    return total;
}

// Basic hex dump (16 byte)
void hex_dump(const void *buf, size_t len) {
    const unsigned char *p = (const unsigned char*)buf;
    for (size_t i = 0; i < len; i += 16) {
        printf("%04zx  ", i);
        size_t j = 0;
        for (; j < 16 && i + j < len; ++j) {
            printf("%02x ", p[i + j]);
        }
        for (; j < 16; ++j) printf("   ");
        printf(" |");
        for (j = 0; j < 16 && i + j < len; ++j) {
            unsigned char c = p[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        printf("|\n");
    }
}

int main(void) {
    const char *msg = "Hello";
    uint8_t packet[64]; // buffer
    uint16_t id  = (uint16_t)(getpid() & 0xFFFF);
    uint16_t seq = 1;

    size_t pkt_len = build_icmp_echo(id, seq,
                                     (const uint8_t*)msg, strlen(msg),
                                     packet, sizeof(packet));

    printf("ICMP Echo paketi oluşturuldu:\n");
    printf("  type=%u code=%u id=0x%04x seq=%u payload_len=%zu total_len=%zu\n",
           ((icmp_echo_hdr*)packet)->type,
           ((icmp_echo_hdr*)packet)->code,
           ntohs(((icmp_echo_hdr*)packet)->id),
           ntohs(((icmp_echo_hdr*)packet)->seq),
           strlen(msg), pkt_len);

    printf("\nHex dump:\n");
    hex_dump(packet, pkt_len);
   
    return 0;
}

