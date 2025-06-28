#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>
#include <net/ethernet.h>

typedef struct {
    char src_ip[16];
    char dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    const u_char *payload;
    uint32_t payload_len;
} packet_info_t;

packet_info_t parse_packet(const u_char *packet, uint32_t length);
void print_packet_info(const packet_info_t *info, const u_char *packet, uint32_t length);
void decode_dns_payload(const u_char *payload, uint32_t len);
void decode_http_payload(const u_char *payload, uint32_t len);

#endif
