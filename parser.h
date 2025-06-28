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
} packet_info_t;

packet_info_t parse_packet(const u_char *packet, uint32_t length);

#endif