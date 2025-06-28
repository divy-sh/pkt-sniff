#include "utils.h"
#include <stdio.h>

void print_packet_info(const packet_info_t *info) {
    if (info->protocol == 0) return;
    printf("SRC: %s:%d -> DST: %s:%d | PROTO: %s\n",
           info->src_ip, info->src_port,
           info->dst_ip, info->dst_port,
           info->protocol == 6 ? "TCP" :
           info->protocol == 17 ? "UDP" : "OTHER");
}