#include "parser.h"
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

packet_info_t parse_packet(const u_char *packet, uint32_t length) {
    packet_info_t info;
    memset(&info, 0, sizeof(packet_info_t));

    if (length < 14) return info;

    const struct ether_header *eth = (struct ether_header *)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return info;

    const struct ip *ip_hdr = (struct ip *)(packet + 14);
    int ip_hdr_len = ip_hdr->ip_hl * 4;

    strncpy(info.src_ip, inet_ntoa(ip_hdr->ip_src), sizeof(info.src_ip));
    strncpy(info.dst_ip, inet_ntoa(ip_hdr->ip_dst), sizeof(info.dst_ip));
    info.protocol = ip_hdr->ip_p;

    if (ip_hdr->ip_p == IPPROTO_TCP) {
        const struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + 14 + ip_hdr_len);
        info.src_port = ntohs(tcp_hdr->th_sport);
        info.dst_port = ntohs(tcp_hdr->th_dport);
    } else if (ip_hdr->ip_p == IPPROTO_UDP) {
        const struct udphdr *udp_hdr = (struct udphdr *)(packet + 14 + ip_hdr_len);
        info.src_port = ntohs(udp_hdr->uh_sport);
        info.dst_port = ntohs(udp_hdr->uh_dport);
    }

    return info;
}