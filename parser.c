#include "parser.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

packet_info_t parse_packet(const u_char *packet, uint32_t length) {
    packet_info_t info;
    memset(&info, 0, sizeof(packet_info_t));

    if (length < sizeof(struct ether_header)) {
        fprintf(stderr, "Packet too short for Ethernet header\n");
        return info;
    }

    const struct ether_header *eth = (struct ether_header *)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        fprintf(stderr, "Not an IPv4 packet (ethertype=0x%04x)\n", ntohs(eth->ether_type));
        return info;
    }

    const u_char *ip_ptr = packet + sizeof(struct ether_header);
    if ((ip_ptr - packet) >= length) {
        fprintf(stderr, "Invalid IP header pointer\n");
        return info;
    }

    const struct ip *ip_hdr = (struct ip *)ip_ptr;
    int ip_hdr_len = ip_hdr->ip_hl * 4;

    if ((ip_ptr + ip_hdr_len) > (packet + length)) {
        fprintf(stderr, "Truncated IP header\n");
        return info;
    }

    strncpy(info.src_ip, inet_ntoa(ip_hdr->ip_src), sizeof(info.src_ip) - 1);
    strncpy(info.dst_ip, inet_ntoa(ip_hdr->ip_dst), sizeof(info.dst_ip) - 1);
    info.protocol = ip_hdr->ip_p;

    const u_char *transport_ptr = ip_ptr + ip_hdr_len;
    uint32_t transport_len = length - (transport_ptr - packet);

    if (ip_hdr->ip_p == IPPROTO_TCP) {
        if (transport_len < sizeof(struct tcphdr)) {
            fprintf(stderr, "Truncated TCP header\n");
            return info;
        }

        const struct tcphdr *tcp_hdr = (struct tcphdr *)transport_ptr;
        info.src_port = ntohs(tcp_hdr->th_sport);
        info.dst_port = ntohs(tcp_hdr->th_dport);

        int tcp_hdr_len = tcp_hdr->th_off * 4;
        if (tcp_hdr_len < sizeof(struct tcphdr) || tcp_hdr_len > transport_len) {
            fprintf(stderr, "Invalid TCP header length\n");
            return info;
        }

        info.payload = transport_ptr + tcp_hdr_len;
        info.payload_len = transport_len - tcp_hdr_len;

        u_char *opt = transport_ptr + sizeof(struct tcphdr);
        
        while (opt < info.payload) {
            u_char opt_code = *opt++;
            u_char opt_len = 0;
            switch (opt_code)
            {
                case 1: //NOP
                //opt += (opt_len - 2)
                break;
                case 0: //EOL
                case 8: // TS
                default:
                opt_len = *opt++;
                opt += (opt_len - 2);
                break;
            }

            printf ("Option code: %d, Option Length: %d\n", opt_code, opt_len);
        }

    } else if (ip_hdr->ip_p == IPPROTO_UDP) {
        if (transport_len < sizeof(struct udphdr)) {
            fprintf(stderr, "Truncated UDP header\n");
            return info;
        }

        const struct udphdr *udp_hdr = (struct udphdr *)transport_ptr;
        info.src_port = ntohs(udp_hdr->uh_sport);
        info.dst_port = ntohs(udp_hdr->uh_dport);

        info.payload = transport_ptr + sizeof(struct udphdr);
        info.payload_len = transport_len - sizeof(struct udphdr);

    } else {
        // For ICMP or other protocols, leave ports and payload empty.
        info.payload = transport_ptr;
        info.payload_len = transport_len;
    }

    return info;
}


void print_packet_info(const packet_info_t *info, const u_char *packet, uint32_t length) {
    const struct ether_header *eth = (struct ether_header *)packet;

    printf("=== Ethernet Header ===\n");
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    printf("Source MAC     : %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("EtherType      : 0x%04x\n\n", ntohs(eth->ether_type));

    const struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));

    printf("=== IP Header ===\n");
    printf("Version        : %d\n", ip_hdr->ip_v);
    printf("Header Length  : %d bytes\n", ip_hdr->ip_hl * 4);
    printf("Type of Service: 0x%02x\n", ip_hdr->ip_tos);
    printf("Total Length   : %d\n", ntohs(ip_hdr->ip_len));
    printf("ID             : %d\n", ntohs(ip_hdr->ip_id));
    printf("TTL            : %d\n", ip_hdr->ip_ttl);
    printf("Protocol       : %d\n", ip_hdr->ip_p);
    printf("Checksum       : 0x%04x\n", ntohs(ip_hdr->ip_sum));
    printf("Source IP      : %s\n", inet_ntoa(ip_hdr->ip_src));
    printf("Destination IP : %s\n\n", inet_ntoa(ip_hdr->ip_dst));

    int ip_hdr_len = ip_hdr->ip_hl * 4;
    const u_char *transport = packet + sizeof(struct ether_header) + ip_hdr_len;

    if (ip_hdr->ip_p == IPPROTO_TCP) {
        const struct tcphdr *tcp = (struct tcphdr *)transport;
        printf("=== TCP Header ===\n");
        printf("Source Port    : %d\n", ntohs(tcp->th_sport));
        printf("Destination Port: %d\n", ntohs(tcp->th_dport));
        printf("Sequence Number: %u\n", ntohl(tcp->th_seq));
        printf("ACK Number     : %u\n", ntohl(tcp->th_ack));
        printf("Header Length  : %d bytes\n", tcp->th_off * 4);
        printf("Flags          : 0x%02x (", tcp->th_flags);
        if (tcp->th_flags & TH_SYN) printf("SYN ");
        if (tcp->th_flags & TH_ACK) printf("ACK ");
        if (tcp->th_flags & TH_RST) printf("RST ");
        if (tcp->th_flags & TH_FIN) printf("FIN ");
        if (tcp->th_flags & TH_PUSH) printf("PSH ");
        if (tcp->th_flags & TH_URG) printf("URG ");
        printf(")\n");
        printf("Window Size    : %d\n", ntohs(tcp->th_win));
        printf("Checksum       : 0x%04x\n\n", ntohs(tcp->th_sum));

    } else if (ip_hdr->ip_p == IPPROTO_UDP) {
        const struct udphdr *udp = (struct udphdr *)transport;
        printf("=== UDP Header ===\n");
        printf("Source Port    : %d\n", ntohs(udp->uh_sport));
        printf("Destination Port: %d\n", ntohs(udp->uh_dport));
        printf("Length         : %d\n", ntohs(udp->uh_ulen));
        printf("Checksum       : 0x%04x\n\n", ntohs(udp->uh_sum));
    }

    if (info->payload && info->payload_len > 0) {
        printf("=== Payload (%u bytes) ===\n", info->payload_len);
        for (uint32_t i = 0; i < info->payload_len; ++i) {
            printf("%02x ", info->payload[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        if (info->payload_len % 16 != 0) printf("\n");
    } else {
        printf("No payload.\n");
    }

    if (info->protocol == IPPROTO_TCP) {
    if (info->dst_port == 80 || info->src_port == 80 ||
        info->dst_port == 8080 || info->src_port == 8080 ||
        info->dst_port == 443 || info->src_port == 443) {
        decode_http_payload(info->payload, info->payload_len);
    }
    } else if (info->protocol == IPPROTO_UDP) {
        if (info->src_port == 53 || info->dst_port == 53) {
            decode_dns_payload(info->payload, info->payload_len);
        }
    }

    printf("--------------------------------------------------\n");
}

void decode_http_payload(const u_char *payload, uint32_t len) {
    if (len < 4) return;

    // Print only if it looks printable (ASCII) and starts with known HTTP verbs
    const char *http_methods[] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"};
    int is_http = 0;
    for (int i = 0; i < 6; i++) {
        if (strncmp((const char *)payload, http_methods[i], strlen(http_methods[i])) == 0) {
            is_http = 1;
            break;
        }
    }

    if (!is_http && strncmp((const char *)payload, "HTTP/", 5) != 0)
        return;

    printf("=== HTTP Message ===\n");
    fwrite(payload, 1, len, stdout); // raw HTTP content
    printf("\n----------------------\n");
}

void decode_dns_payload(const u_char *payload, uint32_t len) {
    if (len < 12) return; // minimum DNS header

    uint16_t qdcount = ntohs(*(uint16_t *)(payload + 4));
    const u_char *ptr = payload + 12;

    printf("=== DNS Query ===\n");
    for (int i = 0; i < qdcount && ptr < payload + len; i++) {
        char name[256];
        int total_len = 0;
        while (ptr[0] != 0 && total_len < sizeof(name) - 1 && ptr < payload + len) {
            int label_len = ptr[0];
            if (label_len + total_len >= sizeof(name) - 1 || ptr + label_len >= payload + len) break;
            if (total_len > 0) name[total_len++] = '.';
            memcpy(&name[total_len], ptr + 1, label_len);
            total_len += label_len;
            ptr += label_len + 1;
        }
        name[total_len] = '\0';
        ptr++; // skip null byte
        if (ptr + 4 > payload + len) break;

        uint16_t qtype = ntohs(*(uint16_t *)ptr);
        ptr += 4;

        printf("Query %d: %s (Type %d)\n", i + 1, name, qtype);
    }
    printf("--------------------\n");
}
