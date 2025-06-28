#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include "parser.h"

#define SNAP_LEN 1518

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    packet_info_t info = parse_packet(bytes, h->caplen);
    print_packet_info(&info, bytes, h->caplen);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(argv[1], SNAP_LEN, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        return 1;
    }

    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
    return 0;
}