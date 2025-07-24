# pkt-sniff

A simple, system-agnostic real-time network packet sniffer written in C using raw sockets and libpcap.  
It captures and parses Ethernet, IP, TCP/UDP, and HTTP layers, supports BPF-based live filtering, protocol analytics, and optional CSV/PCAP export.


## Features

- Capture live network packets from a specified interface.
- Parse Ethernet, IPv4, TCP, UDP, and HTTP headers.
- Display parsed packet information on the console.

## TODO

- BPF (Berkeley Packet Filter) support for live filtering.
- Export captured data optionally to CSV or PCAP files (optional extensions).

## Requirements

- GCC compiler
- libpcap development libraries

### Install dependencies

#### Ubuntu/Debian:
```bash
sudo apt update
sudo apt install build-essential libpcap-dev
