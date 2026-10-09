# Changelog

All notable changes to `packet-analyzer` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-09

### Added
- **PCAP Binary Lexer**: Zero-dependency parser for Libpcap files supporting little-endian and big-endian, microsecond and nanosecond timestamps.
- **Protocol Dissectors**:
  - Layer 2: Ethernet II (with 802.1Q VLAN support) and ARP.
  - Layer 3: IPv4, IPv6, and ICMP.
  - Layer 4: TCP (flags, sequence tracking) and UDP.
  - Layer 7: DNS (RFC 1035 with compression pointers), HTTP/1.x, and TLS (ClientHello SNI extraction).
- **Conversation Tracking & TCP Reassembly**: 5-tuple canonical flow tracking and out-of-order sequence reconstruction.
- **Threat Detection Engine**:
  - TCP SYN sweep and stealth scans (NULL, FIN, XMAS).
  - ARP spoofing and cache poisoning detection.
  - DNS tunneling and DGA detection via Shannon entropy.
  - Cleartext credential and secret leakage in HTTP headers and bodies.
  - Oversized ICMP payload anomaly detection.
- **Analytics & Forensics**: Protocol hierarchy, top talkers, bandwidth throughput metrics.
- **Reporters & CLI**: Multi-format reporting (Rich terminal, JSON, ArcSight CEF) and `pktanalyzer` Typer CLI.
- **REST Control Plane**: FastAPI API service on port 8084 for PCAP upload, telemetry, and stream inspection.
- **Containerization & CI**: Rootless multi-stage Docker container (UID 10001) and GitHub Actions CI workflow.
