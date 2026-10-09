# Network Packet Analysis Tool (`packet-analyzer`)

Enterprise-grade, high-performance Network Packet Analysis, Deep Packet Inspection (DPI) engine, and active cyber threat detector built in Python 3.12.

## Features

- **PCAP Binary Lexer**: Zero-dependency binary reader for Libpcap (little/big-endian, microsecond/nanosecond timestamps).
- **Multi-Layer Protocol Dissectors**:
  - Layer 2: Ethernet II, ARP.
  - Layer 3: IPv4, IPv6, ICMP.
  - Layer 4: TCP, UDP.
  - Layer 7: DNS, HTTP, TLS (ClientHello SNI).
- **Flow Engine & TCP Stream Reassembly**: 5-tuple session tracking, out-of-order packet reordering, bidirectional stream reconstruction.
- **Cyber Threat Detection**:
  - Port scan detection (SYN, FIN, NULL, XMAS).
  - ARP spoofing and cache poisoning detection.
  - DNS tunneling and DGA detection via Shannon entropy.
  - Cleartext credential and PII leakage in HTTP payloads.
- **Analytics & Forensics**: Protocol hierarchy, conversation breakdown, top talkers, bandwidth distribution.
- **Interfaces**: Rich interactive CLI and production FastAPI REST API (:8084).

## Architecture

See [docs/architecture.md](docs/architecture.md) and [docs/threat_model.md](docs/threat_model.md).
