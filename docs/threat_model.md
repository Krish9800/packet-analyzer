# Packet Analyzer Threat Model (STRIDE)

## 1. System Scope & Boundaries

The Packet Analyzer processes untrusted binary PCAP files and network packets. Attackers can intentionally craft malformed packets to crash the dissector, cause denial of service (infinite loops), exhaust memory (gigantic buffer allocations), or exploit parsing vulnerabilities.

## 2. STRIDE Threat Analysis

| Threat Category | Threat Description | Architectural Mitigation |
| --------------- | ------------------ | ------------------------ |
| **Spoofing** | Adversary injects spoofed IP/MAC frames or forged ARP mappings. | `ARPSpoofDetector` flags conflicting MAC-to-IP bindings and unsolicited ARP replies. |
| **Tampering** | Attacker tampers with packet payload lengths or TCP sequence numbers to poison reassembly. | Sequence-bounded `HalfStream` rejects out-of-order bounds exceeding memory limits; retransmission deduplication prevents duplicate injection. |
| **Repudiation** | Network actor denies generating port scans or data exfiltration. | Comprehensive CEF and JSON forensic audit logs record exact frame timestamps, packet headers, and cryptographic session IDs. |
| **Information Disclosure** | Sensitive user credentials or API tokens leaked in cleartext traffic. | `CredentialLeakDetector` alerts on unencrypted HTTP Basic auth, Bearer tokens, and sensitive body parameters. |
| **Denial of Service** | Crafted circular DNS compression pointers or gigantic declared packet lengths to cause infinite loops or memory exhaustion. | 1. DNS pointer loops bounded by strict `max_hops = 20`.<br/>2. PCAP global header and record lengths clamped to buffer bounds; premature EOF raises `PCAPCorruptError`.<br/>3. File upload size clamped to 100 MB. |
| **Elevation of Privilege** | Remote code execution via buffer overflow in native PCAP parser. | Pure Python 3.12 implementation using safe `struct` unpacking and Pydantic models. Zero native C extensions. Rootless Docker container (`UID 10001:10001`). |

## 3. Security Hardening Controls

1. **Rootless Execution**: Docker container runs unprivileged as UID 10001 with read-only root filesystem and `no-new-privileges:true`.
2. **Bounds Checking**: Every protocol dissector enforces explicit minimum byte lengths prior to struct unpacking.
3. **No Unbounded Recursion**: Label resolution in DNS employs loop hop counters to defeat circular reference attacks.
4. **Static Security Gate**: Continuous SAST enforcement via Bandit (`bandit -r src`) in CI.
