# Network Packet Analysis Tool (`packet-analyzer`)

Enterprise-grade, high-performance Network Packet Analysis, Deep Packet Inspection (DPI) engine, and active cyber threat detector built in Python 3.12.

[![CI Pipeline](https://github.com/portfolio/packet-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/portfolio/packet-analyzer/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)

---

## 🚀 Key Capabilities

- **Zero-Dependency PCAP Binary Lexer**: Reads Libpcap captures across little-endian / big-endian, microsecond / nanosecond timestamps.
- **Deep Protocol Dissection (L2 - L7)**:
  - **L2**: Ethernet II (with 802.1Q VLAN support), ARP.
  - **L3**: IPv4 (IHL, options, fragments), IPv6, ICMP.
  - **L4**: TCP (full flag decoding, sequence numbers), UDP.
  - **L7**: DNS (RFC 1035 compression pointer resolution, A/AAAA/CNAME/TXT), HTTP/1.x, TLS (ClientHello SNI hostname extraction).
- **TCP Stream Reassembly & Flow Engine**: 5-tuple canonical conversation tracking, out-of-order sequence reordering, bidirectional payload extraction.
- **Network Threat Detection Engine**:
  - High-speed SYN sweeps and stealth scans (NULL, FIN, XMAS).
  - ARP cache poisoning and MAC spoofing.
  - DNS tunneling and DGA detection via Shannon entropy ($H \ge 3.8$) and large TXT payloads.
  - Cleartext credential and API secret leakage over HTTP.
  - Covert ICMP tunneling anomalies.
- **Forensic Analytics**: Protocol distribution hierarchy, top talkers, bandwidth throughput (B/s, pkt/s).
- **Interactive CLI & Telemetry REST API**: Rich terminal UI, JSON, and ArcSight CEF export, plus FastAPI service on port 8084.

---

## 🛠️ Installation & Setup

```bash
# Clone and setup virtual environment
git clone https://github.com/portfolio/packet-analyzer.git
cd packet-analyzer
python3 -m venv .venv
source .venv/bin/activate

# Install in development mode
pip install -e ".[dev]"
```

---

## 💻 CLI Usage

### 1. Analyze a Capture File
```bash
# Interactive Rich terminal dashboard
pktanalyzer analyze capture.pcap

# JSON format for automated pipelines
pktanalyzer analyze capture.pcap --format json --output report.json

# ArcSight Common Event Format (CEF) for SIEM ingestion
pktanalyzer analyze capture.pcap --format cef --output alerts.cef
```

### 2. Inspect Reconstructed Conversations
```bash
# List all tracked 5-tuple conversations
pktanalyzer flows capture.pcap

# Inspect bidirectional reconstructed stream
pktanalyzer flows capture.pcap --id <session_id>
```

---

## 🌐 REST Control Plane API

Start the API service:
```bash
uvicorn pktanalyzer.api.app:app --host 0.0.0.0 --port 8084
```

| Method | Endpoint | Description |
| ------ | -------- | ----------- |
| `GET` | `/health` | Health check and version status |
| `POST` | `/api/v1/analyze/upload` | Upload `.pcap` capture for analysis and threat detection |
| `GET` | `/api/v1/flows` | List reconstructed conversational flows |
| `GET` | `/api/v1/flows/{id}` | Inspect reconstructed byte stream payload |
| `GET` | `/api/v1/alerts` | Retrieve all detected security threats |

---

## 🐳 Docker Deployment

```bash
docker-compose up --build -d
```

---

## 🧪 Testing & Verification

```bash
# Run full test suite with coverage
pytest --cov=src --cov-report=term-missing --cov-fail-under=90

# Static checks & security scanning
ruff check src tests
ruff format --check src tests
mypy src tests
bandit -r src
```

---

## 📚 Documentation

- [Architecture Blueprint](docs/architecture.md)
- [STRIDE Threat Model](docs/threat_model.md)
- [Changelog](CHANGELOG.md)
