"""Integration tests for FastAPI endpoints."""

import io
import socket
import struct

from fastapi.testclient import TestClient

from pktanalyzer.api.app import app
from pktanalyzer.core.reader import PCAPWriter
from pktanalyzer.models.enums import EtherType, IPProtocol, LinkType, TCPFlag

client = TestClient(app)


def _build_test_pcap_bytes() -> bytes:
    """Construct in-memory PCAP with HTTP traffic and XMAS scan."""
    buf = io.BytesIO()
    writer = PCAPWriter(buf, linktype=LinkType.ETHERNET)

    dst_mac = b"\x00\x11\x22\x33\x44\x55"
    src_mac = b"\x66\x77\x88\x99\xaa\xbb"
    eth_hdr = dst_mac + src_mac + struct.pack("!H", int(EtherType.IPV4))

    src_ip = socket.inet_aton("192.168.1.100")
    dst_ip = socket.inet_aton("10.0.0.1")

    # Packet 1: HTTP GET
    http_payload = b"GET /admin HTTP/1.1\r\nHost: test.local\r\n\r\n"
    tcp_hdr = struct.pack("!HHIIHHHH", 50000, 80, 1, 1, (5 << 12) | 24, 1024, 0, 0) + http_payload
    ip_hdr = (
        struct.pack(
            "!BBHHHBBH", (4 << 4) | 5, 0, 20 + len(tcp_hdr), 1, 0, 64, int(IPProtocol.TCP), 0
        )
        + src_ip
        + dst_ip
    )
    writer.write_packet(eth_hdr + ip_hdr + tcp_hdr, timestamp=1700000000.0)

    # Packet 2: XMAS scan
    tcp_xmas = struct.pack(
        "!HHIIHHHH",
        50001,
        22,
        0,
        0,
        (5 << 12) | (int(TCPFlag.FIN) | int(TCPFlag.PSH) | int(TCPFlag.URG)),
        1024,
        0,
        0,
    )
    ip_xmas = (
        struct.pack(
            "!BBHHHBBH", (4 << 4) | 5, 0, 20 + len(tcp_xmas), 2, 0, 64, int(IPProtocol.TCP), 0
        )
        + src_ip
        + dst_ip
    )
    writer.write_packet(eth_hdr + ip_xmas + tcp_xmas, timestamp=1700000000.1)

    return buf.getvalue()


def test_api_health() -> None:
    """Verify /health endpoint."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["version"] == "0.1.0"
    assert "timestamp" in data


def test_api_upload_and_flows() -> None:
    """Verify PCAP upload, analysis, flow retrieval, and stream inspection."""
    pcap_data = _build_test_pcap_bytes()
    files = {"file": ("test.pcap", pcap_data, "application/vnd.tcpdump.pcap")}

    res_upload = client.post("/api/v1/analyze/upload", files=files)
    assert res_upload.status_code == 200
    ana = res_upload.json()
    assert ana["filename"] == "test.pcap"
    assert ana["summary"]["total_packets"] == 2
    assert len(ana["security_alerts"]) >= 1
    assert ana["conversations_count"] >= 1

    # Check flows
    res_flows = client.get("/api/v1/flows")
    assert res_flows.status_code == 200
    flows = res_flows.json()
    assert len(flows) >= 1
    session_id = flows[0]["session_id"]

    # Check specific flow stream
    res_stream = client.get(f"/api/v1/flows/{session_id}")
    assert res_stream.status_code == 200
    stream = res_stream.json()
    assert stream["session_id"] == session_id

    # Check non-existent flow
    res_404 = client.get("/api/v1/flows/non_existent_id")
    assert res_404.status_code == 404

    # Check alerts endpoint
    res_alerts = client.get("/api/v1/alerts")
    assert res_alerts.status_code == 200
    alerts = res_alerts.json()
    assert len(alerts) >= 1


def test_api_upload_invalid_file() -> None:
    """Verify error on corrupted file upload."""
    files = {"file": ("corrupt.pcap", b"NOT_A_PCAP_FILE", "application/octet-stream")}
    res = client.post("/api/v1/analyze/upload", files=files)
    assert res.status_code == 400
    assert "Error parsing PCAP" in res.json()["detail"]
