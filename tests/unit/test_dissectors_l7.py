"""Unit tests for Layer 7 application protocol dissectors (DNS, HTTP, TLS)."""

import socket
import struct

import pytest

from pktanalyzer.dissectors import (
    PacketDissector,
    dissect_dns,
    dissect_http,
    dissect_tls,
)
from pktanalyzer.models.enums import EtherType, IPProtocol
from pktanalyzer.models.packet import RawPacket


def _build_dns_query_bytes(tx_id: int, domain: str, qtype: int = 1) -> bytes:
    """Helper to synthesize DNS query payload."""
    # Header: ID, Flags (0x0100 standard query), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    hdr = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    qname = b""
    for part in domain.split("."):
        qname += bytes([len(part)]) + part.encode("ascii")
    qname += b"\x00"
    question = qname + struct.pack("!HH", qtype, 1)  # QTYPE, QCLASS=IN
    return hdr + question


def test_dissect_dns_query() -> None:
    """Verify DNS query parsing."""
    raw = _build_dns_query_bytes(0x1234, "api.github.com", qtype=1)
    dns = dissect_dns(raw)
    assert dns.transaction_id == 0x1234
    assert dns.is_response is False
    assert len(dns.questions) == 1
    assert dns.questions[0].name == "api.github.com"
    assert dns.questions[0].qtype == 1


def test_dissect_dns_response() -> None:
    """Verify DNS response parsing with answers."""
    query = _build_dns_query_bytes(0x5678, "example.com")
    # Response header: flags=0x8180 (Standard response, No error), QDCOUNT=1, ANCOUNT=2
    hdr = struct.pack("!HHHHHH", 0x5678, 0x8180, 1, 2, 0, 0)
    question = query[12:]

    # Answer 1: pointer to question name (offset 12 = 0xC00C), A record, TTL 300, 4 bytes IP
    ans1 = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton("93.184.216.34")

    # Answer 2: pointer to question name, TXT record, TTL 60, string "v=spf1"
    txt_data = b"v=spf1"
    ans2 = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, len(txt_data)) + txt_data

    raw = hdr + question + ans1 + ans2
    dns = dissect_dns(raw)
    assert dns.is_response is True
    assert len(dns.answers) == 2
    assert dns.answers[0].rtype == 1
    assert dns.answers[0].rdata == "93.184.216.34"
    assert dns.answers[1].rtype == 16
    assert dns.answers[1].rdata == "v=spf1"


def test_dissect_dns_errors() -> None:
    """Verify DNS exception on short payload."""
    with pytest.raises(ValueError, match="too short for DNS header"):
        dissect_dns(b"\x00" * 8)


def test_dissect_http_request_and_response() -> None:
    """Verify HTTP/1.1 request and response parsing."""
    req_payload = (
        b"GET /api/v1/users?page=1 HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Authorization: Bearer test_token_xyz\r\n"
        b"\r\n"
    )
    req = dissect_http(req_payload)
    assert req.is_request is True
    assert req.method == "GET"
    assert req.uri == "/api/v1/users?page=1"
    assert req.headers["Host"] == "example.com"
    assert req.headers["Authorization"] == "Bearer test_token_xyz"

    resp_payload = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 17\r\n"
        b"\r\n"
        b'{"status":"ok"}'
    )
    resp = dissect_http(resp_payload)
    assert resp.is_request is False
    assert resp.status_code == 200
    assert resp.reason_phrase == "OK"
    assert resp.body == '{"status":"ok"}'


def test_dissect_http_errors() -> None:
    """Verify HTTP parser error handling."""
    with pytest.raises(ValueError, match="too short"):
        dissect_http(b"GET")

    with pytest.raises(ValueError, match="Not a recognizable HTTP"):
        dissect_http(b"UNKNOWN_PROTOCOL_DATA_HERE\r\n\r\n")


def test_dissect_tls_client_hello_sni() -> None:
    """Verify TLS ClientHello dissection and SNI extraction."""
    # Build TLS ClientHello
    hostname = b"secure.target.local"
    # SNI extension: ext_type=0, ext_len, list_len, name_type=0, host_len, host
    sni_ext_payload = struct.pack("!HBH", len(hostname) + 3, 0, len(hostname)) + hostname
    sni_ext = struct.pack("!HH", 0, len(sni_ext_payload)) + sni_ext_payload
    extensions = struct.pack("!H", len(sni_ext)) + sni_ext

    # ClientHello body with cipher suites and SNI extension
    ch_body = (
        struct.pack("!H", 0x0303)
        + (b"\x00" * 32)
        + b"\x00"
        + struct.pack("!H", 2)
        + b"\x13\x01"
        + b"\x01\x00"
        + extensions
    )
    # Handshake header: type=1 (ClientHello), length=uint24
    hs_len = len(ch_body)
    hs_hdr = bytes([1, (hs_len >> 16) & 0xFF, (hs_len >> 8) & 0xFF, hs_len & 0xFF])
    record_payload = hs_hdr + ch_body

    # TLS Record Header: content_type=22 (Handshake), version=0x0301 (TLS 1.0), length
    rec_hdr = struct.pack("!BBBH", 22, 3, 1, len(record_payload))
    full_tls = rec_hdr + record_payload

    tls = dissect_tls(full_tls)
    assert tls.content_type == 22
    assert tls.is_handshake is True
    assert tls.handshake_type == 1
    assert tls.sni_hostname == "secure.target.local"


def test_dissect_tls_app_data_and_errors() -> None:
    """Verify TLS AppData record and error conditions."""
    app_data = struct.pack("!BBBH", 23, 3, 3, 16) + (b"\xaa" * 16)
    tls = dissect_tls(app_data)
    assert tls.content_type == 23
    assert not tls.is_handshake

    with pytest.raises(ValueError, match="too short for TLS record"):
        dissect_tls(b"\x16\x03")

    with pytest.raises(ValueError, match="Invalid TLS record header"):
        dissect_tls(b"\x99\x01\x00\x00\x05" + b"\x00" * 5)


def test_dissector_l7_coordinator_integration() -> None:
    """Verify PacketDissector end-to-end with L7 protocols."""
    coord = PacketDissector()

    # Synthetic UDP DNS Packet
    dns_payload = _build_dns_query_bytes(0x7777, "corp.internal")
    udp_hdr = struct.pack("!HHHH", 50000, 53, 8 + len(dns_payload), 0) + dns_payload
    ip_hdr = (
        struct.pack(
            "!BBHHHBBH", (4 << 4) | 5, 0, 20 + len(udp_hdr), 1, 0, 64, int(IPProtocol.UDP), 0
        )
        + socket.inet_aton("192.168.1.50")
        + socket.inet_aton("8.8.8.8")
    )
    eth_hdr = b"\x00" * 6 + b"\x11" * 6 + struct.pack("!H", int(EtherType.IPV4))
    full_dns = eth_hdr + ip_hdr + udp_hdr

    raw_dns = RawPacket(
        frame_number=1,
        timestamp=1700000000.0,
        caplen=len(full_dns),
        wirelen=len(full_dns),
        data=full_dns,
    )
    pkt_dns = coord.dissect(raw_dns)
    assert pkt_dns.dns is not None
    assert pkt_dns.protocol_name == "DNS"
    assert "Query: corp.internal" in pkt_dns.summary

    # Synthetic TCP HTTP Packet
    http_payload = b"GET /index.html HTTP/1.1\r\nHost: myapp.test\r\n\r\n"
    tcp_hdr = struct.pack("!HHIIHHHH", 44000, 80, 1, 1, (5 << 12) | 24, 1024, 0, 0) + http_payload
    ip_http = (
        struct.pack(
            "!BBHHHBBH", (4 << 4) | 5, 0, 20 + len(tcp_hdr), 2, 0, 64, int(IPProtocol.TCP), 0
        )
        + socket.inet_aton("10.0.0.2")
        + socket.inet_aton("10.0.0.1")
    )
    full_http = eth_hdr + ip_http + tcp_hdr

    pkt_http = coord.dissect(
        RawPacket(
            frame_number=2,
            timestamp=1700000001.0,
            caplen=len(full_http),
            wirelen=len(full_http),
            data=full_http,
        )
    )
    assert pkt_http.http is not None
    assert pkt_http.protocol_name == "HTTP"
    assert "GET /index.html HTTP/1.1" in pkt_http.summary
