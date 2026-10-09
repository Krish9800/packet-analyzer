"""Unit tests for network threat detection engine and anomaly algorithms."""

import base64

from pktanalyzer.config.settings import AnalyzerSettings
from pktanalyzer.models.enums import TCPFlag, ThreatCategory, ThreatSeverity
from pktanalyzer.models.packet import DissectedPacket
from pktanalyzer.models.protocols import (
    ARPPacket,
    DNSMessage,
    DNSQuestion,
    DNSResourceRecord,
    HTTPMessage,
    ICMPPacket,
    IPv4Packet,
    TCPSegment,
)
from pktanalyzer.threats import (
    ARPSpoofDetector,
    CredentialLeakDetector,
    DNSTunnelDetector,
    ICMPAnomalyDetector,
    PortScanDetector,
    ThreatDetectionEngine,
    calculate_shannon_entropy,
)


def test_shannon_entropy() -> None:
    """Verify Shannon entropy calculation."""
    assert calculate_shannon_entropy("") == 0.0
    # All identical characters -> entropy is 0
    assert calculate_shannon_entropy("aaaaaaa") == 0.0
    # Uniform 4 characters -> -4 * (0.25 * log2(0.25)) = 2.0
    assert abs(calculate_shannon_entropy("abcd") - 2.0) < 0.001
    # Base64-like random string has high entropy > 3.8
    ent = calculate_shannon_entropy("a8b2c9d1e4f7g0h3j5k6l8m9")
    assert ent > 3.8


def test_port_scan_stealth_and_sweep() -> None:
    """Verify detection of stealth scans (XMAS, FIN, NULL) and SYN sweeps."""
    detector = PortScanDetector(threshold=5, window_seconds=2.0)

    ip_src = IPv4Packet(
        ihl=5,
        dscp=0,
        ecn=0,
        total_length=40,
        identification=1,
        flags=0,
        fragment_offset=0,
        ttl=64,
        protocol=6,
        checksum=0,
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
    )

    # 1. XMAS Scan packet
    xmas_pkt = DissectedPacket(
        frame_number=1,
        timestamp=1700000000.0,
        link_type=1,
        ipv4=ip_src,
        tcp=TCPSegment(
            src_port=40000,
            dst_port=80,
            seq_number=0,
            ack_number=0,
            data_offset=5,
            flags=int(TCPFlag.FIN) | int(TCPFlag.PSH) | int(TCPFlag.URG),
            window_size=1024,
            checksum=0,
            urgent_pointer=0,
            flag_names=["FIN", "PSH", "URG"],
        ),
    )
    alerts = detector.process_packet(xmas_pkt)
    assert len(alerts) == 1
    assert alerts[0].category == ThreatCategory.PORT_SCAN
    assert "XMAS Scan" in alerts[0].title

    # 2. FIN Scan packet
    fin_pkt = DissectedPacket(
        frame_number=2,
        timestamp=1700000000.1,
        link_type=1,
        ipv4=ip_src,
        tcp=TCPSegment(
            src_port=40001,
            dst_port=443,
            seq_number=0,
            ack_number=0,
            data_offset=5,
            flags=int(TCPFlag.FIN),
            window_size=1024,
            checksum=0,
            urgent_pointer=0,
            flag_names=["FIN"],
        ),
    )
    assert len(detector.process_packet(fin_pkt)) == 1

    # 3. NULL Scan packet
    null_pkt = DissectedPacket(
        frame_number=3,
        timestamp=1700000000.2,
        link_type=1,
        ipv4=ip_src,
        tcp=TCPSegment(
            src_port=40002,
            dst_port=22,
            seq_number=0,
            ack_number=0,
            data_offset=5,
            flags=0,
            window_size=1024,
            checksum=0,
            urgent_pointer=0,
            flag_names=[],
        ),
    )
    assert len(detector.process_packet(null_pkt)) == 1

    # 4. Rapid SYN sweep across multiple ports
    sweep_alerts = []
    for port in range(1001, 1008):
        syn_pkt = DissectedPacket(
            frame_number=port,
            timestamp=1700000000.5,
            link_type=1,
            ipv4=ip_src,
            tcp=TCPSegment(
                src_port=50000,
                dst_port=port,
                seq_number=0,
                ack_number=0,
                data_offset=5,
                flags=int(TCPFlag.SYN),
                window_size=1024,
                checksum=0,
                urgent_pointer=0,
                flag_names=["SYN"],
            ),
        )
        sweep_alerts.extend(detector.process_packet(syn_pkt))

    assert any(a.title == "High-Speed TCP Port Scan Sweep" for a in sweep_alerts)


def test_arp_spoof_detector() -> None:
    """Verify ARP cache poisoning detection on altered MAC mapping."""
    detector = ARPSpoofDetector()

    # Initial legitimate ARP announcement
    pkt1 = DissectedPacket(
        frame_number=1,
        timestamp=1700000000.0,
        link_type=1,
        arp=ARPPacket(
            hw_type=1,
            proto_type=0x0800,
            hw_size=6,
            proto_size=4,
            opcode=2,
            sender_mac="00:11:22:33:44:55",
            sender_ip="192.168.1.1",
            target_mac="ff:ff:ff:ff:ff:ff",
            target_ip="192.168.1.50",
        ),
    )
    assert len(detector.process_packet(pkt1)) == 0

    # Attacker claiming 192.168.1.1 from a different MAC
    pkt_poison = DissectedPacket(
        frame_number=2,
        timestamp=1700000001.0,
        link_type=1,
        arp=ARPPacket(
            hw_type=1,
            proto_type=0x0800,
            hw_size=6,
            proto_size=4,
            opcode=2,
            sender_mac="de:ad:be:ef:00:01",
            sender_ip="192.168.1.1",
            target_mac="ff:ff:ff:ff:ff:ff",
            target_ip="192.168.1.50",
        ),
    )
    alerts = detector.process_packet(pkt_poison)
    assert len(alerts) == 1
    assert alerts[0].category == ThreatCategory.ARP_POISONING
    assert alerts[0].severity == ThreatSeverity.CRITICAL


def test_dns_tunnel_detector() -> None:
    """Verify detection of DNS tunneling query entropy and large TXT answers."""
    detector = DNSTunnelDetector(entropy_threshold=3.5)

    # Legitimate low entropy domain
    normal_dns = DissectedPacket(
        frame_number=1,
        timestamp=1700000000.0,
        link_type=1,
        dns=DNSMessage(
            transaction_id=1,
            flags=0,
            is_response=False,
            opcode=0,
            rcode=0,
            questions=[DNSQuestion(name="mail.google.com", qtype=1, qclass=1)],
        ),
    )
    assert len(detector.process_packet(normal_dns)) == 0

    # High-entropy encoded subdomain
    tunnel_dns = DissectedPacket(
        frame_number=2,
        timestamp=1700000001.0,
        link_type=1,
        dns=DNSMessage(
            transaction_id=2,
            flags=0,
            is_response=False,
            opcode=0,
            rcode=0,
            questions=[
                DNSQuestion(
                    name="9f3b18c0e294711db5a4891bca7e8.tunnel.evil.org",
                    qtype=1,
                    qclass=1,
                )
            ],
        ),
    )
    alerts = detector.process_packet(tunnel_dns)
    assert len(alerts) == 1
    assert alerts[0].category == ThreatCategory.DNS_TUNNELING
    assert "High Shannon entropy" in alerts[0].description

    # Anomalous large TXT record in response
    large_txt = DissectedPacket(
        frame_number=3,
        timestamp=1700000002.0,
        link_type=1,
        dns=DNSMessage(
            transaction_id=3,
            flags=0x8180,
            is_response=True,
            opcode=0,
            rcode=0,
            answers=[
                DNSResourceRecord(
                    name="c2.evil.org",
                    rtype=16,
                    rclass=1,
                    ttl=10,
                    rdata="A" * 300,
                )
            ],
        ),
    )
    txt_alerts = detector.process_packet(large_txt)
    assert len(txt_alerts) == 1
    assert "Large DNS TXT" in txt_alerts[0].title


def test_credential_leak_detector() -> None:
    """Verify cleartext HTTP authentication and body credential leakage."""
    detector = CredentialLeakDetector()

    # Basic Auth header leak
    basic_val = base64.b64encode(b"admin:SecretP@ssword123").decode()
    pkt_basic = DissectedPacket(
        frame_number=1,
        timestamp=1700000000.0,
        link_type=1,
        http=HTTPMessage(
            is_request=True,
            method="GET",
            uri="/admin/panel",
            headers={"Authorization": f"Basic {basic_val}"},
        ),
    )
    alerts = detector.process_packet(pkt_basic)
    assert len(alerts) == 1
    assert alerts[0].category == ThreatCategory.CLEARTEXT_CREDENTIALS
    assert "Basic Authentication" in alerts[0].title

    # Bearer Token header leak
    pkt_bearer = DissectedPacket(
        frame_number=2,
        timestamp=1700000001.0,
        link_type=1,
        http=HTTPMessage(
            is_request=True,
            method="POST",
            uri="/api/data",
            headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz"},
        ),
    )
    alerts_bearer = detector.process_packet(pkt_bearer)
    assert len(alerts_bearer) == 1
    assert "Bearer Token" in alerts_bearer[0].title

    # Cleartext password parameter in POST body
    pkt_body = DissectedPacket(
        frame_number=3,
        timestamp=1700000002.0,
        link_type=1,
        http=HTTPMessage(
            is_request=True,
            method="POST",
            uri="/login",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body="username=john&password=UnencryptedPassword999",
        ),
    )
    alerts_body = detector.process_packet(pkt_body)
    assert len(alerts_body) == 1
    assert "Cleartext Secret Exposed" in alerts_body[0].title


def test_icmp_anomaly_detector() -> None:
    """Verify detection of jumbo / oversized ICMP payloads."""
    detector = ICMPAnomalyDetector(max_payload_bytes=64)

    ip_hdr = IPv4Packet(
        ihl=5,
        dscp=0,
        ecn=0,
        total_length=1000,
        identification=1,
        flags=0,
        fragment_offset=0,
        ttl=64,
        protocol=1,
        checksum=0,
        src_ip="10.0.0.5",
        dst_ip="10.0.0.1",
    )

    # Normal 32-byte ping
    normal_icmp = DissectedPacket(
        frame_number=1,
        timestamp=1700000000.0,
        link_type=1,
        ipv4=ip_hdr,
        icmp=ICMPPacket(type=8, code=0, checksum=0, payload_bytes=b"\x00" * 32),
    )
    assert len(detector.process_packet(normal_icmp)) == 0

    # Jumbo 512-byte ping
    jumbo_icmp = DissectedPacket(
        frame_number=2,
        timestamp=1700000001.0,
        link_type=1,
        ipv4=ip_hdr,
        icmp=ICMPPacket(type=8, code=0, checksum=0, payload_bytes=b"\x00" * 512),
    )
    alerts = detector.process_packet(jumbo_icmp)
    assert len(alerts) == 1
    assert alerts[0].category == ThreatCategory.ICMP_ANOMALY


def test_threat_detection_engine_coordinator() -> None:
    """Verify central ThreatDetectionEngine lifecycle and aggregation."""
    settings = AnalyzerSettings(port_scan_threshold=5, dns_entropy_threshold=3.5)
    engine = ThreatDetectionEngine(settings=settings)

    # Send a jumbo ICMP packet
    ip_hdr = IPv4Packet(
        ihl=5,
        dscp=0,
        ecn=0,
        total_length=600,
        identification=1,
        flags=0,
        fragment_offset=0,
        ttl=64,
        protocol=1,
        checksum=0,
        src_ip="10.0.0.5",
        dst_ip="10.0.0.1",
    )
    pkt = DissectedPacket(
        frame_number=1,
        timestamp=1700000000.0,
        link_type=1,
        ipv4=ip_hdr,
        icmp=ICMPPacket(type=8, code=0, checksum=0, payload_bytes=b"\xaa" * 500),
    )
    new_alerts = engine.analyze_packet(pkt)
    assert len(new_alerts) == 1
    assert len(engine.get_all_alerts()) == 1

    engine.clear()
    assert len(engine.get_all_alerts()) == 0
