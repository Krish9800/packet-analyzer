"""Unit tests for traffic analytics and forensic reporting."""

from pktanalyzer.analytics import AnalyticsEngine
from pktanalyzer.models.packet import DissectedPacket
from pktanalyzer.models.protocols import (
    EthernetFrame,
    HTTPMessage,
    IPv4Packet,
    IPv6Packet,
    TCPSegment,
)


def test_empty_analytics_engine() -> None:
    """Verify empty analytics engine yields default metrics."""
    engine = AnalyticsEngine()
    summary = engine.get_summary()
    assert summary.total_packets == 0
    assert summary.total_bytes == 0
    assert summary.bytes_per_second == 0.0
    assert engine.get_protocol_hierarchy() == []
    assert engine.get_top_talkers() == []


def test_analytics_engine_with_traffic() -> None:
    """Verify metrics calculation across diverse traffic."""
    engine = AnalyticsEngine()

    ip1 = IPv4Packet(
        ihl=5,
        dscp=0,
        ecn=0,
        total_length=100,
        identification=1,
        flags=0,
        fragment_offset=0,
        ttl=64,
        protocol=6,
        checksum=0,
        src_ip="192.168.1.10",
        dst_ip="93.184.216.34",
    )
    ip2 = IPv4Packet(
        ihl=5,
        dscp=0,
        ecn=0,
        total_length=200,
        identification=2,
        flags=0,
        fragment_offset=0,
        ttl=56,
        protocol=6,
        checksum=0,
        src_ip="93.184.216.34",
        dst_ip="192.168.1.10",
    )

    # Packet 1: HTTP Request
    pkt1 = DissectedPacket(
        frame_number=1,
        timestamp=1700000000.0,
        link_type=1,
        ipv4=ip1,
        tcp=TCPSegment(
            src_port=54321,
            dst_port=80,
            seq_number=1,
            ack_number=1,
            data_offset=5,
            flags=24,
            window_size=1024,
            checksum=0,
            urgent_pointer=0,
        ),
        http=HTTPMessage(is_request=True, method="GET", uri="/"),
    )
    engine.process_packet(pkt1)

    # Packet 2: HTTP Response
    pkt2 = DissectedPacket(
        frame_number=2,
        timestamp=1700000002.0,
        link_type=1,
        ipv4=ip2,
        tcp=TCPSegment(
            src_port=80,
            dst_port=54321,
            seq_number=1,
            ack_number=1,
            data_offset=5,
            flags=24,
            window_size=1024,
            checksum=0,
            urgent_pointer=0,
        ),
        http=HTTPMessage(is_request=False, status_code=200),
    )
    engine.process_packet(pkt2)

    # Packet 3: IPv6 packet
    pkt3 = DissectedPacket(
        frame_number=3,
        timestamp=1700000004.0,
        link_type=1,
        ipv6=IPv6Packet(
            traffic_class=0,
            flow_label=0,
            payload_length=60,
            next_header=6,
            hop_limit=64,
            src_ip="2001:db8::1",
            dst_ip="2001:db8::2",
        ),
        tcp=TCPSegment(
            src_port=1000,
            dst_port=2000,
            seq_number=1,
            ack_number=1,
            data_offset=5,
            flags=2,
            window_size=1024,
            checksum=0,
            urgent_pointer=0,
        ),
    )
    engine.process_packet(pkt3)

    # Packet 4: Ethernet only
    pkt4 = DissectedPacket(
        frame_number=4,
        timestamp=1700000005.0,
        link_type=1,
        ethernet=EthernetFrame(
            src_mac="00:11:22:33:44:55",
            dst_mac="aa:bb:cc:dd:ee:ff",
            ethertype=0x88CC,
            payload_bytes=b"\x00" * 30,
        ),
    )
    engine.process_packet(pkt4)

    summary = engine.get_summary()
    assert summary.total_packets == 4
    # Bytes: 100 + 200 + (60 + 40) + (14 + 30) = 444
    assert summary.total_bytes == 444
    assert summary.duration_seconds == 5.0
    assert summary.bytes_per_second > 0

    proto_hierarchy = engine.get_protocol_hierarchy()
    assert len(proto_hierarchy) >= 2
    assert any(p.protocol == "HTTP" for p in proto_hierarchy)

    top_talkers = engine.get_top_talkers(limit=5)
    assert len(top_talkers) >= 2
    top_ips = {top_talkers[0].ip, top_talkers[1].ip}
    assert "93.184.216.34" in top_ips
    assert "192.168.1.10" in top_ips
    assert top_talkers[0].total_bytes == 300

    report = engine.generate_report(active_flows=2, alerts_count=1)
    assert report.active_conversations_count == 2
    assert report.security_alerts_count == 1
    assert len(report.protocols) > 0
