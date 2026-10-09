"""Unit tests for conversation flow tracking and TCP stream reassembly."""

from pktanalyzer.core.flow import (
    FlowKey,
    FlowTracker,
    HalfStream,
)
from pktanalyzer.models.enums import TCPFlag
from pktanalyzer.models.packet import DissectedPacket
from pktanalyzer.models.protocols import IPv4Packet, TCPSegment, UDPDatagram


def test_flow_key_symmetry() -> None:
    """Verify FlowKey produces identical keys regardless of direction."""
    k1 = FlowKey.from_endpoints("192.168.1.100", 50000, "10.0.0.1", 80, 6)
    k2 = FlowKey.from_endpoints("10.0.0.1", 80, "192.168.1.100", 50000, 6)
    assert k1 == k2


def test_half_stream_in_order() -> None:
    """Verify strictly in-order sequence reassembly."""
    hs = HalfStream()
    hs.add_segment(1000, b"Hello ")
    hs.add_segment(1006, b"World!")
    assert hs.buffer == b"Hello World!"
    assert hs.total_payload_bytes == 12


def test_half_stream_out_of_order() -> None:
    """Verify out-of-order segment reordering."""
    hs = HalfStream()
    # Segment 1 arrives
    hs.add_segment(1000, b"AAA")
    # Segment 3 arrives before segment 2
    hs.add_segment(1006, b"CCC")
    assert hs.buffer == b"AAA"
    assert 1006 in hs.out_of_order

    # Segment 2 arrives, unblocking segment 3
    hs.add_segment(1003, b"BBB")
    assert hs.buffer == b"AAABBBCCC"
    assert len(hs.out_of_order) == 0


def test_half_stream_overlap_and_retransmission() -> None:
    """Verify handling of overlapping sequences and duplicate retransmissions."""
    hs = HalfStream()
    hs.add_segment(100, b"0123456789")
    # Duplicate retransmission
    hs.add_segment(100, b"0123456789")
    assert hs.buffer == b"0123456789"

    # Overlapping segment starting at 105 through 115
    hs.add_segment(105, b"56789ABCDE")
    assert hs.buffer == b"0123456789ABCDE"


def test_flow_tracker_tcp_lifecycle_and_reassembly() -> None:
    """Verify FlowTracker tracking full TCP lifecycle and bidirectional streams."""
    tracker = FlowTracker()

    ip_c2s = IPv4Packet(
        ihl=5,
        dscp=0,
        ecn=0,
        total_length=60,
        identification=1,
        flags=0,
        fragment_offset=0,
        ttl=64,
        protocol=6,
        checksum=0,
        src_ip="192.168.1.50",
        dst_ip="93.184.216.34",
    )
    ip_s2c = IPv4Packet(
        ihl=5,
        dscp=0,
        ecn=0,
        total_length=60,
        identification=2,
        flags=0,
        fragment_offset=0,
        ttl=56,
        protocol=6,
        checksum=0,
        src_ip="93.184.216.34",
        dst_ip="192.168.1.50",
    )

    # Packet 1: SYN from client
    pkt_syn = DissectedPacket(
        frame_number=1,
        timestamp=1700000000.0,
        link_type=1,
        ipv4=ip_c2s,
        tcp=TCPSegment(
            src_port=54321,
            dst_port=80,
            seq_number=1000,
            ack_number=0,
            data_offset=5,
            flags=int(TCPFlag.SYN),
            window_size=65535,
            checksum=0,
            urgent_pointer=0,
        ),
    )
    sess1 = tracker.process_packet(pkt_syn)
    assert sess1 is not None
    assert sess1.tcp_state == "SYN_SENT"
    assert sess1.packet_count == 1

    # Packet 2: SYN-ACK from server
    pkt_synack = DissectedPacket(
        frame_number=2,
        timestamp=1700000000.05,
        link_type=1,
        ipv4=ip_s2c,
        tcp=TCPSegment(
            src_port=80,
            dst_port=54321,
            seq_number=5000,
            ack_number=1001,
            data_offset=5,
            flags=int(TCPFlag.SYN) | int(TCPFlag.ACK),
            window_size=65535,
            checksum=0,
            urgent_pointer=0,
        ),
    )
    sess2 = tracker.process_packet(pkt_synack)
    assert sess2 is not None
    assert sess2.tcp_state == "SYN_RECEIVED"

    # Packet 3: HTTP Request from client
    http_req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkt_data_c = DissectedPacket(
        frame_number=3,
        timestamp=1700000000.1,
        link_type=1,
        ipv4=ip_c2s,
        tcp=TCPSegment(
            src_port=54321,
            dst_port=80,
            seq_number=1001,
            ack_number=5001,
            data_offset=5,
            flags=int(TCPFlag.ACK) | int(TCPFlag.PSH),
            window_size=65535,
            checksum=0,
            urgent_pointer=0,
            payload_bytes=http_req,
        ),
    )
    tracker.process_packet(pkt_data_c)

    # Packet 4: HTTP Response from server
    http_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
    pkt_data_s = DissectedPacket(
        frame_number=4,
        timestamp=1700000000.2,
        link_type=1,
        ipv4=ip_s2c,
        tcp=TCPSegment(
            src_port=80,
            dst_port=54321,
            seq_number=5001,
            ack_number=1001 + len(http_req),
            data_offset=5,
            flags=int(TCPFlag.ACK) | int(TCPFlag.PSH),
            window_size=65535,
            checksum=0,
            urgent_pointer=0,
            payload_bytes=http_resp,
        ),
    )
    tracker.process_packet(pkt_data_s)

    # Packet 5: FIN from client
    pkt_fin = DissectedPacket(
        frame_number=5,
        timestamp=1700000000.3,
        link_type=1,
        ipv4=ip_c2s,
        tcp=TCPSegment(
            src_port=54321,
            dst_port=80,
            seq_number=1001 + len(http_req),
            ack_number=5001 + len(http_resp),
            data_offset=5,
            flags=int(TCPFlag.FIN) | int(TCPFlag.ACK),
            window_size=65535,
            checksum=0,
            urgent_pointer=0,
        ),
    )
    final_sess = tracker.process_packet(pkt_fin)
    assert final_sess is not None
    assert final_sess.tcp_state == "CLOSED"
    assert final_sess.reassembled_client_data == http_req
    assert final_sess.reassembled_server_data == http_resp
    assert final_sess.duration > 0.25
    assert len(tracker.get_all_sessions()) == 1


def test_flow_tracker_udp_and_non_ip() -> None:
    """Verify UDP flows and skipping non-IP frames."""
    tracker = FlowTracker()

    # Packet without IP
    non_ip = DissectedPacket(frame_number=1, timestamp=1700000000.0, link_type=1)
    assert tracker.process_packet(non_ip) is None

    # UDP Packet
    ip_udp = IPv4Packet(
        ihl=5,
        dscp=0,
        ecn=0,
        total_length=40,
        identification=1,
        flags=0,
        fragment_offset=0,
        ttl=64,
        protocol=17,
        checksum=0,
        src_ip="10.0.0.5",
        dst_ip="10.0.0.1",
    )
    pkt_udp = DissectedPacket(
        frame_number=2,
        timestamp=1700000001.0,
        link_type=1,
        ipv4=ip_udp,
        udp=UDPDatagram(src_port=53535, dst_port=53, length=20, checksum=0),
    )
    sess = tracker.process_packet(pkt_udp)
    assert sess is not None
    assert sess.protocol_name == "UDP"
    assert sess.packet_count == 1
