"""Unit tests for Layer 2, Layer 3, and Layer 4 protocol dissectors."""

import socket
import struct

import pytest

from pktanalyzer.dissectors import (
    PacketDissector,
    dissect_arp,
    dissect_ethernet,
    dissect_icmp,
    dissect_ipv4,
    dissect_ipv6,
    dissect_tcp,
    dissect_udp,
    mac_to_str,
    parse_tcp_flags,
)
from pktanalyzer.models.enums import EtherType, ICMPType, IPProtocol, LinkType, TCPFlag
from pktanalyzer.models.packet import RawPacket


def test_mac_to_str() -> None:
    """Verify MAC address formatting."""
    mac_bytes = b"\x00\x0c\x29\x3e\x5b\x8a"
    assert mac_to_str(mac_bytes) == "00:0c:29:3e:5b:8a"


def test_dissect_ethernet_standard() -> None:
    """Verify standard Ethernet II frame dissection."""
    dst_mac = b"\xff\xff\xff\xff\xff\xff"
    src_mac = b"\x00\x11\x22\x33\x44\x55"
    ethertype = 0x0800
    payload = b"IP_PAYLOAD_HERE"
    raw = dst_mac + src_mac + struct.pack("!H", ethertype) + payload

    frame, remaining = dissect_ethernet(raw)
    assert frame.dst_mac == "ff:ff:ff:ff:ff:ff"
    assert frame.src_mac == "00:11:22:33:44:55"
    assert frame.ethertype == 0x0800
    assert remaining == payload


def test_dissect_ethernet_vlan_tagged() -> None:
    """Verify 802.1Q VLAN tagged frame dissection."""
    dst_mac = b"\x00\x01\x02\x03\x04\x05"
    src_mac = b"\x10\x11\x12\x13\x14\x15"
    vlan_ethertype = 0x8100
    tci = 0x0064  # VLAN ID 100
    inner_ethertype = 0x0800
    payload = b"VLAN_PAYLOAD"
    raw = (
        dst_mac
        + src_mac
        + struct.pack("!H", vlan_ethertype)
        + struct.pack("!HH", tci, inner_ethertype)
        + payload
    )

    frame, remaining = dissect_ethernet(raw)
    assert frame.ethertype == 0x0800
    assert remaining == payload


def test_dissect_ethernet_too_short() -> None:
    """Verify exception on truncated Ethernet frame."""
    with pytest.raises(ValueError, match="too short"):
        dissect_ethernet(b"\x00" * 10)


def test_dissect_arp_request_and_reply() -> None:
    """Verify ARP request and reply packet parsing."""
    sender_mac = b"\x00\xaa\xbb\xcc\xdd\xee"
    target_mac = b"\x00\x00\x00\x00\x00\x00"
    sender_ip = socket.inet_aton("192.168.1.100")
    target_ip = socket.inet_aton("192.168.1.1")

    # ARP Request
    hdr = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
    raw = hdr + sender_mac + sender_ip + target_mac + target_ip

    arp = dissect_arp(raw)
    assert arp.hw_type == 1
    assert arp.proto_type == 0x0800
    assert arp.opcode == 1
    assert arp.sender_mac == "00:aa:bb:cc:dd:ee"
    assert arp.sender_ip == "192.168.1.100"
    assert arp.target_ip == "192.168.1.1"

    # Truncated ARP
    with pytest.raises(ValueError, match="too short"):
        dissect_arp(b"\x00" * 20)


def test_dissect_ipv4_standard_and_options() -> None:
    """Verify IPv4 header and option fields."""
    src = socket.inet_aton("10.0.0.1")
    dst = socket.inet_aton("10.0.0.2")

    # 20 bytes standard header
    first_byte = (4 << 4) | 5  # Version 4, IHL 5
    tos = 0
    total_len = 40
    ident = 0x1234
    flags_frag = 0x4000  # DF bit set
    ttl = 64
    proto = 6  # TCP
    checksum = 0

    hdr20 = struct.pack(
        "!BBHHHBBH", first_byte, tos, total_len, ident, flags_frag, ttl, proto, checksum
    )
    raw_ip = hdr20 + src + dst + (b"\x00" * 20)  # 20 bytes payload

    ip, payload = dissect_ipv4(raw_ip)
    assert ip.version == 4
    assert ip.ihl == 5
    assert ip.src_ip == "10.0.0.1"
    assert ip.dst_ip == "10.0.0.2"
    assert ip.protocol == 6
    assert len(payload) == 20

    # Header with options (IHL 6 = 24 bytes)
    hdr24_byte = (4 << 4) | 6
    hdr24 = struct.pack("!BBHHHBBH", hdr24_byte, tos, 44, ident, flags_frag, ttl, proto, checksum)
    raw_opt = hdr24 + src + dst + b"\x01\x01\x01\x01" + (b"\xaa" * 20)
    ip_opt, payload_opt = dissect_ipv4(raw_opt)
    assert ip_opt.ihl == 6
    assert ip_opt.options == b"\x01\x01\x01\x01"
    assert len(payload_opt) == 20


def test_dissect_ipv4_errors() -> None:
    """Verify error conditions on invalid IPv4 frames."""
    with pytest.raises(ValueError, match="too short"):
        dissect_ipv4(b"\x00" * 15)

    # IHL < 5
    bad_ihl = bytes([(4 << 4) | 4]) + (b"\x00" * 19)
    with pytest.raises(ValueError, match="Invalid IPv4 IHL"):
        dissect_ipv4(bad_ihl)


def test_dissect_ipv6() -> None:
    """Verify IPv6 packet dissection."""
    first_word = (6 << 28) | (0 << 20) | 0
    payload_len = 16
    next_header = 17  # UDP
    hop_limit = 64
    src_raw = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    dst_raw = socket.inet_pton(socket.AF_INET6, "2001:db8::2")

    hdr = struct.pack("!IHBB", first_word, payload_len, next_header, hop_limit)
    payload = b"UDP_TEST_PAYLOAD"
    raw = hdr + src_raw + dst_raw + payload

    ip6, remaining = dissect_ipv6(raw)
    assert ip6.version == 6
    assert ip6.src_ip == "2001:db8::1"
    assert ip6.dst_ip == "2001:db8::2"
    assert ip6.next_header == 17
    assert remaining == payload

    with pytest.raises(ValueError, match="too short"):
        dissect_ipv6(b"\x00" * 30)


def test_dissect_icmp() -> None:
    """Verify ICMP Echo Request and payload dissection."""
    ident = 0x55AA
    seq = 1
    raw = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + b"PINGPAYLOAD"

    icmp = dissect_icmp(raw)
    assert icmp.type == int(ICMPType.ECHO_REQUEST)
    assert icmp.code == 0
    assert icmp.identifier == 0x55AA
    assert icmp.sequence == 1
    assert icmp.payload_bytes == b"PINGPAYLOAD"

    with pytest.raises(ValueError, match="too short"):
        dissect_icmp(b"\x00" * 4)


def test_dissect_tcp() -> None:
    """Verify TCP segment parsing and flag decoding."""
    flags_byte = int(TCPFlag.SYN) | int(TCPFlag.ACK)
    flags_list = parse_tcp_flags(flags_byte)
    assert "SYN" in flags_list
    assert "ACK" in flags_list

    # Data offset 5 = 20 bytes
    offset_flags = (5 << 12) | flags_byte
    hdr = struct.pack("!HHIIHHHH", 44332, 443, 1000, 2000, offset_flags, 65535, 0, 0)
    raw = hdr + b"TLS_CLIENT_HELLO"

    seg, payload = dissect_tcp(raw)
    assert seg.src_port == 44332
    assert seg.dst_port == 443
    assert seg.seq_number == 1000
    assert seg.ack_number == 2000
    assert "SYN" in seg.flag_names
    assert "ACK" in seg.flag_names
    assert payload == b"TLS_CLIENT_HELLO"

    with pytest.raises(ValueError, match="too short"):
        dissect_tcp(b"\x00" * 16)


def test_dissect_udp() -> None:
    """Verify UDP datagram parsing."""
    raw = struct.pack("!HHHH", 5353, 53, 15, 0) + b"DNS_PKT"

    udp, payload = dissect_udp(raw)
    assert udp.src_port == 5353
    assert udp.dst_port == 53
    assert udp.length == 15
    assert payload == b"DNS_PKT"

    with pytest.raises(ValueError, match="too short"):
        dissect_udp(b"\x00" * 4)


def test_packet_dissector_end_to_end() -> None:
    """Verify coordinator on synthesized full frames."""
    coord = PacketDissector()

    dst_mac = b"\x00\x11\x22\x33\x44\x55"
    src_mac = b"\x66\x77\x88\x99\xaa\xbb"
    eth_hdr = dst_mac + src_mac + struct.pack("!H", int(EtherType.IPV4))

    src_ip = socket.inet_aton("192.168.1.10")
    dst_ip = socket.inet_aton("192.168.1.1")
    ip_hdr = (
        struct.pack("!BBHHHBBH", (4 << 4) | 5, 0, 40, 1, 0, 64, int(IPProtocol.TCP), 0)
        + src_ip
        + dst_ip
    )

    offset_flags = (5 << 12) | int(TCPFlag.SYN)
    tcp_hdr = struct.pack("!HHIIHHHH", 49152, 80, 100, 0, offset_flags, 1024, 0, 0)

    full_pkt = eth_hdr + ip_hdr + tcp_hdr

    raw = RawPacket(
        frame_number=1,
        timestamp=1700000000.0,
        caplen=len(full_pkt),
        wirelen=len(full_pkt),
        data=full_pkt,
    )

    dissected = coord.dissect(raw)
    assert dissected.ethernet is not None
    assert dissected.ipv4 is not None
    assert dissected.tcp is not None
    assert dissected.tcp.src_port == 49152
    assert dissected.tcp.dst_port == 80
    assert "SYN" in dissected.tcp.flag_names
    assert "192.168.1.10:49152 -> 192.168.1.1:80 [TCP] [SYN]" in dissected.summary

    # Synthetic Ethernet + ARP
    arp_payload = (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
        + b"\xaa\xbb\xcc\xdd\xee\xff"
        + socket.inet_aton("10.0.0.5")
        + b"\x00\x00\x00\x00\x00\x00"
        + socket.inet_aton("10.0.0.1")
    )
    eth_arp = dst_mac + src_mac + struct.pack("!H", int(EtherType.ARP)) + arp_payload
    raw_arp = RawPacket(
        frame_number=2,
        timestamp=1700000001.0,
        caplen=len(eth_arp),
        wirelen=len(eth_arp),
        data=eth_arp,
    )
    dissected_arp = coord.dissect(raw_arp)
    assert dissected_arp.arp is not None
    assert "ARP Request" in dissected_arp.summary

    # Raw link type
    raw_ip_pkt = RawPacket(
        frame_number=3,
        timestamp=1700000002.0,
        caplen=len(ip_hdr + tcp_hdr),
        wirelen=len(ip_hdr + tcp_hdr),
        data=ip_hdr + tcp_hdr,
    )
    dissected_raw = coord.dissect(raw_ip_pkt, link_type=int(LinkType.RAW))
    assert dissected_raw.ipv4 is not None
    assert dissected_raw.tcp is not None

    # Synthetic IPv4 + UDP
    udp_hdr = struct.pack("!HHHH", 1024, 53, 8 + 4, 0) + b"test"
    ip_udp_hdr = (
        struct.pack(
            "!BBHHHBBH", (4 << 4) | 5, 0, 20 + len(udp_hdr), 2, 0, 64, int(IPProtocol.UDP), 0
        )
        + src_ip
        + dst_ip
    )
    full_udp = eth_hdr + ip_udp_hdr + udp_hdr
    pkt_udp = RawPacket(
        frame_number=4,
        timestamp=1700000003.0,
        caplen=len(full_udp),
        wirelen=len(full_udp),
        data=full_udp,
    )
    dissected_udp = coord.dissect(pkt_udp)
    assert dissected_udp.udp is not None
    assert "[UDP]" in dissected_udp.summary

    # Synthetic IPv4 + ICMP
    icmp_hdr = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"ping"
    ip_icmp_hdr = (
        struct.pack(
            "!BBHHHBBH", (4 << 4) | 5, 0, 20 + len(icmp_hdr), 3, 0, 64, int(IPProtocol.ICMP), 0
        )
        + src_ip
        + dst_ip
    )
    full_icmp = eth_hdr + ip_icmp_hdr + icmp_hdr
    pkt_icmp = RawPacket(
        frame_number=5,
        timestamp=1700000004.0,
        caplen=len(full_icmp),
        wirelen=len(full_icmp),
        data=full_icmp,
    )
    dissected_icmp = coord.dissect(pkt_icmp)
    assert dissected_icmp.icmp is not None
    assert "[ICMP]" in dissected_icmp.summary

    # Synthetic IPv6 + TCP
    src_v6 = socket.inet_pton(socket.AF_INET6, "2001:db8::10")
    dst_v6 = socket.inet_pton(socket.AF_INET6, "2001:db8::20")
    v6_word = 6 << 28
    ip6_hdr = struct.pack("!IHBB", v6_word, 20, int(IPProtocol.TCP), 64) + src_v6 + dst_v6
    eth_v6 = dst_mac + src_mac + struct.pack("!H", int(EtherType.IPV6)) + ip6_hdr + tcp_hdr
    pkt_v6 = RawPacket(
        frame_number=6,
        timestamp=1700000005.0,
        caplen=len(eth_v6),
        wirelen=len(eth_v6),
        data=eth_v6,
    )
    dissected_v6 = coord.dissect(pkt_v6)
    assert dissected_v6.ipv6 is not None
    assert dissected_v6.tcp is not None

    # Synthetic ARP Reply
    arp_reply_payload = (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
        + b"\xaa\xbb\xcc\xdd\xee\xff"
        + socket.inet_aton("10.0.0.1")
        + b"\x11\x22\x33\x44\x55\x66"
        + socket.inet_aton("10.0.0.5")
    )
    eth_arp_rep = dst_mac + src_mac + struct.pack("!H", int(EtherType.ARP)) + arp_reply_payload
    dissected_rep = coord.dissect(
        RawPacket(
            frame_number=7,
            timestamp=1700000006.0,
            caplen=len(eth_arp_rep),
            wirelen=len(eth_arp_rep),
            data=eth_arp_rep,
        )
    )
    assert "ARP Reply" in dissected_rep.summary

    # Loopback / NULL DLT with IPv4
    null_pkt = struct.pack("!I", 2) + ip_hdr + tcp_hdr
    dissected_null = coord.dissect(
        RawPacket(
            frame_number=8,
            timestamp=1700000007.0,
            caplen=len(null_pkt),
            wirelen=len(null_pkt),
            data=null_pkt,
        ),
        link_type=int(LinkType.NULL),
    )
    assert dissected_null.ipv4 is not None

    # Summary fallbacks
    eth_only = RawPacket(
        frame_number=9,
        timestamp=1700000008.0,
        caplen=14,
        wirelen=14,
        data=dst_mac + src_mac + struct.pack("!H", 0x9999),
    )
    assert "Ethernet" in coord.dissect(eth_only).summary

    raw_frame = RawPacket(
        frame_number=10,
        timestamp=1700000009.0,
        caplen=10,
        wirelen=10,
        data=b"\x00" * 10,
    )
    assert "Frame #10" in coord.dissect(raw_frame, link_type=999).summary


def test_dissector_edge_cases() -> None:
    """Verify parser edge cases and error branches."""
    # Truncated VLAN tag
    truncated_vlan = b"\x00" * 12 + struct.pack("!H", 0x8100) + b"\x00\x00"
    with pytest.raises(ValueError, match="too short for 802.1Q"):
        dissect_ethernet(truncated_vlan)

    # IPv4 data smaller than declared header length
    short_ip = bytes([(4 << 4) | 8]) + b"\x00" * 20
    with pytest.raises(ValueError, match="smaller than declared header length"):
        dissect_ipv4(short_ip)

    # TCP invalid data offset < 5
    bad_offset = struct.pack("!HHIIHHHH", 80, 80, 0, 0, (3 << 12), 1024, 0, 0)
    with pytest.raises(ValueError, match="Invalid TCP data offset"):
        dissect_tcp(bad_offset)

    # TCP segment truncated compared to data offset
    short_tcp = struct.pack("!HHIIHHHH", 80, 80, 0, 0, (6 << 12), 1024, 0, 0)
    with pytest.raises(ValueError, match="TCP segment truncated"):
        dissect_tcp(short_tcp)

    # UDP length < 8
    bad_udp = struct.pack("!HHHH", 80, 80, 5, 0)
    with pytest.raises(ValueError, match="Invalid UDP datagram length"):
        dissect_udp(bad_udp)
