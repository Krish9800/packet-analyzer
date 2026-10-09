"""Unit tests for domain models, protocol schemas, and taxonomy."""

from pktanalyzer.models import (
    ARPPacket,
    DissectedPacket,
    DNSMessage,
    DNSQuestion,
    DNSResourceRecord,
    EthernetFrame,
    EtherType,
    HTTPMessage,
    ICMPPacket,
    ICMPType,
    IPProtocol,
    IPv4Packet,
    IPv6Packet,
    LinkType,
    RawPacket,
    SecurityAlert,
    TCPFlag,
    TCPSegment,
    ThreatCategory,
    ThreatSeverity,
    TLSMessage,
    UDPDatagram,
)


def test_enums() -> None:
    """Verify enumeration values and memberships."""
    assert int(LinkType.ETHERNET) == 1
    assert int(EtherType.IPV4) == 0x0800
    assert int(EtherType.ARP) == 0x0806
    assert int(IPProtocol.TCP) == 6
    assert int(IPProtocol.UDP) == 17
    assert int(IPProtocol.ICMP) == 1
    assert int(TCPFlag.SYN) == 0x02
    assert int(TCPFlag.ACK) == 0x10
    assert int(ICMPType.ECHO_REQUEST) == 8
    assert ThreatSeverity.CRITICAL == "CRITICAL"
    assert ThreatCategory.PORT_SCAN == "PORT_SCAN"


def test_ethernet_and_arp_models() -> None:
    """Verify Ethernet frame and ARP models."""
    eth = EthernetFrame(
        src_mac="00:11:22:33:44:55",
        dst_mac="ff:ff:ff:ff:ff:ff",
        ethertype=int(EtherType.ARP),
        payload_bytes=b"\x00" * 28,
    )
    assert eth.src_mac == "00:11:22:33:44:55"
    assert eth.ethertype == 0x0806

    arp = ARPPacket(
        hw_type=1,
        proto_type=0x0800,
        hw_size=6,
        proto_size=4,
        opcode=1,
        sender_mac="00:11:22:33:44:55",
        sender_ip="192.168.1.50",
        target_mac="00:00:00:00:00:00",
        target_ip="192.168.1.1",
    )
    assert arp.sender_ip == "192.168.1.50"
    assert arp.target_ip == "192.168.1.1"


def test_ipv4_and_tcp_models() -> None:
    """Verify IPv4 and TCP models."""
    ip = IPv4Packet(
        ihl=5,
        dscp=0,
        ecn=0,
        total_length=60,
        identification=1234,
        flags=2,
        fragment_offset=0,
        ttl=64,
        protocol=int(IPProtocol.TCP),
        checksum=0x1234,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
    )
    assert ip.version == 4
    assert ip.src_ip == "10.0.0.1"

    tcp = TCPSegment(
        src_port=44332,
        dst_port=443,
        seq_number=1000,
        ack_number=0,
        data_offset=5,
        flags=int(TCPFlag.SYN),
        window_size=65535,
        checksum=0xABCD,
        urgent_pointer=0,
        flag_names=["SYN"],
    )
    assert tcp.src_port == 44332
    assert "SYN" in tcp.flag_names


def test_l7_application_models() -> None:
    """Verify DNS, HTTP, and TLS application models."""
    dns = DNSMessage(
        transaction_id=0x1234,
        flags=0x0100,
        is_response=False,
        opcode=0,
        rcode=0,
        questions=[DNSQuestion(name="example.com", qtype=1, qclass=1)],
        answers=[
            DNSResourceRecord(name="example.com", rtype=1, rclass=1, ttl=300, rdata="93.184.216.34")
        ],
    )
    assert len(dns.questions) == 1
    assert dns.questions[0].name == "example.com"
    assert dns.answers[0].rdata == "93.184.216.34"

    http = HTTPMessage(
        is_request=True,
        method="POST",
        uri="/login",
        version="HTTP/1.1",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body="user=admin&pass=secret",
    )
    assert http.method == "POST"
    assert http.body == "user=admin&pass=secret"

    tls = TLSMessage(
        content_type=22,
        version_major=3,
        version_minor=3,
        length=512,
        is_handshake=True,
        handshake_type=1,
        sni_hostname="secure.example.com",
    )
    assert tls.sni_hostname == "secure.example.com"


def test_raw_and_dissected_packet_properties() -> None:
    """Verify DissectedPacket properties for endpoints and protocol detection."""
    raw = RawPacket(
        frame_number=1,
        timestamp=1700000000.123,
        caplen=54,
        wirelen=54,
        data=b"\x00" * 54,
    )
    assert raw.frame_number == 1

    # Dissected with IPv4 + TCP + HTTP
    pkt1 = DissectedPacket(
        frame_number=1,
        timestamp=1700000000.123,
        link_type=int(LinkType.ETHERNET),
        ipv4=IPv4Packet(
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
            dst_ip="192.168.1.1",
        ),
        tcp=TCPSegment(
            src_port=50000,
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
    assert pkt1.src_endpoint == "192.168.1.10:50000"
    assert pkt1.dst_endpoint == "192.168.1.1:80"
    assert pkt1.protocol_name == "HTTP"

    # Dissected with IPv6 + UDP + DNS
    pkt2 = DissectedPacket(
        frame_number=2,
        timestamp=1700000000.456,
        link_type=int(LinkType.ETHERNET),
        ipv6=IPv6Packet(
            traffic_class=0,
            flow_label=0,
            payload_length=40,
            next_header=17,
            hop_limit=64,
            src_ip="2001:db8::1",
            dst_ip="2001:db8::2",
        ),
        udp=UDPDatagram(src_port=53535, dst_port=53, length=40, checksum=0),
        dns=DNSMessage(transaction_id=1, flags=0, is_response=False, opcode=0, rcode=0),
    )
    assert pkt2.src_endpoint == "[2001:db8::1]:53535"
    assert pkt2.dst_endpoint == "[2001:db8::2]:53"
    assert pkt2.protocol_name == "DNS"

    # Dissected with ARP
    pkt3 = DissectedPacket(
        frame_number=3,
        timestamp=1700000000.789,
        link_type=int(LinkType.ETHERNET),
        arp=ARPPacket(
            hw_type=1,
            proto_type=0x0800,
            hw_size=6,
            proto_size=4,
            opcode=1,
            sender_mac="00:11:22:33:44:55",
            sender_ip="10.0.0.5",
            target_mac="ff:ff:ff:ff:ff:ff",
            target_ip="10.0.0.1",
        ),
    )
    assert pkt3.src_endpoint == "10.0.0.5"
    assert pkt3.dst_endpoint == "10.0.0.1"
    assert pkt3.protocol_name == "ARP"

    # Dissected with Ethernet only
    pkt4 = DissectedPacket(
        frame_number=4,
        timestamp=1700000001.0,
        link_type=int(LinkType.ETHERNET),
        ethernet=EthernetFrame(
            src_mac="00:11:22:33:44:55",
            dst_mac="aa:bb:cc:dd:ee:ff",
            ethertype=0x88CC,
        ),
    )
    assert pkt4.src_endpoint == "00:11:22:33:44:55"
    assert pkt4.dst_endpoint == "aa:bb:cc:dd:ee:ff"
    assert pkt4.protocol_name == "Ethernet"

    # Dissected with empty
    pkt5 = DissectedPacket(frame_number=5, timestamp=1700000002.0, link_type=0)
    assert pkt5.src_endpoint == "Unknown"
    assert pkt5.dst_endpoint == "Unknown"
    assert pkt5.protocol_name == "Raw"

    # Branch coverage for other protocols
    pkt_tls = DissectedPacket(
        frame_number=6,
        timestamp=1700000003.0,
        link_type=1,
        tls=TLSMessage(content_type=22, version_major=3, version_minor=3, length=100),
    )
    assert pkt_tls.protocol_name == "TLS"

    pkt_tcp = DissectedPacket(
        frame_number=7,
        timestamp=1700000004.0,
        link_type=1,
        ipv4=IPv4Packet(
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
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
        ),
        tcp=TCPSegment(
            src_port=80,
            dst_port=50000,
            seq_number=1,
            ack_number=1,
            data_offset=5,
            flags=16,
            window_size=1024,
            checksum=0,
            urgent_pointer=0,
        ),
    )
    assert pkt_tcp.protocol_name == "TCP"

    pkt_udp = DissectedPacket(
        frame_number=8,
        timestamp=1700000005.0,
        link_type=1,
        udp=UDPDatagram(src_port=123, dst_port=123, length=48, checksum=0),
    )
    assert pkt_udp.protocol_name == "UDP"

    pkt_icmp = DissectedPacket(
        frame_number=9,
        timestamp=1700000006.0,
        link_type=1,
        icmp=ICMPPacket(type=8, code=0, checksum=0),
    )
    assert pkt_icmp.protocol_name == "ICMP"

    pkt_ip4_only = DissectedPacket(
        frame_number=10,
        timestamp=1700000007.0,
        link_type=1,
        ipv4=IPv4Packet(
            ihl=5,
            dscp=0,
            ecn=0,
            total_length=20,
            identification=1,
            flags=0,
            fragment_offset=0,
            ttl=64,
            protocol=2,
            checksum=0,
            src_ip="10.1.1.1",
            dst_ip="10.1.1.2",
        ),
    )
    assert pkt_ip4_only.src_endpoint == "10.1.1.1"
    assert pkt_ip4_only.dst_endpoint == "10.1.1.2"
    assert pkt_ip4_only.protocol_name == "IPv4"

    pkt_ip6_only = DissectedPacket(
        frame_number=11,
        timestamp=1700000008.0,
        link_type=1,
        ipv6=IPv6Packet(
            traffic_class=0,
            flow_label=0,
            payload_length=0,
            next_header=59,
            hop_limit=64,
            src_ip="2001:db8::3",
            dst_ip="2001:db8::4",
        ),
    )
    assert pkt_ip6_only.src_endpoint == "[2001:db8::3]"
    assert pkt_ip6_only.dst_endpoint == "[2001:db8::4]"
    assert pkt_ip6_only.protocol_name == "IPv6"


def test_security_alert_model() -> None:
    """Verify SecurityAlert schema."""
    alert = SecurityAlert(
        alert_id="ALT-1001",
        timestamp=1700000010.0,
        category=ThreatCategory.PORT_SCAN,
        severity=ThreatSeverity.HIGH,
        title="TCP SYN Port Scan Detected",
        description="Source IP 10.0.0.99 probed 25 distinct ports in 1.2s",
        src_ip="10.0.0.99",
        dst_ip="10.0.0.1",
        evidence={"ports_probed": [21, 22, 23, 25, 80, 443], "scan_type": "SYN"},
    )
    assert alert.alert_id == "ALT-1001"
    assert alert.category == ThreatCategory.PORT_SCAN
    assert alert.severity == ThreatSeverity.HIGH
    assert len(alert.evidence["ports_probed"]) == 6
