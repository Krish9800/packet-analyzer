"""Coordinator for packet dissection across network and transport layers."""

import contextlib

from pktanalyzer.dissectors.arp import dissect_arp
from pktanalyzer.dissectors.ethernet import dissect_ethernet
from pktanalyzer.dissectors.icmp import dissect_icmp
from pktanalyzer.dissectors.ipv4 import dissect_ipv4
from pktanalyzer.dissectors.ipv6 import dissect_ipv6
from pktanalyzer.dissectors.tcp import dissect_tcp
from pktanalyzer.dissectors.udp import dissect_udp
from pktanalyzer.models.enums import EtherType, IPProtocol, LinkType
from pktanalyzer.models.packet import DissectedPacket, RawPacket
from pktanalyzer.models.protocols import (
    ARPPacket,
    EthernetFrame,
    ICMPPacket,
    IPv4Packet,
    IPv6Packet,
    TCPSegment,
    UDPDatagram,
)


class PacketDissector:
    """Multi-layer protocol dissector coordinator."""

    def __init__(self, default_link_type: int = int(LinkType.ETHERNET)) -> None:
        self.default_link_type = default_link_type

    def dissect(self, raw: RawPacket, link_type: int | None = None) -> DissectedPacket:
        """Dissect raw packet through L2, L3, and L4 protocol layers."""
        dlt = link_type if link_type is not None else self.default_link_type
        data = raw.data

        eth: EthernetFrame | None = None
        arp: ARPPacket | None = None
        ip4: IPv4Packet | None = None
        ip6: IPv6Packet | None = None
        icmp: ICMPPacket | None = None
        tcp: TCPSegment | None = None
        udp: UDPDatagram | None = None

        l3_data = data
        ethertype: int | None = None

        # Layer 2 Processing
        if dlt == int(LinkType.ETHERNET):
            if len(data) >= 14:
                with contextlib.suppress(Exception):
                    eth, l3_data = dissect_ethernet(data)
                    ethertype = eth.ethertype
        elif dlt in (int(LinkType.RAW), int(LinkType.IPV4)):
            ethertype = int(EtherType.IPV4)
        elif dlt == int(LinkType.IPV6):
            ethertype = int(EtherType.IPV6)
        elif dlt in (int(LinkType.NULL), int(LinkType.LOOPBACK)) and len(data) >= 4:
            # 4-byte family header
            l3_data = data[4:]
            if len(l3_data) > 0 and (l3_data[0] >> 4) == 4:
                ethertype = int(EtherType.IPV4)
            else:
                ethertype = int(EtherType.IPV6)

        # Layer 2.5 ARP
        if ethertype == int(EtherType.ARP) and l3_data:
            with contextlib.suppress(Exception):
                arp = dissect_arp(l3_data)

        # Layer 3 Processing
        l4_data = b""
        l4_proto: int | None = None

        is_ipv4 = ethertype == int(EtherType.IPV4) or (
            ethertype is None and len(l3_data) >= 20 and (l3_data[0] >> 4) == 4
        )
        is_ipv6 = ethertype == int(EtherType.IPV6) or (
            ethertype is None and len(l3_data) >= 40 and (l3_data[0] >> 4) == 6
        )

        if is_ipv4:
            with contextlib.suppress(Exception):
                ip4, l4_data = dissect_ipv4(l3_data)
                l4_proto = ip4.protocol
        elif is_ipv6:
            with contextlib.suppress(Exception):
                ip6, l4_data = dissect_ipv6(l3_data)
                l4_proto = ip6.next_header

        # Layer 4 Processing
        if l4_proto == int(IPProtocol.TCP) and l4_data:
            with contextlib.suppress(Exception):
                tcp, _ = dissect_tcp(l4_data)
        elif l4_proto == int(IPProtocol.UDP) and l4_data:
            with contextlib.suppress(Exception):
                udp, _ = dissect_udp(l4_data)
        elif l4_proto in (int(IPProtocol.ICMP), int(IPProtocol.ICMPV6)) and l4_data:
            with contextlib.suppress(Exception):
                icmp = dissect_icmp(l4_data)

        summary = self._generate_summary(raw, eth, arp, ip4, ip6, icmp, tcp, udp)

        return DissectedPacket(
            frame_number=raw.frame_number,
            timestamp=raw.timestamp,
            link_type=dlt,
            ethernet=eth,
            arp=arp,
            ipv4=ip4,
            ipv6=ip6,
            icmp=icmp,
            tcp=tcp,
            udp=udp,
            summary=summary,
        )

    def _generate_summary(
        self,
        raw: RawPacket,
        eth: EthernetFrame | None,
        arp: ARPPacket | None,
        ip4: IPv4Packet | None,
        ip6: IPv6Packet | None,
        icmp: ICMPPacket | None,
        tcp: TCPSegment | None,
        udp: UDPDatagram | None,
    ) -> str:
        """Create single-line human-readable packet summary."""
        if tcp and (ip4 or ip6):
            src = f"{ip4.src_ip if ip4 else ip6.src_ip}:{tcp.src_port}"  # type: ignore[union-attr]
            dst = f"{ip4.dst_ip if ip4 else ip6.dst_ip}:{tcp.dst_port}"  # type: ignore[union-attr]
            flags = ",".join(tcp.flag_names) if tcp.flag_names else "NONE"
            return (
                f"{src} -> {dst} [TCP] [{flags}] "
                f"Seq={tcp.seq_number} Ack={tcp.ack_number} Win={tcp.window_size}"
            )

        if udp and (ip4 or ip6):
            src = f"{ip4.src_ip if ip4 else ip6.src_ip}:{udp.src_port}"  # type: ignore[union-attr]
            dst = f"{ip4.dst_ip if ip4 else ip6.dst_ip}:{udp.dst_port}"  # type: ignore[union-attr]
            return f"{src} -> {dst} [UDP] Len={udp.length}"

        if icmp and ip4:
            return f"{ip4.src_ip} -> {ip4.dst_ip} [ICMP] Type={icmp.type} Code={icmp.code}"

        if arp:
            op = (
                "Request"
                if arp.opcode == 1
                else ("Reply" if arp.opcode == 2 else f"Op{arp.opcode}")
            )
            return f"ARP {op} Who has {arp.target_ip}? Tell {arp.sender_ip}"

        if ip4:
            return (
                f"{ip4.src_ip} -> {ip4.dst_ip} [IPv4] Proto={ip4.protocol} Len={ip4.total_length}"
            )

        if ip6:
            return f"[{ip6.src_ip}] -> [{ip6.dst_ip}] [IPv6] Next={ip6.next_header}"

        if eth:
            return f"{eth.src_mac} -> {eth.dst_mac} [Ethernet] Type=0x{eth.ethertype:04x}"

        return f"Frame #{raw.frame_number} ({raw.caplen} bytes)"
