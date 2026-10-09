"""Coordinator for packet dissection across network, transport, and application layers."""

import contextlib

from pktanalyzer.dissectors.arp import dissect_arp
from pktanalyzer.dissectors.dns import dissect_dns
from pktanalyzer.dissectors.ethernet import dissect_ethernet
from pktanalyzer.dissectors.http import HTTP_METHODS, dissect_http
from pktanalyzer.dissectors.icmp import dissect_icmp
from pktanalyzer.dissectors.ipv4 import dissect_ipv4
from pktanalyzer.dissectors.ipv6 import dissect_ipv6
from pktanalyzer.dissectors.tcp import dissect_tcp
from pktanalyzer.dissectors.tls import dissect_tls
from pktanalyzer.dissectors.udp import dissect_udp
from pktanalyzer.models.enums import EtherType, IPProtocol, LinkType
from pktanalyzer.models.packet import DissectedPacket, RawPacket
from pktanalyzer.models.protocols import (
    ARPPacket,
    DNSMessage,
    EthernetFrame,
    HTTPMessage,
    ICMPPacket,
    IPv4Packet,
    IPv6Packet,
    TCPSegment,
    TLSMessage,
    UDPDatagram,
)


class PacketDissector:
    """Multi-layer protocol dissector coordinator."""

    def __init__(self, default_link_type: int = int(LinkType.ETHERNET)) -> None:
        self.default_link_type = default_link_type

    def dissect(self, raw: RawPacket, link_type: int | None = None) -> DissectedPacket:
        """Dissect raw packet through L2, L3, L4, and L7 protocol layers."""
        dlt = link_type if link_type is not None else self.default_link_type
        data = raw.data

        eth: EthernetFrame | None = None
        arp: ARPPacket | None = None
        ip4: IPv4Packet | None = None
        ip6: IPv6Packet | None = None
        icmp: ICMPPacket | None = None
        tcp: TCPSegment | None = None
        udp: UDPDatagram | None = None
        dns: DNSMessage | None = None
        http: HTTPMessage | None = None
        tls: TLSMessage | None = None

        l3_data = data
        ethertype: int | None = None

        # Layer 2 Processing
        if dlt == int(LinkType.ETHERNET) and len(data) >= 14:
            with contextlib.suppress(Exception):
                eth, l3_data = dissect_ethernet(data)
                ethertype = eth.ethertype
        elif dlt in (int(LinkType.RAW), int(LinkType.IPV4)):
            ethertype = int(EtherType.IPV4)
        elif dlt == int(LinkType.IPV6):
            ethertype = int(EtherType.IPV6)
        elif dlt in (int(LinkType.NULL), int(LinkType.LOOPBACK)) and len(data) >= 4:
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

        # Layer 4 & Layer 7 Processing
        app_payload = b""
        if l4_proto == int(IPProtocol.TCP) and l4_data:
            with contextlib.suppress(Exception):
                tcp, app_payload = dissect_tcp(l4_data)
        elif l4_proto == int(IPProtocol.UDP) and l4_data:
            with contextlib.suppress(Exception):
                udp, app_payload = dissect_udp(l4_data)
        elif l4_proto in (int(IPProtocol.ICMP), int(IPProtocol.ICMPV6)) and l4_data:
            with contextlib.suppress(Exception):
                icmp = dissect_icmp(l4_data)

        if app_payload:
            # Check DNS
            is_dns_port = (udp and (udp.src_port in (53, 5353) or udp.dst_port in (53, 5353))) or (
                tcp and (tcp.src_port == 53 or tcp.dst_port == 53)
            )
            if is_dns_port and len(app_payload) >= 12:
                with contextlib.suppress(Exception):
                    dns_bytes = app_payload[2:] if (tcp and len(app_payload) > 2) else app_payload
                    dns = dissect_dns(dns_bytes)

            # Check HTTP
            first_word = app_payload.split(b" ")[0].decode("ascii", errors="ignore")
            is_http = (
                first_word in HTTP_METHODS
                or app_payload.startswith(b"HTTP/1.")
                or (tcp and (tcp.src_port in (80, 8080) or tcp.dst_port in (80, 8080)))
            )
            if is_http and not dns:
                with contextlib.suppress(Exception):
                    http = dissect_http(app_payload)

            # Check TLS
            is_tls = (
                len(app_payload) >= 5
                and app_payload[0] in (20, 21, 22, 23, 24)
                and app_payload[1] == 3
            )
            if is_tls and not http and not dns:
                with contextlib.suppress(Exception):
                    tls = dissect_tls(app_payload)

        summary = self._generate_summary(raw, eth, arp, ip4, ip6, icmp, tcp, udp, dns, http, tls)

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
            dns=dns,
            http=http,
            tls=tls,
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
        dns: DNSMessage | None,
        http: HTTPMessage | None,
        tls: TLSMessage | None,
    ) -> str:
        """Create single-line human-readable packet summary."""
        src_ip = ip4.src_ip if ip4 else (ip6.src_ip if ip6 else "")
        dst_ip = ip4.dst_ip if ip4 else (ip6.dst_ip if ip6 else "")

        if http:
            if http.is_request:
                return f"{src_ip} -> {dst_ip} [HTTP] {http.method} {http.uri} {http.version}"
            return (
                f"{src_ip} -> {dst_ip} [HTTP] "
                f"{http.version} {http.status_code} {http.reason_phrase}"
            )

        if dns:
            if dns.questions:
                qname = dns.questions[0].name
                kind = "Response" if dns.is_response else "Query"
                return f"{src_ip} -> {dst_ip} [DNS] {kind}: {qname}"
            return f"{src_ip} -> {dst_ip} [DNS] ID=0x{dns.transaction_id:04x}"

        if tls:
            if tls.sni_hostname:
                return f"{src_ip} -> {dst_ip} [TLS] ClientHello SNI={tls.sni_hostname}"
            rec_type = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "AppData"}.get(
                tls.content_type, f"Type={tls.content_type}"
            )
            return f"{src_ip} -> {dst_ip} [TLS] {rec_type}"

        if tcp and (ip4 or ip6):
            src = f"{src_ip}:{tcp.src_port}"
            dst = f"{dst_ip}:{tcp.dst_port}"
            flags = ",".join(tcp.flag_names) if tcp.flag_names else "NONE"
            return (
                f"{src} -> {dst} [TCP] [{flags}] "
                f"Seq={tcp.seq_number} Ack={tcp.ack_number} Win={tcp.window_size}"
            )

        if udp and (ip4 or ip6):
            src = f"{src_ip}:{udp.src_port}"
            dst = f"{dst_ip}:{udp.dst_port}"
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
