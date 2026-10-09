"""Packet representations for raw binary frames and dissecting layers."""

from pydantic import BaseModel, ConfigDict, Field

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


class RawPacket(BaseModel):
    """Raw frame ingested from PCAP or network interface."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    frame_number: int
    timestamp: float
    caplen: int
    wirelen: int
    data: bytes = Field(repr=False)


class DissectedPacket(BaseModel):
    """Structured network packet decoded across protocol layers."""

    frame_number: int
    timestamp: float
    link_type: int
    ethernet: EthernetFrame | None = None
    arp: ARPPacket | None = None
    ipv4: IPv4Packet | None = None
    ipv6: IPv6Packet | None = None
    icmp: ICMPPacket | None = None
    tcp: TCPSegment | None = None
    udp: UDPDatagram | None = None
    dns: DNSMessage | None = None
    http: HTTPMessage | None = None
    tls: TLSMessage | None = None
    summary: str = ""

    @property
    def src_endpoint(self) -> str:
        """Return the primary source host or IP."""
        if self.ipv4:
            port = (
                f":{self.tcp.src_port}"
                if self.tcp
                else (f":{self.udp.src_port}" if self.udp else "")
            )
            return f"{self.ipv4.src_ip}{port}"
        if self.ipv6:
            port = (
                f":{self.tcp.src_port}"
                if self.tcp
                else (f":{self.udp.src_port}" if self.udp else "")
            )
            return f"[{self.ipv6.src_ip}]{port}"
        if self.arp:
            return self.arp.sender_ip
        if self.ethernet:
            return self.ethernet.src_mac
        return "Unknown"

    @property
    def dst_endpoint(self) -> str:
        """Return the primary destination host or IP."""
        if self.ipv4:
            port = (
                f":{self.tcp.dst_port}"
                if self.tcp
                else (f":{self.udp.dst_port}" if self.udp else "")
            )
            return f"{self.ipv4.dst_ip}{port}"
        if self.ipv6:
            port = (
                f":{self.tcp.dst_port}"
                if self.tcp
                else (f":{self.udp.dst_port}" if self.udp else "")
            )
            return f"[{self.ipv6.dst_ip}]{port}"
        if self.arp:
            return self.arp.target_ip
        if self.ethernet:
            return self.ethernet.dst_mac
        return "Unknown"

    @property
    def protocol_name(self) -> str:
        """Return highest-level protocol detected."""
        if self.http:
            return "HTTP"
        if self.dns:
            return "DNS"
        if self.tls:
            return "TLS"
        if self.tcp:
            return "TCP"
        if self.udp:
            return "UDP"
        if self.icmp:
            return "ICMP"
        if self.ipv4:
            return "IPv4"
        if self.ipv6:
            return "IPv6"
        if self.arp:
            return "ARP"
        if self.ethernet:
            return "Ethernet"
        return "Raw"
