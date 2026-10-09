"""Domain enumerations and constants for Packet Analyzer."""

from enum import IntEnum, StrEnum


class LinkType(IntEnum):
    """PCAP Data Link Layer types (RFC / Libpcap DLT)."""

    NULL = 0
    ETHERNET = 1
    AX25 = 3
    PRONET = 4
    CHAOS = 5
    IEEE802_5 = 6
    ARCNET_BSD = 7
    SLIP = 8
    PPP = 9
    FDDI = 10
    RAW = 12
    LOOPBACK = 108
    LINUX_SLL = 113
    IPV4 = 228
    IPV6 = 229


class EtherType(IntEnum):
    """IEEE 802.3 Ethernet type codes."""

    IPV4 = 0x0800
    ARP = 0x0806
    RARP = 0x8035
    VLAN = 0x8100
    IPV6 = 0x86DD
    QINQ = 0x88A8
    MPLS_UNICAST = 0x8847


class IPProtocol(IntEnum):
    """IANA IP protocol numbers."""

    HOPOPT = 0
    ICMP = 1
    IGMP = 2
    GGP = 3
    IPV4 = 4
    TCP = 6
    EGP = 8
    IGP = 9
    UDP = 17
    IPV6 = 41
    ROUTING = 43
    FRAGMENT = 44
    ESP = 50
    AH = 51
    ICMPV6 = 58
    NONE = 59
    DSTOPTS = 60
    OSPF = 89
    SCTP = 132


class TCPFlag(IntEnum):
    """TCP control flags bitmask."""

    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80


class ICMPType(IntEnum):
    """ICMPv4 message types."""

    ECHO_REPLY = 0
    DEST_UNREACHABLE = 3
    SOURCE_QUENCH = 4
    REDIRECT = 5
    ECHO_REQUEST = 8
    ROUTER_ADVERTISEMENT = 9
    ROUTER_SOLICITATION = 10
    TIME_EXCEEDED = 11
    PARAMETER_PROBLEM = 12
    TIMESTAMP = 13
    TIMESTAMP_REPLY = 14


class ThreatSeverity(StrEnum):
    """Security alert severity levels."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatCategory(StrEnum):
    """Taxonomy of detected network threats."""

    PORT_SCAN = "PORT_SCAN"
    ARP_POISONING = "ARP_POISONING"
    DNS_TUNNELING = "DNS_TUNNELING"
    CLEARTEXT_CREDENTIALS = "CLEARTEXT_CREDENTIALS"
    ICMP_ANOMALY = "ICMP_ANOMALY"
    DOS_FLOOD = "DOS_FLOOD"
    SUSPICIOUS_PAYLOAD = "SUSPICIOUS_PAYLOAD"
