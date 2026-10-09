"""Pydantic data models for parsed L2-L7 network protocols."""

from pydantic import BaseModel, ConfigDict, Field


class EthernetFrame(BaseModel):
    """Layer 2 Ethernet II Frame."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    src_mac: str
    dst_mac: str
    ethertype: int
    payload_bytes: bytes = Field(default=b"", repr=False)


class ARPPacket(BaseModel):
    """Layer 2.5 Address Resolution Protocol Packet."""

    hw_type: int
    proto_type: int
    hw_size: int
    proto_size: int
    opcode: int
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str


class IPv4Packet(BaseModel):
    """Layer 3 IPv4 Packet."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    version: int = 4
    ihl: int
    dscp: int
    ecn: int
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int
    checksum: int
    src_ip: str
    dst_ip: str
    options: bytes = Field(default=b"", repr=False)
    payload_bytes: bytes = Field(default=b"", repr=False)


class IPv6Packet(BaseModel):
    """Layer 3 IPv6 Packet."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    version: int = 6
    traffic_class: int
    flow_label: int
    payload_length: int
    next_header: int
    hop_limit: int
    src_ip: str
    dst_ip: str
    payload_bytes: bytes = Field(default=b"", repr=False)


class ICMPPacket(BaseModel):
    """Layer 3.5 ICMP Packet."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    type: int
    code: int
    checksum: int
    identifier: int | None = None
    sequence: int | None = None
    payload_bytes: bytes = Field(default=b"", repr=False)


class TCPSegment(BaseModel):
    """Layer 4 TCP Segment."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    src_port: int
    dst_port: int
    seq_number: int
    ack_number: int
    data_offset: int
    flags: int
    window_size: int
    checksum: int
    urgent_pointer: int
    flag_names: list[str] = Field(default_factory=list)
    payload_bytes: bytes = Field(default=b"", repr=False)


class UDPDatagram(BaseModel):
    """Layer 4 UDP Datagram."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    src_port: int
    dst_port: int
    length: int
    checksum: int
    payload_bytes: bytes = Field(default=b"", repr=False)


class DNSQuestion(BaseModel):
    """DNS Question entry."""

    name: str
    qtype: int
    qclass: int


class DNSResourceRecord(BaseModel):
    """DNS Resource Record entry."""

    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: str


class DNSMessage(BaseModel):
    """Layer 7 DNS Protocol Message."""

    transaction_id: int
    flags: int
    is_response: bool
    opcode: int
    rcode: int
    questions: list[DNSQuestion] = Field(default_factory=list)
    answers: list[DNSResourceRecord] = Field(default_factory=list)


class HTTPMessage(BaseModel):
    """Layer 7 HTTP/1.x Protocol Message."""

    is_request: bool
    method: str | None = None
    uri: str | None = None
    version: str = "HTTP/1.1"
    status_code: int | None = None
    reason_phrase: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None


class TLSMessage(BaseModel):
    """Layer 7 TLS Record / Handshake metadata."""

    content_type: int
    version_major: int
    version_minor: int
    length: int
    is_handshake: bool = False
    handshake_type: int | None = None
    sni_hostname: str | None = None
