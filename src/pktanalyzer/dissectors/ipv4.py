"""Dissector for Layer 3 IPv4 packets."""

import socket
import struct

from pktanalyzer.models.protocols import IPv4Packet


def dissect_ipv4(data: bytes) -> tuple[IPv4Packet, bytes]:
    """Parse IPv4 packet header, fields, options, and extract transport payload."""
    if len(data) < 20:
        raise ValueError(f"Data too short for IPv4 header: {len(data)} bytes")

    first_byte = data[0]
    version = (first_byte >> 4) & 0x0F
    ihl = first_byte & 0x0F
    if ihl < 5:
        raise ValueError(f"Invalid IPv4 IHL {ihl}: must be at least 5 (20 bytes)")

    header_len = ihl * 4
    if len(data) < header_len:
        raise ValueError(
            f"IPv4 packet smaller than declared header length: {len(data)} < {header_len}"
        )

    tos = data[1]
    dscp = (tos >> 2) & 0x3F
    ecn = tos & 0x03

    total_len, identification, flags_frag, ttl, protocol, checksum = struct.unpack(
        "!HHHBBH", data[2:12]
    )
    flags = (flags_frag >> 13) & 0x07
    frag_offset = (flags_frag & 0x1FFF) * 8

    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])

    options = data[20:header_len] if header_len > 20 else b""

    # Sliced to declared total_length if packet capture is complete, else whatever was captured
    effective_end = total_len if (total_len > 0 and total_len <= len(data)) else len(data)
    payload = data[header_len:effective_end]

    packet = IPv4Packet(
        version=version,
        ihl=ihl,
        dscp=dscp,
        ecn=ecn,
        total_length=total_len,
        identification=identification,
        flags=flags,
        fragment_offset=frag_offset,
        ttl=ttl,
        protocol=protocol,
        checksum=checksum,
        src_ip=src_ip,
        dst_ip=dst_ip,
        options=options,
        payload_bytes=payload,
    )
    return packet, payload
