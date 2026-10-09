"""Dissector for Layer 4 UDP datagrams."""

import struct

from pktanalyzer.models.protocols import UDPDatagram


def dissect_udp(data: bytes) -> tuple[UDPDatagram, bytes]:
    """Parse UDP datagram header and extract application payload."""
    if len(data) < 8:
        raise ValueError(f"Data too short for UDP header: {len(data)} bytes")

    src_port, dst_port, length, checksum = struct.unpack("!HHHH", data[:8])
    if length < 8:
        raise ValueError(f"Invalid UDP datagram length: {length} < 8 bytes")

    effective_end = length if (length <= len(data)) else len(data)
    payload = data[8:effective_end]

    datagram = UDPDatagram(
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        checksum=checksum,
        payload_bytes=payload,
    )
    return datagram, payload
