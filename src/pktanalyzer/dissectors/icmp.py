"""Dissector for Layer 3.5 ICMP packets."""

import struct

from pktanalyzer.models.enums import ICMPType
from pktanalyzer.models.protocols import ICMPPacket


def dissect_icmp(data: bytes) -> ICMPPacket:
    """Parse ICMP header, code, checksum, and payload."""
    if len(data) < 8:
        raise ValueError(f"Data too short for ICMP header: {len(data)} bytes")

    icmp_type, code, checksum = struct.unpack("!BBH", data[:4])

    identifier: int | None = None
    sequence: int | None = None
    payload = data[8:]

    # Echo Request (8) and Echo Reply (0) carry Identifier and Sequence number
    if icmp_type in (int(ICMPType.ECHO_REQUEST), int(ICMPType.ECHO_REPLY)):
        identifier, sequence = struct.unpack("!HH", data[4:8])

    return ICMPPacket(
        type=icmp_type,
        code=code,
        checksum=checksum,
        identifier=identifier,
        sequence=sequence,
        payload_bytes=payload,
    )
