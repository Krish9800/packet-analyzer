"""Dissector for Layer 4 TCP segments."""

import struct

from pktanalyzer.models.enums import TCPFlag
from pktanalyzer.models.protocols import TCPSegment

FLAG_NAMES = [
    (TCPFlag.FIN, "FIN"),
    (TCPFlag.SYN, "SYN"),
    (TCPFlag.RST, "RST"),
    (TCPFlag.PSH, "PSH"),
    (TCPFlag.ACK, "ACK"),
    (TCPFlag.URG, "URG"),
    (TCPFlag.ECE, "ECE"),
    (TCPFlag.CWR, "CWR"),
]


def parse_tcp_flags(flags_byte: int) -> list[str]:
    """Return active human-readable flag names for bitmask."""
    return [name for flag_val, name in FLAG_NAMES if flags_byte & int(flag_val)]


def dissect_tcp(data: bytes) -> tuple[TCPSegment, bytes]:
    """Parse TCP segment header, flags, options and payload."""
    if len(data) < 20:
        raise ValueError(f"Data too short for TCP header: {len(data)} bytes")

    src_port, dst_port, seq_num, ack_num, offset_flags, window, checksum, urgent = struct.unpack(
        "!HHIIHHHH", data[:20]
    )

    data_offset = (offset_flags >> 12) & 0x0F
    flags = offset_flags & 0x01FF  # lowest 9 bits (including NS bit)

    header_len = data_offset * 4
    if header_len < 20:
        raise ValueError(f"Invalid TCP data offset {data_offset}: must be >= 5 (20 bytes)")
    if len(data) < header_len:
        raise ValueError(f"TCP segment truncated: {len(data)} < header length {header_len}")

    payload = data[header_len:]
    active_flags = parse_tcp_flags(flags & 0xFF)

    segment = TCPSegment(
        src_port=src_port,
        dst_port=dst_port,
        seq_number=seq_num,
        ack_number=ack_num,
        data_offset=data_offset,
        flags=flags,
        window_size=window,
        checksum=checksum,
        urgent_pointer=urgent,
        flag_names=active_flags,
        payload_bytes=payload,
    )
    return segment, payload
