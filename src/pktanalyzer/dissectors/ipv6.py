"""Dissector for Layer 3 IPv6 packets."""

import ipaddress
import struct

from pktanalyzer.models.protocols import IPv6Packet


def dissect_ipv6(data: bytes) -> tuple[IPv6Packet, bytes]:
    """Parse IPv6 fixed header and payload."""
    if len(data) < 40:
        raise ValueError(f"Data too short for IPv6 header: {len(data)} bytes")

    first_word = struct.unpack("!I", data[0:4])[0]
    version = (first_word >> 28) & 0x0F
    traffic_class = (first_word >> 20) & 0xFF
    flow_label = first_word & 0xFFFFF

    payload_length, next_header, hop_limit = struct.unpack("!HBB", data[4:8])

    src_ip_raw = data[8:24]
    dst_ip_raw = data[24:40]

    src_ip = str(ipaddress.IPv6Address(src_ip_raw))
    dst_ip = str(ipaddress.IPv6Address(dst_ip_raw))

    header_len = 40
    effective_end = (
        (header_len + payload_length)
        if (payload_length > 0 and (header_len + payload_length) <= len(data))
        else len(data)
    )
    payload = data[header_len:effective_end]

    packet = IPv6Packet(
        version=version,
        traffic_class=traffic_class,
        flow_label=flow_label,
        payload_length=payload_length,
        next_header=next_header,
        hop_limit=hop_limit,
        src_ip=src_ip,
        dst_ip=dst_ip,
        payload_bytes=payload,
    )
    return packet, payload
