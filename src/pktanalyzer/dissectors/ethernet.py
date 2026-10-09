"""Dissector for Layer 2 Ethernet II frames."""

import struct

from pktanalyzer.models.enums import EtherType
from pktanalyzer.models.protocols import EthernetFrame


def mac_to_str(mac_bytes: bytes) -> str:
    """Format 6 raw MAC bytes into canonical colon-delimited string."""
    return ":".join(f"{b:02x}" for b in mac_bytes)


def dissect_ethernet(data: bytes) -> tuple[EthernetFrame, bytes]:
    """Parse Ethernet II header, unpack MAC addresses, EtherType and payload."""
    if len(data) < 14:
        raise ValueError(f"Data too short for Ethernet II frame: {len(data)} bytes")

    dst_mac_raw, src_mac_raw, ethertype = struct.unpack("!6s6sH", data[:14])
    payload = data[14:]

    # Handle IEEE 802.1Q VLAN Tagging (0x8100)
    if ethertype == int(EtherType.VLAN):
        if len(payload) < 4:
            raise ValueError("Data too short for 802.1Q VLAN tag")
        # 2 bytes TCI (Priority + CFI + VLAN ID), 2 bytes inner EtherType
        _, inner_ethertype = struct.unpack("!HH", payload[:4])
        ethertype = inner_ethertype
        payload = payload[4:]

    frame = EthernetFrame(
        src_mac=mac_to_str(src_mac_raw),
        dst_mac=mac_to_str(dst_mac_raw),
        ethertype=ethertype,
        payload_bytes=payload,
    )
    return frame, payload
