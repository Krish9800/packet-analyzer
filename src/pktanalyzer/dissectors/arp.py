"""Dissector for Address Resolution Protocol (ARP)."""

import socket
import struct

from pktanalyzer.dissectors.ethernet import mac_to_str
from pktanalyzer.models.protocols import ARPPacket


def dissect_arp(data: bytes) -> ARPPacket:
    """Parse ARP packet header and network hardware/protocol bindings."""
    if len(data) < 28:
        raise ValueError(f"Data too short for ARP packet: {len(data)} bytes")

    hw_type, proto_type, hw_size, proto_size, opcode = struct.unpack("!HHBBH", data[:8])

    offset = 8
    sender_mac_raw = data[offset : offset + hw_size]
    offset += hw_size
    sender_ip_raw = data[offset : offset + proto_size]
    offset += proto_size
    target_mac_raw = data[offset : offset + hw_size]
    offset += hw_size
    target_ip_raw = data[offset : offset + proto_size]

    sender_mac = mac_to_str(sender_mac_raw) if hw_size == 6 else sender_mac_raw.hex()
    target_mac = mac_to_str(target_mac_raw) if hw_size == 6 else target_mac_raw.hex()

    sender_ip = (
        socket.inet_ntoa(sender_ip_raw)
        if proto_size == 4
        else sender_ip_raw.decode("utf-8", errors="replace")
    )
    target_ip = (
        socket.inet_ntoa(target_ip_raw)
        if proto_size == 4
        else target_ip_raw.decode("utf-8", errors="replace")
    )

    return ARPPacket(
        hw_type=hw_type,
        proto_type=proto_type,
        hw_size=hw_size,
        proto_size=proto_size,
        opcode=opcode,
        sender_mac=sender_mac,
        sender_ip=sender_ip,
        target_mac=target_mac,
        target_ip=target_ip,
    )
