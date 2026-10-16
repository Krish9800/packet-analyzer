"""PCAP file sanitization and privacy anonymization engine."""

from dataclasses import dataclass
from pathlib import Path
import socket
import struct
from typing import BinaryIO

from pktanalyzer.core.reader import PCAPReader, PCAPWriter
from pktanalyzer.models.enums import EtherType, IPProtocol, LinkType


@dataclass
class SanitizationReport:
    """Statistical summary of PCAP sanitization and anonymization."""

    total_packets: int
    anonymized_ips_count: int
    anonymized_macs_count: int
    payload_bytes_scrubbed: int


def _compute_ipv4_checksum(header: bytes) -> int:
    """Calculate standard 16-bit one's complement checksum for IPv4 header."""
    if len(header) % 2 != 0:
        header += b"\x00"
    total = 0
    for i in range(0, len(header), 2):
        if i == 10:  # Skip the checksum field (bytes 10-11)
            continue
        word = (header[i] << 8) + header[i + 1]
        total += word
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class PCAPSanitizer:
    """Sanitizes PCAP captures by anonymizing IPs, MACs, and scrubbing sensitive payloads."""

    def __init__(
        self,
        anonymize_ips: bool = True,
        anonymize_macs: bool = True,
        scrub_payload: bool = False,
    ) -> None:
        self.anonymize_ips = anonymize_ips
        self.anonymize_macs = anonymize_macs
        self.scrub_payload = scrub_payload

        # Consistent mapping tables
        self._ip_map: dict[str, str] = {}
        self._mac_map: dict[bytes, bytes] = {}
        self._next_ip_idx = 1
        self._next_mac_idx = 1

    def _get_anonymized_ip(self, original_ip: str) -> str:
        """Deterministically map IP to synthetic 10.0.0.X range."""
        if original_ip not in self._ip_map:
            idx = self._next_ip_idx
            self._next_ip_idx += 1
            b2 = (idx >> 16) & 0xFF
            b3 = (idx >> 8) & 0xFF
            b4 = idx & 0xFF
            self._ip_map[original_ip] = f"10.{b2}.{b3}.{b4}"
        return self._ip_map[original_ip]

    def _get_anonymized_mac(self, original_mac: bytes) -> bytes:
        """Deterministically map MAC to synthetic 02:00:00:xx:xx:xx range."""
        if original_mac not in self._mac_map:
            idx = self._next_mac_idx
            self._next_mac_idx += 1
            b4 = (idx >> 16) & 0xFF
            b5 = (idx >> 8) & 0xFF
            b6 = idx & 0xFF
            self._mac_map[original_mac] = bytes([0x02, 0x00, 0x00, b4, b5, b6])
        return self._mac_map[original_mac]

    def sanitize_packet(
        self, packet_bytes: bytes, linktype: int = int(LinkType.ETHERNET)
    ) -> tuple[bytes, int]:
        """Sanitize a raw packet buffer according to active privacy rules.

        Returns:
            tuple of (sanitized_packet_bytes, scrubbed_payload_byte_count)
        """
        if linktype != int(LinkType.ETHERNET) or len(packet_bytes) < 14:
            return packet_bytes, 0

        data = bytearray(packet_bytes)
        scrubbed_count = 0

        # 1. Anonymize Layer 2 MAC addresses
        if self.anonymize_macs:
            dst_mac = bytes(data[0:6])
            src_mac = bytes(data[6:12])
            data[0:6] = self._get_anonymized_mac(dst_mac)
            data[6:12] = self._get_anonymized_mac(src_mac)

        ethertype = struct.unpack("!H", data[12:14])[0]
        l3_offset = 14

        # Handle 802.1Q VLAN Tagging
        if ethertype == int(EtherType.VLAN) and len(data) >= 18:
            ethertype = struct.unpack("!H", data[16:18])[0]
            l3_offset = 18

        # 2. Anonymize Layer 3 IPv4
        if ethertype == int(EtherType.IPV4) and len(data) >= l3_offset + 20:
            first_byte = data[l3_offset]
            version = (first_byte >> 4) & 0x0F
            ihl = first_byte & 0x0F
            header_len = ihl * 4

            if version == 4 and ihl >= 5 and len(data) >= l3_offset + header_len:
                proto = data[l3_offset + 9]

                if self.anonymize_ips:
                    src_ip_str = socket.inet_ntoa(data[l3_offset + 12 : l3_offset + 16])
                    dst_ip_str = socket.inet_ntoa(data[l3_offset + 16 : l3_offset + 20])
                    anon_src = socket.inet_aton(self._get_anonymized_ip(src_ip_str))
                    anon_dst = socket.inet_aton(self._get_anonymized_ip(dst_ip_str))
                    data[l3_offset + 12 : l3_offset + 16] = anon_src
                    data[l3_offset + 16 : l3_offset + 20] = anon_dst

                    # Recalculate IPv4 header checksum
                    new_chk = _compute_ipv4_checksum(bytes(data[l3_offset : l3_offset + header_len]))
                    data[l3_offset + 10 : l3_offset + 12] = struct.pack("!H", new_chk)

                # 3. Scrub L4 Payload
                l4_offset = l3_offset + header_len
                if self.scrub_payload:
                    if proto == int(IPProtocol.TCP) and len(data) >= l4_offset + 20:
                        tcp_offset_val = (data[l4_offset + 12] >> 4) * 4
                        payload_start = l4_offset + tcp_offset_val
                        if len(data) > payload_start:
                            payload_len = len(data) - payload_start
                            data[payload_start:] = b"\x00" * payload_len
                            scrubbed_count += payload_len
                    elif proto == int(IPProtocol.UDP) and len(data) >= l4_offset + 8:
                        payload_start = l4_offset + 8
                        if len(data) > payload_start:
                            payload_len = len(data) - payload_start
                            data[payload_start:] = b"\x00" * payload_len
                            scrubbed_count += payload_len

        return bytes(data), scrubbed_count

    def sanitize_file(
        self,
        input_source: str | Path | BinaryIO,
        output_target: str | Path | BinaryIO,
        ignore_errors: bool = True,
    ) -> SanitizationReport:
        """Sanitize an entire PCAP file, producing an anonymized output PCAP file."""
        total_packets = 0
        total_scrubbed_bytes = 0

        with PCAPReader(input_source) as reader:
            with PCAPWriter(output_target, linktype=reader.header.linktype) as writer:
                for raw_pkt in reader.read_packets(ignore_errors=ignore_errors):
                    total_packets += 1
                    sanitized_bytes, scrubbed_len = self.sanitize_packet(
                        raw_pkt.data, linktype=reader.header.linktype
                    )
                    total_scrubbed_bytes += scrubbed_len
                    writer.write_packet(sanitized_bytes, timestamp=raw_pkt.timestamp)

        return SanitizationReport(
            total_packets=total_packets,
            anonymized_ips_count=len(self._ip_map),
            anonymized_macs_count=len(self._mac_map),
            payload_bytes_scrubbed=total_scrubbed_bytes,
        )
