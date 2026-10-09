"""ARP cache poisoning and spoofing detection engine."""

import uuid

from pktanalyzer.models.enums import ThreatCategory, ThreatSeverity
from pktanalyzer.models.packet import DissectedPacket
from pktanalyzer.models.threats import SecurityAlert


class ARPSpoofDetector:
    """Detects IP-to-MAC address mapping changes and unsolicited gratuitous ARP poisoning."""

    def __init__(self) -> None:
        # ip -> (mac, last_seen_timestamp)
        self._ip_mac_table: dict[str, tuple[str, float]] = {}

    def process_packet(self, packet: DissectedPacket) -> list[SecurityAlert]:
        """Analyze ARP packet for conflicting IP mappings."""
        if not packet.arp:
            return []

        arp = packet.arp
        ts = packet.timestamp
        alerts: list[SecurityAlert] = []

        sender_ip = arp.sender_ip
        sender_mac = arp.sender_mac.lower()

        # Ignore invalid/zero IPs and broadcasts
        if sender_ip in ("0.0.0.0", "255.255.255.255") or sender_mac == "ff:ff:ff:ff:ff:ff":  # nosec B104
            return []

        if sender_ip in self._ip_mac_table:
            known_mac, _ = self._ip_mac_table[sender_ip]
            if known_mac != sender_mac:
                # Potential ARP Poisoning Attack
                alerts.append(
                    SecurityAlert(
                        alert_id=f"ARP-{uuid.uuid4().hex[:8].upper()}",
                        timestamp=ts,
                        category=ThreatCategory.ARP_POISONING,
                        severity=ThreatSeverity.CRITICAL,
                        title="ARP Cache Poisoning / Spoofing Detected",
                        description=(
                            f"Host {sender_ip} changed MAC binding from {known_mac} "
                            f"to {sender_mac} (Opcode={arp.opcode})"
                        ),
                        src_ip=sender_ip,
                        evidence={
                            "claimed_ip": sender_ip,
                            "original_mac": known_mac,
                            "spoofed_mac": sender_mac,
                            "opcode": arp.opcode,
                        },
                    )
                )

        # Update cache table
        self._ip_mac_table[sender_ip] = (sender_mac, ts)
        return alerts
