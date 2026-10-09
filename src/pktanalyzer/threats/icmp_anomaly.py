"""ICMP anomaly and covert channel tunneling detection engine."""

import uuid

from pktanalyzer.models.enums import ThreatCategory, ThreatSeverity
from pktanalyzer.models.packet import DissectedPacket
from pktanalyzer.models.threats import SecurityAlert


class ICMPAnomalyDetector:
    """Detects oversized ICMP payloads and covert channel tunneling signatures."""

    def __init__(self, max_payload_bytes: int = 128) -> None:
        self.max_payload_bytes = max_payload_bytes
        self._alerted_pairs: set[str] = set()

    def process_packet(self, packet: DissectedPacket) -> list[SecurityAlert]:
        """Analyze ICMP payload size and contents for covert channel tunneling."""
        if not packet.icmp or not packet.ipv4:
            return []

        icmp = packet.icmp
        payload = icmp.payload_bytes
        src_ip = packet.ipv4.src_ip
        dst_ip = packet.ipv4.dst_ip
        ts = packet.timestamp

        alerts: list[SecurityAlert] = []

        if len(payload) > self.max_payload_bytes:
            pair_key = f"{src_ip}:{dst_ip}:{len(payload)}"
            if pair_key not in self._alerted_pairs:
                self._alerted_pairs.add(pair_key)
                alerts.append(
                    SecurityAlert(
                        alert_id=f"ICMP-{uuid.uuid4().hex[:8].upper()}",
                        timestamp=ts,
                        category=ThreatCategory.ICMP_ANOMALY,
                        severity=ThreatSeverity.MEDIUM,
                        title="Oversized ICMP Payload (Possible Tunnel/Exfiltration)",
                        description=(
                            f"Host {src_ip} sent {len(payload)}-byte ICMP packet to {dst_ip} "
                            f"(normal baseline <= {self.max_payload_bytes} bytes)"
                        ),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        evidence={
                            "payload_length": len(payload),
                            "icmp_type": icmp.type,
                            "icmp_code": icmp.code,
                        },
                    )
                )

        return alerts
