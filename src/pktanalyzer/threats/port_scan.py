"""Port scan and stealth probe detection engine."""

import uuid
from collections import defaultdict

from pktanalyzer.models.enums import TCPFlag, ThreatCategory, ThreatSeverity
from pktanalyzer.models.packet import DissectedPacket
from pktanalyzer.models.threats import SecurityAlert


class PortScanDetector:
    """Detects TCP SYN scans, stealth FIN/NULL/XMAS probes across sliding time windows."""

    def __init__(self, threshold: int = 15, window_seconds: float = 5.0) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        # src_ip -> list of (timestamp, dst_port, scan_type)
        self._history: dict[str, list[tuple[float, int, str]]] = defaultdict(list)
        self._alerted_scans: set[str] = set()

    def process_packet(self, packet: DissectedPacket) -> list[SecurityAlert]:
        """Analyze packet for port scan signatures."""
        if not packet.tcp or not packet.ipv4:
            return []

        src_ip = packet.ipv4.src_ip
        dst_ip = packet.ipv4.dst_ip
        dst_port = packet.tcp.dst_port
        flags = packet.tcp.flags
        ts = packet.timestamp

        scan_type: str | None = None

        # Check stealth scan types
        is_null = (flags & 0xFF) == 0
        is_fin = (flags & 0xFF) == int(TCPFlag.FIN)
        is_xmas = (flags & 0xFF) == (int(TCPFlag.FIN) | int(TCPFlag.PSH) | int(TCPFlag.URG))
        is_syn = (flags & int(TCPFlag.SYN)) and not (flags & int(TCPFlag.ACK))

        if is_null:
            scan_type = "NULL Scan"
        elif is_fin:
            scan_type = "FIN Scan"
        elif is_xmas:
            scan_type = "XMAS Scan"
        elif is_syn:
            scan_type = "SYN Scan"

        if not scan_type:
            return []

        alerts: list[SecurityAlert] = []

        # Single stealth packet immediate alert
        if scan_type in ("NULL Scan", "FIN Scan", "XMAS Scan"):
            alert_key = f"{src_ip}:{dst_ip}:{dst_port}:{scan_type}"
            if alert_key not in self._alerted_scans:
                self._alerted_scans.add(alert_key)
                alerts.append(
                    SecurityAlert(
                        alert_id=f"SCAN-{uuid.uuid4().hex[:8].upper()}",
                        timestamp=ts,
                        category=ThreatCategory.PORT_SCAN,
                        severity=ThreatSeverity.HIGH,
                        title=f"Stealth TCP {scan_type} Detected",
                        description=(
                            f"Host {src_ip} sent anomalous TCP {scan_type} probe "
                            f"to {dst_ip}:{dst_port}"
                        ),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        evidence={"scan_type": scan_type, "flags": packet.tcp.flag_names},
                    )
                )

        # Sliding window volume tracking for SYN scans
        history = self._history[src_ip]
        history.append((ts, dst_port, scan_type))

        # Evict old entries outside window
        cutoff = ts - self.window_seconds
        valid_entries = [e for e in history if e[0] >= cutoff]
        self._history[src_ip] = valid_entries

        unique_ports = {e[1] for e in valid_entries}
        if len(unique_ports) >= self.threshold:
            sweep_key = f"SWEEP:{src_ip}:{int(ts // self.window_seconds)}"
            if sweep_key not in self._alerted_scans:
                self._alerted_scans.add(sweep_key)
                alerts.append(
                    SecurityAlert(
                        alert_id=f"SCAN-{uuid.uuid4().hex[:8].upper()}",
                        timestamp=ts,
                        category=ThreatCategory.PORT_SCAN,
                        severity=ThreatSeverity.CRITICAL,
                        title="High-Speed TCP Port Scan Sweep",
                        description=(
                            f"Host {src_ip} probed {len(unique_ports)} distinct ports within "
                            f"{self.window_seconds}s"
                        ),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        evidence={
                            "probed_ports": sorted(unique_ports),
                            "probe_count": len(valid_entries),
                            "window_seconds": self.window_seconds,
                        },
                    )
                )

        return alerts
