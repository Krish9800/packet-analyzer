"""Threat detection coordinator unifying all security analytics modules."""

from pktanalyzer.config.settings import AnalyzerSettings, get_settings
from pktanalyzer.models.packet import DissectedPacket
from pktanalyzer.models.threats import SecurityAlert
from pktanalyzer.threats.arp_spoof import ARPSpoofDetector
from pktanalyzer.threats.credential_leak import CredentialLeakDetector
from pktanalyzer.threats.dns_tunnel import DNSTunnelDetector
from pktanalyzer.threats.icmp_anomaly import ICMPAnomalyDetector
from pktanalyzer.threats.port_scan import PortScanDetector


class ThreatDetectionEngine:
    """Unified network intrusion and anomaly detection engine."""

    def __init__(self, settings: AnalyzerSettings | None = None) -> None:
        self.settings = settings or get_settings()
        self.port_scan_detector = PortScanDetector(
            threshold=self.settings.port_scan_threshold,
            window_seconds=self.settings.port_scan_window_seconds,
        )
        self.arp_spoof_detector = ARPSpoofDetector()
        self.dns_tunnel_detector = DNSTunnelDetector(
            entropy_threshold=self.settings.dns_entropy_threshold,
        )
        self.credential_leak_detector = CredentialLeakDetector()
        self.icmp_anomaly_detector = ICMPAnomalyDetector()
        self.alerts: list[SecurityAlert] = []

    def analyze_packet(self, packet: DissectedPacket) -> list[SecurityAlert]:
        """Evaluate packet across all specialized threat detectors."""
        new_alerts: list[SecurityAlert] = []

        new_alerts.extend(self.port_scan_detector.process_packet(packet))
        new_alerts.extend(self.arp_spoof_detector.process_packet(packet))
        new_alerts.extend(self.dns_tunnel_detector.process_packet(packet))
        new_alerts.extend(self.credential_leak_detector.process_packet(packet))
        new_alerts.extend(self.icmp_anomaly_detector.process_packet(packet))

        self.alerts.extend(new_alerts)
        return new_alerts

    def get_all_alerts(self) -> list[SecurityAlert]:
        """Return all historical alerts detected during current analysis."""
        return list(self.alerts)

    def clear(self) -> None:
        """Reset internal alert list."""
        self.alerts.clear()
