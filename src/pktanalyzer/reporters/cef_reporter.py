"""Common Event Format (CEF) log emitter for security SIEM integration."""

from pktanalyzer.models.enums import ThreatSeverity
from pktanalyzer.models.threats import SecurityAlert

SEVERITY_MAP = {
    ThreatSeverity.INFO: 1,
    ThreatSeverity.LOW: 3,
    ThreatSeverity.MEDIUM: 6,
    ThreatSeverity.HIGH: 8,
    ThreatSeverity.CRITICAL: 10,
}


def alert_to_cef(alert: SecurityAlert) -> str:
    """Format single SecurityAlert into standard CEF log string."""
    sev_num = SEVERITY_MAP.get(alert.severity, 5)
    fields = [
        f"rt={int(alert.timestamp * 1000)}",
        f"cat={alert.category}",
        f"msg={alert.description.replace('|', '_')}",
    ]
    if alert.src_ip:
        fields.append(f"src={alert.src_ip}")
    if alert.dst_ip:
        fields.append(f"dst={alert.dst_ip}")
    if alert.src_port:
        fields.append(f"spt={alert.src_port}")
    if alert.dst_port:
        fields.append(f"dpt={alert.dst_port}")

    extension = " ".join(fields)
    return (
        f"CEF:0|PacketAnalyzer|PacketAnalyzerEngine|0.1.0|"
        f"{alert.category}|{alert.title}|{sev_num}|{extension}"
    )


def generate_cef_report(alerts: list[SecurityAlert]) -> str:
    """Format list of alerts into newline-separated CEF entries."""
    return "\n".join(alert_to_cef(a) for a in alerts)
