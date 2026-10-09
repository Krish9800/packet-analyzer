"""Unit tests for reporting modules (JSON, CEF, Rich)."""

import io
import json

from rich.console import Console

from pktanalyzer.analytics.models import (
    AnalyticsReport,
    EndpointStats,
    ProtocolStats,
    TrafficSummary,
)
from pktanalyzer.core.flow import FlowSession
from pktanalyzer.models.enums import ThreatCategory, ThreatSeverity
from pktanalyzer.models.threats import SecurityAlert
from pktanalyzer.reporters import (
    alert_to_cef,
    generate_cef_report,
    generate_json_report,
    render_rich_report,
)


def test_json_and_cef_reporters() -> None:
    """Verify JSON and CEF report serializers."""
    summary = TrafficSummary(
        total_packets=10,
        total_bytes=1500,
        start_time=1700000000.0,
        end_time=1700000001.0,
        duration_seconds=1.0,
        bytes_per_second=1500.0,
        packets_per_second=10.0,
    )
    protocols = [ProtocolStats(protocol="HTTP", packet_count=10, byte_count=1500, percentage=100.0)]
    talkers = [EndpointStats(ip="10.0.0.1", total_bytes=1500)]
    report = AnalyticsReport(summary=summary, protocols=protocols, top_talkers=talkers)

    alert = SecurityAlert(
        alert_id="ALT-1",
        timestamp=1700000000.5,
        category=ThreatCategory.PORT_SCAN,
        severity=ThreatSeverity.HIGH,
        title="TCP SYN Port Scan",
        description="Probe to multiple ports",
        src_ip="192.168.1.5",
        dst_ip="10.0.0.1",
        src_port=4444,
        dst_port=80,
    )

    session = FlowSession(
        session_id="abcdef1234567890",
        initiator_ip="192.168.1.5",
        initiator_port=4444,
        responder_ip="10.0.0.1",
        responder_port=80,
        protocol_name="TCP",
        start_time=1700000000.0,
        last_time=1700000001.0,
        packet_count=10,
        total_bytes=1500,
    )

    # JSON test
    json_str = generate_json_report(report, [alert], sessions=[session])
    parsed = json.loads(json_str)
    assert parsed["summary"]["total_packets"] == 10
    assert len(parsed["security_alerts"]) == 1
    assert parsed["security_alerts"][0]["category"] == "PORT_SCAN"
    assert len(parsed["conversations"]) == 1

    # CEF test
    cef_single = alert_to_cef(alert)
    assert "CEF:0|PacketAnalyzer|PacketAnalyzerEngine|0.1.0|PORT_SCAN|" in cef_single
    assert "src=192.168.1.5" in cef_single
    assert "dst=10.0.0.1" in cef_single

    cef_multi = generate_cef_report([alert])
    assert cef_multi == cef_single


def test_rich_reporter() -> None:
    """Verify render_rich_report outputs without error."""
    summary = TrafficSummary(total_packets=2, total_bytes=200)
    report = AnalyticsReport(summary=summary)
    alert = SecurityAlert(
        alert_id="A1",
        timestamp=1.0,
        category=ThreatCategory.ARP_POISONING,
        severity=ThreatSeverity.CRITICAL,
        title="Poisoning",
        description="desc",
    )
    buffer = io.StringIO()
    test_console = Console(file=buffer, color_system=None)
    render_rich_report(report, [alert], sessions=None, console=test_console)
    output = buffer.getvalue()
    assert "Capture Analysis Overview" in output
    assert "Poisoning" in output
