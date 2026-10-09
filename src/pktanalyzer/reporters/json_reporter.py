"""JSON report serializer for packet analysis results."""

import json
from typing import Any

from pktanalyzer.analytics.models import AnalyticsReport
from pktanalyzer.core.flow import FlowSession
from pktanalyzer.models.threats import SecurityAlert


def generate_json_report(
    report: AnalyticsReport,
    alerts: list[SecurityAlert],
    sessions: list[FlowSession] | None = None,
    indent: int = 2,
) -> str:
    """Format complete packet capture analysis into structured JSON string."""
    data: dict[str, Any] = {
        "summary": report.summary.model_dump(),
        "protocols": [p.model_dump() for p in report.protocols],
        "top_talkers": [t.model_dump() for t in report.top_talkers],
        "security_alerts": [a.model_dump() for a in alerts],
    }

    if sessions is not None:
        data["conversations"] = [
            {
                "session_id": s.session_id,
                "initiator": f"{s.initiator_ip}:{s.initiator_port}",
                "responder": f"{s.responder_ip}:{s.responder_port}",
                "protocol": s.protocol_name,
                "packet_count": s.packet_count,
                "total_bytes": s.total_bytes,
                "duration_seconds": round(s.duration, 3),
                "state": s.tcp_state,
            }
            for s in sessions
        ]

    return json.dumps(data, indent=indent)
