"""REST API route handlers for packet ingestion and telemetry."""

import time

from fastapi import APIRouter, File, HTTPException, UploadFile

from pktanalyzer import __version__
from pktanalyzer.analytics import AnalyticsEngine
from pktanalyzer.api.schemas import (
    AnalysisResponse,
    FlowSummaryResponse,
    HealthResponse,
    StreamInspectResponse,
)
from pktanalyzer.config.settings import get_settings
from pktanalyzer.core.flow import FlowTracker
from pktanalyzer.core.reader import PCAPReader
from pktanalyzer.dissectors import PacketDissector
from pktanalyzer.models.threats import SecurityAlert
from pktanalyzer.threats import ThreatDetectionEngine

router = APIRouter()

# Global state caches for latest telemetry view
_latest_flows: FlowTracker = FlowTracker()
_latest_threats: ThreatDetectionEngine = ThreatDetectionEngine()
_latest_analytics: AnalyticsEngine = AnalyticsEngine()


@router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """Return system liveness and version info."""
    settings = get_settings()
    return HealthResponse(
        status="healthy",
        version=__version__,
        app_name=settings.app_name,
        timestamp=time.time(),
    )


@router.post("/api/v1/analyze/upload", response_model=AnalysisResponse)
async def upload_and_analyze_pcap(
    file: UploadFile = File(...),
) -> AnalysisResponse:
    """Ingest uploaded PCAP file, dissect frames, and detect cyber threats."""
    settings = get_settings()
    content = await file.read()
    if len(content) > settings.max_pcap_size_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"PCAP upload exceeds {settings.max_pcap_size_bytes} byte limit",
        )

    dissector = PacketDissector()
    flow_tracker = FlowTracker()
    threat_engine = ThreatDetectionEngine(settings=settings)
    analytics_engine = AnalyticsEngine()

    try:
        with PCAPReader(content) as reader:
            for raw_pkt in reader.read_packets():
                dissected = dissector.dissect(raw_pkt, link_type=reader.header.linktype)
                flow_tracker.process_packet(dissected)
                threat_engine.analyze_packet(dissected)
                analytics_engine.process_packet(dissected)
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Error parsing PCAP capture: {exc}",
        ) from exc

    # Store in global state
    global _latest_flows, _latest_threats, _latest_analytics
    _latest_flows = flow_tracker
    _latest_threats = threat_engine
    _latest_analytics = analytics_engine

    sessions = flow_tracker.get_all_sessions()
    alerts = threat_engine.get_all_alerts()
    report = analytics_engine.generate_report(
        active_flows=len(sessions),
        alerts_count=len(alerts),
    )

    return AnalysisResponse(
        filename=file.filename or "uploaded.pcap",
        summary=report.summary,
        protocols=report.protocols,
        top_talkers=report.top_talkers,
        security_alerts=alerts,
        conversations_count=len(sessions),
    )


@router.get("/api/v1/flows", response_model=list[FlowSummaryResponse])
def get_flows() -> list[FlowSummaryResponse]:
    """Return all active and reconstructed flows from latest capture."""
    sessions = _latest_flows.get_all_sessions()
    return [
        FlowSummaryResponse(
            session_id=s.session_id,
            initiator=f"{s.initiator_ip}:{s.initiator_port}",
            responder=f"{s.responder_ip}:{s.responder_port}",
            protocol=s.protocol_name,
            packet_count=s.packet_count,
            total_bytes=s.total_bytes,
            duration_seconds=round(s.duration, 3),
            state=s.tcp_state,
        )
        for s in sessions
    ]


@router.get("/api/v1/flows/{session_id}", response_model=StreamInspectResponse)
def get_flow_stream(session_id: str) -> StreamInspectResponse:
    """Inspect reconstructed bidirectional byte streams for a session."""
    sessions = _latest_flows.get_all_sessions()
    target = next((s for s in sessions if s.session_id.startswith(session_id)), None)
    if not target:
        raise HTTPException(status_code=404, detail=f"Flow session '{session_id}' not found")

    return StreamInspectResponse(
        session_id=target.session_id,
        initiator=f"{target.initiator_ip}:{target.initiator_port}",
        responder=f"{target.responder_ip}:{target.responder_port}",
        protocol=target.protocol_name,
        client_stream=target.reassembled_client_data.decode("utf-8", errors="replace"),
        server_stream=target.reassembled_server_data.decode("utf-8", errors="replace"),
    )


@router.get("/api/v1/alerts", response_model=list[SecurityAlert])
def get_alerts() -> list[SecurityAlert]:
    """Return security alerts from latest capture analysis."""
    return _latest_threats.get_all_alerts()
