"""Pydantic schemas for REST API endpoints."""

from typing import Any

from pydantic import BaseModel, Field

from pktanalyzer.analytics.models import EndpointStats, ProtocolStats, TrafficSummary
from pktanalyzer.models.threats import SecurityAlert


class HealthResponse(BaseModel):
    """API health status schema."""

    status: str = "healthy"
    version: str
    app_name: str
    timestamp: float


class FlowSummaryResponse(BaseModel):
    """Conversation summary item schema."""

    session_id: str
    initiator: str
    responder: str
    protocol: str
    packet_count: int
    total_bytes: int
    duration_seconds: float
    state: str


class StreamInspectResponse(BaseModel):
    """Reconstructed bidirectional stream schema."""

    session_id: str
    initiator: str
    responder: str
    protocol: str
    client_stream: str
    server_stream: str


class AnalysisResponse(BaseModel):
    """Capture analysis results schema."""

    filename: str
    summary: TrafficSummary
    protocols: list[ProtocolStats] = Field(default_factory=list)
    top_talkers: list[EndpointStats] = Field(default_factory=list)
    security_alerts: list[SecurityAlert] = Field(default_factory=list)
    conversations_count: int = 0
    extra: dict[str, Any] = Field(default_factory=dict)
