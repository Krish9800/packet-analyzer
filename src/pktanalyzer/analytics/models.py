"""Models for traffic analytics and forensics reporting."""

from pydantic import BaseModel, Field


class TrafficSummary(BaseModel):
    """Overall capture metrics summary."""

    total_packets: int = 0
    total_bytes: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    duration_seconds: float = 0.0
    bytes_per_second: float = 0.0
    packets_per_second: float = 0.0


class ProtocolStats(BaseModel):
    """Protocol layer volume breakdown."""

    protocol: str
    packet_count: int = 0
    byte_count: int = 0
    percentage: float = 0.0


class EndpointStats(BaseModel):
    """Host communication metrics."""

    ip: str
    sent_packets: int = 0
    received_packets: int = 0
    sent_bytes: int = 0
    received_bytes: int = 0
    total_bytes: int = 0


class AnalyticsReport(BaseModel):
    """Aggregated forensics and analytics report."""

    summary: TrafficSummary
    protocols: list[ProtocolStats] = Field(default_factory=list)
    top_talkers: list[EndpointStats] = Field(default_factory=list)
    active_conversations_count: int = 0
    security_alerts_count: int = 0
