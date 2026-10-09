"""Traffic analytics and network forensics computation engine."""

from collections import defaultdict

from pktanalyzer.analytics.models import (
    AnalyticsReport,
    EndpointStats,
    ProtocolStats,
    TrafficSummary,
)
from pktanalyzer.models.packet import DissectedPacket


class AnalyticsEngine:
    """Aggregates packet streams into forensic metrics, hierarchy and top talkers."""

    def __init__(self) -> None:
        self.total_packets = 0
        self.total_bytes = 0
        self.first_timestamp: float | None = None
        self.last_timestamp: float | None = None

        # protocol -> [packet_count, byte_count]
        self.protocol_counts: dict[str, list[int]] = defaultdict(lambda: [0, 0])

        # ip -> dict with keys: sent_pkts, recv_pkts, sent_bytes, recv_bytes
        self.endpoint_stats: dict[str, dict[str, int]] = defaultdict(
            lambda: {"sent_pkts": 0, "recv_pkts": 0, "sent_bytes": 0, "recv_bytes": 0}
        )

    def process_packet(self, packet: DissectedPacket) -> None:
        """Incorporate dissected packet into traffic statistics."""
        self.total_packets += 1
        ts = packet.timestamp

        if self.first_timestamp is None or ts < self.first_timestamp:
            self.first_timestamp = ts
        if self.last_timestamp is None or ts > self.last_timestamp:
            self.last_timestamp = ts

        # Determine wire/packet bytes
        pkt_bytes = 0
        if packet.ipv4:
            pkt_bytes = packet.ipv4.total_length
        elif packet.ipv6:
            pkt_bytes = packet.ipv6.payload_length + 40
        elif packet.ethernet:
            pkt_bytes = 14 + len(packet.ethernet.payload_bytes)

        self.total_bytes += pkt_bytes

        # Protocol hierarchy accumulation
        proto_name = packet.protocol_name
        self.protocol_counts[proto_name][0] += 1
        self.protocol_counts[proto_name][1] += pkt_bytes

        # Host endpoint accounting
        src_ip: str | None = None
        dst_ip: str | None = None

        if packet.ipv4:
            src_ip = packet.ipv4.src_ip
            dst_ip = packet.ipv4.dst_ip
        elif packet.ipv6:
            src_ip = packet.ipv6.src_ip
            dst_ip = packet.ipv6.dst_ip

        if src_ip:
            self.endpoint_stats[src_ip]["sent_pkts"] += 1
            self.endpoint_stats[src_ip]["sent_bytes"] += pkt_bytes
        if dst_ip:
            self.endpoint_stats[dst_ip]["recv_pkts"] += 1
            self.endpoint_stats[dst_ip]["recv_bytes"] += pkt_bytes

    def get_summary(self) -> TrafficSummary:
        """Generate high-level traffic summary."""
        duration = 0.0
        if self.first_timestamp is not None and self.last_timestamp is not None:
            duration = max(0.0, self.last_timestamp - self.first_timestamp)

        bps = (self.total_bytes / duration) if duration > 0 else 0.0
        pps = (self.total_packets / duration) if duration > 0 else 0.0

        return TrafficSummary(
            total_packets=self.total_packets,
            total_bytes=self.total_bytes,
            start_time=self.first_timestamp or 0.0,
            end_time=self.last_timestamp or 0.0,
            duration_seconds=round(duration, 3),
            bytes_per_second=round(bps, 2),
            packets_per_second=round(pps, 2),
        )

    def get_protocol_hierarchy(self) -> list[ProtocolStats]:
        """Return protocol distribution sorted by packet count descending."""
        stats: list[ProtocolStats] = []
        for proto, (p_cnt, b_cnt) in self.protocol_counts.items():
            pct = (p_cnt / self.total_packets * 100.0) if self.total_packets > 0 else 0.0
            stats.append(
                ProtocolStats(
                    protocol=proto,
                    packet_count=p_cnt,
                    byte_count=b_cnt,
                    percentage=round(pct, 2),
                )
            )
        stats.sort(key=lambda s: s.packet_count, reverse=True)
        return stats

    def get_top_talkers(self, limit: int = 10) -> list[EndpointStats]:
        """Return top communicating IP endpoints sorted by total throughput bytes."""
        endpoints: list[EndpointStats] = []
        for ip, counts in self.endpoint_stats.items():
            tot = counts["sent_bytes"] + counts["recv_bytes"]
            endpoints.append(
                EndpointStats(
                    ip=ip,
                    sent_packets=counts["sent_pkts"],
                    received_packets=counts["recv_pkts"],
                    sent_bytes=counts["sent_bytes"],
                    received_bytes=counts["recv_bytes"],
                    total_bytes=tot,
                )
            )
        endpoints.sort(key=lambda e: e.total_bytes, reverse=True)
        return endpoints[:limit]

    def generate_report(self, active_flows: int = 0, alerts_count: int = 0) -> AnalyticsReport:
        """Produce full analytics report."""
        return AnalyticsReport(
            summary=self.get_summary(),
            protocols=self.get_protocol_hierarchy(),
            top_talkers=self.get_top_talkers(),
            active_conversations_count=active_flows,
            security_alerts_count=alerts_count,
        )
