"""Rich terminal reporter for interactive CLI visualization."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from pktanalyzer.analytics.models import AnalyticsReport
from pktanalyzer.core.flow import FlowSession
from pktanalyzer.models.enums import ThreatSeverity
from pktanalyzer.models.threats import SecurityAlert


def render_rich_report(
    report: AnalyticsReport,
    alerts: list[SecurityAlert],
    sessions: list[FlowSession] | None = None,
    console: Console | None = None,
) -> None:
    """Print comprehensive, colorized report tables and panels to terminal."""
    con = console or Console()

    # 1. Capture Overview Panel
    summary = report.summary
    summary_text = (
        f"[bold cyan]Total Packets:[/bold cyan] {summary.total_packets:,}    "
        f"[bold cyan]Total Bytes:[/bold cyan] {summary.total_bytes:,} bytes\n"
        f"[bold cyan]Duration:[/bold cyan] {summary.duration_seconds:.2f}s    "
        f"[bold cyan]Throughput:[/bold cyan] {summary.bytes_per_second:,.1f} B/s "
        f"({summary.packets_per_second:.1f} pkt/s)\n"
        f"[bold cyan]Conversations:[/bold cyan] {report.active_conversations_count}    "
        f"[bold red]Security Alerts:[/bold red] {len(alerts)}"
    )
    con.print(Panel(summary_text, title="🔍 PCAP Capture Analysis Overview", border_style="cyan"))

    # 2. Protocol Breakdown Table
    if report.protocols:
        proto_table = Table(title="📊 Protocol Hierarchy Breakdown", border_style="blue")
        proto_table.add_column("Protocol", style="bold")
        proto_table.add_column("Packets", justify="right")
        proto_table.add_column("Bytes", justify="right")
        proto_table.add_column("Share", justify="right")

        for p in report.protocols:
            proto_table.add_row(
                p.protocol,
                f"{p.packet_count:,}",
                f"{p.byte_count:,}",
                f"{p.percentage:.1f}%",
            )
        con.print(proto_table)

    # 3. Top Talkers Table
    if report.top_talkers:
        talkers_table = Table(title="🌐 Top Communicating Host Endpoints", border_style="magenta")
        talkers_table.add_column("IP Address", style="bold")
        talkers_table.add_column("Sent Pkts", justify="right")
        talkers_table.add_column("Recv Pkts", justify="right")
        talkers_table.add_column("Total Bytes", justify="right")

        for t in report.top_talkers:
            talkers_table.add_row(
                t.ip,
                f"{t.sent_packets:,}",
                f"{t.received_packets:,}",
                f"{t.total_bytes:,}",
            )
        con.print(talkers_table)

    # 4. Security Alerts Table
    if alerts:
        alerts_table = Table(title="🚨 Detected Security Threats & Anomalies", border_style="red")
        alerts_table.add_column("Severity", justify="center")
        alerts_table.add_column("Category", style="yellow")
        alerts_table.add_column("Title", style="bold")
        alerts_table.add_column("Source / Host")
        alerts_table.add_column("Description")

        for a in alerts:
            sev_style = (
                "bold red"
                if a.severity == ThreatSeverity.CRITICAL
                else (
                    "red"
                    if a.severity == ThreatSeverity.HIGH
                    else ("yellow" if a.severity == ThreatSeverity.MEDIUM else "blue")
                )
            )
            alerts_table.add_row(
                f"[{sev_style}]{a.severity}[/{sev_style}]",
                a.category,
                a.title,
                a.src_ip or "N/A",
                a.description,
            )
        con.print(alerts_table)
    else:
        con.print("[green]✔ No security anomalies or threat signatures detected.[/green]")

    # 5. Conversations / Flows Table
    if sessions:
        flow_table = Table(title="🔄 Reconstructed TCP / UDP Sessions", border_style="green")
        flow_table.add_column("ID", style="dim")
        flow_table.add_column("Initiator")
        flow_table.add_column("Responder")
        flow_table.add_column("Proto")
        flow_table.add_column("Packets", justify="right")
        flow_table.add_column("Bytes", justify="right")
        flow_table.add_column("State", justify="center")

        for s in sessions[:15]:
            flow_table.add_row(
                s.session_id[:8],
                f"{s.initiator_ip}:{s.initiator_port}",
                f"{s.responder_ip}:{s.responder_port}",
                s.protocol_name,
                str(s.packet_count),
                f"{s.total_bytes:,}",
                s.tcp_state,
            )
        con.print(flow_table)
