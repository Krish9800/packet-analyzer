"""Command-line interface for Packet Analyzer."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from pktanalyzer import __version__
from pktanalyzer.analytics import AnalyticsEngine
from pktanalyzer.core.flow import FlowTracker
from pktanalyzer.core.reader import PCAPReader
from pktanalyzer.dissectors import PacketDissector
from pktanalyzer.reporters import (
    generate_cef_report,
    generate_json_report,
    render_rich_report,
)
from pktanalyzer.threats import ThreatDetectionEngine

app = typer.Typer(
    name="pktanalyzer",
    help="Packet Analyzer: Deep Packet Inspection & Network Threat Detector",
    add_completion=False,
)
console = Console()


@app.command()
def analyze(
    pcap_file: Annotated[Path, typer.Argument(help="Path to Libpcap capture file (.pcap)")],
    format: Annotated[
        str, typer.Option("--format", "-f", help="Output format: rich, json, cef")
    ] = "rich",
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="File path to save output report")
    ] = None,
    alerts_only: Annotated[
        bool, typer.Option("--alerts-only", help="Display only security alerts")
    ] = False,
    max_packets: Annotated[
        int | None, typer.Option("--max-packets", "-n", help="Max packets to dissect")
    ] = None,
) -> None:
    """Analyze a PCAP capture file for protocol metrics and cyber threats."""
    if not pcap_file.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {pcap_file}")
        raise typer.Exit(code=1)

    dissector = PacketDissector()
    flow_tracker = FlowTracker()
    threat_engine = ThreatDetectionEngine()
    analytics_engine = AnalyticsEngine()

    packet_count = 0
    with PCAPReader(pcap_file) as reader:
        for raw_pkt in reader.read_packets():
            packet_count += 1
            if max_packets and packet_count > max_packets:
                break

            dissected = dissector.dissect(raw_pkt, link_type=reader.header.linktype)
            flow_tracker.process_packet(dissected)
            threat_engine.analyze_packet(dissected)
            analytics_engine.process_packet(dissected)

    sessions = flow_tracker.get_all_sessions()
    alerts = threat_engine.get_all_alerts()
    report = analytics_engine.generate_report(
        active_flows=len(sessions),
        alerts_count=len(alerts),
    )

    fmt = format.lower()
    if fmt == "json":
        json_output = generate_json_report(report, alerts, sessions=sessions)
        if output:
            output.write_text(json_output, encoding="utf-8")
            console.print(f"[green]Report saved to {output}[/green]")
        else:
            console.print(json_output)
    elif fmt == "cef":
        cef_output = generate_cef_report(alerts)
        if output:
            output.write_text(cef_output, encoding="utf-8")
            console.print(f"[green]CEF alerts saved to {output}[/green]")
        else:
            console.print(cef_output if cef_output else "No security alerts detected.")
    else:
        render_rich_report(report, alerts, sessions=sessions if not alerts_only else None)
        if output:
            json_fallback = generate_json_report(report, alerts, sessions=sessions)
            output.write_text(json_fallback, encoding="utf-8")
            console.print(f"[green]Copy saved to {output}[/green]")


@app.command()
def flows(
    pcap_file: Annotated[Path, typer.Argument(help="Path to Libpcap capture file (.pcap)")],
    session_id: Annotated[
        str | None, typer.Option("--id", help="Session ID to inspect reconstructed stream")
    ] = None,
) -> None:
    """List or inspect reassembled TCP/UDP conversation sessions."""
    if not pcap_file.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {pcap_file}")
        raise typer.Exit(code=1)

    dissector = PacketDissector()
    flow_tracker = FlowTracker()

    with PCAPReader(pcap_file) as reader:
        for raw_pkt in reader.read_packets():
            dissected = dissector.dissect(raw_pkt, link_type=reader.header.linktype)
            flow_tracker.process_packet(dissected)

    sessions = flow_tracker.get_all_sessions()
    if session_id:
        target = next((s for s in sessions if s.session_id.startswith(session_id)), None)
        if not target:
            console.print(f"[bold red]Session not found matching '{session_id}'[/bold red]")
            raise typer.Exit(code=1)

        console.print(f"[bold cyan]Session:[/bold cyan] {target.session_id}")
        console.print(
            f"[bold green]Client:[/bold green] {target.initiator_ip}:{target.initiator_port}"
        )
        console.print(
            f"[bold blue]Server:[/bold blue] {target.responder_ip}:{target.responder_port}"
        )
        console.print(f"[bold yellow]Protocol:[/bold yellow] {target.protocol_name}")
        console.print("\n--- [bold green]Reconstructed Client Stream[/bold green] ---")
        console.print(target.reassembled_client_data.decode("utf-8", errors="replace"))
        console.print("\n--- [bold blue]Reconstructed Server Stream[/bold blue] ---")
        console.print(target.reassembled_server_data.decode("utf-8", errors="replace"))
    else:
        console.print(f"[bold cyan]Total Conversations Tracked:[/bold cyan] {len(sessions)}")
        for s in sessions:
            console.print(
                f"[{s.session_id[:8]}] {s.initiator_ip}:{s.initiator_port} -> "
                f"{s.responder_ip}:{s.responder_port} ({s.protocol_name}) - "
                f"{s.packet_count} packets, {s.total_bytes} bytes"
            )


@app.command()
def sanitize(
    input_pcap: Annotated[Path, typer.Argument(help="Path to input PCAP capture file")],
    output_pcap: Annotated[Path, typer.Argument(help="Target path for sanitized PCAP file")],
    anonymize_ips: Annotated[
        bool, typer.Option("--ips/--no-ips", help="Anonymize IPv4/IPv6 addresses")
    ] = True,
    anonymize_macs: Annotated[
        bool, typer.Option("--macs/--no-macs", help="Anonymize Ethernet MAC addresses")
    ] = True,
    scrub_payload: Annotated[
        bool, typer.Option("--scrub-payload/--keep-payload", help="Zero-out L4 payload bytes")
    ] = False,
) -> None:
    """Sanitize and anonymize a PCAP file to prevent privacy and credential leakage."""
    if not input_pcap.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {input_pcap}")
        raise typer.Exit(code=1)

    from pktanalyzer.core.sanitizer import PCAPSanitizer

    sanitizer = PCAPSanitizer(
        anonymize_ips=anonymize_ips,
        anonymize_macs=anonymize_macs,
        scrub_payload=scrub_payload,
    )
    report = sanitizer.sanitize_file(input_pcap, output_pcap)
    console.print(
        f"[bold green]Successfully sanitized {report.total_packets} packets -> {output_pcap}[/bold green]"
    )
    console.print(f"  Anonymized IPs: {report.anonymized_ips_count}")
    console.print(f"  Anonymized MACs: {report.anonymized_macs_count}")
    if scrub_payload:
        console.print(f"  Scrubbed Payload Bytes: {report.payload_bytes_scrubbed}")


@app.command()
def version() -> None:
    """Show the Packet Analyzer version."""
    console.print(f"Packet Analyzer v{__version__}")


if __name__ == "__main__":
    app()
