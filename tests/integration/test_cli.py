"""Integration tests for pktanalyzer CLI."""

import socket
import struct
from pathlib import Path

from typer.testing import CliRunner

from pktanalyzer.cli.main import app
from pktanalyzer.core.reader import PCAPWriter
from pktanalyzer.models.enums import EtherType, IPProtocol, LinkType, TCPFlag

runner = CliRunner()


def _create_sample_pcap(path: Path) -> None:
    """Helper creating synthetic PCAP file with HTTP traffic and SYN probe."""
    writer = PCAPWriter(path, linktype=LinkType.ETHERNET)

    # Ethernet + IPv4 + TCP SYN Packet
    dst_mac = b"\x00\x11\x22\x33\x44\x55"
    src_mac = b"\x66\x77\x88\x99\xaa\xbb"
    eth_hdr = dst_mac + src_mac + struct.pack("!H", int(EtherType.IPV4))

    src_ip = socket.inet_aton("192.168.1.100")
    dst_ip = socket.inet_aton("10.0.0.1")

    # Packet 1: HTTP GET
    http_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    tcp_hdr = struct.pack("!HHIIHHHH", 50000, 80, 1, 1, (5 << 12) | 24, 1024, 0, 0) + http_payload
    ip_hdr = (
        struct.pack(
            "!BBHHHBBH", (4 << 4) | 5, 0, 20 + len(tcp_hdr), 1, 0, 64, int(IPProtocol.TCP), 0
        )
        + src_ip
        + dst_ip
    )
    writer.write_packet(eth_hdr + ip_hdr + tcp_hdr, timestamp=1700000000.0)

    # Packet 2: XMAS scan
    tcp_xmas = struct.pack(
        "!HHIIHHHH",
        50001,
        22,
        0,
        0,
        (5 << 12) | (int(TCPFlag.FIN) | int(TCPFlag.PSH) | int(TCPFlag.URG)),
        1024,
        0,
        0,
    )
    ip_xmas = (
        struct.pack(
            "!BBHHHBBH", (4 << 4) | 5, 0, 20 + len(tcp_xmas), 2, 0, 64, int(IPProtocol.TCP), 0
        )
        + src_ip
        + dst_ip
    )
    writer.write_packet(eth_hdr + ip_xmas + tcp_xmas, timestamp=1700000000.1)

    writer.close()


def test_cli_version() -> None:
    """Verify version command."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "Packet Analyzer v0.1.0" in result.output


def test_cli_analyze_rich_and_json(tmp_path: Path) -> None:
    """Verify analyze command with rich and json formats."""
    pcap_path = tmp_path / "traffic.pcap"
    _create_sample_pcap(pcap_path)

    # Rich format
    res_rich = runner.invoke(app, ["analyze", str(pcap_path)])
    assert res_rich.exit_code == 0
    assert "Capture Analysis Overview" in res_rich.output
    assert "XMAS Scan" in res_rich.output

    # JSON format
    res_json = runner.invoke(app, ["analyze", str(pcap_path), "--format", "json"])
    assert res_json.exit_code == 0
    assert '"total_packets": 2' in res_json.output
    assert '"category": "PORT_SCAN"' in res_json.output

    # CEF format
    res_cef = runner.invoke(app, ["analyze", str(pcap_path), "--format", "cef"])
    assert res_cef.exit_code == 0
    assert "CEF:0|PacketAnalyzer|" in res_cef.output

    # CEF to file
    cef_file = tmp_path / "alerts.cef"
    res_cef_out = runner.invoke(
        app, ["analyze", str(pcap_path), "--format", "cef", "--output", str(cef_file)]
    )
    assert res_cef_out.exit_code == 0
    assert cef_file.exists()

    # Output to file
    out_file = tmp_path / "report.json"
    res_out = runner.invoke(
        app, ["analyze", str(pcap_path), "--format", "json", "--output", str(out_file)]
    )
    assert res_out.exit_code == 0
    assert out_file.exists()

    # Alerts-only and max-packets
    res_alerts = runner.invoke(
        app, ["analyze", str(pcap_path), "--alerts-only", "--max-packets", "1"]
    )
    assert res_alerts.exit_code == 0

    # Rich format with file copy
    rich_file = tmp_path / "rich.json"
    res_rich_f = runner.invoke(app, ["analyze", str(pcap_path), "--output", str(rich_file)])
    assert res_rich_f.exit_code == 0
    assert rich_file.exists()


def test_cli_flows(tmp_path: Path) -> None:
    """Verify flows command and session inspection."""
    pcap_path = tmp_path / "traffic.pcap"
    _create_sample_pcap(pcap_path)

    res = runner.invoke(app, ["flows", str(pcap_path)])
    assert res.exit_code == 0
    assert "Total Conversations Tracked" in res.output

    # Inspect flow session by ID
    flow_line = next((line for line in res.output.splitlines() if "[" in line and "]" in line), "")
    sess_id = flow_line.split("[")[1].split("]")[0]
    res_sess = runner.invoke(app, ["flows", str(pcap_path), "--id", sess_id])
    assert res_sess.exit_code == 0
    assert "Reconstructed Client Stream" in res_sess.output

    # Bad session ID
    res_bad = runner.invoke(app, ["flows", str(pcap_path), "--id", "unknown_9999"])
    assert res_bad.exit_code == 1

    # Nonexistent file
    res_missing = runner.invoke(app, ["flows", "non_existent.pcap"])
    assert res_missing.exit_code == 1

    # Nonexistent analyze file
    res_missing_ana = runner.invoke(app, ["analyze", "non_existent.pcap"])
    assert res_missing_ana.exit_code == 1
