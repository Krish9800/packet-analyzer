"""Unit tests for PCAP sanitization, anonymization, and resilient error recovery."""

import io
from pathlib import Path
import struct

from typer.testing import CliRunner

from pktanalyzer.cli.main import app
from pktanalyzer.core.exceptions import PCAPCorruptError
from pktanalyzer.core.reader import PCAPReader, PCAPWriter
from pktanalyzer.core.sanitizer import PCAPSanitizer
from pktanalyzer.models.enums import LinkType


def _build_test_ethernet_ipv4_udp_packet(
    src_ip: bytes = b"\xc0\xa8\x01\x32",  # 192.168.1.50
    dst_ip: bytes = b"\x0a\x00\x00\x01",  # 10.0.0.1
    src_mac: bytes = b"\x00\x11\x22\x33\x44\x55",
    dst_mac: bytes = b"\xaa\xbb\xcc\xdd\xee\xff",
    payload: bytes = b"SECRET_PASSWORD_PAYLOAD_1234",
) -> bytes:
    """Build a valid binary Ethernet + IPv4 + UDP packet buffer."""
    eth_header = dst_mac + src_mac + struct.pack("!H", 0x0800)  # EtherType IPv4

    udp_len = 8 + len(payload)
    total_ip_len = 20 + udp_len

    # IPv4 header: version 4, IHL 5, total len, proto 17 (UDP)
    ip_header_no_chk = (
        b"\x45\x00"
        + struct.pack("!H", total_ip_len)
        + b"\x12\x34\x00\x00\x40\x11\x00\x00"
        + src_ip
        + dst_ip
    )
    # Dummy checksum for testing
    ip_header = ip_header_no_chk[:10] + b"\xb5\x8e" + ip_header_no_chk[12:]

    # UDP Header: src port 1234, dst port 53, length, checksum 0
    udp_header = struct.pack("!HHHH", 1234, 53, udp_len, 0x0000)

    return eth_header + ip_header + udp_header + payload


def test_sanitizer_anonymize_ips_and_macs() -> None:
    """Verify IP and MAC address substitution in raw packet buffers."""
    sanitizer = PCAPSanitizer(anonymize_ips=True, anonymize_macs=True, scrub_payload=False)
    pkt_data = _build_test_ethernet_ipv4_udp_packet()

    sanitized, scrubbed_len = sanitizer.sanitize_packet(pkt_data)
    assert scrubbed_len == 0

    # Ensure MACs were replaced (new MACs start with 0x02 Locally Administered)
    assert sanitized[0:3] == b"\x02\x00\x00"
    assert sanitized[6:9] == b"\x02\x00\x00"

    # Ensure original IPs (192.168.1.50) are no longer in packet data
    assert b"\xc0\xa8\x01\x32" not in sanitized
    # Ensure payload is preserved when scrub_payload=False
    assert b"SECRET_PASSWORD_PAYLOAD_1234" in sanitized


def test_sanitizer_scrub_payload() -> None:
    """Verify L4 application payload is zeroed out when scrub_payload=True."""
    sanitizer = PCAPSanitizer(anonymize_ips=True, anonymize_macs=True, scrub_payload=True)
    pkt_data = _build_test_ethernet_ipv4_udp_packet()

    sanitized, scrubbed_len = sanitizer.sanitize_packet(pkt_data)
    assert scrubbed_len == len(b"SECRET_PASSWORD_PAYLOAD_1234")
    assert b"SECRET_PASSWORD_PAYLOAD_1234" not in sanitized
    assert b"\x00" * len(b"SECRET_PASSWORD_PAYLOAD_1234") in sanitized


def test_sanitizer_file_e2e(tmp_path: Path) -> None:
    """Verify PCAP file-to-file sanitization workflow."""
    input_pcap = tmp_path / "raw_capture.pcap"
    output_pcap = tmp_path / "sanitized_capture.pcap"

    with PCAPWriter(input_pcap, linktype=LinkType.ETHERNET) as writer:
        for _ in range(5):
            writer.write_packet(_build_test_ethernet_ipv4_udp_packet(), timestamp=1700000000.0)

    sanitizer = PCAPSanitizer(anonymize_ips=True, anonymize_macs=True, scrub_payload=True)
    report = sanitizer.sanitize_file(input_pcap, output_pcap)

    assert report.total_packets == 5
    assert report.anonymized_ips_count == 2
    assert report.anonymized_macs_count == 2
    assert report.payload_bytes_scrubbed == 5 * len(b"SECRET_PASSWORD_PAYLOAD_1234")

    # Verify output file is a readable valid PCAP
    with PCAPReader(output_pcap) as reader:
        pkts = list(reader.read_packets())
        assert len(pkts) == 5
        assert b"SECRET_PASSWORD_PAYLOAD_1234" not in pkts[0].data


def test_pcap_reader_ignore_errors_on_corrupt_file() -> None:
    """Verify PCAPReader.read_packets(ignore_errors=True) stops cleanly on truncation."""
    buf = io.BytesIO()
    with PCAPWriter(buf, linktype=LinkType.ETHERNET) as writer:
        writer.write_packet(b"ValidPacket1", timestamp=1700000000.0)
        writer.write_packet(b"ValidPacket2", timestamp=1700000001.0)

    # Append half a packet header to simulate sudden EOF/truncation
    buf.write(b"\x00\x00\x01\x02\x03")
    truncated_bytes = buf.getvalue()

    # Without ignore_errors, should raise PCAPCorruptError
    with PCAPReader(truncated_bytes) as reader:
        try:
            list(reader.read_packets(ignore_errors=False))
            raised = False
        except PCAPCorruptError:
            raised = True
        assert raised is True

    # With ignore_errors=True, should yield valid packets and stop cleanly
    with PCAPReader(truncated_bytes) as reader:
        packets = list(reader.read_packets(ignore_errors=True))
        assert len(packets) == 2


def test_cli_sanitize_command(tmp_path: Path) -> None:
    """Verify 'pktanalyzer sanitize' CLI command execution."""
    input_pcap = tmp_path / "cli_input.pcap"
    output_pcap = tmp_path / "cli_output.pcap"

    with PCAPWriter(input_pcap, linktype=LinkType.ETHERNET) as writer:
        writer.write_packet(_build_test_ethernet_ipv4_udp_packet())

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["sanitize", str(input_pcap), str(output_pcap), "--scrub-payload"],
    )

    assert result.exit_code == 0
    assert "Successfully sanitized 1 packets" in result.stdout
    assert output_pcap.exists()
