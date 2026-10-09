"""Unit tests for PCAP binary lexer and writer."""

import io
import struct
from pathlib import Path

import pytest

from pktanalyzer.core.exceptions import PCAPCorruptError, PCAPFormatError
from pktanalyzer.core.reader import (
    MAGIC_MICRO_LE,
    MAGIC_NANO_LE,
    PCAPReader,
    PCAPWriter,
)
from pktanalyzer.models.enums import LinkType


def test_write_and_read_pcap_in_memory() -> None:
    """Verify PCAP roundtrip in BytesIO buffer."""
    buf = io.BytesIO()
    with PCAPWriter(buf, linktype=LinkType.ETHERNET) as writer:
        writer.write_packet(b"PacketPayload1", timestamp=1700000000.5)
        writer.write_packet(b"PacketPayload2", timestamp=1700000001.25)

    buf.seek(0)
    with PCAPReader(buf) as reader:
        assert reader.header.magic == MAGIC_MICRO_LE
        assert reader.header.version_major == 2
        assert reader.header.version_minor == 4
        assert reader.header.linktype == int(LinkType.ETHERNET)
        assert reader.header.is_little_endian is True
        assert reader.header.is_nanosecond is False

        packets = list(reader.read_packets())
        assert len(packets) == 2

        assert packets[0].frame_number == 1
        assert packets[0].data == b"PacketPayload1"
        assert abs(packets[0].timestamp - 1700000000.5) < 0.0001
        assert packets[0].caplen == len(b"PacketPayload1")

        assert packets[1].frame_number == 2
        assert packets[1].data == b"PacketPayload2"
        assert abs(packets[1].timestamp - 1700000001.25) < 0.0001


def test_read_pcap_from_bytes() -> None:
    """Verify PCAP reading directly from raw bytes object."""
    buf = io.BytesIO()
    with PCAPWriter(buf, linktype=LinkType.RAW):
        buf.seek(0)  # write global header
    raw_bytes = buf.getvalue()

    with PCAPReader(raw_bytes) as reader:
        assert reader.header.linktype == int(LinkType.RAW)
        assert list(reader.read_packets()) == []


def test_write_and_read_pcap_file(tmp_path: Path) -> None:
    """Verify PCAP file creation and reading from disk."""
    pcap_path = tmp_path / "test_sample.pcap"
    writer = PCAPWriter(pcap_path, linktype=LinkType.ETHERNET)
    writer.write_packet(b"\x01\x02\x03\x04\x05")
    writer.close()

    assert pcap_path.exists()
    reader = PCAPReader(pcap_path)
    packets = list(reader.read_packets())
    assert len(packets) == 1
    assert packets[0].data == b"\x01\x02\x03\x04\x05"
    reader.close()


def test_big_endian_microsecond_pcap() -> None:
    """Verify parsing big-endian microsecond captures."""
    # Big-endian magic 0xa1b2c3d4 encoded in >I
    hdr = struct.pack(">IHHiIII", MAGIC_MICRO_LE, 2, 4, 0, 0, 65535, 1)
    rec = struct.pack(">IIII", 1700000000, 100000, 4, 4) + b"TEST"

    reader = PCAPReader(hdr + rec)
    assert reader.header.is_little_endian is False
    assert reader.header.is_nanosecond is False

    pkts = list(reader.read_packets())
    assert len(pkts) == 1
    assert pkts[0].data == b"TEST"
    assert abs(pkts[0].timestamp - 1700000000.1) < 0.0001


def test_little_endian_nanosecond_pcap() -> None:
    """Verify parsing little-endian nanosecond captures."""
    hdr = struct.pack("<IHHiIII", MAGIC_NANO_LE, 2, 4, 0, 0, 65535, 1)
    rec = struct.pack("<IIII", 1700000000, 500000000, 4, 4) + b"NANO"

    reader = PCAPReader(hdr + rec)
    assert reader.header.is_little_endian is True
    assert reader.header.is_nanosecond is True

    pkts = list(reader.read_packets())
    assert len(pkts) == 1
    assert pkts[0].data == b"NANO"
    assert abs(pkts[0].timestamp - 1700000000.5) < 0.0001


def test_big_endian_nanosecond_pcap() -> None:
    """Verify parsing big-endian nanosecond captures."""
    hdr = struct.pack(">IHHiIII", MAGIC_NANO_LE, 2, 4, 0, 0, 65535, 1)
    rec = struct.pack(">IIII", 1700000000, 250000000, 4, 4) + b"NANO"

    reader = PCAPReader(hdr + rec)
    assert reader.header.is_little_endian is False
    assert reader.header.is_nanosecond is True

    pkts = list(reader.read_packets())
    assert len(pkts) == 1
    assert pkts[0].data == b"NANO"
    assert abs(pkts[0].timestamp - 1700000000.25) < 0.0001


def test_pcap_format_error_too_short() -> None:
    """Verify error on capture under 24 bytes."""
    with pytest.raises(PCAPFormatError, match="smaller than 24-byte"):
        PCAPReader(b"\x00" * 10)


def test_pcap_format_error_invalid_magic() -> None:
    """Verify error on unrecognized magic number."""
    with pytest.raises(PCAPFormatError, match="Unrecognized PCAP magic number"):
        PCAPReader(b"\xff\xff\xff\xff" + b"\x00" * 20)


def test_pcap_corrupt_packet_header() -> None:
    """Verify error when packet record header is truncated."""
    buf = io.BytesIO()
    with PCAPWriter(buf):
        pass
    # append 8 bytes instead of 16-byte record header
    data = buf.getvalue() + b"\x00" * 8
    reader = PCAPReader(data)
    with pytest.raises(PCAPCorruptError, match="Truncated packet header"):
        list(reader.read_packets())


def test_pcap_corrupt_packet_data() -> None:
    """Verify error when packet record claims 20 bytes but file ends after 5."""
    buf = io.BytesIO()
    with PCAPWriter(buf):
        pass
    rec = struct.pack("<IIII", 1700000000, 0, 20, 20) + b"SHORT"
    data = buf.getvalue() + rec
    reader = PCAPReader(data)
    with pytest.raises(PCAPCorruptError, match="Truncated packet data"):
        list(reader.read_packets())
