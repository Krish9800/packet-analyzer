"""Adversarial security tests for fuzzing, malformed frames, and resource exhaustion."""

import struct

import pytest

from pktanalyzer.core.exceptions import PCAPCorruptError, PCAPFormatError
from pktanalyzer.core.reader import PCAPReader
from pktanalyzer.dissectors import PacketDissector, dissect_dns, dissect_ipv4, dissect_tcp
from pktanalyzer.models.packet import RawPacket


def test_circular_dns_compression_pointer_dos() -> None:
    """Verify that circular DNS compression pointers terminate without infinite loop."""
    # DNS header: ID=1, Flags=0, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    hdr = struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0)
    # Self-referencing pointer: offset 12 points to offset 12 (0xC00C)
    looping_qname = b"\xc0\x0c" + struct.pack("!HH", 1, 1)
    malicious_dns = hdr + looping_qname

    # Should safely terminate with max_hops and return empty or partial name
    dns = dissect_dns(malicious_dns)
    assert dns.transaction_id == 1
    # Pointer loop must not hang process
    assert len(dns.questions) == 1


def test_corrupt_magic_bytes_rejected() -> None:
    """Verify arbitrary corrupted magic numbers are immediately rejected."""
    bad_magics = [b"\x00\x00\x00\x00", b"\xff\xff\xff\xff", b"PK\x03\x04", b"\x7fELF"]
    for magic in bad_magics:
        data = magic + (b"\x00" * 20)
        with pytest.raises(PCAPFormatError):
            PCAPReader(data)


def test_packet_declared_length_overflow() -> None:
    """Verify parser rejects records claiming gigabytes of data with premature EOF."""
    hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    # Packet header claims 0x7FFFFFFF bytes, but file ends immediately
    rec = struct.pack("<IIII", 1700000000, 0, 0x7FFFFFFF, 0x7FFFFFFF)
    with pytest.raises(PCAPCorruptError):
        reader = PCAPReader(hdr + rec)
        list(reader.read_packets())


def test_dissector_fuzzing_resilience() -> None:
    """Verify dissectors handle random truncated byte garbage without unhandled crash."""
    dissector = PacketDissector()

    fuzz_payloads = [
        b"",
        b"\x00",
        b"\xff" * 13,  # 1 byte short of Ethernet
        b"\x00" * 14,  # Ethernet with zero payload
        b"\x00" * 33,  # Truncated IPv4
        b"\x45\x00\x00\x50" + (b"\x00" * 10),  # Declared length > actual length
        b"\x4f\x00\x00\x20" + (b"\x00" * 16),  # Max IHL (15*4=60 bytes) but only 20 bytes given
    ]

    for idx, payload in enumerate(fuzz_payloads):
        raw = RawPacket(
            frame_number=idx + 1,
            timestamp=1700000000.0,
            caplen=len(payload),
            wirelen=len(payload),
            data=payload,
        )
        # Must execute cleanly and return DissectedPacket without crashing
        res = dissector.dissect(raw)
        assert res.frame_number == idx + 1


def test_tcp_and_ipv4_boundary_violations() -> None:
    """Verify boundary checks on TCP and IPv4 parsing."""
    # IPv4 IHL=0
    with pytest.raises(ValueError):
        dissect_ipv4(b"\x40\x00\x00\x14" + b"\x00" * 16)

    # TCP Data Offset=0
    with pytest.raises(ValueError):
        dissect_tcp(struct.pack("!HHIIHHHH", 80, 80, 0, 0, 0, 1024, 0, 0))
