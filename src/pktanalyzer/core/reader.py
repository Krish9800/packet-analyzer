"""Zero-dependency binary PCAP file reader and writer."""

import io
import struct
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

from pktanalyzer.core.exceptions import PCAPCorruptError, PCAPFormatError
from pktanalyzer.models.enums import LinkType
from pktanalyzer.models.packet import RawPacket

# PCAP Magic Numbers
MAGIC_MICRO_LE = 0xA1B2C3D4  # Little-endian, microseconds
MAGIC_MICRO_BE = 0xD4C3B2A1  # Big-endian, microseconds
MAGIC_NANO_LE = 0xA1B23C4D  # Little-endian, nanoseconds
MAGIC_NANO_BE = 0x4D3CB2A1  # Big-endian, nanoseconds


class PCAPGlobalHeader:
    """Represents a 24-byte PCAP file global header."""

    def __init__(
        self,
        magic: int,
        version_major: int,
        version_minor: int,
        thiszone: int,
        sigfigs: int,
        snaplen: int,
        linktype: int,
        is_little_endian: bool,
        is_nanosecond: bool,
    ) -> None:
        self.magic = magic
        self.version_major = version_major
        self.version_minor = version_minor
        self.thiszone = thiszone
        self.sigfigs = sigfigs
        self.snaplen = snaplen
        self.linktype = linktype
        self.is_little_endian = is_little_endian
        self.is_nanosecond = is_nanosecond


class PCAPReader:
    """Binary reader for Libpcap capture files."""

    def __init__(self, source: str | Path | bytes | BinaryIO) -> None:
        """Initialize PCAP reader from file path, raw bytes, or stream."""
        if isinstance(source, (str, Path)):
            self._stream: BinaryIO = open(source, "rb")  # noqa: SIM115
            self._should_close = True
        elif isinstance(source, bytes):
            self._stream = io.BytesIO(source)
            self._should_close = False
        else:
            self._stream = source
            self._should_close = False

        self.header: PCAPGlobalHeader = self._read_global_header()

    def close(self) -> None:
        """Close underlying stream if owned."""
        if self._should_close and not self._stream.closed:
            self._stream.close()

    def __enter__(self) -> "PCAPReader":
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()

    def _read_global_header(self) -> PCAPGlobalHeader:
        """Parse and validate 24-byte Libpcap global header."""
        raw_header = self._stream.read(24)
        if len(raw_header) < 24:
            raise PCAPFormatError("File is smaller than 24-byte PCAP global header")

        magic_raw = raw_header[0:4]
        # Determine endianness and timestamp resolution
        magic_le = struct.unpack("<I", magic_raw)[0]
        if magic_le == MAGIC_MICRO_LE:
            endian = "<"
            is_le = True
            is_nano = False
        elif magic_le == MAGIC_NANO_LE:
            endian = "<"
            is_le = True
            is_nano = True
        else:
            magic_be = struct.unpack(">I", magic_raw)[0]
            if magic_be == MAGIC_MICRO_LE:
                endian = ">"
                is_le = False
                is_nano = False
            elif magic_be == MAGIC_NANO_LE:
                endian = ">"
                is_le = False
                is_nano = True
            else:
                raise PCAPFormatError(f"Unrecognized PCAP magic number: {magic_raw.hex()}")

        fmt = f"{endian}IHHiIII"
        fields = struct.unpack(fmt, raw_header)
        return PCAPGlobalHeader(
            magic=fields[0],
            version_major=fields[1],
            version_minor=fields[2],
            thiszone=fields[3],
            sigfigs=fields[4],
            snaplen=fields[5],
            linktype=fields[6],
            is_little_endian=is_le,
            is_nanosecond=is_nano,
        )

    def read_packets(self, ignore_errors: bool = False) -> Iterator[RawPacket]:
        """Stream packets from capture as RawPacket models.

        Args:
            ignore_errors: When True, cleanly stops iteration on truncated or corrupt
                           frames instead of raising PCAPCorruptError.
        """
        endian = "<" if self.header.is_little_endian else ">"
        rec_hdr_fmt = f"{endian}IIII"
        rec_hdr_size = struct.calcsize(rec_hdr_fmt)
        divisor = 1_000_000_000.0 if self.header.is_nanosecond else 1_000_000.0

        frame_num = 0
        while True:
            rec_hdr = self._stream.read(rec_hdr_size)
            if not rec_hdr:
                break
            if len(rec_hdr) < rec_hdr_size:
                if ignore_errors:
                    break
                raise PCAPCorruptError(
                    f"Truncated packet header at frame {frame_num + 1}: "
                    f"expected {rec_hdr_size} bytes, got {len(rec_hdr)}"
                )

            ts_sec, ts_sub, caplen, orig_len = struct.unpack(rec_hdr_fmt, rec_hdr)
            pkt_data = self._stream.read(caplen)
            if len(pkt_data) < caplen:
                if ignore_errors:
                    break
                raise PCAPCorruptError(
                    f"Truncated packet data at frame {frame_num + 1}: "
                    f"expected {caplen} bytes, got {len(pkt_data)}"
                )

            frame_num += 1
            timestamp = float(ts_sec) + (float(ts_sub) / divisor)
            yield RawPacket(
                frame_number=frame_num,
                timestamp=timestamp,
                caplen=caplen,
                wirelen=orig_len,
                data=pkt_data,
            )


class PCAPWriter:
    """Binary serializer to produce standard Libpcap capture files."""

    def __init__(
        self,
        target: str | Path | BinaryIO,
        linktype: LinkType | int = LinkType.ETHERNET,
        snaplen: int = 65535,
    ) -> None:
        """Initialize PCAP writer."""
        if isinstance(target, (str, Path)):
            self._stream: BinaryIO = open(target, "wb")  # noqa: SIM115
            self._should_close = True
        else:
            self._stream = target
            self._should_close = False

        self.linktype = int(linktype)
        self.snaplen = snaplen
        self._write_global_header()

    def _write_global_header(self) -> None:
        """Write standard little-endian microsecond 24-byte PCAP header."""
        header_bytes = struct.pack(
            "<IHHiIII",
            MAGIC_MICRO_LE,
            2,  # version_major
            4,  # version_minor
            0,  # thiszone
            0,  # sigfigs
            self.snaplen,
            self.linktype,
        )
        self._stream.write(header_bytes)

    def write_packet(self, data: bytes, timestamp: float | None = None) -> None:
        """Write a packet record to the PCAP stream."""
        if timestamp is None:
            import time

            timestamp = time.time()

        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1_000_000)
        caplen = min(len(data), self.snaplen)
        orig_len = len(data)

        rec_header = struct.pack("<IIII", ts_sec, ts_usec, caplen, orig_len)
        self._stream.write(rec_header)
        self._stream.write(data[:caplen])

    def close(self) -> None:
        """Close underlying stream if owned."""
        if self._should_close and not self._stream.closed:
            self._stream.close()

    def __enter__(self) -> "PCAPWriter":
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()
