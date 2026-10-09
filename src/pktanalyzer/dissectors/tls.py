"""Dissector for Transport Layer Security (TLS) records and handshake metadata."""

import contextlib
import struct

from pktanalyzer.models.protocols import TLSMessage


def dissect_tls(data: bytes) -> TLSMessage:
    """Parse TLS record header, handshake message and extract SNI hostname."""
    if len(data) < 5:
        raise ValueError(f"Data too short for TLS record header: {len(data)} < 5 bytes")

    content_type, major, minor, record_len = struct.unpack("!BBBH", data[:5])

    # Validate TLS major version (typically SSL 3.0 / TLS 1.x is major 3)
    if major != 3 or content_type not in (20, 21, 22, 23, 24):
        raise ValueError("Invalid TLS record header markers")

    is_handshake = content_type == 22
    handshake_type: int | None = None
    sni_hostname: str | None = None

    if is_handshake and len(data) >= 9:
        handshake_type = data[5]
        # ClientHello is handshake type 1
        if handshake_type == 1:
            with contextlib.suppress(Exception):
                offset = 9  # Skip 5-byte record hdr + 4-byte handshake hdr
                # Skip Client Version (2 bytes) + Random (32 bytes)
                offset += 2 + 32
                if offset < len(data):
                    # Session ID length
                    sess_len = data[offset]
                    offset += 1 + sess_len

                if offset + 2 <= len(data):
                    # Cipher suites length
                    cipher_len = struct.unpack("!H", data[offset : offset + 2])[0]
                    offset += 2 + cipher_len

                if offset < len(data):
                    # Compression methods length
                    comp_len = data[offset]
                    offset += 1 + comp_len

                if offset + 2 <= len(data):
                    # Extensions length
                    ext_total_len = struct.unpack("!H", data[offset : offset + 2])[0]
                    ext_end = min(len(data), offset + 2 + ext_total_len)
                    offset += 2

                    while offset + 4 <= ext_end:
                        ext_type, ext_len = struct.unpack("!HH", data[offset : offset + 4])
                        offset += 4
                        ext_payload = data[offset : offset + ext_len]

                        # Extension 0 is server_name (SNI)
                        if ext_type == 0 and len(ext_payload) >= 5:
                            # 2 bytes list len, 1 byte type (0=host_name), 2 bytes host len
                            name_type = ext_payload[2]
                            host_len = struct.unpack("!H", ext_payload[3:5])[0]
                            if name_type == 0 and len(ext_payload) >= 5 + host_len:
                                sni_hostname = ext_payload[5 : 5 + host_len].decode(
                                    "ascii", errors="replace"
                                )
                                break
                        offset += ext_len

    return TLSMessage(
        content_type=content_type,
        version_major=major,
        version_minor=minor,
        length=record_len,
        is_handshake=is_handshake,
        handshake_type=handshake_type,
        sni_hostname=sni_hostname,
    )
