"""Dissector for Domain Name System (DNS) protocol."""

import socket
import struct

from pktanalyzer.models.protocols import DNSMessage, DNSQuestion, DNSResourceRecord


def _parse_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Parse DNS domain name with label length encoding and compression pointers."""
    labels: list[str] = []
    jumped = False
    original_offset = offset
    max_hops = 20
    hops = 0

    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            if not jumped:
                offset += 1
            break

        # Pointer (RFC 1035 compression: top two bits set 0b11000000 = 0xC0)
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer_offset = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2
                jumped = True
            hops += 1
            if hops > max_hops:
                break
            offset = pointer_offset
        else:
            offset += 1
            if offset + length > len(data):
                break
            labels.append(data[offset : offset + length].decode("latin1", errors="replace"))
            offset += length

    name = ".".join(labels)
    return name, (original_offset if jumped else offset)


def dissect_dns(data: bytes) -> DNSMessage:
    """Parse DNS message including header, questions, and resource records."""
    if len(data) < 12:
        raise ValueError(f"Data too short for DNS header: {len(data)} < 12 bytes")

    tx_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    is_response = bool((flags >> 15) & 0x01)
    opcode = (flags >> 11) & 0x0F
    rcode = flags & 0x0F

    offset = 12
    questions: list[DNSQuestion] = []
    for _ in range(qdcount):
        if offset >= len(data):
            break
        name, offset = _parse_dns_name(data, offset)
        if offset + 4 > len(data):
            break
        qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        questions.append(DNSQuestion(name=name, qtype=qtype, qclass=qclass))

    answers: list[DNSResourceRecord] = []
    for _ in range(ancount):
        if offset >= len(data):
            break
        name, offset = _parse_dns_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            break
        rdata_raw = data[offset : offset + rdlength]
        offset += rdlength

        # Format rdata based on type
        rdata_str: str
        if rtype == 1 and len(rdata_raw) == 4:  # A
            rdata_str = socket.inet_ntoa(rdata_raw)
        elif rtype == 28 and len(rdata_raw) == 16:  # AAAA
            rdata_str = socket.inet_ntop(socket.AF_INET6, rdata_raw)
        elif rtype in (2, 5, 12):  # NS, CNAME, PTR
            rdata_name, _ = _parse_dns_name(data, offset - rdlength)
            rdata_str = rdata_name or rdata_raw.hex()
        elif rtype == 16:  # TXT
            rdata_str = rdata_raw.decode("utf-8", errors="replace")
        else:
            rdata_str = rdata_raw.hex()

        answers.append(
            DNSResourceRecord(
                name=name,
                rtype=rtype,
                rclass=rclass,
                ttl=ttl,
                rdata=rdata_str,
            )
        )

    return DNSMessage(
        transaction_id=tx_id,
        flags=flags,
        is_response=is_response,
        opcode=opcode,
        rcode=rcode,
        questions=questions,
        answers=answers,
    )
