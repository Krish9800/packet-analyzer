"""Dissector for Hypertext Transfer Protocol (HTTP/1.x)."""

import contextlib

from pktanalyzer.models.protocols import HTTPMessage

HTTP_METHODS = {
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "PATCH",
    "CONNECT",
    "TRACE",
}


def dissect_http(data: bytes) -> HTTPMessage:
    """Parse HTTP/1.x request or response payload."""
    if len(data) < 10:
        raise ValueError("Data too short for HTTP message")

    # Split headers and body
    delimiter = b"\r\n\r\n"
    body_raw: bytes = b""
    if delimiter in data:
        header_part, body_raw = data.split(delimiter, 1)
    elif b"\n\n" in data:
        header_part, body_raw = data.split(b"\n\n", 1)
    else:
        header_part = data

    header_text = header_part.decode("iso-8859-1", errors="replace")
    lines = header_text.splitlines()
    if not lines:
        raise ValueError("Empty HTTP message")

    first_line = lines[0].strip()
    parts = first_line.split(" ")

    is_request = False
    method: str | None = None
    uri: str | None = None
    version = "HTTP/1.1"
    status_code: int | None = None
    reason_phrase: str | None = None

    if parts[0] in HTTP_METHODS and len(parts) >= 2:
        is_request = True
        method = parts[0]
        uri = parts[1]
        if len(parts) >= 3:
            version = parts[2]
    elif parts[0].startswith("HTTP/") and len(parts) >= 2:
        is_request = False
        version = parts[0]
        with contextlib.suppress(ValueError):
            status_code = int(parts[1])
        if len(parts) >= 3:
            reason_phrase = " ".join(parts[2:])
    else:
        raise ValueError("Not a recognizable HTTP/1.x request or response line")

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            name, val = line.split(":", 1)
            headers[name.strip()] = val.strip()

    body: str | None = None
    if body_raw:
        body = body_raw.decode("utf-8", errors="replace")

    return HTTPMessage(
        is_request=is_request,
        method=method,
        uri=uri,
        version=version,
        status_code=status_code,
        reason_phrase=reason_phrase,
        headers=headers,
        body=body,
    )
