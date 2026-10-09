"""Cleartext credential and sensitive secret leakage detection engine."""

import base64
import contextlib
import re
import uuid

from pktanalyzer.models.enums import ThreatCategory, ThreatSeverity
from pktanalyzer.models.packet import DissectedPacket
from pktanalyzer.models.threats import SecurityAlert

SENSITIVE_BODY_PATTERNS = [
    re.compile(r"(?:password|passwd|pwd|pass)\s*[:=]\s*([^\s&]+)", re.IGNORECASE),
    re.compile(r"(?:api[_-]?key|secret|token|access[_-]?token)\s*[:=]\s*([^\s&]+)", re.IGNORECASE),
    re.compile(r"(?:authorization|bearer)\s+([a-zA-Z0-9\-_.]+)", re.IGNORECASE),
]


class CredentialLeakDetector:
    """Detects cleartext passwords, Basic Auth headers, and API keys over unencrypted HTTP."""

    def __init__(self) -> None:
        self._alerted_hashes: set[str] = set()

    def process_packet(self, packet: DissectedPacket) -> list[SecurityAlert]:
        """Analyze HTTP messages for cleartext secrets."""
        if not packet.http or not packet.http.is_request:
            return []

        http = packet.http
        ts = packet.timestamp
        src_ip = packet.src_endpoint
        dst_ip = packet.dst_endpoint
        alerts: list[SecurityAlert] = []

        # 1. Check Authorization Headers
        auth_header = http.headers.get("Authorization") or http.headers.get("authorization")
        if auth_header:
            if auth_header.startswith("Basic "):
                b64_val = auth_header[6:].strip()
                decoded = ""
                with contextlib.suppress(Exception):
                    decoded = base64.b64decode(b64_val).decode("utf-8", errors="replace")

                alert_key = f"BASIC:{src_ip}:{dst_ip}:{http.uri}"
                if alert_key not in self._alerted_hashes:
                    self._alerted_hashes.add(alert_key)
                    alerts.append(
                        SecurityAlert(
                            alert_id=f"LEAK-{uuid.uuid4().hex[:8].upper()}",
                            timestamp=ts,
                            category=ThreatCategory.CLEARTEXT_CREDENTIALS,
                            severity=ThreatSeverity.CRITICAL,
                            title="Cleartext HTTP Basic Authentication Exposed",
                            description=(
                                f"Host {src_ip} transmitted unencrypted Basic credentials "
                                f"to {dst_ip}{http.uri}"
                            ),
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            evidence={
                                "auth_type": "Basic",
                                "credential_pair": (
                                    f"{decoded.split(':')[0]}:***" if ":" in decoded else "***"
                                ),
                                "uri": http.uri,
                            },
                        )
                    )
            elif auth_header.startswith("Bearer "):
                alert_key = f"BEARER:{src_ip}:{dst_ip}:{http.uri}"
                if alert_key not in self._alerted_hashes:
                    self._alerted_hashes.add(alert_key)
                    alerts.append(
                        SecurityAlert(
                            alert_id=f"LEAK-{uuid.uuid4().hex[:8].upper()}",
                            timestamp=ts,
                            category=ThreatCategory.CLEARTEXT_CREDENTIALS,
                            severity=ThreatSeverity.HIGH,
                            title="Cleartext Bearer Token Transmitted Over HTTP",
                            description=(
                                f"Host {src_ip} transmitted an unencrypted Bearer token "
                                f"to {dst_ip}{http.uri}"
                            ),
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            evidence={"auth_type": "Bearer", "uri": http.uri},
                        )
                    )

        # 2. Check HTTP Request Body
        if http.body:
            for pattern in SENSITIVE_BODY_PATTERNS:
                match = pattern.search(http.body)
                if match:
                    leak_key = f"BODY:{src_ip}:{dst_ip}:{pattern.pattern}"
                    if leak_key not in self._alerted_hashes:
                        self._alerted_hashes.add(leak_key)
                        alerts.append(
                            SecurityAlert(
                                alert_id=f"LEAK-{uuid.uuid4().hex[:8].upper()}",
                                timestamp=ts,
                                category=ThreatCategory.CLEARTEXT_CREDENTIALS,
                                severity=ThreatSeverity.HIGH,
                                title="Cleartext Secret Exposed in HTTP Payload",
                                description=(
                                    f"Host {src_ip} submitted sensitive credential parameter "
                                    f"over cleartext HTTP to {dst_ip}"
                                ),
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                evidence={
                                    "matched_pattern": pattern.pattern,
                                    "uri": http.uri,
                                },
                            )
                        )
                    break

        return alerts
