"""DNS tunneling, DGA, and data exfiltration detection engine."""

import math
import uuid
from collections import Counter

from pktanalyzer.models.enums import ThreatCategory, ThreatSeverity
from pktanalyzer.models.packet import DissectedPacket
from pktanalyzer.models.threats import SecurityAlert


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy H(X) in bits per character."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class DNSTunnelDetector:
    """Detects high-entropy domain queries, oversized labels, and anomalous TXT exfil."""

    def __init__(self, entropy_threshold: float = 3.8, max_label_length: int = 45) -> None:
        self.entropy_threshold = entropy_threshold
        self.max_label_length = max_label_length
        self._alerted_queries: set[str] = set()

    def process_packet(self, packet: DissectedPacket) -> list[SecurityAlert]:
        """Analyze DNS message queries and resource records for tunneling anomalies."""
        if not packet.dns:
            return []

        dns = packet.dns
        ts = packet.timestamp
        src_ip = packet.src_endpoint
        alerts: list[SecurityAlert] = []

        # Analyze Questions
        for q in dns.questions:
            domain = q.name.lower()
            labels = domain.split(".")
            if not labels:
                continue

            # Evaluate leftmost subdomain labels
            for label in labels[:-2]:  # exclude TLD and second-level domain
                if not label:
                    continue

                entropy = calculate_shannon_entropy(label)
                label_len = len(label)

                is_suspicious_entropy = len(label) >= 12 and entropy >= self.entropy_threshold
                is_suspicious_length = label_len >= self.max_label_length

                if (
                    is_suspicious_entropy or is_suspicious_length
                ) and domain not in self._alerted_queries:
                    self._alerted_queries.add(domain)
                    reason = (
                        f"High Shannon entropy ({entropy:.2f} >= {self.entropy_threshold})"
                        if is_suspicious_entropy
                        else f"Excessive label length ({label_len} >= {self.max_label_length})"
                    )
                    alerts.append(
                        SecurityAlert(
                            alert_id=f"DNS-{uuid.uuid4().hex[:8].upper()}",
                            timestamp=ts,
                            category=ThreatCategory.DNS_TUNNELING,
                            severity=ThreatSeverity.HIGH,
                            title="DNS Tunneling / Data Exfiltration Anomaly",
                            description=f"Suspicious DNS query '{domain}' detected: {reason}",
                            src_ip=src_ip,
                            evidence={
                                "domain": domain,
                                "label": label,
                                "entropy": round(entropy, 3),
                                "label_length": label_len,
                                "qtype": q.qtype,
                            },
                        )
                    )

        # Analyze Answers for anomalous TXT payloads
        for ans in dns.answers:
            if ans.rtype == 16 and len(ans.rdata) > 200:  # TXT record > 200 bytes
                txt_key = f"TXT:{ans.name}:{len(ans.rdata)}"
                if txt_key not in self._alerted_queries:
                    self._alerted_queries.add(txt_key)
                    alerts.append(
                        SecurityAlert(
                            alert_id=f"DNS-{uuid.uuid4().hex[:8].upper()}",
                            timestamp=ts,
                            category=ThreatCategory.DNS_TUNNELING,
                            severity=ThreatSeverity.MEDIUM,
                            title="Large DNS TXT Record Payload (Possible Tunnel/C2)",
                            description=(
                                f"DNS response for {ans.name} returned unusually large TXT payload "
                                f"({len(ans.rdata)} bytes)"
                            ),
                            src_ip=src_ip,
                            evidence={
                                "domain": ans.name,
                                "payload_length": len(ans.rdata),
                                "ttl": ans.ttl,
                            },
                        )
                    )

        return alerts
