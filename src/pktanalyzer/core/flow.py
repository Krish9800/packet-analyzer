"""TCP Conversation Flow Tracking and Stream Reassembly Engine."""

import hashlib
from dataclasses import dataclass, field
from typing import NamedTuple

from pktanalyzer.models.enums import IPProtocol, TCPFlag
from pktanalyzer.models.packet import DissectedPacket


class FlowEndpoint(NamedTuple):
    """Network address and transport port."""

    ip: str
    port: int


class FlowKey(NamedTuple):
    """Bidirectional 5-tuple canonical conversation key."""

    ep1: FlowEndpoint
    ep2: FlowEndpoint
    protocol: int

    @classmethod
    def from_endpoints(
        cls, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: int
    ) -> "FlowKey":
        """Construct canonical symmetric flow key."""
        ep_a = FlowEndpoint(src_ip, src_port)
        ep_b = FlowEndpoint(dst_ip, dst_port)
        if (ep_a.ip, ep_a.port) <= (ep_b.ip, ep_b.port):
            return cls(ep1=ep_a, ep2=ep_b, protocol=protocol)
        return cls(ep1=ep_b, ep2=ep_a, protocol=protocol)


@dataclass
class HalfStream:
    """Unidirectional byte stream reassembler tracking sequence numbers."""

    initial_seq: int | None = None
    next_expected_seq: int = 0
    buffer: bytearray = field(default_factory=bytearray)
    out_of_order: dict[int, bytes] = field(default_factory=dict)
    total_payload_bytes: int = 0

    def add_segment(self, seq: int, data: bytes) -> None:
        """Add segment, handling in-order appending and out-of-order reordering."""
        if not data:
            return

        self.total_payload_bytes += len(data)

        if self.initial_seq is None:
            self.initial_seq = seq
            self.next_expected_seq = seq

        # If data is in-order
        if seq == self.next_expected_seq:
            self.buffer.extend(data)
            self.next_expected_seq += len(data)
            self._drain_out_of_order()
        elif seq > self.next_expected_seq:
            # Out-of-order segment: cache until missing bytes arrive
            self.out_of_order[seq] = data
        else:
            # Overlapping or retransmission
            end_seq = seq + len(data)
            if end_seq > self.next_expected_seq:
                overlap = self.next_expected_seq - seq
                self.buffer.extend(data[overlap:])
                self.next_expected_seq = end_seq
                self._drain_out_of_order()

    def _drain_out_of_order(self) -> None:
        """Drain queued out-of-order segments that are now contiguous."""
        while self.next_expected_seq in self.out_of_order:
            chunk = self.out_of_order.pop(self.next_expected_seq)
            self.buffer.extend(chunk)
            self.next_expected_seq += len(chunk)


@dataclass
class FlowSession:
    """Full-duplex conversation session record."""

    session_id: str
    initiator_ip: str
    initiator_port: int
    responder_ip: str
    responder_port: int
    protocol_name: str
    start_time: float
    last_time: float
    packet_count: int = 0
    total_bytes: int = 0
    client_bytes: int = 0
    server_bytes: int = 0
    tcp_state: str = "ESTABLISHED"
    client_stream: HalfStream = field(default_factory=HalfStream)
    server_stream: HalfStream = field(default_factory=HalfStream)

    @property
    def duration(self) -> float:
        """Conversation duration in seconds."""
        return max(0.0, self.last_time - self.start_time)

    @property
    def reassembled_client_data(self) -> bytes:
        """Reconstructed client-to-server stream."""
        return bytes(self.client_stream.buffer)

    @property
    def reassembled_server_data(self) -> bytes:
        """Reconstructed server-to-client stream."""
        return bytes(self.server_stream.buffer)


class FlowTracker:
    """Stateful engine tracking conversations and reassembling TCP streams."""

    def __init__(self, idle_timeout_seconds: float = 60.0) -> None:
        self.idle_timeout_seconds = idle_timeout_seconds
        self.sessions: dict[FlowKey, FlowSession] = {}

    def process_packet(self, packet: DissectedPacket) -> FlowSession | None:
        """Update flow session state with packet and return associated session."""
        src_ip: str | None = None
        dst_ip: str | None = None
        src_port: int = 0
        dst_port: int = 0
        proto_num: int = 0

        if packet.ipv4:
            src_ip = packet.ipv4.src_ip
            dst_ip = packet.ipv4.dst_ip
            proto_num = packet.ipv4.protocol
        elif packet.ipv6:
            src_ip = packet.ipv6.src_ip
            dst_ip = packet.ipv6.dst_ip
            proto_num = packet.ipv6.next_header

        if not src_ip or not dst_ip:
            return None

        if packet.tcp:
            src_port = packet.tcp.src_port
            dst_port = packet.tcp.dst_port
            proto_num = int(IPProtocol.TCP)
        elif packet.udp:
            src_port = packet.udp.src_port
            dst_port = packet.udp.dst_port
            proto_num = int(IPProtocol.UDP)

        flow_key = FlowKey.from_endpoints(src_ip, src_port, dst_ip, dst_port, proto_num)

        if flow_key not in self.sessions:
            sess_id_raw = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}@{packet.timestamp}"
            session_id = hashlib.sha256(sess_id_raw.encode()).hexdigest()[:16]
            proto_str = (
                "TCP"
                if proto_num == int(IPProtocol.TCP)
                else ("UDP" if proto_num == int(IPProtocol.UDP) else f"Proto-{proto_num}")
            )
            session = FlowSession(
                session_id=session_id,
                initiator_ip=src_ip,
                initiator_port=src_port,
                responder_ip=dst_ip,
                responder_port=dst_port,
                protocol_name=proto_str,
                start_time=packet.timestamp,
                last_time=packet.timestamp,
            )
            self.sessions[flow_key] = session
        else:
            session = self.sessions[flow_key]
            session.last_time = max(session.last_time, packet.timestamp)

        wire_len = (
            packet.ipv4.total_length
            if packet.ipv4
            else (packet.ipv6.payload_length + 40 if packet.ipv6 else 0)
        )
        session.packet_count += 1
        session.total_bytes += wire_len

        is_client = src_ip == session.initiator_ip and src_port == session.initiator_port

        # Stream reassembly for TCP
        if packet.tcp:
            payload = packet.tcp.payload_bytes
            flags = packet.tcp.flags

            if flags & int(TCPFlag.SYN) and not (flags & int(TCPFlag.ACK)):
                session.tcp_state = "SYN_SENT"
            elif flags & int(TCPFlag.SYN) and (flags & int(TCPFlag.ACK)):
                session.tcp_state = "SYN_RECEIVED"
            elif flags & (int(TCPFlag.FIN) | int(TCPFlag.RST)):
                session.tcp_state = "CLOSED"

            if is_client:
                session.client_bytes += wire_len
                session.client_stream.add_segment(packet.tcp.seq_number, payload)
            else:
                session.server_bytes += wire_len
                session.server_stream.add_segment(packet.tcp.seq_number, payload)
        elif is_client:
            session.client_bytes += wire_len
        else:
            session.server_bytes += wire_len

        return session

    def get_all_sessions(self) -> list[FlowSession]:
        """Return all active and completed conversation sessions."""
        return list(self.sessions.values())
