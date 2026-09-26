"""Track bidirectional network flows from shared ParsedPacket objects."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from math import isfinite
from typing import Dict, List, Optional, Tuple

from .packet import ParsedPacket


FlowKey = Tuple[str, str, Optional[int], Optional[int], str]

DEFAULT_FLOW_TIMEOUT_SECONDS = 120.0


@dataclass
class FlowStats:
    """Statistics for a bidirectional flow.

    The first observed packet's direction is forward. Reverse packets are
    counted as backward. If capture begins mid-connection, that first
    observed direction may not be the connection initiator's direction.
    """

    key: FlowKey
    first_seen: datetime
    last_seen: datetime
    packet_count: int = 0
    total_bytes: int = 0  # Full packet bytes, retained for diagnostics.
    packet_sizes: List[int] = field(default_factory=list)
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    forward_packet_count: int = 0
    backward_packet_count: int = 0
    forward_payload_bytes: int = 0
    backward_payload_bytes: int = 0

    @property
    def duration_seconds(self) -> float:
        """Elapsed seconds between the first and last observed packets."""
        return max(0.0, (self.last_seen - self.first_seen).total_seconds())

    @property
    def duration_microseconds(self) -> float:
        """Elapsed duration in microseconds, matching CICFlowMeter units."""
        return self.duration_seconds * 1_000_000


class FlowTracker:
    """Track bidirectional flows using IPs, ports, and protocol.

    The first packet observed for a 5-tuple defines the forward direction.
    ParsedPacket timestamps are Unix epoch seconds and are converted to
    timezone-aware UTC datetimes. Flows terminate on TCP FIN or after the
    configured maximum flow duration.
    """

    def __init__(
        self,
        flow_timeout_seconds: float = DEFAULT_FLOW_TIMEOUT_SECONDS,
    ) -> None:
        if flow_timeout_seconds <= 0:
            raise ValueError("flow_timeout_seconds must be greater than zero")

        self.flow_timeout_seconds = flow_timeout_seconds
        self._flows: Dict[FlowKey, FlowStats] = {}

    def ingest(self, packet: ParsedPacket) -> List[FlowStats]:
        """Add a packet and return flows expired before or by this packet."""
        if not isfinite(packet.timestamp):
            raise ValueError("packet timestamp must be a finite Unix timestamp")
        if packet.packet_length < 0:
            raise ValueError("packet_length cannot be negative")

        payload_length = getattr(packet, "payload_length", 0) or 0
        if payload_length < 0:
            raise ValueError("payload_length cannot be negative")

        timestamp = datetime.fromtimestamp(packet.timestamp, tz=timezone.utc)
        expired = self.expire(timestamp)

        protocol = packet.protocol.strip().upper()
        forward_key: FlowKey = (
            packet.src_ip,
            packet.dst_ip,
            packet.src_port,
            packet.dst_port,
            protocol,
        )
        reverse_key: FlowKey = (
            packet.dst_ip,
            packet.src_ip,
            packet.dst_port,
            packet.src_port,
            protocol,
        )

        flow = self._flows.get(forward_key)
        is_forward = flow is not None

        if flow is None:
            flow = self._flows.get(reverse_key)
            is_forward = False

        if flow is None:
            flow = FlowStats(
                key=forward_key,
                first_seen=timestamp,
                last_seen=timestamp,
            )
            self._flows[forward_key] = flow
            is_forward = True

        # Keep first_seen as the first packet observed, since that packet
        # determines the flow's forward direction.
        if timestamp > flow.last_seen:
            flow.last_seen = timestamp

        flow.packet_count += 1
        flow.total_bytes += packet.packet_length
        flow.packet_sizes.append(packet.packet_length)

        if is_forward:
            flow.forward_packet_count += 1
            flow.forward_payload_bytes += payload_length
        else:
            flow.backward_packet_count += 1
            flow.backward_payload_bytes += payload_length

        flags = (packet.tcp_flags or "").upper()
        flow.syn_count += int("S" in flags)
        flow.ack_count += int("A" in flags)
        flow.rst_count += int("R" in flags)
        flow.fin_count += int("F" in flags)

        # Count the FIN packet, then terminate the bidirectional TCP flow.
        if protocol == "TCP" and "F" in flags:
            expired.append(self._flows.pop(flow.key))

        return expired

    def process_packet(self, packet: ParsedPacket) -> List[FlowStats]:
        """Compatibility alias; new callers should use ingest()."""
        return self.ingest(packet)

    def expire(self, now: datetime) -> List[FlowStats]:
        """Remove flows that have reached the maximum duration."""
        expired: List[FlowStats] = []

        for key, flow in list(self._flows.items()):
            age_seconds = (now - flow.first_seen).total_seconds()
            if age_seconds >= self.flow_timeout_seconds:
                expired.append(self._flows.pop(key))

        return expired

    def flush(self) -> List[FlowStats]:
        """Return all tracked flows and clear the tracker."""
        remaining = list(self._flows.values())
        self._flows.clear()
        return remaining

    @property
    def active_flow_count(self) -> int:
        """Number of flows currently being tracked."""
        return len(self._flows)

    @property
    def active_flows(self) -> List[FlowStats]:
        """Current flows, for deciding which windows must remain open."""
        return list(self._flows.values())