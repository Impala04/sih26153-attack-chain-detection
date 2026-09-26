"""Track directional network flows from shared ParsedPacket objects."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from math import isfinite
from typing import Dict, List, Optional, Tuple

from .packet import ParsedPacket


FlowKey = Tuple[str, str, Optional[int], Optional[int], str]

DEFAULT_IDLE_TIMEOUT_SECONDS = 60.0


@dataclass
class FlowStats:
    """Statistics collected for one directional flow."""

    key: FlowKey
    first_seen: datetime
    last_seen: datetime
    packet_count: int = 0
    total_bytes: int = 0
    packet_sizes: List[int] = field(default_factory=list)
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0

    @property
    def duration_seconds(self) -> float:
        """Elapsed seconds between the first and last packet."""
        return max(0.0, (self.last_seen - self.first_seen).total_seconds())


class FlowTracker:
    """Track packets by the five-part directional flow key.

    ParsedPacket timestamps are Unix epoch seconds. They are converted to
    timezone-aware UTC datetimes for flow duration and expiration.
    Packets should arrive in timestamp order.
    """

    def __init__(
        self,
        idle_timeout_seconds: float = DEFAULT_IDLE_TIMEOUT_SECONDS,
    ) -> None:
        if idle_timeout_seconds <= 0:
            raise ValueError("idle_timeout_seconds must be greater than zero")

        self.idle_timeout_seconds = idle_timeout_seconds
        self._flows: Dict[FlowKey, FlowStats] = {}

    def ingest(self, packet: ParsedPacket) -> List[FlowStats]:
        """Add a packet and return any flows that expired before it arrived."""
        if not isfinite(packet.timestamp):
            raise ValueError("packet timestamp must be a finite Unix timestamp")
        if packet.packet_length < 0:
            raise ValueError("packet_length cannot be negative")

        timestamp = datetime.fromtimestamp(packet.timestamp, tz=timezone.utc)
        expired = self.expire(timestamp)

        protocol = packet.protocol.strip().upper()
        key: FlowKey = (
            packet.src_ip,
            packet.dst_ip,
            packet.src_port,
            packet.dst_port,
            protocol,
        )

        flow = self._flows.get(key)
        if flow is None:
            flow = FlowStats(
                key=key,
                first_seen=timestamp,
                last_seen=timestamp,
            )
            self._flows[key] = flow

        flow.first_seen = min(flow.first_seen, timestamp)
        flow.last_seen = max(flow.last_seen, timestamp)
        flow.packet_count += 1
        flow.total_bytes += packet.packet_length
        flow.packet_sizes.append(packet.packet_length)

        flags = (packet.tcp_flags or "").upper()
        flow.syn_count += int("S" in flags)
        flow.ack_count += int("A" in flags)
        flow.rst_count += int("R" in flags)
        flow.fin_count += int("F" in flags)

        return expired

    def process_packet(self, packet: ParsedPacket) -> List[FlowStats]:
        """Compatibility alias; new callers should use ingest()."""
        return self.ingest(packet)

    def expire(self, now: datetime) -> List[FlowStats]:
        """Remove and return flows idle for at least the configured timeout."""
        expired: List[FlowStats] = []

        for key, flow in list(self._flows.items()):
            idle_seconds = (now - flow.last_seen).total_seconds()
            if idle_seconds >= self.idle_timeout_seconds:
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