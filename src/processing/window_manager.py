"""Group completed flows into fixed time windows."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Tuple

from .flow_tracker import FlowStats


@dataclass
class TrafficWindow:
    """Completed flows for one source, destination, and time window."""

    src_ip: str
    dst_ip: str
    window_start: datetime
    window_seconds: int
    flows: List[FlowStats] = field(default_factory=list)

    @property
    def window_end(self) -> datetime:
        return self.window_start + timedelta(seconds=self.window_seconds)


WindowKey = Tuple[str, str, datetime]


class WindowManager:
    """Bucket completed flows by (src_ip, dst_ip, window_start).

    Flow timestamps must be timezone-aware UTC datetimes. A window can be
    emitted only after it has ended and none of its source's flows that began
    in that window are still active.
    """

    def __init__(self, window_seconds: int = 30) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than zero")

        self.window_seconds = window_seconds
        self._windows: Dict[WindowKey, TrafficWindow] = {}

    def get_window_start(self, timestamp: datetime) -> datetime:
        """Return the UTC-aligned start of the window containing timestamp."""
        epoch_seconds = timestamp.timestamp()
        bucket_epoch = (
            int(epoch_seconds // self.window_seconds) * self.window_seconds
        )
        return datetime.fromtimestamp(bucket_epoch, tz=timestamp.tzinfo)

    def add_completed_flow(self, flow: FlowStats) -> None:
        """Add a finalized flow to the window where it started."""
        src_ip, dst_ip = flow.key[0], flow.key[1]
        window_start = self.get_window_start(flow.first_seen)
        key: WindowKey = (src_ip, dst_ip, window_start)

        window = self._windows.get(key)
        if window is None:
            window = TrafficWindow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                window_start=window_start,
                window_seconds=self.window_seconds,
            )
            self._windows[key] = window

        window.flows.append(flow)

    def close_ready(
        self,
        current_time: datetime,
        active_flows: Iterable[FlowStats],
    ) -> List[TrafficWindow]:
        """Return ended source windows with no still-active flow from them."""
        current_window = self.get_window_start(current_time)

        active_source_windows = {
            (flow.key[0], self.get_window_start(flow.first_seen))
            for flow in active_flows
        }

        ready_keys = [
            key
            for key in self._windows
            if key[2] < current_window
            and (key[0], key[2]) not in active_source_windows
        ]

        ready_keys.sort(key=lambda key: (key[2], key[0], key[1]))
        return [self._windows.pop(key) for key in ready_keys]

    def flush(self) -> List[TrafficWindow]:
        """Return all buffered windows, for orderly shutdown or offline input."""
        keys = sorted(
            self._windows,
            key=lambda key: (key[2], key[0], key[1]),
        )
        return [self._windows.pop(key) for key in keys]