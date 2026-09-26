"""Source-independent packet-to-detection processing pipeline."""

from datetime import datetime, timezone
from typing import List, Optional

from .detector import DetectionEngine
from .events import DetectionEvent
from .feature_extractor import FeatureExtractor
from .flow_tracker import FlowTracker
from .packet import ParsedPacket
from .window_manager import WindowManager


class ProcessingPipeline:
    """Process ParsedPacket objects from live, PCAP, or other adapters.

    Call ingest() for each packet in timestamp order. Call flush() when the
    input ends or the pipeline is stopping to emit remaining buffered flows.
    """

    def __init__(
        self,
        window_seconds: int = 30,
        idle_timeout_seconds: float = 60.0,
        detector: Optional[DetectionEngine] = None,
    ) -> None:
        self.flow_tracker = FlowTracker(
            idle_timeout_seconds=idle_timeout_seconds
        )
        self.window_manager = WindowManager(
            window_seconds=window_seconds
        )
        self.feature_extractor = FeatureExtractor()
        self.detector = detector or DetectionEngine()

    def ingest(self, packet: ParsedPacket) -> List[DetectionEvent]:
        """Ingest one normalized packet and return any ready detection events."""
        expired_flows = self.flow_tracker.ingest(packet)
        for flow in expired_flows:
            self.window_manager.add_completed_flow(flow)

        current_time = datetime.fromtimestamp(
            packet.timestamp,
            tz=timezone.utc,
        )
        ready_windows = self.window_manager.close_ready(
            current_time=current_time,
            active_flows=self.flow_tracker.active_flows,
        )
        return self._detect_windows(ready_windows)

    def flush(self) -> List[DetectionEvent]:
        """Finalize active flows and detect on all remaining windows."""
        for flow in self.flow_tracker.flush():
            self.window_manager.add_completed_flow(flow)

        remaining_windows = self.window_manager.flush()
        return self._detect_windows(remaining_windows)

    def _detect_windows(self, windows) -> List[DetectionEvent]:
        feature_rows = self.feature_extractor.extract(windows)
        events: List[DetectionEvent] = []

        for row in feature_rows:
            events.extend(self.detector.detect(row))

        return events