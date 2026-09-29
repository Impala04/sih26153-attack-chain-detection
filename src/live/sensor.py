"""Live sensor: current packets -> ProcessingPipeline -> scored DetectionEvents.

Only current traffic is used. This module never reads host_features_v2*.csv or
any dataset. If capture cannot start it raises LiveSensorError; it never falls
back to stored data. Scores come from the same Isolation Forest scoring used
for PCAP input (trained on CIC-IDS2017 features), so treat them as anomaly
indicators, not verdicts.
"""

from __future__ import annotations

import threading
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Optional

from src.processing.events import DetectionEvent
from src.processing.pipeline import ProcessingPipeline


class LiveSensorError(RuntimeError):
    """Raised when live capture cannot run."""


def _default_score(event: DetectionEvent) -> Dict[str, Any]:
    from src.model.event_scoring import score_detection_event
    from src.model.score import DEFAULT_MODEL_PATH

    return score_detection_event(event, model_path=DEFAULT_MODEL_PATH)


def _default_sniffer(callback, iface=None, bpf_filter=None):
    from src.capture.live_sniffer import LiveSniffer

    return LiveSniffer(callback=callback, iface=iface, bpf_filter=bpf_filter)


class LiveSensor:
    def __init__(
        self,
        pipeline: Optional[ProcessingPipeline] = None,
        score_fn: Optional[Callable[[DetectionEvent], Dict[str, Any]]] = None,
        sniffer_factory: Optional[Callable[..., Any]] = None,
        iface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        flush_interval: float = 30.0,
        max_events: int = 1000,
    ) -> None:
        self.pipeline = pipeline or ProcessingPipeline()
        self._score = score_fn or _default_score
        self._sniffer_factory = sniffer_factory or _default_sniffer
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.flush_interval = flush_interval
        self._lock = threading.Lock()
        self._events: Deque[DetectionEvent] = deque(maxlen=max_events)
        self._sniffer = None
        self._flush_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._running = False
        self._error: Optional[str] = None
        self._packets_seen = 0

    def _collect(self, events: List[DetectionEvent]) -> List[DetectionEvent]:
        for event in events:
            try:
                event.metadata["ml_score"] = self._score(event)
            except Exception as exc:  # one bad event must not stop capture
                event.metadata["ml_score_error"] = str(exc)
            self._events.append(event)
        return events

    def handle_packet(self, packet) -> List[DetectionEvent]:
        with self._lock:
            self._packets_seen += 1
            return self._collect(self.pipeline.ingest(packet))

    def flush(self) -> List[DetectionEvent]:
        with self._lock:
            return self._collect(self.pipeline.flush())

    def events(self) -> List[DetectionEvent]:
        with self._lock:
            return list(self._events)

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "running": self._running,
                "error": self._error,
                "packets_seen": self._packets_seen,
                "events_buffered": len(self._events),
                "source": "live",
            }

    def _flush_loop(self) -> None:
        while not self._stop.wait(self.flush_interval):
            self.flush()

    def start(self) -> None:
        if self._running:
            raise LiveSensorError("Live sensor is already running")
        try:
            sniffer = self._sniffer_factory(
                callback=self.handle_packet,
                iface=self.iface,
                bpf_filter=self.bpf_filter,
            )
            sniffer.start()
        except Exception as exc:
            self._error = f"Live capture unavailable: {exc}"
            self._running = False
            raise LiveSensorError(self._error) from exc
        self._sniffer = sniffer
        self._error = None
        self._stop.clear()
        self._running = True
        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._flush_thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sniffer is not None:
            self._sniffer.stop()
        if self._flush_thread is not None:
            self._flush_thread.join(timeout=2.0)
        self._running = False
        self.flush()