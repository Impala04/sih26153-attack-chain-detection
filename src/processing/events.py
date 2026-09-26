"""Extensible event format returned by the processing detector."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DetectionEvent:
    """A cautious, evidence-backed suspicious-traffic event.

    Timestamps use Unix epoch seconds, matching ParsedPacket.
    """

    event_id: str
    timestamp: float
    window_start: float
    window_end: float
    src_ip: str
    dst_ip: Optional[str]
    detection_type: str
    confidence: float
    features: Dict[str, Any]
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-friendly dictionary; metadata can hold future fields."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "detection_type": self.detection_type,
            "confidence": self.confidence,
            "features": dict(self.features),
            "evidence": list(self.evidence),
            "metadata": dict(self.metadata),
        }