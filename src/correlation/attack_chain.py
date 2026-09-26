"""JSON-serializable representation of a correlated attack chain."""

from dataclasses import dataclass, field
import json
from typing import List, Optional, Set

from src.processing.events import DetectionEvent


@dataclass
class AttackChain:
    """Related detection events observed over a bounded period of time."""

    chain_id: str
    source_hosts: Set[str]
    destination_hosts: Set[str]
    start_time: float
    last_seen: float
    events: List[DetectionEvent] = field(default_factory=list)
    stages: List[str] = field(default_factory=list)
    current_stage: Optional[str] = None
    confidence: float = 0.0
    is_active: bool = True

    def to_dict(self) -> dict:
        """Return a JSON-friendly copy of this chain."""
        return {
            "chain_id": self.chain_id,
            "source_hosts": sorted(self.source_hosts),
            "destination_hosts": sorted(self.destination_hosts),
            "start_time": self.start_time,
            "last_seen": self.last_seen,
            "events": [event.to_dict() for event in self.events],
            "stages": list(self.stages),
            "current_stage": self.current_stage,
            "confidence": self.confidence,
            "is_active": self.is_active,
        }

    def to_json(self) -> str:
        """Serialize this chain to JSON."""
        return json.dumps(self.to_dict(), sort_keys=True)
