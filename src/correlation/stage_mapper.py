"""Interfaces for mapping detection events to attack-chain stages."""

from abc import ABC, abstractmethod

from src.processing.events import DetectionEvent


class StageMapper(ABC):
    """Map a processing detection event to an attack-chain stage label."""

    @abstractmethod
    def map_event(self, event: DetectionEvent) -> str:
        """Return the stage label for ``event``."""


class FallbackStageMapper(StageMapper):
    """Temporary, replaceable mapping for the detector's current event types.

    Simar's future MITRE mapper should implement ``StageMapper`` and be
    injected into ``AttackChainCorrelator`` without changing its logic.
    """

    _STAGES = {
        "potential_network_scan": "Discovery",
        "potential_flood": "Impact",
        # detector.py emits this only when lateral_move_flag == 1.
        "suspicious_traffic": "Lateral Movement",
    }


    def map_event(self, event: DetectionEvent) -> str:
        """Return the temporary stage label for a known detection type.

        Falls back to "Unknown" for any detection_type not yet in
        _STAGES, so an unrecognized event degrades correlation instead
        of raising KeyError and taking down the whole orchestrator.
        """
        return self._STAGES.get(event.detection_type, "Unknown")
