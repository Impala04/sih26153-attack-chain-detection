"""MITRE ATT&CK mapping provider: maps observed behavior to techniques."""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from typing import Any, Dict, List

from src.contracts import MitreMapping

# A small, fixed lookup table keyed by detection_type, used by the mock so
# outputs read as plausible mappings rather than arbitrary noise. This is
# NOT a claim of correctness -- Simar's real mapper replaces this entirely.
_KNOWN_TECHNIQUES = [
    ("T1046", "Network Service Discovery", "Discovery"),
    ("T1071", "Application Layer Protocol", "Command and Control"),
    ("T1021", "Remote Services", "Lateral Movement"),
    ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    ("T1499", "Endpoint Denial of Service", "Impact"),
]


class MitreProvider(ABC):
    """Interface every MITRE mapping provider (real or mock) must satisfy."""

    @abstractmethod
    def map_techniques(self, context: Dict[str, Any]) -> List[MitreMapping]:
        """Return zero or more MitreMapping entries for the given context.

        ``context`` typically carries "detections" (a list of
        DetectionEvent.to_dict()) and/or "attack_chain" (AttackChain.to_dict()).
        """
        raise NotImplementedError


class MockMitreMapper(MitreProvider):
    """Deterministic placeholder mapper.

    Picks one technique per distinct detection_type present in the input,
    derived from a hash of the detection_type string (not randomness), so
    the same detections always produce the same mappings.
    """

    def map_techniques(self, context: Dict[str, Any]) -> List[MitreMapping]:
        detections = context.get("detections") or []
        detection_types = sorted(
            {
                d.get("detection_type")
                for d in detections
                if isinstance(d, dict) and d.get("detection_type")
            }
        )

        if not detection_types:
            return []

        mappings: List[MitreMapping] = []
        for detection_type in detection_types:
            digest = hashlib.sha256(detection_type.encode("utf-8")).hexdigest()
            index = int(digest[:8], 16) % len(_KNOWN_TECHNIQUES)
            technique_id, technique_name, tactic = _KNOWN_TECHNIQUES[index]
            confidence = round(0.5 + (int(digest[8:12], 16) % 40) / 100.0, 4)  # 0.50-0.89

            mappings.append(
                MitreMapping(
                    technique_id=technique_id,
                    technique_name=technique_name,
                    tactic=tactic,
                    confidence=confidence,
                    source="mock",
                )
            )

        return mappings
