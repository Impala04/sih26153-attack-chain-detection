"""Real MITRE provider: wraps MitreStageMapper to emit contract MitreMapping entries."""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, List, Optional

from src.contracts import MitreMapping as ContractMitreMapping
from src.correlation.mitre_stage_mapper import MitreStageMapper
from src.processing.events import DetectionEvent
from src.providers.mitre_provider import MitreProvider

_EVENT_FIELDS = {f.name for f in dataclasses.fields(DetectionEvent)}


def _event_from_dict(d: Dict[str, Any]) -> DetectionEvent:
    return DetectionEvent(**{k: v for k, v in d.items() if k in _EVENT_FIELDS})


class RealMitreProvider(MitreProvider):
    """Maps detections to real ATT&CK techniques via MitreStageMapper.

    Tactic-only mappings (no technique asserted) are skipped. Confidence is
    the detection's confidence, not a separate certainty about the mapping.
    """

    def __init__(self, mapper: Optional[MitreStageMapper] = None) -> None:
        self.mapper = mapper or MitreStageMapper()

    def map_techniques(self, context: Dict[str, Any]) -> List[ContractMitreMapping]:
        best: Dict[str, ContractMitreMapping] = {}
        for det in context.get("detections") or []:
            if not isinstance(det, dict):
                continue
            event = _event_from_dict(det)
            detail = self.mapper.map_event_detail(event)
            if not detail.technique_id:
                continue
            mapping = ContractMitreMapping(
                technique_id=detail.technique_id,
                technique_name=detail.technique_name or detail.technique_id,
                tactic=detail.tactic,
                confidence=min(1.0, max(0.0, float(event.confidence))),
                source="real",
            )
            current = best.get(detail.technique_id)
            if current is None or mapping.confidence > current.confidence:
                best[detail.technique_id] = mapping
        return sorted(best.values(), key=lambda m: m.technique_id)
