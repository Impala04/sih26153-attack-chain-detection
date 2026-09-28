"""Risk engine provider: aggregates signals into one final risk score.

The real risk formula (per the project's own build-order notes) is meant to
combine anomaly score + MITRE stage severity + forecast confidence. This
mock implements exactly that combination using whatever pieces of context
are actually available, so it can be swapped for a more sophisticated real
engine later without changing the interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict

from src.contracts import RiskAssessment

# Rough per-tactic weight so a chain further along the kill chain scores
# higher risk for the same anomaly/forecast confidence. Placeholder values;
# the real risk engine should replace this with something justified.
_TACTIC_SEVERITY = {
    "Discovery": 0.3,
    "Command and Control": 0.5,
    "Lateral Movement": 0.7,
    "Exfiltration": 0.9,
    "Impact": 1.0,
}
_DEFAULT_TACTIC_SEVERITY = 0.4


class RiskProvider(ABC):
    """Interface every risk engine provider (real or mock) must satisfy."""

    @abstractmethod
    def assess_risk(self, context: Dict[str, Any]) -> RiskAssessment:
        """Return a RiskAssessment for the given context.

        ``context`` may carry "detections" (for anomaly confidence),
        "mitre" (a list of MitreMapping.to_dict()-shaped dicts, for stage
        severity), and "forecast" (a ForecastResult.to_dict()-shaped dict).
        Any of these may be missing; the mock degrades gracefully.
        """
        raise NotImplementedError


class MockRiskEngine(RiskProvider):
    """Deterministic combination of anomaly + MITRE severity + forecast confidence.

    risk_score (0-100) = 100 * weighted average of:
      - max detection confidence (0-1), weight 0.4
      - highest-severity MITRE tactic present (0-1), weight 0.3
      - forecast confidence (0-1), weight 0.3
    Missing pieces are dropped and the remaining weights renormalized, so a
    partial AnalysisResult (e.g. no forecast yet) still gets a sensible score
    rather than being silently penalized to zero.
    """

    def assess_risk(self, context: Dict[str, Any]) -> RiskAssessment:
        components = []  # list of (value, weight)

        detections = context.get("detections") or []
        confidences = [
            d.get("confidence", 0.0) for d in detections if isinstance(d, dict)
        ]
        if confidences:
            components.append((max(confidences), 0.4))

        mitre = context.get("mitre") or []
        severities = [
            _TACTIC_SEVERITY.get(m.get("tactic"), _DEFAULT_TACTIC_SEVERITY)
            for m in mitre
            if isinstance(m, dict)
        ]
        if severities:
            components.append((max(severities), 0.3))

        forecast = context.get("forecast")
        if isinstance(forecast, dict) and forecast.get("confidence") is not None:
            components.append((float(forecast["confidence"]), 0.3))

        if not components:
            risk_score = 0.0
        else:
            total_weight = sum(weight for _, weight in components)
            weighted_sum = sum(value * weight for value, weight in components)
            risk_score = 100.0 * (weighted_sum / total_weight)

        risk_score = max(0.0, min(100.0, round(risk_score, 4)))

        return RiskAssessment(risk_score=risk_score, source="mock")
