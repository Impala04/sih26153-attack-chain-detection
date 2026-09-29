"""Risk provider backed by the repository's weighted Risk Engine.

This is a deterministic, rule/weighted engine (backend/risk_engine.py), not a
trained or scientifically validated model. It scores the strongest detection
using only signals present on the events; it does not use forecast values.
"""

from __future__ import annotations

from typing import Any, Dict

from src.contracts import RiskAssessment
from src.providers.risk_provider import RiskProvider


def _num(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return default if number != number else number  # NaN guard


class RealRiskEngine(RiskProvider):
    """Adapt AnalysisOrchestrator's risk context to backend.risk_engine."""

    def assess_risk(self, context: Dict[str, Any]) -> RiskAssessment:
        detections = [d for d in (context.get("detections") or []) if isinstance(d, dict)]
        if not detections:
            return RiskAssessment(risk_score=0.0, source="real")

        try:
            from backend.risk_engine import calculate_risk
        except ImportError:
            from risk_engine import calculate_risk

        anomaly = 0.0
        lateral = 0.0
        connections = 1.0
        for det in detections:
            ml = (det.get("metadata") or {}).get("ml_score") or {}
            feats = det.get("features") or {}
            anomaly = max(anomaly, _num(ml.get("anomaly_risk")))
            lateral = max(lateral, _num(feats.get("lateral_move_flag")))
            connections = max(connections, _num(feats.get("connection_count"), 1.0))

        row = {
            "anomaly_risk": anomaly,
            "lateral_move_flag": 1 if lateral > 0 else 0,
            "connection_count": connections,
        }
        result = calculate_risk(row)
        score = max(0.0, min(100.0, round(_num(result.get("risk_score")), 4)))
        return RiskAssessment(risk_score=score, source="real")