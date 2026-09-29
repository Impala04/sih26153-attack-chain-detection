"""Pydantic contracts for pipeline stage outputs and the final API response.

Conventions carried over from the existing dataclasses (DetectionEvent,
AttackChain):
    - confidence values are floats in [0.0, 1.0]
    - timestamps are Unix epoch seconds (floats)
    - every model exposes a JSON round trip

New convention introduced here, since these are provider outputs that may
come from a real implementation or a placeholder:
    - every stage result carries a ``source: "real" | "mock"`` field, so a
      caller (and the orchestrator) can always tell whether a given piece of
      the response is a genuine model/provider result or a teammate's
      not-yet-built component standing in for one.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, model_validator

Source = Literal["real", "mock"]


class StageProbability(BaseModel):
    """One candidate next stage in a forecast, with its likelihood."""

    stage: str
    probability: float = Field(ge=0.0, le=1.0)


class FutureAttackProbability(BaseModel):
    """One model score for a particular future traffic window."""

    step: int = Field(ge=1)
    window_start: str
    probability: float = Field(ge=0.0, le=1.0)
    threshold: float = Field(ge=0.0, le=1.0)
    predicted_attack: bool


class ForecastResult(BaseModel):
    """A stage forecast from a mock or a future-attack score from the GRU.

    ``predicted_stage`` and ``probable_next_stages`` remain for compatibility
    with the current API. The GRU does not predict MITRE/attack-chain stages;
    for ``forecast_kind="attack_probability"`` use the explicit per-window
    ``future_attack_probabilities`` field instead.
    """

    predicted_stage: str
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    probable_next_stages: List[StageProbability] = Field(default_factory=list)
    time_window_seconds: float = Field(ge=0.0)
    source: Source
    forecast_kind: Literal["attack_stage", "attack_probability"] = "attack_stage"
    forecast_status: Literal["ready", "insufficient_history"] = "ready"
    future_attack_probabilities: List[FutureAttackProbability] = Field(default_factory=list)
    forecast_horizon_steps: int = Field(default=0, ge=0)
    probability_note: Optional[str] = None
    warning: Optional[str] = None

    @model_validator(mode="after")
    def _check_probabilities_sum(self) -> "ForecastResult":
        total = sum(item.probability for item in self.probable_next_stages)
        # Small floating-point slack; anything meaningfully over 1.0 is a bug.
        if total > 1.0 + 1e-6:
            raise ValueError(
                f"probable_next_stages probabilities sum to {total}, which exceeds 1.0"
            )
        return self


class MitreMapping(BaseModel):
    """A single MITRE ATT&CK technique mapped to observed behavior."""

    technique_id: str
    technique_name: str
    tactic: str
    confidence: float = Field(ge=0.0, le=1.0)
    source: Source


class FeatureImpact(BaseModel):
    """One feature's contribution to an explanation."""

    feature: str
    impact: float
    direction: str


class ExplanationResult(BaseModel):
    """Human-readable explanation of why a detection/risk score fired."""

    summary: str
    top_features: List[FeatureImpact] = Field(default_factory=list)
    source: Source


class RiskAssessment(BaseModel):
    """Final aggregated risk score for an analysis."""

    risk_score: float = Field(ge=0.0, le=100.0)
    severity: Literal["low", "medium", "high", "critical"] = "low"
    source: Source

    @model_validator(mode="after")
    def _derive_severity(self) -> "RiskAssessment":
        # Severity is always derived from risk_score, not independently
        # trusted input, so two RiskAssessments with the same score always
        # agree on severity regardless of what a caller passed in.
        score = self.risk_score
        if score >= 80:
            derived = "critical"
        elif score >= 60:
            derived = "high"
        elif score >= 30:
            derived = "medium"
        else:
            derived = "low"
        object.__setattr__(self, "severity", derived)
        return self


class AnalysisResult(BaseModel):
    """The single top-level object returned by the orchestrator and the API.

    ``detections`` and ``attack_chains`` are plain dicts (the output of
    DetectionEvent.to_dict() / AttackChain.to_dict()) rather than re-declared
    Pydantic models, so this contract never drifts out of sync with the
    existing dataclasses; it just carries their JSON-friendly shape.

    Every pipeline stage past detection/correlation is Optional, since the
    orchestrator must be able to build a partial, valid AnalysisResult even
    when a downstream provider (forecast, MITRE, explanation, risk) fails or
    is not yet available -- that failure is instead recorded in ``warnings``.
    """

    analysis_id: str
    timestamp: float
    input_source: str
    detections: List[Dict[str, Any]] = Field(default_factory=list)
    attack_chains: List[Dict[str, Any]] = Field(default_factory=list)
    forecast: Optional[ForecastResult] = None
    mitre: Optional[List[MitreMapping]] = None
    explanation: Optional[ExplanationResult] = None
    risk: Optional[RiskAssessment] = None
    warnings: List[str] = Field(default_factory=list)

    def to_json(self) -> str:
        """Serialize to a JSON string."""
        return self.model_dump_json()

    @classmethod
    def from_json(cls, data: str) -> "AnalysisResult":
        """Parse a JSON string back into an AnalysisResult."""
        return cls.model_validate_json(data)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-friendly dict, matching the existing dataclasses' convention."""
        return json.loads(self.to_json())
