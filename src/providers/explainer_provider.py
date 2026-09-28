"""Explainability provider: produces a human-readable rationale for a result."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List

from src.contracts import ExplanationResult, FeatureImpact


class ExplainerProvider(ABC):
    """Interface every explainability provider (real or mock) must satisfy."""

    @abstractmethod
    def explain(self, context: Dict[str, Any]) -> ExplanationResult:
        """Return an ExplanationResult for the given context.

        ``context`` typically carries "detections" (a list of
        DetectionEvent.to_dict()), each of which already has its own
        "features" and "evidence" fields from the detection engine.
        """
        raise NotImplementedError


class MockExplainer(ExplainerProvider):
    """Deterministic placeholder explainer.

    Builds its summary and top_features directly from the highest-confidence
    detection's own ``features``/``evidence`` fields (already produced by the
    real detection engine), rather than inventing anything -- so this reads
    as a plausible explanation stand-in rather than random text, and is
    exactly reproducible for the same input. Real SHAP-based explanation
    replaces this later.
    """

    def explain(self, context: Dict[str, Any]) -> ExplanationResult:
        detections = context.get("detections") or []
        valid_detections = [d for d in detections if isinstance(d, dict)]

        if not valid_detections:
            return ExplanationResult(
                summary="No detections available to explain.",
                top_features=[],
                source="mock",
            )

        top_detection = max(
            valid_detections, key=lambda d: d.get("confidence", 0.0)
        )
        detection_type = top_detection.get("detection_type", "unknown behavior")
        confidence = top_detection.get("confidence", 0.0)
        evidence = top_detection.get("evidence") or []
        features = top_detection.get("features") or {}

        summary_parts = [
            f"Highest-confidence finding: {detection_type} (confidence {confidence:.2f})."
        ]
        if evidence:
            summary_parts.append(str(evidence[0]))
        summary = " ".join(summary_parts)

        # Sort feature items for determinism (dict insertion order is not
        # guaranteed to be stable across the pipeline's own runs).
        top_features: List[FeatureImpact] = []
        for name, value in sorted(features.items()):
            try:
                numeric_value = float(value)
            except (TypeError, ValueError):
                continue
            top_features.append(
                FeatureImpact(
                    feature=name,
                    impact=round(numeric_value, 4),
                    direction="above_normal" if numeric_value > 0 else "at_or_below_normal",
                )
            )

        return ExplanationResult(
            summary=summary,
            top_features=top_features,
            source="mock",
        )
