"""Shared, JSON-serializable contracts for the analysis pipeline.

These are the schemas that flow between pipeline stages and out through the
API. Unlike the internal dataclasses in ``src.processing.events`` and
``src.correlation.attack_chain`` (which are optimized for the detection/
correlation engines themselves), these are Pydantic models: the boundary
layer that validates data before it's returned to a caller.
"""

from .analysis_result import (
    AnalysisResult,
    ExplanationResult,
    FeatureImpact,
    ForecastResult,
    MitreMapping,
    RiskAssessment,
    StageProbability,
)

__all__ = [
    "AnalysisResult",
    "ExplanationResult",
    "FeatureImpact",
    "ForecastResult",
    "MitreMapping",
    "RiskAssessment",
    "StageProbability",
]
