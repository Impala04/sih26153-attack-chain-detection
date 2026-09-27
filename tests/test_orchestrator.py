"""Tests for the Checkpoint 3 orchestrator: detections -> AnalysisResult."""

import pytest

from src.orchestrator import AnalysisOrchestrator
from src.processing.events import DetectionEvent
from src.providers.risk_provider import RiskProvider
from src.contracts import RiskAssessment


def _scan_event(event_id="e1", timestamp=1.0, src_ip="10.0.0.5", dst_ip="10.0.0.9"):
    return DetectionEvent(
        event_id=event_id,
        timestamp=timestamp,
        window_start=timestamp - 1,
        window_end=timestamp + 29,
        src_ip=src_ip,
        dst_ip=dst_ip,
        detection_type="potential_network_scan",
        confidence=0.7,
        features={"x": 1.0},
        evidence=["scan evidence"],
    )


def _lateral_event(event_id="e2", timestamp=40.0, src_ip="10.0.0.5", dst_ip="10.0.0.9"):
    return DetectionEvent(
        event_id=event_id,
        timestamp=timestamp,
        window_start=timestamp - 10,
        window_end=timestamp + 20,
        src_ip=src_ip,
        dst_ip=dst_ip,
        detection_type="suspicious_traffic",
        confidence=0.8,
        features={"y": 2.0},
        evidence=["lateral evidence"],
    )


def test_analyze_builds_result_with_all_providers():
    orchestrator = AnalysisOrchestrator()
    events = [_scan_event(), _lateral_event()]

    result = orchestrator.analyze(events, input_source="csv:test.csv")

    assert result.input_source == "csv:test.csv"
    assert result.warnings == []
    assert len(result.detections) == 2
    assert len(result.attack_chains) == 1
    assert result.attack_chains[0]["stages"] == ["Discovery", "Lateral Movement"]

    assert result.forecast is not None
    assert result.forecast.source == "mock"
    assert result.mitre is not None
    assert len(result.mitre) == 2  # one per distinct detection_type
    assert result.explanation is not None
    assert "suspicious_traffic" in result.explanation.summary
    assert result.risk is not None
    assert 0.0 <= result.risk.risk_score <= 100.0


def test_analyze_handles_empty_detections_gracefully():
    orchestrator = AnalysisOrchestrator()

    result = orchestrator.analyze([], input_source="csv:empty.csv")

    assert result.detections == []
    assert result.attack_chains == []
    assert result.warnings == []
    # Mock providers still return a deterministic result for an empty chain.
    assert result.forecast is not None
    assert result.mitre == []
    assert result.explanation.summary == "No detections available to explain."
    assert result.risk is not None


def test_provider_failure_is_recorded_as_warning_not_exception():
    class BrokenRiskProvider(RiskProvider):
        def assess_risk(self, context):
            raise RuntimeError("boom")

    orchestrator = AnalysisOrchestrator(risk_provider=BrokenRiskProvider())
    events = [_scan_event()]

    result = orchestrator.analyze(events, input_source="live")

    assert result.risk is None
    assert len(result.warnings) == 1
    assert "risk provider failed: boom" in result.warnings[0]
    # Other providers still ran fine.
    assert result.forecast is not None
    assert result.mitre is not None


def test_real_provider_can_be_injected_and_used():
    class StubRiskProvider(RiskProvider):
        def assess_risk(self, context):
            return RiskAssessment(risk_score=42.0, source="real")

    orchestrator = AnalysisOrchestrator(risk_provider=StubRiskProvider())
    result = orchestrator.analyze([_scan_event()], input_source="live")

    assert result.risk.risk_score == 42.0
    assert result.risk.source == "real"
    assert result.risk.severity == "medium"


def test_correlator_and_stage_mapper_are_mutually_exclusive():
    from src.correlation.correlator import AttackChainCorrelator
    from src.correlation.stage_mapper import FallbackStageMapper

    with pytest.raises(ValueError):
        AnalysisOrchestrator(
            correlator=AttackChainCorrelator(),
            stage_mapper=FallbackStageMapper(),
        )
