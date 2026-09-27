import json

import pytest
from pydantic import ValidationError

from src.contracts import (
    AnalysisResult,
    ExplanationResult,
    ForecastResult,
    MitreMapping,
    RiskAssessment,
    StageProbability,
)
from src.correlation.attack_chain import AttackChain
from src.processing.events import DetectionEvent


def _sample_event() -> DetectionEvent:
    return DetectionEvent(
        event_id="evt-1",
        timestamp=1000.0,
        window_start=990.0,
        window_end=1000.0,
        src_ip="10.0.0.5",
        dst_ip="10.0.0.9",
        detection_type="potential_network_scan",
        confidence=0.8,
        features={"unique_ports": 42},
        evidence=["42 unique destination ports in 10s"],
    )


def _sample_chain() -> AttackChain:
    return AttackChain(
        chain_id="chain-1",
        source_hosts={"10.0.0.5"},
        destination_hosts={"10.0.0.9"},
        start_time=990.0,
        last_seen=1005.0,
        events=[_sample_event()],
        stages=["Discovery"],
        current_stage="Discovery",
        confidence=0.8,
    )


def test_fully_populated_analysis_result_constructs():
    result = AnalysisResult(
        analysis_id="a1",
        timestamp=1000.0,
        input_source="test.csv",
        detections=[_sample_event().to_dict()],
        attack_chains=[_sample_chain().to_dict()],
        forecast=ForecastResult(
            predicted_stage="Lateral Movement",
            confidence=0.7,
            probable_next_stages=[
                StageProbability(stage="Lateral Movement", probability=0.7),
                StageProbability(stage="Impact", probability=0.2),
            ],
            time_window_seconds=300.0,
            source="mock",
        ),
        mitre=[
            MitreMapping(
                technique_id="T1046",
                technique_name="Network Service Discovery",
                tactic="Discovery",
                confidence=0.6,
                source="mock",
            )
        ],
        explanation=ExplanationResult(summary="High port fan-out", source="mock"),
        risk=RiskAssessment(risk_score=72.0, source="mock"),
        warnings=[],
    )
    assert result.risk.severity == "high"
    assert result.forecast.predicted_stage == "Lateral Movement"


def test_analysis_result_with_all_optional_fields_none():
    # Simulates an early pipeline stage: detection + correlation ran, nothing
    # downstream has executed yet.
    result = AnalysisResult(
        analysis_id="a2",
        timestamp=1000.0,
        input_source="test.csv",
        detections=[_sample_event().to_dict()],
        attack_chains=[],
        forecast=None,
        mitre=None,
        explanation=None,
        risk=None,
        warnings=["forecast unavailable: module not implemented"],
    )
    assert result.forecast is None
    assert result.risk is None
    # Must still serialize cleanly with everything None.
    parsed = json.loads(result.to_json())
    assert parsed["forecast"] is None
    assert parsed["risk"] is None


def test_risk_score_out_of_range_is_rejected():
    with pytest.raises(ValidationError):
        RiskAssessment(risk_score=150.0, source="mock")


def test_forecast_probabilities_over_one_is_rejected():
    with pytest.raises(ValidationError):
        ForecastResult(
            predicted_stage="Impact",
            confidence=0.5,
            probable_next_stages=[
                StageProbability(stage="Impact", probability=0.9),
                StageProbability(stage="Exfiltration", probability=0.6),
            ],
            time_window_seconds=60.0,
            source="mock",
        )


def test_severity_is_derived_not_trusted():
    # Passing a mismatched severity should not survive; it's recomputed.
    risk = RiskAssessment(risk_score=10.0, severity="critical", source="mock")
    assert risk.severity == "low"


def test_full_round_trip_with_real_nested_objects():
    event = _sample_event()
    chain = _sample_chain()

    original = AnalysisResult(
        analysis_id="a3",
        timestamp=1234.5,
        input_source="capture.pcap",
        detections=[event.to_dict()],
        attack_chains=[chain.to_dict()],
        forecast=ForecastResult(
            predicted_stage="Lateral Movement",
            confidence=0.65,
            probable_next_stages=[
                StageProbability(stage="Lateral Movement", probability=0.65)
            ],
            time_window_seconds=180.0,
            source="mock",
        ),
        mitre=None,
        explanation=None,
        risk=RiskAssessment(risk_score=45.0, source="mock"),
        warnings=["mitre unavailable: waiting on real mapper"],
    )

    raw_json = original.to_json()
    # Must be genuinely valid JSON, not just a Python repr.
    json.loads(raw_json)

    restored = AnalysisResult.from_json(raw_json)

    assert restored.analysis_id == original.analysis_id
    assert restored.detections == original.detections
    assert restored.attack_chains == original.attack_chains
    assert restored.forecast.predicted_stage == original.forecast.predicted_stage
    assert restored.risk.severity == "medium"
    assert restored.warnings == original.warnings
