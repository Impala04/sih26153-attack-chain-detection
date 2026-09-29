"""Tests for AnalysisOrchestrator, focused on Phase 9 error handling."""

import re

import pytest

from src.correlation.mitre_stage_mapper import MitreStageMapper
from src.orchestrator import AnalysisOrchestrator
from src.processing.events import DetectionEvent
from src.providers.real_mitre_provider import RealMitreProvider


def make_event(detection_type: str, event_id: str = "evt-1") -> DetectionEvent:
    return DetectionEvent(
        event_id=event_id,
        timestamp=1000.0,
        window_start=970.0,
        window_end=1000.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        detection_type=detection_type,
        confidence=0.8,
        features={"unique_destinations": 12},
        evidence=["test evidence"],
    )


def test_analyze_handles_unrecognized_detection_type():
    """A single unrecognized detection_type doesn't crash, and the chain
    has no known current_stage yet (guard prevents assigning "Unknown")."""
    orchestrator = AnalysisOrchestrator()
    event = make_event("not_a_real_detection_type")
    result = orchestrator.analyze([event], "test")
    assert result.attack_chains
    assert result.attack_chains[0]["current_stage"] is None
    assert result.attack_chains[0]["stages"] == []


def test_analyze_handles_known_detection_types():
    """Happy path: recognized detection_type still correlates normally."""
    orchestrator = AnalysisOrchestrator()
    event = make_event("suspicious_traffic")
    result = orchestrator.analyze([event], "test")
    assert result.attack_chains
    assert result.attack_chains[0]["current_stage"] == "Lateral Movement"
    assert result.warnings == []


def test_analyze_mixed_batch_unknown_and_known_types():
    """A batch with one unrecognized type shouldn't corrupt the rest.

    These two events share hosts, so they correlate into a single chain.
    The known stage should remain current_stage; "Unknown" should not
    appear in the chain's stage history at all.
    """
    orchestrator = AnalysisOrchestrator()
    events = [
        make_event("suspicious_traffic", event_id="evt-1"),
        make_event("not_a_real_detection_type", event_id="evt-2"),
    ]
    result = orchestrator.analyze(events, "test")
    assert len(result.attack_chains) == 1
    chain = result.attack_chains[0]
    assert chain["current_stage"] == "Lateral Movement"
    assert "Unknown" not in chain["stages"]


def test_unknown_stage_does_not_overwrite_current_stage():
    """An unrecognized detection_type shouldn't erase a chain's known stage."""
    orchestrator = AnalysisOrchestrator()
    events = [
        make_event("suspicious_traffic", event_id="evt-1"),
        make_event("not_a_real_detection_type", event_id="evt-2"),
    ]
    result = orchestrator.analyze(events, "test")
    assert len(result.attack_chains) == 1
    chain = result.attack_chains[0]
    assert chain["current_stage"] == "Lateral Movement"
    assert "Unknown" not in chain["stages"]


def test_orchestrator_emits_real_attack_techniques():
    """With the real mapper and provider, results carry real ATT&CK IDs."""
    orchestrator = AnalysisOrchestrator(
        stage_mapper=MitreStageMapper(),
        mitre_provider=RealMitreProvider(),
    )
    event = DetectionEvent(
        event_id="evt-scan",
        timestamp=1000.0,
        window_start=970.0,
        window_end=1000.0,
        src_ip="203.0.113.5",
        dst_ip="10.0.0.2",
        detection_type="potential_network_scan",
        confidence=0.8,
        features={"unique_dst_ports": 25, "unique_destinations": 1},
        evidence=["test evidence"],
    )
    result = orchestrator.analyze([event], "test")

    assert result.mitre, "expected at least one real technique"
    ids = {m.technique_id for m in result.mitre}
    assert "T1595" in ids
    for m in result.mitre:
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", m.technique_id)
        assert m.source == "real"
    assert result.attack_chains[0]["current_stage"] == "Reconnaissance"
