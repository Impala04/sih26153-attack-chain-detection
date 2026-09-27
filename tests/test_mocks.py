"""Determinism: every mock must return byte-identical output for the same
input, on repeated calls and across fresh instances -- no randomness, no
wall-clock dependence, no reliance on dict ordering."""

from src.providers import MockExplainer, MockMitreMapper, MockRiskEngine, MockWorldModel


def test_mock_world_model_is_deterministic():
    context = {"attack_chain": {"chain_id": "c1", "current_stage": "Discovery"}}
    first = MockWorldModel().forecast(context)
    second = MockWorldModel().forecast(context)
    assert first == second


def test_mock_world_model_differs_for_different_input():
    result_a = MockWorldModel().forecast(
        {"attack_chain": {"chain_id": "c1", "current_stage": "Discovery"}}
    )
    result_b = MockWorldModel().forecast(
        {"attack_chain": {"chain_id": "c2", "current_stage": "Impact"}}
    )
    assert result_a.predicted_stage != result_b.predicted_stage or (
        result_a.confidence != result_b.confidence
    )


def test_mock_mitre_mapper_is_deterministic():
    context = {
        "detections": [
            {"detection_type": "potential_network_scan"},
            {"detection_type": "lateral_movement_suspected"},
        ]
    }
    first = MockMitreMapper().map_techniques(context)
    second = MockMitreMapper().map_techniques(context)
    assert first == second


def test_mock_mitre_mapper_ignores_detection_order():
    context_a = {
        "detections": [
            {"detection_type": "potential_network_scan"},
            {"detection_type": "lateral_movement_suspected"},
        ]
    }
    context_b = {
        "detections": [
            {"detection_type": "lateral_movement_suspected"},
            {"detection_type": "potential_network_scan"},
        ]
    }
    result_a = MockMitreMapper().map_techniques(context_a)
    result_b = MockMitreMapper().map_techniques(context_b)
    assert result_a == result_b


def test_mock_explainer_is_deterministic():
    context = {
        "detections": [
            {
                "detection_type": "potential_network_scan",
                "confidence": 0.8,
                "evidence": ["42 unique destination ports in 10s"],
                "features": {"unique_ports": 42, "flows_per_second": 3.5},
            }
        ]
    }
    first = MockExplainer().explain(context)
    second = MockExplainer().explain(context)
    assert first == second


def test_mock_explainer_features_are_order_independent():
    features_a = {"unique_ports": 42, "flows_per_second": 3.5}
    features_b = {"flows_per_second": 3.5, "unique_ports": 42}
    detection = {
        "detection_type": "potential_network_scan",
        "confidence": 0.8,
        "evidence": ["evidence"],
    }
    result_a = MockExplainer().explain({"detections": [{**detection, "features": features_a}]})
    result_b = MockExplainer().explain({"detections": [{**detection, "features": features_b}]})
    assert result_a.top_features == result_b.top_features


def test_mock_risk_engine_is_deterministic():
    context = {
        "detections": [{"confidence": 0.8}],
        "mitre": [{"tactic": "Lateral Movement"}],
        "forecast": {"confidence": 0.6},
    }
    first = MockRiskEngine().assess_risk(context)
    second = MockRiskEngine().assess_risk(context)
    assert first == second


def test_mock_risk_engine_higher_severity_tactic_scores_higher():
    base_detections = [{"confidence": 0.5}]
    low_severity = MockRiskEngine().assess_risk(
        {"detections": base_detections, "mitre": [{"tactic": "Discovery"}]}
    )
    high_severity = MockRiskEngine().assess_risk(
        {"detections": base_detections, "mitre": [{"tactic": "Impact"}]}
    )
    assert high_severity.risk_score > low_severity.risk_score
