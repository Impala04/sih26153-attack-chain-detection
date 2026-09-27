"""Interface conformance: every mock must satisfy its provider ABC and
return the correct contract type."""

from src.contracts import ExplanationResult, ForecastResult, MitreMapping, RiskAssessment
from src.providers import (
    ExplainerProvider,
    MitreProvider,
    MockExplainer,
    MockMitreMapper,
    MockRiskEngine,
    MockWorldModel,
    RiskProvider,
    WorldModelProvider,
)


def test_mock_world_model_satisfies_interface():
    provider = MockWorldModel()
    assert isinstance(provider, WorldModelProvider)
    result = provider.forecast({"attack_chain": {"chain_id": "c1", "current_stage": "Discovery"}})
    assert isinstance(result, ForecastResult)
    assert result.source == "mock"


def test_mock_mitre_mapper_satisfies_interface():
    provider = MockMitreMapper()
    assert isinstance(provider, MitreProvider)
    result = provider.map_techniques(
        {"detections": [{"detection_type": "potential_network_scan"}]}
    )
    assert all(isinstance(item, MitreMapping) for item in result)
    assert all(item.source == "mock" for item in result)


def test_mock_explainer_satisfies_interface():
    provider = MockExplainer()
    assert isinstance(provider, ExplainerProvider)
    result = provider.explain(
        {
            "detections": [
                {
                    "detection_type": "potential_network_scan",
                    "confidence": 0.8,
                    "evidence": ["42 unique destination ports in 10s"],
                    "features": {"unique_ports": 42},
                }
            ]
        }
    )
    assert isinstance(result, ExplanationResult)
    assert result.source == "mock"


def test_mock_risk_engine_satisfies_interface():
    provider = MockRiskEngine()
    assert isinstance(provider, RiskProvider)
    result = provider.assess_risk({"detections": [{"confidence": 0.8}]})
    assert isinstance(result, RiskAssessment)
    assert result.source == "mock"


def test_mock_world_model_handles_empty_context():
    provider = MockWorldModel()
    result = provider.forecast({})
    assert isinstance(result, ForecastResult)


def test_mock_mitre_mapper_handles_no_detections():
    provider = MockMitreMapper()
    assert provider.map_techniques({}) == []


def test_mock_explainer_handles_no_detections():
    provider = MockExplainer()
    result = provider.explain({})
    assert result.top_features == []
    assert "No detections" in result.summary


def test_mock_risk_engine_handles_empty_context():
    provider = MockRiskEngine()
    result = provider.assess_risk({})
    assert result.risk_score == 0.0
    assert result.severity == "low"
