from src.orchestrator import AnalysisOrchestrator
from src.providers.real_risk_engine import RealRiskEngine


def _det(anomaly_risk, lateral=0, connections=1):
    return {
        "features": {"lateral_move_flag": lateral, "connection_count": connections},
        "metadata": {"ml_score": {"anomaly_risk": anomaly_risk}},
    }


def test_orchestrator_default_risk_is_real():
    assert isinstance(AnalysisOrchestrator().risk_provider, RealRiskEngine)


def test_no_detections_gives_zero_risk():
    result = RealRiskEngine().assess_risk({"detections": []})
    assert result.risk_score == 0.0
    assert result.source == "real"


def test_higher_anomaly_gives_higher_risk():
    low = RealRiskEngine().assess_risk({"detections": [_det(5)]})
    high = RealRiskEngine().assess_risk({"detections": [_det(90, lateral=1, connections=20)]})
    assert high.risk_score > low.risk_score
    assert 0.0 <= low.risk_score <= 100.0
    assert 0.0 <= high.risk_score <= 100.0


def test_deterministic_and_missing_fields_ok():
    ctx = {"detections": [_det(40), {"features": {}, "metadata": {}}]}
    first = RealRiskEngine().assess_risk(ctx)
    second = RealRiskEngine().assess_risk(ctx)
    assert first == second
    assert first.source == "real"