import pytest

from src.orchestrator import build_production_orchestrator
from src.processing.events import DetectionEvent


def test_production_orchestrator_uses_real_mitre():
    event = DetectionEvent(
        event_id="e1", timestamp=1000.0, window_start=970.0, window_end=1000.0,
        src_ip="203.0.113.5", dst_ip="10.0.0.2",
        detection_type="potential_network_scan", confidence=0.8,
        features={"unique_dst_ports": 25, "unique_destinations": 1},
    )
    result = build_production_orchestrator().analyze([event], "test")
    assert {m.technique_id for m in result.mitre} >= {"T1595"}
    assert all(m.source == "real" for m in result.mitre)
    assert result.attack_chains[0]["current_stage"] == "Reconnaissance"


def test_production_orchestrator_requires_real_world_model(monkeypatch):
    import src.providers.world_model_provider as providers

    def unavailable(*args, **kwargs):
        raise RuntimeError("World Model unavailable")

    monkeypatch.setattr(providers, "RealWorldModelProvider", unavailable)
    with pytest.raises(RuntimeError, match="World Model unavailable"):
        build_production_orchestrator()
