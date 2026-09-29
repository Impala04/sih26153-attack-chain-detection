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
