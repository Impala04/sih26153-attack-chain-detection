"""Non-finite feature values must not crash MitreStageMapper."""
import pytest

from src.correlation.mitre_stage_mapper import MitreStageMapper
from src.processing.events import DetectionEvent

NON_FINITE = [float("nan"), float("inf"), float("-inf")]


def make_event(detection_type, src_ip, dst_ip="192.168.1.5",
               features=None, metadata=None):
    return DetectionEvent(
        event_id="e1", timestamp=1.0, window_start=0.0, window_end=1.0,
        src_ip=src_ip, dst_ip=dst_ip, detection_type=detection_type,
        confidence=0.9, features=features or {}, metadata=metadata or {},
    )


def test_finite_scan_still_maps_to_discovery_technique():
    # Control: proves the helper works, so failures below are about non-finite values.
    event = make_event("potential_network_scan", "192.168.1.9",
                       features={"unique_dst_ports": 5.0, "unique_dst_ips": 1.0})
    mapping = MitreStageMapper().map_event_detail(event)
    assert mapping.tactic == "Discovery"
    assert mapping.technique_id == "T1046"


@pytest.mark.parametrize("bad", NON_FINITE)
def test_external_scan_with_nonfinite_ports(bad):
    event = make_event("potential_network_scan", "8.8.8.8",
                       features={"unique_dst_ports": bad, "unique_dst_ips": 3.0})
    assert MitreStageMapper().map_event_detail(event).tactic == "Reconnaissance"


@pytest.mark.parametrize("bad", NON_FINITE)
def test_internal_scan_with_nonfinite_hosts(bad):
    event = make_event("potential_network_scan", "192.168.1.9",
                       features={"unique_dst_ports": 4.0, "unique_dst_ips": bad})
    assert MitreStageMapper().map_event_detail(event).tactic == "Discovery"


@pytest.mark.parametrize("bad", NON_FINITE)
def test_flood_with_nonfinite_rate_asserts_no_technique(bad):
    event = make_event("potential_flood", "8.8.8.8",
                       features={"packets_per_second": bad})
    mapping = MitreStageMapper().map_event_detail(event)
    assert mapping.tactic == "Impact"
    assert mapping.technique_id is None


@pytest.mark.parametrize("bad", NON_FINITE)
def test_lateral_with_nonfinite_features(bad):
    event = make_event("suspicious_traffic", "192.168.1.9",
                       features={"dst_port": bad, "unique_destinations": bad})
    mapping = MitreStageMapper().map_event_detail(event)
    assert mapping.tactic == "Lateral Movement"
    assert mapping.technique_id is None


@pytest.mark.parametrize("bad", NON_FINITE)
def test_lateral_with_nonfinite_metadata_port(bad):
    event = make_event("suspicious_traffic", "192.168.1.9",
                       features={"unique_destinations": 4.0},
                       metadata={"dst_port": bad})
    mapping = MitreStageMapper().map_event_detail(event)
    assert mapping.tactic == "Lateral Movement"
    assert mapping.technique_id is None
