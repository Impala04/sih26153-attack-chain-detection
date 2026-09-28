"""Tests for the MITRE stage mapper and its integration with the correlator."""

import json

import pytest

from src.correlation.correlator import AttackChainCorrelator
from src.correlation.mitre_stage_mapper import (
    EVIDENCE_TACTIC_ONLY,
    EVIDENCE_TECHNIQUE,
    UNKNOWN_STAGE,
    MitreStageMapper,
    annotate_event,
    describe_progression,
)
from src.correlation.stage_mapper import FallbackStageMapper
from src.processing.detector import DetectionEngine
from src.processing.events import DetectionEvent


def make_event(detection_type, src_ip="10.0.0.5", dst_ip="10.0.0.9", features=None,
               metadata=None, event_id="e1", timestamp=1000.0):
    return DetectionEvent(
        event_id=event_id,
        timestamp=timestamp,
        window_start=timestamp - 60,
        window_end=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        detection_type=detection_type,
        confidence=0.7,
        features=features or {},
        metadata=metadata or {},
    )


@pytest.fixture
def mapper():
    return MitreStageMapper()


# ---- scans -------------------------------------------------------------
def test_external_port_scan_is_reconnaissance(mapper):
    event = make_event("potential_network_scan", src_ip="203.0.113.50",
                       features={"unique_dst_ports": 40, "unique_dst_ips": 1})
    result = mapper.map_event_detail(event)
    assert (result.tactic, result.technique_id) == ("Reconnaissance", "T1595")
    assert result.tactic_id == "TA0043"
    assert result.evidence_level == EVIDENCE_TECHNIQUE


def test_external_host_sweep_uses_ip_block_subtechnique(mapper):
    event = make_event("potential_network_scan", src_ip="203.0.113.50", dst_ip=None,
                       features={"unique_dst_ports": 2, "unique_dst_ips": 60})
    assert mapper.map_event_detail(event).technique_id == "T1595.001"


def test_internal_port_scan_is_discovery_t1046(mapper):
    event = make_event("potential_network_scan",
                       features={"unique_dst_ports": 40, "unique_dst_ips": 1})
    result = mapper.map_event_detail(event)
    assert (result.tactic, result.technique_id) == ("Discovery", "T1046")
    assert result.technique_name == "Network Service Discovery"


def test_internal_host_sweep_is_discovery_t1018(mapper):
    event = make_event("potential_network_scan", dst_ip=None,
                       features={"unique_dst_ports": 2, "unique_dst_ips": 30})
    assert mapper.map_event_detail(event).technique_id == "T1018"


def test_alias_feature_names_are_understood(mapper):
    # detector.py also accepts unique_ports / unique_destinations
    event = make_event("potential_network_scan",
                       features={"unique_ports": 40, "unique_destinations": 1})
    assert mapper.map_event_detail(event).technique_id == "T1046"


def test_scan_without_fanout_features_asserts_no_technique(mapper):
    result = mapper.map_event_detail(make_event("potential_network_scan"))
    assert result.tactic == "Discovery"
    assert result.technique_id is None
    assert result.evidence_level == EVIDENCE_TACTIC_ONLY


def test_scan_between_two_external_hosts_is_tactic_only(mapper):
    event = make_event("potential_network_scan", src_ip="203.0.113.50",
                       dst_ip="198.51.100.7", features={"unique_dst_ports": 40})
    result = mapper.map_event_detail(event)
    assert result.tactic == "Reconnaissance"
    assert result.technique_id is None


def test_unparseable_source_ip_falls_back_to_discovery(mapper):
    event = make_event("potential_network_scan", src_ip="not-an-ip",
                       features={"unique_dst_ports": 40})
    assert mapper.map_event(event) == "Discovery"


def test_custom_internal_network_changes_classification():
    lab = MitreStageMapper(internal_networks=["192.168.10.0/24"])
    attacker = make_event("potential_network_scan", src_ip="172.16.0.1",
                          dst_ip="192.168.10.50", features={"unique_dst_ports": 40})
    assert lab.map_event(attacker) == "Reconnaissance"


# ---- floods ------------------------------------------------------------
def test_flood_maps_to_impact_direct_network_flood(mapper):
    event = make_event("potential_flood", features={"packets_per_second": 5000.0})
    result = mapper.map_event_detail(event)
    assert (result.tactic, result.technique_id) == ("Impact", "T1498.001")
    assert "packets_per_second=5000" in result.rationale


def test_flood_without_rate_features_is_tactic_only(mapper):
    result = mapper.map_event_detail(make_event("potential_flood"))
    assert result.tactic == "Impact"
    assert result.technique_id is None


# ---- lateral movement --------------------------------------------------
@pytest.mark.parametrize("port,technique", [
    (445, "T1021.002"), (3389, "T1021.001"), (22, "T1021.004"),
    (5985, "T1021.006"), (5900, "T1021.005"),
])
def test_lateral_movement_with_remote_service_port(mapper, port, technique):
    event = make_event("suspicious_traffic",
                       features={"unique_destinations": 12, "dst_port": port})
    result = mapper.map_event_detail(event)
    assert (result.tactic, result.technique_id) == ("Lateral Movement", technique)


def test_lateral_movement_without_port_evidence_is_tactic_only(mapper):
    event = make_event("suspicious_traffic", features={"unique_destinations": 12})
    result = mapper.map_event_detail(event)
    assert result.tactic == "Lateral Movement"
    assert result.technique_id is None
    assert result.evidence_level == EVIDENCE_TACTIC_ONLY


def test_lateral_movement_from_external_source_is_flagged(mapper):
    event = make_event("suspicious_traffic", src_ip="203.0.113.50",
                       features={"unique_destinations": 12, "dst_port": 445})
    result = mapper.map_event_detail(event)
    assert result.technique_id is None
    assert "outside the internal networks" in result.rationale


# ---- unknown / proposed types -----------------------------------------
def test_unknown_type_returns_unknown_by_default(mapper):
    assert mapper.map_event(make_event("brand_new_type")) == UNKNOWN_STAGE


def test_strict_mode_raises_on_unknown_type():
    with pytest.raises(ValueError):
        MitreStageMapper(strict=True).map_event(make_event("brand_new_type"))


def test_proposed_types_are_off_by_default(mapper):
    assert mapper.map_event(make_event("potential_brute_force")) == UNKNOWN_STAGE


def test_proposed_types_when_enabled():
    opted_in = MitreStageMapper(enable_proposed_types=True)
    brute = opted_in.map_event_detail(make_event("potential_brute_force"))
    assert (brute.tactic, brute.technique_id) == ("Credential Access", "T1110")
    assert opted_in.map_event(make_event("potential_beaconing")) == "Command and Control"
    assert opted_in.map_event(make_event("potential_exfiltration")) == "Exfiltration"


# ---- contract / regression ---------------------------------------------
def test_map_event_returns_plain_string(mapper):
    assert isinstance(mapper.map_event(make_event("potential_flood")), str)


@pytest.mark.parametrize("detection_type", [
    "potential_network_scan", "potential_flood", "suspicious_traffic",
])
def test_agrees_with_fallback_mapper_for_internal_sources(mapper, detection_type):
    event = make_event(detection_type, features={"unique_dst_ports": 40})
    assert mapper.map_event(event) == FallbackStageMapper().map_event(event)


def test_annotate_event_writes_json_safe_metadata(mapper):
    event = make_event("potential_flood", features={"packets_per_second": 5000.0})
    annotate_event(event, mapper)
    assert event.metadata["mitre"]["technique_id"] == "T1498.001"
    json.dumps(event.to_dict())  # must stay serializable


def test_describe_progression_is_informational():
    steps = describe_progression(["Reconnaissance", "Discovery", "Lateral Movement", "Discovery"])
    assert [s["relation"] for s in steps] == ["forward", "forward", "backward"]
    assert describe_progression(["Discovery", "Unknown"])[0]["relation"] == "unknown"


# ---- end to end with the team's REAL detector + correlator --------------
def _row(src, dst, end, **values):
    base = {"src_ip": src, "dst_ip": dst, "window_start": end - 60.0, "window_end": end}
    base.update(values)
    return base


def test_end_to_end_with_real_detector_and_correlator():
    engine = DetectionEngine()
    rows = [
        # external host scans a protected host
        _row("203.0.113.50", "10.0.0.5", 1060.0, unique_dst_ports=25, unique_dst_ips=1,
             syn_ratio=0.9, connection_attempt_rate=10.0),
        # that host is now compromised and sweeps the internal network
        _row("10.0.0.5", None, 1120.0, unique_dst_ports=2, unique_dst_ips=15,
             syn_ratio=0.85, connection_attempt_rate=9.0),
        # then fans out over SMB
        _row("10.0.0.5", None, 1180.0, lateral_move_flag=1, unique_destinations=12,
             dst_port=445, syn_ratio=0.1),
        # then floods an external target
        _row("10.0.0.5", "198.51.100.7", 1240.0, packets_per_second=5000.0),
    ]
    events = [event for row in rows for event in engine.detect(row)]
    assert len(events) == 4

    correlator = AttackChainCorrelator(stage_mapper=MitreStageMapper())
    for event in events:
        annotate_event(event, correlator.stage_mapper)
    chains = correlator.correlate(events)

    assert len(chains) == 1
    chain = chains[0]
    assert chain.stages == ["Reconnaissance", "Discovery", "Lateral Movement", "Impact"]
    assert chain.current_stage == "Impact"

    payload = json.loads(chain.to_json())
    techniques = [e["metadata"]["mitre"]["technique_id"] for e in payload["events"]]
    assert techniques == ["T1595", "T1018", "T1021.002", "T1498.001"]
