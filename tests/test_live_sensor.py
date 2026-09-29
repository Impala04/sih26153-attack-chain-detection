import pytest

from src.capture.packet_schema import ParsedPacket
from src.live.sensor import LiveSensor, LiveSensorError

BASE = 1_735_732_800.0


def _syn(i, dst="10.0.0.10", dport=None):
    return ParsedPacket(
        timestamp=BASE + i,
        src_ip="10.0.0.5",
        dst_ip=dst,
        protocol="TCP",
        packet_length=54,
        src_port=40000 + i,
        dst_port=dport if dport is not None else 20 + i,
        tcp_flags="S",
    )


class FakeSniffer:
    def __init__(self, callback, iface=None, bpf_filter=None):
        self.callback = callback
        self.started = False

    def start(self):
        self.started = True

    def stop(self):
        self.started = False


class BrokenSniffer(FakeSniffer):
    def start(self):
        raise OSError("no capture permission")


def _scan(sensor):
    for i in range(10):
        sensor.handle_packet(_syn(i))
    return sensor.flush()


def test_live_packets_become_scored_detection_events():
    sensor = LiveSensor(sniffer_factory=FakeSniffer)
    events = _scan(sensor)
    assert events, "no detection events from live packets"
    assert "potential_network_scan" in [e.detection_type for e in events]
    for event in events:
        assert "ml_score" in event.metadata
        assert "ml_score_error" not in event.metadata
        assert 0.0 <= event.metadata["ml_score"]["anomaly_risk"] <= 100.0
    assert len(sensor.events()) == len(events)


def test_live_mode_never_loads_dataset_csvs(monkeypatch):
    import pandas as pd

    def boom(*args, **kwargs):
        raise AssertionError("live mode must not read CSV datasets")

    monkeypatch.setattr(pd, "read_csv", boom)
    monkeypatch.setattr("src.ingestion.csv_adapter.build_events_from_csv", boom)
    sensor = LiveSensor(sniffer_factory=FakeSniffer)
    assert _scan(sensor)


def test_capture_failure_is_explicit_and_returns_no_data():
    sensor = LiveSensor(sniffer_factory=BrokenSniffer)
    with pytest.raises(LiveSensorError, match="Live capture unavailable"):
        sensor.start()
    status = sensor.status()
    assert status["running"] is False
    assert "Live capture unavailable" in status["error"]
    assert sensor.events() == []


def test_start_stop_status():
    sensor = LiveSensor(sniffer_factory=FakeSniffer, flush_interval=3600)
    sensor.start()
    assert sensor.status()["running"] is True
    sensor.stop()
    assert sensor.status()["running"] is False