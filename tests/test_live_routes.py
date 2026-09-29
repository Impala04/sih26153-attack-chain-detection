"""Tests for the live sensor API routes (backend/live_routes.py).

The real LiveSensor is replaced with a fake, so no packets are captured.
"""
from dataclasses import dataclass

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend import live_routes
from src.live.sensor import LiveSensorError


@dataclass
class _Event:
    n: int


class _PlainEvent:
    def __init__(self, n):
        self.n = n


class FakeSensor:
    instances = []
    fail_on_start = False
    events_to_return = []

    def __init__(self, iface=None, bpf_filter=None):
        self.iface = iface
        self.bpf_filter = bpf_filter
        self._running = False
        FakeSensor.instances.append(self)

    def start(self):
        if FakeSensor.fail_on_start:
            raise LiveSensorError("capture not permitted")
        self._running = True

    def stop(self):
        self._running = False

    def status(self):
        return {"running": self._running, "error": None, "packets_seen": 0,
                "events_buffered": len(FakeSensor.events_to_return),
                "source": "live"}

    def events(self):
        return list(FakeSensor.events_to_return)


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    FakeSensor.instances = []
    FakeSensor.fail_on_start = False
    FakeSensor.events_to_return = []
    monkeypatch.setattr(live_routes, "_sensor", None)
    monkeypatch.setattr(live_routes, "LiveSensor", FakeSensor)


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(live_routes.router)
    return TestClient(app)


def test_status_is_idle_before_any_start(client):
    body = client.get("/api/live/status").json()
    assert body["running"] is False
    assert body["source"] == "live"


def test_events_empty_before_any_start(client):
    assert client.get("/api/live/events").json() == {"source": "live", "events": []}


def test_stop_without_sensor_returns_idle(client):
    response = client.post("/api/live/stop")
    assert response.status_code == 200
    assert response.json()["running"] is False


def test_start_passes_iface_and_filter(client):
    response = client.post("/api/live/start", params={"iface": "Wi-Fi", "bpf_filter": "tcp"})
    assert response.status_code == 200
    assert response.json()["running"] is True
    assert FakeSensor.instances[0].iface == "Wi-Fi"
    assert FakeSensor.instances[0].bpf_filter == "tcp"


def test_start_while_running_reuses_sensor(client):
    client.post("/api/live/start")
    response = client.post("/api/live/start")
    assert response.json()["running"] is True
    assert len(FakeSensor.instances) == 1


def test_start_after_stop_creates_new_sensor(client):
    client.post("/api/live/start")
    assert client.post("/api/live/stop").json()["running"] is False
    client.post("/api/live/start")
    assert len(FakeSensor.instances) == 2


def test_start_failure_returns_503_and_not_running(client):
    FakeSensor.fail_on_start = True
    response = client.post("/api/live/start")
    assert response.status_code == 503
    assert "capture not permitted" in response.json()["detail"]
    assert client.get("/api/live/status").json()["running"] is False


def test_events_returns_dicts_and_respects_limit(client):
    FakeSensor.events_to_return = [_Event(1), _PlainEvent(2), _Event(3)]
    client.post("/api/live/start")
    body = client.get("/api/live/events", params={"limit": 2}).json()
    assert body["source"] == "live"
    assert body["events"] == [{"n": 2}, {"n": 3}]


def test_main_app_exposes_live_routes():
    from backend.app import app as main_app
    main_client = TestClient(main_app)
    status = main_client.get("/api/live/status")
    assert status.status_code == 200
    assert status.json()["running"] is False
    events = main_client.get("/api/live/events")
    assert events.status_code == 200
    assert events.json() == {"source": "live", "events": []}