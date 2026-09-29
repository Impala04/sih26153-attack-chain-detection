from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend import live_routes
from src.contracts import AnalysisResult
from src.orchestrator import AnalysisOrchestrator
from src.processing.events import DetectionEvent

app = FastAPI()
app.include_router(live_routes.router)
client = TestClient(app)


class FakeSensor:
    def events(self):
        return []

    def status(self):
        return {"running": True, "error": None, "packets_seen": 0,
                "events_buffered": 0, "source": "live"}


def test_analysis_not_started(monkeypatch):
    monkeypatch.setattr(live_routes, "_sensor", None)
    body = client.get("/api/live/analysis").json()
    assert body["state"] == "not_started"
    assert body["result"] is None


def test_analysis_no_relevant_traffic(monkeypatch):
    monkeypatch.setattr(live_routes, "_sensor", FakeSensor())
    body = client.get("/api/live/analysis").json()
    assert body["state"] == "no_relevant_traffic"
    assert "safe" not in body["message"].lower()


def test_analysis_returns_valid_result_for_captured_events(monkeypatch):
    event = DetectionEvent(
        event_id="live-event", timestamp=1000.0, window_start=970.0,
        window_end=1000.0, src_ip="10.0.0.5", dst_ip="10.0.0.10",
        detection_type="potential_network_scan", confidence=0.8,
        features={"unique_dst_ports": 10, "syn_ratio": 0.8},
    )

    class PopulatedSensor(FakeSensor):
        def events(self):
            return [event]

    monkeypatch.setattr(live_routes, "_sensor", PopulatedSensor())
    monkeypatch.setattr(
        "src.orchestrator.build_production_orchestrator",
        lambda: AnalysisOrchestrator(),
    )
    response = client.get("/api/live/analysis")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["state"] == "analyzed"
    assert body["source"] == "live"
    AnalysisResult.model_validate(body["result"])


def test_analysis_returns_503_when_real_world_model_is_unavailable(monkeypatch):
    event = DetectionEvent(
        event_id="live-event", timestamp=1000.0, window_start=970.0,
        window_end=1000.0, src_ip="10.0.0.5", dst_ip="10.0.0.10",
        detection_type="potential_network_scan", confidence=0.8,
        features={},
    )

    class PopulatedSensor(FakeSensor):
        def events(self):
            return [event]

    def unavailable():
        raise FileNotFoundError("World Model weights not found")

    monkeypatch.setattr(live_routes, "_sensor", PopulatedSensor())
    monkeypatch.setattr("src.orchestrator.build_production_orchestrator", unavailable)
    response = client.get("/api/live/analysis")

    assert response.status_code == 503
    assert "real World Model is unavailable" in response.json()["detail"]


def test_unresolvable_target_is_400(monkeypatch):
    monkeypatch.setattr(live_routes, "_sensor", None)
    resp = client.post("/api/live/start", params={"target": "no-such-host.invalid"})
    assert resp.status_code == 400


def test_ip_target_resolves_without_dns():
    assert live_routes._resolve_target("192.168.10.5")["ips"] == ["192.168.10.5"]
