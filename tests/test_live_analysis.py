from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend import live_routes

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


def test_unresolvable_target_is_400(monkeypatch):
    monkeypatch.setattr(live_routes, "_sensor", None)
    resp = client.post("/api/live/start", params={"target": "no-such-host.invalid"})
    assert resp.status_code == 400


def test_ip_target_resolves_without_dns():
    assert live_routes._resolve_target("192.168.10.5")["ips"] == ["192.168.10.5"]
