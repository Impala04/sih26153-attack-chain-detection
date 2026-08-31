"""
Backend API for the predictive network security dashboard.

Currently serves realistic MOCK data so the frontend can be built and demoed
before the full model is trained end-to-end. Every function marked
"REPLACE WITH REAL MODEL" is the exact place to plug in the pipeline from
preprocessing.py / models.py / explainability.py.

Run:
    uvicorn app:app --reload --port 8000

Endpoints:
    GET  /api/hosts                    -> current risk score per monitored host
    GET  /api/hosts/{host_id}/trend    -> risk score over recent time windows
    GET  /api/hosts/{host_id}/explain  -> top features driving that host's risk
"""

import random
import time
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Predictive Network Security API")

# Allow the dashboard (opened as a local file or dev server) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Mock "network" state. REPLACE WITH REAL MODEL:
# In production this would instead read the latest windowed predictions
# coming out of TemporalRiskLSTM for each host, refreshed on a schedule
# (e.g. a background task recomputing every N seconds from live traffic).
# ---------------------------------------------------------------------------
HOSTS = [
    {"id": "10.0.0.12", "label": "Finance-DB-01"},
    {"id": "10.0.0.34", "label": "Web-Gateway-02"},
    {"id": "10.0.0.51", "label": "Employee-Laptop-118"},
    {"id": "10.0.0.77", "label": "SCADA-Controller-03"},
    {"id": "10.0.0.88", "label": "Backup-Server-01"},
]

# Simple in-memory "drift" simulation so scores evolve realistically each poll
_state = {h["id"]: {"risk": random.uniform(0.05, 0.2), "trend": []} for h in HOSTS}
_state["10.0.0.77"]["risk"] = 0.62  # seed one host as already elevated for the demo


def _step_simulation():
    """
    REPLACE WITH REAL MODEL: this function fakes the passage of time by
    nudging each host's risk score. In the real system, this is where you'd
    call TemporalRiskLSTM.forward() on the latest window of flow features
    for each host and store the returned probability.
    """
    now = datetime.utcnow()
    for host in HOSTS:
        hid = host["id"]
        current = _state[hid]["risk"]

        # SCADA controller has a scripted slow escalation for demo purposes
        if hid == "10.0.0.77":
            drift = random.uniform(0.01, 0.04)
        else:
            drift = random.uniform(-0.03, 0.03)

        new_risk = max(0.02, min(0.98, current + drift))
        _state[hid]["risk"] = new_risk
        _state[hid]["trend"].append({"t": now.isoformat(), "risk": round(new_risk, 3)})
        _state[hid]["trend"] = _state[hid]["trend"][-30:]  # keep last 30 points


def _severity(risk: float) -> str:
    if risk >= 0.7:
        return "critical"
    if risk >= 0.45:
        return "high"
    if risk >= 0.2:
        return "medium"
    return "low"


# Pre-seed some trend history so the chart isn't empty on first load
for _ in range(15):
    _step_simulation()


@app.get("/api/hosts")
def get_hosts():
    """Current risk snapshot for every monitored host."""
    _step_simulation()
    return [
        {
            "id": h["id"],
            "label": h["label"],
            "risk": round(_state[h["id"]]["risk"], 3),
            "severity": _severity(_state[h["id"]]["risk"]),
        }
        for h in HOSTS
    ]


@app.get("/api/hosts/{host_id}/trend")
def get_trend(host_id: str):
    if host_id not in _state:
        raise HTTPException(status_code=404, detail="Unknown host")
    return _state[host_id]["trend"]


@app.get("/api/hosts/{host_id}/explain")
def get_explanation(host_id: str):
    """
    REPLACE WITH REAL MODEL: call explain_prediction() from explainability.py
    on this host's latest window, using the trained RandomForest proxy +
    SHAP TreeExplainer. Return that ranked feature list in the same shape
    below so the frontend needs no changes.
    """
    if host_id not in _state:
        raise HTTPException(status_code=404, detail="Unknown host")

    risk = _state[host_id]["risk"]
    if host_id == "10.0.0.77":
        mock_features = [
            {"feature": "outbound_connections_rare_ports", "impact": 0.31, "direction": "increases risk"},
            {"feature": "failed_auth_attempts", "impact": 0.24, "direction": "increases risk"},
            {"feature": "avg_flow_duration", "impact": 0.11, "direction": "increases risk"},
            {"feature": "byte_count_variance", "impact": 0.08, "direction": "increases risk"},
            {"feature": "known_service_ratio", "impact": -0.05, "direction": "decreases risk"},
        ]
    else:
        mock_features = [
            {"feature": "byte_count_variance", "impact": 0.04, "direction": "increases risk"},
            {"feature": "known_service_ratio", "impact": -0.09, "direction": "decreases risk"},
            {"feature": "avg_flow_duration", "impact": 0.02, "direction": "increases risk"},
        ]

    return {
        "host_id": host_id,
        "risk": round(risk, 3),
        "severity": _severity(risk),
        "top_features": mock_features,
    }


@app.get("/")
def root():
    return {"status": "ok", "message": "Predictive Network Security API is running"}