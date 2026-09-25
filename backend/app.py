"""CyberFlux API with replayable, already-scored traffic Demo Mode.

Run the feature builder and scorer first, then run this API from ``backend``:
``uvicorn app:app --reload --port 8000``.  By default the replay reads
``data/host_features_v2_scored.csv``; override it with ``DEMO_DATA_PATH``.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA_PATH = ROOT / "data" / "host_features_v2_scored.csv"
SCENARIOS = {"clean": "Clean traffic", "ddos": "DDoS burst", "infiltration": "Subtle infiltration"}

app = FastAPI(title="CyberFlux Demo API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


def column(frame: pd.DataFrame, *names: str) -> str | None:
    lookup = {str(name).lower(): str(name) for name in frame.columns}
    return next((lookup[name.lower()] for name in names if name.lower() in lookup), None)


def risk(value: Any) -> float:
    try:
        value = float(value)
    except (TypeError, ValueError):
        return 0.0
    if pd.isna(value):
        return 0.0
    return max(0.0, min(1.0, value / 100 if value > 1 else value))


def severity(value: float) -> str:
    return "critical" if value >= .8 else "high" if value >= .6 else "medium" if value >= .3 else "low"


def features(row: pd.Series) -> list[dict[str, Any]]:
    text = str(row.get("_explanation", ""))
    if text and text != "nan":
        return [{"feature": part.strip(), "impact": .2, "direction": "increases risk"} for part in text.split(";")[:5]]
    names = [("connection_count", "connection volume"), ("unique_ports", "distinct ports"), ("flows_per_second", "flows per second"), ("bytes_per_connection", "bytes per connection")]
    return [{"feature": label, "impact": .2, "direction": "increases risk"} for key, label in names if pd.notna(row.get(key)) and float(row.get(key, 0)) > 0]


@dataclass
class Replay:
    data: pd.DataFrame | None = None
    source_label: str = ""
    scenario: str = "clean"
    running: bool = False
    interval_seconds: float = 1.0
    cursor: int = 0
    last_step: float = 0.0
    hosts: dict[str, dict[str, Any]] = field(default_factory=dict)
    trends: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    explanations: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    @property
    def path(self) -> Path:
        return Path(os.environ.get("DEMO_DATA_PATH", str(DEFAULT_DATA_PATH))).expanduser()

    def load(self) -> None:
        if not self.path.exists():
            raise FileNotFoundError(f"Scored demo data not found: {self.path}. Run score.py, or set DEMO_DATA_PATH.")
        self.set_frame(pd.read_csv(self.path, low_memory=False), source_label=str(self.path))

    def set_frame(self, frame: pd.DataFrame, source_label: str) -> None:
        """Use an already-scored frame as the current replay data source."""
        timestamp, source, score = column(frame, "window_start", "time_window", "timestamp"), column(frame, "src_ip", "source ip", "source_ip"), column(frame, "risk_score", "anomaly_risk", "risk")
        if not timestamp or not source or not score:
            raise ValueError("The scored CSV needs window_start, src_ip, and risk_score (or anomaly_risk) columns.")
        frame["_time"] = pd.to_datetime(frame[timestamp], errors="coerce")
        frame = frame.dropna(subset=["_time", source]).copy()
        frame["_host"], frame["_risk"] = frame[source].astype(str), frame[score].map(risk)
        file_col, label_col, explanation_col = column(frame, "source_file"), column(frame, "label", "attack_label"), column(frame, "explanation")
        frame["_source_file"] = frame[file_col].astype(str) if file_col else ""
        frame["_label"] = frame[label_col].astype(str) if label_col else ""
        frame["_explanation"] = frame[explanation_col].astype(str) if explanation_col else ""
        self.data = frame.sort_values("_time").reset_index(drop=True)
        self.source_label = source_label
        self.reset()

    def rows(self) -> pd.DataFrame:
        if self.data is None:
            self.load()
        assert self.data is not None
        search = (self.data["_source_file"] + " " + self.data["_label"]).str.lower()
        attack = self.data.get("is_attack_window", pd.Series(0, index=self.data.index)).fillna(0).astype(float).gt(0)
        if self.scenario == "clean":
            selected = self.data[search.str.contains("monday|benign", regex=True) | ~attack]
        elif self.scenario == "ddos":
            # A DDoS source CSV also contains benign traffic.  Replay only its
            # labeled attack windows so the presentation segment is the real,
            # loud DDoS burst (22 windows in the supplied CIC-IDS2017 files).
            selected = self.data[search.str.contains("ddos|hulk|goldeneye", regex=True) & attack]
            if selected.empty:
                selected = self.data[attack].nlargest(250, "_risk")
        elif self.scenario == "infiltration":
            # CIC-IDS2017's original filename misspells Infiltration as
            # "Infilteration"; accept both spellings.
            selected = self.data[search.str.contains("infiltration|infilteration", regex=True) & attack]
            if selected.empty:
                selected = self.data[attack & self.data["_risk"].lt(self.data["_risk"].quantile(.8))]
        else:
            selected = self.data
        return selected.sort_values("_time").head(600).reset_index(drop=True)

    def reset(self) -> None:
        self.running, self.cursor, self.last_step = False, 0, 0.0
        self.hosts, self.trends, self.explanations = {}, {}, {}

    def advance(self) -> None:
        if not self.running:
            return
        rows = self.rows()
        now = time.monotonic()
        # The frontend polls once per second. Catch up when an interval shorter
        # than one second is selected, rather than silently limiting replay to
        # one row per poll.
        steps = 1 if not self.last_step else max(0, int((now - self.last_step) / self.interval_seconds))
        for _ in range(steps):
            if self.cursor >= len(rows):
                self.running = False
                break
            row = rows.iloc[self.cursor]
            host, score = row["_host"], float(row["_risk"])
            event_time = row["_time"].isoformat()
            self.hosts[host] = {"id": host, "label": row["_label"] or "Replay host", "risk": score, "severity": severity(score), "status": "Demo replay", "window_start": event_time}
            self.trends.setdefault(host, []).append({"time": event_time, "risk": round(score, 3)})
            self.trends[host] = self.trends[host][-60:]
            self.explanations[host] = features(row)
            self.cursor += 1
        if steps:
            self.last_step = now

    def status(self) -> dict[str, Any]:
        try:
            total, error = len(self.rows()), None
        except (FileNotFoundError, ValueError) as exc:
            total, error = 0, str(exc)
        return {"mode": "demo", "scenario": self.scenario, "scenario_label": SCENARIOS[self.scenario], "running": self.running, "interval_seconds": self.interval_seconds, "cursor": self.cursor, "total": total, "data_path": str(self.path), "data_source": self.source_label or str(self.path), "error": error}


replay = Replay()


class Settings(BaseModel):
    scenario: str | None = None
    interval_seconds: float | None = Field(default=None, ge=.2, le=30)


@app.get("/api/demo/status")
def demo_status():
    return replay.status()


@app.post("/api/demo/start")
def demo_start(settings: Settings | None = None):
    if settings and settings.scenario:
        if settings.scenario not in SCENARIOS:
            raise HTTPException(400, "Unknown demo scenario")
        replay.scenario = settings.scenario
        replay.reset()
    if settings and settings.interval_seconds:
        replay.interval_seconds = settings.interval_seconds
    try:
        replay.rows()
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(503, str(exc)) from exc
    replay.running = True
    return replay.status()


@app.post("/api/demo/pause")
def demo_pause():
    replay.running = False
    return replay.status()


@app.post("/api/demo/reset")
def demo_reset():
    replay.reset()
    return replay.status()


@app.post("/api/demo/settings")
def demo_settings(settings: Settings):
    if settings.scenario:
        if settings.scenario not in SCENARIOS:
            raise HTTPException(400, "Unknown demo scenario")
        replay.scenario, replay.cursor = settings.scenario, 0
        replay.hosts, replay.trends, replay.explanations = {}, {}, {}
    if settings.interval_seconds:
        replay.interval_seconds = settings.interval_seconds
    return replay.status()


@app.get("/api/hosts")
def get_hosts():
    replay.advance()
    return list(replay.hosts.values())


@app.get("/api/hosts/{host_id}/trend")
def get_trend(host_id: str):
    if host_id not in replay.trends:
        raise HTTPException(404, "Host has not appeared in the replay yet")
    return replay.trends[host_id]


@app.get("/api/hosts/{host_id}/explain")
def get_explanation(host_id: str):
    if host_id not in replay.hosts:
        raise HTTPException(404, "Host has not appeared in the replay yet")
    host = replay.hosts[host_id]
    return {"host_id": host_id, "risk": host["risk"], "severity": host["severity"], "top_features": replay.explanations.get(host_id, [])}


@app.get("/")
def root():
    return {"status": "ok", "demo": replay.status()}
