"""CyberFlux API with replayable, already-scored traffic Demo Mode.

Run the feature builder and scorer first, then run this API from ``backend``:
``uvicorn app:app --reload --port 8000``. By default the replay reads
``data/host_features_v2_scored.csv``; override it with ``DEMO_DATA_PATH``.

The CyberFlux Risk Engine is integrated into the replay pipeline.
"""

from __future__ import annotations

import json
import math
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

try:
    from risk_engine import calculate_risk
except ImportError:
    from backend.risk_engine import calculate_risk


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA_PATH = ROOT / "data" / "host_features_v2_scored.csv"

SCENARIOS = {
    "clean": "Clean traffic",
    "ddos": "DDoS burst",
    "infiltration": "Subtle infiltration",
}

app = FastAPI(title="CyberFlux Demo API")
from backend.live_routes import router as live_router
app.include_router(live_router)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

import sys  # noqa: E402

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from backend.analysis_routes import router as analysis_router  # noqa: E402

app.include_router(analysis_router)

MAX_PCAP_UPLOAD_BYTES = 100 * 1024 * 1024
MAX_PCAP_RESPONSE_PACKETS = 10_000
PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}


def column(frame: pd.DataFrame, *names: str) -> str | None:
    lookup = {
        str(name).lower(): str(name)
        for name in frame.columns
    }

    return next(
        (
            lookup[name.lower()]
            for name in names
            if name.lower() in lookup
        ),
        None,
    )


def risk(value: Any) -> float:
    try:
        value = float(value)
    except (TypeError, ValueError):
        return 0.0

    if pd.isna(value):
        return 0.0

    return max(
        0.0,
        min(
            1.0,
            value / 100 if value > 1 else value,
        ),
    )


def severity(value: float) -> str:
    return (
        "critical"
        if value >= 0.8
        else "high"
        if value >= 0.6
        else "medium"
        if value >= 0.3
        else "low"
    )


def features(row: pd.Series) -> list[dict[str, Any]]:
    text = row.get("_explanation", "")
    text = text.strip() if isinstance(text, str) else ""

    if text and text.lower() != "nan":
        looks_structured = text.startswith(("{", "["))

        try:
            explanation = json.loads(text)
            looks_structured = True
        except json.JSONDecodeError:
            explanation = None

        if looks_structured:
            if (
                isinstance(explanation, dict)
                and explanation.get("status") == "available"
            ):
                items = []

                top_features = explanation.get("top_features")

                if not isinstance(top_features, list):
                    top_features = []

                for item in top_features:
                    if not isinstance(item, dict):
                        continue

                    name = item.get("feature")
                    contribution = item.get(
                        "contribution",
                        item.get("impact"),
                    )

                    if (
                        not isinstance(name, str)
                        or not name.strip()
                        or isinstance(contribution, bool)
                        or not isinstance(contribution, (int, float))
                    ):
                        continue

                    try:
                        contribution = float(contribution)
                    except (OverflowError, ValueError):
                        continue

                    if not math.isfinite(contribution):
                        continue

                    direction = (
                        "increases risk"
                        if contribution > 0
                        else "decreases risk"
                        if contribution < 0
                        else "neutral"
                    )

                    items.append(
                        {
                            "feature": name,
                            "impact": contribution,
                            "direction": direction,
                        }
                    )

                    if len(items) == 5:
                        break

                if items:
                    return items

        else:
            # Preserve the prior semicolon-separated explanation format.
            parts = [
                part.strip()
                for part in text.split(";")
                if part.strip()
            ]

            if parts:
                return [
                    {
                        "feature": part,
                        "impact": 0.2,
                        "direction": "increases risk",
                    }
                    for part in parts[:5]
                ]

    names = [
        ("connection_count", "connection volume"),
        ("unique_ports", "distinct ports"),
        ("flows_per_second", "flows per second"),
        ("bytes_per_connection", "bytes per connection"),
    ]

    return [
        {
            "feature": label,
            "impact": 0.2,
            "direction": "increases risk",
        }
        for key, label in names
        if pd.notna(row.get(key))
        and float(row.get(key, 0)) > 0
    ]


@dataclass
class Replay:
    data: pd.DataFrame | None = None
    source_label: str = ""
    scenario: str = "clean"
    running: bool = False
    interval_seconds: float = 1.0
    cursor: int = 0
    last_step: float = 0.0

    hosts: dict[str, dict[str, Any]] = field(
        default_factory=dict
    )

    trends: dict[str, list[dict[str, Any]]] = field(
        default_factory=dict
    )

    explanations: dict[str, list[dict[str, Any]]] = field(
        default_factory=dict
    )

    @property
    def path(self) -> Path:
        return Path(
            os.environ.get(
                "DEMO_DATA_PATH",
                str(DEFAULT_DATA_PATH),
            )
        ).expanduser()

    def load(self) -> None:
        if not self.path.exists():
            raise FileNotFoundError(
                f"Scored demo data not found: {self.path}. "
                "Run score.py, or set DEMO_DATA_PATH."
            )

        self.set_frame(
            pd.read_csv(
                self.path,
                low_memory=False,
            ),
            source_label=str(self.path),
        )

    def set_frame(
        self,
        frame: pd.DataFrame,
        source_label: str,
    ) -> None:
        """Use an already-scored frame as the current replay data source."""

        timestamp = column(
            frame,
            "window_start",
            "time_window",
            "timestamp",
        )

        source = column(
            frame,
            "src_ip",
            "source ip",
            "source_ip",
        )

        score = column(
            frame,
            "risk_score",
            "anomaly_risk",
            "risk",
        )

        if not timestamp or not source or not score:
            raise ValueError(
                "The scored CSV needs window_start, src_ip, "
                "and risk_score (or anomaly_risk) columns."
            )

        frame["_time"] = pd.to_datetime(
            frame[timestamp],
            errors="coerce",
        )

        frame = frame.dropna(
            subset=["_time", source]
        ).copy()

        frame["_host"] = frame[source].astype(str)
        frame["_risk"] = frame[score].map(risk)

        file_col = column(
            frame,
            "source_file",
        )

        label_col = column(
            frame,
            "label",
            "attack_label",
        )

        explanation_col = column(
            frame,
            "explanation",
        )

        frame["_source_file"] = (
            frame[file_col].astype(str)
            if file_col
            else ""
        )

        frame["_label"] = (
            frame[label_col].astype(str)
            if label_col
            else ""
        )

        frame["_explanation"] = (
            frame[explanation_col].astype(str)
            if explanation_col
            else ""
        )

        self.data = (
            frame
            .sort_values("_time")
            .reset_index(drop=True)
        )

        self.source_label = source_label
        self.reset()

    def rows(self) -> pd.DataFrame:
        if self.data is None:
            self.load()

        assert self.data is not None

        search = (
            self.data["_source_file"]
            + " "
            + self.data["_label"]
        ).str.lower()

        attack = (
            self.data
            .get(
                "is_attack_window",
                pd.Series(
                    0,
                    index=self.data.index,
                ),
            )
            .fillna(0)
            .astype(float)
            .gt(0)
        )

        if self.scenario == "clean":
            selected = self.data[
                search.str.contains(
                    "monday|benign",
                    regex=True,
                )
                | ~attack
            ]

        elif self.scenario == "ddos":
            selected = self.data[
                search.str.contains(
                    "ddos|hulk|goldeneye",
                    regex=True,
                )
                & attack
            ]

            if selected.empty:
                selected = self.data[
                    attack
                ].nlargest(
                    250,
                    "_risk",
                )

        elif self.scenario == "infiltration":
            selected = self.data[
                search.str.contains(
                    "infiltration|infilteration",
                    regex=True,
                )
                & attack
            ]

            if selected.empty:
                selected = self.data[
                    attack
                    & self.data["_risk"].lt(
                        self.data["_risk"].quantile(0.8)
                    )
                ]

        else:
            selected = self.data

        return (
            selected
            .sort_values("_time")
            .head(600)
            .reset_index(drop=True)
        )

    def reset(self) -> None:
        self.running = False
        self.cursor = 0
        self.last_step = 0.0

        self.hosts = {}
        self.trends = {}
        self.explanations = {}

    def advance(self) -> None:
        if not self.running:
            return

        rows = self.rows()
        now = time.monotonic()

        # The frontend polls once per second. Catch up when an interval
        # shorter than one second is selected.
        steps = (
            1
            if not self.last_step
            else max(
                0,
                int(
                    (now - self.last_step)
                    / self.interval_seconds
                ),
            )
        )

        for _ in range(steps):

            if self.cursor >= len(rows):
                self.running = False
                break

            row = rows.iloc[self.cursor]

            # ----------------------------------------------------------
            # CYBERFLUX RISK ENGINE
            # ----------------------------------------------------------

            host = row["_host"]
            event_time = row["_time"].isoformat()

            # Pass the complete available row to the Risk Engine.
            risk_input = row.to_dict()

            risk_result = calculate_risk(
                risk_input
            )

            score = risk_result["risk_score"]

            # ----------------------------------------------------------
            # Store Risk Engine result while preserving the existing
            # frontend-compatible "risk" field.
            # ----------------------------------------------------------

            self.hosts[host] = {
                "id": host,
                "label": (
                    row["_label"]
                    or "Replay host"
                ),

                # Existing frontend field.
                "risk": score,

                # Risk Engine fields.
                "risk_score": score,
                "risk_level": risk_result[
                    "risk_level"
                ],

                "severity": risk_result[
                    "risk_level"
                ],

                "confidence": risk_result[
                    "confidence"
                ],

                "uncertainty": risk_result[
                    "uncertainty"
                ],

                "contributing_factors": (
                    risk_result[
                        "contributing_factors"
                    ]
                ),

                "recommended_action": (
                    risk_result[
                        "recommended_action"
                    ]
                ),

                "signals_used": (
                    risk_result[
                        "signals_used"
                    ]
                ),

                "signals_missing": (
                    risk_result[
                        "signals_missing"
                    ]
                ),

                "factor_values": (
                    risk_result[
                        "factor_values"
                    ]
                ),

                "status": "Risk Engine",
                "window_start": event_time,
            }

            # ----------------------------------------------------------
            # Existing trend history.
            # ----------------------------------------------------------

            self.trends.setdefault(
                host,
                [],
            ).append(
                {
                    "time": event_time,
                    "risk": round(score, 3),
                }
            )

            self.trends[host] = (
                self.trends[host][-60:]
            )

            # Keep the repository's existing explanation mechanism.
            self.explanations[host] = features(row)

            self.cursor += 1

        if steps:
            self.last_step = now

    def status(self) -> dict[str, Any]:
        try:
            total = len(self.rows())
            error = None

        except (
            FileNotFoundError,
            ValueError,
        ) as exc:
            total = 0
            error = str(exc)

        return {
            "mode": "demo",
            "scenario": self.scenario,
            "scenario_label": SCENARIOS[
                self.scenario
            ],
            "running": self.running,
            "interval_seconds": self.interval_seconds,
            "cursor": self.cursor,
            "total": total,
            "data_path": str(self.path),
            "data_source": (
                self.source_label
                or str(self.path)
            ),
            "error": error,
        }


replay = Replay()


class Settings(BaseModel):
    scenario: Optional[str] = None
    interval_seconds: Optional[float] = Field(
        default=None,
        ge=0.2,
        le=30,
    )


@app.get("/api/demo/status")
def demo_status():
    return replay.status()


@app.post("/api/demo/start")
def demo_start(
    settings: Optional[Settings] = None,
):
    if settings and settings.scenario:

        if settings.scenario not in SCENARIOS:
            raise HTTPException(
                400,
                "Unknown demo scenario",
            )

        replay.scenario = settings.scenario
        replay.reset()

    if settings and settings.interval_seconds:
        replay.interval_seconds = (
            settings.interval_seconds
        )

    try:
        replay.rows()

    except (
        FileNotFoundError,
        ValueError,
    ) as exc:
        raise HTTPException(
            503,
            str(exc),
        ) from exc

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
def demo_settings(
    settings: Settings,
):
    if settings.scenario:

        if settings.scenario not in SCENARIOS:
            raise HTTPException(
                400,
                "Unknown demo scenario",
            )

        replay.scenario = settings.scenario
        replay.cursor = 0

        replay.hosts = {}
        replay.trends = {}
        replay.explanations = {}

    if settings.interval_seconds:
        replay.interval_seconds = (
            settings.interval_seconds
        )

    return replay.status()


@app.get("/api/hosts")
def get_hosts():
    replay.advance()
    return list(
        replay.hosts.values()
    )


@app.get("/api/hosts/{host_id}/trend")
def get_trend(
    host_id: str,
):
    if host_id not in replay.trends:
        raise HTTPException(
            404,
            "Host has not appeared in the replay yet",
        )

    return replay.trends[host_id]


@app.get("/api/hosts/{host_id}/explain")
def get_explanation(
    host_id: str,
):
    if host_id not in replay.hosts:
        raise HTTPException(
            404,
            "Host has not appeared in the replay yet",
        )

    host = replay.hosts[host_id]

    return {
        "host_id": host_id,

        # Existing frontend fields.
        "risk": host.get(
            "risk",
            0,
        ),

        "severity": host.get(
            "severity",
            "low",
        ),

        "top_features": replay.explanations.get(
            host_id,
            [],
        ),

        # Risk Engine fields.
        "risk_score": host.get(
            "risk_score",
            host.get("risk", 0),
        ),

        "risk_level": host.get(
            "risk_level",
            host.get("severity", "Low"),
        ),

        "confidence": host.get(
            "confidence"
        ),

        "uncertainty": host.get(
            "uncertainty"
        ),

        "contributing_factors": host.get(
            "contributing_factors",
            [],
        ),

        "recommended_action": host.get(
            "recommended_action",
            "Continue monitoring.",
        ),

        "signals_used": host.get(
            "signals_used",
            [],
        ),

        "signals_missing": host.get(
            "signals_missing",
            [],
        ),

        "factor_values": host.get(
            "factor_values",
            {},
        ),
    }


@app.post("/api/risk/evaluate")
def evaluate_risk(
    payload: dict[str, Any],
):
    """
    Direct integration endpoint for the CyberFlux Risk Engine.

    Accepts structured model/event outputs and returns
    a JSON-serialisable RiskResult.
    """

    try:
        return calculate_risk(payload)

    except Exception as exc:
        raise HTTPException(
            400,
            f"Risk evaluation failed: {exc}",
        ) from exc


@app.get("/")
def root():
    return {
        "status": "ok",
        "demo": replay.status(),
    }


@app.post("/api/pcap/parse")
async def parse_pcap_upload(
    file: UploadFile = File(...),
):
    """Parse an uploaded capture without feeding it into the detection pipeline."""

    import sys
    import tempfile

    # The documented launch command runs Uvicorn from ``backend/``,
    # so expose the repository root when this route imports
    # the shared capture reader.
    if str(ROOT) not in sys.path:
        sys.path.insert(
            0,
            str(ROOT),
        )

    from src.ingestion.pcap_reader import (
        PcapReadError,
        iter_pcap,
    )

    filename = Path(
        file.filename or "capture.pcap"
    ).name

    suffix = Path(
        filename
    ).suffix.lower()

    if suffix not in PCAP_SUFFIXES:
        await file.close()

        raise HTTPException(
            415,
            "Upload a .pcap, .pcapng, or .cap capture",
        )

    temp_path: Path | None = None
    size = 0

    try:
        with tempfile.NamedTemporaryFile(
            prefix="cyberflux-",
            suffix=suffix,
            delete=False,
        ) as temp_file:

            temp_path = Path(
                temp_file.name
            )

            while chunk := await file.read(
                1024 * 1024
            ):
                size += len(chunk)

                if size > MAX_PCAP_UPLOAD_BYTES:
                    raise HTTPException(
                        413,
                        "Capture exceeds the 100 MB upload limit",
                    )

                temp_file.write(chunk)

        if size == 0:
            raise HTTPException(
                400,
                "The capture file is empty",
            )

        packets = []
        truncated = False

        try:
            for packet in iter_pcap(
                temp_path
            ):
                if (
                    len(packets)
                    == MAX_PCAP_RESPONSE_PACKETS
                ):
                    truncated = True
                    break

                packets.append(
                    packet.to_dict()
                )

        except PcapReadError as exc:
            raise HTTPException(
                400,
                str(exc),
            ) from exc

        return {
            "filename": filename,
            "packet_count": len(packets),
            "truncated": truncated,
            "packets": packets,
        }

    finally:
        await file.close()

        if temp_path is not None:
            temp_path.unlink(
                missing_ok=True
            )
