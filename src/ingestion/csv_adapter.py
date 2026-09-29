"""
CSV Adapter — Phase 4.

Converts a CIC-style windowed feature CSV into DetectionEvents, reusing the
existing DetectionEngine (src/processing/detector.py) to build events and
the existing score_detection_event() (src/model/event_scoring.py) to attach
ML risk scores. No new DetectionEvent-construction logic is introduced here.

--- Schema-gap decision ---
The windowed CSV (as produced by src/features/build_windows.py) does not
require the rate-based diagnostic fields DetectionEngine's scan/flood rules
use (syn_ratio, connection_attempt_rate, packets_per_second,
bytes_per_second) or window_end. Resolution:
  - window_end is derived as window_start + window_seconds
  - unique_dst_ports is aliased from unique_ports
  - unique_dst_ips is aliased from unique_destinations
  - supplied diagnostic fields are passed to DetectionEngine unchanged
  - missing diagnostics are omitted, so their rules cannot fire without
    evidence in the CSV
"""

from __future__ import annotations

from datetime import timedelta
from typing import List

import numpy as np
import pandas as pd

from src.model.event_scoring import score_detection_event
from src.model.score import DEFAULT_MODEL_PATH
from src.model.train import LATERAL_MOVE_THRESHOLD
from src.processing.detector import DetectionEngine
from src.processing.events import DetectionEvent
from src.processing.feature_extractor import PHASE1_FEATURE_COLUMNS

REQUIRED_BASE_COLUMNS = ["src_ip", "dst_ip", "window_start"]
REQUIRED_FEATURE_COLUMNS = [c for c in PHASE1_FEATURE_COLUMNS if c != "lateral_move_flag"]
OPTIONAL_DETECTION_COLUMNS = (
    "unique_dst_ports",
    "unique_dst_ips",
    "syn_ratio",
    "connection_attempt_rate",
    "packets_per_second",
    "bytes_per_second",
)


def _load_and_validate(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    df.columns = [c.strip() for c in df.columns]

    required = REQUIRED_BASE_COLUMNS + REQUIRED_FEATURE_COLUMNS
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"CSV is missing required columns: {missing}")

    return df


def _clean(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    df["window_start"] = pd.to_datetime(df["window_start"], errors="coerce")

    for col in REQUIRED_FEATURE_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df[REQUIRED_FEATURE_COLUMNS] = df[REQUIRED_FEATURE_COLUMNS].replace(
        [np.inf, -np.inf], np.nan
    )

    before = len(df)
    df = df.dropna(subset=["window_start"] + REQUIRED_FEATURE_COLUMNS)
    dropped = before - len(df)
    if dropped:
        print(f"csv_adapter: dropped {dropped} row(s) with bad timestamps/values")

    if df.empty:
        raise ValueError("No valid rows remained after cleaning the CSV")

    if "lateral_move_flag" not in df.columns:
        df["lateral_move_flag"] = (
            df["unique_destinations"] > LATERAL_MOVE_THRESHOLD
        ).astype(int)
    else:
        df["lateral_move_flag"] = (
            pd.to_numeric(df["lateral_move_flag"], errors="coerce").fillna(0).astype(int)
        )

    return df


def _row_to_detector_input(row: pd.Series, window_seconds: float) -> dict:
    window_start = row["window_start"].to_pydatetime()
    window_end = window_start + timedelta(seconds=window_seconds)

    detector_row = {
        "src_ip": str(row["src_ip"]),
        "dst_ip": str(row["dst_ip"]),
        "window_start": window_start,
        "window_end": window_end,
        "unique_dst_ports": float(row["unique_ports"]),
        "unique_dst_ips": float(row["unique_destinations"]),
    }
    for column in OPTIONAL_DETECTION_COLUMNS:
        if column in row.index:
            value = pd.to_numeric(row[column], errors="coerce")
            if pd.notna(value) and np.isfinite(value):
                detector_row[column] = float(value)
    for col in PHASE1_FEATURE_COLUMNS:
        detector_row[col] = row[col]

    return detector_row


def build_events_from_csv(
    path: str,
    window_seconds: float = 30.0,
    model_path: str = DEFAULT_MODEL_PATH,
) -> List[DetectionEvent]:
    """Read a CIC-style windowed feature CSV and return scored DetectionEvents.

    Raises ValueError for missing columns or if no valid rows remain after
    cleaning. Per-event scoring failures are recorded in
    event.metadata["ml_score_error"] rather than aborting the whole batch.
    """
    df = _load_and_validate(path)
    df = _clean(df)

    engine = DetectionEngine()
    events: List[DetectionEvent] = []

    for _, row in df.iterrows():
        detector_row = _row_to_detector_input(row, window_seconds)
        events.extend(engine.detect(detector_row))

    for event in events:
        try:
            event.metadata["ml_score"] = score_detection_event(event, model_path=model_path)
        except Exception as exc:  # noqa: BLE001 - one bad event shouldn't kill the batch
            event.metadata["ml_score_error"] = str(exc)

    return events
