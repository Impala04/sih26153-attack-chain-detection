"""Bridge module: score a live DetectionEvent using the trained NetGuard model."""

import json
from pathlib import Path
from typing import Dict

import pandas as pd

from .score import load_model_and_features, DEFAULT_MODEL_PATH
from .train import generate_explanation
from ..processing.events import DetectionEvent


def score_detection_event(
    event: DetectionEvent, model_path: str = DEFAULT_MODEL_PATH
) -> Dict[str, object]:
    """Score a single DetectionEvent against the trained model.

    Uses the training-time anomaly_score_raw min/max (saved in meta.json)
    to normalize anomaly_risk, since batch min-max normalization breaks
    down for a single-row input.
    """
    model, feature_cols = load_model_and_features(model_path)

    meta_path = str(Path(model_path).with_suffix(".meta.json"))
    with open(meta_path) as f:
        meta = json.load(f)
    raw_min = meta["anomaly_score_raw_min"]
    raw_max = meta["anomaly_score_raw_max"]

    missing = [c for c in feature_cols if c not in event.features]
    if missing:
        raise ValueError(
            f"DetectionEvent {event.event_id} is missing model features: {missing}"
        )

    row = {col: event.features[col] for col in feature_cols}
    df = pd.DataFrame([row])

    X = df[feature_cols]
    anomaly_score = int(model.predict(X)[0])
    anomaly_score_raw = float(model.decision_function(X)[0])

    denom = raw_max - raw_min
    anomaly_risk = (
        ((raw_max - anomaly_score_raw) / denom) * 100 if denom != 0 else 50.0
    )
    anomaly_risk = max(0.0, min(100.0, anomaly_risk))

    row_with_scores = pd.Series(
        {**row, "anomaly_score": anomaly_score, "anomaly_score_raw": anomaly_score_raw}
    )
    explanation = generate_explanation(row_with_scores)

    return {
        "event_id": event.event_id,
        "anomaly_score": anomaly_score,
        "anomaly_score_raw": anomaly_score_raw,
        "anomaly_risk": round(anomaly_risk, 2),
        "explanation": explanation,
    }