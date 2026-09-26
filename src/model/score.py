"""
score.py — Score new/incoming data with the pre-trained NetGuard model.

This is what the live sniffer, demo replay, and PCAP-upload paths will all
call (Phase 2) so every intake method produces identical output shapes.

Usage:
    python src/model/score.py --input data/new_windows.csv --out data/scored.csv

    # Or import and call directly from the FastAPI backend / live pipeline:
    from src.model.score import score_dataframe
    scored_df = score_dataframe(raw_df)
"""

import argparse
import json
from pathlib import Path

import joblib
import pandas as pd

from .train import (
    add_lateral_move_flag,
    compute_anomaly_risk,
    compute_risk_score,
    generate_explanation,
    LATERAL_MOVE_THRESHOLD,
)

DEFAULT_MODEL_PATH = "models/isolation_forest.joblib"


def load_model_and_features(model_path: str = DEFAULT_MODEL_PATH):
    model = joblib.load(model_path)
    meta_path = str(Path(model_path).with_suffix(".meta.json"))
    with open(meta_path) as f:
        meta = json.load(f)
    return model, meta["feature_cols"]


def score_dataframe(df: pd.DataFrame, model_path: str = DEFAULT_MODEL_PATH) -> pd.DataFrame:
    """Score a dataframe of windowed host features. Expects the same raw
    columns as training data MINUS anomaly_score/anomaly_risk/etc (those
    get computed here). lateral_move_flag will be added automatically if
    missing, so callers (live sniffer, demo mode, PCAP parser) don't each
    need to reimplement that logic."""
    model, feature_cols = load_model_and_features(model_path)
    df = df.copy()

    if "lateral_move_flag" not in df.columns:
        df = add_lateral_move_flag(df, threshold=LATERAL_MOVE_THRESHOLD)

    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        raise ValueError(
            f"Input data is missing columns the model expects: {missing}. "
            f"Check that upstream feature extraction (live sniffer / demo / "
            f"PCAP parser) matches the training schema exactly."
        )

    X = df[feature_cols]
    df["anomaly_score"] = model.predict(X)
    df["anomaly_score_raw"] = model.decision_function(X)

    df = compute_anomaly_risk(df)
    df = compute_risk_score(df)  # no-op if attack_flow_ratio isn't present (e.g. live data)
    df["explanation"] = df.apply(generate_explanation, axis=1)

    return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Score new data with the trained NetGuard model")
    parser.add_argument("--input", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--model", default=DEFAULT_MODEL_PATH)
    args = parser.parse_args()

    raw_df = pd.read_csv(args.input)
    scored = score_dataframe(raw_df, model_path=args.model)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    scored.to_csv(args.out, index=False)
    print(f"Scored {scored.shape[0]} rows -> {args.out}")
    print(scored[["Source IP", "time_window", "anomaly_risk", "risk_score"]].head(10) if "Source IP" in scored.columns else scored.head(10))