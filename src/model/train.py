"""
train.py — Fit and save the NetGuard anomaly detection model.

Reproduces the logic from notebooks/03_anomaly_detection.ipynb, but as a
reusable script: run this whenever you want to retrain on new/updated data.

Usage:
    python src/model/train.py
    python src/model/train.py --input data/host_features_all.csv --out data/host_features_with_anomaly.csv
"""

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

# v2 schema (from src/features/build_windows.py) — short (default 30s) windows
# per (src_ip, dst_ip) pair with burst-aware features, replacing the original
# diluted 5-minute-per-host windowing. If Jerusha/Aaron change the windowing
# script's output columns, update this list to match.
FEATURE_COLS = [
    "connection_count",
    "unique_destinations",
    "unique_ports",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_bytes_fwd",
    "total_bytes_bwd",
    "avg_flow_duration",
    "max_flow_duration",
    "std_flow_duration",
    "max_bytes_total",
    "std_bytes_total",
    "max_packets_total",
    "bytes_per_connection",
    "flows_per_second",
    "lateral_move_flag",  # added: see add_lateral_move_flag()
]

LATERAL_MOVE_THRESHOLD = 5  # tune this after checking Step 1's distribution


def add_lateral_move_flag(df: pd.DataFrame, threshold: int = LATERAL_MOVE_THRESHOLD) -> pd.DataFrame:
    """Aaron's original spec: flag hosts contacting more than `threshold`
    distinct internal destinations in a single time window."""
    df = df.copy()
    df["lateral_move_flag"] = (df["unique_destinations"] > threshold).astype(int)
    return df


def compute_anomaly_risk(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize anomaly_score_raw to a friendly 0-100 risk scale.
    More negative raw score = more anomalous = higher risk."""
    df = df.copy()
    raw = df["anomaly_score_raw"]
    df["anomaly_risk"] = ((raw.max() - raw) / (raw.max() - raw.min())) * 100
    return df


def compute_risk_score(df: pd.DataFrame) -> pd.DataFrame:
    """Combined score: 50% anomaly risk + 50% known-attack-pattern ratio.
    NOTE: this is a placeholder version of Niya's Risk Engine formula
    (which also folds in stage_severity + forecast_confidence once those
    exist). Keep this here for now so score.py's output is immediately
    useful standalone, but expect Niya's formula to supersede it."""
    df = df.copy()
    if "attack_flow_ratio" in df.columns:
        df["risk_score"] = (0.5 * df["anomaly_risk"]) + (0.5 * df["attack_flow_ratio"] * 100)
        df["risk_score"] = df["risk_score"].round(1)
    elif "is_attack_window" in df.columns:
        # v2 schema: attack_flow_ratio may be near-zero even in real attack
        # windows (one bad flow among many benign ones), so use the binary
        # is_attack_window flag as a coarser but non-diluted signal instead.
        df["risk_score"] = (0.5 * df["anomaly_risk"]) + (0.5 * df["is_attack_window"] * 100)
        df["risk_score"] = df["risk_score"].round(1)
    return df


def generate_explanation(row: pd.Series) -> str:
    """Compatibility stub; rule text cannot explain a model prediction."""
    return "unavailable: rule-only text does not attribute the model prediction"
def train(input_path: str, output_path: str, model_path: str, contamination: float = 0.05):
    df = pd.read_csv(input_path)
    # v1 schema used "time_window", v2 (build_windows.py) uses "window_start"
    time_col = "window_start" if "window_start" in df.columns else "time_window"
    df[time_col] = pd.to_datetime(df[time_col])
    print(f"Loaded {df.shape[0]} rows, {df.shape[1]} columns from {input_path} (time column: {time_col})")

    # Step 4: fill in lateral_move_flag if not already present
    if "lateral_move_flag" not in df.columns:
        df = add_lateral_move_flag(df)
        print(f"Added lateral_move_flag (threshold={LATERAL_MOVE_THRESHOLD})")

    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing expected feature columns: {missing}")

    X = df[FEATURE_COLS]

    iso = IsolationForest(contamination=contamination, random_state=42)
    df["anomaly_score"] = iso.fit_predict(X)
    df["anomaly_score_raw"] = iso.decision_function(X)

    df = compute_anomaly_risk(df)
    df = compute_risk_score(df)
    # Local explanations are produced on demand at inference with a stored reference baseline.
    df["explanation"] = None

    # Save model + the exact feature column order (score.py needs this to
    # avoid silently scoring on misordered/mismatched columns later)
    Path(model_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(iso, model_path)
    meta_path = str(Path(model_path).with_suffix(".meta.json"))
    with open(meta_path, "w") as f:
        json.dump({"feature_cols": FEATURE_COLS, "contamination": contamination,
                  "reference_features": {key: float(value) for key, value in X.median(numeric_only=True).items()}}, f, indent=2)
    print(f"Saved model to {model_path}")
    print(f"Saved feature metadata to {meta_path}")

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Saved scored data to {output_path}: {df.shape}")

    # Quick sanity check, same as the notebook's spot-check
    print("\nanomaly_score value counts:")
    print(df["anomaly_score"].value_counts())

    return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train NetGuard anomaly detection model")
    parser.add_argument("--input", default="data/host_features_all.csv")
    parser.add_argument("--out", default="data/host_features_with_anomaly.csv")
    parser.add_argument("--model", default="models/isolation_forest.joblib")
    parser.add_argument("--contamination", type=float, default=0.05)
    args = parser.parse_args()

    train(args.input, args.out, args.model, args.contamination)
