"""
compare_baseline.py — Phase 5: compare the IsolationForest anomaly detector
against a supervised Logistic Regression baseline on the same features.

This directly satisfies the NetGuard spec's "Performance Validation" item:
train a standard Logistic Regression on the same dataset and report
F1-score, precision, recall, and false positive rate for both models,
using is_attack_window as ground truth.

Usage:
    python src/evaluate/compare_baseline.py --input ../sih26153-attack-chain-detection/data/host_features_v2_scored.csv
"""

import argparse

import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    f1_score,
    precision_score,
    recall_score,
    confusion_matrix,
    classification_report,
)

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
    "lateral_move_flag",
]


def compute_metrics(y_true, y_pred, model_name: str) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {
        "model": model_name,
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "false_positive_rate": fpr,
        "true_positives": int(tp),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_negatives": int(tn),
    }


def main(input_path: str, test_size: float = 0.3):
    df = pd.read_csv(input_path)

    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing feature columns: {missing}")
    if "is_attack_window" not in df.columns:
        raise ValueError("Need 'is_attack_window' column as ground truth label")

    X = df[FEATURE_COLS]
    y = df["is_attack_window"]

    print(f"Total rows: {len(df)}, attack windows: {y.sum()} ({y.mean()*100:.3f}%)")

    # Stratified split so the (rare) attack windows are represented in both
    # train and test sets proportionally
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=y
    )
    print(f"Train: {len(X_train)} rows ({y_train.sum()} attack) | Test: {len(X_test)} rows ({y_test.sum()} attack)")

    # --- Baseline: Logistic Regression (supervised) ---
    # Features range from 0/1 flags to byte counts in the 100,000s, so scale
    # them first — unscaled inputs make LogReg converge slowly/poorly and
    # give misleadingly weak results that aren't a fair comparison.
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # class_weight="balanced" compensates for the ~0.2% attack rate; without
    # it, LogReg would likely just predict "normal" for everything and still
    # score high accuracy while being useless.
    logreg = LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42)
    logreg.fit(X_train_scaled, y_train)
    y_pred_logreg = logreg.predict(X_test_scaled)

    # --- IsolationForest results (already computed in df, unsupervised) ---
    # Convert sklearn's -1/1 convention to 1/0 (1 = anomaly/attack) to match
    # is_attack_window's convention for fair comparison.
    df_test = df.loc[X_test.index]
    y_pred_iso = (df_test["anomaly_score"] == -1).astype(int)

    results = [
        compute_metrics(y_test, y_pred_logreg, "Logistic Regression (supervised)"),
        compute_metrics(y_test, y_pred_iso, "Isolation Forest (unsupervised)"),
    ]

    results_df = pd.DataFrame(results)
    pd.set_option("display.width", 120)
    print("\n=== Baseline Comparison ===")
    print(results_df.to_string(index=False))

    print("\n=== Logistic Regression classification report ===")
    print(classification_report(y_test, y_pred_logreg, target_names=["Normal", "Attack"], zero_division=0))

    print("\n=== Isolation Forest classification report ===")
    print(classification_report(y_test, y_pred_iso, target_names=["Normal", "Attack"], zero_division=0))

    return results_df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compare IsolationForest vs Logistic Regression baseline")
    parser.add_argument("--input", default="../sih26153-attack-chain-detection/data/host_features_v2_scored.csv")
    parser.add_argument("--test_size", type=float, default=0.3)
    args = parser.parse_args()

    main(args.input, args.test_size)