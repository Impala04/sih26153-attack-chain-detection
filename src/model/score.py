"""
Score incoming windows with the pre-trained IsolationForest model.

For a small selected set, pass ``explain_limit`` and the saved training
reference baseline is used for real local feature ablation explanations.
"""

import argparse
import json
import sys
from pathlib import Path

import joblib
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.explainability import explain_prediction
from src.model.train import (
    add_lateral_move_flag,
    compute_anomaly_risk,
    compute_risk_score,
    LATERAL_MOVE_THRESHOLD,
)

DEFAULT_MODEL_PATH = str(Path(__file__).resolve().parents[2] / "models" / "isolation_forest.joblib")


def load_model_and_features(model_path: str = DEFAULT_MODEL_PATH):
    model = joblib.load(model_path)
    meta_path = str(Path(model_path).with_suffix(".meta.json"))
    with open(meta_path, encoding="utf-8") as f:
        meta = json.load(f)
    return model, meta["feature_cols"]


def score_dataframe(
    df: pd.DataFrame,
    model_path: str = DEFAULT_MODEL_PATH,
    *,
    explain_limit: int = 0,
    explanation_top_k: int = 5,
) -> pd.DataFrame:
    """Score host-window rows; optionally explain only the first selected rows.

    Set ``explain_limit`` to a small positive count to attach JSON explanation
    strings. Explanations use local single-feature ablation against training
    feature medians stored in model metadata.
    """
    if explain_limit < 0:
        raise ValueError("explain_limit cannot be negative")
    model, feature_cols = load_model_and_features(model_path)
    df = df.copy()

    if "lateral_move_flag" not in df.columns:
        df = add_lateral_move_flag(df, threshold=LATERAL_MOVE_THRESHOLD)

    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        raise ValueError(
            f"Input data is missing columns the model expects: {missing}. "
            "Check upstream feature extraction against the training schema."
        )

    X = df[feature_cols]
    df["anomaly_score"] = model.predict(X)
    df["anomaly_score_raw"] = model.decision_function(X)
    df = compute_anomaly_risk(df)
    df = compute_risk_score(df)
    df["explanation"] = None

    if explain_limit:
        meta_path = Path(model_path).with_suffix(".meta.json")
        with meta_path.open(encoding="utf-8") as f:
            baseline = json.load(f).get("reference_features")
        if baseline is None:
            raise ValueError("Model metadata has no reference_features baseline; retrain to enable explanations")
        selected = min(explain_limit, len(df))
        for position in range(selected):
            row = df.iloc[position][feature_cols]
            result = explain_prediction(
                model,
                row.to_dict(),
                prediction=float(-df.iloc[position]["anomaly_score_raw"]),
                top_k=explanation_top_k,
                baseline=baseline,
            )
            df.iat[position, df.columns.get_loc("explanation")] = json.dumps(result, allow_nan=False)
    return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Score new data with the trained CyberFlux model")
    parser.add_argument("--input", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--model", default=DEFAULT_MODEL_PATH)
    parser.add_argument("--explain-limit", type=int, default=0)
    args = parser.parse_args()

    raw_df = pd.read_csv(args.input)
    scored = score_dataframe(raw_df, model_path=args.model, explain_limit=args.explain_limit)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    scored.to_csv(args.out, index=False)
    print(f"Scored {scored.shape[0]} rows -> {args.out}")
    print(scored[["Source IP", "time_window", "anomaly_risk", "risk_score"]].head(10) if "Source IP" in scored.columns else scored.head(10))
