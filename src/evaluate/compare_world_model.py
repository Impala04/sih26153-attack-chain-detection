"""Compare World Model forecasts with a current-window Logistic Regression baseline."""

"""Compare World Model forecasts with a current-window Logistic Regression baseline."""

import argparse
import json
from pathlib import Path
from typing import Dict, Tuple

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression

from src.model.forecast_world_model import load_world_model
from src.model.sequence_builder import (
    build_sequences,
    chronological_split,
    densify_pair_windows,
)
from src.model.train import FEATURE_COLS, add_lateral_move_flag
from src.model.train_world_model import calculate_metrics, choose_threshold


def scale_partition(
    frame: pd.DataFrame,
    mean: np.ndarray,
    scale: np.ndarray,
) -> pd.DataFrame:
    """Use the exact StandardScaler parameters saved with the GRU."""
    result = frame.copy()
    raw = result[FEATURE_COLS].apply(pd.to_numeric, errors="raise").to_numpy(
        dtype=np.float32
    )
    if not np.isfinite(raw).all():
        raise ValueError("Feature data contains NaN or infinite values")

    # Convert integer columns to floating point before writing scaled values.
    result[FEATURE_COLS] = result[FEATURE_COLS].astype(np.float32)
    result.loc[:, FEATURE_COLS] = (raw - mean) / scale
    return result


def summarize_horizons(
    y_true: np.ndarray,
    probabilities: np.ndarray,
    threshold: float,
) -> Dict[str, object]:
    """Return combined metrics and metrics separately for each future step."""
    result: Dict[str, object] = {
        "all_horizons": calculate_metrics(y_true, probabilities, threshold),
        "per_horizon": {},
    }

    per_horizon = {}
    for index in range(y_true.shape[1]):
        per_horizon[f"step_{index + 1}"] = calculate_metrics(
            y_true[:, index : index + 1],
            probabilities[:, index : index + 1],
            threshold,
        )
    result["per_horizon"] = per_horizon
    return result


def load_temporal_datasets(
    input_path: str,
    forecaster,
) -> Tuple[object, object, object]:
    """Build train/validation/test sequences using saved model preprocessing."""
    frame = pd.read_csv(input_path)

    if "lateral_move_flag" not in frame.columns:
        if "unique_destinations" not in frame.columns:
            raise ValueError(
                "Cannot derive lateral_move_flag: "
                "unique_destinations is missing."
            )
        frame = add_lateral_move_flag(frame)

    required_columns = (
        list(FEATURE_COLS)
        + ["src_ip", "dst_ip", "window_start", "is_attack_window"]
    )
    missing = [column for column in required_columns if column not in frame]
    if missing:
        raise ValueError(f"Input CSV is missing required columns: {missing}")

    train_frame, validation_frame, test_frame = chronological_split(frame)

    # Match training: fill short missing pair windows independently in each
    # chronological partition, before applying the saved normalization.
    window_seconds = forecaster.window_seconds
    train_frame = densify_pair_windows(
        train_frame, window_seconds=window_seconds
    )
    validation_frame = densify_pair_windows(
        validation_frame, window_seconds=window_seconds
    )
    test_frame = densify_pair_windows(
        test_frame, window_seconds=window_seconds
    )

    normalization = forecaster.metadata["normalization"]
    mean = np.asarray(normalization["mean"], dtype=np.float32)
    scale = np.asarray(normalization["scale"], dtype=np.float32)

    sequence_length = forecaster.model.sequence_length
    horizon = forecaster.model.forecast_horizon

    options = {
        "sequence_length": sequence_length,
        "forecast_horizon": horizon,
        "window_seconds": window_seconds,
    }

    train_data = build_sequences(
        scale_partition(train_frame, mean, scale),
        **options,
    )
    validation_data = build_sequences(
        scale_partition(validation_frame, mean, scale),
        **options,
    )
    test_data = build_sequences(
        scale_partition(test_frame, mean, scale),
        **options,
    )

    for name, dataset in (
        ("training", train_data),
        ("validation", validation_data),
        ("test", test_data),
    ):
        if len(dataset.X) == 0:
            raise ValueError(
                f"No {name} sequences found after filling short "
                "within-pair gaps. Check the input timestamps and "
                "capture-session gaps."
            )

    return train_data, validation_data, test_data


def fit_logistic_baseline(
    train_data,
    validation_data,
    test_data,
    seed: int,
) -> Tuple[np.ndarray, np.ndarray]:
    """Fit one LR model per future step, using the latest input window."""
    X_train = train_data.X[:, -1, :]
    X_validation = validation_data.X[:, -1, :]
    X_test = test_data.X[:, -1, :]

    horizon = train_data.y.shape[1]
    validation_probabilities = np.zeros(
        (len(X_validation), horizon),
        dtype=np.float32,
    )
    test_probabilities = np.zeros(
        (len(X_test), horizon),
        dtype=np.float32,
    )

    for step_index in range(horizon):
        y_train_step = train_data.y[:, step_index].astype(int)
        if len(np.unique(y_train_step)) != 2:
            raise ValueError(
                f"Logistic Regression cannot train for future step "
                f"{step_index + 1}: its training labels contain only one class."
            )

        model = LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            random_state=seed,
        )
        model.fit(X_train, y_train_step)

        validation_probabilities[:, step_index] = model.predict_proba(
            X_validation
        )[:, 1]
        test_probabilities[:, step_index] = model.predict_proba(X_test)[:, 1]

    return validation_probabilities, test_probabilities


def compare_models(
    input_path: str,
    model_path: str,
    seed: int = 42,
) -> Dict[str, object]:
    """Evaluate GRU and LR on the same chronological future-label samples."""
    forecaster = load_world_model(model_path)
    train_data, validation_data, test_data = load_temporal_datasets(
        input_path,
        forecaster,
    )

    gru_validation_probabilities = forecaster.model.forecast(
        validation_data.X
    )
    gru_test_probabilities = forecaster.model.forecast(test_data.X)

    lr_validation_probabilities, lr_test_probabilities = fit_logistic_baseline(
        train_data,
        validation_data,
        test_data,
        seed,
    )

    # The GRU threshold was selected on validation data by its training script.
    gru_threshold = forecaster.threshold

    # Select the LR threshold on the same validation period, never on test data.
    lr_threshold = choose_threshold(
        validation_data.y,
        lr_validation_probabilities,
    )

    results = {
        "dataset": str(input_path),
        "model": str(model_path),
        "comparison_method": (
            "Both models use identical chronological train/validation/test "
            "splits and future labels. The GRU uses the full input sequence; "
            "Logistic Regression uses only the latest window in that sequence."
        ),
        "sequence_counts": {
            "train": len(train_data.X),
            "validation": len(validation_data.X),
            "test": len(test_data.X),
        },
        "forecast_horizon": int(train_data.y.shape[1]),
        "thresholds": {
            "gru_validation_selected": float(gru_threshold),
            "logistic_regression_validation_selected": float(lr_threshold),
        },
        "test_metrics": {
            "gru_world_model": summarize_horizons(
                test_data.y,
                gru_test_probabilities,
                gru_threshold,
            ),
            "logistic_regression": summarize_horizons(
                test_data.y,
                lr_test_probabilities,
                lr_threshold,
            ),
        },
    }
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Compare the World Model against a Logistic Regression "
            "future-forecast baseline."
        )
    )
    parser.add_argument("--input", required=True, help="Window-feature CSV")
    parser.add_argument(
        "--model",
        default="models/world_model/world_model.pt",
        help="Saved World Model weights",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Optional JSON output path for the comparison",
    )
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    results = compare_models(
        input_path=args.input,
        model_path=args.model,
        seed=args.seed,
    )

    output = json.dumps(results, indent=2)
    print(output)

    if args.out:
        output_path = Path(args.out)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output)
        print(f"Saved comparison results to {output_path}")


if __name__ == "__main__":
    main()