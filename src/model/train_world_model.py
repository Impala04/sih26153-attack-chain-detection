"""Train the temporal GRU World Model on windowed feature data."""

import argparse
import json
import random
from copy import deepcopy
from pathlib import Path
from typing import Dict

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import StandardScaler
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from src.model.sequence_builder import (
    build_sequences,
    chronological_split,
    densify_pair_windows,
)
from src.model.train import FEATURE_COLS, add_lateral_move_flag
from src.model.world_model import GRUWorldModel


def set_reproducible_seed(seed: int) -> None:
    """Set Python, NumPy, and PyTorch seeds for repeatable CPU training."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.use_deterministic_algorithms(True)


def scale_partition(
    frame: pd.DataFrame,
    scaler: StandardScaler,
) -> pd.DataFrame:
    """Apply a scaler that was fitted on training rows only."""
    result = frame.copy()
    result[FEATURE_COLS] = result[FEATURE_COLS].astype(np.float32)
    result[FEATURE_COLS] = scaler.transform(
        result[FEATURE_COLS]
    ).astype(np.float32)
    return result


def choose_threshold(y_true: np.ndarray, probabilities: np.ndarray) -> float:
    """Choose the F1-maximizing threshold using validation data only."""
    flat_labels = y_true.reshape(-1).astype(int)
    flat_probabilities = probabilities.reshape(-1)

    # With no positive validation examples, F1 cannot select a useful
    # threshold. Use the conventional default and report validation metrics.
    if int(flat_labels.sum()) == 0:
        return 0.5

    best_threshold = 0.5
    best_f1 = -1.0

    for threshold in np.linspace(0.05, 0.95, 91):
        predictions = (flat_probabilities >= threshold).astype(int)
        score = f1_score(flat_labels, predictions, zero_division=0)

        # On ties, prefer the higher threshold to avoid unnecessary alerts.
        if score > best_f1 or (
            score == best_f1 and threshold > best_threshold
        ):
            best_f1 = float(score)
            best_threshold = float(threshold)

    return best_threshold


def calculate_metrics(
    y_true: np.ndarray,
    probabilities: np.ndarray,
    threshold: float,
) -> Dict[str, object]:
    """Calculate metrics from real labels and model probabilities."""
    labels = y_true.reshape(-1).astype(int)
    scores = probabilities.reshape(-1)
    predictions = (scores >= threshold).astype(int)

    true_negative = int(((labels == 0) & (predictions == 0)).sum())
    false_positive = int(((labels == 0) & (predictions == 1)).sum())
    false_negative = int(((labels == 1) & (predictions == 0)).sum())
    true_positive = int(((labels == 1) & (predictions == 1)).sum())

    false_positive_rate = (
        false_positive / (false_positive + true_negative)
        if false_positive + true_negative
        else 0.0
    )

    has_both_classes = len(np.unique(labels)) == 2
    auc = (
        float(roc_auc_score(labels, scores))
        if has_both_classes
        else None
    )
    average_precision = (
        float(average_precision_score(labels, scores))
        if int(labels.sum()) > 0
        else None
    )

    return {
        "threshold": float(threshold),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
        "false_positive_rate": float(false_positive_rate),
        "accuracy": float(accuracy_score(labels, predictions)),
        "roc_auc": auc,
        "average_precision": average_precision,
        "brier_score": float(brier_score_loss(labels, scores)),
        "true_negative": true_negative,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "true_positive": true_positive,
    }


def evaluate_loss(
    model: GRUWorldModel,
    X: torch.Tensor,
    y: torch.Tensor,
    loss_function: nn.Module,
) -> float:
    """Return mean validation loss."""
    model.eval()
    with torch.no_grad():
        loss = loss_function(model(X), y)
    return float(loss.item())


def train_world_model(args: argparse.Namespace) -> None:
    """Load data, train the GRU, evaluate it, and save model artifacts."""
    set_reproducible_seed(args.seed)

    input_path = Path(args.input)
    if not input_path.is_file():
        raise FileNotFoundError(f"Input CSV not found: {input_path}")

    frame = pd.read_csv(input_path)
    if frame.empty:
        raise ValueError(f"Input CSV contains no rows: {input_path}")

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
    missing = [column for column in required_columns if column not in frame.columns]
    if missing:
        raise ValueError(f"Input CSV is missing required columns: {missing}")

    train_frame, validation_frame, test_frame = chronological_split(frame)
    train_frame = densify_pair_windows(
    train_frame, window_seconds=args.window_seconds
    )
    validation_frame = densify_pair_windows(
        validation_frame, window_seconds=args.window_seconds
    )
    test_frame = densify_pair_windows(
        test_frame, window_seconds=args.window_seconds
    )

    # Fit normalization on training rows only to prevent future-data leakage.
    scaler = StandardScaler()
    scaler.fit(train_frame[FEATURE_COLS])

    train_scaled = scale_partition(train_frame, scaler)
    validation_scaled = scale_partition(validation_frame, scaler)
    test_scaled = scale_partition(test_frame, scaler)

    sequence_options = {
        "sequence_length": args.sequence_length,
        "forecast_horizon": args.forecast_horizon,
        "window_seconds": args.window_seconds,
    }
    train_data = build_sequences(train_scaled, **sequence_options)
    validation_data = build_sequences(validation_scaled, **sequence_options)
    test_data = build_sequences(test_scaled, **sequence_options)

    for name, dataset in (
        ("training", train_data),
        ("validation", validation_data),
        ("test", test_data),
    ):
        if len(dataset.X) == 0:
            raise ValueError(
                f"No {name} sequences were constructed. The input needs "
                "enough consecutive windows for each source-destination pair."
            )

    y_train = train_data.y
    positive_count = int(y_train.sum())
    negative_count = int(y_train.size - positive_count)
    if positive_count == 0 or negative_count == 0:
        raise ValueError(
            "Training targets must contain both benign and attack labels; "
            f"found {negative_count} benign and {positive_count} attack targets."
        )

    X_train = torch.from_numpy(train_data.X)
    y_train_tensor = torch.from_numpy(train_data.y)
    X_validation = torch.from_numpy(validation_data.X)
    y_validation = torch.from_numpy(validation_data.y)
    X_test = torch.from_numpy(test_data.X)

    generator = torch.Generator()
    generator.manual_seed(args.seed)
    train_loader = DataLoader(
        TensorDataset(X_train, y_train_tensor),
        batch_size=args.batch_size,
        shuffle=True,
        generator=generator,
        num_workers=0,
    )

    model_config = {
        "feature_count": len(FEATURE_COLS),
        "sequence_length": args.sequence_length,
        "forecast_horizon": args.forecast_horizon,
        "hidden_size": args.hidden_size,
        "num_layers": args.num_layers,
        "dropout": args.dropout,
    }
    model = GRUWorldModel(**model_config)

    positive_weight = torch.tensor(
        [negative_count / positive_count],
        dtype=torch.float32,
    )
    loss_function = nn.BCEWithLogitsLoss(pos_weight=positive_weight)
    optimizer = torch.optim.Adam(model.parameters(), lr=args.learning_rate)

    best_validation_loss = float("inf")
    best_state = None
    epochs_without_improvement = 0

    for epoch in range(1, args.epochs + 1):
        model.train()
        for batch_X, batch_y in train_loader:
            optimizer.zero_grad()
            logits = model(batch_X)
            loss = loss_function(logits, batch_y)
            loss.backward()
            optimizer.step()

        validation_loss = evaluate_loss(
            model,
            X_validation,
            y_validation,
            loss_function,
        )
        print(
            f"Epoch {epoch}/{args.epochs} "
            f"train_batches={len(train_loader)} "
            f"validation_loss={validation_loss:.6f}"
        )

        if validation_loss < best_validation_loss:
            best_validation_loss = validation_loss
            best_state = deepcopy(model.state_dict())
            epochs_without_improvement = 0
        else:
            epochs_without_improvement += 1

        if epochs_without_improvement >= args.patience:
            print(f"Early stopping after epoch {epoch}")
            break

    if best_state is None:
        raise RuntimeError("Training did not produce a valid model checkpoint")

    model.load_state_dict(best_state)
    model.eval()

    with torch.no_grad():
        validation_probabilities = torch.sigmoid(
            model(X_validation)
        ).cpu().numpy()
        test_probabilities = torch.sigmoid(
            model(X_test)
        ).cpu().numpy()

    # Pick the operating threshold on validation data, then freeze it for test.
    threshold = choose_threshold(
        validation_data.y,
        validation_probabilities,
    )
    validation_metrics = calculate_metrics(
        validation_data.y,
        validation_probabilities,
        threshold,
    )
    test_metrics = calculate_metrics(
        test_data.y,
        test_probabilities,
        threshold,
    )

    output_directory = Path(args.output_dir)
    output_directory.mkdir(parents=True, exist_ok=True)

    model_path = output_directory / "world_model.pt"
    metadata_path = output_directory / "world_model_meta.json"
    metrics_path = output_directory / "world_model_metrics.json"

    torch.save(
        {
            "state_dict": model.state_dict(),
            "model_config": model_config,
        },
        model_path,
    )

    metadata = {
        "model_type": "GRUWorldModel",
        "version": 1,
        "feature_columns": list(FEATURE_COLS),
        "group_columns": ["src_ip", "dst_ip"],
        "target_column": "is_attack_window",
        "window_seconds": args.window_seconds,
        "model_config": model_config,
        "threshold": threshold,
        "normalization": {
            "type": "StandardScaler",
            "fit_on": "training rows only",
            "mean": scaler.mean_.tolist(),
            "scale": scaler.scale_.tolist(),
        },
        "training": {
            "seed": args.seed,
            "epochs_requested": args.epochs,
            "best_validation_loss": best_validation_loss,
            "batch_size": args.batch_size,
            "learning_rate": args.learning_rate,
            "positive_weight": negative_count / positive_count,
        },
        "split_ranges": {
            "train_start": str(train_frame["window_start"].min()),
            "train_end": str(train_frame["window_start"].max()),
            "validation_start": str(validation_frame["window_start"].min()),
            "validation_end": str(validation_frame["window_start"].max()),
            "test_start": str(test_frame["window_start"].min()),
            "test_end": str(test_frame["window_start"].max()),
        },
        "probability_note": (
            "Outputs are sigmoid scores. Calibration has not been established."
        ),
    }
    metadata_path.write_text(json.dumps(metadata, indent=2))

    metrics = {
        "validation": validation_metrics,
        "test": test_metrics,
        "sequence_counts": {
            "train": len(train_data.X),
            "validation": len(validation_data.X),
            "test": len(test_data.X),
        },
    }
    metrics_path.write_text(json.dumps(metrics, indent=2))

    print(f"Saved model: {model_path}")
    print(f"Saved metadata: {metadata_path}")
    print(f"Saved metrics: {metrics_path}")
    print(f"Validation threshold selected: {threshold:.2f}")
    print("Test metrics:")
    print(json.dumps(test_metrics, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Train a chronological multi-step GRU attack forecaster."
    )
    parser.add_argument("--input", required=True, help="Window-feature CSV path")
    parser.add_argument(
        "--output-dir",
        default="models/world_model",
        help="Directory where model and metadata will be saved",
    )
    parser.add_argument("--sequence-length", type=int, default=5)
    parser.add_argument("--forecast-horizon", type=int, default=3)
    parser.add_argument("--window-seconds", type=int, default=30)
    parser.add_argument("--hidden-size", type=int, default=32)
    parser.add_argument("--num-layers", type=int, default=1)
    parser.add_argument("--dropout", type=float, default=0.1)
    parser.add_argument("--learning-rate", type=float, default=0.001)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--patience", type=int, default=7)
    parser.add_argument("--seed", type=int, default=42)
    return parser


if __name__ == "__main__":
    train_world_model(build_parser().parse_args())