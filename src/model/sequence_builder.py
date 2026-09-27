"""Build chronological temporal sequences from CIC window features."""

from dataclasses import dataclass
from typing import List, Sequence, Tuple

import numpy as np
import pandas as pd

from src.model.train import FEATURE_COLS


@dataclass
class SequenceDataset:
    """Model inputs, future attack labels, and window metadata."""

    X: np.ndarray
    y: np.ndarray
    metadata: pd.DataFrame


def chronological_split(
    df: pd.DataFrame,
    train_fraction: float = 0.70,
    validation_fraction: float = 0.15,
    time_column: str = "window_start",
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Split rows by distinct timestamps, keeping later periods out of training.

    Rows with the same timestamp always stay in the same partition. Each
    partition is returned in chronological order. Sequences should be built
    independently inside each partition to prevent target leakage.
    """
    if not 0.0 < train_fraction < 1.0:
        raise ValueError("train_fraction must be between 0 and 1")
    if not 0.0 < validation_fraction < 1.0:
        raise ValueError("validation_fraction must be between 0 and 1")
    if train_fraction + validation_fraction >= 1.0:
        raise ValueError("train_fraction + validation_fraction must be < 1")
    if time_column not in df.columns:
        raise ValueError(f"Missing time column: {time_column}")

    result = df.copy()
    parsed_times = pd.to_datetime(result[time_column], errors="coerce", utc=True)

    if parsed_times.isna().any():
        raise ValueError(f"{time_column} contains missing or invalid timestamps")

    unique_times = pd.DatetimeIndex(parsed_times.drop_duplicates().sort_values())
    n_times = len(unique_times)
    if n_times < 3:
        raise ValueError("At least 3 distinct timestamps are required to split")

    train_end_index = max(1, int(n_times * train_fraction))
    validation_end_index = max(
        train_end_index + 1,
        int(n_times * (train_fraction + validation_fraction)),
    )
    validation_end_index = min(validation_end_index, n_times - 1)

    train_end = unique_times[train_end_index]
    validation_end = unique_times[validation_end_index]

    result[time_column] = parsed_times
    train = result[parsed_times < train_end].copy()
    validation = result[
        (parsed_times >= train_end) & (parsed_times < validation_end)
    ].copy()
    test = result[parsed_times >= validation_end].copy()

    if train.empty or validation.empty or test.empty:
        raise ValueError(
            "Chronological split produced an empty partition. "
            "Provide more distinct timestamps or adjust the split fractions."
        )

    return (
        train.sort_values(time_column).reset_index(drop=True),
        validation.sort_values(time_column).reset_index(drop=True),
        test.sort_values(time_column).reset_index(drop=True),
    )


def build_sequences(
    df: pd.DataFrame,
    sequence_length: int = 5,
    forecast_horizon: int = 3,
    window_seconds: int = 30,
    feature_columns: Sequence[str] = FEATURE_COLS,
    group_columns: Sequence[str] = ("src_ip", "dst_ip"),
    time_column: str = "window_start",
    target_column: str = "is_attack_window",
) -> SequenceDataset:
    """Build per-pair sequences and their next-K attack labels.

    A sample with sequence_length=5 and forecast_horizon=3 uses five
    consecutive historical windows as X and the next three windows' labels
    as y. Rows spanning a missing or non-30-second interval are skipped.
    No missing window is fabricated.
    """
    if sequence_length <= 0:
        raise ValueError("sequence_length must be greater than zero")
    if forecast_horizon <= 0:
        raise ValueError("forecast_horizon must be greater than zero")
    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than zero")
    if not feature_columns:
        raise ValueError("feature_columns cannot be empty")
    if not group_columns:
        raise ValueError("group_columns cannot be empty")

    required = list(group_columns) + [time_column, target_column] + list(feature_columns)
    missing = [column for column in required if column not in df.columns]
    if missing:
        raise ValueError(f"Input data is missing required columns: {missing}")

    work = df[required].copy()
    work[time_column] = pd.to_datetime(work[time_column], errors="coerce", utc=True)

    if work[time_column].isna().any():
        raise ValueError(f"{time_column} contains missing or invalid timestamps")
    if work[list(group_columns)].isna().any().any():
        raise ValueError("Grouping columns contain missing values")

    for column in feature_columns:
        work[column] = pd.to_numeric(work[column], errors="coerce")

    feature_values = work[list(feature_columns)].to_numpy(dtype=np.float32)
    if not np.isfinite(feature_values).all():
        raise ValueError("Feature values contain NaN or infinite values")

    labels = pd.to_numeric(work[target_column], errors="coerce").to_numpy()
    if not np.isfinite(labels).all():
        raise ValueError(f"{target_column} contains NaN or infinite values")
    if not np.isin(labels, [0, 1]).all():
        raise ValueError(f"{target_column} must contain only 0 or 1")

    work[target_column] = labels.astype(np.float32)

    X_rows: List[np.ndarray] = []
    y_rows: List[np.ndarray] = []
    metadata_rows = []

    group_arg = list(group_columns)
    for group_key, group in work.groupby(group_arg, sort=False, dropna=False):
        group = group.sort_values(time_column).reset_index(drop=True)

        if group[time_column].duplicated().any():
            raise ValueError(
                "Expected one row per group and timestamp; duplicate "
                f"window found for group {group_key}"
            )

        values = group[list(feature_columns)].to_numpy(dtype=np.float32)
        group_labels = group[target_column].to_numpy(dtype=np.float32)
        time_ns = group[time_column].astype("int64").to_numpy()

        total_length = sequence_length + forecast_horizon
        for start in range(0, len(group) - total_length + 1):
            end = start + total_length
            interval_ns = np.diff(time_ns[start:end])
            expected_interval_ns = window_seconds * 1_000_000_000

            # Do not treat rows separated by a gap as adjacent time steps.
            if not np.all(interval_ns == expected_interval_ns):
                continue

            input_end = start + sequence_length
            target_end = input_end + forecast_horizon

            X_rows.append(values[start:input_end])
            y_rows.append(group_labels[input_end:target_end])

            metadata = {}
            for column in group_columns:
                metadata[column] = group.iloc[input_end - 1][column]
            metadata["current_window"] = group.iloc[input_end - 1][time_column]
            metadata["forecast_window_starts"] = (
                group.iloc[input_end:target_end][time_column].tolist()
            )
            metadata_rows.append(metadata)

    if X_rows:
        X = np.stack(X_rows).astype(np.float32)
        y = np.stack(y_rows).astype(np.float32)
    else:
        X = np.empty(
            (0, sequence_length, len(feature_columns)),
            dtype=np.float32,
        )
        y = np.empty((0, forecast_horizon), dtype=np.float32)

    return SequenceDataset(
        X=X,
        y=y,
        metadata=pd.DataFrame(metadata_rows),
    )