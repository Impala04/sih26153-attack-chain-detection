"""Load a trained World Model and produce timestamped K-step forecasts."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Union

import numpy as np
import pandas as pd
import torch

from src.model.train import FEATURE_COLS
from src.model.world_model import GRUWorldModel


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL_PATH = REPOSITORY_ROOT / "models" / "world_model" / "world_model.pt"


@dataclass
class ForecastStep:
    """Prediction for one future 30-second window."""

    step: int
    window_start: str
    probability: float
    threshold: float
    predicted_attack: bool

    def to_dict(self) -> Dict[str, object]:
        return {
            "step": self.step,
            "window_start": self.window_start,
            "probability": self.probability,
            "threshold": self.threshold,
            "predicted_attack": self.predicted_attack,
        }


@dataclass
class ForecastResult:
    """Structured forecast output for downstream integration."""

    current_window: str
    horizon: int
    predictions: List[ForecastStep]
    model_type: str
    probability_note: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "current_window": self.current_window,
            "horizon": self.horizon,
            "predictions": [step.to_dict() for step in self.predictions],
            "model_type": self.model_type,
            "probability_note": self.probability_note,
        }


class WorldModelForecaster:
    """Apply stored normalization and forecast future attack probabilities."""

    def __init__(
        self,
        model: GRUWorldModel,
        metadata: Dict[str, object],
    ) -> None:
        self.model = model
        self.metadata = metadata

        expected_columns = list(FEATURE_COLS)
        if metadata.get("feature_columns") != expected_columns:
            raise ValueError(
                "Model metadata feature_columns do not match the current "
                "Phase 1 feature order"
            )

        normalization = metadata.get("normalization")
        if not isinstance(normalization, dict):
            raise ValueError("Model metadata has no normalization settings")

        if normalization.get("type") != "StandardScaler":
            raise ValueError("Unsupported normalization type in model metadata")

        self.mean = np.asarray(normalization.get("mean"), dtype=np.float32)
        self.scale = np.asarray(normalization.get("scale"), dtype=np.float32)

        expected_shape = (len(expected_columns),)
        if self.mean.shape != expected_shape or self.scale.shape != expected_shape:
            raise ValueError(
                "Scaler mean and scale must each contain one value per feature"
            )
        if not np.isfinite(self.mean).all() or not np.isfinite(self.scale).all():
            raise ValueError("Scaler metadata contains NaN or infinite values")
        if np.any(self.scale <= 0):
            raise ValueError("Scaler values must all be greater than zero")

        self.threshold = float(metadata["threshold"])
        if not 0.0 <= self.threshold <= 1.0:
            raise ValueError("Model threshold must be between 0 and 1")

        self.window_seconds = int(metadata["window_seconds"])
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be greater than zero")

        self.model_type = str(metadata.get("model_type", "GRUWorldModel"))
        self.probability_note = str(
            metadata.get(
                "probability_note",
                "Sigmoid scores; calibration has not been established.",
            )
        )

    def forecast(
        self,
        windows: pd.DataFrame,
        horizon: Optional[int] = None,
    ) -> ForecastResult:
        """Forecast using exactly sequence_length ordered, consecutive windows.

        `windows` must contain the Phase 1 feature columns and `window_start`.
        Feature columns are selected in the saved training order regardless
        of their order in the input dataframe.
        """
        if not isinstance(windows, pd.DataFrame):
            raise TypeError("windows must be a pandas DataFrame")

        required_columns = list(FEATURE_COLS) + ["window_start"]
        missing = [column for column in required_columns if column not in windows]
        if missing:
            raise ValueError(f"Input windows are missing columns: {missing}")

        expected_rows = self.model.sequence_length
        if len(windows) != expected_rows:
            raise ValueError(
                f"Expected {expected_rows} input windows, received {len(windows)}"
            )

        timestamps = pd.to_datetime(
            windows["window_start"],
            errors="coerce",
            utc=True,
        )
        if timestamps.isna().any():
            raise ValueError("window_start contains invalid timestamps")

        step_s = int(self.window_seconds)
        timestamps = timestamps.dt.floor(f"{step_s}s")

        # Force nanosecond resolution explicitly: pandas >= 3.0 defaults
        # pd.to_datetime(..., utc=True) to microsecond resolution rather
        # than the nanosecond resolution pandas 2.x used, which silently
        # broke the interval check below (it compared against a
        # hardcoded nanosecond-per-second constant). Casting explicitly
        # makes this correct regardless of the pandas version's default.
        timestamp_ns = (
            timestamps.dt.tz_convert(None)
            .to_numpy()
            .astype("datetime64[ns]")
            .astype("int64")
        )
        step_ns = int(self.window_seconds) * 1_000_000_000
        if not np.all(np.diff(timestamp_ns) == step_ns):
            raise ValueError(
                "Input windows must be in chronological order with no gaps; "
                f"expected {self.window_seconds}-second intervals"
            )

        try:
            raw_values = windows[list(FEATURE_COLS)].apply(
                pd.to_numeric,
                errors="raise",
            ).to_numpy(dtype=np.float32)
        except (TypeError, ValueError) as exc:
            raise ValueError("Feature columns must contain numeric values") from exc

        if not np.isfinite(raw_values).all():
            raise ValueError("Feature values contain NaN or infinite values")

        normalized_values = (raw_values - self.mean) / self.scale
        probabilities = self.model.forecast(
            normalized_values,
            horizon=horizon,
        )

        actual_horizon = len(probabilities)
        current_time = timestamps.iloc[-1]
        predictions = []

        for step_index, probability in enumerate(probabilities, start=1):
            future_time = current_time + pd.Timedelta(
                seconds=self.window_seconds * step_index
            )
            probability_value = float(probability)
            predictions.append(
                ForecastStep(
                    step=step_index,
                    window_start=future_time.isoformat(),
                    probability=probability_value,
                    threshold=self.threshold,
                    predicted_attack=probability_value >= self.threshold,
                )
            )

        return ForecastResult(
            current_window=timestamps.iloc[-1].isoformat(),
            horizon=actual_horizon,
            predictions=predictions,
            model_type=self.model_type,
            probability_note=self.probability_note,
        )


def load_world_model(
    model_path: Union[str, Path] = DEFAULT_MODEL_PATH,
) -> WorldModelForecaster:
    """Load model weights and adjacent world_model_meta.json metadata."""
    weights_path = Path(model_path)
    if not weights_path.is_absolute():
        weights_path = REPOSITORY_ROOT / weights_path
    metadata_path = weights_path.with_name("world_model_meta.json")

    if not weights_path.is_file():
        raise FileNotFoundError(f"World Model weights not found: {weights_path}")
    if not metadata_path.is_file():
        raise FileNotFoundError(f"World Model metadata not found: {metadata_path}")

    try:
        metadata = json.loads(metadata_path.read_text())
        if not isinstance(metadata, dict):
            raise ValueError("metadata root must be a JSON object")
        model_config = metadata.get("model_config")
        if not isinstance(model_config, dict):
            raise ValueError("Model metadata has no model_config")

        checkpoint = torch.load(weights_path, map_location="cpu")
        if not isinstance(checkpoint, dict) or "state_dict" not in checkpoint:
            raise ValueError("Model checkpoint does not contain a state_dict")
        if checkpoint.get("model_config") != model_config:
            raise ValueError("Checkpoint model_config does not match metadata")

        model = GRUWorldModel(**model_config)
        model.load_state_dict(checkpoint["state_dict"])
        model.eval()
        return WorldModelForecaster(model=model, metadata=metadata)
    except Exception as exc:  # noqa: BLE001 - convert artifact errors to API-safe config errors
        raise ValueError(
            "Invalid World Model artifact; expected compatible weights and "
            f"metadata at {weights_path} and {metadata_path}: {exc}"
        ) from exc
