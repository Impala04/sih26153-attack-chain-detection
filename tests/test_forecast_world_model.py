import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import torch

from src.model.forecast_world_model import (
    WorldModelForecaster,
    load_world_model,
)
from src.model.train import FEATURE_COLS
from src.model.world_model import GRUWorldModel


def make_metadata(model_config):
    return {
        "model_type": "GRUWorldModel",
        "feature_columns": list(FEATURE_COLS),
        "window_seconds": 30,
        "model_config": model_config,
        "threshold": 0.6,
        "normalization": {
            "type": "StandardScaler",
            "mean": [0.0] * len(FEATURE_COLS),
            "scale": [1.0] * len(FEATURE_COLS),
        },
        "probability_note": "Test model scores; calibration not established.",
    }


def make_windows(row_count=5, gap_at=None):
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    rows = []

    for index in range(row_count):
        offset = index * 30
        if gap_at is not None and index >= gap_at:
            offset += 30

        row = {column: float(index) for column in FEATURE_COLS}
        row["window_start"] = start + timedelta(seconds=offset)
        rows.append(row)

    return pd.DataFrame(rows)


class WorldModelForecastTests(unittest.TestCase):
    def setUp(self):
        self.model_config = {
            "feature_count": len(FEATURE_COLS),
            "sequence_length": 5,
            "forecast_horizon": 3,
            "hidden_size": 8,
            "num_layers": 1,
            "dropout": 0.0,
        }
        torch.manual_seed(11)
        model = GRUWorldModel(**self.model_config)
        self.forecaster = WorldModelForecaster(
            model=model,
            metadata=make_metadata(self.model_config),
        )

    def test_forecast_returns_timestamped_k_step_result(self):
        result = self.forecaster.forecast(make_windows(), horizon=3)

        self.assertEqual(result.horizon, 3)
        self.assertEqual(len(result.predictions), 3)
        self.assertEqual(
            [item.step for item in result.predictions],
            [1, 2, 3],
        )
        self.assertTrue(
            all(0.0 <= item.probability <= 1.0 for item in result.predictions)
        )
        self.assertTrue(
            all(item.threshold == 0.6 for item in result.predictions)
        )

        forecast_times = [
            pd.Timestamp(item.window_start)
            for item in result.predictions
        ]
        self.assertEqual(
            forecast_times[1] - forecast_times[0],
            pd.Timedelta(seconds=30),
        )

    def test_forecast_result_is_json_serializable(self):
        result = self.forecaster.forecast(make_windows(), horizon=1)

        encoded = json.dumps(result.to_dict())
        self.assertIn('"horizon": 1', encoded)
        self.assertIn('"predicted_attack"', encoded)

    def test_rejects_input_with_a_time_gap(self):
        windows = make_windows(gap_at=3)

        with self.assertRaisesRegex(ValueError, "no gaps"):
            self.forecaster.forecast(windows)

    def test_rejects_non_finite_feature_value(self):
        windows = make_windows()
        windows.loc[0, FEATURE_COLS[0]] = np.nan

        with self.assertRaisesRegex(ValueError, "NaN or infinite"):
            self.forecaster.forecast(windows)

    def test_loads_saved_model_and_forecasts(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            weights_path = root / "world_model.pt"
            metadata_path = root / "world_model_meta.json"

            checkpoint_model = GRUWorldModel(**self.model_config)
            torch.save(
                {
                    "state_dict": checkpoint_model.state_dict(),
                    "model_config": self.model_config,
                },
                weights_path,
            )
            metadata_path.write_text(
                json.dumps(make_metadata(self.model_config))
            )

            loaded_forecaster = load_world_model(weights_path)
            result = loaded_forecaster.forecast(make_windows(), horizon=3)

            self.assertEqual(result.horizon, 3)
            self.assertEqual(len(result.predictions), 3)


if __name__ == "__main__":
    unittest.main()