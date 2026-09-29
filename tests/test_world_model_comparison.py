import io
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

pytest.importorskip("torch")

import pandas as pd

from src.evaluate.compare_world_model import compare_models
from src.model.train import FEATURE_COLS
from src.model.train_world_model import train_world_model


def make_synthetic_frame(row_count=240):
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    rows = []

    for index in range(row_count):
        row = {
            column: float((index + column_index) % 19)
            for column_index, column in enumerate(FEATURE_COLS)
        }
        row.update(
            {
                "src_ip": "192.168.10.5",
                "dst_ip": "192.168.10.3",
                "window_start": start + timedelta(seconds=30 * index),
                "is_attack_window": int((index % 8) >= 5),
            }
        )
        rows.append(row)

    return pd.DataFrame(rows)


class WorldModelComparisonTests(unittest.TestCase):
    def test_gru_and_logistic_regression_compare_on_same_future_targets(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            input_path = root / "synthetic_windows.csv"
            model_directory = root / "model"
            model_path = model_directory / "world_model.pt"

            make_synthetic_frame().to_csv(input_path, index=False)

            args = Namespace(
                input=str(input_path),
                output_dir=str(model_directory),
                sequence_length=3,
                forecast_horizon=2,
                window_seconds=30,
                hidden_size=4,
                num_layers=1,
                dropout=0.0,
                learning_rate=0.001,
                batch_size=32,
                epochs=2,
                patience=1,
                seed=42,
            )

            # Suppress training metrics from this synthetic smoke test.
            with redirect_stdout(io.StringIO()):
                train_world_model(args)

            results = compare_models(
                input_path=str(input_path),
                model_path=str(model_path),
                seed=42,
            )

            self.assertEqual(results["forecast_horizon"], 2)
            self.assertGreater(results["sequence_counts"]["train"], 0)
            self.assertGreater(results["sequence_counts"]["validation"], 0)
            self.assertGreater(results["sequence_counts"]["test"], 0)

            test_metrics = results["test_metrics"]
            self.assertIn("gru_world_model", test_metrics)
            self.assertIn("logistic_regression", test_metrics)
            self.assertIn(
                "f1",
                test_metrics["gru_world_model"]["all_horizons"],
            )
            self.assertIn(
                "false_positive_rate",
                test_metrics["logistic_regression"]["all_horizons"],
            )
            self.assertIn(
                "step_1",
                test_metrics["gru_world_model"]["per_horizon"],
            )
            self.assertIn(
                "step_2",
                test_metrics["logistic_regression"]["per_horizon"],
            )


if __name__ == "__main__":
    unittest.main()