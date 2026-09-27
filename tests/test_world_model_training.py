import json
import tempfile
import unittest
from argparse import Namespace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import pytest

pytest.importorskip("torch")

from src.model.train import FEATURE_COLS
from src.model.train_world_model import train_world_model


def make_synthetic_feature_frame(row_count=180):
    """Create synthetic consecutive windows only for a training smoke test."""
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    rows = []

    for index in range(row_count):
        row = {
            column: float((index + column_index) % 17)
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


class WorldModelTrainingTests(unittest.TestCase):
    def test_training_saves_model_metadata_and_metrics(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            input_path = root / "synthetic_windows.csv"
            output_directory = root / "artifacts"

            make_synthetic_feature_frame().to_csv(input_path, index=False)

            args = Namespace(
                input=str(input_path),
                output_dir=str(output_directory),
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

            train_world_model(args)

            model_path = output_directory / "world_model.pt"
            metadata_path = output_directory / "world_model_meta.json"
            metrics_path = output_directory / "world_model_metrics.json"

            self.assertTrue(model_path.is_file())
            self.assertTrue(metadata_path.is_file())
            self.assertTrue(metrics_path.is_file())

            metadata = json.loads(metadata_path.read_text())
            metrics = json.loads(metrics_path.read_text())

            self.assertEqual(metadata["model_type"], "GRUWorldModel")
            self.assertEqual(metadata["feature_columns"], list(FEATURE_COLS))
            self.assertEqual(metadata["model_config"]["forecast_horizon"], 2)
            self.assertEqual(metadata["normalization"]["fit_on"], "training rows only")
            self.assertGreaterEqual(metadata["threshold"], 0.0)
            self.assertLessEqual(metadata["threshold"], 1.0)

            self.assertGreater(metrics["sequence_counts"]["train"], 0)
            self.assertGreater(metrics["sequence_counts"]["validation"], 0)
            self.assertGreater(metrics["sequence_counts"]["test"], 0)
            self.assertIn("f1", metrics["test"])
            self.assertIn("false_positive_rate", metrics["test"])


if __name__ == "__main__":
    unittest.main()