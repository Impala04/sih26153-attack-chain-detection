import tempfile
import unittest
from pathlib import Path

import pandas as pd

from src.ingestion.csv_adapter import build_events_from_csv
from src.model.train import train


def _base_row(**overrides):
    row = {
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.9",
        "window_start": "2025-01-01 12:00:00",
        "connection_count": 5,
        "unique_destinations": 1,
        "unique_ports": 5,
        "total_fwd_packets": 5,
        "total_bwd_packets": 5,
        "total_bytes_fwd": 500,
        "total_bytes_bwd": 500,
        "avg_flow_duration": 1000.0,
        "max_flow_duration": 2000.0,
        "std_flow_duration": 100.0,
        "max_bytes_total": 200.0,
        "std_bytes_total": 20.0,
        "max_packets_total": 5.0,
        "bytes_per_connection": 100.0,
        "flows_per_second": 0.2,
    }
    row.update(overrides)
    return row


class CsvAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _write_csv(self, rows, name="input.csv"):
        path = self.tmp_path / name
        pd.DataFrame(rows).to_csv(path, index=False)
        return str(path)

    def test_missing_column_raises(self):
        df = pd.DataFrame([_base_row()]).drop(columns=["unique_ports"])
        path = self.tmp_path / "bad.csv"
        df.to_csv(path, index=False)
        with self.assertRaises(ValueError) as ctx:
            build_events_from_csv(str(path))
        self.assertIn("unique_ports", str(ctx.exception))

    def test_bad_timestamp_row_is_dropped_not_crashed(self):
        rows = [_base_row(), _base_row(window_start="not-a-date", src_ip="10.0.0.6")]
        path = self._write_csv(rows)
        events = build_events_from_csv(path)  # should not raise
        self.assertIsInstance(events, list)

    def test_all_bad_rows_raises(self):
        rows = [_base_row(window_start="not-a-date")]
        path = self._write_csv(rows)
        with self.assertRaises(ValueError):
            build_events_from_csv(path)

    def test_lateral_movement_row_produces_event(self):
        rows = [_base_row(unique_destinations=10, lateral_move_flag=1)]
        path = self._write_csv(rows)
        events = build_events_from_csv(path)
        self.assertTrue(any(e.detection_type == "suspicious_traffic" for e in events))

    def test_lateral_move_flag_auto_computed_when_missing(self):
        rows = [_base_row(unique_destinations=10)]  # no lateral_move_flag column at all
        path = self._write_csv(rows)
        events = build_events_from_csv(path)
        self.assertTrue(any(e.detection_type == "suspicious_traffic" for e in events))

    def test_scoring_attaches_metadata(self):
        train_rows = [
            _base_row(window_start=f"2025-01-01 12:{i:02d}:00") for i in range(20)
        ]
        for i in range(3):
            train_rows.append(_base_row(
                window_start=f"2025-01-01 13:{i:02d}:00",
                connection_count=300, unique_destinations=60, unique_ports=300,
                total_fwd_packets=300, total_bwd_packets=0, total_bytes_fwd=30000,
                total_bytes_bwd=0, avg_flow_duration=5.0, max_flow_duration=10.0,
                std_flow_duration=2.0, max_bytes_total=1000.0, std_bytes_total=300.0,
                max_packets_total=10.0, bytes_per_connection=100.0, flows_per_second=60.0,
            ))
        train_csv = self._write_csv(train_rows, name="train.csv")
        model_path = str(self.tmp_path / "model.joblib")
        train(
            input_path=train_csv,
            output_path=str(self.tmp_path / "scored.csv"),
            model_path=model_path,
            contamination=0.15,
        )

        rows = [_base_row(unique_destinations=10)]
        path = self._write_csv(rows, name="score_input.csv")
        events = build_events_from_csv(path, model_path=model_path)
        for e in events:
            self.assertIn("ml_score", e.metadata)
            self.assertGreaterEqual(e.metadata["ml_score"]["anomaly_risk"], 0.0)
            self.assertLessEqual(e.metadata["ml_score"]["anomaly_risk"], 100.0)


if __name__ == "__main__":
    unittest.main()