import json
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from src.model.train import train
from src.model.event_scoring import score_detection_event
from src.processing.events import DetectionEvent

FEATURE_COLS = [
    "connection_count", "unique_destinations", "unique_ports",
    "total_fwd_packets", "total_bwd_packets", "total_bytes_fwd",
    "total_bytes_bwd", "avg_flow_duration", "max_flow_duration",
    "std_flow_duration", "max_bytes_total", "std_bytes_total",
    "max_packets_total", "bytes_per_connection", "flows_per_second",
]


def make_event(event_id, features, detection_type="potential_network_scan"):
    return DetectionEvent(
        event_id=event_id, timestamp=0, window_start=0, window_end=30,
        src_ip="10.0.0.5", dst_ip="10.0.0.10", detection_type=detection_type,
        confidence=0.5, features=features,
    )


class EventScoringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Train a small throwaway model on synthetic data, once for all tests."""
        cls.tmpdir = tempfile.TemporaryDirectory()
        tmp_path = Path(cls.tmpdir.name)

        # 20 "normal" low-traffic rows + a few high-traffic "scan-like" rows,
        # enough for IsolationForest to separate them.
        rows = []
        for i in range(20):
            rows.append({
                "connection_count": 5, "unique_destinations": 1, "unique_ports": 5,
                "total_fwd_packets": 5, "total_bwd_packets": 5, "total_bytes_fwd": 500,
                "total_bytes_bwd": 500, "avg_flow_duration": 1000.0,
                "max_flow_duration": 2000.0, "std_flow_duration": 100.0,
                "max_bytes_total": 200.0, "std_bytes_total": 20.0,
                "max_packets_total": 5.0, "bytes_per_connection": 100.0,
                "flows_per_second": 0.2, "window_start": i,
            })
        for i in range(3):
            rows.append({
                "connection_count": 300, "unique_destinations": 60, "unique_ports": 300,
                "total_fwd_packets": 300, "total_bwd_packets": 0, "total_bytes_fwd": 30000,
                "total_bytes_bwd": 0, "avg_flow_duration": 5.0,
                "max_flow_duration": 10.0, "std_flow_duration": 2.0,
                "max_bytes_total": 1000.0, "std_bytes_total": 300.0,
                "max_packets_total": 10.0, "bytes_per_connection": 100.0,
                "flows_per_second": 60.0, "window_start": 100 + i,
            })

        cls.input_csv = tmp_path / "synthetic.csv"
        pd.DataFrame(rows).to_csv(cls.input_csv, index=False)

        cls.model_path = str(tmp_path / "model.joblib")
        cls.output_csv = str(tmp_path / "scored.csv")

        train(
            input_path=str(cls.input_csv),
            output_path=cls.output_csv,
            model_path=cls.model_path,
            contamination=0.15,
        )

    @classmethod
    def tearDownClass(cls):
        cls.tmpdir.cleanup()

    def test_normal_event_scores_low_risk(self):
        event = make_event("normal1", {
            "connection_count": 5, "unique_destinations": 1, "unique_ports": 5,
            "total_fwd_packets": 5, "total_bwd_packets": 5, "total_bytes_fwd": 500,
            "total_bytes_bwd": 500, "avg_flow_duration": 1000.0,
            "max_flow_duration": 2000.0, "std_flow_duration": 100.0,
            "max_bytes_total": 200.0, "std_bytes_total": 20.0,
            "max_packets_total": 5.0, "bytes_per_connection": 100.0,
            "flows_per_second": 0.2, "lateral_move_flag": 0,
        })
        result = score_detection_event(event, model_path=self.model_path)
        self.assertEqual(result["anomaly_score"], 1)
        self.assertLess(result["anomaly_risk"], 50)

    def test_scan_like_event_scores_high_risk(self):
        event = make_event("scan1", {
            "connection_count": 300, "unique_destinations": 60, "unique_ports": 300,
            "total_fwd_packets": 300, "total_bwd_packets": 0, "total_bytes_fwd": 30000,
            "total_bytes_bwd": 0, "avg_flow_duration": 5.0,
            "max_flow_duration": 10.0, "std_flow_duration": 2.0,
            "max_bytes_total": 1000.0, "std_bytes_total": 300.0,
            "max_packets_total": 10.0, "bytes_per_connection": 100.0,
            "flows_per_second": 60.0, "lateral_move_flag": 1,
        })
        result = score_detection_event(event, model_path=self.model_path)
        self.assertEqual(result["anomaly_score"], -1)
        self.assertGreater(result["anomaly_risk"], 50)

    def test_missing_feature_raises(self):
        event = make_event("bad1", {"connection_count": 5})
        with self.assertRaises(ValueError):
            score_detection_event(event, model_path=self.model_path)

    def test_risk_is_within_bounds(self):
        event = make_event("normal2", {
            "connection_count": 5, "unique_destinations": 1, "unique_ports": 5,
            "total_fwd_packets": 5, "total_bwd_packets": 5, "total_bytes_fwd": 500,
            "total_bytes_bwd": 500, "avg_flow_duration": 1000.0,
            "max_flow_duration": 2000.0, "std_flow_duration": 100.0,
            "max_bytes_total": 200.0, "std_bytes_total": 20.0,
            "max_packets_total": 5.0, "bytes_per_connection": 100.0,
            "flows_per_second": 0.2, "lateral_move_flag": 0,
        })
        result = score_detection_event(event, model_path=self.model_path)
        self.assertGreaterEqual(result["anomaly_risk"], 0.0)
        self.assertLessEqual(result["anomaly_risk"], 100.0)


if __name__ == "__main__":
    unittest.main()