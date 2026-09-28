"""Tests for Phase 10 logging in the orchestrator."""

import tempfile
import unittest
from pathlib import Path

import pandas as pd

from src.orchestrator import AnalysisOrchestrator, run_analysis
from src.processing.events import DetectionEvent
from src.providers.world_model_provider import MockWorldModel


class FailingWorldModel(MockWorldModel):
    """A forecast provider that always raises, to exercise _safe_call."""

    def forecast(self, context):
        raise RuntimeError("simulated forecast failure")


def _event() -> DetectionEvent:
    return DetectionEvent(
        event_id="evt-1",
        timestamp=1000.0,
        window_start=970.0,
        window_end=1000.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        detection_type="suspicious_traffic",
        confidence=0.8,
        features={"unique_destinations": 12},
        evidence=["test evidence"],
    )


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


class OrchestratorLoggingTests(unittest.TestCase):
    def test_provider_failure_is_logged_and_still_in_warnings(self):
        orchestrator = AnalysisOrchestrator(world_model_provider=FailingWorldModel())
        with self.assertLogs("src.orchestrator", level="WARNING") as captured:
            result = orchestrator.analyze([_event()], "test")
        joined = " ".join(captured.output)
        self.assertIn("forecast provider failed", joined)
        self.assertIn("simulated forecast failure", joined)
        # Graceful degradation is unchanged: forecast is None, warning recorded.
        self.assertIsNone(result.forecast)
        self.assertTrue(any("forecast" in w for w in result.warnings))

    def test_successful_analysis_logs_correlation_summary(self):
        orchestrator = AnalysisOrchestrator()
        with self.assertLogs("src.orchestrator", level="INFO") as captured:
            orchestrator.analyze([_event()], "test-source")
        joined = " ".join(captured.output)
        self.assertIn("Correlated 1 detections into 1 attack chains", joined)
        self.assertIn("test-source", joined)

    def test_run_analysis_logs_csv_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.csv"
            pd.DataFrame(
                [_base_row(unique_destinations=10, lateral_move_flag=1)]
            ).to_csv(path, index=False)
            with self.assertLogs("src.orchestrator", level="INFO") as captured:
                run_analysis(str(path))
        joined = " ".join(captured.output)
        self.assertIn("loading CSV input", joined)
        self.assertIn("CSV adapter produced", joined)

    def test_run_analysis_logs_pcap_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "capture.pcap"
            fake.write_bytes(b"\x00")
            with self.assertLogs("src.orchestrator", level="WARNING") as captured:
                with self.assertRaises(NotImplementedError):
                    run_analysis(str(fake))
        self.assertIn("not yet supported", " ".join(captured.output))


if __name__ == "__main__":
    unittest.main()
