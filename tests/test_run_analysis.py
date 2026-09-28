"""Tests for the run_analysis entry point (Phase 5)."""

import tempfile
import unittest
from pathlib import Path

import pandas as pd

from src.orchestrator import run_analysis


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


class RunAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _write_csv(self, rows, name="input.csv"):
        path = self.tmp_path / name
        pd.DataFrame(rows).to_csv(path, index=False)
        return str(path)

    def test_run_analysis_csv_returns_valid_result(self):
        # A row that trips the lateral-movement rule, same shape as
        # test_csv_adapter.py's test_lateral_movement_row_produces_event,
        # so we know it produces at least one real DetectionEvent.
        rows = [_base_row(unique_destinations=10, lateral_move_flag=1)]
        path = self._write_csv(rows)

        result = run_analysis(path)

        self.assertTrue(result.analysis_id)
        self.assertTrue(result.input_source.startswith("csv:"))
        self.assertIsInstance(result.detections, list)
        self.assertTrue(len(result.detections) > 0)
        # Providers are mocks but should still populate on a normal run;
        # if a provider ever fails, it shows up in warnings instead of
        # silently leaving the field None, so check for either.
        self.assertTrue(
            result.forecast is not None
            or any("forecast" in w for w in result.warnings)
        )
        self.assertTrue(
            result.risk is not None
            or any("risk" in w for w in result.warnings)
        )

    def test_run_analysis_pcap_raises_not_implemented(self):
        fake_pcap = self.tmp_path / "capture.pcap"
        fake_pcap.write_bytes(b"\x00")  # content is irrelevant; never read
        with self.assertRaises(NotImplementedError):
            run_analysis(str(fake_pcap))

    def test_run_analysis_missing_file_raises_filenotfound(self):
        missing = self.tmp_path / "does_not_exist.csv"
        with self.assertRaises(FileNotFoundError):
            run_analysis(str(missing))

    def test_run_analysis_unsupported_extension_raises_valueerror(self):
        weird = self.tmp_path / "data.xyz"
        weird.write_text("nonsense")
        with self.assertRaises(ValueError):
            run_analysis(str(weird))


if __name__ == "__main__":
    unittest.main()