"""Phase 12: the analysis pipeline must work with no network access."""

import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pandas as pd

from src.orchestrator import run_analysis
from tests.test_run_analysis import _write_scan_pcap

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


def _blocked(*args, **kwargs):
    raise AssertionError("network access attempted during offline test")


class OfflineTests(unittest.TestCase):
    def test_run_analysis_makes_no_network_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.csv"
            pd.DataFrame(
                [_base_row(unique_destinations=10, lateral_move_flag=1)]
            ).to_csv(path, index=False)

            with mock.patch.object(socket, "socket", _blocked), \
                 mock.patch.object(socket, "create_connection", _blocked), \
                 mock.patch.object(socket, "getaddrinfo", _blocked):
                result = run_analysis(str(path))

        self.assertTrue(result.analysis_id)
        self.assertTrue(len(result.detections) > 0)
    def test_run_analysis_pcap_makes_no_network_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.pcap"
            _write_scan_pcap(path)

            with mock.patch.object(socket, "socket", _blocked), \
                 mock.patch.object(socket, "create_connection", _blocked), \
                 mock.patch.object(socket, "getaddrinfo", _blocked):
                result = run_analysis(str(path))

        self.assertTrue(len(result.detections) > 0)
        for det in result.detections:
            self.assertNotIn("ml_score_error", det["metadata"])    


if __name__ == "__main__":
    unittest.main()