from datetime import datetime, timedelta, timezone
import unittest

from src.processing.detector import DetectionEngine, DetectionThresholds


class DetectionEngineTests(unittest.TestCase):
    def setUp(self):
        thresholds = DetectionThresholds(
            scan_min_unique_dst_ports=4,
            scan_min_unique_dst_ips=4,
            scan_min_connection_attempt_rate=2.0,
            scan_min_syn_ratio=0.7,
            flood_min_packets_per_second=100.0,
            flood_min_bytes_per_second=10_000.0,
            flood_min_flows_per_second=50.0,
        )
        self.engine = DetectionEngine(thresholds)

    def make_row(self):
        start = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        return {
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.20",
            "window_start": start,
            "window_end": start + timedelta(seconds=30),
            "unique_dst_ports": 1,
            "unique_dst_ips": 1,
            "unique_ports": 1,
            "unique_destinations": 1,
            "syn_ratio": 0.1,
            "connection_attempt_rate": 0.5,
            "packets_per_second": 10.0,
            "bytes_per_second": 500.0,
            "flows_per_second": 0.1,
            "lateral_move_flag": 0,
        }

    def test_flags_scan_like_traffic_with_evidence(self):
        row = self.make_row()
        row["unique_dst_ports"] = 5
        row["unique_ports"] = 5
        row["syn_ratio"] = 0.9
        row["connection_attempt_rate"] = 3.0

        events = self.engine.detect(row)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].detection_type, "potential_network_scan")
        self.assertGreaterEqual(events[0].confidence, 0.0)
        self.assertLessEqual(events[0].confidence, 1.0)
        self.assertTrue(events[0].evidence)
        self.assertEqual(
            events[0].to_dict()["detection_type"],
            "potential_network_scan",
        )

    def test_flags_flood_like_traffic(self):
        row = self.make_row()
        row["packets_per_second"] = 200.0

        events = self.engine.detect(row)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].detection_type, "potential_flood")
        self.assertIn("packet rate", events[0].evidence[0])

    def test_quiet_traffic_produces_no_event(self):
        events = self.engine.detect(self.make_row())
        self.assertEqual(events, [])


if __name__ == "__main__":
    unittest.main()