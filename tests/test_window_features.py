from datetime import datetime, timedelta, timezone
import unittest

from src.processing.feature_extractor import (
    FeatureExtractor,
    PHASE1_FEATURE_COLUMNS,
)
from src.processing.flow_tracker import FlowStats
from src.processing.window_manager import WindowManager


SOURCE_IP = "192.168.1.10"


def make_flow(dst_ip, dst_port, start, packet_count, total_bytes, duration, sizes):
    return FlowStats(
        key=(SOURCE_IP, dst_ip, 50000, dst_port, "TCP"),
        first_seen=start,
        last_seen=start + timedelta(seconds=duration),
        packet_count=packet_count,
        total_bytes=total_bytes,
        packet_sizes=sizes,
        syn_count=1,
        ack_count=max(0, packet_count - 1),
        rst_count=0,
        fin_count=0,
    )


class WindowFeatureTests(unittest.TestCase):
    def test_source_window_waits_for_active_flow_and_counts_destinations(self):
        start = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        manager = WindowManager(window_seconds=30)

        manager.add_completed_flow(
            make_flow(
                "192.168.1.20",
                80,
                start + timedelta(seconds=2),
                packet_count=2,
                total_bytes=1200,
                duration=2,
                sizes=[700, 500],
            )
        )
        manager.add_completed_flow(
            make_flow(
                "192.168.1.30",
                443,
                start + timedelta(seconds=8),
                packet_count=1,
                total_bytes=500,
                duration=0,
                sizes=[500],
            )
        )

        # This active flow is for another destination but the same source
        # and 30-second window, so both destination windows must stay open.
        active_flow = make_flow(
            "192.168.1.40",
            22,
            start + timedelta(seconds=20),
            packet_count=1,
            total_bytes=100,
            duration=0,
            sizes=[100],
        )
        ready = manager.close_ready(
            start + timedelta(seconds=35),
            active_flows=[active_flow],
        )
        self.assertEqual(ready, [])

        ready = manager.close_ready(
            start + timedelta(seconds=35),
            active_flows=[],
        )
        self.assertEqual(len(ready), 2)

        rows = FeatureExtractor().extract(ready)
        self.assertEqual(len(rows), 2)
        self.assertEqual(
            {row["unique_destinations"] for row in rows},
            {2},
        )
        self.assertEqual(
            {row["lateral_move_flag"] for row in rows},
            {0},
        )

        first_destination_row = next(
            row for row in rows if row["dst_ip"] == "192.168.1.20"
        )
        self.assertEqual(first_destination_row["connection_count"], 1)
        self.assertEqual(first_destination_row["total_fwd_packets"], 2)
        self.assertEqual(first_destination_row["total_bytes_fwd"], 1200)
        self.assertEqual(first_destination_row["max_flow_duration"], 2)

    def test_feature_rows_include_all_phase1_feature_names(self):
        start = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        manager = WindowManager(window_seconds=30)
        manager.add_completed_flow(
            make_flow(
                "192.168.1.20",
                80,
                start + timedelta(seconds=2),
                packet_count=1,
                total_bytes=100,
                duration=0,
                sizes=[100],
            )
        )

        windows = manager.flush()
        rows = FeatureExtractor().extract(windows)

        self.assertEqual(len(rows), 1)
        for column in PHASE1_FEATURE_COLUMNS:
            self.assertIn(column, rows[0])


if __name__ == "__main__":
    unittest.main()