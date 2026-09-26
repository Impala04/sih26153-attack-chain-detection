from datetime import datetime, timedelta, timezone
import unittest

from src.capture.packet_schema import ParsedPacket
from src.processing.flow_tracker import FlowTracker


class FlowTrackerTests(unittest.TestCase):
    def test_counts_packets_and_expires_idle_flow(self):
        start = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        tracker = FlowTracker(idle_timeout_seconds=10)

        packet = ParsedPacket(
            timestamp=start.timestamp(),
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            src_port=50000,
            dst_port=443,
            protocol="TCP",
            packet_length=1000,
            tcp_flags="S",
        )
        tracker.ingest(packet)

        second_packet = ParsedPacket(
            timestamp=(start + timedelta(seconds=2)).timestamp(),
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            src_port=50000,
            dst_port=443,
            protocol="TCP",
            packet_length=500,
            tcp_flags="A",
        )
        tracker.ingest(second_packet)

        flow = tracker.active_flows[0]
        self.assertEqual(tracker.active_flow_count, 1)
        self.assertEqual(flow.packet_count, 2)
        self.assertEqual(flow.total_bytes, 1500)
        self.assertEqual(flow.syn_count, 1)
        self.assertEqual(flow.ack_count, 1)
        self.assertEqual(flow.duration_seconds, 2)

        expired = tracker.expire((start + timedelta(seconds=12)))
        self.assertEqual(len(expired), 1)
        self.assertEqual(tracker.active_flow_count, 0)


if __name__ == "__main__":
    unittest.main()