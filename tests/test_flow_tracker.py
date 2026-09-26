from datetime import datetime, timedelta, timezone
import unittest

from src.capture.packet_schema import ParsedPacket
from src.processing.flow_tracker import FlowTracker


class FlowTrackerTests(unittest.TestCase):
    def setUp(self):
        self.start = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    def make_packet(
        self,
        *,
        seconds=0,
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        packet_length=100,
        payload_length=40,
        tcp_flags="",
    ):
        timestamp = self.start + timedelta(seconds=seconds)
        return ParsedPacket(
            timestamp=timestamp.timestamp(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            packet_length=packet_length,
            payload_length=payload_length,
            src_port=src_port,
            dst_port=dst_port,
            tcp_flags=tcp_flags,
        )

    def test_forward_and_reverse_packets_share_one_bidirectional_flow(self):
        tracker = FlowTracker()

        tracker.ingest(self.make_packet(tcp_flags="S"))
        tracker.ingest(
            self.make_packet(
                seconds=1,
                src_ip="192.168.1.20",
                dst_ip="192.168.1.10",
                src_port=443,
                dst_port=50000,
                payload_length=20,
                tcp_flags="A",
            )
        )

        self.assertEqual(tracker.active_flow_count, 1)
        flow = tracker.active_flows[0]
        self.assertEqual(flow.forward_packet_count, 1)
        self.assertEqual(flow.backward_packet_count, 1)
        self.assertEqual(flow.forward_payload_bytes, 40)
        self.assertEqual(flow.backward_payload_bytes, 20)
        self.assertEqual(flow.packet_count, 2)

    def test_tcp_fin_terminates_flow_after_counting_fin_packet(self):
        tracker = FlowTracker()

        tracker.ingest(self.make_packet(tcp_flags="S"))
        completed = tracker.ingest(
            self.make_packet(seconds=2, tcp_flags="FA")
        )

        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0].packet_count, 2)
        self.assertEqual(completed[0].fin_count, 1)
        self.assertEqual(tracker.active_flow_count, 0)

    def test_flow_expires_at_120_second_maximum_duration(self):
        tracker = FlowTracker(flow_timeout_seconds=120)
        tracker.ingest(self.make_packet())

        just_before_limit = self.start + timedelta(seconds=119)
        self.assertEqual(tracker.expire(just_before_limit), [])
        self.assertEqual(tracker.active_flow_count, 1)

        at_limit = self.start + timedelta(seconds=120)
        expired = tracker.expire(at_limit)
        self.assertEqual(len(expired), 1)
        self.assertEqual(tracker.active_flow_count, 0)

    def test_flow_duration_is_reported_in_microseconds(self):
        tracker = FlowTracker()
        tracker.ingest(self.make_packet())
        tracker.ingest(self.make_packet(seconds=2))

        flow = tracker.active_flows[0]
        self.assertEqual(flow.duration_seconds, 2)
        self.assertEqual(flow.duration_microseconds, 2_000_000)


if __name__ == "__main__":
    unittest.main()