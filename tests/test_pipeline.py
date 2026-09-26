from datetime import datetime, timedelta, timezone
import unittest

from src.capture.mock_packets import EXAMPLE_PACKETS
from src.capture.packet_parser import parse_packet
from src.capture.packet_schema import ParsedPacket
from src.processing.detector import DetectionEngine, DetectionThresholds
from src.processing.pipeline import ProcessingPipeline


class ProcessingPipelineTests(unittest.TestCase):
    def make_packet(self, timestamp, dst_port, protocol="TCP", flags="S"):
        return ParsedPacket(
            timestamp=timestamp,
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            src_port=50000 + dst_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_length=100,
            tcp_flags=flags if protocol == "TCP" else None,
        )

    def make_test_detector(self):
        thresholds = DetectionThresholds(
            scan_min_unique_dst_ports=4,
            scan_min_unique_dst_ips=4,
            scan_min_connection_attempt_rate=2.0,
            scan_min_syn_ratio=0.7,
            flood_min_packets_per_second=100.0,
            flood_min_bytes_per_second=10_000.0,
            flood_min_flows_per_second=50.0,
        )
        return DetectionEngine(thresholds)

    def test_scan_packets_flow_through_to_detection_event(self):
        start = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        pipeline = ProcessingPipeline(detector=self.make_test_detector())

        for offset, port in enumerate(range(80, 85)):
            packet_time = start + timedelta(seconds=offset)
            events = pipeline.ingest(
                self.make_packet(packet_time.timestamp(), port)
            )
            self.assertEqual(events, [])

        events = pipeline.flush()

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].detection_type, "potential_network_scan")
        self.assertEqual(events[0].src_ip, "192.168.1.10")
        self.assertTrue(events[0].evidence)

    def test_single_normal_flow_produces_no_event(self):
        start = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        pipeline = ProcessingPipeline()

        pipeline.ingest(
            self.make_packet(
                start.timestamp(),
                53,
                protocol="UDP",
                flags="",
            )
        )

        events = pipeline.flush()
        self.assertEqual(events, [])

    def test_capture_mock_packets_are_accepted_by_pipeline(self):
        pipeline = ProcessingPipeline()
        parsed_count = 0

        for raw_packet in EXAMPLE_PACKETS:
            packet = parse_packet(raw_packet)
            if packet is not None:
                parsed_count += 1
                pipeline.ingest(packet)

        events = pipeline.flush()

        self.assertEqual(parsed_count, len(EXAMPLE_PACKETS))
        self.assertEqual(events, [])


if __name__ == "__main__":
    unittest.main()