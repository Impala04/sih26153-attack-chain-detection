import json
import unittest

from src.correlation.correlator import AttackChainCorrelator
from src.correlation.stage_mapper import FallbackStageMapper, StageMapper
from src.processing.events import DetectionEvent


class MockStageMapper(StageMapper):
    def map_event(self, event):
        return "Mock Stage"


class AttackChainCorrelatorTests(unittest.TestCase):
    def setUp(self):
        self.correlator = AttackChainCorrelator(max_event_gap_seconds=60, chain_timeout_seconds=120)

    def event(self, event_id, timestamp, src_ip="10.0.0.1", dst_ip="10.0.0.2", detection_type="potential_network_scan"):
        return DetectionEvent(event_id=event_id, timestamp=timestamp, window_start=timestamp - 30, window_end=timestamp, src_ip=src_ip, dst_ip=dst_ip, detection_type=detection_type, confidence=0.8, features={}, evidence=[], metadata={})

    def test_single_event_creates_chain(self):
        chain = self.correlator.add_event(self.event("one", 100))
        self.assertEqual(len(self.correlator.chains), 1)
        self.assertEqual(chain.events[0].event_id, "one")

    def test_related_events_merge(self):
        self.correlator.add_event(self.event("one", 100))
        chain = self.correlator.add_event(self.event("two", 120, dst_ip="10.0.0.3"))
        self.assertEqual(len(self.correlator.chains), 1)
        self.assertEqual(len(chain.events), 2)

    def test_sequential_stage_progression(self):
        self.correlator.add_event(self.event("one", 100))
        chain = self.correlator.add_event(self.event("two", 110, detection_type="suspicious_traffic"))
        self.assertEqual(chain.stages, ["Discovery", "Lateral Movement"])
        self.assertEqual(chain.current_stage, "Lateral Movement")

    def test_unrelated_hosts_create_separate_chains(self):
        self.correlator.add_event(self.event("one", 100))
        self.correlator.add_event(self.event("two", 110, "10.0.9.1", "10.0.9.2"))
        self.assertEqual(len(self.correlator.chains), 2)

    def test_multiple_simultaneous_chains(self):
        self.correlator.correlate([self.event("a1", 100, "a", "b"), self.event("b1", 101, "c", "d"), self.event("a2", 102, "a", "e"), self.event("b2", 103, "d", "f")])
        self.assertEqual(sorted(len(chain.events) for chain in self.correlator.chains), [2, 2])

    def test_event_outside_time_window_does_not_correlate(self):
        self.correlator.add_event(self.event("one", 100))
        self.correlator.add_event(self.event("two", 161))
        self.assertEqual(len(self.correlator.chains), 2)

    def test_chain_expiration_keeps_history(self):
        chain = self.correlator.add_event(self.event("one", 100))
        self.correlator.expire_chains(221)
        self.assertFalse(chain.is_active)
        self.assertIn(chain, self.correlator.chains)

    def test_confidence_is_deterministic(self):
        events = [self.event("one", 100), self.event("two", 110, detection_type="potential_flood")]
        left = AttackChainCorrelator(max_event_gap_seconds=60).correlate(events)[0].confidence
        right = AttackChainCorrelator(max_event_gap_seconds=60).correlate(events)[0].confidence
        self.assertEqual(left, right)
        self.assertEqual(left, 0.75)

    def test_out_of_order_input_matches_ordered_result(self):
        ordered = [self.event("one", 100), self.event("two", 110, detection_type="potential_flood")]
        first = AttackChainCorrelator(max_event_gap_seconds=60).correlate(ordered)[0]
        second = AttackChainCorrelator(max_event_gap_seconds=60).correlate(list(reversed(ordered)))[0]
        self.assertEqual(first.to_dict(), second.to_dict())

    def test_empty_input(self):
        self.assertEqual(self.correlator.correlate([]), [])

    def test_duplicate_event_is_not_added_twice(self):
        event = self.event("one", 100)
        self.correlator.add_event(event)
        chain = self.correlator.add_event(event)
        self.assertEqual(len(chain.events), 1)

    def test_json_serialization(self):
        chain = self.correlator.add_event(self.event("one", 100, dst_ip=None))
        payload = json.loads(chain.to_json())
        self.assertEqual(payload["source_hosts"], ["10.0.0.1"])
        self.assertEqual(payload["destination_hosts"], [])
        self.assertEqual(payload["events"][0]["dst_ip"], None)

    def test_fallback_stage_mapping(self):
        mapper = FallbackStageMapper()
        self.assertEqual(mapper.map_event(self.event("scan", 1)), "Discovery")
        self.assertEqual(mapper.map_event(self.event("flood", 1, detection_type="potential_flood")), "Impact")
        self.assertEqual(mapper.map_event(self.event("lateral", 1, detection_type="suspicious_traffic")), "Lateral Movement")

    def test_mock_stage_mapper_can_be_swapped(self):
        correlator = AttackChainCorrelator(stage_mapper=MockStageMapper())
        chain = correlator.add_event(self.event("one", 100))
        self.assertEqual(chain.current_stage, "Mock Stage")


if __name__ == "__main__":
    unittest.main()
