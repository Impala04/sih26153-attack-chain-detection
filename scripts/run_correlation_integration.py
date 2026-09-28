"""Temporary end-to-end correlation example using real pipeline output.

Run from the repository root:
    python scripts/run_correlation_integration.py
"""

import json
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from src.capture.packet_schema import ParsedPacket
from src.correlation.correlator import AttackChainCorrelator
from src.processing.pipeline import ProcessingPipeline


SOURCE_IP = "10.0.0.5"
SCAN_DESTINATION = "10.0.0.10"
BASE_TIMESTAMP = 1_735_732_800.0  # 2025-01-01T00:00:00Z


def build_packets():
    """Create SYN flows for a scan, then six more destination hosts.

    FeatureExtractor sets lateral_move_flag when unique_destinations is
    greater than five for one source/window. The lateral packets use the next
    30-second window, so the real events progress from scan to lateral traffic.
    """
    packets = []

    for offset, destination_port in enumerate(range(20, 30)):
        packets.append(
            ParsedPacket(
                timestamp=BASE_TIMESTAMP + offset,
                src_ip=SOURCE_IP,
                dst_ip=SCAN_DESTINATION,
                src_port=40_000 + offset,
                dst_port=destination_port,
                protocol="TCP",
                packet_length=100,
                tcp_flags="S",
            )
        )

    for offset, host_number in enumerate(range(20, 26), start=31):
        packets.append(
            ParsedPacket(
                timestamp=BASE_TIMESTAMP + offset,
                src_ip=SOURCE_IP,
                dst_ip=f"10.0.0.{host_number}",
                src_port=41_000 + offset,
                dst_port=445,
                protocol="TCP",
                packet_length=100,
                tcp_flags="S",
            )
        )

    return packets


def main():
    pipeline = ProcessingPipeline()
    events = []

    for packet in build_packets():
        events.extend(pipeline.ingest(packet))
    events.extend(pipeline.flush())

    print("DetectionEvent objects from the real ProcessingPipeline:")
    for event in events:
        print(event)

    chains = AttackChainCorrelator().correlate(events)
    print("\nCorrelated AttackChain JSON:")
    for chain in chains:
        print(json.dumps(json.loads(chain.to_json()), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
