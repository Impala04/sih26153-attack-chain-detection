from src.capture.mock_packets import EXAMPLE_PACKETS
from src.capture.packet_parser import parse_packet
from src.processing.pipeline import ProcessingPipeline

pipeline = ProcessingPipeline()
parsed_count = 0
events = []

for raw_packet in EXAMPLE_PACKETS:
    packet = parse_packet(raw_packet)

    if packet is not None:
        parsed_count += 1
        events.extend(pipeline.ingest(packet))

# Process any flows still open after the mock packets finish.
events.extend(pipeline.flush())

print(f"Parsed packets: {parsed_count}")
print(f"Detection events: {len(events)}")

for event in events:
    print(event.to_dict())