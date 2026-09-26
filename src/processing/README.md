# Packet processing pipeline

This package turns parsed packets into flow features and rule-based detection events.

## Flow

1. `src.capture.packet_parser.parse_packet()` converts a Scapy packet to `ParsedPacket`.
2. `FlowTracker` groups packets by directional flow and expires idle flows.
3. `WindowManager` groups completed flows into 30-second source/destination windows.
4. `FeatureExtractor` creates feature rows using the Phase 1 feature names.
5. `DetectionEngine` applies configurable scan and flood rules and emits `DetectionEvent` objects.
6. `ProcessingPipeline` connects these parts.

The processing code accepts `ParsedPacket` objects. It does not capture packets itself and does not require Scapy for flow tracking or detection.

## Run the tests

From the repository root, activate the project’s virtual environment, then run:

```bash
python -m pytest -v