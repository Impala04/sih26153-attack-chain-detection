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

## CICFlowMeter compatibility notes

The live flow tracker and Phase 1 feature extractor target the documented
CICFlowMeter-V3 flow behavior for the 16 existing model features. The model
feature names and order are unchanged.

- The first packet observed for a bidirectional flow defines its forward
  direction. Packets matching the reversed IP/port/protocol tuple count as
  backward packets. If capture begins in the middle of a connection, the
  first observed direction may differ from the original connection initiator.
- TCP flows terminate when a FIN packet is observed. Other flows are finalized
  after 120 seconds from the first observed packet.
- Model-facing flow durations are expressed in microseconds.
- Model-facing directional byte totals count TCP/UDP payload bytes. Full
  captured packet lengths are retained separately for live diagnostics.
- The 30-second feature window and the 120-second maximum flow duration serve
  different purposes: flows are assigned to feature windows by their first
  observed packet, while a flow may continue across multiple windows before
  it terminates.

The exact historical CICFlowMeter build ID and settings used to generate the
original CIC-IDS-2017 CSVs could not be verified. Therefore, this implementation
targets documented CICFlowMeter-V3 behavior, but exact equivalence to that
unknown historical build is not claimed.