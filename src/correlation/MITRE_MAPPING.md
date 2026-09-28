# MITRE ATT&CK mapping

`MitreStageMapper` implements `StageMapper`, so it drops into the correlator
without changing any correlator code:

```python
from src.correlation.correlator import AttackChainCorrelator
from src.correlation.mitre_stage_mapper import MitreStageMapper, annotate_event

mapper = MitreStageMapper(internal_networks=["192.168.10.0/24"])  # your protected subnet
correlator = AttackChainCorrelator(stage_mapper=mapper)

for event in events:
    annotate_event(event, mapper)   # optional: puts technique + rationale in event.metadata["mitre"]
chains = correlator.correlate(events)
```

`chain.stages` holds ATT&CK tactic names. Because `annotate_event` writes to
`event.metadata`, `chain.to_json()` already carries technique IDs and the
rationale for every event, for reports and the dashboard.

## What the detector can produce today

| detection_type | Condition | Tactic | Technique | Evidence level |
|---|---|---|---|---|
| `potential_network_scan` | source outside internal networks, target inside | Reconnaissance (TA0043) | T1595 Active Scanning (T1595.001 if host-focused) | technique |
| `potential_network_scan` | internal source, port-focused fan-out | Discovery (TA0007) | T1046 Network Service Discovery | technique |
| `potential_network_scan` | internal source, host-focused fan-out | Discovery (TA0007) | T1018 Remote System Discovery | technique |
| `potential_network_scan` | no fan-out features, or both endpoints external | Discovery / Reconnaissance | none | tactic_only |
| `potential_flood` | at least one rate feature present | Impact (TA0040) | T1498.001 Direct Network Flood | technique |
| `suspicious_traffic` | `dst_port` in {22, 445, 3389, 5900, 5985, 5986} | Lateral Movement (TA0008) | T1021.00x by port | technique |
| `suspicious_traffic` | no remote-service port evidence | Lateral Movement (TA0008) | none | tactic_only |
| `suspicious_traffic` | source outside internal networks | Lateral Movement (TA0008) | none, flagged | tactic_only |
| anything else | | `Unknown` | none | unmapped |

`tactic_only` means the tactic is reasonable but flow features cannot prove a
specific technique, so none is claimed.

## Not reachable with today's detector

Of the five stages in the problem statement, only Reconnaissance and Lateral
Movement can be produced. Initial Access, Command and Control and Exfiltration
need new detection types. `PROPOSED_DETECTION_TYPES` pre-registers
`potential_brute_force` (Credential Access, T1110), `potential_beaconing`
(C2, tactic only) and `potential_exfiltration` (Exfiltration, tactic only).
They are off by default: `MitreStageMapper(enable_proposed_types=True)`.

## Open decisions

1. **Unmapped events inflate chain confidence.** The correlator counts distinct
   stage labels, so `Unknown` adds a phantom stage (+0.10). Suggest the
   correlator skips `UNKNOWN_STAGE` in `_confidence` and in `chain.stages`.
2. **`dst_port` in window features.** Technique-level lateral movement needs the
   dominant destination port in `DetectionEvent.features` (or `metadata`). Ask
   the flow/window owner whether the window row can carry it.
3. **Internal networks.** Reconnaissance vs Discovery depends on
   `internal_networks`. In an all-private lab capture, pass only the victim
   subnet, otherwise every scan is classified as Discovery.
4. **Stage vocabulary.** These are real ATT&CK tactic names, so they include
   Discovery, Credential Access and Impact, which the problem statement's
   five-stage list does not name. Decide how to present them.

## Verification status

Checked against attack.mitre.org-derived pages: T1046, T1595 / T1595.001,
T1498.001, T1021 and its sub-techniques, T1110 (Credential Access).
Not separately checked: T1018 (Remote System Discovery, Discovery tactic).
ATT&CK is versioned, so re-check names before publishing.

## Limits

Rules are evidence gates, not calibrated detectors. Thresholds live in the
detector. `describe_progression` reports forward / same / backward in ATT&CK
matrix order and never labels a step invalid, because real intrusions loop and
sensors miss stages.
