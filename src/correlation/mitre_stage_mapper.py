"""Evidence-gated MITRE ATT&CK stage mapper for CyberFlux detection events.

Drop-in replacement for ``FallbackStageMapper``::

    correlator = AttackChainCorrelator(stage_mapper=MitreStageMapper())

Contract (fixed by ``StageMapper``): one ``DetectionEvent`` in, one stage
label (an ATT&CK *tactic* name) out. ``map_event_detail`` additionally returns
the technique and the reasoning, for reports and the dashboard.

Design rules
------------
* Stage labels are real ATT&CK tactic names (verified against attack.mitre.org
  pages: T1046 -> Discovery, T1595 -> Reconnaissance, T1498.001 -> Impact,
  T1021 -> Lateral Movement, T1110 -> Credential Access).
* A technique ID is only asserted when the event carries the evidence that
  technique needs. Otherwise the mapping is ``tactic_only`` and says why.
  We never claim more than flow features can show.
* The mapper only maps what the detector emits. It cannot invent stages the
  detector never signals (see PROPOSED_DETECTION_TYPES for what is missing).
* Nothing here is calibrated against real traffic. Thresholds live in the
  detector, not here.
"""

from dataclasses import dataclass
from ipaddress import ip_address, ip_network
import logging
from typing import Any, Dict, Iterable, List, Optional, Sequence

from src.processing.events import DetectionEvent

from .stage_mapper import StageMapper

logger = logging.getLogger(__name__)

UNKNOWN_STAGE = "Unknown"

# ATT&CK Enterprise tactics used by CyberFlux, in ATT&CK matrix column order.
TACTIC_ORDER: Sequence[str] = (
    "Reconnaissance",
    "Initial Access",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Command and Control",
    "Exfiltration",
    "Impact",
)
TACTIC_IDS: Dict[str, str] = {
    "Reconnaissance": "TA0043",
    "Initial Access": "TA0001",
    "Credential Access": "TA0006",
    "Discovery": "TA0007",
    "Lateral Movement": "TA0008",
    "Command and Control": "TA0011",
    "Exfiltration": "TA0010",
    "Impact": "TA0040",
}

EVIDENCE_TECHNIQUE = "technique"     # technique ID justified by event evidence
EVIDENCE_TACTIC_ONLY = "tactic_only"  # tactic is reasonable, technique is not provable
EVIDENCE_UNMAPPED = "unmapped"

DEFAULT_INTERNAL_NETWORKS = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
    "::1/128",
)

# Remote-service ports -> T1021 sub-technique (id, name).
_REMOTE_SERVICE_PORTS = {
    22: ("T1021.004", "Remote Services: SSH"),
    445: ("T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    3389: ("T1021.001", "Remote Services: Remote Desktop Protocol"),
    5900: ("T1021.005", "Remote Services: VNC"),
    5985: ("T1021.006", "Remote Services: Windows Remote Management"),
    5986: ("T1021.006", "Remote Services: Windows Remote Management"),
}


@dataclass(frozen=True)
class MitreMapping:
    """Full result for one event. ``tactic`` is what the correlator sees."""

    tactic: str
    tactic_id: Optional[str]
    technique_id: Optional[str]
    technique_name: Optional[str]
    evidence_level: str
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tactic": self.tactic,
            "tactic_id": self.tactic_id,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "evidence_level": self.evidence_level,
            "rationale": self.rationale,
        }


def _mapping(
    tactic: str,
    technique: Optional[tuple],
    level: str,
    rationale: str,
) -> MitreMapping:
    return MitreMapping(
        tactic=tactic,
        tactic_id=TACTIC_IDS.get(tactic),
        technique_id=technique[0] if technique else None,
        technique_name=technique[1] if technique else None,
        evidence_level=level,
        rationale=rationale,
    )


# Detection types the detector does NOT emit yet. Opt-in only
# (MitreStageMapper(enable_proposed_types=True)) so default behaviour is
# exactly "what the detector can really produce today".
PROPOSED_DETECTION_TYPES: Dict[str, MitreMapping] = {
    "potential_brute_force": _mapping(
        "Credential Access",
        ("T1110", "Brute Force"),
        EVIDENCE_TECHNIQUE,
        "proposed detector type: repeated short attempts against one service",
    ),
    "potential_beaconing": _mapping(
        "Command and Control",
        None,
        EVIDENCE_TACTIC_ONLY,
        "proposed detector type: periodic connections suggest a C2 channel, "
        "but flow features do not reveal the application protocol, so no "
        "technique is asserted",
    ),
    "potential_exfiltration": _mapping(
        "Exfiltration",
        None,
        EVIDENCE_TACTIC_ONLY,
        "proposed detector type: large outbound volume; the exfiltration "
        "channel (over C2 or an alternative protocol) cannot be told from "
        "flow features alone, so no technique is asserted",
    ),
}


class MitreStageMapper(StageMapper):
    """Map detection events to ATT&CK tactics, with evidence-gated techniques."""

    def __init__(
        self,
        internal_networks: Iterable[str] = DEFAULT_INTERNAL_NETWORKS,
        strict: bool = False,
        enable_proposed_types: bool = False,
    ) -> None:
        """
        internal_networks: CIDRs you treat as protected. Scans from outside
            them are Reconnaissance (pre-compromise); scans from inside are
            Discovery (post-compromise). In an all-private lab capture, pass
            only the victim subnet, e.g. ["192.168.10.0/24"].
        strict: raise ValueError on unmapped detection types (like the
            fallback mapper does) instead of returning UNKNOWN_STAGE.
        enable_proposed_types: also map detector types that do not exist yet.
        """
        self._internal = [ip_network(net) for net in internal_networks]
        self.strict = strict
        self.enable_proposed_types = enable_proposed_types

    # ---- StageMapper interface -------------------------------------------
    def map_event(self, event: DetectionEvent) -> str:
        return self.map_event_detail(event).tactic

    # ---- richer API -------------------------------------------------------
    def map_event_detail(self, event: DetectionEvent) -> MitreMapping:
        handler = {
            "potential_network_scan": self._map_scan,
            "potential_flood": self._map_flood,
            "suspicious_traffic": self._map_lateral,
        }.get(event.detection_type)

        if handler is not None:
            return handler(event)

        if self.enable_proposed_types and event.detection_type in PROPOSED_DETECTION_TYPES:
            return PROPOSED_DETECTION_TYPES[event.detection_type]

        if self.strict:
            raise ValueError(f"no MITRE mapping for detection_type={event.detection_type!r}")
        logger.warning("no MITRE mapping for detection_type=%r", event.detection_type)
        return _mapping(
            UNKNOWN_STAGE, None, EVIDENCE_UNMAPPED,
            f"detection_type {event.detection_type!r} has no MITRE mapping",
        )

    # ---- helpers ----------------------------------------------------------
    def _is_internal(self, value: Optional[str]) -> Optional[bool]:
        """True/False if the IP parses, None if missing or unparseable."""
        if not value:
            return None
        try:
            addr = ip_address(value)
        except ValueError:
            return None
        return any(addr in net for net in self._internal)

    @staticmethod
    def _first_number(features: Dict[str, Any], *names: str) -> float:
        for name in names:
            value = features.get(name)
            if isinstance(value, (int, float)) and value:
                return float(value)
        return 0.0

    # ---- per-type rules ---------------------------------------------------
    def _map_scan(self, event: DetectionEvent) -> MitreMapping:
        ports = self._first_number(event.features, "unique_dst_ports", "unique_ports")
        hosts = self._first_number(event.features, "unique_dst_ips", "unique_destinations")
        src_internal = self._is_internal(event.src_ip)
        dst_internal = self._is_internal(event.dst_ip)
        shape = f"{int(ports)} distinct ports, {int(hosts)} distinct hosts"

        if src_internal is False:
            if dst_internal is False:
                return _mapping(
                    "Reconnaissance", None, EVIDENCE_TACTIC_ONLY,
                    f"scan ({shape}) with both endpoints outside the internal "
                    "networks; cannot confirm it targets protected infrastructure",
                )
            if ports == 0 and hosts == 0:
                return _mapping(
                    "Reconnaissance", None, EVIDENCE_TACTIC_ONLY,
                    "external scan event carries no port/host fan-out features",
                )
            host_focused = hosts > ports
            technique = (
                ("T1595.001", "Active Scanning: Scanning IP Blocks")
                if host_focused else ("T1595", "Active Scanning")
            )
            return _mapping(
                "Reconnaissance", technique, EVIDENCE_TECHNIQUE,
                f"external source probing internal space ({shape})",
            )

        # Internal (or unknown) source: post-compromise discovery.
        if ports == 0 and hosts == 0:
            return _mapping(
                "Discovery", None, EVIDENCE_TACTIC_ONLY,
                "scan event carries no port/host fan-out features; "
                "technique not asserted",
            )
        if ports >= hosts:
            technique = ("T1046", "Network Service Discovery")
            why = "port-focused fan-out"
        else:
            technique = ("T1018", "Remote System Discovery")
            why = "host-focused fan-out"
        origin = "internal source" if src_internal else "source not classifiable as external"
        return _mapping(
            "Discovery", technique, EVIDENCE_TECHNIQUE,
            f"{origin}, {why} ({shape})",
        )

    def _map_flood(self, event: DetectionEvent) -> MitreMapping:
        rates = {
            name: self._first_number(event.features, name)
            for name in ("packets_per_second", "bytes_per_second", "flows_per_second")
        }
        present = {name: value for name, value in rates.items() if value > 0}
        if not present:
            return _mapping(
                "Impact", None, EVIDENCE_TACTIC_ONLY,
                "flood event carries no rate features; technique not asserted",
            )
        detail = ", ".join(f"{name}={value:.0f}" for name, value in present.items())
        return _mapping(
            "Impact",
            ("T1498.001", "Network Denial of Service: Direct Network Flood"),
            EVIDENCE_TECHNIQUE,
            f"sustained high-rate traffic ({detail}); reflection/amplification "
            "cannot be distinguished from flow features",
        )

    def _map_lateral(self, event: DetectionEvent) -> MitreMapping:
        port = self._first_number(event.features, "dst_port")
        if not port:
            raw = event.metadata.get("dst_port")
            port = float(raw) if isinstance(raw, (int, float)) else 0.0
        fan_out = int(self._first_number(event.features, "unique_destinations", "unique_dst_ips"))

        if self._is_internal(event.src_ip) is False:
            return _mapping(
                "Lateral Movement", None, EVIDENCE_TACTIC_ONLY,
                "source is outside the internal networks; lateral movement "
                "normally starts from a compromised internal host, so treat "
                "this label with caution",
            )
        service = _REMOTE_SERVICE_PORTS.get(int(port))
        if service:
            return _mapping(
                "Lateral Movement", service, EVIDENCE_TECHNIQUE,
                f"fan-out to {fan_out} destinations on remote-service port {int(port)}",
            )
        return _mapping(
            "Lateral Movement", None, EVIDENCE_TACTIC_ONLY,
            f"fan-out to {fan_out} destinations, but no remote-service port "
            "evidence, so no technique is asserted",
        )


# ---- integration helpers (#12: MITRE -> attack chain) -----------------------
def annotate_event(event: DetectionEvent, mapper: Optional[MitreStageMapper] = None) -> MitreMapping:
    """Store the full mapping in ``event.metadata['mitre']``.

    ``DetectionEvent.to_dict()`` and ``AttackChain.to_json()`` already include
    metadata, so technique IDs and rationale reach reports and the dashboard
    with no change to the correlator. Call this before ``correlator.add_event``.
    """
    mapper = mapper or MitreStageMapper()
    mapping = mapper.map_event_detail(event)
    event.metadata["mitre"] = mapping.to_dict()
    return mapping


def describe_progression(stages: Sequence[str]) -> List[Dict[str, str]]:
    """Describe how consecutive chain stages relate in ATT&CK matrix order.

    Informational only. Real intruders loop (they re-run discovery after
    lateral movement) and sensors miss stages, so ``backward`` and skipped
    stages are NOT errors and this function never labels a step invalid.
    relation is one of: forward, same, backward, unknown.
    """
    steps: List[Dict[str, str]] = []
    for prev, curr in zip(stages, stages[1:]):
        if prev not in TACTIC_ORDER or curr not in TACTIC_ORDER:
            relation = "unknown"
        else:
            delta = TACTIC_ORDER.index(curr) - TACTIC_ORDER.index(prev)
            relation = "forward" if delta > 0 else "same" if delta == 0 else "backward"
        steps.append({"from": prev, "to": curr, "relation": relation})
    return steps
