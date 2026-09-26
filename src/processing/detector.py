"""Explainable behavioral rules that emit cautious detection events."""

from dataclasses import dataclass
from datetime import datetime
from math import isfinite
from typing import Any, Dict, List, Sequence
from uuid import uuid4

from .events import DetectionEvent


@dataclass(frozen=True)
class DetectionThresholds:
    """Configurable initial thresholds for demo and synthetic testing.

    These defaults are provisional examples, not calibrated production
    thresholds. Tune them against representative benign traffic and attack
    traffic before relying on them operationally.
    """

    scan_min_unique_dst_ports: int = 10
    scan_min_unique_dst_ips: int = 10
    scan_min_connection_attempt_rate: float = 5.0
    scan_min_syn_ratio: float = 0.7
    flood_min_packets_per_second: float = 1000.0
    flood_min_bytes_per_second: float = 1_000_000.0
    flood_min_flows_per_second: float = 100.0

    def __post_init__(self) -> None:
        positive_values = (
            self.scan_min_unique_dst_ports,
            self.scan_min_unique_dst_ips,
            self.scan_min_connection_attempt_rate,
            self.flood_min_packets_per_second,
            self.flood_min_bytes_per_second,
            self.flood_min_flows_per_second,
        )
        if any(value <= 0 for value in positive_values):
            raise ValueError("detection thresholds must be greater than zero")
        if not 0.0 < self.scan_min_syn_ratio <= 1.0:
            raise ValueError("scan_min_syn_ratio must be in (0.0, 1.0]")


class DetectionEngine:
    """Apply configurable rules to one extracted source/destination window."""

    def __init__(
        self,
        thresholds: DetectionThresholds = DetectionThresholds(),
    ) -> None:
        self.thresholds = thresholds

    @staticmethod
    def _number(features: Dict[str, Any], name: str) -> float:
        value = features.get(name, 0)
        try:
            number = float(value)
        except (TypeError, ValueError):
            return 0.0
        return number if isfinite(number) else 0.0

    @staticmethod
    def _epoch_seconds(value: Any) -> float:
        if isinstance(value, datetime):
            return value.timestamp()
        return float(value)

    @staticmethod
    def _heuristic_confidence(exceedance_ratios: Sequence[float]) -> float:
        """Return a rule-strength score, not a calibrated probability."""
        strongest = max(exceedance_ratios, default=1.0)
        return min(0.99, 0.5 + 0.1 * max(0.0, strongest - 1.0))

    def _make_event(
        self,
        row: Dict[str, Any],
        detection_type: str,
        evidence: List[str],
        confidence: float,
    ) -> DetectionEvent:
        numeric_features = {
            key: value
            for key, value in row.items()
            if isinstance(value, (int, float))
        }
        window_start = self._epoch_seconds(row["window_start"])
        window_end = self._epoch_seconds(row["window_end"])

        return DetectionEvent(
            event_id=str(uuid4()),
            timestamp=window_end,
            window_start=window_start,
            window_end=window_end,
            src_ip=str(row["src_ip"]),
            dst_ip=row.get("dst_ip"),
            detection_type=detection_type,
            confidence=confidence,
            features=numeric_features,
            evidence=evidence,
        )

    def detect(self, row: Dict[str, Any]) -> List[DetectionEvent]:
        """Return zero or more suspicious events for an extracted feature row."""
        events: List[DetectionEvent] = []
        t = self.thresholds

        unique_dst_ports = self._number(
            row, "unique_dst_ports"
        ) or self._number(row, "unique_ports")
        unique_dst_ips = self._number(row, "unique_dst_ips") or self._number(
            row, "unique_destinations"
        )
        syn_ratio = self._number(row, "syn_ratio")
        attempt_rate = self._number(row, "connection_attempt_rate")

        port_scan = (
            unique_dst_ports >= t.scan_min_unique_dst_ports
            and syn_ratio >= t.scan_min_syn_ratio
        )
        host_scan = (
            unique_dst_ips >= t.scan_min_unique_dst_ips
            and attempt_rate >= t.scan_min_connection_attempt_rate
            and syn_ratio >= t.scan_min_syn_ratio
        )

        if port_scan or host_scan:
            evidence: List[str] = []
            ratios = [syn_ratio / t.scan_min_syn_ratio]

            if port_scan:
                evidence.append(
                    f"{int(unique_dst_ports)} distinct destination ports "
                    f"with SYN ratio {syn_ratio:.2f}"
                )
                ratios.append(unique_dst_ports / t.scan_min_unique_dst_ports)

            if host_scan:
                evidence.append(
                    f"{int(unique_dst_ips)} distinct destination IPs and "
                    f"{attempt_rate:.2f} SYN attempts per second"
                )
                ratios.extend(
                    [
                        unique_dst_ips / t.scan_min_unique_dst_ips,
                        attempt_rate / t.scan_min_connection_attempt_rate,
                    ]
                )

            events.append(
                self._make_event(
                    row,
                    "potential_network_scan",
                    evidence,
                    self._heuristic_confidence(ratios),
                )
            )

        packets_per_second = self._number(row, "packets_per_second")
        bytes_per_second = self._number(row, "bytes_per_second")
        flows_per_second = self._number(row, "flows_per_second")

        flood_evidence: List[str] = []
        flood_ratios: List[float] = []

        if packets_per_second >= t.flood_min_packets_per_second:
            flood_evidence.append(
                f"packet rate {packets_per_second:.2f} packets/second"
            )
            flood_ratios.append(
                packets_per_second / t.flood_min_packets_per_second
            )

        if bytes_per_second >= t.flood_min_bytes_per_second:
            flood_evidence.append(
                f"byte rate {bytes_per_second:.2f} bytes/second"
            )
            flood_ratios.append(
                bytes_per_second / t.flood_min_bytes_per_second
            )

        if flows_per_second >= t.flood_min_flows_per_second:
            flood_evidence.append(
                f"flow creation rate {flows_per_second:.2f} flows/second"
            )
            flood_ratios.append(
                flows_per_second / t.flood_min_flows_per_second
            )

        if flood_evidence:
            events.append(
                self._make_event(
                    row,
                    "potential_flood",
                    flood_evidence,
                    self._heuristic_confidence(flood_ratios),
                )
            )

        if self._number(row, "lateral_move_flag") == 1:
            events.append(
                self._make_event(
                    row,
                    "suspicious_traffic",
                    [
                        f"source contacted more than "
                        f"{int(self._number(row, 'unique_destinations'))} "
                        f"distinct destinations in the window"
                    ],
                    0.55,
                )
            )

        return events