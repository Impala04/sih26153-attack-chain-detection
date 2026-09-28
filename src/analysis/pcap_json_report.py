"""Deterministic JSON reporting for PCAP investigation results.

This module accepts the structured output from the investigation layer. It has
no dependency on Scapy, the PCAP reader, or the statistics implementation.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

REQUIRED_SECTIONS = (
    "capture",
    "protocols",
    "ips",
    "ports",
    "traffic",
    "tcp_flags",
    "top_communications",
    "time_series",
)


class PcapJsonReportError(ValueError):
    """Raised when investigation results cannot form a valid JSON report."""


def build_json_report(investigation: Mapping[str, Any]) -> dict[str, Any]:
    """Create the JSON report structure from investigation statistics."""
    if not isinstance(investigation, Mapping):
        raise PcapJsonReportError("Investigation results must be a mapping")

    missing = [section for section in REQUIRED_SECTIONS if section not in investigation]
    if missing:
        raise PcapJsonReportError(f"Investigation results are missing sections: {', '.join(missing)}")

    capture = investigation["capture"]
    if not isinstance(capture, Mapping) or "total_packets" not in capture:
        raise PcapJsonReportError("Investigation results must include capture.total_packets")

    report = dict(investigation)
    report["packet_count"] = capture["total_packets"]
    return report


def serialize_json_report(investigation: Mapping[str, Any]) -> str:
    """Return stable, strict JSON with sorted object keys and a final newline."""
    report = build_json_report(investigation)
    try:
        return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
    except (TypeError, ValueError) as exc:
        raise PcapJsonReportError(f"Investigation results are not valid JSON data: {exc}") from exc


def write_json_report(investigation: Mapping[str, Any], path: str | Path) -> None:
    """Write a deterministic UTF-8 JSON report to ``path``."""
    Path(path).write_text(serialize_json_report(investigation), encoding="utf-8")
