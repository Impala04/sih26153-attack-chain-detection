import json

import pytest

from src.analysis.pcap_json_report import (
    PcapJsonReportError,
    build_json_report,
    serialize_json_report,
    write_json_report,
)


def investigation_result():
    return {
        "capture": {"total_packets": 2, "duration_seconds": 1.0},
        "protocols": {"counts": {"TCP": 1, "UDP": 1}},
        "ips": {"unique_source_ips": 2, "unique_destination_ips": 2},
        "ports": {"top_sources": [{"value": 53000, "packets": 1}]},
        "traffic": {
            "total_bytes": 120,
            "average_packets_per_second": 2.0,
            "average_bytes_per_second": 120.0,
        },
        "tcp_flags": {"SYN": 1, "SYN-ACK": 0},
        "top_communications": [
            {"src_ip": "192.0.2.1", "dst_ip": "192.0.2.2", "packet_count": 1, "byte_count": 60}
        ],
        "time_series": [{"window_start": 100.0, "packet_count": 2, "byte_count": 120}],
    }


def test_json_report_is_structured_valid_and_deterministic(tmp_path):
    source = investigation_result()
    report = build_json_report(source)
    serialized = serialize_json_report(source)
    output_path = tmp_path / "investigation.json"
    write_json_report(source, output_path)

    decoded = json.loads(serialized)
    assert decoded == report
    assert decoded["packet_count"] == 2
    assert {"protocols", "ips", "ports", "tcp_flags", "traffic", "top_communications", "time_series"} <= decoded.keys()
    assert serialize_json_report(dict(reversed(list(source.items())))) == serialized
    assert serialized.endswith("\n")
    assert output_path.read_text(encoding="utf-8") == serialized
    json.dumps(decoded, allow_nan=False)


def test_json_report_rejects_incomplete_and_non_finite_results():
    with pytest.raises(PcapJsonReportError, match="missing sections"):
        build_json_report({"capture": {"total_packets": 0}})

    source = investigation_result()
    source["traffic"]["average_bytes_per_second"] = float("nan")
    with pytest.raises(PcapJsonReportError, match="not valid JSON"):
        serialize_json_report(source)
