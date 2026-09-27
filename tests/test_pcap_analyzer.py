import json
import sys

import pytest
from scapy.all import Ether, ICMP, IP, TCP, UDP, wrpcap

from src.analysis.pcap_analyzer import analyze_packets, analyze_pcap, write_html_report
from src.analysis.pcap_analyzer import main as analyzer_main
from src.capture.packet_schema import ParsedPacket


def frame(packet):
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / packet


def test_statistics_for_deterministic_capture(tmp_path):
    path = tmp_path / "known.pcap"
    packets = [
        frame(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=443, flags="S")),
        frame(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=443, flags="SA")),
        frame(IP(src="10.0.0.2", dst="8.8.8.8") / UDP(sport=40000, dport=53)),
        frame(IP(src="10.0.0.2", dst="10.0.0.1") / ICMP()),
    ]
    for packet, ts in zip(packets, (100, 100.5, 101.25, 102)):
        packet.time = ts
    wrpcap(str(path), packets)

    report = analyze_pcap(path, window_seconds=1)
    assert report["capture"]["total_packets"] == 4
    assert report["capture"]["duration_seconds"] == pytest.approx(2)
    assert report["protocols"]["counts"] == {"TCP": 2, "UDP": 1, "ICMP": 1, "OTHER": 0}
    assert report["protocols"]["distribution_percent"] == {"TCP": 50, "UDP": 25, "ICMP": 25, "OTHER": 0}
    assert report["ips"]["unique_source_ips"] == 2
    assert report["ips"]["unique_destination_ips"] == 3
    assert report["ips"]["unique_communicating_pairs"] == 3
    assert report["ports"]["top_destinations"] == [{"value": 443, "packets": 2}, {"value": 53, "packets": 1}]
    assert report["ports"]["common_service_ports"]["443"]["destination_packets"] == 2
    assert report["tcp_flags"]["SYN"] == 1
    assert report["tcp_flags"]["SYN-ACK"] == 1
    assert report["traffic"]["total_bytes"] == sum(len(p) for p in packets)
    assert report["traffic"]["average_packet_size_bytes"] == pytest.approx(report["traffic"]["total_bytes"] / 4)
    assert report["traffic"]["average_packets_per_second"] == pytest.approx(2)
    assert report["top_communications"][0]["packet_count"] == 2
    assert [window["packet_count"] for window in report["time_series"]] == [2, 1, 1]
    json.dumps(report, allow_nan=False)

    html_path = tmp_path / "report.html"
    write_html_report(report, html_path)
    html_report = html_path.read_text(encoding="utf-8")
    assert "Traffic over time" in html_report
    assert "Top source IPs" in html_report
    assert "Top destination ports" in html_report

    rate_report = analyze_pcap(path, window_seconds=5)
    write_html_report(rate_report, html_path)
    html_report = html_path.read_text(encoding="utf-8")
    assert "const values=[0.8]" in html_report
    assert "Packets per second" in html_report


def test_observations_are_deterministic_and_statistical(tmp_path, monkeypatch):
    path = tmp_path / "synthetic.pcap"
    path.write_bytes(b"fixture")
    packets = [
        ParsedPacket(100.0, "10.0.0.1", f"192.0.2.{index}", "UDP", 60, 53000, 53)
        for index in range(1, 52)
    ]
    monkeypatch.setattr("src.analysis.pcap_analyzer.iter_pcap", lambda _path: iter(packets))
    first = analyze_pcap(path)
    second = analyze_pcap(path)
    expected = ["A time window included at least 50 unique destination IP addresses."]
    assert first["observations"] == expected
    assert second["observations"] == expected
    assert not any("attack" in observation.lower() for observation in first["observations"])


def test_cli_writes_json_and_html_from_same_report(tmp_path, monkeypatch, capsys):
    capture_path = tmp_path / "known.pcap"
    packets = [
        frame(IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=50000, dport=53)),
        frame(IP(src="10.0.0.2", dst="10.0.0.1") / ICMP()),
    ]
    for packet, timestamp in zip(packets, (100, 102)):
        packet.time = timestamp
    wrpcap(str(capture_path), packets)
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    monkeypatch.setattr(sys, "argv", [
        "pcap_analyzer", str(capture_path), "--output", str(json_path), "--html", str(html_path), "--window", "5",
    ])
    analyzer_main()
    report = json.loads(json_path.read_text(encoding="utf-8"))
    json.dumps(report, allow_nan=False)
    assert html_path.exists()
    assert "const values=[0.4]" in html_path.read_text(encoding="utf-8")
    assert "Wrote" in capsys.readouterr().out


def test_cli_invalid_capture_has_clean_nonzero_error(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["pcap_analyzer", str(tmp_path / "missing.pcap")])
    with pytest.raises(SystemExit) as result:
        analyzer_main()
    assert result.value.code == 2
    error = capsys.readouterr().err
    assert "Cannot stat capture" in error
    assert "Traceback" not in error


def test_empty_capture_has_zero_safe_statistics(tmp_path):
    path = tmp_path / "empty.pcap"
    path.write_bytes(bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000"))
    report = analyze_pcap(path)
    assert report["capture"]["total_packets"] == 0
    assert report["traffic"]["total_bytes"] == 0
    assert report["traffic"]["average_packets_per_second"] == 0
    assert report["observations"] == ["No supported IPv4 packets were available for analysis."]
    json.dumps(report, allow_nan=False)


def test_packet_analysis_skips_invalid_timestamps_and_missing_metadata():
    packets = [
        ParsedPacket(None, "192.0.2.1", "192.0.2.2", "TCP", 60),
        ParsedPacket(float("nan"), "192.0.2.1", "192.0.2.3", "UDP", 60),
        ParsedPacket(float("inf"), "192.0.2.1", "192.0.2.4", "ICMP", 60),
        ParsedPacket("not-a-time", "192.0.2.1", "192.0.2.5", "TCP", 60),
        ParsedPacket(1e100, "192.0.2.1", "192.0.2.6", "TCP", 60),
        ParsedPacket(100.0, "192.0.2.1", "192.0.2.2", "TCP", 60),
        ParsedPacket(100.5, "192.0.2.2", "192.0.2.1", "UDP", 50, None, 53),
    ]

    report = analyze_packets(packets, window_seconds=1)

    assert report["capture"]["total_packets"] == 2
    assert report["capture"]["start_time"] == 100.0
    assert report["capture"]["end_time"] == 100.5
    assert report["protocols"]["counts"] == {"TCP": 1, "UDP": 1, "ICMP": 0, "OTHER": 0}
    assert report["ports"]["top_sources"] == []
    assert report["ports"]["top_destinations"] == [{"value": 53, "packets": 1}]
    assert all(value == 0 for value in report["tcp_flags"].values())
    assert report["top_communications"] == [
        {"src_ip": "192.0.2.1", "dst_ip": "192.0.2.2", "packet_count": 1, "byte_count": 60},
        {"src_ip": "192.0.2.2", "dst_ip": "192.0.2.1", "packet_count": 1, "byte_count": 50},
    ]
    json.dumps(report, allow_nan=False)
