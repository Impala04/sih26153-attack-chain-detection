import json

import pytest
from scapy.all import Ether, ICMP, IP, TCP, UDP, wrpcap

from src.analysis.pcap_analyzer import analyze_pcap, write_html_report


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
    json.dumps(report)

    html_path = tmp_path / "report.html"
    write_html_report(report, html_path)
    html_report = html_path.read_text(encoding="utf-8")
    assert "Traffic over time" in html_report
    assert "Top source IPs" in html_report
    assert "Top destination ports" in html_report


def test_empty_capture_has_zero_safe_statistics(tmp_path):
    path = tmp_path / "empty.pcap"
    path.write_bytes(bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000"))
    report = analyze_pcap(path)
    assert report["capture"]["total_packets"] == 0
    assert report["traffic"]["total_bytes"] == 0
    assert report["traffic"]["average_packets_per_second"] == 0
