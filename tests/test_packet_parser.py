"""
test_packet_parser.py — Unit tests for packet_parser.py using synthetic
Scapy packets. No real network access or capture permissions required.

Run with: pytest tests/test_packet_parser.py -v
"""

"""Unit tests for packet_parser.py using synthetic Scapy packets."""

from src.capture.packet_parser import parse_packet
from src.capture.mock_packets import (
    make_tcp_packet,
    make_udp_packet,
    make_icmp_packet,
    make_non_ip_packet,
)


def test_tcp_packet_parses_correctly():
    pkt = make_tcp_packet(
        "192.168.1.10",
        "192.168.1.20",
        51000,
        80,
        flags="S",
        payload_size=500,
    )
    parsed = parse_packet(pkt)

    assert parsed is not None
    assert parsed.src_ip == "192.168.1.10"
    assert parsed.dst_ip == "192.168.1.20"
    assert parsed.protocol == "TCP"
    assert parsed.src_port == 51000
    assert parsed.dst_port == 80
    assert parsed.tcp_flags == "S"
    assert parsed.payload_length == 500
    assert parsed.packet_length > parsed.payload_length


def test_udp_packet_parses_correctly():
    pkt = make_udp_packet(
        "192.168.1.10",
        "8.8.8.8",
        51002,
        53,
        payload_size=300,
    )
    parsed = parse_packet(pkt)

    assert parsed is not None
    assert parsed.protocol == "UDP"
    assert parsed.src_port == 51002
    assert parsed.dst_port == 53
    assert parsed.tcp_flags is None
    assert parsed.payload_length == 300


def test_icmp_packet_parses_correctly():
    pkt = make_icmp_packet("192.168.1.10", "192.168.1.20")
    parsed = parse_packet(pkt)

    assert parsed is not None
    assert parsed.protocol == "ICMP"
    assert parsed.src_port is None
    assert parsed.dst_port is None
    assert parsed.tcp_flags is None
    assert parsed.payload_length == 0


def test_non_ip_packet_returns_none():
    pkt = make_non_ip_packet()
    parsed = parse_packet(pkt)

    assert parsed is None


def test_packet_length_is_positive():
    pkt = make_tcp_packet(
        "10.0.0.1",
        "10.0.0.2",
        1234,
        443,
        flags="PA",
        payload_size=500,
    )
    parsed = parse_packet(pkt)

    assert parsed is not None
    assert parsed.packet_length > 500
    assert parsed.payload_length == 500


def test_missing_fields_handled_safely():
    pkt = make_icmp_packet("172.16.0.1", "172.16.0.2")
    parsed = parse_packet(pkt)

    assert parsed is not None
    assert parsed.tcp_flags is None
    assert parsed.src_port is None
    assert parsed.dst_port is None
    assert parsed.payload_length == 0