"""
test_packet_parser.py — Unit tests for packet_parser.py using synthetic
Scapy packets. No real network access or capture permissions required.

Run with: pytest tests/test_packet_parser.py -v
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.capture.packet_parser import parse_packet
from src.capture.mock_packets import (
    make_tcp_packet,
    make_udp_packet,
    make_icmp_packet,
    make_non_ip_packet,
)


def test_tcp_packet_parses_correctly():
    pkt = make_tcp_packet("192.168.1.10", "192.168.1.20", 51000, 80, flags="S")
    parsed = parse_packet(pkt)

    assert parsed is not None
    assert parsed.src_ip == "192.168.1.10"
    assert parsed.dst_ip == "192.168.1.20"
    assert parsed.protocol == "TCP"
    assert parsed.src_port == 51000
    assert parsed.dst_port == 80
    assert parsed.tcp_flags == "S"


def test_udp_packet_parses_correctly():
    pkt = make_udp_packet("192.168.1.10", "8.8.8.8", 51002, 53)
    parsed = parse_packet(pkt)

    assert parsed is not None
    assert parsed.protocol == "UDP"
    assert parsed.src_port == 51002
    assert parsed.dst_port == 53
    assert parsed.tcp_flags is None  # UDP has no TCP flags


def test_icmp_packet_parses_correctly():
    pkt = make_icmp_packet("192.168.1.10", "192.168.1.20")
    parsed = parse_packet(pkt)

    assert parsed is not None
    assert parsed.protocol == "ICMP"
    assert parsed.src_port is None  # ICMP has no ports
    assert parsed.dst_port is None


def test_non_ip_packet_returns_none():
    pkt = make_non_ip_packet()
    parsed = parse_packet(pkt)

    assert parsed is None  # must not crash, must not fabricate data


def test_packet_length_is_positive():
    pkt = make_tcp_packet("10.0.0.1", "10.0.0.2", 1234, 443, flags="PA", payload_size=500)
    parsed = parse_packet(pkt)

    assert parsed.packet_length > 500  # payload + headers


def test_missing_fields_handled_safely():
    # ICMP packet with no ports/flags should not raise, and fields should
    # default to None rather than crashing
    pkt = make_icmp_packet("172.16.0.1", "172.16.0.2")
    parsed = parse_packet(pkt)

    assert parsed.tcp_flags is None
    assert parsed.src_port is None
    assert parsed.dst_port is None