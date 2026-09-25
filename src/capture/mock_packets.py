"""
mock_packets.py — Synthetic Scapy packets for testing the parser and for
Aaron to test his downstream pipeline without needing real network traffic
or root/admin capture permissions.

Usage:
    from src.capture.mock_packets import make_tcp_packet, make_udp_packet, make_icmp_packet

    pkt = make_tcp_packet("192.168.1.10", "192.168.1.20", 51000, 443, flags="PA")
"""

from scapy.all import IP, TCP, UDP, ICMP, Ether, Raw


def make_tcp_packet(src_ip: str, dst_ip: str, sport: int, dport: int,
                     flags: str = "S", payload_size: int = 0):
    pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags=flags)
    if payload_size:
        pkt = pkt / Raw(load=b"x" * payload_size)
    return pkt


def make_udp_packet(src_ip: str, dst_ip: str, sport: int, dport: int,
                     payload_size: int = 0):
    pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport)
    if payload_size:
        pkt = pkt / Raw(load=b"x" * payload_size)
    return pkt


def make_icmp_packet(src_ip: str, dst_ip: str, payload_size: int = 0):
    pkt = IP(src=src_ip, dst=dst_ip) / ICMP()
    if payload_size:
        pkt = pkt / Raw(load=b"x" * payload_size)
    return pkt


def make_non_ip_packet():
    """A raw Ethernet frame with no IP layer — parser must ignore this
    cleanly rather than crash."""
    return Ether()


# A few ready-made example flows matching the task's sample scenarios
EXAMPLE_PACKETS = [
    make_tcp_packet("192.168.1.10", "192.168.1.20", 51000, 80, flags="S"),
    make_tcp_packet("192.168.1.10", "192.168.1.20", 51001, 443, flags="PA"),
    make_udp_packet("192.168.1.10", "8.8.8.8", 51002, 53),
]