"""
packet_parser.py — Converts a raw Scapy packet into a ParsedPacket.

This is the shared core used by both live capture (live_sniffer.py) and,
later, PCAP replay — both paths call parse_packet() so downstream code
(Aaron's flow tracker) always receives the same shape regardless of source.

No detection, windowing, or scoring happens here — purely normalization.
"""

import time
from typing import Optional

from scapy.all import IP, TCP, UDP, ICMP

from src.capture.packet_schema import ParsedPacket


def parse_packet(pkt) -> Optional[ParsedPacket]:
    """Parse a raw Scapy packet into a ParsedPacket, or return None if the
    packet isn't IP-based (e.g. ARP, raw Ethernet)."""
    if not pkt.haslayer(IP):
        return None

    ip_layer = pkt[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    packet_length = len(pkt)

    # CIC-compatible bytes count TCP/UDP payload, excluding packet headers.
    payload_length = 0

    # Use the packet's capture timestamp when available; otherwise use now.
    timestamp = float(getattr(pkt, "time", time.time()))

    src_port = None
    dst_port = None
    tcp_flags = None
    protocol = "OTHER"

    if pkt.haslayer(TCP):
        tcp_layer = pkt[TCP]
        protocol = "TCP"
        src_port = int(tcp_layer.sport)
        dst_port = int(tcp_layer.dport)
        tcp_flags = str(tcp_layer.flags)
        payload_length = len(bytes(tcp_layer.payload))
    elif pkt.haslayer(UDP):
        udp_layer = pkt[UDP]
        protocol = "UDP"
        src_port = int(udp_layer.sport)
        dst_port = int(udp_layer.dport)
        payload_length = len(bytes(udp_layer.payload))
        # UDP has no TCP flags, so tcp_flags remains None.
    elif pkt.haslayer(ICMP):
        protocol = "ICMP"
        # ICMP has no ports; payload_length remains 0.

    return ParsedPacket(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        packet_length=packet_length,
        payload_length=payload_length,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
    )