"""Convert raw IPv4 Scapy packets to the source-independent ParsedPacket."""

import time
from typing import Optional

from scapy.all import IP, TCP, UDP, ICMP

from src.capture.packet_schema import ParsedPacket


def parse_packet(pkt) -> Optional[ParsedPacket]:
    """Normalize IPv4 packets; return None for unsupported/non-IPv4 packets."""
    if not pkt.haslayer(IP):
        return None

    ip_layer = pkt[IP]
    packet_length = len(pkt)
    # CIC-compatible payload bytes exclude IP/TCP/UDP headers.
    payload_length = 0
    timestamp = float(getattr(pkt, "time", time.time()))
    src_port = dst_port = tcp_flags = tcp_window = tcp_seq = None
    protocol = "OTHER"
    payload_size = None

    if pkt.haslayer(TCP):
        tcp_layer = pkt[TCP]
        protocol = "TCP"
        src_port, dst_port = int(tcp_layer.sport), int(tcp_layer.dport)
        tcp_flags = str(tcp_layer.flags)
        tcp_window = int(tcp_layer.window)
        tcp_seq = int(tcp_layer.seq)
        payload_size = len(bytes(tcp_layer.payload))
        payload_length = payload_size
    elif pkt.haslayer(UDP):
        udp_layer = pkt[UDP]
        protocol = "UDP"
        src_port, dst_port = int(udp_layer.sport), int(udp_layer.dport)
        payload_size = len(bytes(udp_layer.payload))
        payload_length = payload_size
    elif pkt.haslayer(ICMP):
        protocol = "ICMP"
        payload_size = len(bytes(pkt[ICMP].payload))

    flags = int(ip_layer.flags)
    fragmented = bool(flags & 0x1 or int(ip_layer.frag) > 0)
    ttl = int(ip_layer.ttl)
    if not 1 <= ttl <= 255:
        ttl = None

    return ParsedPacket(
        timestamp=timestamp,
        src_ip=ip_layer.src,
        dst_ip=ip_layer.dst,
        protocol=protocol,
        packet_length=packet_length,
        payload_length=payload_length,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        ttl=ttl,
        tcp_window=tcp_window,
        fragmented=fragmented,
        payload_size=payload_size,
        tcp_seq=tcp_seq,
    )
