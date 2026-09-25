"""
packet_schema.py — Shared ParsedPacket contract.

This is the single interface between the capture/ingestion layer (this
branch, feature/live-capture) and Aaron's flow-tracking/feature/detection
pipeline. Both live capture and (later) PCAP replay must produce this same
shape so downstream code never needs to know which source a packet came
from.

Do not add detection/scoring fields here — this is a normalized packet
record only, one level above raw bytes.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ParsedPacket:
    timestamp: float  # unix epoch seconds (float, sub-second precision)
    src_ip: str
    dst_ip: str
    protocol: str  # "TCP" | "UDP" | "ICMP" | "OTHER"
    packet_length: int

    # Not every protocol has ports/flags — these are None when not
    # applicable (e.g. ICMP has no ports; UDP has no TCP flags).
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packet_length": self.packet_length,
            "tcp_flags": self.tcp_flags,
        }