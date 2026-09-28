"""Shared ParsedPacket contract between capture, replay, and analysis."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ParsedPacket:
    """Normalized packet metadata; no raw Scapy objects cross this boundary."""

    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    packet_length: int
    # Application payload bytes used by the bidirectional flow tracker.
    payload_length: int = 0
    # Not every protocol has ports/flags; these are None when not applicable.
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None
    ttl: Optional[int] = None
    tcp_window: Optional[int] = None
    fragmented: Optional[bool] = None
    payload_size: Optional[int] = None
    tcp_seq: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packet_length": self.packet_length,
            "payload_length": self.payload_length,
            "tcp_flags": self.tcp_flags,
            "ttl": self.ttl,
            "tcp_window": self.tcp_window,
            "fragmented": self.fragmented,
            "payload_size": self.payload_size,
            "tcp_seq": self.tcp_seq,
        }
