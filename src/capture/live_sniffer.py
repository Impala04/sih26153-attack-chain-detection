"""
live_sniffer.py — Live packet capture using Scapy.

    Network Interface -> Scapy sniff() -> parse_packet() -> callback(ParsedPacket)

This module does NOT do detection, windowing, scoring, or MITRE mapping —
it only captures and normalizes packets, then hands each ParsedPacket to
whatever callback the caller provides (e.g. Aaron's FlowTracker.ingest()).

Requires:
  - Windows: Npcap installed (https://npcap.com/)
  - Linux/Mac: root/sudo, or CAP_NET_RAW capability
"""

import threading
from typing import Callable, Optional

from scapy.all import sniff

from src.capture.packet_parser import parse_packet
from src.capture.packet_schema import ParsedPacket


class LiveSniffer:
    """Wraps scapy.sniff() to produce ParsedPacket objects via callback.

    Usage:
        def handle_packet(pkt: ParsedPacket):
            flow_tracker.ingest(pkt)  # Aaron's pipeline

        sniffer = LiveSniffer(callback=handle_packet, iface="eth0", bpf_filter="tcp or udp")
        sniffer.start()
        ...
        sniffer.stop()
    """

    def __init__(
        self,
        callback: Callable[[ParsedPacket], None],
        iface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
    ):
        """
        callback: called once per successfully parsed IP packet.
        iface: network interface name, or None for Scapy's default.
        bpf_filter: optional BPF filter string, e.g. "tcp", "udp", "port 443".
                    None captures all traffic — do not hard-code a default
                    filter that would silently exclude protocols.
        """
        self.callback = callback
        self.iface = iface
        self.bpf_filter = bpf_filter
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _on_packet(self, pkt):
        try:
            parsed = parse_packet(pkt)
            if parsed is not None:
                self.callback(parsed)
        except Exception as e:
            # A single malformed packet must never kill the capture loop.
            print(f"[LiveSniffer] error parsing packet: {e}")

    def _run(self):
        sniff(
            iface=self.iface,
            filter=self.bpf_filter,
            prn=self._on_packet,
            stop_filter=lambda _: self._stop_event.is_set(),
            store=False,  # don't buffer packets in memory
        )

    def start(self):
        """Start capture in a background thread (non-blocking)."""
        if self._thread is not None and self._thread.is_alive():
            raise RuntimeError("Sniffer is already running")
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0):
        """Signal the capture loop to stop and wait for it to exit."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)