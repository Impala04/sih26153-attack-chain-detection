"""Stream PCAP/PCAPNG packets into CyberFlux's shared ParsedPacket type."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Iterator

from scapy.error import Scapy_Exception
from scapy.utils import PcapReader

from src.capture.packet_parser import parse_packet
from src.capture.packet_schema import ParsedPacket

logger = logging.getLogger(__name__)


class PcapReadError(Exception):
    """Raised when a capture cannot be opened or is not chronologically ordered."""


def iter_pcap(path: str | Path) -> Iterator[ParsedPacket]:
    """Yield parsed IPv4 packets from a PCAP/PCAPNG file in timestamp order.

    Unsupported/non-IP packets (including ARP and IPv6) are skipped. A packet
    that fails normalization is logged and skipped. Capture records are streamed
    and must be timestamp ordered; a backwards timestamp raises PcapReadError
    because sorting an arbitrary capture would require buffering the full file.
    Equal timestamps retain their original record order.
    """
    capture_path = Path(path)
    if capture_path.suffix.lower() not in {".pcap", ".pcapng"}:
        raise PcapReadError(f"Unsupported capture format: {capture_path.suffix or '(no extension)'}")
    if not capture_path.is_file():
        raise PcapReadError(f"Capture file does not exist or is not a file: {capture_path}")

    try:
        reader = PcapReader(str(capture_path))
    except (OSError, Scapy_Exception, ValueError) as exc:
        raise PcapReadError(f"Could not open capture {capture_path}: {exc}") from exc

    last_timestamp: float | None = None
    packet_number = 0
    try:
        with reader:
            while True:
                try:
                    raw_packet = reader.read_packet()
                except EOFError:
                    break
                except (OSError, Scapy_Exception, ValueError) as exc:
                    raise PcapReadError(
                        f"Could not read capture {capture_path} near packet {packet_number + 1}: {exc}"
                    ) from exc
                if raw_packet is None:
                    break
                packet_number += 1
                try:
                    parsed = parse_packet(raw_packet)
                except Exception:
                    logger.warning("Skipping malformed packet %d in %s", packet_number, capture_path, exc_info=True)
                    continue
                if parsed is None:
                    logger.debug("Skipping unsupported/non-IPv4 packet %d in %s", packet_number, capture_path)
                    continue
                if last_timestamp is not None and parsed.timestamp < last_timestamp:
                    raise PcapReadError(
                        f"Capture timestamps go backwards at packet {packet_number}: "
                        f"{parsed.timestamp} follows {last_timestamp}"
                    )
                last_timestamp = parsed.timestamp
                yield parsed
    except PcapReadError:
        raise
    except (OSError, Scapy_Exception, ValueError) as exc:
        raise PcapReadError(f"Could not read capture {capture_path}: {exc}") from exc


def read_pcap(path: str | Path) -> Iterator[ParsedPacket]:
    """Compatibility-friendly streaming alias for :func:`iter_pcap`."""
    return iter_pcap(path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Stream parsed packets from a PCAP/PCAPNG capture")
    parser.add_argument("path", help="Path to a .pcap or .pcapng file")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        count = 0
        for packet in iter_pcap(args.path):
            print(packet.to_dict())
            count += 1
        logger.info("Parsed %d IPv4 packets", count)
    except PcapReadError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
