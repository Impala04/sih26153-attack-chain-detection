"""Stream PCAP/PCAPNG packets into CyberFlux's shared ParsedPacket type."""

from __future__ import annotations

import argparse
import logging
import math
from pathlib import Path
from typing import Iterator

from scapy.error import Scapy_Exception
from scapy.utils import PcapReader

from src.capture.packet_parser import parse_packet
from src.capture.packet_schema import ParsedPacket

logger = logging.getLogger(__name__)

_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",  # little-endian microsecond timestamps
    b"\xa1\xb2\xc3\xd4",  # big-endian microsecond timestamps
    b"\x4d\x3c\xb2\xa1",  # little-endian nanosecond timestamps
    b"\xa1\xb2\x3c\x4d",  # big-endian nanosecond timestamps
}


def _has_capture_header(path: Path) -> bool:
    """Reject files with missing or obviously invalid capture headers."""
    try:
        with path.open("rb") as capture_file:
            header = capture_file.read(28)
    except OSError:
        return False
    if header[:4] in _PCAP_MAGICS:
        return len(header) >= 24
    if header[:4] != b"\x0a\x0d\x0d\x0a" or len(header) < 28:
        return False
    byte_order = header[8:12]
    if byte_order == b"\x1a\x2b\x3c\x4d":
        byteorder = "big"
    elif byte_order == b"\x4d\x3c\x2b\x1a":
        byteorder = "little"
    else:
        return False
    block_length = int.from_bytes(header[4:8], byteorder)
    try:
        file_size = path.stat().st_size
    except OSError:
        return False
    return block_length >= 28 and block_length % 4 == 0 and block_length <= file_size


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
    if capture_path.suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
        raise PcapReadError(f"Unsupported capture format: {capture_path.suffix or '(no extension)'}")
    if not capture_path.is_file():
        raise PcapReadError(f"Capture file does not exist or is not a file: {capture_path}")
    if not _has_capture_header(capture_path):
        raise PcapReadError(f"Capture file has an invalid or incomplete PCAP/PCAPNG header: {capture_path}")

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
                if not math.isfinite(parsed.timestamp):
                    logger.warning("Skipping packet %d in %s with a non-finite timestamp", packet_number, capture_path)
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
