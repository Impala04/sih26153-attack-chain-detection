from pathlib import Path

import pytest
from scapy.all import Ether, IP, TCP, UDP, wrpcap

from src.capture.packet_schema import ParsedPacket
from src.ingestion import pcap_reader
from src.ingestion.pcap_reader import PcapReadError, iter_pcap

DATA = Path(__file__).parent / "data"


def capture(tmp_path: Path, packets, suffix=".pcap") -> Path:
    path = tmp_path / f"sample{suffix}"
    wrpcap(str(path), packets)
    return path


def stamp(packet, timestamp):
    packet.time = timestamp
    return packet


def frame(packet):
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / packet


def test_investigation_fixture_covers_protocols_flags_pairs_and_unsupported_frames():
    parsed = list(iter_pcap(DATA / "investigation_fixture.pcap"))

    assert [packet.protocol for packet in parsed] == ["TCP", "TCP", "TCP", "UDP", "UDP", "ICMP", "OTHER"]
    assert [packet.timestamp for packet in parsed] == pytest.approx([
        1700000300.0, 1700000300.25, 1700000300.5, 1700000300.75,
        1700000301.0, 1700000301.5, 1700000302.0,
    ])
    assert (parsed[0].src_ip, parsed[0].dst_ip, parsed[0].src_port, parsed[0].dst_port, parsed[0].tcp_flags) == (
        "10.10.0.1", "10.10.0.2", 51514, 443, "S"
    )
    assert (parsed[1].src_port, parsed[1].dst_port, parsed[1].tcp_flags) == (443, 51514, "SA")
    assert (parsed[2].tcp_flags, parsed[3].src_port, parsed[3].dst_port) == ("A", 53000, 53)
    assert (parsed[5].src_port, parsed[5].dst_port, parsed[5].tcp_flags) == (None, None, None)
    assert (parsed[6].src_port, parsed[6].dst_port, parsed[6].tcp_flags) == (None, None, None)
    assert all(packet.packet_length > 0 for packet in parsed)
    # The fixture also contains IPv6 and ARP records; the IPv4-only reader skips them.
    assert len(parsed) == 7


def test_pcapng_fixture_is_readable_and_preserves_metadata():
    path = DATA / "investigation_fixture.pcapng"
    assert path.read_bytes().startswith(bytes.fromhex("0a0d0d0a"))

    parsed = list(iter_pcap(path))

    assert [packet.protocol for packet in parsed] == ["TCP", "TCP", "UDP", "ICMP"]
    assert [packet.timestamp for packet in parsed] == pytest.approx([
        1700000400.0, 1700000400.5, 1700000401.0, 1700000402.0,
    ])
    assert (parsed[0].src_ip, parsed[0].dst_ip, parsed[0].src_port, parsed[0].dst_port) == (
        "192.0.2.10", "192.0.2.20", 50100, 443
    )
    assert parsed[0].tcp_flags == "S"
    assert parsed[1].tcp_flags == "SA"
    assert (parsed[2].src_port, parsed[2].dst_port) == (53000, 53)
    assert parsed[3].src_port is None and parsed[3].dst_port is None


def test_empty_and_invalid_path(tmp_path):
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000"))
    assert list(iter_pcap(empty)) == []
    with pytest.raises(PcapReadError, match="does not exist"):
        list(iter_pcap(tmp_path / "missing.pcap"))
    with pytest.raises(PcapReadError, match="Unsupported capture format"):
        list(iter_pcap(tmp_path / "capture.txt"))
    with pytest.raises(PcapReadError, match="invalid or incomplete"):
        list(iter_pcap(DATA / "malformed_capture.pcap"))

    cap_file = capture(tmp_path, [stamp(frame(IP() / UDP(sport=53)), 5)], ".cap")
    parsed, = list(iter_pcap(cap_file))
    assert parsed.protocol == "UDP"


def test_timestamp_order_and_equal_timestamps(tmp_path):
    ordered = [stamp(frame(IP() / UDP()), t) for t in (1, 1, 2)]
    assert [p.timestamp for p in iter_pcap(capture(tmp_path, ordered))] == [1, 1, 2]
    backward = [stamp(frame(IP() / UDP()), t) for t in (2, 1)]
    with pytest.raises(PcapReadError, match="go backwards"):
        list(iter_pcap(capture(tmp_path, backward)))


def test_malformed_packet_is_skipped_and_reading_continues(tmp_path, monkeypatch):
    packets = [
        stamp(frame(IP() / UDP(sport=1000, dport=53)), 1),
        stamp(frame(IP() / TCP(sport=2000, dport=443, flags="S")), 2),
    ]
    path = capture(tmp_path, packets)
    original_parse_packet = pcap_reader.parse_packet
    packet_number = 0

    def parse_with_corrupt_record(raw_packet):
        nonlocal packet_number
        packet_number += 1
        if packet_number == 1:
            raise ValueError("malformed packet")
        return original_parse_packet(raw_packet)

    monkeypatch.setattr(pcap_reader, "parse_packet", parse_with_corrupt_record)
    parsed, = list(iter_pcap(path))
    assert parsed.protocol == "TCP"


def test_non_finite_timestamp_is_skipped(tmp_path, monkeypatch):
    path = capture(tmp_path, [stamp(frame(IP() / UDP()), 1)])
    malformed = ParsedPacket(float("nan"), "10.0.0.1", "10.0.0.2", "UDP", 42, 1, 2)
    monkeypatch.setattr(pcap_reader, "parse_packet", lambda _packet: malformed)
    assert list(iter_pcap(path)) == []


def test_existing_synthetic_fixtures_are_readable():
    expected = {
        "tcp_test.pcap": ["TCP", "TCP"],
        "udp_test.pcap": ["UDP"],
        "icmp_test.pcap": ["ICMP"],
        "mixed_test.pcap": ["TCP", "UDP", "ICMP"],
        "burst_test.pcap": ["UDP"] * 20,
    }
    for filename, protocols in expected.items():
        assert [packet.protocol for packet in iter_pcap(DATA / filename)] == protocols
