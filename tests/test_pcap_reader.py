from pathlib import Path

import pytest
from scapy.all import ARP, Ether, ICMP, IP, Raw, TCP, UDP, IPv6, wrpcap

from src.capture.packet_schema import ParsedPacket
from src.ingestion.pcap_reader import PcapReadError, iter_pcap


def capture(tmp_path: Path, packets, suffix=".pcap") -> Path:
    path = tmp_path / f"sample{suffix}"
    wrpcap(str(path), packets)
    return path


def stamp(packet, timestamp):
    packet.time = timestamp
    return packet


def frame(packet):
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / packet


def test_tcp_fields_and_timestamp(tmp_path):
    raw = stamp(frame(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1200, dport=443, flags="SA")), 1700000000.125)
    parsed, = list(iter_pcap(capture(tmp_path, [raw])))
    assert isinstance(parsed, ParsedPacket)
    assert (parsed.src_ip, parsed.dst_ip, parsed.protocol) == ("10.0.0.1", "10.0.0.2", "TCP")
    assert (parsed.src_port, parsed.dst_port, parsed.tcp_flags) == (1200, 443, "SA")
    assert parsed.timestamp == pytest.approx(1700000000.125)
    assert parsed.packet_length == len(raw)


def test_udp_icmp_and_unsupported_are_handled(tmp_path):
    packets = [
        stamp(frame(IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=2000, dport=53)), 10),
        stamp(frame(IP(src="10.0.0.2", dst="10.0.0.1") / ICMP()), 11),
        stamp(frame(IP(src="10.0.0.9", dst="10.0.0.10", proto=99) / Raw(load=b"unknown")), 12),
        stamp(frame(IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP()), 13),
        stamp(frame(ARP()), 14),
    ]
    parsed = list(iter_pcap(capture(tmp_path, packets)))
    assert [packet.protocol for packet in parsed] == ["UDP", "ICMP", "OTHER"]
    assert (parsed[0].src_port, parsed[0].dst_port, parsed[0].tcp_flags) == (2000, 53, None)
    assert (parsed[1].src_port, parsed[1].dst_port, parsed[1].tcp_flags) == (None, None, None)
    assert parsed[1].packet_length > 0
    assert (parsed[2].src_port, parsed[2].dst_port) == (None, None)


def test_pcapng_supported(tmp_path):
    packets = [stamp(frame(IP() / UDP()), 5)]
    assert len(list(iter_pcap(capture(tmp_path, packets, ".pcapng")))) == 1


def test_empty_and_invalid_path(tmp_path):
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000"))
    assert list(iter_pcap(empty)) == []
    with pytest.raises(PcapReadError, match="does not exist"):
        list(iter_pcap(tmp_path / "missing.pcap"))
    with pytest.raises(PcapReadError, match="Unsupported capture format"):
        list(iter_pcap(tmp_path / "capture.txt"))


def test_timestamp_order_and_equal_timestamps(tmp_path):
    ordered = [stamp(frame(IP() / UDP()), t) for t in (1, 1, 2)]
    assert [p.timestamp for p in iter_pcap(capture(tmp_path, ordered))] == [1, 1, 2]
    backward = [stamp(frame(IP() / UDP()), t) for t in (2, 1)]
    with pytest.raises(PcapReadError, match="go backwards"):
        list(iter_pcap(capture(tmp_path, backward)))


def test_malformed_capture_fails_cleanly(tmp_path):
    path = tmp_path / "broken.pcap"
    path.write_bytes(b"not a pcap")
    with pytest.raises(PcapReadError):
        list(iter_pcap(path))


def test_committed_synthetic_fixtures_are_readable():
    data = Path(__file__).parent / "data"
    expected = {
        "tcp_test.pcap": ["TCP", "TCP"],
        "udp_test.pcap": ["UDP"],
        "icmp_test.pcap": ["ICMP"],
        "mixed_test.pcap": ["TCP", "UDP", "ICMP"],
        "burst_test.pcap": ["UDP"] * 20,
    }
    for filename, protocols in expected.items():
        assert [packet.protocol for packet in iter_pcap(data / filename)] == protocols
