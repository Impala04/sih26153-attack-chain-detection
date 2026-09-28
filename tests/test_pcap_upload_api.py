from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from scapy.all import Ether, ICMP, IP, TCP, UDP, wrpcap
from scapy.utils import PcapNgWriter

from backend.app import app


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_pcap_upload_returns_parsed_packet_metadata(client, tmp_path: Path):
    capture_path = tmp_path / "investigation.pcap"
    wrpcap(
        str(capture_path),
        [
            Ether() / IP(src="192.0.2.1", dst="198.51.100.2") / TCP(sport=443, dport=51515, flags="SA"),
            Ether() / IP(src="192.0.2.1", dst="198.51.100.2") / UDP(sport=53, dport=53000),
            Ether() / IP(src="192.0.2.1", dst="198.51.100.2") / ICMP(),
        ],
    )

    response = client.post(
        "/api/pcap/parse",
        files={"file": (capture_path.name, capture_path.read_bytes(), "application/octet-stream")},
    )

    assert response.status_code == 200
    result = response.json()
    assert result["filename"] == "investigation.pcap"
    assert result["packet_count"] == 3
    assert result["truncated"] is False
    tcp, udp, icmp = result["packets"]
    assert (tcp["src_ip"], tcp["dst_ip"], tcp["src_port"], tcp["dst_port"]) == (
        "192.0.2.1", "198.51.100.2", 443, 51515
    )
    assert tcp["protocol"] == "TCP"
    assert tcp["tcp_flags"] == "SA"
    assert tcp["packet_length"] > 0
    assert tcp["timestamp"] > 0
    assert udp["protocol"] == "UDP"
    assert (udp["src_port"], udp["dst_port"]) == (53, 53000)
    assert icmp["protocol"] == "ICMP"
    assert icmp["src_port"] is None and icmp["dst_port"] is None


def test_pcapng_upload_returns_parsed_packet_metadata(client, tmp_path: Path):
    capture_path = tmp_path / "investigation.pcapng"
    writer = PcapNgWriter(str(capture_path))
    try:
        writer.write(Ether() / IP(src="203.0.113.4", dst="203.0.113.5") / UDP(sport=12345, dport=53))
    finally:
        writer.close()

    response = client.post(
        "/api/pcap/parse",
        files={"file": (capture_path.name, capture_path.read_bytes(), "application/octet-stream")},
    )

    assert response.status_code == 200
    result = response.json()
    assert result["filename"] == "investigation.pcapng"
    assert result["packet_count"] == 1
    packet = result["packets"][0]
    assert packet["protocol"] == "UDP"
    assert packet["src_ip"] == "203.0.113.4"
    assert packet["dst_ip"] == "203.0.113.5"
    assert (packet["src_port"], packet["dst_port"]) == (12345, 53)


@pytest.mark.parametrize(
    ("filename", "content", "status"),
    [
        ("notes.txt", b"not a capture", 415),
        ("broken.pcap", b"not a capture", 400),
        ("empty.pcap", b"", 400),
    ],
)
def test_pcap_upload_rejects_bad_inputs(client, filename: str, content: bytes, status: int):
    response = client.post(
        "/api/pcap/parse",
        files={"file": (filename, content, "application/octet-stream")},
    )

    assert response.status_code == status
