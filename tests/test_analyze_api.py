from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from scapy.all import Ether, IP, TCP, wrpcap

from backend.app import app

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def _write_scan_capture(path: Path) -> None:
    base = 1_735_732_800.0
    packets = []
    for i, port in enumerate(range(20, 30)):
        packets.append(
            Ether() / IP(src="10.0.0.5", dst="10.0.0.10") / TCP(sport=40000 + i, dport=port, flags="S")
        )
    for i, host in enumerate(range(20, 26)):
        packets.append(
            Ether() / IP(src="10.0.0.5", dst=f"10.0.0.{host}") / TCP(sport=41000 + i, dport=445, flags="S")
        )
    for i, packet in enumerate(packets):
        packet.time = base + i * 0.5
    wrpcap(str(path), packets)


def _post(client, name: str, content: bytes):
    return client.post(
        "/api/analyze",
        files={"file": (name, content, "application/octet-stream")},
    )


def _assert_scored(response) -> dict:
    assert response.status_code == 200, response.text
    body = response.json()
    detections = body["detections"]
    assert detections, "scan capture produced no detections"
    for detection in detections:
        meta = detection.get("metadata", {})
        assert "ml_score_error" not in meta, meta.get("ml_score_error")
        assert "ml_score" in meta, list(detection)
    return body


def test_analyze_pcap_returns_scored_detections(client, tmp_path: Path):
    capture = tmp_path / "scan.pcap"
    _write_scan_capture(capture)
    response = _post(client, capture.name, capture.read_bytes())
    _assert_scored(response)
    assert "pcap:scan.pcap" in response.text


def test_analyze_scores_when_started_from_backend_dir(client, tmp_path: Path, monkeypatch):
    capture = tmp_path / "scan.pcap"
    _write_scan_capture(capture)
    content = capture.read_bytes()
    monkeypatch.chdir(REPO_ROOT / "backend")
    _assert_scored(_post(client, capture.name, content))


@pytest.mark.parametrize(
    ("filename", "content", "status"),
    [
        ("notes.txt", b"not a capture", 415),
        ("broken.pcap", b"not a capture", 400),
        ("empty.pcap", b"", 400),
    ],
)
def test_analyze_rejects_bad_inputs(client, filename: str, content: bytes, status: int):
    assert _post(client, filename, content).status_code == status