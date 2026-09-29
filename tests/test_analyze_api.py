from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from scapy.all import Ether, IP, TCP, wrpcap

from backend.app import app

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def client(monkeypatch):
    # API behavior tests don't require a private, trained model artifact.
    # The dedicated production-provider tests cover real artifact loading.
    from backend import analysis_routes
    from src.orchestrator import AnalysisOrchestrator

    monkeypatch.setattr(
        analysis_routes, "_production_orchestrator", AnalysisOrchestrator
    )
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

import csv
import io


def _csv_row(**overrides):
    row = {
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.9",
        "window_start": "2025-01-01 12:00:00",
        "connection_count": 5,
        "unique_destinations": 1,
        "unique_ports": 5,
        "total_fwd_packets": 5,
        "total_bwd_packets": 5,
        "total_bytes_fwd": 500,
        "total_bytes_bwd": 500,
        "avg_flow_duration": 1000.0,
        "max_flow_duration": 2000.0,
        "std_flow_duration": 100.0,
        "max_bytes_total": 200.0,
        "std_bytes_total": 20.0,
        "max_packets_total": 5.0,
        "bytes_per_connection": 100.0,
        "flows_per_second": 0.2,
    }
    row.update(overrides)
    return row


def _csv_bytes(rows) -> bytes:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue().encode()


def test_analyze_csv_returns_result(client):
    response = _post(client, "flows.csv", _csv_bytes([_csv_row()]))
    assert response.status_code == 200, response.text
    assert response.json()["input_source"] == "csv:flows.csv"


def test_analyze_csv_lateral_movement_is_detected_and_scored(client):
    from src.model.train import LATERAL_MOVE_THRESHOLD

    row = _csv_row(unique_destinations=int(LATERAL_MOVE_THRESHOLD) + 5)
    response = _post(client, "lateral.csv", _csv_bytes([row]))
    _assert_scored(response)


@pytest.mark.parametrize(
    "content",
    [
        b"src_ip,dst_ip\n1.1.1.1,2.2.2.2\n",
        (",".join(_csv_row().keys()) + "\n").encode(),
        b"\xff\xfe\x00\x01garbage\x80\x81",
    ],
    ids=["missing_columns", "header_only", "garbage_bytes"],
)
def test_analyze_csv_bad_content_returns_400(client, content: bytes):
    assert _post(client, "bad.csv", content).status_code == 400


def test_analyze_returns_service_unavailable_when_real_model_is_missing(client, monkeypatch):
    from backend import analysis_routes

    def missing_model():
        raise FileNotFoundError("World Model weights not found")

    monkeypatch.setattr(analysis_routes, "_production_orchestrator", missing_model)
    response = _post(client, "flows.csv", _csv_bytes([_csv_row()]))
    assert response.status_code == 503
    assert "real World Model is unavailable" in response.json()["detail"]
