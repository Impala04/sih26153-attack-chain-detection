import json
import os
import re
from pathlib import Path

from scapy.all import Ether, IP, TCP
from scapy.utils import PcapNgWriter

from src.orchestrator import run_analysis
from tests.test_run_analysis import _write_scan_pcap

GOLDEN_PATH = Path(__file__).resolve().parent / "data" / "golden_scan_analysis.json"
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _normalize(result: dict) -> dict:
    """Drop per-run fields and make ids stable so two runs can be compared."""
    data = dict(result)
    data.pop("analysis_id", None)
    data.pop("timestamp", None)
    seen: dict = {}

    def walk(value):
        if isinstance(value, dict):
            return {key: walk(item) for key, item in value.items()}
        if isinstance(value, list):
            return [walk(item) for item in value]
        if isinstance(value, float):
            return round(value, 4)
        if isinstance(value, str) and UUID_RE.match(value):
            return seen.setdefault(value, f"<id-{len(seen) + 1}>")
        return value

    return _mask_mock_outputs(_stabilize_chain_events(walk(data)))


def _stabilize_chain_events(data: dict) -> dict:
    """Same-timestamp events in a chain come out in a different order between
    runs (correlate() tie-breaks on event_id). Keep the real invariant
    (timestamps never go backwards) and sort ties so runs are comparable."""
    for chain in data.get("attack_chains", []):
        events = chain.get("events", [])
        stamps = [event["timestamp"] for event in events]
        assert stamps == sorted(stamps), "chain events are not in timestamp order"
        events.sort(
            key=lambda e: (
                e["timestamp"],
                e["detection_type"],
                e["src_ip"],
                e.get("dst_ip") or "",
            )
        )
    return data

def _mask_mock_outputs(data: dict) -> dict:
    """Mock forecast/risk values change between runs, so compare only their
    shape (and risk's provider label), not the mock numbers."""
    forecast = data.get("forecast")
    if forecast is not None:
        data["forecast"] = {"keys": sorted(forecast)}
    risk = data.get("risk")
    if risk is not None:
        data["risk"] = {"keys": sorted(risk), "source": risk.get("source")}
    return data

def _run_scan(tmp_path: Path) -> dict:
    capture = tmp_path / "golden_scan.pcap"
    _write_scan_pcap(capture)
    result = run_analysis(capture)
    return _normalize(json.loads(result.model_dump_json()))


def test_scan_analysis_matches_golden(tmp_path: Path):
    actual = _run_scan(tmp_path)
    assert len(actual["detections"]) == 7, "unexpected detection count for the scan capture"
    if os.environ.get("UPDATE_GOLDEN") == "1":
        GOLDEN_PATH.write_text(json.dumps(actual, indent=2, sort_keys=True), encoding="utf-8")
    assert GOLDEN_PATH.exists(), "golden file missing; run once with UPDATE_GOLDEN=1"
    expected = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    assert actual == expected


def test_scan_analysis_is_deterministic(tmp_path: Path):
    assert _run_scan(tmp_path) == _run_scan(tmp_path)


def _write_scan_pcapng(path: Path) -> None:
    base = 1_735_732_800.0
    packets = []
    for i, port in enumerate(range(20, 30)):
        packets.append((base + i, "10.0.0.10", port, 40000 + i))
    for i, host in enumerate(range(20, 26), start=31):
        packets.append((base + i, f"10.0.0.{host}", 445, 41000 + i))
    writer = PcapNgWriter(str(path))
    try:
        for t, dst, dport, sport in packets:
            pkt = Ether() / IP(src="10.0.0.5", dst=dst) / TCP(sport=sport, dport=dport, flags="S")
            pkt.time = t
            writer.write(pkt)
    finally:
        writer.close()


def test_pcapng_scan_gets_ml_scores(tmp_path: Path):
    capture = tmp_path / "scan.pcapng"
    _write_scan_pcapng(capture)
    result = run_analysis(capture)
    assert result.detections, "pcapng scan produced no detections"
    assert "scan.pcapng" in result.input_source
    for detection in result.detections:
        meta = detection.get("metadata", {})
        assert "ml_score_error" not in meta, meta.get("ml_score_error")
        assert "ml_score" in meta