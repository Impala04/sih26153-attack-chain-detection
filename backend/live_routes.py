"""Live sensor API. Only live capture; never falls back to dataset data."""
import ipaddress
import json
import socket
from dataclasses import asdict, is_dataclass
from typing import Optional

from fastapi import APIRouter, HTTPException

from src.live.sensor import LiveSensor, LiveSensorError

router = APIRouter(prefix="/api/live", tags=["live"])
_sensor: Optional[LiveSensor] = None
_target: Optional[dict] = None  # {"input": str, "ips": [str]}


def _to_dict(event):
    return asdict(event) if is_dataclass(event) else dict(vars(event))


def _idle_status():
    return {"running": False, "error": None, "packets_seen": 0,
            "events_buffered": 0, "source": "live", "target": _target}


def _demo_detection_packets():
    """Use the project's deterministic detection-test packets, never invented events."""
    from src.capture.mock_packets import make_tcp_packet
    from src.capture.packet_parser import parse_packet

    packets = []
    for index, port in enumerate(range(20, 30)):
        parsed = parse_packet(
            make_tcp_packet("10.0.0.5", "10.0.0.10", 40000 + index, port, "S")
        )
        if parsed is not None:
            packets.append(parsed)
    return packets


def _resolve_target(target: str) -> dict:
    target = target.strip()
    try:
        ipaddress.ip_address(target)
        return {"input": target, "ips": [target]}
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(target, None)
    except socket.gaierror as exc:
        raise HTTPException(400, f"Could not resolve target '{target}': {exc}")
    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise HTTPException(400, f"Target '{target}' resolved to no addresses")
    return {"input": target, "ips": ips}


def _relevant_events():
    if _sensor is None:
        return []
    events = _sensor.events()
    if not _target:
        return events
    ips = set(_target["ips"])
    return [
        e for e in events
        if getattr(e, "src_ip", None) in ips or getattr(e, "dst_ip", None) in ips
    ]


@router.post("/start")
def start(iface: Optional[str] = None, bpf_filter: Optional[str] = None,
          target: Optional[str] = None, demo: bool = False):
    global _sensor, _target
    if _sensor is not None and _sensor.status()["running"]:
        return {**_sensor.status(), "target": _target}
    resolved = _resolve_target(target) if target else None
    if resolved and not bpf_filter:
        bpf_filter = " or ".join(f"host {ip}" for ip in resolved["ips"])
    _sensor = LiveSensor(iface=iface, bpf_filter=bpf_filter)
    _target = (resolved if not demo else {
        "input": "CyberFlux detection-test replay",
        "ips": ["10.0.0.5", "10.0.0.10"],
        "mode": "demo_test_capture",
    })
    try:
        if demo:
            _sensor.start_replay(_demo_detection_packets())
        else:
            _sensor.start()
    except LiveSensorError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return {**_sensor.status(), "target": _target,
            "source": "demo_test_capture" if demo else "live"}


@router.post("/stop")
def stop():
    if _sensor is not None:
        _sensor.stop()
        return {**_sensor.status(), "target": _target}
    return _idle_status()


@router.get("/status")
def status():
    if _sensor is not None:
        return {**_sensor.status(), "target": _target}
    return _idle_status()


@router.get("/events")
def events(limit: int = 100):
    if _sensor is None:
        return {"source": "live", "events": []}
    items = _relevant_events()[-limit:]
    return {"source": "live", "events": [_to_dict(e) for e in items]}


@router.get("/analysis")
def analysis():
    if _sensor is None:
        return {"source": "live", "state": "not_started", "result": None,
                "message": "Live capture has not been started."}
    items = _relevant_events()
    if not items:
        return {"source": "live", "state": "no_relevant_traffic", "result": None,
                "target": _target,
                "message": "No relevant traffic captured yet. Nothing to assess."}
    from src.orchestrator import build_production_orchestrator
    try:
        orchestrator = build_production_orchestrator()
        result = orchestrator.analyze(items, input_source="live")
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        raise HTTPException(
            503,
            f"The real World Model is unavailable: {exc}",
        ) from exc
    except Exception as exc:
        raise HTTPException(500, f"Live analysis failed: {exc}")
    data = json.loads(result.model_dump_json())
    if data["attack_chains"]:
        state, message = "analyzed", "Suspicious activity observed in live traffic."
    else:
        state = "no_observed_threat"
        message = ("No observed threat in the traffic captured so far. "
                   "This does not guarantee the target is safe.")
    return {"source": "live", "state": state, "message": message,
            "target": _target, "result": data}
