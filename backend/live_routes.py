"""Live sensor API. Only live capture; never falls back to dataset data."""
from dataclasses import asdict, is_dataclass
from typing import Optional

from fastapi import APIRouter, HTTPException

from src.live.sensor import LiveSensor, LiveSensorError

router = APIRouter(prefix="/api/live", tags=["live"])
_sensor: Optional[LiveSensor] = None


def _to_dict(event):
    return asdict(event) if is_dataclass(event) else dict(vars(event))


def _idle_status():
    return {"running": False, "error": None, "packets_seen": 0,
            "events_buffered": 0, "source": "live"}


@router.post("/start")
def start(iface: Optional[str] = None, bpf_filter: Optional[str] = None):
    global _sensor
    if _sensor is not None and _sensor.status()["running"]:
        return _sensor.status()
    _sensor = LiveSensor(iface=iface, bpf_filter=bpf_filter)
    try:
        _sensor.start()
    except LiveSensorError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return _sensor.status()


@router.post("/stop")
def stop():
    if _sensor is not None:
        _sensor.stop()
        return _sensor.status()
    return _idle_status()


@router.get("/status")
def status():
    return _sensor.status() if _sensor is not None else _idle_status()


@router.get("/events")
def events(limit: int = 100):
    if _sensor is None:
        return {"source": "live", "events": []}
    items = _sensor.events()[-limit:]
    return {"source": "live", "events": [_to_dict(e) for e in items]}