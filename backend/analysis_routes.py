"""Analysis API: upload a CSV or PCAP and run the full attack-chain analysis."""

from __future__ import annotations

import sys
import tempfile
from functools import lru_cache
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, Response, UploadFile
from fastapi.concurrency import run_in_threadpool

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


router = APIRouter()

MAX_UPLOAD_BYTES = 100 * 1024 * 1024
ANALYSIS_SUFFIXES = {".csv", ".pcap", ".pcapng"}


@lru_cache(maxsize=1)
def _production_orchestrator():
    """Load the real World Model once per API worker; never use a mock here."""
    from src.orchestrator import create_production_orchestrator

    return create_production_orchestrator()


@router.post("/api/analyze")
async def analyze_upload(file: UploadFile = File(...)):
    from src.ingestion.pcap_reader import PcapReadError  # noqa: E402
    from src.orchestrator import run_analysis  # noqa: E402

    filename = Path(file.filename or "upload").name
    suffix = Path(filename).suffix.lower()
    if suffix not in ANALYSIS_SUFFIXES:
        await file.close()
        raise HTTPException(415, "Upload a .csv, .pcap, or .pcapng file")

    try:
        # Temp dir is created and removed by this code only; the upload keeps
        # its original name so input_source reads e.g. "pcap:scan.pcap".
        with tempfile.TemporaryDirectory(prefix="cyberflux-analyze-") as temp_dir:
            temp_path = Path(temp_dir) / filename
            size = 0
            with temp_path.open("wb") as out:
                while chunk := await file.read(1024 * 1024):
                    size += len(chunk)
                    if size > MAX_UPLOAD_BYTES:
                        raise HTTPException(413, "File exceeds the 100 MB upload limit")
                    out.write(chunk)
            if size == 0:
                raise HTTPException(400, "The uploaded file is empty")
            try:
                orchestrator = _production_orchestrator()
            except (FileNotFoundError, RuntimeError, ValueError) as exc:
                raise HTTPException(
                    503,
                    "The real World Model is unavailable. Install its dependencies "
                    "and supply the trained weights plus adjacent metadata: "
                    f"{exc}",
                ) from exc
            try:
                result = await run_in_threadpool(
                    run_analysis, temp_path, orchestrator
                )
            except (PcapReadError, ValueError) as exc:
                raise HTTPException(400, str(exc)) from exc
    finally:
        await file.close()

    return Response(content=result.model_dump_json(), media_type="application/json")
