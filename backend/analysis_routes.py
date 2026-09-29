"""Analysis API: upload a CSV or PCAP and run the full attack-chain analysis."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, Response, UploadFile
from fastapi.concurrency import run_in_threadpool

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


router = APIRouter()

MAX_UPLOAD_BYTES = 100 * 1024 * 1024
ANALYSIS_SUFFIXES = {".csv", ".pcap", ".pcapng"}


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
        with tempfile.TemporaryDirectory(
            prefix="cyberflux-analyze-", ignore_cleanup_errors=True
        ) as temp_dir:
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
                result = await run_in_threadpool(run_analysis, temp_path)
            except (PcapReadError, ValueError) as exc:
                raise HTTPException(400, str(exc)) from exc
            except Exception as exc:
                raise HTTPException(500, f"Analysis failed: {type(exc).__name__}: {exc}") from exc
    finally:
        await file.close()

    return Response(content=result.model_dump_json(), media_type="application/json")