# POST /api/analyze

Upload a network capture or a flow CSV and get one `AnalysisResult` back: detections, attack chains, forecast, MITRE mapping, explanation and risk.

Implemented in `backend/analysis_routes.py`. The route is mounted from `backend/app.py`.

## Request

- Method and path: `POST /api/analyze`
- Body: `multipart/form-data` with one field named `file`
- Accepted extensions: `.csv`, `.pcap`, `.pcapng`
- Maximum size: 100 MB
- `.cap` is not accepted here (the separate `/api/pcap/parse` route accepts it, but it only parses).

The upload is saved to a temporary folder under its original file name and removed afterwards, so `input_source` reads like `pcap:scan.pcap` or `csv:flows.csv`.

Example (not run as part of writing this doc):

```powershell
curl.exe -F "file=@C:\path\to\scan.pcap" http://localhost:8000/api/analyze
```

## Responses

| Status | When |
|--------|------|
| 200 | Analysis finished. Body is the `AnalysisResult` JSON below. |
| 400 | The file is empty, or analysis raised `PcapReadError` (corrupt capture) or `ValueError` (for example a CSV with missing columns or no valid rows). The message is in `detail`. |
| 413 | The file is larger than 100 MB. |
| 415 | The extension is not `.csv`, `.pcap` or `.pcapng`. |

A request with no `file` field is rejected by FastAPI's own validation, not by this route.

## Response fields (`AnalysisResult`)

| Field | Meaning |
|-------|---------|
| `analysis_id` | Random id per call. |
| `timestamp` | Unix seconds when the analysis ran. |
| `input_source` | `pcap:<name>` or `csv:<name>`. |
| `detections` | List of detection events (see below). |
| `attack_chains` | List of correlated chains (see below). |
| `forecast` | Predicted next stage, `confidence`, `probable_next_stages`, `time_window_seconds`, `source`. |
| `mitre` | List of technique mappings, each with `source`. |
| `explanation` | Summary and top features, with `source`. |
| `risk` | `risk_score` (0-100) and `severity` (derived from the score), with `source`. |
| `warnings` | A provider that fails is left `null` and reported here instead of failing the call. |

Every stage result carries `source: "real" | "mock"`.

### Detection events

Each item in `detections` has `event_id`, `detection_type`, `src_ip`, `dst_ip`, `timestamp`, `window_start`, `window_end`, `confidence`, `evidence`, `features` and `metadata`.

For `.pcap` and `.pcapng` uploads, each event's `metadata` also has either:

- `ml_score`: `anomaly_risk`, `anomaly_score`, `anomaly_score_raw`, `event_id`, `explanation`
- `ml_score_error`: the error text, when scoring that event failed. Other events are still scored.

CSV uploads are not scored this way.

### Attack chains

Each item in `attack_chains` includes `chain_id`, `source_hosts`, `destination_hosts`, `start_time`, `last_seen`, `stages`, `current_stage`, `confidence` and `events`.

## Known limitations

- **Mock providers.** `run_analysis` uses the mock forecast, MITRE, explanation and risk providers (`source: "mock"`). The real world model needs `models/world_model/world_model.pt`, which is not in the repo. With zero detections the mock risk still reports 40 (medium).
- **Mock output is not stable.** Two runs on the same file can return a different `forecast` and `risk`.
- **Ids and same-time ordering vary.** Event ids are random (`uuid4`), so `chain_id` and the order of same-timestamp events inside a chain can differ between runs.
- **PCAP ML scores are unvalidated.** The model was trained on CSV flow features. Treat `ml_score` on captures as unvalidated until checked on real traffic.
- **CSV coverage.** The CSV adapter reliably reaches only the lateral-movement rule.
- **No real-capture run yet.** PCAP behavior has been tested on synthetic captures only.

## Running it

Backend (from the `backend/` folder):

```powershell
python -m uvicorn app:app --port 8000
```

Frontend (from the `frontend/` folder):

```powershell
npm run dev
```

The upload page is at `/analyze` on the URL that `npm run dev` prints. It calls `http://localhost:8000`. Backend CORS allows all origins.

## Tests

- `tests/test_analyze_api.py`: upload, reject and error cases
- `tests/test_run_analysis.py`: `run_analysis` on CSV and PCAP
- `tests/test_golden_analysis.py`: golden-file check of the scan capture. It masks mock forecast/risk, sorts same-timestamp chain events and ignores `chain_id`. Re-record it (`UPDATE_GOLDEN=1`, one run, then unset) when the model file or detection rules change.