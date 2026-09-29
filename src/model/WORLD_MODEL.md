# CyberFlux World Model

## Role in CyberFlux

The World Model forecasts future binary attack-window labels from a temporal
sequence. It complements current-window detection. It does not predict MITRE
techniques, attack-chain stages, or future feature vectors.

```text
CSV / PCAP → 30-second pair windows → recent sequence → GRU
          → K future attack scores → AnalysisResult.forecast → API/dashboard
```

The FastAPI analysis route uses `RealWorldModelProvider`. It does not silently
fall back to the mock provider. The mock remains available for tests and
explicit development use. No model training occurs during application startup.

## Existing real evaluation

The previously completed real CIC-IDS2017 run used 523,714 source/destination
windows, a five-window input sequence, and a three-window forecast horizon.
Training stopped after epoch 8 through early stopping. The validation-selected
threshold was 0.94. On the held-out test split, the recorded GRU metrics were:

| Metric | Test result |
| --- | ---: |
| Precision | 0.3333 |
| Recall | 0.0288 |
| F1 | 0.0530 |
| False-positive rate | 0.000569 |
| Accuracy | 0.98994 |
| ROC AUC | 0.6531 |
| Average precision | 0.0514 |
| Brier score | 0.01121 |
| True positive / false positive | 65 / 130 |
| False negative / true negative | 2,193 / 228,450 |

These are the previously reported run results, not a claim that inference has
been rerun from this checkout. Accuracy is affected by class imbalance. At
the selected threshold, recall is low. Treat scores as uncalibrated sigmoid
model scores; the project has not established probability calibration.

## Training input and temporal semantics

The training CSV is produced by `src/features/build_windows.py`, normally
`data/host_features_v2.csv`. It contains `src_ip`, `dst_ip`, `window_start`,
`is_attack_window`, and the 16 features ordered in `src/model/train.py`.
The target is `1` when that pair/window contains at least one non-BENIGN flow.

Partitions are chronological by distinct timestamps: 70% train, 15% validation,
15% test. Sequences are made independently within each partition. The
StandardScaler is fitted only on training rows; the saved mean and scale are
used unchanged during inference. The threshold is selected using validation
labels, not test labels.

Training groups rows by `(src_ip, dst_ip)`. `densify_pair_windows` inserts
zero-activity pair rows across gaps of up to five minutes to match the current
training representation. Longer gaps start a new segment. Source-wide
`unique_destinations` and `lateral_move_flag` values are carried into inserted
rows when available. The model uses the latest five consecutive 30-second
rows to predict the next three pair/window attack labels by default.

## Model artifact and deployment

Inference requires two adjacent files:

```text
world_model.pt
world_model_meta.json
```

The weights file contains the GRU `state_dict` and `model_config`. The metadata
file supplies the model configuration, exact ordered feature columns,
30-second window size, forecast threshold, normalization type/mean/scale,
training sequence length/horizon, and score interpretation. The loader checks
that the checkpoint configuration matches metadata and that feature order
matches the current Phase 1 schema. The metadata is required; weights alone
are insufficient.

Model artifacts are intentionally excluded from Git. Put the pair in
`models/world_model/` to use the default, repository-relative location:

```text
models/world_model/world_model.pt
models/world_model/world_model_meta.json
```

For deployment or another location, set `CYBERFLUX_WORLD_MODEL_PATH` to the
absolute path of `world_model.pt`. Keep `world_model_meta.json` beside it. The
default is resolved relative to the repository, not the process working
directory. If either file or the PyTorch dependency is missing, the production
API returns HTTP 503 with the setup error; it does not train another model or
substitute mock forecasts.

Install the pinned optional GRU dependencies from the repository root:

```bash
python -m pip install -r requirements-world-model.txt
```

The pinned stack was tested with Python 3.9.6; the file documents Python
3.9–3.12 as supported for those pins. Training still requires the real feature
CSV. Application startup only loads the supplied artifact.

To create artifacts from the CSV:

```bash
python -m src.model.train_world_model --input data/host_features_v2.csv
```

The default output directory is `models/world_model/`. Training produces
`world_model.pt`, `world_model_meta.json`, and `world_model_metrics.json`.

## Provider input and output contract

`RealWorldModelProvider.forecast` receives `context["recent_windows"]` as a
Pandas DataFrame (or rows convertible to one). It needs:

- `window_start`, parseable timestamps aligned to 30-second window starts;
- all 16 Phase 1 feature columns; order in the input frame can vary because
  the provider selects the saved training order;
- `src_ip` and `dst_ip` to select and group the newest pair sequence. If the
  input is already a selected sequence, those two columns may be omitted.
- `lateral_move_flag` can be omitted only when `unique_destinations` exists;
  it is then derived using the existing `unique_destinations > 5` rule.

At least five consecutive windows for one pair are needed for the default
trained model. For pair-grouped input, short gaps are densified with the same
five-minute policy as training. The provider picks the newest valid pair
sequence. It never fits a scaler from request data. It performs inference with
the saved StandardScaler parameters and returns one result per requested
future step.

The API forecast has the legacy fields `predicted_stage`, `confidence`, and
`probable_next_stages` for wire compatibility, plus explicit GRU fields:

```json
{
  "forecast_kind": "attack_probability",
  "forecast_status": "ready",
  "forecast_horizon_steps": 3,
  "future_attack_probabilities": [
    {
      "step": 1,
      "window_start": "2025-01-01T00:02:30+00:00",
      "probability": 0.18,
      "threshold": 0.94,
      "predicted_attack": false
    }
  ],
  "probability_note": "Sigmoid scores; calibration has not been established."
}
```

The example values are illustrative, not model output. `confidence` is a
legacy alias for the maximum score among future steps and is also uncalibrated.
`predicted_stage` is the compatibility string `Future attack probability`;
the GRU does not emit an attack stage. For insufficient history, the response
uses `forecast_status: "insufficient_history"`, has no future scores, sets
confidence to `null`, and includes a warning. The orchestrator copies that
warning into `AnalysisResult.warnings`.

## API usage

The production entry point is `POST /api/analyze` with a CSV, PCAP, or PCAPNG
upload. It constructs the production orchestrator, whose forecast provider is
the real model. For CSV, the original window rows are also passed to the
forecast provider; detections alone are not enough because the detector only
emits suspicious rows. For PCAP, the processing pipeline retains generated
window feature rows as they become available and supplies the latest pair
sequences when analysis is assembled.

The chain is:

```text
World Model → AnalysisOrchestrator → AnalysisResult → FastAPI → dashboard
```

No frontend code calls the model directly. Unit tests may still instantiate
`AnalysisOrchestrator()` to get deterministic mocks.

## Baseline comparison

The comparison command evaluates the GRU and the temporal logistic-regression
baseline using the same chronological partitions and future targets. The GRU
uses a sequence; the baseline uses the latest window's features. Each model's
threshold is selected from validation data. Synthetic test metrics are only
smoke-test results and are not CyberFlux performance results.

```bash
python -m src.evaluate.compare_world_model \
  --input data/host_features_v2.csv \
  --model models/world_model/world_model.pt \
  --out models/world_model/world_model_vs_logreg.json
```

## Tests and known boundaries

Run the World Model tests with its optional requirements installed:

```bash
python -m pytest tests/test_sequence_builder.py tests/test_world_model.py \
  tests/test_world_model_training.py tests/test_forecast_world_model.py \
  tests/test_world_model_comparison.py tests/test_real_world_model_provider.py -q
```

The tests use small temporary/synthetic checkpoints; those are not the saved
CIC-IDS2017 model and their metrics must not be reported as project results.
The actual model artifact is not stored in this repository and must be
supplied separately at deployment. Forecasting is binary and pair-specific;
the model does not predict attack family, MITRE technique, or attack-chain
stage.
