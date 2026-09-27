# CyberFlux World Model

## Purpose

The World Model forecasts future attack-containing network windows from a
sequence of historical 30-second windows. It complements the current-window
Isolation Forest detector; it does not replace it.

```text
30-second window features
        ↓
chronological sequence for one source-destination pair
        ↓
GRU
        ↓
attack probabilities for the next K windows
```

The model directly predicts the future attack labels for steps `t+1` through
`t+K`. It does not predict a full future feature vector and feed it back into
itself.

## Input data contract

Use the output of `src/features/build_windows.py`, normally
`data/host_features_v2.csv`. Required columns are:

- `src_ip`
- `dst_ip`
- `window_start`
- `is_attack_window`
- the 16 Phase 1 feature columns in the order defined by
  `src/model/train.py`

The target is `is_attack_window`: `1` means that the corresponding CIC window
contains at least one non-BENIGN flow; `0` means it contains only BENIGN flows.

Rows are grouped into sequences by `(src_ip, dst_ip)`. A sequence only uses
consecutive windows at the configured interval (30 seconds by default).
Sequences spanning gaps are skipped; the builder does not invent zero-valued
windows.

## Leakage prevention and normalization

The data is split chronologically by distinct `window_start` timestamps:

- first 70%: training
- next 15%: validation
- final 15%: test

Rows sharing a timestamp stay in the same partition. Sequences are built
independently within each partition, so no sequence crosses a split boundary.
The `StandardScaler` is fitted on training rows only and its mean and scale
are saved with the model for inference.

The forecast threshold is selected using validation labels only. Test labels
are used only for final metrics.

## Model

`GRUWorldModel` is a compact CPU-compatible PyTorch GRU. Default configuration:

- input features: 16
- sequence length: 5 windows
- forecast horizon: 3 windows
- hidden size: 32
- layers: 1
- dropout: 0.1

The horizon is selected when training. Inference can request a shorter horizon
than the trained horizon, but cannot request a longer one.

The model produces one sigmoid score per future step. These are model scores;
they are **not claimed to be calibrated probabilities**. Brier score is
reported as a probability-quality diagnostic.

## Install dependencies

From the repository root:

```bash
python -m pip install -r requirements-world-model.txt
```

## Train

Training requires the real window-feature CSV. It has not been run or evaluated
on real CIC data yet.

From the repository root:

```bash
python -m src.model.train_world_model --input data/host_features_v2.csv
```

The defaults write these local artifacts:

```text
models/world_model/world_model.pt
models/world_model/world_model_meta.json
models/world_model/world_model_metrics.json
```

You can change the training configuration with command-line options. For
example:

```bash
python -m src.model.train_world_model \
  --input data/host_features_v2.csv \
  --sequence-length 5 \
  --forecast-horizon 3 \
  --hidden-size 32 \
  --epochs 50 \
  --seed 42
```

Training prints validation loss while it runs. The metrics JSON records
validation-selected threshold, test precision, recall, F1, false-positive rate,
accuracy, ROC-AUC when defined, average precision when defined, and Brier
score. These metrics must only be reported after training on the real dataset.

## Compare with Logistic Regression

The existing `src/evaluate/compare_baseline.py` evaluates current-window
detection with a random split. It is not the future-forecasting baseline.

The World Model comparison uses chronological partitions and the same future
targets for both models. The GRU uses all historical windows in a sequence;
the Logistic Regression baseline uses only the latest window's 16 features.

After training, run:

```bash
python -m src.evaluate.compare_world_model \
  --input data/host_features_v2.csv \
  --model models/world_model/world_model.pt \
  --out models/world_model/world_model_vs_logreg.json
```

The comparison reports combined and per-horizon test metrics. Each model's
threshold is chosen from validation data, not from the test set.

## Inference

Provide exactly the configured number of consecutive historical windows for
one `(src_ip, dst_ip)` pair. The DataFrame must contain `window_start` and all
16 features. The forecaster applies the saved normalization parameters.

Example:

```python
import pandas as pd

from src.model.forecast_world_model import load_world_model

all_windows = pd.read_csv("data/host_features_v2.csv")
pair_windows = all_windows[
    (all_windows["src_ip"] == "192.168.10.5")
    & (all_windows["dst_ip"] == "192.168.10.3")
].sort_values("window_start")

forecaster = load_world_model("models/world_model/world_model.pt")
result = forecaster.forecast(pair_windows.tail(5), horizon=3)
print(result.to_dict())
```

The output contains the current window, each future window timestamp, its
forecast score, the saved threshold, and the thresholded attack prediction.
It is JSON-serializable through `result.to_dict()`.

## Tests

Run the World Model tests:

```bash
python -m pytest \
  tests/test_sequence_builder.py \
  tests/test_world_model.py \
  tests/test_world_model_training.py \
  tests/test_forecast_world_model.py \
  tests/test_world_model_comparison.py \
  -q
```

The training and comparison tests use synthetic data only. They verify the
code path and saved artifacts; their metrics are not CyberFlux performance
results.

## Limitations

- Real CIC-IDS2017 training and evaluation remain pending until the feature CSV
  is available.
- Forecast targets are pair-specific because the source feature builder
  groups by `(src_ip, dst_ip, window_start)`.
- A missing pair window breaks a sequence. The model does not currently
  forecast activity for a pair that has no consecutive history.
- Attack prediction is binary. The model does not predict attack family,
  MITRE technique, or attack-chain stage.
- Sigmoid outputs are not calibrated probabilities.
- The Logistic Regression comparator is a non-temporal baseline using the
  latest input window.