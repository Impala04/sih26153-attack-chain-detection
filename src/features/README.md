# Packet features and explainability

`src.features.packet_features.packet_features(packets) -> dict` accepts an iterable of `ParsedPacket` (or mapping records) and returns `{"packet": {...}}`. Features include population mean/variance/min/max and sample counts for valid IPv4 TTLs, TCP windows, transport payload byte sizes, and timestamp-sorted nonnegative IATs; fragmentation count/ratio; retransmission count/status; unique destination port count/diversity; and sequential/randomness signals. Missing measurements are `null` with a zero sample count where applicable. Empty/unsupported fragmentation and unavailable retransmission data are explicitly represented.

IAT sorts finite packet timestamps and retains equal timestamps (zero interval). TTL uses only 1..255 IPv4 TTL values; this parser currently normalizes IPv4 only. Payload size is the bytes after TCP/UDP/ICMP headers, not total packet length. Variances use population variance. Retransmissions count repeated positive-payload TCP sequence ranges in the same directional 4-tuple (SYN sequence adjustment included); duplicates in a capture cannot be distinguished from network retransmission. Port scan features group destination-port observations by source/destination IP: sequential score is the fraction of adjacent distinct observed ports differing by one; randomness is normalized Shannon entropy multiplied by one minus the sequential score. These are descriptive signals, not scan verdicts.

## Explainability integration contract

`src.explainability.explain_prediction(model, features, prediction=None, top_k=5, *, baseline=None, feature_names=None, native_attributions=None, score_fn=None) -> dict` accepts a mapping or ordered numeric vector. It returns status, prediction/context, method, and sorted numeric contributions with direction and raw value. Supply native per-prediction attributions for a World Model. Set `native_attributions_are_signed=False` for unsigned attention weights, whose direction cannot be inferred. For local ablation, supply a one-value-per-feature reference baseline. IsolationForest's `decision_function` is inverted so higher explanation scores mean more anomalous. For another model, pass `score_fn(model, row)` with higher scores meaning greater risk. Missing baseline/score methods return `status="unavailable"`; invalid `top_k` raises `ValueError`.

`score_dataframe(df, model_path=..., explain_limit=0, explanation_top_k=5)` can explain only the first requested rows using numeric feature medians stored when training. Set a small `explain_limit`; `explanation` is JSON text for those rows and null for the rest. Retrain an older model to store `reference_features`.

Example:

```python
from src.features.packet_features import packet_features
from src.explainability import explain_prediction
packet_result = packet_features(parsed_packets)
explanation = explain_prediction(model, model_features, prediction=0.78,
                                 baseline=training_medians, top_k=5)
```


## Joshua's integration details

### Packet feature API

- **Input:** an iterable of normalized `ParsedPacket` instances (or equivalent mapping objects); no Scapy packet is required.
- **Output:** JSON-safe `dict` shaped as `{"packet": {feature_name: value}}`. Numeric fields are integers/floats, unknown measurements use `None`, and counts/status fields explain coverage.
- **Exceptions:** input must be iterable; malformed individual records are counted and skipped where possible. A non-iterable input raises Python's `TypeError`.
- **Dependencies:** Python standard library and the existing `ParsedPacket` schema. Scapy is only required upstream by capture parsing.
- **Example:**

```python
from src.features.packet_features import packet_features
packet_result = packet_features(parsed_packets)
packet_row = packet_result["packet"]
```

### Explanation API

- **Input:** model, one feature mapping or ordered vector, optional actual prediction, `top_k`, and either a reference baseline or native per-prediction attributions. Other models can pass `score_fn(model, row)`; higher score must mean higher risk.
- **Output:** JSON-safe dictionary with `status`, prediction/model context, method, and ranked `top_features` containing feature, numeric contribution, direction, and observed value. World Model attention without signed risk attribution should pass `native_attributions_are_signed=False`; direction is then `unknown`.
- **Exceptions:** negative `top_k` raises `ValueError`; absent/unsupported scores, baselines, or invalid numeric data return `status="unavailable"` with a reason.
- **Dependencies:** Python standard library. Isolation Forest methods are consumed through its model API; no SHAP dependency is required.
- **Example:**

```python
explanation = explain_prediction(
    model, feature_row, prediction=model_output, baseline=training_medians, top_k=5
)
```

`score_dataframe` additionally requires the existing pandas/joblib/IsolationForest runtime. It takes a dataframe using the stored model feature columns and explains up to `explain_limit` leading rows; output JSON explanations are in the `explanation` column.
