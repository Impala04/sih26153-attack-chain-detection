"""Local, perturbation-based explanations for numeric model inputs."""

from __future__ import annotations

from math import isfinite
from typing import Any, Callable, Mapping, Sequence


def _unavailable(reason: str, prediction: Any = None) -> dict[str, Any]:
    return {"status": "unavailable", "reason": reason, "prediction": prediction, "top_features": []}


def _score(model: Any, row: list[float], score_fn: Callable | None) -> float:
    if score_fn is not None:
        value = score_fn(model, row)
    elif callable(getattr(model, "decision_function", None)):
        # IsolationForest decision_function is higher for normal observations;
        # invert it so positive attribution means greater anomaly/risk.
        value = -float(model.decision_function([row])[0])
    elif callable(getattr(model, "score_samples", None)):
        value = -float(model.score_samples([row])[0])
    elif callable(getattr(model, "predict_proba", None)):
        probabilities = model.predict_proba([row])[0]
        classes = list(getattr(model, "classes_", range(len(probabilities))))
        positive = next((i for i, label in enumerate(classes) if label in (1, True, "1", "positive", "anomaly")), None)
        if positive is None:
            raise ValueError("model has no identifiable positive class")
        value = float(probabilities[positive])
    else:
        raise ValueError("model exposes no defensible numeric score method")
    result = float(value)
    if not isfinite(result):
        raise ValueError("model returned a non-finite score")
    return result


def explain_prediction(
    model: Any,
    features: Mapping[str, Any] | Sequence[float],
    prediction: Any = None,
    top_k: int = 5,
    *,
    baseline: Mapping[str, float] | Sequence[float] | None = None,
    feature_names: Sequence[str] | None = None,
    native_attributions: Mapping[str, float] | None = None,
    native_attributions_are_signed: bool = True,
    score_fn: Callable | None = None,
) -> dict[str, Any]:
    """Explain one prediction using supplied native attributions or ablation.

    Ablation compares the observed model score against each feature replaced by
    an explicit reference/baseline. For IsolationForest the score is
    ``-decision_function`` so positive contributions increase anomaly score.
    Other models must pass ``score_fn(model, row)`` with higher values meaning
    greater risk. Batch/global SHAP computations are intentionally omitted.
    """
    if top_k < 0:
        raise ValueError("top_k cannot be negative")
    mapping_input = isinstance(features, Mapping)
    if mapping_input:
        names = list(features.keys())
        try:
            row = [float(features[name]) for name in names]
        except (TypeError, ValueError):
            return _unavailable("features must contain finite numeric values", prediction)
    else:
        row = list(map(float, features))
        names = list(feature_names or [f"feature_{i}" for i in range(len(row))])
    if len(names) != len(row) or not all(isfinite(x) for x in row):
        return _unavailable("feature names and finite numeric feature values are required", prediction)
    if native_attributions is not None:
        if not all(isinstance(v, (int, float)) and isfinite(float(v)) for v in native_attributions.values()):
            return _unavailable("native attributions must be finite numeric values", prediction)
        ranked = [
            {"feature": name, "contribution": float(value), "direction": ("increases_risk" if value > 0 else "decreases_risk" if value < 0 else "neutral") if native_attributions_are_signed else "unknown", "value": features.get(name) if mapping_input else row[names.index(name)] if name in names else None}
            for name, value in native_attributions.items()
        ]
        ranked.sort(key=lambda item: (-abs(item["contribution"]), item["feature"]))
        return {"status": "available", "prediction": prediction, "method": "model_native_attribution", "top_features": ranked[:top_k]}
    if baseline is None:
        return _unavailable("perturbation explanation requires an explicit reference baseline", prediction)
    try:
        base = [float(baseline[name]) for name in names] if isinstance(baseline, Mapping) else list(map(float, baseline))
        if len(base) != len(row) or not all(isfinite(x) for x in base):
            return _unavailable("baseline must provide one finite numeric value per feature", prediction)
        original_score = _score(model, row, score_fn)
        attributions = []
        for index, name in enumerate(names):
            ablated = list(row)
            ablated[index] = base[index]
            score_delta = original_score - _score(model, ablated, score_fn)
            attributions.append({
                "feature": name,
                "contribution": score_delta,
                "direction": "increases_risk" if score_delta > 0 else "decreases_risk" if score_delta < 0 else "neutral",
                "value": row[index],
            })
        attributions.sort(key=lambda item: (-abs(item["contribution"]), item["feature"]))
        return {
            "status": "available",
            "prediction": prediction if prediction is not None else original_score,
            "method": "single_feature_ablation",
            "score_semantics": "higher_is_more_anomalous_or_risky",
            "baseline": dict(zip(names, base)),
            "top_features": attributions[:top_k],
        }
    except (TypeError, ValueError, AttributeError, IndexError, KeyError) as exc:
        return _unavailable(str(exc), prediction)
