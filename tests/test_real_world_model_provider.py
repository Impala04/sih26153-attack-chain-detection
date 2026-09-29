"""Production GRU provider and orchestrator integration checks."""

import json
from datetime import datetime, timedelta, timezone

import pandas as pd
import pytest

torch = pytest.importorskip("torch")

from src.model.train import FEATURE_COLS
from src.model.world_model import GRUWorldModel
from src.orchestrator import (
    AnalysisOrchestrator,
    create_production_orchestrator,
    run_analysis,
)
from src.processing.events import DetectionEvent
from src.providers.world_model_provider import RealWorldModelProvider


MODEL_CONFIG = {
    "feature_count": len(FEATURE_COLS),
    "sequence_length": 5,
    "forecast_horizon": 3,
    "hidden_size": 4,
    "num_layers": 1,
    "dropout": 0.0,
}


def _write_artifact(directory):
    weights = directory / "world_model.pt"
    metadata = {
        "model_type": "GRUWorldModel",
        "feature_columns": list(FEATURE_COLS),
        "group_columns": ["src_ip", "dst_ip"],
        "window_seconds": 30,
        "model_config": MODEL_CONFIG,
        "threshold": 0.94,
        "normalization": {
            "type": "StandardScaler",
            "mean": [0.0] * len(FEATURE_COLS),
            "scale": [1.0] * len(FEATURE_COLS),
        },
        "probability_note": "Sigmoid scores; calibration has not been established.",
    }
    torch.manual_seed(17)
    model = GRUWorldModel(**MODEL_CONFIG)
    torch.save(
        {"state_dict": model.state_dict(), "model_config": MODEL_CONFIG},
        weights,
    )
    weights.with_name("world_model_meta.json").write_text(json.dumps(metadata))
    return weights


def _windows(count=5, start=None):
    start = start or datetime(2025, 1, 1, tzinfo=timezone.utc)
    rows = []
    for index in range(count):
        row = {column: float(index + 1) for column in FEATURE_COLS}
        row.update(
            {
                "src_ip": "192.0.2.10",
                "dst_ip": "198.51.100.20",
                "window_start": start + timedelta(seconds=30 * index),
                "is_attack_window": 0,
            }
        )
        rows.append(row)
    return pd.DataFrame(rows)


def _event():
    return DetectionEvent(
        event_id="evt-world-model",
        timestamp=1735689720.0,
        window_start=1735689690.0,
        window_end=1735689720.0,
        src_ip="192.0.2.10",
        dst_ip="198.51.100.20",
        detection_type="suspicious_traffic",
        confidence=0.8,
        features={"connection_count": 3},
        evidence=["synthetic integration fixture"],
    )


def test_real_provider_loads_artifact_and_returns_deterministic_json_scores(tmp_path):
    weights = _write_artifact(tmp_path)
    provider = RealWorldModelProvider(weights)
    context = {"recent_windows": _windows()}

    result = provider.forecast(context)
    repeated = provider.forecast(context)

    assert result.source == "real"
    assert result.forecast_kind == "attack_probability"
    assert result.forecast_status == "ready"
    assert result.forecast_horizon_steps == 3
    assert [item.step for item in result.future_attack_probabilities] == [1, 2, 3]
    assert result.future_attack_probabilities == repeated.future_attack_probabilities
    assert result.probable_next_stages == []
    assert "calibration has not been established" in result.probability_note
    json.dumps(result.model_dump(mode="json"))


def test_provider_reports_insufficient_or_nonconsecutive_history_without_scores(tmp_path):
    provider = RealWorldModelProvider(_write_artifact(tmp_path))

    short = provider.forecast({"recent_windows": _windows(4)})
    gapped_windows = _windows()
    # A 330-second gap exceeds the five-minute densification limit used in
    # training and therefore leaves fewer than five rows in either segment.
    gapped_windows.loc[4, "window_start"] += timedelta(seconds=300)
    gapped = provider.forecast({"recent_windows": gapped_windows})

    for result in (short, gapped):
        assert result.forecast_kind == "attack_probability"
        assert result.forecast_status == "insufficient_history"
        assert result.future_attack_probabilities == []
        assert result.confidence is None
        assert result.warning


def test_real_provider_requires_weights_and_adjacent_metadata(tmp_path):
    with pytest.raises(FileNotFoundError, match="World Model weights not found"):
        RealWorldModelProvider(tmp_path / "missing.pt")

    weights = _write_artifact(tmp_path)
    weights.with_name("world_model_meta.json").unlink()
    with pytest.raises(FileNotFoundError, match="World Model metadata not found"):
        RealWorldModelProvider(weights)


def test_production_orchestrator_keeps_real_forecast_in_analysis_result(tmp_path):
    weights = _write_artifact(tmp_path)
    orchestrator = create_production_orchestrator(weights)
    assert isinstance(orchestrator.world_model_provider, RealWorldModelProvider)

    result = orchestrator.analyze(
        [_event()],
        input_source="integration-test",
        recent_windows=_windows(),
    )

    assert result.forecast is not None
    assert result.forecast.source == "real"
    assert result.forecast.forecast_kind == "attack_probability"
    assert len(result.forecast.future_attack_probabilities) == 3
    payload = json.loads(result.model_dump_json())
    assert payload["forecast"]["future_attack_probabilities"][0]["step"] == 1


def test_csv_analysis_passes_window_rows_to_real_provider(tmp_path):
    weights = _write_artifact(tmp_path)
    csv_path = tmp_path / "windows.csv"
    _windows().to_csv(csv_path, index=False)

    result = run_analysis(csv_path, create_production_orchestrator(weights))

    assert result.forecast is not None
    assert result.forecast.source == "real"
    assert result.forecast.forecast_kind == "attack_probability"
    assert result.forecast.forecast_status == "ready"
    assert len(result.forecast.future_attack_probabilities) == 3


def test_real_forecast_insufficient_history_is_visible_as_analysis_warning(tmp_path):
    orchestrator = AnalysisOrchestrator(
        world_model_provider=RealWorldModelProvider(_write_artifact(tmp_path))
    )

    result = orchestrator.analyze(
        [_event()], input_source="integration-test", recent_windows=_windows(2)
    )

    assert result.forecast.forecast_status == "insufficient_history"
    assert result.forecast.future_attack_probabilities == []
    assert any("requires 5" in warning for warning in result.warnings)
