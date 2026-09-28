import json

import pytest
pd = pytest.importorskip("pandas")

from src.model import score


class DummyIsolationModel:
    def predict(self, frame):
        return [-1 if value > 2 else 1 for value in frame["signal"]]

    def decision_function(self, rows):
        values = rows["signal"] if hasattr(rows, "columns") else [row[0] for row in rows]
        return [1.0 - float(value) for value in values]


def setup_model(monkeypatch):
    model = DummyIsolationModel()
    monkeypatch.setattr(score, "load_model_and_features", lambda _path: (model, ["signal"]))
    return model


def test_score_dataframe_explains_only_requested_rows(monkeypatch, tmp_path):
    setup_model(monkeypatch)
    model_path = tmp_path / "model.joblib"
    model_path.with_suffix(".meta.json").write_text(
        json.dumps({"reference_features": {"signal": 0}}), encoding="utf-8"
    )
    frame = pd.DataFrame({"signal": [3.0, 1.0], "lateral_move_flag": [0, 0]})
    scored = score.score_dataframe(frame, str(model_path), explain_limit=1, explanation_top_k=1)
    result = json.loads(scored.iloc[0]["explanation"])
    assert result["status"] == "available"
    assert result["method"] == "single_feature_ablation"
    assert result["top_features"][0]["feature"] == "signal"
    assert scored.iloc[1]["explanation"] is None


def test_scoring_without_explainability_matches_existing_model_path(monkeypatch):
    model = setup_model(monkeypatch)
    monkeypatch.setattr(
        score,
        "explain_prediction",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("explainer called")),
    )
    frame = pd.DataFrame({"signal": [3.0, 1.0], "lateral_move_flag": [0, 0]})
    scored = score.score_dataframe(frame, model_path="missing-model.json", explain_limit=0)

    expected_anomaly = model.predict(frame[["signal"]])
    expected_raw = model.decision_function(frame[["signal"]])
    assert scored["anomaly_score"].tolist() == expected_anomaly
    assert scored["anomaly_score_raw"].tolist() == expected_raw
    assert scored["anomaly_risk"].tolist() == [100.0, 0.0]
    assert scored["explanation"].isna().all()
