from src.explainability import explain_prediction


class LinearRiskModel:
    def decision_function(self, rows):
        return [10.0 - 2.0 * row[0] - row[1] for row in rows]


def test_ablation_explanation_is_numeric_ordered_and_top_k():
    result = explain_prediction(
        LinearRiskModel(), {"strong": 4.0, "weak": 2.0}, prediction=0.8,
        baseline={"strong": 0.0, "weak": 0.0}, top_k=1,
    )
    assert result["status"] == "available"
    assert result["method"] == "single_feature_ablation"
    assert result["prediction"] == 0.8
    assert result["top_features"][0]["feature"] == "strong"
    assert result["top_features"][0]["contribution"] == 8.0
    assert result["top_features"][0]["direction"] == "increases_risk"
    assert isinstance(result["top_features"][0]["contribution"], float)


def test_native_attributions_are_consumed_without_fabrication():
    result = explain_prediction(None, {"x": 3}, prediction="stage-2", top_k=1,
                                native_attributions={"x": -0.25})
    assert result["status"] == "available"
    assert result["top_features"][0]["direction"] == "decreases_risk"
    assert result["top_features"][0]["contribution"] == -0.25
    unsigned = explain_prediction(None, {"x": 3}, native_attributions={"x": 0.7},
                                    native_attributions_are_signed=False)
    assert unsigned["top_features"][0]["direction"] == "unknown"


def test_unavailable_model_and_missing_baseline_are_explicit():
    assert explain_prediction(object(), {"x": 1}, prediction=0.5)["status"] == "unavailable"
    assert explain_prediction(object(), {"x": 1}, baseline={"x": 0})["status"] == "unavailable"
