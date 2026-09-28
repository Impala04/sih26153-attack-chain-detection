import json

import pandas as pd
import pytest

from backend.app import features


def fallback_row(explanation):
    return pd.Series({"_explanation": explanation, "connection_count": 3})


def test_features_reads_structured_json_names_contributions_and_signs():
    explanation = {
        "status": "available",
        "prediction": 0.8,
        "top_features": [
            {"feature": f"feature_{index}", "contribution": value}
            for index, value in enumerate((0.41, -0.3, 0.1, -0.05, 0.02, 0.01))
        ],
    }
    result = features(pd.Series({"_explanation": json.dumps(explanation)}))

    assert len(result) == 5
    assert result[0] == {"feature": "feature_0", "impact": 0.41, "direction": "increases risk"}
    assert result[1] == {"feature": "feature_1", "impact": -0.3, "direction": "decreases risk"}
    assert result[2]["direction"] == "increases risk"
    assert result[3]["direction"] == "decreases risk"
    assert result[4]["direction"] == "increases risk"


@pytest.mark.parametrize(
    "explanation",
    [
        '{"status":"available","top_features":[',
        '{"status":"unavailable","reason":"no attribution","top_features":[]} ',
        '{"status":"available","top_features":null}',
        "",
    ],
)
def test_malformed_unavailable_or_empty_explanation_uses_existing_fallback(explanation):
    assert features(fallback_row(explanation)) == [
        {"feature": "connection volume", "impact": 0.2, "direction": "increases risk"}
    ]


def test_legacy_plain_text_keeps_semicolon_fallback():
    result = features(fallback_row("unique_ports; iat_variance; retransmission_count"))
    assert result == [
        {"feature": "unique_ports", "impact": 0.2, "direction": "increases risk"},
        {"feature": "iat_variance", "impact": 0.2, "direction": "increases risk"},
        {"feature": "retransmission_count", "impact": 0.2, "direction": "increases risk"},
    ]
