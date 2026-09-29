"""
CyberFlux Risk Engine

Consumes the signals that actually exist in the CyberFlux repository's
host_features_v2_scored.csv.

Real repository signals currently available:
    anomaly_risk          0-100
    anomaly_score         -1 to 1
    lateral_move_flag     0/1
    is_attack_window      0/1
    attack_flow_ratio     0-1
    connection_count      >= 1
    risk_score             0-100

Optional future signals:
    forecast_risk
    attack_stage
    confidence
    uncertainty
    vulnerability_score

The engine never invents unavailable model outputs.

It produces:
    risk_score
    risk_level
    contributing_factors
    recommended_action
    confidence
    uncertainty
    signals_used
    signals_missing
    timestamp
"""


from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Mapping


# ============================================================
# CONFIGURATION
# ============================================================

@dataclass(frozen=True)
class RiskConfig:

    # Current CyberFlux signals
    anomaly_weight: float = 0.45
    attack_chain_weight: float = 0.25
    detection_weight: float = 0.30

    # Risk bands required by the project brief
    low_max: float = 30.0
    moderate_max: float = 60.0
    high_max: float = 80.0


DEFAULT_CONFIG = RiskConfig()


# ============================================================
# BASIC HELPERS
# ============================================================

def _number(value: Any) -> float | None:
    """Safely convert a value to a finite float."""

    if value is None or isinstance(value, bool):
        return None

    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None

    if not math.isfinite(number):
        return None

    return number


def _clamp(
    value: float,
    low: float = 0.0,
    high: float = 1.0,
) -> float:

    return max(
        low,
        min(high, value),
    )


def _normalise_0_100(value: Any) -> float | None:
    """
    Convert a repository risk value from 0-100 into 0-1.
    """

    number = _number(value)

    if number is None:
        return None

    if number < 0 or number > 100:
        return None

    return number / 100.0


def _normalise_0_1(value: Any) -> float | None:
    """
    Convert a repository probability/ratio from 0-1 into 0-1.
    """

    number = _number(value)

    if number is None:
        return None

    if number < 0 or number > 1:
        return None

    return number


def _get(
    row: Mapping[str, Any],
    *names: str,
) -> tuple[Any, str | None]:

    lowered = {
        str(key).strip().lower(): value
        for key, value in row.items()
    }

    for name in names:

        key = name.lower()

        if key in lowered:
            return lowered[key], name

    return None, None


# ============================================================
# ATTACK STAGE
# ============================================================

STAGE_RISK = {
    "reconnaissance": 0.25,
    "resource development": 0.30,
    "discovery": 0.35,
    "initial access": 0.55,
    "execution": 0.65,
    "persistence": 0.65,
    "privilege escalation": 0.75,
    "defense evasion": 0.75,
    "credential access": 0.80,
    "lateral movement": 0.85,
    "collection": 0.85,
    "command and control": 0.90,
    "c2": 0.90,
    "exfiltration": 0.95,
    "impact": 1.00,
}


def stage_to_risk(
    stage: Any,
) -> float | None:

    if stage is None:
        return None

    text = str(stage).strip().lower()

    if not text:
        return None

    if text in {
        "none",
        "unknown",
        "nan",
        "n/a",
    }:
        return None

    if text in STAGE_RISK:
        return STAGE_RISK[text]

    for stage_name, stage_value in STAGE_RISK.items():

        if stage_name in text:
            return stage_value

    return None


# ============================================================
# RESULT CONTRACT
# ============================================================

@dataclass
class RiskResult:

    risk_score: float
    risk_level: str

    contributing_factors: list[
        dict[str, Any]
    ]

    recommended_action: str

    confidence: float | None
    uncertainty: float | None

    signals_used: list[str]
    signals_missing: list[str]

    timestamp: str

    factor_values: dict[
        str,
        float | None,
    ]


# ============================================================
# RISK ENGINE
# ============================================================

class RiskEngine:

    def __init__(
        self,
        config: RiskConfig = DEFAULT_CONFIG,
    ):
        self.config = config

    # --------------------------------------------------------
    # Risk level
    # --------------------------------------------------------

    def risk_level(
        self,
        score: float,
    ) -> str:

        if score <= self.config.low_max:
            return "Low"

        if score <= self.config.moderate_max:
            return "Moderate"

        if score <= self.config.high_max:
            return "High"

        return "Very High"

    # --------------------------------------------------------
    # Recommended action
    # --------------------------------------------------------

    def recommended_action(
        self,
        score: float,
    ) -> str:

        level = self.risk_level(score)

        if level == "Low":

            return (
                "Continue monitoring the host "
                "and collect additional telemetry."
            )

        if level == "Moderate":

            return (
                "Investigate the host and monitor "
                "related traffic for escalation."
            )

        if level == "High":

            return (
                "Prioritise SOC investigation and "
                "consider isolating the affected host."
            )

        return (
            "Initiate urgent SOC response, investigate "
            "the attack chain, and consider host isolation "
            "and credential containment."
        )

    # --------------------------------------------------------
    # Evaluation
    # --------------------------------------------------------

    def evaluate(
        self,
        row: Mapping[str, Any],
    ) -> RiskResult:

        # ====================================================
        # M — ANOMALY / MALICIOUS BEHAVIOUR
        # ====================================================

        anomaly_raw, anomaly_source = _get(
            row,
            "anomaly_risk",
        )

        anomaly = _normalise_0_100(
            anomaly_raw
        )

        # Fallback to anomaly_score if anomaly_risk
        # isn't available.
        if anomaly is None:

            anomaly_score_raw, anomaly_score_source = _get(
                row,
                "anomaly_score",
            )

            anomaly_score = _number(
                anomaly_score_raw
            )

            if anomaly_score is not None:

                # Repository anomaly_score is -1 to 1.
                # Convert to 0-1 without inventing a prediction.
                anomaly = _clamp(
                    (
                        anomaly_score + 1.0
                    ) / 2.0
                )

                anomaly_source = (
                    anomaly_score_source
                )

        # ====================================================
        # A — ATTACK CHAIN / LATERAL MOVEMENT
        # ====================================================

        lateral_raw, lateral_source = _get(
            row,
            "lateral_move_flag",
        )

        lateral_flag = _normalise_0_1(
            lateral_raw
        )

        attack_chain = lateral_flag

        # Optional future attack-stage signal.
        stage_raw, stage_source = _get(
            row,
            "attack_stage",
            "current_stage",
            "mitre_stage",
            "predicted_stage",
        )

        stage_risk = stage_to_risk(
            stage_raw
        )

        if stage_risk is not None:

            if attack_chain is None:
                attack_chain = stage_risk

            else:
                # If both actual lateral-movement evidence
                # and a stage prediction exist, use the stronger
                # documented signal without creating a new model.
                attack_chain = max(
                    attack_chain,
                    stage_risk,
                )

        # Optional explicit chain score.
        chain_raw, chain_source = _get(
            row,
            "attack_chain_score",
            "attack_chain_risk",
            "progression_score",
        )

        chain_score = _normalise_0_1(
            chain_raw
        )

        if chain_score is not None:
            attack_chain = chain_score

        # ====================================================
        # D — DETECTION / EVENT EVIDENCE
        # ====================================================

        attack_ratio_raw, attack_ratio_source = _get(
            row,
            "attack_flow_ratio",
        )

        attack_flow_ratio = _normalise_0_1(
            attack_ratio_raw
        )

        attack_window_raw, attack_window_source = _get(
            row,
            "is_attack_window",
        )

        attack_window = _normalise_0_1(
            attack_window_raw
        )

        connection_raw, connection_source = _get(
            row,
            "connection_count",
        )

        connection_count = _number(
            connection_raw
        )

        # Convert traffic volume into bounded evidence.
        #
        # This prevents a huge connection count from directly
        # becoming a 100% risk value.
        connection_evidence = None

        if (
            connection_count is not None
            and connection_count >= 0
        ):

            connection_evidence = _clamp(
                math.log1p(
                    connection_count
                )
                / math.log1p(100.0)
            )

        detection_components = []

        if attack_flow_ratio is not None:
            detection_components.append(
                attack_flow_ratio
            )

        if attack_window is not None:
            detection_components.append(
                attack_window
            )

        if connection_evidence is not None:
            detection_components.append(
                connection_evidence
            )

        detection = (
            sum(detection_components)
            / len(detection_components)
            if detection_components
            else None
        )

        # ====================================================
        # OPTIONAL FUTURE SIGNALS
        # ====================================================

        forecast_raw, forecast_source = _get(
            row,
            "forecast_risk",
            "forecast_score",
            "forecast_probability",
        )

        forecast = _normalise_0_1(
            forecast_raw
        )

        confidence_raw, confidence_source = _get(
            row,
            "confidence",
            "model_confidence",
            "prediction_confidence",
        )

        confidence = _normalise_0_1(
            confidence_raw
        )

        uncertainty_raw, uncertainty_source = _get(
            row,
            "uncertainty",
            "prediction_uncertainty",
        )

        uncertainty = _normalise_0_1(
            uncertainty_raw
        )

        if (
            confidence is None
            and uncertainty is not None
        ):
            confidence = 1.0 - uncertainty

        vulnerability_raw, vulnerability_source = _get(
            row,
            "vulnerability_score",
            "vulnerability_risk",
            "asset_criticality",
        )

        vulnerability = _normalise_0_1(
            vulnerability_raw
        )

        # ====================================================
        # CURRENT ENGINE WEIGHTS
        # ====================================================

        factors = {
            "M": anomaly,
            "A": attack_chain,
            "D": detection,
        }

        weights = {
            "M": self.config.anomaly_weight,
            "A": self.config.attack_chain_weight,
            "D": self.config.detection_weight,
        }

        available = {
            key: value
            for key, value in factors.items()
            if value is not None
        }

        # ====================================================
        # NO SIGNAL
        # ====================================================

        if not available:

            score = 0.0

        else:

            total_weight = sum(
                weights[key]
                for key in available
            )

            weighted_score = sum(
                available[key]
                * weights[key]
                for key in available
            )

            score = (
                weighted_score / total_weight
                if total_weight > 0
                else 0.0
            )

        score = round(
            _clamp(score) * 100.0,
            2,
        )

        # ====================================================
        # CONTRIBUTING FACTORS
        # ====================================================

        factor_names = {
            "M": (
                "Observed malicious or "
                "anomalous behaviour"
            ),
            "A": (
                "Attack-chain / lateral "
                "movement evidence"
            ),
            "D": (
                "Detection and traffic evidence"
            ),
        }

        contributing_factors = []

        for key, value in available.items():

            contribution = (
                value
                * weights[key]
            )

            if value >= 0.7:
                effect = "increases risk"

            elif value >= 0.3:
                effect = "moderate"

            else:
                effect = "low"

            contributing_factors.append(
                {
                    "factor": key,
                    "name": factor_names[key],
                    "value": round(
                        value,
                        4,
                    ),
                    "weight": weights[key],
                    "contribution": round(
                        contribution,
                        4,
                    ),
                    "effect": effect,
                }
            )

        contributing_factors.sort(
            key=lambda item: item[
                "contribution"
            ],
            reverse=True,
        )

        # ====================================================
        # SIGNAL SOURCES
        # ====================================================

        source_candidates = [
            anomaly_source,
            lateral_source,
            stage_source,
            chain_source,
            attack_ratio_source,
            attack_window_source,
            connection_source,
        ]

        signals_used = sorted(
            {
                source
                for source in source_candidates
                if source is not None
            }
        )

        signals_missing = []

        if anomaly is None:
            signals_missing.append(
                "anomaly"
            )

        if attack_chain is None:
            signals_missing.append(
                "attack-chain/stage"
            )

        if detection is None:
            signals_missing.append(
                "detection/evidence"
            )

        if forecast is None:
            signals_missing.append(
                "forecast"
            )

        if confidence is None:
            signals_missing.append(
                "confidence"
            )

        if vulnerability is None:
            signals_missing.append(
                "vulnerability"
            )

        # ====================================================
        # RETURN
        # ====================================================

        return RiskResult(

            risk_score=score,

            risk_level=self.risk_level(
                score
            ),

            contributing_factors=(
                contributing_factors
            ),

            recommended_action=(
                self.recommended_action(
                    score
                )
            ),

            confidence=(
                round(
                    confidence,
                    4,
                )
                if confidence is not None
                else None
            ),

            uncertainty=(
                round(
                    uncertainty,
                    4,
                )
                if uncertainty is not None
                else None
            ),

            signals_used=signals_used,

            signals_missing=signals_missing,

            timestamp=(
                datetime.now(
                    timezone.utc
                ).isoformat()
            ),

            factor_values={
                "M": (
                    round(anomaly, 4)
                    if anomaly is not None
                    else None
                ),
                "A": (
                    round(
                        attack_chain,
                        4,
                    )
                    if attack_chain is not None
                    else None
                ),
                "D": (
                    round(
                        detection,
                        4,
                    )
                    if detection is not None
                    else None
                ),
                "F": (
                    round(
                        forecast,
                        4,
                    )
                    if forecast is not None
                    else None
                ),
                "C": (
                    round(
                        confidence,
                        4,
                    )
                    if confidence is not None
                    else None
                ),
                "V": (
                    round(
                        vulnerability,
                        4,
                    )
                    if vulnerability is not None
                    else None
                ),
            },
        )


# ============================================================
# PUBLIC API
# ============================================================

_engine = RiskEngine()


def calculate_risk(
    row: Mapping[str, Any],
) -> dict[str, Any]:
    """
    Public JSON-serialisable Risk Engine interface.
    """

    return asdict(
        _engine.evaluate(row)
    )