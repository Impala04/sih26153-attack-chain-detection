"""Forecasting provider: predicts the next attack-chain stage.

IMPORTANT — stage mismatch with the real World Model (see WORLD_MODEL.md):
Aaron's ``WorldModelForecaster`` (src/model/forecast_world_model.py) predicts
a *binary attack/no-attack probability* per future 30-second window for one
(src_ip, dst_ip) pair. It does not predict which MITRE-chain *stage* comes
next. The pipeline contract (``contracts.ForecastResult.predicted_stage``)
asks for a stage name.

``RealWorldModelProvider`` below is therefore an adapter, not a 1:1 wrapper:
it calls the real model and maps its binary output onto a two-value
pseudo-stage ("Attack Likely" / "No Attack Predicted") using the top future
step's probability as confidence. This is a deliberate stopgap so the
orchestrator has something real to call today. True stage-transition
forecasting (Discovery -> Lateral Movement -> ...) needs either a retrained
model or a mapping layer, and should be revisited with Simar/Aaron once MITRE
mapping exists.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from src.contracts import ForecastResult, StageProbability


class WorldModelProvider(ABC):
    """Interface every forecasting provider (real or mock) must satisfy."""

    @abstractmethod
    def forecast(self, context: Dict[str, Any]) -> ForecastResult:
        """Produce a ForecastResult from pipeline context.

        ``context`` is a plain dict so callers don't need to depend on any
        one provider's preferred input shape. At minimum it may contain:
          - "attack_chain": an AttackChain.to_dict() or None
          - "recent_windows": a list/DataFrame of recent feature windows
          - "window_seconds": the pipeline's window size, for confidence work
        Implementations should read only the keys they need and ignore the
        rest, since different providers need different context.
        """
        raise NotImplementedError


class MockWorldModel(WorldModelProvider):
    """Deterministic placeholder forecaster.

    Produces the same ForecastResult for the same input every time (no
    randomness, no wall-clock dependence), so tests and demos are
    reproducible. The "prediction" is derived from a hash of the current
    attack chain's stage/id, not a real model, and is clearly stamped
    ``source="mock"``.
    """

    _CANDIDATE_STAGES = [
        "Reconnaissance",
        "Initial Access",
        "Discovery",
        "Lateral Movement",
        "Exfiltration",
        "Impact",
    ]

    def __init__(self, window_seconds: float = 30.0) -> None:
        self.window_seconds = window_seconds

    def forecast(self, context: Dict[str, Any]) -> ForecastResult:
        seed_text = self._seed_text(context)
        digest = hashlib.sha256(seed_text.encode("utf-8")).hexdigest()
        seed_int = int(digest[:8], 16)

        stages = self._CANDIDATE_STAGES
        primary_index = seed_int % len(stages)
        secondary_index = (seed_int // len(stages)) % len(stages)
        if secondary_index == primary_index:
            secondary_index = (secondary_index + 1) % len(stages)

        # Deterministic but bounded confidence, never exactly 0 or 1.
        primary_confidence = 0.4 + (seed_int % 50) / 100.0  # 0.40-0.89
        secondary_confidence = round(max(0.0, 1.0 - primary_confidence) * 0.5, 4)

        return ForecastResult(
            predicted_stage=stages[primary_index],
            confidence=round(primary_confidence, 4),
            probable_next_stages=[
                StageProbability(
                    stage=stages[primary_index], probability=round(primary_confidence, 4)
                ),
                StageProbability(
                    stage=stages[secondary_index], probability=secondary_confidence
                ),
            ],
            time_window_seconds=self.window_seconds,
            source="mock",
        )

    @staticmethod
    def _seed_text(context: Dict[str, Any]) -> str:
        chain = context.get("attack_chain") or {}
        chain_id = chain.get("chain_id") if isinstance(chain, dict) else None
        current_stage = chain.get("current_stage") if isinstance(chain, dict) else None
        return f"{chain_id}|{current_stage}"


class RealWorldModelProvider(WorldModelProvider):
    """Adapter over Aaron's trained GRU World Model.

    Lazily imports torch/the real forecaster so this module can still be
    imported (and MockWorldModel used) on machines without torch installed.
    Construction raises immediately if the real dependencies or trained
    checkpoint are unavailable -- callers should fall back to MockWorldModel
    in that case rather than let the whole pipeline fail.
    """

    def __init__(
        self,
        model_path: Union[str, Path] = "models/world_model/world_model.pt",
        window_seconds: float = 30.0,
    ) -> None:
        try:
            from src.model.forecast_world_model import load_world_model
        except ImportError as exc:  # torch (or numpy) not installed
            raise RuntimeError(
                "RealWorldModelProvider requires torch/numpy to be installed "
                "(see requirements-world-model.txt)"
            ) from exc

        self._forecaster = load_world_model(model_path)
        self.window_seconds = window_seconds

    def forecast(self, context: Dict[str, Any]) -> ForecastResult:
        windows = context.get("recent_windows")
        if windows is None:
            raise ValueError(
                "RealWorldModelProvider.forecast requires context['recent_windows'] "
                "(a DataFrame of consecutive feature windows for one src/dst pair)"
            )

        horizon = context.get("horizon")
        raw_result = self._forecaster.forecast(windows, horizon=horizon)

        if not raw_result.predictions:
            # No future steps produced; report "no attack predicted" with
            # zero confidence rather than raising, so a caller still gets a
            # valid (if uninformative) ForecastResult.
            return ForecastResult(
                predicted_stage="No Attack Predicted",
                confidence=0.0,
                probable_next_stages=[],
                time_window_seconds=self.window_seconds,
                source="real",
            )

        top_step = max(raw_result.predictions, key=lambda step: step.probability)
        predicted_stage = (
            "Attack Likely" if top_step.predicted_attack else "No Attack Predicted"
        )

        stage_probabilities: List[StageProbability] = [
            StageProbability(
                stage="Attack Likely" if step.predicted_attack else "No Attack Predicted",
                probability=round(step.probability, 4),
            )
            for step in raw_result.predictions
        ]
        # Guard against float drift pushing the contract-level sum check
        # over 1.0 when multiple future steps predict the same pseudo-stage.
        total = sum(item.probability for item in stage_probabilities)
        if total > 1.0:
            scale = 1.0 / total
            stage_probabilities = [
                StageProbability(stage=item.stage, probability=round(item.probability * scale, 4))
                for item in stage_probabilities
            ]

        return ForecastResult(
            predicted_stage=predicted_stage,
            confidence=round(float(top_step.probability), 4),
            probable_next_stages=stage_probabilities,
            time_window_seconds=self.window_seconds,
            source="real",
        )
