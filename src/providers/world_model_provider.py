"""Mock attack-stage forecasts and the real future attack-probability model."""

from __future__ import annotations

import hashlib
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import pandas as pd

from src.contracts import ForecastResult, FutureAttackProbability, StageProbability
from src.model.train import FEATURE_COLS, LATERAL_MOVE_THRESHOLD


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
    """Load the trained GRU once and return real future attack scores.

    ``recent_windows`` may be a CSV-style dataframe containing many pairs or
    an already-selected sequence. Sparse pair windows are filled using the
    same five-minute gap rule as training. No forecast is fabricated when a
    pair lacks enough consecutive history.
    """

    MODEL_PATH_ENV = "CYBERFLUX_WORLD_MODEL_PATH"
    DEFAULT_MODEL_RELATIVE_PATH = Path("models/world_model/world_model.pt")

    def __init__(
        self,
        model_path: Optional[Union[str, Path]] = None,
        window_seconds: Optional[float] = None,
    ) -> None:
        try:
            from src.model.forecast_world_model import load_world_model
        except ImportError as exc:  # torch (or numpy) not installed
            raise RuntimeError(
                "RealWorldModelProvider requires torch/numpy to be installed "
                "(see requirements-world-model.txt)"
            ) from exc

        repository_root = Path(__file__).resolve().parents[2]
        configured_path = model_path or os.environ.get(self.MODEL_PATH_ENV)
        weights_path = (
            Path(configured_path)
            if configured_path
            else self.DEFAULT_MODEL_RELATIVE_PATH
        )
        if not weights_path.is_absolute():
            weights_path = repository_root / weights_path

        # load_world_model validates weights against adjacent metadata. This
        # happens once per provider instance, not once per analysis request.
        self._forecaster = load_world_model(weights_path)
        self.model_path = weights_path
        self.window_seconds = float(self._forecaster.window_seconds)
        self.sequence_length = int(self._forecaster.model.sequence_length)
        self.forecast_horizon = int(self._forecaster.model.forecast_horizon)
        if (
            window_seconds is not None
            and float(window_seconds) != self.window_seconds
        ):
            raise ValueError(
                "Configured window_seconds does not match the trained model "
                f"({window_seconds} != {self.window_seconds})"
            )

    def forecast(self, context: Dict[str, Any]) -> ForecastResult:
        windows = context.get("recent_windows")
        sequence, unavailable_reason = self._select_recent_sequence(windows)
        if sequence is None:
            return ForecastResult(
                predicted_stage="Insufficient history",
                confidence=None,
                probable_next_stages=[],
                time_window_seconds=self.window_seconds,
                source="real",
                forecast_kind="attack_probability",
                forecast_status="insufficient_history",
                probability_note=self._forecaster.probability_note,
                warning=unavailable_reason,
            )

        horizon = context.get("horizon")
        raw_result = self._forecaster.forecast(sequence, horizon=horizon)
        future_scores = [
            FutureAttackProbability(
                step=step.step,
                window_start=step.window_start,
                probability=round(float(step.probability), 6),
                threshold=round(float(step.threshold), 6),
                predicted_attack=bool(step.predicted_attack),
            )
            for step in raw_result.predictions
        ]
        maximum_score = max((item.probability for item in future_scores), default=None)
        return ForecastResult(
            # Keep the legacy display field populated, but never claim a
            # MITRE or attack-chain stage from this binary model.
            predicted_stage="Future attack probability",
            confidence=maximum_score,
            probable_next_stages=[],
            time_window_seconds=self.window_seconds,
            source="real",
            forecast_kind="attack_probability",
            forecast_status="ready",
            future_attack_probabilities=future_scores,
            forecast_horizon_steps=len(future_scores),
            probability_note=raw_result.probability_note,
        )

    def _select_recent_sequence(
        self, windows: Any
    ) -> Tuple[Optional[pd.DataFrame], Optional[str]]:
        """Select the newest valid pair sequence or describe missing history."""
        if windows is None:
            return None, "No recent window features were supplied to the World Model."
        if not isinstance(windows, pd.DataFrame):
            try:
                windows = pd.DataFrame(windows)
            except (TypeError, ValueError) as exc:
                raise TypeError("recent_windows must be a DataFrame or rows") from exc
        if windows.empty:
            return None, "No recent window features were available for forecasting."

        frame = windows.copy()
        frame.columns = [str(column).strip() for column in frame.columns]
        required_features = list(FEATURE_COLS)
        if "lateral_move_flag" not in frame.columns:
            if "unique_destinations" not in frame.columns:
                raise ValueError(
                    "recent_windows is missing lateral_move_flag and "
                    "unique_destinations, so the Phase 1 feature cannot be derived"
                )
            frame["lateral_move_flag"] = (
                pd.to_numeric(frame["unique_destinations"], errors="raise")
                > LATERAL_MOVE_THRESHOLD
            ).astype(int)

        missing = [
            column
            for column in required_features + ["window_start"]
            if column not in frame
        ]
        if missing:
            raise ValueError(f"recent_windows is missing required columns: {missing}")
        frame["window_start"] = pd.to_datetime(
            frame["window_start"], errors="coerce", utc=True
        )
        if frame["window_start"].isna().any():
            return None, "Recent window features contain invalid window_start timestamps."

        expected_rows = int(self._forecaster.model.sequence_length)
        has_pair_keys = {"src_ip", "dst_ip"}.issubset(frame.columns)
        if not has_pair_keys:
            if len(frame) < expected_rows:
                return None, (
                    f"World Model needs {expected_rows} consecutive windows; "
                    f"received {len(frame)}."
                )
            sequence = frame.sort_values("window_start").tail(expected_rows).copy()
            timestamps = pd.to_datetime(
                sequence["window_start"], errors="coerce", utc=True
            )
            expected_step = pd.Timedelta(seconds=self.window_seconds)
            if (
                timestamps.isna().any()
                or not timestamps.diff().iloc[1:].eq(expected_step).all()
            ):
                return None, (
                    "The supplied recent windows are not a complete consecutive "
                    f"{self.window_seconds:g}-second sequence."
                )
            return sequence, None

        # The training builder inserts zero-activity rows for gaps up to five
        # minutes. Use the exact same policy at inference so sparse observed
        # windows have the same meaning as the trained input representation.
        from src.model.sequence_builder import densify_pair_windows

        frame["is_attack_window"] = 0
        dense = densify_pair_windows(
            frame,
            window_seconds=self.window_seconds,
            max_gap_seconds=300,
        )
        candidates = []
        for _, pair in dense.groupby(["src_ip", "dst_ip"], sort=False):
            pair = pair.sort_values("window_start").reset_index(drop=True)
            stamps = pd.to_datetime(pair["window_start"], utc=True)
            segment_ids = (
                stamps.diff().dt.total_seconds().fillna(self.window_seconds)
                .ne(self.window_seconds)
                .cumsum()
            )
            for _, segment in pair.groupby(segment_ids, sort=False):
                if len(segment) >= expected_rows:
                    sequence = segment.tail(expected_rows)
                    candidates.append((sequence["window_start"].iloc[-1], sequence))

        if not candidates:
            return None, (
                "No source/destination pair has enough consecutive "
                f"{self.window_seconds:g}-second windows; the model requires "
                f"{expected_rows}."
            )
        _, latest = max(candidates, key=lambda item: item[0])
        return latest, None
