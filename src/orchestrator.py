"""Checkpoint 3: orchestrates detection events into a single AnalysisResult.

This is the missing link between:

    DetectionEvent (processing pipeline)
        -> AttackChain (correlation)
        -> forecast / mitre / explanation / risk (providers, real or mock)
        -> AnalysisResult (contracts)

Every provider call is wrapped so that a failing or not-yet-real provider
degrades the AnalysisResult gracefully: the corresponding field is left
``None`` and a message is appended to ``warnings`` instead of the whole
analysis failing. This matches the AnalysisResult contract's own
documented intent (every stage past detection/correlation is Optional).
"""

from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from src.contracts import AnalysisResult
from src.correlation.attack_chain import AttackChain
from src.correlation.correlator import AttackChainCorrelator
from src.correlation.stage_mapper import StageMapper
from src.processing.events import DetectionEvent
from src.providers.explainer_provider import ExplainerProvider, MockExplainer
from src.providers.mitre_provider import MitreProvider, MockMitreMapper
from src.providers.risk_provider import MockRiskEngine, RiskProvider
from src.providers.world_model_provider import WorldModelProvider, MockWorldModel

logger = logging.getLogger(__name__)


class AnalysisOrchestrator:
    """Turn a batch of DetectionEvents into a complete AnalysisResult.

    Providers default to the Checkpoint 2 mocks so the orchestrator is
    usable end-to-end today; pass real implementations in as they become
    available (they satisfy the same abstract interfaces, so no other code
    here needs to change).
    """

    def __init__(
        self,
        correlator: Optional[AttackChainCorrelator] = None,
        stage_mapper: Optional[StageMapper] = None,
        world_model_provider: Optional[WorldModelProvider] = None,
        mitre_provider: Optional[MitreProvider] = None,
        explainer_provider: Optional[ExplainerProvider] = None,
        risk_provider: Optional[RiskProvider] = None,
    ) -> None:
        if correlator is not None and stage_mapper is not None:
            raise ValueError(
                "pass stage_mapper OR a pre-built correlator, not both"
            )

        self.correlator = correlator or AttackChainCorrelator(
            stage_mapper=stage_mapper
        )
        self.world_model_provider = world_model_provider or MockWorldModel()
        self.mitre_provider = mitre_provider or MockMitreMapper()
        self.explainer_provider = explainer_provider or MockExplainer()
        self.risk_provider = risk_provider or MockRiskEngine()

    def analyze(
        self,
        detections: List[DetectionEvent],
        input_source: str,
        recent_windows: Any = None,
    ) -> AnalysisResult:
        """Correlate ``detections`` and run every provider to build one AnalysisResult.

        ``input_source`` is a free-text label for where the detections came
        from (e.g. "csv:flows_2024.csv", "pcap:capture.pcap", "live").
        ``recent_windows`` is passed straight through to the forecasting
        provider's context (only ``RealWorldModelProvider`` currently uses
        it); the mock ignores it.
        """
        warnings: List[str] = []

        detection_dicts = [event.to_dict() for event in detections]

        chains: List[AttackChain] = self.correlator.correlate(detections)
        chain_dicts = [chain.to_dict() for chain in chains]

        logger.info(
            "Correlated %d detections into %d attack chains (input_source=%s)",
            len(detections),
            len(chains),
            input_source,
        )

        primary_chain_dict = self._primary_chain_dict(chain_dicts)

        forecast = self._safe_call(
            "forecast",
            warnings,
            self.world_model_provider.forecast,
            {
                "attack_chain": primary_chain_dict,
                "recent_windows": recent_windows,
                "window_seconds": getattr(
                    self.world_model_provider,
                    "window_seconds",
                    None,
                ),
            },
        )
        if (
            forecast is not None
            and forecast.forecast_status == "insufficient_history"
            and forecast.warning
        ):
            warnings.append(forecast.warning)

        mitre = self._safe_call(
            "mitre",
            warnings,
            self.mitre_provider.map_techniques,
            {
                "detections": detection_dicts,
                "attack_chain": primary_chain_dict,
            },
        )

        mitre_dicts = (
            [m.model_dump() for m in mitre]
            if mitre is not None
            else None
        )

        explanation = self._safe_call(
            "explanation",
            warnings,
            self.explainer_provider.explain,
            {"detections": detection_dicts},
        )

        risk = self._safe_call(
            "risk",
            warnings,
            self.risk_provider.assess_risk,
            {
                "detections": detection_dicts,
                "mitre": mitre_dicts,
                "forecast": (
                    forecast.model_dump()
                    if forecast is not None
                    else None
                ),
            },
        )

        if warnings:
            logger.warning(
                "Analysis completed with %d warning(s): %s",
                len(warnings),
                warnings,
            )

        return AnalysisResult(
            analysis_id=str(uuid.uuid4()),
            timestamp=time.time(),
            input_source=input_source,
            detections=detection_dicts,
            attack_chains=chain_dicts,
            forecast=forecast,
            mitre=mitre,
            explanation=explanation,
            risk=risk,
            warnings=warnings,
        )

    @staticmethod
    def _primary_chain_dict(
        chain_dicts: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """Pick the chain a single-chain-shaped provider context should see.

        Providers (forecast especially) are built around "the" attack
        chain, not a list of them. Prefer the most recently active chain;
        fall back to None when there are no chains at all (e.g. an empty
        or all-benign batch of detections).
        """
        if not chain_dicts:
            return None

        return max(chain_dicts, key=lambda c: c["last_seen"])

    @staticmethod
    def _safe_call(
        label: str,
        warnings: List[str],
        func,
        context: Dict[str, Any],
    ):
        """Call a provider, converting any exception into a warning + None.

        This is what keeps one broken/unavailable provider (e.g. a real
        WorldModelProvider with a missing checkpoint file) from taking down
        the whole AnalysisResult.
        """
        try:
            return func(context)
        except Exception as exc:  # noqa: BLE001 - providers are third-party-ish
            logger.warning(
                "%s provider failed: %s",
                label,
                exc,
                exc_info=True,
            )
            warnings.append(f"{label} provider failed: {exc}")
            return None


def create_production_orchestrator(
    model_path: Optional[Union[str, Path]] = None,
) -> AnalysisOrchestrator:
    """Build an orchestrator that requires the real trained World Model.

    This factory deliberately does not fall back to ``MockWorldModel`` when
    dependencies or artifacts are missing. Unit tests may continue creating
    ``AnalysisOrchestrator()`` directly to use deterministic mocks.
    """
    from src.providers.world_model_provider import RealWorldModelProvider

    return AnalysisOrchestrator(
        world_model_provider=RealWorldModelProvider(model_path=model_path)
    )


def run_analysis(
    input_path: Union[str, Path],
    orchestrator: Optional[AnalysisOrchestrator] = None,
) -> AnalysisResult:
    """Single entry point: load detections from a file and produce an AnalysisResult.

    Dispatches on file extension:
      - .csv  -> src.ingestion.csv_adapter.build_events_from_csv
      - .pcap/.pcapng -> src.ingestion.pcap_reader.iter_pcap ->
        ProcessingPipeline. Raises PcapReadError for a corrupt capture.

    ``orchestrator`` can be supplied for testing (e.g. with mock providers
    already configured); defaults to a fresh AnalysisOrchestrator() otherwise.
    """
    path = Path(input_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Input file does not exist or is not a file: {path}"
        )

    suffix = path.suffix.lower()
    orchestrator = orchestrator or AnalysisOrchestrator()

    if suffix == ".csv":
        from src.ingestion.csv_adapter import build_events_from_csv
        from src.providers.world_model_provider import RealWorldModelProvider

        logger.info("run_analysis: loading CSV input %s", path)

        detections = build_events_from_csv(str(path))
        recent_windows = None
        if isinstance(orchestrator.world_model_provider, RealWorldModelProvider):
            import pandas as pd

            # Keep the full temporal feature frame for forecasting; the CSV
            # adapter's DetectionEvents include only rows that triggered a rule.
            recent_windows = pd.read_csv(path)

        logger.info(
            "run_analysis: CSV adapter produced %d detection events",
            len(detections),
        )

        return orchestrator.analyze(
            detections,
            input_source=f"csv:{path.name}",
            recent_windows=recent_windows,
        )

    if suffix in {".pcap", ".pcapng"}:
        from src.ingestion.pcap_reader import iter_pcap
        from src.processing.pipeline import ProcessingPipeline
        from src.model.event_scoring import score_detection_event
        from src.model.score import DEFAULT_MODEL_PATH
        from src.providers.world_model_provider import RealWorldModelProvider

        logger.info("run_analysis: loading PCAP input %s", path)

        real_provider = (
            orchestrator.world_model_provider
            if isinstance(orchestrator.world_model_provider, RealWorldModelProvider)
            else None
        )
        recent_rows_by_pair: Dict[tuple, List[Dict[str, Any]]] = {}

        def capture_window_features(rows: List[Dict[str, Any]]) -> None:
            if real_provider is None:
                return
            import pandas as pd

            for row in rows:
                key = (str(row["src_ip"]), str(row["dst_ip"]))
                pair_rows = recent_rows_by_pair.setdefault(key, [])
                current_time = pd.to_datetime(row["window_start"], utc=True)
                if pair_rows:
                    previous_time = pd.to_datetime(
                        pair_rows[-1]["window_start"], utc=True
                    )
                    if (current_time - previous_time).total_seconds() > 300:
                        pair_rows.clear()
                pair_rows.append(row)
                if len(pair_rows) > real_provider.sequence_length:
                    del pair_rows[:-real_provider.sequence_length]

        pipeline = ProcessingPipeline(on_window_features=capture_window_features)
        detections = []

        for packet in iter_pcap(path):
            detections.extend(pipeline.ingest(packet))

        detections.extend(pipeline.flush())

        for event in detections:
            try:
                event.metadata["ml_score"] = score_detection_event(
                    event, model_path=DEFAULT_MODEL_PATH
                )
            except Exception as exc:
                event.metadata["ml_score_error"] = str(exc)
                
        logger.info(
            "run_analysis: PCAP pipeline produced %d detection events",
            len(detections),
        )

        return orchestrator.analyze(
            detections,
            input_source=f"pcap:{path.name}",
            recent_windows=(
                [row for rows in recent_rows_by_pair.values() for row in rows]
                if real_provider is not None
                else None
            ),
        )

    raise ValueError(
        f"Unsupported input file type: {suffix or '(no extension)'}"
    )
