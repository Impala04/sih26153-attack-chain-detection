"""Provider interfaces + mock implementations for pipeline stages that are
not yet backed by a finished real component.

Follows the same pattern already used by ``src/correlation/stage_mapper.py``
(``StageMapper`` interface + ``FallbackStageMapper`` implementation): define
an abstract interface each real implementation must satisfy, and ship a
deterministic mock that satisfies it today so the orchestrator can be built,
wired, and tested end-to-end before every real provider exists.

Every provider returns one of the Pydantic contracts from ``src.contracts``
and stamps it with ``source="real"`` or ``source="mock"``, per the contracts'
own convention, so a caller can always tell which parts of an AnalysisResult
are genuine and which are stand-ins.
"""

from .explainer_provider import ExplainerProvider, MockExplainer
from .mitre_provider import MitreProvider, MockMitreMapper
from .risk_provider import MockRiskEngine, RiskProvider
from .world_model_provider import MockWorldModel, WorldModelProvider

__all__ = [
    "ExplainerProvider",
    "MockExplainer",
    "MitreProvider",
    "MockMitreMapper",
    "RiskProvider",
    "MockRiskEngine",
    "WorldModelProvider",
    "MockWorldModel",
]
