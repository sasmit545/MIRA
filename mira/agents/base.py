"""The specialist interface (README section 11).

Every specialist receives an objective and produces the same shape, so the
Coordinator can assign work without knowing which specialist will run it.
"""

from __future__ import annotations

from dataclasses import dataclass

from typing import Optional, Protocol, runtime_checkable

from mira.core.objective import InvestigationObjective
from mira.core.state import InvestigationState
from mira.reasoning.contracts.finding import Confidence, Finding


@dataclass(frozen=True)
class InvestigationFinding:
    """The FINDING message a specialist returns (design document, section 10).

    This lands directly in an orchestrating model's context window, so it
    carries an assessment and references rather than raw capability output.
    The full observation behind any reference is pulled on demand, by
    identifier, from the shared state and the run's trace.

    The objective is not repeated back: the orchestrator assigned it and
    already holds it.
    """

    artifact_id: str
    assessment: str
    findings: list[Finding]
    evidence_refs: list[str]
    # The enum, like each Finding's own confidence. Stringifying it here would
    # be the one place the contract quietly downgrades a typed value.
    confidence: Confidence
    recommended_actions: list[str]


@runtime_checkable
class Specialist(Protocol):
    """What the Coordinator can assign an objective to.

    Structural rather than inherited: a specialist satisfies this by having
    the method, so Dynamic and Forensics need not import a base class to
    qualify.
    """

    async def investigate(
        self,
        objective: InvestigationObjective,
        artifact_id: str,
        state: Optional[InvestigationState] = None,
    ) -> InvestigationFinding: ...
