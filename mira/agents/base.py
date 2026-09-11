"""The specialist interface (README section 11).

Every specialist receives an objective and produces the same shape, so the
Coordinator can assign work without knowing which specialist will run it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from mira.core.objective import InvestigationObjective
from mira.reasoning.contracts.output import FinalOutput


@dataclass(frozen=True)
class InvestigationFinding:
    """Results and normalized evidence produced while pursuing one objective.

    `evidence` is normalized for the Coordinator to reason over; `output` is
    the specialist's own verdict from its reasoning loop.
    """

    objective: InvestigationObjective
    results: dict[str, dict]
    evidence: list[dict]
    output: FinalOutput


@runtime_checkable
class Specialist(Protocol):
    """What the Coordinator can assign an objective to.

    Structural rather than inherited: a specialist satisfies this by having
    the method, so Dynamic and Forensics need not import a base class to
    qualify.
    """

    async def investigate(
        self, objective: InvestigationObjective, artifact_id: str
    ) -> InvestigationFinding: ...
