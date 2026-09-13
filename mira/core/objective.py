"""The objective a Coordinator assigns to a specialist.

This lives in core rather than beside any one specialist: the Coordinator
produces these and every specialist consumes them, so neither side owns the
type. Putting it in a specialist module would make core depend on a concrete
agent, which inverts the layering.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class InvestigationObjective:
    """An investigation task the Coordinator assigns to a specialist.

    `capabilities` bounds what the assigned specialist may use; the specialist
    chooses which of them to actually call.
    """

    name: str
    description: str
    reason: str
    capabilities: tuple[str, ...] = ()
