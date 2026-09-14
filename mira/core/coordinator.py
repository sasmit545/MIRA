"""Minimal coordinator that assigns Static Agent objectives only."""

from __future__ import annotations

from mira.core.evidence import Evidence
from mira.core.objective import InvestigationObjective

ENTROPY_SIGNAL = "entropy"


class StaticCoordinator:
    """Chooses the next static objective from accumulated evidence."""

    def select_next_objective(self, evidence: list[Evidence]) -> InvestigationObjective:
        # Evidence carries an analyst's sentence rather than a closed set of
        # kinds, so this reads the observation. A real orchestrator is a model
        # doing the same thing; this two-branch stand-in matches on a word.
        if any(
            item.capability == "analyze_pe" and ENTROPY_SIGNAL in item.observation
            for item in evidence
        ):
            return InvestigationObjective(
                name="Assess packing indicators",
                description="Assess whether the executable's high-entropy sections indicate packing or protection.",
                reason="Structural PE analysis found a high-entropy executable section.",
                capabilities=("detect_packer", "extract_strings"),
            )
        return InvestigationObjective(
            name="Characterize sample",
            description="Identify the artifact and characterize its executable structure.",
            reason="No evidence has yet established the sample's structure.",
            capabilities=("file_info", "analyze_pe"),
        )
