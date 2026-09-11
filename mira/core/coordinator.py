"""Minimal coordinator that assigns Static Agent objectives only."""

from __future__ import annotations

from mira.agents.static_agent import InvestigationObjective


class StaticCoordinator:
    """Chooses the next static objective from accumulated evidence."""

    def select_next_objective(self, evidence: list[dict]) -> InvestigationObjective:
        if any(item.get("kind") == "high_entropy_executable_section" for item in evidence):
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
