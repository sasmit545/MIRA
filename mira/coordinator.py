"""Minimal coordinator that assigns Static Agent objectives only."""

from __future__ import annotations

from mira.agents.static_agent import StaticObjective


class StaticCoordinator:
    """Chooses the next static objective from accumulated evidence."""

    def select_next_objective(self, evidence: list[dict]) -> StaticObjective:
        if any(item.get("kind") == "high_entropy_executable_section" for item in evidence):
            return StaticObjective(
                name="Assess packing indicators",
                description="Assess whether the executable's high-entropy sections indicate packing or protection.",
                reason="Structural PE analysis found a high-entropy executable section.",
                capabilities=("detect_packer", "extract_strings"),
            )
        return StaticObjective(
            name="Characterize sample",
            description="Identify the artifact and characterize its executable structure.",
            reason="No evidence has yet established the sample's structure.",
            capabilities=("file_info", "analyze_pe"),
        )
