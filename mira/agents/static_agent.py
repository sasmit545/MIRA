"""Local static investigation loop driven by the assigned objective."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class StaticClient(Protocol):
    async def invoke(self, capability: str, **payload: object) -> dict: ...


@dataclass(frozen=True)
class StaticObjective:
    name: str
    description: str
    reason: str


@dataclass(frozen=True)
class StaticFinding:
    objective: StaticObjective
    evidence: list[dict]
    capability_results: list[dict]


class StaticAgent:
    """Chooses a small, objective-specific sequence of MCP capabilities."""

    def __init__(self, client: StaticClient):
        self.client = client

    async def investigate(self, objective: StaticObjective, artifact_id: str) -> StaticFinding:
        capabilities = self._select_capabilities(objective)
        results = []
        for capability in capabilities:
            results.append(await self.client.invoke(capability, artifact_id=artifact_id))
        evidence = [
            observation
            for capability, result in zip(capabilities, results, strict=True)
            for observation in self._interpret(capability, result, artifact_id)
        ]
        return StaticFinding(objective=objective, evidence=evidence, capability_results=results)

    @staticmethod
    def _select_capabilities(objective: StaticObjective) -> tuple[str, ...]:
        if objective.name == "Characterize sample":
            return ("file_info", "analyze_pe")
        if objective.name == "Assess packing indicators":
            return ("detect_packer", "extract_strings")
        return ("file_info",)

    @staticmethod
    def _interpret(capability: str, result: dict, artifact_id: str) -> list[dict]:
        if result.get("status") != "ok":
            return []
        data = result["data"]
        evidence = []
        if capability == "file_info" and data.get("entropy", 0) >= 7.2:
            evidence.append({"kind": "high_entropy_file", "artifact_id": artifact_id, "capability": capability, "confidence": 0.7, "observation": "Whole-file entropy is high."})
        if capability == "analyze_pe":
            for section in data.get("sections", []):
                if section.get("entropy", 0) >= 7.2:
                    evidence.append({"kind": "high_entropy_executable_section", "artifact_id": artifact_id, "capability": capability, "confidence": 0.8, "observation": f"Section {section.get('name', '<unnamed>')} has high entropy."})
        if capability == "detect_packer" and data.get("packed"):
            evidence.append({"kind": "packing_indicator", "artifact_id": artifact_id, "capability": capability, "confidence": data.get("confidence", 0.5), "observation": "; ".join(data.get("indicators", [])) or "Packing indicators detected."})
        return evidence
