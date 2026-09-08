"""Static Analysis Agent using MCP contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mira.mcp.client import StaticMCPClient
from mira.contracts.requests import CapabilityRequest
from mira.contracts.results import CapabilityResult
from mira.contracts.capabilities.analyze_pe import AnalyzePEInput, AnalyzePEOutput
from mira.contracts.capabilities.list_imports import ListImportsInput, ListImportsOutput


@dataclass(frozen=True)
class StaticObjective:
    """A static-analysis task selected by the coordinator."""

    name: str
    description: str
    reason: str
    capabilities: tuple[str, ...] = ()


@dataclass(frozen=True)
class StaticFinding:
    """Results and normalized evidence produced while pursuing one objective."""

    objective: StaticObjective
    results: dict[str, dict]
    evidence: list[dict]


class StaticAgent:
    """Example static analysis agent that uses MCP contracts."""

    def __init__(self, client: StaticMCPClient):
        self._client = client

    async def analyze_pe(self, artifact_id: str) -> CapabilityResult[AnalyzePEOutput]:
        """Invoke the analyze_pe capability."""
        request = CapabilityRequest[AnalyzePEInput](
            request_id="req_001",  # In practice, generate a unique ID
            capability="analyze_pe",
            input=AnalyzePEInput(artifact_id=artifact_id)
        )
        return await self._client.invoke_request(request)

    async def list_imports(self, artifact_id: str, limit: int = 100, offset: int = 0) -> CapabilityResult[ListImportsOutput]:
        """Invoke the list_imports capability."""
        request = CapabilityRequest[ListImportsInput](
            request_id="req_002",
            capability="list_imports",
            input=ListImportsInput(artifact_id=artifact_id, limit=limit, offset=offset)
        )
        return await self._client.invoke_request(request)

    async def investigate(self, objective: StaticObjective, artifact_id: str) -> StaticFinding:
        """Execute an objective's declared capabilities and normalize their evidence."""
        results: dict[str, dict] = {}
        evidence: list[dict] = []
        for capability in objective.capabilities:
            result = await self._client.invoke(capability, artifact_id=artifact_id)
            results[capability] = result
            evidence.extend(self._evidence_from_result(capability, artifact_id, result))
        return StaticFinding(objective=objective, results=results, evidence=evidence)

    @staticmethod
    def _evidence_from_result(capability: str, artifact_id: str, result: dict) -> list[dict]:
        """Turn capability output into the evidence shape used by the coordinator."""
        if result.get("status") != "ok":
            return []

        data: dict[str, Any] = result.get("data") or {}
        if capability == "analyze_pe":
            return [
                {
                    "kind": "high_entropy_executable_section",
                    "artifact_id": artifact_id,
                    "capability": capability,
                    "section": section.get("name"),
                    "entropy": section["entropy"],
                }
                for section in data.get("sections", [])
                if section.get("entropy", 0) >= 7.2
            ]
        if capability == "detect_packer" and (data.get("packed") or data.get("indicators")):
            return [
                {
                    "kind": "packing_indicator",
                    "artifact_id": artifact_id,
                    "capability": capability,
                    "packed": bool(data.get("packed")),
                    "indicators": data.get("indicators", []),
                }
            ]
        return []
