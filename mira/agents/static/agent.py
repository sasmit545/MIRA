"""Static Analysis Agent using MCP contracts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mira.agents.base import InvestigationFinding
from mira.agents.static.wiring import (
    STATIC_ROLE,
    STATIC_SCOPE,
    build_executor,
    tool_manifest,
)
from mira.contracts.capabilities.static.analyze_pe import AnalyzePEInput, AnalyzePEOutput
from mira.contracts.capabilities.static.list_imports import ListImportsInput, ListImportsOutput
from mira.contracts.requests import CapabilityRequest
from mira.contracts.results import CapabilityResult
from mira.core.objective import InvestigationObjective
from mira.mcp.client import StaticMCPClient
from mira.reasoning.composition import (
    DEFAULT_MAX_TOOL_CALLS,
    DEFAULT_MAX_TURNS,
    build_loop,
    build_run_id,
    build_tracer,
)
from mira.reasoning.contracts.objective import Objective as LoopObjective
from mira.reasoning.contracts.output import FinalOutput
from mira.reasoning.definition.agent import AgentDefinition
from mira.reasoning.runtime.tool_runtime import ToolRuntime


class StaticAgent:
    """The static specialist.

    The Coordinator decides *what* to investigate by assigning an objective;
    the reasoning loop decides *how*, choosing capabilities from the ones that
    objective permits.
    """

    def __init__(
        self,
        client: StaticMCPClient,
        *,
        model=None,
        trace_dir: Path = Path("runs"),
        max_turns: int = DEFAULT_MAX_TURNS,
        max_tool_calls: int = DEFAULT_MAX_TOOL_CALLS,
    ):
        self._client = client
        self._model = model
        self._trace_dir = Path(trace_dir)
        self._max_turns = max_turns
        self._max_tool_calls = max_tool_calls

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

    async def investigate(
        self, objective: InvestigationObjective, artifact_id: str
    ) -> InvestigationFinding:
        """Pursue one objective, letting the model choose within its capabilities.

        Only the objective's capabilities reach the runtime, so a capability
        the Coordinator did not authorize is refused rather than executed.
        """
        results: dict[str, dict] = {}
        evidence: list[dict] = []
        invoke = build_executor(self._client, artifact_id)

        async def execute(capability: str, arguments: dict):
            result = await invoke(capability, arguments)
            results[capability] = result
            evidence.extend(self._evidence_from_result(capability, artifact_id, result))
            return result

        manifest = tool_manifest()
        permitted = [spec for spec in manifest if spec.name in objective.capabilities]

        agent_definition = AgentDefinition(
            role=STATIC_ROLE,
            scope=STATIC_SCOPE,
            tool_manifest=manifest,
            allowed_tools=permitted,
            max_turns=self._max_turns,
            max_tool_calls=self._max_tool_calls,
            output_contract=FinalOutput,
        )
        loop = build_loop(
            tool_runtime=ToolRuntime(permitted, execute),
            tracer=build_tracer(
                run_id=build_run_id(artifact_id, objective.name),
                trace_dir=self._trace_dir,
            ),
            model=self._model,
        )

        output = await loop.run(
            LoopObjective(description=objective.description), agent_definition
        )
        return InvestigationFinding(
            objective=objective, results=results, evidence=evidence, output=output
        )

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
