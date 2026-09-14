"""Static Analysis Agent using MCP contracts."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from mira.agents.base import InvestigationFinding
from mira.agents.static.evidence import normalize
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
from mira.core.evidence import Evidence
from mira.core.objective import InvestigationObjective
from mira.core.state import InvestigationState
from mira.mcp.client import StaticMCPClient
from mira.reasoning.composition import (
    DEFAULT_MAX_TOOL_CALLS,
    DEFAULT_MAX_TURNS,
    build_loop,
    build_run_id,
    build_tracer,
)
from mira.reasoning.contracts.finding import Confidence, Finding, Severity
from mira.reasoning.contracts.objective import Objective as LoopObjective
from mira.reasoning.contracts.output import FinalOutput
from mira.reasoning.definition.agent import AgentDefinition
from mira.reasoning.runtime.tool_runtime import ToolRuntime
from mira.reasoning.runtime.trace import trace_provenance

SOURCE_AGENT = "static"

# Enum declaration order is ascending, so it doubles as the ranking.
_SEVERITY_RANK = {member: rank for rank, member in enumerate(Severity)}
_CONFIDENCE_RANK = {member: rank for rank, member in enumerate(Confidence)}


def _overall_confidence(findings: list[Finding]) -> Confidence:
    """The specialist is as confident as it is in its most serious claim.

    Not the highest confidence anywhere: a certain INFO finding says nothing
    about how sure the specialist is of the thing that actually matters.
    """
    if not findings:
        return Confidence.LOW
    gravest = max(
        findings,
        key=lambda finding: (
            _SEVERITY_RANK[finding.severity],
            _CONFIDENCE_RANK[finding.confidence],
        ),
    )
    return gravest.confidence


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
        self,
        objective: InvestigationObjective,
        artifact_id: str,
        state: InvestigationState | None = None,
    ) -> InvestigationFinding:
        """Pursue one objective, letting the model choose within its capabilities.

        Only the objective's capabilities reach the runtime, so a capability
        the Coordinator did not authorize is refused rather than executed.

        `state`, when given, is the shared investigation state this run
        deposits its evidence into. Without one the run behaves exactly as
        before, which is what the CLI path wants.
        """
        results: dict[str, dict] = {}
        evidence: list[Evidence] = []
        run_id = build_run_id(artifact_id, objective.name)
        invoke = build_executor(self._client, artifact_id)
        # The specialist is the one place that sees every result in order, so
        # it is where evidence identifiers are minted (KTD1). Positions are
        # counted per capability: the runtime refuses a capability outside the
        # objective before it reaches this executor, yet the refusal still
        # reaches the trace, so a single run-wide counter drifts from it.
        occurrences: Counter[str] = Counter()
        # Numbering continues past whatever the shared state already holds:
        # two runs both minting "E1" would leave their findings citing an
        # identifier the orchestrator cannot resolve to one observation.
        minted = len(state.evidence) if state is not None else 0

        async def execute(capability: str, arguments: dict):
            result = await invoke(capability, arguments)
            provenance = trace_provenance(run_id, capability, occurrences[capability])
            occurrences[capability] += 1
            # `results` is deliberately read before this result joins it: a
            # normalizer's `prior` is what earlier capabilities reported.
            for signal in normalize(capability, result, results):
                item = Evidence(
                    id=f"E{minted + len(evidence) + 1}",
                    observation=signal.observation,
                    source_agent=SOURCE_AGENT,
                    capability=capability,
                    artifact_id=artifact_id,
                    confidence=signal.confidence,
                    provenance=provenance,
                )
                evidence.append(item)
                if state is not None:
                    # add_evidence already logs the change into its history.
                    state.add_evidence(item)
            results[capability] = result
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
            tracer=build_tracer(run_id=run_id, trace_dir=self._trace_dir),
            model=self._model,
        )

        output = await loop.run(
            LoopObjective(description=objective.description),
            agent_definition,
            evidence=evidence,
        )
        return InvestigationFinding(
            artifact_id=artifact_id,
            # The verdict leads the assessment rather than taking a field of
            # its own: section 10's payload names an assessment, and a reader
            # needs the judgement in the sentence they are given.
            assessment=f"{output.verdict}: {output.summary}",
            findings=output.findings,
            # The loop already reduced the shared accumulator to identifiers.
            evidence_refs=output.evidence,
            confidence=_overall_confidence(output.findings),
            recommended_actions=output.recommended_actions,
        )

