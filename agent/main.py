"""Composition root: assemble the static investigator and run it on a sample."""

from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path

from mira.core.artifact import ArtifactStore
from mira.mcp.capability_registry import STATIC_CAPABILITIES
from mira.mcp.client import StaticMCPClient
from mira.mcp.servers.static_server import StaticMCPServer

from .contracts.objective import Objective
from .contracts.output import FinalOutput
from .contracts.tool import ToolSpec
from .definition.agent import StaticAgentDefinition
from .model.adapter import ModelAdapter
from .runtime.completion import CompletionChecker
from .runtime.context import ContextBuilder
from .runtime.loop import AgentLoop
from .runtime.tool_runtime import ToolRuntime
from .runtime.trace import Tracer

ARTIFACT_ID = "sample"
DEFAULT_MAX_TURNS = 10
DEFAULT_MAX_TOOL_CALLS = 20


def load_env(path: Path = Path(".env")) -> None:
    """Populate os.environ from a .env file. Real env vars win."""
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        os.environ.setdefault(name.strip(), value.strip().strip("\"'"))


def tool_manifest() -> list[ToolSpec]:
    """Expose the registered MCP capabilities as tool specs for the model."""
    return [
        ToolSpec(
            name=definition.name,
            description=definition.description,
            parameters=definition.input_schema,
        )
        for definition in STATIC_CAPABILITIES.values()
    ]


def build_client(sample_path: Path) -> tuple[StaticMCPClient, str]:
    """Register the sample and return a client bound to its store."""
    store = ArtifactStore(sample_path.parent)
    store.register(ARTIFACT_ID, sample_path)
    return StaticMCPClient(StaticMCPServer(store)), ARTIFACT_ID


def build_executor(client: StaticMCPClient, artifact_id: str):
    """Bind the artifact so the model never chooses which sample to analyze."""

    def execute(capability: str, arguments: dict):
        parameters = {**arguments}
        parameters.pop("artifact_id", None)
        return client.invoke(capability, artifact_id=artifact_id, **parameters)

    return execute


async def investigate(
    sample_path: Path,
    objective_text: str,
    *,
    trace_dir: Path,
    model=None,
    max_turns: int = DEFAULT_MAX_TURNS,
    max_tool_calls: int = DEFAULT_MAX_TOOL_CALLS,
) -> FinalOutput:
    """Compose the agent and run one investigation.

    `model` defaults to the real provider adapter; tests inject a scripted one.
    """
    client, artifact_id = build_client(sample_path)
    manifest = tool_manifest()

    agent_def = StaticAgentDefinition(
        instructions="Static malware investigator.",
        tool_manifest=manifest,
        allowed_tools=manifest,
        max_turns=max_turns,
        max_tool_calls=max_tool_calls,
        output_contract=FinalOutput,
    )
    objective = Objective(description=objective_text)

    loop = AgentLoop(
        model_adapter=model or ModelAdapter(),
        tool_runtime=ToolRuntime(manifest, build_executor(client, artifact_id)),
        completion_checker=CompletionChecker(),
        context_builder=ContextBuilder(),
        tracer=Tracer(run_id=sample_path.stem, output_dir=str(trace_dir)),
    )
    return await loop.run(objective, agent_def)


def main() -> None:
    load_env()
    parser = argparse.ArgumentParser(description="Investigate a sample with the static agent.")
    parser.add_argument("sample", type=Path, help="path to the sample to investigate")
    parser.add_argument("--objective", default="Identify suspicious behavior")
    parser.add_argument("--trace-dir", type=Path, default=Path("runs"))
    parser.add_argument("--max-turns", type=int, default=DEFAULT_MAX_TURNS)
    parser.add_argument("--max-tool-calls", type=int, default=DEFAULT_MAX_TOOL_CALLS)
    arguments = parser.parse_args()

    output = asyncio.run(
        investigate(
            arguments.sample.resolve(),
            arguments.objective,
            trace_dir=arguments.trace_dir,
            max_turns=arguments.max_turns,
            max_tool_calls=arguments.max_tool_calls,
        )
    )

    print(f"verdict:   {output.verdict}")
    print(f"reason:    {output.completion_reason}")
    print(f"summary:   {output.summary}")
    print(f"findings:  {len(output.findings)}")
    print(f"metadata:  {output.metadata}")


if __name__ == "__main__":
    main()
