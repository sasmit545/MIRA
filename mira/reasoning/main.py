"""Composition root: assemble the static investigator and run it on a sample.

This file is static-specific by nature — it names the static wiring and the
static role. Dynamic and Forensics will each get their own composition root;
what they share is `composition.py` and the loop beneath it.
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from mira.agents.static_wiring import (
    STATIC_ROLE,
    STATIC_SCOPE,
    build_client,
    build_executor,
    tool_manifest,
)

from .composition import (
    DEFAULT_MAX_TOOL_CALLS,
    DEFAULT_MAX_TURNS,
    build_loop,
    build_tracer,
    load_env,
)
from .contracts.objective import Objective
from .contracts.output import FinalOutput
from .definition.agent import AgentDefinition
from .runtime.tool_runtime import ToolRuntime


async def investigate(
    sample_path: Path,
    objective_text: str,
    *,
    trace_dir: Path,
    model=None,
    max_turns: int = DEFAULT_MAX_TURNS,
    max_tool_calls: int = DEFAULT_MAX_TOOL_CALLS,
) -> FinalOutput:
    """Compose the static agent and run one investigation.

    `model` defaults to the real provider adapter; tests inject a scripted one.
    """
    client, artifact_id = build_client(sample_path)
    manifest = tool_manifest()

    agent_def = AgentDefinition(
        role=STATIC_ROLE,
        scope=STATIC_SCOPE,
        instructions="Static malware investigator.",
        tool_manifest=manifest,
        allowed_tools=manifest,
        max_turns=max_turns,
        max_tool_calls=max_tool_calls,
        output_contract=FinalOutput,
    )

    loop = build_loop(
        tool_runtime=ToolRuntime(manifest, build_executor(client, artifact_id)),
        tracer=build_tracer(run_id=sample_path.stem, trace_dir=trace_dir),
        model=model,
    )
    return await loop.run(Objective(description=objective_text), agent_def)


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
