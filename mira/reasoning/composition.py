"""Generic assembly helpers every specialist's composition root reuses.

Nothing here knows which specialist is being built. The static, dynamic, and
forensic wiring each live beside their own specialist.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .model.adapter import ModelAdapter
from .runtime.completion import CompletionChecker
from .runtime.context import ContextBuilder
from .runtime.loop import AgentLoop
from .runtime.tool_runtime import ToolRuntime
from .runtime.trace import Tracer

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


def build_run_id(artifact_id: str, objective: str) -> str:
    """Name one run, from its inputs alone.

    Stable across processes, and distinct per objective so two objectives on
    one artifact don't overwrite each other's trace. Slugified because this
    value becomes a filename.
    """
    slug = re.sub(r"[^a-z0-9]+", "_", objective.lower()).strip("_")
    return f"{artifact_id}_{slug}"


def build_tracer(run_id: str, trace_dir: Path) -> Tracer:
    """Record this run's turns under `trace_dir`."""
    return Tracer(run_id=run_id, output_dir=str(trace_dir))


def build_loop(
    tool_runtime: ToolRuntime,
    tracer: Tracer,
    model=None,
    on_turn=None,
) -> AgentLoop:
    """Assemble the reasoning loop.

    `model` defaults to the real provider adapter; callers inject a scripted
    one in tests. The adapter is only constructed when no model is supplied,
    so a scripted run needs no API key. `on_turn`, when given, is called with
    an event dict after every turn - a live view for a CLI.
    """
    return AgentLoop(
        model_adapter=model or ModelAdapter(),
        tool_runtime=tool_runtime,
        completion_checker=CompletionChecker(),
        context_builder=ContextBuilder(),
        tracer=tracer,
        on_turn=on_turn,
    )
