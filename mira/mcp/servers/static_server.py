"""Async, static-only MCP server facade with artifact-ID based access."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Callable

from mira.artifacts import ArtifactError, ArtifactStore
from mira.capabilities.static.common import result_error
from mira.mcp.capability_registry import STATIC_CAPABILITIES
from mira.mcp.isolation import AnalysisJob, AnalysisLimits, ExecutionResult, run_isolated


class StaticMCPServer:
    """Validates requests then executes each analysis in an isolated process."""

    def __init__(
        self,
        artifact_store: ArtifactStore,
        *,
        rulesets: dict[str, Path] | None = None,
        limits: AnalysisLimits | None = None,
        runner: Callable[[AnalysisJob, AnalysisLimits], ExecutionResult] = run_isolated,
    ):
        self.artifact_store = artifact_store
        self.rulesets = rulesets or {}
        self.limits = limits or AnalysisLimits()
        self._runner = runner
        self._semaphore = asyncio.Semaphore(self.limits.max_concurrent)
        self._parameters = {
            name: set(definition.input_schema) - {"artifact_id"}
            for name, definition in STATIC_CAPABILITIES.items()
        }

    async def capabilities(self) -> dict:
        return {name: definition.__dict__ for name, definition in STATIC_CAPABILITIES.items()}

    async def call(self, capability: str, payload: dict[str, Any]) -> dict:
        artifact, parameters, error = self._validate(capability, payload)
        if error:
            return error
        job = AnalysisJob(capability, artifact, parameters, self.rulesets)
        async with self._semaphore:
            execution = await asyncio.to_thread(self._runner, job, self.limits)
        if execution.status == "ok":
            return execution.response or result_error(artifact.artifact_id, capability, "ANALYSIS_FAILED", "analysis returned no result")
        if execution.status == "timeout":
            return result_error(artifact.artifact_id, capability, "TIMEOUT", execution.message or "analysis timed out")
        if execution.status == "resource_limit":
            return result_error(artifact.artifact_id, capability, "RESOURCE_LIMIT", execution.message or "analysis resource limit exceeded")
        return result_error(artifact.artifact_id, capability, "ANALYSIS_FAILED", execution.message or "analysis worker failed")

    def _validate(self, capability: str, payload: dict[str, Any]) -> tuple[object | None, dict, dict | None]:
        if capability not in STATIC_CAPABILITIES:
            return None, {}, result_error(None, capability, "INVALID_INPUT", "capability is not registered")
        if not isinstance(payload, dict) or not isinstance(payload.get("artifact_id"), str):
            artifact_id = payload.get("artifact_id") if isinstance(payload, dict) else None
            return None, {}, result_error(artifact_id, capability, "INVALID_INPUT", "artifact_id is required")
        try:
            artifact = self.artifact_store.get(payload["artifact_id"])
        except ArtifactError:
            return None, {}, result_error(payload["artifact_id"], capability, "ARTIFACT_NOT_FOUND", "artifact was not found")
        parameters = {key: value for key, value in payload.items() if key != "artifact_id"}
        unexpected = parameters.keys() - self._parameters[capability]
        if unexpected:
            message = f"unsupported parameter(s): {', '.join(sorted(unexpected))}"
            return None, {}, result_error(artifact.artifact_id, capability, "INVALID_INPUT", message)
        return artifact, parameters, None

def build_fastmcp(server: StaticMCPServer):
    """Create an app whose FastMCP handlers await isolated capability work."""
    try:
        from fastmcp import FastMCP
    except ImportError as error:
        raise RuntimeError("FastMCP is not installed; install project dependencies first") from error
    app = FastMCP("MIRA Static Analysis")
    for capability in STATIC_CAPABILITIES:
        app.tool()(make_tool(server, capability))
    return app


def make_tool(server: StaticMCPServer, capability: str):
    async def tool(payload: dict) -> dict:
        return await server.call(capability, payload)

    tool.__name__ = capability
    return tool
