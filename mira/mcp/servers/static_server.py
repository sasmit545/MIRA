"""Async, static-only MCP server facade with artifact-ID based access."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Callable

from mira.artifacts import ArtifactError, ArtifactStore
from mira.capabilities.static.common import result_error
from mira.mcp.capability_registry import STATIC_CAPABILITIES
from mira.mcp.isolation import AnalysisJob, AnalysisLimits, ExecutionResult, run_isolated
from pydantic import ValidationError


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

    async def capabilities(self) -> dict:
        return {
            name: {
                "name": definition.name,
                "description": definition.description,
                "category": definition.category,
                "supported_artifact_types": definition.supported_artifact_types,
                "input_schema": definition.input_schema,
                "output_schema": definition.output_schema,
            }
            for name, definition in STATIC_CAPABILITIES.items()
        }

    async def call(self, capability: str, payload: dict[str, Any]) -> dict:
        artifact, parameters, error = self._validate(capability, payload)
        if error:
            return error
        job = AnalysisJob(capability, artifact, parameters, self.rulesets)
        async with self._semaphore:
            execution = await asyncio.to_thread(self._runner, job, self.limits)
        if execution.status == "ok":
            if execution.response is None:
                return result_error(artifact.artifact_id, capability, "ANALYSIS_FAILED", "analysis returned no result")
            if "status" in execution.response:
                return execution.response
            return {"status": "ok", "data": execution.response}
        if execution.status == "timeout":
            return result_error(artifact.artifact_id, capability, "TIMEOUT", execution.message or "analysis timed out")
        if execution.status == "resource_limit":
            return result_error(artifact.artifact_id, capability, "RESOURCE_LIMIT", execution.message or "analysis resource limit exceeded")
        return result_error(artifact.artifact_id, capability, "ANALYSIS_FAILED", execution.message or "analysis worker failed")

    def _validate(self, capability: str, payload: dict[str, Any]) -> tuple[object | None, dict, dict | None]:
        if capability not in STATIC_CAPABILITIES:
            return None, {}, result_error(None, capability, "INVALID_INPUT", "capability is not registered")
        definition = STATIC_CAPABILITIES[capability]
        if not isinstance(payload, dict):
            return None, {}, result_error(None, capability, "INVALID_INPUT", "input must be an object")
        try:
            validated_input = definition.input_model(**payload)
        except ValidationError as e:
            return None, {}, result_error(None, capability, "INVALID_INPUT", _validation_message(e))
        artifact_id = validated_input.artifact_id
        try:
            artifact = self.artifact_store.get(artifact_id)
        except ArtifactError:
            return None, {}, result_error(artifact_id, capability, "ARTIFACT_NOT_FOUND", "artifact was not found")
        # Exclude artifact_id from parameters for the job
        parameters = validated_input.model_dump(exclude={"artifact_id", "contract_version"})
        return artifact, parameters, None


def _validation_message(error: ValidationError) -> str:
    """Translate Pydantic errors into stable messages for capability callers."""
    messages = []
    for item in error.errors():
        location = ".".join(str(part) for part in item["loc"])
        error_type = item["type"]
        if error_type == "missing":
            messages.append(f"{location} is required")
        elif error_type == "extra_forbidden":
            messages.append(f"{location} is not permitted")
        else:
            messages.append(f"{location}: {item['msg']}")
    return "; ".join(messages)

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
