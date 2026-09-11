"""Wiring that makes a reasoning run a *static* investigation.

Dynamic and Forensics will each need their own equivalent of this module —
their own capability manifest, their own client, their own role and scope.
None of it is shared, which is why it lives beside the specialist rather than
in the reasoning package.
"""

from __future__ import annotations

from pathlib import Path

from mira.core.artifact import ArtifactStore
from mira.mcp.capability_registry import STATIC_CAPABILITIES
from mira.mcp.client import StaticMCPClient
from mira.mcp.servers.static_server import StaticMCPServer
from mira.reasoning.contracts.tool import ToolSpec

ARTIFACT_ID = "sample"

STATIC_ROLE = "You are a static malware investigator."
STATIC_SCOPE = (
    "Static analysis only. The artifact under investigation is bound by the runtime, "
    "so tool arguments never need to name it."
)


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
    """Bind the artifact so the model never chooses which sample to analyze.

    Any model-supplied `artifact_id` is stripped and replaced with the real
    one, so a model cannot retarget another sample.
    """

    def execute(capability: str, arguments: dict):
        parameters = {**arguments}
        parameters.pop("artifact_id", None)
        return client.invoke(capability, artifact_id=artifact_id, **parameters)

    return execute
