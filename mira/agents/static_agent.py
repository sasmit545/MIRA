"""Static Analysis Agent using MCP contracts."""

from __future__ import annotations

from mira.mcp.client import StaticMCPClient
from mira.contracts.requests import CapabilityRequest
from mira.contracts.results import CapabilityResult
from mira.contracts.capabilities.analyze_pe import AnalyzePEInput, AnalyzePEOutput
from mira.contracts.capabilities.list_imports import ListImportsInput, ListImportsOutput


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

    # Add more methods for other capabilities as needed
