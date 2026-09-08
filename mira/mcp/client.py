"""Static Agent client boundary; it does not import capabilities directly."""

from __future__ import annotations

from typing import Protocol, TypeVar

from mira.contracts.requests import CapabilityRequest
from mira.contracts.results import CapabilityResult
from mira.mcp.capability_registry import STATIC_CAPABILITIES

T = TypeVar('T')


class StaticCapabilityTransport(Protocol):
    async def call(self, capability: str, payload: dict) -> dict: ...

    async def capabilities(self) -> dict: ...


class StaticMCPClient:
    def __init__(self, transport: StaticCapabilityTransport):
        self._transport = transport

    @property
    def server(self) -> StaticCapabilityTransport:
        """The configured transport, exposed as the client/server boundary."""
        return self._transport

    async def discover_capabilities(self) -> dict:
        return await self._transport.capabilities()

    async def invoke(self, capability: str, artifact_id: str, **kwargs) -> dict:
        """Invoke a capability using only a registered artifact identifier."""
        input_data = {"artifact_id": artifact_id, **kwargs}
        return await self.server.call(capability, input_data)

    async def invoke_request(self, request: CapabilityRequest[T]) -> CapabilityResult:
        """Invoke a capability with a contract request and return a contract result."""
        payload = request.model_dump()
        result_dict = await self._transport.call(request.capability, payload)
        if "request_id" not in result_dict:
            result_dict = {
                "request_id": request.request_id,
                "metadata": {},
                **result_dict,
            }
        output_model = STATIC_CAPABILITIES[request.capability].output_model
        return CapabilityResult[output_model].model_validate(result_dict)
