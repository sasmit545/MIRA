"""Static Agent client boundary; it does not import capabilities directly."""

from __future__ import annotations

from typing import Protocol, TypeVar

from mira.contracts.requests import CapabilityRequest
from mira.contracts.results import CapabilityResult

T = TypeVar('T')


class StaticCapabilityTransport(Protocol):
    async def call(self, capability: str, payload: dict) -> dict: ...

    async def capabilities(self) -> dict: ...


class StaticMCPClient:
    def __init__(self, transport: StaticCapabilityTransport):
        self._transport = transport

    async def discover_capabilities(self) -> dict:
        return await self._transport.capabilities()

    async def invoke_request(self, request: CapabilityRequest[T]) -> CapabilityResult[T]:
        """Invoke a capability with a contract request and return a contract result."""
        payload = request.model_dump()
        result_dict = await self._transport.call(request.capability, payload)
        return CapabilityResult[T].model_validate(result_dict)
