"""Static Agent client boundary; it does not import capabilities directly."""

from __future__ import annotations

from typing import Protocol


class StaticCapabilityTransport(Protocol):
    async def call(self, capability: str, payload: dict) -> dict: ...

    async def capabilities(self) -> dict: ...


class StaticMCPClient:
    def __init__(self, transport: StaticCapabilityTransport):
        self._transport = transport

    async def discover_capabilities(self) -> dict:
        return await self._transport.capabilities()

    async def invoke(self, capability: str, **payload: object) -> dict:
        return await self._transport.call(capability, payload)
