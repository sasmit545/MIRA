"""
Integration tests for StaticAgent using contract models and mocked transport.
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock

from mira.agents.static_agent import StaticAgent
from mira.mcp.client import StaticMCPClient
from mira.contracts.requests import CapabilityRequest
from mira.contracts.results import CapabilityResult
from mira.contracts.capabilities.analyze_pe import AnalyzePEInput, AnalyzePEOutput, Section
from mira.contracts.capabilities.list_imports import ListImportsInput, ListImportsOutput


class MockTransport:
    """Mock transport that returns a predefined result."""
    def __init__(self):
        self.calls = []

    async def call(self, capability: str, payload: dict) -> dict:
        self.calls.append((capability, payload))
        # Return different results based on capability
        if capability == "analyze_pe":
            sec_dict = {
                "name": ".text",
                "virtual_address": 0x1000,
                "virtual_size": 0x200,
                "raw_data_pointer": 0x400,
                "raw_data_size": 0x200,
                "characteristics": 0x60000020,
            }
            return {
                "contract_version": "1.0",
                "request_id": payload["request_id"],
                "status": "ok",
                "data": {
                    "architecture": "x64",
                    "entry_point": 0x2000,
                    "image_base": 0x10000,
                    "sections": [sec_dict],
                },
                "error": None,
                "metadata": {},
            }
        elif capability == "list_imports":
            return {
                "contract_version": "1.0",
                "request_id": payload["request_id"],
                "status": "ok",
                "data": {
                    "entries": [],
                    "total": 0,
                    "limit": payload["input"]["limit"],
                    "offset": payload["input"]["offset"],
                },
                "error": None,
                "metadata": {},
            }
        else:
            return {
                "contract_version": "1.0",
                "request_id": payload["request_id"],
                "status": "error",
                "data": None,
                "error": {
                    "code": "UNSUPPORTED_CAPABILITY",
                    "message": f"Capability {capability} not implemented in mock",
                },
                "metadata": {},
            }

    async def capabilities(self) -> dict:
        return {}


@pytest.mark.asyncio
async def test_static_agent_analyze_pe():
    """Test that StaticAgent correctly invokes analyze_pe and returns typed result."""
    transport = MockTransport()
    client = StaticMCPClient(transport)
    agent = StaticAgent(client)

    result = await agent.analyze_pe("artifact_001")

    # Check that transport was called
    assert len(transport.calls) == 1
    capability, payload = transport.calls[0]
    assert capability == "analyze_pe"
    assert payload["request_id"] == "req_001"
    assert payload["capability"] == "analyze_pe"
    assert payload["input"]["artifact_id"] == "artifact_001"

    # Check result
    assert isinstance(result, CapabilityResult)
    assert result.request_id == "req_001"
    assert result.status == "ok"
    assert result.data is not None
    assert isinstance(result.data, AnalyzePEOutput)
    assert result.data.architecture == "x64"
    assert result.data.entry_point == 0x2000
    assert result.data.image_base == 0x10000
    assert len(result.data.sections) == 1
    assert result.data.sections[0].name == ".text"


@pytest.mark.asyncio
async def test_static_agent_list_imports():
    """Test that StaticAgent correctly invokes list_imports with pagination."""
    transport = MockTransport()
    client = StaticMCPClient(transport)
    agent = StaticAgent(client)

    result = await agent.list_imports("artifact_001", limit=50, offset=10)

    # Check that transport was called
    assert len(transport.calls) == 1
    capability, payload = transport.calls[0]
    assert capability == "list_imports"
    assert payload["request_id"] == "req_002"
    assert payload["capability"] == "list_imports"
    assert payload["input"]["artifact_id"] == "artifact_001"
    assert payload["input"]["limit"] == 50
    assert payload["input"]["offset"] == 10

    # Check result
    assert isinstance(result, CapabilityResult)
    assert result.request_id == "req_002"
    assert result.status == "ok"
    assert result.data is not None
    assert isinstance(result.data, ListImportsOutput)
    assert result.data.total == 0
    assert result.data.limit == 50
    assert result.data.offset == 10
    assert len(result.data.entries) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
