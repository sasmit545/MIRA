"""
Integration tests for MCP contract flow.
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from mira.mcp.client import StaticMCPClient
from mira.contracts.requests import CapabilityRequest
from mira.contracts.results import CapabilityResult
from mira.contracts.capabilities.analyze_pe import AnalyzePEInput, AnalyzePEOutput, Section


class MockTransport:
    """Mock transport that returns a predefined result."""
    def __init__(self, result_dict: dict):
        self.result_dict = result_dict
        self.called_with = None

    async def call(self, capability: str, payload: dict) -> dict:
        self.called_with = (capability, payload)
        return self.result_dict

    async def capabilities(self) -> dict:
        return {}


@pytest.mark.asyncio
async def test_mcp_client_invokes_analyze_pe():
    """Test that the client correctly invokes a capability and returns a typed result."""
    # Prepare a mock result dict that matches AnalyzePEOutput
    sec_dict = {
        "name": ".text",
        "virtual_address": 0x1000,
        "virtual_size": 0x200,
        "raw_data_pointer": 0x400,
        "raw_data_size": 0x200,
        "characteristics": 0x60000020,
    }
    result_dict = {
        "contract_version": "1.0",
        "request_id": "req_001",
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

    transport = MockTransport(result_dict)
    client = StaticMCPClient(transport)

    # Create a request
    request = CapabilityRequest[AnalyzePEInput](
        request_id="req_001",
        capability="analyze_pe",
        input=AnalyzePEInput(artifact_id="artifact_001"),
    )

    # Invoke the capability
    result = await client.invoke_request(request)

    # Check that the transport was called with the correct capability and payload
    assert transport.called_with is not None
    capability, payload = transport.called_with
    assert capability == "analyze_pe"
    assert payload == request.model_dump()

    # Check that the result is correctly typed and validated
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
async def test_mcp_client_handles_error():
    """Test that the client correctly handles an error result."""
    error_dict = {
        "contract_version": "1.0",
        "request_id": "req_002",
        "status": "error",
        "data": None,
        "error": {
            "code": "ARTIFACT_NOT_FOUND",
            "message": "Artifact not found",
            "details": {"artifact_id": "unknown"},
        },
        "metadata": {},
    }

    transport = MockTransport(error_dict)
    client = StaticMCPClient(transport)

    request = CapabilityRequest[AnalyzePEInput](
        request_id="req_002",
        capability="analyze_pe",
        input=AnalyzePEInput(artifact_id="unknown"),
    )

    result = await client.invoke_request(request)

    assert result.status == "error"
    assert result.error is not None
    assert result.error.code == "ARTIFACT_NOT_FOUND"
    assert result.data is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
