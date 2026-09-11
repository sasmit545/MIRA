"""
Integration tests for StaticMCPServer validation using contract models.
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from mira.mcp.servers.static_server import StaticMCPServer
from mira.core.artifact import ArtifactStore, ArtifactError
from mira.mcp.isolation import AnalysisJob, AnalysisLimits, ExecutionResult
from mira.contracts.capabilities.analyze_pe import AnalyzePEInput, AnalyzePEOutput
from mira.contracts.capabilities.list_imports import ListImportsInput, ListImportsOutput
from mira.contracts.errors import ARTIFACT_NOT_FOUND, INVALID_INPUT
from mira.mcp.capability_registry import STATIC_CAPABILITIES


class MockArtifactStore(ArtifactStore):
    def __init__(self):
        self._artifacts = {"artifact_001": MagicMock(artifact_id="artifact_001")}

    def get(self, artifact_id: str):
        if artifact_id not in self._artifacts:
            raise ArtifactError(f"Artifact {artifact_id} not found")
        return self._artifacts[artifact_id]


class MockRunner:
    def __init__(self, result: ExecutionResult = None):
        self.result = result or ExecutionResult(status="ok", response={"test": "data"})
        self.called_with = None

    def __call__(self, job: AnalysisJob, limits: AnalysisLimits) -> ExecutionResult:
        self.called_with = job
        return self.result


def test_static_server_validation_missing_artifact_id():
    """Test that server rejects requests missing artifact_id."""
    server = StaticMCPServer(MockArtifactStore())
    import asyncio

    async def run_test():
        # Missing artifact_id
        result = await server.call("analyze_pe", {})
        assert result["status"] == "error"
        assert result["error"]["code"] == INVALID_INPUT
        assert "artifact_id is required" in result["error"]["message"]

    asyncio.run(run_test())


def test_static_server_validation_unknown_artifact():
    """Test that server returns ARTIFACT_NOT_FOUND for unknown artifact."""
    server = StaticMCPServer(MockArtifactStore())
    import asyncio

    async def run_test():
        result = await server.call("analyze_pe", {"artifact_id": "unknown"})
        assert result["status"] == "error"
        assert result["error"]["code"] == ARTIFACT_NOT_FOUND
        assert "artifact was not found" in result["error"]["message"]

    asyncio.run(run_test())


def test_static_server_validation_invalid_capability():
    """Test that server rejects unknown capability."""
    server = StaticMCPServer(MockArtifactStore())
    import asyncio

    async def run_test():
        result = await server.call("unknown_capability", {"artifact_id": "artifact_001"})
        assert result["status"] == "error"
        assert result["error"]["code"] == INVALID_INPUT
        assert "capability is not registered" in result["error"]["message"]

    asyncio.run(run_test())


def test_static_server_validation_invalid_input():
    """Test that server validates input against contract model."""
    server = StaticMCPServer(MockArtifactStore())
    import asyncio

    async def run_test():
        # Provide invalid input (wrong type for a field if we had one)
        # For AnalyzePE, only artifact_id is required, so let's test with extra field
        result = await server.call("analyze_pe", {
            "artifact_id": "artifact_001",
            "extra_field": "should be forbidden"  # This should be caught by input model validation
        })
        # Actually, our current implementation passes extra fields to the job parameters
        # The validation happens in the input model, which for AnalyzePEInput only has artifact_id
        # So extra fields would be included in parameters. Let's check if they are forbidden.
        # Looking at the contract, we have extra = 'forbid' in the Config.
        # So the input model should reject extra fields.
        assert result["status"] == "error"
        assert result["error"]["code"] == INVALID_INPUT
        # Should contain validation error about extra field

    asyncio.run(run_test())


def test_static_server_valid_request():
    """Test that server processes valid request and calls runner."""
    server = StaticMCPServer(MockArtifactStore())
    mock_result = ExecutionResult(
        status="ok",
        response={
            "architecture": "x64",
            "entry_point": 0x2000,
            "image_base": 0x10000,
            "sections": [{
                "name": ".text",
                "virtual_address": 0x1000,
                "virtual_size": 0x200,
                "raw_data_pointer": 0x400,
                "raw_data_size": 0x200,
                "characteristics": 0x60000020,
            }]
        }
    )
    runner = MockRunner(mock_result)
    server._runner = runner
    import asyncio

    async def run_test():
        result = await server.call("analyze_pe", {
            "artifact_id": "artifact_001"
        })
        assert result["status"] == "ok"
        assert result["data"]["architecture"] == "x64"
        assert runner.called_with is not None
        assert runner.called_with.capability == "analyze_pe"
        assert runner.called_with.artifact.artifact_id == "artifact_001"
        # parameters should be empty for analyze_pe (only artifact_id)
        assert runner.called_with.parameters == {}

    asyncio.run(run_test())


def test_static_server_pagination_validation():
    """Test that pagination parameters are validated."""
    server = StaticMCPServer(MockArtifactStore())
    import asyncio

    async def run_test():
        # Test invalid limit (too high)
        result = await server.call("list_imports", {
            "artifact_id": "artifact_001",
            "limit": 1001  # max is 1000
        })
        assert result["status"] == "error"
        assert result["error"]["code"] == INVALID_INPUT

        # Test invalid offset (negative)
        result = await server.call("list_imports", {
            "artifact_id": "artifact_001",
            "offset": -1
        })
        assert result["status"] == "error"
        assert result["error"]["code"] == INVALID_INPUT

        # Test valid pagination
        mock_result = ExecutionResult(
            status="ok",
            response={
                "entries": [],
                "total": 0,
                "limit": 10,
                "offset": 0
            }
        )
        runner = MockRunner(mock_result)
        server._runner = runner
        
        result = await server.call("list_imports", {
            "artifact_id": "artifact_001",
            "limit": 10,
            "offset": 0
        })
        assert result["status"] == "ok"
        assert runner.called_with.parameters["limit"] == 10
        assert runner.called_with.parameters["offset"] == 0

    asyncio.run(run_test())


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
