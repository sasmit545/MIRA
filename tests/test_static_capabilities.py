import tempfile
import unittest
from pathlib import Path

from mira.core.artifact import ArtifactStore
from mira.capabilities.static.file_info import analyze_file_info
from mira.capabilities.static.string_analyzer import extract_strings
from mira.mcp.client import StaticMCPClient
from mira.mcp.isolation import AnalysisLimits, ExecutionResult
from mira.mcp.servers.static_server import StaticMCPServer


class FileInfoTests(unittest.TestCase):
    def test_file_info_reports_hashes_and_entropy_for_registered_artifact(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact_path = Path(temporary_directory) / "sample.bin"
            artifact_path.write_bytes(b"MZ" + b"A" * 128)
            store = ArtifactStore(temporary_directory)
            artifact = store.register("sample-1", artifact_path)

            result = analyze_file_info(artifact)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["data"]["size"], 130)
        self.assertEqual(
            result["data"]["sha256"],
            "b12a51f310beb524171f4549e37bd450188920698f24a7b04e25e56dd5ea2ffc",
        )
        self.assertEqual(result["metadata"]["artifact_id"], "sample-1")

    def test_string_results_are_paginated(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact_path = Path(temporary_directory) / "sample.bin"
            artifact_path.write_bytes(b"one-string\x00second-string\x00third-string")
            artifact = ArtifactStore(temporary_directory).register("sample-2", artifact_path)

            result = extract_strings(artifact, min_length=4, limit=2)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(result["data"]["strings"]), 2)
        self.assertTrue(result["metadata"]["has_more"])

class AsyncServerTests(unittest.IsolatedAsyncioTestCase):
    def test_analysis_limits_reject_invalid_configuration(self):
        with self.assertRaises(ValueError):
            AnalysisLimits(max_concurrent=0)

    async def test_server_runs_registered_artifact_in_an_isolated_worker(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact_path = Path(temporary_directory) / "sample.bin"
            artifact_path.write_bytes(b"test")
            store = ArtifactStore(temporary_directory)
            store.register("known", artifact_path)
            client = StaticMCPClient(StaticMCPServer(store))

            result = await client.invoke("file_info", artifact_id="known")

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["data"]["size"], 4)

    async def test_server_translates_worker_timeout_to_standard_envelope(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact_path = Path(temporary_directory) / "sample.bin"
            artifact_path.write_bytes(b"test")
            store = ArtifactStore(temporary_directory)
            store.register("known", artifact_path)
            server = StaticMCPServer(store, runner=lambda job, limits: ExecutionResult("timeout"))

            result = await server.call("file_info", {"artifact_id": "known"})

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error"]["code"], "TIMEOUT")

    async def test_server_rejects_unknown_artifacts_without_accepting_paths(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact_path = Path(temporary_directory) / "sample.bin"
            artifact_path.write_bytes(b"test")
            store = ArtifactStore(temporary_directory)
            store.register("known", artifact_path)
            client = StaticMCPClient(StaticMCPServer(store))
            result = await client.invoke("file_info", artifact_id="known", path="C:/Windows/not-allowed")

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error"]["code"], "INVALID_INPUT")


if __name__ == "__main__":
    unittest.main()
