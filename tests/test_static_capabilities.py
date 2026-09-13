import struct
import tempfile
import unittest
from pathlib import Path

from mira.core.artifact import ArtifactStore, detect_file_type
from mira.capabilities.static.file_info import analyze_file_info
from mira.capabilities.static.string_analyzer import extract_strings
from mira.mcp.client import StaticMCPClient
from mira.mcp.isolation import AnalysisLimits, ExecutionResult
from mira.mcp.servers.static.server import StaticMCPServer


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


def build_minimal_pe() -> bytes:
    """A real enough PE32 that pefile parses it and PE capabilities run."""
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    optional = struct.pack("<HBBIIIII", 0x10B, 1, 0, 0x200, 0, 0, 0x1000, 0x1000)
    optional += struct.pack("<II", 0x400000, 0x1000)
    optional += struct.pack("<I", 0x200) + b"\x00" * (0xE0 - len(optional) - 4)
    section = (
        b".text\x00\x00\x00"
        + struct.pack("<IIII", 0x200, 0x1000, 0x200, 0x400)
        + b"\x00" * 12
        + struct.pack("<I", 0x60000020)
    )
    head = dos + b"PE\x00\x00" + coff + optional + section
    return head + b"\x00" * (0x400 - len(head)) + b"\x90" * 0x200


class ContractConformanceTests(unittest.IsolatedAsyncioTestCase):
    """Handlers must satisfy the output contracts the server advertises.

    The server rejects a drifting payload with CONTRACT_VIOLATION, so this
    fails the moment a handler and its contract disagree.
    """

    PE_CAPABILITIES = (
        "file_info",
        "analyze_pe",
        "list_imports",
        "list_exports",
        "extract_strings",
        "calculate_entropy",
        "detect_packer",
        "list_functions",
    )

    def test_a_pe_is_recognized_as_a_pe(self):
        """Everything PE-only is unreachable if this returns 'unknown'."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact_path = Path(temporary_directory) / "sample.exe"
            artifact_path.write_bytes(build_minimal_pe())

            self.assertEqual(detect_file_type(artifact_path), "pe")

    async def test_real_handlers_match_their_declared_output(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact_path = Path(temporary_directory) / "sample.exe"
            artifact_path.write_bytes(build_minimal_pe())
            store = ArtifactStore(temporary_directory)
            store.register("pe-1", artifact_path)
            server = StaticMCPServer(store)

            for capability in self.PE_CAPABILITIES:
                result = await server.call(capability, {"artifact_id": "pe-1"})
                code = (result.get("error") or {}).get("code")
                self.assertNotEqual(
                    code, "CONTRACT_VIOLATION", f"{capability}: {result.get('error')}"
                )
                self.assertEqual(result["status"], "ok", capability)


if __name__ == "__main__":
    unittest.main()
