import json
import tempfile
import unittest
from pathlib import Path

from support import build_minimal_pe

from mira.core.artifact import ArtifactStore, detect_file_type
from mira.capabilities.static.entropy_analyzer import calculate_entropy
from mira.capabilities.static.file_info import analyze_file_info
from mira.capabilities.static.pe_analyzer import analyze_pe
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


class PESupportTests(unittest.TestCase):
    def test_a_pe_handler_does_not_hold_the_sample_open(self):
        # pefile.PE(name=path) used to mmap the file and never release it,
        # which on Windows blocks deleting/moving the sample until the
        # process exits. A direct, non-isolated call is the reproduction:
        # the isolated worker masked this because its subprocess always
        # exits (and releases the handle) before the tempdir is cleaned up.
        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact_path = Path(temporary_directory) / "sample.exe"
            artifact_path.write_bytes(build_minimal_pe())
            artifact = ArtifactStore(temporary_directory).register("pe-leak", artifact_path)

            result = analyze_pe(artifact)

        self.assertEqual(result["status"], "ok")


class EntropyTests(unittest.TestCase):
    def test_chunk_size_splits_the_region_into_windows(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact_path = Path(temporary_directory) / "sample.bin"
            artifact_path.write_bytes(b"\x00" * 8 + bytes(range(256)) * 2)
            artifact = ArtifactStore(temporary_directory).register("sample-3", artifact_path)

            result = calculate_entropy(artifact, offset=0, length=8 + 512, chunk_size=8)

        self.assertEqual(result["status"], "ok")
        chunks = result["data"]["chunks"]
        self.assertEqual(len(chunks), 65)
        self.assertEqual(chunks[0]["entropy"], 0.0)
        self.assertGreater(chunks[-1]["entropy"], 0.0)
        self.assertEqual(sum(chunk["length"] for chunk in chunks), 8 + 512)

    def test_chunk_size_without_a_region_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact_path = Path(temporary_directory) / "sample.bin"
            artifact_path.write_bytes(b"data")
            artifact = ArtifactStore(temporary_directory).register("sample-4", artifact_path)

            result = calculate_entropy(artifact, chunk_size=4)

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error"]["code"], "INVALID_INPUT")


class DisassemblerTests(unittest.IsolatedAsyncioTestCase):
    async def test_offset_pages_past_the_first_batch(self):
        # Goes through the isolated worker, like ContractConformanceTests: PE
        # handlers never close their pefile.PE, so a direct in-process call
        # would leave the sample locked on Windows until the process exits.
        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact_path = Path(temporary_directory) / "sample.exe"
            artifact_path.write_bytes(build_minimal_pe())
            store = ArtifactStore(temporary_directory)
            store.register("pe-disasm", artifact_path)
            server = StaticMCPServer(store)

            first = await server.call("disassemble_function", {"artifact_id": "pe-disasm", "function_address": 0x2000, "limit": 5})
            second = await server.call("disassemble_function", {"artifact_id": "pe-disasm", "function_address": 0x2000, "limit": 5, "offset": 5})

        self.assertEqual(first["status"], "ok")
        self.assertEqual(second["status"], "ok")
        first_addresses = [instruction["address"] for instruction in first["data"]["instructions"]]
        second_addresses = [instruction["address"] for instruction in second["data"]["instructions"]]
        self.assertEqual(len(first_addresses), 5)
        self.assertEqual(len(second_addresses), 5)
        self.assertTrue(set(first_addresses).isdisjoint(second_addresses))
        self.assertTrue(first["metadata"]["has_more"])


class YaraScannerTests(unittest.IsolatedAsyncioTestCase):
    async def test_limit_and_offset_page_across_matching_rules(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact_path = Path(temporary_directory) / "sample.exe"
            artifact_path.write_bytes(build_minimal_pe())
            store = ArtifactStore(temporary_directory)
            store.register("pe-yara", artifact_path)

            rules_path = Path(temporary_directory) / "rules.yar"
            rules_path.write_text("\n".join(f"rule r{i} {{ condition: uint16(0) == 0x5A4D }}" for i in range(3)))
            server = StaticMCPServer(store, rulesets={"test": rules_path})

            first = await server.call("scan_yara", {"artifact_id": "pe-yara", "ruleset": "test", "limit": 2})
            second = await server.call("scan_yara", {"artifact_id": "pe-yara", "ruleset": "test", "limit": 2, "offset": 2})

        self.assertEqual(first["status"], "ok")
        self.assertEqual(len(first["data"]["matches"]), 2)
        self.assertTrue(first["metadata"]["has_more"])
        self.assertEqual(second["status"], "ok")
        self.assertEqual(len(second["data"]["matches"]), 1)
        self.assertFalse(second["metadata"]["has_more"])


class CapaAnalyzerTests(unittest.IsolatedAsyncioTestCase):
    async def test_tool_not_available_without_a_configured_rules_directory(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact_path = Path(temporary_directory) / "sample.exe"
            artifact_path.write_bytes(build_minimal_pe())
            store = ArtifactStore(temporary_directory)
            store.register("pe-capa", artifact_path)
            server = StaticMCPServer(store)

            result = await server.call("run_capa", {"artifact_id": "pe-capa"})

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error"]["code"], "TOOL_NOT_AVAILABLE")

    async def test_matches_a_configured_rule_against_the_sample(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact_path = Path(temporary_directory) / "sample.exe"
            artifact_path.write_bytes(build_minimal_pe() + b"MIRA-TEST-MARKER\x00")
            store = ArtifactStore(temporary_directory)
            store.register("pe-capa", artifact_path)

            rules_dir = Path(temporary_directory) / "rules"
            rules_dir.mkdir()
            (rules_dir / "marker.yml").write_text(
                "rule:\n"
                "  meta:\n"
                "    name: contains marker string\n"
                "    namespace: example\n"
                "    authors: [test@example.com]\n"
                "    scopes: {static: file, dynamic: file}\n"
                "    examples: ['0000000000000000000000000000000000000000000000000000000000000000:0x0']\n"
                "  features:\n"
                '    - string: "MIRA-TEST-MARKER"\n'
            )
            server = StaticMCPServer(store, capa_rules_dir=rules_dir)

            result = await server.call("run_capa", {"artifact_id": "pe-capa"})

        self.assertEqual(result["status"], "ok")
        findings = result["data"]["findings"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "contains marker string")
        self.assertEqual(findings[0]["namespace"], "example")


class CapaResourceTests(unittest.TestCase):
    def test_does_not_hold_the_sample_open_after_returning(self):
        # capa's vivisect backend (vivisect/parsers/pe.py) opens the sample
        # with a plain open() and never closes it - not our code, so a direct
        # call is the reproduction the same way PESupportTests's is: the
        # isolated worker masks it because its subprocess always exits before
        # the tempdir is cleaned up.
        from mira.capabilities.static.capa_analyzer import run_capa

        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact_path = Path(temporary_directory) / "sample.exe"
            artifact_path.write_bytes(build_minimal_pe())
            artifact = ArtifactStore(temporary_directory).register("pe-capa-leak", artifact_path)

            rules_dir = Path(temporary_directory) / "rules"
            rules_dir.mkdir()
            (rules_dir / "marker.yml").write_text(
                "rule:\n"
                "  meta:\n"
                "    name: always\n"
                "    namespace: example\n"
                "    authors: [test@example.com]\n"
                "    scopes: {static: file, dynamic: file}\n"
                "    examples: ['0000000000000000000000000000000000000000000000000000000000000000:0x0']\n"
                "  features:\n"
                "    - string: \"MZ\"\n"
            )

            result = run_capa(artifact, rules_dir=rules_dir)

        self.assertEqual(result["status"], "ok")


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


class LargeResultTests(unittest.IsolatedAsyncioTestCase):
    """A result bigger than the worker pipe's buffer must still come back.

    multiprocessing.Queue is backed by a pipe with a finite OS buffer. A child
    putting more than fits blocks in its feeder thread until the parent drains
    it, so a parent that joins before reading waits out the whole timeout and
    reports a perfectly healthy analysis as a timeout. That silently capped
    every paginated capability at a page the buffer happened to fit.
    """

    async def test_a_page_larger_than_the_pipe_buffer_is_returned(self):
        bulk = b"".join(
            f"https://command-and-control-{n:04}.example.invalid/beacon\x00".encode()
            for n in range(2000)
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact_path = Path(temporary_directory) / "sample.exe"
            artifact_path.write_bytes(build_minimal_pe() + bulk)
            store = ArtifactStore(temporary_directory)
            store.register("bulk", artifact_path)
            # Short timeout: a regression should fail fast, not wait minutes.
            server = StaticMCPServer(store, limits=AnalysisLimits(timeout_seconds=20))

            result = await server.call(
                "extract_strings", {"artifact_id": "bulk", "limit": 1000, "min_length": 4}
            )

        self.assertEqual(result["status"], "ok", result.get("error"))
        self.assertEqual(len(result["data"]["strings"]), 1000)
        self.assertGreater(len(json.dumps(result).encode()), 64 * 1024)
