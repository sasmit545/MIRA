import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mira.agents.static.wiring import (
    _check_vendored_rules_initialized,
    _configured_capa_rules_dir,
    _configured_yara_rulesets,
)


class YaraRulesetDiscoveryTests(unittest.TestCase):
    def test_discovers_yar_and_yara_files_by_stem(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "suspicious.yar").write_text("rule r { condition: true }")
            (root / "packers.yara").write_text("rule p { condition: true }")
            (root / "notes.txt").write_text("ignored")

            previous = os.environ.get("MIRA_YARA_RULES_DIR")
            os.environ["MIRA_YARA_RULES_DIR"] = str(root)
            try:
                rulesets = _configured_yara_rulesets()
            finally:
                if previous is None:
                    os.environ.pop("MIRA_YARA_RULES_DIR", None)
                else:
                    os.environ["MIRA_YARA_RULES_DIR"] = previous

        self.assertEqual(set(rulesets), {"suspicious", "packers"})

    def test_unset_env_var_falls_back_to_the_vendored_submodule(self):
        previous = os.environ.pop("MIRA_YARA_RULES_DIR", None)
        try:
            rulesets = _configured_yara_rulesets()
        finally:
            if previous is not None:
                os.environ["MIRA_YARA_RULES_DIR"] = previous

        if not rulesets:
            self.skipTest("rules/signature-base submodule not initialized - run scripts/fetch_rules.sh")
        self.assertIn("apt_apt28", rulesets)
        self.assertTrue(rulesets["apt_apt28"].is_file())


class CapaRulesDirDiscoveryTests(unittest.TestCase):
    def test_unset_env_var_falls_back_to_the_vendored_submodule(self):
        previous = os.environ.pop("MIRA_CAPA_RULES_DIR", None)
        try:
            rules_dir = _configured_capa_rules_dir()
        finally:
            if previous is not None:
                os.environ["MIRA_CAPA_RULES_DIR"] = previous

        if rules_dir is None or not any(rules_dir.iterdir()):
            self.skipTest("rules/capa submodule not initialized - run scripts/fetch_rules.sh")
        self.assertTrue((rules_dir / "LICENSE.txt").is_file())

    def test_explicit_env_var_overrides_the_fallback(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            previous = os.environ.get("MIRA_CAPA_RULES_DIR")
            os.environ["MIRA_CAPA_RULES_DIR"] = temporary_directory
            try:
                rules_dir = _configured_capa_rules_dir()
            finally:
                if previous is None:
                    os.environ.pop("MIRA_CAPA_RULES_DIR", None)
                else:
                    os.environ["MIRA_CAPA_RULES_DIR"] = previous

        self.assertEqual(rules_dir, Path(temporary_directory))


class VendoredRulesInitializedCheckTests(unittest.TestCase):
    def test_raises_a_clear_error_when_a_submodule_is_present_but_empty(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "rules" / "capa").mkdir(parents=True)
            (root / "rules" / "signature-base").mkdir(parents=True)

            for previous_env in ("MIRA_CAPA_RULES_DIR", "MIRA_YARA_RULES_DIR"):
                os.environ.pop(previous_env, None)

            with patch("mira.agents.static.wiring._repo_root", return_value=root):
                with self.assertRaisesRegex(RuntimeError, "rules/capa.*git submodule update --init"):
                    _check_vendored_rules_initialized()

    def test_does_not_raise_once_the_capa_submodule_has_content(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "rules" / "capa").mkdir(parents=True)
            (root / "rules" / "capa" / "LICENSE.txt").write_text("...")
            (root / "rules" / "signature-base").mkdir(parents=True)
            (root / "rules" / "signature-base" / "yara").mkdir()

            for previous_env in ("MIRA_CAPA_RULES_DIR", "MIRA_YARA_RULES_DIR"):
                os.environ.pop(previous_env, None)

            with patch("mira.agents.static.wiring._repo_root", return_value=root):
                _check_vendored_rules_initialized()

    def test_explicit_env_override_skips_the_check_for_that_ruleset(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "rules" / "capa").mkdir(parents=True)
            (root / "rules" / "signature-base").mkdir(parents=True)

            previous = os.environ.get("MIRA_CAPA_RULES_DIR")
            os.environ["MIRA_CAPA_RULES_DIR"] = str(root)
            try:
                with patch("mira.agents.static.wiring._repo_root", return_value=root):
                    with self.assertRaisesRegex(RuntimeError, "rules/signature-base"):
                        _check_vendored_rules_initialized()
            finally:
                if previous is None:
                    os.environ.pop("MIRA_CAPA_RULES_DIR", None)
                else:
                    os.environ["MIRA_CAPA_RULES_DIR"] = previous


if __name__ == "__main__":
    unittest.main()


class EvidenceExecutorTests(unittest.IsolatedAsyncioTestCase):
    PACKED = {"status": "ok", "data": {"packed": True, "indicators": ["high entropy"]}, "metadata": {}}

    async def run_once(self, state=None):
        from mira.agents.static.wiring import build_evidence_executor

        async def invoke(capability, arguments):
            return self.PACKED

        evidence = []
        execute = build_evidence_executor(
            invoke, run_id="r", artifact_id="sample", evidence=evidence, state=state
        )
        await execute("detect_packer", {})
        return evidence

    async def test_mints_evidence_with_provenance_and_no_shared_state(self):
        evidence = await self.run_once()
        self.assertEqual([item.id for item in evidence], ["E1"])
        self.assertEqual(evidence[0].provenance, "r#detect_packer#0")

    async def test_deposits_into_shared_state_and_continues_numbering(self):
        from mira.core.state import InvestigationState

        state = InvestigationState()
        await self.run_once(state)
        evidence = await self.run_once(state)
        self.assertEqual([item.id for item in state.evidence], ["E1", "E2"])
        self.assertEqual(evidence[0].id, "E2")


# --- A collected capability returns its whole list as one observation (KTD1)

import pytest

from mira.agents.static.wiring import COLLECTED_CAPABILITIES, build_executor
from mira.capabilities.static.common import paginate
from mira.contracts.capabilities.static.list_imports import ListImportsOutput

IMPORT_CAP = COLLECTED_CAPABILITIES["list_imports"][1]


class PagedImports:
    """Serves list_imports pages the way the server does, recording each call."""

    def __init__(self, count, fail_from=None, raise_from=None):
        self.imports = [
            {"dll": "KERNEL32.dll", "name": f"Fn{index}", "ordinal": None, "address": 0x1000 + index}
            for index in range(count)
        ]
        self.calls = []
        self.fail_from = fail_from
        self.raise_from = raise_from

    async def invoke(self, capability, artifact_id, **parameters):
        self.calls.append({"artifact_id": artifact_id, **parameters})
        offset = parameters.get("offset", 0)
        if self.raise_from is not None and offset >= self.raise_from:
            raise RuntimeError("worker crashed")
        if self.fail_from is not None and offset >= self.fail_from:
            return {
                "status": "error", "data": None,
                "error": {"code": "RESOURCE_LIMIT", "message": "analysis timed out"},
                "metadata": {"artifact_id": artifact_id, "capability": capability},
            }
        selected, page = paginate(self.imports, parameters.get("limit", 100), offset)
        return {
            "status": "ok", "data": {"imports": selected},
            "metadata": {"artifact_id": artifact_id, "capability": capability, "tool_version": "0.1.0", **page},
        }


async def collect(client, **arguments):
    return await build_executor(client, "sample")("list_imports", arguments)


async def test_one_call_collects_every_page():
    client = PagedImports(2345)

    result = await collect(client)

    assert len(result["data"]["imports"]) == 2345
    metadata = result["metadata"]
    assert (metadata["total"], metadata["fetched"], metadata["unfetched"], metadata["pages"]) == (2345, 2345, 0, 3)
    assert metadata["has_more"] is False and "next_offset" not in metadata and "fetch_error" not in metadata
    assert [call["offset"] for call in client.calls] == [0, 1000, 2000]
    ListImportsOutput.model_validate(result["data"])


async def test_a_list_over_the_cap_stops_at_the_cap_and_says_where_the_rest_starts():
    client = PagedImports(IMPORT_CAP + 250)

    result = await collect(client)

    metadata = result["metadata"]
    assert len(result["data"]["imports"]) == IMPORT_CAP
    assert (metadata["fetched"], metadata["unfetched"], metadata["next_offset"]) == (IMPORT_CAP, 250, IMPORT_CAP)
    assert metadata["has_more"] is True
    assert sum(call["limit"] for call in client.calls) == IMPORT_CAP


async def test_the_model_offset_starts_the_walk():
    client = PagedImports(2345)

    result = await collect(client, offset=500)

    metadata = result["metadata"]
    assert result["data"]["imports"][0]["name"] == "Fn500"
    assert (metadata["offset"], metadata["fetched"], metadata["unfetched"]) == (500, 1845, 500)
    assert client.calls[0]["offset"] == 500


@pytest.mark.parametrize("client, failure", [
    (PagedImports(2345, fail_from=1000), "RESOURCE_LIMIT: analysis timed out"),
    (PagedImports(2345, raise_from=1000), "worker crashed"),
])
async def test_a_later_page_failure_keeps_the_pages_already_fetched(client, failure):
    result = await collect(client)

    metadata = result["metadata"]
    assert result["status"] == "ok"
    assert len(result["data"]["imports"]) == 1000
    assert failure in metadata["fetch_error"]
    assert (metadata["unfetched"], metadata["next_offset"]) == (1345, 1000)


async def test_a_first_page_failure_is_the_capability_failure_unchanged():
    client = PagedImports(10, fail_from=0)

    result = await collect(client)

    assert result == await client.invoke("list_imports", "sample", offset=0)


async def test_a_model_supplied_artifact_id_and_limit_are_ignored():
    client = PagedImports(5)

    await collect(client, artifact_id="other-sample", limit=2)

    assert client.calls[0]["artifact_id"] == "sample"
    assert client.calls[0]["limit"] == 1000


async def test_an_uncollected_capability_is_passed_through():
    client = PagedImports(5)

    await build_executor(client, "sample")("list_exports", {"limit": 2})

    assert client.calls == [{"artifact_id": "sample", "limit": 2}]
