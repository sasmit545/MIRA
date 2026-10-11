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

from support import PagedList

from mira.agents.static.wiring import COLLECTED_CAPABILITIES, build_executor
from mira.contracts.capabilities.static.list_imports import ListImportsOutput

IMPORT_CAP = COLLECTED_CAPABILITIES["list_imports"]


async def collect(client, **arguments):
    return await build_executor(client, "sample")("list_imports", arguments)


async def test_one_call_collects_every_page():
    client = PagedList(2345)

    result = await collect(client)

    assert len(result["data"]["imports"]) == 2345
    metadata = result["metadata"]
    assert (metadata["total"], metadata["fetched"], metadata["unfetched"], metadata["pages"]) == (2345, 2345, 0, 3)
    assert metadata["has_more"] is False and "next_offset" not in metadata and "fetch_error" not in metadata
    assert [call["offset"] for call in client.calls] == [0, 1000, 2000]
    ListImportsOutput.model_validate(result["data"])


async def test_a_list_over_the_cap_stops_at_the_cap_and_says_where_the_rest_starts():
    client = PagedList(IMPORT_CAP + 250)

    result = await collect(client)

    metadata = result["metadata"]
    assert len(result["data"]["imports"]) == IMPORT_CAP
    assert (metadata["fetched"], metadata["unfetched"], metadata["next_offset"]) == (IMPORT_CAP, 250, IMPORT_CAP)
    assert metadata["has_more"] is True
    assert sum(call["limit"] for call in client.calls) == IMPORT_CAP


async def test_the_model_offset_starts_the_walk():
    client = PagedList(2345)

    result = await collect(client, offset=500)

    metadata = result["metadata"]
    assert result["data"]["imports"][0]["name"] == "Fn500"
    assert (metadata["offset"], metadata["fetched"], metadata["unfetched"]) == (500, 1845, 500)
    assert client.calls[0]["offset"] == 500


@pytest.mark.parametrize("client, failure", [
    (PagedList(2345, fail_from=1000), "RESOURCE_LIMIT: analysis timed out"),
    (PagedList(2345, raise_from=1000), "worker crashed"),
])
async def test_a_later_page_failure_keeps_the_pages_already_fetched(client, failure):
    result = await collect(client)

    metadata = result["metadata"]
    assert result["status"] == "ok"
    assert len(result["data"]["imports"]) == 1000
    assert failure in metadata["fetch_error"]
    assert (metadata["unfetched"], metadata["next_offset"]) == (1345, 1000)


async def test_a_first_page_failure_is_the_capability_failure_unchanged():
    client = PagedList(10, fail_from=0)

    result = await collect(client)

    assert result == await client.invoke("list_imports", "sample", offset=0)


async def test_a_model_supplied_artifact_id_and_limit_are_ignored():
    client = PagedList(5)

    await collect(client, artifact_id="other-sample", limit=2)

    assert client.calls[0]["artifact_id"] == "sample"
    assert client.calls[0]["limit"] == 1000


async def test_an_uncollected_capability_is_passed_through():
    client = PagedList(5)

    await build_executor(client, "sample")("calculate_entropy", {"offset": 0, "length": 16})

    assert client.calls == [{"artifact_id": "sample", "offset": 0, "length": 16}]


async def test_an_offset_sent_as_text_is_walked_from_the_validated_offset():
    client = PagedList(2345)

    result = await collect(client, offset="500")

    assert result["metadata"]["offset"] == 500
    assert result["metadata"]["fetched"] == 1845


class StalledImports(PagedList):
    """Claims more remain but returns nothing past the first page."""

    async def invoke(self, capability, artifact_id, **parameters):
        page = await super().invoke(capability, artifact_id, **parameters)
        if parameters.get("offset", 0) >= 1000:
            page = {**page, "data": {"imports": []}, "metadata": {**page["metadata"], "has_more": True}}
        return page


async def test_a_page_that_adds_nothing_ends_the_walk():
    client = StalledImports(2345)

    result = await collect(client)

    assert result["metadata"]["fetched"] == 1000
    assert len(client.calls) == 2


async def test_the_rest_past_a_late_offset_is_counted_from_where_it_starts():
    from mira.reasoning.runtime.payload import digest

    result = await collect(PagedList(25_000), offset=10_000)

    text = digest(result)
    assert "15000 not fetched" in text  # everything this call does not hold
    assert "the 5000 past it with list_imports(offset=20000)" in text


# --- Every paged capability is collected (U10) -------------------------------

from mira.agents.static.evidence import PAGED_CAPABILITIES

NEWLY_COLLECTED = sorted(set(PAGED_CAPABILITIES) - {"list_imports"})


def test_every_paged_capability_is_collected():
    assert set(COLLECTED_CAPABILITIES) == set(PAGED_CAPABILITIES)


@pytest.mark.parametrize("capability", NEWLY_COLLECTED)
async def test_a_collected_capability_merges_its_pages(capability):
    key = PAGED_CAPABILITIES[capability][0]
    count = min(COLLECTED_CAPABILITIES[capability], 2345)
    client = PagedList(count, key=key)

    result = await build_executor(client, "sample")(capability, {})

    metadata = result["metadata"]
    assert len(result["data"][key]) == count
    assert (metadata["total"], metadata["fetched"], metadata["unfetched"]) == (count, count, 0)
    assert len(client.calls) == -(-count // 1000)


async def test_capa_with_a_few_findings_is_one_worker_call():
    client = PagedList(30, key="findings")

    await build_executor(client, "sample")("run_capa", {})

    assert len(client.calls) == 1


async def test_strings_past_the_cap_say_how_many_were_not_fetched():
    from mira.reasoning.runtime.payload import digest

    cap = COLLECTED_CAPABILITIES["extract_strings"]
    result = await build_executor(PagedList(cap + 2000, key="strings"), "sample")("extract_strings", {"min_length": 6})

    assert result["metadata"]["unfetched"] == 2000
    assert "2000 not fetched" in digest(result)


async def test_a_page_without_paging_counters_is_passed_through():
    class Unpaged:
        async def invoke(self, capability, artifact_id, **parameters):
            return {"status": "ok", "data": {"strings": [{"value": "x"}]}, "metadata": {}}

    result = await build_executor(Unpaged(), "sample")("extract_strings", {})

    assert result["metadata"] == {}
