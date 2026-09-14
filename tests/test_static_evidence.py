"""Each static capability turns its own result into readable evidence.

The orchestrator reads `observation` prose, so these assert that the signal
is *named* in the sentence, not that a particular sentence was written.
"""

import pytest

from mira.agents.static.evidence import (
    HIGH_REGION_ENTROPY,
    MAX_RULE_SIGNALS,
    PACKED_SECTION_ENTROPY,
    PAGED_CAPABILITIES,
    normalize,
)


def ok(data: dict) -> dict:
    return {"status": "ok", "data": data, "metadata": {}}


def error(code: str = "ANALYSIS_FAILED") -> dict:
    return {"status": "error", "data": None, "error": {"code": code, "message": "boom"}}


def unsupported() -> dict:
    return {"status": "unsupported", "data": None, "error": {"code": "UNSUPPORTED", "message": "no"}}


def section(name=".text", entropy=6.0):
    return {
        "name": name,
        "virtual_address": 0x1000,
        "virtual_size": 0x200,
        "raw_size": 0x200,
        "characteristics": 0x60000020,
        "entropy": entropy,
    }


# One (capability, signalling result, expected substring) per capability, plus
# the clean result that must stay silent. Table-driven so a capability cannot
# be quietly skipped: the count is asserted below.
SIGNALS = [
    (
        "analyze_pe",
        ok({"sections": [section(entropy=7.9)]}),
        "entropy",
        ok({"sections": [section(entropy=5.0)]}),
    ),
    (
        "analyze_pe",
        ok({"sections": [section(name="UPX0")]}),
        "UPX0",
        ok({"sections": [section(name=".rdata")]}),
    ),
    (
        "detect_packer",
        ok({"packed": True, "packer": "UPX", "confidence": 0.9, "indicators": ["UPX0 section"]}),
        "UPX",
        ok({"packed": False, "packer": None, "confidence": 0.0, "indicators": []}),
    ),
    (
        "list_imports",
        ok({"imports": [{"dll": "kernel32.dll", "name": "IsDebuggerPresent", "address": 1}]}),
        "IsDebuggerPresent",
        ok({"imports": [{"dll": "kernel32.dll", "name": "GetTickCount", "address": 1}]}),
    ),
    (
        "list_exports",
        ok({"exports": [{"name": None, "ordinal": 3, "address": 1}]}),
        "ordinal",
        ok({"exports": [{"name": "DllRegisterServer", "ordinal": 1, "address": 1}]}),
    ),
    (
        "extract_strings",
        ok({"strings": [{"value": "http://evil.example/c2", "offset": 0, "encoding": "ascii"}]}),
        "http://evil.example/c2",
        ok({"strings": [{"value": "Hello world", "offset": 0, "encoding": "ascii"}]}),
    ),
    (
        "calculate_entropy",
        ok({"entropy": 7.8, "offset": 0, "length": 1024, "chunks": None}),
        "7.8",
        ok({"entropy": 4.1, "offset": 0, "length": 1024, "chunks": None}),
    ),
    (
        "scan_yara",
        ok({"matches": [{"rule": "Emotet_Loader", "namespace": "apt", "tags": ["trojan"]}]}),
        "Emotet_Loader",
        ok({"matches": []}),
    ),
    (
        "run_capa",
        ok({"findings": [{"rule_id": "inject code", "namespace": "host/process", "meta": {}}]}),
        "inject code",
        ok({"findings": []}),
    ),
    (
        "list_functions",
        ok({"functions": [{"address": 1, "size": None, "name": "entry", "discovery_source": "header"}],
            "limitations": "entry point only"}),
        "function",
        ok({"functions": [{"address": n, "size": None, "name": f"f{n}", "discovery_source": "header"}
                          for n in range(400)],
            "limitations": "entry point only"}),
    ),
    (
        "disassemble_function",
        ok({"function_address": 0x1000, "architecture": "x86",
            "instructions": [{"address": 1, "bytes": "0f31", "mnemonic": "rdtsc", "operands": ""}]}),
        "rdtsc",
        ok({"function_address": 0x1000, "architecture": "x86",
            "instructions": [{"address": 1, "bytes": "90", "mnemonic": "nop", "operands": ""}]}),
    ),
    (
        "file_info",
        ok({"file_type": "unknown", "size": 1024, "md5": "a", "sha1": "b", "sha256": "c",
            "entropy": 7.9}),
        "entropy",
        ok({"file_type": "pe", "size": 1024, "md5": "a", "sha1": "b", "sha256": "c",
            "entropy": 5.0}),
    ),
]

# Shared context the two cross-capability signals read. list_functions needs a
# file size to judge density against; list_exports needs the DLL header bit.
PRIOR = {
    "file_info": ok({"file_type": "pe", "size": 4 * 1024 * 1024, "md5": "a", "sha1": "b",
                     "sha256": "c", "entropy": 6.0}),
    # DLL characteristic set, so exports are expected and stay unremarkable.
    "analyze_pe": ok({"coff_header": {"machine": 0x14C, "characteristics": 0x2102},
                      "sections": [section()]}),
}


def test_exports_from_a_non_dll_are_evidence():
    """The only signal that needs another capability's result: an executable
    that exports symbols without declaring itself a DLL."""
    prior = {"analyze_pe": ok({"coff_header": {"machine": 0x14C, "characteristics": 0x102},
                               "sections": [section()]})}
    result = ok({"exports": [{"name": "DllRegisterServer", "ordinal": 1, "address": 1}]})

    signals = normalize("list_exports", result, prior)

    assert any("DLL" in signal.observation for signal in signals)


def test_a_signal_needing_an_absent_prior_result_stays_silent():
    """Normalizers run in whatever order the model calls capabilities, so a
    cross-capability signal must not fire on a missing or failed prior."""
    result = ok({"functions": [{"address": 1, "size": None, "name": "entry",
                                "discovery_source": "header"}],
                 "limitations": "entry point only"})

    assert normalize("list_functions", result, {}) == []
    assert normalize("list_functions", result, {"file_info": error()}) == []


def test_every_capability_has_a_normalizer():
    """Eleven capabilities; a missing normalizer is a capability that silently
    produces nothing."""
    from mira.agents.static.wiring import tool_manifest

    covered = {capability for capability, *_ in SIGNALS}
    assert {spec.name for spec in tool_manifest()} == covered


@pytest.mark.parametrize("capability,result,expected,_clean", SIGNALS)
def test_a_signal_is_named_in_the_observation(capability, result, expected, _clean):
    signals = normalize(capability, result, PRIOR)

    assert signals, f"{capability} produced no evidence for its signal"
    assert any(expected in signal.observation for signal in signals)


@pytest.mark.parametrize("capability,_result,_expected,clean", SIGNALS)
def test_a_clean_result_produces_no_evidence(capability, _result, _expected, clean):
    assert normalize(capability, clean, PRIOR) == []


@pytest.mark.parametrize("capability", sorted({capability for capability, *_ in SIGNALS}))
def test_a_failed_result_produces_no_evidence_and_does_not_raise(capability):
    assert normalize(capability, error(), PRIOR) == []
    assert normalize(capability, unsupported(), PRIOR) == []


@pytest.mark.parametrize("capability,result,_expected,_clean", SIGNALS)
def test_confidence_is_in_range_without_relying_on_the_clamp(capability, result, _expected, _clean):
    for signal in normalize(capability, result, PRIOR):
        assert 0.0 <= signal.confidence <= 1.0


@pytest.mark.parametrize("capability", sorted(PAGED_CAPABILITIES))
def test_paginated_evidence_says_it_covers_only_the_returned_page(capability):
    result, expected = next(
        (result, expected) for name, result, expected, _ in SIGNALS if name == capability
    )
    signals = normalize(capability, result, PRIOR)

    assert signals
    for signal in signals:
        assert "returned page" in signal.observation


def test_each_yara_rule_match_is_its_own_evidence():
    result = ok({"matches": [
        {"rule": "Rule_A", "namespace": "n", "tags": []},
        {"rule": "Rule_B", "namespace": "n", "tags": []},
        {"rule": "Rule_C", "namespace": "n", "tags": []},
    ]})

    signals = normalize("scan_yara", result, PRIOR)

    assert len(signals) == 3
    assert {"Rule_A", "Rule_B", "Rule_C"} == {
        rule for rule in ("Rule_A", "Rule_B", "Rule_C")
        if any(rule in signal.observation for signal in signals)
    }


def test_a_noisy_ruleset_does_not_mint_unbounded_evidence():
    """A page holds up to a thousand rule hits. One evidence record each would
    put a thousand identifiers into a message that has to stay bounded."""
    result = ok({"matches": [
        {"rule": f"Rule_{n}", "namespace": "n", "tags": []} for n in range(500)
    ]})

    signals = normalize("scan_yara", result, PRIOR)

    assert len(signals) == MAX_RULE_SIGNALS + 1
    assert "Rule_0" in signals[0].observation
    # The count of what was not named individually is never lost.
    assert str(500 - MAX_RULE_SIGNALS) in signals[-1].observation


def test_a_ruleset_under_the_cap_names_every_rule():
    result = ok({"findings": [
        {"rule_id": f"cap {n}", "namespace": "host", "meta": {}} for n in range(3)
    ]})

    signals = normalize("run_capa", result, PRIOR)

    assert len(signals) == 3


def test_an_unknown_capability_produces_no_evidence():
    assert normalize("not_a_capability", ok({}), PRIOR) == []


def test_entropy_thresholds_are_the_documented_knobs():
    """These are tuning knobs the signal table depends on, not literals."""
    assert PACKED_SECTION_ENTROPY <= 8.0
    assert HIGH_REGION_ENTROPY <= 8.0
