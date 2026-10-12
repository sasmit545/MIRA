"""Each static capability turns its own result into readable evidence.

The orchestrator reads `observation` prose, so these assert that the signal
is *named* in the sentence, not that a particular sentence was written.
"""

import pytest

from support import PagedList, ToolThenReportModel

from mira.agents.static.agent import StaticAgent
from mira.agents.static.evidence import (
    CONFIDENCE_WEAK,
    HIGH_REGION_ENTROPY,
    MAX_RULE_SIGNALS,
    PACKED_SECTION_ENTROPY,
    PAGED_CAPABILITIES,
    normalize,
)
from mira.core.objective import InvestigationObjective
from mira.core.state import InvestigationState
from mira.reasoning.runtime.trace import resolve_observation


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


def signalling(capability):
    return next(result for name, result, _, _ in SIGNALS if name == capability)


@pytest.mark.parametrize("capability", sorted(PAGED_CAPABILITIES))
def test_paginated_evidence_names_how_much_of_the_list_it_covers(capability):
    result = {**signalling(capability), "metadata": {"offset": 0, "total": 500}}

    signals = normalize(capability, result, PRIOR)

    assert signals
    for signal in signals:
        assert "of 500" in signal.observation and "fetched" in signal.observation


@pytest.mark.parametrize("capability", sorted(PAGED_CAPABILITIES))
def test_a_page_without_totals_claims_only_the_returned_page(capability):
    for signal in normalize(capability, signalling(capability), PRIOR):
        assert "returned page" in signal.observation


# --- Import evidence covers the whole collected list (R14, R16) ------------


def imports_result(names, total=None, offset=0):
    imports = [
        {"dll": "kernel32.dll", "name": name, "ordinal": None if name else 7, "address": index}
        for index, name in enumerate(names)
    ]
    total = len(imports) if total is None else total
    return {"status": "ok", "data": {"imports": imports},
            "metadata": {"offset": offset, "total": total, "fetched": len(imports), "unfetched": total - len(imports)}}


def late_injection(count=2000, at=1500):
    names = [f"Fn{index}" for index in range(count)]
    names[at] = "VirtualAllocEx"
    return names


def test_an_import_deep_in_a_collected_list_is_evidence():
    signals = normalize("list_imports", imports_result(late_injection()), {})

    injection = [signal.observation for signal in signals if "process injection" in signal.observation]
    assert injection and "VirtualAllocEx" in injection[0]
    assert "among all 2000 imports" in injection[0]


def test_a_truncated_list_names_what_was_fetched_and_the_total():
    signals = normalize("list_imports", imports_result(["VirtualAllocEx", "Fn1"], total=8214), {})

    assert "within the first 2 of 8214 imports fetched" in signals[0].observation


def test_a_list_fetched_from_an_offset_says_where_it_starts():
    signals = normalize("list_imports", imports_result(["VirtualAllocEx"], total=8214, offset=500), {})

    assert "1 of 8214 imports fetched from offset 500" in signals[0].observation


def test_nameless_imports_are_counted_as_ordinal_only():
    signals = normalize("list_imports", imports_result([None, None, None, "GetTickCount"]), {})

    assert len(signals) == 1
    assert "3 of" in signals[0].observation and "ordinal" in signals[0].observation


def test_run_time_api_resolution_is_weak_evidence():
    signals = normalize("list_imports", imports_result(["GetProcAddress", "LoadLibraryA"]), {})

    assert len(signals) == 1
    assert "GetProcAddress" in signals[0].observation and "LoadLibraryA" in signals[0].observation
    assert signals[0].confidence == CONFIDENCE_WEAK


async def test_collected_evidence_resolves_to_the_collected_call(tmp_path):
    imports = imports_result(late_injection())["data"]["imports"]
    objective = InvestigationObjective(
        name="Assess imports", description="d", reason="test", capabilities=("list_imports",)
    )
    agent = StaticAgent(PagedList(0, imports=imports), model=ToolThenReportModel("list_imports"), trace_dir=tmp_path)
    state = InvestigationState()

    await agent.investigate(objective, "sample-1", state=state)

    item = next(item for item in state.evidence if "VirtualAllocEx" in item.observation)
    observation = resolve_observation(tmp_path, item.provenance)
    assert observation["call"]["name"] == "list_imports"
    assert len(observation["result"]["output"]["data"]["imports"]) == 2000


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


# --- Entropy windows reach the evidence (R15) ------------------------------


def windows(high_at=()):
    chunks = [{"offset": index * 64, "length": 64, "entropy": 7.6 if index in high_at else 3.0} for index in range(65)]
    return ok({"entropy": 4.0, "offset": 0, "length": 65 * 64, "chunks": chunks})


def test_high_entropy_windows_are_one_observation_with_their_offsets():
    signals = normalize("calculate_entropy", windows(high_at=(3, 40)), {})

    assert len(signals) == 1
    assert "2 of 65" in signals[0].observation
    assert "192" in signals[0].observation and "2560" in signals[0].observation


def test_windows_and_region_below_the_threshold_are_silent():
    assert normalize("calculate_entropy", windows(), {}) == []


# --- False positives on a genuine Windows binary -----------------------------

from mira.agents.static.evidence import CONFIDENCE_MODERATE, CONFIDENCE_RULE_MATCH


def test_entry_point_only_discovery_says_nothing_about_function_density():
    """The capability only reads the PE entry point, so one function in a
    large file is its limitation, not a sign of packing."""
    result = ok({"functions": [{"address": 1, "size": None, "name": "entry_point", "discovery_source": "pe_entry_point"}],
                 "limitations": "Only the PE entry point is discovered without an analysis engine."})

    assert normalize("list_functions", result, PRIOR) == []


def capa(*namespaces):
    return ok({"findings": [{"rule_id": f"rule {index}", "namespace": namespace, "meta": {}}
                            for index, namespace in enumerate(namespaces)]})


@pytest.mark.parametrize("namespace, confidence", [
    ("anti-analysis/anti-debugging/debugger-detection", CONFIDENCE_RULE_MATCH),
    ("persistence/registry/run", CONFIDENCE_RULE_MATCH),
    ("collection/keylog", CONFIDENCE_MODERATE),
    ("host-interaction/file-system/delete", CONFIDENCE_WEAK),
    (None, CONFIDENCE_WEAK),
])
def test_a_capa_hit_is_graded_by_its_namespace(namespace, confidence):
    (signal,) = normalize("run_capa", capa(namespace), PRIOR)

    assert signal.confidence == confidence


def test_an_ordinary_capability_says_benign_software_has_it_too():
    (weak,) = normalize("run_capa", capa("host-interaction/file-system/delete"), PRIOR)
    (strong,) = normalize("run_capa", capa("anti-analysis/anti-vm"), PRIOR)

    assert "benign software" in weak.observation
    assert "benign software" not in strong.observation


def test_the_strongest_capa_hits_are_named_before_the_cap():
    ordinary = ["host-interaction/file-system"] * (MAX_RULE_SIGNALS + 5)
    result = capa(*ordinary, "anti-analysis/anti-debugging", "impact/wipe-disk")

    signals = normalize("run_capa", result, PRIOR)

    named = signals[:MAX_RULE_SIGNALS]
    assert sum(signal.confidence == CONFIDENCE_RULE_MATCH for signal in named) == 2
    assert signals[-1].confidence == CONFIDENCE_WEAK  # the remainder is only ordinary hits


# --- Calibrated on 2,111 System32 binaries (October 2026) --------------------


@pytest.mark.parametrize("name", ["fothk", ".00cfg", "GFIDS", ".imrsiv", "INIT"])
def test_sections_the_microsoft_toolchain_emits_are_not_flagged(name):
    assert normalize("analyze_pe", ok({"sections": [section(name=name)]}), {}) == []


def imports_named(*names):
    return ok({"imports": [{"dll": "kernel32.dll", "name": name, "address": index} for index, name in enumerate(names)]})


def test_debugger_checks_the_c_runtime_makes_are_weak_and_say_so():
    (signal,) = normalize("list_imports", imports_named("IsDebuggerPresent", "OutputDebugStringW"), {})

    assert signal.confidence == CONFIDENCE_WEAK
    assert "C runtime" in signal.observation and "IsDebuggerPresent" in signal.observation


def test_a_rarer_debugger_check_is_still_strong_anti_debugging_evidence():
    from mira.agents.static.evidence import CONFIDENCE_STRONG

    (signal,) = normalize("list_imports", imports_named("CheckRemoteDebuggerPresent"), {})

    assert signal.confidence == CONFIDENCE_STRONG and "anti-debugging" in signal.observation


def test_run_time_resolution_says_most_programs_import_it():
    (signal,) = normalize("list_imports", imports_named("GetProcAddress"), {})

    assert "most Windows programs" in signal.observation


# --- Rule keys for the signal survey (KTD9) ----------------------------------


@pytest.mark.parametrize("capability,result,_expected,_clean", SIGNALS)
def test_every_signal_names_a_stable_rule(capability, result, _expected, _clean):
    first, second = normalize(capability, result, PRIOR), normalize(capability, result, PRIOR)

    assert first
    for signal in first:
        assert ":" in signal.rule and signal.rule.split(":", 1)[1]
    assert [signal.rule for signal in first] == [signal.rule for signal in second]


def test_different_categories_get_different_rules():
    imports = normalize("list_imports", imports_result(["IsDebuggerPresent", "VirtualAllocEx", "GetProcAddress", None]), {})
    strings = normalize("extract_strings", ok({"strings": [
        {"value": "http://a.example/x"}, {"value": "HKLM\Software\Run"}, {"value": "10.0.0.1"},
    ]}), {})
    sections = normalize("analyze_pe", ok({"sections": [section(name="UPX0", entropy=7.9)]}), {})
    capa_hits = normalize("run_capa", capa("anti-analysis/anti-vm", "anti-analysis/anti-vm"), PRIOR)

    for signals, count in ((imports, 4), (strings, 3), (sections, 2), (capa_hits, 2)):
        assert len({signal.rule for signal in signals}) == count
    assert {"strings:URL", "section:high-entropy", "section:nonstandard-name"} <= {
        signal.rule for signal in strings + sections
    }
    assert {signal.rule for signal in capa_hits} == {"capa:rule 0", "capa:rule 1"}


def test_a_yara_rule_is_keyed_by_namespace_and_rule():
    (signal,) = normalize("scan_yara", ok({"matches": [{"rule": "Emotet_Loader", "namespace": "default", "tags": []}]}), PRIOR)

    assert signal.rule == "yara:default/Emotet_Loader"


def test_hits_past_the_cap_share_one_remainder_rule():
    result = ok({"matches": [{"rule": f"Rule_{n}", "namespace": "n", "tags": []} for n in range(30)]})

    assert normalize("scan_yara", result, PRIOR)[-1].rule == "yara:remainder"


# --- One definition of each grade (KTD1) -------------------------------------


@pytest.mark.parametrize("confidence, expected", [
    (0.4, "weak"), (0.59, "weak"), (0.6, "moderate"), (0.79, "moderate"), (0.8, "strong"), (1.0, "strong"),
])
def test_confidence_bands(confidence, expected):
    from mira.core.evidence import grade

    assert grade(confidence) == expected


def test_static_confidence_constants_fall_in_the_band_their_names_imply():
    from mira.agents.static.evidence import BASE_CONFIDENCE, CONFIDENCE_STRONG
    from mira.core.evidence import grade

    assert grade(CONFIDENCE_STRONG) == grade(CONFIDENCE_RULE_MATCH) == "strong"
    assert grade(CONFIDENCE_MODERATE) == "moderate"
    assert grade(CONFIDENCE_WEAK) == grade(BASE_CONFIDENCE) == "weak"


# --- Entropy and packing support a finding but never corroborate one --------


def test_entropy_and_packing_signals_are_supporting_and_strong_rules_are_not():
    supporting = [
        *normalize("calculate_entropy", windows(high_at=(3,)), {}),
        *normalize("file_info", ok({"entropy": 7.9, "file_type": "pe"}), {}),
        *normalize("analyze_pe", ok({"sections": [{"name": ".text", "entropy": 7.9}]}), {}),
        *normalize("detect_packer", ok({"packed": True, "packer": "UPX", "confidence": 0.9}), {}),
        *normalize("run_capa", capa("anti-analysis/packer/upx"), {}),
    ]
    corroborating = normalize("run_capa", capa("anti-analysis/anti-debugging/debugger-detection"), {})

    assert len(supporting) == 5 and all(signal.supporting for signal in supporting)
    assert corroborating and not any(signal.supporting for signal in corroborating)
