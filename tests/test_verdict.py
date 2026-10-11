"""The verdict gate: structural rules a report must meet before it stands
(KTD2-KTD7). Passing shows a report is policy-compliant, not that it is right."""

from mira.core.evidence import Evidence
from mira.reasoning.contracts.finding import Confidence, Evidence as Ref, Finding, Severity
from mira.reasoning.contracts.memory import MemoryHypothesis, WorkingMemory
from mira.reasoning.runtime.verdict import check

WEAK, MODERATE, STRONG = 0.4, 0.6, 0.9


def item(id, capability="run_capa", confidence=STRONG):
    return Evidence(id=id, observation=f"observation {id}", source_agent="static", capability=capability, confidence=confidence)


def finding(*refs, severity=Severity.HIGH):
    return Finding(
        title="t", description="d", severity=severity, confidence=Confidence.MEDIUM,
        evidence_refs=[Ref(evidence_id=ref) for ref in refs], source_location="",
    )


CORROBORATED = [item("E1", "run_capa"), item("E2", "list_imports")]


def gate(verdict, findings, evidence, memory=None, final=False):
    return check(verdict, findings, evidence, memory or WorkingMemory(), final=final)


def test_a_verdict_is_matched_after_trimming_and_lowercasing():
    outcome = gate(" Malicious ", [finding("E1", "E2")], CORROBORATED)

    assert not outcome.failure
    assert outcome.verdict == "malicious"
    assert outcome.record["outcome"] == "accepted"


def test_an_unknown_verdict_is_rejected_with_the_allowed_ones():
    outcome = gate("suspicious", [finding("E1")], CORROBORATED)

    assert outcome.record["outcome"] == "rejected"
    for allowed in ("benign", "malicious", "inconclusive"):
        assert allowed in outcome.failure


def test_an_unknown_verdict_on_the_final_turn_becomes_inconclusive():
    outcome = gate("suspicious", [finding("E1")], CORROBORATED, final=True)

    assert not outcome.failure
    assert outcome.verdict == "inconclusive"
    assert outcome.record["outcome"] == "downgraded"
    assert outcome.record["submitted_verdict"] == "suspicious"
    assert outcome.record["reasons"]


def test_severity_is_capped_at_the_strongest_cited_grade():
    weak = gate("inconclusive", [finding("E1", severity=Severity.HIGH)], [item("E1", confidence=WEAK)])
    moderate = gate("inconclusive", [finding("E1", severity=Severity.CRITICAL)], [item("E1", confidence=MODERATE)])
    strong = gate("inconclusive", [finding("E1", severity=Severity.CRITICAL)], [item("E1")])

    assert weak.findings[0].severity is Severity.LOW and len(weak.record["repairs"]) == 1
    assert weak.record["outcome"] == "repaired"
    assert moderate.findings[0].severity is Severity.MEDIUM
    assert strong.findings[0].severity is Severity.CRITICAL and strong.record["repairs"] == []


def test_a_severity_already_under_the_cap_is_left_alone():
    outcome = gate("inconclusive", [finding("E1", severity=Severity.INFO)], [item("E1", confidence=WEAK)])

    assert outcome.findings[0].severity is Severity.INFO and outcome.record["repairs"] == []


def test_a_finding_citing_nothing_in_a_run_without_evidence_is_info():
    outcome = gate("benign", [finding(severity=Severity.MEDIUM)], [])

    assert outcome.findings[0].severity is Severity.INFO


def test_malicious_with_strong_evidence_from_two_capabilities_stands():
    assert gate("malicious", [finding("E1"), finding("E2")], CORROBORATED).verdict == "malicious"


def test_malicious_from_one_capability_is_rejected_and_inconclusive_is_then_accepted():
    evidence = [item("E1"), item("E2")]

    rejected = gate("malicious", [finding("E1", "E2")], evidence)
    accepted = gate("inconclusive", [finding("E1", "E2")], evidence)

    assert rejected.record["outcome"] == "rejected" and "different capabilities" in rejected.failure
    assert not accepted.failure and accepted.verdict == "inconclusive"


def test_malicious_on_moderate_evidence_is_rejected():
    evidence = [item("E1", "run_capa", MODERATE), item("E2", "list_imports", MODERATE)]

    assert gate("malicious", [finding("E1", "E2")], evidence).record["outcome"] == "rejected"


def test_uncorroborated_malicious_on_the_final_turn_becomes_inconclusive():
    for evidence in ([item("E1"), item("E2")], [item("E1", "run_capa", MODERATE), item("E2", "list_imports", MODERATE)]):
        outcome = gate("malicious", [finding("E1", "E2")], evidence, final=True)

        assert outcome.verdict == "inconclusive" and not outcome.failure
        assert outcome.record["submitted_verdict"] == "malicious"
        assert any("different capabilities" in reason for reason in outcome.record["reasons"])


def hypothesis(supporting, contradicting, status="supported"):
    return MemoryHypothesis(
        id="H1", statement="s", confidence=0.7, status=status,
        supporting_evidence=list(supporting), contradicting_evidence=list(contradicting),
    )


def test_a_contradicted_hypothesis_behind_the_verdict_is_recorded_not_enforced():
    memory = WorkingMemory(hypotheses=[hypothesis(["E1"], ["E3"])])
    evidence = [*CORROBORATED, item("E3", "extract_strings", WEAK)]

    outcome = gate("malicious", [finding("E1", "E2")], evidence, memory)

    assert outcome.verdict == "malicious"
    assert outcome.record["contradicted_hypotheses"] == ["H1"]


def test_a_contradiction_removed_from_the_notes_is_not_recorded():
    memory = WorkingMemory(hypotheses=[hypothesis(["E1"], [])])

    outcome = gate("malicious", [finding("E1", "E2")], CORROBORATED, memory)

    assert outcome.verdict == "malicious" and outcome.record["contradicted_hypotheses"] == []


def test_a_contradiction_on_a_hypothesis_no_cited_strong_item_supports_is_not_recorded():
    memory = WorkingMemory(hypotheses=[hypothesis(["E3"], ["E1"])])
    evidence = [*CORROBORATED, item("E3", "extract_strings", WEAK)]

    outcome = gate("malicious", [finding("E1", "E2", "E3")], evidence, memory)

    assert outcome.record["contradicted_hypotheses"] == []


def test_benign_with_uncited_strong_evidence_stands_and_lists_it():
    outcome = gate("benign", [finding("E3")], [*CORROBORATED, item("E3", "file_info", WEAK)])

    assert outcome.verdict == "benign" and not outcome.failure
    assert outcome.record["uncited_strong"] == ["E1", "E2"]


def test_strong_evidence_left_uncited_beside_a_corroborated_verdict_is_listed():
    outcome = gate("malicious", [finding("E1", "E2")], [*CORROBORATED, item("E4", "scan_yara")])

    assert outcome.verdict == "malicious" and outcome.record["uncited_strong"] == ["E4"]


async def test_a_specialist_run_claiming_malicious_on_weak_evidence_reports_inconclusive(tmp_path):
    import json

    from support import EMPTY_NOTES, PagedList

    from mira.agents.static.agent import StaticAgent
    from mira.core.objective import InvestigationObjective
    from mira.reasoning.contracts.model import ModelResponse
    from mira.reasoning.contracts.tool import ToolCall

    class MaliciousOnWeakEvidence:
        def __init__(self):
            self.turns = 0

        def generate(self, context, tools, force=None):
            if force == "record_memory":
                return ModelResponse()
            self.turns += 1
            if self.turns == 1:
                return ModelResponse(tool_calls=[ToolCall("1", "list_imports", {})], memory_update=dict(EMPTY_NOTES))
            return ModelResponse(report=json.dumps({"summary": "It checks for a debugger.", "verdict": "malicious", "findings": [{
                "title": "Debugger check", "description": "d", "severity": "high", "confidence": "high", "evidence_refs": ["E1"],
            }]}))

    imports = [{"dll": "kernel32.dll", "name": "IsDebuggerPresent", "ordinal": None, "address": 1}]
    objective = InvestigationObjective(name="Assess imports", description="d", reason="test", capabilities=("list_imports",))
    agent = StaticAgent(PagedList(0, imports=imports), model=MaliciousOnWeakEvidence(), trace_dir=tmp_path)

    finding = await agent.investigate(objective, "sample-1")

    assert finding.assessment.startswith("inconclusive:")
