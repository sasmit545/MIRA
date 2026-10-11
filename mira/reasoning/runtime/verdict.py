"""The verdict gate: structural rules a submitted report must meet (KTD2).

Pure. It checks the verdict is one of three (KTD3), caps each finding's
severity at the grade of the strongest evidence it cites (KTD5), and requires
strong cited evidence from two different capabilities for `malicious` (KTD4).
It reads only core concepts - a grade, a capability name, the working notes -
so every specialist's loop inherits it.

The guarantee is structural. Nothing here checks that a cited item supports
its claim, so a report that passes is policy-compliant, not proven right.
"""

import dataclasses
from typing import List

from mira.core.evidence import grade

from ..contracts.finding import Finding, Severity
from ..contracts.memory import WorkingMemory
from ..contracts.output import VERDICTS

# Strong evidence must come from this many capabilities. Source diversity, not
# proven independence: an import and a capa rule matching that same API are
# two capabilities reporting one fact (KTD4).
CORROBORATING_CAPABILITIES = 2
# The highest severity each grade of cited evidence allows; strong is uncapped.
SEVERITY_CAP = {"weak": Severity.LOW, "moderate": Severity.MEDIUM}
SEVERITY_ORDER = list(Severity)  # info < low < medium < high < critical


@dataclasses.dataclass(frozen=True)
class Outcome:
    """What stands of a report. `failure` is set only when a normal turn must
    reject it; `record` is the audit the trace keeps for every report (R13)."""

    verdict: str
    findings: List[Finding]
    failure: str
    record: dict


def check(submitted: object, findings: List[Finding], evidence: list, memory: WorkingMemory, *, final: bool) -> Outcome:
    """Gate one report. On the final report turn a failure downgrades the
    verdict to inconclusive instead of rejecting, since no turn follows (KTD6)."""
    by_id = {item.id: item for item in evidence}
    verdict = submitted.strip().lower() if isinstance(submitted, str) else ""
    reasons = []
    if verdict not in VERDICTS:
        reasons.append(f"verdict {submitted!r} is not one of: {', '.join(VERDICTS)}")

    repairs: list[str] = []
    findings = [_capped(finding, position, by_id, repairs) for position, finding in enumerate(findings)]

    cited = {ref.evidence_id for finding in findings for ref in finding.evidence_refs}
    strong = [item for item in evidence if grade(item.confidence) == "strong"]
    strong_cited = {item.id for item in strong if item.id in cited}
    if verdict == "malicious":
        sources = sorted({by_id[ref].capability for ref in strong_cited})
        if len(sources) < CORROBORATING_CAPABILITIES:
            reasons.append(
                f"malicious needs strong cited evidence from at least {CORROBORATING_CAPABILITIES} different "
                f"capabilities, and the findings cite strong evidence from {len(sources)}"
                f"{' (' + ', '.join(sources) + ')' if sources else ''}. "
                "Gather corroborating evidence and cite it, or submit inconclusive"
            )

    if not reasons:
        outcome, failure = ("repaired" if repairs else "accepted"), ""
    elif final:
        outcome, failure, verdict = "downgraded", "", "inconclusive"
    else:
        outcome, failure = "rejected", "; ".join(reasons)
    return Outcome(verdict, findings, failure, {
        "outcome": outcome,
        "submitted_verdict": submitted,
        "reasons": reasons,
        "repairs": repairs,
        "uncited_strong": [item.id for item in strong if item.id not in cited],
        # Recorded, not enforced (KTD7): the notes cannot yet say whether a
        # contradiction was resolved, so a verdict is never changed for one.
        "contradicted_hypotheses": [
            hypothesis.id for hypothesis in memory.hypotheses
            if hypothesis.contradicting_evidence and strong_cited & set(hypothesis.supporting_evidence)
        ],
    })


def _capped(finding: Finding, position: int, by_id: dict, repairs: list) -> Finding:
    """Severity is the model's opinion and a grade is code's measurement, so
    an overstated severity is lowered, not rejected (KTD5)."""
    grades = [grade(by_id[ref.evidence_id].confidence) for ref in finding.evidence_refs if ref.evidence_id in by_id]
    if not grades:
        cap, basis = Severity.INFO, "it cites no evidence"
    elif "strong" in grades:
        return finding
    else:
        strongest = "moderate" if "moderate" in grades else "weak"
        cap, basis = SEVERITY_CAP[strongest], f"its strongest cited evidence is {strongest}"
    if SEVERITY_ORDER.index(finding.severity) <= SEVERITY_ORDER.index(cap):
        return finding
    repairs.append(f"findings[{position}] severity {finding.severity.value} lowered to {cap.value}: {basis}")
    return dataclasses.replace(finding, severity=cap)
