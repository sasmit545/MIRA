"""Count how often each evidence rule fires on benign and malicious dev samples, with no model (KTD9, KTD10).

    python scripts/survey_signals.py samples.csv --skip run_capa --ruleset all

Reads the benchmark manifest (see benchmark_static.py) and surveys every row
outside the test split, which no grade may be tuned on (R6). Each sample runs
the static capabilities in a fixed order with default arguments, and each
result is normalized into signals as an investigation would, but no evidence is
minted and no model is called. disassemble_function is never run: it needs an
address a model chooses. scan_yara runs once per --ruleset and not at all
without one; `--ruleset all` scans every configured ruleset, which is slow.

A rule counts as evaluated on a sample only when its capability, and every
capability its normalizer reads as prior, succeeded. A failure is a failed
evaluation, never a rule that did not fire. A rule's grade ceiling follows its
benign firing rate, and only when the survey is adequate for it.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from benchmark_static import _rate, read_manifest, unreadable

from mira.agents.static.evidence import NORMALIZERS, PRIOR_CAPABILITIES, normalize
from mira.agents.static.wiring import _configured_yara_rulesets, build_client, build_executor
from mira.core.evidence import grade

# file_info and analyze_pe first: later normalizers read them as prior.
SURVEY_ORDER = (
    "file_info", "analyze_pe", "list_imports", "list_exports", "extract_strings",
    "calculate_entropy", "detect_packer", "list_functions", "run_capa", "scan_yara",
)
NEVER_RUN = "disassemble_function"
LABELS = ("benign", "malicious")

# KTD10. Provisional rules: a ceiling, never a reason to raise a grade.
MIN_BENIGN_EVALUATED = 50
MIN_COVERAGE = 0.9
STRONG_CEILING = 0.05  # highest benign firing rate a strong rule may have
MODERATE_CEILING = 0.20


async def survey_sample(path: Path, skip=frozenset(), rulesets=()) -> dict:
    """Which capabilities succeeded on one sample, and the rules that fired,
    each with its capability and strongest confidence."""
    client, artifact_id = build_client(path)
    execute = build_executor(client, artifact_id)
    prior, succeeded, fired = {}, {}, {}
    for capability in SURVEY_ORDER:
        calls = [{"ruleset": name} for name in rulesets] if capability == "scan_yara" else [{}]
        if capability in skip or not calls:
            continue
        outcomes = []
        for arguments in calls:
            try:
                result = await execute(capability, arguments)
            except Exception as error:  # a crashed worker is a failed evaluation
                result = {"status": "error", "error": {"message": f"{type(error).__name__}: {error}"}}
            outcomes.append(result)
            for signal in normalize(capability, result, prior):
                strongest = max(signal.confidence, fired.get(signal.rule, ("", 0.0))[1])
                fired[signal.rule] = (capability, strongest)
        succeeded[capability] = all(result.get("status") == "ok" for result in outcomes)
        prior[capability] = outcomes[-1]
    return {"succeeded": succeeded, "fired": fired}


def _evaluated(sample: dict, capability: str) -> bool:
    return all(sample["succeeded"].get(name) for name in (capability, *PRIOR_CAPABILITIES.get(capability, ())))


def ceiling(benign: dict) -> str:
    """The highest grade a rule's benign firing rate allows (KTD10)."""
    if benign["evaluated"] < MIN_BENIGN_EVALUATED or benign["evaluated"] < MIN_COVERAGE * benign["attempted"]:
        return "blocked: coverage"
    rate = benign["fired"] / benign["evaluated"]
    return "strong" if rate <= STRONG_CEILING else "moderate" if rate <= MODERATE_CEILING else "weak"


def tally(samples: list[dict]) -> list[dict]:
    """One row per rule that fired on any surveyed sample."""
    rules: dict[str, dict] = {}
    for sample in samples:
        for rule, (capability, confidence) in sample["fired"].items():
            known = rules.setdefault(rule, {"capability": capability, "confidence": confidence})
            known["confidence"] = max(known["confidence"], confidence)
    rows = []
    for rule, known in sorted(rules.items()):
        row = {"rule": rule, **known}
        for label in LABELS:
            attempted = [s for s in samples if s["label"] == label and known["capability"] in s["succeeded"]]
            evaluated = [s for s in attempted if _evaluated(s, known["capability"])]
            row[label] = {
                "attempted": len(attempted), "evaluated": len(evaluated),
                "fired": sum(rule in s["fired"] for s in evaluated),
            }
        row["ceiling"] = ceiling(row["benign"])
        rows.append(row)
    return rows


def report(samples: list[dict], skipped, refused: list[str]) -> str:
    lines = [f"{len(samples)} sample{'' if len(samples) == 1 else 's'} surveyed, test split excluded."]
    lines += [f"refused {line}" for line in refused]
    lines += ["", "Capabilities"]
    for capability in sorted(NORMALIZERS):
        runs = {label: [s["succeeded"][capability] for s in samples if s["label"] == label and capability in s["succeeded"]]
                for label in LABELS}
        if capability in skipped or capability == NEVER_RUN or not any(runs.values()):
            lines.append(f"  {capability:<20} skipped")
            continue
        lines.append(f"  {capability:<20} " + "  ".join(
            f"{label} {sum(outcomes)}/{len(outcomes)} succeeded" for label, outcomes in runs.items()
        ))
    lines += [
        "", "Rules: fired over evaluated per label, failed evaluations, coverage (evaluated over attempted), "
        f"and the ceiling its benign rate allows (needs {MIN_BENIGN_EVALUATED} benign evaluated and "
        f"{MIN_COVERAGE:.0%} coverage)",
    ]
    for row in tally(samples):
        lines.append(f"{row['rule']}  [{row['capability']}, now {grade(row['confidence'])} {row['confidence']:.2f}]")
        for label in LABELS:
            count = row[label]
            lines.append(
                f"  {label:<10} fired {_rate(count['fired'], count['evaluated'])}  "
                f"failed {count['attempted'] - count['evaluated']}  coverage {_rate(count['evaluated'], count['attempted'])}"
            )
        lines.append(f"  ceiling    {row['ceiling']}")
    return "\n".join(lines)


async def survey(manifest: Path, skip=frozenset(), rulesets=()) -> str:
    samples, refused = [], []
    for entry in read_manifest(manifest):
        if entry["split"] == "test":
            continue
        path = entry.pop("path")
        error = unreadable(path, entry)
        if error:
            refused.append(f"{path}: {error}")
            continue
        print(f"surveying {path}", file=sys.stderr, flush=True)
        samples.append({"label": entry["label"].lower(), **await survey_sample(path, skip, rulesets)})
    return report(samples, skip, refused)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--skip", action="append", default=[], choices=SURVEY_ORDER, help="a capability not to attempt")
    parser.add_argument("--ruleset", action="append", default=[], help="a YARA ruleset to scan, or all")
    arguments = parser.parse_args()
    rulesets = sorted(_configured_yara_rulesets()) if "all" in arguments.ruleset else arguments.ruleset
    print(asyncio.run(survey(arguments.manifest, set(arguments.skip), rulesets)))


# The isolated capability workers start with spawn, which re-imports this file.
if __name__ == "__main__":
    main()
