"""Benchmark the static investigator over a labeled sample manifest (R19, R20).

    python scripts/benchmark_static.py run samples.csv --runs 3 --out runs/benchmarks/baseline.jsonl
    python scripts/benchmark_static.py compare runs/benchmarks/baseline.jsonl runs/benchmarks/pipeline.jsonl

The manifest holds one `path,label` row per sample; blank lines and `#`
comments are skipped, and a relative path is read from the manifest's folder.
Samples stay outside the repo. Each run writes one JSON row as it finishes, so
an interrupted benchmark keeps what it measured.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import statistics
import time
from collections import Counter, defaultdict
from pathlib import Path

from mira.reasoning.composition import load_env
from mira.reasoning.main import investigate

DEFAULT_OBJECTIVE = "Identify suspicious behavior"
METRICS = (
    "model_calls",
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "turns",
    "tool_calls",
    "reruns_refused",
    "recalls_requested",
    "repeat_recalls",
    "findings_discarded",
)
# Paging counters a capability envelope may carry in its metadata.
COVERAGE_KEYS = ("offset", "limit", "has_more", "total", "fetched", "unfetched", "fetch_error")
EFFICIENCY_COLUMNS = ("model_calls", "prompt_tokens", "completion_tokens", "turns", "tool_calls", "seconds")


def read_manifest(path: Path) -> list[tuple[Path, str]]:
    rows = []
    with path.open(newline="") as manifest:
        for row in csv.reader(manifest):
            if not row or not row[0].strip() or row[0].lstrip().startswith("#"):
                continue
            sample = Path(row[0].strip())
            label = row[1].strip() if len(row) > 1 else ""
            rows.append((sample if sample.is_absolute() else path.parent / sample, label))
    return rows


def coverage(observations) -> list[dict]:
    """What each paged capability call fetched, from its envelope metadata."""
    found = []
    for result in observations:
        metadata = result.output.get("metadata") if result.success and isinstance(result.output, dict) else None
        if isinstance(metadata, dict) and any(key in metadata for key in COVERAGE_KEYS):
            found.append({"capability": metadata.get("capability"), **{k: metadata[k] for k in COVERAGE_KEYS if k in metadata}})
    return found


async def run_sample(sample: Path, label: str, run: int, objective: str, trace_dir: Path, model=None) -> dict:
    row = {"sample": str(sample), "label": label, "run": run}
    if not sample.is_file():
        return {**row, "ok": False, "error": f"sample not found: {sample}"}
    started = time.perf_counter()
    try:
        output = await investigate(sample, objective, trace_dir=trace_dir / f"run{run}", model=model)
    except Exception as error:  # one broken sample must not end the benchmark
        return {**row, "ok": False, "error": f"{type(error).__name__}: {error}", "seconds": time.perf_counter() - started}
    return {
        **row,
        "ok": True,
        "seconds": time.perf_counter() - started,
        "verdict": output.verdict,
        "completion_reason": output.completion_reason,
        "findings": [
            {"title": finding.title, "evidence_refs": [ref.evidence_id for ref in finding.evidence_refs]}
            for finding in output.findings
        ],
        **{key: output.metadata.get(key) for key in METRICS},
        "coverage": coverage(output.observations),
    }


async def run_manifest(manifest: Path, runs: int, objective: str, trace_dir: Path, out: Path, model_factory=None) -> list[dict]:
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    with out.open("a") as sink:
        for sample, label in read_manifest(manifest):
            # A missing file is one failed row, not one per run.
            for run in range(runs if sample.is_file() else 1):
                row = await run_sample(sample, label, run, objective, trace_dir, model_factory() if model_factory else None)
                rows.append(row)
                sink.write(json.dumps(row) + "\n")
                sink.flush()
                print(f"{Path(row['sample']).name} run {run}: " + (row.get("verdict") or row.get("error", "")))
    return rows


def load_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _by_sample(rows: list[dict]) -> dict[str, list[dict]]:
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["sample"]].append(row)
    return grouped


def _spread(values: list) -> str:
    values = [value for value in values if value is not None]
    if not values:
        return "-"
    median = statistics.median(values)
    shown = f"{median:.1f}" if isinstance(median, float) and not median.is_integer() else f"{median:g}"
    return f"{shown} ({min(values):g}-{max(values):g})" if len(values) > 1 else shown


def _verdicts(rows: list[dict]) -> Counter:
    return Counter(row["verdict"] for row in rows if row.get("ok"))


def _majority(rows: list[dict]) -> str:
    verdicts = _verdicts(rows)
    if not verdicts:
        return "no run"
    return ", ".join(f"{verdict} x{count}" for verdict, count in verdicts.most_common())


def compare(baseline: list[dict], pipeline: list[dict]) -> str:
    """Efficiency and detection as separate tables: a cheaper run says nothing
    about whether it still finds what it should (R20)."""
    before, after = _by_sample(baseline), _by_sample(pipeline)
    samples = sorted(set(before) | set(after))
    lines = ["Efficiency: median (min-max) per sample, baseline -> pipeline", ""]
    for sample in samples:
        old = [row for row in before.get(sample, []) if row.get("ok")]
        new = [row for row in after.get(sample, []) if row.get("ok")]
        lines.append(f"{Path(sample).name}  ({len(old)} -> {len(new)} ok runs)")
        for column in EFFICIENCY_COLUMNS:
            lines.append(f"  {column:<18} {_spread([row.get(column) for row in old]):>22} -> {_spread([row.get(column) for row in new])}")
    lines += ["", "Detection: verdicts per sample against its label", ""]
    for sample in samples:
        old, new = before.get(sample, []), after.get(sample, [])
        label = (old or new)[0]["label"]
        changed = "" if _top(old) == _top(new) else "  CHANGED"
        lines.append(f"{Path(sample).name}  label={label}{changed}")
        lines.append(f"  baseline: {_majority(old)}; reasons {_reasons(old)}")
        lines.append(f"  pipeline: {_majority(new)}; reasons {_reasons(new)}")
        failures = [row["error"] for row in old + new if not row.get("ok")]
        if failures:
            lines.append(f"  failed runs: {'; '.join(failures)}")
        if changed:
            for name, rows in (("baseline", old), ("pipeline", new)):
                titles = sorted({finding["title"] for row in rows if row.get("ok") for finding in row["findings"]})
                lines.append(f"  {name} findings: {'; '.join(titles) or 'none'}")
    return "\n".join(lines)


def _top(rows: list[dict]):
    verdicts = _verdicts(rows)
    return verdicts.most_common(1)[0][0] if verdicts else None


def _reasons(rows: list[dict]) -> str:
    reasons = Counter(row.get("completion_reason") for row in rows if row.get("ok"))
    return ", ".join(f"{reason} x{count}" for reason, count in reasons.most_common()) or "-"


def main() -> None:
    load_env()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="run every manifest sample several times")
    run.add_argument("manifest", type=Path)
    run.add_argument("--runs", type=int, default=3)
    run.add_argument("--objective", default=DEFAULT_OBJECTIVE)
    run.add_argument("--out", type=Path, default=Path("runs/benchmarks/benchmark.jsonl"))
    run.add_argument("--trace-dir", type=Path, default=Path("runs/benchmarks/traces"))
    versus = commands.add_parser("compare", help="compare a baseline row set with a pipeline row set")
    versus.add_argument("baseline", type=Path)
    versus.add_argument("pipeline", type=Path)
    arguments = parser.parse_args()

    if arguments.command == "run":
        asyncio.run(run_manifest(arguments.manifest, arguments.runs, arguments.objective, arguments.trace_dir, arguments.out))
    else:
        print(compare(load_rows(arguments.baseline), load_rows(arguments.pipeline)))


# The isolated capability workers start with spawn, which re-imports this file.
if __name__ == "__main__":
    main()
