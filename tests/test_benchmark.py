"""The benchmark harness: one row per run, and a comparison that keeps
efficiency and detection apart (R19, R20)."""

import hashlib
import importlib.util
import json
from pathlib import Path

from support import build_minimal_pe

from mira.reasoning.contracts.model import ModelResponse
from mira.reasoning.contracts.tool import ToolCall

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_static.py"
_spec = importlib.util.spec_from_file_location("benchmark_static", SCRIPT)
benchmark = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(benchmark)

REPORT = '{"summary": "small", "verdict": "benign", "findings": []}'


class ImportsThenReport:
    def __init__(self):
        self.turn = 0

    def generate(self, context, tools, force=None):
        if force == "record_memory":
            return ModelResponse()
        self.turn += 1
        if self.turn == 1:
            return ModelResponse(tool_calls=[ToolCall("1", "list_imports", {})])
        return ModelResponse(report=REPORT)


def manifest(tmp_path, *rows):
    path = tmp_path / "samples.csv"
    path.write_text("# path,label\n" + "\n".join(rows) + "\n")
    return path


async def test_a_run_row_has_every_metric_and_the_label(tmp_path):
    (tmp_path / "tiny.exe").write_bytes(build_minimal_pe())
    out = tmp_path / "rows.jsonl"

    rows = await benchmark.run_manifest(
        manifest(tmp_path, "tiny.exe,benign"), 2, "Identify suspicious behavior",
        tmp_path / "traces", out, model_factory=ImportsThenReport,
    )

    assert len(rows) == 2
    row = rows[0]
    assert row["ok"] and row["label"] == "benign" and row["verdict"] == "benign"
    for key in (*benchmark.METRICS, "seconds", "completion_reason", "coverage", "findings"):
        assert key in row, key
    assert row["model_calls"] == 2
    assert row["coverage"][0]["capability"] == "list_imports"
    assert [json.loads(line) for line in out.read_text().splitlines()] == rows


async def test_a_missing_sample_is_a_failed_row_and_the_rest_still_run(tmp_path):
    (tmp_path / "tiny.exe").write_bytes(build_minimal_pe())

    rows = await benchmark.run_manifest(
        manifest(tmp_path, "gone.exe,malicious", "tiny.exe,benign"), 1, "Identify suspicious behavior",
        tmp_path / "traces", tmp_path / "rows.jsonl", model_factory=ImportsThenReport,
    )

    assert [row["ok"] for row in rows] == [False, True]
    assert "not found" in rows[0]["error"]


FULL_HEADER = "path,label,sha256,label_source,labeled_on,split,source,family,packed"


def write_sample(tmp_path, name="tiny.exe"):
    path = tmp_path / name
    path.write_bytes(build_minimal_pe())
    return hashlib.sha256(path.read_bytes()).hexdigest()


async def run(tmp_path, *rows, split=None, header=FULL_HEADER):
    path = tmp_path / "samples.csv"
    path.write_text("\n".join([header, *rows]) + "\n")
    return await benchmark.run_manifest(
        path, 1, "objective", tmp_path / "traces", tmp_path / "rows.jsonl",
        model_factory=ImportsThenReport, split=split,
    )


async def test_a_labeled_manifest_carries_its_sample_fields_into_each_row(tmp_path):
    digest = write_sample(tmp_path)

    (row,) = await run(tmp_path, f"tiny.exe,benign,{digest.upper()},vendor,2026-10-11,dev,system32,,no")

    assert row["ok"]
    assert row["sha256"] == digest
    assert (row["split"], row["source"], row["family"], row["packed"]) == ("dev", "system32", "", "no")
    assert (row["label_source"], row["labeled_on"]) == ("vendor", "2026-10-11")


async def test_a_legacy_manifest_still_runs_and_records_the_computed_hash(tmp_path):
    digest = write_sample(tmp_path)

    (row,) = await run(tmp_path, "tiny.exe,benign", header="# path,label")

    assert row["ok"] and row["label"] == "benign"
    assert row["sha256"] == digest
    assert row["split"] == row["source"] == row["family"] == row["label_source"] == ""


async def test_a_sample_whose_bytes_changed_is_a_failed_row_and_the_rest_still_run(tmp_path):
    digest = write_sample(tmp_path)
    write_sample(tmp_path, "other.exe")

    rows = await run(tmp_path, f"tiny.exe,benign,{'0' * 64}", f"other.exe,benign,{digest}")

    assert [row["ok"] for row in rows] == [False, True]
    assert "hash mismatch" in rows[0]["error"]
    assert rows[0]["sha256"] == digest  # the file's own hash, not the recorded one


async def test_a_split_filter_runs_only_that_split(tmp_path):
    write_sample(tmp_path)
    write_sample(tmp_path, "other.exe")

    rows = await run(tmp_path, "tiny.exe,benign,,,,dev", "other.exe,benign,,,,test", split="dev")

    assert [Path(row["sample"]).name for row in rows] == ["tiny.exe"]


def test_the_cli_and_the_benchmark_default_to_one_neutral_objective(tmp_path, monkeypatch):
    """test_web.py checks the web form and the dashboard against the same constant."""
    import sys

    import pytest

    from mira.reasoning import main as cli

    seen = []

    async def record(sample, objective, *args, **kwargs):
        seen.append(objective)
        raise RuntimeError("stop after the objective is known")

    monkeypatch.setattr(cli, "investigate", record)
    monkeypatch.setattr(sys, "argv", ["mira", str(tmp_path / "sample.exe")])
    with pytest.raises(RuntimeError, match="objective is known"):
        cli.main()

    async def record_manifest(manifest, runs, objective, *args, **kwargs):
        seen.append(objective)

    monkeypatch.setattr(benchmark, "run_manifest", record_manifest)
    monkeypatch.setattr(sys, "argv", ["benchmark", "run", "samples.csv"])
    benchmark.main()

    assert seen == [cli.DEFAULT_OBJECTIVE] * 2
    assert "suspicious" not in cli.DEFAULT_OBJECTIVE.lower()


async def test_every_row_records_where_and_how_it_ran(tmp_path):
    write_sample(tmp_path)

    rows = await run(tmp_path, "tiny.exe,benign", "missing.exe,malicious")

    for row in rows:
        assert row["revision"] and isinstance(row["dirty"], (bool, type(None)))
        assert row["model"] == "scripted" and row["endpoint_host"] == ""
        assert row["objective"] == "objective"


def row(sample, verdict, calls, label="malicious"):
    return {
        "sample": sample, "label": label, "run": 0, "ok": True, "verdict": verdict,
        "completion_reason": "reported", "findings": [{"title": f"{verdict} finding", "evidence_refs": ["E1"]}],
        "model_calls": calls, "prompt_tokens": calls * 100, "completion_tokens": 10,
        "turns": calls, "tool_calls": 1, "seconds": 1.0,
    }


def test_compare_reports_medians_and_keeps_detection_separate():
    baseline = [row("a.exe", "malicious", n) for n in (4, 6, 9)]
    pipeline = [row("a.exe", "malicious", 3), row("a.exe", "benign", 3), row("a.exe", "benign", 5)]

    text = benchmark.compare(baseline, pipeline)

    efficiency, detection = text.split("Detection:")
    assert "model_calls" in efficiency and "6 (4-9)" in efficiency and "3 (3-5)" in efficiency
    assert "malicious" not in efficiency and "benign" not in efficiency
    assert "CHANGED" in detection
    assert "baseline: malicious x3" in detection and "pipeline: benign x2, malicious x1" in detection
    assert "benign finding" in detection
