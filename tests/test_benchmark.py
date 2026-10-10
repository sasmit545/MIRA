"""The benchmark harness: one row per run, and a comparison that keeps
efficiency and detection apart (R19, R20)."""

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
