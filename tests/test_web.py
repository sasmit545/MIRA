import asyncio
import json

from fastapi.testclient import TestClient

from mira.reasoning.contracts.output import FinalOutput
from mira.web import create_app


async def test_web_run_returns_report_and_trace(tmp_path, monkeypatch):
    async def fake_investigate(sample_path, objective, **kwargs):
        kwargs["on_turn"]({"kind": "tool_calls", "turn": 1, "calls": [], "results": []})
        (kwargs["trace_dir"] / "trace_sample_identify_suspicious_behavior.json").write_text("[]")
        return FinalOutput(
            summary="Completed safely.", verdict="suspicious", findings=[], evidence=[],
            completion_reason="reported", metadata={"run_id": "sample_identify_suspicious_behavior", "total_tokens": 3},
        )

    monkeypatch.setattr("mira.web.investigate", fake_investigate)
    with TestClient(create_app(tmp_path / "runs")) as client:
        response = client.post(
            "/api/investigations",
            data={"objective": "Identify suspicious behavior", "max_turns": "2", "max_tool_calls": "2"},
            files={"sample": ("sample.exe", b"MZ", "application/octet-stream")},
        )
        assert response.status_code == 202
        run = response.json()
        for _ in range(20):
            detail = client.get(f"/api/investigations/{run['id']}").json()
            if detail["status"] == "completed":
                break
            await asyncio.sleep(0.01)

        assert detail["result"]["verdict"] == "suspicious"
        assert client.get(f"/api/investigations/{run['id']}/trace").json() == []

        # A viewer arriving after the run gets each event once, and the closing
        # event carries the report the page renders.
        stream = client.get(f"/api/investigations/{run['id']}/events").text
        events = [json.loads(chunk[len("data: "):]) for chunk in stream.split("\n\n") if chunk]
        assert [event["kind"] for event in events] == ["tool_calls", "completed"]
        assert events[-1]["result"]["verdict"] == "suspicious"


async def test_a_failed_run_leaves_its_events_and_traceback_on_disk(tmp_path, monkeypatch):
    async def failing_investigate(sample_path, objective, **kwargs):
        kwargs["on_turn"]({"kind": "empty", "turn": 1})
        raise RuntimeError("model endpoint unreachable")

    monkeypatch.setattr("mira.web.investigate", failing_investigate)
    with TestClient(create_app(tmp_path / "runs")) as client:
        run = client.post(
            "/api/investigations",
            data={"objective": "Identify suspicious behavior"},
            files={"sample": ("sample.exe", b"MZ", "application/octet-stream")},
        ).json()
        for _ in range(20):
            if client.get(f"/api/investigations/{run['id']}").json()["status"] == "failed":
                break
            await asyncio.sleep(0.01)

    log = tmp_path / "runs" / run["id"] / "events.jsonl"
    events = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert [event["kind"] for event in events] == ["empty", "failed"]
    assert events[-1]["error"] == "model endpoint unreachable"
    assert "failing_investigate" in events[-1]["traceback"]


async def test_the_web_form_defaults_to_the_cli_objective(tmp_path, monkeypatch):
    """test_benchmark.py checks the CLI and the benchmark against the same constant."""
    import html
    import re
    from pathlib import Path

    from mira.reasoning.main import DEFAULT_OBJECTIVE

    seen = []

    async def record(sample_path, objective, **kwargs):
        seen.append(objective)
        raise RuntimeError("stop after the objective is known")

    # Posted without an objective.
    monkeypatch.setattr("mira.web.investigate", record)
    with TestClient(create_app(tmp_path / "runs")) as client:
        client.post("/api/investigations", files={"sample": ("sample.exe", b"MZ", "application/octet-stream")})
        for _ in range(20):
            if seen:
                break
            await asyncio.sleep(0.01)

    page = (Path(__file__).resolve().parents[1] / "mira" / "web" / "dashboard.html").read_text(encoding="utf-8")
    field = re.search(r'<textarea[^>]*id="f-objective"[^>]*>(.*?)</textarea>', page, re.S).group(1)

    assert seen == [DEFAULT_OBJECTIVE]
    assert html.unescape(field) == DEFAULT_OBJECTIVE


async def test_the_stream_carries_bounded_tool_output_and_no_raw_observations(tmp_path, monkeypatch):
    from mira.reasoning.contracts.tool import ToolCall, ToolResult
    from mira.reasoning.runtime.payload import MAX_DIGEST_CHARS

    big = {"status": "ok", "data": {"strings": [{"value": f"s{i}" * 20, "offset": i} for i in range(5000)]}}
    call = ToolCall(tool_call_id="c1", name="extract_strings", arguments={})

    async def fake_investigate(sample_path, objective, **kwargs):
        kwargs["on_turn"]({"kind": "tool_calls", "turn": 1, "calls": [call], "results": [
            ToolResult(tool_call_id="c1", success=True, output=big),
            ToolResult(tool_call_id="c2", success=False, error="INVALID_INPUT: no such ruleset"),
        ]})
        return FinalOutput(
            summary="s", verdict="benign", findings=[], evidence=[], completion_reason="reported",
            metadata={"run_id": "r"}, observations=[ToolResult(tool_call_id="c1", success=True, output=big)],
        )

    monkeypatch.setattr("mira.web.investigate", fake_investigate)
    with TestClient(create_app(tmp_path / "runs")) as client:
        run = client.post(
            "/api/investigations", data={"objective": "o"},
            files={"sample": ("sample.exe", b"MZ", "application/octet-stream")},
        ).json()
        for _ in range(20):
            detail = client.get(f"/api/investigations/{run['id']}").json()
            if detail["status"] == "completed":
                break
            await asyncio.sleep(0.01)
        stream = client.get(f"/api/investigations/{run['id']}/events").text

    events = [json.loads(chunk[len("data: "):]) for chunk in stream.split("\n\n") if chunk]
    ok, failed = events[0]["results"]
    # The trace keeps the full output; the stream carries the digest the model saw.
    assert isinstance(ok["output"], str) and len(ok["output"]) < MAX_DIGEST_CHARS + 200
    assert failed["error"] == "INVALID_INPUT: no such ruleset"
    assert "observations" not in events[-1]["result"]
    assert "observations" not in detail["result"]
    assert detail["result"]["verdict"] == "benign"


async def test_the_chosen_model_reaches_the_investigation_and_an_unknown_one_is_refused(tmp_path, monkeypatch):
    seen = []

    async def record(sample_path, objective, **kwargs):
        seen.append(kwargs["model"])
        raise RuntimeError("stop after the model is known")

    monkeypatch.setattr("mira.web.investigate", record)
    sample = {"sample": ("sample.exe", b"MZ", "application/octet-stream")}
    with TestClient(create_app(tmp_path / "runs")) as client:
        chosen = client.post("/api/investigations", files=sample, data={"model": "azure"})
        default = client.post("/api/investigations", files=sample)
        unknown = client.post("/api/investigations", files=sample, data={"model": "nope"})
        models = client.get("/api/models").json()
        for _ in range(20):
            if len(seen) == 2:
                break
            await asyncio.sleep(0.01)

    assert chosen.json()["model"] == "azure" and default.json()["model"] == "nemotron"
    assert unknown.status_code == 400
    assert sorted(seen) == ["azure", "nemotron"]
    assert {m["id"] for m in models} == {"nemotron", "azure"}
