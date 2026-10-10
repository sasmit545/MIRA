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
