"""Local browser interface for MIRA's static-analysis vertical slice."""

from __future__ import annotations

import asyncio
import json
import shutil
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse

from mira.reasoning.composition import load_env
from mira.reasoning.main import investigate
from mira.reasoning.runtime.trace import trace_path

TERMINAL = {"completed", "failed"}


def _json_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return _json_value(asdict(value))
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def create_app(data_dir: Path = Path("runs/ui")) -> FastAPI:
    """Create a local-only UI service backed by the existing investigator."""
    app = FastAPI(title="MIRA Investigation Console")
    app.state.data_dir = data_dir
    app.state.runs: dict[str, dict[str, Any]] = {}

    @app.get("/", response_class=HTMLResponse)
    async def dashboard() -> FileResponse:
        return FileResponse(Path(__file__).with_name("web") / "dashboard.html")

    @app.post("/api/investigations", status_code=202)
    async def start_investigation(
        sample: UploadFile = File(...),
        objective: str = Form("Identify suspicious behavior"),
        max_turns: int = Form(10),
        max_tool_calls: int = Form(20),
    ) -> dict[str, Any]:
        if not sample.filename:
            raise HTTPException(400, "A sample file is required")
        if not objective.strip():
            raise HTTPException(400, "An investigation objective is required")
        if max_turns < 1 or max_tool_calls < 1:
            raise HTTPException(400, "Turn and tool-call limits must be positive")

        investigation_id = uuid4().hex
        run_dir = app.state.data_dir / investigation_id
        run_dir.mkdir(parents=True, exist_ok=False)
        sample_path = run_dir / Path(sample.filename).name
        with sample_path.open("wb") as destination:
            shutil.copyfileobj(sample.file, destination)

        record = {
            "id": investigation_id,
            "status": "queued",
            "objective": objective.strip(),
            "sample_name": sample_path.name,
            "run_dir": run_dir,
            "events": [],
            "changed": asyncio.Event(),
            "result": None,
            "error": None,
        }
        app.state.runs[investigation_id] = record
        asyncio.create_task(_run(record, sample_path, max_turns, max_tool_calls))
        return _public_record(record)

    @app.get("/api/investigations/{investigation_id}")
    async def get_investigation(investigation_id: str) -> dict[str, Any]:
        return _record_or_404(app, investigation_id)

    @app.get("/api/investigations/{investigation_id}/events")
    async def stream_events(investigation_id: str) -> StreamingResponse:
        record = _record_or_404(app, investigation_id, raw=True)

        async def events():
            # Each subscriber reads the shared log at its own cursor, so a late
            # or second viewer gets a full replay and nobody steals events.
            sent = 0
            while True:
                changed = record["changed"]
                while sent < len(record["events"]):
                    event = record["events"][sent]
                    sent += 1
                    yield _sse(event)
                    if event["kind"] in TERMINAL:
                        return
                await changed.wait()

        return StreamingResponse(events(), media_type="text/event-stream")

    @app.get("/api/investigations/{investigation_id}/trace")
    async def get_trace(investigation_id: str) -> Any:
        record = _record_or_404(app, investigation_id, raw=True)
        result = record["result"]
        if result is None:
            raise HTTPException(409, "The investigation has not finished")
        path = Path(trace_path(record["run_dir"], result["metadata"]["run_id"]))
        if not path.is_file():
            raise HTTPException(404, "Trace file not found")
        return json.loads(path.read_text(encoding="utf-8"))

    return app


async def _run(record: dict[str, Any], sample_path: Path, max_turns: int, max_tool_calls: int) -> None:
    record["status"] = "running"

    def publish(event: dict) -> None:
        # Called on the event loop thread, so swapping the Event is race-free:
        # a subscriber captures it before reading and waits on that one.
        record["events"].append(_json_value(event))
        changed, record["changed"] = record["changed"], asyncio.Event()
        changed.set()

    try:
        load_env()
        output = await investigate(
            sample_path,
            record["objective"],
            trace_dir=record["run_dir"],
            max_turns=max_turns,
            max_tool_calls=max_tool_calls,
            on_turn=publish,
        )
        record["result"] = _json_value(output)
        record["status"] = "completed"
    except Exception as error:  # The UI reports the failed run; the trace remains inspectable.
        record["error"] = str(error)
        record["status"] = "failed"
    finally:
        publish({"kind": record["status"], "result": record["result"], "error": record["error"]})


def _record_or_404(app: FastAPI, investigation_id: str, *, raw: bool = False) -> dict[str, Any]:
    record = app.state.runs.get(investigation_id)
    if record is None:
        raise HTTPException(404, "Investigation not found")
    return record if raw else _public_record(record)


def _public_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": record["id"],
        "status": record["status"],
        "objective": record["objective"],
        "sample_name": record["sample_name"],
        "result": record["result"],
        "error": record["error"],
    }


def _sse(event: dict[str, Any]) -> str:
    return f"data: {json.dumps(_json_value(event))}\n\n"


app = create_app()

if __name__ == "__main__":
    import uvicorn

    # Loopback only: uploads are live malware samples and the API has no auth.
    uvicorn.run(app, host="127.0.0.1", port=8000)
