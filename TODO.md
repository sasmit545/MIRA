# TODO — Restructure for the Multi-Agent System

Handoff for a new session. Written 2026-09-11 on `feature/static-mcp-server`.

---

## Where things stand

The static vertical slice **works end to end**. The agent picks its own tools,
recovers from tool failures, and writes a run trace.

```bash
.venv/Scripts/python.exe -m pytest -q          # 52 passed
.venv/Scripts/python.exe -m agent.main <sample> --objective "Identify suspicious behavior" \
    --max-turns 5 --max-tool-calls 5 --trace-dir runs
```

Two commits are **unpushed**: `2ece585` (agent runnable end to end),
`9e449c1` (capability contracts match implementations).

All 11 MCP capabilities are reachable through the isolated worker.
`run_capa` returns an honest `TOOL_NOT_AVAILABLE`; `scan_yara` needs a
configured ruleset. Both are correct behaviour, not bugs.

---

## Decisions already made — do not relitigate

| Decision | Rationale |
|---|---|
| **Keep both architectures.** The Coordinator assigns the objective; the reasoning loop chooses tools within it. | Matches `plan/PLAN_MCP_SERVER.md`'s success criterion: *evidence causes the Coordinator to assign a different objective*. `plan/phase1.md` describes a single agent with no Coordinator — that plan is **superseded** on this point. |
| **Contract inputs were bent to match handlers**, not the reverse. | Implementing pagination in `run_capa`/`scan_yara` is real feature work. Deferrals are marked `TODO(pagination)` at each contract. |
| **Output contracts stay unreconciled for now.** | All 11 disagree with what handlers return. It does not block the agent, which uses the untyped `client.invoke()` path and never validates outputs. |
| **Do not build Dynamic/Forensics agents yet.** | Deferred in the scope doc, and no dynamic capabilities exist for them to call. Scaffolding for agents that cannot act is the trap to avoid. |
| **Model: `gemini-3.6-flash`.** | `gemini-pro` and `gemini-2.5-flash` are both refused for new keys. `list_models()` still advertises models the key cannot call — trust the error, not the listing. Override with `GEMINI_MODEL`. |

---

## The work, in order

**Order matters: move before composing.** Step 4 adds imports that step 1
would otherwise force you to rewrite twice.

### 1. Move `agent/` → `mira/reasoning/`

The loop is shared substrate that all three specialists will use. Today it is
a second top-level package whose name differs from `mira/agents/` by one
letter, which is actively confusing.

- `git mv agent mira/reasoning`
- Update `pyproject.toml`: `include = ["mira*"]` (drop `agent*`)
- Fix imports in `tests/test_state.py`, `test_context.py`, `test_loop.py`,
  `test_completion.py`, `test_agent_e2e.py`
- Entrypoint becomes `python -m mira.reasoning.main`

**Done when:** 52 tests still pass and the CLI still runs.

### 2. De-static the reasoning package

Only four things in it are static-specific. Everything else is already
agent-agnostic — verified by grep, not assumed.

- `definition/agent.py` — rename `StaticAgentDefinition` → `AgentDefinition`.
  The class holds nothing static (instructions, tool_manifest, allowed_tools,
  max_turns, max_tool_calls, output_contract). Update `runtime/loop.py` and
  `runtime/completion.py`, which type-hint it.
- `definition/instructions.py:15` — `"Role: You are a static malware
  investigator."` is hardcoded. Make `role` a parameter.
- `runtime/context.py` — the `SCOPE` constant says "Static analysis only".
  Move it onto `AgentDefinition` so each specialist supplies its own.

**Done when:** nothing under `mira/reasoning/` contains the word "static"
except `main.py`, and no module there imports `mira.*` except `main.py`.

### 3. Split the composition root

`main.py` is the only file importing `mira.*` (`StaticMCPServer`,
`STATIC_CAPABILITIES`, `ArtifactStore`). It is static-specific by nature —
Dynamic and Forensics will each need their own wiring.

- Generic helpers (build loop, build tracer) stay in `mira/reasoning/`
- Static wiring (`build_client`, `tool_manifest`, `build_executor`) moves
  beside the static specialist

Keep `build_executor`'s artifact binding: it strips any model-supplied
`artifact_id` and substitutes the real one, so the model cannot retarget
another sample. There is a test for this in `tests/test_agent_e2e.py`.

### 4. Compose `StaticAgent` onto the loop

This is what makes "keep both" real.

`mira/agents/static_agent.py::investigate()` currently runs a fixed list:

```python
for capability in objective.capabilities:      # replace this
    result = await self._client.invoke(capability, artifact_id=artifact_id)
```

Replace it with the reasoning loop, passing `objective.capabilities` as the
definition's `allowed_tools` — the Coordinator sets the objective, the model
picks tools *within* it.

- **Keep the signature** `investigate(objective, artifact_id) -> StaticFinding`.
  That signature *is* the specialist interface Dynamic and Forensics will
  implement (README §11).
- **Keep `_evidence_from_result`.** It normalizes tool output into the
  evidence shape the Coordinator reads. Evidence-driven reassignment depends
  on it — if it breaks, the whole demo breaks.

⚠️ **`tests/test_static_investigation_loop.py` will break.** It asserts a
fixed sequence `["file_info", "analyze_pe", "detect_packer", "extract_strings"]`.
Once a model chooses, that is no longer deterministic. Rewrite it with a
scripted model (see `ScriptedModel` in `tests/test_agent_e2e.py`). The test
should still prove *evidence changes the second objective* — just without
pretending tool choice is fixed.

### 5. Finish the shared investigation state

`mira/core/state.py` **does not import** — it needs `mira/core/hypothesis.py`
and `mira/core/task.py`, which were never written. Nothing imports it today,
so nothing breaks; it is unfinished work, not cruft.
`plan/PLAN_MCP_SERVER.md` lists hypothesis/task models as **in scope**.

With one agent this is optional bookkeeping. With three it is the point: it is
the shared memory specialists write into and the orchestrator reasons over.

- Write `hypothesis.py` and `task.py` per README §9
- Make `InvestigationState` import and round-trip via `to_dict`/`from_dict`
- `mira/core/evidence.py` already has a `source_agent` field — it was designed
  for exactly this

### 6. Optional, cheap now

Rename `StaticObjective`/`StaticFinding` → `Objective`/`Finding`. README §11
says every specialist produces the same shape, so they should share one type.
A rename today; a refactor across three agents later.

---

## Traps

- **`multiprocessing` uses `spawn`.** Any probe script must be a real `.py`
  file with an `if __name__ == "__main__":` guard. Running one via heredoc or
  stdin makes the worker die with
  `OSError: Invalid argument: '<stdin>'`, which surfaces as a misleading
  `RESOURCE_LIMIT: analysis worker exited without a result`.
- **Never let the model adapter swallow exceptions.** It used to return an
  empty `ModelResponse` on any error, which disguised a 404 as a polite
  "degraded" exit and cost real debugging time. API failures must propagate;
  only *unparseable text* counts as an empty response.
- **Transport success is not tool success.** `ToolRuntime._envelope_error`
  maps a capability's own `status: error` payload to a failed `ToolResult`.
  Without it the model sees errors as successes and retries the same broken
  call until it hits the limit. Do not regress this.
- **`agent/model/testing.py` (`MockModel`) is unused.** Tests define their own
  scripted models. Either adopt it or delete it.
- **`salvage-broken-state`** is a local-only tag holding a previously damaged
  working tree. Safe to delete once you are confident: `git tag -d salvage-broken-state`.

---

## Explicitly deferred — not now

- `dynamic_agent.py`, `forensics_agent.py`, and their MCP servers
- Specialist selection in the Coordinator (it assigns static objectives only
  this milestone)
- Pagination for `run_capa`, `scan_yara`, `disassemble_function`
  (`TODO(pagination)` markers mark each site)
- Chunked entropy (`chunk_size`, `chunks[]`) — the handler measures the whole
  file or one bounded region
- Reconciling the 11 output contracts
- Migrating off `google-generativeai` (end-of-life; warns on every run) to
  `google-genai`, which installs cleanly as `google-genai 2.23.0`
