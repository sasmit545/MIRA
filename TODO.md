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

All 11 MCP capabilities are reachable through the isolated worker and all now
have real implementations — `run_capa` runs flare-capa's vivisect backend and
`scan_yara` runs yara-python, both against a rule set.

Rules are **git submodules** — `rules/capa` (`mandiant/capa-rules`, pinned to
the `v9.1.0` tag, matching the installed `flare-capa` major version) and
`rules/signature-base` (`Neo23x0/signature-base`, pinned to whatever commit
was current when added). `.gitmodules` records both; the superproject only
stores a commit pointer per submodule, not the file content, so bumping a
pin is a tiny diff regardless of how much the upstream rule set changed.

**A plain `git clone` leaves both as empty directories** — that's how
submodules work, not a bug. Run `scripts/fetch_rules.sh` (a thin
`git submodule update --init --recursive` wrapper) once after cloning; CI
does this too (`.circleci/config.yml`). `wiring.py` falls back to
`rules/capa` / `rules/signature-base/yara` whenever `MIRA_CAPA_RULES_DIR` /
`MIRA_YARA_RULES_DIR` aren't set — if the submodules were never initialized
that fallback resolves to nothing and both capabilities just report
`TOOL_NOT_AVAILABLE`, silently, so if either stops working the first thing to
check is `git submodule status`.

To update to a newer upstream version:
```bash
git -C rules/capa fetch --tags && git -C rules/capa checkout <new-tag>
git -C rules/signature-base pull origin master
git add rules/capa rules/signature-base && git commit
```

Unlike a plain vendored copy, submodules can't be trimmed to just the files
each capability reads — `rules/signature-base` carries its full repo
(`iocs/`, `misc/`, `vendor/`, tests, CI config, none of it touched by
`scan_yara`) alongside the `yara/` subtree that actually matters.

Verified against both real corpora before the submodule switch (capa-rules
and signature-base content is identical at the pins above; only the
packaging — trimmed vendored copy vs. full submodule checkout — changed):

- `run_capa` against the full ~1000-rule capa-rules set took **24-36s** on a
  trivial synthetic PE (vivisect's cost, not rule count) — `wiring.py` bumps
  the default timeout to 90s automatically once a capa rules dir resolves
  (vendored or configured); override `MIRA_ANALYSIS_TIMEOUT_SECONDS` directly
  if that's still not enough for real-sized samples.
- `scan_yara` compiles and scans **751/751** signature-base files cleanly.
  13 of them need YARA external variables (`filename`, `filepath`,
  `extension`, `filetype`, `owner`, `imphash` — the LOKI/THOR convention);
  `scan_yara` now declares all six on every compile. `filename`/`filepath`/
  `extension`/`imphash` are real facts about the artifact; `filetype`/`owner`
  have no reliable equivalent here (no THOR-taxonomy classifier, no live
  filesystem ACL) and are best-effort placeholders — rules gated on them
  just don't match, which is correct, not an error.

---

## Decisions already made — do not relitigate

| Decision | Rationale |
|---|---|
| **Keep both architectures.** The Coordinator assigns the objective; the reasoning loop chooses tools within it. | Matches `plan/PLAN_MCP_SERVER.md`'s success criterion: *evidence causes the Coordinator to assign a different objective*. `plan/phase1.md` describes a single agent with no Coordinator — that plan is **superseded** on this point. |
| **Contract inputs were bent to match handlers**, not the reverse. | Now moot: `run_capa`, `scan_yara`, and `disassemble_function` all page with `limit`/`offset` via the shared `paginate()` helper, and their contracts match. |
| **Output contracts are reconciled.** | All 11 handlers match what their contracts declare; `StaticMCPServer` rejects a drift as `CONTRACT_VIOLATION`. |
| **Do not build Dynamic/Forensics agents yet.** | Deferred in the scope doc, and no dynamic capabilities exist for them to call. Scaffolding for agents that cannot act is the trap to avoid. |
| **Model: `grok-4.6` via Azure AI Foundry (OpenAI-compatible API).** | Replaced Gemini: `google-generativeai` was end-of-life and its free tier's 5 req/min quota made multi-turn runs unusable. Override with `MODEL_NAME`; key goes in `MODEL_API_KEY`. |

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
- Auto-updating the `rules/` submodule pins. Bumping them is a manual
  `git checkout <tag>` + commit for now (see above), not scheduled or
  automatic.
- capa's rule cache (`enable_cache=False` always) — fine for the ~1000-rule
  set at 24-36s a call, would matter more against something larger
