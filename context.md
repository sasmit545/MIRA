# Session handoff — Phase 2 Static Agent Working Memory

Updated 2026-10-10. Read this first, then the plan it points to.

## Where to work

- Branch: `feat/static-agent-working-memory`. Pushed, in sync with origin (head `15410a5`).
- Plan being executed: `docs/plans/2026-09-15-1200-feat-static-agent-working-memory-plan.md`
  (units U1–U9, Key Technical Decisions KTD1–KTD14, requirements R1–R23).
  Concept doc behind it: `plan/phase_2_static_agent_working_memory.md`.
- The previous plan, `docs/plans/2026-09-14-1337-feat-specialist-finding-contract-plan.md`
  (FINDING contract), is fully done and merged to `main`.
- Tests: `.venv/Scripts/python.exe -m pytest -q` — 281 pass.
- `docs/`, `plan/mira_static_agent_harness_idea_plan.md`, `plan/phase_2_static_agent_working_memory.md`
  are still **untracked** on purpose (user hasn't decided whether to commit them).
- `mira.egg-info/*` has local modifications; never commit them. Use `git pull --rebase --autostash` before pushing.
- `TODO.md` is stale (2026-09-11, old `agent.*` module names) — ignore it.

## Done (commits on the branch)

| Unit | Commit | What |
|---|---|---|
| U1 | `2ba6861` | `mira/reasoning/contracts/memory.py`: `WorkingMemory` (understanding, hypotheses, open_questions, candidates), `MemoryHypothesis` (mirrors `mira/core/hypothesis.py`: float confidence clamped 0..1, supporting/contradicting_evidence, status limited to `PROVISIONAL`, `unknowns`), `OpenQuestion`, `Candidate`. On `State.working_memory`; in `snapshot()`. `scratch` removed. |
| U9 | `342d18d` | `build_evidence_executor` in `mira/agents/static/wiring.py` — evidence minting shared by `StaticAgent.investigate` and the CLI (`mira/reasoning/main.py`). |
| U3 | `947984e` | `record_memory` declared in `adapter.declarations()` beside `submit_report`. Adapter splits it into `ModelResponse.memory_update`. Loop runs capability calls before judging a sibling report. |
| U4 | `ef95331` | `narrative.py` `apply_narrative()` — all-or-nothing validate + additive merge; `close` by id; status coerced via difflib; evidence refs must be minted ids. Notes required on any turn with capability calls; rejection is an off-budget harness observation; `MAX_MEMORY_REJECTIONS = 3` total → `degraded`. Valid report completes even if its notes were rejected. |
| U2 | `31c6f17` | `trace.py`: `_numbered()` is the one per-capability counting rule; `resolve_observation()` (trace file) and `live_observation(state, handle)` both go through `_find()`. `capability_history(state)` → `CapabilityRecord(handle, name, arguments, success, error, digest, evidence)`. Harness entries marked `'harness': True` and excluded. Fixed: evidence executor claims its occurrence before `invoke`. |
| U5 + digest redesign + U6 history | `3e3df41` | New `runtime/payload.py` (generic JSON, KTD1): `digest()` = structural sketch (arrays ≤8 items whole; larger ones first two + `…k more…` + last; `arrays: data.strings (1000)` line; `PARTIAL_MARKER`; cap 2000 chars). `select(output, args)` = recall query (`path`, `start`/`count` ≤200, `contains` case-insensitive substrings, not regex; arrays only; 6000-char cap with continuation hints). `truncate` lives here (trace + context re-export). `recall_observation` declared in adapter; loop intercepts by name before ToolRuntime (KTD7), `_recall()` → `State.recalled`, cleared right after each `context.build` so it shows in exactly the next prompt; off-budget; max 3/turn; recall-only turn owes no notes. Prompt history = `[handle] call` + evidence ids + digest; harness notes shown without a handle. Tests: `tests/test_recall.py`. |
| U7 | `12dc53a` | `FinalOutput.memory`; `StaticAgent` promotes hypotheses only on `reported` + state, ids continue past `len(state.hypotheses)`; assessment lists understanding, hypotheses (status, confidence, unknowns), unresolved questions. |
| U8 | `a89286c` | `ToolThenReportModel` sends `EMPTY_NOTES`; `NoNotesModel` stops on the rejection bound; high-volume e2e: no raw array middle in any prompt, growth < 10k chars, H1 carries, promotion matches notes; neutral-vocabulary test. Mutation-checked. **All units done; 295 pass.** |
| U6 rest | `6d157a5` | `render_memory()` in `context.py` (understanding, hypotheses with status/confidence/supported by/weakened by/unknowns, open questions, candidates; empty = "(none recorded yet)"). `instructions.py`: "Working notes" section (required with every capability call, additive, close by id, cite E-ids) and an R22 report-summary line. **U6 done.** |

**U3 live probe result** (grok-4.6 via Azure, 5 runs × 5 turns): `record_memory` + a capability call arrived together on **25/25** turns. Caveats: `submit_report`+`record_memory` never reached live; the model repeated `file_info`/`analyze_pe` (U2/U6 now show handles and refuse identical reruns).

## Verification of U6 (user's three checks)

`tests/test_memory_integration.py` (`15410a5`) drives the real loop with `build_evidence_executor`:
1. **Note persistence — confirmed.** An omitted hypothesis reads back unchanged in the next prompt; a reused id revises only the given fields; an empty `understanding` keeps the old one.
2. **Evidence integrity — confirmed, with one gap.** Every cited id is minted evidence and its provenance resolves to the producing call; an unknown id rejects the whole update. **Gap: recall never mints evidence.** A recalled fact is citable only through evidence the normalizer already minted from that call (provenance == handle). **Decided (user, 2026-10-10): keep evidence code-driven.** Recall never mints evidence; a gap is closed by adding a normalizer rule, not by citing recalled text.
3. **Final-state consistency — not testable until U7.** This becomes U7's main test.

## Next job: manual acceptance run (U7, U8 done — see table)

`python -m mira.reasoning.main <sample> --objective "Assess packing and capability" --trace-dir runs`; read successive `context_sent`, count `recall_observation` calls. The U7 notes below are historical.

## (Done) U7 — promote hypotheses at completion

Touchpoints (verified):
- `mira/reasoning/contracts/output.py` `FinalOutput`: add the final `WorkingMemory` (e.g. `memory: WorkingMemory = field(default_factory=WorkingMemory)`); set it in both `AgentLoop._parse_report` and the non-reported return at the end of `_run` (`loop.py`).
- `mira/agents/static/agent.py` `StaticAgent.investigate` (~line 100–160): after `loop.run`, **only if `output.completion_reason == "reported"` and `state is not None`**, build `mira.core.hypothesis.Hypothesis(id, statement, confidence, supporting_evidence, contradicting_evidence, status)` from each memory hypothesis and call `state.add_hypothesis()` (`mira/core/state.py:38`).
- Ids: memory uses model ids (`H1`…); continue numbering past `len(state.hypotheses)` so two runs never both deposit `H1` (same reason as evidence numbering in `build_evidence_executor`).
- `core.Hypothesis` has **no `unknowns` field**. **Decided (user, 2026-10-10): preserve unknowns in the assessment text**, one per hypothesis line (e.g. `H1 (supported, 0.80) "statement" — unknown: ...`). Do not add a field to `core.Hypothesis`.
- Assessment (R22): currently `f"{output.verdict}: {output.summary}"`. Append the final understanding, the hypotheses weighed (id, status, confidence) and unclosed open questions. No new FINDING field.
- Tests to write: a report after several note updates carries the **latest** memory (the user's check 3); hypotheses promoted only on `reported` (not on `limit_turns`/`degraded`); none without a state; ids continue past existing; promoted evidence refs resolve to `state.evidence`; assessment mentions unclosed questions.

Then:
- **U8** — end-to-end proof: give `ToolThenReportModel` in `tests/support.py` a default valid narrative; a second double that omits/malforms notes; assert no raw successful payload in any traced prompt, memory continuity, promoted hypotheses match final memory; specialist-neutral context regression test. `tests/test_memory_integration.py` already covers part of this — extend rather than duplicate.
- **Manual acceptance run** on a real sample via `python -m mira.reasoning.main <sample>`; count `recall_observation` invocations (plan risk: nothing forces the model to recall).

## Known gaps / decisions to keep in mind

- Recall output is not citable evidence (decided: evidence stays code-driven).
- Rejected reports still spend `tool_call_count` (pre-existing behavior, kept) though they now go through `record_harness_observation`.
- A memory-only response (no calls, no report) counts as non-empty; only `max_turns` bounds a model that never calls anything.
- Hypothesis evidence refs are validated against minted evidence ids (stricter than the plan; keeps U7's promoted refs resolvable).
- `Candidate.reason` exists on the contract but the `record_memory` schema doesn't offer it, so it's always empty.
- Recall search is substring-only (no regex, avoids ReDoS); IP-shaped search relies on the static normalizer's evidence.
- Recall covers one returned page; a capability page with `has_more: true` needs a new call with `offset`.

## Working conventions with this user

- Explain what you'll do and why before doing a unit; plain language, they asked for detail when lost.
- Commit per unit; push when asked (they have said "commit and push" / "push it"). `git pull --rebase --autostash` before pushing.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Windows + Git Bash: write multi-line Python edit scripts to the scratchpad and run them; never start a Bash command with a bare `cat >` (it hung once waiting on stdin).




You're right that it matters, and not only for installers. Inflating a file is a common evasion trick: attackers pad a binary to hundreds of MB with junk so it goes past scanners' and sandboxes' size limits. A fixed 64 MB limit is exactly the kind of limit that trick is built for. So "handle large files" is a real requirement. Raising the number alone wouldn't get you there, though.

What would break if we just raised the limit

All 11 capabilities treat the whole file as one unit:
- pe_support.py:28 and yara_scanner.py:59 read the entire file into memory (read_bytes()) and run a full PE parse. Each capability does this separately, in its own isolated worker.
- extract_strings scans every byte. On a 233 MB installer that's millions of strings, nearly all of them compressed noise.
- run_capa already takes about 150 seconds on 350 KB. It would hit its timeout on anything large.

With a bigger limit, the run would get further and then die on timeouts instead of failing cleanly at the start.

How analysis tools usually handle it

A large file is almost always a small program plus a big blob. The scalable approach is to find the blob and deal with it separately, not analyze all of it:

1. Accept big files, but stream them. Copy uploads in chunks, check the size at upload time, and raise the limit to something like 1 GB.
2. Make cheap capabilities work at any size. Hashes, PE headers, sections, entropy per region and overlay detection only need parts of the file (headers, offsets), so they stay fast on 500 MB.
3. Point expensive capabilities at the PE image only. capa, disassembly and strings run on the actual program, excluding the appended data. When something really is too big, they return act on: "too large for capa; check the overlayfirst".
4. Turn the blob into separate small files. New capabilities would:
   - detect the overlay (data appended after the program);
   - strip junk padding;
   - unpack common installer formats (NSIS, Inno Setup, 7z, MSI).

   Each extracted file becomes its own small artifact that the agent can investigate. Step 4 is what makes this scale: a 233 MB
   installer becomes a few small, analyzable files.

My recommendation

Make this its own phase, after Phase 2's acceptance run. It touches the artifact store, the isolated workers and the capability set, and adds a "child artifact" idea the system doesn't have yet. That's a planning-sized change, not a patch, and folding it into this branch
would muddy what Phase 2 proves.

So:
1. Now: run notepad.exe through the console and finish Phase 2's acceptance check.
2. Next: write up the large-artifact plan covering thart that with a brainstorm or a plan document wheneveryou're ready.

Should I go ahead with that order?