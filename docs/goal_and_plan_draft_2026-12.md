# MIRA — Goal, Methodology, Progress and Plan to December 2026

*Draft, 11 October 2026. Work done is taken from the repository (107 commits since 4 Sep 2026). The plan from Oct to Dec is a proposal for review.*

## 1. Goal

Build **MIRA**, an adaptive multi-agent malware investigation system. A Coordinator decides *who* investigates next. Domain specialists (Static, Dynamic, Forensics) decide *how* to investigate within their domain, using tools reached only through MCP servers. Findings and evidence go into a shared investigation state. The system is deliberately **not** a fixed static → dynamic → memory pipeline: new evidence or a newly found artifact can send the investigation back to any specialist.

**Target outcome by Dec 2026:** a working Static specialist whose verdicts are *measured* as reliable on labeled samples, plus a Coordinator that drives it through the `INVESTIGATE` / `FINDING` contract. Dynamic and Forensics remain design work.

## 2. Subgoals

1. **Static vertical slice.** An LLM-driven specialist that chooses among static tools, recovers from tool failures and leaves a full trace.
2. **Working memory.** The specialist keeps hypotheses, open questions and facts across many tool calls without carrying raw tool output in its prompt.
3. **Retrieval at scale.** The agent can examine whole import, string and function lists without overflowing context. The trace and report say what was examined and what was not.
4. **Verdict reliability.** A *malicious* verdict must rest on corroborated strong evidence. False-positive and detection rates are measured on a labeled set, not on single files.
5. **Coordinator and contract.** Replace the Coordinator stub with message-passing over `INVESTIGATE` / `FINDING` / `ARTIFACT` / `REQUEST_SPECIALIST` / `STATUS`.
6. **Large and nested artifacts.** Treat installers and padded files as a small program plus a blob. Extract the parts as child artifacts with lineage.

## 3. Methodology

- **Architecture.** Four layers: shared state (`mira.core`), reasoning harness (`mira.reasoning`), specialist (`mira.agents`), and capability layer (`mira.capabilities`, `mira.mcp`). Each capability runs in an isolated worker behind FastMCP, so tools are replaceable without touching the agent.
- **Two reasoning levels.** The specialist runs a local plan → call tool → interpret loop. The Coordinator runs the global loop over shared state. The two contexts are kept separate: specialist working memory versus investigation state.
- **State over transcript.** Agents pass compact references and evidence ids, never raw tool output. Evidence is minted by code from tool results (normalizer rules with grades), not by the model. Model notes may cite only minted ids.
- **Code-enforced invariants.** Notes are validated all-or-nothing, a deterministic gate checks every report's verdict against the grade and source of the evidence it cites, and loops are bounded and end with a report.
- **Plan-first delivery.** Each feature has a written plan (requirements, key technical decisions, numbered units) under `docs/plans/`. One commit per unit, tests per unit, and stop conditions where a measurement must come before the next change.
- **Evaluation.** A labeled benchmark records each sample's hash, label provenance and split. It reports false-positive rate, precision, recall, MCC, abstention, coverage and failures over *unique files*, with intervals. A no-model survey measures how often each evidence rule fires on benign and malicious files, and grades are changed only where survey coverage is adequate.
- **Model.** Any OpenAI-compatible endpoint, configured through environment variables. Runs are traced to disk and counted (model calls, recalls, refusals, tokens).

## 4. Work done (4 Sep – 11 Oct 2026)

| Period | Delivered |
|---|---|
| 4–11 Sep | Repository, CI, isolated async static MCP server, YARA and capa integration, pydantic contract layer, 11 static capabilities, first runnable agent with run traces. |
| 11–14 Sep | Restructure into specialist-agnostic `mira.reasoning` plus static wiring. FINDING contract (what crosses the specialist boundary), merged to `main`. |
| 15 Sep – 10 Oct | **Working memory** (plan units U1–U9, all done): validated `record_memory` notes, additive merge, capability history, structural digests, `recall_observation`, hypothesis promotion to shared state on a completed report. Live probe: notes and capability call arrived together on 25 of 25 turns. |
| 11 Oct | **Retrieval pipeline**: whole lists collected once with totals and coverage, recall filters and per-value counts, retrieval ledger, stalled-walk handling. **Benchmark harness** with provenance and splits. **Evidence grades** shown to the model. **Verdict gate** on cited evidence. Web investigation console with evidence explorer and trace inspector. Normalizer fixes for traits most Windows binaries share. |
| State | 295+ tests pass on branch `feat/static-agent-working-memory`. |

**Open problem.** The genuine, catalog-signed `notepad.exe` was judged malicious in 10 of 11 benchmark runs. Four normalizer defects were fixed (function density, capa grading, section names, debugger imports), but the last check still said malicious. The verdict-reliability work (gate and survey-based grades) targets this, and its effect has not yet been measured.

**Not built:** the Coordinator is a stub, the message contract is design intent, and Dynamic and Forensics agents and MCP servers do not exist.

## 5. Plan, Oct – Dec 2026 (proposed)

| When | Milestone | Done when |
|---|---|---|
| Oct (wk 2–3) | Finish Phase 2 acceptance on real samples. Decide whether to commit `docs/` and `plan/`. | `notepad.exe` run read end to end, recall use counted, branch merged to `main`. |
| Oct (wk 3–4) | Build the labeled sample set (benign downloads script exists, malicious from public corpora). Record the **baseline** benchmark before any further verdict change. | Baseline FPR, recall and MCC on unique files with intervals. |
| Nov (wk 1–2) | Apply survey-based grades and the verdict gate. Re-run the benchmark. | Measured before/after comparison. Claim only what the numbers show. |
| Nov (wk 2–3) | Large-artifact plan and implementation: streamed upload, cheap capabilities at any size, overlay detection, child artifacts with lineage. | A 200 MB+ installer yields small analyzable child artifacts. |
| Nov (wk 3–4) | Coordinator v1: `INVESTIGATE` / `FINDING` message passing, assignment from shared-state evidence, Static re-entry on new artifacts. | Coordinator runs Static twice on one sample with a new artifact in between. |
| Dec (wk 1–2) | Dynamic specialist design and a thin prototype behind an external sandbox (execution stays behind the MCP boundary). | One end-to-end Static → Dynamic → Static run, or a design document if the sandbox is not available. |
| Dec (wk 3–4) | Final evaluation, ablations (with and without working memory, recall, gate), write-up. | Report with results, limitations and next steps. |

**Risks.** Hours-long benchmark passes and the need for labeled samples limit iterations. Model-endpoint cost and variance affect repeatability. The Dynamic milestone depends on sandbox access, so it is the first to slip, and the benchmark and Coordinator take priority.
