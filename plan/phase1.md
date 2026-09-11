Here's the full plan as a ready-to-save markdown file:

````markdown
# Phase 1 — Agent Prototype (Revised)

**Goal:** Build a single-agent static malware investigator that autonomously selects MCP tools,
observes results, recovers from failures, and produces a validated structured report.
MCP server/client remain unchanged. Persistence, guardrails, and context summarization are
explicitly deferred to Phase 2.

---

## Directory Layout

```text
agent/
├── contracts/
│   ├── objective.py
│   ├── state.py
│   ├── tool.py
│   ├── model.py
│   ├── finding.py
│   └── output.py
│
├── definition/
│   ├── agent.py
│   └── instructions.py
│
├── runtime/
│   ├── loop.py
│   ├── context.py
│   ├── tool_runtime.py
│   ├── completion.py
│   └── trace.py
│
├── model/
│   ├── adapter.py
│   └── testing.py          # mock Model lives here, not in tests/
│
└── tests/
    ├── test_state.py
    ├── test_context.py
    ├── test_loop.py         # includes error-path cases
    ├── test_completion.py
    └── test_e2e_mock.py
```

---

## Step 1 — Core Contracts

Define stable types first.

```text
Objective
ToolSpec
ToolCall
ToolResult        (success | error variants)
ModelResponse     (tool_calls | report | empty)
Finding
Evidence
State
TurnRecord
FinalOutput
```

**Rules:**

- No execution logic in these.
- `ToolResult` has an explicit error variant. Tools fail; the type system must admit it.
- `ModelResponse` distinguishes three shapes: tool calls, a report submission, or nothing useful.
- `severity` and `confidence` are **closed enums**
  (e.g., `severity ∈ {info, low, medium, high, critical}`). No free text.

---

## Step 2 — Investigation State

Mutable state owned by the run.

```text
State
├── objective
├── turn_count
├── tool_call_count
├── findings[]
├── evidence[]
├── observations[]      # one entry per tool call: call + result (possibly truncated)
├── scratch             # visible to model, excluded from output, lifecycle documented
└── run_id
```

**Implement:**

```text
record_turn()          # appends a TurnRecord
record_tool_call()
record_tool_result()
add_finding()
add_evidence()
snapshot()
```

**Key decision:** State stores full raw tool results; context only ever sees truncated ones.
Evidence is the curated, model-promoted subset of observations.

In-memory for Phase 1. Resumability deferred.

---

## Step 3 — Agent Definition (Policy Collapsed In)

With one agent, a separate Policy object is over-engineering. Policy is merged into the
definition:

```text
StaticAgentDefinition          (immutable, read-only config)
├── instructions
├── tool_manifest               # what exists
├── allowed_tools               # what is permitted this run (subset of manifest)
├── max_turns
├── max_tool_calls
└── output_contract
```

If Phase 2 needs swappable policies, the split can be reintroduced — the seam is
`AgentDefinition` being immutable, which is preserved either way.

**Objective is NOT here.** The objective is per-run input, passed at invocation.

---

## Step 4 — Completion Semantics

Termination is explicit and blunt. The investigation ends when exactly one of:

```text
1. Model submits a report via the report tool        (normal completion)
2. max_turns reached                                 (limit)
3. max_tool_calls reached                            (limit)
4. Model returns empty/degraded response twice       (failure)
```

Nothing fuzzy. "Sufficient evidence gathered" is not a Phase 1 condition — it's a
Phase 2 judgment.

**The report is a pseudo-tool.** `submit_report` is declared in the tool manifest like any
other tool. This:

- reuses the existing tool-call path,
- works across providers (no provider-specific JSON mode leakage),
- makes "model wants to stop" an explicit, validated signal rather than a heuristic,
- forces the report payload through the same validation as any tool call.

**Mid-turn overflow rule:** if `max_tool_calls` is hit with pending calls, execute none of
them, record a limit observation, and force termination on the next cycle.

---

## Step 5 — Instructions / Prompt

System prompt defines:

```text
Role
↓
Investigation objective
↓
Available capabilities (from tool_manifest)
↓
How to evaluate evidence (→ promote to Evidence)
↓
How to decide next action
↓
Error handling: tool failures are observations, not dead ends
↓
When to stop (call submit_report)
↓
Required report schema
```

Templated:

```text
{objective}
{scope}
{available_tools}
{current_state}
```

One assembler only: the ContextBuilder (Step 7). Nothing else constructs model-facing text.

---

## Step 6 — Model Abstraction

```python
class Model(Protocol):
    def generate(
        self,
        context: ModelContext,
        tools: list[ToolSpec],
    ) -> ModelResponse: ...
```

The concrete `ProviderAdapter`:

- is the **only** file that touches the provider SDK,
- exposes **seedable randomness** (temperature/seed control) — otherwise every test above
  unit level is flaky,
- reports **token/cost usage per call** — surfaced into the turn record. Phase 2 context
  management needs this data; retrofitting it is painful.

`model/testing.py` contains the MockModel — a first-class component, not a test
afterthought. It is scriptable (plays a sequence of canned responses) and seedable. The
entire loop is testable through it.

---

## Step 7 — Context Builder

```text
ContextBuilder.build(state, agent_definition)
```

Generates:

```text
SYSTEM
OBJECTIVE
CURRENT STATE
INVESTIGATION HISTORY     (truncated observations)
RELEVANT FINDINGS / EVIDENCE
AVAILABLE TOOLS
```

Phase 1 sends full history — but **truncated tool results**. Truncation happens at
normalization time (Step 8), not here. Full raw results live in State and are available to
the report builder, only summarized in context. A real malware sample's import table or
string dump will blow the context window in one turn otherwise — this is not a "later"
problem.

---

## Step 8 — Tool Runtime

Thin, over the existing MCP client.

```text
ToolCall
   ↓
validate against ToolSpec     → invalid? → ToolResult(error, "reason") as an observation
   ↓
MCP Client                    → raises?  → ToolResult(error, "timeout/crash") as an observation
   ↓
normalize_result()            → truncate long payloads for context; full result into State
   ↓
ToolResult
```

Failure is a **normal result** the model can observe and adapt to. No exceptions cross the
tool runtime boundary. No other guardrails yet.

---

## Step 9 — Agent Loop

```text
while completion.check(state, definition) is active:

    context = context_builder.build(state, definition)
    response = model.generate(context, tools)

    if response is report_submission:
        validated = output_validator.validate(response.payload)
        if valid:
            return FinalOutput
        else:
            record validation error as observation   # one retry, then degrade

    if response is empty:
        record empty-response observation             # two in a row → terminate degraded

    for tool_call in response.tool_calls:
        if tool_call is submit_report:
            → handled above
        result = tool_runtime.execute(tool_call)      # never raises
        state.record(tool_call, result)
        trace.append(turn_record)

    state.turn_count += 1
```

### Error-Path Decision Table

This is the actual core of the loop:

| Situation | Action |
|---|---|
| Invalid tool call (bad name/args) | `ToolResult(error)` fed back as observation |
| Tool execution failure | `ToolResult(error)` fed back as observation |
| Empty model response | Observation + nudge retry; 2× → degraded exit |
| Malformed report submission | Validation errors as observation; 1 retry |
| Retried report still malformed | Degraded exit with best-effort output |
| Limits reached | Forced termination, output marked `limit_reached` |

A single agent with no recovery path is just a script that sometimes crashes. Observing and
recovering from failure is the actual test of agent-ness — this is deliberately Phase 1,
not Phase 2.

**Tracing:** every turn is recorded as a full `TurnRecord` —
`(context_sent, response_received, tool_calls, results, state_snapshot, token_usage)` —
and written to a run log (JSON file next to the report). This is simultaneously: your
debugging mechanism, your flaky-run forensics, and your seed data for Phase 2 evals. Build
it with the loop, not after.

---

## Step 10 — Structured Output

```text
FinalOutput
├── summary
├── verdict
├── findings[]
├── evidence[]           (references into full observations held in State)
├── completion_reason    (reported | limit_turns | limit_calls | degraded)
└── metadata             (turns, tool calls, token usage, run_id)

Finding
├── title
├── description
├── severity             (enum)
├── confidence           (enum)
├── evidence_refs[]
└── source/location
```

Report arrives via the `submit_report` tool, validated against the output contract. Schema
stays small.

---

## Step 11 — First Real Investigation

Real PE sample. Target flow:

```text
Objective
   ↓
Agent
   ↓
analyze_pe → observe
   ↓
list_imports → observe
   ↓
search_strings → observe
   ↓
(model's choice — possibly retry after a tool failure, deliberately inject one)
   ↓
submit_report
   ↓
validated FinalOutput
```

The critical property: **the model chooses the next tool**, including after failures. Run
it at least once with a deliberately broken tool to watch the recovery path fire.

---

## Step 12 — Tests (Written With the Loop, Not After It)

```text
Unit
├── State (records, snapshot)
├── ContextBuilder (assembly, truncation applied)
├── Completion (all four termination paths)
└── Output validation (schema, enums)

Integration — MockModel-driven, deterministic, runs in CI
├── Happy path: multi-turn, multi-tool, submit_report
├── Invalid tool call → observed error → model recovers
├── Tool execution failure → observed error → model adapts
├── Empty responses ×2 → degraded exit
├── Malformed report → retry → succeed
├── Malformed report twice → degraded exit
├── Limit mid-turn → forced termination
└── Agent + real MCP client (tool execution only)

E2E — live model, smoke-level, NOT a CI gate
└── PE → autonomous investigation → report
    Relaxed assertions only: valid FinalOutput, 2+ tool calls,
    within limits, trace file written.
```

The MockModel integration suite is the proof that Phase 1 works. The live-model run is a
demo, not a test.

---

## Definition of Done

Phase 1 is complete when this works:

```text
mira investigate sample.exe \
  --objective "Identify suspicious behavior"
```

and the system can:

```text
1.  Load agent definition
2.  Receive objective
3.  Ask model what to do
4.  Select an MCP tool
5.  Execute it — or observe and recover from its failure
6.  Feed result (truncated) back to model
7.  Repeat autonomously
8.  Terminate via one of the four explicit conditions
9.  Produce a validated FinalOutput
10. Write a full run trace alongside the report
11. Pass the deterministic MockModel suite in CI
```

Then **Phase 2 = the real Harness**: guardrails, recovery policies beyond "observe and
adapt," context summarization, resumability, and observability infrastructure — built on
the trace and token-usage data Phase 1 now collects.

---

## Changes from the Original Plan

| Original | Revised | Why |
|---|---|---|
| Policy as separate object | Merged into AgentDefinition | Single agent; split was over-engineering; seam preserved for Phase 2 |
| Objectives inside Policy | Objective is per-run input | Ambiguity about which wins |
| Fuzzy completion conditions | Four explicit conditions + `submit_report` pseudo-tool | "Sufficient evidence" is Phase 2 judgment; pseudo-tool is provider-agnostic and validated |
| Undefined error paths | Full decision table in the loop | Failure observation is the core agent behavior, not an edge case |
| Full raw results in context | Truncate at normalization; full results in State | Real malware data blows the context window in one turn |
| Mock model buried in tests | First-class `model/testing.py`, seedable | It's the component that makes the loop testable |
| E2E as the primary proof | Deterministic MockModel suite in CI; live run as smoke test | Live-model E2E is flaky by construction |
| Tests written last | Integration tests written with the loop (Step 9) | Debugging the whole stack cold is miserable |
| No run trace | TurnRecord per turn, written to JSON | Debugging + Phase 2 eval seed data |
| Free-text severity/confidence | Closed enums | Reporting sanity |
````

Save it as `PHASE1_PLAN.md` (or whatever fits your repo conventions — `docs/phase1-agent-prototype.md` works too). Let me know if you want any sections adjusted or trimmed.