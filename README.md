<a id="readme-top"></a>

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f172a,100:4f46e5&height=180&section=header&text=MIRA&fontSize=70&fontColor=ffffff&animation=fadeIn&fontAlignY=38&desc=Multi-Agent%20Malware%20Investigation%20System&descAlignY=58&descSize=18" width="100%" alt="MIRA"/>

<img src="https://readme-typing-svg.demolab.com/?font=Fira+Code&size=16&pause=1400&color=6366F1&center=true&vCenter=true&width=760&lines=Coordinator+decides+WHO+should+investigate;Specialist+decides+WHAT%2FHOW+within+its+domain;MCP+provides+the+execution+interface;Shared+state+records+WHAT+WAS+LEARNED" alt="Typing SVG" />

[![CircleCI](https://circleci.com/gh/sasmit545/MIRA.svg?style=svg)](https://circleci.com/gh/sasmit545/MIRA)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![status](https://img.shields.io/badge/status-static%20slice%20working-brightgreen)
![last commit](https://img.shields.io/github/last-commit/sasmit545/MIRA?color=6366F1)
![issues](https://img.shields.io/github/issues/sasmit545/MIRA?color=6366F1)

<br/>

![pefile](https://img.shields.io/badge/pefile-PE%20parsing-0f172a?style=flat-square)
![capstone](https://img.shields.io/badge/capstone-disassembly-0f172a?style=flat-square)
![yara--python](https://img.shields.io/badge/yara--python-scanning-0f172a?style=flat-square)
![flare--capa](https://img.shields.io/badge/flare--capa-capability%20detection-0f172a?style=flat-square)
![FastMCP](https://img.shields.io/badge/FastMCP-capability%20layer-0f172a?style=flat-square)
![pydantic](https://img.shields.io/badge/pydantic-contracts-0f172a?style=flat-square)

</div>

---

## Executive summary

MIRA is an adaptive multi-agent malware investigation system: a small set of domain-specialist agents reason over an evolving investigation state and use **MCP servers** to access analysis tools. It is deliberately **not** a fixed static → dynamic → memory pipeline — each specialist runs its own local investigation loop, while a Coordinator runs a global loop that keeps reallocating work as evidence, hypotheses, and artifacts change. A newly discovered artifact re-enters shared state and can trigger another cycle, including re-analysis with different tools.

## Design goals

- Adaptive investigation, not a predetermined pipeline
- A small number of specialists, each with real, distinct expertise
- Agent-local iterative reasoning and tool-use loops
- A global coordination loop driven by evolving evidence
- MCP-based extensibility — new tools plug in without redesigning the system
- Minimal Coordinator context: specialists return concise findings, not raw tool output
- Strong provenance, evidence traceability, artifact lineage, reproducibility

## Core principles

| Principle | Meaning |
|---|---|
| **Artifact-centric** | The unit of investigation is an artifact, not a pipeline stage |
| **Specialist-centric** | Agents represent coherent investigative expertise, not individual tools |
| **MCP-mediated execution** | Agents reach tools only through their domain MCP server |
| **Dual-loop reasoning** | Every specialist runs a local loop; the Coordinator runs a global loop |
| **State over transcript** | Evidence/artifacts live in shared state; messages carry compact references, not raw output |
| **Open-ended extensibility** | New MCP tools register without touching the Coordinator contract |

## Dual-level investigation loops

**Specialist-local loop** — the specialist iterates on its own until satisfied, without pinging the Coordinator after every tool call:

```
Specialist ─▶ Plan ─▶ select/invoke MCP tool ─▶ analyze result
                 ▲                                   │
                 └── objective not yet satisfied ◀────┘
                                   │
                          satisfied → concise finding
```

**Global coordination loop** — the Coordinator re-plans whenever new information could change strategy. The next specialist is never predetermined: a sample can go Static → Dynamic → Static → Forensics → Static, or any other order the evidence justifies.

```
Shared Investigation State ─▶ Coordinator ─▶ select specialist + objective
        ▲                                              │
        └── finding / artifact / evidence update ◀─────┘
```

## Agents

| Agent | Scope | Boundary |
|---|---|---|
| **Coordinator** | Cross-domain investigation management — assigns objectives, correlates findings, decides where investigation continues | Never executes low-level analysis, doesn't know individual tools |
| **Static** | Non-executing code/binary investigation — PE structure, imports, strings, entropy, signatures, packing, disassembly, CFG | Chooses and sequences static tools internally |
| **Dynamic** | Observed execution behavior — sandboxing, process/API activity, filesystem, registry, network telemetry | Network analysis is a *capability* here, not a separate mandatory agent |
| **Forensics** | Runtime/memory-state investigation — memory dumps, injected code, unpacked payloads, shellcode, reflective loading | Focuses on runtime state, not ordinary execution telemetry |

A new specialist is only justified when a domain needs genuinely distinct expertise and its own autonomous loop — see [Design decisions to preserve](#design-decisions-to-preserve).

## MCP capability layer

Each specialist owns a domain MCP server. The server is a tool boundary, not an agent — the specialist decides which of its available tools are useful for the objective at hand.

```
Static Agent ──▶ Static MCP ──▶ PE/ELF/.NET · YARA/capa · strings/entropy · disassembly …
Dynamic Agent ─▶ Dynamic MCP ─▶ sandbox · process/API monitor · filesystem/registry · network capture …
Forensics Agent ▶ Forensics MCP ▶ memory acquisition · injection analysis · shellcode/payload extraction …
```

Agent identity stays stable while the tool set underneath it evolves — new capabilities register through MCP without adding an agent or touching the Coordinator's contract.

## Inter-agent contract

Agents exchange decisions and references, never raw tool output.

| Message | Direction | Payload |
|---|---|---|
| `INVESTIGATE` | Coordinator → Specialist | `artifact_id`, objective, constraints |
| `FINDING` | Specialist → Coordinator | `artifact_id`, assessment, evidence refs, confidence, recommended actions |
| `ARTIFACT` | Specialist → Coordinator | `artifact_id`, `parent_id`, relation, type, provenance |
| `REQUEST_SPECIALIST` | Specialist → Coordinator | target role, `artifact_id`, objective, reason |
| `STATUS` | Specialist → Coordinator | `task_id`, status, blocking reason |

## What's actually built

The **static-analysis vertical slice** runs end to end: an LLM-driven agent investigates a PE sample, freely choosing among 11 static-analysis tools, recovering from tool failures, and writing a full run trace.

```bash
python -m mira.reasoning.main sample.exe \
    --objective "Identify suspicious behavior" \
    --max-turns 5 --max-tool-calls 5 --trace-dir runs
```

Everything above the line is the target architecture. Today, concretely:

- `mira/core/coordinator.py` is a **minimal stub** — it assigns Static objectives only, from a hand-rolled evidence check, not yet the global loop over all three specialists
- The `INVESTIGATE`/`FINDING`/`ARTIFACT`/`REQUEST_SPECIALIST`/`STATUS` contract above is design intent — Static runs standalone today, there's no message-passing Coordinator↔Specialist wiring yet
- Dynamic and Forensics agents/MCP servers don't exist yet; only Static is implemented
- The specialist-local loop (plan → select tool → analyze → refine) **is** real, in `mira/reasoning/runtime/loop.py`

## Layout

| Package | Responsibility |
|---|---|
| `mira.core` | Shared state — `Artifact`, `Evidence`, `Hypothesis`, `Task`, `Coordinator` |
| `mira.reasoning` | Agent runtime: model adapter, tool-calling loop, tracing, output contracts |
| `mira.agents.static` | Static specialist definition + tool wiring |
| `mira.capabilities.static` | The actual analysis code (pefile, capstone, yara-python, flare-capa) |
| `mira.contracts.capabilities` | Typed request/result schemas each capability speaks |
| `mira.mcp` | MCP client, capability registry, and the isolated worker capabilities run inside |

### Static capabilities

`analyze_pe` · `extract_strings` · `list_imports` · `list_exports` · `disassemble` · `analyze_functions` · `detect_packer` · `compute_entropy` · `file_info` · `run_capa` · `scan_yara`

`run_capa` and `scan_yara` match against real, pinned rule sets vendored as git submodules — [capa-rules](https://github.com/mandiant/capa-rules) and [signature-base](https://github.com/Neo23x0/signature-base).

## Efficiency strategy

- Don't expose every tool to the Coordinator — let specialists pick tools locally
- Prefer targeted analysis based on artifact type and objective, not "run everything"
- Skip re-analysis when the artifact and relevant state haven't changed
- Treat every newly created artifact as a fresh investigation opportunity
- Pass evidence references, not full observations, into agent prompts

## Security and governance

- Dynamic execution runs in an isolated analysis environment (`mira/mcp/isolation.py`)
- MCP tools expose narrowly scoped operations with explicit input schemas
- Tool execution is auditable through provenance and run traces
- Artifacts are treated as immutable/versioned once registered, so evidence stays reproducible
- The Coordinator never bypasses specialist/MCP boundaries to run a tool directly

## Design decisions to preserve

- No fixed Static → Dynamic → Memory ordering
- No agent-per-tool design
- No raw tool-output flooding of the Coordinator
- No mandatory standalone Network Agent — network analysis is a Dynamic capability
- No Artifact Agent — artifact management is shared infrastructure, not an agent
- Specialists may iterate locally before reporting
- Every meaningful new artifact returns to the global investigation loop

<div align="center">
<img src="https://capsule-render.vercel.app/api?type=rect&color=0:0f172a,100:4f46e5&height=3&width=100%25" width="100%" alt=""/>
</div>

## Getting started

```bash
git clone https://github.com/sasmit545/MIRA.git
cd MIRA
git submodule update --init --recursive   # or: scripts/fetch_rules.sh
pip install -e ".[dev]"
pytest -q
```

A plain clone leaves `rules/capa` and `rules/signature-base` empty — that's how submodules work. Without them, `run_capa`/`scan_yara` just report `TOOL_NOT_AVAILABLE`.

## Model

The reasoning loop talks to Grok via Azure AI Foundry (`mira/reasoning/model/adapter.py`). Tests inject a scripted model, so the suite runs with no live API calls.

## Design notes

Full architecture rationale, message contracts, and the example investigation walkthrough live in the original design document (`multi_agent_malware_investigation_design.docx`). Phase planning docs are in [`plan/`](plan); `TODO.md` has the current handoff notes.

<div align="center">

[⬆ back to top](#readme-top)

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:4f46e5,100:0f172a&height=100&section=footer" width="100%" alt=""/>

</div>
