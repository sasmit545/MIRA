# MIRA

## Multi-Agent Investigation and Reasoning Architecture

**MIRA** is an adaptive multi-agent architecture for evidence-driven malware investigation.

MIRA treats malware analysis as an **investigation process** rather than a fixed sequence of analysis stages. The system continuously determines what should be investigated next based on the evidence, artifacts, hypotheses, and investigation status accumulated so far.

> **Coordinator decides WHO investigates next.  
> Specialist decides HOW to investigate.  
> Evidence determines WHAT happens next.**

---

## 1. Core Idea

A conventional malware-analysis pipeline may follow a fixed workflow:

```text
Static Analysis
      ↓
Dynamic Analysis
      ↓
Forensics
      ↓
Report
```

MIRA instead uses an adaptive investigation loop:

```text
Malware Sample
      ↓
Investigation State
      ↓
Coordinator
      ↓
Select Specialist + Objective
      ↓
Specialist Reasoning
      ↓
Select Capability
      ↓
MCP
      ↓
Analysis Tool
      ↓
Evidence / Artifacts
      ↓
Update Investigation State
      ↓
Update Hypotheses
      ↓
Coordinator
      ↓
Select Next Investigation
      ↓
...
```

The investigation path can therefore differ between malware samples depending on what has already been discovered.

---

# 2. Architecture

MIRA consists of four primary layers.

## 2.1 Investigation Layer

### Coordinator

The Coordinator manages the **global investigation strategy**.

Responsibilities:

- Understand the current investigation state.
- Identify important evidence and unresolved hypotheses.
- Determine what should be investigated next.
- Select the appropriate specialist.
- Assign an investigation objective.
- Decide whether an investigation should continue, revisit an earlier analysis, or terminate.

The Coordinator should **not directly execute malware-analysis tools**.

---

## 2.2 Specialist Layer

Specialist agents perform domain-specific investigation.

Initial specialists:

### Static Agent

Responsible for static investigation, including capabilities such as:

- PE/file metadata
- Strings
- Imports/exports
- Sections
- Suspicious APIs
- Resources
- Signatures
- Disassembly/decompilation where available

### Dynamic Agent

Responsible for runtime investigation, including:

- Process behavior
- File operations
- Registry activity
- Process creation
- Network activity
- Runtime payload behavior
- Memory behavior
- Payload extraction

### Forensics Agent

Responsible for forensic investigation, including:

- Memory artifacts
- Process relationships
- Injected code
- Persistence artifacts
- Extracted payloads
- Artifact relationships
- Evidence validation

The architecture should remain extensible so additional specialists can be added later.

Possible future specialists:

- Network Agent
- Memory Agent
- Reverse Engineering Agent
- Threat Intelligence Agent
- Sandbox Agent

---

# 3. Capability Layer

MIRA uses **MCP as the capability layer**.

The main principle is:

```text
Agent Reasoning
      ≠
Tool Execution
```

Agents reason about the investigation and select capabilities.

MCP exposes analysis capabilities through standardized interfaces.

```text
Specialist Agent
      ↓
Capability Selection
      ↓
MCP
      ↓
Analysis Tool
      ↓
Structured Result
      ↓
Specialist
```

This provides:

- Modularity
- Extensibility
- Tool isolation
- Auditability
- Specialist-specific capabilities

Adding or replacing an analysis tool should not require redesigning the agent.

---

# 4. Shared Investigation State

The investigation state is the **memory of the investigation**.

It should contain four major categories.

## 4.1 Artifacts and Lineage

Track what was discovered and where it came from.

Example:

```text
malware.exe
    ↓
decrypted payload
    ↓
payload.bin
    ↓
shellcode
```

Example representation:

```json
{
  "artifact_id": "artifact_004",
  "type": "shellcode",
  "source": "artifact_003",
  "derived_by": "dynamic_agent",
  "tool": "memory_dump"
}
```

Every derived artifact should retain provenance whenever possible.

---

## 4.2 Evidence and Findings

Store observations produced by agents and tools.

Example:

```text
Observation:
"Payload is decrypted in memory."

Source:
Dynamic Agent

Capability:
memory_dump

Confidence:
0.91
```

Evidence should ideally contain:

- Unique ID
- Observation
- Source agent
- Capability/tool
- Related artifact
- Confidence
- Provenance
- Timestamp

---

## 4.3 Hypotheses and Confidence

MIRA should explicitly represent what the system currently believes.

Example:

```text
H1:
Payload contains process-injection capability.

Confidence:
0.72
```

Hypotheses can be:

```text
OPEN
SUPPORTED
WEAKENED
CONFIRMED
REJECTED
```

Example:

```json
{
  "hypothesis_id": "H1",
  "statement": "Payload performs process injection",
  "confidence": 0.72,
  "status": "open"
}
```

Evidence should be linked to the hypotheses it supports or contradicts.

---

## 4.4 Tasks and Status

Track:

- Completed investigations
- Active investigations
- Pending investigations
- Failed investigations
- Unresolved questions

Example:

```text
[✓] Extract strings
[✓] Inspect imports
[✓] Execute sample
[ ] Investigate process injection
[ ] Analyze decrypted payload
```

---

# 5. Adaptive Investigation Loop

This is the central mechanism of MIRA.

MIRA should **not generate the entire investigation plan upfront**.

Instead:

```text
1. Observe current state
2. Identify important evidence/hypotheses
3. Identify unresolved investigation questions
4. Select the next specialist
5. Assign an investigation objective
6. Specialist decides how to investigate
7. Specialist selects required capabilities
8. MCP executes the capability
9. Receive structured results
10. Add evidence and artifacts to state
11. Update hypotheses and confidence
12. Re-evaluate the investigation
13. Select the next action
14. Repeat until sufficient investigation is completed
```

Conceptual pseudocode:

```python
while not investigation_finished(state):

    objective = coordinator.select_next_investigation(state)

    specialist = coordinator.select_specialist(
        objective,
        state
    )

    result = specialist.investigate(
        objective,
        state
    )

    state = update_state(
        state,
        result
    )

    state = update_hypotheses(
        state,
        result
    )
```

The defining property is:

> **The next investigation depends on the newly updated state.**

---

# 6. Two-Level Reasoning

MIRA separates reasoning into two levels.

## Global Reasoning

Performed by the Coordinator.

Question:

> **What should happen next?**

The Coordinator considers:

- Current evidence
- Hypotheses
- Confidence
- Unresolved questions
- Available specialists
- Previous tasks
- Investigation history

and selects the next investigation.

## Local Reasoning

Performed by the Specialist.

Question:

> **How should I investigate it?**

The specialist decides:

- Which capabilities are useful
- Which tools to invoke
- What parameters to use
- How to interpret results
- Whether additional investigation is required

This separation should remain a core architectural constraint.

---

# 7. Example Investigation

Suppose MIRA receives:

```text
sample.exe
```

### Step 1 — Static Investigation

The Coordinator selects the Static Agent.

Objective:

```text
Identify suspicious executable characteristics
and determine whether further behavioral investigation
is warranted.
```

The Static Agent executes relevant capabilities.

Possible findings:

```text
- Suspicious imports
- Encoded strings
- Resource containing executable-like data
```

The findings are added to the shared state.

---

### Step 2 — Hypothesis Formation

Based on the new evidence:

```text
H1:
Sample contains an embedded payload.

Confidence:
0.76
```

The Coordinator determines that runtime investigation is useful.

---

### Step 3 — Dynamic Investigation

The Coordinator selects the Dynamic Agent.

Objective:

```text
Determine whether the embedded payload is decoded
or executed at runtime.
```

The Dynamic Agent selects appropriate capabilities.

Possible result:

```text
Payload observed in process memory.
```

A new artifact is created:

```text
payload.bin
```

Lineage:

```text
sample.exe
    ↓
runtime memory
    ↓
payload.bin
```

---

### Step 4 — Hypothesis Update

The Coordinator updates the investigation state.

For example:

```text
H2:
Payload may perform process injection.

Confidence:
0.72
```

The Coordinator may now select the Forensics Agent.

Objective:

```text
Investigate evidence supporting or rejecting
process injection.
```

The investigation continues according to the evidence.

---

# 8. Project Structure

Recommended initial structure:

```text
mira/
│
├── README.md
├── main.py
│
├── config/
│   └── config.yaml
│
├── core/
│   ├── coordinator.py
│   ├── investigation.py
│   ├── state.py
│   ├── evidence.py
│   ├── artifact.py
│   ├── hypothesis.py
│   └── task.py
│
├── agents/
│   ├── base_agent.py
│   ├── static_agent.py
│   ├── dynamic_agent.py
│   └── forensics_agent.py
│
├── mcp/
│   ├── client.py
│   ├── capability_registry.py
│   └── servers/
│
├── capabilities/
│   ├── static/
│   ├── dynamic/
│   └── forensics/
│
├── storage/
│   ├── state_store.py
│   └── artifacts/
│
├── prompts/
│   ├── coordinator.txt
│   ├── static_agent.txt
│   ├── dynamic_agent.txt
│   └── forensics_agent.txt
│
├── evaluation/
│   ├── metrics.py
│   └── benchmark.py
│
└── tests/
```

Keep the implementation modular. The architecture should not depend on one specific LLM, MCP server, or malware-analysis tool.

---

# 9. Initial Data Model

Start with simple structured objects.

## InvestigationState

```python
class InvestigationState:

    sample = None

    artifacts = []
    evidence = []
    hypotheses = []
    tasks = []

    history = []

    status = "running"
```

## InvestigationTask

```python
class InvestigationTask:

    id = None
    objective = None
    specialist = None

    status = None

    depends_on = []
    evidence_required = []
```

## Evidence

```python
class Evidence:

    id = None

    observation = None

    source_agent = None
    capability = None

    artifact_id = None

    confidence = 0.0

    provenance = None
```

## Hypothesis

```python
class Hypothesis:

    id = None
    statement = None

    confidence = 0.0

    supporting_evidence = []
    contradicting_evidence = []

    status = "open"
```

These models can evolve after the first working investigation loop.

---

# 10. Coordinator Interface

The Coordinator should operate over structured investigation state.

Input:

```text
InvestigationState
```

Output:

```text
NextInvestigation
```

Example:

```json
{
  "specialist": "dynamic",
  "objective": "Determine whether the embedded payload is decrypted during execution.",
  "priority": 0.91,
  "reason": "Static evidence indicates an embedded executable payload."
}
```

The Coordinator's responsibility is **investigation planning**, not direct tool execution.

---

# 11. Specialist Interface

Each specialist receives:

```text
Current State
+
Investigation Objective
```

and produces:

```text
Evidence
+
Artifacts
+
Hypothesis Updates
+
Investigation Status
```

Example:

```text
Dynamic Agent

Objective:
Determine whether embedded payload is decrypted at runtime.

Reasoning:
1. Execute sample in a controlled environment.
2. Monitor memory changes.
3. Search memory for PE-like structures.
4. Extract candidate payload.
5. Compare with static artifacts.

Output:
- New artifact: payload.bin
- Evidence: payload appears in memory after execution
- Hypothesis H1 confidence increased
```

---

# 12. MCP Capability Design

Do not tightly couple agents to individual tools.

Expose capabilities such as:

```text
analyze_pe
extract_strings
list_imports
disassemble
execute_sample
capture_network
dump_memory
extract_process
search_memory
```

The specialist interacts with a capability interface:

```text
Capability:
dump_memory

Input:
process_id

Output:
memory_dump
```

The underlying implementation can later be replaced without changing the specialist's reasoning logic.

---

# 13. Evidence-First Design

Avoid making MIRA:

```text
LLM decides everything
```

Instead:

```text
Analysis Tools
      ↓
Structured Observations
      ↓
Evidence
      ↓
Hypotheses
      ↓
Coordinator Decision
      ↓
Next Investigation
```

The system should reason over evidence rather than inventing investigation state.

Important decisions should be traceable:

```text
Decision
   ↓
Evidence
   ↓
Artifact / Tool Result
```

This makes the system easier to debug, evaluate, and reproduce.

---

# 14. Investigation History

Maintain a complete investigation trace.

Example:

```text
T1
Static Agent
    ↓
PE Analysis
    ↓
Evidence E1

T2
Static Agent
    ↓
Resource Extraction
    ↓
Evidence E2

T3
Coordinator
    ↓
Hypothesis H1 Created

T4
Dynamic Agent
    ↓
Memory Analysis
    ↓
Artifact A4

T5
Coordinator
    ↓
H1 Confidence Updated
    ↓
Forensics Agent Selected
```

This history is important for:

- Debugging
- Reproducibility
- Evaluation
- Provenance
- Explaining decisions

---

# 15. First Implementation Goal

Do **not** begin by implementing every malware-analysis capability.

Build the smallest complete loop first:

```text
Sample
  ↓
Coordinator
  ↓
One Specialist
  ↓
One MCP Capability
  ↓
Evidence
  ↓
State Update
  ↓
Coordinator
  ↓
Next Action
```

Once this works, add:

```text
Static
    ↓
Dynamic
    ↓
Forensics
```

and then expand the capability set.

The first milestone should demonstrate:

> **The system changes its next investigation because of newly discovered evidence.**

That is more important than having a large number of tools.

---

# 16. Safety and Execution Boundary

Malware analysis capabilities should execute inside an appropriately isolated analysis environment.

Keep the architecture separated into:

```text
Reasoning Layer
      ↓
Capability Interface
      ↓
Isolated Analysis Environment
      ↓
Structured Results
```

The agents should not directly access the host system or unrestricted execution environment.

Tool execution should be controlled, logged, and auditable.

---

# 17. Evaluation

MIRA should be evaluated as an **adaptive investigation system**, not only as a malware classifier.

Important evaluation dimensions:

## Adaptivity

Does MIRA select different investigation paths for different malware samples?

## Evidence Utilization

Does newly discovered evidence influence subsequent actions?

## Investigation Efficiency

Does MIRA avoid unnecessary analysis?

## Hypothesis Quality

Does evidence appropriately increase or decrease hypothesis confidence?

## Specialist Selection

Does the Coordinator select an appropriate specialist for the current investigation objective?

## Capability Selection

Does the specialist select useful capabilities?

## Investigation Completeness

Does the system discover relevant malware behaviors and artifacts?

## Reproducibility

Can the complete investigation trace be reconstructed?

---

# 18. Baselines

Potential baselines:

```text
Fixed Analysis Pipeline
        vs
Single-Agent Malware Analysis
        vs
Multi-Agent Malware Analysis
        vs
MIRA
```

A particularly important experiment is:

```text
Fixed Pipeline
      vs
MIRA
```

The goal is to demonstrate that MIRA does not merely run more agents or more tools.

It **changes the investigation trajectory based on evidence**.

---

# 19. What MIRA Is Not

MIRA is not simply:

- A chatbot for malware analysis
- A fixed malware-analysis pipeline
- Multiple independent agents running in parallel
- An LLM wrapper around existing tools
- A replacement for malware-analysis tools
- A system tightly coupled to one tool
- A system limited to exactly three specialists

MIRA is an **adaptive investigation architecture**.

---

# 20. Architecture Summary

```text
                         MIRA
                          │
                          ▼
                 ┌─────────────────┐
                 │   Coordinator   │
                 │ Global Reasoning│
                 └────────┬────────┘
                          │
                   Select Specialist
                          │
            ┌─────────────┼─────────────┐
            ▼             ▼             ▼
       ┌─────────┐   ┌─────────┐   ┌───────────┐
       │ Static  │   │ Dynamic │   │ Forensics │
       │  Agent  │   │  Agent  │   │   Agent   │
       └────┬────┘   └────┬────┘   └─────┬─────┘
            │             │              │
            └─────────────┼──────────────┘
                          ▼
                   ┌────────────┐
                   │    MCP     │
                   │Capabilities│
                   └─────┬──────┘
                         ▼
                   Analysis Tools
                         │
                         ▼
                ┌──────────────────┐
                │ Investigation    │
                │      State       │
                ├──────────────────┤
                │ Evidence         │
                │ Artifacts        │
                │ Lineage          │
                │ Hypotheses       │
                │ Confidence       │
                │ Tasks            │
                └────────┬─────────┘
                         │
                         │ Feedback
                         ▼
                   Coordinator
                         │
                         ▼
                      NEXT STEP
```

---

# 21. Guiding Principle

Everything in the implementation should preserve:

> **Coordinator decides WHO.  
> Specialist decides HOW.  
> Evidence determines WHAT NEXT.**

If a component violates this separation, reconsider its responsibility.

---

# 22. Development Roadmap

## Phase 1 — Core Skeleton

- [ ] Create project structure
- [ ] Define InvestigationState
- [ ] Define Evidence
- [ ] Define Artifact
- [ ] Define Hypothesis
- [ ] Define Task
- [ ] Implement investigation history

## Phase 2 — Coordinator

- [ ] Coordinator state input
- [ ] Next-investigation selection
- [ ] Specialist selection
- [ ] Investigation objective generation
- [ ] Priority/reason generation
- [ ] Stop/continue decision

## Phase 3 — First Specialist

- [ ] BaseAgent
- [ ] StaticAgent
- [ ] Specialist reasoning loop
- [ ] Structured output

## Phase 4 — MCP

- [ ] MCP client
- [ ] Capability registry
- [ ] First analysis capability
- [ ] Structured tool result
- [ ] Tool-call logging

## Phase 5 — Feedback Loop

- [ ] Evidence ingestion
- [ ] State update
- [ ] Hypothesis update
- [ ] Coordinator re-evaluation
- [ ] Next-step selection

## Phase 6 — Additional Specialists

- [ ] DynamicAgent
- [ ] ForensicsAgent
- [ ] Specialist-specific capabilities

## Phase 7 — Evaluation

- [ ] Fixed pipeline baseline
- [ ] Single-agent baseline
- [ ] Investigation traces
- [ ] Adaptivity metrics
- [ ] Efficiency metrics
- [ ] Evidence/hypothesis evaluation

---

# 23. Final Target

MIRA should behave like an autonomous malware investigation team:

```text
                    ┌─────────────┐
                    │   Malware   │
                    └──────┬──────┘
                           ↓
                    ┌─────────────┐
                    │    MIRA     │
                    └──────┬──────┘
                           ↓
                 Investigate → Observe
                           ↓
                   Update Evidence
                           ↓
                  Update Hypotheses
                           ↓
                 Decide What's Next
                           ↓
                    Investigate
                           ↓
                         ...
```

The goal is **not** to execute every available analysis.

The goal is to perform the **most useful next investigation based on the current evidence and hypotheses**.
