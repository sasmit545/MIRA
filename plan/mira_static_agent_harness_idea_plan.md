# Mira Static Agent Harness — Concept Plan

## Goal

Build a small, reusable **harness for the Static Agent** in the Adaptive Multi-Agent Malware Investigation system.

The harness provides the environment in which the Static Agent can:

1. receive an investigation assignment,
2. reason about how to investigate it,
3. select an appropriate static-analysis capability,
4. receive and interpret the capability result,
5. continue investigating when necessary,
6. produce findings and evidence for the shared investigation state.

The Static Agent decides **how** to investigate. The Coordinator decides **who** investigates next. Evidence and investigation state determine **what happens next**.

---

## Core Idea

The harness sits between the specialist's reasoning and its available capabilities.

```text
                    Static Agent
                         |
                         | investigation reasoning
                         v
                      Harness
                         |
              +----------+----------+
              v          v          v
            Model      Context   Capabilities
                                      |
                                      v
                                     MCP
                                      |
                                      v
                            Static Analysis Tools
```

The harness should not become the Static Agent itself.

---

## What the Harness Owns

### 1. Reasoning Loop

The harness maintains the interaction cycle:

```text
Investigation Assignment
        |
      Reason
        |
 Select Capability
        |
   Receive Result
        |
 Interpret Evidence
        |
   Need More Work?
      /       \
    Yes        No
     |          |
     +-> Reason  v
             Finding
```

The Static Agent can therefore perform multiple investigation steps instead of being limited to one capability call.

### 2. Context

The harness maintains the Static Agent's local working context:

- investigation assignment,
- relevant evidence,
- previous capability calls,
- capability results,
- current reasoning context.

This is the specialist's working context, not the global investigation state.

### 3. Capability Access

The harness gives the Static Agent access to its allowed capabilities.

The Static Agent should not be tightly coupled to individual malware-analysis tools.

```text
Static Agent
      |
Static Capabilities
      |
     MCP
      |
Static Analysis Tools
```

### 4. Lifecycle

The harness manages the lifecycle of a specialist investigation:

```text
Start -> Investigate -> Capability interaction -> Investigate -> Complete
```

It should distinguish events such as investigation started, capability requested, result received, completed, failed, and cancelled.

### 5. Investigation Result

The Static Agent should eventually produce:

```text
Findings
Evidence
Artifacts
Hypotheses
Confidence
Suggested next investigations
```

The harness provides the boundary through which this result reaches the broader investigation system.

---

## What the Harness Does NOT Own

Keep the first harness deliberately small.

It should not own:

- Coordinator
- Dynamic Agent
- Forensics Agent
- Multi-agent orchestration
- Global investigation strategy
- Sandbox management
- Execution infrastructure
- Tool implementation
- Malware-analysis algorithms
- Long-term investigation database
- Scheduling
- Workflow management
- User interface

---

## Context vs Shared Investigation State

This is a critical boundary.

### Static Agent Context

Answers:

> What does this specialist currently know while working on its assignment?

```text
Static Agent Context
├── Assignment
├── Relevant evidence
├── Capability interactions
├── Results
└── Current reasoning context
```

### Shared Investigation State

Answers:

> What does the entire investigation currently know?

```text
Shared Investigation State
├── Evidence
├── Findings
├── Artifacts
├── Artifact lineage
├── Hypotheses
├── Confidence
└── Tasks / status
```

The shared state is the memory of the investigation. The Coordinator uses it to decide what should happen next.

Do not merge these two concepts.

---

## Relationship to MCP

MCP should remain the **capability layer**.

```text
                 Static Agent
                       |
                "I need to..."
                       |
                       v
                 Capability Layer
                       |
                       v
                      MCP
                       |
             +---------+---------+
             v         v         v
            YARA     capa    Disassembly
```

This gives the system:

- modularity,
- extensibility,
- isolation,
- auditability,
- specialization.

The Static Agent reasons about which capability is useful; MCP exposes and executes the capability.

---

## Relationship to the External Sandbox

The Static Agent harness does **not** need to own a sandbox.

If a capability requires execution, that execution remains behind the capability/MCP boundary.

```text
Static Agent
     |
  Harness
     |
 Capability
     |
    MCP
     |
External infrastructure
```

The Static Agent should not care where the underlying capability runs.

---

## Two-Level Reasoning

The overall system has two reasoning levels.

### Global level

The Coordinator asks:

> **What should happen next?**

```text
Investigation State
        |
    Coordinator
        |
  Select Specialist
```

### Local level

The Static Agent asks:

> **How should I investigate this?**

```text
Investigation Assignment
        |
    Static Agent
        |
 Select capability
        |
 Interpret result
        |
 Investigate further?
```

The harness supports this local specialist loop. It should not take over the Coordinator's global role.

---

## Static Agent Investigation Flow

```text
Assignment
   |
Understand objective
   |
Inspect available evidence
   |
Form or evaluate hypotheses
   |
Choose static capability
   |
Receive result
   |
Interpret result
   |
Update understanding
   |
Need more static evidence?
   |              |
  Yes             No
   |               |
choose another     v
capability       Findings
                   |
              Investigation Result
```

This is an adaptive investigation rather than a fixed static-analysis pipeline.

---

## Evidence as the Feedback Mechanism

The larger investigation loop is:

```text
             Investigation State
                     |
                 Assignment
                     v
                Static Agent
                     |
                Investigation
                     |
                  Evidence
                     |
                     v
             Investigation State
```

New evidence can:

- strengthen a hypothesis,
- weaken a hypothesis,
- create a new hypothesis,
- reveal a new artifact,
- indicate that more investigation is necessary.

---

## What V1 Should Prove

The first harness should answer one question:

> **Can one Static Agent autonomously investigate an assigned static-analysis problem through a bounded set of capabilities and return useful, structured findings?**

Desired flow:

```text
Assignment
    |
Static Agent
    |
Harness
    |
Reason
    |
Select capability
    |
MCP
    |
Static analysis result
    |
Interpret evidence
    |
Reason again if necessary
    |
Structured findings
    |
Shared Investigation State
```

If this works reliably, the same conceptual harness can later support other specialists.

---

## Later Extensions

Only after the Static Agent works should the harness be considered for:

- stronger context management,
- context compaction,
- persistence,
- checkpointing,
- richer lifecycle events,
- advanced error recovery,
- policy/permission handling,
- streaming,
- specialist-specific configuration.

Add these because the system needs them, not because another harness contains them.

---

## Existing Systems as References

Existing agent harnesses should be used as architectural references rather than adopted wholesale.

### DeepSeek Harness

Study:

- service boundaries,
- dependency separation,
- agent-loop separation,
- replaceable components,
- capability/plugin composition.

### Pi Agent Core

Study:

- minimal agent loop,
- context/tool boundaries,
- lightweight runtime.

### Cline Agent

Study:

- separation of core agent execution from larger application state,
- lifecycle events,
- tool orchestration.

### OpenHands

Study:

- agent/conversation lifecycle,
- event-oriented execution,
- mature agent runtime patterns.

### Malware-specific agent systems

Study:

- evidence-grounded reasoning,
- hypotheses,
- artifacts,
- investigation state,
- iterative investigation.

The goal is to preserve Mira's own architecture while borrowing proven ideas.

---

## Final Concept

```text
                  Investigation Assignment
                            |
                            v
                  +--------------------+
                  |    Static Agent    |
                  |                    |
                  | "How investigate?" |
                  +---------+----------+
                            |
                            v
                  +--------------------+
                  |      Harness       |
                  |                    |
                  | Reasoning Loop     |
                  | Context            |
                  | Capability Access  |
                  | Lifecycle          |
                  +---------+----------+
                            |
                            v
                  +--------------------+
                  |  MCP Capability    |
                  |      Layer         |
                  +---------+----------+
                            |
                            v
                  +--------------------+
                  | Static Analysis    |
                  | Capabilities       |
                  +---------+----------+
                            |
                            v
                         Evidence
                            |
                            v
                  +--------------------+
                  | Shared Investigation|
                  | State              |
                  +--------------------+
```

## Fundamental Separation

**Coordinator** → decides **WHO** investigates.

**Static Agent** → decides **HOW** to investigate.

**Harness** → enables the specialist's investigation loop.

**MCP** → provides **CAPABILITIES**.

**Investigation State** → records **WHAT IS KNOWN**.

**Evidence** → determines **WHAT HAPPENS NEXT**.
