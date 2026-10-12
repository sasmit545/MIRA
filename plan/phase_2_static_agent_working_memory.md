# Phase 2 — Static Agent Working Memory

## Objective

Give the Static Agent a persistent local understanding of its current investigation across multiple capability calls.

The working memory should answer:

> What does the Static Agent currently know, believe, and still need to determine?

This is separate from the global Investigation State.

---

## 1. Define the Boundary

### Static Agent Working Memory

Information needed by this specialist to continue its current assignment.

```text
Static Agent Working Memory
├── Assignment
├── Current understanding
├── Hypotheses
├── Important evidence
├── Capability history
├── Confirmed facts
├── Open questions
└── Next investigation candidates
```

### Shared Investigation State

Information relevant to the entire investigation.

```text
Shared Investigation State
├── Evidence
├── Findings
├── Artifacts
├── Lineage
├── Hypotheses
├── Confidence
└── Tasks / Status
```

Keep these concepts separate.

---

## 2. Assignment Memory

The assignment should remain available throughout the specialist's investigation.

It should capture:

- Investigation objective
- Relevant artifact/sample
- Constraints
- Expected outcome
- Initial evidence supplied with the assignment

The Static Agent should always be able to answer:

> What exactly am I trying to determine?

---

## 3. Current Understanding

Maintain a compact representation of the Static Agent's current mental model of the sample.

It should capture:

- What appears normal
- What appears suspicious
- Important characteristics discovered
- Relationships between observations
- Current interpretation
- Changes in understanding after new evidence

This should be a concise interpretation, not a copy of tool output.

---

## 4. Hypothesis Memory

The Static Agent should explicitly maintain hypotheses across investigation steps.

Each hypothesis should capture:

- Current suspicion
- Supporting evidence
- Contradicting or weakening evidence
- Confidence
- What remains unknown
- What could confirm or reject it

New evidence should be able to strengthen, weaken, modify, or eliminate a hypothesis.

The purpose is to enable adaptive investigation rather than independent tool calls.

---

## 5. Evidence Index

Working memory should reference important evidence rather than contain every raw observation.

For each important evidence item, retain:

- Evidence ID
- Short description
- Why it matters
- Related hypothesis
- Relevance/confidence
- Whether it has influenced an investigation decision

The complete observation remains available through the evidence/trace system.

Example:

```text
E12 → suspicious process-injection import
E17 → encoded network-related string
E21 → high entropy section
```

---

## 6. Capability History

Remember what the Static Agent has already investigated.

Track conceptually:

```text
Capability History
├── Capability used
├── Purpose
├── Important result
├── Evidence generated
└── Investigation impact
```

This should help prevent unnecessary repeated investigations and provide continuity between reasoning steps.

---

## 7. Confirmed Facts

Separate established facts from interpretations.

### Facts

Information supported by evidence.

```text
PE executable
High entropy section
YARA rule matched
Suspicious API imported
```

### Hypotheses

Interpretations that may still be wrong.

```text
Likely packed
Possibly performs process injection
Possibly communicates with C2
```

The agent should be able to revise hypotheses without losing established facts.

---

## 8. Open Questions

Explicitly track what the investigation still does not know.

Examples:

```text
Open Questions

- Is the sample actually packed?
- Which function performs the suspicious behavior?
- Is the network string operational or dead data?
- Is process injection actually reachable?
```

Open questions should help drive the next investigation.

---

## 9. Next Investigation Candidates

Maintain possible next investigations rather than a fixed sequence.

Each candidate should have:

- Proposed investigation
- Reason it may be useful
- Related hypothesis/question
- Relevant evidence

These are candidates, not permanent plans.

New evidence should be able to change them.

---

## 10. Memory Update Cycle

Working memory should evolve after every meaningful capability interaction.

```text
Capability Result
       ↓
Interpret result
       ↓
Identify important information
       ↓
Update facts
       ↓
Update evidence index
       ↓
Update hypotheses
       ↓
Resolve/create open questions
       ↓
Reconsider next investigations
       ↓
Updated Working Memory
```

This is the central mechanism that makes the investigation adaptive.

---

## 11. Memory Promotion Rules

Not every observation should become persistent working memory.

Promote information when it:

- Changes current understanding
- Supports or weakens a hypothesis
- Answers an important question
- Creates a new question
- Identifies suspicious behavior
- Determines the next investigation
- Prevents redundant investigation
- Is necessary for the final finding

Unimportant raw output should remain outside working memory.

---

## 12. Memory Lifecycle

The working memory should have a clear lifecycle.

```text
Assignment
    ↓
Initialize memory
    ↓
Investigation
    ↓
Update memory
    ↓
Update memory
    ↓
Update memory
    ↓
Investigation complete
    ↓
Final findings
```

At completion, useful conclusions and evidence references are promoted into the shared Investigation State.

The specialist's temporary working context can then be discarded.

---

## 13. Working Memory vs Model Context

Working memory and model context are not the same thing.

```text
Complete Evidence / History
          ↓
     Working Memory
          ↓
 Relevant Context Selection
          ↓
        LLM
```

Working memory is the specialist's structured understanding.

Model context is the subset currently presented to the model.

Context selection and compaction belong to later phases.

---

## 14. What Phase 2 Does NOT Cover

Do not solve these as part of Phase 2:

- Context compaction
- Long-term persistence
- Coordinator
- Multi-agent memory
- Dynamic/Forensics memory
- Evaluation corpus
- Advanced retrieval
- Complex memory architectures

Phase 2 establishes the specialist's coherent investigation state.

---

## 15. Phase 2 Acceptance Criteria

Phase 2 is successful when the Static Agent can:

- **Understand:** remember what it was asked to investigate.
- **Remember:** know what capabilities it has already used.
- **Reason:** maintain hypotheses across multiple steps.
- **Ground:** connect conclusions to evidence IDs.
- **Adapt:** change its investigation when new evidence appears.
- **Avoid repetition:** recognize investigations it has already performed.
- **Identify gaps:** maintain explicit open questions.
- **Plan:** generate sensible candidate next investigations.
- **Recover:** continue reasoning without requiring the entire raw history in model context.

---

## 16. Final Target

Move from:

```text
Tool → Result → Tool → Result → Tool → Result
```

to:

```text
             Working Memory
                  ↑   ↓
                  LLM
               ↗       ↘
          Capability   Reasoning
               ↓
             Evidence
               ↓
          Working Memory
```

## Core Principle

> Do not simply give the Static Agent more context.

> Give it a stable investigative state that preserves what matters, while keeping the complete investigation recoverable.
