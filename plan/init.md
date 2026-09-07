# MIRA Implementation Plan

## Context
MIRA is an adaptive multi-agent architecture for evidence-driven malware investigation. The system treats malware analysis as an investigation process where:
- Coordinator decides WHO investigates next (global reasoning)
- Specialist decides HOW to investigate (local reasoning)  
- Evidence determines WHAT happens next

This repository currently contains only the architecture specification (README.md and design doc). We will implement a minimal working loop that demonstrates the core adaptive behavior: the system changes its next investigation based on newly discovered evidence.

Key insights from the design document:
- Dual-loop reasoning: Specialist-local loop (tool selection/usage) + Global coordination loop (specialist reassignment)
- Artifact-centric approach with explicit lineage tracking
- Compact inter-agent contract (INVESTIGATE, FINDING, ARTIFACT messages)
- Specialists perform local multi-step tool selection without Coordinator involvement after each tool
- Evidence and artifacts live in shared state; messages carry compact references
- New meaningful artifacts return to global investigation loop

## Approach
Following a bottom-up approach that prioritizes the most novel and risky components first, we will implement in this order:

### Phase 1: Core Data Models & Configuration
- Define structured data models matching README Section 9 and design doc Section 9:
  - `InvestigationState`: tracks sample, artifacts, evidence, hypotheses, tasks, history
  - `Evidence`: normalized observation with source, location, tool, timestamp, confidence, provenance
  - `Artifact`: discovered files with type, hash, version, parent/child lineage, relationships
  - `Hypothesis`: statements with confidence levels, status, supporting/contradicting evidence
  - `InvestigationTask`: active/completed/failed tasks with dependencies and status
- Create configuration system (environment variables + config.yaml)
- Implement basic logging, audit trail, and artifact/repository management

### Phase 2: MCP Capability Server (Static Analysis)
- Build FastMCP server exposing static analysis capabilities:
  - `analyze_pe`: PE file metadata (entry point, sections, characteristics)
  - `extract_strings`: ASCII/Unicode strings with minimum length and entropy
  - `list_imports`: DLL imports and functions
  - `file_info`: basic file properties (size, hashes, entropy)
  - `detect_packer`: packing/obfuscation detection
- Each capability wraps real analysis tools (pefile, capstone, yara-python, hashlib, strings via subprocess)
- Returns structured JSON results that map cleanly to Evidence/Artifact objects
- Includes basic error handling, timeout controls, and audit logging

### Phase 3: Static Agent Specialist with Local Loop
- Create base agent class handling LLM interaction (configurable via env var)
- Implement StaticAgent that:
  - Receives investigation objective and current state via INVESTIGATE message
  - Uses LLM to reason about which MCP capabilities are needed (local planning)
  - Executes capabilities via tool calls to the MCP server
  - Analyzes results locally, potentially invoking additional tools based on intermediate findings
  - Structures results into Evidence and Artifact objects with full provenance
  - Returns concise FINDING and/or ARTIFACT messages (not raw tool output)
- Initial focus: demonstrate LLM-driven capability selection, local tool chaining, and evidence generation

### Phase 4: Coordinator & Global Investigation Loop
- Implement Coordinator that:
  - Takes InvestigationState as input
  - Selects next specialist + objective based on evidence/hypotheses/artifacts
  - Generates investigation objective and constraints
  - Determines priority and provides reasoning
  - Handles ARTIFACT messages from specialists (updating state, checking for new investigation opportunities)
- Wire up the dual-loop system:
  - **Specialist-local loop**: Agent plans → selects/uses MCP tools → analyzes → refines until objective satisfied
  - **Global coordination loop**: State → Coordinator selects specialist/objective → Specialist investigates → State updated → Coordinator re-evaluates
- Demonstrate that new evidence/artifacts changes the next investigation (per README Section 15 milestone)

### Phase 5: Verification & Extension
- Test loop with sample PE file showing adaptive behavior
- Example: Static analysis finds suspicious import/encrypted region → Coordinator assigns Dynamic investigation
- Prepare for Phase 6: adding Dynamic and Forensics agents with their MCP servers and capability sets

## Critical Files to Create
Incorporating recommendations from both README Section 8 and design doc insights:

```
mira/
├── main.py                    # Entry point: initialization and global loop
├── config/
│   └── config.yaml            # Configuration (LLM provider, API keys, paths, MCP ports)
├── core/
│   ├── coordinator.py         # Global reasoning: selects WHO next (global loop)
│   ├── investigation.py       # Investigation state container (artifacts, evidence, hypotheses, tasks)
│   ├── state.py               # InvestigationState class
│   ├── evidence.py            # Evidence class (normalized observations)
│   ├── artifact.py            # Artifact class (with lineage and relationships)
│   ├── hypothesis.py          # Hypothesis class
│   ├── task.py                # InvestigationTask class
│   └── message.py             # Inter-agent message types (INVESTIGATE, FINDING, ARTIFACT, etc.)
├── agents/
│   ├── base_agent.py          # LLM interaction base class + local loop scaffolding
│   ├── static_agent.py        # Static specialist: local reasoning + MCP tool selection
│   ├── dynamic_agent.py       # (Phase 6)
│   └── forensics_agent.py     # (Phase 6)
├── mcp/
│   ├── client.py              # MCP client for agent-tool communication
│   ├── capability_registry.py # Registry of available capabilities with schemas
│   └── servers/
│       ├── static_server.py   # FastMCP server for static analysis capabilities
│       ├── dynamic_server.py  # (Phase 6)
│       └── forensics_server.py # (Phase 6)
├── capabilities/
│   └── static/                # Static analysis capability implementations
│       ├── pe_analyzer.py
│       ├── string_entropy_analyzer.py
│       ├── import_lister.py
│       ├── file_info.py
│       └── packer_detector.py
├── storage/
│   ├── state_store.py         # Persistence for investigation state (JSON/SQLite)
│   ├── artifact_store.py      # Storage for derived artifacts (content-addressed)
│   └── evidence_store.py      # Indexed evidence storage for retrieval by ID
├── prompts/
│   ├── coordinator.txt        # Prompt templates for Coordinator reasoning/global loop
│   ├── static_agent.txt       # Prompt templates for Static Agent local loop/reasoning
│   ├── dynamic_agent.txt      # (Phase 6)
│   └── forensics_agent.txt    # (Phase 6)
├── evaluation/
│   ├── metrics.py             # Adaptivity, evidence utilization, efficiency metrics
│   └── benchmark.py           # Comparison against fixed pipeline baseline
└── tests/
```

## Verification
To verify the implementation works as intended:

1. **Basic functionality**: 
   - System starts and accepts a malware sample file path
   - MCP server responds to capability calls with structured results
   - Agents exchange compact messages (not raw tool output)

2. **Specialist-local loop demonstration**:
   - Static Agent receives objective: "Identify suspicious executable characteristics"
   - Agent locally decides to run `analyze_pe` → `extract_strings` → `list_imports` based on intermediate results
   - Agent potentially chains tools: finds packed executable → runs `detect_packer` → if packed, attempts entropy analysis
   - Agent returns concise FINDING with evidence references, not raw tool dumps

3. **Global coordination loop demonstration**:
   - Coordinator assigns initial Static investigation
   - Static Agent returns new Evidence (suspicious import) and Artifact (extracted strings)
   - Shared state updated with new evidence/artifact
   - Coordinator re-evaluates and assigns Dynamic investigation based on evidence
   - Demonstrate non-linear flow: Static → Dynamic → Static (if new artifact needs re-analysis)

4. **Architecture constraints**:
   - Coordinator never calls analysis tools directly (only via MCP capabilities)
   - Specialists only reason about investigation, never modify state directly (state updates via message handling)
   - All evidence includes confidence scores, provenance, tool source, and timestamps
   - Investigation history maintains complete trace of decisions, tool usage, and artifact lineage

5. **Extensibility check**:
   - Adding a new capability requires only implementing the function with proper schema and registering it
   - Adding a new specialist follows the same pattern (base agent + local loop + MCP client)
   - Changing LLM provider requires only updating config/env vars
   - New MCP servers can be added without changing Coordinator contract

This approach delivers the core adaptive investigation behavior defined in README Section 15 as the first milestone: **"The system changes its next investigation because of newly discovered evidence."** while implementing the dual-loop reasoning and artifact-centric approach emphasized in the design document.