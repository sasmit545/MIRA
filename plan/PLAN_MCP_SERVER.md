Yep 😄 — you meant **just the Markdown code block here**, not a file.

````md
# Plan for Building Static MCP Server and Static-Only MIRA Vertical Slice

## Context

We are implementing the Multi-Agent Investigation and Reasoning Architecture (MIRA) as a **static-only vertical slice**.

The goal of this milestone is to demonstrate the core adaptive behavior of MIRA:

> The Static Agent selects analysis capabilities locally, produces evidence, and newly discovered evidence causes the Coordinator to assign a different Static investigation objective.

The implementation does not include dynamic analysis, forensics, live malware execution, sandboxing, memory acquisition, or network capture.

## Scope

### Included

- Static MCP server
- Static analysis capability modules
- Static Agent with a local tool-selection loop
- Artifact, evidence, hypothesis, task, and provenance models required by the static workflow
- Minimal Coordinator
- Coordinator-to-Static-Agent objective assignment and reassignment
- Safe, benign PE fixtures for testing
- End-to-end demonstration of evidence-driven reassignment

### Deferred

- `dynamic_agent.py`
- `forensics_agent.py`
- Dynamic MCP server
- Forensics MCP server
- Dynamic or forensic investigation assignments
- Live malware execution
- Sandbox execution
- Memory dumps
- Network capture

The Coordinator in this milestone assigns **Static Agent objectives only**.

---

## Architecture

```text
                 Coordinator
                      |
              STATIC objective
                      |
                      v
                Static Agent
                      |
             local reasoning loop
                      |
                MCP Client
                      |
                      v
             Static MCP Server
                      |
          +-----------+-----------+
          |           |           |
          v           v           v
      file_info    analyze_pe   imports
          |           |           |
          +-----------+-----------+
                      |
                      v
                  Evidence
                      |
                State update
                      |
                      v
                 Coordinator
                      |
              new STATIC objective
                      |
                      v
                Static Agent
````

The MCP layer performs deterministic analysis.

The Static Agent:

* selects capabilities
* interprets returned results
* forms and updates investigation hypotheses
* decides whether additional static analysis is needed

The Coordinator:

* assigns static investigation objectives
* evaluates accumulated evidence
* reassigns static objectives when warranted

---

## 1. Define the Binary and Artifact Input Contract

All Static MCP capabilities operate on an MIRA `artifact_id`.

The artifact store resolves the ID to the underlying file. Capabilities should not accept unrestricted filesystem paths from the agent.

Example:

```json
{
  "artifact_id": "artifact_001"
}
```

Capabilities may additionally accept operation-specific parameters.

Example:

```json
{
  "artifact_id": "artifact_001",
  "offset": 1048576,
  "length": 4096
}
```

### Artifact Requirements

The artifact model should provide:

* `artifact_id`
* file path/location managed by the artifact store
* file type
* size
* hash
* parent artifact where applicable

### Input Validation

The server must validate:

* artifact exists
* artifact is accessible
* requested operation is supported for the artifact type
* offsets/ranges are within file bounds
* requested size does not exceed configured limits

`analyze_pe` must return `unsupported` rather than attempting PE parsing when the artifact is not a valid PE.

---

## 2. Define a Standard MCP Result Envelope

Every capability returns a consistent structured result.

### Success

```json
{
  "status": "ok",
  "data": {},
  "metadata": {
    "artifact_id": "artifact_001",
    "capability": "analyze_pe",
    "tool_version": "..."
  }
}
```

### Unsupported

```json
{
  "status": "unsupported",
  "data": null,
  "error": {
    "code": "UNSUPPORTED_FILE_TYPE",
    "message": "Artifact is not a valid PE file."
  },
  "metadata": {
    "artifact_id": "artifact_001",
    "capability": "analyze_pe"
  }
}
```

### Error

```json
{
  "status": "error",
  "data": null,
  "error": {
    "code": "ANALYSIS_FAILED",
    "message": "PE parsing failed."
  },
  "metadata": {}
}
```

Initial error categories should include:

* `ARTIFACT_NOT_FOUND`
* `INVALID_INPUT`
* `UNSUPPORTED_FILE_TYPE`
* `ANALYSIS_FAILED`
* `TOOL_NOT_AVAILABLE`
* `TIMEOUT`
* `RESOURCE_LIMIT`
* `PERMISSION_DENIED`

This allows the Static Agent to react programmatically instead of interpreting inconsistent failure messages.

---

## 3. Static MCP Capabilities

The initial Static MCP server exposes the following capabilities.

### `file_info`

Returns basic artifact identification information:

* file type
* file size
* MD5
* SHA1
* SHA256
* whole-file entropy

This is the primary artifact triage capability.

### `analyze_pe`

Performs **structural PE analysis**.

Returns:

* architecture
* PE/COFF headers
* optional-header metadata
* entry point
* image base
* subsystem
* DLL characteristics
* PE characteristics
* section metadata
* section sizes
* section permissions/characteristics
* section entropy where available
* overlay information where available

`analyze_pe` intentionally does **not** return the complete import/export tables.

Imports and exports remain separate capabilities so that the Static Agent can request them independently and large results can be limited or paginated.

### `list_imports`

Returns:

* imported DLLs
* imported functions
* optional RVA/location information

Supports result limits and pagination for large import tables.

### `list_exports`

Returns:

* exported names
* ordinals
* addresses/RVAs

Supports result limits and pagination.

### `extract_strings`

Extracts:

* ASCII strings
* Unicode strings
* offsets/locations where available

The capability should support configurable:

* minimum string length
* maximum number of results
* offset-based pagination

A later implementation may support FLOSS-based extraction, but the initial contract should remain independent of the underlying extraction engine.

### `calculate_entropy`

Calculates entropy for:

* entire file
* PE section
* selected file region

Inputs should allow a bounded region:

```json
{
  "artifact_id": "artifact_001",
  "offset": 100000,
  "length": 4096
}
```

The server must reject unbounded or excessively large region requests.

### `detect_packer`

Identifies **packing/protection indicators**, distinct from generic entropy analysis.

Possible detection sources include:

* known packer signatures
* protector signatures
* known section-name patterns
* entry-point anomalies
* import-table characteristics
* PE structural heuristics

The result should report indicators and confidence rather than simply duplicating the entropy result.

Example:

```json
{
  "packed": true,
  "packer": "UPX",
  "confidence": 0.96,
  "indicators": [
    "UPX section names",
    "known UPX signature"
  ]
}
```

Entropy itself remains available through `calculate_entropy`.

### `scan_yara`

Runs YARA against the artifact.

The initial implementation uses a **configured, version-controlled rules directory**.

Configuration should specify:

* rules directory
* enabled rule sets
* rule-set version/hash

The MCP request should select a configured ruleset rather than accept arbitrary filesystem paths.

Example:

```json
{
  "artifact_id": "artifact_001",
  "ruleset": "default"
}
```

The response includes:

* matched rule names
* namespaces/tags
* matched strings where available
* ruleset identifier/version

User-supplied arbitrary YARA rules are out of scope for this milestone.

### `run_capa`

Runs CAPA against the artifact.

The implementation must record the CAPA version and rule-set version/hash in the result metadata.

Returns:

* detected capabilities
* associated rule information
* ATT&CK mappings where provided by CAPA

CAPA is treated as a deterministic detection capability; the Static Agent interprets what the detected capabilities imply for the investigation.

### `list_functions`

Discovers statically identified functions.

The initial implementation should use the selected disassembly/analysis engine and clearly document that function discovery is heuristic and may be incomplete.

Returns:

* function address
* size where available
* name where available
* discovery source

Supports limits and pagination.

### `disassemble_function`

Disassembles a **selected function**, rather than an entire binary.

Input:

```json
{
  "artifact_id": "artifact_001",
  "function_address": "0x401230"
}
```

The initial implementation uses **Capstone** for instruction disassembly.

Capstone performs instruction decoding but does not itself provide sophisticated function discovery or recovery of complete control-flow structures. Therefore `list_functions` should use the PE/disassembly analysis available in the implementation and document its limitations.

The response should include:

* function address
* architecture
* instructions
* byte/address information where useful

Large output must be bounded.

---

## 4. Output Limits and Pagination

Capabilities that can produce large results must support bounded responses.

This applies particularly to:

* strings
* imports
* exports
* functions
* disassembly
* YARA matches

Common parameters:

```json
{
  "limit": 100,
  "offset": 0
}
```

The server should return metadata indicating whether additional results exist.

The MCP server must never return an uncontrolled complete dump of a large binary's analysis output.

---

## 5. Static Capability Modules

Create:

```text
mira/
└── capabilities/
    └── static/
        ├── file_info.py
        ├── pe_analyzer.py
        ├── import_lister.py
        ├── export_lister.py
        ├── string_analyzer.py
        ├── entropy_analyzer.py
        ├── packer_detector.py
        ├── yara_scanner.py
        ├── capa_analyzer.py
        ├── function_analyzer.py
        └── disassembler.py
```

Each module should:

* implement one well-defined analysis operation
* accept validated artifact references
* return structured results
* include provenance metadata
* enforce configured limits
* handle unsupported inputs explicitly
* avoid returning unnecessary raw tool output

---

## 6. Static MCP Server

Create:

```text
mira/mcp/servers/static_server.py
```

The server will:

* initialize FastMCP
* register Static capabilities
* validate tool inputs
* resolve artifacts
* invoke capability implementations
* enforce resource limits
* return the standard result envelope

The MCP server does not:

* generate hypotheses
* decide the next investigation step
* classify the sample
* modify MIRA investigation state
* communicate with the Coordinator

---

## 7. MCP Client

Create:

```text
mira/mcp/client.py
```

The client provides the Static Agent with:

* MCP connection
* capability discovery
* capability invocation
* structured responses
* error handling

The Static Agent must call capabilities through the MCP client rather than importing capability implementations directly.

---

## 8. Capability Registry

Create:

```text
mira/mcp/capability_registry.py
```

The registry provides metadata about Static capabilities:

* capability name
* description
* input schema
* output schema
* supported artifact types
* capability category

FastMCP remains responsible for actual MCP tool registration.

---

## 9. Artifact, Evidence, and Provenance

The vertical slice retains MIRA's artifact/evidence/provenance model.

### Artifact

Tracks:

* artifact ID
* type
* hash
* parent artifact
* source/creation metadata

### Evidence

Tracks:

* evidence ID
* observation
* artifact ID
* capability/tool
* location where applicable
* confidence
* timestamp
* provenance

The MCP capability result should provide sufficient provenance for the Static Agent to construct Evidence objects.

---

## 10. Static Agent

The Static Agent implements the local investigation loop:

```text
Receive objective
       ↓
Inspect current state
       ↓
Select MCP capability
       ↓
Execute capability
       ↓
Interpret result
       ↓
Generate/update evidence
       ↓
Decide whether additional static analysis is needed
       ↓
Return finding
```

The agent can chain multiple capabilities during a single objective without consulting the Coordinator after every tool call.

---

## 11. Minimal Static Coordinator

The Coordinator is deliberately limited.

It can:

* assign a Static Agent objective
* receive findings/evidence
* update investigation state
* evaluate whether another static objective is warranted
* reassign a new Static Agent objective

It must not assign:

* Dynamic investigation
* Forensics investigation
* Sandbox analysis
* Memory analysis
* Network analysis

---

## 12. Security and Resource Isolation

Because the MCP server may analyze hostile files, capability execution must be treated as untrusted processing.

The implementation must include:

* artifact-ID based access rather than arbitrary agent-provided filesystem paths
* path validation through the artifact store
* no arbitrary file reads
* configurable file-size limits
* CPU limits where supported
* memory limits where supported
* execution timeouts
* bounded output sizes
* isolated temporary working directories
* controlled external-tool invocation
* no execution of the analyzed PE

The server performs **static analysis only**. None of the capabilities may execute the analyzed binary.

---

## 13. Dependency Pinning

Record exact versions of important dependencies in the project configuration.

Initial dependencies include:

* `fastmcp`
* `pefile`
* `capstone`
* `yara-python`
* `flare-capa`
* Python standard library `hashlib`

Optional:

* `lief`

External tools such as FLOSS or Detect-It-Easy should only be introduced when their corresponding capability is implemented.

The test environment should pin compatible versions of external tools and rulesets as well.

---

## 14. Testing and Verification

### Capability Unit Tests

Test every capability independently using safe PE fixtures.

At minimum include:

* a benign Hello World PE
* a benign PE with imports/exports
* a fixture with multiple sections and differing entropy
* a fixture that produces known YARA/CAPA results
* a packed/protected benign test artifact where legally and safely available

Tests should verify both successful and unsupported/error cases.

### MCP Integration Test

Verify:

```text
MCP Client
    ↓
Static MCP Server
    ↓
Capability
    ↓
Structured result
```

### Static Agent Test

Verify:

```text
Objective
   ↓
tool selection
   ↓
MCP invocation
   ↓
result interpretation
   ↓
additional tool selection
   ↓
finding
```

### Coordinator Test

Verify that evidence changes the next static objective:

```text
Coordinator
    ↓
"Characterize sample"
    ↓
Static Agent
    ↓
file_info + analyze_pe
    ↓
Evidence:
high-entropy executable section
    ↓
Coordinator
    ↓
"Assess packing indicators"
    ↓
Static Agent
    ↓
detect_packer + extract_strings
```

The test should explicitly verify that the second objective is selected because of the first investigation's evidence rather than because of a fixed pipeline.

### Provenance Test

Every Evidence object must be traceable:

```text
Evidence
   ↓
Capability result
   ↓
Artifact
   ↓
Underlying analysis tool/version
```

---

## 15. Files to Create

```text
mira/
├── mcp/
│   ├── client.py
│   ├── capability_registry.py
│   └── servers/
│       └── static_server.py
│
├── capabilities/
│   └── static/
│       ├── file_info.py
│       ├── pe_analyzer.py
│       ├── import_lister.py
│       ├── export_lister.py
│       ├── string_analyzer.py
│       ├── entropy_analyzer.py
│       ├── packer_detector.py
│       ├── yara_scanner.py
│       ├── capa_analyzer.py
│       ├── function_analyzer.py
│       └── disassembler.py
│
├── agents/
│   └── static_agent.py
│
└── tests/
    ├── fixtures/
    │   └── benign_pe/
    ├── test_capabilities.py
    ├── test_mcp_server.py
    ├── test_static_agent.py
    └── test_coordinator_static_loop.py
```

---

## 16. Known Test Corpus

Maintain a small version-controlled corpus of **safe, benign PE fixtures** with expected analysis properties.

Each fixture should have:

* SHA256
* expected file type
* expected PE architecture
* expected section structure
* expected imports/exports where relevant
* expected entropy characteristics where relevant
* expected YARA matches where applicable
* expected CAPA results where applicable

The corpus should remain stable so changes to analysis dependencies or rulesets can be detected during CI.

---

## 17. Out of Scope

```text
Dynamic execution
Sandboxing
Process tracing
Memory analysis
Memory dumps
Network capture
Dynamic Agent
Forensics Agent
Dynamic MCP server
Forensics MCP server
Cross-specialist coordination
Live malware execution
```

## Success Criterion

The first MIRA milestone is complete when the system demonstrates:

```text
Coordinator
    ↓
Static investigation objective
    ↓
Static Agent
    ↓
local MCP tool selection
    ↓
structured analysis
    ↓
Evidence
    ↓
Coordinator re-evaluates state
    ↓
new Static investigation objective
```

The key demonstration is that **the next investigation is evidence-driven rather than a predefined static-analysis sequence**.

```
```
