# Plan: Define Agent ↔ MCP Contracts

## Goal

Introduce a typed, versioned contract layer between the Static Agent and
MCP server.

The contracts should be the stable boundary between:

``` text
Static Agent
    ↓
Contract
    ↓
MCP Client
    ↓
MCP Server
    ↓
Capability
```

The existing architecture already defines artifact-ID based inputs,
structured MCP results, capability schemas, pagination, and provenance.
This plan turns those concepts into concrete code-level contracts.

------------------------------------------------------------------------

## 1. Create a Dedicated Contracts Package

Create:

``` text
mira/
├── contracts/
│   ├── __init__.py
│   ├── common.py
│   ├── requests.py
│   ├── results.py
│   ├── errors.py
│   ├── evidence.py
│   └── capabilities/
│       ├── __init__.py
│       ├── file_info.py
│       ├── analyze_pe.py
│       ├── imports.py
│       ├── exports.py
│       ├── strings.py
│       ├── entropy.py
│       ├── packer.py
│       ├── yara.py
│       ├── capa.py
│       ├── functions.py
│       └── disassembly.py
```

The contracts package should contain the canonical models used by the
Agent, MCP client, registry, and MCP server.

------------------------------------------------------------------------

## 3. Define Common Types

Create reusable types in `common.py`.

Examples:

``` text
ContractVersion
RequestId
ArtifactId
CapabilityName
Timestamp
```

Use constrained/validated types where appropriate.

------------------------------------------------------------------------

## 3. Define the MCP Request Contract

Create `CapabilityRequest` in `requests.py`.

Example:

``` json
{
  "contract_version": "1.0",
  "request_id": "req_001",
  "capability": "analyze_pe",
  "input": {
    "artifact_id": "artifact_001"
  }
}
```

Requirements:

-   Require `artifact_id` where applicable.
-   Validate capability-specific parameters.
-   Reject arbitrary filesystem paths.
-   Support pagination where applicable.
-   Validate bounded offset/length parameters.

The Agent/MCP client should construct requests using this contract.

The `input` field should use a union or generic of capability-specific input models.

Validation should include:

- Reject arbitrary filesystem paths.
- Require `artifact_id` where applicable.
- Validate capability-specific parameters.
- Validate bounded offset/length parameters.

------------------------------------------------------------------------

## 4. Define the MCP Result Contract

Create a generic `CapabilityResult[T]` in `results.py`.

Example:

``` json
{
  "contract_version": "1.0",
  "request_id": "req_001",
  "status": "ok",
  "data": {},
  "error": null,
  "metadata": {}
}
```

Supported statuses:

``` text
ok
unsupported
error
```

The result should be generic so each capability has a typed output.

For example:

``` text
CapabilityResult[AnalyzePEOutput]
CapabilityResult[ListImportsOutput]
CapabilityResult[ExtractStringsOutput]
```

------------------------------------------------------------------------

## 6. Define Standardized Errors

Create `errors.py`.

Initial error codes:

``` text
ARTIFACT_NOT_FOUND
INVALID_INPUT
UNSUPPORTED_FILE_TYPE
ANALYSIS_FAILED
TOOL_NOT_AVAILABLE
TIMEOUT
RESOURCE_LIMIT
PERMISSION_DENIED
```

Create a structured error model:

``` text
CapabilityError
    code
    message
    details
```

The Agent should make decisions based on `code`, not by parsing error
messages.

------------------------------------------------------------------------

## 7. Define Capability-Specific Schemas

Each capability gets an input and output model.

For example:

``` text
AnalyzePEInput
AnalyzePEOutput

ListImportsInput
ListImportsOutput

ListExportsInput
ListExportsOutput

ExtractStringsInput
ExtractStringsOutput

CalculateEntropyInput
CalculateEntropyOutput

DetectPackerInput
DetectPackerOutput

ScanYaraInput
ScanYaraOutput

RunCapaInput
RunCapaOutput

ListFunctionsInput
ListFunctionsOutput

DisassembleFunctionInput
DisassembleFunctionOutput
```

Example:

``` python
class AnalyzePEInput(BaseModel):
    artifact_id: str


class AnalyzePEOutput(BaseModel):
    architecture: str
    entry_point: int
    image_base: int
    sections: list[Section]
```

The models should describe the public contract, not the underlying
implementation.

------------------------------------------------------------------------

## 8. Define Shared Pagination Models

Create reusable pagination models rather than duplicating them across
capabilities.

``` text
PaginationInput
PaginationMetadata
```

Example:

``` json
{
  "limit": 100,
  "offset": 0
}
```

Response metadata:

``` json
{
  "limit": 100,
  "offset": 0,
  "total": 523,
  "has_more": true
}
```

Apply this to:

-   imports
-   exports
-   strings
-   functions
-   disassembly
-   YARA matches
-   other potentially large results

------------------------------------------------------------------------

## 9. Define Evidence Contract

Create `evidence.py`.

The Evidence model should contain at least:

``` text
evidence_id
observation
artifact_id
capability
location
confidence
timestamp
provenance
```

The MCP result must provide enough metadata for the Static Agent to
construct an Evidence object.

Evidence should remain an Agent/MIRA state concept, not an MCP
capability implementation concern.

------------------------------------------------------------------------

## 9. Update the Capability Registry

Update:

``` text
mira/mcp/capability_registry.py
```

Each capability entry should contain:

``` text
name
description
input_model
output_model
supported_artifact_types
category
```

Example:

``` text
analyze_pe
    ↓
AnalyzePEInput
    ↓
AnalyzePEOutput
```

The registry becomes the authoritative mapping between capabilities and
their contracts.

------------------------------------------------------------------------

## 10. Connect Contracts to FastMCP

Update:

``` text
mira/mcp/servers/static_server.py
```

Use the Pydantic models directly when exposing MCP tools.

The same models should drive:

``` text
Runtime validation
MCP input schema
MCP output schema
Agent-side typing
Tests
```

Avoid maintaining separate hand-written schemas for the same capability.

**One source of truth.**

------------------------------------------------------------------------

## 11. Update the MCP Client

Update:

``` text
mira/mcp/client.py
```

The flow should become:

``` text
Agent
  ↓
CapabilityRequest
  ↓
MCP Client
  ↓
MCP Server
  ↓
CapabilityResult[T]
  ↓
Typed capability output
  ↓
Agent
```

The Static Agent must not import analysis implementations directly.

For example, the Agent should not directly depend on:

``` text
pefile
capstone
yara
capa
```

Those dependencies belong behind the MCP capability boundary.

------------------------------------------------------------------------

## 13. Add Contract Tests

Create:

``` text
tests/
└── contracts/
    ├── test_requests.py
    ├── test_results.py
    ├── test_errors.py
    └── test_capability_schemas.py
```

Test:

-   valid requests
-   invalid requests
-   missing artifact IDs
-   invalid pagination
-   invalid offsets/ranges
-   malformed results
-   error codes
-   serialization/deserialization
-   schema generation
-   MCP schema compatibility

------------------------------------------------------------------------

## 14. Add MCP Integration Tests

Verify that:

``` text
Contract
    ↓
MCP Client
    ↓
MCP Server
    ↓
Capability
    ↓
Typed Result
```

works end-to-end.

The integration test should confirm that the schemas exposed by MCP
match the canonical contract models.

------------------------------------------------------------------------

## 15. Version the Contract

Start with:

``` text
contract_version = "1.0"
```

The version should be included in request/result envelopes.

Future breaking changes should produce a new major version instead of
silently changing existing semantics.

Example:

``` text
1.0
1.1   compatible extension
2.0   breaking change
```

------------------------------------------------------------------------

## 16. Final Architecture

``` text
                    Coordinator
                         │
                         ▼
                   Static Agent
                         │
                         │ typed contract
                         ▼
                    MCP Client
                         │
                         │ MCP protocol
                         ▼
                  Static MCP Server
                         │
                         ▼
                 Capability Registry
                         │
                         ▼
                  Static Capability
                         │
                         ▼
                 Analysis Engine
```

The boundary should be:

``` text
Agent
  = reasoning + tool selection

Contracts
  = stable typed interface

MCP
  = transport + capability exposure

Capabilities
  = deterministic analysis

Analysis engines
  = pefile / Capstone / YARA / CAPA / etc.
```

## Implementation Order

Implement in this order:

1.  `contracts/common.py`
2.  `contracts/errors.py`
3.  `contracts/requests.py`
4.  `contracts/results.py`
5.  `contracts/evidence.py`
6.  Capability-specific input/output models
7.  Pagination models
8.  Capability registry integration
9.  FastMCP integration
10. MCP client integration
11. Contract tests
12. MCP integration tests

## Key Principle

**Pydantic contract models should be the single source of truth for the
Agent ↔ MCP interface.**

Do not create parallel schemas for the Agent, MCP server, and tests
unless there is a specific protocol transformation that requires one.
