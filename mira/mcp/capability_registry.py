"""The shape of a capability registry entry.

Generic on purpose: each specialist server owns its own registry of these.
The static one is mira/mcp/servers/static/capabilities.py.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel


@dataclass(frozen=True)
class CapabilityDefinition:
    name: str
    description: str
    category: str
    supported_artifact_types: tuple[str, ...]
    input_model: type[BaseModel]
    output_model: type[BaseModel]

    @property
    def input_schema(self) -> dict:
        return self.input_model.model_json_schema()

    @property
    def output_schema(self) -> dict:
        return self.output_model.model_json_schema()
