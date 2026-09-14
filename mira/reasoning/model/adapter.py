"""Model provider adapter for Azure AI Foundry, spoken over the OpenAI SDK.

The only file that touches the provider SDK.
"""

import json
import os
from typing import Any, List, Optional

from openai import OpenAI

from ..contracts.finding import Confidence, Severity
from ..contracts.model import ModelResponse
from ..contracts.tool import ToolCall

BASE_URL = "https://testingrpmtpm.services.ai.azure.com/openai/v1"
DEFAULT_MODEL = "grok-4.6"
MAX_TOKENS = 16384

REPORT_TOOL = "submit_report"


class ModelAdapter:
    """Adapter for the Azure-hosted Grok deployment."""

    def __init__(self, api_key: Optional[str] = None):
        if api_key is None:
            api_key = os.getenv("MODEL_API_KEY")
        if not api_key:
            raise ValueError("MODEL_API_KEY environment variable is not set")
        self.model_name = os.getenv("MODEL_NAME", DEFAULT_MODEL)
        self.client = OpenAI(base_url=BASE_URL, api_key=api_key)

    def generate(self, context: str, tools: List[Any]) -> ModelResponse:
        """Ask the model for its next move as a native tool call."""
        # API failures deliberately propagate. Returning an empty response here
        # is indistinguishable from a model with nothing to say, which hides
        # 404s, auth failures, and quota errors behind a "degraded" exit.
        # The SDK already retries 429s and connection errors on its own.
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=[{"role": "user", "content": context}],
            tools=declarations(tools),
            max_tokens=MAX_TOKENS,
        )

        usage = _usage(response.usage)
        message = response.choices[0].message
        calls: list[ToolCall] = []
        for call in message.tool_calls or []:
            arguments = _arguments(call.function.arguments)
            if call.function.name == REPORT_TOOL:
                # The report rides the existing report path; findings default to
                # empty so a terse submission still satisfies the output contract.
                return ModelResponse(report=json.dumps({"findings": [], **arguments}), usage=usage)
            calls.append(
                ToolCall(
                    tool_call_id=call.id,
                    name=call.function.name,
                    arguments=arguments,
                )
            )

        if calls:
            return ModelResponse(tool_calls=calls, usage=usage)

        # No tool call: fall back to a JSON report in plain text. Text the model
        # spoke but we cannot use IS a real empty response — it can recover next
        # turn — unlike an API failure, which raises above.
        result = _from_text(message.content or "")
        result.usage = usage
        return result


# Supplied by the runtime, never by the model. artifact_id in particular is
# bound by build_executor so the model cannot retarget another sample.
BOUND_FIELDS = ("artifact_id", "contract_version")


def tool_parameters(schema: dict) -> dict:
    """Reshape a capability's pydantic schema into a tool declaration.

    Without this the model is told every capability takes no arguments, so
    required ones like disassemble_function's function_address can never be
    supplied and the call fails validation every time.
    """
    properties = {
        name: _declarable(field)
        for name, field in schema.get("properties", {}).items()
        if name not in BOUND_FIELDS
    }
    required = [
        name for name in schema.get("required", []) if name not in BOUND_FIELDS
    ]
    declared = {"type": "object", "properties": properties}
    if required:
        declared["required"] = required
    return declared


def _declarable(field: dict) -> dict:
    """Flatten Optional[X] to X.

    A bare type reads more clearly to the model than an anyOf with a null
    branch, and nothing downstream distinguishes "absent" from "null".
    """
    for option in field.get("anyOf", []):
        if option.get("type") != "null":
            return {**option, "description": field.get("description", "")}
    return field


def declarations(tools: List[Any]) -> list[dict]:
    """Declare capabilities to the provider, plus the report pseudo-tool."""
    declared = [
        {
            "name": spec.name,
            "description": spec.description,
            "parameters": tool_parameters(spec.parameters),
        }
        for spec in tools
    ]
    declared.append(
        {
            "name": REPORT_TOOL,
            "description": "Submit the final report and end the investigation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "summary": {"type": "string", "description": "What was found."},
                    "verdict": {"type": "string", "description": "benign, suspicious, or malicious."},
                    "findings": {
                        "type": "array",
                        "description": "Individual findings supporting the verdict.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "title": {"type": "string", "description": "One line naming the finding."},
                                "description": {"type": "string", "description": "What was found and why it matters."},
                                "severity": {
                                    "type": "string",
                                    "enum": [member.value for member in Severity],
                                    "description": "How serious this finding is.",
                                },
                                "confidence": {
                                    "type": "string",
                                    "enum": [member.value for member in Confidence],
                                    "description": "How sure you are of this finding.",
                                },
                                "evidence_refs": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": (
                                        "Identifiers of the gathered evidence supporting this "
                                        "finding, as listed in the context (E1, E2, ...)."
                                    ),
                                },
                                "source_location": {
                                    "type": "string",
                                    "description": "Where in the artifact this was found, if known.",
                                },
                            },
                            "required": [
                                "title",
                                "description",
                                "severity",
                                "confidence",
                                "evidence_refs",
                            ],
                        },
                    },
                    "recommended_actions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "What the investigation should do next.",
                    },
                },
                "required": ["summary", "verdict", "findings"],
            },
        }
    )
    return [{"type": "function", "function": function} for function in declared]


def _usage(usage: Any) -> Optional[dict]:
    """The provider's per-call token accounting, when it sends one."""
    if usage is None:
        return None
    return {
        "prompt_tokens": usage.prompt_tokens,
        "completion_tokens": usage.completion_tokens,
        "total_tokens": usage.total_tokens,
    }


def _arguments(raw: str | None) -> dict:
    """Tool arguments arrive as a JSON string; a model can still send junk."""
    try:
        parsed = json.loads(raw or "{}")
    except (json.JSONDecodeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _from_text(text: str) -> ModelResponse:
    try:
        parsed = json.loads(text.strip())
    except (json.JSONDecodeError, ValueError):
        return ModelResponse()
    if not isinstance(parsed, dict):
        return ModelResponse()
    if isinstance(parsed.get("report"), str):
        return ModelResponse(report=parsed["report"])
    if {"summary", "verdict"} <= parsed.keys():
        return ModelResponse(report=json.dumps({"findings": [], **parsed}))
    return ModelResponse()
