"""Model provider adapter for Azure AI Foundry, spoken over the OpenAI SDK.

The only file that touches the provider SDK.
"""

import json
import os
from typing import Any, List, Optional

from openai import OpenAI

from mira.core.hypothesis import PROVISIONAL

from ..contracts.finding import Confidence, Severity
from ..contracts.model import ModelResponse
from ..contracts.tool import ToolCall

BASE_URL = "https://testingrpmtpm.services.ai.azure.com/openai/v1"
DEFAULT_MODEL = "grok-4.6"
MAX_TOKENS = 16384

REPORT_TOOL = "submit_report"
MEMORY_TOOL = "record_memory"
RECALL_TOOL = "recall_observation"  # rides tool_calls; the loop intercepts it by name


class ModelAdapter:
    """Adapter for the Azure-hosted Grok deployment."""

    def __init__(self, api_key: Optional[str] = None):
        if api_key is None:
            api_key = os.getenv("MODEL_API_KEY")
        if not api_key:
            raise ValueError("MODEL_API_KEY environment variable is not set")
        self.model_name = os.getenv("MODEL_NAME", DEFAULT_MODEL)
        self.client = OpenAI(base_url=BASE_URL, api_key=api_key)

    def generate(self, context: str, tools: List[Any], force: Optional[str] = None) -> ModelResponse:
        """Ask the model for its next move as a native tool call.

        `force` names one harness tool (submit_report or record_memory): only
        that tool is declared, and the model must call it.
        """
        # API failures deliberately propagate. Returning an empty response here
        # is indistinguishable from a model with nothing to say, which hides
        # 404s, auth failures, and quota errors behind a "degraded" exit.
        # The SDK already retries 429s and connection errors on its own.
        declared = declarations(tools)
        extra = {}
        if force is not None:
            # Left a free choice, a live model spent its final report turn on
            # recall_observation and skipped record_memory on most turns.
            declared = [d for d in declared if d["function"]["name"] == force]
            extra["tool_choice"] = {"type": "function", "function": {"name": force}}
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=[{"role": "user", "content": context}],
            tools=declared,
            max_tokens=MAX_TOKENS,
            **extra,
        )

        usage = _usage(response.usage)
        message = response.choices[0].message
        calls: list[ToolCall] = []
        report: Optional[str] = None
        memory_update: Optional[dict] = None
        for call in message.tool_calls or []:
            arguments = _arguments(call.function.arguments)
            if call.function.name == REPORT_TOOL:
                # The report rides the existing report path; findings default to
                # empty so a terse submission still satisfies the output contract.
                report = json.dumps({"findings": [], **arguments})
            elif call.function.name == MEMORY_TOOL:
                memory_update = arguments
            else:
                calls.append(
                    ToolCall(
                        tool_call_id=call.id,
                        name=call.function.name,
                        arguments=arguments,
                    )
                )

        # One turn can carry any mix; a sibling call is never dropped.
        if calls or report is not None or memory_update is not None:
            return ModelResponse(
                tool_calls=calls or None,
                report=report,
                memory_update=memory_update,
                usage=usage,
            )

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
    declared.append(_memory_declaration())
    declared.append(_recall_declaration())
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


def _memory_declaration() -> dict:
    """The notebook the model keeps across turns. Declared independently of the
    objective's allowlist, like submit_report: it is the harness's, not a capability."""

    def entries(key: str, description: str) -> dict:
        return {
            "type": "array",
            "description": description,
            "items": {
                "type": "object",
                "properties": {"id": {"type": "string"}, key: {"type": "string"}},
                "required": ["id", key],
            },
        }

    return {
        "name": MEMORY_TOOL,
        "description": (
            "Record your working notes. Call this every turn, in the same response "
            "as your capability call, even when nothing changed (send empty lists). "
            "A turn that also recalls may defer its notes one turn. Entries you omit are left unchanged."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "understanding": {
                    "type": "string",
                    "description": "A short current interpretation of the sample, not a copy of tool output.",
                },
                "hypotheses": {
                    "type": "array",
                    "description": "Beliefs you hold. Reuse an id to revise one.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "statement": {"type": "string"},
                            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                            "status": {"type": "string", "enum": list(PROVISIONAL)},
                            "supporting_evidence": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Evidence ids (E1, E2, ...).",
                            },
                            "contradicting_evidence": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Evidence ids that weaken it.",
                            },
                            "unknowns": {"type": "string", "description": "What would confirm or reject it."},
                        },
                        "required": ["id", "statement", "confidence", "status"],
                    },
                },
                "open_questions": entries("question", "Questions still open."),
                "candidates": entries("investigation", "Possible next investigations - candidates, not a plan."),
                "close": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Ids of hypotheses, questions or candidates to remove because they are resolved or obsolete.",
                },
            },
            "required": ["understanding", "hypotheses", "open_questions", "candidates"],
        },
    }


def _recall_declaration() -> dict:
    """Retrieval of what a digest left out. Harness, not a capability: it reads
    results already gathered and never touches the sample."""
    return {
        "name": RECALL_TOOL,
        "description": (
            "Read part of an earlier capability result that its digest in the capability "
            "history left out. The answer appears in your next turn only, so record what "
            "matters in record_memory. Does not use the tool-call budget. With only a "
            "handle, returns the whole result if it is small. To read a large array, give "
            "a range (start, count) or search it (contains); for example search "
            "data.strings with contains [\"http\", \"://\"] for URL-like strings. Ranges "
            "and search apply to arrays only."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "handle": {
                    "type": "string",
                    "description": "The call's handle exactly as listed in the capability history (run#capability#n).",
                },
                "path": {
                    "type": "string",
                    "description": (
                        "Dotted path inside the result, such as data.strings or data.sections.2. "
                        "Optional when the result holds exactly one array and you give start, count or contains."
                    ),
                },
                "start": {"type": "integer", "minimum": 0, "description": "First array index to return. Default 0."},
                "count": {"type": "integer", "minimum": 1, "maximum": 200, "description": "Most items to return. Default 50."},
                "contains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Return only array items whose text contains any of these, ignoring case. Plain text, not regex.",
                },
            },
            "required": ["handle"],
        },
    }


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
