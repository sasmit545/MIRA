"""Model provider adapter for any OpenAI-compatible endpoint, spoken over the OpenAI SDK.

The only file that touches the provider SDK.
"""

import dataclasses
import json
import os
import re
from typing import Any, List, Optional
from urllib.parse import urlparse

from openai import OpenAI

from mira.core.hypothesis import PROVISIONAL

from ..contracts.finding import Confidence, Severity
from ..contracts.model import ModelResponse
from ..contracts.output import VERDICTS
from ..contracts.tool import ToolCall

MAX_TOKENS = 16384

REPORT_TOOL = "submit_report"
MEMORY_TOOL = "record_memory"
RECALL_TOOL = "recall_observation"  # rides tool_calls; the loop intercepts it by name


@dataclasses.dataclass(frozen=True)
class ModelProfile:
    """One selectable model. A profile with no fixed URL or name reads it from
    the environment, so a missing setting never reaches a stale deployment."""

    label: str
    key_env: str
    base_url: Optional[str] = None  # None: MODEL_BASE_URL
    name: Optional[str] = None  # None: MODEL_NAME
    request: dict = dataclasses.field(default_factory=dict)  # extra create() arguments
    open_source: bool = False  # weights published, so it can also be self-hosted


MODELS = {
    "nemotron": ModelProfile(
        label="NVIDIA Nemotron 3 super 120B (a12b)",
        key_env="NVIDIA_API_KEY",
        base_url="https://integrate.api.nvidia.com/v1",
        name="nvidia/nemotron-3-super-120b-a12b",
        open_source=True,
        # As NVIDIA's own example calls it.
        request={
            "temperature": 1,
            "top_p": 0.95,
            "extra_body": {"chat_template_kwargs": {"enable_thinking": True}, "reasoning_budget": 16384},
        },
    ),
    "azure": ModelProfile(label="Azure deployment (MODEL_NAME)", key_env="MODEL_API_KEY"),
}
# The cheaper model; the Azure deployment stays one choice away.
DEFAULT_MODEL = "nemotron"


def available_models() -> list[dict]:
    """Every profile, and whether its key is set, for a model picker."""
    return [
        {
            "id": model_id,
            "label": profile.label.replace("MODEL_NAME", os.getenv("MODEL_NAME") or "MODEL_NAME"),
            "ready": bool(os.getenv(profile.key_env)),
            "open_source": profile.open_source,
            "default": model_id == DEFAULT_MODEL,
        }
        for model_id, profile in MODELS.items()
    ]


class ModelAdapter:
    """Adapter for one model in MODELS, the default unless named."""

    def __init__(self, api_key: Optional[str] = None, model: str = DEFAULT_MODEL):
        profile = MODELS.get(model)
        if profile is None:
            raise ValueError(f"unknown model {model!r}; choose one of: {', '.join(MODELS)}")
        if api_key is None:
            api_key = os.getenv(profile.key_env)
        if not api_key:
            raise ValueError(f"{profile.key_env} environment variable is not set")
        base_url = profile.base_url or _required("MODEL_BASE_URL")
        self.model_name = profile.name or _required("MODEL_NAME")
        self.endpoint_host = urlparse(base_url).hostname or base_url
        self.request = profile.request
        self.client = OpenAI(base_url=base_url, api_key=api_key)

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
            **getattr(self, "request", {}),
            **extra,
        )

        usage = _usage(response.usage)
        message = response.choices[0].message
        calls: list[ToolCall] = []
        report: Optional[str] = None
        memory_update: Optional[dict] = None
        for call in message.tool_calls or []:
            arguments, unreadable = _parsed_arguments(call.function.arguments)
            if call.function.name == REPORT_TOOL:
                # The report rides the existing report path; findings default to
                # empty so a terse submission still satisfies the output contract.
                # Unreadable, it goes on raw: the validator then names the JSON
                # error to the model, and the trace keeps what was sent, where
                # an empty {} read as "missing summary, verdict".
                report = (call.function.arguments or "") if unreadable else json.dumps({"findings": [], **arguments})
            elif call.function.name == MEMORY_TOOL:
                # Unreadable notes are notes not sent, so the loop asks again.
                memory_update = None if unreadable else arguments
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
                    "verdict": {
                        "type": "string",
                        "enum": list(VERDICTS),
                        "description": "benign, malicious, or inconclusive when the evidence does not settle it.",
                    },
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
            "handle, returns the whole result if it is small. Over a large array: filter "
            "items by exact key values (where), count items per value of one key "
            "(group_by), search item text (contains), page (offset, limit), and show only "
            "some keys (fields); for example where {\"dll\": \"advapi32.dll\"}, or group_by "
            "\"dll\". Each item is shown with its index. Unknown arguments and keys fail "
            "and list the ones that exist."
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
                        "Optional when the result holds exactly one array and you give another selector."
                    ),
                },
                "offset": {"type": "integer", "minimum": 0, "description": "Array index to start from. Default 0."},
                "limit": {
                    "type": "integer", "minimum": 1, "maximum": 200,
                    "description": "Most items (or group_by values) to return. Default 50 items.",
                },
                "where": {
                    "type": "object",
                    "description": (
                        "Keep items whose keys equal these values, such as {\"dll\": \"kernel32.dll\"}; "
                        "a list means any of them, and null matches a missing value. Strings ignore case; "
                        "several keys must all match."
                    ),
                },
                "group_by": {
                    "type": "string",
                    "description": "Count the matched items per value of this key, most common first, instead of listing them.",
                },
                "contains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Return only array items whose text contains any of these, ignoring case. Plain text, not regex.",
                },
                "fields": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Show only these keys of each array item, such as [\"rule_id\"] or [\"dll\", \"name\"], "
                        "so a whole large array fits in one recall. contains still searches whole items."
                    ),
                },
            },
            "required": ["handle"],
        },
    }


def _required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise ValueError(f"{name} environment variable is not set")
    return value


def _usage(usage: Any) -> Optional[dict]:
    """The provider's per-call token accounting, when it sends one."""
    if usage is None:
        return None
    return {
        "prompt_tokens": usage.prompt_tokens,
        "completion_tokens": usage.completion_tokens,
        "total_tokens": usage.total_tokens,
    }


# A valid JSON escape, or a lone backslash that starts none.
_ESCAPE = re.compile(r'\\(["\\/bfnrt]|u[0-9a-fA-F]{4})|\\')


def _arguments(raw: str | None) -> dict:
    """Tool arguments arrive as a JSON string; a model can still send junk."""
    parsed, _ = _parsed_arguments(raw)
    return parsed


def _parsed_arguments(raw: str | None) -> tuple[dict, str]:
    """The arguments, or {} and why they could not be read.

    A model quoting a Windows path writes `Software\\Microsoft` with a single
    backslash, an invalid JSON escape that failed a live run's whole report.
    Such a backslash is read as a literal one before giving up.
    """
    text = raw or "{}"
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError) as error:
        repaired = _ESCAPE.sub(lambda match: match.group(0) if match.group(1) else "\\\\", text)
        try:
            parsed = json.loads(repaired)
        except (json.JSONDecodeError, ValueError):
            return {}, f"its arguments were not valid JSON ({error})"
    if not isinstance(parsed, dict):
        return {}, "its arguments were not a JSON object"
    return parsed, ""


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
