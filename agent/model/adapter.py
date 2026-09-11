"""Model provider adapter for Gemini.

The only file that touches the provider SDK.
"""

import json
import os
from typing import Any, List, Optional

# Try to import google.generativeai, but allow it to be missing for testing
try:
    import google.generativeai as genai
    GENAI_AVAILABLE = True
except ImportError:
    genai = None  # type: ignore
    GENAI_AVAILABLE = False

from ..contracts.model import ModelResponse
from ..contracts.tool import ToolCall

# Model names churn: `gemini-pro` and `gemini-2.5-flash` are both already
# refused for new keys, and list_models() still advertises them. Verified
# working 2026-09-11. Override with GEMINI_MODEL when this one is retired too.
DEFAULT_MODEL = "gemini-3.6-flash"

REPORT_TOOL = "submit_report"


class ModelAdapter:
    """Adapter for Gemini model provider."""

    def __init__(self, api_key: Optional[str] = None):
        if not GENAI_AVAILABLE:
            self.model = None
            self.model_name = DEFAULT_MODEL
            return
        if api_key is None:
            api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("GOOGLE_API_KEY environment variable is not set")
        genai.configure(api_key=api_key)
        self.model_name = os.getenv("GEMINI_MODEL", DEFAULT_MODEL)
        self.model = genai.GenerativeModel(self.model_name)

    def generate(self, context: str, tools: List[Any]) -> ModelResponse:
        """Ask the model for its next move as a native function call."""
        if not GENAI_AVAILABLE or self.model is None:
            return ModelResponse()

        # API failures deliberately propagate. Returning an empty response here
        # is indistinguishable from a model with nothing to say, which hides
        # 404s, auth failures, and quota errors behind a "degraded" exit.
        response = self.model.generate_content(context, tools=declarations(tools))

        parts = _parts(response)
        calls: list[ToolCall] = []
        for index, part in enumerate(parts):
            call = getattr(part, "function_call", None)
            if not (call and call.name):
                continue
            arguments = _plain(call.args) if call.args else {}
            if call.name == REPORT_TOOL:
                # The report rides the existing report path; findings default to
                # empty so a terse submission still satisfies the output contract.
                return ModelResponse(report=json.dumps({"findings": [], **arguments}))
            calls.append(
                ToolCall(
                    tool_call_id=f"{call.name}-{index}",
                    name=call.name,
                    arguments=arguments,
                )
            )

        if calls:
            return ModelResponse(tool_calls=calls)

        # No function call: fall back to a JSON report in plain text. Text the
        # model spoke but we cannot use IS a real empty response — it can
        # recover next turn — unlike an API failure, which raises above.
        return _from_text("".join(getattr(part, "text", "") or "" for part in parts))


def declarations(tools: List[Any]) -> list[dict]:
    """Declare capabilities to the provider, plus the report pseudo-tool.

    Capabilities take no parameters: the runtime binds the artifact, so the
    model only ever chooses which capability to run.
    """
    declared = [
        {
            "name": spec.name,
            "description": spec.description,
            "parameters": {"type": "object", "properties": {}},
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
                                "title": {"type": "string"},
                                "description": {"type": "string"},
                                "severity": {"type": "string"},
                                "confidence": {"type": "string"},
                            },
                        },
                    },
                },
                "required": ["summary", "verdict"],
            },
        }
    )
    return [{"function_declarations": declared}]


def _parts(response: Any) -> list:
    """Reach the response parts without touching `.text`, which raises on a
    function_call part."""
    candidates = getattr(response, "candidates", None) or []
    if not candidates:
        return []
    content = getattr(candidates[0], "content", None)
    return list(getattr(content, "parts", None) or [])


def _plain(value: Any) -> Any:
    """Convert provider proto containers into plain JSON-serializable values."""
    if isinstance(value, (str, bytes, int, float, bool)) or value is None:
        return value
    if hasattr(value, "items"):
        return {key: _plain(item) for key, item in value.items()}
    if hasattr(value, "__iter__"):
        return [_plain(item) for item in value]
    return value


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
