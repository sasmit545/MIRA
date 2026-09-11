"""Model provider adapter for Gemini."""

import os
import json
from typing import List, Any, Optional

# Try to import google.generativeai, but allow it to be missing for testing
try:
    import google.generativeai as genai
    GENAI_AVAILABLE = True
except ImportError:
    genai = None  # type: ignore
    GENAI_AVAILABLE = False

from ..contracts.model import ModelResponse
from ..contracts.tool import ToolCall


class ModelAdapter:
    """Adapter for Gemini model provider."""

    def __init__(self, api_key: Optional[str] = None):
        if not GENAI_AVAILABLE:
            # If the package is not available, we cannot initialize the model.
            # We'll allow instantiation but generate will return empty responses.
            self.model = None
            return
        if api_key is None:
            api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("GOOGLE_API_KEY environment variable is not set")
        genai.configure(api_key=api_key)
        # Use gemini-pro model; can be configured otherwise
        self.model = genai.GenerativeModel("gemini-pro")

    def generate(self, context: str, tools: List[Any]) -> ModelResponse:
        """Generate a response from the Gemini model given the context and available tools.
        Expects the model to output a JSON object with either:
        - {"tool_calls": [{"id": "...", "name": "...", "arguments": {...}}, ...]}
        - {"report": "..."}
        or an empty JSON object {} for no response.
        """
        if not GENAI_AVAILABLE or self.model is None:
            # If the package is not available or model not initialized, return empty response.
            return ModelResponse()
        try:
            response = self.model.generate_content(context)
            response_text = response.text.strip()

            # Try to parse as JSON
            try:
                parsed = json.loads(response_text)
            except json.JSONDecodeError:
                # If not JSON, treat as empty response
                return ModelResponse()

            # Check for tool_calls
            if "tool_calls" in parsed and isinstance(parsed["tool_calls"], list):
                tool_calls = []
                for tc in parsed["tool_calls"]:
                    # Expect each tool call to have: id, name, arguments
                    tool_call = ToolCall(
                        tool_call_id=tc.get("id", ""),
                        name=tc.get("name", ""),
                        arguments=tc.get("arguments", {}),
                    )
                    tool_calls.append(tool_call)
                return ModelResponse(tool_calls=tool_calls)

            # Check for report
            if "report" in parsed and isinstance(parsed["report"], str):
                return ModelResponse(report=parsed["report"])

            # If neither, treat as empty
            return ModelResponse()
        except Exception as e:
            # In case of any error, return empty response to avoid breaking the loop
            # In a real system, you might want to log this error.
            return ModelResponse()
