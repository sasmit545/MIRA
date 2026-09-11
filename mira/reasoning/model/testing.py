"""Mock model for testing."""

from typing import List, Optional
from ..contracts.tool import ToolCall
from ..contracts.model import ModelResponse


class MockModel:
    """A mock model that plays a sequence of canned responses and is seedable."""

    def __init__(self, responses: List[ModelResponse], seed: Optional[int] = None):
        self.responses = responses
        self.seed = seed
        self.call_count = 0
        # If seed is provided, we could use it to seed a random number generator
        # for varying responses, but for now we just play the sequence.

    def generate(self, context: str, tools: List[ToolCall]) -> ModelResponse:
        """Return the next response in the sequence."""
        if self.call_count < len(self.responses):
            response = self.responses[self.call_count]
            self.call_count += 1
            return response
        else:
            # If we run out of responses, return an empty response
            return ModelResponse()
