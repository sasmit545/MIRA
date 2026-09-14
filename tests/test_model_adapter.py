"""Token usage should ride along with every ModelResponse shape the adapter returns."""

import json
import unittest
from types import SimpleNamespace

from mira.reasoning.model.adapter import ModelAdapter


def _fake_response(*, tool_calls=None, content=None):
    usage = SimpleNamespace(prompt_tokens=10, completion_tokens=5, total_tokens=15)
    message = SimpleNamespace(tool_calls=tool_calls, content=content)
    return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=usage)


def _adapter_with_response(response):
    adapter = ModelAdapter.__new__(ModelAdapter)
    adapter.model_name = "test-model"
    adapter.client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=lambda **_: response))
    )
    return adapter


class TokenUsageTests(unittest.TestCase):
    def test_usage_attached_to_a_tool_call_response(self):
        call = SimpleNamespace(
            id="1", function=SimpleNamespace(name="scan_yara", arguments="{}")
        )
        adapter = _adapter_with_response(_fake_response(tool_calls=[call]))

        result = adapter.generate(context="ctx", tools=[])

        self.assertEqual(result.usage, {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15})

    def test_usage_attached_to_a_submit_report_response(self):
        call = SimpleNamespace(
            id="1",
            function=SimpleNamespace(
                name="submit_report",
                arguments=json.dumps({"summary": "s", "verdict": "benign"}),
            ),
        )
        adapter = _adapter_with_response(_fake_response(tool_calls=[call]))

        result = adapter.generate(context="ctx", tools=[])

        self.assertIsNotNone(result.report)
        self.assertEqual(result.usage["total_tokens"], 15)

    def test_usage_attached_to_a_plain_text_response(self):
        adapter = _adapter_with_response(_fake_response(content="not a tool call"))

        result = adapter.generate(context="ctx", tools=[])

        self.assertEqual(result.usage["total_tokens"], 15)


if __name__ == "__main__":
    unittest.main()
