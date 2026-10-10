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


def _call(name, arguments="{}", id="1"):
    return SimpleNamespace(id=id, function=SimpleNamespace(name=name, arguments=arguments))


REPORT_CALL = ("submit_report", json.dumps({"summary": "s", "verdict": "benign"}))
MEMORY_CALL = ("record_memory", json.dumps({"understanding": "u"}))


class SiblingCallTests(unittest.TestCase):
    def generate(self, *calls):
        built = [_call(name, args, id=str(i)) for i, (name, args) in enumerate(calls)]
        adapter = _adapter_with_response(_fake_response(tool_calls=built))
        return adapter.generate(context="ctx", tools=[])

    def test_memory_alone_yields_an_update_and_no_capability_calls(self):
        result = self.generate(MEMORY_CALL)

        self.assertEqual(result.memory_update, {"understanding": "u"})
        self.assertIsNone(result.tool_calls)

    def test_capability_plus_memory_yields_both(self):
        result = self.generate(MEMORY_CALL, ("file_info", "{}"))

        self.assertEqual(result.memory_update, {"understanding": "u"})
        self.assertEqual([call.name for call in result.tool_calls], ["file_info"])

    def test_report_plus_memory_yields_both(self):
        result = self.generate(MEMORY_CALL, REPORT_CALL)

        self.assertIsNotNone(result.report)
        self.assertEqual(result.memory_update, {"understanding": "u"})

    def test_report_plus_capability_keeps_the_capability_call(self):
        result = self.generate(("file_info", "{}"), REPORT_CALL)

        self.assertIsNotNone(result.report)
        self.assertEqual([call.name for call in result.tool_calls], ["file_info"])


if __name__ == "__main__":
    unittest.main()


def test_force_declares_and_requires_exactly_one_tool():
    """The loop's forced turns: nothing else may be on offer, or a model uses it."""
    from mira.reasoning.contracts.tool import ToolSpec

    sent = []
    adapter = ModelAdapter.__new__(ModelAdapter)
    adapter.model_name = "test-model"
    adapter.client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(
        create=lambda **kwargs: sent.append(kwargs) or _fake_response(content="")
    )))

    spec = ToolSpec(name="file_info", description="d", parameters={})
    adapter.generate(context="ctx", tools=[], force="submit_report")
    adapter.generate(context="ctx", tools=[spec], force="record_memory")
    adapter.generate(context="ctx", tools=[spec])

    report, notes, normal = sent
    assert [d["function"]["name"] for d in report["tools"]] == ["submit_report"]
    assert report["tool_choice"] == {"type": "function", "function": {"name": "submit_report"}}
    assert [d["function"]["name"] for d in notes["tools"]] == ["record_memory"]
    assert notes["tool_choice"] == {"type": "function", "function": {"name": "record_memory"}}
    assert "tool_choice" not in normal
    assert {"file_info", "record_memory", "recall_observation", "submit_report"} <= {
        d["function"]["name"] for d in normal["tools"]
    }
