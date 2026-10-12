"""Token usage should ride along with every ModelResponse shape the adapter returns."""

import json
import os
import unittest
from types import SimpleNamespace
from unittest import mock

import pytest

from mira.reasoning.model.adapter import MODELS, ModelAdapter

ENDPOINT = {
    "MODEL_API_KEY": "key",
    "MODEL_BASE_URL": "https://models.example.test/openai/v1",
    "MODEL_NAME": "some-model",
}


def test_the_azure_endpoint_and_model_come_from_the_environment():
    with mock.patch.dict(os.environ, ENDPOINT, clear=True):
        adapter = ModelAdapter(model="azure")

    assert str(adapter.client.base_url).rstrip("/") == ENDPOINT["MODEL_BASE_URL"]
    assert adapter.model_name == "some-model"
    assert adapter.endpoint_host == "models.example.test"


@pytest.mark.parametrize("missing", ["MODEL_BASE_URL", "MODEL_NAME"])
def test_a_missing_endpoint_setting_fails_by_name(missing):
    settings = {name: value for name, value in ENDPOINT.items() if name != missing}
    with mock.patch.dict(os.environ, settings, clear=True), pytest.raises(ValueError, match=missing):
        ModelAdapter(model="azure")


def test_the_default_model_is_nemotron_on_nvidia_with_its_own_key():
    with mock.patch.dict(os.environ, {"NVIDIA_API_KEY": "nv"}, clear=True):
        adapter = ModelAdapter()

    assert adapter.model_name == MODELS["nemotron"].name and adapter.model_name.startswith("nvidia/")
    assert adapter.endpoint_host == "integrate.api.nvidia.com"
    assert adapter.request["extra_body"]["chat_template_kwargs"] == {"enable_thinking": True}


def test_a_model_without_its_key_or_an_unknown_model_fails_by_name():
    with mock.patch.dict(os.environ, {}, clear=True), pytest.raises(ValueError, match="NVIDIA_API_KEY"):
        ModelAdapter()
    with pytest.raises(ValueError, match="unknown model"):
        ModelAdapter(model="nope")


def test_the_picker_lists_every_model_and_which_have_keys():
    from mira.reasoning.model.adapter import available_models

    with mock.patch.dict(os.environ, {**ENDPOINT}, clear=True):
        models = {m["id"]: m for m in available_models()}

    assert models["nemotron"]["default"] and not models["nemotron"]["ready"]
    assert models["nemotron"]["open_source"] and not models["azure"]["open_source"]
    assert models["azure"]["ready"] and models["azure"]["label"] == "Azure deployment (some-model)"


async def test_a_scripted_model_needs_no_endpoint_settings(tmp_path):
    """build_loop constructs the real adapter only when no model is given."""
    from mira.reasoning.main import investigate
    from tests.support import ToolThenReportModel, build_minimal_pe

    sample = tmp_path / "sample.exe"
    sample.write_bytes(build_minimal_pe())
    unset = {name: value for name, value in os.environ.items() if not name.startswith("MODEL_")}
    with mock.patch.dict(os.environ, unset, clear=True):
        output = await investigate(sample, "objective", trace_dir=tmp_path, model=ToolThenReportModel())

    assert output.completion_reason == "reported"


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
