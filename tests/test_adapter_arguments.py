"""Tool arguments the model sends as malformed JSON are repaired or reported, never silently dropped."""

import json
from types import SimpleNamespace as Namespace

from mira.reasoning.model.adapter import ModelAdapter, _parsed_arguments

# What a live model wrote: a Windows registry path with single backslashes.
WINDOWS_PATH_REPORT = '{"summary": "Reads Software\\Microsoft\\Notepad settings", "verdict": "benign", "findings": []}'


def adapter_answering(name, raw_arguments):
    """A ModelAdapter whose provider returns one tool call with these raw arguments."""
    call = Namespace(id="c1", function=Namespace(name=name, arguments=raw_arguments))
    message = Namespace(tool_calls=[call], content=None)
    response = Namespace(choices=[Namespace(message=message)], usage=None)
    adapter = ModelAdapter.__new__(ModelAdapter)
    adapter.model_name = "test"
    adapter.client = Namespace(chat=Namespace(completions=Namespace(create=lambda **_: response)))
    return adapter


def test_a_lone_backslash_from_a_windows_path_is_read_literally():
    parsed, unreadable = _parsed_arguments(WINDOWS_PATH_REPORT)

    assert not unreadable
    assert parsed["summary"] == "Reads Software\\Microsoft\\Notepad settings"


def test_valid_escapes_are_left_alone():
    parsed, _ = _parsed_arguments('{"a": "line\\nnext \\"quoted\\" C:\\\\Windows \\u0041"}')

    assert parsed["a"] == 'line\nnext "quoted" C:\\Windows A'


def test_a_windows_path_report_keeps_its_summary_and_verdict():
    response = adapter_answering("submit_report", WINDOWS_PATH_REPORT).generate("context", [])

    report = json.loads(response.report)
    assert report["verdict"] == "benign" and "Notepad" in report["summary"]


def test_an_unreadable_report_reaches_the_validator_raw_instead_of_as_an_empty_object():
    raw = '{"summary": "cut off'

    response = adapter_answering("submit_report", raw).generate("context", [])

    assert response.report == raw


def test_unreadable_notes_count_as_notes_not_sent():
    response = adapter_answering("record_memory", '{"understanding": "cut off').generate("context", [])

    assert response.memory_update is None
