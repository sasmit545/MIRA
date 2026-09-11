"""Tests for State."""

from agent.contracts.objective import Objective
from agent.contracts.state import State
from agent.contracts.finding import Finding
from agent.contracts.tool import ToolCall, ToolResult


def test_state_initialization():
    obj = Objective(description="Test objective")
    state = State(objective=obj)
    assert state.objective == obj
    assert state.turn_count == 0
    assert state.tool_call_count == 0
    assert state.findings == []
    assert state.evidence == []
    assert state.observations == []
    assert state.scratch == {}
    assert state.run_id == "run_" + str(hash(obj.description))


def test_record_tool_call_and_result():
    obj = Objective(description="Test objective")
    state = State(objective=obj)
    tool_call = ToolCall(tool_call_id="1", name="test_tool", arguments={})
    state.record_tool_call(tool_call)
    assert state.tool_call_count == 1
    assert len(state.observations) == 1
    assert state.observations[0]['call'] == tool_call
    assert state.observations[0]['result'] is None

    tool_result = ToolResult(tool_call_id="1", success=True, output="test")
    state.record_tool_result(tool_result)
    assert state.observations[0]['result'] == tool_result


def test_add_finding_and_evidence():
    obj = Objective(description="Test objective")
    state = State(objective=obj)
    finding = Finding(title="Test", description="Test", severity="info", confidence="low", evidence_refs=[], source_location="test")
    state.add_finding(finding)
    assert state.findings == [finding]

    evidence = {"test": "evidence"}
    state.add_evidence(evidence)
    assert state.evidence == [evidence]


def test_snapshot():
    obj = Objective(description="Test objective")
    state = State(objective=obj)
    snap = state.snapshot()
    assert snap['objective'] == obj.description
    assert snap['turn_count'] == 0
    assert snap['tool_call_count'] == 0
    assert snap['findings_count'] == 0
    assert snap['evidence_count'] == 0
    assert snap['observations_count'] == 0
    assert snap['scratch'] == {}
    assert snap['run_id'] == state.run_id
