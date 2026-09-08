import unittest

from mira.agents.static_agent import StaticAgent
from mira.coordinator import StaticCoordinator


class ScriptedClient:
    def __init__(self):
        self.calls = []

    async def invoke(self, capability, **payload):
        self.calls.append(capability)
        responses = {
            "file_info": {"status": "ok", "data": {"entropy": 7.8}, "metadata": {}},
            "analyze_pe": {"status": "ok", "data": {"sections": [{"name": ".text", "entropy": 7.9}]}, "metadata": {}},
            "detect_packer": {"status": "ok", "data": {"packed": True, "indicators": ["high entropy"]}, "metadata": {}},
            "extract_strings": {"status": "ok", "data": {"strings": []}, "metadata": {}},
        }
        return responses[capability]


class StaticInvestigationLoopTests(unittest.IsolatedAsyncioTestCase):
    async def test_evidence_changes_the_second_static_objective(self):
        client = ScriptedClient()
        coordinator = StaticCoordinator()
        agent = StaticAgent(client)

        first_objective = coordinator.select_next_objective([])
        first_finding = await agent.investigate(first_objective, "sample-1")
        second_objective = coordinator.select_next_objective(first_finding.evidence)
        second_finding = await agent.investigate(second_objective, "sample-1")

        self.assertEqual(first_objective.name, "Characterize sample")
        self.assertEqual(second_objective.name, "Assess packing indicators")
        self.assertEqual(client.calls, ["file_info", "analyze_pe", "detect_packer", "extract_strings"])
        self.assertTrue(any(item["kind"] == "packing_indicator" for item in second_finding.evidence))


if __name__ == "__main__":
    unittest.main()
