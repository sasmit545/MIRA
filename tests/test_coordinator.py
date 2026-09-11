import unittest

from mira.core.coordinator import StaticCoordinator


class StaticCoordinatorTests(unittest.TestCase):
    def test_select_next_objective_returns_initial_objective(self):
        objective = StaticCoordinator().select_next_objective([])

        self.assertEqual(objective.name, "Characterize sample")
        self.assertEqual(
            objective.description,
            "Identify the artifact and characterize its executable structure.",
        )
        self.assertEqual(
            objective.reason,
            "No evidence has yet established the sample's structure.",
        )

    def test_the_objective_type_is_shared_not_owned_by_a_specialist(self):
        """The Coordinator assigns work without depending on a concrete agent."""
        objective = StaticCoordinator().select_next_objective([])

        self.assertEqual(type(objective).__module__, "mira.core.objective")


if __name__ == "__main__":
    unittest.main()
