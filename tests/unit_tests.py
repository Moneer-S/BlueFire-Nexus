# tests/unit_tests.py
import unittest
from src.core.anti_sandbox import EnvironmentValidator
from src.core.polymorphic_engine import PolymorphicMutator

class CoreFunctionalityTests(unittest.TestCase):
    def test_mutation_consistency(self):
        mutator = PolymorphicMutator(seed=42)
        original = b"ABCDEF"
        mutated = mutator.morph_payload(original)
        self.assertNotEqual(original, mutated)
        self.assertEqual(len(mutated), len(original) + 4)  # Expected padding

    def test_sandbox_detection(self):
        env = EnvironmentValidator()
        self.assertFalse(env.detect_sandbox(),
            "Should return False in development environment")

if __name__ == "__main__":
    unittest.main()