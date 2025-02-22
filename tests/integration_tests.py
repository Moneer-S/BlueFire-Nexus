import unittest
from src.core import anti_sandbox, polymorphic_engine
from src.modules import ai_analysis

class TestApocalypse(unittest.TestCase):
    def test_polymorphic_evasion(self):
        mutator = polymorphic_engine.PolymorphicMutator()
        payload = b"\x90\x90\xCC"  # NOP sled + breakpoint
        mutated = mutator.morph_payload(payload)
        self.assertNotIn(b"\xCC", mutated)  # Breakpoint removed
        
    def test_ai_mimicry(self):
        mimic = ai_analysis.TrafficMimic()
        traffic = mimic.generate_traffic(60)
        self.assertEqual(len(traffic['intervals']), 3)
        self.assertIn('tls_fprints', traffic)
        
    def test_sandbox_detection(self):
        env = anti_sandbox.EnvironmentValidator()
        self.assertFalse(env.detect_sandbox())  # Should pass in dev