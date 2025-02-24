# tests/unit_tests.py
import unittest
from unittest.mock import patch
import base64
from src.core.anti_sandbox import EnvironmentValidator
from src.core.polymorphic_engine import PolymorphicMutator
from src.operators.c2_protocols.dns_tunneling import DNSTunnel

# Define a simple mock process for testing sandbox detection
class MockProcess:
    def __init__(self, name):
        self._name = name
    def name(self):
        return self._name

class SecurityTests(unittest.TestCase):
    
    @patch('psutil.process_iter')
    def test_sandbox_process_detection(self, mock_procs):
        mock_procs.return_value = [MockProcess('vboxservice.exe')]
        self.assertTrue(EnvironmentValidator().detect_sandbox())

    def test_dns_encryption(self):
        tunnel = DNSTunnel(encryption_key=b'test-key')
        encrypted = tunnel._encrypt(b'test')
        # Verify that the encrypted output does not contain the plain text
        self.assertNotIn(b'test', base64.b32decode(encrypted + '==='))

if __name__ == '__main__':
    unittest.main()
