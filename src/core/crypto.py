# src/core/crypto.py
from pqcrypto.sign.dilithium3 import generate_keypair, sign, verify

class QuantumCrypto:
    """
    Demonstration of quantum-resistant signatures using Dilithium3.
    """

    def __init__(self):
        self.pk, self.sk = generate_keypair()
    
    def sign_command(self, data: bytes) -> bytes:
        return sign(self.sk, data)
    
    def verify_command(self, signature: bytes, data: bytes) -> bool:
        try:
            verify(self.pk, data, signature)
            return True
        except Exception:
            return False
