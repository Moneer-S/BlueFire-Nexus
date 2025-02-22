import hashlib
import binascii
import random
import os

class PolymorphicMutator:
    def __init__(self, seed=None):
        self.rng = random.SystemRandom(seed or os.urandom(16))
        self.junk_ops = [
            'nop', 'xchg eax, eax', 'lea rbx, [rip+0x0]',
            'pause', 'lfence', 'db 0x90', 'jmp $+1'
        ]
    
    def _generate_junk_asm(self):
        """Generates non-repeating junk code blocks"""
        return '\n'.join([
            f"; JUNK: {binascii.hexlify(os.urandom(4)).decode()}"
            f"{self.rng.choice(self.junk_ops)}"
            for _ in range(self.rng.randint(5,15))
        ])

    def morph_payload(self, payload: bytes) -> bytes:
        mutated = []
        for byte in payload:
            mutated.append(byte ^ self.rng.randint(1,255))
            if self.rng.random() > 0.7:
                mutated.extend([self.rng.randint(0,255) for _ in range(2)])
        return bytes(mutated)

    def generate_stub(self, real_code: str) -> str:
        return f"""
        {self._generate_junk_asm()}
        {real_code}
        {self._generate_junk_asm()}
        """

# Example usage:
if __name__ == "__main__":
    mutator = PolymorphicMutator()
    print(mutator.generate_stub("mov edi, 0x1337"))