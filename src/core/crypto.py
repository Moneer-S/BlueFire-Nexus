# src/core/crypto.py
"""Quantum-resistant signature demonstration.

This module is preserved research code that demonstrates Dilithium3
post-quantum signatures via the optional `pqcrypto` dependency. It is
NOT imported by the runtime baseline. The `pqcrypto` import is
deferred so importing `src.core.crypto` does not crash on hosts
without the optional dependency installed; instead, only the
``QuantumCrypto`` constructor raises if the dep is missing.
"""

from __future__ import annotations

from typing import Any, Tuple


def _load_dilithium() -> Tuple[Any, Any, Any]:
    """Lazy-import of the Dilithium3 primitives.

    Raises ``ImportError`` with a helpful message when the optional
    ``pqcrypto`` dependency is not installed, rather than failing at
    module-import time and breaking unrelated callers that import
    ``src.core.crypto`` for type or capability discovery.
    """
    try:
        from pqcrypto.sign.dilithium3 import (  # type: ignore[import-not-found]
            generate_keypair,
            sign,
            verify,
        )
    except ImportError as exc:  # pragma: no cover - depends on optional dep state
        raise ImportError(
            "QuantumCrypto requires the optional `pqcrypto` package. Install "
            "with `pip install pqcrypto` to enable this preserved-research "
            "demonstration; the BlueFire-Nexus baseline does not depend on it."
        ) from exc
    return generate_keypair, sign, verify


class QuantumCrypto:
    """
    Demonstration of quantum-resistant signatures using Dilithium3.
    """

    def __init__(self):
        generate_keypair, _sign, _verify = _load_dilithium()
        self._sign = _sign
        self._verify = _verify
        self.pk, self.sk = generate_keypair()

    def sign_command(self, data: bytes) -> bytes:
        return self._sign(self.sk, data)

    def verify_command(self, signature: bytes, data: bytes) -> bool:
        try:
            self._verify(self.pk, data, signature)
            return True
        except Exception:
            return False
