"""Maintained Ed25519 key validation for signed action packages."""

from __future__ import annotations

import base64
import hashlib
from typing import TypeAlias

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from nacl.bindings import crypto_core_ed25519_is_valid_point

from .action_package_errors import ActionPackageError

PublicKeyValue: TypeAlias = bytes | Ed25519PublicKey


def normalize_ed25519_public_key(value: PublicKeyValue) -> bytes:
    """Return a canonical non-identity prime-order Ed25519 public key."""

    if isinstance(value, Ed25519PublicKey):
        raw = value.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    elif isinstance(value, bytes):
        raw = value
    else:
        raise ActionPackageError("trusted signer key must be an Ed25519 public key")
    if len(raw) != 32:
        raise ActionPackageError("trusted signer key must contain exactly 32 raw bytes")
    if not crypto_core_ed25519_is_valid_point(raw):
        raise ActionPackageError(
            "trusted signer key must be a canonical non-identity prime-order Ed25519 point"
        )
    try:
        Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise ActionPackageError("trusted signer key is not a valid Ed25519 public key") from exc
    return raw


def canonical_public_key_b64u(value: PublicKeyValue) -> str:
    """Return the canonical unpadded base64url public-key encoding."""

    return (
        base64.urlsafe_b64encode(normalize_ed25519_public_key(value)).rstrip(b"=").decode("ascii")
    )


def ed25519_public_key_fingerprint(value: PublicKeyValue) -> str:
    """Return the stable SHA-256 fingerprint of a raw Ed25519 public key."""

    return "sha256:" + hashlib.sha256(normalize_ed25519_public_key(value)).hexdigest()


__all__ = [
    "PublicKeyValue",
    "canonical_public_key_b64u",
    "ed25519_public_key_fingerprint",
    "normalize_ed25519_public_key",
]
