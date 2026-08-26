from __future__ import annotations

import os

import pytest

from bluefire.secret_store import (
    InMemorySecretProvider,
    SecretProvider,
    SecretStoreError,
    WindowsDPAPISecretProvider,
    default_secret_provider,
)


def test_in_memory_provider_persists_only_random_process_local_handles() -> None:
    provider = InMemorySecretProvider()
    plaintext = b"violet-river-sensitive-material"

    first = provider.protect("runner.client-key", plaintext)
    second = provider.protect("runner.client-key", plaintext)

    assert provider.provider_id == "in-memory-test.v1"
    assert isinstance(provider, SecretProvider)
    assert first != second
    assert plaintext not in first
    assert plaintext not in second
    assert provider.unprotect("runner.client-key", first) == plaintext
    assert provider.unprotect("runner.client-key", second) == plaintext
    assert plaintext.decode() not in repr(provider)

    with pytest.raises(SecretStoreError, match="invalid or cannot be opened"):
        provider.unprotect("runner.server-key", first)

    # A handle is a reference into one provider instance, not reversible data.
    with pytest.raises(SecretStoreError, match="invalid or cannot be opened"):
        InMemorySecretProvider().unprotect("runner.client-key", first)


def test_in_memory_provider_rejects_tampered_or_unsupported_envelopes() -> None:
    provider = InMemorySecretProvider()
    opaque = provider.protect("runner.hmac-key", b"bounded-sensitive-material")

    tampered = bytearray(opaque)
    tampered[-1] ^= 0x01
    with pytest.raises(SecretStoreError, match="invalid or cannot be opened"):
        provider.unprotect("runner.hmac-key", bytes(tampered))

    wrong_version = bytearray(opaque)
    wrong_version[4] += 1
    with pytest.raises(SecretStoreError, match="invalid or cannot be opened"):
        provider.unprotect("runner.hmac-key", bytes(wrong_version))

    wrong_provider = bytearray(opaque)
    wrong_provider[5] = 1
    with pytest.raises(SecretStoreError, match="invalid or cannot be opened"):
        provider.unprotect("runner.hmac-key", bytes(wrong_provider))

    truncated = opaque[:-1]
    with pytest.raises(SecretStoreError, match="invalid or cannot be opened"):
        provider.unprotect("runner.hmac-key", truncated)


def test_secret_provider_validates_purpose_and_size_limits() -> None:
    provider = InMemorySecretProvider()

    with pytest.raises(SecretStoreError, match="purpose is invalid"):
        provider.protect("", b"material")
    with pytest.raises(SecretStoreError, match="purpose is invalid"):
        provider.protect("bad\npurpose", b"material")
    with pytest.raises(SecretStoreError, match="protection limit"):
        provider.protect("bounded-purpose", b"x" * (1024 * 1024 + 1))
    with pytest.raises(SecretStoreError, match="invalid or cannot be opened"):
        provider.unprotect("bounded-purpose", b"x" * (2 * 1024 * 1024 + 32))


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI is Windows-only")
def test_windows_dpapi_is_current_user_purpose_bound_and_randomized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Loading known DLLs is system32-constrained and must not derive a path from
    # an attacker-controlled SYSTEMROOT environment variable.
    monkeypatch.setenv("SYSTEMROOT", r"C:\attacker-controlled")
    provider = WindowsDPAPISecretProvider()
    plaintext = b"ember-lake-sensitive-material"

    first = provider.protect("runner.client-key", plaintext)
    second = provider.protect("runner.client-key", plaintext)

    assert provider.provider_id == "windows-dpapi-current-user.v1"
    assert isinstance(provider, SecretProvider)
    assert first != second
    assert plaintext not in first
    assert plaintext not in second
    assert provider.unprotect("runner.client-key", first) == plaintext
    assert isinstance(default_secret_provider(), WindowsDPAPISecretProvider)

    with pytest.raises(SecretStoreError) as wrong_purpose:
        provider.unprotect("runner.server-key", first)
    assert str(wrong_purpose.value) == "Protected secret is invalid or cannot be opened."
    assert plaintext.decode() not in str(wrong_purpose.value)

    tampered = bytearray(first)
    tampered[-1] ^= 0x01
    with pytest.raises(SecretStoreError) as corrupt:
        provider.unprotect("runner.client-key", bytes(tampered))
    assert str(corrupt.value) == "Protected secret is invalid or cannot be opened."
    assert plaintext.decode() not in str(corrupt.value)


@pytest.mark.skipif(os.name == "nt", reason="unsupported-platform behavior")
def test_default_provider_fails_closed_when_no_os_provider_exists() -> None:
    with pytest.raises(SecretStoreError, match="unavailable"):
        default_secret_provider()
