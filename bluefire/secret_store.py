"""Operating-system-backed protection for locally persisted secret references.

This module deliberately exposes opaque bytes rather than a filesystem or
environment-variable convention.  The production provider delegates key
management to Windows DPAPI for the current user.  The in-memory provider is
only a deterministic test boundary: its opaque values are random handles and
the corresponding plaintext never leaves process memory.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import os
import secrets
import struct
import threading
from ctypes import wintypes
from typing import Protocol, runtime_checkable

_ENVELOPE_MAGIC = b"BFSX"
_ENVELOPE_VERSION = 1
_PROVIDER_WINDOWS_DPAPI = 1
_PROVIDER_IN_MEMORY = 255
_ENVELOPE_HEADER = struct.Struct(">4sBBI")

_MAX_PURPOSE_BYTES = 512
_MAX_PLAINTEXT_BYTES = 1024 * 1024
_MAX_PROTECTED_PAYLOAD_BYTES = 2 * 1024 * 1024
_MAX_OPAQUE_BYTES = _ENVELOPE_HEADER.size + _MAX_PROTECTED_PAYLOAD_BYTES
_MEMORY_HANDLE_BYTES = 32

_PURPOSE_DOMAIN = b"bluefire.secret-store.purpose.v1\x00"
_CRYPTPROTECT_UI_FORBIDDEN = 0x00000001
_LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800


class SecretStoreError(RuntimeError):
    """A sanitized refusal from the secret-protection boundary."""


@runtime_checkable
class SecretProvider(Protocol):
    """Protect and recover bytes for one explicit application purpose."""

    @property
    def provider_id(self) -> str: ...

    def protect(self, purpose: str, plaintext: bytes) -> bytes: ...

    def unprotect(self, purpose: str, opaque: bytes) -> bytes: ...


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


class WindowsDPAPISecretProvider:
    """Current-user Windows DPAPI provider with purpose-bound entropy.

    The provider loads only known DLLs through the system32-only loader flag.
    It neither reads ``SYSTEMROOT`` nor launches a helper process.  DPAPI's
    machine-scope flag is intentionally absent, so only the enrolling Windows
    user can normally recover a protected value.
    """

    @property
    def provider_id(self) -> str:
        return "windows-dpapi-current-user.v1"

    def __init__(self) -> None:
        if os.name != "nt":
            raise SecretStoreError("Operating-system secret protection is unavailable.")
        try:
            win_dll = ctypes.WinDLL  # type: ignore[attr-defined]
            crypt32 = win_dll(
                "crypt32.dll",
                use_last_error=True,
                winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
            kernel32 = win_dll(
                "kernel32.dll",
                use_last_error=True,
                winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
            protect = crypt32.CryptProtectData
            unprotect = crypt32.CryptUnprotectData
            local_free = kernel32.LocalFree

            blob_pointer = ctypes.POINTER(_DataBlob)
            protect.argtypes = [
                blob_pointer,
                wintypes.LPCWSTR,
                blob_pointer,
                ctypes.c_void_p,
                ctypes.c_void_p,
                wintypes.DWORD,
                blob_pointer,
            ]
            protect.restype = wintypes.BOOL
            unprotect.argtypes = list(protect.argtypes)
            unprotect.restype = wintypes.BOOL
            local_free.argtypes = [ctypes.c_void_p]
            local_free.restype = ctypes.c_void_p
        except (AttributeError, OSError, TypeError):
            raise SecretStoreError("Operating-system secret protection is unavailable.") from None

        self._protect_data = protect
        self._unprotect_data = unprotect
        self._local_free = local_free

    def protect(self, purpose: str, plaintext: bytes) -> bytes:
        purpose_digest = _purpose_digest(purpose)
        secret = _validated_plaintext(plaintext)
        payload = self._call_dpapi(self._protect_data, secret, purpose_digest, protecting=True)
        return _encode_envelope(_PROVIDER_WINDOWS_DPAPI, payload)

    def unprotect(self, purpose: str, opaque: bytes) -> bytes:
        purpose_digest = _purpose_digest(purpose)
        payload = _decode_envelope(opaque, expected_provider=_PROVIDER_WINDOWS_DPAPI)
        return self._call_dpapi(
            self._unprotect_data,
            payload,
            purpose_digest,
            protecting=False,
        )

    def _call_dpapi(
        self,
        operation: object,
        value: bytes,
        purpose_digest: bytes,
        *,
        protecting: bool,
    ) -> bytes:
        input_blob, input_buffer = _blob_from_bytes(value)
        entropy_blob, entropy_buffer = _blob_from_bytes(purpose_digest)
        output_blob = _DataBlob()
        # Keep the backing buffers alive until the native call returns.
        _ = (input_buffer, entropy_buffer)
        try:
            succeeded = operation(  # type: ignore[operator]
                ctypes.byref(input_blob),
                None,
                ctypes.byref(entropy_blob),
                None,
                None,
                _CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(output_blob),
            )
        except (OSError, ValueError):
            succeeded = False

        if not succeeded:
            message = (
                "Secret protection failed."
                if protecting
                else "Protected secret is invalid or cannot be opened."
            )
            raise SecretStoreError(message) from None

        try:
            output_size = int(output_blob.cbData)
            if (
                output_size < 0
                or output_size > _MAX_PROTECTED_PAYLOAD_BYTES
                or (output_size and not bool(output_blob.pbData))
            ):
                raise SecretStoreError(
                    "Secret protection failed."
                    if protecting
                    else "Protected secret is invalid or cannot be opened."
                )
            recovered = bytes(ctypes.string_at(output_blob.pbData, output_size))
        finally:
            if output_blob.pbData:
                self._local_free(ctypes.cast(output_blob.pbData, ctypes.c_void_p))

        if not protecting and len(recovered) > _MAX_PLAINTEXT_BYTES:
            raise SecretStoreError("Protected secret is invalid or cannot be opened.")
        return recovered


class InMemorySecretProvider:
    """Process-local test provider backed by unguessable opaque handles.

    This is not an encryption fallback and is never selected automatically.
    Each protection call creates a new random handle, even for the same value.
    Purpose bindings and plaintext values remain only in the private in-memory
    mapping, so persisting the returned envelope cannot reveal or recover them
    in another process.
    """

    @property
    def provider_id(self) -> str:
        return "in-memory-test.v1"

    def __init__(self) -> None:
        self._values: dict[bytes, tuple[bytes, bytes]] = {}
        self._lock = threading.RLock()

    def protect(self, purpose: str, plaintext: bytes) -> bytes:
        purpose_digest = _purpose_digest(purpose)
        secret = _validated_plaintext(plaintext)
        with self._lock:
            while True:
                handle = secrets.token_bytes(_MEMORY_HANDLE_BYTES)
                if handle not in self._values:
                    break
            self._values[handle] = (purpose_digest, secret)
        return _encode_envelope(_PROVIDER_IN_MEMORY, handle)

    def unprotect(self, purpose: str, opaque: bytes) -> bytes:
        purpose_digest = _purpose_digest(purpose)
        handle = _decode_envelope(opaque, expected_provider=_PROVIDER_IN_MEMORY)
        if len(handle) != _MEMORY_HANDLE_BYTES:
            raise SecretStoreError("Protected secret is invalid or cannot be opened.")
        with self._lock:
            record = self._values.get(handle)
        if record is None or not hmac.compare_digest(record[0], purpose_digest):
            raise SecretStoreError("Protected secret is invalid or cannot be opened.")
        return record[1]


def default_secret_provider() -> SecretProvider:
    """Return the production provider, failing closed on unsupported systems."""

    if os.name == "nt":
        return WindowsDPAPISecretProvider()
    raise SecretStoreError("Operating-system secret protection is unavailable.")


def _purpose_digest(purpose: str) -> bytes:
    if not isinstance(purpose, str) or not purpose:
        raise SecretStoreError("Secret purpose is invalid.")
    try:
        encoded = purpose.encode("utf-8", errors="strict")
    except UnicodeError:
        raise SecretStoreError("Secret purpose is invalid.") from None
    if len(encoded) > _MAX_PURPOSE_BYTES or any(
        character < " " or character == "\x7f" for character in purpose
    ):
        raise SecretStoreError("Secret purpose is invalid.")
    return hashlib.sha256(_PURPOSE_DOMAIN + encoded).digest()


def _validated_plaintext(plaintext: bytes) -> bytes:
    if not isinstance(plaintext, bytes) or len(plaintext) > _MAX_PLAINTEXT_BYTES:
        raise SecretStoreError("Secret value is invalid or exceeds the protection limit.")
    return plaintext


def _encode_envelope(provider: int, payload: bytes) -> bytes:
    if not payload or len(payload) > _MAX_PROTECTED_PAYLOAD_BYTES:
        raise SecretStoreError("Secret protection failed.")
    return (
        _ENVELOPE_HEADER.pack(
            _ENVELOPE_MAGIC,
            _ENVELOPE_VERSION,
            provider,
            len(payload),
        )
        + payload
    )


def _decode_envelope(opaque: bytes, *, expected_provider: int) -> bytes:
    if (
        not isinstance(opaque, bytes)
        or len(opaque) < _ENVELOPE_HEADER.size
        or len(opaque) > _MAX_OPAQUE_BYTES
    ):
        raise SecretStoreError("Protected secret is invalid or cannot be opened.")
    try:
        magic, version, provider, payload_size = _ENVELOPE_HEADER.unpack_from(opaque)
    except struct.error:
        raise SecretStoreError("Protected secret is invalid or cannot be opened.") from None
    payload = opaque[_ENVELOPE_HEADER.size :]
    if (
        magic != _ENVELOPE_MAGIC
        or version != _ENVELOPE_VERSION
        or provider != expected_provider
        or payload_size != len(payload)
        or not payload
    ):
        raise SecretStoreError("Protected secret is invalid or cannot be opened.")
    return payload


def _blob_from_bytes(value: bytes) -> tuple[_DataBlob, ctypes.Array[ctypes.c_char]]:
    # Allocate one byte for an empty input while preserving the native cbData=0.
    backing = ctypes.create_string_buffer(value, max(1, len(value)))
    pointer = ctypes.cast(backing, ctypes.POINTER(ctypes.c_ubyte))
    return _DataBlob(len(value), pointer), backing


__all__ = [
    "InMemorySecretProvider",
    "SecretProvider",
    "SecretStoreError",
    "WindowsDPAPISecretProvider",
    "default_secret_provider",
]
