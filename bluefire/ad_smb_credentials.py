"""Read-only, role-private AD credential admission. No enrollment or secret export.

The OS/provider can retain copies; wiping our mutable buffers is not complete
process-memory zeroization. Public metadata contains only exact opaque handles
and digests. Plain UPN/password bytes are resolved once, after worker readiness.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import struct
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .ad_smb_channel import AdSmbHostChannel
from .ad_smb_contract import AdSmbError, AdSmbScope, digest, document, exact
from .ad_smb_private_storage import private_root
from .ad_smb_worker_wire import BEGIN_MAX, WorkerPacket, begin_prefix, frame
from .runner_trust import (
    RunnerTrustError,
    _PinnedDirectory,
    _secret_provider,
)
from .secret_store import SecretProvider
from .util import canonical_json_bytes, content_hash

_FILES = {"credentials.json", "probe.secret", "legitimate.secret"}
_MAX_PROTECTED = 16384


def _sha(raw: bytes | bytearray | memoryview) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _purpose(channel: AdSmbHostChannel, reader: str, row: dict[str, Any]) -> str:
    return (
        "bluefire.ad-smb-credential.v1:" + channel.digest + ":" + reader + ":" + content_hash(row)
    )


def _metadata(
    raw: bytes, scope: AdSmbScope, channel: AdSmbHostChannel, provider: SecretProvider
) -> dict[str, Any]:
    row = document(raw, limit=16384)
    exact(
        row,
        {
            "schema_version",
            "scope_digest",
            "channel_digest",
            "client_host_id",
            "secret_provider",
            "readers",
        },
        "AD credential binding",
    )
    source = scope.to_dict()
    if (
        row["schema_version"] != "bluefire.ad-smb-credentials.v1"
        or row["scope_digest"] != scope.digest
        or row["channel_digest"] != channel.digest
        or row["client_host_id"] != source["hosts"]["client"]["host_id"]
        or channel.to_dict()["role"] != "client"
        or row["secret_provider"] != provider.provider_id
    ):
        raise AdSmbError("AD credential binding differs from the enrolled client.")
    exact(row["readers"], {"probe", "legitimate"}, "AD reader credentials")
    for reader, value in row["readers"].items():
        exact(
            value,
            {
                "sid",
                "credential_handle",
                "identity_receipt_digest",
                "upn_sha256",
                "protected_sha256",
            },
            "AD reader binding",
        )
        if any(
            value[key] != source["principals"][reader][key]
            for key in ("sid", "credential_handle", "identity_receipt_digest")
        ):
            raise AdSmbError("AD credential principal differs from the exact scoped reader.")
        digest(value["upn_sha256"])
        digest(value["protected_sha256"])
    if row["readers"]["probe"]["upn_sha256"] == row["readers"]["legitimate"]["upn_sha256"]:
        raise AdSmbError("AD reader credential identities must be distinct.")
    return row


@dataclass(frozen=True)
class CredentialBinding:
    _root: Path = field(repr=False)
    _raw: bytes = field(repr=False)
    _scope: AdSmbScope = field(repr=False)
    _channel: AdSmbHostChannel = field(repr=False)
    _provider: SecretProvider = field(repr=False)

    @property
    def digest(self) -> str:
        return content_hash(document(self._raw))

    def reader_binding(self, reader: str) -> tuple[str, str]:
        if reader not in {"probe", "legitimate"}:
            raise AdSmbError("AD credential reader is unsupported.")
        row = document(self._raw)
        return self.digest, row["readers"][reader]["upn_sha256"]

    def one_use(self, packet: WorkerPacket) -> OneUseCredential:
        public, request = packet.to_dict(), packet.request
        if (
            public["host_role"] != "client"
            or public["channel_digest"] != self._channel.digest
            or request["scope_digest"] != self._scope.digest
            or request["principal_binding_digest"] != self.digest
        ):
            raise AdSmbError("AD credential delivery is not bound to this client task.")
        reader = request["target"]["reader"]
        binding, upn = self.reader_binding(reader)
        if public["credential_binding_digest"] != binding or public["expected_upn_sha256"] != upn:
            raise AdSmbError("AD credential delivery binding changed.")
        return OneUseCredential(self, packet, reader)


class OneUseCredential:
    """A task-local resolver; it cannot be reused by retry or original recovery."""

    def __init__(self, binding: CredentialBinding, packet: WorkerPacket, reader: str) -> None:
        self._binding, self._packet, self._reader = binding, packet, reader
        self._used = False
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return "<OneUseCredential redacted>"

    def matches(self, packet: WorkerPacket) -> bool:
        return self._packet.digest == packet.digest

    def begin(self) -> bytearray:
        with self._lock:
            if self._used:
                raise AdSmbError("AD credential delivery was already consumed.")
            self._used = True
        private = bytearray()
        payload = bytearray()
        try:
            binding = self._binding
            binding._channel.assert_current()
            with _PinnedDirectory(
                binding._root, private=True, verify_permissions_only=True
            ) as storage:
                row, blobs = _read(storage, binding._scope, binding._channel, binding._provider)
                if canonical_json_bytes(row) != binding._raw:
                    raise AdSmbError("AD credential binding changed before delivery.")
                selected = row["readers"][self._reader]
                # protected_sha256 is an integrity pin, not part of encryption
                # purpose (including ciphertext in its own purpose is circular).
                purpose_row = {
                    key: value for key, value in selected.items() if key != "protected_sha256"
                }
                private.extend(
                    binding._provider.unprotect(
                        _purpose(binding._channel, self._reader, purpose_row),
                        blobs[self._reader + ".secret"],
                    )
                )
                _private_payload(private, selected["upn_sha256"])
                repeated, repeated_blobs = _read(
                    storage, binding._scope, binding._channel, binding._provider
                )
                if repeated != row or repeated_blobs != blobs:
                    raise AdSmbError("AD credential storage changed during delivery.")
            payload = begin_prefix(self._packet, reader=True)
            payload.extend(memoryview(private)[8:])
            return frame(payload, BEGIN_MAX)
        except Exception:
            raise AdSmbError("AD protected credential delivery was refused.") from None
        finally:
            private[:] = b"\0" * len(private)
            payload[:] = b"\0" * len(payload)


def _private_payload(raw: bytearray, expected_upn: str) -> None:
    try:
        if not 14 <= len(raw) <= 2048 or raw[:8] != b"BFADCRD1":
            raise ValueError
        size = struct.unpack_from("<H", raw, 8)[0]
        if not 3 <= size <= 318 or 10 + size + 2 > len(raw):
            raise ValueError
        upn = memoryview(raw)[10 : 10 + size]
        # Restrict UPN syntax without carrying it into diagnostics or exports.
        decoded = upn.tobytes().decode("ascii", errors="strict")
        name, separator, domain = decoded.partition("@")
        if (
            not separator
            or re.fullmatch(r"[a-z0-9._-]{1,64}", name) is None
            or not 3 <= len(domain) <= 253
            or "." not in domain
            or any(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None
                for label in domain.split(".")
            )
            or _sha(upn) != expected_upn
        ):
            raise ValueError
        try:
            ipaddress.ip_address(domain)
        except ValueError:
            pass
        else:
            raise ValueError
        units = struct.unpack_from("<H", raw, 10 + size)[0]
        if not 1 <= units <= 256 or len(raw) != 12 + size + units * 2:
            raise ValueError
        password = memoryview(raw)[12 + size :]
        text = password.tobytes().decode("utf-16-le", errors="strict")
        if "\0" in text:
            raise ValueError
    except (ValueError, UnicodeError, struct.error):
        raise AdSmbError("AD private credential payload is invalid.") from None


def _read(
    storage: _PinnedDirectory,
    scope: AdSmbScope,
    channel: AdSmbHostChannel,
    provider: SecretProvider,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    if set(storage.names(maximum=4)) != _FILES:
        raise AdSmbError("AD credential storage has unexpected material.")
    blobs = {name: storage.read(name, maximum=_MAX_PROTECTED) for name in sorted(_FILES)}
    row = _metadata(blobs["credentials.json"], scope, channel, provider)
    if any(
        _sha(blobs[reader + ".secret"]) != row["readers"][reader]["protected_sha256"]
        for reader in ("probe", "legitimate")
    ):
        raise AdSmbError("AD protected credential material changed.")
    return row, blobs


def load_credential_binding(
    root: str | Path,
    *,
    scope: AdSmbScope,
    channel: AdSmbHostChannel,
    expected_digest: str,
    secret_provider: SecretProvider | None = None,
) -> CredentialBinding:
    """Inspect existing protected bindings without decrypting any credential."""
    try:
        digest(expected_digest)
        checked = AdSmbHostChannel.from_mapping(scope, channel.to_dict())
        checked.assert_current()
        path = private_root(root)
        provider = _secret_provider(secret_provider)
        with _PinnedDirectory(path, private=True, verify_permissions_only=True) as storage:
            row, _ = _read(storage, scope, checked, provider)
            if content_hash(row) != expected_digest:
                raise AdSmbError("AD credential enrollment pin changed.")
        return CredentialBinding(path, canonical_json_bytes(row), scope, checked, provider)
    except (RunnerTrustError, OSError, ValueError, TypeError):
        raise AdSmbError("AD protected credential binding is unavailable.") from None
