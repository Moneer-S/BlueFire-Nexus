"""Local enrollment material for the authenticated runner transport.

The trust document is deliberately public metadata: it contains identities,
certificate fingerprints, and the exact profile allow-list, but never private
keys, shared authentication material, or local filesystem paths.
"""

from __future__ import annotations

import base64
import ctypes
import errno
import hashlib
import ipaddress
import json
import os
import re
import secrets
import stat
import subprocess  # nosec B404
import threading
import time
from contextlib import contextmanager
from csv import reader as csv_reader
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .secret_store import SecretProvider, SecretStoreError, default_secret_provider
from .util import canonical_json_bytes

# Only fixed, absolute Windows system utilities are invoked for ACL handling.

TRUST_SCHEMA_VERSION = "bluefire.runner-trust.v1"
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")
_TRUST_FIELDS = frozenset(
    {
        "schema_version",
        "runner_id",
        "client_id",
        "allowed_profile_ids",
        "status",
        "ca_fingerprint",
        "server_fingerprint",
        "client_fingerprint",
        "created_at",
        "expires_at",
        "revoked_at",
        "secret_provider",
    }
)
_MATERIAL_NAMES = frozenset(
    {
        "ca-cert.pem",
        "server-cert.pem",
        "server-key.pem",
        "server-key-password.secret",
        "client-cert.pem",
        "client-key.pem",
        "client-key-password.secret",
        "hmac.secret",
        "trust.json",
    }
)
_MAX_TRUST_BYTES = 64 * 1024
_MAX_MATERIAL_BYTES = 1024 * 1024
_HMAC_KEY_BYTES = 32
_TRUST_TEMP_NAME = ".trust.json.tmp"
_CREATION_SUFFIX = ".creating"
_REMOVAL_SUFFIX = ".removing"
_CREATION_INTENT_SUFFIX = ".creation-intent.json"
_REVOCATION_INTENT_SUFFIX = ".revocation-intent.json"
_REMOVAL_INTENT_SUFFIX = ".removal-intent.json"
_TRANSITION_LOCK_SUFFIX = ".transition.lock"
_INTENT_SCHEMA_VERSION = "bluefire.runner-trust-intent.v1"
_INTENT_FIELDS = frozenset(
    {
        "schema_version",
        "operation",
        "runner_id",
        "client_id",
        "root_digest",
        "secret_provider",
        "protected_payload",
    }
)
_REMOVAL_IDENTITY_NAMES = ("trust.json", "server-cert.pem")
_TRANSIENT_MATERIAL_NAMES = _MATERIAL_NAMES | {_TRUST_TEMP_NAME}
_LOCAL_TRANSITION_LOCKS_GUARD = threading.Lock()
_LOCAL_TRANSITION_LOCKS: dict[str, threading.RLock] = {}

_WINDOWS_GENERIC_READ = 0x80000000
_WINDOWS_GENERIC_WRITE = 0x40000000
_WINDOWS_DELETE = 0x00010000
_WINDOWS_WRITE_DAC = 0x00040000
_WINDOWS_FILE_SHARE_READ = 0x00000001
_WINDOWS_FILE_SHARE_WRITE = 0x00000002
_WINDOWS_OPEN_EXISTING = 3
_WINDOWS_CREATE_NEW = 1
_WINDOWS_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_WINDOWS_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_WINDOWS_FILE_DISPOSITION_INFO = 4


class _WindowsFileInformation(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", wintypes.FILETIME),
        ("ftLastAccessTime", wintypes.FILETIME),
        ("ftLastWriteTime", wintypes.FILETIME),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    ]


class _WindowsFileDisposition(ctypes.Structure):
    _fields_ = [("DeleteFile", wintypes.BOOL)]


class RunnerTrustError(RuntimeError):
    """A secret- and path-safe enrollment failure."""


@dataclass(frozen=True, repr=False)
class RunnerEnrollment:
    """Validated paths and public metadata for one local enrollment."""

    root: Path
    metadata: Mapping[str, Any]
    secret_provider: SecretProvider

    def __repr__(self) -> str:
        return f"RunnerEnrollment(runner_id={self.runner_id!r}, status={self.status!r})"

    @property
    def runner_id(self) -> str:
        return str(self.metadata["runner_id"])

    @property
    def client_id(self) -> str:
        return str(self.metadata["client_id"])

    @property
    def allowed_profile_ids(self) -> tuple[str, ...]:
        return tuple(str(value) for value in self.metadata["allowed_profile_ids"])

    @property
    def status(self) -> str:
        return str(self.metadata["status"])

    @property
    def ca_certificate(self) -> Path:
        return self.root / "ca-cert.pem"

    @property
    def server_certificate(self) -> Path:
        return self.root / "server-cert.pem"

    @property
    def server_private_key(self) -> Path:
        return self.root / "server-key.pem"

    @property
    def client_certificate(self) -> Path:
        return self.root / "client-cert.pem"

    @property
    def client_private_key(self) -> Path:
        return self.root / "client-key.pem"

    @property
    def hmac_key_file(self) -> Path:
        return self.root / "hmac.secret"

    @property
    def trust_file(self) -> Path:
        return self.root / "trust.json"

    def hmac_key(self) -> bytes:
        """Read the validated per-enrollment authentication key."""

        value = self._secret("hmac.secret", "request-hmac")
        if len(value) != _HMAC_KEY_BYTES:
            raise RunnerTrustError("Enrollment authentication material is invalid.")
        return value

    def server_key_password(self) -> bytes:
        return self._secret("server-key-password.secret", "server-key-password")

    def client_key_password(self) -> bytes:
        return self._secret("client-key-password.secret", "client-key-password")

    def _secret(self, filename: str, purpose: str) -> bytes:
        try:
            opaque = _bounded_regular_read(self.root / filename, _MAX_MATERIAL_BYTES)
            return cast(bytes, self.secret_provider.unprotect(self._purpose(purpose), opaque))
        except (MemoryError, OSError, RunnerTrustError, SecretStoreError):
            raise RunnerTrustError("Enrollment authentication material is unavailable.") from None

    def _purpose(self, purpose: str) -> str:
        return f"bluefire.runner-enrollment.v1:{self.runner_id}:{self.client_id}:{purpose}"


def create_local_enrollment(
    root: str | Path,
    *,
    runner_id: str,
    client_id: str,
    allowed_profile_ids: Sequence[str],
    validity_days: int = 30,
    secret_provider: SecretProvider | None = None,
) -> RunnerEnrollment:
    """Create a CA and mutually authenticated loopback identities.

    Creation is exclusive and fail-closed so an existing trust root is never
    silently replaced. The CA signing key exists only during issuance; runtime
    private-key passwords and the HMAC key are stored as OS-protected references.
    """

    checked_runner_id = _identifier(runner_id, "runner identity")
    checked_client_id = _identifier(client_id, "client identity")
    checked_profiles = _profile_ids(allowed_profile_ids)
    provider = _secret_provider(secret_provider)
    if isinstance(validity_days, bool) or not isinstance(validity_days, int):
        raise RunnerTrustError("Enrollment validity is invalid.")
    if not 1 <= validity_days <= 365:
        raise RunnerTrustError("Enrollment validity must be between 1 and 365 days.")

    try:
        destination = _canonical_transition_path(root, create_parent=True)
    except RunnerTrustError:
        raise
    except OSError:
        raise RunnerTrustError("Enrollment could not be created.") from None

    with _enrollment_transition_lock(destination):
        return _create_local_enrollment_locked(
            destination,
            runner_id=checked_runner_id,
            client_id=checked_client_id,
            allowed_profile_ids=checked_profiles,
            validity_days=validity_days,
            secret_provider=provider,
        )


def _create_local_enrollment_locked(
    destination: Path,
    *,
    runner_id: str,
    client_id: str,
    allowed_profile_ids: tuple[str, ...],
    validity_days: int,
    secret_provider: SecretProvider,
) -> RunnerEnrollment:
    staging = _transition_sibling(destination, _CREATION_SUFFIX)
    creation_intent = _transition_sibling(destination, _CREATION_INTENT_SUFFIX)
    tombstone = _transition_sibling(destination, _REMOVAL_SUFFIX)
    revocation_intent = _transition_sibling(destination, _REVOCATION_INTENT_SUFFIX)
    removal_intent = _transition_sibling(destination, _REMOVAL_INTENT_SUFFIX)
    request = {
        "runner_id": runner_id,
        "client_id": client_id,
        "allowed_profile_ids": list(allowed_profile_ids),
        "validity_days": validity_days,
    }

    if any(_path_entry_exists(path) for path in (tombstone, revocation_intent, removal_intent)):
        raise RunnerTrustError("Enrollment removal must be recovered before creation.")

    if _path_entry_exists(destination):
        if not _path_entry_exists(creation_intent) or _path_entry_exists(staging):
            raise RunnerTrustError("Enrollment could not be created.")
        _load_transition_intent(
            creation_intent,
            destination=destination,
            operation="create",
            secret_provider=secret_provider,
            expected=request,
        )
        enrolled = load_local_enrollment(destination, secret_provider=secret_provider)
        _validate_creation_recovery(
            enrolled,
            runner_id=runner_id,
            client_id=client_id,
            allowed_profile_ids=allowed_profile_ids,
            validity_days=validity_days,
        )
        _unlink_transition_file(creation_intent)
        return enrolled

    if _path_entry_exists(creation_intent):
        _load_transition_intent(
            creation_intent,
            destination=destination,
            operation="create",
            secret_provider=secret_provider,
            expected=request,
        )
    else:
        if _path_entry_exists(staging):
            raise RunnerTrustError(
                "Enrollment creation stage is not authenticated by a transition intent."
            )
        _write_transition_intent(
            creation_intent,
            destination=destination,
            operation="create",
            runner_id=runner_id,
            client_id=client_id,
            secret_provider=secret_provider,
            payload=request,
        )

    if _path_entry_exists(staging):
        try:
            staged = load_local_enrollment(staging, secret_provider=secret_provider)
        except RunnerTrustError:
            _cleanup_authenticated_creation_stage(staging)
        else:
            _validate_creation_recovery(
                staged,
                runner_id=runner_id,
                client_id=client_id,
                allowed_profile_ids=allowed_profile_ids,
                validity_days=validity_days,
            )
            _discard_stale_trust_temporary(staging)

    if not _path_entry_exists(staging):
        _populate_enrollment_stage(
            staging,
            runner_id=runner_id,
            client_id=client_id,
            allowed_profile_ids=allowed_profile_ids,
            validity_days=validity_days,
            secret_provider=secret_provider,
        )

    try:
        staged = load_local_enrollment(staging, secret_provider=secret_provider)
        _validate_creation_recovery(
            staged,
            runner_id=runner_id,
            client_id=client_id,
            allowed_profile_ids=allowed_profile_ids,
            validity_days=validity_days,
        )
        staging_identity = _directory_identity(staged.root)
        if any(_path_entry_exists(path) for path in (destination, tombstone, removal_intent)):
            raise RunnerTrustError("Enrollment creation state is inconsistent.")
        os.rename(staged.root, destination)
        _assert_directory_identity(destination, staging_identity)
        _sync_directory(destination.parent)
        enrolled = load_local_enrollment(destination, secret_provider=secret_provider)
        _unlink_transition_file(creation_intent)
        return enrolled
    except RunnerTrustError:
        raise
    except (OSError, SecretStoreError, TypeError, ValueError):
        raise RunnerTrustError("Enrollment could not be created.") from None


def _populate_enrollment_stage(
    staging: Path,
    *,
    runner_id: str,
    client_id: str,
    allowed_profile_ids: tuple[str, ...],
    validity_days: int,
    secret_provider: SecretProvider,
) -> None:
    created = False
    try:
        staging.mkdir(mode=0o700, exist_ok=False)
        created = True
        if _is_link_or_reparse(staging) or not staging.is_dir():
            raise RunnerTrustError("Enrollment directory is unavailable or unsafe.")
        with _PinnedDirectory(staging, private=True):
            pass
        _sync_directory(staging.parent)

        now = datetime.now(timezone.utc).replace(microsecond=0)
        not_before = now - timedelta(minutes=5)
        expires = now + timedelta(days=validity_days)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "BlueFire Local CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(expires)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )
        server_key, server_cert = _issue_leaf(
            ca_key=ca_key,
            ca_cert=ca_cert,
            common_name=runner_id,
            usage=ExtendedKeyUsageOID.SERVER_AUTH,
            not_before=not_before,
            not_after=expires,
            loopback_sans=True,
        )
        client_key, client_cert = _issue_leaf(
            ca_key=ca_key,
            ca_cert=ca_cert,
            common_name=client_id,
            usage=ExtendedKeyUsageOID.CLIENT_AUTH,
            not_before=not_before,
            not_after=expires,
            loopback_sans=False,
        )

        _write_certificate(staging / "ca-cert.pem", ca_cert)
        server_password = secrets.token_bytes(32)
        client_password = secrets.token_bytes(32)
        _write_private_key(staging / "server-key.pem", server_key, server_password)
        _write_certificate(staging / "server-cert.pem", server_cert)
        _write_private_key(staging / "client-key.pem", client_key, client_password)
        _write_certificate(staging / "client-cert.pem", client_cert)
        purposes = {
            "server-key-password.secret": "server-key-password",  # pragma: allowlist secret
            "client-key-password.secret": "client-key-password",  # pragma: allowlist secret
            "hmac.secret": "request-hmac",  # pragma: allowlist secret
        }
        plaintext = {
            "server-key-password.secret": server_password,
            "client-key-password.secret": client_password,
            "hmac.secret": secrets.token_bytes(_HMAC_KEY_BYTES),
        }
        for filename, purpose in purposes.items():
            protected = secret_provider.protect(
                _secret_purpose(runner_id, client_id, purpose),
                plaintext[filename],
            )
            _write_secret(staging / filename, protected)

        metadata = {
            "schema_version": TRUST_SCHEMA_VERSION,
            "runner_id": runner_id,
            "client_id": client_id,
            "allowed_profile_ids": list(allowed_profile_ids),
            "status": "active",
            "ca_fingerprint": certificate_fingerprint(ca_cert),
            "server_fingerprint": certificate_fingerprint(server_cert),
            "client_fingerprint": certificate_fingerprint(client_cert),
            "created_at": _timestamp(now),
            "expires_at": _timestamp(expires),
            "revoked_at": None,
            "secret_provider": secret_provider.provider_id,
        }
        _write_json(staging / "trust.json", metadata)
        _sync_directory(staging)
    except RunnerTrustError:
        if created:
            _cleanup_failed_creation(staging)
        raise
    except (OSError, SecretStoreError, TypeError, ValueError):
        if created:
            _cleanup_failed_creation(staging)
        raise RunnerTrustError("Enrollment could not be created.") from None


def load_local_enrollment(
    root: str | Path,
    *,
    require_active: bool = True,
    secret_provider: SecretProvider | None = None,
) -> RunnerEnrollment:
    """Load and cryptographically validate an enrollment without trusting paths in JSON."""

    try:
        return _load_local_enrollment(
            root,
            require_active=require_active,
            secret_provider=secret_provider,
        )
    except MemoryError:
        raise RunnerTrustError("Enrollment material is unavailable or unsafe.") from None


def _load_local_enrollment(
    root: str | Path,
    *,
    require_active: bool,
    secret_provider: SecretProvider | None,
    allow_revocation_recovery: bool = False,
) -> RunnerEnrollment:
    destination = _validated_enrollment_root(root)
    if not allow_revocation_recovery and _path_entry_exists(
        _transition_sibling(destination, _REVOCATION_INTENT_SUFFIX)
    ):
        raise RunnerTrustError("Enrollment revocation must be recovered before use.")
    try:
        materials = _read_enrollment_materials(destination)
        payload = materials["trust.json"]
        if not payload or len(payload) > _MAX_TRUST_BYTES:
            raise RunnerTrustError("Enrollment metadata exceeds its size limit.")
        metadata = json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_object)
    except RunnerTrustError:
        raise
    except (OSError, UnicodeDecodeError, ValueError):
        raise RunnerTrustError("Enrollment metadata is unavailable or invalid.") from None
    if not isinstance(metadata, dict) or set(metadata) != _TRUST_FIELDS:
        raise RunnerTrustError("Enrollment metadata has an unsupported shape.")
    _validate_metadata(metadata)
    provider = _secret_provider(secret_provider)
    if metadata["secret_provider"] != provider.provider_id:
        raise RunnerTrustError("Enrollment secret provider is incompatible.")
    if require_active and metadata["status"] != "active":
        raise RunnerTrustError("Enrollment is not active.")

    try:
        ca_cert = x509.load_pem_x509_certificate(materials["ca-cert.pem"])
        server_cert = x509.load_pem_x509_certificate(materials["server-cert.pem"])
        client_cert = x509.load_pem_x509_certificate(materials["client-cert.pem"])
        server_password = provider.unprotect(
            _secret_purpose(metadata["runner_id"], metadata["client_id"], "server-key-password"),
            materials["server-key-password.secret"],
        )
        client_password = provider.unprotect(
            _secret_purpose(metadata["runner_id"], metadata["client_id"], "client-key-password"),
            materials["client-key-password.secret"],
        )
        hmac_key = provider.unprotect(
            _secret_purpose(metadata["runner_id"], metadata["client_id"], "request-hmac"),
            materials["hmac.secret"],
        )
        server_key = _read_private_key_bytes(materials["server-key.pem"], server_password)
        client_key = _read_private_key_bytes(materials["client-key.pem"], client_password)
        if len(hmac_key) != _HMAC_KEY_BYTES:
            raise ValueError("invalid authentication key")
        _validate_certificates(
            metadata,
            ca_cert=ca_cert,
            server_cert=server_cert,
            client_cert=client_cert,
            server_key=server_key,
            client_key=client_key,
            require_current_validity=require_active,
        )
    except RunnerTrustError:
        raise
    except (OSError, TypeError, ValueError, x509.ExtensionNotFound, SecretStoreError):
        raise RunnerTrustError("Enrollment cryptographic material is invalid.") from None
    return RunnerEnrollment(
        root=destination.resolve(strict=True),
        metadata=dict(metadata),
        secret_provider=provider,
    )


def enrollment_status(
    root: str | Path, *, secret_provider: SecretProvider | None = None
) -> Mapping[str, Any]:
    """Return validated, secret-free status suitable for a management surface."""

    enrollment = load_local_enrollment(root, require_active=False, secret_provider=secret_provider)
    status = dict(enrollment.metadata)
    if status["status"] == "active" and datetime.now(timezone.utc) >= _parse_timestamp(
        status["expires_at"]
    ):
        status["status"] = "expired"
    return status


def local_enrollment_creation_path(root: str | Path) -> Path:
    """Return the validated deterministic staging path without changing storage."""

    destination = _canonical_transition_path(root, create_parent=False)
    staging = _transition_sibling(destination, _CREATION_SUFFIX)
    for candidate in (destination, staging):
        if _path_entry_exists(candidate) and (
            _is_link_or_reparse(candidate) or not candidate.is_dir()
        ):
            raise RunnerTrustError("Enrollment directory is unavailable or unsafe.")
    return staging


def revoke_local_enrollment(
    root: str | Path, *, secret_provider: SecretProvider | None = None
) -> RunnerEnrollment:
    """Durably revoke an enrollment with authenticated, fail-closed recovery."""

    try:
        destination = _canonical_transition_path(root, create_parent=False)
        with _enrollment_transition_lock(destination):
            conflicting_transitions = (
                _transition_sibling(destination, _CREATION_SUFFIX),
                _transition_sibling(destination, _CREATION_INTENT_SUFFIX),
                _transition_sibling(destination, _REMOVAL_SUFFIX),
                _transition_sibling(destination, _REMOVAL_INTENT_SUFFIX),
            )
            if any(_path_entry_exists(path) for path in conflicting_transitions):
                raise RunnerTrustError("Enrollment transition must be recovered before revocation.")
            intent_path = _transition_sibling(destination, _REVOCATION_INTENT_SUFFIX)
            provider = _secret_provider(secret_provider)
            if _path_entry_exists(intent_path):
                intent = _load_transition_intent(
                    intent_path,
                    destination=destination,
                    operation="revoke",
                    secret_provider=provider,
                )
                return _recover_revocation_from_intent(
                    destination,
                    intent_path=intent_path,
                    intent=intent,
                    secret_provider=provider,
                )
            enrollment = load_local_enrollment(
                destination,
                require_active=False,
                secret_provider=secret_provider,
            )
            if enrollment.status == "revoked":
                return enrollment
            _discard_stale_trust_temporary(enrollment.root)
            with _pinned_regular_update(
                enrollment.trust_file,
                maximum=_MAX_TRUST_BYTES,
            ) as target:
                # Revalidate the enrollment while the exact metadata file is pinned.
                enrollment = load_local_enrollment(
                    destination,
                    require_active=False,
                    secret_provider=secret_provider,
                )
                if enrollment.status == "revoked":
                    return enrollment
                metadata = dict(enrollment.metadata)
                metadata["status"] = "revoked"
                metadata["revoked_at"] = _timestamp(
                    datetime.now(timezone.utc).replace(microsecond=0)
                )
                payload = canonical_json_bytes(metadata) + b"\n"
                if not payload or len(payload) > _MAX_TRUST_BYTES:
                    raise RunnerTrustError("Enrollment metadata exceeds its size limit.")
                provider = enrollment.secret_provider
                _write_transition_intent(
                    intent_path,
                    destination=destination,
                    operation="revoke",
                    runner_id=enrollment.runner_id,
                    client_id=enrollment.client_id,
                    secret_provider=provider,
                    payload={
                        "trust_device": target.identity[0],
                        "trust_inode": target.identity[1],
                        "revoked_metadata": metadata,
                    },
                )
                target.write(payload)
            return _validate_completed_revocation(
                destination,
                intent_path=intent_path,
                metadata=metadata,
                secret_provider=provider,
            )
    except RunnerTrustError:
        raise
    except (MemoryError, OSError, SecretStoreError, TypeError, ValueError):
        raise RunnerTrustError("Enrollment could not be revoked.") from None


def remove_local_enrollment(
    root: str | Path,
    *,
    secret_provider: SecretProvider | None = None,
    confirm_runner_id: str | None = None,
) -> None:
    """Permanently remove only a validated, flat enrollment directory.

    A damaged enrollment can still be removed when its runner identity is
    explicitly confirmed and recoverable from public metadata or certificate.
    """

    confirmed = (
        _identifier(confirm_runner_id, "runner identity") if confirm_runner_id is not None else None
    )
    try:
        destination = _canonical_transition_path(root, create_parent=False)
        with _enrollment_transition_lock(destination):
            _remove_local_enrollment_locked(
                destination,
                secret_provider=_secret_provider(secret_provider),
                confirmed=confirmed,
            )
    except RunnerTrustError:
        raise
    except (MemoryError, OSError, SecretStoreError, TypeError, ValueError):
        raise RunnerTrustError("Enrollment could not be removed.") from None


def _remove_local_enrollment_locked(
    destination: Path,
    *,
    secret_provider: SecretProvider,
    confirmed: str | None,
) -> None:
    tombstone = _transition_sibling(destination, _REMOVAL_SUFFIX)
    intent_path = _transition_sibling(destination, _REMOVAL_INTENT_SUFFIX)
    creation_paths = (
        _transition_sibling(destination, _CREATION_SUFFIX),
        _transition_sibling(destination, _CREATION_INTENT_SUFFIX),
        _transition_sibling(destination, _REVOCATION_INTENT_SUFFIX),
    )
    if any(_path_entry_exists(path) for path in creation_paths):
        raise RunnerTrustError("Enrollment transition must be recovered before removal.")

    destination_exists = _path_entry_exists(destination)
    tombstone_exists = _path_entry_exists(tombstone)
    intent_exists = _path_entry_exists(intent_path)
    if destination_exists and tombstone_exists:
        raise RunnerTrustError("Enrollment removal state is inconsistent.")

    intent: Mapping[str, Any] | None = None
    if intent_exists:
        intent = _load_transition_intent(
            intent_path,
            destination=destination,
            operation="remove",
            secret_provider=secret_provider,
        )
        journal_runner = _identifier(intent.get("runner_id"), "runner identity")
        journal_identity = _removal_intent_identity(intent)
        if confirmed is not None and confirmed != journal_runner:
            raise RunnerTrustError("Enrollment removal confirmation does not match.")
    else:
        journal_runner = None
        journal_identity = None

    if not destination_exists and not tombstone_exists:
        if intent is not None:
            _unlink_transition_file(intent_path)
            return
        if confirmed is not None:
            return
        raise RunnerTrustError("Enrollment directory is unavailable or unsafe.")

    tombstone_identity: tuple[int, int]
    if destination_exists:
        try:
            enrollment = load_local_enrollment(
                destination,
                require_active=False,
                secret_provider=secret_provider,
            )
            removal_identity = enrollment.runner_id
            if confirmed is not None and removal_identity != confirmed:
                raise RunnerTrustError("Enrollment removal confirmation does not match.")
            validated_root, entries, directory_identity = _validated_removal_root(enrollment.root)
        except RunnerTrustError:
            effective_confirmation = confirmed or journal_runner
            if effective_confirmation is None:
                raise
            validated_root, entries, directory_identity = _validated_removal_root(destination)
            if intent is None and (
                not entries
                or effective_confirmation not in _public_removal_identities(validated_root)
            ):
                raise RunnerTrustError("Enrollment removal confirmation does not match.") from None
            removal_identity = effective_confirmation

        if journal_runner is not None and journal_runner != removal_identity:
            raise RunnerTrustError("Enrollment removal confirmation does not match.")
        if journal_identity is not None and journal_identity != directory_identity:
            raise RunnerTrustError("Enrollment directory is unavailable or unsafe.")
        if intent is None:
            _write_transition_intent(
                intent_path,
                destination=destination,
                operation="remove",
                runner_id=removal_identity,
                client_id="local-removal.v1",
                secret_provider=secret_provider,
                payload={
                    "runner_id": removal_identity,
                    "directory_device": directory_identity[0],
                    "directory_inode": directory_identity[1],
                },
            )
        if _path_entry_exists(tombstone):
            raise RunnerTrustError("Enrollment removal state is inconsistent.")
        _assert_directory_identity(validated_root, directory_identity)
        os.rename(validated_root, tombstone)
        _assert_directory_identity(tombstone, directory_identity)
        _sync_directory(tombstone.parent)
        tombstone_identity = directory_identity
    else:
        validated_tombstone, entries, tombstone_identity = _validated_removal_root(tombstone)
        if journal_identity is not None and journal_identity != tombstone_identity:
            raise RunnerTrustError("Enrollment directory is unavailable or unsafe.")
        if journal_runner is None:
            if confirmed is None:
                try:
                    enrollment = load_local_enrollment(
                        validated_tombstone,
                        require_active=False,
                        secret_provider=secret_provider,
                    )
                except RunnerTrustError:
                    raise RunnerTrustError("Enrollment removal confirmation is required.") from None
                removal_identity = enrollment.runner_id
            else:
                if entries and confirmed not in _public_removal_identities(validated_tombstone):
                    raise RunnerTrustError(
                        "Enrollment removal confirmation does not match."
                    ) from None
                removal_identity = confirmed
            _write_transition_intent(
                intent_path,
                destination=destination,
                operation="remove",
                runner_id=removal_identity,
                client_id="local-removal.v1",
                secret_provider=secret_provider,
                payload={
                    "runner_id": removal_identity,
                    "directory_device": tombstone_identity[0],
                    "directory_inode": tombstone_identity[1],
                },
            )
        else:
            removal_identity = journal_runner

    _cleanup_removal_tombstone(
        tombstone,
        runner_id=removal_identity,
        directory_identity=tombstone_identity,
    )
    _unlink_transition_file(intent_path)


def _canonical_transition_path(root: str | Path, *, create_parent: bool) -> Path:
    supplied = Path(root).expanduser()
    if not supplied.name or supplied.name in {".", ".."}:
        raise RunnerTrustError("Enrollment directory is unavailable or unsafe.")
    lexical = supplied if supplied.is_absolute() else Path.cwd() / supplied
    candidate = Path(os.path.abspath(lexical))
    if lexical != candidate:
        raise RunnerTrustError("Enrollment directory is unavailable or unsafe.")
    try:
        _assert_existing_ancestors_safe(candidate.parent)
        if create_parent:
            candidate.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not candidate.parent.is_dir():
            if create_parent:
                raise RunnerTrustError("Enrollment directory is unavailable or unsafe.")
            return candidate
        parent = candidate.parent.resolve(strict=True)
    except OSError:
        raise RunnerTrustError("Enrollment directory is unavailable or unsafe.") from None
    if parent != candidate.parent:
        raise RunnerTrustError("Enrollment directory is unavailable or unsafe.")
    _assert_existing_ancestors_safe(parent)
    return parent / candidate.name


def _transition_sibling(destination: Path, suffix: str) -> Path:
    return destination.with_name(f".{destination.name}{suffix}")


@contextmanager
def _enrollment_transition_lock(destination: Path) -> Iterator[None]:
    lock_path = _transition_sibling(destination, _TRANSITION_LOCK_SUFFIX)
    key = os.path.normcase(str(lock_path))
    with _LOCAL_TRANSITION_LOCKS_GUARD:
        local_lock = _LOCAL_TRANSITION_LOCKS.setdefault(key, threading.RLock())
    with local_lock:
        existed = _path_entry_exists(lock_path)
        try:
            descriptor = _open_transition_lock_descriptor(lock_path)
        except (OSError, RunnerTrustError):
            raise RunnerTrustError("Enrollment transition lock is unavailable.") from None
        locked = False
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
                raise RunnerTrustError("Enrollment transition lock is unavailable.")
            if details.st_size == 0:
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                while True:
                    try:
                        msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                        break
                    except OSError as error:
                        if error.errno not in {
                            errno.EACCES,
                            errno.EAGAIN,
                            getattr(errno, "EDEADLK", errno.EACCES),
                        }:
                            raise
                        time.sleep(0.05)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX)  # type: ignore[attr-defined]
            locked = True
            if not existed:
                _sync_directory(lock_path.parent)
        except RunnerTrustError:
            os.close(descriptor)
            raise
        except OSError:
            os.close(descriptor)
            raise RunnerTrustError("Enrollment transition lock is unavailable.") from None
        try:
            yield
        finally:
            if locked:
                try:
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    if os.name == "nt":
                        import msvcrt

                        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(descriptor, fcntl.LOCK_UN)  # type: ignore[attr-defined]
                except OSError:
                    pass
            os.close(descriptor)


def _root_digest(destination: Path) -> str:
    canonical = os.path.normcase(str(destination))
    return hashlib.sha256(os.fsencode(canonical)).hexdigest()


def _intent_purpose(
    operation: str,
    destination: Path,
    runner_id: str,
    client_id: str,
) -> str:
    return (
        f"bluefire.runner-trust-intent.v1:{operation}:{_root_digest(destination)}:"
        f"{runner_id}:{client_id}"
    )


def _write_transition_intent(
    path: Path,
    *,
    destination: Path,
    operation: str,
    runner_id: str,
    client_id: str,
    secret_provider: SecretProvider,
    payload: Mapping[str, Any],
) -> None:
    if operation not in {"create", "revoke", "remove"}:
        raise RunnerTrustError("Enrollment transition intent is invalid.")
    checked_runner = _identifier(runner_id, "runner identity")
    checked_client = _identifier(client_id, "client identity")
    digest = _root_digest(destination)
    protected_payload = {
        "schema_version": _INTENT_SCHEMA_VERSION,
        "operation": operation,
        "runner_id": checked_runner,
        "client_id": checked_client,
        "root_digest": digest,
        "payload": dict(payload),
        "nonce": secrets.token_hex(16),
    }
    try:
        protected = secret_provider.protect(
            _intent_purpose(operation, destination, checked_runner, checked_client),
            canonical_json_bytes(protected_payload),
        )
        envelope = {
            "schema_version": _INTENT_SCHEMA_VERSION,
            "operation": operation,
            "runner_id": checked_runner,
            "client_id": checked_client,
            "root_digest": digest,
            "secret_provider": secret_provider.provider_id,
            "protected_payload": base64.b64encode(protected).decode("ascii"),
        }
        encoded = canonical_json_bytes(envelope) + b"\n"
        if not encoded or len(encoded) > _MAX_TRUST_BYTES:
            raise RunnerTrustError("Enrollment transition intent exceeds its size limit.")
        _write_secret(path, encoded)
        _sync_directory(path.parent)
    except RunnerTrustError:
        raise
    except (MemoryError, OSError, SecretStoreError, TypeError, ValueError):
        raise RunnerTrustError("Enrollment transition intent could not be persisted.") from None


def _load_transition_intent(
    path: Path,
    *,
    destination: Path,
    operation: str,
    secret_provider: SecretProvider,
    expected: Mapping[str, Any] | None = None,
) -> Mapping[str, Any]:
    try:
        raw = _bounded_regular_read(path, _MAX_TRUST_BYTES)
        envelope = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
        if not isinstance(envelope, dict) or set(envelope) != _INTENT_FIELDS:
            raise RunnerTrustError("Enrollment transition intent is invalid.")
        runner_id = _identifier(envelope.get("runner_id"), "runner identity")
        client_id = _identifier(envelope.get("client_id"), "client identity")
        digest = _root_digest(destination)
        if (
            envelope.get("schema_version") != _INTENT_SCHEMA_VERSION
            or envelope.get("operation") != operation
            or envelope.get("root_digest") != digest
            or envelope.get("secret_provider") != secret_provider.provider_id
            or not isinstance(envelope.get("protected_payload"), str)
        ):
            raise RunnerTrustError("Enrollment transition intent is invalid.")
        opaque = base64.b64decode(envelope["protected_payload"], validate=True)
        plaintext = secret_provider.unprotect(
            _intent_purpose(operation, destination, runner_id, client_id),
            opaque,
        )
        if not plaintext or len(plaintext) > _MAX_TRUST_BYTES:
            raise RunnerTrustError("Enrollment transition intent is invalid.")
        body = json.loads(plaintext.decode("utf-8"), object_pairs_hook=_strict_object)
        if not isinstance(body, dict) or set(body) != {
            "schema_version",
            "operation",
            "runner_id",
            "client_id",
            "root_digest",
            "payload",
            "nonce",
        }:
            raise RunnerTrustError("Enrollment transition intent is invalid.")
        if (
            body.get("schema_version") != _INTENT_SCHEMA_VERSION
            or body.get("operation") != operation
            or body.get("runner_id") != runner_id
            or body.get("client_id") != client_id
            or body.get("root_digest") != digest
            or not isinstance(body.get("payload"), dict)
            or not isinstance(body.get("nonce"), str)
            or len(body["nonce"]) != 32
        ):
            raise RunnerTrustError("Enrollment transition intent is invalid.")
        if expected is not None and body["payload"] != dict(expected):
            raise RunnerTrustError("Enrollment creation recovery does not match.")
        return body
    except RunnerTrustError:
        raise
    except (MemoryError, OSError, SecretStoreError, UnicodeError, ValueError):
        raise RunnerTrustError("Enrollment transition intent is invalid.") from None


def _removal_intent_identity(intent: Mapping[str, Any]) -> tuple[int, int]:
    payload = intent.get("payload")
    if not isinstance(payload, dict) or set(payload) != {
        "runner_id",
        "directory_device",
        "directory_inode",
    }:
        raise RunnerTrustError("Enrollment transition intent is invalid.")
    if payload.get("runner_id") != intent.get("runner_id"):
        raise RunnerTrustError("Enrollment transition intent is invalid.")
    device = payload.get("directory_device")
    inode = payload.get("directory_inode")
    if (
        isinstance(device, bool)
        or not isinstance(device, int)
        or device < 0
        or isinstance(inode, bool)
        or not isinstance(inode, int)
        or inode < 0
    ):
        raise RunnerTrustError("Enrollment transition intent is invalid.")
    return device, inode


def _revocation_intent_details(
    intent: Mapping[str, Any],
) -> tuple[tuple[int, int], dict[str, Any]]:
    payload = intent.get("payload")
    if not isinstance(payload, dict) or set(payload) != {
        "trust_device",
        "trust_inode",
        "revoked_metadata",
    }:
        raise RunnerTrustError("Enrollment transition intent is invalid.")
    device = payload.get("trust_device")
    inode = payload.get("trust_inode")
    metadata = payload.get("revoked_metadata")
    if (
        isinstance(device, bool)
        or not isinstance(device, int)
        or device < 0
        or isinstance(inode, bool)
        or not isinstance(inode, int)
        or inode < 0
        or not isinstance(metadata, dict)
        or set(metadata) != _TRUST_FIELDS
    ):
        raise RunnerTrustError("Enrollment transition intent is invalid.")
    checked_metadata = dict(metadata)
    _validate_metadata(checked_metadata)
    if (
        checked_metadata.get("status") != "revoked"
        or checked_metadata.get("runner_id") != intent.get("runner_id")
        or checked_metadata.get("client_id") != intent.get("client_id")
        or checked_metadata.get("revoked_at") is None
    ):
        raise RunnerTrustError("Enrollment transition intent is invalid.")
    encoded = canonical_json_bytes(checked_metadata) + b"\n"
    if not encoded or len(encoded) > _MAX_TRUST_BYTES:
        raise RunnerTrustError("Enrollment transition intent is invalid.")
    return (device, inode), checked_metadata


def _recover_revocation_from_intent(
    destination: Path,
    *,
    intent_path: Path,
    intent: Mapping[str, Any],
    secret_provider: SecretProvider,
) -> RunnerEnrollment:
    expected_identity, metadata = _revocation_intent_details(intent)
    with _pinned_regular_update(
        destination / "trust.json",
        maximum=_MAX_TRUST_BYTES,
    ) as target:
        if target.identity != expected_identity:
            raise RunnerTrustError("Enrollment metadata identity changed during revocation.")
        target.write(canonical_json_bytes(metadata) + b"\n")
    return _validate_completed_revocation(
        destination,
        intent_path=intent_path,
        metadata=metadata,
        secret_provider=secret_provider,
    )


def _validate_completed_revocation(
    destination: Path,
    *,
    intent_path: Path,
    metadata: Mapping[str, Any],
    secret_provider: SecretProvider,
) -> RunnerEnrollment:
    enrollment = _load_local_enrollment(
        destination,
        require_active=False,
        secret_provider=secret_provider,
        allow_revocation_recovery=True,
    )
    if enrollment.status != "revoked" or enrollment.metadata != dict(metadata):
        raise RunnerTrustError("Enrollment revocation recovery did not match.")
    _unlink_transition_file(intent_path)
    return enrollment


def _unlink_transition_file(path: Path) -> None:
    if not _path_entry_exists(path):
        return
    with _PinnedDirectory(path.parent, private=False) as directory:
        directory.unlink(path.name, maximum=_MAX_TRUST_BYTES)
        directory.sync()


def _windows_kernel_functions() -> tuple[Any, Any, Any, Any]:
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        create_file.restype = wintypes.HANDLE
        get_information = kernel32.GetFileInformationByHandle
        get_information.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_WindowsFileInformation),
        ]
        get_information.restype = wintypes.BOOL
        set_information = kernel32.SetFileInformationByHandle
        set_information.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        set_information.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
    except (AttributeError, OSError, TypeError):
        raise RunnerTrustError("Enrollment pinned storage is unavailable.") from None
    return create_file, get_information, set_information, close_handle


def _windows_open_pinned(
    path: Path,
    *,
    directory: bool,
    delete: bool,
    write: bool = False,
    write_dac: bool = False,
    share_write: bool = True,
) -> int:
    create_file, _, _, _ = _windows_kernel_functions()
    access = (
        _WINDOWS_GENERIC_READ
        | (_WINDOWS_GENERIC_WRITE if write else 0)
        | (_WINDOWS_DELETE if delete else 0)
        | (_WINDOWS_WRITE_DAC if write_dac else 0)
    )
    flags = _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS
    handle = create_file(
        str(path),
        access,
        _WINDOWS_FILE_SHARE_READ | (_WINDOWS_FILE_SHARE_WRITE if share_write else 0),
        None,
        _WINDOWS_OPEN_EXISTING,
        flags,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    raw = ctypes.cast(handle, ctypes.c_void_p).value
    if raw is None or raw == invalid:
        raise RunnerTrustError("Enrollment pinned storage is unavailable.")
    return int(raw)


def _windows_create_pinned(path: Path) -> int:
    create_file, _, _, _ = _windows_kernel_functions()
    handle = create_file(
        str(path),
        _WINDOWS_GENERIC_READ | _WINDOWS_GENERIC_WRITE | _WINDOWS_DELETE | _WINDOWS_WRITE_DAC,
        _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE,
        None,
        _WINDOWS_CREATE_NEW,
        _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    raw = ctypes.cast(handle, ctypes.c_void_p).value
    if raw is None or raw == invalid:
        raise RunnerTrustError("Enrollment material could not be written safely.")
    return int(raw)


def _windows_file_information(handle: int) -> _WindowsFileInformation:
    _, get_information, _, _ = _windows_kernel_functions()
    information = _WindowsFileInformation()
    if not get_information(wintypes.HANDLE(handle), ctypes.byref(information)):
        raise RunnerTrustError("Enrollment pinned storage is unavailable.")
    return information


def _windows_information_identity(information: _WindowsFileInformation) -> tuple[int, int]:
    file_index = (int(information.nFileIndexHigh) << 32) | int(information.nFileIndexLow)
    return int(information.dwVolumeSerialNumber), file_index


def _windows_mark_delete(handle: int) -> None:
    _, _, set_information, _ = _windows_kernel_functions()
    disposition = _WindowsFileDisposition(True)
    if not set_information(
        wintypes.HANDLE(handle),
        _WINDOWS_FILE_DISPOSITION_INFO,
        ctypes.byref(disposition),
        ctypes.sizeof(disposition),
    ):
        raise RunnerTrustError("Enrollment material could not be removed safely.")


def _windows_close_handle(handle: int) -> None:
    _, _, _, close_handle = _windows_kernel_functions()
    close_handle(wintypes.HANDLE(handle))


@dataclass
class _PinnedRegularUpdate:
    path: Path
    descriptor: int
    identity: tuple[int, int]
    maximum: int
    parent_descriptor: int | None = None

    def write(self, payload: bytes) -> None:
        if not payload or len(payload) > self.maximum:
            raise RunnerTrustError("Enrollment metadata exceeds its size limit.")
        try:
            os.lseek(self.descriptor, 0, os.SEEK_SET)
            os.ftruncate(self.descriptor, 0)
            _write_descriptor_all(self.descriptor, payload)
            os.ftruncate(self.descriptor, len(payload))
            os.fsync(self.descriptor)
            if os.name == "nt":
                import msvcrt

                information = _validate_windows_regular_information(
                    _windows_file_information(msvcrt.get_osfhandle(self.descriptor)),
                    maximum=self.maximum,
                )
                if _windows_information_identity(information) != self.identity or (
                    (int(information.nFileSizeHigh) << 32) | int(information.nFileSizeLow)
                ) != len(payload):
                    raise RunnerTrustError("Enrollment metadata changed during revocation.")
                return

            details = _validate_posix_regular_descriptor(
                self.descriptor,
                maximum=self.maximum,
            )
            if (
                (details.st_dev, details.st_ino) != self.identity
                or details.st_size != len(payload)
                or self.parent_descriptor is None
            ):
                raise RunnerTrustError("Enrollment metadata changed during revocation.")
            current = os.stat(
                self.path.name,
                dir_fd=self.parent_descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_nlink != 1
                or (current.st_dev, current.st_ino) != self.identity
            ):
                raise RunnerTrustError("Enrollment metadata changed during revocation.")
            _sync_descriptor(self.parent_descriptor)
        except RunnerTrustError:
            raise
        except (MemoryError, OSError):
            raise RunnerTrustError("Enrollment metadata could not be updated safely.") from None


@contextmanager
def _pinned_regular_update(
    path: Path,
    *,
    maximum: int,
) -> Iterator[_PinnedRegularUpdate]:
    if os.name == "nt":
        handle = -1
        descriptor: int | None = None
        try:
            handle = _windows_open_pinned(
                path,
                directory=False,
                delete=False,
                write=True,
                write_dac=True,
            )
            information = _validate_windows_regular_information(
                _windows_file_information(handle),
                maximum=maximum,
            )
            identity = _windows_information_identity(information)
            _owner_private_native_handle(handle, directory=False)
            final = _validate_windows_regular_information(
                _windows_file_information(handle),
                maximum=maximum,
            )
            if _windows_information_identity(final) != identity:
                raise RunnerTrustError("Enrollment metadata changed during revocation.")
            import msvcrt

            descriptor = msvcrt.open_osfhandle(
                handle,
                os.O_RDWR | getattr(os, "O_BINARY", 0),
            )
            handle = -1
        except RunnerTrustError:
            if descriptor is not None:
                os.close(descriptor)
            if handle != -1:
                _windows_close_handle(handle)
            raise
        except (MemoryError, OSError):
            if descriptor is not None:
                os.close(descriptor)
            if handle != -1:
                _windows_close_handle(handle)
            raise RunnerTrustError("Enrollment metadata could not be pinned safely.") from None
        try:
            yield _PinnedRegularUpdate(path, descriptor, identity, maximum)
        finally:
            os.close(descriptor)
        return

    parent_descriptor: int | None = None
    descriptor = None
    try:
        parent_descriptor = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        descriptor = os.open(
            path.name,
            os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        details = _validate_posix_regular_descriptor(descriptor, maximum=maximum)
        identity = details.st_dev, details.st_ino
        _posix_fchmod(descriptor, 0o600)
        current = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or (current.st_dev, current.st_ino) != identity
        ):
            raise RunnerTrustError("Enrollment metadata changed during revocation.")
    except RunnerTrustError:
        if descriptor is not None:
            os.close(descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        raise
    except (MemoryError, OSError):
        if descriptor is not None:
            os.close(descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        raise RunnerTrustError("Enrollment metadata could not be pinned safely.") from None
    try:
        yield _PinnedRegularUpdate(
            path,
            descriptor,
            identity,
            maximum,
            parent_descriptor,
        )
    finally:
        os.close(descriptor)
        os.close(parent_descriptor)


class _PinnedDirectory:
    """Pin one exact directory while bounded child operations are performed."""

    def __init__(self, path: Path, *, private: bool, delete: bool = False) -> None:
        self.path = path
        self.private = private
        self.delete = delete
        self._descriptor: int | None = None
        self._parent_descriptor: int | None = None
        self._handle: int | None = None
        self._identity: tuple[int, int] | None = None
        self._delete_marked = False

    @property
    def identity(self) -> tuple[int, int]:
        if self._identity is None:
            raise RunnerTrustError("Enrollment pinned storage is unavailable.")
        return self._identity

    def __enter__(self) -> _PinnedDirectory:
        if os.name == "nt":
            try:
                self._handle = _windows_open_pinned(
                    self.path,
                    directory=True,
                    delete=self.delete,
                    write_dac=self.private,
                )
                information = _windows_file_information(self._handle)
                attributes = int(information.dwFileAttributes)
                if (
                    not attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY
                    or attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
                ):
                    raise RunnerTrustError("Enrollment directory is unavailable or unsafe.")
                self._identity = _windows_information_identity(information)
                if self.private:
                    _owner_private_native_handle(self._handle, directory=True)
                if (
                    _windows_information_identity(_windows_file_information(self._handle))
                    != self.identity
                ):
                    raise RunnerTrustError("Enrollment directory is unavailable or unsafe.")
                return self
            except RunnerTrustError:
                self.close()
                raise
            except OSError:
                self.close()
                raise RunnerTrustError("Enrollment directory is unavailable or unsafe.") from None

        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            self._parent_descriptor = os.open(
                self.path.parent,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            self._descriptor = os.open(
                self.path.name,
                flags,
                dir_fd=self._parent_descriptor,
            )
            details = os.fstat(self._descriptor)
            if not stat.S_ISDIR(details.st_mode):
                raise RunnerTrustError("Enrollment directory is unavailable or unsafe.")
            self._identity = details.st_dev, details.st_ino
            if self.private:
                getuid = getattr(os, "getuid", None)
                if callable(getuid) and details.st_uid != getuid():
                    raise RunnerTrustError("Enrollment material is not owned by this user.")
                _posix_fchmod(self._descriptor, 0o700)
                details = os.fstat(self._descriptor)
                if stat.S_IMODE(details.st_mode) != 0o700:
                    raise RunnerTrustError("Enrollment permissions could not be restricted.")
            return self
        except RunnerTrustError:
            self.close()
            raise
        except OSError:
            self.close()
            raise RunnerTrustError("Enrollment directory is unavailable or unsafe.") from None

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        if self._handle is not None:
            _windows_close_handle(self._handle)
            self._handle = None
        if self._descriptor is not None:
            os.close(self._descriptor)
            self._descriptor = None
        if self._parent_descriptor is not None:
            os.close(self._parent_descriptor)
            self._parent_descriptor = None

    def names(self) -> tuple[str, ...]:
        try:
            if os.name == "nt":
                return tuple(entry.name for entry in self.path.iterdir())
            if self._descriptor is None:
                raise RunnerTrustError("Enrollment pinned storage is unavailable.")
            return tuple(os.listdir(self._descriptor))
        except RunnerTrustError:
            raise
        except OSError:
            raise RunnerTrustError("Enrollment directory is unavailable or unsafe.") from None

    def create(self, name: str, payload: bytes) -> tuple[int, int]:
        if not name or Path(name).name != name or len(payload) > _MAX_MATERIAL_BYTES:
            raise RunnerTrustError("Enrollment material could not be written safely.")
        if os.name == "nt":
            handle = _windows_create_pinned(self.path / name)
            try:
                windows_initial = _validate_windows_regular_information(
                    _windows_file_information(handle),
                    maximum=_MAX_MATERIAL_BYTES,
                )
                identity = _windows_information_identity(windows_initial)
                import msvcrt

                descriptor = msvcrt.open_osfhandle(
                    handle,
                    os.O_RDWR | getattr(os, "O_BINARY", 0),
                )
                handle = -1
                try:
                    _write_descriptor_all(descriptor, payload)
                    os.fsync(descriptor)
                    _owner_private_handle(descriptor, directory=False)
                    windows_final = _windows_file_information(msvcrt.get_osfhandle(descriptor))
                    _validate_windows_regular_information(
                        windows_final,
                        maximum=_MAX_MATERIAL_BYTES,
                    )
                    if _windows_information_identity(windows_final) != identity or (
                        (int(windows_final.nFileSizeHigh) << 32) | int(windows_final.nFileSizeLow)
                    ) != len(payload):
                        raise RunnerTrustError("Enrollment material could not be written safely.")
                    return identity
                finally:
                    os.close(descriptor)
            finally:
                if handle != -1:
                    _windows_close_handle(handle)

        if self._descriptor is None:
            raise RunnerTrustError("Enrollment pinned storage is unavailable.")
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=self._descriptor)
            try:
                posix_initial = _validate_posix_regular_descriptor(
                    descriptor,
                    maximum=_MAX_MATERIAL_BYTES,
                )
                identity = posix_initial.st_dev, posix_initial.st_ino
                _posix_fchmod(descriptor, 0o600)
                _write_descriptor_all(descriptor, payload)
                os.fsync(descriptor)
                posix_final = _validate_posix_regular_descriptor(
                    descriptor,
                    maximum=_MAX_MATERIAL_BYTES,
                )
                if (
                    (posix_final.st_dev, posix_final.st_ino) != identity
                    or posix_final.st_size != len(payload)
                    or stat.S_IMODE(posix_final.st_mode) != 0o600
                ):
                    raise RunnerTrustError("Enrollment material could not be written safely.")
                return identity
            finally:
                os.close(descriptor)
        except RunnerTrustError:
            raise
        except (MemoryError, OSError):
            raise RunnerTrustError("Enrollment material could not be written safely.") from None

    def read_with_identity(
        self,
        name: str,
        *,
        maximum: int,
        exclusive: bool = False,
    ) -> tuple[bytes, tuple[int, int], tuple[int, int, int, int, int]]:
        """Read one exact owner-bound file and return its handle-derived identity."""

        if not name or Path(name).name != name:
            raise RunnerTrustError("Enrollment material is unavailable or unsafe.")
        if os.name == "nt":
            handle = _windows_open_pinned(
                self.path / name,
                directory=False,
                delete=False,
                write_dac=True,
                share_write=not exclusive,
            )
            try:
                windows_initial = _validate_windows_regular_information(
                    _windows_file_information(handle), maximum=maximum
                )
                identity = _windows_information_identity(windows_initial)
                initial_write_time = (
                    int(windows_initial.ftLastWriteTime.dwHighDateTime) << 32
                ) | int(windows_initial.ftLastWriteTime.dwLowDateTime)
                _owner_private_native_handle(handle, directory=False)
                if _windows_information_identity(_windows_file_information(handle)) != identity:
                    raise RunnerTrustError("Enrollment material is unavailable or unsafe.")
                import msvcrt

                descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | getattr(os, "O_BINARY", 0))
                handle = -1
                try:
                    stat_initial = os.fstat(descriptor)
                    payload = _read_descriptor_bounded(descriptor, maximum)
                    stat_final = os.fstat(descriptor)
                    windows_final = _validate_windows_regular_information(
                        _windows_file_information(msvcrt.get_osfhandle(descriptor)),
                        maximum=maximum,
                    )
                    final_write_time = (
                        int(windows_final.ftLastWriteTime.dwHighDateTime) << 32
                    ) | int(windows_final.ftLastWriteTime.dwLowDateTime)
                    final_size = (int(windows_final.nFileSizeHigh) << 32) | int(
                        windows_final.nFileSizeLow
                    )
                    if (
                        _windows_information_identity(windows_final) != identity
                        or final_write_time != initial_write_time
                        or final_size != len(payload)
                        or not stat.S_ISREG(stat_final.st_mode)
                        or stat_final.st_nlink != 1
                        or (
                            stat_initial.st_dev,
                            stat_initial.st_ino,
                            stat_initial.st_mode,
                            stat_initial.st_size,
                            stat_initial.st_mtime_ns,
                        )
                        != (
                            stat_final.st_dev,
                            stat_final.st_ino,
                            stat_final.st_mode,
                            stat_final.st_size,
                            stat_final.st_mtime_ns,
                        )
                    ):
                        raise RunnerTrustError("Enrollment material is unavailable or unsafe.")
                    return (
                        payload,
                        identity,
                        (
                            stat_final.st_dev,
                            stat_final.st_ino,
                            stat_final.st_mode,
                            stat_final.st_size,
                            stat_final.st_mtime_ns,
                        ),
                    )
                finally:
                    os.close(descriptor)
            finally:
                if handle != -1:
                    _windows_close_handle(handle)

        if self._descriptor is None:
            raise RunnerTrustError("Enrollment pinned storage is unavailable.")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(name, flags, dir_fd=self._descriptor)
            try:
                posix_initial = _validate_posix_regular_descriptor(descriptor, maximum=maximum)
                _posix_fchmod(descriptor, 0o600)
                payload = _read_descriptor_bounded(descriptor, maximum)
                posix_final = _validate_posix_regular_descriptor(descriptor, maximum=maximum)
                if (
                    (posix_initial.st_dev, posix_initial.st_ino)
                    != (
                        posix_final.st_dev,
                        posix_final.st_ino,
                    )
                    or posix_final.st_size != len(payload)
                    or (
                        posix_final.st_mtime_ns != posix_initial.st_mtime_ns
                        or stat.S_IMODE(posix_final.st_mode) != 0o600
                    )
                ):
                    raise RunnerTrustError("Enrollment material is unavailable or unsafe.")
                return (
                    payload,
                    (posix_final.st_dev, posix_final.st_ino),
                    (
                        posix_final.st_dev,
                        posix_final.st_ino,
                        posix_final.st_mode,
                        posix_final.st_size,
                        posix_final.st_mtime_ns,
                    ),
                )
            finally:
                os.close(descriptor)
        except RunnerTrustError:
            raise
        except OSError:
            raise RunnerTrustError("Enrollment material is unavailable or unsafe.") from None

    def read(self, name: str, *, maximum: int) -> bytes:
        payload, _identity, _snapshot = self.read_with_identity(name, maximum=maximum)
        return payload

    def validate(self, name: str, *, maximum: int) -> None:
        self.read(name, maximum=maximum)

    def unlink(
        self,
        name: str,
        *,
        maximum: int,
        expected_identity: tuple[int, int] | None = None,
    ) -> None:
        if not name or Path(name).name != name:
            raise RunnerTrustError("Enrollment material is unavailable or unsafe.")
        if os.name == "nt":
            handle = _windows_open_pinned(
                self.path / name,
                directory=False,
                delete=True,
                write_dac=True,
            )
            try:
                windows_initial = _validate_windows_regular_information(
                    _windows_file_information(handle), maximum=maximum
                )
                if (
                    expected_identity is not None
                    and _windows_information_identity(windows_initial) != expected_identity
                ):
                    raise RunnerTrustError("Enrollment material is unavailable or unsafe.")
                _owner_private_native_handle(handle, directory=False)
                windows_final = _validate_windows_regular_information(
                    _windows_file_information(handle), maximum=maximum
                )
                if _windows_information_identity(windows_initial) != _windows_information_identity(
                    windows_final
                ):
                    raise RunnerTrustError("Enrollment material is unavailable or unsafe.")
                _windows_mark_delete(handle)
            finally:
                _windows_close_handle(handle)
            return

        if self._descriptor is None:
            raise RunnerTrustError("Enrollment pinned storage is unavailable.")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(name, flags, dir_fd=self._descriptor)
            try:
                posix_initial = _validate_posix_regular_descriptor(descriptor, maximum=maximum)
                if (
                    expected_identity is not None
                    and (
                        posix_initial.st_dev,
                        posix_initial.st_ino,
                    )
                    != expected_identity
                ):
                    raise RunnerTrustError("Enrollment material is unavailable or unsafe.")
                _posix_fchmod(descriptor, 0o600)
                current = os.stat(name, dir_fd=self._descriptor, follow_symlinks=False)
                if (
                    not stat.S_ISREG(current.st_mode)
                    or current.st_nlink != 1
                    or (current.st_dev, current.st_ino)
                    != (posix_initial.st_dev, posix_initial.st_ino)
                ):
                    raise RunnerTrustError("Enrollment material is unavailable or unsafe.")
                os.unlink(name, dir_fd=self._descriptor)
            finally:
                os.close(descriptor)
        except RunnerTrustError:
            raise
        except OSError:
            raise RunnerTrustError("Enrollment material could not be removed safely.") from None

    def sync(self) -> None:
        if os.name != "nt" and self._descriptor is not None:
            _sync_descriptor(self._descriptor)

    def remove(self) -> None:
        if self.names():
            raise RunnerTrustError("Enrollment contains unexpected files and was not removed.")
        if os.name == "nt":
            if self._handle is None or not self.delete:
                raise RunnerTrustError("Enrollment material could not be removed safely.")
            _windows_mark_delete(self._handle)
            self._delete_marked = True
            return
        if self._descriptor is None or self._parent_descriptor is None:
            raise RunnerTrustError("Enrollment pinned storage is unavailable.")
        current = os.stat(self.path.name, dir_fd=self._parent_descriptor, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != self.identity or not stat.S_ISDIR(current.st_mode):
            raise RunnerTrustError("Enrollment directory is unavailable or unsafe.")
        os.rmdir(self.path.name, dir_fd=self._parent_descriptor)
        _sync_descriptor(self._parent_descriptor)


def _validate_windows_regular_information(
    information: _WindowsFileInformation,
    *,
    maximum: int,
) -> _WindowsFileInformation:
    attributes = int(information.dwFileAttributes)
    size = (int(information.nFileSizeHigh) << 32) | int(information.nFileSizeLow)
    if (
        attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY
        or attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
        or int(information.nNumberOfLinks) != 1
        or size > maximum
    ):
        raise RunnerTrustError("Enrollment material is unavailable or unsafe.")
    return information


def _validate_posix_regular_descriptor(descriptor: int, *, maximum: int) -> os.stat_result:
    details = os.fstat(descriptor)
    getuid = getattr(os, "getuid", None)
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_nlink != 1
        or details.st_size > maximum
        or (callable(getuid) and details.st_uid != getuid())
    ):
        raise RunnerTrustError("Enrollment material is unavailable or unsafe.")
    return details


def _posix_fchmod(descriptor: int, mode: int) -> None:
    operation = os.__dict__.get("fchmod")
    if not callable(operation):
        raise RunnerTrustError("Enrollment permissions could not be restricted.")
    try:
        operation(descriptor, mode)
    except OSError:
        raise RunnerTrustError("Enrollment permissions could not be restricted.") from None


def _read_descriptor_bounded(descriptor: int, maximum: int) -> bytes:
    try:
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
    except MemoryError:
        raise RunnerTrustError("Enrollment material exceeds its size limit.") from None
    if len(payload) > maximum:
        raise RunnerTrustError("Enrollment material exceeds its size limit.")
    return payload


def _write_descriptor_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    offset = 0
    try:
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise OSError("short enrollment write")
            offset += written
    except (MemoryError, OSError):
        raise RunnerTrustError("Enrollment material could not be written safely.") from None


def _bounded_regular_read(path: Path, maximum: int) -> bytes:
    with _PinnedDirectory(path.parent, private=False) as directory:
        return directory.read(path.name, maximum=maximum)


def _open_transition_lock_descriptor(path: Path) -> int:
    with _PinnedDirectory(path.parent, private=False) as directory:
        if path.name not in set(directory.names()):
            try:
                directory.create(path.name, b"\0")
                directory.sync()
            except RunnerTrustError:
                if path.name not in set(directory.names()):
                    raise
        # Creation applies owner-only protection while the exact file is pinned.
        # Replaying a path-based Windows ACL update here would fail whenever a
        # peer already holds its no-delete-share lock handle open.  Validate the
        # exact handle below instead.
        if os.name == "nt":
            handle = _windows_open_pinned(
                path,
                directory=False,
                delete=False,
                write=True,
            )
            try:
                _validate_windows_regular_information(_windows_file_information(handle), maximum=1)
                import msvcrt

                descriptor = msvcrt.open_osfhandle(
                    handle,
                    os.O_RDWR | getattr(os, "O_BINARY", 0),
                )
                handle = -1
                return descriptor
            finally:
                if handle != -1:
                    _windows_close_handle(handle)
        if directory._descriptor is None:
            raise RunnerTrustError("Enrollment transition lock is unavailable.")
        descriptor = os.open(
            path.name,
            os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory._descriptor,
        )
        try:
            details = _validate_posix_regular_descriptor(descriptor, maximum=1)
            _posix_fchmod(descriptor, 0o600)
            if details.st_size not in {0, 1}:
                raise RunnerTrustError("Enrollment transition lock is unavailable.")
            return descriptor
        except (OSError, RunnerTrustError):
            os.close(descriptor)
            raise


def _material_limit(name: str) -> int:
    return _MAX_TRUST_BYTES if name in {"trust.json", _TRUST_TEMP_NAME} else _MAX_MATERIAL_BYTES


def _read_enrollment_materials(root: Path) -> dict[str, bytes]:
    with _PinnedDirectory(root, private=True) as directory:
        names = set(directory.names())
        if names not in (_MATERIAL_NAMES, _MATERIAL_NAMES | {_TRUST_TEMP_NAME}):
            raise RunnerTrustError("Enrollment material is unavailable or unsafe.")
        if _TRUST_TEMP_NAME in names:
            directory.validate(_TRUST_TEMP_NAME, maximum=_MAX_TRUST_BYTES)
        return {
            name: directory.read(name, maximum=_material_limit(name)) for name in _MATERIAL_NAMES
        }


def _sync_descriptor(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except OSError as error:
        unsupported = {
            errno.EBADF,
            errno.EINVAL,
            getattr(errno, "ENOTSUP", errno.EINVAL),
            getattr(errno, "EOPNOTSUPP", errno.EINVAL),
        }
        if error.errno not in unsupported:
            raise RunnerTrustError("Enrollment storage could not be synchronized.") from None


def _path_entry_exists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        raise RunnerTrustError("Enrollment directory is unavailable or unsafe.") from None
    return True


def _assert_existing_ancestors_safe(path: Path) -> None:
    current = path
    while True:
        if _path_entry_exists(current) and (_is_link_or_reparse(current) or not current.is_dir()):
            raise RunnerTrustError("Enrollment directory is unavailable or unsafe.")
        if current.parent == current:
            return
        current = current.parent


def _directory_identity(path: Path) -> tuple[int, int]:
    try:
        details = path.stat()
    except OSError:
        raise RunnerTrustError("Enrollment directory is unavailable or unsafe.") from None
    return details.st_dev, details.st_ino


def _assert_directory_identity(path: Path, expected: tuple[int, int]) -> None:
    canonical = _canonical_transition_path(path, create_parent=False)
    if (
        canonical != path
        or _is_link_or_reparse(path)
        or not path.is_dir()
        or _directory_identity(path) != expected
    ):
        raise RunnerTrustError("Enrollment directory is unavailable or unsafe.")


def _validate_creation_recovery(
    enrollment: RunnerEnrollment,
    *,
    runner_id: str,
    client_id: str,
    allowed_profile_ids: tuple[str, ...],
    validity_days: int,
) -> None:
    created = _parse_timestamp(enrollment.metadata["created_at"])
    expires = _parse_timestamp(enrollment.metadata["expires_at"])
    if (
        enrollment.runner_id != runner_id
        or enrollment.client_id != client_id
        or enrollment.allowed_profile_ids != allowed_profile_ids
        or expires - created != timedelta(days=validity_days)
    ):
        raise RunnerTrustError("Enrollment creation recovery does not match.")


def _discard_stale_trust_temporary(root: Path) -> None:
    with _PinnedDirectory(root, private=True) as directory:
        if _TRUST_TEMP_NAME not in set(directory.names()):
            return
        directory.unlink(_TRUST_TEMP_NAME, maximum=_MAX_TRUST_BYTES)
        directory.sync()


def _cleanup_authenticated_creation_stage(staging: Path) -> None:
    """Remove only an intent-owned flat stage through a pinned directory."""

    with _PinnedDirectory(staging, private=True, delete=True) as directory:
        names = set(directory.names())
        if not names <= _TRANSIENT_MATERIAL_NAMES:
            raise RunnerTrustError("Enrollment creation state is unsafe.")
        for name in sorted(names):
            directory.validate(name, maximum=_material_limit(name))
        for name in sorted(names):
            directory.unlink(name, maximum=_material_limit(name))
            directory.sync()
        directory.remove()


def _validated_removal_root(
    root: Path,
) -> tuple[Path, tuple[Path, ...], tuple[int, int]]:
    try:
        canonical = _canonical_transition_path(root, create_parent=False)
        if canonical != root or _is_link_or_reparse(root) or not root.is_dir():
            raise RunnerTrustError("Enrollment directory is unavailable or unsafe.")
        resolved = root.resolve(strict=True)
        if resolved != root:
            raise RunnerTrustError("Enrollment directory is unavailable or unsafe.")
        with _PinnedDirectory(resolved, private=True) as directory:
            identity = _directory_identity(resolved)
            names = set(directory.names())
            if not names <= _TRANSIENT_MATERIAL_NAMES:
                raise RunnerTrustError("Enrollment contains unexpected files and was not removed.")
            for name in names:
                directory.validate(name, maximum=_material_limit(name))
            _assert_directory_identity(resolved, identity)
            return resolved, tuple(resolved / name for name in names), identity
    except RunnerTrustError:
        raise
    except OSError:
        raise RunnerTrustError("Enrollment directory is unavailable or unsafe.") from None


def _cleanup_removal_tombstone(
    tombstone: Path,
    *,
    runner_id: str,
    directory_identity: tuple[int, int],
) -> None:
    _identifier(runner_id, "runner identity")
    with _PinnedDirectory(tombstone, private=True, delete=True) as directory:
        if _directory_identity(tombstone) != directory_identity:
            raise RunnerTrustError("Enrollment directory is unavailable or unsafe.")
        names = set(directory.names())
        if not names <= _TRANSIENT_MATERIAL_NAMES:
            raise RunnerTrustError("Enrollment contains unexpected files and was not removed.")
        for name in names:
            directory.validate(name, maximum=_material_limit(name))
        for name in sorted(names):
            directory.unlink(name, maximum=_material_limit(name))
            directory.sync()
        directory.remove()


def _public_removal_identities(root: Path) -> set[str]:
    identities: set[str] = set()
    try:
        payload = _bounded_regular_read(root / "trust.json", _MAX_TRUST_BYTES)
        metadata = json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_object)
        if isinstance(metadata, Mapping):
            identities.add(_identifier(metadata.get("runner_id"), "runner identity"))
    except (MemoryError, OSError, UnicodeError, ValueError, RunnerTrustError):
        pass
    try:
        certificate = x509.load_pem_x509_certificate(
            _bounded_regular_read(root / "server-cert.pem", _MAX_MATERIAL_BYTES)
        )
        common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(common_names) == 1:
            identities.add(_identifier(common_names[0].value, "runner identity"))
    except (MemoryError, OSError, ValueError, RunnerTrustError):
        pass
    return identities


# Short names keep the public API natural while the explicit names make call sites clear.
create_enrollment = create_local_enrollment
load_enrollment = load_local_enrollment
revoke_enrollment = revoke_local_enrollment
remove_enrollment = remove_local_enrollment


def certificate_fingerprint(certificate: x509.Certificate | bytes) -> str:
    cert = (
        x509.load_der_x509_certificate(certificate)
        if isinstance(certificate, bytes)
        else certificate
    )
    return "sha256:" + cast(bytes, cert.fingerprint(hashes.SHA256())).hex()


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 160 or not _IDENTIFIER.fullmatch(value):
        raise RunnerTrustError(f"{label.capitalize()} is invalid.")
    return value


def _profile_ids(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, str) or not isinstance(values, Sequence):
        raise RunnerTrustError("Allowed profile identities are invalid.")
    result = tuple(_identifier(value, "profile identity") for value in values)
    if not result or len(result) > 128 or len(set(result)) != len(result):
        raise RunnerTrustError("Allowed profile identities must be unique and non-empty.")
    return result


def _secret_provider(provider: SecretProvider | None) -> SecretProvider:
    try:
        resolved = default_secret_provider() if provider is None else provider
        provider_id = resolved.provider_id
    except (AttributeError, SecretStoreError):
        raise RunnerTrustError("Operating-system secret protection is unavailable.") from None
    if not isinstance(provider_id, str) or not _IDENTIFIER.fullmatch(provider_id):
        raise RunnerTrustError("Operating-system secret protection is unavailable.")
    return resolved


def _secret_purpose(runner_id: str, client_id: str, purpose: str) -> str:
    return f"bluefire.runner-enrollment.v1:{runner_id}:{client_id}:{purpose}"


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _issue_leaf(
    *,
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    common_name: str,
    usage: x509.ObjectIdentifier,
    not_before: datetime,
    not_after: datetime,
    loopback_sans: bool,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if loopback_sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.IPAddress(ipaddress.ip_address("::1")),
                ]
            ),
            critical=False,
        )
    return key, builder.sign(ca_key, hashes.SHA256())


def _write_private_key(path: Path, key: ec.EllipticCurvePrivateKey, password: bytes) -> None:
    _write_secret(
        path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password),
        ),
    )


def _write_certificate(path: Path, certificate: x509.Certificate) -> None:
    _write_secret(path, certificate.public_bytes(serialization.Encoding.PEM))


def _write_secret(path: Path, payload: bytes) -> None:
    with _PinnedDirectory(path.parent, private=False) as directory:
        directory.create(path.name, payload)
        directory.sync()


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    payload = canonical_json_bytes(dict(value)) + b"\n"
    if len(payload) > _MAX_TRUST_BYTES:
        raise RunnerTrustError("Enrollment metadata exceeds its size limit.")
    _write_secret(path, payload)


def _owner_private(path: Path, *, directory: bool) -> None:
    if os.name == "nt":
        _windows_owner_private(path, directory=directory)
        return
    try:
        path.chmod(stat.S_IRWXU if directory else stat.S_IRUSR | stat.S_IWUSR)
        details = path.stat()
        getuid = getattr(os, "getuid", None)
        if callable(getuid) and details.st_uid != getuid():
            raise RunnerTrustError("Enrollment material is not owned by this user.")
        expected = 0o700 if directory else 0o600
        if stat.S_IMODE(details.st_mode) != expected:
            raise RunnerTrustError("Enrollment permissions could not be restricted.")
    except RunnerTrustError:
        raise
    except OSError:
        raise RunnerTrustError("Enrollment permissions could not be restricted.") from None


def _owner_private_handle(descriptor: int, *, directory: bool) -> None:
    """Apply and verify a private Windows DACL on one pinned object handle."""

    if os.name != "nt":
        raise RunnerTrustError("Windows enrollment permissions are unavailable.")
    try:
        from .windows_owner_acl import WindowsOwnerAclError, apply_owner_private_acl
    except ImportError:
        raise RunnerTrustError("Enrollment permissions could not be restricted.") from None
    try:
        apply_owner_private_acl(
            descriptor,
            directory=directory,
        )
    except (OSError, WindowsOwnerAclError):
        raise RunnerTrustError("Enrollment permissions could not be restricted.") from None


def _owner_private_native_handle(handle: int, *, directory: bool) -> None:
    """Apply and verify a private Windows DACL on an already pinned native handle."""

    if os.name != "nt":
        raise RunnerTrustError("Windows enrollment permissions are unavailable.")
    try:
        from .windows_owner_acl import WindowsOwnerAclError, apply_owner_private_acl_handle
    except ImportError:
        raise RunnerTrustError("Enrollment permissions could not be restricted.") from None
    try:
        apply_owner_private_acl_handle(handle, directory=directory)
    except (OSError, WindowsOwnerAclError):
        raise RunnerTrustError("Enrollment permissions could not be restricted.") from None


@lru_cache(maxsize=1)
def _windows_current_sid() -> str:
    executable = _windows_system_directory() / "whoami.exe"
    try:
        result = subprocess.run(  # nosec B603
            [str(executable), "/user", "/fo", "csv", "/nh"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        rows = list(csv_reader(result.stdout.splitlines()))
        sid = rows[0][1].strip() if len(rows) == 1 and len(rows[0]) == 2 else ""
    except (OSError, IndexError, subprocess.SubprocessError):
        raise RunnerTrustError("Enrollment permissions could not be restricted.") from None
    if re.fullmatch(r"S-1-(?:\d+-){1,14}\d+", sid) is None:
        raise RunnerTrustError("Enrollment permissions could not be restricted.")
    return sid


def _windows_owner_private(path: Path, *, directory: bool) -> None:
    executable = _windows_system_directory() / "icacls.exe"
    grant = f"*{_windows_current_sid()}:{'(OI)(CI)' if directory else ''}F"
    commands = (
        [str(executable), str(path), "/reset", "/Q"],
        [str(executable), str(path), "/inheritance:r", "/grant:r", grant, "/Q"],
        [str(executable), str(path), "/verify", "/Q"],
    )
    try:
        for command in commands:
            subprocess.run(  # nosec B603
                command,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
    except (OSError, subprocess.SubprocessError):
        raise RunnerTrustError("Enrollment permissions could not be restricted.") from None


@lru_cache(maxsize=1)
def _windows_system_directory() -> Path:
    if os.name != "nt":
        raise RunnerTrustError("Windows enrollment permissions are unavailable.")
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))  # type: ignore[attr-defined]
    if not length or length >= len(buffer):
        raise RunnerTrustError("Enrollment permissions could not be restricted.")
    path = Path(buffer.value)
    if not path.is_absolute() or not path.is_dir():
        raise RunnerTrustError("Enrollment permissions could not be restricted.")
    return path


def _cleanup_failed_creation(destination: Path) -> None:
    """Best-effort flat cleanup without following caller-controlled tree content."""

    try:
        _cleanup_authenticated_creation_stage(destination)
    except (OSError, RunnerTrustError):
        return


def _validated_enrollment_root(root: str | Path) -> Path:
    destination = _canonical_transition_path(root, create_parent=False)
    try:
        if _is_link_or_reparse(destination) or not destination.is_dir():
            raise RunnerTrustError("Enrollment directory is unavailable or unsafe.")
        resolved = destination.resolve(strict=True)
        if resolved != destination:
            raise RunnerTrustError("Enrollment directory is unavailable or unsafe.")
        with _PinnedDirectory(resolved, private=True) as directory:
            names = set(directory.names())
            if names not in (
                _MATERIAL_NAMES,
                _MATERIAL_NAMES | {_TRUST_TEMP_NAME},
            ):
                raise RunnerTrustError("Enrollment material is unavailable or unsafe.")
            for name in names:
                directory.validate(name, maximum=_material_limit(name))
        return resolved
    except RunnerTrustError:
        raise
    except OSError:
        raise RunnerTrustError("Enrollment directory is unavailable or unsafe.") from None


def _is_link_or_reparse(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        if os.name == "nt" and path.exists():
            attributes = getattr(path.lstat(), "st_file_attributes", 0)
            reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            return bool(attributes & reparse)
        return False
    except OSError:
        return True


def _sync_directory(path: Path) -> None:
    """Flush a POSIX directory transition.

    Windows file payloads are flushed, and handle-based operations are safe
    against a process crash after their system call returns. Python exposes no
    portable write-through directory flush there, so this module does not claim
    power-loss durability for Windows directory-entry transitions.
    """

    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        unsupported = {
            errno.EBADF,
            errno.EINVAL,
            getattr(errno, "ENOTSUP", errno.EINVAL),
            getattr(errno, "EOPNOTSUPP", errno.EINVAL),
        }
        if error.errno not in unsupported:
            raise RunnerTrustError("Enrollment storage could not be synchronized.") from None


def _read_certificate(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(_bounded_regular_read(path, _MAX_MATERIAL_BYTES))


def _read_private_key(path: Path, password: bytes) -> ec.EllipticCurvePrivateKey:
    return _read_private_key_bytes(
        _bounded_regular_read(path, _MAX_MATERIAL_BYTES),
        password,
    )


def _read_private_key_bytes(payload: bytes, password: bytes) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(payload, password=password)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("unsupported key")
    return key


def _validate_metadata(metadata: Mapping[str, Any]) -> None:
    if metadata.get("schema_version") != TRUST_SCHEMA_VERSION:
        raise RunnerTrustError("Enrollment metadata schema is unsupported.")
    _identifier(metadata.get("runner_id"), "runner identity")
    _identifier(metadata.get("client_id"), "client identity")
    raw_profiles = metadata.get("allowed_profile_ids")
    if not isinstance(raw_profiles, list):
        raise RunnerTrustError("Allowed profile identities are invalid.")
    _profile_ids(raw_profiles)
    status = metadata.get("status")
    revoked_at = metadata.get("revoked_at")
    if status not in {"active", "revoked"}:
        raise RunnerTrustError("Enrollment status is invalid.")
    if status == "active" and revoked_at is not None:
        raise RunnerTrustError("Enrollment status metadata is inconsistent.")
    if status == "revoked" and not isinstance(revoked_at, str):
        raise RunnerTrustError("Enrollment status metadata is inconsistent.")
    for field in ("ca_fingerprint", "server_fingerprint", "client_fingerprint"):
        if not isinstance(metadata.get(field), str) or not _FINGERPRINT.fullmatch(metadata[field]):
            raise RunnerTrustError("Enrollment certificate fingerprint is invalid.")
    created = _parse_timestamp(metadata.get("created_at"))
    expires = _parse_timestamp(metadata.get("expires_at"))
    if expires <= created:
        raise RunnerTrustError("Enrollment validity metadata is invalid.")
    if isinstance(revoked_at, str):
        _parse_timestamp(revoked_at)
    secret_provider = metadata.get("secret_provider")
    if not isinstance(secret_provider, str) or not _IDENTIFIER.fullmatch(secret_provider):
        raise RunnerTrustError("Enrollment secret provider is invalid.")


def _validate_certificates(
    metadata: Mapping[str, Any],
    *,
    ca_cert: x509.Certificate,
    server_cert: x509.Certificate,
    client_cert: x509.Certificate,
    server_key: ec.EllipticCurvePrivateKey,
    client_key: ec.EllipticCurvePrivateKey,
    require_current_validity: bool,
) -> None:
    fingerprints = {
        "ca_fingerprint": certificate_fingerprint(ca_cert),
        "server_fingerprint": certificate_fingerprint(server_cert),
        "client_fingerprint": certificate_fingerprint(client_cert),
    }
    if any(metadata[field] != value for field, value in fingerprints.items()):
        raise RunnerTrustError("Enrollment certificate fingerprint does not match.")
    if ca_cert.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value != x509.BasicConstraints(ca=True, path_length=0):
        raise RunnerTrustError("Enrollment certificate authority is invalid.")
    if ca_cert.issuer != ca_cert.subject:
        raise RunnerTrustError("Enrollment certificate authority is invalid.")
    ca_usage = ca_cert.extensions.get_extension_for_class(x509.KeyUsage).value
    if not ca_usage.key_cert_sign or not ca_usage.crl_sign or not ca_usage.digital_signature:
        raise RunnerTrustError("Enrollment certificate authority usage is invalid.")
    _verify_signature(ca_cert, ca_cert)
    _match_key(server_key, server_cert)
    _match_key(client_key, client_cert)
    _verify_leaf(ca_cert, server_cert, ExtendedKeyUsageOID.SERVER_AUTH)
    _verify_leaf(ca_cert, client_cert, ExtendedKeyUsageOID.CLIENT_AUTH)
    server_name = server_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    client_name = client_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if [item.value for item in server_name] != [metadata["runner_id"]]:
        raise RunnerTrustError("Enrollment runner certificate identity does not match.")
    if [item.value for item in client_name] != [metadata["client_id"]]:
        raise RunnerTrustError("Enrollment client certificate identity does not match.")
    sans = server_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if set(sans.get_values_for_type(x509.IPAddress)) != {
        ipaddress.ip_address("127.0.0.1"),
        ipaddress.ip_address("::1"),
    }:
        raise RunnerTrustError("Enrollment server certificate is not loopback-only.")
    try:
        client_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        pass
    else:
        raise RunnerTrustError("Enrollment client certificate scope is invalid.")
    expected_expiry = _parse_timestamp(metadata["expires_at"])
    certificates = (ca_cert, server_cert, client_cert)
    if any(certificate.not_valid_after_utc != expected_expiry for certificate in certificates):
        raise RunnerTrustError("Enrollment certificate validity does not match.")
    if any(
        certificate.not_valid_before_utc != ca_cert.not_valid_before_utc
        for certificate in certificates
    ):
        raise RunnerTrustError("Enrollment certificate validity does not match.")
    now = datetime.now(timezone.utc)
    if require_current_validity and any(
        now < certificate.not_valid_before_utc or now >= certificate.not_valid_after_utc
        for certificate in certificates
    ):
        raise RunnerTrustError("Enrollment certificate is not currently valid.")


def _match_key(key: ec.EllipticCurvePrivateKey, certificate: x509.Certificate) -> None:
    expected = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    actual = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if not secrets.compare_digest(actual, expected):
        raise RunnerTrustError("Enrollment private key does not match its certificate.")


def _verify_leaf(
    ca_cert: x509.Certificate,
    leaf: x509.Certificate,
    expected_usage: x509.ObjectIdentifier,
) -> None:
    if leaf.issuer != ca_cert.subject:
        raise RunnerTrustError("Enrollment certificate issuer does not match.")
    if leaf.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value != x509.BasicConstraints(ca=False, path_length=None):
        raise RunnerTrustError("Enrollment leaf certificate constraints are invalid.")
    usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    if not usage.digital_signature or any(
        (
            usage.content_commitment,
            usage.key_encipherment,
            usage.data_encipherment,
            usage.key_agreement,
            usage.key_cert_sign,
            usage.crl_sign,
        )
    ):
        raise RunnerTrustError("Enrollment leaf certificate usage is invalid.")
    usages = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    if list(usages) != [expected_usage]:
        raise RunnerTrustError("Enrollment certificate usage is invalid.")
    _verify_signature(ca_cert, leaf)


def _verify_signature(issuer: x509.Certificate, certificate: x509.Certificate) -> None:
    issuer_public_key = issuer.public_key()
    signature_hash = certificate.signature_hash_algorithm
    if (
        not isinstance(issuer_public_key, ec.EllipticCurvePublicKey)
        or not isinstance(issuer_public_key.curve, ec.SECP256R1)
        or signature_hash is None
        or signature_hash.name != "sha256"
    ):
        raise RunnerTrustError("Enrollment certificate authority key is invalid.")
    try:
        issuer_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(signature_hash),
        )
    except Exception:  # cryptography exposes backend-specific verification failures.
        raise RunnerTrustError("Enrollment certificate signature is invalid.") from None


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RunnerTrustError("Enrollment timestamp is invalid.")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise RunnerTrustError("Enrollment timestamp is invalid.") from None
    if _timestamp(parsed) != value:
        raise RunnerTrustError("Enrollment timestamp is invalid.")
    return parsed


__all__ = [
    "RunnerEnrollment",
    "RunnerTrustError",
    "TRUST_SCHEMA_VERSION",
    "certificate_fingerprint",
    "create_enrollment",
    "create_local_enrollment",
    "enrollment_status",
    "local_enrollment_creation_path",
    "load_enrollment",
    "load_local_enrollment",
    "remove_enrollment",
    "remove_local_enrollment",
    "revoke_enrollment",
    "revoke_local_enrollment",
]
