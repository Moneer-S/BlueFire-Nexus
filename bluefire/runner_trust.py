"""Local enrollment material for the authenticated runner transport.

The trust document is deliberately public metadata: it contains identities,
certificate fingerprints, and the exact profile allow-list, but never private
keys, shared authentication material, or local filesystem paths.
"""

from __future__ import annotations

import ctypes
import ipaddress
import json
import os
import re
import secrets
import stat
import subprocess  # nosec B404
from csv import reader as csv_reader
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping, Sequence

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
_HMAC_KEY_BYTES = 32


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
            opaque = (self.root / filename).read_bytes()
            return self.secret_provider.unprotect(self._purpose(purpose), opaque)
        except (OSError, SecretStoreError):
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

    destination = Path(root).expanduser()
    created = False
    try:
        destination.mkdir(mode=0o700, parents=True, exist_ok=False)
        created = True
        if _is_link_or_reparse(destination) or not destination.is_dir():
            raise RunnerTrustError("Enrollment directory is unavailable or unsafe.")
        _owner_private(destination, directory=True)

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
            common_name=checked_runner_id,
            usage=ExtendedKeyUsageOID.SERVER_AUTH,
            not_before=not_before,
            not_after=expires,
            loopback_sans=True,
        )
        client_key, client_cert = _issue_leaf(
            ca_key=ca_key,
            ca_cert=ca_cert,
            common_name=checked_client_id,
            usage=ExtendedKeyUsageOID.CLIENT_AUTH,
            not_before=not_before,
            not_after=expires,
            loopback_sans=False,
        )

        _write_certificate(destination / "ca-cert.pem", ca_cert)
        server_password = secrets.token_bytes(32)
        client_password = secrets.token_bytes(32)
        _write_private_key(destination / "server-key.pem", server_key, server_password)
        _write_certificate(destination / "server-cert.pem", server_cert)
        _write_private_key(destination / "client-key.pem", client_key, client_password)
        _write_certificate(destination / "client-cert.pem", client_cert)
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
            protected = provider.protect(
                _secret_purpose(checked_runner_id, checked_client_id, purpose),
                plaintext[filename],
            )
            _write_secret(destination / filename, protected)

        metadata = {
            "schema_version": TRUST_SCHEMA_VERSION,
            "runner_id": checked_runner_id,
            "client_id": checked_client_id,
            "allowed_profile_ids": list(checked_profiles),
            "status": "active",
            "ca_fingerprint": certificate_fingerprint(ca_cert),
            "server_fingerprint": certificate_fingerprint(server_cert),
            "client_fingerprint": certificate_fingerprint(client_cert),
            "created_at": _timestamp(now),
            "expires_at": _timestamp(expires),
            "revoked_at": None,
            "secret_provider": provider.provider_id,
        }
        _write_json(destination / "trust.json", metadata)
    except RunnerTrustError:
        if created:
            _cleanup_failed_creation(destination)
        raise
    except (OSError, TypeError, ValueError):
        if created:
            _cleanup_failed_creation(destination)
        raise RunnerTrustError("Enrollment could not be created.") from None
    return load_local_enrollment(destination, secret_provider=provider)


def load_local_enrollment(
    root: str | Path,
    *,
    require_active: bool = True,
    secret_provider: SecretProvider | None = None,
) -> RunnerEnrollment:
    """Load and cryptographically validate an enrollment without trusting paths in JSON."""

    destination = _validated_enrollment_root(root)
    try:
        trust_path = destination / "trust.json"
        for name in _MATERIAL_NAMES:
            material = destination / name
            if _is_link_or_reparse(material) or not material.is_file():
                raise RunnerTrustError("Enrollment material is unavailable or unsafe.")
            _owner_private(material, directory=False)
        payload = trust_path.read_bytes()
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
        ca_cert = _read_certificate(destination / "ca-cert.pem")
        server_cert = _read_certificate(destination / "server-cert.pem")
        client_cert = _read_certificate(destination / "client-cert.pem")
        server_password = provider.unprotect(
            _secret_purpose(metadata["runner_id"], metadata["client_id"], "server-key-password"),
            (destination / "server-key-password.secret").read_bytes(),
        )
        client_password = provider.unprotect(
            _secret_purpose(metadata["runner_id"], metadata["client_id"], "client-key-password"),
            (destination / "client-key-password.secret").read_bytes(),
        )
        hmac_key = provider.unprotect(
            _secret_purpose(metadata["runner_id"], metadata["client_id"], "request-hmac"),
            (destination / "hmac.secret").read_bytes(),
        )
        server_key = _read_private_key(destination / "server-key.pem", server_password)
        client_key = _read_private_key(destination / "client-key.pem", client_password)
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


def revoke_local_enrollment(
    root: str | Path, *, secret_provider: SecretProvider | None = None
) -> RunnerEnrollment:
    """Atomically mark an enrollment revoked while retaining audit metadata."""

    enrollment = load_local_enrollment(root, require_active=False, secret_provider=secret_provider)
    if enrollment.status == "revoked":
        return enrollment
    metadata = dict(enrollment.metadata)
    metadata["status"] = "revoked"
    metadata["revoked_at"] = _timestamp(datetime.now(timezone.utc).replace(microsecond=0))
    try:
        _write_json(enrollment.trust_file, metadata, replace=True)
    except OSError:
        raise RunnerTrustError("Enrollment could not be revoked.") from None
    return load_local_enrollment(
        enrollment.root,
        require_active=False,
        secret_provider=enrollment.secret_provider,
    )


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
        enrollment = load_local_enrollment(
            root, require_active=False, secret_provider=secret_provider
        )
        if confirmed is not None and enrollment.runner_id != confirmed:
            raise RunnerTrustError("Enrollment removal confirmation does not match.")
        destination = enrollment.root
    except RunnerTrustError:
        if confirmed is None:
            raise
        destination = _validated_enrollment_root(root)
        if confirmed not in _public_removal_identities(destination):
            raise RunnerTrustError("Enrollment removal confirmation does not match.") from None
    try:
        identity = (destination.stat().st_dev, destination.stat().st_ino)
        entries = tuple(destination.iterdir())
        if {entry.name for entry in entries} != _MATERIAL_NAMES:
            raise RunnerTrustError("Enrollment contains unexpected files and was not removed.")
        for entry in entries:
            if _is_link_or_reparse(entry) or not entry.is_file():
                raise RunnerTrustError("Enrollment material is unavailable or unsafe.")
            _owner_private(entry, directory=False)
        if (
            _is_link_or_reparse(destination)
            or (
                destination.stat().st_dev,
                destination.stat().st_ino,
            )
            != identity
        ):
            raise RunnerTrustError("Enrollment directory is unavailable or unsafe.")
        for entry in entries:
            entry.unlink()
        destination.rmdir()
    except RunnerTrustError:
        raise
    except OSError:
        raise RunnerTrustError("Enrollment could not be removed.") from None


def _public_removal_identities(root: Path) -> set[str]:
    identities: set[str] = set()
    try:
        payload = (root / "trust.json").read_bytes()
        metadata = json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_object)
        if isinstance(metadata, Mapping):
            identities.add(_identifier(metadata.get("runner_id"), "runner identity"))
    except (OSError, UnicodeError, ValueError, RunnerTrustError):
        pass
    try:
        certificate = _read_certificate(root / "server-cert.pem")
        common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(common_names) == 1:
            identities.add(_identifier(common_names[0].value, "runner identity"))
    except (OSError, ValueError, RunnerTrustError):
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
    return "sha256:" + cert.fingerprint(hashes.SHA256()).hex()


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
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        _owner_private(path, directory=False)


def _write_json(path: Path, value: Mapping[str, Any], *, replace: bool = False) -> None:
    payload = canonical_json_bytes(dict(value)) + b"\n"
    if len(payload) > _MAX_TRUST_BYTES:
        raise RunnerTrustError("Enrollment metadata exceeds its size limit.")
    if not replace:
        _write_secret(path, payload)
        return
    temporary = path.with_name(".trust.json.tmp")
    try:
        if temporary.exists():
            temporary.unlink()
        _write_secret(temporary, payload)
        os.replace(temporary, path)
        _owner_private(path, directory=False)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


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
        if _is_link_or_reparse(destination) or not destination.is_dir():
            return
        entries = tuple(destination.iterdir())
        for entry in entries:
            if (
                entry.name not in _MATERIAL_NAMES
                or _is_link_or_reparse(entry)
                or not entry.is_file()
            ):
                return
        for entry in entries:
            entry.unlink()
        destination.rmdir()
    except OSError:
        return


def _validated_enrollment_root(root: str | Path) -> Path:
    destination = Path(root).expanduser()
    try:
        if _is_link_or_reparse(destination) or not destination.is_dir():
            raise RunnerTrustError("Enrollment directory is unavailable or unsafe.")
        resolved = destination.resolve(strict=True)
        if {entry.name for entry in resolved.iterdir()} != _MATERIAL_NAMES:
            raise RunnerTrustError("Enrollment material is unavailable or unsafe.")
        _owner_private(resolved, directory=True)
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


def _read_certificate(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def _read_private_key(path: Path, password: bytes) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=password)
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
    "load_enrollment",
    "load_local_enrollment",
    "remove_enrollment",
    "remove_local_enrollment",
    "revoke_enrollment",
    "revoke_local_enrollment",
]
