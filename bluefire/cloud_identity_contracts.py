"""Strict public contracts and opaque-credential boundary for the AWS lab pack."""

from __future__ import annotations

import hashlib
import os
import re
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping, Protocol, runtime_checkable

from .run_store import RunStore
from .secret_store import InMemorySecretProvider, SecretStoreError

PACK_ID = "bluefire.aws-identity-lab.v1"
PROFILE_ID = "aws-identity-lab.v1"
PROFILE_SCHEMA = "bluefire.aws-identity-lab-profile.v1"
APPROVAL_SCHEMA = "bluefire.aws-identity-lab-approval.v1"
SIMULATE_REQUEST_SCHEMA = "bluefire.aws-identity-lab-simulate.v1"
EXECUTE_REQUEST_SCHEMA = "bluefire.aws-identity-lab-execute.v1"
RUN_RESULT_SCHEMA = "bluefire.aws-identity-lab-result.v1"
MANUAL_SMOKE_SCHEMA = "bluefire.aws-identity-lab-manual-smoke.v1"

CONTROL_ACTION = "iam:TagRole"
REVOCATION_ACTION = "iam:UntagRole"
CONTROL_TAG_KEY = "bluefire:nexus:identity-lab"
MANUAL_CONFIRMATION = "APPLY-REVERSIBLE-IAM-LAB-TAG"

_PROFILE_FIELDS = frozenset(
    {
        "schema_version",
        "profile_id",
        "pack_id",
        "provider",
        "account_id",
        "region",
        "role_name",
        "credential_handle",
    }
)
_APPROVAL_FIELDS = frozenset(
    {
        "schema_version",
        "approval_id",
        "profile_id",
        "account_id",
        "role_name",
        "action",
        "revocation_action",
    }
)
_REQUEST_FIELDS = frozenset({"schema_version", "operation_id", "profile", "approval"})
ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
REGION_RE = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]?$", re.ASCII)
ROLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+=,.@_-]{0,63}$", re.ASCII)
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", re.ASCII)
HANDLE_RE = re.compile(r"^credential-[0-9a-f]{32}$", re.ASCII)
PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$", re.ASCII)
MAX_CREDENTIAL_BYTES = 64 * 1024
MIN_CREDENTIAL_BYTES = 24


class CloudIdentityPackError(ValueError):
    """A sanitized fail-closed refusal from the identity-lab pack."""


class AwsManualSmokeError(ValueError):
    """A sanitized refusal or failure from the manual AWS smoke path."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CloudIdentityPackError(message)


def exact_mapping(value: Any, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CloudIdentityPackError(f"{label} fields do not match the schema")
    return value


def safe_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SAFE_ID_RE.fullmatch(value):
        raise CloudIdentityPackError(f"{label} is invalid")
    return value


def control_tag_value(operation_id: str) -> str:
    digest = hashlib.sha256(operation_id.encode("utf-8", errors="strict")).hexdigest()[:20]
    return f"run-{digest}"


@dataclass(frozen=True, slots=True)
class AwsIdentityLabProfile:
    """Explicit AWS lab target containing an opaque credential handle only."""

    account_id: str
    region: str
    role_name: str
    credential_handle: str
    schema_version: str = PROFILE_SCHEMA
    profile_id: str = PROFILE_ID
    pack_id: str = PACK_ID
    provider: str = "aws"

    def __post_init__(self) -> None:
        require(self.schema_version == PROFILE_SCHEMA, "cloud profile schema is unsupported")
        require(self.profile_id == PROFILE_ID, "cloud profile id is unsupported")
        require(self.pack_id == PACK_ID, "cloud behavior pack id is unsupported")
        require(self.provider == "aws", "cloud provider is unsupported")
        require(bool(ACCOUNT_RE.fullmatch(self.account_id)), "AWS account id is invalid")
        require(bool(REGION_RE.fullmatch(self.region)), "AWS region is invalid")
        require(bool(ROLE_RE.fullmatch(self.role_name)), "AWS lab role name is invalid")
        require(
            bool(HANDLE_RE.fullmatch(self.credential_handle)),
            "opaque credential handle is invalid",
        )

    @property
    def role_arn(self) -> str:
        return f"arn:aws:iam::{self.account_id}:role/{self.role_name}"

    def to_dict(self) -> dict[str, str]:
        return {
            "schema_version": self.schema_version,
            "profile_id": self.profile_id,
            "pack_id": self.pack_id,
            "provider": self.provider,
            "account_id": self.account_id,
            "region": self.region,
            "role_name": self.role_name,
            "credential_handle": self.credential_handle,
        }

    @classmethod
    def from_mapping(cls, value: Any) -> "AwsIdentityLabProfile":
        raw = exact_mapping(value, _PROFILE_FIELDS, "cloud profile")
        if any(not isinstance(raw[field], str) for field in _PROFILE_FIELDS):
            raise CloudIdentityPackError("cloud profile values must be strings")
        return cls(
            account_id=str(raw["account_id"]),
            region=str(raw["region"]),
            role_name=str(raw["role_name"]),
            credential_handle=str(raw["credential_handle"]),
            schema_version=str(raw["schema_version"]),
            profile_id=str(raw["profile_id"]),
            pack_id=str(raw["pack_id"]),
            provider=str(raw["provider"]),
        )


@dataclass(frozen=True, slots=True)
class AwsIdentityLabApproval:
    """Approval bound to one profile, account, role, action, and cleanup action."""

    approval_id: str
    account_id: str
    role_name: str
    schema_version: str = APPROVAL_SCHEMA
    profile_id: str = PROFILE_ID
    action: str = CONTROL_ACTION
    revocation_action: str = REVOCATION_ACTION

    def __post_init__(self) -> None:
        require(self.schema_version == APPROVAL_SCHEMA, "cloud approval schema is unsupported")
        safe_identifier(self.approval_id, "cloud approval id")
        require(self.profile_id == PROFILE_ID, "cloud approval profile is unsupported")
        require(bool(ACCOUNT_RE.fullmatch(self.account_id)), "approved AWS account is invalid")
        require(bool(ROLE_RE.fullmatch(self.role_name)), "approved AWS role is invalid")
        require(self.action == CONTROL_ACTION, "cloud approval action is unsupported")
        require(
            self.revocation_action == REVOCATION_ACTION,
            "cloud approval revocation action is unsupported",
        )

    def assert_binds(self, profile: AwsIdentityLabProfile) -> None:
        require(
            self.profile_id == profile.profile_id
            and self.account_id == profile.account_id
            and self.role_name == profile.role_name,
            "cloud approval does not bind the requested lab target",
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "schema_version": self.schema_version,
            "approval_id": self.approval_id,
            "profile_id": self.profile_id,
            "account_id": self.account_id,
            "role_name": self.role_name,
            "action": self.action,
            "revocation_action": self.revocation_action,
        }

    @classmethod
    def from_mapping(cls, value: Any) -> "AwsIdentityLabApproval":
        raw = exact_mapping(value, _APPROVAL_FIELDS, "cloud approval")
        if any(not isinstance(raw[field], str) for field in _APPROVAL_FIELDS):
            raise CloudIdentityPackError("cloud approval values must be strings")
        return cls(
            approval_id=str(raw["approval_id"]),
            account_id=str(raw["account_id"]),
            role_name=str(raw["role_name"]),
            schema_version=str(raw["schema_version"]),
            profile_id=str(raw["profile_id"]),
            action=str(raw["action"]),
            revocation_action=str(raw["revocation_action"]),
        )


@dataclass(frozen=True, slots=True)
class SimulateRequest:
    operation_id: str
    profile: AwsIdentityLabProfile
    approval: AwsIdentityLabApproval
    schema_version: str = SIMULATE_REQUEST_SCHEMA

    def __post_init__(self) -> None:
        require(
            self.schema_version == SIMULATE_REQUEST_SCHEMA,
            "cloud Simulate schema is unsupported",
        )
        safe_identifier(self.operation_id, "cloud operation id")
        self.approval.assert_binds(self.profile)

    @classmethod
    def from_mapping(cls, value: Any) -> "SimulateRequest":
        raw = exact_mapping(value, _REQUEST_FIELDS, "cloud Simulate request")
        if not isinstance(raw["schema_version"], str) or not isinstance(raw["operation_id"], str):
            raise CloudIdentityPackError("cloud Simulate request values are invalid")
        return cls(
            operation_id=str(raw["operation_id"]),
            profile=AwsIdentityLabProfile.from_mapping(raw["profile"]),
            approval=AwsIdentityLabApproval.from_mapping(raw["approval"]),
            schema_version=str(raw["schema_version"]),
        )


@dataclass(frozen=True, slots=True)
class ExecuteRequest:
    operation_id: str
    profile: AwsIdentityLabProfile
    approval: AwsIdentityLabApproval
    schema_version: str = EXECUTE_REQUEST_SCHEMA

    def __post_init__(self) -> None:
        require(
            self.schema_version == EXECUTE_REQUEST_SCHEMA,
            "cloud Execute schema is unsupported",
        )
        safe_identifier(self.operation_id, "cloud operation id")
        self.approval.assert_binds(self.profile)

    @classmethod
    def from_mapping(cls, value: Any) -> "ExecuteRequest":
        raw = exact_mapping(value, _REQUEST_FIELDS, "cloud Execute request")
        if not isinstance(raw["schema_version"], str) or not isinstance(raw["operation_id"], str):
            raise CloudIdentityPackError("cloud Execute request values are invalid")
        return cls(
            operation_id=str(raw["operation_id"]),
            profile=AwsIdentityLabProfile.from_mapping(raw["profile"]),
            approval=AwsIdentityLabApproval.from_mapping(raw["approval"]),
            schema_version=str(raw["schema_version"]),
        )


@dataclass(frozen=True, slots=True)
class CloudEnumeration:
    account_id: str
    principal_arn: str
    role_arns: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "principal_arn": self.principal_arn,
            "role_arns": list(self.role_arns),
        }


@dataclass(frozen=True, slots=True)
class SecretScanReport:
    files_scanned: int
    bytes_scanned: int
    encodings_checked: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.secret-material-scan.v1",
            "passed": True,
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "encodings_checked": list(self.encodings_checked),
        }


@dataclass(frozen=True, slots=True)
class CloudIdentityRunReceipt:
    mode: str
    run_id: str
    bundle_path: Path
    bundle_hash: str
    cleanup_verified: bool
    audit_verified: bool
    credential_revoked: bool
    acceptance_binding: Mapping[str, Any] | None
    secret_scan: SecretScanReport

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.aws-identity-lab-run-receipt.v1",
            "mode": self.mode,
            "run_id": self.run_id,
            "bundle_path": str(self.bundle_path),
            "bundle_hash": self.bundle_hash,
            "cleanup_verified": self.cleanup_verified,
            "audit_verified": self.audit_verified,
            "credential_revoked": self.credential_revoked,
            "acceptance_binding": (
                dict(self.acceptance_binding) if self.acceptance_binding is not None else None
            ),
            "secret_scan": self.secret_scan.to_dict(),
        }


@dataclass(slots=True)
class _CredentialRecord:
    provider: InMemorySecretProvider
    purpose: str
    opaque: bytes


class InMemoryCloudCredentialVault:
    """Own one in-memory secret provider per opaque cloud credential handle."""

    def __init__(self) -> None:
        self._records: dict[str, _CredentialRecord] = {}
        self._lock = threading.RLock()

    def enroll(self, credential: bytes) -> str:
        if (
            not isinstance(credential, bytes)
            or not MIN_CREDENTIAL_BYTES <= len(credential) <= MAX_CREDENTIAL_BYTES
        ):
            raise CloudIdentityPackError("cloud credential bytes are invalid")
        provider = InMemorySecretProvider()
        while True:
            handle = "credential-" + os.urandom(16).hex()
            with self._lock:
                if handle not in self._records:
                    break
        purpose = f"{PACK_ID}:{handle}"
        try:
            opaque = provider.protect(purpose, credential)
        except SecretStoreError as exc:
            raise CloudIdentityPackError("cloud credential enrollment failed") from exc
        with self._lock:
            self._records[handle] = _CredentialRecord(provider, purpose, opaque)
        return handle

    def contains(self, handle: str) -> bool:
        with self._lock:
            return handle in self._records

    @contextmanager
    def open(self, handle: str) -> Iterator[memoryview]:
        if not isinstance(handle, str) or not HANDLE_RE.fullmatch(handle):
            raise CloudIdentityPackError("opaque credential handle is invalid")
        with self._lock:
            record = self._records.get(handle)
        if record is None:
            raise CloudIdentityPackError("opaque credential handle is unavailable")
        try:
            recovered = record.provider.unprotect(record.purpose, record.opaque)
        except SecretStoreError as exc:
            raise CloudIdentityPackError("opaque credential handle is unavailable") from exc
        material = bytearray(recovered)
        try:
            yield memoryview(material).toreadonly()
        finally:
            material[:] = b"\x00" * len(material)

    def revoke(self, handle: str) -> bool:
        with self._lock:
            return self._records.pop(handle, None) is not None


@runtime_checkable
class AwsIdentityExecuteBackend(Protocol):
    """Typed Execute interface for an authorized AWS identity-lab backend."""

    def enumerate(
        self, profile: AwsIdentityLabProfile, credential: memoryview
    ) -> CloudEnumeration: ...

    def apply_control(
        self,
        profile: AwsIdentityLabProfile,
        credential: memoryview,
        *,
        tag_value: str,
    ) -> Mapping[str, Any]: ...

    def observe_control(
        self,
        profile: AwsIdentityLabProfile,
        credential: memoryview,
        *,
        tag_value: str,
    ) -> bool: ...

    def revoke_control(
        self,
        profile: AwsIdentityLabProfile,
        credential: memoryview,
        *,
        tag_value: str,
    ) -> Mapping[str, Any]: ...

    def observe_cleanup(self, profile: AwsIdentityLabProfile, credential: memoryview) -> bool: ...

    def audit_events(self) -> tuple[Mapping[str, Any], ...]: ...


@runtime_checkable
class CloudIdentitySimulate(Protocol):
    def simulate(self, request: SimulateRequest, store: RunStore) -> CloudIdentityRunReceipt: ...


@runtime_checkable
class CloudIdentityExecute(Protocol):
    def execute(self, request: ExecuteRequest, store: RunStore) -> CloudIdentityRunReceipt: ...


__all__ = [
    "ACCOUNT_RE",
    "APPROVAL_SCHEMA",
    "AwsIdentityExecuteBackend",
    "AwsIdentityLabApproval",
    "AwsIdentityLabProfile",
    "AwsManualSmokeError",
    "CloudEnumeration",
    "CloudIdentityExecute",
    "CloudIdentityPackError",
    "CloudIdentityRunReceipt",
    "CloudIdentitySimulate",
    "CONTROL_ACTION",
    "CONTROL_TAG_KEY",
    "EXECUTE_REQUEST_SCHEMA",
    "ExecuteRequest",
    "InMemoryCloudCredentialVault",
    "MANUAL_CONFIRMATION",
    "MANUAL_SMOKE_SCHEMA",
    "MAX_CREDENTIAL_BYTES",
    "MIN_CREDENTIAL_BYTES",
    "PACK_ID",
    "PROFILE_ID",
    "PROFILE_NAME_RE",
    "PROFILE_SCHEMA",
    "REGION_RE",
    "REVOCATION_ACTION",
    "ROLE_RE",
    "RUN_RESULT_SCHEMA",
    "SAFE_ID_RE",
    "SIMULATE_REQUEST_SCHEMA",
    "SecretScanReport",
    "SimulateRequest",
    "control_tag_value",
    "require",
    "safe_identifier",
]
