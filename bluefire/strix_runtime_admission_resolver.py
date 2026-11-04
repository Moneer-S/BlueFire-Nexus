"""Resolve one persisted Strix admission from controller-owned authority.

This module is deliberately read only.  It does not create an attempt
admission, allocate runtime resources, qualify a target, or manufacture any
network, custody, protected-root, or containment receipt.  The caller must
provide an append-only authority source, an already protected qualification
artifact source, and an already persisted per-attempt admission source.

Authority is reread for every resolution.  An active authority can reopen the
exact saved admission; a revoked authority returns the same admission data
with the launch qualification gate closed so recovery can still reconcile the
saved custody without replaying work.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping, Protocol

from .engine_attempt_contract import EngineAttemptBinding
from .engine_delegation import EngineCapabilityDelegation
from .strix_adapter import StrixBuildIdentity
from .strix_engine_runtime import StrixRuntimeAdmission, StrixRuntimeAdmissionResolution
from .strix_runtime_qualification import (
    QualifiedStrixRuntime,
    StrixRuntimeQualificationError,
    load_strix_runtime_qualification,
)
from .util import content_hash, parse_iso8601_datetime
from .windows_owner_acl import (
    WindowsOwnerAclError,
    _windows_open_descriptor,
    verify_owner_private_acl,
)


class StrixRuntimeAdmissionResolverError(RuntimeError):
    """The controller could not prove an exact persisted runtime admission."""


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_ARTIFACT_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{31,127}$")
_AUTHORITY_FIELDS = frozenset(
    {
        "schema_version",
        "generation",
        "state",
        "qualification_manifest_ref",
        "protected_artifact_key",
        "installed_bluefire_revision",
        "strix_build_digest",
        "threat_review_ref",
        "recorded_at",
        "revocation_reason",
    }
)
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise StrixRuntimeAdmissionResolverError(f"{label} is invalid")
    return value


def _revision(value: Any, label: str) -> str:
    if not isinstance(value, str) or _REVISION.fullmatch(value) is None:
        raise StrixRuntimeAdmissionResolverError(f"{label} is invalid")
    return value


def _is_link_or_reparse(details: os.stat_result) -> bool:
    return stat.S_ISLNK(details.st_mode) or bool(
        int(getattr(details, "st_file_attributes", 0)) & _REPARSE_POINT
    )


def _identity(details: os.stat_result) -> tuple[int, int]:
    return int(details.st_dev), int(details.st_ino)


def _effective_uid() -> int:
    getter = getattr(os, "geteuid", None)
    if getter is None:  # pragma: no cover - guarded by the POSIX-only callers
        raise StrixRuntimeAdmissionResolverError("effective controller owner is unavailable")
    return int(getter())


def _safe_lstat(path: Path, label: str) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as exc:
        raise StrixRuntimeAdmissionResolverError(f"{label} is unavailable") from exc


def _absolute_components(path: Path) -> tuple[Path, ...]:
    absolute = path.absolute()
    if not absolute.is_absolute() or not absolute.anchor:
        raise StrixRuntimeAdmissionResolverError("protected qualification root is invalid")
    current = Path(absolute.anchor)
    components = [current]
    for part in absolute.parts[1:]:
        current = current / part
        components.append(current)
    return tuple(components)


def _validate_ancestor(path: Path, details: os.stat_result) -> None:
    if not stat.S_ISDIR(details.st_mode) or _is_link_or_reparse(details):
        raise StrixRuntimeAdmissionResolverError(
            "protected qualification root has an unsafe ancestor"
        )
    if os.name != "posix":
        return
    owner = int(details.st_uid)
    effective = _effective_uid()
    if owner not in {0, effective}:
        raise StrixRuntimeAdmissionResolverError(
            "protected qualification root has an untrusted ancestor owner"
        )
    mode = stat.S_IMODE(details.st_mode)
    if mode & 0o022 and not mode & stat.S_ISVTX:
        raise StrixRuntimeAdmissionResolverError(
            "protected qualification root has a replaceable ancestor"
        )


def _validate_private_root(path: Path, details: os.stat_result) -> None:
    _validate_ancestor(path, details)
    if os.name == "nt":
        _verify_windows_private(path, details, directory=True)
        return
    if os.name != "posix":
        raise StrixRuntimeAdmissionResolverError(
            "protected qualification root permissions are unsupported"
        )
    if int(details.st_uid) != _effective_uid() or stat.S_IMODE(details.st_mode) & 0o077:
        raise StrixRuntimeAdmissionResolverError(
            "protected qualification root is not controller-private"
        )


def _verify_windows_private(
    path: Path,
    named_details: os.stat_result,
    *,
    directory: bool,
) -> None:
    descriptor: int | None = None
    try:
        descriptor = _windows_open_descriptor(path, directory=directory)
        opened = os.fstat(descriptor)
        if (
            stat.S_ISDIR(opened.st_mode) is not directory
            or _is_link_or_reparse(opened)
            or _identity(opened) != _identity(named_details)
            or (not directory and int(opened.st_nlink) != 1)
        ):
            raise StrixRuntimeAdmissionResolverError(
                "protected qualification object changed while being opened"
            )
        verify_owner_private_acl(descriptor, directory=directory)
    except StrixRuntimeAdmissionResolverError:
        raise
    except (OSError, WindowsOwnerAclError) as exc:
        raise StrixRuntimeAdmissionResolverError(
            "protected qualification object lacks an owner-private DACL"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _validate_private_artifact(path: Path, details: os.stat_result) -> None:
    if (
        not stat.S_ISREG(details.st_mode)
        or _is_link_or_reparse(details)
        or int(details.st_nlink) != 1
    ):
        raise StrixRuntimeAdmissionResolverError(
            "protected qualification artifact is not a private regular file"
        )
    if os.name == "nt":
        _verify_windows_private(path, details, directory=False)
        return
    if os.name != "posix":
        raise StrixRuntimeAdmissionResolverError(
            "protected qualification artifact permissions are unsupported"
        )
    if int(details.st_uid) != _effective_uid() or stat.S_IMODE(details.st_mode) & 0o077:
        raise StrixRuntimeAdmissionResolverError(
            "protected qualification artifact is not controller-private"
        )


@dataclass(frozen=True, slots=True)
class StrixRuntimeAuthorityRecord:
    """Current head from a trusted append-only runtime-authority source."""

    schema_version: str
    generation: int
    state: str
    qualification_manifest_ref: str
    protected_artifact_key: str
    installed_bluefire_revision: str
    strix_build_digest: str
    threat_review_ref: str
    recorded_at: str
    revocation_reason: str | None

    def __post_init__(self) -> None:
        if self.schema_version != "bluefire.strix-runtime-authority.v1":
            raise StrixRuntimeAdmissionResolverError("runtime authority schema is unsupported")
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation < 1
        ):
            raise StrixRuntimeAdmissionResolverError("runtime authority generation is invalid")
        if self.state not in {"active", "revoked"}:
            raise StrixRuntimeAdmissionResolverError("runtime authority state is invalid")
        _digest(self.qualification_manifest_ref, "runtime qualification manifest ref")
        if (
            not isinstance(self.protected_artifact_key, str)
            or _ARTIFACT_KEY.fullmatch(self.protected_artifact_key) is None
        ):
            raise StrixRuntimeAdmissionResolverError(
                "protected qualification artifact key is invalid"
            )
        _revision(self.installed_bluefire_revision, "installed BlueFire revision")
        _digest(self.strix_build_digest, "Strix build digest")
        _digest(self.threat_review_ref, "threat-review ref")
        try:
            parse_iso8601_datetime(self.recorded_at)
        except (TypeError, ValueError) as exc:
            raise StrixRuntimeAdmissionResolverError(
                "runtime authority timestamp is invalid"
            ) from exc
        if self.state == "active":
            if self.revocation_reason is not None:
                raise StrixRuntimeAdmissionResolverError(
                    "active runtime authority has a revocation reason"
                )
        elif (
            not isinstance(self.revocation_reason, str)
            or not self.revocation_reason
            or len(self.revocation_reason) > 200
            or any(ord(character) < 32 for character in self.revocation_reason)
        ):
            raise StrixRuntimeAdmissionResolverError(
                "revoked runtime authority has no valid reason"
            )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> StrixRuntimeAuthorityRecord:
        if not isinstance(value, Mapping) or set(value) != _AUTHORITY_FIELDS:
            raise StrixRuntimeAdmissionResolverError("runtime authority fields are invalid")
        return cls(**{name: value[name] for name in cls.__dataclass_fields__})

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


class AppendOnlyStrixRuntimeAuthoritySource(Protocol):
    """Return the durable current head of an append-only authority log.

    Implementations must resolve the latest committed generation on every call,
    prevent generation rollback, and retain revoked generations and referenced
    artifacts while any admitted attempt may still require reconciliation.
    """

    def read_current(self) -> StrixRuntimeAuthorityRecord: ...

    def read_exact(
        self,
        *,
        generation: int,
        record_digest: str,
    ) -> StrixRuntimeAuthorityRecord | None: ...

    def is_descendant(
        self,
        *,
        ancestor_generation: int,
        ancestor_record_digest: str,
        descendant_generation: int,
        descendant_record_digest: str,
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class PersistedStrixRuntimeAdmissionRecord:
    """Controller-owned identity for one immutable saved admission."""

    schema_version: str
    record_ref: str
    record_digest: str
    custody_source_ref: str
    custody_record_ref: str
    custody_record_digest: str
    binding_digest: str
    authority_generation: int
    authority_record_digest: str
    delegation_digest: str
    lifecycle_state: str
    lifecycle_head_digest: str
    admission: StrixRuntimeAdmission

    def __post_init__(self) -> None:
        if self.schema_version != "bluefire.persisted-strix-runtime-admission.v1":
            raise StrixRuntimeAdmissionResolverError(
                "persisted Strix admission record schema is unsupported"
            )
        _digest(self.record_ref, "persisted Strix admission record ref")
        _digest(self.record_digest, "persisted Strix admission record digest")
        _digest(self.custody_source_ref, "persisted Strix custody source ref")
        _digest(self.custody_record_ref, "persisted Strix custody record ref")
        _digest(self.custody_record_digest, "persisted Strix custody record digest")
        _digest(self.binding_digest, "persisted Strix binding")
        if (
            isinstance(self.authority_generation, bool)
            or not isinstance(self.authority_generation, int)
            or self.authority_generation < 1
        ):
            raise StrixRuntimeAdmissionResolverError(
                "persisted Strix authority generation is invalid"
            )
        _digest(self.authority_record_digest, "persisted Strix authority record")
        _digest(self.delegation_digest, "persisted Strix delegation")
        if self.lifecycle_state not in {"VERIFIED", "UNKNOWN", "REVOKED", "CLEANED"}:
            raise StrixRuntimeAdmissionResolverError(
                "persisted Strix admission lifecycle is invalid"
            )
        _digest(self.lifecycle_head_digest, "persisted Strix admission lifecycle head")
        if not isinstance(self.admission, StrixRuntimeAdmission):
            raise StrixRuntimeAdmissionResolverError("persisted Strix admission record is invalid")


class StrixQualificationManifestSource(Protocol):
    def load_exact(
        self,
        *,
        protected_artifact_key: str,
        expected_ref: str,
    ) -> QualifiedStrixRuntime: ...


class PersistedStrixRuntimeAdmissionSource(Protocol):
    """Reopen an admission already persisted by the trusted controller."""

    def reopen_exact(
        self,
        *,
        attempt_id: str,
        binding_digest: str,
        delegation_digest: str,
    ) -> PersistedStrixRuntimeAdmissionRecord | None: ...


class ProtectedStrixQualificationManifestSource:
    """Load qualification manifests by opaque key from one pinned private root."""

    def __init__(self, protected_root: Path) -> None:
        if not isinstance(protected_root, Path):
            raise StrixRuntimeAdmissionResolverError("protected qualification root must be a path")
        components = _absolute_components(protected_root)
        pinned: list[tuple[Path, tuple[int, int]]] = []
        for component in components:
            details = _safe_lstat(component, "protected qualification root ancestor")
            _validate_ancestor(component, details)
            pinned.append((component, _identity(details)))
        root = components[-1]
        root_details = _safe_lstat(root, "protected qualification root")
        _validate_private_root(root, root_details)
        self._root = root
        self._pinned_components = tuple(pinned)

    def _revalidate_root(self) -> None:
        for component, expected_identity in self._pinned_components:
            details = _safe_lstat(component, "protected qualification root ancestor")
            _validate_ancestor(component, details)
            if _identity(details) != expected_identity:
                raise StrixRuntimeAdmissionResolverError(
                    "protected qualification root identity changed"
                )
        _validate_private_root(
            self._root,
            _safe_lstat(self._root, "protected qualification root"),
        )

    def load_exact(
        self,
        *,
        protected_artifact_key: str,
        expected_ref: str,
    ) -> QualifiedStrixRuntime:
        if (
            not isinstance(protected_artifact_key, str)
            or _ARTIFACT_KEY.fullmatch(protected_artifact_key) is None
        ):
            raise StrixRuntimeAdmissionResolverError(
                "protected qualification artifact key is invalid"
            )
        _digest(expected_ref, "runtime qualification manifest ref")
        self._revalidate_root()
        artifact = self._root / f"{protected_artifact_key}.json"
        before = _safe_lstat(artifact, "protected qualification artifact")
        _validate_private_artifact(artifact, before)
        before_identity = (
            *_identity(before),
            int(before.st_size),
            int(before.st_mtime_ns),
            int(before.st_ctime_ns),
            int(before.st_nlink),
        )
        try:
            loaded = load_strix_runtime_qualification(artifact, expected_ref=expected_ref)
        except StrixRuntimeQualificationError as exc:
            raise StrixRuntimeAdmissionResolverError(
                "protected qualification artifact is invalid"
            ) from exc
        after = _safe_lstat(artifact, "protected qualification artifact")
        _validate_private_artifact(artifact, after)
        after_identity = (
            *_identity(after),
            int(after.st_size),
            int(after.st_mtime_ns),
            int(after.st_ctime_ns),
            int(after.st_nlink),
        )
        self._revalidate_root()
        if before_identity != after_identity:
            raise StrixRuntimeAdmissionResolverError(
                "protected qualification artifact changed while being loaded"
            )
        return loaded


def _admission_identity_document(
    admission: StrixRuntimeAdmission,
    *,
    custody_source_ref: str,
    custody_record_ref: str,
    custody_record_digest: str,
) -> dict[str, Any]:
    """Canonical non-secret identity for one exact persisted admission."""

    _digest(custody_source_ref, "persisted Strix custody source ref")
    _digest(custody_record_ref, "persisted Strix custody record ref")
    _digest(custody_record_digest, "persisted Strix custody record digest")
    workspace = admission.workspace
    return {
        "schema_version": "bluefire.strix-runtime-admission-identity.v1",
        "objective_ref": admission.objective_ref,
        "environment_ref": admission.environment_ref,
        "runtime_qualification_ref": admission.runtime_qualification_ref,
        "runtime_qualified": admission.runtime_qualified,
        "build": admission.build.to_dict(),
        "scope": {
            "target": admission.scope.target,
            "resolved_addresses": list(admission.scope.resolved_addresses),
            "target_snapshot_digest": admission.scope.target_snapshot_digest,
            "scope_digest": admission.scope.scope_digest,
            "network_policy_digest": admission.scope.network_policy_digest,
            "network_name": admission.scope.network_name,
        },
        "gateway": {
            "model": admission.gateway.model,
            "base_url": admission.gateway.base_url,
            "authorization_digest": admission.gateway.authorization_digest,
        },
        "budgets": {
            "wall_seconds": admission.budgets.wall_seconds,
            "max_turns_per_agent": admission.budgets.max_turns_per_agent,
            "max_model_cost_usd": admission.budgets.max_model_cost_usd,
        },
        "limits": {
            "memory": admission.limits.memory,
            "cpus": admission.limits.cpus,
            "pids": admission.limits.pids,
            "log_size": admission.limits.log_size,
            "log_files": admission.limits.log_files,
        },
        "workspace": {
            "attempt_id": workspace.attempt_id,
            "cwd": str(workspace.cwd),
            "home": str(workspace.home),
            "temporary": str(workspace.temporary),
            "objective_file": str(workspace.objective_file),
            "config_file": str(workspace.config_file),
            "mcp_file": str(workspace.mcp_file),
            "objective_sha256": workspace.objective_sha256,
        },
        "executable": str(admission.executable),
        "path_environment": admission.path_environment,
        "control_root": str(admission.control_root),
        "network_plan": admission.network_plan.to_dict(),
        "network_snapshot": admission.network_snapshot.to_dict(),
        "network_verification": admission.network_verification.to_dict(),
        "custody_plan": admission.custody_plan.to_dict(),
        "protected_roots": admission.protected_roots.to_dict(),
        "containment": admission.containment.to_dict(),
        "custody_source_ref": custody_source_ref,
        "custody_record_ref": custody_record_ref,
        "custody_record_digest": custody_record_digest,
    }


def _persisted_record_identity(record: PersistedStrixRuntimeAdmissionRecord) -> str:
    return content_hash(
        {
            "schema_version": record.schema_version,
            "record_ref": record.record_ref,
            "record_digest": record.record_digest,
            "custody_source_ref": record.custody_source_ref,
            "custody_record_ref": record.custody_record_ref,
            "custody_record_digest": record.custody_record_digest,
            "binding_digest": record.binding_digest,
            "authority_generation": record.authority_generation,
            "authority_record_digest": record.authority_record_digest,
            "delegation_digest": record.delegation_digest,
            "lifecycle_state": record.lifecycle_state,
            "lifecycle_head_digest": record.lifecycle_head_digest,
            "admission_identity": _admission_identity_document(
                record.admission,
                custody_source_ref=record.custody_source_ref,
                custody_record_ref=record.custody_record_ref,
                custody_record_digest=record.custody_record_digest,
            ),
        }
    )


class ControllerQualifiedStrixAdmissionResolver:
    """Resolve only the exact controller-saved admission for one attempt."""

    def __init__(
        self,
        *,
        authority_source: AppendOnlyStrixRuntimeAuthoritySource,
        protected_manifest_source: StrixQualificationManifestSource,
        persisted_admission_source: PersistedStrixRuntimeAdmissionSource,
        installed_bluefire_revision: str,
    ) -> None:
        self._authority_source = authority_source
        self._manifest_source = protected_manifest_source
        self._admission_source = persisted_admission_source
        self._installed_bluefire_revision = _revision(
            installed_bluefire_revision, "installed BlueFire revision"
        )

    def resolve(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
    ) -> StrixRuntimeAdmission:
        return self._resolve(binding, delegation, launch_only=False).admission

    def resolve_for_launch(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
    ) -> StrixRuntimeAdmissionResolution:
        return self._resolve(binding, delegation, launch_only=True)

    def require_current(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        *,
        expected_resolution_ref: str,
    ) -> StrixRuntimeAdmissionResolution:
        _digest(expected_resolution_ref, "expected Strix runtime resolution")
        current = self._resolve(binding, delegation, launch_only=True)
        if current.resolution_ref != expected_resolution_ref:
            raise StrixRuntimeAdmissionResolverError(
                "Strix runtime authority or saved admission changed before launch"
            )
        return current

    def _resolve(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        *,
        launch_only: bool,
    ) -> StrixRuntimeAdmissionResolution:
        try:
            checked_delegation = EngineCapabilityDelegation.from_mapping(delegation.to_dict())
            checked_binding = checked_delegation.validate_attempt_binding(binding)
        except (AttributeError, TypeError, ValueError) as exc:
            raise StrixRuntimeAdmissionResolverError("Strix attempt authority is invalid") from exc

        try:
            current = self._authority_source.read_current()
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise StrixRuntimeAdmissionResolverError("runtime authority is unavailable") from exc
        if not isinstance(current, StrixRuntimeAuthorityRecord):
            raise StrixRuntimeAdmissionResolverError("runtime authority is invalid")
        current_authority = StrixRuntimeAuthorityRecord.from_mapping(current.to_dict())
        if current_authority.installed_bluefire_revision != self._installed_bluefire_revision:
            raise StrixRuntimeAdmissionResolverError(
                "runtime authority belongs to another BlueFire revision"
            )
        current_authority_digest = content_hash(current_authority.to_dict())

        try:
            persisted = self._admission_source.reopen_exact(
                attempt_id=checked_binding.attempt_id,
                binding_digest=checked_binding.binding_digest,
                delegation_digest=checked_delegation.delegation_digest,
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise StrixRuntimeAdmissionResolverError(
                "persisted Strix admission is unavailable"
            ) from exc
        if persisted is None:
            raise StrixRuntimeAdmissionResolverError("persisted Strix admission is missing")
        if not isinstance(persisted, PersistedStrixRuntimeAdmissionRecord):
            raise StrixRuntimeAdmissionResolverError(
                "persisted Strix admission source returned an invalid record"
            )
        if (
            persisted.binding_digest != checked_binding.binding_digest
            or persisted.delegation_digest != checked_delegation.delegation_digest
        ):
            raise StrixRuntimeAdmissionResolverError(
                "persisted Strix admission record differs from the exact attempt authority"
            )
        persisted_identity = _persisted_record_identity(persisted)
        try:
            admitted_raw = self._authority_source.read_exact(
                generation=persisted.authority_generation,
                record_digest=persisted.authority_record_digest,
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise StrixRuntimeAdmissionResolverError(
                "admitted runtime authority is unavailable"
            ) from exc
        if not isinstance(admitted_raw, StrixRuntimeAuthorityRecord):
            raise StrixRuntimeAdmissionResolverError(
                "admitted runtime authority is missing or invalid"
            )
        admitted_authority = StrixRuntimeAuthorityRecord.from_mapping(admitted_raw.to_dict())
        if (
            admitted_authority.generation != persisted.authority_generation
            or content_hash(admitted_authority.to_dict()) != persisted.authority_record_digest
            or admitted_authority.installed_bluefire_revision != self._installed_bluefire_revision
            or admitted_authority.state != "active"
        ):
            raise StrixRuntimeAdmissionResolverError(
                "persisted Strix admission authority provenance is invalid"
            )
        exact_current_head = (
            current_authority.generation == persisted.authority_generation
            and current_authority_digest == persisted.authority_record_digest
        )
        if not exact_current_head:
            try:
                descendant = self._authority_source.is_descendant(
                    ancestor_generation=persisted.authority_generation,
                    ancestor_record_digest=persisted.authority_record_digest,
                    descendant_generation=current_authority.generation,
                    descendant_record_digest=current_authority_digest,
                )
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                raise StrixRuntimeAdmissionResolverError(
                    "current runtime authority lineage is unavailable"
                ) from exc
            if descendant is not True:
                raise StrixRuntimeAdmissionResolverError(
                    "current runtime authority is not a proven descendant"
                )

        qualified = self._manifest_source.load_exact(
            protected_artifact_key=admitted_authority.protected_artifact_key,
            expected_ref=admitted_authority.qualification_manifest_ref,
        )
        if not isinstance(qualified, QualifiedStrixRuntime):
            raise StrixRuntimeAdmissionResolverError(
                "protected qualification source returned an invalid value"
            )
        if (
            qualified.runtime_qualification_ref != admitted_authority.qualification_manifest_ref
            or qualified.bluefire_source_revision != admitted_authority.installed_bluefire_revision
            or content_hash(qualified.build.to_dict()) != admitted_authority.strix_build_digest
            or qualified.threat_review_ref != admitted_authority.threat_review_ref
            or qualified.runtime_qualified is not True
        ):
            raise StrixRuntimeAdmissionResolverError(
                "runtime qualification differs from admitted controller authority"
            )
        saved = persisted.admission
        if not isinstance(saved, StrixRuntimeAdmission) or not isinstance(
            saved.build, StrixBuildIdentity
        ):
            raise StrixRuntimeAdmissionResolverError("persisted Strix admission is invalid")
        if (
            saved.objective_ref != checked_binding.objective_ref
            or saved.environment_ref != checked_binding.environment_ref
            or saved.runtime_qualification_ref != admitted_authority.qualification_manifest_ref
            or saved.build.to_dict() != qualified.build.to_dict()
            or content_hash(saved.build.to_dict()) != admitted_authority.strix_build_digest
            or checked_binding.engine_id != "strix"
            or checked_binding.engine_version != saved.build.package_version
            or checked_binding.engine_revision != saved.build.source_revision
            or checked_binding.engine_package_digest != saved.build.package_sha256
            or checked_binding.policy_overlay_digest != saved.build.prompt_overlay_sha256
        ):
            raise StrixRuntimeAdmissionResolverError(
                "persisted Strix admission differs from the exact attempt authority"
            )
        try:
            final_persisted = self._admission_source.reopen_exact(
                attempt_id=checked_binding.attempt_id,
                binding_digest=checked_binding.binding_digest,
                delegation_digest=checked_delegation.delegation_digest,
            )
            final_current_raw = self._authority_source.read_current()
            final_persisted_identity = (
                _persisted_record_identity(final_persisted)
                if isinstance(final_persisted, PersistedStrixRuntimeAdmissionRecord)
                else None
            )
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as exc:
            raise StrixRuntimeAdmissionResolverError(
                "runtime authority changed while admission was resolved"
            ) from exc
        if (
            not isinstance(final_persisted, PersistedStrixRuntimeAdmissionRecord)
            or final_persisted_identity != persisted_identity
            or not isinstance(final_current_raw, StrixRuntimeAuthorityRecord)
        ):
            raise StrixRuntimeAdmissionResolverError(
                "runtime authority changed while admission was resolved"
            )
        final_current = StrixRuntimeAuthorityRecord.from_mapping(final_current_raw.to_dict())
        if (
            final_current.generation != current_authority.generation
            or content_hash(final_current.to_dict()) != current_authority_digest
        ):
            raise StrixRuntimeAdmissionResolverError(
                "runtime authority changed while admission was resolved"
            )
        launchable = exact_current_head and persisted.lifecycle_state == "VERIFIED"
        if launch_only and not launchable:
            raise StrixRuntimeAdmissionResolverError(
                "runtime authority or admission lifecycle is no longer launchable"
            )
        if not launchable:
            saved = (
                saved
                if saved.runtime_qualified is False
                else replace(saved, runtime_qualified=False)
            )
        elif saved.runtime_qualified is not True:
            raise StrixRuntimeAdmissionResolverError(
                "persisted Strix admission is not launch-qualified"
            )
        admission_identity_digest = content_hash(
            _admission_identity_document(
                saved,
                custody_source_ref=persisted.custody_source_ref,
                custody_record_ref=persisted.custody_record_ref,
                custody_record_digest=persisted.custody_record_digest,
            )
        )
        resolution_ref = content_hash(
            {
                "schema_version": "bluefire.strix-runtime-resolution.v1",
                "binding_digest": checked_binding.binding_digest,
                "delegation_digest": checked_delegation.delegation_digest,
                "admitted_authority_generation": persisted.authority_generation,
                "admitted_authority_record_digest": persisted.authority_record_digest,
                "current_authority_generation": current_authority.generation,
                "current_authority_record_digest": current_authority_digest,
                "persisted_admission_record_ref": persisted.record_ref,
                "persisted_admission_record_digest": persisted.record_digest,
                "custody_source_ref": persisted.custody_source_ref,
                "custody_record_ref": persisted.custody_record_ref,
                "custody_record_digest": persisted.custody_record_digest,
                "lifecycle_state": persisted.lifecycle_state,
                "lifecycle_head_digest": persisted.lifecycle_head_digest,
                "admission_identity_digest": admission_identity_digest,
            }
        )
        return StrixRuntimeAdmissionResolution(
            admission=saved,
            resolution_ref=resolution_ref,
        )


__all__ = [
    "AppendOnlyStrixRuntimeAuthoritySource",
    "ControllerQualifiedStrixAdmissionResolver",
    "PersistedStrixRuntimeAdmissionRecord",
    "PersistedStrixRuntimeAdmissionSource",
    "ProtectedStrixQualificationManifestSource",
    "StrixQualificationManifestSource",
    "StrixRuntimeAdmissionResolverError",
    "StrixRuntimeAuthorityRecord",
]
