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
from .strix_engine_runtime import StrixRuntimeAdmission
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
        runtime_qualification_ref: str,
    ) -> StrixRuntimeAdmission | None: ...


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
        authority = StrixRuntimeAuthorityRecord.from_mapping(current.to_dict())
        if authority.installed_bluefire_revision != self._installed_bluefire_revision:
            raise StrixRuntimeAdmissionResolverError(
                "runtime authority belongs to another BlueFire revision"
            )

        qualified = self._manifest_source.load_exact(
            protected_artifact_key=authority.protected_artifact_key,
            expected_ref=authority.qualification_manifest_ref,
        )
        if not isinstance(qualified, QualifiedStrixRuntime):
            raise StrixRuntimeAdmissionResolverError(
                "protected qualification source returned an invalid value"
            )
        if (
            qualified.runtime_qualification_ref != authority.qualification_manifest_ref
            or qualified.bluefire_source_revision != authority.installed_bluefire_revision
            or content_hash(qualified.build.to_dict()) != authority.strix_build_digest
            or qualified.threat_review_ref != authority.threat_review_ref
            or qualified.runtime_qualified is not True
        ):
            raise StrixRuntimeAdmissionResolverError(
                "runtime qualification differs from controller authority"
            )

        try:
            saved = self._admission_source.reopen_exact(
                attempt_id=checked_binding.attempt_id,
                binding_digest=checked_binding.binding_digest,
                runtime_qualification_ref=authority.qualification_manifest_ref,
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise StrixRuntimeAdmissionResolverError(
                "persisted Strix admission is unavailable"
            ) from exc
        if saved is None:
            raise StrixRuntimeAdmissionResolverError("persisted Strix admission is missing")
        if not isinstance(saved, StrixRuntimeAdmission) or not isinstance(
            saved.build, StrixBuildIdentity
        ):
            raise StrixRuntimeAdmissionResolverError("persisted Strix admission is invalid")
        if (
            saved.objective_ref != checked_binding.objective_ref
            or saved.environment_ref != checked_binding.environment_ref
            or saved.runtime_qualification_ref != authority.qualification_manifest_ref
            or saved.build.to_dict() != qualified.build.to_dict()
            or content_hash(saved.build.to_dict()) != authority.strix_build_digest
            or checked_binding.engine_id != "strix"
            or checked_binding.engine_version != saved.build.package_version
            or checked_binding.engine_revision != saved.build.source_revision
            or checked_binding.engine_package_digest != saved.build.package_sha256
            or checked_binding.policy_overlay_digest != saved.build.prompt_overlay_sha256
        ):
            raise StrixRuntimeAdmissionResolverError(
                "persisted Strix admission differs from the exact attempt authority"
            )
        if authority.state == "active":
            if saved.runtime_qualified is not True:
                raise StrixRuntimeAdmissionResolverError(
                    "persisted Strix admission is not launch-qualified"
                )
            return saved
        return (
            saved if saved.runtime_qualified is False else replace(saved, runtime_qualified=False)
        )


__all__ = [
    "AppendOnlyStrixRuntimeAuthoritySource",
    "ControllerQualifiedStrixAdmissionResolver",
    "PersistedStrixRuntimeAdmissionSource",
    "ProtectedStrixQualificationManifestSource",
    "StrixQualificationManifestSource",
    "StrixRuntimeAdmissionResolverError",
    "StrixRuntimeAuthorityRecord",
]
