"""Path-contained raw artifact intake for externally managed engine attempts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import threading
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

from .util import canonical_json_bytes, content_hash
from .windows_owner_acl import (
    WindowsOwnerAclError,
    _windows_extended_path,
    _windows_mark_delete_descriptor,
    _windows_open_descriptor,
    apply_owner_private_acl,
    verify_owner_private_acl,
)


class EngineArtifactStoreError(ValueError):
    """Raised when an engine artifact is outside the reviewed intake contract."""


class EngineArtifactPublicationUnknown(EngineArtifactStoreError):
    """A complete attempt was renamed into place but commit durability is unknown."""


ATTEMPT_ID = re.compile(r"^engine-attempt-[0-9a-f]{32}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
SAFE_PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DEFAULT_MAX_FILE_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_FILES = 64
MAX_MANIFEST_BYTES = 512 * 1024
MAX_SOURCE_TREE_ENTRIES = 4096
MAX_SOURCE_TREE_DEPTH = 32
V1_MANIFEST_SCHEMA = "bluefire.engine-artifacts.v1"
V2_MANIFEST_SCHEMA = "bluefire.engine-artifacts.v2"
PUBLICATION_BINDING_SCHEMA = "bluefire.engine-artifact-publication-binding.v1"
PUBLICATION_REF_SCHEMA = "bluefire.engine-artifact-publication-ref.v1"
PUBLICATION_SEAL_SCHEMA = "bluefire.engine-artifact-publication-seal.v2"
WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)


class _ControllerSourceAuthority:
    __slots__ = ()


_CONTROLLER_SOURCE_AUTHORITY = _ControllerSourceAuthority()


@dataclass(frozen=True, slots=True, init=False)
class SourceCollectionSeal:
    """Controller receipt for an immutable, stopped worker output snapshot.

    The service issues this only after it has stopped the worker and revoked its
    write access. It is not an assertion accepted from the external engine.
    """

    schema_version: str
    attempt_id: str
    source_root_device: int
    source_root_inode: int
    source_root_mtime_ns: int
    source_tree_digest: str
    worker_state: str
    write_access_revoked: bool
    controller_receipt_digest: str
    _controller_attestation: object = field(
        repr=False,
        compare=False,
        init=False,
    )

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
        *,
        _controller_authority: object | None = None,
    ) -> "SourceCollectionSeal":
        if _controller_authority is not _CONTROLLER_SOURCE_AUTHORITY:
            raise EngineArtifactStoreError("source collection seal requires controller authority")
        fields = frozenset(name for name in cls.__dataclass_fields__ if not name.startswith("_"))
        if not isinstance(value, Mapping) or set(value) != fields:
            raise EngineArtifactStoreError("source collection seal fields are invalid")
        attempt_id = value["attempt_id"]
        digest = value["controller_receipt_digest"]
        tree_digest = value["source_tree_digest"]
        identities = (
            value["source_root_device"],
            value["source_root_inode"],
            value["source_root_mtime_ns"],
        )
        if (
            value["schema_version"] != "bluefire.engine-source-collection-seal.v1"
            or not isinstance(attempt_id, str)
            or ATTEMPT_ID.fullmatch(attempt_id) is None
            or any(
                isinstance(item, bool) or not isinstance(item, int) or item < 0
                for item in identities
            )
            or value["worker_state"] != "stopped"
            or value["write_access_revoked"] is not True
            or not isinstance(tree_digest, str)
            or SHA256.fullmatch(tree_digest) is None
            or not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None
        ):
            raise EngineArtifactStoreError(
                "source collection seal is not a trusted stopped snapshot"
            )
        seal = object.__new__(cls)
        admitted = {
            "schema_version": "bluefire.engine-source-collection-seal.v1",
            "attempt_id": attempt_id,
            "source_root_device": int(identities[0]),
            "source_root_inode": int(identities[1]),
            "source_root_mtime_ns": int(identities[2]),
            "source_tree_digest": tree_digest,
            "worker_state": "stopped",
            "write_access_revoked": True,
            "controller_receipt_digest": digest,
            "_controller_attestation": _CONTROLLER_SOURCE_AUTHORITY,
        }
        for name, admitted_value in admitted.items():
            object.__setattr__(seal, name, admitted_value)
        return seal

    def to_dict(self) -> dict[str, Any]:
        if self._controller_attestation is not _CONTROLLER_SOURCE_AUTHORITY:
            raise EngineArtifactStoreError("source collection seal requires controller authority")
        document = {
            "schema_version": self.schema_version,
            "attempt_id": self.attempt_id,
            "source_root_device": self.source_root_device,
            "source_root_inode": self.source_root_inode,
            "source_root_mtime_ns": self.source_root_mtime_ns,
            "source_tree_digest": self.source_tree_digest,
            "worker_state": self.worker_state,
            "write_access_revoked": self.write_access_revoked,
            "controller_receipt_digest": self.controller_receipt_digest,
        }
        recreated = type(self).from_mapping(
            document,
            _controller_authority=_CONTROLLER_SOURCE_AUTHORITY,
        )
        if recreated != self:
            raise EngineArtifactStoreError("source collection seal bypassed canonical validation")
        return document


@dataclass(frozen=True, slots=True)
class EngineArtifactPublicationBinding:
    """Immutable execution identity bound into a recoverable artifact publication."""

    attempt_id: str
    binding_digest: str
    delegation_digest: str
    launch_digest: str
    runtime_resolution_ref: str
    execution_claim_ref: str
    worker_outcome_digest: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.attempt_id, str)
            or ATTEMPT_ID.fullmatch(self.attempt_id) is None
            or any(
                not isinstance(value, str) or SHA256.fullmatch(value) is None
                for value in (
                    self.binding_digest,
                    self.delegation_digest,
                    self.launch_digest,
                    self.runtime_resolution_ref,
                    self.execution_claim_ref,
                    self.worker_outcome_digest,
                )
            )
        ):
            raise EngineArtifactStoreError("artifact publication binding is invalid")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "EngineArtifactPublicationBinding":
        fields = {
            "schema_version",
            "attempt_id",
            "binding_digest",
            "delegation_digest",
            "launch_digest",
            "runtime_resolution_ref",
            "execution_claim_ref",
            "worker_outcome_digest",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise EngineArtifactStoreError("artifact publication binding fields are invalid")
        if value.get("schema_version") != PUBLICATION_BINDING_SCHEMA:
            raise EngineArtifactStoreError("artifact publication binding schema is invalid")
        try:
            return cls(
                attempt_id=value["attempt_id"],
                binding_digest=value["binding_digest"],
                delegation_digest=value["delegation_digest"],
                launch_digest=value["launch_digest"],
                runtime_resolution_ref=value["runtime_resolution_ref"],
                execution_claim_ref=value["execution_claim_ref"],
                worker_outcome_digest=value["worker_outcome_digest"],
            )
        except (KeyError, TypeError, EngineArtifactStoreError):
            raise EngineArtifactStoreError("artifact publication binding is invalid") from None

    def to_dict(self) -> dict[str, str]:
        return {
            "schema_version": PUBLICATION_BINDING_SCHEMA,
            "attempt_id": self.attempt_id,
            "binding_digest": self.binding_digest,
            "delegation_digest": self.delegation_digest,
            "launch_digest": self.launch_digest,
            "runtime_resolution_ref": self.runtime_resolution_ref,
            "execution_claim_ref": self.execution_claim_ref,
            "worker_outcome_digest": self.worker_outcome_digest,
        }


@dataclass(frozen=True, slots=True)
class ReopenedEngineArtifact:
    """One exact retained artifact whose payload was verified through a descriptor."""

    name: str
    size_bytes: int
    sha256: str
    payload: bytes = field(repr=False)

    def to_manifest_row(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class ReopenedEngineArtifactAttempt:
    """Immutable, bounded snapshot of one strictly validated final publication."""

    schema_version: str
    attempt_id: str
    storage_boundary: str
    source_collection_receipt: str
    source_tree_digest: str | None
    source_collection_seal_ref: str | None
    source_collection_seal: SourceCollectionSeal | None = field(repr=False)
    artifact_publication_ref: str | None
    publication_binding: EngineArtifactPublicationBinding | None
    artifacts: tuple[ReopenedEngineArtifact, ...]
    total_bytes: int
    manifest_ref: str
    recovery_eligible: bool

    def to_manifest(self) -> dict[str, Any]:
        rows = [artifact.to_manifest_row() for artifact in self.artifacts]
        common: dict[str, Any] = {
            "schema_version": self.schema_version,
            "attempt_id": self.attempt_id,
            "storage_boundary": self.storage_boundary,
            "source_collection_receipt": self.source_collection_receipt,
            "artifact_count": len(rows),
            "total_bytes": self.total_bytes,
            "artifacts": rows,
        }
        if self.schema_version == V2_MANIFEST_SCHEMA:
            if (
                self.source_tree_digest is None
                or self.source_collection_seal_ref is None
                or self.source_collection_seal is None
                or self.artifact_publication_ref is None
                or self.publication_binding is None
            ):
                raise EngineArtifactStoreError("artifact publication snapshot is incomplete")
            common.update(
                {
                    "source_tree_digest": self.source_tree_digest,
                    "source_collection_seal_ref": self.source_collection_seal_ref,
                    "source_collection_seal": self.source_collection_seal.to_dict(),
                    "artifact_publication_ref": self.artifact_publication_ref,
                    "publication_binding": self.publication_binding.to_dict(),
                }
            )
        return common

    def publication_seal(self) -> dict[str, str]:
        """Return the stable cleanup identity shared by live and recovery paths."""

        if (
            not self.recovery_eligible
            or self.artifact_publication_ref is None
            or self.source_tree_digest is None
            or self.source_collection_seal_ref is None
        ):
            raise EngineArtifactStoreError("legacy artifact publication has no recovery seal")
        return {
            "schema_version": PUBLICATION_SEAL_SCHEMA,
            "attempt_id": self.attempt_id,
            "artifact_publication_ref": self.artifact_publication_ref,
            "source_collection_receipt": self.source_collection_receipt,
            "source_tree_digest": self.source_tree_digest,
            "source_collection_seal_ref": self.source_collection_seal_ref,
        }


def _safe_name(value: object) -> tuple[str, tuple[str, ...]]:
    if not isinstance(value, str) or not value or len(value) > 512 or "\\" in value:
        raise EngineArtifactStoreError("artifact name is invalid")
    path = PurePosixPath(value)
    parts = path.parts
    normalized = path.as_posix()
    if (
        path.is_absolute()
        or not parts
        or normalized != value
        or any(
            SAFE_PART.fullmatch(part) is None
            or part.endswith(".")
            or part.split(".", 1)[0].upper() in WINDOWS_RESERVED
            for part in parts
        )
    ):
        raise EngineArtifactStoreError("artifact name is outside the contained namespace")
    return normalized, parts


def _is_reparse(details: os.stat_result) -> bool:
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
    return bool(int(getattr(details, "st_file_attributes", 0)) & marker)


def source_collection_tree_digest(source_run_dir: str | Path) -> str:
    """Bind one bounded source tree without following links or reparse points."""

    root = Path(source_run_dir)
    if os.name == "nt":
        root = _windows_extended_path(root)
    try:
        root_details = root.lstat()
    except OSError as exc:
        raise EngineArtifactStoreError("source run directory is unavailable") from exc
    if root.is_symlink() or _is_reparse(root_details) or not stat.S_ISDIR(root_details.st_mode):
        raise EngineArtifactStoreError("source run directory is unsafe")

    records: list[dict[str, Any]] = []
    pending: list[tuple[Path, tuple[str, ...]]] = [(root, ())]
    while pending:
        current, relative = pending.pop()
        if len(relative) >= MAX_SOURCE_TREE_DEPTH:
            raise EngineArtifactStoreError("source run directory exceeds its depth bound")
        try:
            with os.scandir(current) as iterator:
                entries: list[os.DirEntry[str]] = []
                remaining = MAX_SOURCE_TREE_ENTRIES - len(records)
                for entry in iterator:
                    if len(entries) >= remaining:
                        raise EngineArtifactStoreError(
                            "source run directory exceeds its entry bound"
                        )
                    entries.append(entry)
        except OSError as exc:
            raise EngineArtifactStoreError("source run directory could not be enumerated") from exc
        entries.sort(key=lambda item: (item.name.casefold(), item.name))
        child_directories: list[tuple[Path, tuple[str, ...]]] = []
        for entry in entries:
            try:
                details = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise EngineArtifactStoreError(
                    "source run directory changed during snapshot"
                ) from exc
            entry_relative = (*relative, entry.name)
            if _is_reparse(details):
                kind = "reparse"
            elif stat.S_ISLNK(details.st_mode):
                kind = "symlink"
            elif stat.S_ISDIR(details.st_mode):
                kind = "directory"
                child_directories.append((Path(entry.path), entry_relative))
            elif stat.S_ISREG(details.st_mode):
                kind = "file"
            else:
                kind = "special"
            records.append(
                {
                    "path_bytes": [os.fsencode(part).hex() for part in entry_relative],
                    "kind": kind,
                    "size": details.st_size,
                }
            )
        pending.extend(reversed(child_directories))
    return content_hash(
        {
            "schema_version": "bluefire.engine-source-tree.v1",
            "root_device": root_details.st_dev,
            "root_inode": root_details.st_ino,
            "entries": records,
        }
    )


def normalized_finding_id(attempt_id: str, source_artifact_digest: str, ordinal: int) -> str:
    """Return a stable source identity without treating the finding as verified."""

    if ATTEMPT_ID.fullmatch(attempt_id) is None:
        raise EngineArtifactStoreError("attempt identity is invalid")
    if SHA256.fullmatch(source_artifact_digest) is None:
        raise EngineArtifactStoreError("source artifact digest is invalid")
    if isinstance(ordinal, bool) or not isinstance(ordinal, int) or not 0 <= ordinal <= 1_000_000:
        raise EngineArtifactStoreError("finding ordinal is invalid")
    digest = content_hash(
        {
            "attempt_id": attempt_id,
            "source_artifact_digest": source_artifact_digest,
            "ordinal": ordinal,
        }
    )
    return "engine-finding-" + digest.removeprefix("sha256:")[:24]


class EngineArtifactStore:
    """Copy a finite controller-selected artifact set into an owned store root.

    This boundary establishes path containment, exact bytes, and exclusive
    publication. The caller provisions the ProductStore root. This module
    verifies its owner-private boundary before reading source or writing bytes;
    children inherit that boundary on Windows.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
        max_files: int = DEFAULT_MAX_FILES,
    ) -> None:
        if (
            isinstance(max_file_bytes, bool)
            or not isinstance(max_file_bytes, int)
            or not 1 <= max_file_bytes <= 64 * 1024 * 1024
            or isinstance(max_total_bytes, bool)
            or not isinstance(max_total_bytes, int)
            or not max_file_bytes <= max_total_bytes <= 64 * 1024 * 1024
            or isinstance(max_files, bool)
            or not isinstance(max_files, int)
            or not 1 <= max_files <= 256
        ):
            raise EngineArtifactStoreError("artifact store bounds are invalid")
        candidate = Path(root).expanduser()
        if os.name == "nt":
            candidate = _windows_extended_path(candidate)
        self._prepare_root(candidate)
        details = candidate.lstat()
        if candidate.is_symlink() or _is_reparse(details) or not stat.S_ISDIR(details.st_mode):
            raise EngineArtifactStoreError("artifact store root is unsafe")
        self.root = candidate.resolve(strict=True)
        self._verify_protected_root(self.root)
        self._root_identity = self._filesystem_identity(self.root.lstat())
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.max_files = max_files
        self._publish_lock = threading.RLock()

    @staticmethod
    def _prepare_root(path: Path) -> None:
        if os.name == "nt":
            if not path.exists():
                raise EngineArtifactStoreError(
                    "Windows artifact store root must be provisioned by ProductStore"
                )
            return
        try:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise EngineArtifactStoreError("artifact store root is unavailable") from exc

    def import_attempt(
        self,
        *,
        attempt_id: str,
        source_run_dir: str | Path,
        source_seal: SourceCollectionSeal,
        allowed_names: Iterable[str],
    ) -> dict[str, Any]:
        seal = self._validated_source_seal(attempt_id, source_seal)
        selected = self._normalize_selection(allowed_names, canonical_order=False)
        payloads = self._collect_source_payloads(source_run_dir, seal, selected)
        rows: list[dict[str, Any]] = [
            {"name": name, "size_bytes": len(payload), "sha256": digest}
            for name, _parts, payload, digest in payloads
        ]
        total_bytes = sum(len(payload) for _name, _parts, payload, _digest in payloads)
        manifest = {
            "schema_version": V1_MANIFEST_SCHEMA,
            "attempt_id": attempt_id,
            "storage_boundary": "contained_exclusive_protected_root",
            "source_collection_receipt": seal.controller_receipt_digest,
            "artifact_count": len(rows),
            "total_bytes": total_bytes,
            "artifacts": rows,
        }
        with self._publish_lock:
            self._publish_payloads_locked(attempt_id, payloads, manifest)
        return manifest

    def import_or_reopen(
        self,
        *,
        attempt_id: str,
        source_run_dir: str | Path,
        source_seal: SourceCollectionSeal,
        allowed_names: Iterable[str],
        publication_binding: EngineArtifactPublicationBinding,
    ) -> ReopenedEngineArtifactAttempt:
        """Publish v2 exactly once or reopen the byte-identical final publication.

        A final directory is the durable idempotency anchor. Existing partial
        staging never becomes evidence and is never removed by this recovery
        path. A legacy v1 publication remains readable history but cannot be
        upgraded or treated as a recoverable execution settlement.
        """

        seal = self._validated_source_seal(attempt_id, source_seal)
        binding = self._validated_publication_binding(attempt_id, publication_binding)
        selected = self._normalize_selection(allowed_names, canonical_order=True)
        with self._publish_lock:
            existing = self._reopen_if_final_locked(attempt_id)
            if existing is not None:
                self._require_matching_retry(existing, seal, binding, selected)
                return existing

        payloads = self._collect_source_payloads(source_run_dir, seal, selected)
        rows: list[dict[str, Any]] = [
            {"name": name, "size_bytes": len(payload), "sha256": digest}
            for name, _parts, payload, digest in payloads
        ]
        total_bytes = sum(len(payload) for _name, _parts, payload, _digest in payloads)
        seal_ref = content_hash(seal.to_dict())
        seal_document = seal.to_dict()
        identity = {
            "schema_version": PUBLICATION_REF_SCHEMA,
            "attempt_id": attempt_id,
            "source_collection_receipt": seal.controller_receipt_digest,
            "source_tree_digest": seal.source_tree_digest,
            "source_collection_seal_ref": seal_ref,
            "source_collection_seal": seal_document,
            "publication_binding": binding.to_dict(),
            "artifact_count": len(rows),
            "total_bytes": total_bytes,
            "artifacts": rows,
        }
        manifest = {
            "schema_version": V2_MANIFEST_SCHEMA,
            "attempt_id": attempt_id,
            "storage_boundary": "contained_exclusive_protected_root",
            "artifact_publication_ref": content_hash(identity),
            "source_collection_receipt": seal.controller_receipt_digest,
            "source_tree_digest": seal.source_tree_digest,
            "source_collection_seal_ref": seal_ref,
            "source_collection_seal": seal_document,
            "publication_binding": binding.to_dict(),
            "artifact_count": len(rows),
            "total_bytes": identity["total_bytes"],
            "artifacts": rows,
        }
        with self._publish_lock:
            existing = self._reopen_if_final_locked(attempt_id)
            if existing is not None:
                self._require_matching_retry(existing, seal, binding, selected)
                return existing
            try:
                self._publish_payloads_locked(attempt_id, payloads, manifest)
            except EngineArtifactPublicationUnknown:
                raise
            except EngineArtifactStoreError:
                existing = self._reopen_if_final_locked(attempt_id)
                if existing is None:
                    raise
                self._require_matching_retry(existing, seal, binding, selected)
                return existing
            reopened = self._reopen_attempt_locked(attempt_id)
            self._require_matching_retry(reopened, seal, binding, selected)
            return reopened

    def reopen_attempt(self, attempt_id: str) -> ReopenedEngineArtifactAttempt:
        """Strictly validate and return one bounded immutable final snapshot.

        Legacy v1 publications are display-only and must still satisfy current
        exact protection checks. We never rewrite or relax historical entries.
        """

        if not isinstance(attempt_id, str) or ATTEMPT_ID.fullmatch(attempt_id) is None:
            raise EngineArtifactStoreError("attempt identity is invalid")
        with self._publish_lock:
            pending = self.root / (".pending-" + attempt_id)
            if self._entry_exists(pending):
                raise EngineArtifactPublicationUnknown(
                    "artifact publication is incomplete and requires recovery"
                )
            return self._reopen_attempt_locked(attempt_id)

    def _reopen_if_final_locked(self, attempt_id: str) -> ReopenedEngineArtifactAttempt | None:
        pending = self.root / (".pending-" + attempt_id)
        if self._entry_exists(pending):
            raise EngineArtifactPublicationUnknown(
                "artifact publication is incomplete and requires recovery"
            )
        if not self._entry_exists(self.root / attempt_id):
            return None
        return self._reopen_attempt_locked(attempt_id)

    @staticmethod
    def _validated_publication_binding(
        attempt_id: str,
        publication_binding: EngineArtifactPublicationBinding,
    ) -> EngineArtifactPublicationBinding:
        if not isinstance(publication_binding, EngineArtifactPublicationBinding):
            raise EngineArtifactStoreError("artifact publication binding is invalid")
        binding = EngineArtifactPublicationBinding.from_mapping(publication_binding.to_dict())
        if binding.attempt_id != attempt_id:
            raise EngineArtifactStoreError(
                "artifact publication binding belongs to another attempt"
            )
        return binding

    @staticmethod
    def _validated_source_seal(
        attempt_id: str, source_seal: SourceCollectionSeal
    ) -> SourceCollectionSeal:
        if not isinstance(attempt_id, str) or ATTEMPT_ID.fullmatch(attempt_id) is None:
            raise EngineArtifactStoreError("attempt identity is invalid")
        if (
            not isinstance(source_seal, SourceCollectionSeal)
            or source_seal._controller_attestation is not _CONTROLLER_SOURCE_AUTHORITY
        ):
            raise EngineArtifactStoreError(
                "source collection seal requires a controller-issued receipt"
            )
        seal = SourceCollectionSeal.from_mapping(
            source_seal.to_dict(),
            _controller_authority=_CONTROLLER_SOURCE_AUTHORITY,
        )
        if seal.attempt_id != attempt_id:
            raise EngineArtifactStoreError("source collection seal belongs to another attempt")
        return seal

    def _normalize_selection(
        self,
        allowed_names: Iterable[str],
        *,
        canonical_order: bool,
    ) -> tuple[tuple[str, tuple[str, ...]], ...]:
        selected: list[tuple[str, tuple[str, ...]]] = []
        seen: set[str] = set()
        selected_portable_parts: list[tuple[str, ...]] = []
        if isinstance(allowed_names, (str, bytes)):
            raise EngineArtifactStoreError("artifact selection must be a finite name collection")
        try:
            iterator = iter(allowed_names)
        except TypeError:
            raise EngineArtifactStoreError(
                "artifact selection must be a finite name collection"
            ) from None
        for supplied in iterator:
            if len(selected) >= self.max_files:
                raise EngineArtifactStoreError("artifact selection count is outside its bound")
            name, parts = _safe_name(supplied)
            if len(parts) > MAX_SOURCE_TREE_DEPTH:
                raise EngineArtifactStoreError("artifact name exceeds its depth bound")
            portable_identity = name.casefold()
            portable_parts = tuple(part.casefold() for part in parts)
            if portable_identity in seen:
                raise EngineArtifactStoreError("artifact selection contains portable aliases")
            if any(
                portable_parts[: len(existing)] == existing
                or existing[: len(portable_parts)] == portable_parts
                for existing in selected_portable_parts
            ):
                raise EngineArtifactStoreError(
                    "artifact selection contains a file-directory conflict"
                )
            seen.add(portable_identity)
            selected_portable_parts.append(portable_parts)
            selected.append((name, parts))
        if not selected:
            raise EngineArtifactStoreError("artifact selection count is outside its bound")
        if canonical_order:
            selected.sort(key=lambda item: (item[0].casefold(), item[0]))
        return tuple(selected)

    def _collect_source_payloads(
        self,
        source_run_dir: str | Path,
        seal: SourceCollectionSeal,
        selected: tuple[tuple[str, tuple[str, ...]], ...],
    ) -> tuple[tuple[str, tuple[str, ...], bytes, str], ...]:
        self._require_root_identity()
        source = Path(source_run_dir)
        if os.name == "nt":
            source = _windows_extended_path(source)
        try:
            source_details = source.lstat()
        except OSError:
            raise EngineArtifactStoreError("source run directory is unavailable") from None
        if (
            source.is_symlink()
            or _is_reparse(source_details)
            or not stat.S_ISDIR(source_details.st_mode)
            or (source_details.st_dev, source_details.st_ino, source_details.st_mtime_ns)
            != (
                seal.source_root_device,
                seal.source_root_inode,
                seal.source_root_mtime_ns,
            )
        ):
            raise EngineArtifactStoreError("source run directory is unsafe")
        try:
            source = source.resolve(strict=True)
        except OSError:
            raise EngineArtifactStoreError("source run directory is unavailable") from None
        initial_tree_digest = source_collection_tree_digest(source)
        if initial_tree_digest != seal.source_tree_digest:
            raise EngineArtifactStoreError("source run directory is unsafe or changed")
        payloads: list[tuple[str, tuple[str, ...], bytes, str]] = []
        total = 0
        for name, parts in selected:
            payload = self._read_source(source, parts)
            total += len(payload)
            if total > self.max_total_bytes:
                raise EngineArtifactStoreError(
                    "artifact selection exceeds the aggregate byte bound"
                )
            payloads.append((name, parts, payload, "sha256:" + hashlib.sha256(payload).hexdigest()))
        try:
            current_source = source.lstat()
        except OSError:
            raise EngineArtifactStoreError(
                "source run directory changed during collection"
            ) from None
        if (
            source.is_symlink()
            or _is_reparse(current_source)
            or (current_source.st_dev, current_source.st_ino, current_source.st_mtime_ns)
            != (source_details.st_dev, source_details.st_ino, source_details.st_mtime_ns)
            or source_collection_tree_digest(source) != initial_tree_digest
        ):
            raise EngineArtifactStoreError("source run directory changed during collection")
        return tuple(payloads)

    @staticmethod
    def _require_matching_retry(
        reopened: ReopenedEngineArtifactAttempt,
        seal: SourceCollectionSeal,
        binding: EngineArtifactPublicationBinding,
        selected: tuple[tuple[str, tuple[str, ...]], ...],
    ) -> None:
        if (
            not reopened.recovery_eligible
            or reopened.schema_version != V2_MANIFEST_SCHEMA
            or reopened.attempt_id != seal.attempt_id
            or reopened.source_collection_receipt != seal.controller_receipt_digest
            or reopened.source_tree_digest != seal.source_tree_digest
            or reopened.source_collection_seal_ref != content_hash(seal.to_dict())
            or reopened.source_collection_seal != seal
            or reopened.publication_binding != binding
            or tuple(artifact.name for artifact in reopened.artifacts)
            != tuple(name for name, _parts in selected)
        ):
            raise EngineArtifactStoreError(
                "existing artifact publication does not match the exact retry"
            )

    def _publish_payloads_locked(
        self,
        attempt_id: str,
        payloads: tuple[tuple[str, tuple[str, ...], bytes, str], ...],
        manifest: Mapping[str, Any],
    ) -> None:
        self._require_root_identity()
        attempt_root = self.root / attempt_id
        staging_root = self.root / (".pending-" + attempt_id)
        if self._entry_exists(attempt_root):
            raise EngineArtifactStoreError("attempt artifact destination already exists")
        if self._entry_exists(staging_root):
            raise EngineArtifactPublicationUnknown(
                "a prior incomplete artifact intake requires recovery"
            )
        staging_created = False
        try:
            try:
                staging_root.mkdir(mode=0o700, exist_ok=False)
            except FileExistsError:
                raise EngineArtifactPublicationUnknown(
                    "a concurrent artifact intake requires exact retry recovery"
                ) from None
            except OSError:
                raise EngineArtifactStoreError(
                    "artifact publication staging is unavailable"
                ) from None
            staging_created = True
            self._harden_private(staging_root, directory=True)
            staging_identity = self._filesystem_identity(staging_root.lstat())
            if self._entry_exists(attempt_root):
                self._release_empty_staging_claim(
                    staging_root,
                    expected_identity=staging_identity,
                )
                staging_created = False
                raise EngineArtifactStoreError("attempt artifact destination already exists")
            raw_root = staging_root / "raw"
            raw_root.mkdir(mode=0o700, exist_ok=False)
            created_directories: list[Path] = []
            for _name, parts, payload, _digest in payloads:
                parent = raw_root
                for part in parts[:-1]:
                    parent = parent / part
                    if not self._entry_exists(parent):
                        parent.mkdir(mode=0o700, exist_ok=False)
                        created_directories.append(parent)
                    details = parent.lstat()
                    if (
                        parent.is_symlink()
                        or _is_reparse(details)
                        or not stat.S_ISDIR(details.st_mode)
                    ):
                        raise EngineArtifactStoreError("artifact destination directory is unsafe")
                target = parent / parts[-1]
                self._write_exclusive(target, payload)
                self._harden_private(target, directory=False)
            manifest_path = staging_root / "manifest.json"
            self._write_exclusive(manifest_path, canonical_json_bytes(manifest) + b"\n")
            self._harden_private(manifest_path, directory=False)
            for directory in [*reversed(created_directories), raw_root, staging_root]:
                self._harden_private(directory, directory=True)
                self._sync_directory(directory)
            self._require_root_identity()
            if self._entry_exists(attempt_root):
                raise EngineArtifactStoreError("attempt artifact destination already exists")
            self._publish_staging(staging_root, attempt_root)
            staging_created = False
            try:
                self._sync_directory(self.root)
            except BaseException as exc:
                raise EngineArtifactPublicationUnknown(
                    "artifact attempt is published but commit durability is unknown; "
                    "reconcile the complete manifest before retrying"
                ) from exc
        except BaseException as failure:
            if staging_created:
                final_exists = self._entry_exists(attempt_root)
                staging_exists = self._entry_exists(staging_root)
                if final_exists and not staging_exists:
                    if isinstance(failure, EngineArtifactPublicationUnknown):
                        raise
                    raise EngineArtifactPublicationUnknown(
                        "artifact attempt publication completed but its final commit state "
                        "requires manifest reconciliation"
                    ) from failure
                if staging_exists:
                    raise EngineArtifactPublicationUnknown(
                        "artifact intake is incomplete; its exact retained staging "
                        "requires guarded recovery"
                    ) from failure
                raise EngineArtifactPublicationUnknown(
                    "artifact intake state changed and requires guarded recovery"
                ) from failure
            raise

    def _reopen_attempt_locked(self, attempt_id: str) -> ReopenedEngineArtifactAttempt:
        pending = self.root / (".pending-" + attempt_id)
        if self._entry_exists(pending):
            raise EngineArtifactPublicationUnknown(
                "artifact publication is incomplete and requires recovery"
            )
        self._require_root_identity()
        root_descriptor = self._open_directory_descriptor(self.root)
        attempt_descriptor: int | None = None
        try:
            self._verify_protected_root_descriptor(root_descriptor)
            if self._filesystem_identity(os.fstat(root_descriptor)) != self._root_identity:
                raise EngineArtifactStoreError("artifact store root identity changed")
            attempt_root = self.root / attempt_id
            try:
                attempt_details = attempt_root.lstat()
            except OSError:
                raise EngineArtifactStoreError("artifact publication is unavailable") from None
            if (
                attempt_root.is_symlink()
                or _is_reparse(attempt_details)
                or not stat.S_ISDIR(attempt_details.st_mode)
            ):
                raise EngineArtifactStoreError("artifact publication inventory is unsafe")
            attempt_identity = self._filesystem_identity(attempt_details)
            self._verify_private_entry(attempt_root, directory=True)
            attempt_descriptor = self._open_directory_descriptor(attempt_root)
            self._verify_private_descriptor(attempt_descriptor, directory=True)
            opened_attempt = os.fstat(attempt_descriptor)
            if (
                _is_reparse(opened_attempt)
                or not stat.S_ISDIR(opened_attempt.st_mode)
                or self._filesystem_identity(opened_attempt) != attempt_identity
            ):
                raise EngineArtifactStoreError("artifact publication inventory is unsafe")
            top = self._enumerate_directory(attempt_root, limit=3)
            if set(top) != {"manifest.json", "raw"}:
                raise EngineArtifactStoreError("artifact publication inventory is not exact")
            manifest_path = attempt_root / "manifest.json"
            raw_root = attempt_root / "raw"
            manifest_details = top["manifest.json"]
            raw_details = top["raw"]
            if (
                _is_reparse(manifest_details)
                or not stat.S_ISREG(manifest_details.st_mode)
                or manifest_details.st_nlink != 1
                or not 1 <= manifest_details.st_size <= MAX_MANIFEST_BYTES
                or _is_reparse(raw_details)
                or not stat.S_ISDIR(raw_details.st_mode)
            ):
                raise EngineArtifactStoreError("artifact publication inventory is unsafe")
            self._verify_private_entry(manifest_path, directory=False)
            self._verify_private_entry(raw_root, directory=True)
            manifest_payload = self._read_retained_file(
                manifest_path,
                expected_size=manifest_details.st_size,
                max_size=MAX_MANIFEST_BYTES,
                expected_identity=self._filesystem_identity(manifest_details),
            )
            parsed = self._parse_manifest(manifest_payload, attempt_id=attempt_id)
            artifacts = self._read_exact_raw_inventory(raw_root, parsed["artifacts"])
            current_top = self._enumerate_directory(attempt_root, limit=3)
            if (
                set(current_top) != {"manifest.json", "raw"}
                or self._filesystem_identity(current_top["manifest.json"])
                != self._filesystem_identity(manifest_details)
                or self._filesystem_identity(current_top["raw"])
                != self._filesystem_identity(raw_details)
                or self._filesystem_identity(attempt_root.lstat()) != attempt_identity
                or self._filesystem_identity(os.fstat(attempt_descriptor)) != attempt_identity
                or self._filesystem_identity(os.fstat(root_descriptor)) != self._root_identity
            ):
                raise EngineArtifactStoreError("artifact publication changed during reopen")
            self._verify_private_descriptor(attempt_descriptor, directory=True)
            self._verify_protected_root_descriptor(root_descriptor)
            self._require_root_identity()
        except EngineArtifactStoreError:
            raise
        except (OSError, UnicodeError, ValueError, TypeError, RecursionError):
            raise EngineArtifactStoreError("artifact publication is invalid") from None
        finally:
            if attempt_descriptor is not None:
                os.close(attempt_descriptor)
            os.close(root_descriptor)

        schema = parsed["schema_version"]
        binding = parsed.get("publication_binding")
        result = ReopenedEngineArtifactAttempt(
            schema_version=schema,
            attempt_id=attempt_id,
            storage_boundary=parsed["storage_boundary"],
            source_collection_receipt=parsed["source_collection_receipt"],
            source_tree_digest=parsed.get("source_tree_digest"),
            source_collection_seal_ref=parsed.get("source_collection_seal_ref"),
            source_collection_seal=parsed.get("source_collection_seal"),
            artifact_publication_ref=parsed.get("artifact_publication_ref"),
            publication_binding=binding,
            artifacts=artifacts,
            total_bytes=parsed["total_bytes"],
            manifest_ref=content_hash(parsed["manifest"]),
            recovery_eligible=schema == V2_MANIFEST_SCHEMA,
        )
        if result.to_manifest() != parsed["manifest"]:
            raise EngineArtifactStoreError("artifact publication snapshot is not canonical")
        return result

    def _parse_manifest(self, payload: bytes, *, attempt_id: str) -> dict[str, Any]:
        def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("duplicate field")
                value[key] = item
            return value

        def invalid_constant(_value: str) -> None:
            raise ValueError("non-finite number")

        try:
            value = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=unique_object,
                parse_constant=invalid_constant,
            )
        except (UnicodeError, ValueError, TypeError, RecursionError):
            raise EngineArtifactStoreError("artifact manifest is invalid") from None
        if not isinstance(value, Mapping) or canonical_json_bytes(value) + b"\n" != payload:
            raise EngineArtifactStoreError("artifact manifest is not canonical")
        schema = value.get("schema_version")
        common_fields = {
            "schema_version",
            "attempt_id",
            "storage_boundary",
            "source_collection_receipt",
            "artifact_count",
            "total_bytes",
            "artifacts",
        }
        v2_fields = common_fields | {
            "artifact_publication_ref",
            "source_tree_digest",
            "source_collection_seal_ref",
            "source_collection_seal",
            "publication_binding",
        }
        expected_fields = common_fields if schema == V1_MANIFEST_SCHEMA else v2_fields
        if (
            schema not in {V1_MANIFEST_SCHEMA, V2_MANIFEST_SCHEMA}
            or set(value) != expected_fields
            or value.get("attempt_id") != attempt_id
            or value.get("storage_boundary") != "contained_exclusive_protected_root"
            or not isinstance(value.get("source_collection_receipt"), str)
            or SHA256.fullmatch(value["source_collection_receipt"]) is None
        ):
            raise EngineArtifactStoreError("artifact manifest identity is invalid")
        rows = self._validate_manifest_rows(
            value.get("artifacts"),
            canonical_order=schema == V2_MANIFEST_SCHEMA,
        )
        count = value.get("artifact_count")
        total = value.get("total_bytes")
        expected_total = sum(row["size_bytes"] for row in rows)
        if (
            isinstance(count, bool)
            or not isinstance(count, int)
            or count != len(rows)
            or isinstance(total, bool)
            or not isinstance(total, int)
            or total != expected_total
            or total > self.max_total_bytes
        ):
            raise EngineArtifactStoreError("artifact manifest aggregate is invalid")
        parsed: dict[str, Any] = {
            "schema_version": schema,
            "storage_boundary": value["storage_boundary"],
            "source_collection_receipt": value["source_collection_receipt"],
            "total_bytes": total,
            "artifacts": rows,
            "manifest": dict(value),
        }
        if schema == V1_MANIFEST_SCHEMA:
            return parsed
        source_tree_digest = value.get("source_tree_digest")
        source_seal_ref = value.get("source_collection_seal_ref")
        publication_ref = value.get("artifact_publication_ref")
        if any(
            not isinstance(item, str) or SHA256.fullmatch(item) is None
            for item in (source_tree_digest, source_seal_ref, publication_ref)
        ):
            raise EngineArtifactStoreError("artifact manifest recovery identity is invalid")
        try:
            binding = EngineArtifactPublicationBinding.from_mapping(value["publication_binding"])
        except (KeyError, EngineArtifactStoreError):
            raise EngineArtifactStoreError(
                "artifact manifest recovery binding is invalid"
            ) from None
        if binding.attempt_id != attempt_id:
            raise EngineArtifactStoreError("artifact manifest recovery binding changed")
        try:
            source_seal = SourceCollectionSeal.from_mapping(
                value["source_collection_seal"],
                _controller_authority=_CONTROLLER_SOURCE_AUTHORITY,
            )
        except (KeyError, TypeError, EngineArtifactStoreError):
            raise EngineArtifactStoreError("artifact manifest source seal is invalid") from None
        if (
            source_seal.attempt_id != attempt_id
            or source_seal.controller_receipt_digest != value["source_collection_receipt"]
            or source_seal.source_tree_digest != source_tree_digest
            or content_hash(source_seal.to_dict()) != source_seal_ref
        ):
            raise EngineArtifactStoreError("artifact manifest source seal changed")
        identity = {
            "schema_version": PUBLICATION_REF_SCHEMA,
            "attempt_id": attempt_id,
            "source_collection_receipt": value["source_collection_receipt"],
            "source_tree_digest": source_tree_digest,
            "source_collection_seal_ref": source_seal_ref,
            "source_collection_seal": source_seal.to_dict(),
            "publication_binding": binding.to_dict(),
            "artifact_count": len(rows),
            "total_bytes": total,
            "artifacts": rows,
        }
        if content_hash(identity) != publication_ref:
            raise EngineArtifactStoreError("artifact publication reference is invalid")
        parsed.update(
            {
                "source_tree_digest": source_tree_digest,
                "source_collection_seal_ref": source_seal_ref,
                "source_collection_seal": source_seal,
                "artifact_publication_ref": publication_ref,
                "publication_binding": binding,
            }
        )
        return parsed

    def _validate_manifest_rows(
        self,
        value: object,
        *,
        canonical_order: bool,
    ) -> list[dict[str, Any]]:
        if not isinstance(value, list) or not 1 <= len(value) <= self.max_files:
            raise EngineArtifactStoreError("artifact manifest inventory count is invalid")
        rows: list[dict[str, Any]] = []
        portable_names: set[str] = set()
        portable_parts: list[tuple[str, ...]] = []
        for item in value:
            if not isinstance(item, Mapping) or set(item) != {"name", "size_bytes", "sha256"}:
                raise EngineArtifactStoreError("artifact manifest row is invalid")
            name, parts = _safe_name(item.get("name"))
            size = item.get("size_bytes")
            digest = item.get("sha256")
            folded = name.casefold()
            folded_parts = tuple(part.casefold() for part in parts)
            if (
                len(parts) > MAX_SOURCE_TREE_DEPTH
                or folded in portable_names
                or isinstance(size, bool)
                or not isinstance(size, int)
                or not 1 <= size <= self.max_file_bytes
                or not isinstance(digest, str)
                or SHA256.fullmatch(digest) is None
                or any(
                    folded_parts[: len(existing)] == existing
                    or existing[: len(folded_parts)] == folded_parts
                    for existing in portable_parts
                )
            ):
                raise EngineArtifactStoreError("artifact manifest row is invalid")
            portable_names.add(folded)
            portable_parts.append(folded_parts)
            rows.append({"name": name, "size_bytes": size, "sha256": digest})
        if canonical_order and rows != sorted(
            rows, key=lambda row: (row["name"].casefold(), row["name"])
        ):
            raise EngineArtifactStoreError("artifact manifest inventory is not canonical")
        return rows

    def _read_exact_raw_inventory(
        self,
        raw_root: Path,
        rows: list[dict[str, Any]],
    ) -> tuple[ReopenedEngineArtifact, ...]:
        expected_files: dict[tuple[str, ...], dict[str, Any]] = {}
        expected_directories: set[tuple[str, ...]] = {()}
        for row in rows:
            _name, parts = _safe_name(row["name"])
            expected_files[parts] = row
            expected_directories.update(parts[:index] for index in range(1, len(parts)))
        payloads: dict[str, bytes] = {}
        retained_identities: set[tuple[int, int, int]] = set()
        scanned_entries = 0

        def visit(directory: Path, relative: tuple[str, ...]) -> None:
            nonlocal scanned_entries
            if len(relative) >= MAX_SOURCE_TREE_DEPTH:
                raise EngineArtifactStoreError("artifact publication exceeds its depth bound")
            try:
                before = directory.lstat()
            except OSError:
                raise EngineArtifactStoreError(
                    "artifact publication inventory is unavailable"
                ) from None
            if directory.is_symlink() or _is_reparse(before) or not stat.S_ISDIR(before.st_mode):
                raise EngineArtifactStoreError("artifact publication inventory is unsafe")
            identity = self._filesystem_identity(before)
            self._verify_private_entry(directory, directory=True)
            descriptor = self._open_directory_descriptor(directory)
            try:
                self._verify_private_descriptor(descriptor, directory=True)
                opened = os.fstat(descriptor)
                if (
                    _is_reparse(opened)
                    or not stat.S_ISDIR(opened.st_mode)
                    or self._filesystem_identity(opened) != identity
                ):
                    raise EngineArtifactStoreError("artifact publication inventory is unsafe")
                entries = self._enumerate_directory(
                    directory,
                    limit=MAX_SOURCE_TREE_ENTRIES - scanned_entries + 1,
                )
                scanned_entries += len(entries)
                if scanned_entries > MAX_SOURCE_TREE_ENTRIES:
                    raise EngineArtifactStoreError(
                        "artifact publication exceeds its inventory bound"
                    )
                expected_names = {
                    parts[-1]
                    for parts in expected_directories
                    if len(parts) == len(relative) + 1 and parts[:-1] == relative
                } | {
                    parts[-1]
                    for parts in expected_files
                    if len(parts) == len(relative) + 1 and parts[:-1] == relative
                }
                if set(entries) != expected_names or len(
                    {name.casefold() for name in entries}
                ) != len(entries):
                    raise EngineArtifactStoreError("artifact publication inventory is not exact")
                for name in sorted(entries, key=lambda item: (item.casefold(), item)):
                    path = directory / name
                    child = (*relative, name)
                    details = entries[name]
                    if child in expected_directories:
                        if _is_reparse(details) or not stat.S_ISDIR(details.st_mode):
                            raise EngineArtifactStoreError(
                                "artifact publication inventory is unsafe"
                            )
                        visit(path, child)
                        continue
                    row = expected_files.get(child)
                    if row is None:
                        raise EngineArtifactStoreError(
                            "artifact publication inventory is not exact"
                        )
                    file_identity = self._filesystem_identity(details)
                    if (
                        _is_reparse(details)
                        or not stat.S_ISREG(details.st_mode)
                        or details.st_nlink != 1
                        or details.st_size != row["size_bytes"]
                        or file_identity in retained_identities
                    ):
                        raise EngineArtifactStoreError("artifact publication inventory is unsafe")
                    retained_identities.add(file_identity)
                    self._verify_private_entry(path, directory=False)
                    payload = self._read_retained_file(
                        path,
                        expected_size=row["size_bytes"],
                        max_size=self.max_file_bytes,
                        expected_identity=file_identity,
                    )
                    if "sha256:" + hashlib.sha256(payload).hexdigest() != row["sha256"]:
                        raise EngineArtifactStoreError("artifact publication payload changed")
                    payloads[row["name"]] = payload
                after_entries = self._enumerate_directory(
                    directory,
                    limit=MAX_SOURCE_TREE_ENTRIES - scanned_entries + len(entries) + 1,
                )
                if (
                    set(after_entries) != set(entries)
                    or any(
                        self._filesystem_identity(after_entries[name])
                        != self._filesystem_identity(entries[name])
                        for name in entries
                    )
                    or self._filesystem_identity(directory.lstat()) != identity
                    or self._filesystem_identity(os.fstat(descriptor)) != identity
                ):
                    raise EngineArtifactStoreError(
                        "artifact publication inventory changed during reopen"
                    )
                self._verify_private_descriptor(descriptor, directory=True)
            except EngineArtifactStoreError:
                raise
            except OSError:
                raise EngineArtifactStoreError(
                    "artifact publication inventory is invalid"
                ) from None
            finally:
                os.close(descriptor)

        visit(raw_root, ())
        if set(payloads) != {row["name"] for row in rows}:
            raise EngineArtifactStoreError("artifact publication inventory is incomplete")
        return tuple(
            ReopenedEngineArtifact(
                name=row["name"],
                size_bytes=row["size_bytes"],
                sha256=row["sha256"],
                payload=payloads[row["name"]],
            )
            for row in rows
        )

    def _read_retained_file(
        self,
        path: Path,
        *,
        expected_size: int,
        max_size: int,
        expected_identity: tuple[int, int, int],
    ) -> bytes:
        if not 1 <= expected_size <= max_size:
            raise EngineArtifactStoreError("artifact publication file size is invalid")
        descriptor: int | None = None
        try:
            before = path.lstat()
            if (
                path.is_symlink()
                or _is_reparse(before)
                or not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size != expected_size
                or self._filesystem_identity(before) != expected_identity
            ):
                raise EngineArtifactStoreError("artifact publication file is unsafe")
            if os.name == "nt":
                descriptor = _windows_open_descriptor(path, directory=False)
            else:
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(path, flags)
            opened = os.fstat(descriptor)
            self._verify_private_descriptor(descriptor, directory=False)
            opened_state = (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
                stat.S_IMODE(opened.st_mode),
            )
            if (
                _is_reparse(opened)
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_size != expected_size
                or self._filesystem_identity(opened) != expected_identity
            ):
                raise EngineArtifactStoreError("artifact publication file is unsafe")
            chunks: list[bytes] = []
            remaining = expected_size + 1
            while remaining:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            after_open = os.fstat(descriptor)
            self._verify_private_descriptor(descriptor, directory=False)
            after = path.lstat()
            if (
                len(payload) != expected_size
                or (
                    after_open.st_dev,
                    after_open.st_ino,
                    after_open.st_size,
                    after_open.st_mtime_ns,
                    stat.S_IMODE(after_open.st_mode),
                )
                != opened_state
                or path.is_symlink()
                or _is_reparse(after)
                or after.st_nlink != 1
                or (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    stat.S_IMODE(after.st_mode),
                )
                != opened_state
            ):
                raise EngineArtifactStoreError("artifact publication file changed during reopen")
            return payload
        except EngineArtifactStoreError:
            raise
        except OSError:
            raise EngineArtifactStoreError("artifact publication file is unreadable") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def _enumerate_directory(path: Path, *, limit: int) -> dict[str, os.stat_result]:
        if limit < 1:
            raise EngineArtifactStoreError("artifact publication exceeds its inventory bound")
        entries: dict[str, os.stat_result] = {}
        try:
            with os.scandir(path) as iterator:
                for entry in iterator:
                    if len(entries) >= limit:
                        raise EngineArtifactStoreError(
                            "artifact publication exceeds its inventory bound"
                        )
                    if entry.name in entries:
                        raise EngineArtifactStoreError(
                            "artifact publication inventory is not exact"
                        )
                    # Windows DirEntry.stat may omit link count and file identity.
                    # Resolve the exact child without following links so later
                    # descriptor checks receive the complete identity tuple.
                    entries[entry.name] = (path / entry.name).lstat()
        except EngineArtifactStoreError:
            raise
        except OSError:
            raise EngineArtifactStoreError(
                "artifact publication inventory is unavailable"
            ) from None
        return entries

    @staticmethod
    def _open_directory_descriptor(path: Path) -> int:
        try:
            if os.name == "nt":
                return _windows_open_descriptor(path, directory=True)
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            return os.open(path, flags)
        except OSError:
            raise EngineArtifactStoreError("artifact publication directory is unreadable") from None

    @staticmethod
    def _filesystem_identity(details: os.stat_result) -> tuple[int, int, int]:
        return int(details.st_dev), int(details.st_ino), stat.S_IFMT(details.st_mode)

    def _require_root_identity(self) -> None:
        try:
            self._verify_protected_root(self.root)
            details = self.root.lstat()
        except (OSError, EngineArtifactStoreError):
            raise EngineArtifactStoreError("artifact store root identity is unavailable") from None
        if self._filesystem_identity(details) != self._root_identity:
            raise EngineArtifactStoreError("artifact store root identity changed")

    @staticmethod
    def _verify_private_entry(path: Path, *, directory: bool) -> None:
        if os.name == "nt":
            descriptor: int | None = None
            try:
                descriptor = _windows_open_descriptor(path, directory=directory)
                verify_owner_private_acl(descriptor, directory=directory)
            except (OSError, WindowsOwnerAclError):
                raise EngineArtifactStoreError(
                    "artifact publication permissions are unsafe"
                ) from None
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            return
        try:
            details = path.lstat()
        except OSError:
            raise EngineArtifactStoreError(
                "artifact publication permissions are unavailable"
            ) from None
        get_effective_user = getattr(os, "geteuid", None)
        if not callable(get_effective_user):
            get_effective_user = getattr(os, "getuid", None)
        expected_mode = 0o700 if directory else 0o600
        if (
            path.is_symlink()
            or _is_reparse(details)
            or stat.S_ISDIR(details.st_mode) is not directory
            or stat.S_IMODE(details.st_mode) != expected_mode
            or (callable(get_effective_user) and details.st_uid != get_effective_user())
        ):
            raise EngineArtifactStoreError("artifact publication permissions are unsafe")

    @staticmethod
    def _verify_private_descriptor(descriptor: int, *, directory: bool) -> None:
        if os.name == "nt":
            try:
                verify_owner_private_acl(descriptor, directory=directory)
            except (OSError, WindowsOwnerAclError):
                raise EngineArtifactStoreError(
                    "artifact publication permissions are unsafe"
                ) from None
            return
        try:
            details = os.fstat(descriptor)
        except OSError:
            raise EngineArtifactStoreError(
                "artifact publication permissions are unavailable"
            ) from None
        get_effective_user = getattr(os, "geteuid", None)
        if not callable(get_effective_user):
            get_effective_user = getattr(os, "getuid", None)
        expected_mode = 0o700 if directory else 0o600
        if (
            _is_reparse(details)
            or stat.S_ISDIR(details.st_mode) is not directory
            or stat.S_IMODE(details.st_mode) != expected_mode
            or (callable(get_effective_user) and details.st_uid != get_effective_user())
        ):
            raise EngineArtifactStoreError("artifact publication permissions are unsafe")

    @staticmethod
    def _verify_protected_root_descriptor(descriptor: int) -> None:
        EngineArtifactStore._verify_private_descriptor(descriptor, directory=True)

    def _read_source(self, root: Path, parts: tuple[str, ...]) -> bytes:
        current = root
        parents: list[tuple[Path, tuple[int, int, int]]] = []
        for part in parts[:-1]:
            current = current / part
            try:
                details = current.lstat()
            except OSError as exc:
                raise EngineArtifactStoreError("selected artifact parent is unavailable") from exc
            if current.is_symlink() or _is_reparse(details) or not stat.S_ISDIR(details.st_mode):
                raise EngineArtifactStoreError("selected artifact parent is unsafe")
            parents.append((current, (details.st_dev, details.st_ino, details.st_mtime_ns)))
        target = current / parts[-1]
        try:
            before = target.lstat()
        except OSError as exc:
            raise EngineArtifactStoreError("selected artifact is unavailable") from exc
        if (
            target.is_symlink()
            or _is_reparse(before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 1 <= before.st_size <= self.max_file_bytes
        ):
            raise EngineArtifactStoreError("selected artifact is unsafe or outside its byte bound")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(target, flags)
        except OSError as exc:
            raise EngineArtifactStoreError("selected artifact could not be opened safely") from exc
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or _is_reparse(opened)
                or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                or opened.st_size != before.st_size
            ):
                raise EngineArtifactStoreError("selected artifact changed before it was opened")
            chunks: list[bytes] = []
            remaining = opened.st_size
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    raise EngineArtifactStoreError(
                        "selected artifact was truncated during collection"
                    )
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise EngineArtifactStoreError("selected artifact grew during collection")
        finally:
            os.close(descriptor)
        try:
            after = target.lstat()
        except OSError as exc:
            raise EngineArtifactStoreError(
                "selected artifact disappeared during collection"
            ) from exc
        if (
            target.is_symlink()
            or _is_reparse(after)
            or not stat.S_ISREG(after.st_mode)
            or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        ):
            raise EngineArtifactStoreError("selected artifact changed during collection")
        for parent, identity in reversed(parents):
            try:
                current_parent = parent.lstat()
            except OSError as exc:
                raise EngineArtifactStoreError(
                    "selected artifact parent disappeared during collection"
                ) from exc
            if (
                parent.is_symlink()
                or _is_reparse(current_parent)
                or not stat.S_ISDIR(current_parent.st_mode)
                or (current_parent.st_dev, current_parent.st_ino, current_parent.st_mtime_ns)
                != identity
            ):
                raise EngineArtifactStoreError("selected artifact parent changed during collection")
        return b"".join(chunks)

    @staticmethod
    def _write_exclusive(path: Path, payload: bytes) -> None:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as exc:
            raise EngineArtifactStoreError(
                "artifact destination is not exclusively writable"
            ) from exc
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise EngineArtifactStoreError("artifact destination write was incomplete")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _harden_private(path: Path, *, directory: bool) -> None:
        if os.name == "nt":
            descriptor: int | None = None
            try:
                descriptor = _windows_open_descriptor(
                    path,
                    directory=directory,
                    write_dac=True,
                )
                apply_owner_private_acl(descriptor, directory=directory)
                verify_owner_private_acl(descriptor, directory=directory)
            except (OSError, WindowsOwnerAclError):
                raise EngineArtifactStoreError(
                    "artifact destination private permissions are unavailable"
                ) from None
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            return
        try:
            os.chmod(path, 0o700 if directory else 0o600, follow_symlinks=False)
            details = path.lstat()
        except OSError as exc:
            raise EngineArtifactStoreError(
                "artifact destination private permissions are unavailable"
            ) from exc
        getuid = getattr(os, "geteuid", None)
        if not callable(getuid):
            getuid = getattr(os, "getuid", None)
        if (
            path.is_symlink()
            or stat.S_ISDIR(details.st_mode) is not directory
            or stat.S_IMODE(details.st_mode) != (0o700 if directory else 0o600)
            or (callable(getuid) and details.st_uid != getuid())
        ):
            raise EngineArtifactStoreError("artifact destination private permissions are invalid")

    @staticmethod
    def _verify_protected_root(path: Path) -> None:
        if os.name == "nt":
            descriptor: int | None = None
            try:
                descriptor = _windows_open_descriptor(path, directory=True)
                verify_owner_private_acl(descriptor, directory=True)
            except (OSError, WindowsOwnerAclError) as exc:
                raise EngineArtifactStoreError(
                    "artifact store root lacks a verified owner-private DACL"
                ) from exc
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            return
        try:
            details = path.lstat()
        except OSError:
            raise EngineArtifactStoreError("artifact store root is unavailable") from None
        getuid = getattr(os, "geteuid", None)
        if not callable(getuid):
            getuid = getattr(os, "getuid", None)
        if (
            path.is_symlink()
            or _is_reparse(details)
            or not stat.S_ISDIR(details.st_mode)
            or stat.S_IMODE(details.st_mode) != 0o700
            or (callable(getuid) and details.st_uid != getuid())
        ):
            raise EngineArtifactStoreError("artifact store root is not owner-private")

    @staticmethod
    def _sync_directory(path: Path) -> None:
        if os.name == "nt":
            return
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise EngineArtifactStoreError("artifact directory could not be synchronized") from exc

    @staticmethod
    def _entry_exists(path: Path) -> bool:
        try:
            path.lstat()
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise EngineArtifactStoreError("artifact publication state is unavailable") from exc
        return True

    def _publish_staging(self, staging_root: Path, attempt_root: Path) -> None:
        root_descriptor: int | None = None
        staging_descriptor: int | None = None
        try:
            if (
                staging_root.parent != self.root
                or staging_root.name != ".pending-" + attempt_root.name
                or attempt_root.parent != self.root
                or ATTEMPT_ID.fullmatch(attempt_root.name) is None
            ):
                raise EngineArtifactStoreError("artifact publication target is invalid")
            self._require_root_identity()
            root_details = self.root.lstat()
            staging_details = staging_root.lstat()
            root_identity = self._filesystem_identity(root_details)
            staging_identity = self._filesystem_identity(staging_details)
            if (
                root_identity != self._root_identity
                or _is_reparse(staging_details)
                or not stat.S_ISDIR(staging_details.st_mode)
            ):
                raise EngineArtifactStoreError("artifact publication staging is unsafe")
            if os.name == "nt":
                root_descriptor = _windows_open_descriptor(self.root, directory=True)
                staging_descriptor = _windows_open_descriptor(
                    staging_root,
                    directory=True,
                    delete=True,
                    share_delete=True,
                )
            else:
                flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                root_descriptor = os.open(self.root, flags)
                staging_descriptor = os.open(
                    staging_root.name,
                    flags,
                    dir_fd=root_descriptor,
                )
            if (
                self._filesystem_identity(os.fstat(root_descriptor)) != root_identity
                or self._filesystem_identity(os.fstat(staging_descriptor)) != staging_identity
                or self._filesystem_identity(self.root.lstat()) != root_identity
                or self._filesystem_identity(staging_root.lstat()) != staging_identity
            ):
                raise EngineArtifactStoreError("artifact publication staging changed")
            self._verify_protected_root_descriptor(root_descriptor)
            self._verify_private_descriptor(staging_descriptor, directory=True)
            try:
                if os.name == "nt":
                    self._windows_rename_directory_no_replace(
                        staging_descriptor,
                        attempt_root,
                    )
                else:
                    from .source_intake import _posix_rename_no_replace

                    _posix_rename_no_replace(
                        root_descriptor,
                        staging_root.name,
                        attempt_root.name,
                    )
            except FileExistsError:
                raise EngineArtifactStoreError(
                    "attempt artifact destination already exists"
                ) from None
            published = attempt_root.lstat()
            if (
                _is_reparse(published)
                or not stat.S_ISDIR(published.st_mode)
                or self._filesystem_identity(published) != staging_identity
                or self._filesystem_identity(os.fstat(staging_descriptor)) != staging_identity
                or self._filesystem_identity(self.root.lstat()) != root_identity
            ):
                raise EngineArtifactStoreError(
                    "artifact attempt atomic publication identity changed"
                )
            self._verify_private_descriptor(staging_descriptor, directory=True)
            self._verify_protected_root_descriptor(root_descriptor)
            try:
                staging_root.lstat()
            except FileNotFoundError:
                pass
            else:
                raise EngineArtifactStoreError(
                    "artifact attempt staging remained after publication"
                )
        except EngineArtifactStoreError:
            raise
        except OSError:
            raise EngineArtifactStoreError(
                "artifact attempt could not be atomically published"
            ) from None
        finally:
            for descriptor in (staging_descriptor, root_descriptor):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass

    def _release_empty_staging_claim(
        self,
        staging_root: Path,
        *,
        expected_identity: tuple[int, int, int],
    ) -> None:
        """Release only this publisher's still-empty, descriptor-pinned claim."""

        root_descriptor: int | None = None
        staging_descriptor: int | None = None
        try:
            pending_attempt_id = staging_root.name.removeprefix(".pending-")
            if (
                staging_root.parent != self.root
                or staging_root.name != ".pending-" + pending_attempt_id
                or ATTEMPT_ID.fullmatch(pending_attempt_id) is None
                or self._filesystem_identity(staging_root.lstat()) != expected_identity
            ):
                raise EngineArtifactPublicationUnknown(
                    "empty artifact staging claim changed before release"
                )
            if os.name == "nt":
                root_descriptor = _windows_open_descriptor(self.root, directory=True)
                staging_descriptor = _windows_open_descriptor(
                    staging_root,
                    directory=True,
                    delete=True,
                )
                with os.scandir(staging_root) as entries:
                    names = [entry.name for entry in entries]
            else:
                flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                root_descriptor = os.open(self.root, flags)
                staging_descriptor = os.open(
                    staging_root.name,
                    flags,
                    dir_fd=root_descriptor,
                )
                names = os.listdir(staging_descriptor)
            self._verify_protected_root_descriptor(root_descriptor)
            self._verify_private_descriptor(staging_descriptor, directory=True)
            if (
                names
                or self._filesystem_identity(os.fstat(root_descriptor)) != self._root_identity
                or self._filesystem_identity(os.fstat(staging_descriptor)) != expected_identity
                or self._filesystem_identity(staging_root.lstat()) != expected_identity
            ):
                raise EngineArtifactPublicationUnknown(
                    "empty artifact staging claim changed before release"
                )
            if os.name == "nt":
                _windows_mark_delete_descriptor(staging_descriptor)
            else:
                os.rmdir(staging_root.name, dir_fd=root_descriptor)
            self._verify_protected_root_descriptor(root_descriptor)
        except EngineArtifactPublicationUnknown:
            raise
        except (OSError, WindowsOwnerAclError):
            raise EngineArtifactPublicationUnknown(
                "empty artifact staging claim could not be released safely"
            ) from None
        finally:
            for descriptor in (staging_descriptor, root_descriptor):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
        if self._entry_exists(staging_root):
            raise EngineArtifactPublicationUnknown(
                "empty artifact staging claim release is unknown"
            )

    @staticmethod
    def _windows_rename_directory_no_replace(descriptor: int, target: Path) -> None:
        """Rename an exact Windows directory handle without replacing a target."""

        if os.name != "nt":
            raise OSError("Windows artifact publication is unavailable")
        import ctypes
        import msvcrt
        from ctypes import wintypes

        target_name = os.path.abspath(os.fspath(target))
        if not target.is_absolute() or not target_name or "\x00" in target_name:
            raise OSError("artifact publication target is invalid")

        class FileRenameInfo(ctypes.Structure):
            _fields_ = [
                ("ReplaceIfExists", wintypes.BOOL),
                ("RootDirectory", wintypes.HANDLE),
                ("FileNameLength", wintypes.DWORD),
                ("FileName", wintypes.WCHAR * 1),
            ]

        encoded_name = target_name.encode("utf-16-le")
        name_offset = FileRenameInfo.FileName.offset
        rename_buffer = ctypes.create_string_buffer(name_offset + len(encoded_name) + 2)
        rename = FileRenameInfo.from_buffer(rename_buffer)
        rename.ReplaceIfExists = False
        rename.RootDirectory = None
        rename.FileNameLength = len(encoded_name)
        ctypes.memmove(
            ctypes.addressof(rename_buffer) + name_offset,
            encoded_name,
            len(encoded_name),
        )
        rename_file = ctypes.WinDLL("kernel32", use_last_error=True).SetFileInformationByHandle
        rename_file.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        )
        rename_file.restype = wintypes.BOOL
        if not rename_file(
            wintypes.HANDLE(msvcrt.get_osfhandle(descriptor)),
            3,  # FileRenameInfo
            rename_buffer,
            len(rename_buffer),
        ):
            error = ctypes.get_last_error()
            if error in {80, 183}:
                raise FileExistsError(error, "artifact publication target exists")
            raise OSError(error, "artifact publication rename failed")
