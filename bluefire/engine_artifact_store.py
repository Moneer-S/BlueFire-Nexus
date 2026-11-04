"""Path-contained raw artifact intake for externally managed engine attempts."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import threading
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

from .util import canonical_json_bytes, content_hash
from .windows_owner_acl import (
    WindowsOwnerAclError,
    _windows_extended_path,
    _windows_open_descriptor,
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
            "worker_state": "stopped",
            "write_access_revoked": True,
            "controller_receipt_digest": digest,
            "_controller_attestation": _CONTROLLER_SOURCE_AUTHORITY,
        }
        for name, admitted_value in admitted.items():
            object.__setattr__(seal, name, admitted_value)
        return seal


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
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.max_files = max_files
        self._publish_lock = threading.Lock()

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
        if ATTEMPT_ID.fullmatch(attempt_id) is None:
            raise EngineArtifactStoreError("attempt identity is invalid")
        if (
            not isinstance(source_seal, SourceCollectionSeal)
            or source_seal._controller_attestation is not _CONTROLLER_SOURCE_AUTHORITY
        ):
            raise EngineArtifactStoreError(
                "source collection seal requires a controller-issued receipt"
            )
        seal = source_seal
        if seal.attempt_id != attempt_id:
            raise EngineArtifactStoreError("source collection seal belongs to another attempt")
        self._verify_protected_root(self.root)
        source = Path(source_run_dir)
        if os.name == "nt":
            source = _windows_extended_path(source)
        try:
            source_details = source.lstat()
        except OSError as exc:
            raise EngineArtifactStoreError("source run directory is unavailable") from exc
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
        source = source.resolve(strict=True)
        selected: list[tuple[str, tuple[str, ...]]] = []
        seen: set[str] = set()
        selected_portable_parts: list[tuple[str, ...]] = []
        if isinstance(allowed_names, (str, bytes)):
            raise EngineArtifactStoreError("artifact selection must be a finite name collection")
        for supplied in allowed_names:
            if len(selected) >= self.max_files:
                raise EngineArtifactStoreError("artifact selection count is outside its bound")
            name, parts = _safe_name(supplied)
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
        current_source = source.lstat()
        if (
            source.is_symlink()
            or _is_reparse(current_source)
            or (current_source.st_dev, current_source.st_ino, current_source.st_mtime_ns)
            != (source_details.st_dev, source_details.st_ino, source_details.st_mtime_ns)
        ):
            raise EngineArtifactStoreError("source run directory changed during collection")

        with self._publish_lock:
            attempt_root = self.root / attempt_id
            staging_root = self.root / (".pending-" + attempt_id)
            if attempt_root.exists():
                raise EngineArtifactStoreError("attempt artifact destination already exists")
            if staging_root.exists():
                raise EngineArtifactStoreError(
                    "a prior incomplete artifact intake requires recovery"
                )
            staging_created = False
            try:
                staging_root.mkdir(mode=0o700, exist_ok=False)
                staging_created = True
                raw_root = staging_root / "raw"
                raw_root.mkdir(mode=0o700, exist_ok=False)
                manifest_rows: list[dict[str, Any]] = []
                created_directories: list[Path] = []
                for name, parts, payload, digest in payloads:
                    parent = raw_root
                    for part in parts[:-1]:
                        parent = parent / part
                        if not parent.exists():
                            parent.mkdir(mode=0o700, exist_ok=False)
                            created_directories.append(parent)
                        details = parent.lstat()
                        if (
                            parent.is_symlink()
                            or _is_reparse(details)
                            or not stat.S_ISDIR(details.st_mode)
                        ):
                            raise EngineArtifactStoreError(
                                "artifact destination directory is unsafe"
                            )
                    target = parent / parts[-1]
                    self._write_exclusive(target, payload)
                    self._harden_private(target, directory=False)
                    manifest_rows.append(
                        {"name": name, "size_bytes": len(payload), "sha256": digest}
                    )
                manifest = {
                    "schema_version": "bluefire.engine-artifacts.v1",
                    "attempt_id": attempt_id,
                    "storage_boundary": "contained_exclusive_protected_root",
                    "source_collection_receipt": seal.controller_receipt_digest,
                    "artifact_count": len(manifest_rows),
                    "total_bytes": total,
                    "artifacts": manifest_rows,
                }
                manifest_path = staging_root / "manifest.json"
                self._write_exclusive(manifest_path, canonical_json_bytes(manifest) + b"\n")
                self._harden_private(manifest_path, directory=False)
                for directory in [*reversed(created_directories), raw_root, staging_root]:
                    self._harden_private(directory, directory=True)
                    self._sync_directory(directory)
                if attempt_root.exists():
                    raise EngineArtifactStoreError("attempt artifact destination already exists")
                os.rename(staging_root, attempt_root)
                staging_created = False
                try:
                    self._sync_directory(self.root)
                except EngineArtifactStoreError as exc:
                    raise EngineArtifactPublicationUnknown(
                        "artifact attempt is published but commit durability is unknown; "
                        "reconcile the complete manifest before retrying"
                    ) from exc
                return manifest
            except BaseException:
                if staging_created:
                    self._remove_failed_attempt(staging_root, attempt_id=attempt_id)
                raise

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
            # The ProductStore root owns the DACL boundary. Rewriting it here
            # can remove an AppContainer capability from an otherwise valid
            # protected root. Windows confidentiality is therefore a caller
            # precondition rather than a claim made by this intake module.
            return
        try:
            os.chmod(path, 0o700 if directory else 0o600, follow_symlinks=False)
            details = path.lstat()
        except OSError as exc:
            raise EngineArtifactStoreError(
                "artifact destination private permissions are unavailable"
            ) from exc
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
        details = path.lstat()
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

    def _remove_failed_attempt(self, attempt_root: Path, *, attempt_id: str) -> None:
        try:
            if (
                attempt_root.parent.resolve(strict=True) != self.root
                or attempt_root.name != ".pending-" + attempt_id
            ):
                raise EngineArtifactStoreError("failed artifact intake is outside the store root")
            shutil.rmtree(attempt_root)
        except EngineArtifactStoreError:
            raise
        except OSError as exc:
            raise EngineArtifactStoreError(
                "failed artifact intake could not be removed; manual recovery is required"
            ) from exc
