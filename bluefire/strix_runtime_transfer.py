"""Bounded transfer archive for the fresh-runner Strix startup probe.

The archive deliberately excludes the first job's installed runtime. It carries
the validated candidate, preparation receipts and offline wheelhouse, plus the
exact pinned pip wheel needed to build a new runtime on the fresh runner. The
archive carries no authority: the admission controller revalidates every byte
before constructing and inspecting the runtime itself.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import stat
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, cast

from .util import canonical_json_bytes, json_clone


class StrixRuntimeTransferError(ValueError):
    """Raised when a runtime-transfer bundle is unsafe or inconsistent."""


SCHEMA = "bluefire.strix-runtime-admission-transfer.v1"
METADATA_NAME = "bluefire-strix-transfer.json"
CANDIDATE_DIRECTORY = "bluefire-strix-candidate-output"
PREPARATION_DIRECTORY = "bluefire-strix-qualification-output"
WORK_DIRECTORY = "bluefire-strix-qualification-work"
PIP_PREFIX = f"{WORK_DIRECTORY}/pip-tool"
MAX_BUNDLE_BYTES = 4 * 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 1024 * 1024 * 1024
MAX_MEMBER_COUNT = 100_000
MAX_PATH_BYTES = 1_024
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOP_LEVEL = frozenset({CANDIDATE_DIRECTORY, PREPARATION_DIRECTORY, WORK_DIRECTORY})


def _safe_name(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        not value
        or len(value.encode("utf-8")) > MAX_PATH_BYTES
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise StrixRuntimeTransferError("transfer member path is unsafe")
    return path


def _member_mode(metadata: os.stat_result) -> int:
    return 0o555 if metadata.st_mode & 0o111 else 0o444


def _tar_info(name: str, mode: int, *, member_type: bytes, size: int = 0) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = member_type
    info.mode = mode
    info.size = size
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    return info


def _open_regular(path: Path, maximum: int) -> tuple[BinaryIO, os.stat_result]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise StrixRuntimeTransferError("transfer source cannot be opened safely") from exc
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size < 0
        or metadata.st_size > maximum
        or metadata.st_nlink != 1
    ):
        os.close(descriptor)
        raise StrixRuntimeTransferError("transfer source is not a bounded regular file")
    return os.fdopen(descriptor, "rb", closefd=True), metadata


def _add_regular(archive: tarfile.TarFile, source: Path, name: str) -> int:
    handle, before = _open_regular(source, MAX_MEMBER_BYTES)
    with handle:
        archive.addfile(
            _tar_info(name, _member_mode(before), member_type=tarfile.REGTYPE, size=before.st_size),
            handle,
        )
        after = os.fstat(handle.fileno())
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise StrixRuntimeTransferError("transfer source changed while archived")
    return before.st_size


def _iter_tree(root: Path, prefix: str) -> list[tuple[Path, str, os.stat_result]]:
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        raise StrixRuntimeTransferError("transfer source root is not a directory")
    rows = [(resolved, prefix, resolved.lstat())]
    for path in sorted(resolved.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(resolved).as_posix()
        rows.append((path, f"{prefix}/{relative}", path.lstat()))
    return rows


def create_transfer_bundle(
    destination: Path,
    *,
    candidate_root: Path,
    preparation_root: Path,
    preparation_work_root: Path,
    bluefire_source_revision: str,
    threat_review_ref: str,
) -> str:
    """Create one deterministic uncompressed tar and return its SHA-256 ref."""

    if _REVISION.fullmatch(bluefire_source_revision) is None:
        raise StrixRuntimeTransferError("BlueFire revision must be an exact commit")
    if _DIGEST.fullmatch(threat_review_ref) is None:
        raise StrixRuntimeTransferError("threat-review ref is invalid")
    work = preparation_work_root.resolve(strict=True)
    if work.name != WORK_DIRECTORY:
        raise StrixRuntimeTransferError("preparation work must use the fixed hosted transfer path")
    pip_tool = (work / "pip-tool").resolve(strict=True)
    if pip_tool.parent != work or not pip_tool.is_dir():
        raise StrixRuntimeTransferError("pinned pip tool directory is unavailable")
    output = destination.resolve(strict=False)
    if output.exists() or output.parent.resolve(strict=True) in {
        candidate_root.resolve(strict=True),
        preparation_root.resolve(strict=True),
        work,
        pip_tool,
    }:
        raise StrixRuntimeTransferError("transfer output must be new and separate")

    rows: list[tuple[Path, str, os.stat_result]] = [(work, WORK_DIRECTORY, work.lstat())]
    for source, prefix in (
        (candidate_root, CANDIDATE_DIRECTORY),
        (preparation_root, PREPARATION_DIRECTORY),
        (pip_tool, PIP_PREFIX),
    ):
        rows.extend(_iter_tree(source, prefix))
    if len(rows) + 1 > MAX_MEMBER_COUNT:
        raise StrixRuntimeTransferError("transfer contains too many members")

    transfer_metadata = {
        "schema": SCHEMA,
        "bluefire_source_revision": bluefire_source_revision,
        "threat_review_ref": threat_review_ref,
        "preparation_work_root": work.as_posix(),
        "runtime_root": (work / "runtime").as_posix(),
        "pip_tool_root": pip_tool.as_posix(),
        "top_level": sorted(_TOP_LEVEL),
        "claims": {
            "strix_executed": False,
            "target": False,
            "model": False,
            "network_probe": False,
        },
    }
    metadata_payload = canonical_json_bytes(transfer_metadata) + b"\n"
    total = len(metadata_payload)
    try:
        with tarfile.open(output, "x", format=tarfile.PAX_FORMAT) as archive:
            info = _tar_info(
                METADATA_NAME,
                0o444,
                member_type=tarfile.REGTYPE,
                size=len(metadata_payload),
            )
            archive.addfile(info, io.BytesIO(metadata_payload))
            for path, name, member_metadata in sorted(rows, key=lambda row: row[1]):
                _safe_name(name)
                if stat.S_ISDIR(member_metadata.st_mode):
                    archive.addfile(_tar_info(name, 0o555, member_type=tarfile.DIRTYPE))
                elif stat.S_ISREG(member_metadata.st_mode):
                    total += _add_regular(archive, path, name)
                    if total > MAX_BUNDLE_BYTES:
                        raise StrixRuntimeTransferError("transfer payload exceeds its byte bound")
                else:
                    raise StrixRuntimeTransferError("transfer contains a special file")
        size = output.stat().st_size
        if size <= 0 or size > MAX_BUNDLE_BYTES:
            raise StrixRuntimeTransferError("transfer archive exceeds its byte bound")
        digest = hashlib.sha256()
        handle, _metadata = _open_regular(output, MAX_BUNDLE_BYTES)
        with handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        return f"sha256:{digest.hexdigest()}"
    except BaseException:
        output.unlink(missing_ok=True)
        raise


def _canonical_metadata(archive: tarfile.TarFile, member: tarfile.TarInfo) -> dict[str, Any]:
    if not member.isfile() or member.size > 1024 * 1024:
        raise StrixRuntimeTransferError("transfer metadata is invalid")
    handle = archive.extractfile(member)
    if handle is None:
        raise StrixRuntimeTransferError("transfer metadata is unavailable")
    payload = handle.read(1024 * 1024 + 1)
    if len(payload) != member.size or len(payload) > 1024 * 1024:
        raise StrixRuntimeTransferError("transfer metadata is oversized")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StrixRuntimeTransferError("transfer metadata is not JSON") from exc
    if not isinstance(value, dict) or payload != canonical_json_bytes(value) + b"\n":
        raise StrixRuntimeTransferError("transfer metadata is not canonical")
    return cast(dict[str, Any], json_clone(value))


def _preflight(
    archive: tarfile.TarFile,
    *,
    transfer_root: Path,
    bluefire_source_revision: str,
    threat_review_ref: str,
) -> tuple[list[tarfile.TarInfo], dict[str, Any]]:
    members = archive.getmembers()
    if not members or len(members) > MAX_MEMBER_COUNT:
        raise StrixRuntimeTransferError("transfer member count is invalid")
    by_name: dict[str, tarfile.TarInfo] = {}
    casefolded: set[str] = set()
    total = 0
    for member in members:
        name = _safe_name(member.name).as_posix()
        if name in by_name or name.casefold() in casefolded:
            raise StrixRuntimeTransferError("transfer member inventory is ambiguous")
        if set(member.pax_headers) - {"path", "linkpath"}:
            raise StrixRuntimeTransferError("transfer member has unsupported PAX metadata")
        if member.type not in {tarfile.REGTYPE, tarfile.DIRTYPE}:
            raise StrixRuntimeTransferError("transfer member type is unsafe")
        if member.isfile():
            if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                raise StrixRuntimeTransferError("transfer member is oversized")
            total += member.size
            if total > MAX_BUNDLE_BYTES:
                raise StrixRuntimeTransferError("transfer contents exceed their byte bound")
            if member.mode not in {0o444, 0o555}:
                raise StrixRuntimeTransferError("transfer file mode is invalid")
        elif member.isdir() and member.mode != 0o555:
            raise StrixRuntimeTransferError("transfer directory mode is invalid")
        by_name[name] = member
        casefolded.add(name.casefold())
    if METADATA_NAME not in by_name:
        raise StrixRuntimeTransferError("transfer metadata is missing")
    if any(name not in by_name or not by_name[name].isdir() for name in _TOP_LEVEL):
        raise StrixRuntimeTransferError("transfer top-level directories are incomplete")
    if PIP_PREFIX not in by_name or not by_name[PIP_PREFIX].isdir():
        raise StrixRuntimeTransferError("transfer pinned pip directory is missing")
    for name, _member in by_name.items():
        if name == METADATA_NAME:
            continue
        path = PurePosixPath(name)
        if path.parts[0] not in _TOP_LEVEL:
            raise StrixRuntimeTransferError("transfer top-level path is unsupported")
        if (
            path.parts[0] == WORK_DIRECTORY
            and name
            not in {
                WORK_DIRECTORY,
                PIP_PREFIX,
            }
            and not name.startswith(f"{PIP_PREFIX}/")
        ):
            raise StrixRuntimeTransferError("transfer work path escapes the pip-tool tree")
        for depth in range(1, len(path.parts)):
            ancestor = PurePosixPath(*path.parts[:depth]).as_posix()
            prior = by_name.get(ancestor)
            if prior is not None and not prior.isdir():
                raise StrixRuntimeTransferError("transfer path crosses a non-directory")

    metadata = _canonical_metadata(archive, by_name[METADATA_NAME])
    expected_work = (transfer_root.resolve(strict=True) / WORK_DIRECTORY).as_posix()
    expected_runtime = f"{expected_work}/runtime"
    if set(metadata) != {
        "schema",
        "bluefire_source_revision",
        "threat_review_ref",
        "preparation_work_root",
        "runtime_root",
        "pip_tool_root",
        "top_level",
        "claims",
    } or metadata != {
        "schema": SCHEMA,
        "bluefire_source_revision": bluefire_source_revision,
        "threat_review_ref": threat_review_ref,
        "preparation_work_root": expected_work,
        "runtime_root": expected_runtime,
        "pip_tool_root": f"{expected_work}/pip-tool",
        "top_level": sorted(_TOP_LEVEL),
        "claims": {
            "strix_executed": False,
            "target": False,
            "model": False,
            "network_probe": False,
        },
    }:
        raise StrixRuntimeTransferError("transfer metadata identity is invalid")
    return members, metadata


def _destination(root: Path, name: str) -> Path:
    path = root.joinpath(*PurePosixPath(name).parts)
    if root not in path.parents:
        raise StrixRuntimeTransferError("transfer destination escaped its root")
    return path


def _remove_root(path: Path) -> None:
    if path.is_symlink():
        path.unlink()
        return
    if not path.exists():
        return
    for directory, subdirectories, filenames in os.walk(path, topdown=False, followlinks=False):
        current = Path(directory)
        for name in [*subdirectories, *filenames]:
            child = current / name
            if not child.is_symlink():
                os.chmod(child, 0o700 if child.is_dir() else 0o600)
        os.chmod(current, 0o700)
    shutil.rmtree(path, ignore_errors=False)


def extract_transfer_bundle(
    bundle: Path,
    *,
    transfer_root: Path,
    expected_ref: str,
    bluefire_source_revision: str,
    threat_review_ref: str,
) -> tuple[Path, Path, Path]:
    """Verify and manually extract one archive into fixed, absent directories."""

    if _DIGEST.fullmatch(expected_ref) is None:
        raise StrixRuntimeTransferError("transfer expected ref is invalid")
    if _REVISION.fullmatch(bluefire_source_revision) is None:
        raise StrixRuntimeTransferError("BlueFire revision must be an exact commit")
    if _DIGEST.fullmatch(threat_review_ref) is None:
        raise StrixRuntimeTransferError("threat-review ref is invalid")
    root = transfer_root.resolve(strict=True)
    targets = [root / name for name in sorted(_TOP_LEVEL)]
    if any(path.exists() or path.is_symlink() for path in targets):
        raise StrixRuntimeTransferError("transfer destination must be new")
    created = False
    try:
        digest = hashlib.sha256()
        handle, before = _open_regular(bundle, MAX_BUNDLE_BYTES)
        with handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
            if f"sha256:{digest.hexdigest()}" != expected_ref:
                raise StrixRuntimeTransferError("transfer archive reference changed")
            handle.seek(0)
            with tarfile.open(fileobj=handle, mode="r:") as archive:
                members, _transfer_metadata = _preflight(
                    archive,
                    transfer_root=root,
                    bluefire_source_revision=bluefire_source_revision,
                    threat_review_ref=threat_review_ref,
                )
                directories = sorted(
                    (member for member in members if member.isdir()),
                    key=lambda member: len(PurePosixPath(member.name).parts),
                )
                created = True
                for member in directories:
                    destination = _destination(root, member.name)
                    destination.mkdir(mode=0o700)
                for member in members:
                    if not member.isfile() or member.name == METADATA_NAME:
                        continue
                    destination = _destination(root, member.name)
                    source = archive.extractfile(member)
                    if source is None:
                        raise StrixRuntimeTransferError("transfer member is unavailable")
                    flags = (
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_BINARY", 0)
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0)
                    )
                    descriptor = os.open(destination, flags, 0o600)
                    written = 0
                    try:
                        while chunk := source.read(min(1024 * 1024, member.size + 1 - written)):
                            written += len(chunk)
                            if written > member.size:
                                raise StrixRuntimeTransferError(
                                    "transfer member grew during extraction"
                                )
                            view = memoryview(chunk)
                            while view:
                                count = os.write(descriptor, view)
                                if count <= 0:
                                    raise StrixRuntimeTransferError(
                                        "transfer member could not be written"
                                    )
                                view = view[count:]
                        if written != member.size:
                            raise StrixRuntimeTransferError("transfer member was truncated")
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    os.chmod(destination, member.mode)
                for member in sorted(
                    directories,
                    key=lambda row: len(PurePosixPath(row.name).parts),
                    reverse=True,
                ):
                    os.chmod(_destination(root, member.name), 0o555)  # nosec B103
            after = os.fstat(handle.fileno())
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise StrixRuntimeTransferError("transfer archive changed during extraction")
    except BaseException as extraction_error:
        if created:
            for path in targets:
                _remove_root(path)
                if path.exists() or path.is_symlink():
                    raise StrixRuntimeTransferError(
                        "partial transfer extraction remains after cleanup"
                    ) from extraction_error
        raise
    return (
        root / CANDIDATE_DIRECTORY,
        root / PREPARATION_DIRECTORY,
        root / WORK_DIRECTORY,
    )


def remove_transfer_tree(transfer_root: Path) -> None:
    """Remove only the three fixed roots created by :func:`extract_transfer_bundle`."""

    root = transfer_root.resolve(strict=True)
    for name in _TOP_LEVEL:
        path = root / name
        _remove_root(path)
        if path.exists() or path.is_symlink():
            raise StrixRuntimeTransferError("transfer extraction remains after cleanup")
