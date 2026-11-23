"""Ownership-checked reads and atomic publication of reviewed intake state."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any, Mapping

from . import source_intake_package
from .source_intake import SourceIntakeError
from .util import canonical_json_bytes

_WINDOWS_REPARSE_POINT = 0x0400


def _read_owned_canonical_document(
    path: Path,
    *,
    directory: Path,
    directory_identity: tuple[int, int, int],
    maximum_bytes: int,
    context: str,
) -> tuple[Mapping[str, Any], bytes, tuple[int, int, int]]:
    """Read one bounded canonical singly-linked file under an exact directory."""

    try:
        directory_metadata = directory.lstat()
        metadata = path.lstat()
    except OSError as exc:
        raise SourceIntakeError(f"{context} is unavailable") from exc
    if (
        path.parent != directory
        or _unsafe_directory_metadata(directory_metadata)
        or _filesystem_identity(directory_metadata) != directory_identity
        or _unsafe_regular_file_metadata(metadata)
        or not _same_filesystem_owner(metadata, directory_metadata)
        or not 1 <= metadata.st_size <= maximum_bytes
    ):
        raise SourceIntakeError(f"{context} identity or size is invalid")
    identity = _filesystem_identity(metadata)
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        descriptor_before = os.fstat(descriptor)
        observed = bytearray()
        while len(observed) <= maximum_bytes:
            block = os.read(
                descriptor,
                min(64 * 1024, maximum_bytes + 1 - len(observed)),
            )
            if not block:
                break
            observed.extend(block)
        descriptor_after = os.fstat(descriptor)
    except OSError as exc:
        raise SourceIntakeError(f"{context} could not be read safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    try:
        current_directory = directory.lstat()
        current = path.lstat()
    except OSError as exc:
        raise SourceIntakeError(f"{context} changed while it was read") from exc
    payload = bytes(observed)
    if (
        _unsafe_regular_file_metadata(descriptor_before)
        or _filesystem_identity(descriptor_before) != identity
        or _filesystem_identity(descriptor_after) != identity
        or _filesystem_identity(current) != identity
        or _filesystem_identity(current_directory) != directory_identity
        or descriptor_after.st_size != descriptor_before.st_size
        or descriptor_after.st_mtime_ns != descriptor_before.st_mtime_ns
        or len(payload) != descriptor_before.st_size
        or len(payload) > maximum_bytes
    ):
        raise SourceIntakeError(f"{context} changed while it was read")
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise SourceIntakeError(f"{context} is not canonical JSON") from exc
    if not isinstance(document, Mapping) or canonical_json_bytes(document) != payload:
        raise SourceIntakeError(f"{context} is not canonical JSON")
    return document, payload, identity


def _remove_exact_source_intake_file(
    destination: Path,
    published: tuple[Path, tuple[int, int, int], bytes],
    *,
    expected_name: str,
) -> bool:
    path, identity, expected_payload = published
    if path.parent != destination or path.name != expected_name:
        return False
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        observed = bytearray()
        while len(observed) <= len(expected_payload):
            block = os.read(
                descriptor,
                min(64 * 1024, len(expected_payload) + 1 - len(observed)),
            )
            if not block:
                break
            observed.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = path.lstat()
    if (
        _unsafe_regular_file_metadata(before)
        or _filesystem_identity(before) != identity
        or _filesystem_identity(after) != identity
        or after.st_size != before.st_size
        or after.st_mtime_ns != before.st_mtime_ns
        or _filesystem_identity(current) != identity
        or bytes(observed) != expected_payload
    ):
        return False
    path.unlink()
    return True


def _publish_owned_payload_no_replace(
    directory: Path,
    *,
    directory_identity: tuple[int, int, int],
    target: Path,
    payload: bytes,
    context: str,
) -> tuple[int, int, int]:
    """Fsync a private temp and hard-link it into authority without overwriting."""

    if target.parent != directory or not payload:
        raise OSError(f"{context} publication target is invalid")
    descriptor: int | None = None
    temporary: Path | None = None
    temporary_identity: tuple[int, int, int] | None = None
    target_linked = False
    completed = False
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=directory,
            prefix=f".{target.name}.",
            suffix=".tmp",
        )
        temporary = Path(temporary_name)
        before = os.fstat(descriptor)
        temporary_identity = _filesystem_identity(before)
        if (
            temporary.parent != directory
            or _unsafe_regular_file_metadata(before)
            or before.st_size != 0
        ):
            raise OSError(f"{context} temporary file is unsafe")
        _write_reviewed_state_payload(descriptor, payload, context=context)
        _fsync_reviewed_state_temporary(descriptor)
        after = os.fstat(descriptor)
        current_directory = directory.lstat()
        current_temporary = temporary.lstat()
        _validate_reviewed_state_temporary(
            current_directory=current_directory,
            directory_identity=directory_identity,
            descriptor_metadata=after,
            temporary_metadata=current_temporary,
            temporary_identity=temporary_identity,
            expected_size=len(payload),
            context=context,
        )
        os.close(descriptor)
        descriptor = None
        os.link(temporary, target, follow_symlinks=False)
        target_linked = True
        linked = target.lstat()
        if (
            not stat.S_ISREG(linked.st_mode)
            or stat.S_ISLNK(linked.st_mode)
            or bool(getattr(linked, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT)
            or _filesystem_identity(linked) != temporary_identity
            or linked.st_nlink != 2
            or linked.st_size != len(payload)
        ):
            raise OSError(f"{context} atomic publication identity is invalid")
        temporary.unlink()
        temporary = None
        published = target.lstat()
        if (
            _unsafe_regular_file_metadata(published)
            or _filesystem_identity(published) != temporary_identity
            or published.st_size != len(payload)
        ):
            raise OSError(f"{context} publication did not become authoritative")
        _fsync_reviewed_state_directory(directory, directory_identity)
        completed = True
        return temporary_identity
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary is not None and temporary_identity is not None:
            try:
                current = temporary.lstat()
                if (
                    temporary.parent == directory
                    and _filesystem_identity(current) == temporary_identity
                ):
                    temporary.unlink()
            except OSError:
                pass
        if target_linked and not completed and temporary_identity is not None:
            try:
                current = target.lstat()
                if (
                    target.parent == directory
                    and _filesystem_identity(current) == temporary_identity
                ):
                    target.unlink()
            except OSError:
                pass


def _write_reviewed_state_payload(descriptor: int, payload: bytes, *, context: str) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError(f"{context} write made no progress")
        offset += written


def _fsync_reviewed_state_temporary(descriptor: int) -> None:
    os.fsync(descriptor)


def _validate_reviewed_state_temporary(
    *,
    current_directory: os.stat_result,
    directory_identity: tuple[int, int, int],
    descriptor_metadata: os.stat_result,
    temporary_metadata: os.stat_result,
    temporary_identity: tuple[int, int, int],
    expected_size: int,
    context: str,
) -> None:
    if (
        _unsafe_directory_metadata(current_directory)
        or _filesystem_identity(current_directory) != directory_identity
        or _unsafe_regular_file_metadata(descriptor_metadata)
        or _filesystem_identity(descriptor_metadata) != temporary_identity
        or _filesystem_identity(temporary_metadata) != temporary_identity
        or descriptor_metadata.st_size != expected_size
        or temporary_metadata.st_size != expected_size
    ):
        raise OSError(f"{context} temporary file changed before publication")


def _fsync_reviewed_state_directory(
    directory: Path,
    expected_identity: tuple[int, int, int],
) -> None:
    """Durably publish directory metadata where the host supports directory fsync."""

    try:
        descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        if os.name == "nt":
            return
        raise
    try:
        metadata = os.fstat(descriptor)
        if (
            _unsafe_directory_metadata(metadata)
            or _filesystem_identity(metadata) != expected_identity
        ):
            raise OSError("reviewed state directory identity changed")
        try:
            os.fsync(descriptor)
        except OSError:
            if os.name != "nt":
                raise
    finally:
        os.close(descriptor)


def _verify_reviewed_source_license(path: Path) -> Mapping[str, Any]:
    """Read and bind only the exact packaged license bytes reviewed for T1082."""

    expected_size = source_intake_package.LICENSE_SIZE_BYTES
    try:
        if not path.is_absolute():
            raise OSError("license resource path is not absolute")
        root = path.parent
        root_metadata = root.lstat()
        license_metadata = path.lstat()
        resolved_root = root.resolve(strict=True)
        resolved_license = path.resolve(strict=True)
    except OSError as exc:
        raise SourceIntakeError("reviewed source license is unavailable") from exc
    if (
        _unsafe_directory_metadata(root_metadata)
        or _unsafe_regular_file_metadata(license_metadata)
        or license_metadata.st_size != expected_size
        or resolved_license.parent != resolved_root
    ):
        raise SourceIntakeError("reviewed source license identity or size is invalid")

    root_identity = _filesystem_identity(root_metadata)
    license_identity = _filesystem_identity(license_metadata)
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        observed = bytearray()
        while len(observed) <= expected_size:
            block = os.read(descriptor, min(64 * 1024, expected_size + 1 - len(observed)))
            if not block:
                break
            observed.extend(block)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise SourceIntakeError("reviewed source license could not be read safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)

    try:
        current_root = root.lstat()
        current_license = path.lstat()
    except OSError as exc:
        raise SourceIntakeError("reviewed source license changed while it was read") from exc
    payload = bytes(observed)
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    notice = source_intake_package.REQUIRED_NOTICE.encode("utf-8")
    if (
        _unsafe_directory_metadata(current_root)
        or _unsafe_regular_file_metadata(before)
        or _filesystem_identity(current_root) != root_identity
        or _filesystem_identity(before) != license_identity
        or _filesystem_identity(after) != license_identity
        or _filesystem_identity(current_license) != license_identity
        or len(payload) != expected_size
        or after.st_size != before.st_size
        or after.st_mtime_ns != before.st_mtime_ns
        or digest != source_intake_package.LICENSE_SHA256
        or payload.count(notice) != 1
    ):
        raise SourceIntakeError("reviewed source license bytes do not match their review")
    return {
        "license_id": source_intake_package.LICENSE_ID,
        "reference_url": source_intake_package.LICENSE_REFERENCE,
        "sha256": digest,
        "size_bytes": len(payload),
        "required_notice": source_intake_package.REQUIRED_NOTICE,
        "status": "verified_packaged_bytes",
    }


def _unsafe_directory_metadata(metadata: os.stat_result) -> bool:
    return (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or bool(getattr(metadata, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT)
    )


def _unsafe_regular_file_metadata(metadata: os.stat_result) -> bool:
    return (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or bool(getattr(metadata, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT)
    )


def _filesystem_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_mode


def _filesystem_snapshot(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _same_filesystem_owner(left: os.stat_result, right: os.stat_result) -> bool:
    return getattr(left, "st_uid", None) == getattr(right, "st_uid", None) and getattr(
        left, "st_gid", None
    ) == getattr(right, "st_gid", None)
