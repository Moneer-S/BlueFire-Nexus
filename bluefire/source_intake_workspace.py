"""Owned source-intake destinations, resumable staging, and failure retirement."""

from __future__ import annotations

import json
import os
import stat
from http import HTTPStatus
from pathlib import Path, PurePosixPath
from secrets import token_hex
from typing import Any, Mapping

from . import source_intake_package
from .application_errors import APIError
from .runner_trust import RunnerTrustError, _PinnedDirectory
from .source_intake import SourceIntakeError, _quarantine_directory_no_replace
from .source_intake_publication import (
    _filesystem_identity,
    _filesystem_snapshot,
    _publish_owned_payload_no_replace,
    _read_owned_canonical_document,
    _remove_exact_source_intake_file,
    _same_filesystem_owner,
    _unsafe_directory_metadata,
    _unsafe_regular_file_metadata,
)
from .util import canonical_json_bytes

_REVIEWED_T1082_STAGE_FILE = "mitre-attack-t1082-v19-2-action-package.json"
_REVIEWED_T1082_STAGE_SCHEMA = "bluefire.reviewed-source-intake-package-stage.v1"
_MAX_REVIEWED_T1082_STAGE_BYTES = 1_048_576
_REVIEWED_T1082_RECEIPT_FILE = "intake.mitre-t1082.v1.operation-receipt.json"
_MAX_REVIEWED_T1082_RECEIPT_BYTES = 32 * 1024
_SOURCE_INTAKE_QUARANTINE_PREFIX = ".retained-"
_SOURCE_INTAKE_QUARANTINE_ATTEMPTS = 8


def _allocate_source_intake_destination(
    root: Path, destination_id: str
) -> tuple[Path, tuple[int, int, int], tuple[int, int, int], bool]:
    """Allocate a namespace or securely select an exact interrupted namespace."""

    try:
        state_root = root.resolve(strict=True)
        state_metadata = state_root.lstat()
        intake_root = state_root / "source-intakes"
        intake_root.mkdir(mode=0o700, exist_ok=True)
        with _PinnedDirectory(intake_root, private=True):
            pass
        intake_metadata = intake_root.lstat()
        resolved_intake_root = intake_root.resolve(strict=True)
    except (OSError, RunnerTrustError) as exc:
        raise APIError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "source_intake_state_unavailable",
            "The product-controlled source-intake state root is unavailable.",
        ) from exc
    if (
        _unsafe_directory_metadata(state_metadata)
        or _unsafe_directory_metadata(intake_metadata)
        or resolved_intake_root.parent != state_root
        or not _same_filesystem_owner(intake_metadata, state_metadata)
        or (os.name != "nt" and stat.S_IMODE(intake_metadata.st_mode) != 0o700)
    ):
        raise APIError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "source_intake_state_unsafe",
            "The product-controlled source-intake state root is unsafe.",
        )

    destination = intake_root / destination_id
    created = True
    allocated_identity: tuple[int, int] | None = None
    try:
        destination.mkdir(mode=0o700, exist_ok=False)
    except FileExistsError:
        created = False
    except (OSError, RunnerTrustError) as exc:
        raise APIError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "source_intake_destination_unavailable",
            "The source-intake destination could not be allocated.",
        ) from exc

    try:
        if created:
            with _PinnedDirectory(destination, private=False) as allocated:
                allocated_identity = allocated.identity
        with _PinnedDirectory(destination, private=True):
            pass
        destination_metadata = destination.lstat()
        resolved_destination = destination.resolve(strict=True)
        current_intake_metadata = intake_root.lstat()
    except (OSError, RunnerTrustError) as exc:
        if created and allocated_identity is not None:
            try:
                with _PinnedDirectory(destination, private=False, delete=True) as allocated:
                    if allocated.identity == allocated_identity:
                        allocated.remove()
            except (OSError, RunnerTrustError):
                pass
        raise APIError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "source_intake_destination_unsafe",
            "The source-intake destination did not remain available.",
        ) from exc
    if (
        _unsafe_directory_metadata(destination_metadata)
        or resolved_destination.parent != resolved_intake_root
        or _filesystem_identity(current_intake_metadata) != _filesystem_identity(intake_metadata)
        or not _same_filesystem_owner(destination_metadata, intake_metadata)
        or not _same_filesystem_owner(intake_metadata, state_metadata)
        or (os.name != "nt" and bool(stat.S_IMODE(destination_metadata.st_mode) & 0o077))
    ):
        raise APIError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "source_intake_destination_unsafe",
            "The source-intake destination is unsafe.",
        )
    return (
        resolved_destination,
        _filesystem_identity(destination_metadata),
        _filesystem_identity(intake_metadata),
        created,
    )


def _read_interrupted_t1082_destination(
    destination: Path,
    *,
    destination_identity: tuple[int, int, int],
) -> tuple[
    Mapping[str, Any],
    tuple[Mapping[str, Any], bytes, tuple[int, int, int]] | None,
]:
    """Read only an exact artifact-only or completed interrupted namespace."""

    artifact_name = f"{source_intake_package.INTAKE_ID}.json"
    allowed_names = {artifact_name, _REVIEWED_T1082_RECEIPT_FILE}
    try:
        before = destination.lstat()
        entries = tuple(destination.iterdir())
    except OSError as exc:
        raise SourceIntakeError("interrupted source-intake destination is unavailable") from exc
    names = [entry.name for entry in entries]
    if (
        _unsafe_directory_metadata(before)
        or _filesystem_identity(before) != destination_identity
        or len(names) != len(set(names))
        or artifact_name not in names
        or not set(names).issubset(allowed_names)
    ):
        raise SourceIntakeError("interrupted source-intake destination contains unexpected state")

    artifact, artifact_payload, _artifact_identity = _read_owned_canonical_document(
        destination / artifact_name,
        directory=destination,
        directory_identity=destination_identity,
        maximum_bytes=_MAX_REVIEWED_T1082_STAGE_BYTES,
        context="interrupted source-intake artifact",
    )
    try:
        envelope = source_intake_package.validate_gate09_intake_envelope(artifact)
    except source_intake_package.SourceIntakePackageError as exc:
        raise SourceIntakeError(
            "interrupted source-intake artifact failed its reviewed contract"
        ) from exc
    if canonical_json_bytes(envelope) != artifact_payload:
        raise SourceIntakeError("interrupted source-intake artifact is not canonical")

    receipt: tuple[Mapping[str, Any], bytes, tuple[int, int, int]] | None = None
    if _REVIEWED_T1082_RECEIPT_FILE in names:
        receipt = _read_owned_canonical_document(
            destination / _REVIEWED_T1082_RECEIPT_FILE,
            directory=destination,
            directory_identity=destination_identity,
            maximum_bytes=_MAX_REVIEWED_T1082_RECEIPT_BYTES,
            context="completed source-intake receipt",
        )
    try:
        after = destination.lstat()
        final_names = {entry.name for entry in destination.iterdir()}
    except OSError as exc:
        raise SourceIntakeError(
            "interrupted source-intake destination changed during recovery"
        ) from exc
    if (
        _filesystem_identity(after) != destination_identity
        or after.st_mtime_ns != before.st_mtime_ns
        or final_names != set(names)
    ):
        raise SourceIntakeError("interrupted source-intake destination changed during recovery")
    return envelope, receipt


def _publish_reviewed_t1082_operation_receipt(
    destination: Path,
    *,
    destination_identity: tuple[int, int, int],
    receipt: Mapping[str, Any],
) -> tuple[Path, tuple[int, int, int], bytes]:
    """Exclusively publish canonical receipt bytes in the allocated destination."""

    payload = canonical_json_bytes(receipt)
    if not 1 <= len(payload) <= _MAX_REVIEWED_T1082_RECEIPT_BYTES:
        raise SourceIntakeError("reviewed source operation receipt exceeds its byte bound")
    target = destination / _REVIEWED_T1082_RECEIPT_FILE
    try:
        destination_metadata = destination.lstat()
        resolved_destination = destination.resolve(strict=True)
        if (
            _unsafe_directory_metadata(destination_metadata)
            or _filesystem_identity(destination_metadata) != destination_identity
            or target.parent != resolved_destination
        ):
            raise OSError("source-intake receipt destination identity changed")
        identity = _publish_owned_payload_no_replace(
            resolved_destination,
            directory_identity=destination_identity,
            target=target,
            payload=payload,
            context="reviewed source operation receipt",
        )
    except FileExistsError as exc:
        raise SourceIntakeError(
            "reviewed source operation receipt already exists in the new destination"
        ) from exc
    except OSError as exc:
        raise SourceIntakeError(
            "reviewed source operation receipt could not be published safely"
        ) from exc
    return target, identity, payload


def _release_failed_source_intake_destination(
    destination: Path,
    *,
    destination_identity: tuple[int, int, int],
    intake_root_identity: tuple[int, int, int],
    destination_created: bool,
    published_artifact: tuple[Path, tuple[int, int, int], bytes] | None,
    published_receipt: tuple[Path, tuple[int, int, int], bytes] | None,
) -> tuple[str, str | None]:
    """Release new state by exact quarantine, or preserve an interrupted namespace."""

    if destination_created:
        try:
            with _PinnedDirectory(destination, private=False, delete=True) as allocated:
                if allocated.identity != destination_identity[:2] or allocated.names(maximum=1):
                    raise RunnerTrustError(
                        "failed source-intake destination is not the exact empty namespace"
                    )
                allocated.remove()
            return "released", None
        except (OSError, RunnerTrustError):
            pass
        return _quarantine_failed_source_intake_destination(
            destination,
            destination_identity=destination_identity,
            intake_root_identity=intake_root_identity,
        )

    try:
        intake_root = destination.parent
        intake_metadata = intake_root.lstat()
        destination_metadata = destination.lstat()
        resolved_intake_root = intake_root.resolve(strict=True)
        resolved_destination = destination.resolve(strict=True)
        if (
            intake_root.name != "source-intakes"
            or _unsafe_directory_metadata(intake_metadata)
            or _unsafe_directory_metadata(destination_metadata)
            or _filesystem_identity(intake_metadata) != intake_root_identity
            or _filesystem_identity(destination_metadata) != destination_identity
            or resolved_destination.parent != resolved_intake_root
        ):
            return "retained", None
        if published_receipt is not None and not _remove_exact_source_intake_file(
            destination,
            published_receipt,
            expected_name=_REVIEWED_T1082_RECEIPT_FILE,
        ):
            return "retained", f"source-intakes/{destination.name}"
        if published_artifact is not None and not _remove_exact_source_intake_file(
            destination,
            published_artifact,
            expected_name=f"{source_intake_package.INTAKE_ID}.json",
        ):
            return "retained", f"source-intakes/{destination.name}"
    except OSError:
        return "retained", f"source-intakes/{destination.name}"
    return "existing_preserved", None


def _quarantine_failed_source_intake_destination(
    destination: Path,
    *,
    destination_identity: tuple[int, int, int],
    intake_root_identity: tuple[int, int, int],
) -> tuple[str, str | None]:
    """Move one exact failed namespace aside while preserving every child entry."""

    original_ref = f"source-intakes/{destination.name}"
    for _attempt in range(_SOURCE_INTAKE_QUARANTINE_ATTEMPTS):
        quarantine_name = f"{_SOURCE_INTAKE_QUARANTINE_PREFIX}{destination.name}-{token_hex(8)}"
        quarantine = destination.parent / quarantine_name
        quarantine_ref = f"source-intakes/{quarantine_name}"
        try:
            retained, released = _quarantine_directory_no_replace(
                destination,
                quarantine_name,
                directory_identity=destination_identity,
                parent_identity=intake_root_identity,
            )
        except FileExistsError:
            continue
        except (OSError, SourceIntakeError):
            try:
                retained_metadata = quarantine.lstat()
            except OSError:
                retained_metadata = None
            if (
                retained_metadata is not None
                and not _unsafe_directory_metadata(retained_metadata)
                and _filesystem_identity(retained_metadata) == destination_identity
            ):
                return "quarantined_unverified", quarantine_ref
            try:
                current = destination.lstat()
            except OSError:
                return "retained", None
            if (
                not _unsafe_directory_metadata(current)
                and _filesystem_identity(current) == destination_identity
            ):
                return "retained", original_ref
            return "retained", None
        if retained != quarantine:
            return "retained", None
        return ("quarantined" if released else "quarantined_rebound"), quarantine_ref
    try:
        current = destination.lstat()
    except OSError:
        return "retained", None
    if (
        not _unsafe_directory_metadata(current)
        and _filesystem_identity(current) == destination_identity
    ):
        return "retained", original_ref
    return "retained", None


def _source_intake_release_detail(release: tuple[str, str | None]) -> str | None:
    state, state_ref = release
    if state in {"released", "existing_preserved"}:
        return None
    if state_ref is not None:
        logical_ref = PurePosixPath(state_ref)
        if (
            logical_ref.is_absolute()
            or len(logical_ref.parts) != 2
            or logical_ref.parts[0] != "source-intakes"
            or logical_ref.parts[1] in {"", ".", ".."}
            or "\\" in state_ref
            or ":" in logical_ref.parts[1]
            or any(ord(character) < 32 or ord(character) == 127 for character in state_ref)
        ):
            state_ref = None
    if state == "quarantined" and state_ref is not None:
        return (
            f"Fail-closed retained state was quarantined at {state_ref}; "
            "the requested destination was released for retry."
        )
    if state == "quarantined_rebound" and state_ref is not None:
        return (
            f"Exact retained state was quarantined at {state_ref}, but the requested "
            "destination was rebound to unowned state and was not modified."
        )
    if state == "quarantined_unverified" and state_ref is not None:
        return (
            f"Retained state may remain at {state_ref}; quarantine durability could not be "
            "fully verified and no retained path was deleted."
        )
    if state_ref is not None:
        return (
            f"Retained state remains at {state_ref}; the requested destination could not be "
            "released safely and no retained path was deleted."
        )
    return (
        "Retained source-intake state could not be located or released safely; no unverified "
        "path was deleted."
    )


def _reviewed_t1082_stage_location(
    root: Path,
    *,
    create: bool,
) -> tuple[Path, Path, tuple[int, int, int]] | None:
    """Resolve staging without making an absent read mutate product state."""

    try:
        state_root = root.resolve(strict=True)
        state_metadata = state_root.lstat()
        stage_root = state_root / "source-intake-package-staging"
        if create:
            stage_root.mkdir(mode=0o700, exist_ok=True)
        stage_metadata = stage_root.lstat()
        resolved_stage_root = stage_root.resolve(strict=True)
    except FileNotFoundError:
        if not create:
            return None
        raise SourceIntakeError("reviewed source package staging is unavailable") from None
    except OSError as exc:
        raise SourceIntakeError("reviewed source package staging is unavailable") from exc
    if (
        _unsafe_directory_metadata(state_metadata)
        or _unsafe_directory_metadata(stage_metadata)
        or resolved_stage_root.parent != state_root
    ):
        raise SourceIntakeError("reviewed source package staging is unsafe")
    try:
        with _PinnedDirectory(resolved_stage_root, private=True):
            pass
        current_stage_metadata = resolved_stage_root.lstat()
        current_state_metadata = state_root.lstat()
    except (OSError, RunnerTrustError) as exc:
        raise SourceIntakeError("reviewed source package staging is not owner-private") from exc
    if (
        _filesystem_identity(current_stage_metadata) != _filesystem_identity(stage_metadata)
        or _filesystem_identity(current_state_metadata) != _filesystem_identity(state_metadata)
        or not _same_filesystem_owner(current_stage_metadata, current_state_metadata)
        or (os.name != "nt" and stat.S_IMODE(current_stage_metadata.st_mode) != 0o700)
    ):
        raise SourceIntakeError("reviewed source package staging is not owner-private")
    return (
        resolved_stage_root / _REVIEWED_T1082_STAGE_FILE,
        resolved_stage_root,
        _filesystem_identity(current_stage_metadata),
    )


def _constrain_reviewed_t1082_stage_file(
    path: Path,
    *,
    stage_root: Path,
    stage_root_identity: tuple[int, int, int],
) -> tuple[bytes, tuple[int, int], tuple[int, int, int, int, int]]:
    """Apply and verify private access before staged signing authority is trusted."""

    try:
        with _PinnedDirectory(stage_root, private=True) as pinned:
            payload, identity, snapshot = pinned.read_with_identity(
                path.name,
                maximum=_MAX_REVIEWED_T1082_STAGE_BYTES,
                exclusive=True,
            )
        current_root = stage_root.lstat()
        current = path.lstat()
    except (OSError, RunnerTrustError) as exc:
        raise SourceIntakeError("reviewed source package stage is not owner-private") from exc
    if (
        path.parent != stage_root
        or _unsafe_directory_metadata(current_root)
        or _unsafe_regular_file_metadata(current)
        or _filesystem_identity(current_root) != stage_root_identity
        or not _same_filesystem_owner(current, current_root)
        or _filesystem_snapshot(current) != snapshot
        or (
            os.name != "nt"
            and (
                stat.S_IMODE(current_root.st_mode) != 0o700
                or stat.S_IMODE(current.st_mode) != 0o600
            )
        )
    ):
        raise SourceIntakeError("reviewed source package stage is not owner-private")
    return payload, identity, snapshot


def _read_reviewed_t1082_package_stage(
    root: Path,
) -> tuple[Mapping[str, Any], bytes, tuple[int, int]] | None:
    location = _reviewed_t1082_stage_location(root, create=False)
    if location is None:
        return None
    path, stage_root, stage_root_identity = location
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        try:
            with _PinnedDirectory(stage_root, private=True, delete=True) as pinned:
                pinned.remove()
        except (OSError, RunnerTrustError):
            pass
        return None
    except OSError as exc:
        raise SourceIntakeError("reviewed source package stage could not be inspected") from exc
    if (
        _unsafe_regular_file_metadata(metadata)
        or not 1 <= metadata.st_size <= _MAX_REVIEWED_T1082_STAGE_BYTES
    ):
        raise SourceIntakeError("reviewed source package stage has an unsafe identity or size")
    payload, pinned_identity, pinned_snapshot = _constrain_reviewed_t1082_stage_file(
        path,
        stage_root=stage_root,
        stage_root_identity=stage_root_identity,
    )
    metadata = path.lstat()

    path_identity = _filesystem_identity(metadata)
    try:
        current_root = stage_root.lstat()
        current = path.lstat()
    except OSError as exc:
        raise SourceIntakeError("reviewed source package stage changed while it was read") from exc
    if (
        _unsafe_directory_metadata(current_root)
        or _unsafe_regular_file_metadata(metadata)
        or not _same_filesystem_owner(metadata, current_root)
        or _filesystem_identity(current_root) != stage_root_identity
        or _filesystem_identity(current) != path_identity
        or _filesystem_snapshot(metadata) != pinned_snapshot
        or len(payload) != metadata.st_size
        or len(payload) > _MAX_REVIEWED_T1082_STAGE_BYTES
        or (
            os.name != "nt"
            and (
                stat.S_IMODE(current_root.st_mode) != 0o700
                or stat.S_IMODE(metadata.st_mode) != 0o600
            )
        )
    ):
        raise SourceIntakeError("reviewed source package stage changed while it was read")
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise SourceIntakeError("reviewed source package stage is not canonical JSON") from exc
    if not isinstance(document, Mapping) or canonical_json_bytes(document) != payload:
        raise SourceIntakeError("reviewed source package stage is not canonical JSON")
    return document, payload, pinned_identity


def _stage_reviewed_t1082_package(
    root: Path,
    proposed: Mapping[str, Any],
) -> tuple[Mapping[str, Any], bool, bytes]:
    """Create once, or resume, the public signed bytes needed after a process crash."""

    payload = canonical_json_bytes(proposed)
    if not 1 <= len(payload) <= _MAX_REVIEWED_T1082_STAGE_BYTES:
        raise SourceIntakeError("reviewed source package stage is too large")
    location = _reviewed_t1082_stage_location(root, create=True)
    if location is None:  # pragma: no cover - create=True invariant
        raise SourceIntakeError("reviewed source package staging is unavailable")
    path, stage_root, stage_root_identity = location
    try:
        _publish_owned_payload_no_replace(
            stage_root,
            directory_identity=stage_root_identity,
            target=path,
            payload=payload,
            context="reviewed source package stage",
        )
        _constrain_reviewed_t1082_stage_file(
            path,
            stage_root=stage_root,
            stage_root_identity=stage_root_identity,
        )
    except FileExistsError:
        existing = _read_reviewed_t1082_package_stage(root)
        if existing is None:
            raise SourceIntakeError(
                "reviewed source package stage changed during recovery"
            ) from None
        document, existing_payload, _identity = existing
        return document, False, existing_payload
    except OSError as exc:
        try:
            stage_root.rmdir()
        except OSError:
            pass
        raise SourceIntakeError("reviewed source package stage could not be published") from exc
    return json.loads(payload), True, payload


def _remove_reviewed_t1082_package_stage(root: Path, *, expected_payload: bytes) -> None:
    """Remove only the exact verified stage that has reached durable package storage."""

    staged = _read_reviewed_t1082_package_stage(root)
    if staged is None:
        return
    _document, payload, identity = staged
    location = _reviewed_t1082_stage_location(root, create=False)
    if location is None:
        raise SourceIntakeError("reviewed source package stage disappeared before cleanup")
    path, stage_root, _stage_root_identity = location
    try:
        if payload != expected_payload:
            raise SourceIntakeError("reviewed source package stage changed before recovery cleanup")
        with _PinnedDirectory(stage_root, private=True, delete=True) as pinned:
            pinned.unlink(
                path.name,
                maximum=_MAX_REVIEWED_T1082_STAGE_BYTES,
                expected_identity=identity,
            )
            pinned.sync()
            pinned.remove()
    except SourceIntakeError:
        raise
    except (OSError, RunnerTrustError) as exc:
        raise SourceIntakeError("reviewed source package stage could not be retired") from exc
