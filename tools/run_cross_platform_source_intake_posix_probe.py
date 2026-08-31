"""Fixed native-Linux source-intake publication probes for Gate 11."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence, cast

SOURCE_INTAKE_POSIX_PROBE_SCHEMA = "bluefire.source-intake-posix-probes.v1"
SOURCE_INTAKE_POSIX_PROBE_IDS = (
    "source_intake.posix.publication_preserves_rebound_temporary",
    "source_intake.posix.publication_refuses_target_collision",
    "source_intake.posix.quarantine_retained_namespace_no_replace",
)
SOURCE_INTAKE_POSIX_PROBE_COUNT = 3
SOURCE_INTAKE_POSIX_PROBE_IDS_SHA256 = (
    "sha256:bbdd4c7db581e50913736c64c466e9ba783679435b353adba5ea27f2c9cbe6c1"
)


class SourceIntakePosixProbeError(ValueError):
    """Raised when a fixed Gate 11 POSIX publication probe fails."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SourceIntakePosixProbeError(message)


def probe_ids_sha256(probe_ids: Sequence[str]) -> str:
    payload = json.dumps(
        list(probe_ids), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _payload(path: Path, maximum: int) -> bytes:
    before = path.lstat()
    _require(
        stat.S_ISREG(before.st_mode)
        and not stat.S_ISLNK(before.st_mode)
        and before.st_nlink == 1
        and 0 < before.st_size <= maximum,
        "unsafe POSIX probe artifact",
    )
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)  # type: ignore[attr-defined]
    try:
        opened = os.fstat(descriptor)
        _require(
            stat.S_ISREG(opened.st_mode)
            and opened.st_nlink == 1
            and (opened.st_dev, opened.st_ino, opened.st_size)
            == (before.st_dev, before.st_ino, before.st_size),
            "POSIX probe artifact changed before its pinned read",
        )
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(maximum + 1)
        after = os.fstat(descriptor)
        current = path.lstat()
        _require(
            len(payload) == opened.st_size
            and (after.st_dev, after.st_ino, after.st_size)
            == (opened.st_dev, opened.st_ino, opened.st_size)
            and (current.st_dev, current.st_ino, current.st_size)
            == (opened.st_dev, opened.st_ino, opened.st_size),
            "POSIX probe artifact changed during its pinned read",
        )
        return payload
    finally:
        os.close(descriptor)


def run_probes(workspace: Path) -> Mapping[str, Any]:
    """Exercise the fixed publication and quarantine races on native Linux."""

    _require(os.name == "posix" and sys.platform.startswith("linux"), "invalid probe platform")
    _require(
        len(SOURCE_INTAKE_POSIX_PROBE_IDS) == SOURCE_INTAKE_POSIX_PROBE_COUNT
        and tuple(sorted(SOURCE_INTAKE_POSIX_PROBE_IDS)) == SOURCE_INTAKE_POSIX_PROBE_IDS
        and probe_ids_sha256(SOURCE_INTAKE_POSIX_PROBE_IDS) == SOURCE_INTAKE_POSIX_PROBE_IDS_SHA256,
        "source-intake POSIX probe inventory changed",
    )

    import bluefire.service as service_module
    import bluefire.source_intake as source_intake_module
    from bluefire.source_intake import SourceIntakeError

    probe_root = workspace / "source-intake-posix-probes"
    probe_root.mkdir(mode=0o700)
    passed: list[str] = []

    quarantine_root = probe_root / "quarantine" / "source-intakes"
    quarantine_root.mkdir(mode=0o700, parents=True)
    retained_destination = quarantine_root / "retained-posix"
    retained_destination.mkdir(mode=0o700)
    retained_file = retained_destination / ".bfi-retained"
    retained_file.write_bytes(b"retained-owned-state")
    destination_before = retained_destination.lstat()
    retained_before = retained_file.lstat()
    release = service_module._release_failed_source_intake_destination(
        retained_destination,
        destination_identity=service_module._filesystem_identity(destination_before),
        intake_root_identity=service_module._filesystem_identity(quarantine_root.lstat()),
        destination_created=True,
        published_artifact=None,
        published_receipt=None,
    )
    release_ref = release[1]
    release_path = PurePosixPath(release_ref) if isinstance(release_ref, str) else None
    _require(
        release[0] == "quarantined"
        and release_path is not None
        and len(release_path.parts) == 2
        and release_path.parts[0] == "source-intakes"
        and release_path.parts[1].startswith(".retained-retained-posix-")
        and not retained_destination.exists(),
        "source-intake retained namespace was not exactly quarantined",
    )
    quarantined = quarantine_root / cast(PurePosixPath, release_path).parts[1]
    quarantined_file = quarantined / retained_file.name
    quarantined_details = quarantined.lstat()
    retained_after = quarantined_file.lstat()
    _require(
        (quarantined_details.st_dev, quarantined_details.st_ino, quarantined_details.st_mode)
        == (destination_before.st_dev, destination_before.st_ino, destination_before.st_mode)
        and (retained_after.st_dev, retained_after.st_ino, retained_after.st_mode)
        == (retained_before.st_dev, retained_before.st_ino, retained_before.st_mode)
        and _payload(quarantined_file, 64) == b"retained-owned-state",
        "source-intake quarantine did not retain exact state",
    )
    passed.append("source_intake.posix.quarantine_retained_namespace_no_replace")

    rebound_root = probe_root / "publication-rebound"
    rebound_root.mkdir(mode=0o700)
    rebound_target = rebound_root / "result.json"
    rebound_sources: list[str] = []
    real_rename = source_intake_module._posix_rename_no_replace

    def rename_then_rebind(root_descriptor: int, source_name: str, target_name: str) -> None:
        real_rename(root_descriptor, source_name, target_name)
        rebound_sources.append(source_name)
        (rebound_root / source_name).write_bytes(b"operator-owned-temporary")

    source_intake_module._posix_rename_no_replace = rename_then_rebind
    try:
        try:
            source_intake_module._publish_new_file(
                rebound_root, rebound_target.name, b'{"ok":true}'
            )
        except SourceIntakeError as exc:
            _require(
                "temporary output changed" in str(exc),
                "source-intake rebound publication failed with the wrong reason",
            )
        else:
            raise SourceIntakePosixProbeError("source-intake rebound publication was accepted")
    finally:
        source_intake_module._posix_rename_no_replace = real_rename
    _require(
        len(rebound_sources) == 1
        and _payload(rebound_root / rebound_sources[0], 64) == b"operator-owned-temporary"
        and _payload(rebound_target, 64) == b'{"ok":true}',
        "source-intake rebound state was deleted or replaced",
    )
    passed.append("source_intake.posix.publication_preserves_rebound_temporary")

    collision_root = probe_root / "publication-collision"
    collision_root.mkdir(mode=0o700)
    collision_target = collision_root / "result.json"
    collision_sources: list[str] = []

    def collide_then_rename(root_descriptor: int, source_name: str, target_name: str) -> None:
        collision_sources.append(source_name)
        (collision_root / target_name).write_bytes(b"operator-owned-target")
        real_rename(root_descriptor, source_name, target_name)

    source_intake_module._posix_rename_no_replace = collide_then_rename
    try:
        try:
            source_intake_module._publish_new_file(
                collision_root, collision_target.name, b'{"ok":true}'
            )
        except SourceIntakeError as exc:
            _require(
                "atomically published" in str(exc),
                "source-intake collision failed with the wrong reason",
            )
        else:
            raise SourceIntakePosixProbeError("source-intake target collision was accepted")
    finally:
        source_intake_module._posix_rename_no_replace = real_rename
    _require(
        len(collision_sources) == 1
        and _payload(collision_root / collision_sources[0], 64) == b'{"ok":true}'
        and _payload(collision_target, 64) == b"operator-owned-target",
        "source-intake collision state was deleted or replaced",
    )
    passed.append("source_intake.posix.publication_refuses_target_collision")

    passed_ids = tuple(sorted(passed))
    _require(
        passed_ids == SOURCE_INTAKE_POSIX_PROBE_IDS,
        "source-intake POSIX probes did not all pass",
    )
    return {
        "schema_version": SOURCE_INTAKE_POSIX_PROBE_SCHEMA,
        "platform": "linux",
        "passed": True,
        "probe_count": len(passed_ids),
        "passed_probe_ids": list(passed_ids),
        "passed_probe_ids_sha256": probe_ids_sha256(passed_ids),
    }


__all__ = [
    "SOURCE_INTAKE_POSIX_PROBE_COUNT",
    "SOURCE_INTAKE_POSIX_PROBE_IDS",
    "SOURCE_INTAKE_POSIX_PROBE_IDS_SHA256",
    "SOURCE_INTAKE_POSIX_PROBE_SCHEMA",
    "SourceIntakePosixProbeError",
    "probe_ids_sha256",
    "run_probes",
]
