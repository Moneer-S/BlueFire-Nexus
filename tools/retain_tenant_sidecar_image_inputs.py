"""Retain target-image inputs from the exact installed BlueFire candidate.

This producer runs in the trusted installed-package qualification job. It
checks every wheel payload member against the installed service distribution
before writing a by-reference source for the fixed target image builder.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
import zipfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

from bluefire.tenant_record_sidecar_image import (
    PINNED_PYTHON_BASE,
    FileTargetSidecarBaseAdmissionSource,
    FileTargetSidecarBuildInputSource,
    TenantSidecarImageError,
    _digest,
    _docker_environment,
    _fixed_docker_executable,
    _inspect,
    _private_root,
    _run,
    _write_once,
)
from bluefire.util import content_hash
from tools.verify_installed_engine_experiment import bind_installed_wheel

BASE_SCHEMA = "bluefire.tenant-target-base-admission.v1"
INPUT_SCHEMA = "bluefire.tenant-target-image-build-input.v1"
_REVISION = re.compile(r"[0-9a-f]{40}\Z")


class TargetSidecarBaseAdmissionSource(Protocol):
    """A controller-protected pinned Python base manifest reader."""

    def reopen_base(self, base_ref: str) -> Mapping[str, Any]: ...


def retain_pinned_python_base(*, root: Path) -> Mapping[str, Any]:
    """Attest only the official preloaded linux/amd64 Python 3.12.14 manifest."""

    private = _private_root(Path(root))
    docker = _fixed_docker_executable()
    image = _inspect(
        _run, docker, "unix:///var/run/docker.sock", PINNED_PYTHON_BASE,
        _docker_environment(private), private,
    )
    config = image.get("Config")
    if (
        image.get("Os") != "linux"
        or image.get("Architecture") != "amd64"
        or not isinstance(config, dict)
        or not isinstance(config.get("Env"), list)
        or "PYTHON_VERSION=3.12.14" not in config["Env"]
    ):
        raise TenantSidecarImageError("preloaded Python base differs from pinned manifest")
    base_image_id = _digest(image.get("Id"), "preloaded Python base image ID")
    base = {
        "schema_version": BASE_SCHEMA,
        "base_reference": PINNED_PYTHON_BASE,
        "base_image_id": base_image_id,
        "base_config_ref": content_hash(config),
    }
    base["base_ref"] = content_hash(base)
    _write_once(private, f"base-{base['base_ref'][7:]}.json", base)
    reopened = FileTargetSidecarBaseAdmissionSource(private).reopen_base(base["base_ref"])
    if reopened != base:
        raise TenantSidecarImageError("pinned Python base failed to reopen")
    return reopened


def _wheel_digest(path: Path) -> str:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or path.is_symlink() or not 1 <= before.st_size <= 128 * 1024 * 1024:
        raise TenantSidecarImageError("staged installed wheel is unavailable")
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    after = path.lstat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
    ):
        raise TenantSidecarImageError("staged installed wheel changed during verification")
    return "sha256:" + value.hexdigest()


def _candidate_build_info(wheel: Path, expected_version: str, expected_revision: str) -> None:
    try:
        with zipfile.ZipFile(wheel) as archive:
            names = [
                name for name in archive.namelist()
                if name == "bluefire/_build_info.json"
                or name.endswith("/bluefire/_build_info.json")
            ]
            if len(names) != 1 or archive.getinfo(names[0]).file_size > 16 * 1024:
                raise TenantSidecarImageError("installed wheel build identity is unavailable")
            identity = json.loads(archive.read(names[0]).decode("utf-8"))
    except (OSError, UnicodeError, ValueError, zipfile.BadZipFile) as exc:
        raise TenantSidecarImageError("installed wheel build identity is invalid") from exc
    if (
        not isinstance(identity, dict)
        or identity.get("schema_version") != "bluefire.build-metadata.v1"
        or identity.get("version") != expected_version
        or identity.get("source_revision") != expected_revision
        or identity.get("source_provenance") != "git_archive"
    ):
        raise TenantSidecarImageError("installed wheel differs from the candidate revision")


def retain_target_sidecar_build_inputs(
    *,
    root: Path,
    staged_wheel: Path,
    service_purelib: Path,
    installed_version: str,
    expected_candidate_revision: str,
    expected_product_wheel_digest: str,
    base_admission: TargetSidecarBaseAdmissionSource,
    base_ref: str,
) -> Mapping[str, Any]:
    """Write and reopen one protected image-input record for the installed wheel."""

    private = _private_root(Path(root))
    wheel = Path(staged_wheel)
    if (
        not wheel.is_absolute()
        or not wheel.is_relative_to(private)
        or wheel.parent == private
        or not isinstance(installed_version, str)
        or not installed_version
        or not isinstance(expected_candidate_revision, str)
        or _REVISION.fullmatch(expected_candidate_revision) is None
    ):
        raise TenantSidecarImageError("installed target candidate identity is invalid")
    _digest(expected_product_wheel_digest, "product wheel candidate digest")
    _digest(base_ref, "pinned base admission reference")
    wheel_sha = _wheel_digest(wheel)
    if wheel_sha != expected_product_wheel_digest:
        raise TenantSidecarImageError("staged wheel differs from the product candidate")
    _candidate_build_info(wheel, installed_version, expected_candidate_revision)
    try:
        binding = bind_installed_wheel(
            wheel, purelib=Path(service_purelib), installed_version=installed_version
        )
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as exc:
        raise TenantSidecarImageError("staged wheel differs from installed service") from exc
    installed_payload_digest = _digest(
        binding.get("installed_payload_digest"), "installed service payload digest"
    )
    if binding.get("wheel_payload_digest") != installed_payload_digest:
        raise TenantSidecarImageError("installed service payload differs from wheel")
    try:
        base = base_admission.reopen_base(base_ref)
    except Exception as exc:
        raise TenantSidecarImageError("pinned Python base admission is unavailable") from exc
    fields = {
        "schema_version", "base_reference", "base_image_id", "base_config_ref", "base_ref",
    }
    if (
        not isinstance(base, Mapping)
        or set(base) != fields
        or base.get("schema_version") != BASE_SCHEMA
        or base.get("base_ref") != base_ref
        or base_ref != content_hash({k: v for k, v in base.items() if k != "base_ref"})
    ):
        raise TenantSidecarImageError("pinned Python base admission changed")
    for key in ("base_image_id", "base_config_ref"):
        _digest(base[key], key)
    value: dict[str, Any] = {
        "schema_version": INPUT_SCHEMA,
        "wheel_path": str(wheel),
        "wheel_sha256": wheel_sha,
        "installed_payload_digest": installed_payload_digest,
        "source_revision": expected_candidate_revision,
        "base_reference": base["base_reference"],
        "base_image_id": base["base_image_id"],
        "base_config_ref": base["base_config_ref"],
    }
    value["input_ref"] = content_hash(value)
    _write_once(private, f"build-input-{value['input_ref'][7:]}.json", value)
    reopened = FileTargetSidecarBuildInputSource(private).reopen_inputs(value["input_ref"])
    if reopened != value:
        raise TenantSidecarImageError("installed target image inputs failed to reopen")
    return reopened


__all__ = [
    "TargetSidecarBaseAdmissionSource",
    "retain_pinned_python_base",
    "retain_target_sidecar_build_inputs",
]
