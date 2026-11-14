"""Pinned inputs for the one installed Linux Strix worker launch.

The prepared closure and a reviewed runner binary determine the program.
Objective, configuration, and launch material are sealed before transfer to
the fixed native helper. This module supplies no arbitrary command surface.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from .strix_linux_native_worker import FixedRuntimeDescriptorSet
from .strix_linux_runtime_closure import (
    FIXED_GUEST_PROJECTION_DIGEST,
    PRIVATE_DEVICE_POLICY_DIGEST,
    PinnedStrixRuntimeClosure,
)
from .util import canonical_json_bytes

_NATIVE_MANIFEST_SCHEMA = "bluefire.strix-linux-runtime-native-manifest.v1"
_INPUT_SEALS = (
    fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ATTEMPT = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")
_RUNTIME_FILES = {
    "interpreter": "runtime/bin/python",
    "bootstrap": "bootstrap/worker.py",
    "lockdown": "bootstrap/worker_lockdown.py",
    "strix_entrypoint": "runtime/bin/strix",
}


class StrixNativeLaunchMaterialError(RuntimeError):
    """Pinned installed Strix launch material was unavailable or changed."""


def _refuse() -> StrixNativeLaunchMaterialError:
    return StrixNativeLaunchMaterialError("installed Strix launch material refused")


def _digest(value: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise _refuse()
    return value


def _file_digest(descriptor: int, maximum: int = 256 * 1024 * 1024) -> tuple[str, int]:
    details = os.fstat(descriptor)
    if not stat.S_ISREG(details.st_mode) or not 0 <= details.st_size <= maximum:
        raise _refuse()
    digest = hashlib.sha256()
    position = 0
    while position < details.st_size:
        payload = os.pread(descriptor, min(64 * 1024, details.st_size - position), position)
        if not payload:
            raise _refuse()
        digest.update(payload)
        position += len(payload)
    after = os.fstat(descriptor)
    if (details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ):
        raise _refuse()
    return "sha256:" + digest.hexdigest(), position


def _identity(descriptor: int, *, expected_digest: str | None = None) -> dict[str, Any]:
    details = os.fstat(descriptor)
    digest, size = _file_digest(descriptor)
    if expected_digest is not None and digest != _digest(expected_digest):
        raise _refuse()
    try:
        seals: int | None = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    except OSError:
        seals = None
    return {
        "digest": digest,
        "byte_length": size,
        "mode": stat.S_IMODE(details.st_mode),
        "seals": seals,
    }


def _sealed_file(name: str, payload: bytes, *, mode: int, maximum: int) -> int:
    if type(payload) is not bytes or not 0 < len(payload) <= maximum:
        raise _refuse()
    descriptor = -1
    try:
        descriptor = os.memfd_create(
            "bluefire-strix-" + name,
            os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
        )
        os.fchmod(descriptor, mode)
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise _refuse()
            written += count
        os.lseek(descriptor, 0, os.SEEK_SET)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, _INPUT_SEALS)
        if (
            fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) != _INPUT_SEALS
            or _identity(descriptor) != {
                "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
                "byte_length": len(payload),
                "mode": mode,
                "seals": _INPUT_SEALS,
            }
        ):
            raise _refuse()
        return descriptor
    except BaseException:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        raise _refuse() from None


def _open_beneath(root_fd: int, relative: str) -> int:
    path = PurePosixPath(relative)
    if (
        not relative
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise _refuse()
    current = os.dup(root_fd)
    try:
        for part in path.parts[:-1]:
            next_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=current,
            )
            os.close(current)
            current = next_fd
        return os.open(
            path.parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=current,
        )
    except OSError:
        raise _refuse() from None
    finally:
        os.close(current)


def _native_manifest(pinned: PinnedStrixRuntimeClosure) -> bytes:
    plan = pinned.plan
    document = {
        "schema_version": _NATIVE_MANIFEST_SCHEMA,
        "inventory_digest": plan.inventory_digest,
        "directories": [item.to_dict() for item in plan.directory_inventory],
        "files": [item.to_dict() for item in plan.file_inventory],
    }
    payload = canonical_json_bytes(document)
    if not 0 < len(payload) <= 16 * 1024 * 1024:
        raise _refuse()
    return payload


class PreparedNativeLaunch:
    """Owns all transferred descriptors until the helper accepts or refuses."""

    def __init__(
        self,
        identity: dict[str, Any],
        descriptors: FixedRuntimeDescriptorSet,
        runner_fd: int,
        owned_descriptors: tuple[int, ...],
    ) -> None:
        self.identity = identity
        self.descriptors = descriptors
        self.runner_fd = runner_fd
        self._owned = owned_descriptors

    def close(self) -> None:
        owned, self._owned = self._owned, ()
        for descriptor in owned:
            with contextlib.suppress(OSError):
                os.close(descriptor)

    def __enter__(self) -> "PreparedNativeLaunch":
        return self

    def __exit__(self, *_error: object) -> None:
        self.close()


def prepare_native_launch(
    *,
    pinned: PinnedStrixRuntimeClosure,
    runner_path: Path,
    expected_runner_digest: str,
    attempt_id: str,
    resource_claim_ref: str,
    input_bindings_ref: str,
    sealed_inputs_ref: str,
    objective: bytes,
    config: bytes,
    mcp: bytes,
    launch_material: bytes,
    cancellation_fd: int,
) -> PreparedNativeLaunch:
    """Assemble exact native inputs from a verified installed closure."""
    if sys.platform != "linux" or os.geteuid() != 0:
        raise _refuse()
    if type(attempt_id) is not str or _ATTEMPT.fullmatch(attempt_id) is None:
        raise _refuse()
    for value in (
        expected_runner_digest, resource_claim_ref, input_bindings_ref, sealed_inputs_ref
    ):
        _digest(value)
    owned: list[int] = []

    def keep(fd: int) -> int:
        owned.append(fd)
        return fd

    try:
        pinned.verify()
        plan = pinned.plan
        runner_fd = keep(
            os.open(runner_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        )
        runner = os.fstat(runner_fd)
        if (
            not runner_path.is_absolute()
            or runner_path.name != "bluefire-runner"
            or not stat.S_ISREG(runner.st_mode)
            or runner.st_uid != 0
            or runner.st_nlink != 1
            or runner.st_mode & 0o022
            or not runner.st_mode & 0o111
            or _file_digest(runner_fd)[0] != expected_runner_digest
        ):
            raise _refuse()
        closure_mount = keep(os.dup(pinned.root_fd))
        closure_manifest = keep(
            _sealed_file("native-manifest", _native_manifest(pinned), mode=0o400, maximum=16 * 1024 * 1024)
        )
        files_by_path = {item.path: item for item in plan.file_inventory}
        runtime_fds: dict[str, int] = {}
        runtime_ids: dict[str, dict[str, Any]] = {}
        for name, path in _RUNTIME_FILES.items():
            descriptor = keep(
                os.dup(pinned.executable_fd)
                if name == "interpreter"
                else _open_beneath(pinned.root_fd, path)
            )
            runtime_fds[name] = descriptor
            runtime_ids[name] = _identity(
                descriptor, expected_digest=files_by_path[path].content_digest
            )
            if runtime_ids[name]["mode"] != files_by_path[path].mode:
                raise _refuse()
        objective_fd = keep(_sealed_file("objective", objective, mode=0o444, maximum=32 * 1024))
        config_fd = keep(_sealed_file("config", config, mode=0o444, maximum=4096))
        mcp_fd = keep(_sealed_file("mcp", mcp, mode=0o444, maximum=4096))
        launch_fd = keep(
            _sealed_file("launch", launch_material, mode=0o444, maximum=32 * 1024)
        )
        if type(cancellation_fd) is not int or cancellation_fd < 0:
            raise _refuse()
        os.fstat(cancellation_fd)
        cancellation = keep(os.dup(cancellation_fd))
        manifest_identity = _identity(closure_manifest)
        identity = {
            "plan_ref": plan.plan_ref,
            "closure_inventory_digest": plan.inventory_digest,
            "closure_manifest_ref": manifest_identity["digest"],
            "closure_manifest": manifest_identity,
            "seccomp_profile_digest": plan.seccomp_profile_digest,
            "guest_projection_digest": FIXED_GUEST_PROJECTION_DIGEST,
            **runtime_ids,
            "objective": _identity(objective_fd),
            "config": _identity(config_fd),
            "mcp": _identity(mcp_fd),
            "launch_material": _identity(launch_fd),
            "prelaunch_bindings": {
                "attempt_id": attempt_id,
                "resource_claim_ref": resource_claim_ref,
                "boundary_helper_digest": expected_runner_digest,
                "input_bindings_ref": input_bindings_ref,
                "sealed_inputs_ref": sealed_inputs_ref,
                "startup_overlay_ref": plan.startup_overlay_ref,
                "installed_projection_ref": FIXED_GUEST_PROJECTION_DIGEST,
                "private_device_policy_digest": PRIVATE_DEVICE_POLICY_DIGEST,
                "source_root_identity_digest": plan.root_identity_digest,
                "controller_boot_id": plan.controller_boot_id,
            },
        }
        descriptors = FixedRuntimeDescriptorSet(
            closure_mount=closure_mount,
            closure_manifest=closure_manifest,
            interpreter=runtime_fds["interpreter"],
            bootstrap=runtime_fds["bootstrap"],
            lockdown=runtime_fds["lockdown"],
            strix_entrypoint=runtime_fds["strix_entrypoint"],
            objective=objective_fd,
            config=config_fd,
            mcp=mcp_fd,
            launch_material=launch_fd,
            cancellation=cancellation,
        )
        return PreparedNativeLaunch(identity, descriptors, runner_fd, tuple(owned))
    except BaseException:
        for descriptor in owned:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        raise _refuse() from None


__all__ = [
    "PreparedNativeLaunch",
    "StrixNativeLaunchMaterialError",
    "prepare_native_launch",
]
