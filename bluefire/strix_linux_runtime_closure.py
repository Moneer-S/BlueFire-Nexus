"""Closed Linux runtime tree and fixed-exec contract for the Strix worker.

The model and experiment document never select an executable, argument,
environment variable, mount source, or import root.  A trusted preparation
step inventories a private copied CPython/Strix tree.  The controller reopens
that exact tree and executable by descriptor before a native helper may build
the private mount namespace and perform the one admitted ``execveat``.

The contract deliberately does not claim that an existing venv is hermetic.
The admitted tree must contain its interpreter, standard library, installed
wheel closure, dynamic loader/libraries and CA bundle.  Missing runtime files
fail at launch inside the private root; they never fall back to host paths.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Protocol, cast

from .util import content_hash

PLAN_SCHEMA = "bluefire.strix-linux-runtime-closure.v1"
SOURCE_REVISION = "6b7ae2ebe4d47037a927aade23265ff4e4f27e84"
PYTHON_VERSION = "3.12.14"
MACHINE = "x86_64"
FIXED_MODULE = "bluefire.strix_controlled_installed_worker"
FIXED_ARGV = (
    "/runtime/bin/python",
    "-I",
    "-S",
    "-B",
    "-X",
    "utf8",
    "/bootstrap/worker.py",
)
FIXED_ENVIRONMENT = (
    ("BLUEFIRE_STRIX_WORKER_LAUNCH_FILE", "/run/bluefire/launch.json"),
    ("LANG", "C"),
    ("LC_ALL", "C"),
    ("PATH", "/runtime/bin"),
)
FIXED_INPUT_PATHS = (
    ("config", "/inputs/config.json"),
    ("mcp", "/inputs/mcp.json"),
    ("objective", "/inputs/objective.json"),
)
FIXED_CONTROL_SOCKET = "/run/bluefire/controller.sock"
FIXED_GUEST_PROJECTION = {
    "schema_version": "bluefire.strix-fixed-guest-projection.v1",
    "cli_executable": "/runtime/bin/strix",
    "cwd": "/workspace",
    "home": "/home/worker",
    "tmpdir": "/tmp",
    "config": "/config",
    "inputs": {name: path for name, path in FIXED_INPUT_PATHS},
}
FIXED_GUEST_PROJECTION_DIGEST = content_hash(FIXED_GUEST_PROJECTION)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_MAX_FILES = 65_536
_MAX_DIRECTORIES = 16_384
_MAX_FILE_BYTES = 256 * 1024 * 1024
_MAX_CLOSURE_BYTES = 4 * 1024**3
_ALLOWED_TOP_LEVEL = {
    "config",
    "bootstrap",
    "dev",
    "etc",
    "home",
    "inputs",
    "lib",
    "lib64",
    "run",
    "runtime",
    "tmp",
    "usr",
    "workspace",
}
_REQUIRED_DIRECTORIES = {
    "bootstrap",
    "config",
    "dev",
    "etc",
    "home",
    "home/worker",
    "inputs",
    "lib",
    "lib64",
    "run",
    "run/bluefire",
    "runtime",
    "runtime/bin",
    "runtime/lib",
    "runtime/lib/python3.12",
    "runtime/lib/python3.12/encodings",
    "runtime/lib/python3.12/lib-dynload",
    "runtime/lib/python3.12/site-packages",
    "runtime/lib/python3.12/site-packages/bluefire",
    "runtime/lib/python3.12/site-packages/strix",
    "tmp",
    "workspace",
}
_REQUIRED_FILES = {
    "bootstrap/worker.py",
    "bootstrap/worker_lockdown.py",
    "lib64/ld-linux-x86-64.so.2",
    "runtime/bin/python",
    "runtime/bin/strix",
    "runtime/lib/libpython3.12.so.1.0",
    "runtime/lib/python3.12/encodings/__init__.py",
    "runtime/lib/python3.12/os.py",
    "runtime/lib/python3.12/site.py",
    "runtime/lib/python3.12/site-packages/bluefire/strix_controlled_installed_worker.py",
    "runtime/lib/python3.12/site-packages/strix/__init__.py",
}
PRIVATE_OVERMOUNTS = (
    "config",
    "dev",
    "etc",
    "home/worker",
    "inputs",
    "run/bluefire",
    "tmp",
    "workspace",
)
_DENIED_PARTS = {
    ".aws",
    ".azure",
    ".config",
    ".docker",
    ".git",
    ".gnupg",
    ".kube",
    ".ssh",
    "auth.json",
    "credentials",
    "docker.sock",
    "id_rsa",
    "id_ed25519",
    "shadow",
}
_PRIVATE_DEVICE_POLICY = (
    ("null", 1, 3, 0o666),
    ("random", 1, 8, 0o666),
    ("urandom", 1, 9, 0o666),
    ("zero", 1, 5, 0o666),
)
PRIVATE_DEVICE_POLICY_DIGEST = content_hash(
    {
        "schema_version": "bluefire.strix-private-device-policy.v1",
        "devices": [list(item) for item in _PRIVATE_DEVICE_POLICY],
        "host_device_tree_bound": False,
    }
)
_FORBIDDEN_IMPORT_HOOKS = {"sitecustomize.py", "usercustomize.py"}


class StrixLinuxRuntimeClosureError(ValueError):
    """The fixed Linux runtime tree or its execution proof is not exact."""


def _exact(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise StrixLinuxRuntimeClosureError(f"{label} fields do not match the contract")
    return value


def _text(value: Any, label: str, maximum: int = 200) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise StrixLinuxRuntimeClosureError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    result = _text(value, label, 71)
    if _DIGEST.fullmatch(result) is None:
        raise StrixLinuxRuntimeClosureError(f"{label} must be a sha256 digest")
    return result


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise StrixLinuxRuntimeClosureError(f"{label} is outside its bound")
    return value


def _boolean(value: Any, label: str, expected: bool) -> bool:
    if not isinstance(value, bool) or value is not expected:
        raise StrixLinuxRuntimeClosureError(f"{label} is invalid")
    return value


def _relative(value: Any, label: str) -> str:
    result = _text(value, label, 512)
    path = PurePosixPath(result)
    if (
        path.is_absolute()
        or result != path.as_posix()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.parts[0] not in _ALLOWED_TOP_LEVEL
        or any(part.casefold() in _DENIED_PARTS for part in path.parts)
    ):
        raise StrixLinuxRuntimeClosureError(f"{label} is unsafe")
    if path.parts[0] == "etc" and result != "etc":
        raise StrixLinuxRuntimeClosureError(
            "runtime closure must leave /etc to the private helper mount"
        )
    if PurePosixPath(result).name in _FORBIDDEN_IMPORT_HOOKS or result.endswith(".pth"):
        raise StrixLinuxRuntimeClosureError(
            "runtime closure contains an executable Python startup hook"
        )
    return result


def _file_digest(path: Path, maximum: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            total += len(chunk)
            if total > maximum:
                raise StrixLinuxRuntimeClosureError("runtime closure file exceeds its bound")
            digest.update(chunk)
    return "sha256:" + digest.hexdigest(), total


def _fd_digest(fd: int, maximum: int) -> tuple[str, int]:
    details = os.fstat(fd)
    if not stat.S_ISREG(details.st_mode) or details.st_size > maximum:
        raise StrixLinuxRuntimeClosureError("runtime descriptor is not a bounded file")
    digest = hashlib.sha256()
    total = 0
    duplicate = os.dup(fd)
    try:
        os.lseek(duplicate, 0, os.SEEK_SET)
        while total < details.st_size:
            chunk = os.read(duplicate, min(1024 * 1024, details.st_size - total))
            if not chunk:
                raise StrixLinuxRuntimeClosureError(
                    "runtime descriptor changed while hashing"
                )
            digest.update(chunk)
            total += len(chunk)
    finally:
        os.close(duplicate)
    if os.fstat(fd) != details:
        raise StrixLinuxRuntimeClosureError("runtime descriptor changed while hashing")
    return "sha256:" + digest.hexdigest(), total


@dataclass(frozen=True, slots=True)
class RuntimeDirectory:
    path: str
    mode: int

    @classmethod
    def from_mapping(cls, value: Any) -> "RuntimeDirectory":
        row = _exact(value, {"path", "mode"}, "runtime directory")
        result = cls(
            path=_relative(row["path"], "runtime directory path"),
            mode=_integer(row["mode"], "runtime directory mode", 0, 0o7777),
        )
        if result.mode != 0o555:
            raise StrixLinuxRuntimeClosureError("runtime directories must be immutable")
        return result

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "mode": self.mode}


@dataclass(frozen=True, slots=True)
class RuntimeFile:
    path: str
    mode: int
    size: int
    content_digest: str

    @classmethod
    def from_mapping(cls, value: Any) -> "RuntimeFile":
        row = _exact(value, {"path", "mode", "size", "content_digest"}, "runtime file")
        result = cls(
            path=_relative(row["path"], "runtime file path"),
            mode=_integer(row["mode"], "runtime file mode", 0, 0o7777),
            size=_integer(row["size"], "runtime file size", 0, _MAX_FILE_BYTES),
            content_digest=_digest(row["content_digest"], "runtime file content"),
        )
        if result.mode not in {0o444, 0o555}:
            raise StrixLinuxRuntimeClosureError("runtime files must be immutable")
        executable = result.mode == 0o555
        if executable and result.path not in {
            "runtime/bin/python",
            "lib64/ld-linux-x86-64.so.2",
        }:
            raise StrixLinuxRuntimeClosureError("runtime closure contains an unreviewed executable")
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "mode": self.mode,
            "size": self.size,
            "content_digest": self.content_digest,
        }


@dataclass(frozen=True, slots=True)
class StrixLinuxRuntimeClosurePlan:
    schema_version: str
    source_revision: str
    package_digest: str
    strix_record_digest: str
    worker_source_revision: str
    worker_artifact_digest: str
    worker_record_digest: str
    cpython_artifact_digest: str
    bootstrap_digest: str
    lockdown_source_digest: str
    seccomp_profile_digest: str
    runtime_qualification_ref: str
    preparation_manifest_ref: str
    wheelhouse_ref: str
    elf_dependency_manifest_ref: str
    startup_overlay_ref: str
    controller_generation: int
    closure_generation: int
    platform: str
    machine: str
    python_version: str
    root_st_dev: int
    root_st_ino: int
    source_mount_id: int
    controller_boot_id: str
    root_identity_digest: str
    interpreter_digest: str
    strix_entrypoint_digest: str
    directory_inventory: tuple[RuntimeDirectory, ...]
    file_inventory: tuple[RuntimeFile, ...]
    inventory_digest: str
    private_copy: bool
    external_symlinks_absent: bool
    hardlinks_absent: bool
    special_files_absent: bool
    host_credentials_absent: bool
    docker_sockets_absent: bool
    proc_absent_after_pivot: bool

    @classmethod
    def from_mapping(cls, value: Any) -> "StrixLinuxRuntimeClosurePlan":
        row = _exact(value, set(cls.__dataclass_fields__), "Strix Linux runtime closure")
        directories_raw = row["directory_inventory"]
        files_raw = row["file_inventory"]
        if (
            not isinstance(directories_raw, list)
            or not 1 <= len(directories_raw) <= _MAX_DIRECTORIES
            or not isinstance(files_raw, list)
            or not 1 <= len(files_raw) <= _MAX_FILES
        ):
            raise StrixLinuxRuntimeClosureError("runtime closure inventory is invalid")
        result = cls(
            schema_version=_text(row["schema_version"], "runtime closure schema"),
            source_revision=_text(row["source_revision"], "Strix source revision", 40),
            package_digest=_digest(row["package_digest"], "Strix package"),
            strix_record_digest=_digest(row["strix_record_digest"], "Strix RECORD"),
            worker_source_revision=_text(
                row["worker_source_revision"], "worker source revision", 40
            ),
            worker_artifact_digest=_digest(
                row["worker_artifact_digest"], "worker artifact"
            ),
            worker_record_digest=_digest(
                row["worker_record_digest"], "worker RECORD"
            ),
            cpython_artifact_digest=_digest(
                row["cpython_artifact_digest"], "CPython artifact"
            ),
            bootstrap_digest=_digest(row["bootstrap_digest"], "fixed bootstrap"),
            lockdown_source_digest=_digest(
                row["lockdown_source_digest"], "lockdown source"
            ),
            seccomp_profile_digest=_digest(
                row["seccomp_profile_digest"], "seccomp profile"
            ),
            runtime_qualification_ref=_digest(
                row["runtime_qualification_ref"], "runtime qualification"
            ),
            preparation_manifest_ref=_digest(
                row["preparation_manifest_ref"], "runtime preparation manifest"
            ),
            wheelhouse_ref=_digest(row["wheelhouse_ref"], "runtime wheelhouse"),
            elf_dependency_manifest_ref=_digest(
                row["elf_dependency_manifest_ref"], "ELF dependency manifest"
            ),
            startup_overlay_ref=_digest(row["startup_overlay_ref"], "startup overlay"),
            controller_generation=_integer(
                row["controller_generation"], "controller generation", 1, 2**31 - 1
            ),
            closure_generation=_integer(
                row["closure_generation"], "runtime closure generation", 1, 2**31 - 1
            ),
            platform=_text(row["platform"], "runtime platform", 16),
            machine=_text(row["machine"], "runtime machine", 16),
            python_version=_text(row["python_version"], "runtime Python version", 16),
            root_st_dev=_integer(row["root_st_dev"], "runtime root device", 0, 2**64 - 1),
            root_st_ino=_integer(row["root_st_ino"], "runtime root inode", 1, 2**64 - 1),
            source_mount_id=_integer(
                row["source_mount_id"], "runtime source mount", 1, 2**64 - 1
            ),
            controller_boot_id=_text(
                row["controller_boot_id"], "controller boot identity", 64
            ),
            root_identity_digest=_digest(row["root_identity_digest"], "runtime root identity"),
            interpreter_digest=_digest(row["interpreter_digest"], "runtime interpreter"),
            strix_entrypoint_digest=_digest(
                row["strix_entrypoint_digest"], "Strix console entrypoint"
            ),
            directory_inventory=tuple(
                RuntimeDirectory.from_mapping(item) for item in directories_raw
            ),
            file_inventory=tuple(RuntimeFile.from_mapping(item) for item in files_raw),
            inventory_digest=_digest(row["inventory_digest"], "runtime inventory"),
            private_copy=_boolean(row["private_copy"], "private runtime copy", True),
            external_symlinks_absent=_boolean(
                row["external_symlinks_absent"], "runtime symlink absence", True
            ),
            hardlinks_absent=_boolean(row["hardlinks_absent"], "runtime hardlink absence", True),
            special_files_absent=_boolean(
                row["special_files_absent"], "runtime special-file absence", True
            ),
            host_credentials_absent=_boolean(
                row["host_credentials_absent"], "host credential absence", True
            ),
            docker_sockets_absent=_boolean(
                row["docker_sockets_absent"], "daemon socket absence", True
            ),
            proc_absent_after_pivot=_boolean(
                row["proc_absent_after_pivot"], "post-pivot proc absence", True
            ),
        )
        result.validate()
        return result

    def validate(self) -> None:
        if (
            self.schema_version != PLAN_SCHEMA
            or self.source_revision != SOURCE_REVISION
            or _REVISION.fullmatch(self.source_revision) is None
            or _REVISION.fullmatch(self.worker_source_revision) is None
            or self.platform != "linux"
            or self.machine != MACHINE
            or self.python_version != PYTHON_VERSION
        ):
            raise StrixLinuxRuntimeClosureError("runtime closure identity is unsupported")
        directory_paths = tuple(item.path for item in self.directory_inventory)
        file_paths = tuple(item.path for item in self.file_inventory)
        if (
            directory_paths != tuple(sorted(set(directory_paths)))
            or file_paths != tuple(sorted(set(file_paths)))
            or set(directory_paths) & set(file_paths)
            or not _REQUIRED_DIRECTORIES.issubset(directory_paths)
            or not _REQUIRED_FILES.issubset(file_paths)
            or any(
                parent.as_posix() not in directory_paths
                for path in (*directory_paths, *file_paths)
                for parent in PurePosixPath(path).parents
                if parent.as_posix() != "."
            )
        ):
            raise StrixLinuxRuntimeClosureError("runtime closure hierarchy is incomplete")
        files_by_path = {item.path: item for item in self.file_inventory}
        record_items = {
            item.path.casefold(): item
            for item in self.file_inventory
            if item.path.casefold().endswith(".dist-info/record")
        }
        strix_records = [
            item
            for path, item in record_items.items()
            if "/strix_agent-" in path or "/strix-" in path
        ]
        worker_records = [
            item
            for path, item in record_items.items()
            if "/bluefire_strix_worker-" in path
        ]
        if (
            files_by_path["runtime/bin/python"].content_digest != self.interpreter_digest
            or files_by_path["runtime/bin/python"].mode != 0o555
            or files_by_path["runtime/bin/strix"].content_digest
            != self.strix_entrypoint_digest
            or files_by_path["runtime/bin/strix"].mode != 0o444
            or files_by_path["bootstrap/worker.py"].content_digest != self.bootstrap_digest
            or files_by_path["bootstrap/worker_lockdown.py"].content_digest
            != self.lockdown_source_digest
            or len(strix_records) != 1
            or strix_records[0].content_digest != self.strix_record_digest
            or len(worker_records) != 1
            or worker_records[0].content_digest != self.worker_record_digest
            or not any(
                item.path.startswith("runtime/lib/python3.12/lib-dynload/")
                and item.path.endswith(".so")
                for item in self.file_inventory
            )
            or any(
                not any(
                    PurePosixPath(item.path).name.startswith(stem + ".")
                    and item.path.endswith(".so")
                    for item in self.file_inventory
                )
                for stem in ("_ctypes", "_sha2")
            )
            or any(
                item.path == prefix or item.path.startswith(prefix + "/")
                for item in self.file_inventory
                for prefix in PRIVATE_OVERMOUNTS
            )
            or any(
                "/bluefire_nexus-" in item.path.casefold()
                for item in self.file_inventory
            )
        ):
            raise StrixLinuxRuntimeClosureError(
                "runtime interpreter, package, or private-mount identity is inconsistent"
            )
        total = sum(item.size for item in self.file_inventory)
        if total > _MAX_CLOSURE_BYTES:
            raise StrixLinuxRuntimeClosureError("runtime closure exceeds its aggregate bound")
        inventory = {
            "schema_version": "bluefire.strix-linux-runtime-inventory.v1",
            "directories": [item.to_dict() for item in self.directory_inventory],
            "files": [item.to_dict() for item in self.file_inventory],
            "total_bytes": total,
        }
        if self.inventory_digest != content_hash(inventory):
            raise StrixLinuxRuntimeClosureError("runtime closure inventory digest is invalid")
        expected_root = content_hash(
            {
                "schema_version": "bluefire.strix-runtime-source-root-identity.v1",
                "role": "strix-linux-runtime-closure-root",
                "st_dev": self.root_st_dev,
                "st_ino": self.root_st_ino,
                "mount_id": self.source_mount_id,
                "boot_id": self.controller_boot_id,
            }
        )
        if self.root_identity_digest != expected_root:
            raise StrixLinuxRuntimeClosureError("runtime root identity is invalid")

    @property
    def plan_ref(self) -> str:
        return cast(str, content_hash(self.to_dict()))

    @property
    def fixed_argv(self) -> tuple[str, ...]:
        return FIXED_ARGV

    @property
    def fixed_environment(self) -> tuple[tuple[str, str], ...]:
        return FIXED_ENVIRONMENT

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "source_revision": self.source_revision,
            "package_digest": self.package_digest,
            "strix_record_digest": self.strix_record_digest,
            "worker_source_revision": self.worker_source_revision,
            "worker_artifact_digest": self.worker_artifact_digest,
            "worker_record_digest": self.worker_record_digest,
            "cpython_artifact_digest": self.cpython_artifact_digest,
            "bootstrap_digest": self.bootstrap_digest,
            "lockdown_source_digest": self.lockdown_source_digest,
            "seccomp_profile_digest": self.seccomp_profile_digest,
            "runtime_qualification_ref": self.runtime_qualification_ref,
            "preparation_manifest_ref": self.preparation_manifest_ref,
            "wheelhouse_ref": self.wheelhouse_ref,
            "elf_dependency_manifest_ref": self.elf_dependency_manifest_ref,
            "startup_overlay_ref": self.startup_overlay_ref,
            "controller_generation": self.controller_generation,
            "closure_generation": self.closure_generation,
            "platform": self.platform,
            "machine": self.machine,
            "python_version": self.python_version,
            "root_st_dev": self.root_st_dev,
            "root_st_ino": self.root_st_ino,
            "source_mount_id": self.source_mount_id,
            "controller_boot_id": self.controller_boot_id,
            "root_identity_digest": self.root_identity_digest,
            "interpreter_digest": self.interpreter_digest,
            "strix_entrypoint_digest": self.strix_entrypoint_digest,
            "directory_inventory": [item.to_dict() for item in self.directory_inventory],
            "file_inventory": [item.to_dict() for item in self.file_inventory],
            "inventory_digest": self.inventory_digest,
            "private_copy": self.private_copy,
            "external_symlinks_absent": self.external_symlinks_absent,
            "hardlinks_absent": self.hardlinks_absent,
            "special_files_absent": self.special_files_absent,
            "host_credentials_absent": self.host_credentials_absent,
            "docker_sockets_absent": self.docker_sockets_absent,
            "proc_absent_after_pivot": self.proc_absent_after_pivot,
        }

    def bind_worker_plan(self, worker_plan: "_WorkerPlan") -> None:
        if (
            worker_plan.runtime_qualification_ref != self.runtime_qualification_ref
            or worker_plan.package_digest != self.package_digest
            or worker_plan.executable_digest != self.interpreter_digest
            or worker_plan.controller_generation != self.controller_generation
        ):
            raise StrixLinuxRuntimeClosureError(
                "worker containment plan does not bind the runtime closure"
            )


class _WorkerPlan(Protocol):
    runtime_qualification_ref: str
    package_digest: str
    executable_digest: str
    controller_generation: int


def _inventory_document(
    directories: tuple[RuntimeDirectory, ...], files: tuple[RuntimeFile, ...]
) -> dict[str, Any]:
    return {
        "schema_version": "bluefire.strix-linux-runtime-inventory.v1",
        "directories": [item.to_dict() for item in directories],
        "files": [item.to_dict() for item in files],
        "total_bytes": sum(item.size for item in files),
    }


def inventory_private_runtime_closure(
    root: Path,
    *,
    package_digest: str,
    strix_record_digest: str,
    worker_source_revision: str,
    worker_artifact_digest: str,
    worker_record_digest: str,
    cpython_artifact_digest: str,
    seccomp_profile_digest: str,
    runtime_qualification_ref: str,
    preparation_manifest_ref: str,
    wheelhouse_ref: str,
    elf_dependency_manifest_ref: str,
    startup_overlay_ref: str,
    source_mount_id: int,
    controller_boot_id: str,
    controller_generation: int,
    closure_generation: int,
) -> StrixLinuxRuntimeClosurePlan:
    """Inventory a new private copied root; this does not copy or install it."""

    resolved = root.resolve(strict=True)
    details = resolved.lstat()
    if (
        resolved.name != "strix-linux-runtime-root"
        or not stat.S_ISDIR(details.st_mode)
        or details.st_uid not in {0, getattr(os, "getuid", lambda: -1)()}
        or stat.S_IMODE(details.st_mode) & 0o022
    ):
        raise StrixLinuxRuntimeClosureError("runtime closure root is not protected")
    directories: list[RuntimeDirectory] = []
    files: list[RuntimeFile] = []
    total = 0
    for current, child_directories, child_files in os.walk(resolved, followlinks=False):
        parent = Path(current)
        for name in sorted(child_directories):
            path = parent / name
            metadata = path.lstat()
            relative = path.relative_to(resolved).as_posix()
            if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                raise StrixLinuxRuntimeClosureError("runtime closure contains a link or special directory")
            directories.append(
                RuntimeDirectory.from_mapping(
                    {"path": relative, "mode": stat.S_IMODE(metadata.st_mode)}
                )
            )
        for name in sorted(child_files):
            path = parent / name
            metadata = path.lstat()
            relative = path.relative_to(resolved).as_posix()
            if (
                path.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
            ):
                raise StrixLinuxRuntimeClosureError("runtime closure contains a link or special file")
            digest, size = _file_digest(path, _MAX_FILE_BYTES)
            if size != metadata.st_size:
                raise StrixLinuxRuntimeClosureError("runtime closure file changed during inventory")
            total += size
            if total > _MAX_CLOSURE_BYTES:
                raise StrixLinuxRuntimeClosureError("runtime closure exceeds its aggregate bound")
            files.append(
                RuntimeFile.from_mapping(
                    {
                        "path": relative,
                        "mode": stat.S_IMODE(metadata.st_mode),
                        "size": size,
                        "content_digest": digest,
                    }
                )
            )
    directories_tuple = tuple(sorted(directories, key=lambda item: item.path))
    files_tuple = tuple(sorted(files, key=lambda item: item.path))
    if len(directories_tuple) > _MAX_DIRECTORIES or len(files_tuple) > _MAX_FILES:
        raise StrixLinuxRuntimeClosureError("runtime closure member count exceeds its bound")
    root_identity = content_hash(
        {
            "schema_version": "bluefire.strix-runtime-source-root-identity.v1",
            "role": "strix-linux-runtime-closure-root",
            "st_dev": details.st_dev,
            "st_ino": details.st_ino,
            "mount_id": _integer(source_mount_id, "runtime source mount", 1, 2**64 - 1),
            "boot_id": _text(controller_boot_id, "controller boot identity", 64),
        }
    )
    interpreter = next(
        (item for item in files_tuple if item.path == "runtime/bin/python"), None
    )
    strix_entrypoint = next(
        (item for item in files_tuple if item.path == "runtime/bin/strix"), None
    )
    bootstrap = next((item for item in files_tuple if item.path == "bootstrap/worker.py"), None)
    lockdown = next(
        (
            item
            for item in files_tuple
            if item.path == "bootstrap/worker_lockdown.py"
        ),
        None,
    )
    if (
        interpreter is None
        or strix_entrypoint is None
        or bootstrap is None
        or lockdown is None
    ):
        raise StrixLinuxRuntimeClosureError("fixed runtime entrypoint is missing")
    return StrixLinuxRuntimeClosurePlan.from_mapping(
        {
            "schema_version": PLAN_SCHEMA,
            "source_revision": SOURCE_REVISION,
            "package_digest": _digest(package_digest, "Strix package"),
            "strix_record_digest": _digest(strix_record_digest, "Strix RECORD"),
            "worker_source_revision": _text(
                worker_source_revision, "worker source revision", 40
            ),
            "worker_artifact_digest": _digest(
                worker_artifact_digest, "worker artifact"
            ),
            "worker_record_digest": _digest(
                worker_record_digest, "worker RECORD"
            ),
            "cpython_artifact_digest": _digest(
                cpython_artifact_digest, "CPython artifact"
            ),
            "bootstrap_digest": bootstrap.content_digest,
            "lockdown_source_digest": lockdown.content_digest,
            "seccomp_profile_digest": _digest(
                seccomp_profile_digest, "seccomp profile"
            ),
            "runtime_qualification_ref": _digest(
                runtime_qualification_ref, "runtime qualification"
            ),
            "preparation_manifest_ref": _digest(
                preparation_manifest_ref, "runtime preparation manifest"
            ),
            "wheelhouse_ref": _digest(wheelhouse_ref, "runtime wheelhouse"),
            "elf_dependency_manifest_ref": _digest(
                elf_dependency_manifest_ref, "ELF dependency manifest"
            ),
            "startup_overlay_ref": _digest(startup_overlay_ref, "startup overlay"),
            "controller_generation": controller_generation,
            "closure_generation": closure_generation,
            "platform": "linux",
            "machine": MACHINE,
            "python_version": PYTHON_VERSION,
            "root_st_dev": details.st_dev,
            "root_st_ino": details.st_ino,
            "source_mount_id": source_mount_id,
            "controller_boot_id": controller_boot_id,
            "root_identity_digest": root_identity,
            "interpreter_digest": interpreter.content_digest,
            "strix_entrypoint_digest": strix_entrypoint.content_digest,
            "directory_inventory": [item.to_dict() for item in directories_tuple],
            "file_inventory": [item.to_dict() for item in files_tuple],
            "inventory_digest": content_hash(
                _inventory_document(directories_tuple, files_tuple)
            ),
            "private_copy": True,
            "external_symlinks_absent": True,
            "hardlinks_absent": True,
            "special_files_absent": True,
            "host_credentials_absent": True,
            "docker_sockets_absent": True,
            "proc_absent_after_pivot": True,
        }
    )


class PinnedStrixRuntimeClosure:
    """Controller-owned root/executable descriptors for one exact launch."""

    def __init__(self, plan: StrixLinuxRuntimeClosurePlan, root_fd: int, executable_fd: int) -> None:
        self.plan = plan
        self._root_fd = root_fd
        self._executable_fd = executable_fd
        self._closed = False

    @property
    def root_fd(self) -> int:
        if self._closed:
            raise StrixLinuxRuntimeClosureError("runtime closure is closed")
        return self._root_fd

    @property
    def executable_fd(self) -> int:
        if self._closed:
            raise StrixLinuxRuntimeClosureError("runtime closure is closed")
        return self._executable_fd

    def duplicate_for_helper(self) -> tuple[int, int]:
        if self._closed:
            raise StrixLinuxRuntimeClosureError("runtime closure is closed")
        return os.dup(self._root_fd), os.dup(self._executable_fd)

    def verify(self) -> None:
        if self._closed:
            raise StrixLinuxRuntimeClosureError("runtime closure is closed")
        root = os.fstat(self._root_fd)
        executable = os.fstat(self._executable_fd)
        digest, size = _fd_digest(self._executable_fd, _MAX_FILE_BYTES)
        expected = next(
            item for item in self.plan.file_inventory if item.path == "runtime/bin/python"
        )
        if (
            (root.st_dev, root.st_ino) != (self.plan.root_st_dev, self.plan.root_st_ino)
            or not stat.S_ISDIR(root.st_mode)
            or not stat.S_ISREG(executable.st_mode)
            or executable.st_nlink != 1
            or stat.S_IMODE(executable.st_mode) != expected.mode
            or size != expected.size
            or digest != self.plan.interpreter_digest
        ):
            raise StrixLinuxRuntimeClosureError("pinned runtime closure identity changed")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        os.close(self._executable_fd)
        os.close(self._root_fd)


def pin_runtime_closure(
    root: Path, plan: StrixLinuxRuntimeClosurePlan
) -> PinnedStrixRuntimeClosure:
    """Re-inventory and pin the exact private tree immediately before launch."""

    if sys.platform != "linux":
        raise StrixLinuxRuntimeClosureError("fixed Strix exec requires Linux")
    plan = StrixLinuxRuntimeClosurePlan.from_mapping(plan.to_dict())
    refreshed = inventory_private_runtime_closure(
        root,
        package_digest=plan.package_digest,
        strix_record_digest=plan.strix_record_digest,
        worker_source_revision=plan.worker_source_revision,
        worker_artifact_digest=plan.worker_artifact_digest,
        worker_record_digest=plan.worker_record_digest,
        cpython_artifact_digest=plan.cpython_artifact_digest,
        seccomp_profile_digest=plan.seccomp_profile_digest,
        runtime_qualification_ref=plan.runtime_qualification_ref,
        preparation_manifest_ref=plan.preparation_manifest_ref,
        wheelhouse_ref=plan.wheelhouse_ref,
        elf_dependency_manifest_ref=plan.elf_dependency_manifest_ref,
        startup_overlay_ref=plan.startup_overlay_ref,
        source_mount_id=plan.source_mount_id,
        controller_boot_id=plan.controller_boot_id,
        controller_generation=plan.controller_generation,
        closure_generation=plan.closure_generation,
    )
    if refreshed.to_dict() != plan.to_dict():
        raise StrixLinuxRuntimeClosureError("runtime closure changed before launch")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    directory_flags = flags | os.O_DIRECTORY
    root_fd = os.open(root, directory_flags)
    executable_fd = -1
    runtime_fd = -1
    bin_fd = -1
    try:
        root_details = os.fstat(root_fd)
        if (root_details.st_dev, root_details.st_ino) != (
            plan.root_st_dev,
            plan.root_st_ino,
        ):
            raise StrixLinuxRuntimeClosureError("runtime root descriptor changed")
        runtime_fd = os.open("runtime", directory_flags, dir_fd=root_fd)
        bin_fd = os.open("bin", directory_flags, dir_fd=runtime_fd)
        executable_fd = os.open("python", flags, dir_fd=bin_fd)
        executable_details = os.fstat(executable_fd)
        expected = next(
            item for item in plan.file_inventory if item.path == "runtime/bin/python"
        )
        digest, size = _fd_digest(executable_fd, _MAX_FILE_BYTES)
        if (
            not stat.S_ISREG(executable_details.st_mode)
            or executable_details.st_nlink != 1
            or stat.S_IMODE(executable_details.st_mode) != expected.mode
            or size != expected.size
            or digest != plan.interpreter_digest
        ):
            raise StrixLinuxRuntimeClosureError("runtime interpreter descriptor changed")
        result = PinnedStrixRuntimeClosure(plan, root_fd, executable_fd)
        os.close(bin_fd)
        os.close(runtime_fd)
        return result
    except BaseException:
        if executable_fd >= 0:
            os.close(executable_fd)
        if bin_fd >= 0:
            os.close(bin_fd)
        if runtime_fd >= 0:
            os.close(runtime_fd)
        os.close(root_fd)
        raise


__all__ = [
    "FIXED_ARGV",
    "FIXED_CONTROL_SOCKET",
    "FIXED_ENVIRONMENT",
    "FIXED_GUEST_PROJECTION",
    "FIXED_GUEST_PROJECTION_DIGEST",
    "FIXED_INPUT_PATHS",
    "PRIVATE_DEVICE_POLICY_DIGEST",
    "PRIVATE_OVERMOUNTS",
    "PinnedStrixRuntimeClosure",
    "RuntimeDirectory",
    "RuntimeFile",
    "StrixLinuxRuntimeClosureError",
    "StrixLinuxRuntimeClosurePlan",
    "inventory_private_runtime_closure",
    "pin_runtime_closure",
]
