"""Offline qualification of the fixed tenant target sidecar image.

This is a package and image admission step, not an experiment authorization.
The image is built from an expected installed BlueFire wheel and an already
present, exact Linux Python base. Build commands have no registry pull or
RUN-stage network access. The resulting receipt is kept in a private source
that the Docker sidecar owner reopens before creating a target container.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess  # nosec B404 - fixed Docker command vectors and no shell
import time
import uuid
import zipfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from .util import canonical_json_bytes, content_hash

RECEIPT_SCHEMA = "bluefire.tenant-target-image-qualification.v1"
SOURCE_SCHEMA = "bluefire.tenant-target-image-qualification-source.v1"
INTENT_SCHEMA = "bluefire.tenant-target-image-build-intent.v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_WHEEL = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,180}\.whl\Z")
_MAX_WHEEL = 128 * 1024 * 1024
_MAX_OUTPUT = 2 * 1024 * 1024
_MAX_SOURCE = 16 * 1024
_MAX_COMMAND_SECONDS = 600
_ENTRYPOINT = ["python3", "-I", "-B", "-m", "bluefire.tenant_record_target_sidecar"]
_BASE_REFERENCE = re.compile(r"[a-z0-9.-]+(?:\:[0-9]+)?(?:/[a-z0-9._-]+)+(?::[a-z0-9._-]+)?@sha256:[0-9a-f]{64}\Z")
PINNED_PYTHON_BASE = (
    "docker.io/library/python@sha256:"
    "1aaa65a85fda306ffb8b910824d4e93bdce61e212c7e87168123ea3073b41a1a"
)


class TenantSidecarImageError(RuntimeError):
    """A fixed offline image input or qualification receipt is unavailable."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


CommandRunner = Callable[[Sequence[str], Mapping[str, str], Path, int], CommandResult]


class TargetSidecarBuildInputSource(Protocol):
    """Protected installed-package and preloaded-base admission source."""

    def reopen_inputs(self, input_ref: str) -> Mapping[str, Any]: ...


class FileTargetSidecarBuildInputSource:
    """Read exact controller-retained wheel/base inputs by content reference."""

    def __init__(self, root: Path) -> None:
        self.root = _private_root(Path(root))
        info = self.root.stat()
        self._root_identity = (info.st_dev, info.st_ino)

    def reopen_inputs(self, input_ref: str) -> Mapping[str, Any]:
        _digest(input_ref, "target image build input reference")
        info = _private_root(self.root).stat()
        if (info.st_dev, info.st_ino) != self._root_identity:
            raise TenantSidecarImageError("target image build input root changed")
        value = _read_exact(self.root, f"build-input-{input_ref[7:]}.json")
        if value.get("input_ref") != input_ref:
            raise TenantSidecarImageError("target image build input identity changed")
        return _build_inputs(_InMemoryBuildInputSource(value), input_ref)


class FileTargetSidecarBaseAdmissionSource:
    """Read the exact preloaded, pinned Python base identity by reference."""

    def __init__(self, root: Path) -> None:
        self.root = _private_root(Path(root))
        info = self.root.stat()
        self._root_identity = (info.st_dev, info.st_ino)

    def reopen_base(self, base_ref: str) -> Mapping[str, Any]:
        _digest(base_ref, "pinned Python base reference")
        info = _private_root(self.root).stat()
        if (info.st_dev, info.st_ino) != self._root_identity:
            raise TenantSidecarImageError("pinned Python base source root changed")
        value = _read_exact(self.root, f"base-{base_ref[7:]}.json")
        if (
            set(value)
            != {"schema_version", "base_reference", "base_image_id", "base_config_ref", "base_ref"}
            or value.get("schema_version") != "bluefire.tenant-target-base-admission.v1"
            or value.get("base_reference") != PINNED_PYTHON_BASE
            or value.get("base_ref") != base_ref
            or base_ref != content_hash({k: v for k, v in value.items() if k != "base_ref"})
        ):
            raise TenantSidecarImageError("pinned Python base admission changed")
        _digest(value["base_image_id"], "pinned Python base image ID")
        _digest(value["base_config_ref"], "pinned Python base Config")
        return value


class _InMemoryBuildInputSource:
    def __init__(self, value: Mapping[str, Any]) -> None:
        self.value = value

    def reopen_inputs(self, _input_ref: str) -> Mapping[str, Any]:
        return self.value


def _build_inputs(source: TargetSidecarBuildInputSource, input_ref: str) -> dict[str, str]:
    _digest(input_ref, "target image build input reference")
    try:
        row = source.reopen_inputs(input_ref)
    except Exception as exc:
        raise TenantSidecarImageError("protected target image inputs are unavailable") from exc
    fields = {
        "schema_version", "wheel_path", "wheel_sha256", "installed_payload_digest",
        "source_revision", "base_reference", "base_image_id", "base_config_ref", "input_ref",
    }
    if not isinstance(row, Mapping) or set(row) != fields or row.get("schema_version") != "bluefire.tenant-target-image-build-input.v1":
        raise TenantSidecarImageError("protected target image input shape changed")
    checked = dict(row)
    if checked["input_ref"] != input_ref or input_ref != content_hash({k: v for k, v in checked.items() if k != "input_ref"}):
        raise TenantSidecarImageError("protected target image input digest changed")
    for field_name in ("wheel_sha256", "installed_payload_digest", "base_image_id", "base_config_ref"):
        _digest(checked[field_name], field_name)
    if (
        not isinstance(checked["wheel_path"], str)
        or not Path(checked["wheel_path"]).is_absolute()
        or not isinstance(checked["base_reference"], str)
        or checked["base_reference"] != PINNED_PYTHON_BASE
        or _BASE_REFERENCE.fullmatch(checked["base_reference"]) is None
        or not isinstance(checked["source_revision"], str)
        or re.fullmatch(r"[0-9a-f]{40,64}", checked["source_revision"]) is None
    ):
        raise TenantSidecarImageError("protected target image source identity is invalid")
    return checked


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise TenantSidecarImageError(f"{label} is invalid")
    return value


def _hash_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _run(argv: Sequence[str], environment: Mapping[str, str], cwd: Path, timeout: int) -> CommandResult:
    try:
        process = subprocess.Popen(  # nosec B603 - fixed argv, no shell
            list(argv),
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        raise TenantSidecarImageError("fixed Docker command is unavailable") from exc
    if process.stdout is None or process.stderr is None:
        raise TenantSidecarImageError("Docker command streams are unavailable")
    output = {process.stdout: bytearray(), process.stderr: bytearray()}
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    selector.register(process.stderr, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TenantSidecarImageError("fixed Docker command timed out")
            for key, _mask in selector.select(min(remaining, 1.0)):
                chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffer = output[key.fileobj]
                if len(buffer) + len(chunk) > _MAX_OUTPUT:
                    raise TenantSidecarImageError("Docker command output exceeded its bound")
                buffer.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TenantSidecarImageError("fixed Docker command timed out")
        code = process.wait(timeout=remaining)
        return CommandResult(code, bytes(output[process.stdout]), bytes(output[process.stderr]))
    except (OSError, subprocess.SubprocessError, TenantSidecarImageError) as exc:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.SubprocessError:
            pass
        if isinstance(exc, TenantSidecarImageError):
            raise
        raise TenantSidecarImageError("fixed Docker command failed") from exc
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()


def _fixed_docker_executable() -> str:
    path = Path("/usr/bin/docker")
    try:
        info = path.lstat()
    except OSError as exc:
        raise TenantSidecarImageError("fixed Docker executable is unavailable") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o022
        or not stat.S_IMODE(info.st_mode) & 0o111
    ):
        raise TenantSidecarImageError("fixed Docker executable is not protected")
    return str(path)


def _private_root(root: Path) -> Path:
    if os.name != "posix" or not root.is_absolute():
        raise TenantSidecarImageError("image qualification requires an absolute Linux source")
    current = root
    while True:
        info = current.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if not stat.S_ISDIR(info.st_mode) or current.is_symlink():
            raise TenantSidecarImageError("image qualification ancestor is unsafe")
        if current == root:
            if info.st_uid != os.geteuid() or mode != 0o700:
                raise TenantSidecarImageError("image qualification source is not owner private")
        elif info.st_uid not in {0, os.geteuid()}:
            raise TenantSidecarImageError("image qualification ancestor has another owner")
        elif mode & 0o022 and not (
            current == Path("/tmp") and info.st_uid == 0 and mode & stat.S_ISVTX
        ):
            raise TenantSidecarImageError("image qualification ancestor is writable")
        if current.parent == current:
            break
        current = current.parent
    return root.resolve(strict=True)


def _write_once(root: Path, name: str, value: Mapping[str, Any]) -> None:
    raw = canonical_json_bytes(dict(value))
    if len(raw) > _MAX_SOURCE:
        raise TenantSidecarImageError("image qualification source is excessive")
    directory = os.open(_private_root(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    pending = f".pending-{uuid.uuid4().hex}"
    try:
        descriptor = os.open(
            pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
            dir_fd=directory,
        )
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.link(pending, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        os.unlink(pending, dir_fd=directory)
        os.fsync(directory)
    except Exception:
        try:
            os.unlink(pending, dir_fd=directory)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(directory)


def _read_exact(root: Path, name: str) -> dict[str, Any]:
    directory = os.open(_private_root(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 1 <= before.st_size <= _MAX_SOURCE
        ):
            raise TenantSidecarImageError("image qualification source file is unsafe")
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
            ):
                raise TenantSidecarImageError("image qualification source changed")
            raw = os.read(descriptor, _MAX_SOURCE + 1)
        finally:
            os.close(descriptor)
        after = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
        ):
            raise TenantSidecarImageError("image qualification source changed")
    finally:
        os.close(directory)
    if len(raw) != before.st_size:
        raise TenantSidecarImageError("image qualification source is incomplete")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise TenantSidecarImageError("image qualification source is not JSON") from exc
    if type(value) is not dict or canonical_json_bytes(value) != raw:
        raise TenantSidecarImageError("image qualification source is not canonical")
    return value


class FileTenantSidecarImageQualificationSource:
    """Protected receipt reader used by the installed sidecar owner."""

    def __init__(self, root: Path) -> None:
        self.root = _private_root(Path(root))
        identity = self.root.stat()
        self._root_identity = (identity.st_dev, identity.st_ino)

    def _check_root(self) -> None:
        info = _private_root(self.root).stat()
        if (info.st_dev, info.st_ino) != self._root_identity:
            raise TenantSidecarImageError("image qualification source root changed")

    def reopen_qualification(self, receipt_ref: str) -> Mapping[str, Any]:
        _digest(receipt_ref, "image qualification reference")
        self._check_root()
        source = _read_exact(self.root, f"qualification-{receipt_ref[7:]}.json")
        if set(source) != {
            "schema_version", "receipt", "wheel_digest", "base_image_id", "base_config_ref",
            "dockerfile_digest", "build_command_ref", "image_inspect_ref", "input_ref",
            "build_id", "image_tag", "source_ref",
        } or source["schema_version"] != SOURCE_SCHEMA:
            raise TenantSidecarImageError("image qualification source shape changed")
        source_ref = source.pop("source_ref")
        if source_ref != content_hash(source):
            raise TenantSidecarImageError("image qualification source digest changed")
        build_id = source["build_id"]
        if (
            not isinstance(build_id, str)
            or re.fullmatch(r"[0-9a-f]{32}", build_id) is None
            or source["image_tag"]
            != f"localhost/bluefire/tenant-target-{build_id}:qualified"
        ):
            raise TenantSidecarImageError("image qualification build identity changed")
        pointer = _read_exact(self.root, f"qualified-{build_id}.json")
        if (
            set(pointer)
            != {"schema_version", "build_id", "receipt_ref", "source_ref", "intent_ref", "pointer_ref"}
            or pointer.get("schema_version") != "bluefire.tenant-target-image-qualified-pointer.v1"
            or pointer.get("build_id") != build_id
            or pointer.get("receipt_ref") != receipt_ref
            or pointer.get("source_ref") != source_ref
            or pointer.get("pointer_ref")
            != content_hash({k: v for k, v in pointer.items() if k != "pointer_ref"})
        ):
            raise TenantSidecarImageError("image qualification pointer is unavailable")
        _digest(pointer["intent_ref"], "image build intent")
        receipt = source["receipt"]
        if not isinstance(receipt, dict) or set(receipt) != {
            "schema_version", "image_id", "image_config_ref", "source_artifact_digest",
            "build_recipe_digest", "base_image_digest", "offline_no_pull_verified",
            "receipt_ref",
        } or receipt.get("schema_version") != RECEIPT_SCHEMA:
            raise TenantSidecarImageError("image qualification receipt shape changed")
        if (
            receipt["receipt_ref"] != receipt_ref
            or receipt_ref != content_hash({k: v for k, v in receipt.items() if k != "receipt_ref"})
            or receipt["source_artifact_digest"] != source["wheel_digest"]
            or receipt["base_image_digest"] != source["base_image_id"]
            or receipt["offline_no_pull_verified"] is not True
        ):
            raise TenantSidecarImageError("image qualification receipt binding changed")
        for key in (
            "wheel_digest", "base_image_id", "base_config_ref", "dockerfile_digest",
            "build_command_ref", "image_inspect_ref", "input_ref",
        ):
            _digest(source[key], key)
        return dict(receipt)


def _copy_expected_wheel(source: Path, target: Path, expected_digest: str) -> None:
    if not source.is_absolute() or _WHEEL.fullmatch(source.name) is None:
        raise TenantSidecarImageError("installed wheel path is invalid")
    before = source.lstat()
    if not stat.S_ISREG(before.st_mode) or source.is_symlink() or not 1 <= before.st_size <= _MAX_WHEEL:
        raise TenantSidecarImageError("installed wheel is unavailable")
    digest = hashlib.sha256()
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
        ):
            raise TenantSidecarImageError("installed wheel changed before copy")
        with os.fdopen(descriptor, "rb", closefd=False) as reader, target.open("xb") as output:
            for block in iter(lambda: reader.read(1024 * 1024), b""):
                digest.update(block)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)
    after = source.lstat()
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
    ) or "sha256:" + digest.hexdigest() != expected_digest:
        raise TenantSidecarImageError("installed wheel digest changed")
    try:
        with zipfile.ZipFile(target) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(infos) > 10_000 or len(names) != len(set(names)):
                raise TenantSidecarImageError("installed wheel archive is excessive or ambiguous")
            total = 0
            for info in infos:
                name = info.filename
                stripped = name[:-1] if info.is_dir() else name
                path = PurePosixPath(stripped)
                kind = (info.external_attr >> 16) & 0o170000
                if (
                    not name.isascii()
                    or re.fullmatch(r"[A-Za-z0-9_./-]+", name) is None
                    or name.startswith("/")
                    or "//" in name
                    or "\\" in name
                    or not stripped
                    or path.as_posix() != stripped
                    or any(part in {"", ".", ".."} for part in path.parts)
                    or kind not in {0, stat.S_IFDIR if info.is_dir() else stat.S_IFREG}
                    or info.file_size > 64 * 1024 * 1024
                ):
                    raise TenantSidecarImageError("installed wheel has an unsafe member")
                total += info.file_size
                if total > 256 * 1024 * 1024:
                    raise TenantSidecarImageError("installed wheel expands beyond its bound")
            required = {
                "bluefire/tenant_record_target_sidecar.py",
                "bluefire/tenant_record_target_child.py",
                "bluefire/tenant_record_service.py",
            }
            metadata = [
                name for name in names
                if re.fullmatch(r"bluefire_nexus-[A-Za-z0-9_.-]+\.dist-info/METADATA", name)
            ]
            records = [
                name for name in names
                if re.fullmatch(r"bluefire_nexus-[A-Za-z0-9_.-]+\.dist-info/RECORD", name)
            ]
            if (
                not required.issubset(names)
                or len(metadata) != 1
                or len(records) != 1
                or metadata[0].rsplit("/", 1)[0] != records[0].rsplit("/", 1)[0]
                or b"Name: bluefire-nexus\n" not in archive.read(metadata[0])
                or archive.testzip() is not None
            ):
                raise TenantSidecarImageError("installed wheel lacks the fixed target package")
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise TenantSidecarImageError("installed wheel archive is invalid") from exc


def _dockerfile(base_reference: str, wheel_name: str, wheel_digest: str, build_id: str) -> bytes:
    return (
        f"FROM {base_reference}\n"
        f"LABEL bluefire.target.source-artifact=\"{wheel_digest}\"\n"
        f"LABEL bluefire.target.image-build=\"{build_id}\"\n"
        f"COPY {wheel_name} /tmp/{wheel_name}\n"
        f"RUN python3 -m pip install --no-index --no-deps --no-cache-dir /tmp/{wheel_name} "
        f"&& rm -f /tmp/{wheel_name} "
        "&& python3 -I -B -c 'import bluefire.tenant_record_target_sidecar'\n"
        "USER 1000:1000\n"
        "ENTRYPOINT []\n"
        'CMD ["python3","-I","-B","-m","bluefire.tenant_record_target_sidecar"]\n'
    ).encode("ascii")


def _inspect(runner: CommandRunner, docker: str, host: str, image: str, env: Mapping[str, str], cwd: Path) -> dict[str, Any]:
    result = runner((docker, "--host", host, "image", "inspect", image), env, cwd, 30)
    if result.returncode != 0 or len(result.stdout) > _MAX_OUTPUT or len(result.stderr) > _MAX_OUTPUT:
        raise TenantSidecarImageError("exact local Docker image inspect failed")
    try:
        value = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise TenantSidecarImageError("Docker image inspect is invalid") from exc
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise TenantSidecarImageError("Docker image inspect shape changed")
    return value[0]


def _docker_environment(private: Path) -> dict[str, str]:
    config_dir = private / "docker-config"
    config_dir.mkdir(mode=0o700, exist_ok=True)
    config_info = config_dir.lstat()
    if (
        not stat.S_ISDIR(config_info.st_mode)
        or config_dir.is_symlink()
        or config_info.st_uid != os.geteuid()
        or stat.S_IMODE(config_info.st_mode) != 0o700
    ):
        raise TenantSidecarImageError("Docker configuration directory is unsafe")
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "HOME": str(private),
        "DOCKER_CONFIG": str(config_dir),
        "DOCKER_BUILDKIT": "0",
    }


def _tagged_image_id(
    *, docker: str, host: str, tag: str, env: Mapping[str, str], root: Path
) -> str | None:
    result = _run(
        (docker, "--host", host, "image", "ls", "--quiet", "--no-trunc", "--filter", f"reference={tag}"),
        env, root, 30,
    )
    if result.returncode != 0 or len(result.stdout) > 256 or len(result.stderr) > _MAX_OUTPUT:
        raise TenantSidecarImageError("owned target image inventory is unavailable")
    lines = result.stdout.decode("ascii", "strict").splitlines()
    if not lines:
        return None
    if len(lines) != 1:
        raise TenantSidecarImageError("owned target image tag is ambiguous")
    return _digest(lines[0], "owned target image ID")


def _remove_owned_context(private: Path, build_id: str) -> None:
    context = private / f"context-{build_id}"
    if not (context.exists() or context.is_symlink()):
        return
    info = context.lstat()
    if (
        context.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
        or context.parent != private
    ):
        raise TenantSidecarImageError("target image context cannot be cleaned safely")
    shutil.rmtree(context)


def cleanup_target_sidecar_images(
    *, root: Path, docker_host: str = "unix:///var/run/docker.sock"
) -> tuple[Mapping[str, Any], ...]:
    """No-launch reconciliation of only this source's retained image tags.

    A sidecar still using an image makes Docker removal fail, leaving cleanup
    unknown. The caller must settle the sidecar container first.
    """

    private = _private_root(Path(root))
    if docker_host != "unix:///var/run/docker.sock":
        raise TenantSidecarImageError("Docker endpoint differs from local owner")
    docker = _fixed_docker_executable()
    env = _docker_environment(private)
    intents = sorted(private.glob("intent-*.json"))
    if len(intents) > 32:
        raise TenantSidecarImageError("target image build inventory exceeds its bound")
    terminal: list[Mapping[str, Any]] = []
    for path in intents:
        if re.fullmatch(r"intent-[0-9a-f]{32}\.json", path.name) is None:
            raise TenantSidecarImageError("target image intent name is invalid")
        intent = _read_exact(private, path.name)
        if set(intent) != {
            "schema_version", "build_id", "image_tag", "base_image_id", "input_ref",
            "wheel_digest", "build_recipe_digest", "intent_ref",
        } or intent.get("schema_version") != INTENT_SCHEMA:
            raise TenantSidecarImageError("target image build intent changed")
        build_id = intent["build_id"]
        tag = intent["image_tag"]
        if (
            not isinstance(build_id, str)
            or path.name != f"intent-{build_id}.json"
            or tag != f"localhost/bluefire/tenant-target-{build_id}:qualified"
            or intent["intent_ref"]
            != content_hash({k: v for k, v in intent.items() if k != "intent_ref"})
        ):
            raise TenantSidecarImageError("target image build intent identity changed")
        for name in ("base_image_id", "input_ref", "wheel_digest", "build_recipe_digest"):
            _digest(intent[name], name)
        pointer_path = private / f"qualified-{build_id}.json"
        qualified_ref: str | None = None
        if pointer_path.exists() or pointer_path.is_symlink():
            pointer = _read_exact(private, pointer_path.name)
            qualified_ref = _digest(pointer.get("receipt_ref"), "qualified target image")
            FileTenantSidecarImageQualificationSource(private).reopen_qualification(qualified_ref)
            if pointer.get("intent_ref") != intent["intent_ref"]:
                raise TenantSidecarImageError("qualified target image intent changed")
        cleanup_name = f"cleanup-{build_id}.json"
        cleanup_path = private / cleanup_name
        if cleanup_path.exists() or cleanup_path.is_symlink():
            saved = _read_exact(private, cleanup_name)
            if (
                set(saved)
                != {"schema_version", "build_id", "image_tag", "image_id", "intent_ref", "qualified_ref", "state", "tag_absent_at_check", "cleanup_ref"}
                or saved.get("schema_version") != "bluefire.tenant-target-image-cleanup.v1"
                or saved.get("build_id") != build_id
                or saved.get("image_tag") != tag
                or saved.get("intent_ref") != intent["intent_ref"]
                or saved.get("qualified_ref") != qualified_ref
                or saved.get("state")
                != ("qualified_tag_absent" if qualified_ref is not None else "unqualified_build_unsettled")
                or saved.get("tag_absent_at_check") is not True
                or saved.get("cleanup_ref")
                != content_hash({k: v for k, v in saved.items() if k != "cleanup_ref"})
            ):
                raise TenantSidecarImageError("target image cleanup record changed")
            if _tagged_image_id(docker=docker, host=docker_host, tag=tag, env=env, root=private) is not None:
                raise TenantSidecarImageError("owned target image tag reappeared after cleanup")
            terminal.append(saved)
            _remove_owned_context(private, build_id)
            continue
        image_id = _tagged_image_id(docker=docker, host=docker_host, tag=tag, env=env, root=private)
        if image_id is not None:
            image = _inspect(_run, docker, docker_host, tag, env, private)
            config = image.get("Config")
            if (
                image.get("Id") != image_id
                or not isinstance(config, dict)
                or not isinstance(config.get("Labels"), dict)
                or config["Labels"].get("bluefire.target.source-artifact") != intent["wheel_digest"]
                or config["Labels"].get("bluefire.target.image-build") != build_id
            ):
                raise TenantSidecarImageError("target image tag no longer belongs to this build")
            removed = _run((docker, "--host", docker_host, "image", "rm", "--no-prune", tag), env, private, 30)
            if removed.returncode != 0:
                raise TenantSidecarImageError("owned target image removal is unknown")
            if _tagged_image_id(docker=docker, host=docker_host, tag=tag, env=env, root=private) is not None:
                raise TenantSidecarImageError("owned target image tag remains after removal")
        cleanup = {
            "schema_version": "bluefire.tenant-target-image-cleanup.v1",
            "build_id": build_id,
            "image_tag": tag,
            "image_id": image_id,
            "intent_ref": intent["intent_ref"],
            "qualified_ref": qualified_ref,
            "state": "qualified_tag_absent" if qualified_ref is not None else "unqualified_build_unsettled",
            "tag_absent_at_check": True,
        }
        cleanup["cleanup_ref"] = content_hash(cleanup)
        if qualified_ref is not None:
            # An unqualified build may still publish a tag after its client
            # died. Keep its durable intent and repeat this cleanup on each
            # recovery instead of recording terminal absence prematurely.
            _write_once(private, cleanup_name, cleanup)
        terminal.append(cleanup)
        _remove_owned_context(private, build_id)
    return tuple(terminal)


def qualify_target_sidecar_image(
    *,
    build_inputs: FileTargetSidecarBuildInputSource,
    input_ref: str,
    root: Path,
    docker_host: str = "unix:///var/run/docker.sock",
) -> Mapping[str, Any]:
    """Build one exact no-pull image and retain the qualification before use."""

    if os.name != "posix":
        raise TenantSidecarImageError("target image qualification requires Linux")
    private = _private_root(Path(root))
    if type(build_inputs) is not FileTargetSidecarBuildInputSource or build_inputs.root != private:
        raise TenantSidecarImageError("target image inputs are not from this protected source")
    admitted = _build_inputs(build_inputs, input_ref)
    wheel_path = Path(admitted["wheel_path"])
    if not wheel_path.is_relative_to(private) or wheel_path.parent == private:
        raise TenantSidecarImageError("candidate wheel is outside the protected source")
    wheel_digest = admitted["wheel_sha256"]
    base_image_id = admitted["base_image_id"]
    expected_base_config_ref = admitted["base_config_ref"]
    base_reference = admitted["base_reference"]
    docker = _fixed_docker_executable()
    if docker_host != "unix:///var/run/docker.sock":
        raise TenantSidecarImageError("Docker endpoint differs from the local owner")
    env = _docker_environment(private)
    source = FileTenantSidecarImageQualificationSource(private)
    base = _inspect(_run, docker, docker_host, base_reference, env, private)
    if (
        base.get("Id") != base_image_id
        or base.get("Os") != "linux"
        or base.get("Architecture") != "amd64"
        or not isinstance(base.get("Config"), dict)
        or content_hash(base["Config"]) != expected_base_config_ref
        or not isinstance(base["Config"].get("Env"), list)
        or "PYTHON_VERSION=3.12.14" not in base["Config"]["Env"]
    ):
        raise TenantSidecarImageError("preloaded base identity differs from approval")
    build_id = uuid.uuid4().hex
    context = private / f"context-{build_id}"
    wheel_name = Path(wheel_path).name
    dockerfile = _dockerfile(base_reference, wheel_name, wheel_digest, build_id)
    dockerfile_path = context / "Dockerfile"
    tag = f"localhost/bluefire/tenant-target-{build_id}:qualified"
    if _tagged_image_id(docker=docker, host=docker_host, tag=tag, env=env, root=private) is not None:
        raise TenantSidecarImageError("new target image tag already exists")
    iid_path = private / f"image-{build_id}.iid"
    command = (
        docker, "--host", docker_host, "build", "--quiet", "--pull=false", "--network=none",
        "--no-cache", "--rm", "--iidfile", str(iid_path), "--file", str(dockerfile_path),
        "--tag", tag, str(context),
    )
    recipe_ref = content_hash({
        "schema_version": "bluefire.tenant-target-fixed-build-recipe.v1",
        "base_image_id": base_image_id,
        "base_reference": base_reference,
        "wheel_digest": wheel_digest,
        "dockerfile_digest": _hash_bytes(dockerfile),
        "options": ["--quiet", "--pull=false", "--network=none", "--no-cache", "--rm"],
        "runtime_command": _ENTRYPOINT,
    })
    intent = {
        "schema_version": INTENT_SCHEMA,
        "build_id": build_id,
        "image_tag": tag,
        "base_image_id": base_image_id,
        "input_ref": input_ref,
        "wheel_digest": wheel_digest,
        "build_recipe_digest": recipe_ref,
    }
    intent_ref = content_hash(intent)
    _write_once(private, f"intent-{build_id}.json", {**intent, "intent_ref": intent_ref})
    context.mkdir(mode=0o700)
    _copy_expected_wheel(Path(wheel_path), context / wheel_name, wheel_digest)
    dockerfile_path.write_bytes(dockerfile)
    built = _run(command, env, private, _MAX_COMMAND_SECONDS)
    if built.returncode != 0 or len(built.stdout) > _MAX_OUTPUT or len(built.stderr) > _MAX_OUTPUT:
        raise TenantSidecarImageError("offline fixed target image build failed")
    try:
        image_id = iid_path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise TenantSidecarImageError("built target image ID is unavailable") from exc
    _digest(image_id, "built target image ID")
    if _tagged_image_id(docker=docker, host=docker_host, tag=tag, env=env, root=private) != image_id:
        raise TenantSidecarImageError("built target image tag differs from image ID")
    image = _inspect(_run, docker, docker_host, image_id, env, private)
    config = image.get("Config")
    if (
        image.get("Id") != image_id
        or image.get("Os") != "linux"
        or image.get("Architecture") != base.get("Architecture")
        or not isinstance(config, dict)
        or not isinstance(config.get("Labels"), dict)
        or config["Labels"].get("bluefire.target.source-artifact") != wheel_digest
        or config["Labels"].get("bluefire.target.image-build") != build_id
        or config.get("User") != "1000:1000"
        or config.get("Cmd") != _ENTRYPOINT
        or config.get("Entrypoint") not in ([], None)
    ):
        raise TenantSidecarImageError("built target image config differs from fixed recipe")
    receipt: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA,
        "image_id": image_id,
        "image_config_ref": content_hash(config),
        "source_artifact_digest": wheel_digest,
        "build_recipe_digest": recipe_ref,
        "base_image_digest": base_image_id,
        "offline_no_pull_verified": True,
    }
    receipt["receipt_ref"] = content_hash(receipt)
    source_document = {
        "schema_version": SOURCE_SCHEMA,
        "receipt": receipt,
        "wheel_digest": wheel_digest,
        "base_image_id": base_image_id,
        "base_config_ref": expected_base_config_ref,
        "input_ref": input_ref,
        "build_id": build_id,
        "image_tag": tag,
        "dockerfile_digest": _hash_bytes(dockerfile),
        "build_command_ref": content_hash(list(command)),
        "image_inspect_ref": content_hash(image),
    }
    source_document["source_ref"] = content_hash(source_document)
    _write_once(private, f"qualification-{receipt['receipt_ref'][7:]}.json", source_document)
    pointer = {
        "schema_version": "bluefire.tenant-target-image-qualified-pointer.v1",
        "build_id": build_id,
        "receipt_ref": receipt["receipt_ref"],
        "source_ref": source_document["source_ref"],
        "intent_ref": intent_ref,
    }
    _write_once(private, f"qualified-{build_id}.json", {
        **pointer, "pointer_ref": content_hash(pointer),
    })
    reopened = source.reopen_qualification(receipt["receipt_ref"])
    if reopened != receipt:
        raise TenantSidecarImageError("target image qualification failed to reopen")
    return reopened


__all__ = [
    "CommandResult",
    "FileTargetSidecarBuildInputSource",
    "FileTargetSidecarBaseAdmissionSource",
    "FileTenantSidecarImageQualificationSource",
    "PINNED_PYTHON_BASE",
    "TargetSidecarBuildInputSource",
    "TenantSidecarImageError",
    "cleanup_target_sidecar_images",
    "qualify_target_sidecar_image",
]
