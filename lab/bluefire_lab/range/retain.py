"""Export one hosted range run as a small, verifier-ready raw evidence folder.

The exporter is deliberately tied to a GitHub-hosted ``workflow_dispatch``
job.  It derives the declared provenance from that job's standard environment,
selects only the identity bytes needed for later scoring, and publishes nothing
until :mod:`bluefire_lab.range.retained` accepts the complete candidate.
"""

from __future__ import annotations

import ctypes
import errno
import gzip
import hashlib
import ipaddress
import json
import lzma
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from . import path as range_path
from . import retained, wazuh
from .path import iso
from .spec import Spec, SpecError, load

MAX_PCAP_BYTES = 8 * 1024 * 1024
MAX_RETAINED_BYTES = 16 * 1024 * 1024
CAPTURE_DIR = PurePosixPath("var/log/bluefire/packets")
CAPTURE_PATH = "/" + CAPTURE_DIR.as_posix()
COUNTER_NAMES = ("captured", "received by filter", "dropped by kernel")
COUNTER_BLOCK = re.compile(
    r"(?m)^([0-9]+) packets? captured\r?\n"
    r"([0-9]+) packets? received by filter\r?\n"
    r"([0-9]+) packets? dropped by kernel$"
)
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", "microseconds"),
    b"\xa1\xb2\xc3\xd4": (">", "microseconds"),
    b"\x4d\x3c\xb2\xa1": ("<", "nanoseconds"),
    b"\xa1\xb2\x3c\x4d": (">", "nanoseconds"),
}
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
PLAIN = re.compile(r"[^\x00-\x1f\x7f]+\Z")
INTERFACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
RULES_LOADED = re.compile(r"Total rules enabled: '([0-9]+)'")
AT_FDCWD = -100
RENAME_NOREPLACE = 1


class RetainError(ValueError):
    """A source run or hosted export request is not safe and complete."""


@dataclass(frozen=True)
class HostedContext:
    repository: str
    workflow: PurePosixPath
    run_id: int
    run_attempt: int
    job: str
    head: str
    run_url: str
    workspace: Path
    runner_temp: Path


class SourceRoot:
    """One run directory held by identity while every selected path is read."""

    def __init__(self, parent: Path, relative: PurePosixPath):
        self.original = parent.joinpath(*relative.parts)
        flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = None
        try:
            descriptor = os.open(parent, flags)
            opened = os.fstat(descriptor)
            named = parent.lstat()
            if (
                not stat.S_ISDIR(opened.st_mode)
                or stat.S_ISLNK(named.st_mode)
                or _signature(opened) != _signature(named)
            ):
                raise RetainError("RUNNER_TEMP changed while RUN was being anchored")
            for part in relative.parts:
                child = None
                try:
                    child = os.open(part, flags, dir_fd=descriptor)
                    opened = os.fstat(child)
                    named = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                    if (
                        not stat.S_ISDIR(opened.st_mode)
                        or stat.S_ISLNK(named.st_mode)
                        or _signature(opened) != _signature(named)
                    ):
                        raise RetainError(
                            "RUN changed or gained a linked component while it was being anchored"
                        )
                except Exception:
                    if child is not None:
                        os.close(child)
                    raise
                os.close(descriptor)
                descriptor = child
        except OSError as error:
            if descriptor is not None:
                os.close(descriptor)
            raise RetainError(f"RUN cannot be anchored safely: {error}") from error
        except Exception:
            if descriptor is not None:
                os.close(descriptor)
            raise
        self.descriptor = descriptor
        self.signature = _signature(opened)

    def check(self) -> None:
        try:
            opened = os.fstat(self.descriptor)
            named = self.original.lstat()
        except OSError as error:
            raise RetainError(f"RUN changed while the export was being prepared: {error}") from error
        if (
            _signature(opened) != self.signature
            or stat.S_ISLNK(named.st_mode)
            or _signature(named) != self.signature
        ):
            raise RetainError("RUN changed while the export was being prepared")

    def close(self) -> None:
        os.close(self.descriptor)

    def open_dir(self, relative: PurePosixPath, what: str) -> int:
        descriptor = os.dup(self.descriptor)
        try:
            for part in relative.parts:
                flags = (
                    os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                )
                child = os.open(part, flags, dir_fd=descriptor)
                opened = os.fstat(child)
                named = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or stat.S_ISLNK(named.st_mode)
                    or _signature(opened) != _signature(named)
                ):
                    os.close(child)
                    raise RetainError(f"{what} has a directory component that changed or is a link")
                os.close(descriptor)
                descriptor = child
            return descriptor
        except OSError as error:
            os.close(descriptor)
            raise RetainError(f"{what} cannot be traversed safely: {error}") from error
        except Exception:
            os.close(descriptor)
            raise

    def open_file(self, relative: PurePosixPath, what: str) -> tuple[int, int, str]:
        if not relative.parts:
            raise RetainError(f"{what} has no file name")
        parent_relative = PurePosixPath(*relative.parts[:-1])
        parent = self.open_dir(parent_relative, what)
        leaf = relative.name
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = None
        try:
            descriptor = os.open(leaf, flags, dir_fd=parent)
            opened = os.fstat(descriptor)
            named = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        except OSError as error:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent)
            raise RetainError(f"{what} cannot be opened safely: {error}") from error
        if _signature(opened) != _signature(named):
            os.close(descriptor)
            os.close(parent)
            raise RetainError(f"{what} changed while it was opened")
        return descriptor, parent, leaf

    def list_dir(self, relative: PurePosixPath, what: str) -> list[tuple[str, os.stat_result]]:
        descriptor = self.open_dir(relative, what)
        try:
            with os.scandir(descriptor) as entries:
                return sorted(
                    ((entry.name, entry.stat(follow_symlinks=False)) for entry in entries),
                    key=lambda item: item[0],
                )
        except OSError as error:
            raise RetainError(f"{what} cannot be listed safely: {error}") from error
        finally:
            os.close(descriptor)

    def walk_files(self, relative: PurePosixPath, what: str) -> list[RunPath]:
        found: list[RunPath] = []
        root = self.open_dir(relative, what)

        def visit(descriptor: int, folder: PurePosixPath) -> None:
            try:
                with os.scandir(descriptor) as entries:
                    listed = sorted(
                        ((entry.name, entry.stat(follow_symlinks=False)) for entry in entries),
                        key=lambda item: item[0],
                    )
                for name, status in listed:
                    child_relative = folder / name
                    if stat.S_ISLNK(status.st_mode):
                        raise RetainError(f"{what}/{child_relative.relative_to(relative)} is a link")
                    if stat.S_ISDIR(status.st_mode):
                        flags = (
                            os.O_RDONLY
                            | os.O_DIRECTORY
                            | getattr(os, "O_CLOEXEC", 0)
                            | getattr(os, "O_NOFOLLOW", 0)
                        )
                        child = None
                        try:
                            child = os.open(name, flags, dir_fd=descriptor)
                            opened = os.fstat(child)
                            named = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                            if _signature(opened) != _signature(named):
                                raise RetainError(f"{what} changed while it was traversed")
                            visit(child, child_relative)
                        finally:
                            if child is not None:
                                os.close(child)
                        continue
                    if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                        raise RetainError(
                            f"{what}/{child_relative.relative_to(relative)} is not a single-link regular file"
                        )
                    found.append(RunPath(self, child_relative))
            except OSError as error:
                raise RetainError(f"{what} cannot be traversed safely: {error}") from error

        try:
            visit(root, relative)
        finally:
            os.close(root)
        return found


@dataclass(frozen=True)
class RunPath:
    source: SourceRoot
    relative: PurePosixPath

    @property
    def display(self) -> Path:
        return self.source.original.joinpath(*self.relative.parts)


@dataclass(frozen=True)
class Snapshot:
    path: Path
    locator: Path | RunPath
    what: str
    signature: tuple[int, ...]
    bytes: int
    sha256: str


@dataclass(frozen=True)
class PlannedFile:
    stored_path: PurePosixPath
    run_path: PurePosixPath
    role: str
    payload: bytes | None = None
    source: Snapshot | None = None

    @property
    def bytes(self) -> int:
        return len(self.payload) if self.payload is not None else self.source.bytes


def _plain(value: object, what: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or not PLAIN.fullmatch(value):
        raise RetainError(f"{what} must be non-empty plain text")
    return value


def _positive(value: str, what: str) -> int:
    if not value.isascii() or not value.isdecimal() or value.startswith("0"):
        raise RetainError(f"{what} must be a positive decimal integer")
    number = int(value)
    if number < 1:
        raise RetainError(f"{what} must be a positive decimal integer")
    return number


def _relative(value: object, what: str) -> PurePosixPath:
    text = _plain(value, what)
    path = PurePosixPath(text)
    if (
        "\\" in text
        or path.is_absolute()
        or path.as_posix() != text
        or not path.parts
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise RetainError(f"{what} must be one normalized relative POSIX path")
    return path


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    found = {}
    for key, value in pairs:
        if key in found:
            raise RetainError(f"the JSON document repeats the key {key!r}")
        found[key] = value
    return found


def _json_bytes(data: bytes, what: str) -> dict:
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RetainError(f"{what} cannot be read as JSON: {error}") from error
    if not isinstance(value, dict):
        raise RetainError(f"{what} must be a JSON object")
    return value


def _json_data(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()


def _signature(status: os.stat_result) -> tuple[int, ...]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_nlink,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _regular_directory(path: Path, what: str) -> Path:
    try:
        status = path.lstat()
    except OSError as error:
        raise RetainError(f"{what} cannot be read: {error}") from error
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
        raise RetainError(f"{what} must be a real directory, not a link")
    return path.resolve()


def _check_ancestors(root: Path, path: Path, what: str) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise RetainError(f"{what} is outside {root}") from error
    cursor = root
    for part in relative.parts[:-1]:
        cursor /= part
        try:
            status = cursor.lstat()
        except OSError as error:
            raise RetainError(f"{what} has an unreadable parent folder: {error}") from error
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
            raise RetainError(f"{what} has a parent that is not a real directory")


def _display(locator: Path | RunPath) -> Path:
    return locator.display if isinstance(locator, RunPath) else locator


def _open_locator(locator: Path | RunPath, what: str) -> tuple[int, int | None, str | None]:
    if isinstance(locator, RunPath):
        return locator.source.open_file(locator.relative, what)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(locator, flags), None, None
    except OSError as error:
        raise RetainError(f"{what} cannot be opened safely: {error}") from error


def _named_status(locator: Path | RunPath, parent: int | None, leaf: str | None) -> os.stat_result:
    if isinstance(locator, RunPath):
        return os.stat(leaf, dir_fd=parent, follow_symlinks=False)
    return locator.lstat()


def _close_locator(descriptor: int, parent: int | None) -> None:
    os.close(descriptor)
    if parent is not None:
        os.close(parent)


def _capture(locator: Path | RunPath, what: str, *, content: bool = False) -> tuple[Snapshot, bytes | None]:
    descriptor, parent, leaf = _open_locator(locator, what)
    digest = hashlib.sha256()
    pieces = [] if content else None
    count = 0
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RetainError(f"{what} is not a regular file")
        if before.st_nlink != 1:
            raise RetainError(f"{what} must have exactly one hard link")
        if before.st_size > MAX_RETAINED_BYTES:
            raise RetainError(f"{what} is larger than the {MAX_RETAINED_BYTES}-byte retained limit")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            while block := stream.read(1024 * 1024):
                digest.update(block)
                count += len(block)
                if pieces is not None:
                    pieces.append(block)
        after = os.fstat(descriptor)
        try:
            named = _named_status(locator, parent, leaf)
        except OSError as error:
            raise RetainError(f"{what} disappeared while it was read: {error}") from error
    finally:
        _close_locator(descriptor, parent)
    changed = _signature(before) != _signature(after) or _signature(after) != _signature(named)
    if changed:
        raise RetainError(f"{what} changed while it was read")
    if count != before.st_size:
        raise RetainError(f"{what} changed length while it was read")
    snapshot = Snapshot(_display(locator), locator, what, _signature(before), count, digest.hexdigest())
    return snapshot, b"".join(pieces) if pieces is not None else None


def _remember(
    snapshots: dict[Path, Snapshot], locator: Path | RunPath, what: str, *, content: bool = False
) -> tuple[Snapshot, bytes | None]:
    path = _display(locator)
    existing = snapshots.get(path)
    if existing is not None and not content:
        return existing, None
    snapshot, data = _capture(locator, what, content=content)
    if existing is not None and snapshot != existing:
        raise RetainError(f"{what} changed while the export was being prepared")
    snapshots[path] = snapshot
    return snapshot, data


def _recheck(snapshot: Snapshot) -> None:
    found, _ = _capture(snapshot.locator, snapshot.what)
    if found.signature != snapshot.signature or found.sha256 != snapshot.sha256:
        raise RetainError(f"{snapshot.what} changed while the export was being written")


@contextmanager
def _snapshot_stream(snapshot: Snapshot):
    descriptor, parent, leaf = _open_locator(snapshot.locator, snapshot.what)
    try:
        before = os.fstat(descriptor)
        if _signature(before) != snapshot.signature:
            raise RetainError(f"{snapshot.what} changed before it was read again")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            yield stream
        after = os.fstat(descriptor)
        named = _named_status(snapshot.locator, parent, leaf)
        if _signature(after) != snapshot.signature or _signature(named) != snapshot.signature:
            raise RetainError(f"{snapshot.what} changed while it was read again")
    finally:
        _close_locator(descriptor, parent)


def _source_path(root: SourceRoot, relative: PurePosixPath, what: str) -> RunPath:
    root.check()
    path = RunPath(root, relative)
    descriptor, parent, _ = root.open_file(relative, what)
    _close_locator(descriptor, parent)
    root.check()
    return path


def _git(workspace: Path, *arguments: str) -> bytes:
    environment = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    try:
        return subprocess.run(
            ["git", "--no-replace-objects", "-C", str(workspace), *arguments],
            check=True,
            capture_output=True,
            env=environment,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", b"").decode("utf-8", "replace").strip()
        raise RetainError(
            f"git could not verify the hosted checkout{': ' + detail if detail else ''}"
        ) from error


def _hosted(environ: Mapping[str, str]) -> HostedContext:
    expected = {
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_SERVER_URL": "https://github.com",
    }
    for name, value in expected.items():
        if environ.get(name) != value:
            raise RetainError(f"{name} must be {value!r}; retain runs only in a hosted workflow_dispatch job")
    required = (
        "GITHUB_REPOSITORY",
        "GITHUB_WORKFLOW_REF",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_JOB",
        "GITHUB_SHA",
        "GITHUB_WORKSPACE",
        "RUNNER_TEMP",
    )
    missing = [name for name in required if not environ.get(name)]
    if missing:
        raise RetainError("the hosted context lacks " + ", ".join(missing))
    repository = _plain(environ["GITHUB_REPOSITORY"], "GITHUB_REPOSITORY")
    if not REPOSITORY.fullmatch(repository):
        raise RetainError("GITHUB_REPOSITORY must be an owner and repository name")
    workflow_ref = environ["GITHUB_WORKFLOW_REF"]
    prefix = repository + "/"
    if not workflow_ref.startswith(prefix) or "@" not in workflow_ref[len(prefix) :]:
        raise RetainError("GITHUB_WORKFLOW_REF does not name this repository's workflow and ref")
    workflow_text, ref = workflow_ref[len(prefix) :].rsplit("@", 1)
    workflow = _relative(workflow_text, "GITHUB_WORKFLOW_REF's workflow")
    if workflow.parts[:2] != (".github", "workflows") or workflow.suffix not in (".yml", ".yaml"):
        raise RetainError("GITHUB_WORKFLOW_REF must name YAML below .github/workflows/")
    _plain(ref, "GITHUB_WORKFLOW_REF's ref")
    head = environ["GITHUB_SHA"]
    if not SHA.fullmatch(head):
        raise RetainError("GITHUB_SHA must be one lower-case 40-character commit id")
    workspace = _regular_directory(Path(environ["GITHUB_WORKSPACE"]), "GITHUB_WORKSPACE")
    runner_temp = _regular_directory(Path(environ["RUNNER_TEMP"]), "RUNNER_TEMP")
    run_id = _positive(environ["GITHUB_RUN_ID"], "GITHUB_RUN_ID")
    return HostedContext(
        repository,
        workflow,
        run_id,
        _positive(environ["GITHUB_RUN_ATTEMPT"], "GITHUB_RUN_ATTEMPT"),
        _plain(environ["GITHUB_JOB"], "GITHUB_JOB"),
        head,
        f"https://github.com/{repository}/actions/runs/{run_id}",
        workspace,
        runner_temp,
    )


def _tracked(
    context: HostedContext, spec_path: Path, snapshots: dict[Path, Snapshot]
) -> tuple[Spec, Snapshot, str]:
    top = Path(_git(context.workspace, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    if top != context.workspace:
        raise RetainError("GITHUB_WORKSPACE is not the root of the hosted checkout")
    head = _git(context.workspace, "rev-parse", "HEAD").decode().strip()
    if head != context.head:
        raise RetainError("the hosted checkout HEAD differs from GITHUB_SHA")

    spec_path = Path(spec_path).resolve(strict=False)
    try:
        relative = spec_path.relative_to(context.workspace).as_posix()
    except ValueError as error:
        raise RetainError("--spec must be inside GITHUB_WORKSPACE") from error
    _check_ancestors(context.workspace, spec_path, "the run spec")
    snapshot, spec_bytes = _remember(snapshots, spec_path, "the run spec", content=True)
    committed = _git(context.workspace, "show", f"{context.head}:{relative}")
    if spec_bytes != committed:
        raise RetainError("--spec is not byte-for-byte the file tracked at GITHUB_SHA")

    workflow_path = context.workspace.joinpath(*context.workflow.parts)
    _check_ancestors(context.workspace, workflow_path, "the running workflow")
    _, workflow_bytes = _remember(snapshots, workflow_path, "the running workflow", content=True)
    committed_workflow = _git(context.workspace, "show", f"{context.head}:{context.workflow.as_posix()}")
    if workflow_bytes != committed_workflow:
        raise RetainError("the running workflow is not byte-for-byte the file tracked at GITHUB_SHA")
    try:
        spec = load(spec_path)
    except (OSError, SpecError) as error:
        raise RetainError(f"the tracked run spec cannot be read: {error}") from error
    return spec, snapshot, relative


def _source_run(context: HostedContext, run: Path) -> SourceRoot:
    run = Path(os.path.abspath(run))
    if not run.is_relative_to(context.runner_temp):
        raise RetainError("RUN must be below RUNNER_TEMP on this hosted job")
    artifact_root = context.runner_temp / "retained-artifact"
    if run == artifact_root or run.is_relative_to(artifact_root):
        raise RetainError("RUN must be separate from the retained artifact root")
    relative = run.relative_to(context.runner_temp)
    return SourceRoot(context.runner_temp, PurePosixPath(*relative.parts))


def _output(context: HostedContext, run: Path, out: Path) -> tuple[Path, PurePosixPath]:
    artifact_root = context.runner_temp / "retained-artifact"
    out = Path(out).absolute()
    try:
        relative = out.relative_to(artifact_root)
    except ValueError as error:
        raise RetainError("--out must be below $RUNNER_TEMP/retained-artifact") from error
    prefix = _relative(relative.as_posix(), "the artifact member prefix")
    if os.path.lexists(out):
        raise RetainError(f"{out} exists; retain publishes a new folder only")
    if out == run or out.is_relative_to(run) or run.is_relative_to(out):
        raise RetainError("RUN and --out must not contain one another")
    if (
        out == context.workspace
        or out.is_relative_to(context.workspace)
        or context.workspace.is_relative_to(out)
    ):
        raise RetainError("--out and GITHUB_WORKSPACE must not contain one another")
    cursor = context.runner_temp
    for part in (Path("retained-artifact") / relative.parent).parts:
        cursor /= part
        try:
            cursor.mkdir(mode=0o700)
        except FileExistsError:
            pass
        status = cursor.lstat()
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
            raise RetainError(f"the output parent {cursor} is not a real directory")
    return out, prefix


def _manifest(
    context: HostedContext,
    run: SourceRoot,
    spec: Spec,
    spec_snapshot: Snapshot,
    snapshots: dict[Path, Snapshot],
) -> tuple[dict, dict, Snapshot]:
    path = _source_path(run, PurePosixPath("manifest.json"), "the source manifest")
    snapshot, data = _remember(snapshots, path, "the source manifest", content=True)
    manifest = _json_bytes(data, "the source manifest")
    source_spec = manifest.get("spec")
    checks = (
        (manifest.get("range") == spec.range, "the source manifest names another range"),
        (manifest.get("version") == spec.version, "the source manifest names another spec version"),
        (manifest.get("environment") == "GitHub-hosted runner", "the source run was not hosted"),
        (manifest.get("run_url") == context.run_url, "the source run URL differs from this hosted run"),
        (manifest.get("result") == "sealed", "the source run did not end sealed"),
        (
            type(manifest.get("exit_code")) is int and manifest.get("exit_code") == 0,
            "the source run did not exit 0",
        ),
        (manifest.get("teardown_complete") is True, "the source run did not complete teardown"),
        (manifest.get("reason") is None, "the sealed source run has a failure reason"),
        (isinstance(source_spec, dict), "the source manifest has no spec object"),
        (
            isinstance(source_spec, dict) and source_spec.get("file") == Path(spec_snapshot.path).name,
            "the source manifest names another spec file",
        ),
        (
            isinstance(source_spec, dict) and source_spec.get("sha256") == spec_snapshot.sha256,
            "the source manifest has another spec digest",
        ),
        (
            isinstance(source_spec, dict) and source_spec.get("text") == spec.text,
            "the source manifest has another spec text",
        ),
    )
    for passed, message in checks:
        if not passed:
            raise RetainError(message)
    run_id = _plain(manifest.get("run_id"), "manifest.run_id")
    projected = {
        "range": spec.range,
        "version": spec.version,
        "run_id": run_id,
        "spec": {"file": Path(spec_snapshot.path).name},
        "environment": "GitHub-hosted runner",
        "run_url": context.run_url,
    }
    return manifest, projected, snapshot


def _containers(manifest: dict, spec: Spec) -> dict:
    source = manifest.get("containers")
    if not isinstance(source, dict) or set(source) != set(spec.hosts):
        raise RetainError("manifest.containers must name every host of the tracked spec exactly once")
    projected = {}
    for host, settings in spec.hosts.items():
        entry = source.get(host)
        if not isinstance(entry, dict) or entry.get("name") != spec.container_name(host):
            raise RetainError(f"manifest.containers.{host} does not name the range's container")
        addresses = entry.get("addresses")
        if not isinstance(addresses, dict) or set(addresses) != set(settings.networks):
            raise RetainError(f"manifest.containers.{host}.addresses does not cover its spec networks")
        checked = {}
        for network, address in addresses.items():
            try:
                checked[network] = str(ipaddress.ip_address(address))
            except ValueError as error:
                raise RetainError(
                    f"manifest.containers.{host}.addresses.{network} is not an IP address"
                ) from error
        projected[host] = {"name": entry["name"], "addresses": checked}
    return projected


def _defense(manifest: dict, spec: Spec) -> dict:
    if spec.wazuh is None or spec.manager is None:
        raise RetainError("the tracked spec has no Wazuh defense to rejudge")
    defense = manifest.get("defense")
    if not isinstance(defense, dict):
        raise RetainError("the source manifest has no Wazuh defense record")
    checks = (
        (
            defense.get("wazuh_version") == spec.wazuh.version,
            "the source Wazuh version differs from the spec",
        ),
        (defense.get("manager") == spec.manager, "the source Wazuh manager differs from the spec"),
        (defense.get("agents") == spec.agents, "the source Wazuh agents differ from the spec"),
        (
            defense.get("alert_level") == spec.wazuh.alert_level,
            "the source Wazuh alert level differs from the spec",
        ),
        (defense.get("delivery_gap") is False, "the source Wazuh delivery has a gap or was not assessed"),
        (defense.get("delivery_findings") == [], "the source Wazuh delivery has findings"),
        (defense.get("wazuh_counted_drops") is False, "the source Wazuh counters report dropped events"),
        (not defense.get("collect_error"), "the source Wazuh collection reported an error"),
        (
            isinstance(defense.get("live"), dict)
            and defense["live"].get("files") == ["live/archives.json", "live/alerts.json"],
            "the source manifest does not declare the complete live archive and alerts",
        ),
    )
    for passed, message in checks:
        if not passed:
            raise RetainError(message)
    delivery = defense.get("delivery")
    if not isinstance(delivery, dict) or set(delivery) != set(spec.agents):
        raise RetainError("the source Wazuh delivery must cover every agent")
    for host, rows in delivery.items():
        if (
            not isinstance(rows, list)
            or not rows
            or any(not isinstance(row, dict) or row.get("missing") != 0 for row in rows)
        ):
            raise RetainError(f"the source Wazuh delivery for {host} is incomplete")
    return {
        "wazuh_version": defense["wazuh_version"],
        "alert_level": defense["alert_level"],
        "manager": defense["manager"],
        "agents": defense["agents"],
        "delivery": delivery,
        "delivery_gap": False,
        "delivery_findings": [],
        "drops": defense.get("drops") or {},
        "wazuh_counted_drops": False,
    }


def _docker_clock(run: SourceRoot, snapshots: dict[Path, Snapshot]) -> dict:
    path = _source_path(run, PurePosixPath("docker-events.ndjson"), "the Docker event stream")
    _, data = _remember(snapshots, path, "the Docker event stream", content=True)
    times = []
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise RetainError(f"the Docker event stream is not UTF-8: {error}") from error
    for number, line in enumerate(lines, start=1):
        if not line:
            continue
        event = _json_bytes(line.encode(), f"Docker event line {number}")
        value = event.get("timeNano")
        if type(value) is not int or value < 0:
            raise RetainError(f"Docker event line {number} has no non-negative integer timeNano")
        times.append(value)
    if not times:
        raise RetainError("the Docker event stream has no timestamped event")
    return {
        "started": iso(min(times)),
        "ended": iso(max(times)),
        "basis": "the first and last Docker event timeNano selected by the hosted workflow",
    }


def _pcap(snapshot: Snapshot) -> dict:
    with _snapshot_stream(snapshot) as source:
        header = source.read(24)
        if len(header) != 24:
            raise RetainError(f"{snapshot.path.name}: the PCAP global header is truncated")
        order = PCAP_MAGIC.get(header[:4])
        if order is None:
            raise RetainError(f"{snapshot.path.name}: the file is not classic PCAP")
        endian, resolution = order
        try:
            major, minor, _zone, _accuracy, snaplen, link_type = struct.unpack(endian + "HHIIII", header[4:])
        except struct.error as error:
            raise RetainError(f"{snapshot.path.name}: the PCAP global header cannot be read") from error
        if (major, minor) != (2, 4) or snaplen <= 0:
            raise RetainError(f"{snapshot.path.name}: the PCAP header is not supported")
        packets = captured = wire = 0
        whole = True
        while True:
            record = source.read(16)
            if not record:
                break
            if len(record) != 16:
                raise RetainError(f"{snapshot.path.name}: packet {packets + 1}'s header is truncated")
            try:
                _seconds, fraction, included, original = struct.unpack(endian + "IIII", record)
            except struct.error as error:
                raise RetainError(
                    f"{snapshot.path.name}: packet {packets + 1}'s header cannot be read"
                ) from error
            limit = 1_000_000_000 if resolution == "nanoseconds" else 1_000_000
            if fraction >= limit or included > snaplen or included > original:
                raise RetainError(f"{snapshot.path.name}: packet {packets + 1}'s header is invalid")
            remaining = included
            while remaining:
                block = source.read(min(remaining, 1024 * 1024))
                if not block:
                    raise RetainError(f"{snapshot.path.name}: packet {packets + 1}'s bytes are truncated")
                remaining -= len(block)
            packets += 1
            captured += included
            wire += original
            whole = whole and included == original
    compressor = lzma.LZMACompressor(format=lzma.FORMAT_XZ, preset=9)
    compressed = 0
    with _snapshot_stream(snapshot) as source:
        while block := source.read(1024 * 1024):
            compressed += len(compressor.compress(block))
    compressed += len(compressor.flush())
    return {
        "packets": packets,
        "captured packet bytes": captured,
        "wire packet bytes": wire,
        "whole packets": whole,
        "snap length": snaplen,
        "link type": link_type,
        "timestamp resolution": resolution,
        "xz -9 bytes": compressed,
    }


def _counter(snapshot: Snapshot) -> dict[str, int]:
    try:
        with _snapshot_stream(snapshot) as source:
            text = source.read().decode("utf-8", errors="replace").rstrip("\r\n")
    except OSError as error:
        raise RetainError(f"{snapshot.path.name}: tcpdump's counters cannot be read: {error}") from error
    blocks = list(COUNTER_BLOCK.finditer(text))
    if not blocks or blocks[-1].end() != len(text):
        raise RetainError(f"{snapshot.path.name}: tcpdump's log does not end with a complete counter block")
    return {name: int(value) for name, value in zip(COUNTER_NAMES, blocks[-1].groups(), strict=True)}


def _contains(snapshot: Snapshot, token: str) -> bool:
    wanted = token.encode()
    overlap = b""
    with _snapshot_stream(snapshot) as source:
        while block := source.read(1024 * 1024):
            combined = overlap + block
            if wanted in combined:
                return True
            overlap = combined[-(len(wanted) - 1) :] if len(wanted) > 1 else b""
    return False


def _packet_files(
    run: SourceRoot,
    manifest: dict,
    spec: Spec,
    containers: dict,
    snapshots: dict[Path, Snapshot],
) -> tuple[dict, list[PlannedFile]]:
    capture = manifest.get("packet_capture")
    if not isinstance(capture, dict):
        raise RetainError("the source manifest has no packet_capture record")
    if (
        capture.get("program") != "tcpdump"
        or capture.get("path") != CAPTURE_PATH
        or capture.get("analysed") is not True
        or capture.get("delivery_gap") is not False
        or capture.get("delivery_findings") != []
        or capture.get("collect_error")
    ):
        raise RetainError("the source packet capture is incomplete, has a delivery gap, or was not analysed")
    _plain(capture.get("filter"), "packet_capture.filter")
    hosts = capture.get("hosts")
    if not isinstance(hosts, dict) or not hosts:
        raise RetainError("the source packet capture names no host")
    if not set(hosts).issubset(spec.hosts):
        raise RetainError("the source packet capture names a host outside the tracked spec")
    if all(hasattr(settings, "capture") for settings in spec.hosts.values()):
        declared = {host for host, settings in spec.hosts.items() if settings.capture == "packets"}
        if set(hosts) != declared:
            raise RetainError("the source packet capture hosts differ from the tracked spec")
    home_hosts = sorted(set(spec.agents) | set(hosts))
    if capture.get("home_hosts") != home_hosts:
        raise RetainError("packet_capture.home_hosts differs from the agents and capture hosts")
    home_net = sorted(
        {
            address
            for host in home_hosts
            for address in (containers.get(host, {}).get("addresses") or {}).values()
        },
        key=lambda value: (ipaddress.ip_address(value).version, ipaddress.ip_address(value)),
    )
    if capture.get("home_net") != home_net:
        raise RetainError("packet_capture.home_net differs from the retained host addresses")

    planned = []
    total = 0
    for host, entry in hosts.items():
        if not isinstance(entry, dict) or entry.get("started") is not True:
            raise RetainError(f"packet capture on {host} did not start")
        stopped, collected = entry.get("stopped"), entry.get("collected")
        if (
            not isinstance(stopped, dict)
            or stopped.get("cleanly") is not True
            or stopped.get("error")
            or not isinstance(collected, dict)
            or collected.get("copied") is not True
            or collected.get("error")
            or collected.get("refused")
        ):
            raise RetainError(f"packet capture on {host} was not stopped and collected cleanly")
        ready = entry.get("ready")
        files = entry.get("files")
        if not isinstance(ready, list) or not ready or not isinstance(files, dict) or not files:
            raise RetainError(f"packet capture on {host} has no ready marks or files")
        expected_interfaces = set()
        marks_by_interface: dict[str, list[dict]] = {}
        for mark in ready:
            if not isinstance(mark, dict) or mark.get("seen") is not True:
                raise RetainError(f"packet capture on {host} has an unseen ready mark")
            interface = _plain(mark.get("interface"), f"packet capture on {host}'s ready interface")
            token = _plain(mark.get("token"), f"packet capture on {host}'s ready token")
            if not INTERFACE.fullmatch(interface):
                raise RetainError(f"packet capture on {host} has an unsafe interface name")
            expected_interfaces.add(interface)
            marks_by_interface.setdefault(interface, []).append({**mark, "token": token})
        expected_names = {f"{interface}.pcap" for interface in expected_interfaces}
        if set(files) != expected_names:
            raise RetainError(f"packet capture on {host} does not exactly match its ready interfaces")

        folder_relative = PurePosixPath("raw/hosts") / host / CAPTURE_DIR
        actual_names = set()
        for name, status in run.list_dir(folder_relative, f"the packet folder on {host}"):
            if not stat.S_ISREG(status.st_mode) or stat.S_ISLNK(status.st_mode) or status.st_nlink != 1:
                raise RetainError(f"the packet folder on {host} contains a non-regular or linked entry")
            actual_names.add(name)
        expected_folder_names = expected_names | {f"{interface}.log" for interface in expected_interfaces}
        if actual_names != expected_folder_names:
            raise RetainError(f"the packet folder on {host} has a missing or undeclared file")

        for name in sorted(files):
            record = files[name]
            if not isinstance(record, dict) or record.get("error") or record.get("counter error"):
                raise RetainError(f"packet_capture.hosts.{host}.files.{name} has an error")
            interface = name.removesuffix(".pcap")
            run_path = folder_relative / name
            if record.get("file") != run_path.as_posix():
                raise RetainError(f"packet_capture.hosts.{host}.files.{name}.file is not canonical")
            pcap_path = _source_path(run, run_path, f"packet capture {host}/{name}")
            pcap_snapshot, _ = _remember(snapshots, pcap_path, f"packet capture {host}/{name}")
            facts = _pcap(pcap_snapshot)
            facts.update({"bytes": pcap_snapshot.bytes, "sha256": pcap_snapshot.sha256})
            for key, value in facts.items():
                if record.get(key) != value:
                    raise RetainError(f"packet capture {host}/{name} has another {key} than its manifest")
            if facts["packets"] < 1 or facts["whole packets"] is not True:
                raise RetainError(
                    f"packet capture {host}/{name} is empty or truncated by its snapshot length"
                )
            for mark in marks_by_interface[interface]:
                if not _contains(pcap_snapshot, mark["token"]):
                    raise RetainError(f"packet capture {host}/{name} does not contain its ready token")
            counter_run = run_path.with_suffix(".log")
            counter_path = _source_path(run, counter_run, f"tcpdump counters {host}/{interface}")
            counter_snapshot, _ = _remember(snapshots, counter_path, f"tcpdump counters {host}/{interface}")
            counts = _counter(counter_snapshot)
            if record.get("tcpdump") != counts:
                raise RetainError(f"packet capture {host}/{name} has other counters than its manifest")
            if (
                counts["captured"] != facts["packets"]
                or counts["received by filter"] != counts["captured"] + counts["dropped by kernel"]
                or counts["dropped by kernel"] != 0
            ):
                raise RetainError(f"packet capture {host}/{name} has inconsistent counters or kernel drops")
            total += pcap_snapshot.bytes
            planned += [
                PlannedFile(
                    PurePosixPath("files") / run_path, run_path, "raw packet capture", source=pcap_snapshot
                ),
                PlannedFile(
                    PurePosixPath("files") / counter_run.with_suffix(".txt"),
                    counter_run,
                    "raw tcpdump delivery counters",
                    source=counter_snapshot,
                ),
            ]
    if total > MAX_PCAP_BYTES:
        raise RetainError(f"the packet captures total {total} bytes, above the {MAX_PCAP_BYTES}-byte limit")
    return capture, planned


def _wazuh_files(run: SourceRoot, spec: Spec, snapshots: dict[Path, Snapshot]) -> list[PlannedFile]:
    manager = spec.manager
    assert manager is not None
    mappings = (
        (
            PurePosixPath("live/archives.json"),
            PurePosixPath("raw/hosts") / manager / "var/ossec/logs/archives/archives.json",
            "complete raw Wazuh archive",
        ),
        (
            PurePosixPath("live/alerts.json"),
            PurePosixPath("raw/hosts") / manager / "var/ossec/logs/alerts/alerts.json",
            "complete raw Wazuh alerts",
        ),
        (
            PurePosixPath("raw/hosts") / manager / "var/ossec/logs/ossec.log",
            PurePosixPath("raw/hosts") / manager / "var/ossec/logs/ossec.log",
            "raw Wazuh manager startup record",
        ),
    )
    planned = []
    for source_relative, run_path, role in mappings:
        path = _source_path(run, source_relative, role)
        snapshot, data = _remember(snapshots, path, role, content=True)
        if snapshot.bytes == 0 and run_path.name != "alerts.json":
            raise RetainError(f"{role} is empty")
        if run_path.name == "ossec.log":
            try:
                text = data.decode("utf-8", "replace")
            except AttributeError as error:
                raise RetainError("the Wazuh manager startup record cannot be read") from error
            if not RULES_LOADED.search(text):
                raise RetainError("the Wazuh manager startup record does not say how many rules it loaded")
            stored = (PurePosixPath("files") / run_path).with_suffix(".txt")
        else:
            for number, line in enumerate(data.splitlines(), start=1):
                if line:
                    _json_bytes(line, f"{role} line {number}")
            kind = run_path.parent.name
            _same_as_collected(run, manager, kind, data, snapshots)
            stored = PurePosixPath("files") / run_path
        planned.append(PlannedFile(stored, run_path, role, source=snapshot))
    return planned


def _same_as_collected(
    run: SourceRoot,
    manager: str,
    kind: str,
    live: bytes,
    snapshots: dict[Path, Snapshot],
) -> None:
    relative = PurePosixPath("raw/hosts") / manager / "var/ossec/logs" / kind
    actual = run.walk_files(relative, f"the collected Wazuh {kind} folder")
    ordered = []
    seen_days = set()
    expected_prefix = "ossec-archive-" if kind == "archives" else "ossec-alerts-"
    for path in actual:
        parts = path.relative.relative_to(relative).parts
        if len(parts) != 3:
            raise RetainError(
                f"the collected Wazuh {kind} folder is not an exact set of daily JSON gzip files"
            )
        year, month, filename = parts
        match = wazuh.DAILY.fullmatch(filename)
        if (
            not year.isascii()
            or not year.isdecimal()
            or month not in wazuh.MONTHS
            or match is None
            or not filename.startswith(expected_prefix)
            or not filename.endswith(".json.gz")
        ):
            raise RetainError(
                f"the collected Wazuh {kind} folder is not an exact set of daily JSON gzip files"
            )
        day = (int(year), wazuh.MONTHS.index(month), int(match.group(1)))
        if day in seen_days:
            raise RetainError(f"the collected Wazuh {kind} folder repeats one daily JSON gzip file")
        seen_days.add(day)
        ordered.append((day, path))
    if not ordered:
        raise RetainError(f"the collected Wazuh {kind} folder is not an exact set of daily JSON gzip files")

    digest = hashlib.sha256()
    count = 0
    for _day, path in sorted(ordered, key=lambda item: item[0]):
        relative_path = path.relative.as_posix()
        snapshot, _ = _remember(snapshots, path, f"collected Wazuh file {relative_path}")
        try:
            with _snapshot_stream(snapshot) as compressed:
                with gzip.GzipFile(fileobj=compressed, mode="rb") as source:
                    while block := source.read(1024 * 1024):
                        digest.update(block)
                        count += len(block)
        except (OSError, EOFError, gzip.BadGzipFile) as error:
            raise RetainError(
                f"collected Wazuh file {relative_path} cannot be decompressed: {error}"
            ) from error
    if count != len(live) or digest.hexdigest() != hashlib.sha256(live).hexdigest():
        raise RetainError(f"the live Wazuh {kind} stream differs from the collected daily logs")


def _step_files(
    run: SourceRoot, manifest: dict, spec: Spec, snapshots: dict[Path, Snapshot]
) -> list[PlannedFile]:
    path_record = manifest.get("path")
    if not isinstance(path_record, dict):
        raise RetainError("the source manifest has no completed path record")
    section = range_path.section(spec)
    spec_steps = section.get("steps") if isinstance(section, dict) else None
    if not isinstance(spec_steps, list) or len(spec_steps) != len(spec.steps):
        raise RetainError("the tracked spec has no complete path identity")
    expected = []
    for number, entry in enumerate(spec_steps, start=1):
        if not isinstance(entry, dict):
            raise RetainError(f"step {number} of the tracked spec has no identity")
        step_id = entry.get("id")
        host = entry.get("host")
        technique = entry.get("technique")
        if (
            not isinstance(step_id, str)
            or len(_relative(step_id, f"tracked spec step {number} id").parts) != 1
            or not range_path.STEP_ID.fullmatch(step_id)
            or not isinstance(host, str)
            or not isinstance(technique, str)
            or (technique, host) != spec.steps[number - 1]
        ):
            raise RetainError(f"step {number} of the tracked spec has no valid id, host and technique")
        expected.append((step_id, host, technique))
    planned_ids = path_record.get("planned")
    steps = path_record.get("steps")
    if (
        not isinstance(planned_ids, list)
        or planned_ids != [step_id for step_id, _, _ in expected]
        or not isinstance(steps, list)
        or [
            (entry.get("id"), entry.get("host"), entry.get("technique")) if isinstance(entry, dict) else None
            for entry in steps
        ]
        != expected
        or path_record.get("stopped") is not None
        or path_record.get("skipped") is not None
    ):
        raise RetainError("the source manifest's path does not match every tracked step in order")
    actual_dirs = set()
    for name, status in run.list_dir(PurePosixPath("raw/steps"), "the raw step folder"):
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
            raise RetainError("the raw step folder contains an entry that is not a real directory")
        actual_dirs.add(name)
    if actual_dirs != set(planned_ids):
        raise RetainError("the raw step folders do not exactly match the completed path")
    planned = []
    required = {"command", "prereq.txt", "stdout", "stderr", "check.txt"}
    for step_id in planned_ids:
        relative_root = PurePosixPath("raw/steps") / step_id
        names = set()
        for path in run.walk_files(relative_root, f"raw step {step_id}"):
            run_path = path.relative
            relative = run_path.relative_to(relative_root)
            names.add(relative.as_posix())
            snapshot, _ = _remember(snapshots, path, f"raw step file {run_path}")
            planned.append(
                PlannedFile(
                    PurePosixPath("files") / run_path, run_path, "raw path step evidence", source=snapshot
                )
            )
        if not required.issubset(names):
            raise RetainError(f"raw step {step_id} lacks " + ", ".join(sorted(required - names)))
    return planned


def _project(
    context: HostedContext,
    run: SourceRoot,
    spec: Spec,
    spec_snapshot: Snapshot,
    snapshots: dict[Path, Snapshot],
) -> tuple[dict, list[PlannedFile]]:
    source, projected, _ = _manifest(context, run, spec, spec_snapshot, snapshots)
    containers = _containers(source, spec)
    projected["containers"] = containers
    projected["defense"] = _defense(source, spec)
    if spec.atomics is not None:
        atomic = source.get("atomic_red_team")
        if not isinstance(atomic, dict) or atomic.get("commit") != spec.atomics.commit:
            raise RetainError("the source Atomic Red Team commit differs from the tracked spec")
        projected["atomic_red_team"] = {"commit": atomic["commit"]}
    activity = source.get("activity")
    if spec.activity is not None and not isinstance(activity, dict):
        raise RetainError("the source manifest has no activity context required by the tracked spec")
    if spec.activity is None and activity is not None:
        raise RetainError("the source manifest has activity that is absent from the tracked spec")
    projected["activity"] = activity
    projected["weaknesses"] = source.get("weaknesses") or []
    projected["path"] = source.get("path")
    capture, packet_files = _packet_files(run, source, spec, containers, snapshots)
    projected["packet_capture"] = capture
    projected.update(
        {
            "result": "sealed",
            "reason": None,
            "exit_code": 0,
            "teardown_complete": True,
            "recording_clock": _docker_clock(run, snapshots),
        }
    )
    manifest_bytes = _json_data(projected)
    planned = [
        PlannedFile(
            PurePosixPath("files/manifest.json"),
            PurePosixPath("manifest.json"),
            "minimal truthful run context",
            payload=manifest_bytes,
        ),
        PlannedFile(
            PurePosixPath("files") / spec_snapshot.path.name,
            PurePosixPath(spec_snapshot.path.name),
            "exact tracked run spec",
            source=spec_snapshot,
        ),
        *_wazuh_files(run, spec, snapshots),
        *_step_files(run, source, spec, snapshots),
        *packet_files,
    ]
    return projected, planned


def _validate_plan(planned: list[PlannedFile], prefix: PurePosixPath) -> list[PlannedFile]:
    planned.sort(key=lambda entry: entry.stored_path.as_posix())
    for attribute in ("stored_path", "run_path"):
        values = [getattr(entry, attribute).as_posix() for entry in planned]
        if len(values) != len(set(values)):
            raise RetainError(f"the selected files collide at {attribute}")
    artifacts = [(prefix / entry.stored_path).as_posix() for entry in planned]
    if len(artifacts) != len(set(artifacts)):
        raise RetainError("the selected files collide in the hosted artifact")
    total = sum(entry.bytes for entry in planned)
    if total > MAX_RETAINED_BYTES:
        raise RetainError(
            f"the selected retained files total {total} bytes, above the {MAX_RETAINED_BYTES}-byte limit"
        )
    return planned


def _write_payload(destination: Path, payload: bytes, what: str) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(destination, flags, 0o600)
        with os.fdopen(descriptor, "wb") as target:
            target.write(payload)
            target.flush()
            os.fsync(target.fileno())
    except OSError as error:
        raise RetainError(f"cannot write {what}: {error}") from error


def _copy_snapshot(snapshot: Snapshot, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    write_flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    source_fd, source_parent, source_leaf = _open_locator(snapshot.locator, snapshot.what)
    try:
        target_fd = os.open(destination, write_flags, 0o600)
    except OSError as error:
        _close_locator(source_fd, source_parent)
        raise RetainError(f"cannot copy {snapshot.what}: {error}") from error
    digest = hashlib.sha256()
    count = 0
    try:
        before = os.fstat(source_fd)
        if _signature(before) != snapshot.signature:
            raise RetainError(f"{snapshot.what} changed before it was copied")
        with (
            os.fdopen(source_fd, "rb", closefd=False) as source,
            os.fdopen(target_fd, "wb", closefd=False) as target,
        ):
            while block := source.read(1024 * 1024):
                target.write(block)
                digest.update(block)
                count += len(block)
            target.flush()
            os.fsync(target.fileno())
        after = os.fstat(source_fd)
        named = _named_status(snapshot.locator, source_parent, source_leaf)
    finally:
        _close_locator(source_fd, source_parent)
        os.close(target_fd)
    if (
        _signature(after) != snapshot.signature
        or _signature(named) != snapshot.signature
        or count != snapshot.bytes
        or digest.hexdigest() != snapshot.sha256
    ):
        raise RetainError(f"{snapshot.what} changed while it was copied")
    copied, _ = _capture(destination, f"the copy of {snapshot.what}")
    if copied.bytes != snapshot.bytes or copied.sha256 != snapshot.sha256:
        raise RetainError(f"the copy of {snapshot.what} differs from its source")


def _provenance(
    context: HostedContext,
    spec: Spec,
    projected: dict,
    prefix: PurePosixPath,
    planned: list[PlannedFile],
) -> dict:
    artifact = f"{spec.range}-run-{context.run_attempt}"
    return {
        "schema": retained.SCHEMA,
        "source": {
            "repository": context.repository,
            "workflow": context.workflow.as_posix(),
            "run_id": context.run_id,
            "run_attempt": context.run_attempt,
            "job": context.job,
            "head": context.head[:12],
            "run_url": context.run_url,
            "artifact": artifact,
        },
        "run": {
            "id": projected["run_id"],
            "spec": Path(projected["spec"]["file"]).name,
            "result": "sealed",
            "exit_code": 0,
        },
        "files": [
            {
                "stored_path": entry.stored_path.as_posix(),
                "run_path": entry.run_path.as_posix(),
                "artifact_path": (prefix / entry.stored_path).as_posix(),
                "role": entry.role,
                "bytes": entry.bytes,
            }
            for entry in planned
        ],
    }


def _publish(work: Path, out: Path) -> None:
    """Atomically move ``work`` to a name that must still be absent."""

    library = ctypes.CDLL(None, use_errno=True)
    try:
        rename = library.renameat2
    except AttributeError as error:
        raise RetainError("this hosted runner cannot publish without replacing an existing path") from error
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(AT_FDCWD, os.fsencode(work), AT_FDCWD, os.fsencode(out), RENAME_NOREPLACE) == 0:
        return
    number = ctypes.get_errno()
    if number == errno.EEXIST:
        raise RetainError(f"{out} appeared while the retained candidate was being written")
    raise RetainError(f"cannot publish {out} without replacement: {os.strerror(number)}")


def export(
    run: Path,
    spec_path: Path,
    out: Path,
    environ: Mapping[str, str] | None = None,
) -> tuple[Path, dict]:
    """Build and atomically publish one hosted, verifier-ready retained candidate."""

    context = _hosted(os.environ if environ is None else environ)
    snapshots: dict[Path, Snapshot] = {}
    spec, spec_snapshot, _ = _tracked(context, spec_path, snapshots)
    source = _source_run(context, run)
    try:
        out, prefix = _output(context, source.original, out)
        projected, planned = _project(context, source, spec, spec_snapshot, snapshots)
        source.check()
        planned = _validate_plan(planned, prefix)
        provenance = _provenance(context, spec, projected, prefix, planned)
        provenance_bytes = _json_data(provenance)
        total = sum(entry.bytes for entry in planned) + len(provenance_bytes)
        if total > MAX_RETAINED_BYTES:
            raise RetainError(
                f"the retained candidate totals {total} bytes, above the {MAX_RETAINED_BYTES}-byte limit"
            )

        work = Path(tempfile.mkdtemp(prefix=f".{out.name}.partial-", dir=out.parent))
        published = False
        try:
            for entry in planned:
                destination = work.joinpath(*entry.stored_path.parts)
                if entry.payload is not None:
                    _write_payload(destination, entry.payload, entry.role)
                else:
                    _copy_snapshot(entry.source, destination)
            _write_payload(work / retained.PROVENANCE, provenance_bytes, retained.PROVENANCE)
            retained.verify_retained(work)
            for snapshot in snapshots.values():
                _recheck(snapshot)
            source.check()
            _publish(work, out)
            published = True
        finally:
            if not published:
                shutil.rmtree(work, ignore_errors=True)
    finally:
        source.close()
    return out, provenance


def main(
    run: Path,
    spec_path: Path,
    out: Path,
    environ: Mapping[str, str] | None = None,
) -> int:
    """CLI wrapper for the hosted retained-run exporter."""

    try:
        published, provenance = export(run, spec_path, out, environ)
    except (OSError, RetainError, retained.RetainedError) as error:
        print(f"bluefire-lab range retain: {error}", file=sys.stderr)
        return 2
    print(f"{published}: retained raw run {provenance['run']['id']}")
    print(f"declared source: {provenance['source']['run_url']}")
    print(f"artifact: {provenance['source']['artifact']}")
    return 0
