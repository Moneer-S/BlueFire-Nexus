"""Original creator's fixed normal-workspace launch, not task authority.

The host child may spawn contained tasks. It is never labelled a no-fork native
worker. Popen construction has no hard timeout; late/uncertain construction
cannot receive Go, and its exact provisional object remains retained.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import secrets
import socket
import stat
import subprocess  # nosec B404
import sys
import threading
import time
from _thread import LockType
from _thread import RLock as RLockType
from pathlib import Path, PurePosixPath
from typing import Any, Callable, NoReturn, Protocol, cast

from . import macos_file_access_workspace_validation as validation
from . import runner_lifecycle as host
from .config import AutonomyLevel, BlueFireConfig, EnvironmentType
from .macos_file_access_contract import MacOSFileAccessContractError, validate_binding
from .macos_file_access_creator import MacOSFileAccessCreator
from .macos_file_access_peer import (
    MacOSChildConsistency,
    _query_bsd,
    _supported_runtime,
    darwin_clock_ns,
    observe_owned_child,
)
from .runner_client import _pinned_launch_file
from .secret_store import _validate_darwin_descriptor_security
from .util import canonical_json_bytes, content_hash

WORKSPACE_PARENT = Path("/private/var/db/bluefire-file-access-workspaces")
HANDSHAKE_NS = 5_000_000_000
FRAME_MAX = 16_384
RECIPE_MAX = 128 * 1024
SOURCE_MAX = 256 * 1024 * 1024
HELD_DIRECTORY_MAX = 64
_IDS = ("real_uid", "effective_uid", "saved_uid", "real_gid", "effective_gid", "saved_gid")
_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}


def _missing() -> NoReturn:
    raise MacOSFileAccessContractError("The original Darwin workspace is unavailable.")


def _require(value: bool) -> None:
    if not value:
        _missing()


def _posix_id(name: str) -> int:
    function = getattr(os, name, None)
    if not callable(function):
        _missing()
    value = function()
    _require(type(value) is int and value >= 0)
    return cast(int, value)


def _os_flag(name: str) -> int:
    value = getattr(os, name, None)
    _require(type(value) is int)
    return cast(int, value)


def _socket_constant(name: str) -> int:
    value = getattr(socket, name, None)
    if not isinstance(value, int) or isinstance(value, bool):
        _missing()
    return value


def _root() -> None:
    _require(
        _supported_runtime()
        and sys.implementation.name == "cpython"
        and sys.version_info[:3] == (3, 10, 16)
        and _posix_id("getuid")
        == _posix_id("geteuid")
        == _posix_id("getgid")
        == _posix_id("getegid")
        == 0
    )


def _identity(details: os.stat_result) -> tuple[int, ...]:
    return tuple(
        getattr(details, key)
        for key in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size", "st_mtime_ns")
    )


def _directory(
    path: Path, stack: contextlib.ExitStack, retained: dict[str, Any], *, owner: int = 0
) -> None:
    if str(path) in retained:
        row = retained[str(path)]
        details = os.fstat(row["fd"])
        _require(
            list(_identity(details)[:5]) == row["identity"]
            and os.path.samestat(details, path.lstat())
        )
        _validate_darwin_descriptor_security(row["fd"])
        return
    _require(len(retained) < HELD_DIRECTORY_MAX)
    descriptor = os.open(
        path, os.O_RDONLY | _os_flag("O_DIRECTORY") | _os_flag("O_NOFOLLOW") | _os_flag("O_CLOEXEC")
    )
    stack.callback(os.close, descriptor)
    details = os.fstat(descriptor)
    _require(
        stat.S_ISDIR(details.st_mode)
        and details.st_uid == owner
        and not details.st_mode & 0o022
        and os.path.samestat(details, path.lstat())
    )
    _validate_darwin_descriptor_security(descriptor)
    retained[str(path)] = {
        "path": str(path),
        "fd": descriptor,
        "identity": list(_identity(details)[:5]),
    }


def _parents(path: Path, stack: contextlib.ExitStack, retained: dict[str, Any]) -> None:
    _require(path.is_absolute())
    for parent in (path, *path.parents):
        _directory(parent, stack, retained)


def _file(
    path: Path,
    expected: str,
    stack: contextlib.ExitStack,
    directories: dict[str, Any],
    *,
    retain: bool = True,
    hold_parents: bool = True,
) -> dict[str, Any]:
    _require(
        type(expected) is str
        and len(expected) == 64
        and all(c in "0123456789abcdef" for c in expected)
    )
    if not retain:
        with contextlib.ExitStack() as transient:
            row = _file(path, expected, transient, {}, hold_parents=False)
            return {**row, "fd": None}
    if hold_parents:
        _parents(path.parent, stack, directories)
    else:
        validation._parents(path.parent)
    descriptor = os.open(path, os.O_RDONLY | _os_flag("O_NOFOLLOW") | _os_flag("O_CLOEXEC"))
    stack.callback(os.close, descriptor)
    before = os.fstat(descriptor)
    _require(
        stat.S_ISREG(before.st_mode)
        and before.st_uid == 0
        and not before.st_mode & 0o6022
        and before.st_nlink == 1
        and before.st_size <= SOURCE_MAX
        and os.path.samestat(before, path.lstat())
    )
    _validate_darwin_descriptor_security(descriptor)
    digest = hashlib.sha256()
    count = 0
    while True:
        data = os.read(descriptor, 64 * 1024)
        if not data:
            break
        count += len(data)
        _require(count <= SOURCE_MAX)
        digest.update(data)
    after = os.fstat(descriptor)
    _require(
        count == before.st_size
        and digest.hexdigest() == expected
        and _identity(before) == _identity(after)
    )
    return {
        "path": str(path),
        "sha256": expected,
        "identity": list(_identity(before)),
        "fd": descriptor,
    }


def _config(document: Any, workspace: Path) -> BlueFireConfig:
    config = BlueFireConfig.from_mapping(document)
    _require(config.ai.autonomy is AutonomyLevel.OFF and not config.ai.enabled)
    for profile in config.runner_profiles:
        _require(
            profile.environment_type is EnvironmentType.DISPOSABLE
            and profile.runner_binary.env == "BLUEFIRE_MACOS_RUNNER"
            and profile.sandbox_root.env == "BLUEFIRE_MACOS_SANDBOX"
            and not profile.secrets
            and not profile.native_tool_installations
            and not profile.network_allowlist
            and "macos" in profile.platforms
        )
    return config


def _decode(raw: bytes) -> dict[str, Any]:
    def unique(pairs):
        value = {}
        for key, item in pairs:
            _require(key not in value)
            value[key] = item
        return value

    def reject(_value):
        _require(False)

    _require(0 < len(raw) <= FRAME_MAX)
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=reject)
    _require(type(value) is dict and canonical_json_bytes(value) == raw)
    return cast(dict[str, Any], value)


def _send(stream: socket.socket, document: dict[str, Any], guard) -> None:
    raw = canonical_json_bytes(document)
    _require(0 < len(raw) <= FRAME_MAX)
    remaining = memoryview(len(raw).to_bytes(4, "little") + raw)
    while remaining:
        stream.settimeout(guard())
        count = stream.send(remaining)
        _require(type(count) is int and 0 < count <= len(remaining))
        remaining = remaining[count:]
    guard()


def _receive(stream: socket.socket, guard) -> dict[str, Any]:
    def exact(size):
        value = bytearray()
        while len(value) < size:
            stream.settimeout(guard())
            receive = getattr(stream, "recvmsg", None)
            _require(callable(receive))
            try:
                raw, ancillary, flags, _address = receive(size - len(value), 0)
            except TimeoutError:
                # Preserve partial framing while the original finite guard
                # checks cancellation/lifetime between short socket waits.
                continue
            _require(bool(raw) and len(raw) <= size - len(value) and not ancillary and not flags)
            value.extend(raw)
        guard()
        return bytes(value)

    length = int.from_bytes(exact(4), "little")
    _require(0 < length <= FRAME_MAX)
    return _decode(exact(length))


class _WorkspaceBridgeLifecycle(Protocol):
    def start(self) -> None: ...

    def close(self) -> None: ...

    def join(self) -> None: ...


def _start_bridge(
    owner: MacOSWorkspaceOwner,
    factory: Callable[[MacOSWorkspaceOwner], _WorkspaceBridgeLifecycle],
) -> None:
    owner._bridge = factory(owner)
    owner._bridge.start()


class MacOSWorkspaceOwner:
    """Retained original host and endpoint; documents cannot recreate this owner."""

    _creator: MacOSFileAccessCreator
    _binding: dict[str, Any]
    _recipe: dict[str, Any]
    _pins: contextlib.ExitStack
    _files: list[dict[str, Any]]
    _directories: dict[str, Any]
    _stream: socket.socket | None
    _child_stream: socket.socket | None
    _stream_closed: bool
    _child_closed: bool
    _cleanup_unknown: bool
    _creation_unknown: bool
    _process: subprocess.Popen[bytes] | None
    _launch: host._LaunchProcess | None
    _owned: host._OwnedHostProcess | None
    _consistency: MacOSChildConsistency | None
    _started: bool
    _state: str
    _clock: tuple[int, int]
    _lock: LockType
    _fork_guard: LockType
    _ui_ready: dict[str, Any]
    _creator_pid: int
    _channel_lock: RLockType
    _bridge: _WorkspaceBridgeLifecycle | None

    def __new__(cls, *_args, **_kwargs) -> MacOSWorkspaceOwner:
        raise TypeError("The original privileged workspace preparation is required.")

    @classmethod
    def prepare(
        cls,
        creator: MacOSFileAccessCreator,
        *,
        python: Path,
        python_sha256: str,
        package_root: Path,
        source_sha256: dict[str, str],
        runtime_import_roots: list[str],
        runtime_sha256: dict[str, str],
        workspace_root: Path,
        config: BlueFireConfig,
        retained: list[MacOSWorkspaceOwner],
        port: int = 0,
    ) -> MacOSWorkspaceOwner:
        _root()
        _require(
            type(creator) is MacOSFileAccessCreator
            and type(retained) is list
            and not retained
            and type(config) is BlueFireConfig
            and type(port) is int
            and 0 <= port <= 65535
            and type(source_sha256) is dict
            and 1 <= len(source_sha256) <= 1024
        )
        binding = validate_binding(creator.review_context("baseline")["binding"])
        _require(workspace_root == WORKSPACE_PARENT / binding["generation"])
        for directory in (workspace_root, workspace_root / "runs"):
            details = directory.lstat()
            _require(
                stat.S_ISDIR(details.st_mode)
                and details.st_uid == binding["owner"]["effective_uid"]
                and stat.S_IMODE(details.st_mode) == 0o700
            )
        _require(
            set(os.listdir(workspace_root)) == {"runs"} and not os.listdir(workspace_root / "runs")
        )
        _config(config.to_dict(), workspace_root)
        _require(
            package_root.is_absolute()
            and python.is_absolute()
            and {
                "bluefire/__init__.py",
                "bluefire/macos_file_access_workspace.py",
                "bluefire/macos_file_access_workspace_bootstrap.py",
                "bluefire/macos_file_access_workspace_validation.py",
                "bluefire/macos_file_access_endpoint.py",
                "bluefire/service.py",
                "bluefire/api.py",
            }
            <= set(source_sha256)
        )
        value = object.__new__(cls)
        value._creator, value._binding = creator, binding
        value._pins = contextlib.ExitStack()
        value._files = []
        value._directories = {}
        value._stream = value._child_stream = None
        value._stream_closed = value._child_closed = False
        value._cleanup_unknown = value._creation_unknown = False
        value._process = value._launch = value._owned = value._consistency = None
        value._started = False
        value._state = "preparing"
        value._clock = (0, 0)
        value._creator_pid = os.getpid()
        value._lock = threading.Lock()
        value._fork_guard = threading.Lock()
        value._channel_lock = threading.RLock()
        value._bridge = None
        value._lock.acquire()
        retained.append(value)
        try:
            register = getattr(os, "register_at_fork", None)
            if not callable(register):
                _missing()
            register(
                before=value._before_fork,
                after_in_parent=value._after_fork_parent,
                after_in_child=value._after_fork_child,
            )
            _parents(WORKSPACE_PARENT, value._pins, value._directories)
            for directory in (workspace_root, workspace_root / "runs"):
                _directory(
                    directory,
                    value._pins,
                    value._directories,
                    owner=binding["owner"]["effective_uid"],
                )
            pycache = WORKSPACE_PARENT / "runtime-cache" / binding["generation"]
            _parents(pycache, value._pins, value._directories)
            _require(not os.listdir(pycache))
            validation._import_inventory(runtime_import_roots, runtime_sha256)
            installation = {
                str(package_root / name): digest for name, digest in source_sha256.items()
            }
            validation._import_inventory([str(package_root)], installation)
            for name in runtime_import_roots:
                root = Path(name)
                _parents(
                    root.parent if root.suffix == ".zip" else root, value._pins, value._directories
                )
            runtime = _file(python, python_sha256, value._pins, value._directories)
            _require(os.path.samestat(python.lstat(), Path(sys.executable).stat()))
            value._files.append(runtime)
            native = _file(
                creator._runtime.runner_binary,
                creator._runtime.runner_binary_digest.removeprefix("sha256:"),
                value._pins,
                value._directories,
            )
            value._files.append(native)
            _parents(package_root, value._pins, value._directories)
            total = runtime["identity"][5] + native["identity"][5]
            for name, digest in sorted(source_sha256.items()):
                relative = PurePosixPath(name)
                _require(
                    relative.as_posix() == name
                    and not relative.is_absolute()
                    and not any(part in ("", ".", "..") for part in relative.parts)
                )
                critical = name == "bluefire/macos_file_access_workspace_bootstrap.py"
                row = _file(
                    package_root / name, digest, value._pins, value._directories, retain=critical
                )
                if critical:
                    value._files.append(row)
                total += row["identity"][5]
                _require(total <= SOURCE_MAX)
            for name, digest in sorted(runtime_sha256.items()):
                row = _file(Path(name), digest, value._pins, value._directories, retain=False)
                total += row["identity"][5]
                _require(total <= SOURCE_MAX)
            parent = _query_bsd(os.getpid())
            _require(
                parent.uid == parent.real_uid == parent.saved_uid == 0
                and parent.gid == parent.real_gid == parent.saved_gid == 0
            )
            value._recipe = {
                "schema_version": "bluefire.macos-workspace-bootstrap.v1",
                "binding": binding,
                "binding_digest": content_hash(binding),
                "python": str(python),
                "python_sha256": python_sha256,
                "package_root": str(package_root),
                "source_sha256": dict(source_sha256),
                "workspace_root": str(workspace_root),
                "runtime_import_roots": list(runtime_import_roots),
                "runtime_sha256": dict(runtime_sha256),
                "pycache_root": str(pycache),
                "runner_binary": str(creator._runtime.runner_binary),
                "runner_sha256": native["sha256"],
                "config": config.to_dict(),
                "port": port,
                "creator_pid": os.getpid(),
                "creator_start": [parent.start_seconds, parent.start_microseconds],
            }
            _require(len(canonical_json_bytes(value._recipe)) <= RECIPE_MAX)
            value._state = "prepared"
            value._guard()
            return value
        except BaseException:
            value._state = "unknown"
            value._cleanup_unknown = True
            raise
        finally:
            value._lock.release()

    def _guard(self, deadline: int | None = None) -> float:
        _require(os.getpid() == self._creator_pid == self._recipe["creator_pid"])
        original = _query_bsd(os.getpid())
        _require(
            [original.start_seconds, original.start_microseconds] == self._recipe["creator_start"]
            and original.uid == original.real_uid == original.saved_uid == 0
            and original.gid == original.real_gid == original.saved_gid == 0
        )
        if self._consistency is not None:
            if self._owned is None or self._launch is None or self._process is None:
                _missing()
            _require(
                self._owned.launcher is self._process is self._launch.process
                and not host._launch_exited_without_reap(self._launch)
            )
            _require(
                observe_owned_child(
                    self._process,
                    expected_ids={key: self._binding["owner"][key] for key in _IDS},
                    expected_start=self._consistency.start,
                )
                == self._consistency
            )
        wall, monotonic = time.time_ns() // 1_000_000, darwin_clock_ns()
        limit = (
            min(self._binding["original_deadline_ns"], deadline)
            if deadline is not None
            else self._binding["original_deadline_ns"]
        )
        _require(
            self._binding["issued_at_ms"] <= wall < self._binding["expires_at_ms"]
            and monotonic < limit
            and wall >= self._clock[0]
            and monotonic >= self._clock[1]
        )
        self._clock = wall, monotonic
        return float(min((limit - monotonic) / 1e9, (self._binding["expires_at_ms"] - wall) / 1000))

    def _close_endpoint(self, child: bool = False) -> None:
        with self._channel_lock:
            with self._fork_guard:
                self._close_endpoint_locked(child)

    def _close_endpoint_locked(self, child: bool) -> None:
        name = "_child_stream" if child else "_stream"
        marker = "_child_closed" if child else "_stream_closed"
        if getattr(self, marker):
            return
        setattr(self, marker, True)
        stream = getattr(self, name)
        if stream is not None:
            try:
                stream.close()
            except BaseException:
                self._cleanup_unknown = True
                raise

    def _before_fork(self) -> None:
        self._channel_lock.acquire()
        self._fork_guard.acquire()

    def _after_fork_parent(self) -> None:
        self._fork_guard.release()
        self._channel_lock.release()

    def _after_fork_child(self) -> None:
        # CLOEXEC handles exec, not fork. Close only this process's copies;
        # never signal/reap the parent's host or release its launch-file pin.
        self._state = "unknown"
        self._creation_unknown = True
        self._lock = threading.Lock()
        self._fork_guard = threading.Lock()
        self._channel_lock = threading.RLock()
        if self._bridge is not None:
            self._bridge.close()
        for child in (False, True):
            try:
                self._close_endpoint(child)
            except BaseException:
                self._cleanup_unknown = True

    def assert_current(self) -> None:
        with self._channel_lock:
            self._assert_current_locked()

    def _assert_current_locked(self) -> None:
        try:
            self._assert_current()
        except BaseException:
            self._state = "unknown"
            try:
                self._close_endpoint()
            finally:
                self._close_endpoint(child=True)
            raise

    def _assert_current(self) -> None:
        _root()
        if (
            self._owned is None
            or self._launch is None
            or self._process is None
            or self._consistency is None
            or self._stream is None
        ):
            _missing()
        _require(
            self._state == "active"
            and not self._creation_unknown
            and not self._cleanup_unknown
            and self._owned is not None
            and self._launch is not None
            and self._owned.launcher is self._process is self._launch.process
            and not host._launch_exited_without_reap(self._launch)
        )
        self._guard()
        self._check_directories()
        current = observe_owned_child(
            self._process,
            expected_ids={key: self._binding["owner"][key] for key in _IDS},
            expected_start=self._consistency.start,
        )
        _require(
            current == self._consistency and self._stream is not None and self._stream.fileno() >= 3
        )
        self._stream.getpeername()
        self._guard()

    def _check_directories(self) -> None:
        for row in self._directories.values():
            details = os.fstat(row["fd"])
            _require(
                list(_identity(details)[:5]) == row["identity"]
                and os.path.samestat(details, Path(row["path"]).lstat())
            )
            _validate_darwin_descriptor_security(row["fd"])

    def start(
        self,
        *,
        bridge_factory: Callable[[MacOSWorkspaceOwner], _WorkspaceBridgeLifecycle] | None = None,
    ) -> None:
        if not self._lock.acquire(blocking=False):
            _require(False)
        try:
            _root()
            _require(not self._started and self._state == "prepared")
            if bridge_factory is None or not callable(bridge_factory):
                _missing()
            self._started = True
            self._guard()
            self._check_directories()
            # All descendants are root-owned, positively no-ACL protected and
            # non-writable to the workspace. Root/admin mutation is outside this
            # model; no thousands-of-FDs or adversarial snapshot-stability claim.
            validation._import_inventory(
                self._recipe["runtime_import_roots"], self._recipe["runtime_sha256"]
            )
            validation._import_inventory(
                [self._recipe["package_root"]],
                {
                    str(Path(self._recipe["package_root"]) / name): digest
                    for name, digest in self._recipe["source_sha256"].items()
                },
            )
            self._check_directories()
            self._guard()
            for row in self._files:
                _require(
                    list(_identity(os.fstat(row["fd"]))) == row["identity"]
                    and os.path.samestat(os.fstat(row["fd"]), Path(row["path"]).lstat())
                )
                _validate_darwin_descriptor_security(row["fd"])
            try:
                with self._fork_guard:
                    self._stream, self._child_stream = socket.socketpair(
                        _socket_constant("AF_UNIX"), socket.SOCK_STREAM
                    )
            except BaseException:
                self._cleanup_unknown = True
                raise
            self._stream.set_inheritable(False)
            self._child_stream.set_inheritable(False)
            deadline = min(self._binding["original_deadline_ns"], darwin_clock_ns() + HANDSHAKE_NS)
            nonce = secrets.token_hex(32)
            recipe = {**self._recipe, "nonce": nonce, "handshake_deadline_ns": deadline}
            python = Path(recipe["python"])
            launch = self._pins.enter_context(
                _pinned_launch_file(python, "sha256:" + recipe["python_sha256"])
            )
            bootstrap_path = (
                Path(recipe["package_root"]) / "bluefire/macos_file_access_workspace_bootstrap.py"
            )
            argv = [
                launch[0],
                "-I",
                "-S",
                "-B",
                "-X",
                "pycache_prefix=" + recipe["pycache_root"],
                str(bootstrap_path),
                str(self._child_stream.fileno()),
                canonical_json_bytes(recipe).decode("utf-8"),
            ]
            selected = self._binding["owner"]
            process = cast("subprocess.Popen[bytes]", subprocess.Popen.__new__(subprocess.Popen))
            self._process = process
            # This strong pin precedes __init__; never recover an unseen child by PID.
            try:
                subprocess.Popen.__init__(
                    process,
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    shell=False,
                    close_fds=True,
                    start_new_session=True,
                    pass_fds=(self._child_stream.fileno(),),
                    user=selected["effective_uid"],
                    group=selected["effective_gid"],
                    extra_groups=list(selected["groups"]),
                    umask=0o077,
                    env={
                        **_ENV,
                        "HOME": recipe["workspace_root"],
                        "BLUEFIRE_MACOS_RUNNER": recipe["runner_binary"],
                        "BLUEFIRE_MACOS_SANDBOX": str(Path(recipe["workspace_root"]) / "sandbox"),
                    },
                    cwd=recipe["workspace_root"],
                )
            except BaseException:
                self._creation_unknown = True
                raise
            self._launch = host._LaunchProcess(process=process, containment=process.pid)
            self._owned = host._retain_owned_host_process(self._launch, process.pid)
            self._close_endpoint(child=True)

            def guard() -> float:
                return self._guard(deadline)

            guard()
            ready = _receive(self._stream, guard)
            self._consistency = observe_owned_child(
                process, expected_ids={key: selected[key] for key in _IDS}
            )
            _require(
                ready
                == {
                    "schema_version": "bluefire.macos-workspace-ready.v1",
                    "nonce": nonce,
                    "binding_digest": recipe["binding_digest"],
                    "pid": process.pid,
                    "owner": selected,
                    "handshake_deadline_ns": deadline,
                }
            )
            _send(
                self._stream,
                {
                    "schema_version": "bluefire.macos-workspace-go.v1",
                    "nonce": nonce,
                    "binding_digest": recipe["binding_digest"],
                    "handshake_deadline_ns": deadline,
                },
                guard,
            )
            _require(
                _receive(self._stream, guard)
                == {
                    "schema_version": "bluefire.macos-workspace-handshake-complete.v1",
                    "nonce": nonce,
                    "binding_digest": recipe["binding_digest"],
                }
            )
            guard()
            ready = _receive(self._stream, guard)
            _require(
                set(ready)
                == {
                    "schema_version",
                    "nonce",
                    "binding_digest",
                    "host",
                    "port",
                    "browser_bootstrap_capability",
                }
                and ready["schema_version"] == "bluefire.macos-workspace-ui-ready.v1"
                and ready["nonce"] == nonce
                and ready["binding_digest"] == recipe["binding_digest"]
                and ready["host"] == "127.0.0.1"
                and type(ready["port"]) is int
                and 0 < ready["port"] <= 65535
                and (not recipe["port"] or ready["port"] == recipe["port"])
                and type(ready["browser_bootstrap_capability"]) is str
                and len(ready["browser_bootstrap_capability"]) == 64
                and all(
                    # pragma: allowlist nextline secret - public Base64url alphabet
                    c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                    for c in ready["browser_bootstrap_capability"]
                )
            )
            guard()
            self._ui_ready = dict(ready)
            self._state = "active"
            self.assert_current()
            _start_bridge(self, bridge_factory)
        except BaseException:
            self._state = "unknown"
            try:
                self._close_endpoint()
            finally:
                self._close_endpoint(child=True)
            raise
        finally:
            self._lock.release()

    def ui_readiness(self) -> dict[str, Any]:
        """Private actual address/secret; neither a grant nor a task receipt."""
        self.assert_current()
        return dict(self._ui_ready)

    def close(self) -> dict[str, Any]:
        _root()
        _require(os.getpid() == self._creator_pid)
        if not self._lock.acquire(blocking=False):
            _require(False)
        try:
            _require(self._state != "preparing")
            self._state = "retired"
            if self._bridge is not None:
                self._bridge.close()
            for child in (False, True):
                try:
                    self._close_endpoint(child)
                except BaseException:
                    pass
            if self._bridge is not None:
                try:
                    self._bridge.join()
                except BaseException:
                    self._cleanup_unknown = True
            released = self._process is None
            if self._launch is not None and not self._creation_unknown:
                released = host._terminate_contained_launch(self._launch)
            if released:
                try:
                    self._pins.close()
                except BaseException:
                    self._cleanup_unknown = True
            return {
                "scope": "original_workspace_host_only",
                "host_closed": bool(released),
                "descriptor_cleanup_unknown": self._cleanup_unknown,
                "creation_unknown": self._creation_unknown,
                "task_cleanup_proven": False,
                "whole_setup_cleanup_proven": False,
                "fixture_removed": False,
                "process_creation_hard_bound": False,
            }
        finally:
            self._lock.release()
