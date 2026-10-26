"""Fixed nonroot installed-workspace entry; never a lease or task minter.

Only the original inherited controller is retained. Normal service imports and
loopback binding happen after a finite authenticated startup handshake. Actual
Darwin ABI/credential/descriptor qualification is still required externally.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import socket
import stat
import sys
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, NoReturn, Protocol, cast

if TYPE_CHECKING:
    from bluefire.macos_file_access_endpoint import OriginalWorkspaceEndpoint


def _refuse(value: bool) -> None:
    if not value:
        raise RuntimeError("The original Darwin workspace bootstrap is unavailable.")


def _os_flag(name: str) -> int:
    value = getattr(os, name, None)
    _refuse(type(value) is int)
    return cast(int, value)


def _os_function(name: str) -> Callable[..., Any]:
    value = getattr(os, name, None)
    _refuse(callable(value))
    return cast(Callable[..., Any], value)


def _socket_constant(name: str) -> int:
    value = getattr(socket, name, None)
    _refuse(isinstance(value, int) and not isinstance(value, bool))
    return cast(int, value)


class _FsId(ctypes.Structure):
    _fields_ = [("values", ctypes.c_int32 * 2)]


class _StatFs(ctypes.Structure):
    # Same public 64-bit layout as secret_store._DarwinStatFs, before imports.
    _fields_ = [
        ("f_bsize", ctypes.c_uint32),
        ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", _FsId),
        ("f_owner", ctypes.c_uint32),
        ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32),
        ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * 16),
        ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024),
        ("f_flags_ext", ctypes.c_uint32),
        ("f_reserved", ctypes.c_uint32 * 7),
    ]


def _descriptor_security(descriptor: int) -> None:
    """Bootstrap's standalone copy of the existing positive no-ACL policy."""
    _refuse(
        sys.platform == "darwin" and ctypes.sizeof(_StatFs) == 2168 and _StatFs.f_flags.offset == 64
    )
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    filesystem = library.fstatfs
    filesystem.argtypes = [ctypes.c_int, ctypes.POINTER(_StatFs)]
    filesystem.restype = ctypes.c_int
    details = _StatFs()
    _refuse(filesystem(descriptor, ctypes.byref(details)) == 0 and not details.f_flags & 0x00200000)
    query = library.acl_get_fd_np
    query.argtypes = [ctypes.c_int, ctypes.c_int]
    query.restype = ctypes.c_void_p
    entry = library.acl_get_entry
    entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    entry.restype = ctypes.c_int
    release = library.acl_free
    release.argtypes = [ctypes.c_void_p]
    release.restype = ctypes.c_int
    ctypes.set_errno(0)
    acl = query(descriptor, 0x100)
    error = ctypes.get_errno()
    if not acl:
        _refuse(error == errno.ENOENT)
        return
    item = ctypes.c_void_p()
    try:
        ctypes.set_errno(0)
        result = entry(acl, 0, ctypes.byref(item))
        error = ctypes.get_errno()
    finally:
        _refuse(release(acl) == 0)
    _refuse(result == -1 and error == errno.EINVAL and item.value is None)


def _directory(path: Path, *, owner: int = 0) -> None:
    descriptor = os.open(
        path, os.O_RDONLY | _os_flag("O_DIRECTORY") | _os_flag("O_NOFOLLOW") | _os_flag("O_CLOEXEC")
    )
    try:
        details = os.fstat(descriptor)
        _refuse(
            stat.S_ISDIR(details.st_mode)
            and details.st_uid == owner
            and not details.st_mode & 0o022
            and os.path.samestat(details, path.lstat())
        )
        _descriptor_security(descriptor)
    finally:
        os.close(descriptor)


def _parents(path: Path) -> None:
    _refuse(path.is_absolute())
    for directory in (path, *path.parents):
        _directory(directory)


def _import_inventory(roots: list[str], expected: dict[str, str]) -> None:
    """No-site import roots contain only individually pinned importable files."""
    _refuse(
        type(roots) is list
        and 0 < len(roots) <= 8
        and len(set(roots)) == len(roots)
        and type(expected) is dict
        and 0 < len(expected) <= 4096
    )
    seen = set()
    directories = 0
    total = 0

    def walk_error(error: OSError) -> NoReturn:
        raise error

    for name in roots:
        root = Path(name)
        _refuse(root.is_absolute())
        _parents(root.parent)
        try:
            root.lstat()
        except FileNotFoundError:
            # CPython's fixed zip search path may be absent below protected parents.
            _refuse(root.suffix == ".zip" and str(root) not in expected)
            continue
        if root.is_file():
            _refuse(root.suffix == ".zip" and str(root) in expected)
            _protected_file(root, expected[str(root)])
            seen.add(str(root))
            total += root.lstat().st_size
            continue
        _directory(root)
        for directory, children, files in os.walk(root, followlinks=False, onerror=walk_error):
            directories += 1
            _refuse(directories <= 4096)
            _directory(Path(directory))
            for child in children:
                _directory(Path(directory) / child)
            for leaf in files:
                path = Path(directory) / leaf
                if path.suffix not in (".py", ".pyc", ".so", ".zip"):
                    continue
                _refuse(str(path) in expected)
                if str(path) in seen:
                    continue
                _protected_file(path, expected[str(path)])
                seen.add(str(path))
                total += path.lstat().st_size
                _refuse(total <= 256 * 1024 * 1024)
    _refuse(seen == set(expected) and total <= 256 * 1024 * 1024)


class _FDInfo(ctypes.Structure):
    # Public proc_fdinfo, XNU ac9718fb bsd/sys/proc_info.h; SDK proof is external.
    _fields_ = [("descriptor", ctypes.c_int32), ("kind", ctypes.c_uint32)]


class _ShortBSD(ctypes.Structure):
    # Public proc_bsdshortinfo, pinned XNU proc_info.h:79; no start-time fields.
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("parent", ctypes.c_uint32),
        ("group", ctypes.c_uint32),
        ("status", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("flags", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("real_uid", ctypes.c_uint32),
        ("real_gid", ctypes.c_uint32),
        ("saved_uid", ctypes.c_uint32),
        ("saved_gid", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
    ]


def _short_parent(parent: int) -> None:
    _refuse(
        type(parent) is int
        and 1 < parent < 2**31
        and ctypes.sizeof(_ShortBSD) == 64
        and _ShortBSD.uid.offset == 36
        and _ShortBSD.saved_gid.offset == 56
    )
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    query = library.proc_pidinfo
    query.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    query.restype = ctypes.c_int
    facts = _ShortBSD()
    _refuse(
        query(parent, 13, 0, ctypes.byref(facts), ctypes.sizeof(facts)) == 64
        and facts.pid == parent
        and 1 <= facts.status <= 4
        and facts.flags & 0x10
        and not facts.flags & 0x7
        and facts.uid == facts.real_uid == facts.saved_uid == 0
        and facts.gid == facts.real_gid == facts.saved_gid == 0
    )


def _parent_current(recipe, stream: socket.socket) -> None:
    parent = recipe["creator_pid"]
    _refuse(os.getppid() == parent)
    _short_parent(parent)
    _parent_image(parent, Path(recipe["python"]))
    _peer_root(stream)
    stream.getpeername()
    _short_parent(parent)
    _refuse(os.getppid() == parent)
    # The original direct parent cannot exit/reuse its PID without orphaning this
    # child. These observations plus the inherited channel are not PID adoption,
    # cached peer credentials alone, or a child-read creator start-time claim.


def _inventory(descriptor: int) -> None:
    _refuse(ctypes.sizeof(_FDInfo) == 8 and _FDInfo.kind.offset == 4)
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    query = library.proc_pidinfo
    query.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    query.restype = ctypes.c_int
    rows = (_FDInfo * 128)()
    expected = {(0, 1), (1, 1), (2, 1), (descriptor, 2)}
    for _attempt in range(2):
        count = query(os.getpid(), 1, 0, ctypes.byref(rows), ctypes.sizeof(rows))
        _refuse(0 < count < ctypes.sizeof(rows) and count % ctypes.sizeof(_FDInfo) == 0)
        actual = [(row.descriptor, row.kind) for row in rows[: count // 8]]
        _refuse(len(actual) == 4 and set(actual) == expected)
    for number in (0, 1, 2):
        details = os.fstat(number)
        _refuse(stat.S_ISCHR(details.st_mode))
    _refuse(stat.S_ISSOCK(os.fstat(descriptor).st_mode))


def _parent_image(parent: int, expected: Path) -> None:
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    query = library.proc_pidpath
    query.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    query.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(4096)
    count = query(parent, buffer, len(buffer))
    _refuse(0 < count < len(buffer) and bool(buffer.value))
    visible = Path(buffer.value.decode("utf-8", "strict"))
    _refuse(visible.is_absolute() and os.path.samestat(visible.stat(), expected.stat()))


def _peer_root(stream: socket.socket) -> None:
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    query = library.getpeereid
    query.argtypes = [
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    query.restype = ctypes.c_int
    uid, gid = ctypes.c_uint32(), ctypes.c_uint32()
    _refuse(
        query(stream.fileno(), ctypes.byref(uid), ctypes.byref(gid)) == 0
        and uid.value == gid.value == 0
    )


def _recipe(raw: str):
    _refuse(0 < len(raw.encode("utf-8")) <= 128 * 1024)

    def unique(pairs):
        result = {}
        for key, value in pairs:
            _refuse(key not in result)
            result[key] = value
        return result

    def reject(_value):
        _refuse(False)

    value = json.loads(raw, object_pairs_hook=unique, parse_constant=reject)
    fields = {
        "schema_version",
        "binding",
        "binding_digest",
        "python",
        "python_sha256",
        "package_root",
        "source_sha256",
        "workspace_root",
        "runner_binary",
        "runner_sha256",
        "config",
        "port",
        "creator_pid",
        "creator_start",
        "nonce",
        "handshake_deadline_ns",
        "runtime_import_roots",
        "runtime_sha256",
        "pycache_root",
    }
    _refuse(
        type(value) is dict
        and set(value) == fields
        and value["schema_version"] == "bluefire.macos-workspace-bootstrap.v1"
    )
    return value


def _protected_file(path: Path, digest: str, *, links: int = 1) -> None:
    descriptor = os.open(path, os.O_RDONLY | _os_flag("O_NOFOLLOW") | _os_flag("O_CLOEXEC"))
    try:
        before = os.fstat(descriptor)
        _refuse(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == 0
            and not before.st_mode & 0o6022
            and before.st_nlink == links
            and before.st_size <= 256 * 1024 * 1024
            and os.path.samestat(before, path.lstat())
        )
        _descriptor_security(descriptor)
        checksum = hashlib.sha256()
        size = 0
        while True:
            raw = os.read(descriptor, 64 * 1024)
            if not raw:
                break
            size += len(raw)
            _refuse(size <= before.st_size)
            checksum.update(raw)
        after = os.fstat(descriptor)
        _refuse(
            size == before.st_size
            and checksum.hexdigest() == digest
            and (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_uid,
                before.st_gid,
                before.st_size,
                before.st_mtime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_uid,
                after.st_gid,
                after.st_size,
                after.st_mtime_ns,
            )
        )
    finally:
        os.close(descriptor)


def _handshake(descriptor: int, recipe):
    _refuse(
        bool(sys.flags.isolated)
        and bool(sys.flags.no_site)
        and sys.dont_write_bytecode
        and sys.implementation.name == "cpython"
        and sys.version_info[:3] in ((3, 10, 16), (3, 11, 18))
        and sys.platform == "darwin"
        and type(descriptor) is int
        and descriptor >= 3
    )
    _inventory(descriptor)
    package = Path(recipe["package_root"])
    _refuse(
        Path(__file__).absolute() == package / "bluefire/macos_file_access_workspace_bootstrap.py"
    )
    _parents(package)
    _refuse(type(recipe["source_sha256"]) is dict)
    installation = {}
    for name, digest in recipe["source_sha256"].items():
        relative = Path(name)
        _refuse(
            not relative.is_absolute()
            and relative.as_posix() == name
            and not any(part in ("", ".", "..") for part in relative.parts)
        )
        installation[str(package / name)] = digest
    _import_inventory([str(package)], installation)
    _refuse(sys.path == recipe["runtime_import_roots"])
    _import_inventory(recipe["runtime_import_roots"], recipe["runtime_sha256"])
    pycache = Path(recipe["pycache_root"])
    _parents(pycache)
    _refuse(sys.pycache_prefix == str(pycache) and not os.listdir(pycache))
    # The only application import root is the independently protected installation.
    sys.path.insert(0, str(package))
    if __name__ == "__main__":
        canonical_name = "bluefire.macos_file_access_workspace_bootstrap"
        _refuse(canonical_name not in sys.modules)
        sys.modules[canonical_name] = sys.modules[__name__]
    from bluefire import macos_file_access_workspace as api
    from bluefire.macos_file_access_contract import validate_binding
    from bluefire.macos_file_access_endpoint import OriginalWorkspaceEndpoint
    from bluefire.macos_file_access_peer import _query_bsd, _supported_runtime
    from bluefire.util import content_hash

    _refuse(_supported_runtime())
    binding = validate_binding(recipe["binding"])
    _refuse(
        recipe["binding_digest"] == content_hash(binding)
        and type(recipe["handshake_deadline_ns"]) is int
        and 0 < recipe["handshake_deadline_ns"] <= binding["original_deadline_ns"]
        and type(recipe["nonce"]) is str
        and len(recipe["nonce"]) == 64
        and all(c in "0123456789abcdef" for c in recipe["nonce"])
        and _os_function("getsid")(0) == _os_function("getpgrp")() == os.getpid()
    )
    selected = binding["owner"]
    facts = _query_bsd(os.getpid())
    actual = {
        "real_uid": facts.real_uid,
        "effective_uid": facts.uid,
        "saved_uid": facts.saved_uid,
        "real_gid": facts.real_gid,
        "effective_gid": facts.gid,
        "saved_gid": facts.saved_gid,
        "groups": sorted(set(_os_function("getgroups")()) | {api._posix_id("getegid")}),
    }
    _refuse(
        actual == selected
        and api._posix_id("getuid") == api._posix_id("geteuid") == selected["effective_uid"]
        and api._posix_id("getgid") == api._posix_id("getegid") == selected["effective_gid"]
        and os.getppid() == recipe["creator_pid"]
    )
    _protected_file(Path(recipe["python"]), recipe["python_sha256"], links=2)
    _refuse(os.path.samestat(Path(sys.executable).stat(), Path(recipe["python"]).stat()))
    _protected_file(Path(recipe["runner_binary"]), recipe["runner_sha256"])
    workspace = Path(recipe["workspace_root"])
    _refuse(workspace == api.WORKSPACE_PARENT / binding["generation"])
    _parents(api.WORKSPACE_PARENT)
    for directory in (workspace, workspace / "runs"):
        _directory(directory, owner=selected["effective_uid"])
        details = directory.lstat()
        _refuse(
            stat.S_ISDIR(details.st_mode)
            and details.st_uid == selected["effective_uid"]
            and stat.S_IMODE(details.st_mode) == 0o700
        )
    api._config(recipe["config"], workspace)
    _refuse(type(recipe["port"]) is int and 0 <= recipe["port"] <= 65535)
    expected_environment = {
        **api._ENV,
        "HOME": str(workspace),
        "BLUEFIRE_MACOS_RUNNER": recipe["runner_binary"],
        "BLUEFIRE_MACOS_SANDBOX": str(workspace / "sandbox"),
    }
    _refuse(dict(os.environ) == expected_environment)
    _inventory(descriptor)
    stream = socket.socket(fileno=descriptor)
    stream.set_inheritable(False)
    _refuse(
        stream.family == _socket_constant("AF_UNIX")
        and stream.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM
        and stream.getpeername() in ("", b"")
        and stream.getsockname() in ("", b"")
    )
    _peer_root(stream)
    value: OriginalWorkspaceEndpoint = object.__new__(OriginalWorkspaceEndpoint)
    value._stream, value._recipe, value._api = stream, recipe, api
    value._parent_guard = _parent_current
    value._closed = value._poisoned = value.local_cleanup_unknown = False
    value._clock = (0, 0)
    value._child_pid = os.getpid()
    value._fork_guard = threading.Lock()
    value._io_lock = threading.RLock()
    value._sequence = 0
    try:
        _os_function("register_at_fork")(
            before=value._before_fork,
            after_in_parent=value._after_fork_parent,
            after_in_child=value._after_fork_child,
        )

        def guard() -> float:
            return value.assert_current(handshake=True)

        guard()
        api._require(recipe["handshake_deadline_ns"] - value._clock[1] <= api.HANDSHAKE_NS)
        api._send(
            stream,
            {
                "schema_version": "bluefire.macos-workspace-ready.v1",
                "nonce": recipe["nonce"],
                "binding_digest": recipe["binding_digest"],
                "pid": os.getpid(),
                "owner": selected,
                "handshake_deadline_ns": recipe["handshake_deadline_ns"],
            },
            guard,
        )
        _refuse(
            api._receive(stream, guard)
            == {
                "schema_version": "bluefire.macos-workspace-go.v1",
                "nonce": recipe["nonce"],
                "binding_digest": recipe["binding_digest"],
                "handshake_deadline_ns": recipe["handshake_deadline_ns"],
            }
        )
        guard()
        api._send(
            stream,
            {
                "schema_version": "bluefire.macos-workspace-handshake-complete.v1",
                "nonce": recipe["nonce"],
                "binding_digest": recipe["binding_digest"],
            },
            guard,
        )
        guard()
        return value
    except BaseException:
        value.close()
        raise


class _WorkspaceServiceEndpoint(Protocol):
    _macos_workspace_endpoint: OriginalWorkspaceEndpoint


def _normal_entry(endpoint: OriginalWorkspaceEndpoint) -> None:
    endpoint.assert_current(handshake=True)
    # No service constructor/import is reachable until the original Go succeeds.
    from bluefire.api import generate_browser_bootstrap_capability, serve
    from bluefire.service import BlueFireService

    recipe = endpoint._recipe
    config = endpoint._api._config(recipe["config"], Path(recipe["workspace_root"]))
    capability = generate_browser_bootstrap_capability()
    workspace = Path(recipe["workspace_root"])
    endpoint.assert_current()
    (workspace / "sandbox").mkdir(mode=0o700, parents=False, exist_ok=False)
    service = BlueFireService(config=config, runs_dir=workspace / "runs")
    cast(_WorkspaceServiceEndpoint, service)._macos_workspace_endpoint = endpoint
    stop = threading.Event()
    stopped = threading.Event()
    monitor: threading.Thread | None = None

    def ready(server):
        nonlocal monitor

        def guard() -> float:
            return endpoint.assert_current(handshake=True)

        guard()
        address = server.server_address
        _refuse(
            type(address) is tuple
            and len(address) == 2
            and address[0] == "127.0.0.1"
            and type(address[1]) is int
            and 0 < address[1] <= 65535
            and (not recipe["port"] or address[1] == recipe["port"])
        )
        endpoint._api._send(
            endpoint._stream,
            {
                "schema_version": "bluefire.macos-workspace-ui-ready.v1",
                "nonce": recipe["nonce"],
                "binding_digest": recipe["binding_digest"],
                "host": address[0],
                "port": address[1],
                "browser_bootstrap_capability": capability,
            },
            guard,
        )
        guard()

        def watch():
            try:
                while not stop.wait(0.025):
                    endpoint.check_idle()
            except BaseException:
                endpoint._poisoned = True
                server.shutdown()
            finally:
                stopped.set()

        monitor = threading.Thread(target=watch, name="macos-workspace-original-lease", daemon=True)
        monitor.start()

    try:
        serve(
            service,
            host="127.0.0.1",
            port=recipe["port"],
            browser_bootstrap_capability=capability,
            on_ready=ready,
        )
    finally:
        stop.set()
        try:
            endpoint.close()
        finally:
            try:
                if monitor is not None:
                    monitor.join(timeout=1)
                    _refuse(stopped.is_set())
            finally:
                # Also attempt local service settlement if serve's server_close
                # raised before its own service.close. This is not task closure.
                service.close()


def main() -> int:
    _refuse(len(sys.argv) == 3 and sys.argv[1].isdecimal())
    recipe = _recipe(sys.argv[2])
    endpoint = _handshake(int(sys.argv[1]), recipe)
    try:
        _normal_entry(endpoint)
    finally:
        endpoint.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
