"""One fixed Linux runner helper with authenticated descriptor-only custody.

This client carries no target command or tool selector. The installed Rust
helper validates exact pinned descriptors, creates the guest, and retains its
process/cgroup custody until it verifies termination. Channel loss is unknown
cleanup, never a successful terminal receipt.
"""

from __future__ import annotations

import array
import contextlib
import fcntl
import hashlib
import json
import os
import select
import socket
import stat
import struct
import sys
import time
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any, Mapping

from .util import canonical_json_bytes, content_hash

_SCHEMA = "bluefire.strix-worker-runtime-ipc.v1"
_MAX_PACKET = 64 * 1024
_MAX_STARTUP_SECONDS = 30.0
_MAX_WAIT_SECONDS = 30.0
_LAUNCH_FD = 3
_LAUNCH_FIELD_ORDER = (
    "closure_mount",
    "closure_manifest",
    "interpreter",
    "bootstrap",
    "lockdown",
    "strix_entrypoint",
    "objective",
    "config",
    "mcp",
    "launch_material",
    "cancellation",
)
_OBSERVED_FD_ORDER = (
    "endpoint_directory",
    "control_listener",
    "model_listener",
    "caido_listener",
    "pidfd",
    "workspace",
)


class StrixNativeWorkerError(RuntimeError):
    """The fixed installed worker could not establish or retain custody."""


def _refuse() -> StrixNativeWorkerError:
    return StrixNativeWorkerError("installed Strix worker custody refused")


@dataclass(frozen=True, slots=True)
class FixedRuntimeDescriptorSet:
    closure_mount: int
    closure_manifest: int
    interpreter: int
    bootstrap: int
    lockdown: int
    strix_entrypoint: int
    objective: int
    config: int
    mcp: int
    launch_material: int
    cancellation: int

    def as_tuple(self) -> tuple[int, ...]:
        result = tuple(getattr(self, item.name) for item in fields(self))
        if len(result) != len(_LAUNCH_FIELD_ORDER) or any(
            type(fd) is not int or fd < 0 for fd in result
        ):
            raise _refuse()
        try:
            for descriptor in result:
                os.fstat(descriptor)
        except OSError:
            raise _refuse() from None
        return result


@dataclass(slots=True)
class OpenedWorkerContainmentDescriptors:
    """Exact live kernel handles opened from an authenticated native receipt."""

    pidfd: int
    controller_rpc_fd: int
    cgroup_fd: int
    namespace_fds: dict[str, int]
    root_fds: dict[str, int]
    input_fds: dict[str, int]
    relay_fds: dict[str, int]

    def close(self) -> None:
        descriptors = [self.pidfd, self.controller_rpc_fd, self.cgroup_fd]
        for rows in (self.namespace_fds, self.root_fds, self.input_fds, self.relay_fds):
            descriptors.extend(rows.values())
            rows.clear()
        self.pidfd = self.controller_rpc_fd = self.cgroup_fd = -1
        for descriptor in descriptors:
            if descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(descriptor)


def _canonical_packet(value: Mapping[str, Any]) -> bytes:
    try:
        payload = canonical_json_bytes(dict(value))
    except (TypeError, ValueError, RecursionError):
        raise _refuse() from None
    if not 0 < len(payload) <= _MAX_PACKET:
        raise _refuse()
    return payload


def _copy_document(value: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(_canonical_packet(value).decode("utf-8"))


def _validated_payload(payload: bytes, kinds: frozenset[str]) -> dict[str, Any]:
    try:
        row = json.loads(payload.decode("utf-8"))
        if (
            type(row) is not dict
            or row.get("schema_version") != _SCHEMA
            or row.get("kind") not in kinds
            or _canonical_packet(row) != payload
        ):
            raise _refuse()
        return row
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise _refuse() from None


def _send_packet(connection: socket.socket, value: Mapping[str, Any], rights: tuple[int, ...] = ()) -> None:
    payload = _canonical_packet(value)
    ancillary = (
        [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", rights))]
        if rights
        else []
    )
    try:
        if connection.sendmsg([payload], ancillary, socket.MSG_NOSIGNAL) != len(payload):
            raise _refuse()
    except (OSError, OverflowError):
        raise _refuse() from None


def _receive_packet(
    connection: socket.socket,
    *,
    kinds: frozenset[str],
    rights_count: int,
    helper_pid: int,
    helper_pidfd: int,
    deadline: float,
    allow_helper_exit: bool = False,
) -> tuple[dict[str, Any], tuple[int, ...], str]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _refuse()
    try:
        readable, _, _ = select.select([connection, helper_pidfd], [], [], remaining)
        if connection not in readable or (helper_pidfd in readable and not allow_helper_exit):
            raise _refuse()
        payload, ancillary, flags, _address = connection.recvmsg(
            _MAX_PACKET,
            socket.CMSG_SPACE(max(rights_count, 1) * array.array("i").itemsize)
            + socket.CMSG_SPACE(struct.calcsize("3i")),
            socket.MSG_CMSG_CLOEXEC,
        )
    except (OSError, ValueError):
        raise _refuse() from None
    received: list[int] = []
    credentials: tuple[int, int, int] | None = None
    try:
        if not payload or flags:
            raise _refuse()
        rights_seen = False
        credentials_seen = False
        for level, label, data in ancillary:
            if level != socket.SOL_SOCKET:
                raise _refuse()
            if label == socket.SCM_RIGHTS and not rights_seen:
                rights_seen = True
                if len(data) != rights_count * array.array("i").itemsize:
                    raise _refuse()
                values = array.array("i")
                values.frombytes(data)
                received.extend(values)
            elif label == socket.SCM_CREDENTIALS and not credentials_seen:
                credentials_seen = True
                if len(data) != struct.calcsize("3i"):
                    raise _refuse()
                credentials = struct.unpack("3i", data)
            else:
                raise _refuse()
        if (
            rights_seen != (rights_count > 0)
            or not credentials_seen
            or credentials != (helper_pid, os.geteuid(), os.getegid())
            or len(received) != rights_count
        ):
            raise _refuse()
        return (
            _validated_payload(payload, kinds),
            tuple(received),
            "sha256:" + hashlib.sha256(payload).hexdigest(),
        )
    except BaseException:
        for descriptor in received:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        raise


class InstalledStrixLinuxWorkerController:
    """Retains the exact helper channel and the observed guest descriptors."""

    def __init__(self, connection: socket.socket, helper_pid: int, helper_pidfd: int) -> None:
        self._connection = connection
        self._helper_pid = helper_pid
        self._helper_pidfd = helper_pidfd
        self._observed_descriptors: dict[str, int] = {}
        self._input_descriptors: dict[str, int] = {}
        self.observed: Mapping[str, Any] | None = None
        self._qualified_document: Mapping[str, Any] | None = None
        self.qualified_receipt_ref: str | None = None
        self._terminal: Mapping[str, Any] | None = None
        self._accepted_packets: list[dict[str, Any]] = []
        self._launch_identity: Mapping[str, Any] | None = None
        self.cleanup_uncertain = True
        self._closed = False

    @classmethod
    def start(
        cls,
        *,
        runner_fd: int,
        identity: Mapping[str, Any],
        descriptors: FixedRuntimeDescriptorSet,
    ) -> "InstalledStrixLinuxWorkerController":
        if sys.platform != "linux" or os.geteuid() != 0:
            raise _refuse()
        try:
            if type(runner_fd) is not int or runner_fd < 0:
                raise _refuse()
            details = os.fstat(runner_fd)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != 0
                or details.st_nlink != 1
                or details.st_mode & 0o022
                or not details.st_mode & 0o111
                or not isinstance(identity, Mapping)
            ):
                raise _refuse()
            expected_runner = identity.get("prelaunch_bindings", {}).get("boundary_helper_digest")
            if (
                type(expected_runner) is not str
                or details.st_size <= 0
                or details.st_size > 256 * 1024 * 1024
                or "sha256:" + hashlib.sha256(os.pread(runner_fd, details.st_size, 0)).hexdigest()
                != expected_runner
            ):
                raise _refuse()
            rights = descriptors.as_tuple()
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            child.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            null_fd = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC)
            child_source = fcntl.fcntl(child.fileno(), fcntl.F_DUPFD_CLOEXEC, 16)
            runner_source = fcntl.fcntl(runner_fd, fcntl.F_DUPFD_CLOEXEC, 17)
            null_source = fcntl.fcntl(null_fd, fcntl.F_DUPFD_CLOEXEC, 18)
            actions = [
                (os.POSIX_SPAWN_CLOSE, parent.fileno()),
                (os.POSIX_SPAWN_CLOSE, child.fileno()),
                (os.POSIX_SPAWN_CLOSE, null_fd),
                (os.POSIX_SPAWN_DUP2, child_source, _LAUNCH_FD),
                (os.POSIX_SPAWN_DUP2, runner_source, 4),
                (os.POSIX_SPAWN_DUP2, null_source, 0),
                (os.POSIX_SPAWN_DUP2, null_source, 1),
                (os.POSIX_SPAWN_DUP2, null_source, 2),
                (os.POSIX_SPAWN_CLOSE, child_source),
                (os.POSIX_SPAWN_CLOSE, runner_source),
                (os.POSIX_SPAWN_CLOSE, null_source),
            ]
            pid = os.posix_spawn(
                "/proc/self/fd/4", ["bluefire-runner", "strix-worker-runtime"], {},
                file_actions=actions,
            )
            child.close()
            os.close(null_fd)
            os.close(child_source)
            os.close(runner_source)
            os.close(null_source)
            helper_pidfd = os.pidfd_open(pid, 0)
            result = cls(parent, pid, helper_pidfd)
            _send_packet(
                parent,
                {"schema_version": _SCHEMA, "kind": "launch", "identity": dict(identity)},
                rights,
            )
            packet, observed_rights, packet_digest = _receive_packet(
                parent, kinds=frozenset({"observed"}), rights_count=len(_OBSERVED_FD_ORDER),
                helper_pid=pid, helper_pidfd=helper_pidfd,
                deadline=time.monotonic() + _MAX_STARTUP_SECONDS,
            )
            # Own transferred descriptors before validating their contents so a
            # malformed observation cannot strand guest listener or workspace FDs.
            result._observed_descriptors = dict(zip(_OBSERVED_FD_ORDER, observed_rights, strict=True))
            if set(packet) != {"schema_version", "kind", "observed"} or type(packet["observed"]) is not dict:
                raise _refuse()
            observed = packet["observed"]
            unsigned = {name: value for name, value in observed.items() if name != "observation_ref"}
            if (
                observed.get("schema_version") != "bluefire.strix-worker-runtime-observation.v1"
                or observed.get("observation_ref") != content_hash(unsigned)
                or observed.get("attempt_id") != identity.get("prelaunch_bindings", {}).get("attempt_id")
                or observed.get("plan_ref") != identity.get("plan_ref")
            ):
                raise _refuse()
            result.observed = packet["observed"]
            result._launch_identity = dict(identity)
            workspace = result._observed_descriptors["workspace"]
            workspace_stat = os.fstat(workspace)
            workspace_fact = observed.get("workspace")
            if (
                type(workspace_fact) is not dict
                or not stat.S_ISDIR(workspace_stat.st_mode)
                or {"device": workspace_stat.st_dev, "inode": workspace_stat.st_ino,
                    "mode": stat.S_IMODE(workspace_stat.st_mode),
                    "uid": workspace_stat.st_uid, "gid": workspace_stat.st_gid}
                != workspace_fact
            ):
                raise _refuse()
            result._input_descriptors = {
                name: os.dup(getattr(descriptors, name)) for name in ("config", "mcp", "objective")
            }
            result._accepted_packets.append(
                {"phase": "observed", "sequence": 1, "packet_digest": packet_digest,
                 "helper_pid": pid, "document": observed}
            )
            return result
        except BaseException:
            if "result" in locals():
                result.close()
                # The helper owns guest cleanup on channel EOF. Reap it here
                # when it can finish within the bounded startup failure path;
                # otherwise retain uncertainty for the outer recovery owner.
                deadline = time.monotonic() + 5.0
                while time.monotonic() < deadline:
                    try:
                        reaped, _status = os.waitpid(result._helper_pid, os.WNOHANG)
                    except ChildProcessError:
                        break
                    if reaped == result._helper_pid:
                        break
                    time.sleep(0.01)
            else:
                for value in (locals().get("parent"), locals().get("child")):
                    if isinstance(value, socket.socket):
                        with contextlib.suppress(OSError):
                            value.close()
                if type(locals().get("null_fd")) is int:
                    with contextlib.suppress(OSError):
                        os.close(null_fd)
                for name in ("child_source", "runner_source", "null_source"):
                    source = locals().get(name)
                    if type(source) is int:
                        with contextlib.suppress(OSError):
                            os.close(source)
                spawned = locals().get("pid")
                if type(spawned) is int and spawned > 1:
                    deadline = time.monotonic() + 5.0
                    while time.monotonic() < deadline:
                        try:
                            reaped, _status = os.waitpid(spawned, os.WNOHANG)
                        except ChildProcessError:
                            break
                        if reaped == spawned:
                            break
                        time.sleep(0.01)
            raise _refuse() from None

    def _descriptor(self, name: str) -> int:
        if self._closed or self.observed is None:
            raise _refuse()
        descriptor = self._observed_descriptors.get(name)
        if descriptor is None:
            raise _refuse()
        return descriptor

    @property
    def endpoint_directory_fd(self) -> int:
        return self._descriptor("endpoint_directory")

    @property
    def control_listener_fd(self) -> int:
        return self._descriptor("control_listener")

    @property
    def model_listener_fd(self) -> int:
        return self._descriptor("model_listener")

    @property
    def caido_listener_fd(self) -> int:
        return self._descriptor("caido_listener")

    @property
    def pidfd(self) -> int:
        return self._descriptor("pidfd")

    @property
    def workspace_fd(self) -> int:
        """Pinned guest artifact directory, valid until this controller closes."""
        return self._descriptor("workspace")

    def open_containment_descriptors(self) -> OpenedWorkerContainmentDescriptors:
        """Open observed live handles while the guest is still held before basis.

        These handles support a source-backed containment ref; opening them
        does not release the worker or grant model or effect authority.
        """
        if self._closed or self.observed is None:
            raise _refuse()
        opened: list[int] = []

        def keep(fd: int) -> int:
            opened.append(fd)
            return fd

        def checked_stat(fd: int, expected: Mapping[str, Any], *, directory: bool = False) -> None:
            details = os.fstat(fd)
            if (
                type(expected) is not dict
                or (details.st_dev, details.st_ino) != (expected.get("device"), expected.get("inode"))
                or directory and not stat.S_ISDIR(details.st_mode)
                or "mode" in expected and stat.S_IMODE(details.st_mode) != expected["mode"]
                or "uid" in expected and details.st_uid != expected["uid"]
                or "gid" in expected and details.st_gid != expected["gid"]
            ):
                raise _refuse()

        try:
            worker = self.observed["worker"]
            pid = worker["pid"]
            if type(pid) is not int or pid <= 1:
                raise _refuse()
            pidfd = keep(os.dup(self.pidfd))
            checked_stat(pidfd, self.observed["pidfd"])
            fdinfo = Path(f"/proc/self/fdinfo/{pidfd}").read_text(encoding="ascii")
            if f"Pid:\t{pid}\n" not in fdinfo or select.select([pidfd], [], [], 0)[0]:
                raise _refuse()
            controller = keep(os.dup(self.control_listener_fd))
            checked_stat(controller, self.observed["listeners"]["control"])
            cgroup = self.observed["cgroup"]
            cgroup_path = Path(cgroup["path"])
            if (
                not cgroup_path.is_absolute()
                or not str(cgroup_path).startswith("/sys/fs/cgroup/")
                or ".." in cgroup_path.parts
            ):
                raise _refuse()
            cgroup_fd = keep(
                os.open(cgroup_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            )
            checked_stat(cgroup_fd, cgroup, directory=True)
            namespace_fds: dict[str, int] = {}
            for name in ("ipc", "mnt", "net", "pid", "uts"):
                descriptor = keep(os.open(f"/proc/{pid}/ns/{name}", os.O_RDONLY | os.O_CLOEXEC))
                checked_stat(descriptor, self.observed["namespaces"][name])
                namespace_fds[name] = descriptor
            root_fd = keep(os.open(f"/proc/{pid}/root", os.O_PATH | os.O_CLOEXEC))
            root_fds = {"root": root_fd}
            checked_stat(root_fd, self.observed["roots"]["root"], directory=True)
            for name, relative in (
                ("config", "config"),
                ("home", "home/worker"),
                ("tmp", "tmp"),
                ("workspace", "workspace"),
            ):
                descriptor = keep(
                    os.open(
                        relative,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=root_fd,
                    )
                )
                checked_stat(descriptor, self.observed["roots"][name], directory=True)
                root_fds[name] = descriptor
            input_fds: dict[str, int] = {}
            for name in ("config", "mcp", "objective"):
                descriptor = keep(os.dup(self._input_descriptors[name]))
                expected = self.observed["inputs"][name]
                checked_stat(descriptor, expected)
                details = os.fstat(descriptor)
                if (
                    details.st_nlink != expected.get("nlink")
                    or details.st_size != expected.get("size")
                    or fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) != expected.get("seals")
                    or not 0 < details.st_size <= 4 * 1024 * 1024
                    or "sha256:" + hashlib.sha256(os.pread(descriptor, details.st_size, 0)).hexdigest()
                    != expected.get("digest")
                ):
                    raise _refuse()
                input_fds[name] = descriptor
            relay_fds = {
                "model": keep(os.dup(self.model_listener_fd)),
                "caido": keep(os.dup(self.caido_listener_fd)),
            }
            for name, descriptor in relay_fds.items():
                checked_stat(descriptor, self.observed["listeners"][name])
            if select.select([pidfd], [], [], 0)[0]:
                raise _refuse()
            return OpenedWorkerContainmentDescriptors(
                pidfd, controller, cgroup_fd, namespace_fds, root_fds, input_fds, relay_fds
            )
        except BaseException:
            for descriptor in opened:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            raise _refuse() from None

    def qualify(self, basis: Mapping[str, Any]) -> str:
        if self._closed or self.observed is None or self.qualified_receipt_ref is not None:
            raise _refuse()
        _send_packet(
            self._connection,
            {"schema_version": _SCHEMA, "kind": "basis", "basis": dict(basis)},
        )
        packet, _rights, packet_digest = _receive_packet(
            self._connection, kinds=frozenset({"qualified"}), rights_count=0,
            helper_pid=self._helper_pid, helper_pidfd=self._helper_pidfd,
            deadline=time.monotonic() + _MAX_STARTUP_SECONDS,
        )
        qualified = packet.get("qualified")
        if type(qualified) is not dict:
            raise _refuse()
        receipt_ref = qualified.get("receipt_ref")
        unsigned = {name: value for name, value in qualified.items() if name != "receipt_ref"}
        prelaunch = self._launch_identity.get("prelaunch_bindings", {}) if self._launch_identity else {}
        if (
            set(packet) != {"schema_version", "kind", "qualified"}
            or type(receipt_ref) is not str
            or receipt_ref != content_hash(unsigned)
            or qualified.get("native_observation_ref") != self.observed.get("observation_ref")
            or qualified.get("attempt_id") != prelaunch.get("attempt_id")
            or qualified.get("resource_claim_ref") != prelaunch.get("resource_claim_ref")
            or qualified.get("plan_ref") != self._launch_identity.get("plan_ref")
        ):
            raise _refuse()
        self.qualified_receipt_ref = receipt_ref
        self._qualified_document = qualified
        self._accepted_packets.append(
            {"phase": "qualified", "sequence": 2, "packet_digest": packet_digest,
             "helper_pid": self._helper_pid, "document": qualified}
        )
        return receipt_ref

    def _terminal_operation(self, kind: str, timeout_seconds: float) -> Mapping[str, Any] | None:
        if self._closed or self._terminal is not None or self.observed is None:
            raise _refuse()
        if not 0.0 < timeout_seconds <= _MAX_WAIT_SECONDS:
            raise _refuse()
        _send_packet(
            self._connection,
            {"schema_version": _SCHEMA, "kind": kind},
        )
        packet, _rights, packet_digest = _receive_packet(
            self._connection,
            kinds=frozenset({"terminal"} if kind == "cancel" else {"terminal", "running"}),
            rights_count=0,
            helper_pid=self._helper_pid,
            helper_pidfd=self._helper_pidfd,
            deadline=time.monotonic() + timeout_seconds,
            allow_helper_exit=True,
        )
        if packet["kind"] == "running":
            if set(packet) != {"schema_version", "kind"}:
                raise _refuse()
            return None
        if set(packet) != {"schema_version", "kind", "terminal"} or type(packet["terminal"]) is not dict:
            raise _refuse()
        terminal = packet["terminal"]
        unsigned = {name: value for name, value in terminal.items() if name != "receipt_ref"}
        prelaunch = self._launch_identity.get("prelaunch_bindings", {}) if self._launch_identity else {}
        if (
            terminal.get("schema_version") != "bluefire.strix-worker-runtime-terminal.v1"
            or terminal.get("receipt_ref") != content_hash(unsigned)
            or terminal.get("observation_ref") != self.observed.get("observation_ref")
            or terminal.get("qualified_receipt_ref") != self.qualified_receipt_ref
            or terminal.get("attempt_id") != prelaunch.get("attempt_id")
            or terminal.get("resource_claim_ref") != prelaunch.get("resource_claim_ref")
            or terminal.get("plan_ref") != self._launch_identity.get("plan_ref")
            or terminal.get("verified_absent") is not True
        ):
            raise _refuse()
        self._terminal = terminal
        self._accepted_packets.append(
            {"phase": "terminal", "sequence": 3, "packet_digest": packet_digest,
             "helper_pid": self._helper_pid, "document": terminal}
        )
        helper_deadline = time.monotonic() + 5.0
        while True:
            try:
                reaped, status = os.waitpid(self._helper_pid, os.WNOHANG)
            except ChildProcessError:
                raise _refuse() from None
            if reaped == self._helper_pid:
                if status != 0:
                    raise _refuse()
                break
            if time.monotonic() >= helper_deadline:
                raise _refuse()
            time.sleep(0.01)
        self.cleanup_uncertain = False
        return self._terminal

    def wait_and_reap(self, timeout_seconds: float = _MAX_WAIT_SECONDS) -> Mapping[str, Any] | None:
        return self._terminal_operation("wait", timeout_seconds)

    def cancel_and_reap(self) -> Mapping[str, Any]:
        terminal = self._terminal_operation("cancel", _MAX_WAIT_SECONDS)
        if terminal is None:
            raise _refuse()
        return terminal

    def terminal_receipt(self) -> Mapping[str, Any] | None:
        return None if self._terminal is None else _copy_document(self._terminal)

    def observed_document(self) -> Mapping[str, Any] | None:
        return None if self.observed is None else _copy_document(self.observed)

    @property
    def qualified_document(self) -> Mapping[str, Any] | None:
        return (
            None if self._qualified_document is None
            else _copy_document(self._qualified_document)
        )

    def accepted_native_documents(self) -> tuple[Mapping[str, Any], ...]:
        """Secret-free documents accepted from the one credentialed helper channel."""
        return tuple(_copy_document(item) for item in self._accepted_packets)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(OSError):
            self._connection.close()
        for descriptor in self._observed_descriptors.values():
            with contextlib.suppress(OSError):
                os.close(descriptor)
        self._observed_descriptors.clear()
        for descriptor in self._input_descriptors.values():
            with contextlib.suppress(OSError):
                os.close(descriptor)
        self._input_descriptors.clear()
        with contextlib.suppress(OSError):
            os.close(self._helper_pidfd)


__all__ = [
    "FixedRuntimeDescriptorSet",
    "InstalledStrixLinuxWorkerController",
    "OpenedWorkerContainmentDescriptors",
    "StrixNativeWorkerError",
]
