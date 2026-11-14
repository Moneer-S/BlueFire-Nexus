"""Live Linux authority for one controller-owned Strix worker.

The durable containment receipt is evidence, not authority.  This module owns
the descriptors captured by the native launcher and turns them into a one-shot
verifier.  The verifier rechecks kernel state before a model relay is claimed
and before every admitted effect.  It cannot be reconstructed from serialized
paths, PIDs, or receipt fields.
"""

from __future__ import annotations

import hashlib
import importlib
import os
import re
import select
import socket
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, NoReturn, Protocol, cast

from .strix_worker_containment import StrixWorkerActivationReceipt
from .strix_worker_containment_identity import retained_kernel_identity_digest

_FCNTL: Any = importlib.import_module("fcntl") if sys.platform == "linux" else None
_O_CLOEXEC = int(getattr(os, "O_CLOEXEC", 0))
_O_NOFOLLOW = int(getattr(os, "O_NOFOLLOW", 0))
_PREAD: Any = getattr(os, "pread", None)
_POLL: Any = getattr(select, "poll", None)
_POLLIN = int(getattr(select, "POLLIN", 0))
_POLLHUP = int(getattr(select, "POLLHUP", 0))
_POLLERR = int(getattr(select, "POLLERR", 0))
_AF_UNIX = int(getattr(socket, "AF_UNIX", -1))
_SO_PASSCRED = int(getattr(socket, "SO_PASSCRED", -1))

_SCHEMA = "bluefire.strix-worker-containment-authority.v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CGROUP_FILES = (
    "cgroup.procs",
    "cgroup.threads",
    "pids.current",
    "pids.max",
    "memory.max",
    "memory.swap.max",
    "memory.oom.group",
    "cpu.max",
)
_NAMESPACES = ("ipc", "mnt", "net", "pid", "uts")
_CAPABILITY_FIELDS = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
_INPUT_NAMES = ("config", "mcp", "objective")
_ROOT_NAMES = ("config", "home", "root", "tmp", "workspace")
_RELAY_NAMES = ("caido", "model")
_MAX_INPUT_BYTES = 4 * 1024 * 1024
_MAX_KERNEL_TEXT = 128 * 1024

WorkerCustodyIdentity = tuple[int, int, int, int, tuple[int, ...]]


class StrixWorkerContainmentAuthorityError(RuntimeError):
    """The controller no longer has exact live worker containment authority."""


def _fail(message: str) -> NoReturn:
    raise StrixWorkerContainmentAuthorityError(message)


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _fail(f"{label} is invalid")
    return cast(str, value)


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(f"{label} is outside its bound")
    return int(value)


def _read_fd_text(fd: int, name: str) -> str:
    descriptor = -1
    try:
        descriptor = os.open(name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW, dir_fd=fd)
        raw = os.read(descriptor, _MAX_KERNEL_TEXT + 1)
        if len(raw) > _MAX_KERNEL_TEXT:
            _fail(f"Linux worker {name} exceeds its bound")
        return raw.decode("ascii", "strict")
    except (OSError, UnicodeError):
        _fail(f"Linux worker {name} is unavailable")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _positive_rows(value: str, label: str) -> tuple[int, ...]:
    try:
        rows = tuple(int(item) for item in value.splitlines() if item)
    except ValueError:
        _fail(f"{label} is invalid")
    if not rows or len(rows) != len(set(rows)) or min(rows) <= 0:
        _fail(f"{label} is invalid")
    return tuple(sorted(rows))


def _proc_stat_start_ticks(process_id: int) -> int:
    try:
        raw = (Path("/proc") / str(process_id) / "stat").read_bytes()
    except OSError:
        _fail("Linux worker process identity is unavailable")
    close = raw.rfind(b")")
    fields = raw[close + 2 :].split() if 0 < close < len(raw) - 2 else []
    try:
        ticks = int(fields[19])
    except (IndexError, ValueError):
        _fail("Linux worker process identity is invalid")
    if not 0 < len(raw) <= 4096 or ticks <= 0:
        _fail("Linux worker process identity is invalid")
    return ticks


def _proc_status(process_id: int) -> dict[str, str]:
    try:
        raw = (Path("/proc") / str(process_id) / "status").read_bytes()
    except OSError:
        _fail("Linux worker security state is unavailable")
    if not 0 < len(raw) <= 64 * 1024:
        _fail("Linux worker security state is invalid")
    result: dict[str, str] = {}
    try:
        for line in raw.decode("ascii", "strict").splitlines():
            name, separator, value = line.partition(":")
            if separator and name not in result:
                result[name] = value.strip()
    except UnicodeError:
        _fail("Linux worker security state is invalid")
    return result


def _status_ids(status: Mapping[str, str], name: str) -> tuple[int, ...]:
    try:
        values = tuple(int(item) for item in status[name].split())
    except (KeyError, ValueError):
        _fail(f"Linux worker {name} state is invalid")
    if len(values) != 4 or any(item < 0 for item in values):
        _fail(f"Linux worker {name} state is invalid")
    return values


def _descriptor_identity(fd: int) -> tuple[int, int]:
    try:
        details = os.fstat(fd)
    except OSError:
        _fail("Linux worker retained descriptor is unavailable")
    return details.st_dev, details.st_ino


def _duplicate(fd: int) -> int:
    if type(fd) is not int or fd < 0:
        _fail("Linux worker retained descriptor is invalid")
    try:
        return int(_FCNTL.fcntl(fd, _FCNTL.F_DUPFD_CLOEXEC, 3))
    except OSError:
        _fail("Linux worker retained descriptor cannot be duplicated")


def _sealed_input(fd: int) -> tuple[int, int, int, str]:
    try:
        details = os.fstat(fd)
        seals = _FCNTL.fcntl(fd, _FCNTL.F_GET_SEALS)
        if not callable(_PREAD):
            _fail("Linux worker sealed-input reads are unavailable")
        raw = cast(bytes, _PREAD(fd, _MAX_INPUT_BYTES + 1, 0))
    except OSError:
        _fail("Linux worker sealed input is unavailable")
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_nlink != 0
        or details.st_size < 1
        or details.st_size > _MAX_INPUT_BYTES
        or len(raw) != details.st_size
        or seals & 0xF != 0xF
    ):
        _fail("Linux worker sealed input is invalid")
    return details.st_dev, details.st_ino, seals, "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class LinuxWorkerLimits:
    """Exact cgroup limits admitted for the reviewed same-TGID thread profile."""

    pids_max: int
    memory_max: int
    cpu_quota: int
    cpu_period: int

    def validate(self) -> None:
        _integer(self.pids_max, "Linux worker task limit", 8, 64)
        _integer(self.memory_max, "Linux worker memory limit", 128 * 1024**2, 8 * 1024**3)
        _integer(self.cpu_quota, "Linux worker CPU quota", 1_000, 10_000_000)
        _integer(self.cpu_period, "Linux worker CPU period", 1_000, 1_000_000)
        if self.cpu_quota > 16 * self.cpu_period:
            _fail("Linux worker CPU limit is invalid")


@dataclass(frozen=True, slots=True)
class LinuxWorkerRelay:
    """One controller-owned numeric loopback listener retained by descriptor."""

    host: str
    port: int

    def validate(self) -> None:
        if self.host != "127.0.0.1":
            _fail("Linux worker relay must use numeric IPv4 loopback")
        _integer(self.port, "Linux worker relay port", 1, 65535)


@dataclass(frozen=True, slots=True)
class LinuxWorkerContainmentFacts:
    """Serializable facts captured from live descriptors after child release."""

    schema_version: str
    containment_ref: str
    startup_overlay_ref: str
    installed_projection_ref: str
    sealed_inputs_ref: str
    custody_identity: WorkerCustodyIdentity
    pidfd_ref: str
    policy_digest: str
    clone_filter_digest: str
    helper_digest: str
    limits: LinuxWorkerLimits
    controller_rpc_identity: tuple[int, int]
    cgroup_identity: tuple[int, int]
    namespace_identities: tuple[tuple[str, int, int], ...]
    root_identities: tuple[tuple[str, int, int], ...]
    input_identities: tuple[tuple[str, int, int, int, str], ...]
    relays: tuple[tuple[str, str, int, int, int], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "containment_ref": self.containment_ref,
            "startup_overlay_ref": self.startup_overlay_ref,
            "installed_projection_ref": self.installed_projection_ref,
            "sealed_inputs_ref": self.sealed_inputs_ref,
            "custody_identity": [*self.custody_identity[:4], list(self.custody_identity[4])],
            "pidfd_ref": self.pidfd_ref,
            "policy_digest": self.policy_digest,
            "clone_filter_digest": self.clone_filter_digest,
            "helper_digest": self.helper_digest,
            "limits": {
                "pids_max": self.limits.pids_max,
                "memory_max": self.limits.memory_max,
                "cpu_quota": self.limits.cpu_quota,
                "cpu_period": self.limits.cpu_period,
            },
            "controller_rpc_identity": list(self.controller_rpc_identity),
            "cgroup_identity": list(self.cgroup_identity),
            "namespace_identities": [list(item) for item in self.namespace_identities],
            "root_identities": [list(item) for item in self.root_identities],
            "input_identities": [list(item) for item in self.input_identities],
            "relays": [list(item) for item in self.relays],
        }


class _WorkerLike(Protocol):
    @property
    def custody_identity(self) -> WorkerCustodyIdentity: ...


class _BindingLike(Protocol):
    @property
    def worker_containment_ref(self) -> str: ...

    @property
    def startup_overlay_ref(self) -> str: ...

    @property
    def installed_projection_ref(self) -> str: ...

    @property
    def sealed_inputs_ref(self) -> str: ...


class _LiveVerifier(Protocol):
    def verify(self, authority: "ControlledWorkerContainmentVerifierV1") -> None: ...


class _LinuxLiveVerifier:
    def verify(self, authority: "ControlledWorkerContainmentVerifierV1") -> None:
        authority._verify_linux()  # noqa: SLF001 - private collaborator by construction


class ControlledWorkerContainmentVerifierV1:
    """One live verifier transferred exactly once to the worker RPC server."""

    schema_version = _SCHEMA

    def __init__(
        self,
        facts: LinuxWorkerContainmentFacts,
        descriptors: dict[str, int],
        verifier: _LiveVerifier,
    ) -> None:
        self._facts = facts
        self._descriptors = descriptors
        self._verifier = verifier
        self._closed = False

    @property
    def custody_identity(self) -> WorkerCustodyIdentity:
        return self._facts.custody_identity

    @property
    def containment_ref(self) -> str:
        return self._facts.containment_ref

    @property
    def startup_overlay_ref(self) -> str:
        return self._facts.startup_overlay_ref

    @property
    def installed_projection_ref(self) -> str:
        return self._facts.installed_projection_ref

    @property
    def sealed_inputs_ref(self) -> str:
        return self._facts.sealed_inputs_ref

    def verify(self) -> None:
        if self._closed:
            _fail("Linux worker containment authority is closed")
        self._verifier.verify(self)

    def _verify_linux(self) -> None:
        facts = self._facts
        process_id, uid, gid, start_ticks, namespace_pids = facts.custody_identity
        if not callable(_POLL):
            _fail("Linux worker pidfd polling is unavailable")
        poller = _POLL()
        poller.register(self._descriptors["pidfd"], _POLLIN | _POLLHUP | _POLLERR)
        if poller.poll(0):
            _fail("Linux worker has exited")
        status = _proc_status(process_id)
        if (
            _proc_stat_start_ticks(process_id) != start_ticks
            or _status_ids(status, "Uid") != (uid, uid, uid, uid)
            or _status_ids(status, "Gid") != (gid, gid, gid, gid)
            or tuple(int(item) for item in status.get("NSpid", "").split()) != namespace_pids
        ):
            _fail("Linux worker custody identity drifted")
        if status.get("NoNewPrivs") != "1" or status.get("Seccomp") != "2":
            _fail("Linux worker syscall policy is not active")
        if status.get("Groups", ""):
            _fail("Linux worker retained supplementary groups")
        if any(int(status.get(name, "-1"), 16) != 0 for name in _CAPABILITY_FIELDS):
            _fail("Linux worker retained capabilities")

        controller_rpc_fd = self._descriptors["controller_rpc"]
        if _descriptor_identity(controller_rpc_fd) != facts.controller_rpc_identity:
            _fail("Linux worker controller channel identity drifted")
        if _AF_UNIX < 0 or _SO_PASSCRED < 0:
            _fail("Linux worker credential sockets are unavailable")
        controller_rpc = socket.fromfd(controller_rpc_fd, _AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            if (
                int(controller_rpc.family) != _AF_UNIX
                or controller_rpc.type & socket.SOCK_SEQPACKET != socket.SOCK_SEQPACKET
                or controller_rpc.getsockopt(socket.SOL_SOCKET, _SO_PASSCRED) != 1
                or controller_rpc.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
            ):
                _fail("Linux worker controller channel policy drifted")
        finally:
            controller_rpc.close()

        cgroup_fd = self._descriptors["cgroup"]
        if _descriptor_identity(cgroup_fd) != facts.cgroup_identity:
            _fail("Linux worker cgroup identity drifted")
        values = {name: _read_fd_text(cgroup_fd, name).strip() for name in _CGROUP_FILES}
        expected_cpu = f"{facts.limits.cpu_quota} {facts.limits.cpu_period}"
        if (
            values["pids.max"] != str(facts.limits.pids_max)
            or values["memory.max"] != str(facts.limits.memory_max)
            or values["memory.swap.max"] != "0"
            or values["memory.oom.group"] != "1"
            or values["cpu.max"] != expected_cpu
            or _positive_rows(values["cgroup.procs"], "Linux worker cgroup members")
            != (process_id,)
        ):
            _fail("Linux worker cgroup policy drifted")
        tids = _positive_rows(values["cgroup.threads"], "Linux worker cgroup threads")
        try:
            current = int(values["pids.current"])
        except ValueError:
            _fail("Linux worker cgroup task count is invalid")
        if current != len(tids) or not 1 <= current <= facts.limits.pids_max:
            _fail("Linux worker cgroup task count drifted")
        for thread_id in tids:
            thread_status = _proc_status(thread_id)
            if thread_status.get("Tgid") != str(process_id):
                _fail("Linux worker cgroup contains another process")

        expected_namespaces = {
            name: (device, inode) for name, device, inode in facts.namespace_identities
        }
        for name in _NAMESPACES:
            fd = self._descriptors[f"namespace:{name}"]
            worker_namespace = os.stat(f"/proc/{process_id}/ns/{name}")
            host_namespace = os.stat(f"/proc/self/ns/{name}")
            host_identity = (host_namespace.st_dev, host_namespace.st_ino)
            pid_namespace_matches_host = name == "pid"
            if (
                _descriptor_identity(fd) != expected_namespaces[name]
                or _descriptor_identity(fd) != (worker_namespace.st_dev, worker_namespace.st_ino)
                or (_descriptor_identity(fd) == host_identity) is not pid_namespace_matches_host
            ):
                _fail("Linux worker namespace identity drifted")

        expected_roots = {name: (device, inode) for name, device, inode in facts.root_identities}
        for name in _ROOT_NAMES:
            if _descriptor_identity(self._descriptors[f"root:{name}"]) != expected_roots[name]:
                _fail("Linux worker private root identity drifted")
        worker_root = os.stat(f"/proc/{process_id}/root")
        if (worker_root.st_dev, worker_root.st_ino) != expected_roots["root"]:
            _fail("Linux worker root filesystem drifted")
        try:
            os.stat("proc", dir_fd=self._descriptors["root:root"], follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError:
            _fail("Linux worker private root cannot be inspected")
        else:
            _fail("Linux worker private root exposes procfs")

        for name, device, inode, seals, digest in facts.input_identities:
            expected = (device, inode, seals, digest)
            observed = _sealed_input(self._descriptors[f"input:{name}"])
            if observed != expected:
                _fail("Linux worker sealed input drifted")
            inputs_fd = -1
            mounted_fd = -1
            try:
                inputs_fd = os.open(
                    "inputs",
                    os.O_RDONLY | os.O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW,
                    dir_fd=self._descriptors["root:root"],
                )
                mounted_fd = os.open(
                    f"{name}.json",
                    os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW,
                    dir_fd=inputs_fd,
                )
                details = os.fstat(mounted_fd)
                if stat.S_IMODE(details.st_mode) & 0o222 or _sealed_input(mounted_fd) != expected:
                    _fail("Linux worker mounted input drifted")
            except OSError:
                _fail("Linux worker mounted input is unavailable")
            finally:
                if mounted_fd >= 0:
                    os.close(mounted_fd)
                if inputs_fd >= 0:
                    os.close(inputs_fd)

        admitted_listener_inodes: dict[int, tuple[str, int]] = {}
        for name, host, port, device, inode in facts.relays:
            fd = self._descriptors[f"relay:{name}"]
            if _descriptor_identity(fd) != (device, inode):
                _fail("Linux worker relay identity drifted")
            duplicate = socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM)
            try:
                if (
                    duplicate.getsockname() != (host, port)
                    or duplicate.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                ):
                    _fail("Linux worker relay is not the admitted listener")
            finally:
                duplicate.close()
            admitted_listener_inodes[inode] = (host, port)

        try:
            tcp_rows = (Path("/proc") / str(process_id) / "net" / "tcp").read_text(
                encoding="ascii", errors="strict"
            )
        except OSError:
            _fail("Linux worker network inventory is unavailable")
        observed_listeners: dict[int, str] = {}
        for line in tcp_rows.splitlines()[1:]:
            columns = line.split()
            if len(columns) >= 10 and columns[3] == "0A":
                try:
                    observed_listeners[int(columns[9])] = columns[1]
                except ValueError:
                    _fail("Linux worker listener inventory is invalid")
        if set(observed_listeners) != set(admitted_listener_inodes):
            _fail("Linux worker listener inventory drifted")
        for inode, (_host, port) in admitted_listener_inodes.items():
            if observed_listeners[inode] != f"0100007F:{port:04X}":
                _fail("Linux worker listener address drifted")

        try:
            tcp6_rows = (Path("/proc") / str(process_id) / "net" / "tcp6").read_text(
                encoding="ascii", errors="strict"
            )
            devices = (Path("/proc") / str(process_id) / "net" / "dev").read_text(
                encoding="ascii", errors="strict"
            )
            routes = (Path("/proc") / str(process_id) / "net" / "route").read_text(
                encoding="ascii", errors="strict"
            )
        except OSError:
            _fail("Linux worker route inventory is unavailable")
        if any(
            len(columns := line.split()) >= 4 and columns[3] == "0A"
            for line in tcp6_rows.splitlines()[1:]
        ):
            _fail("Linux worker acquired an IPv6 listener")
        device_names = {
            line.split(":", 1)[0].strip() for line in devices.splitlines()[2:] if ":" in line
        }
        if device_names != {"lo"}:
            _fail("Linux worker acquired a non-loopback interface")
        nonempty = [line.split() for line in routes.splitlines()[1:] if line.strip()]
        if any(len(row) < 2 or row[0] != "lo" or row[1] == "00000000" for row in nonempty):
            _fail("Linux worker acquired a non-loopback route")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        descriptors, self._descriptors = self._descriptors, {}
        for descriptor in descriptors.values():
            try:
                os.close(descriptor)
            except OSError:
                pass


class ControlledWorkerContainmentAuthorityV1:
    """Controller-private, one-shot owner of live worker kernel descriptors."""

    schema_version = _SCHEMA

    def __init__(
        self,
        *,
        activation: StrixWorkerActivationReceipt,
        custody_identity: WorkerCustodyIdentity,
        pidfd_ref: str,
        policy_digest: str,
        clone_filter_digest: str,
        helper_digest: str,
        limits: LinuxWorkerLimits,
        pidfd: int,
        controller_rpc_fd: int,
        cgroup_fd: int,
        namespace_fds: Mapping[str, int],
        root_fds: Mapping[str, int],
        input_fds: Mapping[str, int],
        relay_fds: Mapping[str, tuple[int, LinuxWorkerRelay]],
        _verifier: _LiveVerifier | None = None,
    ) -> None:
        if sys.platform != "linux" and _verifier is None:
            _fail("Linux worker containment is unavailable on this host")
        containment_ref = _digest(activation.receipt_ref, "Linux worker containment reference")
        pidfd_ref = _digest(pidfd_ref, "Linux worker pidfd reference")
        _digest(policy_digest, "Linux worker syscall policy")
        _digest(clone_filter_digest, "Linux worker clone filter")
        _digest(helper_digest, "Linux worker helper")
        limits.validate()
        if (
            set(namespace_fds) != set(_NAMESPACES)
            or set(root_fds) != set(_ROOT_NAMES)
            or set(input_fds) != set(_INPUT_NAMES)
            or set(relay_fds) != set(_RELAY_NAMES)
        ):
            _fail("Linux worker retained descriptor inventory is incomplete")
        process_id, uid, gid, start_ticks, namespace_pids = custody_identity
        _integer(process_id, "Linux worker host PID", 2, 2**31 - 1)
        _integer(uid, "Linux worker UID", 1, 2**31 - 1)
        _integer(gid, "Linux worker GID", 1, 2**31 - 1)
        _integer(start_ticks, "Linux worker start ticks", 1, 2**63 - 1)
        if (
            not namespace_pids
            or namespace_pids[0] != process_id
            or any(item <= 0 for item in namespace_pids)
        ):
            _fail("Linux worker PID namespace identity is invalid")

        descriptors: dict[str, int] = {}
        try:
            descriptors["pidfd"] = _duplicate(pidfd)
            descriptors["controller_rpc"] = _duplicate(controller_rpc_fd)
            descriptors["cgroup"] = _duplicate(cgroup_fd)
            for name, descriptor in namespace_fds.items():
                descriptors[f"namespace:{name}"] = _duplicate(descriptor)
            for name, descriptor in root_fds.items():
                descriptors[f"root:{name}"] = _duplicate(descriptor)
            for name, descriptor in input_fds.items():
                descriptors[f"input:{name}"] = _duplicate(descriptor)
            relay_rows: list[tuple[str, str, int, int, int]] = []
            for name, (descriptor, relay) in relay_fds.items():
                relay.validate()
                duplicate = _duplicate(descriptor)
                descriptors[f"relay:{name}"] = duplicate
                device, inode = _descriptor_identity(duplicate)
                relay_rows.append((name, relay.host, relay.port, device, inode))
            facts = LinuxWorkerContainmentFacts(
                schema_version="bluefire.strix-worker-containment-live-facts.v1",
                containment_ref=containment_ref,
                startup_overlay_ref=_digest(
                    activation.document["startup_overlay_ref"],
                    "Linux worker startup overlay",
                ),
                installed_projection_ref=_digest(
                    activation.document["installed_projection_ref"],
                    "Linux worker installed projection",
                ),
                sealed_inputs_ref=_digest(
                    activation.document["sealed_inputs_ref"],
                    "Linux worker sealed input projection",
                ),
                custody_identity=custody_identity,
                pidfd_ref=pidfd_ref,
                policy_digest=policy_digest,
                clone_filter_digest=clone_filter_digest,
                helper_digest=helper_digest,
                limits=limits,
                controller_rpc_identity=_descriptor_identity(descriptors["controller_rpc"]),
                cgroup_identity=_descriptor_identity(descriptors["cgroup"]),
                namespace_identities=tuple(
                    (name, *_descriptor_identity(descriptors[f"namespace:{name}"]))
                    for name in _NAMESPACES
                ),
                root_identities=tuple(
                    (name, *_descriptor_identity(descriptors[f"root:{name}"]))
                    for name in _ROOT_NAMES
                ),
                input_identities=tuple(
                    (name, *_sealed_input(descriptors[f"input:{name}"])) for name in _INPUT_NAMES
                ),
                relays=tuple(sorted(relay_rows)),
            )
            self._verify_activation_binding(activation, facts, descriptors)
        except Exception:
            for descriptor in descriptors.values():
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise
        self._facts = facts
        self._descriptors = descriptors
        self._verifier = _verifier or _LinuxLiveVerifier()
        self._taken = False

    @staticmethod
    def _verify_activation_binding(
        activation: StrixWorkerActivationReceipt,
        facts: LinuxWorkerContainmentFacts,
        descriptors: Mapping[str, int],
    ) -> None:
        row = activation.document
        identity = row["identity"]
        process = row["process"]
        cgroup = row["cgroup"]
        mount_policy = row["mount_policy"]
        host_pid, uid, gid, start_ticks, _ = facts.custody_identity
        pidfd_identity = _descriptor_identity(descriptors["pidfd"])
        if (
            (uid, gid) != (identity["uid"], identity["gid"])
            or host_pid != process["host_pid"]
            or start_ticks != process["start_ticks"]
            or facts.pidfd_ref != process["pidfd_ref"]
            or pidfd_identity != (process["pidfd_st_dev"], process["pidfd_st_ino"])
            or facts.pidfd_ref
            != retained_kernel_identity_digest(
                role=f"pidfd:{host_pid}:{start_ticks}",
                st_dev=pidfd_identity[0],
                st_ino=pidfd_identity[1],
            )
            or process["pidfd_spawn_owned"] is not True
            or cgroup["inode"] != facts.cgroup_identity[1]
            or cgroup["pids_max"] != facts.limits.pids_max
            or cgroup["memory_max_bytes"] != facts.limits.memory_max
            or cgroup["cpu_quota_micros"] != facts.limits.cpu_quota
            or cgroup["cpu_period_micros"] != facts.limits.cpu_period
            or row["security"]["seccomp_digest"] != facts.policy_digest
            or row["security"]["clone_filter_digest"] != facts.clone_filter_digest
            or row["boundary_helper_digest"] != facts.helper_digest
            or row["startup_overlay_ref"] != facts.startup_overlay_ref
            or row["installed_projection_ref"] != facts.installed_projection_ref
            or row["sealed_inputs_ref"] != facts.sealed_inputs_ref
            or (
                row["controller_rpc_socket_st_dev"],
                row["controller_rpc_socket_st_ino"],
            )
            != facts.controller_rpc_identity
            or row["controller_rpc_socket_identity_digest"]
            != retained_kernel_identity_digest(
                role="controller-rpc-sock-seqpacket",
                st_dev=facts.controller_rpc_identity[0],
                st_ino=facts.controller_rpc_identity[1],
            )
        ):
            _fail("Linux worker activation does not match retained kernel authority")
        namespace_names = {
            "ipc": "ipc",
            "mount": "mnt",
            "network": "net",
            "pid": "pid",
            "uts": "uts",
        }
        observed_namespaces = {name: inode for name, _device, inode in facts.namespace_identities}
        if any(
            observed_namespaces[namespace_names[item["kind"]]] != item["inode"]
            for item in row["namespaces"]
        ):
            _fail("Linux worker activation namespace evidence was substituted")
        observed_inputs = {
            name: (
                digest,
                os.fstat(descriptors[f"input:{name}"]).st_size,
                device,
                inode,
                retained_kernel_identity_digest(
                    role=f"sealed-input:{name}", st_dev=device, st_ino=inode
                ),
            )
            for name, _device, _inode, _seals, digest in facts.input_identities
            for device, inode in [(_device, _inode)]
        }
        if any(
            observed_inputs[item["kind"]]
            != (
                item["content_digest"],
                item["byte_length"],
                item["fd_st_dev"],
                item["fd_st_ino"],
                item["fd_identity_digest"],
            )
            for item in row["sealed_inputs"]
        ):
            _fail("Linux worker activation input evidence was substituted")
        observed_roots = {name: os.fstat(descriptors[f"root:{name}"]) for name in _ROOT_NAMES}
        rootfs = observed_roots["root"]
        if (
            rootfs.st_dev,
            rootfs.st_ino,
            retained_kernel_identity_digest(
                role="private-rootfs", st_dev=rootfs.st_dev, st_ino=rootfs.st_ino
            ),
        ) != (
            mount_policy["rootfs_st_dev"],
            mount_policy["rootfs_st_ino"],
            mount_policy["rootfs_identity_digest"],
        ):
            _fail("Linux worker activation rootfs evidence was substituted")
        if any(
            (
                observed_roots[item["purpose"]].st_uid,
                observed_roots[item["purpose"]].st_gid,
                stat.S_IMODE(observed_roots[item["purpose"]].st_mode),
                observed_roots[item["purpose"]].st_dev,
                observed_roots[item["purpose"]].st_ino,
                retained_kernel_identity_digest(
                    role=f"private-root:{item['purpose']}",
                    st_dev=observed_roots[item["purpose"]].st_dev,
                    st_ino=observed_roots[item["purpose"]].st_ino,
                ),
            )
            != (
                item["owner_uid"],
                item["owner_gid"],
                item["mode"],
                item["st_dev"],
                item["st_ino"],
                item["object_identity_digest"],
            )
            for item in row["private_roots"]
        ):
            _fail("Linux worker activation root evidence was substituted")
        network_namespace_identity = next(
            (device, inode) for name, device, inode in facts.namespace_identities if name == "net"
        )
        observed_relays = {
            name: (
                host,
                port,
                device,
                inode,
                retained_kernel_identity_digest(
                    role=f"relay-socket:{name}",
                    st_dev=device,
                    st_ino=inode,
                    host=host,
                    port=port,
                ),
                *network_namespace_identity,
                retained_kernel_identity_digest(
                    role="worker-network-namespace",
                    st_dev=network_namespace_identity[0],
                    st_ino=network_namespace_identity[1],
                ),
            )
            for name, host, port, device, inode in facts.relays
        }
        if any(
            observed_relays[item["purpose"]]
            != (
                item["host"],
                item["port"],
                item["socket_st_dev"],
                item["socket_st_ino"],
                item["socket_identity_digest"],
                item["network_namespace_st_dev"],
                item["network_namespace_st_ino"],
                item["network_namespace_ref"],
            )
            for item in row["network"]["relays"]
        ):
            _fail("Linux worker activation relay evidence was substituted")

    @property
    def facts(self) -> LinuxWorkerContainmentFacts:
        return self._facts

    @property
    def containment_ref(self) -> str:
        return self._facts.containment_ref

    @property
    def startup_overlay_ref(self) -> str:
        return self._facts.startup_overlay_ref

    @property
    def installed_projection_ref(self) -> str:
        return self._facts.installed_projection_ref

    @property
    def sealed_inputs_ref(self) -> str:
        return self._facts.sealed_inputs_ref

    def take_verifier(
        self, *, worker: _WorkerLike, binding: _BindingLike
    ) -> ControlledWorkerContainmentVerifierV1:
        if self._taken:
            _fail("Linux worker containment authority was already transferred")
        if worker.custody_identity != self._facts.custody_identity:
            _fail("Linux worker RPC custody does not match containment custody")
        if (
            binding.worker_containment_ref != self._facts.containment_ref
            or binding.startup_overlay_ref != self._facts.startup_overlay_ref
            or binding.installed_projection_ref != self._facts.installed_projection_ref
            or binding.sealed_inputs_ref != self._facts.sealed_inputs_ref
        ):
            _fail("Linux worker binding does not match containment")
        verifier = ControlledWorkerContainmentVerifierV1(
            self._facts, self._descriptors, self._verifier
        )
        verifier.verify()
        self._descriptors = {}
        self._taken = True
        return verifier

    def close(self) -> None:
        if self._taken:
            return
        descriptors, self._descriptors = self._descriptors, {}
        self._taken = True
        for descriptor in descriptors.values():
            try:
                os.close(descriptor)
            except OSError:
                pass
