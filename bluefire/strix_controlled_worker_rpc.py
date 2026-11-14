"""One-attempt Linux AF_UNIX I/O for the reviewed controlled worker protocol.

Only the controller owns a listener. This module supplies no Docker, command,
credential, Internet, process-launch, or restart authority. The daemon must
isolate the worker's files and network and retain process/effect custody.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import os
import secrets
import select
import socket
import stat
import struct
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Protocol, cast

from . import strix_controlled_backend as backend
from . import strix_controlled_worker_channel as channel
from . import strix_controlled_worker_packets as packets
from .util import content_hash

HANDSHAKE_LIMIT = 16 * 1024
_MAX_LAUNCH_BYTES = 32 * 1024
GUEST_CONTROL_ENDPOINT = "/run/bluefire/controller.sock"
_SO_NETNS_COOKIE = 71
_POLL_SECONDS = 0.02
CONTAINMENT_AUTHORITY_VERSION = "bluefire.strix-worker-containment-authority.v1"
ENDPOINT_CLEANUP_OWNER_VERSION = "bluefire.strix-worker-endpoint-cleanup-owner.v1"
ENDPOINT_CLEANUP_RECEIPT_VERSION = "bluefire.strix-worker-endpoint-cleanup-receipt.v1"
CONTROLLER_CUSTODY_READY_VERSION = "bluefire.strix-worker-controller-custody-ready.v1"


class ControlledWorkerRPCError(RuntimeError):
    """Sanitized terminal IPC refusal; received or effect text is never exposed."""


def _refuse() -> ControlledWorkerRPCError:
    return ControlledWorkerRPCError("controlled worker RPC refused")


def require_linux() -> None:
    if sys.platform != "linux" or not hasattr(socket, "SO_PEERCRED"):
        raise _refuse()


def peer_matches(connection: socket.socket, pid: int, uid: int, gid: int) -> bool:
    require_linux()
    observed_pid, observed_uid, observed_gid = struct.unpack(
        "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    )
    try:
        return packets.PeerIdentity(pid, uid, gid).accepts(
            packets.PeerIdentity(observed_pid, observed_uid, observed_gid)
        )
    except packets.CredentialedPacketError:
        return False


def _remaining(deadline_ns: int) -> float:
    remaining = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
    if remaining <= 0:
        raise _refuse()
    return remaining


async def _bounded(awaitable: Awaitable[Any], deadline_ns: int) -> Any:
    try:
        timeout = _remaining(deadline_ns)
    except BaseException:
        if hasattr(awaitable, "close"):
            awaitable.close()  # type: ignore[attr-defined]
        raise
    return await asyncio.wait_for(awaitable, timeout)


async def read_frame(
    connection: socket.socket,
    deadline_ns: int,
    *,
    limit: int,
    expected_peer: packets.PeerIdentity,
    frame_timeout_seconds: float | None = None,
) -> bytes:
    try:
        return await packets.read_frame(
            connection,
            deadline_ns,
            limit=limit,
            expected_peer=expected_peer,
            frame_timeout_seconds=frame_timeout_seconds,
        )
    except packets.CredentialedPacketError:
        raise _refuse() from None


async def write_frame(connection: socket.socket, frame: bytes, deadline_ns: int) -> None:
    try:
        await packets.write_frame(connection, frame, deadline_ns)
    except packets.CredentialedPacketError:
        raise _refuse() from None


class OwnedWorkerProcess:
    """Stable process custody supplied by the spawning supervisor.

    Construction immediately duplicates the spawn-owned pidfd. Supplying only
    a numeric PID is never sufficient because it can be recycled before an
    asynchronous server begins.
    """

    __slots__ = ("_custody_identity", "_gid", "_lock", "_pid", "_pidfd", "_uid")

    def __init__(self, pid: int, uid: int, gid: int, pidfd: int) -> None:
        require_linux()
        if (
            type(pid) is not int
            or pid <= 0
            or type(uid) is not int
            or uid < 0
            or type(gid) is not int
            or gid < 0
            or type(pidfd) is not int
            or pidfd < 0
        ):
            raise _refuse()
        duplicate = -1
        try:
            duplicate = os.dup(pidfd)
            os.set_inheritable(duplicate, False)
            custody_identity = _process_custody_identity(duplicate, pid, uid, gid)
        except (OSError, ValueError, ControlledWorkerRPCError):
            if duplicate >= 0:
                with contextlib.suppress(OSError):
                    os.close(duplicate)
            raise _refuse() from None
        self._pid = pid
        self._uid = uid
        self._gid = gid
        self._pidfd = duplicate
        self._custody_identity = custody_identity
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return "OwnedWorkerProcess(<private>)"

    @property
    def pid(self) -> int:
        return self._pid

    @property
    def uid(self) -> int:
        return self._uid

    @property
    def gid(self) -> int:
        return self._gid

    @property
    def peer(self) -> packets.PeerIdentity:
        return packets.PeerIdentity(self._pid, self._uid, self._gid)

    @property
    def custody_identity(self) -> tuple[int, int, int, int, tuple[int, ...]]:
        return self._custody_identity

    def take_pidfd(self) -> int:
        """Transfer the already duplicated stable descriptor exactly once."""
        with self._lock:
            descriptor = self._pidfd
            if descriptor < 0:
                raise _refuse()
            self._pidfd = -1
            return descriptor

    def close(self) -> None:
        lock = getattr(self, "_lock", None)
        if lock is None:
            return
        with lock:
            descriptor = getattr(self, "_pidfd", -1)
            self._pidfd = -1
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)

    def __del__(self) -> None:
        self.close()


def _pidfd_fields(descriptor: int) -> dict[str, str]:
    try:
        values: dict[str, str] = {}
        for row in Path(f"/proc/self/fdinfo/{descriptor}").read_text(encoding="ascii").splitlines():
            name, separator, value = row.partition(":")
            if separator:
                values[name] = value.strip()
        return values
    except (OSError, UnicodeError):
        return {}


def _pidfd_matches(descriptor: int, pid: int) -> bool:
    return _pidfd_fields(descriptor).get("Pid") == str(pid)


def _pidfd_exited(descriptor: int) -> bool:
    try:
        return bool(select.select([descriptor], [], [], 0)[0])
    except (OSError, ValueError):
        return True


def _process_start_ticks(pid: int) -> int:
    try:
        payload = Path(f"/proc/{pid}/stat").read_bytes()
        if not 0 < len(payload) <= 64 * 1024:
            raise _refuse()
        tail = payload[payload.rfind(b")") + 2 :].split()
        if len(tail) <= 19 or not tail[19].isascii() or not tail[19].isdigit():
            raise _refuse()
        return int(tail[19])
    except OSError:
        raise _refuse() from None


def _process_custody_identity(
    descriptor: int, pid: int, uid: int, gid: int
) -> tuple[int, int, int, int, tuple[int, ...]]:
    if not _pidfd_matches(descriptor, pid) or _pidfd_exited(descriptor):
        raise _refuse()
    before = _process_start_ticks(pid)
    fields = _pidfd_fields(descriptor)
    try:
        namespace_pids = tuple(int(value) for value in fields["NSpid"].split())
    except (KeyError, ValueError):
        raise _refuse() from None
    if (
        not namespace_pids
        or namespace_pids[0] != pid
        or before != _process_start_ticks(pid)
        or not _pidfd_matches(descriptor, pid)
        or _pidfd_exited(descriptor)
    ):
        raise _refuse()
    return pid, uid, gid, before, namespace_pids


class ControlledWorkerContainmentVerifierV1(Protocol):
    """Live controller-private verifier; serialized evidence cannot satisfy it."""

    schema_version: str
    custody_identity: tuple[int, int, int, int, tuple[int, ...]]
    containment_ref: str
    startup_overlay_ref: str
    installed_projection_ref: str
    sealed_inputs_ref: str

    def verify(self) -> None: ...

    def close(self) -> None: ...


class ControlledWorkerContainmentAuthorityV1(Protocol):
    """One-use transfer of live kernel containment authority into the RPC server."""

    schema_version: str
    containment_ref: str
    startup_overlay_ref: str
    installed_projection_ref: str
    sealed_inputs_ref: str

    def take_verifier(
        self, *, worker: OwnedWorkerProcess, binding: channel.ControlledWorkerBinding
    ) -> ControlledWorkerContainmentVerifierV1: ...


def _inode_identity(path: Path) -> tuple[int, int]:
    try:
        info = path.lstat()
    except OSError:
        raise _refuse() from None
    return info.st_dev, info.st_ino


def _valid_inode_identity(value: object) -> bool:
    return (
        type(value) is tuple
        and len(value) == 2
        and all(type(item) is int and item >= 0 for item in value)
    )


def _valid_custody_identity(value: object) -> bool:
    if type(value) is not tuple or len(value) != 5:
        return False
    pid, uid, gid, start_ticks, namespace_pids = value
    return (
        type(pid) is int
        and pid > 0
        and type(uid) is int
        and uid >= 0
        and type(gid) is int
        and gid >= 0
        and type(start_ticks) is int
        and start_ticks > 0
        and type(namespace_pids) is tuple
        and len(namespace_pids) >= 1
        and namespace_pids[0] == pid
        and all(type(item) is int and item > 0 for item in namespace_pids)
    )


@dataclass(frozen=True, slots=True)
class WorkerEndpointCleanupReceiptV1:
    """Helper-observed absence of the exact published worker endpoint objects."""

    schema_version: str
    attempt_id: str
    claim_digest: str
    worker_containment_ref: str
    directory_identity: tuple[int, int]
    endpoint_identity: tuple[int, int]
    launch_identity: tuple[int, int] | None
    endpoint_absent: bool
    launch_absent: bool
    directory_absent: bool

    def __post_init__(self) -> None:
        if (
            self.schema_version != ENDPOINT_CLEANUP_RECEIPT_VERSION
            or backend._ATTEMPT_ID.fullmatch(self.attempt_id) is None
            or backend._DIGEST.fullmatch(self.claim_digest) is None
            or backend._DIGEST.fullmatch(self.worker_containment_ref) is None
            or not _valid_inode_identity(self.directory_identity)
            or not _valid_inode_identity(self.endpoint_identity)
            or self.launch_identity is not None
            and not _valid_inode_identity(self.launch_identity)
            or type(self.endpoint_absent) is not bool
            or type(self.launch_absent) is not bool
            or type(self.directory_absent) is not bool
        ):
            raise _refuse()


class WorkerEndpointCleanupOwnerV1(Protocol):
    """Controller-private helper authority prebound to exact endpoint inodes."""

    schema_version: str
    attempt_id: str
    claim_digest: str
    worker_containment_ref: str
    directory_identity: tuple[int, int]
    endpoint_identity: tuple[int, int]

    def cleanup(
        self, *, launch_identity: tuple[int, int] | None
    ) -> WorkerEndpointCleanupReceiptV1: ...


@dataclass(frozen=True, slots=True)
class WorkerControllerCustodyReadyReceiptV1:
    """Non-authorizing proof that this exact server consumed live custody."""

    schema_version: str
    attempt_id: str
    claim_digest: str
    worker_custody_identity: tuple[int, int, int, int, tuple[int, ...]]
    server_identity_ref: str
    containment_ref: str
    startup_overlay_ref: str
    installed_projection_ref: str
    sealed_inputs_ref: str

    def __post_init__(self) -> None:
        if (
            self.schema_version != CONTROLLER_CUSTODY_READY_VERSION
            or backend._ATTEMPT_ID.fullmatch(self.attempt_id) is None
            or any(
                backend._DIGEST.fullmatch(value) is None
                for value in (
                    self.claim_digest,
                    self.server_identity_ref,
                    self.containment_ref,
                    self.startup_overlay_ref,
                    self.installed_projection_ref,
                    self.sealed_inputs_ref,
                )
            )
            or not _valid_custody_identity(self.worker_custody_identity)
        ):
            raise _refuse()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "attempt_id": self.attempt_id,
            "claim_digest": self.claim_digest,
            "worker_custody_identity": [
                *self.worker_custody_identity[:4],
                list(self.worker_custody_identity[4]),
            ],
            "server_identity_ref": self.server_identity_ref,
            "containment_ref": self.containment_ref,
            "startup_overlay_ref": self.startup_overlay_ref,
            "installed_projection_ref": self.installed_projection_ref,
            "sealed_inputs_ref": self.sealed_inputs_ref,
        }

    @property
    def receipt_ref(self) -> str:
        return cast(str, content_hash(self.to_dict()))


def hello(binding: channel.ControlledWorkerBinding, token: str) -> bytes:
    return cast(
        bytes,
        channel.encode_frame(
            {
                "protocol_version": channel.PROTOCOL_VERSION,
                "binding": binding.wire(),
                "token": token,
            }
        ),
    )


def _ack(binding: channel.ControlledWorkerBinding, model_gateway_token: str) -> bytes:
    return cast(
        bytes,
        channel.encode_frame(
            {
                "protocol_version": channel.PROTOCOL_VERSION,
                "binding": binding.wire(),
                "model_gateway_token": model_gateway_token,
            }
        ),
    )


class ControlledModelGatewayLease(Protocol):
    """Controller-owned attempt-bound relay authority, never a provider key."""

    def claim(
        self,
        binding: channel.ControlledWorkerBinding,
        custody_identity: tuple[int, int, int, int, tuple[int, ...]],
    ) -> str: ...

    def revoke(self) -> None: ...


class AttemptControllerServer:
    """Single accepted peer, no reconnect; cancellation awaits effect settlement.

    ``worker`` must hold a spawn-owned pidfd, never only a wire PID claim.
    Returning from ``serve`` means its dispatched coroutines have settled. It
    does not mean external effects or the worker process have ceased.
    """

    def __init__(
        self,
        private_parent: Path,
        profile: backend.ControlledRuntimeProfile,
        binding: channel.ControlledWorkerBinding,
        transport: backend.ControlledControllerTransport,
        model_gateway_lease: ControlledModelGatewayLease,
        *,
        io_timeout_seconds: float = 300.0,
        guest_listener_mode: bool = False,
    ) -> None:
        require_linux()
        if type(io_timeout_seconds) not in {int, float} or not 0.01 <= io_timeout_seconds <= 300:
            raise _refuse()
        self.channel = channel.ControllerChannel(profile, binding)
        self.dispatcher = channel.ControllerDispatcher(
            self.channel, backend._require_transport(transport)
        )
        if not callable(getattr(model_gateway_lease, "claim", None)) or not callable(
            getattr(model_gateway_lease, "revoke", None)
        ):
            raise _refuse()
        self._model_gateway_lease = model_gateway_lease
        self._model_gateway_claimed = False
        self._model_gateway_revoked = False
        self._model_cleanup_uncertain = False
        self._model_revocation_lock = threading.Lock()
        self._model_revocation_started = False
        self._model_revocation_finished = threading.Event()
        self._lifecycle_lock = threading.RLock()
        self.io_timeout_seconds = io_timeout_seconds
        self.token = secrets.token_hex(32)
        self._directory = Path(tempfile.mkdtemp(prefix="rpc-", dir=private_parent))
        if type(guest_listener_mode) is not bool:
            raise _refuse()
        self._guest_listener_mode = guest_listener_mode
        self._guest_listener_adopted = False
        self.endpoint = (
            Path(GUEST_CONTROL_ENDPOINT)
            if guest_listener_mode
            else self._directory / "controller.sock"
        )
        self._directory_identity: tuple[int, int] | None = None
        self._endpoint_identity: tuple[int, int] | None = None
        self._launch_identity: tuple[int, int] | None = None
        self._startup_overlay_ref: str | None = None
        self._installed_projection_ref: str | None = None
        self._endpoint_cleanup_owner: WorkerEndpointCleanupOwnerV1 | None = None
        self.endpoint_cleanup_receipt: WorkerEndpointCleanupReceiptV1 | None = None
        self._endpoint_cleanup_pending = False
        self._endpoint_cleanup_lock = threading.Lock()
        self._distinct_worker_uid = False
        self._planned_worker_uid: int | None = None
        self._custody_ready_event = threading.Event()
        self._custody_ready_failed = False
        self.custody_ready_receipt: WorkerControllerCustodyReadyReceiptV1 | None = None
        self._listener: socket.socket | None = None
        self._connection: socket.socket | None = None
        self._pidfd: int | None = None
        self._containment_verifier: ControlledWorkerContainmentVerifierV1 | None = None
        self._custody_release_lock = threading.RLock()
        self._worker_pid: int | None = None
        self._armed_worker: OwnedWorkerProcess | None = None
        self._armed_containment_authority: ControlledWorkerContainmentAuthorityV1 | None = None
        self._serve_active = False
        self._used = False
        self._cleanup_uncertain = False
        self._stopped = threading.Event()
        try:
            os.chmod(self._directory, 0o700)
            if len(os.fsencode(self.endpoint)) > 100:
                raise _refuse()
            if not guest_listener_mode:
                self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                packets.configure_socket(self._listener)
                self._listener.bind(str(self.endpoint))
                os.chmod(self.endpoint, 0o600)
                self._directory_identity = _inode_identity(self._directory)
                self._endpoint_identity = _inode_identity(self.endpoint)
                self._listener.listen(1)
                self._listener.setblocking(False)
        except BaseException:
            self.close()
            raise _refuse() from None

    def adopt_guest_listener(
        self,
        *,
        endpoint_directory_fd: int,
        listener_fd: int,
        worker_uid: int,
        worker_gid: int,
        native_observed: dict[str, Any],
    ) -> None:
        """Adopt the fixed guest listener after native custody has observed it.

        The caller retains its descriptors. The server duplicates the listener
        and binds its identity to the guest directory and filesystem socket.
        This must happen before the worker is offered a model or effect lease.
        """
        require_linux()
        if (
            not self._guest_listener_mode
            or self._guest_listener_adopted
            or self._stopped.is_set()
            or self._used
            or self._listener is not None
            or type(endpoint_directory_fd) is not int
            or endpoint_directory_fd < 0
            or type(listener_fd) is not int
            or listener_fd < 0
            or type(worker_uid) is not int
            or worker_uid <= 0
            or type(worker_gid) is not int
            or worker_gid <= 0
            or type(native_observed) is not dict
        ):
            raise _refuse()
        duplicate = -1
        listener: socket.socket | None = None
        try:
            directory = os.fstat(endpoint_directory_fd)
            endpoint = os.stat(
                "controller.sock", dir_fd=endpoint_directory_fd, follow_symlinks=False
            )
            duplicate = os.dup(listener_fd)
            listener = socket.socket(fileno=duplicate)
            duplicate = -1
            socket_info = os.fstat(listener.fileno())
            cookie = struct.unpack(
                "=Q", listener.getsockopt(socket.SOL_SOCKET, _SO_NETNS_COOKIE, 8)
            )[0]
            observed_ref = native_observed.get("observation_ref")
            unsigned = {
                name: value for name, value in native_observed.items() if name != "observation_ref"
            }
            listeners = native_observed.get("listeners")
            if type(listeners) is not dict:
                raise _refuse()
            expected_directory = {
                "endpoint_directory_device": directory.st_dev,
                "endpoint_directory_inode": directory.st_ino,
                "endpoint_directory_mode": stat.S_IMODE(directory.st_mode),
                "endpoint_directory_uid": directory.st_uid,
                "endpoint_directory_gid": directory.st_gid,
            }
            expected_path = {
                "device": endpoint.st_dev,
                "inode": endpoint.st_ino,
                "mode": stat.S_IMODE(endpoint.st_mode),
                "uid": endpoint.st_uid,
                "gid": endpoint.st_gid,
            }
            expected_control = {
                "device": socket_info.st_dev,
                "inode": socket_info.st_ino,
                "family": socket.AF_UNIX,
                "socket_type": socket.SOCK_SEQPACKET,
                "accept_conn": True,
                "passcred": True,
                "address": GUEST_CONTROL_ENDPOINT,
                "port": 0,
                "netns_cookie": cookie,
            }
            if (
                type(observed_ref) is not str
                or observed_ref != content_hash(unsigned)
                or any(listeners.get(name) != value for name, value in expected_directory.items())
                or listeners.get("endpoint_path") != expected_path
                or listeners.get("control") != expected_control
                or not stat.S_ISDIR(directory.st_mode)
                or stat.S_IMODE(directory.st_mode) != 0o700
                or (directory.st_uid, directory.st_gid) != (worker_uid, worker_gid)
                or not stat.S_ISSOCK(endpoint.st_mode)
                or stat.S_IMODE(endpoint.st_mode) != 0o600
                or (endpoint.st_uid, endpoint.st_gid) != (worker_uid, worker_gid)
                or listener.family != socket.AF_UNIX
                or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET
                or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or listener.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != 1
                or listener.getsockname() != GUEST_CONTROL_ENDPOINT
                or cookie <= 0
            ):
                listener.close()
                raise _refuse()
            listener.setblocking(False)
            with self._endpoint_cleanup_lock:
                if self._stopped.is_set() or self._listener is not None:
                    listener.close()
                    raise _refuse()
                self._directory_identity = (directory.st_dev, directory.st_ino)
                self._endpoint_identity = (endpoint.st_dev, endpoint.st_ino)
                self._listener = listener
                self._guest_listener_adopted = True
                self._endpoint_cleanup_pending = True
        except BaseException:
            if listener is not None and self._listener is not listener:
                with contextlib.suppress(OSError):
                    listener.close()
            if duplicate >= 0:
                with contextlib.suppress(OSError):
                    os.close(duplicate)
            raise _refuse() from None

    def __repr__(self) -> str:
        return "AttemptControllerServer(<private>)"

    @property
    def private_directory(self) -> Path:
        return self._directory

    @property
    def cleanup_uncertain(self) -> bool:
        return (
            self._cleanup_uncertain
            or self._model_cleanup_uncertain
            or self._endpoint_cleanup_pending
        )

    @cleanup_uncertain.setter
    def cleanup_uncertain(self, value: bool) -> None:
        if type(value) is not bool:
            raise _refuse()
        self._cleanup_uncertain = value

    @property
    def directory_identity(self) -> tuple[int, int]:
        if self._directory_identity is None:
            raise _refuse()
        return self._directory_identity

    @property
    def endpoint_identity(self) -> tuple[int, int]:
        if self._endpoint_identity is None:
            raise _refuse()
        return self._endpoint_identity

    @property
    def retained_containment_verifier(
        self,
    ) -> ControlledWorkerContainmentVerifierV1 | None:
        with self._custody_release_lock:
            return self._containment_verifier

    @property
    def retained_custody_identity(
        self,
    ) -> tuple[int, int, int, int, tuple[int, ...]] | None:
        with self._custody_release_lock:
            verifier = self._containment_verifier
            return None if verifier is None else verifier.custody_identity

    @property
    def retained_containment_ref(self) -> str | None:
        with self._custody_release_lock:
            verifier = self._containment_verifier
            return None if verifier is None else verifier.containment_ref

    @property
    def retained_model_gateway_lease(self) -> ControlledModelGatewayLease:
        return self._model_gateway_lease

    @property
    def custody_active(self) -> bool:
        with self._custody_release_lock:
            return self._pidfd is not None and self._containment_verifier is not None

    @property
    def server_identity_ref(self) -> str:
        return cast(
            str,
            content_hash(
                {
                    "schema_version": "bluefire.strix-worker-controller-server-identity.v1",
                    "attempt_id": self.channel.binding.attempt_id,
                    "claim_digest": self.channel.binding.claim_digest,
                    "directory_identity": list(self.directory_identity),
                    "endpoint_identity": list(self.endpoint_identity),
                },
            ),
        )

    def publish_launch_material(
        self,
        frame: bytes,
        *,
        startup_overlay_ref: str,
        installed_projection_ref: str,
    ) -> Path:
        """Create launch bytes and bind their still-open inode before cleanup can run."""
        if (
            type(frame) is not bytes
            or not 4 < len(frame) <= _MAX_LAUNCH_BYTES
            or type(startup_overlay_ref) is not str
            or backend._DIGEST.fullmatch(startup_overlay_ref) is None
            or type(installed_projection_ref) is not str
            or backend._DIGEST.fullmatch(installed_projection_ref) is None
        ):
            raise _refuse()
        path = self._directory / "launch.json"
        with self._endpoint_cleanup_lock:
            if (
                self._stopped.is_set()
                or self._used
                or (self._listener is None and not self._guest_listener_mode)
                or self._launch_identity is not None
                or self.endpoint_cleanup_receipt is not None
            ):
                raise _refuse()
            descriptor = -1
            created_identity: tuple[int, int] | None = None
            try:
                descriptor = os.open(
                    path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                )
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "wb", closefd=False) as output:
                    output.write(frame)
                    output.flush()
                    os.fsync(descriptor)
                info = os.fstat(descriptor)
                created_identity = info.st_dev, info.st_ino
                if self._stopped.is_set():
                    raise _refuse()
                self._launch_identity = created_identity
                self._startup_overlay_ref = startup_overlay_ref
                self._installed_projection_ref = installed_projection_ref
                return path
            except BaseException:
                if descriptor >= 0 and created_identity is None:
                    with contextlib.suppress(OSError):
                        info = os.fstat(descriptor)
                        created_identity = info.st_dev, info.st_ino
                if created_identity is not None:
                    try:
                        if _inode_identity(path) == created_identity:
                            path.unlink()
                        else:
                            self.cleanup_uncertain = True
                    except FileNotFoundError:
                        pass
                    except OSError:
                        self.cleanup_uncertain = True
                raise _refuse() from None
            finally:
                if descriptor >= 0:
                    with contextlib.suppress(OSError):
                        os.close(descriptor)

    def bind_endpoint_cleanup_owner(
        self, owner: WorkerEndpointCleanupOwnerV1, *, worker_uid: int
    ) -> None:
        """Install one helper cleanup authority before distinct-UID publication."""
        containment_ref = getattr(owner, "worker_containment_ref", None)
        if (
            type(worker_uid) is not int
            or worker_uid <= 0
            or worker_uid == os.geteuid()
            or type(containment_ref) is not str
            or backend._DIGEST.fullmatch(containment_ref) is None
        ):
            raise _refuse()
        with self._endpoint_cleanup_lock:
            if (
                self._stopped.is_set()
                or self._used
                or self._listener is None
                or self._endpoint_cleanup_owner is not None
                or self.endpoint_cleanup_receipt is not None
                or not self._valid_endpoint_cleanup_owner(owner, containment_ref)
            ):
                raise _refuse()
            self._endpoint_cleanup_owner = owner
            self._endpoint_cleanup_pending = True
            self._planned_worker_uid = worker_uid
            self._distinct_worker_uid = True

    def wait_until_custody_ready(
        self, timeout_seconds: float = 5.0
    ) -> WorkerControllerCustodyReadyReceiptV1:
        if type(timeout_seconds) not in {int, float} or not 0.01 <= timeout_seconds <= 30:
            raise _refuse()
        if not self._custody_ready_event.wait(timeout_seconds):
            raise _refuse()
        receipt = self.custody_ready_receipt
        if (
            self._custody_ready_failed
            or receipt is None
            or self._stopped.is_set()
            or not self.custody_active
            or not self._worker_is_live()
        ):
            raise _refuse()
        return receipt

    def deadline(self) -> int:
        return cast(
            int,
            min(
                self.channel.binding.deadline_ns,
                time.monotonic_ns() + int(self.io_timeout_seconds * 1_000_000_000),
            ),
        )

    def _stop_admission(self) -> None:
        """Revoke new authority and streams without releasing process custody."""
        with self._lifecycle_lock:
            self.channel.abandon()
            self.token = ""
            self._stopped.set()
            for connection in (self._listener, self._connection):
                if connection is not None:
                    with contextlib.suppress(OSError):
                        connection.shutdown(socket.SHUT_RDWR)
                    try:
                        connection.close()
                    except OSError:
                        self.cleanup_uncertain = True
            self._listener = self._connection = None
        with self._model_revocation_lock:
            if self._model_revocation_started:
                return
            self._model_revocation_started = True
            self._model_revocation_finished.clear()
            self._model_cleanup_uncertain = True

        def revoke() -> None:
            try:
                self._model_gateway_lease.revoke()
            except Exception:
                with self._model_revocation_lock:
                    self._model_cleanup_uncertain = True
                    self._model_revocation_started = False
            else:
                with self._model_revocation_lock:
                    self._model_gateway_revoked = True
                    self._model_cleanup_uncertain = False
            finally:
                self._model_revocation_finished.set()

        thread = threading.Thread(target=revoke, name="bluefire-model-revoke", daemon=True)
        thread.start()
        # Let quick local revocations settle, with a strict bound for an
        # unresponsive protected relay. Effect settlement stays on the loop.
        thread.join(0.005)

    def _valid_endpoint_cleanup_owner(
        self,
        owner: WorkerEndpointCleanupOwnerV1,
        containment_ref: str,
    ) -> bool:
        return (
            getattr(owner, "schema_version", None) == ENDPOINT_CLEANUP_OWNER_VERSION
            and getattr(owner, "attempt_id", None) == self.channel.binding.attempt_id
            and getattr(owner, "claim_digest", None) == self.channel.binding.claim_digest
            and getattr(owner, "worker_containment_ref", None) == containment_ref
            and getattr(owner, "directory_identity", None) == self.directory_identity
            and getattr(owner, "endpoint_identity", None) == self.endpoint_identity
            and callable(getattr(owner, "cleanup", None))
        )

    def _valid_endpoint_cleanup_receipt(
        self,
        receipt: WorkerEndpointCleanupReceiptV1,
    ) -> bool:
        owner = self._endpoint_cleanup_owner
        return (
            owner is not None
            and getattr(receipt, "schema_version", None) == ENDPOINT_CLEANUP_RECEIPT_VERSION
            and getattr(receipt, "attempt_id", None) == self.channel.binding.attempt_id
            and getattr(receipt, "claim_digest", None) == self.channel.binding.claim_digest
            and getattr(receipt, "worker_containment_ref", None) == owner.worker_containment_ref
            and getattr(receipt, "directory_identity", None) == self.directory_identity
            and getattr(receipt, "endpoint_identity", None) == self.endpoint_identity
            and getattr(receipt, "launch_identity", None) == self._launch_identity
            and getattr(receipt, "endpoint_absent", None) is True
            and getattr(receipt, "launch_absent", None) is True
            and getattr(receipt, "directory_absent", None) is True
            and (
                not self._guest_listener_mode
                or not (self._directory / "launch.json").exists()
                and not self._directory.exists()
            )
        )

    def _cleanup_endpoint_paths(self) -> None:
        with self._endpoint_cleanup_lock:
            self._cleanup_endpoint_paths_locked()

    def _cleanup_endpoint_paths_locked(self) -> None:
        owner = self._endpoint_cleanup_owner
        if self._guest_listener_mode:
            # The launch file is host-private, while the endpoint lives in a
            # guest-only mount. Clean both identities independently.
            path = self._directory / "launch.json"
            if self._launch_identity is not None:
                try:
                    if _inode_identity(path) == self._launch_identity:
                        path.unlink()
                    else:
                        self.cleanup_uncertain = True
                except FileNotFoundError:
                    pass
                except OSError:
                    self.cleanup_uncertain = True
            try:
                self._directory.rmdir()
            except FileNotFoundError:
                pass
            except OSError:
                self.cleanup_uncertain = True
            if path.exists() or self._directory.exists():
                self.cleanup_uncertain = True
            if owner is None:
                self._endpoint_cleanup_pending = self._guest_listener_adopted
                return
            if self.endpoint_cleanup_receipt is not None:
                return
            self._endpoint_cleanup_pending = True
            try:
                receipt = owner.cleanup(launch_identity=self._launch_identity)
                if not self._valid_endpoint_cleanup_receipt(receipt):
                    raise _refuse()
            except Exception:
                return
            self.endpoint_cleanup_receipt = receipt
            self._endpoint_cleanup_pending = False
            return
        if owner is not None:
            if self.endpoint_cleanup_receipt is not None:
                return
            self._endpoint_cleanup_pending = True
            try:
                receipt = owner.cleanup(launch_identity=self._launch_identity)
                if not self._valid_endpoint_cleanup_receipt(receipt):
                    raise _refuse()
            except Exception:
                return
            self.endpoint_cleanup_receipt = receipt
            self._endpoint_cleanup_pending = False
            return
        if self._distinct_worker_uid:
            self._endpoint_cleanup_pending = True
            return
        for path in (self.endpoint, self._directory / "launch.json"):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                self.cleanup_uncertain = True
        try:
            self._directory.rmdir()
        except FileNotFoundError:
            pass
        except OSError:
            self.cleanup_uncertain = True

    def _release_custody(self) -> None:
        """Release live containment only after every accepted effect settles."""
        with self._custody_release_lock:
            if self._containment_verifier is not None:
                try:
                    self._containment_verifier.close()
                except Exception:
                    self.cleanup_uncertain = True
                    return
                else:
                    self._containment_verifier = None
            if self._pidfd is not None:
                descriptor = self._pidfd
                self._pidfd = None
                try:
                    os.close(descriptor)
                except OSError:
                    self.cleanup_uncertain = True

    def close(self) -> None:
        """Stop admission now; release custody only outside active settlement."""
        if self.custody_ready_receipt is None:
            self._custody_ready_failed = True
            self._custody_ready_event.set()
        self._stop_admission()
        if not self._serve_active:
            self._release_custody()
        self._cleanup_endpoint_paths()

    def arm_custody(
        self,
        *,
        worker: OwnedWorkerProcess,
        containment_authority: ControlledWorkerContainmentAuthorityV1,
        endpoint_cleanup_owner: WorkerEndpointCleanupOwnerV1 | None = None,
    ) -> WorkerControllerCustodyReadyReceiptV1:
        """Validate live worker custody without accepting a request or model lease."""
        if (
            self._used
            or self._listener is None
            or self._armed_worker is not None
            or self._stopped.is_set()
            or self._guest_listener_mode and not self._guest_listener_adopted
        ):
            raise _refuse()
        if self._startup_overlay_ref is None or self._installed_projection_ref is None:
            self._custody_ready_failed = True
            self._custody_ready_event.set()
            self.close()
            raise _refuse()
        if type(worker) is not OwnedWorkerProcess:
            self.close()
            raise _refuse()
        actual_distinct_worker_uid = worker.uid != os.geteuid()
        self._distinct_worker_uid = self._distinct_worker_uid or actual_distinct_worker_uid
        if (
            getattr(containment_authority, "schema_version", None) != CONTAINMENT_AUTHORITY_VERSION
            or backend._DIGEST.fullmatch(getattr(containment_authority, "containment_ref", ""))
            is None
            or getattr(containment_authority, "startup_overlay_ref", None)
            != self._startup_overlay_ref
            or getattr(containment_authority, "installed_projection_ref", None)
            != self._installed_projection_ref
            or backend._DIGEST.fullmatch(getattr(containment_authority, "sealed_inputs_ref", ""))
            is None
            or not callable(getattr(containment_authority, "take_verifier", None))
        ):
            self.close()
            raise _refuse()
        containment_ref = containment_authority.containment_ref
        with self._endpoint_cleanup_lock:
            if (
                endpoint_cleanup_owner is not None
                and self._endpoint_cleanup_owner is None
                and not actual_distinct_worker_uid
                and not self._stopped.is_set()
                and self._valid_endpoint_cleanup_owner(endpoint_cleanup_owner, containment_ref)
            ):
                self._endpoint_cleanup_owner = endpoint_cleanup_owner
                self._endpoint_cleanup_pending = True
            owner = self._endpoint_cleanup_owner
            cleanup_owner_valid = (
                not self._stopped.is_set()
                and (self._planned_worker_uid is None or worker.uid == self._planned_worker_uid)
                and (endpoint_cleanup_owner is None or endpoint_cleanup_owner is owner)
                and (owner is None or self._valid_endpoint_cleanup_owner(owner, containment_ref))
                and (
                    not actual_distinct_worker_uid
                    or owner is not None and self._planned_worker_uid == worker.uid
                )
            )
        if not cleanup_owner_valid:
            self.close()
            raise _refuse()
        try:
            with self._custody_release_lock:
                if self._stopped.is_set():
                    raise _refuse()
                self._pidfd = worker.take_pidfd()
                self._worker_pid = worker.pid
                self._containment_verifier = containment_authority.take_verifier(
                    worker=worker, binding=self.channel.binding
                )
                if (
                    getattr(self._containment_verifier, "schema_version", None)
                    != CONTAINMENT_AUTHORITY_VERSION
                    or getattr(self._containment_verifier, "custody_identity", None)
                    != worker.custody_identity
                    or getattr(self._containment_verifier, "containment_ref", None) != containment_ref
                    or getattr(self._containment_verifier, "startup_overlay_ref", None)
                    != self._startup_overlay_ref
                    or getattr(self._containment_verifier, "installed_projection_ref", None)
                    != self._installed_projection_ref
                    or getattr(self._containment_verifier, "sealed_inputs_ref", None)
                    != containment_authority.sealed_inputs_ref
                    or not callable(getattr(self._containment_verifier, "verify", None))
                    or not callable(getattr(self._containment_verifier, "close", None))
                    or not self._worker_is_live()
                    or self._stopped.is_set()
                ):
                    raise _refuse()
                self.custody_ready_receipt = WorkerControllerCustodyReadyReceiptV1(
                    schema_version=CONTROLLER_CUSTODY_READY_VERSION,
                    attempt_id=self.channel.binding.attempt_id,
                    claim_digest=self.channel.binding.claim_digest,
                    worker_custody_identity=worker.custody_identity,
                    server_identity_ref=self.server_identity_ref,
                    containment_ref=containment_ref,
                    startup_overlay_ref=self._startup_overlay_ref,
                    installed_projection_ref=self._installed_projection_ref,
                    sealed_inputs_ref=containment_authority.sealed_inputs_ref,
                )
                self._armed_worker = worker
                self._armed_containment_authority = containment_authority
                self._custody_ready_event.set()
        except Exception:
            self.close()
            raise _refuse() from None
        return self.custody_ready_receipt

    async def serve(
        self,
        *,
        worker: OwnedWorkerProcess,
        containment_authority: ControlledWorkerContainmentAuthorityV1,
        cancellation: Any,
        endpoint_cleanup_owner: WorkerEndpointCleanupOwnerV1 | None = None,
    ) -> None:
        if self._armed_worker is None:
            self.arm_custody(
                worker=worker,
                containment_authority=containment_authority,
                endpoint_cleanup_owner=endpoint_cleanup_owner,
            )
        with self._lifecycle_lock:
            if (
                self._used
                or self._listener is None
                or self._stopped.is_set()
                or self._armed_worker is not worker
                or self._armed_containment_authority is not containment_authority
                or endpoint_cleanup_owner is not None
                and endpoint_cleanup_owner is not self._endpoint_cleanup_owner
                or self.custody_ready_receipt is None
                or not self._worker_is_live()
            ):
                raise _refuse()
            listener = self._listener
            self._used = True
            self._serve_active = True
        tasks: set[asyncio.Task[None]] = set()
        send_lock = asyncio.Lock()
        failed = asyncio.Event()

        async def dispatch(accepted: Awaitable[bytes]) -> None:
            try:
                if cancellation.is_set() or self._stopped.is_set() or not self._worker_is_live():
                    if hasattr(accepted, "close"):
                        accepted.close()  # type: ignore[attr-defined]
                    raise _refuse()
                response = await accepted
                async with send_lock:
                    if self._connection is None or self._stopped.is_set():
                        raise _refuse()
                    await write_frame(self._connection, response, self.deadline())
                if not self.channel.usable:
                    raise _refuse()
            except BaseException:
                self.close()
                failed.set()

        async def receive() -> None:
            connection, _address = await _bounded(
                asyncio.get_running_loop().sock_accept(listener), self.deadline()
            )
            self._connection = connection
            listener.close()
            self._listener = None
            packets.configure_socket(connection)
            if not peer_matches(connection, worker.pid, worker.uid, worker.gid):
                raise _refuse()
            value = channel.decode_frame(
                await read_frame(
                    connection,
                    self.deadline(),
                    limit=HANDSHAKE_LIMIT,
                    expected_peer=worker.peer,
                )
            )
            expected = channel.decode_frame(hello(self.channel.binding, self.token))
            if (
                set(value) != set(expected)
                or type(value.get("token")) is not str
                or not hmac.compare_digest(value["token"], self.token)
                or {key: value[key] for key in value if key != "token"}
                != {key: expected[key] for key in expected if key != "token"}
            ):
                raise _refuse()
            self.token = ""  # Authentication is consumed; this listener is never reopened.
            if self._model_gateway_claimed:
                raise _refuse()
            if cancellation.is_set() or self._stopped.is_set() or not self._worker_is_live():
                raise _refuse()
            model_gateway_token = await _bounded(
                asyncio.to_thread(
                    self._model_gateway_lease.claim,
                    self.channel.binding,
                    worker.custody_identity,
                ),
                self.deadline(),
            )
            if (
                type(model_gateway_token) is not str
                or not 32 <= len(model_gateway_token) <= 512
                or any(
                    ord(character) < 33 or ord(character) == 127
                    for character in model_gateway_token
                )
            ):
                raise _refuse()
            self._model_gateway_claimed = True
            if cancellation.is_set() or self._stopped.is_set() or not self._worker_is_live():
                raise _refuse()
            await write_frame(
                connection, _ack(self.channel.binding, model_gateway_token), self.deadline()
            )
            while not self._stopped.is_set():
                frame = await read_frame(
                    connection,
                    self.channel.binding.deadline_ns,
                    limit=channel.MAX_FRAME_BYTES,
                    expected_peer=worker.peer,
                    frame_timeout_seconds=self.io_timeout_seconds,
                )
                if cancellation.is_set() or self._stopped.is_set() or not self._worker_is_live():
                    raise _refuse()
                accepted = self.dispatcher.accept(frame, received_ns=time.monotonic_ns())
                task = asyncio.create_task(dispatch(accepted))
                tasks.add(task)
                task.add_done_callback(tasks.discard)

                # Cancellation may win before dispatch's first instruction.
                # Always dispose of its admitted coroutine after settlement.
                def dispose(
                    _task: asyncio.Task[None], operation: Awaitable[bytes] = accepted
                ) -> None:
                    operation.close()  # type: ignore[attr-defined]

                task.add_done_callback(dispose)

        reader = asyncio.create_task(receive())
        try:
            while not reader.done() and not failed.is_set() and not self._stopped.is_set():
                if (
                    cancellation.is_set()
                    or not self._worker_is_live()
                    or time.monotonic_ns() >= self.channel.binding.deadline_ns
                ):
                    raise _refuse()
                await asyncio.sleep(_POLL_SECONDS)
            if reader.done():
                reader.result()
        except BaseException:
            pass
        finally:
            self._stop_admission()
            # Remove the rendezvous path immediately. An accepted effect may
            # still be settling, so keep pidfd and containment custody below.
            self._cleanup_endpoint_paths()
            reader.cancel()
            for task in tasks:
                task.cancel()
            # Repeated cancellation cannot release controller custody early.
            settlement = asyncio.gather(reader, *tuple(tasks), return_exceptions=True)
            while not settlement.done():
                try:
                    await asyncio.shield(settlement)
                except asyncio.CancelledError:
                    continue
            settlement.result()
            self._serve_active = False
            self.close()
        raise _refuse()

    def _worker_is_live(self) -> bool:
        with self._custody_release_lock:
            return (
                self._pidfd is not None
                and self._worker_pid is not None
                and _pidfd_matches(self._pidfd, self._worker_pid)
                and not _pidfd_exited(self._pidfd)
                and self._containment_is_current()
            )

    def _containment_is_current(self) -> bool:
        if self._containment_verifier is None:
            return False
        try:
            return cast(Any, self._containment_verifier).verify() is None
        except BaseException:
            return False


class SocketControlledControllerTransport:
    """The exact fifteen typed methods over an authenticated connected socket.

    The reader is lazy because the official CLI creates its own event loop.
    A transport is bound to one loop and never reconnects after any ambiguity.
    """

    def __init__(
        self,
        connection: socket.socket,
        worker: channel.WorkerChannel,
        *,
        controller_peer: packets.PeerIdentity,
        io_timeout_seconds: float = 300.0,
    ) -> None:
        require_linux()
        if (
            connection.family != socket.AF_UNIX
            or connection.type & socket.SOCK_SEQPACKET != socket.SOCK_SEQPACKET
            or type(controller_peer) is not packets.PeerIdentity
            or type(io_timeout_seconds) not in {int, float}
            or not 0.01 <= io_timeout_seconds <= 300
        ):
            raise _refuse()
        self._connection = connection
        self.channel = worker
        self._controller_peer = controller_peer
        self._timeout = io_timeout_seconds
        self._pending: dict[str, asyncio.Future[Any]] = {}
        self._reader: asyncio.Task[None] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._send_lock: asyncio.Lock | None = None
        self._closed = False
        self._state_lock = threading.Lock()
        packets.configure_socket(connection)

    def close(self) -> None:
        with self._state_lock:
            first_close = not self._closed
            self._closed = True
            loop = self._loop
        if first_close:
            self.channel.abandon()
            with contextlib.suppress(OSError):
                self._connection.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                self._connection.close()
        if loop is not None and loop.is_running():
            with contextlib.suppress(RuntimeError):
                loop.call_soon_threadsafe(self._settle_owner_loop)

    def _settle_owner_loop(self) -> None:
        """Mutate loop-owned Task/Futures only on their owning loop."""
        if self._reader is not None and not self._reader.done():
            self._reader.cancel()
        for future in self._pending.values():
            if not future.done():
                future.cancel()

    def _deadline(self) -> int:
        return cast(
            int,
            min(
                self.channel.binding.deadline_ns,
                time.monotonic_ns() + int(self._timeout * 1_000_000_000),
            ),
        )

    async def _receive(self) -> None:
        try:
            while not self._closed:
                frame = await read_frame(
                    self._connection,
                    self.channel.binding.deadline_ns,
                    limit=channel.MAX_FRAME_BYTES,
                    expected_peer=self._controller_peer,
                    frame_timeout_seconds=self._timeout,
                )
                _method, request_id, receipt = self.channel.response(
                    frame, now_ns=time.monotonic_ns()
                )
                future = self._pending.pop(request_id)
                future.set_result(receipt)
                if not self.channel.usable:
                    raise _refuse()
        except BaseException:
            self.close()

    async def _call(self, method: str, request: Any) -> Any:
        try:
            loop = asyncio.get_running_loop()
            with self._state_lock:
                if self._closed or (self._loop is not None and self._loop is not loop):
                    raise _refuse()
                if self._loop is None:
                    self._loop = loop
                    self._send_lock = asyncio.Lock()
                    self._reader = asyncio.create_task(self._receive())
            assert self._send_lock is not None
            request_id = secrets.token_hex(16)
            future = loop.create_future()
            async with self._send_lock:
                frame = self.channel.request(
                    method, request, request_id=request_id, now_ns=time.monotonic_ns()
                )
                self._pending[request_id] = future
                await write_frame(self._connection, frame, self._deadline())
            return await _bounded(asyncio.shield(future), self._deadline())
        except BaseException:
            self.close()
            # Consume the local future too when cancellation/partial write won.
            if "future" in locals() and future.done() and not future.cancelled():
                future.exception()
        raise _refuse()

    async def create_exact(
        self, request: backend.ControlledCreateRequest
    ) -> backend.ControlledCreateReceipt:
        return cast(backend.ControlledCreateReceipt, await self._call("create_exact", request))

    async def reconcile_create(
        self, request: backend.ControlledLifecycleRequest
    ) -> backend.ControlledLifecycleReceipt:
        return cast(
            backend.ControlledLifecycleReceipt, await self._call("reconcile_create", request)
        )

    async def exec_exact(
        self, request: backend.ControlledExecRequest
    ) -> backend.ControlledExecReceipt:
        return cast(backend.ControlledExecReceipt, await self._call("exec_exact", request))

    async def cancel_exact(
        self, request: backend.ControlledLifecycleRequest
    ) -> backend.ControlledLifecycleReceipt:
        return cast(backend.ControlledLifecycleReceipt, await self._call("cancel_exact", request))

    async def read_exact(
        self, request: backend.ControlledReadRequest
    ) -> backend.ControlledReadReceipt:
        return cast(backend.ControlledReadReceipt, await self._call("read_exact", request))

    async def begin_write_exact(
        self, request: backend.ControlledWriteBeginRequest
    ) -> backend.ControlledWriteBeginReceipt:
        return cast(
            backend.ControlledWriteBeginReceipt, await self._call("begin_write_exact", request)
        )

    async def write_chunk_exact(
        self, request: backend.ControlledWriteChunkRequest
    ) -> backend.ControlledWriteChunkReceipt:
        return cast(
            backend.ControlledWriteChunkReceipt, await self._call("write_chunk_exact", request)
        )

    async def commit_write_exact(
        self, request: backend.ControlledWriteCommitRequest
    ) -> backend.ControlledWriteCommitReceipt:
        return cast(
            backend.ControlledWriteCommitReceipt, await self._call("commit_write_exact", request)
        )

    async def reconcile_write_exact(
        self, request: backend.ControlledWriteReconcileRequest
    ) -> backend.ControlledWriteReconcileReceipt:
        return cast(
            backend.ControlledWriteReconcileReceipt,
            await self._call("reconcile_write_exact", request),
        )

    async def abort_write_exact(
        self, request: backend.ControlledWriteAbortRequest
    ) -> backend.ControlledLifecycleReceipt:
        return cast(
            backend.ControlledLifecycleReceipt, await self._call("abort_write_exact", request)
        )

    async def running_exact(
        self, request: backend.ControlledLifecycleRequest
    ) -> backend.ControlledLifecycleReceipt:
        return cast(backend.ControlledLifecycleReceipt, await self._call("running_exact", request))

    async def persist_exact(
        self, request: backend.ControlledWorkspaceBlobRequest
    ) -> backend.ControlledWorkspaceBlobReceipt:
        return cast(
            backend.ControlledWorkspaceBlobReceipt, await self._call("persist_exact", request)
        )

    async def hydrate_exact(
        self, request: backend.ControlledWorkspaceBlobRequest
    ) -> backend.ControlledHydrateReceipt:
        return cast(backend.ControlledHydrateReceipt, await self._call("hydrate_exact", request))

    async def resolve_caido_exact(
        self, request: backend.ControlledPortRequest
    ) -> backend.ControlledPortReceipt:
        return cast(backend.ControlledPortReceipt, await self._call("resolve_caido_exact", request))

    async def delete_exact(
        self, request: backend.ControlledLifecycleRequest
    ) -> backend.ControlledLifecycleReceipt:
        return cast(backend.ControlledLifecycleReceipt, await self._call("delete_exact", request))
