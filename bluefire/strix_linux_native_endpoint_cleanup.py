"""Observed guest endpoint cleanup for the fixed Linux Strix worker.

The guest socket lives in a private mount namespace. The controller retains
its directory and listener descriptors, while the native helper owns removal.
This owner can be registered before activation but issues an absence receipt
only after the authenticated native terminal and independent descriptor checks.
"""

from __future__ import annotations

import contextlib
import os
import re
import socket
import stat
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

from .util import content_hash

OWNER_SCHEMA = "bluefire.strix-worker-endpoint-cleanup-owner.v1"
RECEIPT_SCHEMA = "bluefire.strix-native-guest-endpoint-cleanup-receipt.v1"
_OBSERVATION_SCHEMA = "bluefire.strix-worker-runtime-observation.v1"
_TERMINAL_SCHEMA = "bluefire.strix-worker-runtime-terminal.v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ATTEMPT = re.compile(r"^engine-attempt-[0-9a-f]{32}$")


class NativeGuestEndpointCleanupError(RuntimeError):
    """The exact guest endpoint absence has not been established."""


def _refuse() -> NativeGuestEndpointCleanupError:
    return NativeGuestEndpointCleanupError("installed Strix endpoint cleanup unavailable")


def _digest(value: Any) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise _refuse()
    return value


def _identity(value: Any) -> tuple[int, int]:
    if (
        not isinstance(value, (list, tuple))
        or len(value) != 2
        or any(type(item) is not int or item <= 0 for item in value)
    ):
        raise _refuse()
    return (value[0], value[1])


def _fact_identity(value: Any) -> tuple[int, int]:
    if type(value) is not dict:
        raise _refuse()
    return _identity((value.get("device"), value.get("inode")))


def _stat_identity(details: os.stat_result) -> tuple[int, int]:
    return (details.st_dev, details.st_ino)


def _content_ref(document: Mapping[str, Any], key: str) -> str:
    ref = _digest(document.get(key))
    if content_hash({name: item for name, item in document.items() if name != key}) != ref:
        raise _refuse()
    return ref


class _NativeWorker(Protocol):
    endpoint_directory_fd: int
    control_listener_fd: int
    qualified_receipt_ref: str | None
    cleanup_uncertain: bool

    def observed_document(self) -> Mapping[str, Any] | None: ...

    def terminal_receipt(self) -> Mapping[str, Any] | None: ...


@dataclass(frozen=True, slots=True)
class NativeGuestEndpointCleanupReceipt:
    """RPC-compatible receipt with its original native sources exposed."""

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
    native_worker_absent: bool
    socket_entry_unlinked: bool
    host_staging_absent: bool
    retained_directory_fd_open: bool
    native_observation_ref: str
    native_terminal_ref: str
    cleanup_owner_ref: str
    receipt_ref: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "attempt_id": self.attempt_id,
            "claim_digest": self.claim_digest,
            "worker_containment_ref": self.worker_containment_ref,
            "directory_identity": list(self.directory_identity),
            "endpoint_identity": list(self.endpoint_identity),
            "launch_identity": None if self.launch_identity is None else list(self.launch_identity),
            "endpoint_absent": self.endpoint_absent,
            "launch_absent": self.launch_absent,
            "directory_absent": self.directory_absent,
            "native_worker_absent": self.native_worker_absent,
            "socket_entry_unlinked": self.socket_entry_unlinked,
            "host_staging_absent": self.host_staging_absent,
            "retained_directory_fd_open": self.retained_directory_fd_open,
            "native_observation_ref": self.native_observation_ref,
            "native_terminal_ref": self.native_terminal_ref,
            "cleanup_owner_ref": self.cleanup_owner_ref,
            "receipt_ref": self.receipt_ref,
        }


class NativeGuestEndpointCleanupOwner:
    """One guest endpoint generation, retained across preterminal retries.

    ``directory_absent`` means the endpoint has no reachable guest pathname
    after the worker namespace and host staging root end. The controller still
    holds a descriptor to the detached tmpfs directory for verification.
    """

    schema_version = OWNER_SCHEMA

    def __init__(
        self,
        *,
        worker: _NativeWorker,
        attempt_id: str,
        claim_digest: str,
        resource_claim_ref: str,
        worker_containment_ref: str,
        host_launch_directory: Path,
        host_directory_identity: tuple[int, int],
        require_launch_file: bool = True,
    ) -> None:
        if sys.platform != "linux":
            raise _refuse()
        if type(attempt_id) is not str or _ATTEMPT.fullmatch(attempt_id) is None:
            raise _refuse()
        self.attempt_id = attempt_id
        self.claim_digest = _digest(claim_digest)
        self.resource_claim_ref = _digest(resource_claim_ref)
        self.worker_containment_ref = _digest(worker_containment_ref)
        if not host_launch_directory.is_absolute() or host_launch_directory.name in {"", ".", ".."}:
            raise _refuse()
        self._host_path = host_launch_directory
        self._host_directory_identity = _identity(host_directory_identity)
        self._worker = worker
        self._guest_directory_fd = -1
        self._guest_listener_fd = -1
        self._host_directory_fd = -1
        self._host_parent_fd = -1
        self._receipt: NativeGuestEndpointCleanupReceipt | None = None
        self._closed = False
        self._lock = threading.Lock()
        try:
            observed = worker.observed_document()
            if type(observed) is not dict or observed.get("schema_version") != _OBSERVATION_SCHEMA:
                raise _refuse()
            self._native_observation_ref = _content_ref(observed, "observation_ref")
            if observed.get("attempt_id") != attempt_id:
                raise _refuse()
            listeners = observed.get("listeners")
            if type(listeners) is not dict:
                raise _refuse()
            self._directory_fact = {
                "device": listeners.get("endpoint_directory_device"),
                "inode": listeners.get("endpoint_directory_inode"),
                "mode": listeners.get("endpoint_directory_mode"),
                "uid": listeners.get("endpoint_directory_uid"),
                "gid": listeners.get("endpoint_directory_gid"),
            }
            self.directory_identity = _fact_identity(self._directory_fact)
            endpoint = listeners.get("endpoint_path")
            self.endpoint_identity = _fact_identity(endpoint)
            control = listeners.get("control")
            self._control_identity = _fact_identity(control)
            worker_fact = observed.get("worker")
            if (
                type(worker_fact) is not dict
                or self._directory_fact["mode"] != 0o700
                or self._directory_fact["uid"] != worker_fact.get("uid")
                or self._directory_fact["gid"] != worker_fact.get("gid")
                or endpoint.get("uid") != worker_fact.get("uid")
                or endpoint.get("gid") != worker_fact.get("gid")
            ):
                raise _refuse()
            self._worker_pid = worker_fact.get("pid")
            if type(self._worker_pid) is not int or self._worker_pid <= 1:
                raise _refuse()
            self._worker_start_ticks = worker_fact.get("start_ticks")
            if type(self._worker_start_ticks) is not int or self._worker_start_ticks <= 0:
                raise _refuse()
            self._plan_ref = _digest(observed.get("plan_ref"))
            self._cgroup_ref = _digest(observed.get("cgroup_ref"))
            self._guest_directory_fd = os.dup(worker.endpoint_directory_fd)
            self._guest_listener_fd = os.dup(worker.control_listener_fd)
            self._check_guest_identity(endpoint_present=True)
            self._host_parent_fd = os.open(
                host_launch_directory.parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            self._host_directory_fd = os.open(
                host_launch_directory,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            host_directory = os.fstat(self._host_directory_fd)
            if (
                _stat_identity(host_directory) != self._host_directory_identity
                or not stat.S_ISDIR(host_directory.st_mode)
                or stat.S_IMODE(host_directory.st_mode) != 0o700
                or host_directory.st_uid != os.geteuid()
            ):
                raise _refuse()
            if type(require_launch_file) is not bool:
                raise _refuse()
            try:
                launch = os.stat(
                    "launch.json", dir_fd=self._host_directory_fd, follow_symlinks=False
                )
            except FileNotFoundError:
                if require_launch_file:
                    raise _refuse() from None
                self._launch_identity = None
            else:
                if (
                    not require_launch_file
                    or not stat.S_ISREG(launch.st_mode)
                    or launch.st_nlink != 1
                ):
                    raise _refuse()
                self._launch_identity = _stat_identity(launch)
            self.cleanup_owner_ref = content_hash(
                {
                    "schema_version": OWNER_SCHEMA,
                    "attempt_id": attempt_id,
                    "claim_digest": self.claim_digest,
                    "resource_claim_ref": self.resource_claim_ref,
                    "worker_containment_ref": self.worker_containment_ref,
                    "native_observation_ref": self._native_observation_ref,
                    "directory_identity": list(self.directory_identity),
                    "endpoint_identity": list(self.endpoint_identity),
                    "control_listener_identity": list(self._control_identity),
                    "host_directory_identity": list(self._host_directory_identity),
                    "host_parent_identity": list(_stat_identity(os.fstat(self._host_parent_fd))),
                    "host_directory_name": host_launch_directory.name,
                    "launch_identity": (
                        None if self._launch_identity is None else list(self._launch_identity)
                    ),
                }
            )
        except BaseException:
            self.close()
            raise _refuse() from None

    def _check_guest_identity(self, *, endpoint_present: bool) -> None:
        directory = os.fstat(self._guest_directory_fd)
        listener = os.fstat(self._guest_listener_fd)
        if (
            _stat_identity(directory) != self.directory_identity
            or stat.S_IMODE(directory.st_mode) != self._directory_fact["mode"]
            or directory.st_uid != self._directory_fact["uid"]
            or directory.st_gid != self._directory_fact["gid"]
            or not stat.S_ISDIR(directory.st_mode)
            or _stat_identity(listener) != self._control_identity
            or not stat.S_ISSOCK(listener.st_mode)
        ):
            raise _refuse()
        duplicate = os.dup(self._guest_listener_fd)
        try:
            check = socket.socket(fileno=duplicate)
        except BaseException:
            os.close(duplicate)
            raise
        try:
            if (
                check.family != socket.AF_UNIX
                or check.type & socket.SOCK_SEQPACKET != socket.SOCK_SEQPACKET
                or check.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or check.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != 1
            ):
                raise _refuse()
        finally:
            check.close()
        try:
            endpoint = os.stat(
                "controller.sock", dir_fd=self._guest_directory_fd, follow_symlinks=False
            )
        except FileNotFoundError:
            if endpoint_present:
                raise _refuse() from None
        else:
            if (
                not endpoint_present
                or _stat_identity(endpoint) != self.endpoint_identity
                or not stat.S_ISSOCK(endpoint.st_mode)
            ):
                raise _refuse()

    def cleanup(
        self, *, launch_identity: tuple[int, int] | None
    ) -> NativeGuestEndpointCleanupReceipt:
        with self._lock:
            if launch_identity != self._launch_identity:
                raise _refuse()
            if self._receipt is not None:
                return self._receipt
            if self._closed:
                raise _refuse()
            terminal = self._worker.terminal_receipt()
            if (
                self._worker.cleanup_uncertain is not False
                or type(terminal) is not dict
                or terminal.get("schema_version") != _TERMINAL_SCHEMA
            ):
                raise _refuse()
            terminal_ref = _content_ref(terminal, "receipt_ref")
            required = (
                "verified_absent",
                "worker_reaped",
                "cgroup_empty_and_removed",
                "endpoint_absent",
                "staging_root_absent",
                "identity_released",
            )
            if (
                terminal.get("attempt_id") != self.attempt_id
                or terminal.get("resource_claim_ref") != self.resource_claim_ref
                or terminal.get("observation_ref") != self._native_observation_ref
                or terminal.get("qualified_receipt_ref") != self._worker.qualified_receipt_ref
                or terminal.get("plan_ref") != self._plan_ref
                or terminal.get("cgroup_ref") != self._cgroup_ref
                or terminal.get("worker_pid") != self._worker_pid
                or terminal.get("worker_start_ticks") != self._worker_start_ticks
                or any(terminal.get(name) is not True for name in required)
            ):
                raise _refuse()
            self._check_guest_identity(endpoint_present=False)
            try:
                os.stat("launch.json", dir_fd=self._host_directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise _refuse()
            if os.fstat(self._host_directory_fd).st_nlink != 0:
                raise _refuse()
            try:
                os.stat(self._host_path.name, dir_fd=self._host_parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise _refuse()
            # Native terminal establishes that the now-dead guest namespace
            # and its staging pathname cannot expose the retained tmpfs root.
            staging = Path(f"/tmp/bluefire-strix-runtime-root-{self._worker_pid}")
            if os.path.lexists(staging):
                raise _refuse()
            body: dict[str, Any] = {
                "schema_version": RECEIPT_SCHEMA,
                "attempt_id": self.attempt_id,
                "claim_digest": self.claim_digest,
                "worker_containment_ref": self.worker_containment_ref,
                "directory_identity": list(self.directory_identity),
                "endpoint_identity": list(self.endpoint_identity),
                "launch_identity": (
                    None if self._launch_identity is None else list(self._launch_identity)
                ),
                "endpoint_absent": True,
                "launch_absent": True,
                "directory_absent": True,
                "native_worker_absent": True,
                "socket_entry_unlinked": True,
                "host_staging_absent": True,
                "retained_directory_fd_open": True,
                "native_observation_ref": self._native_observation_ref,
                "native_terminal_ref": terminal_ref,
                "cleanup_owner_ref": self.cleanup_owner_ref,
            }
            self._receipt = NativeGuestEndpointCleanupReceipt(
                schema_version=RECEIPT_SCHEMA,
                attempt_id=self.attempt_id,
                claim_digest=self.claim_digest,
                worker_containment_ref=self.worker_containment_ref,
                directory_identity=self.directory_identity,
                endpoint_identity=self.endpoint_identity,
                launch_identity=self._launch_identity,
                endpoint_absent=True,
                launch_absent=True,
                directory_absent=True,
                native_worker_absent=True,
                socket_entry_unlinked=True,
                host_staging_absent=True,
                retained_directory_fd_open=True,
                native_observation_ref=self._native_observation_ref,
                native_terminal_ref=terminal_ref,
                cleanup_owner_ref=self.cleanup_owner_ref,
                receipt_ref=content_hash(body),
            )
            return self._receipt

    def reopen_live_terminal(self) -> NativeGuestEndpointCleanupReceipt:
        """Recheck the held endpoint identities before durable source retention.

        The receipt records the first successful cleanup. This method checks
        the still-owned descriptors and paths again; it does not mint a new
        observation time or replace the original receipt.
        """

        with self._lock:
            receipt = self._receipt
            if receipt is None or self._closed or self._worker.cleanup_uncertain:
                raise _refuse()
            terminal = self._worker.terminal_receipt()
            if (
                type(terminal) is not dict
                or _content_ref(terminal, "receipt_ref") != receipt.native_terminal_ref
                or terminal.get("verified_absent") is not True
            ):
                raise _refuse()
            self._check_guest_identity(endpoint_present=False)
            if os.fstat(self._host_directory_fd).st_nlink != 0:
                raise _refuse()
            try:
                os.stat("launch.json", dir_fd=self._host_directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise _refuse()
            try:
                os.stat(self._host_path.name, dir_fd=self._host_parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise _refuse()
            if os.path.lexists(Path(f"/tmp/bluefire-strix-runtime-root-{self._worker_pid}")):
                raise _refuse()
            return receipt

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            for name in (
                "_guest_directory_fd",
                "_guest_listener_fd",
                "_host_directory_fd",
                "_host_parent_fd",
            ):
                descriptor = getattr(self, name)
                setattr(self, name, -1)
                if descriptor >= 0:
                    with contextlib.suppress(OSError):
                        os.close(descriptor)


__all__ = [
    "NativeGuestEndpointCleanupError",
    "NativeGuestEndpointCleanupOwner",
    "NativeGuestEndpointCleanupReceipt",
]
