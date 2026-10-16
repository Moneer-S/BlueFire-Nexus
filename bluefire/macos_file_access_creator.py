"""Original sealed-namespace producer; no public task or lease minter.

Creation is explicit privileged setup. The authenticated workspace bridge must
later mint original reservations after committed journal validation. An intent,
receipt, PID, or digest alone cannot enter any of the private effect methods.
"""

from __future__ import annotations

import os
import secrets
import socket
import subprocess
import threading
import time
from _thread import LockType
from typing import Any, Callable, Protocol, cast

from . import runner_client as runner
from .macos_file_access_contract import (
    MAX_MESSAGE,
    MAX_REQUESTS,
    REQUEST_SCHEMA,
    MacOSFileAccessContractError,
    validate_credentials,
    validate_observation,
    validate_request,
)
from .macos_file_access_intent import ReviewedMacOSTaskIntent as ReviewedMacOSTaskIntent
from .macos_file_access_namespace import SealedMacOSNamespace
from .macos_file_access_peer import MacOSChildConsistency, darwin_clock_ns, observe_owned_child
from .macos_file_access_worker import MacOSFileAccessWorker
from .util import canonical_json_bytes, content_hash

_OPERATIONS = ("baseline", "harden", "probe", "verify_owner", "rollback", "close_attempt")
_IDS = ("real_uid", "effective_uid", "saved_uid", "real_gid", "effective_gid", "saved_gid")


def _require(value: bool) -> None:
    if not value:
        raise MacOSFileAccessContractError("The original Darwin creator operation is unavailable.")


def _socket_constant(name: str) -> int:
    value = getattr(socket, name, None)
    if not isinstance(value, int) or isinstance(value, bool):
        raise MacOSFileAccessContractError("The original Darwin creator operation is unavailable.")
    return cast(int, value)


class _WorkspaceCustody(Protocol):
    @property
    def _creator(self) -> MacOSFileAccessCreator: ...

    @property
    def _process(self) -> subprocess.Popen[bytes] | None: ...

    @property
    def _consistency(self) -> MacOSChildConsistency | None: ...

    @property
    def _stream(self) -> socket.socket | None: ...

    def assert_current(self) -> None: ...


class OriginalMacOSControllerLease:
    """Only the concrete inherited-controller bootstrap may mint this type."""

    __slots__ = (
        "_creator",
        "_runtime",
        "_channel",
        "_workspace_process",
        "_workspace_consistency",
        "_closed",
        "_poisoned",
        "_workspace_owner",
        "_check_current",
    )

    _creator: MacOSFileAccessCreator
    _runtime: runner.SubprocessRustRunner
    _channel: socket.socket
    _workspace_process: subprocess.Popen[bytes]
    _workspace_consistency: MacOSChildConsistency
    _closed: bool
    _poisoned: bool
    _workspace_owner: _WorkspaceCustody
    _check_current: Callable[[], None]

    def __new__(cls, *_args, **_kwargs):
        raise TypeError("The original authenticated controller bootstrap is required.")


class OriginalMacOSTaskReservation:
    """Minted only while the original bridge consumes a committed child frame."""

    __slots__ = (
        "_creator",
        "_lease",
        "_intent",
        "_used",
        "_budget_reserved",
        "_attempt_id",
        "_probe_task_id",
        "_probe_receipt_digest",
    )

    _creator: MacOSFileAccessCreator
    _lease: OriginalMacOSControllerLease
    _intent: ReviewedMacOSTaskIntent
    _used: bool
    _budget_reserved: bool
    _attempt_id: str | None
    _probe_task_id: str | None
    _probe_receipt_digest: str | None

    def __new__(cls, *_args, **_kwargs):
        raise TypeError("An original committed controller task reservation is required.")


class OwnedMacOSTaskReceipt:
    """Original per-request evidence, never whole-enrollment cleanup authority."""

    __slots__ = ("_creator", "_document")

    _creator: MacOSFileAccessCreator
    _document: dict[str, Any]

    def __new__(cls, *_args, **_kwargs):
        raise TypeError("The original creator must retain and close this request.")

    def document(self) -> dict[str, Any]:
        # Documents are inactive history; the opaque instance retains its producer.
        import json

        value = json.loads(canonical_json_bytes(self._document))
        _require(type(value) is dict)
        return cast(dict[str, Any], value)


class MacOSFileAccessCreator:
    """One original namespace and three retained workers, not another coordinator."""

    _runtime: runner.SubprocessRustRunner
    _creator_pid: int
    _lock: LockType
    _namespaces: list[SealedMacOSNamespace]
    _workers: dict[str, MacOSFileAccessWorker]
    _sockets: list[tuple[socket.socket, socket.socket]]
    _lease: OriginalMacOSControllerLease | None
    _revision: int
    _state: str
    _used_budget: int
    _sequences: dict[str, int]
    _tasks: dict[str, OwnedMacOSTaskReceipt | None]
    _task_attempts: dict[str, str | None]
    _last_probe: OwnedMacOSTaskReceipt | None
    _last_clock: tuple[int, int]
    _last_binding: dict[str, Any] | None
    _local_cleanup_unknown: bool
    _orphan_close_attempted: set[tuple[int, int]]
    _custody_digest: str
    _namespace: SealedMacOSNamespace

    def __new__(cls, *_args, **_kwargs):
        raise TypeError("Explicit original privileged setup is required.")

    @classmethod
    def create(
        cls,
        runtime: runner.SubprocessRustRunner,
        *,
        owner: dict[str, Any],
        reader: dict[str, Any],
        retained: list[MacOSFileAccessCreator],
    ) -> MacOSFileAccessCreator:
        _require(
            type(runtime) is runner.SubprocessRustRunner and type(retained) is list and not retained
        )
        owner, reader = validate_credentials(owner), validate_credentials(reader)
        value = cast(MacOSFileAccessCreator, object.__new__(cls))
        value._runtime = runtime
        value._creator_pid = os.getpid()
        value._lock = threading.Lock()
        value._namespaces = []
        value._workers = {}
        value._sockets = []
        value._lease = None
        value._revision = 1
        value._state = "creating"
        value._used_budget = 0
        value._sequences = {role: 0 for role in ("reader", "owner", "control")}
        value._tasks = {}
        value._task_attempts = {}
        value._last_probe = None
        value._last_clock = (0, 0)
        value._last_binding = None
        value._local_cleanup_unknown = False
        value._orphan_close_attempted = set()
        value._custody_digest = content_hash(
            {
                "schema_version": "bluefire.macos-file-access-creator-instance.v1",
                "nonce": secrets.token_hex(32),
                "creator_pid": value._creator_pid,
                "runner_digest": runtime.runner_binary_digest,
                "interpreter_digest": runtime._watchdog_interpreter_digest,  # noqa: SLF001
                "helper_digest": runtime.parent_death_script_digest,
            }
        )
        # The caller retains partial ownership before namespace or child creation.
        value._lock.acquire()
        try:
            retained.append(value)
            namespace = SealedMacOSNamespace.create(
                owner=owner, reader=reader, retained=value._namespaces
            )
            value._namespace = namespace
            original = namespace.binding(custody_digest=value._custody_digest, revision=1)
            value._last_binding = original
            for role in ("reader", "owner", "control"):
                with namespace.operation():
                    parent, child = socket.socketpair(
                        _socket_constant("AF_UNIX"), _socket_constant("SOCK_STREAM")
                    )
                    value._sockets.append((parent, child))
                    parent.set_inheritable(False)
                    child.set_inheritable(False)
                    worker = MacOSFileAccessWorker(
                        runtime,
                        original,
                        role=role,
                        resource_fd=namespace.descriptor(role),
                        channel=parent,
                        child_channel=child,
                    )
                    value._workers[role] = worker
                    worker.start()
            value._state = "created"
            return value
        except BaseException:
            value._state = "unknown"
            raise
        finally:
            value._lock.release()

    def _binding(self) -> dict[str, Any]:
        _require(
            os.getpid() == self._creator_pid
            and self._state not in ("creating", "unknown", "retired")
        )
        current = self._namespace.binding(
            custody_digest=self._custody_digest, revision=self._revision
        )
        self._last_binding = current
        return current

    def _guard(self, intent: dict[str, Any]) -> None:
        self._namespace.assert_current()
        wall, monotonic = time.time_ns() // 1_000_000, darwin_clock_ns()
        binding = self._last_binding
        _require(
            binding is not None
            and binding["issued_at_ms"] <= intent["issued_at_ms"]
            and intent["expires_at_ms"] <= binding["expires_at_ms"]
            and intent["deadline_ns"] <= binding["original_deadline_ns"]
            and intent["issued_at_ms"] <= wall < intent["expires_at_ms"]
            and intent["issued_monotonic_ns"] <= monotonic < intent["deadline_ns"]
            and wall >= self._last_clock[0]
            and monotonic >= self._last_clock[1]
        )
        self._last_clock = wall, monotonic

    def _require_lease(self) -> None:
        lease = self._lease
        if type(lease) is not OriginalMacOSControllerLease:
            raise MacOSFileAccessContractError(
                "The original Darwin creator operation is unavailable."
            )
        _require(
            lease._creator is self
            and lease._runtime is self._runtime
            and lease._closed is False
            and lease._poisoned is False
            and isinstance(lease._channel, socket.socket)
            and lease._channel.family == _socket_constant("AF_UNIX")
            and lease._channel.fileno() >= 3
            and lease._channel.getsockopt(
                _socket_constant("SOL_SOCKET"), _socket_constant("SO_TYPE")
            )
            == _socket_constant("SOCK_STREAM")
            and type(lease._workspace_consistency) is MacOSChildConsistency
        )
        lease._channel.getpeername()
        # This is the ordinary HOST workspace, whose original private session
        # may have fixed descendants. Primitive workers retain no-fork custody.
        workspace = lease._workspace_owner
        workspace.assert_current()
        _require(
            workspace._creator is self
            and workspace._process is lease._workspace_process
            and workspace._consistency == lease._workspace_consistency
            and workspace._stream is lease._channel
        )
        lease._check_current()
        process = lease._workspace_process
        binding = self._last_binding
        if binding is None:
            raise MacOSFileAccessContractError(
                "The original Darwin creator operation is unavailable."
            )
        owner = binding["owner"]
        actual = observe_owned_child(
            process,
            expected_ids={key: owner[key] for key in _IDS},
            expected_start=lease._workspace_consistency.start,
        )
        _require(actual == lease._workspace_consistency)

    def _context(self, operation: str, current: dict[str, Any]) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.macos-file-access-creator-context.v1",
            "operation": operation,
            "state": self._state,
            "binding": current,
            "probe_digest": (
                None if self._last_probe is None else content_hash(self._last_probe.document())
            ),
        }

    def review_context(self, operation: str) -> dict[str, Any]:
        _require(type(operation) is str and operation in _OPERATIONS)
        if not self._lock.acquire(blocking=False):
            _require(False)
        try:
            with self._namespace.operation():
                body = self._context(operation, self._binding())
                return {**body, "context_digest": content_hash(body)}
        finally:
            self._lock.release()

    def _receipt(
        self,
        intent: dict[str, Any],
        requests: list[dict[str, Any]],
        terminals: list[dict[str, Any]],
        before: int,
        complete: bool,
    ) -> OwnedMacOSTaskReceipt:
        row = {
            "schema_version": "bluefire.macos-file-access-task-receipt.v1",
            **{
                key: intent[key]
                for key in (
                    "task_id",
                    "transport_request_hash",
                    "context_digest",
                    "binding_digest",
                    "operation",
                )
            },
            "state": "complete" if complete else "unknown",
            "dispatch": "attempted" if complete else "unknown",
            "producer_request_usage": "settled" if complete else "unknown",
            "settlement_scope": "producer_local_only",
            "original_workers": "retained",
            "namespace": "original_creator_held" if complete else "unknown",
            "whole_enrollment_cleanup": False,
            "control_revision_before": before,
            "control_revision_after": self._revision,
            "requests": [
                {
                    "request_id": req["request_id"],
                    "sequence": req["sequence"],
                    "operation": req["operation"],
                    "request_digest": content_hash(req),
                }
                for req in requests
            ],
            "terminals": terminals,
            "shared_request_budget_used": self._used_budget,
        }
        _require(len(canonical_json_bytes(row)) <= MAX_MESSAGE)
        value = cast(OwnedMacOSTaskReceipt, object.__new__(OwnedMacOSTaskReceipt))
        value._creator, value._document = self, row
        return value

    def _perform(
        self,
        reservation: OriginalMacOSTaskReservation,
        operation: str,
        plan: tuple[tuple[str, str], ...],
    ) -> OwnedMacOSTaskReceipt:
        if not self._lock.acquire(blocking=False):
            _require(False)
        requests: list[dict[str, Any]] = []
        terminals: list[dict[str, Any]] = []
        intent: dict[str, Any] | None = None
        before = self._revision
        consumed = False
        try:
            _require(
                type(reservation) is OriginalMacOSTaskReservation
                and reservation._creator is self
                and reservation._lease is self._lease
                and reservation._used is False
                and type(reservation._intent) is ReviewedMacOSTaskIntent
            )
            self._require_lease()
            intent = reservation._intent.document()
            current = self._binding()
            self._guard(intent)
            allowed = {
                "baseline": ("created", "rolled_back"),
                "harden": ("baseline_verified", "rolled_back"),
                "probe": ("hardened",),
                "verify_owner": ("hardened",),
                "rollback": ("hardened",),
            }
            _require(
                intent["operation"] == operation
                and self._state in allowed[operation]
                and intent["control_revision"] == self._revision
                and intent["binding_digest"] == content_hash(current)
                and intent["context_digest"] == content_hash(self._context(operation, current))
                and intent["task_id"] not in self._tasks
                and reservation._budget_reserved
                and self._used_budget <= MAX_REQUESTS
            )
            if operation in ("probe", "verify_owner"):
                _require(reservation._attempt_id is not None)
            if operation == "verify_owner":
                _require(
                    self._last_probe is not None
                    and self._last_probe._creator is self
                    and self._last_probe.document()["control_revision_after"] == self._revision
                    and reservation._attempt_id is not None
                    and reservation._probe_task_id == self._last_probe.document()["task_id"]
                    and reservation._probe_receipt_digest
                    == content_hash(self._last_probe.document())
                    and self._task_attempts.get(self._last_probe.document()["task_id"])
                    == reservation._attempt_id
                    and self._tasks.get(self._last_probe.document()["task_id"]) is self._last_probe
                )
            with self._namespace.operation():
                _require(self._binding() == current)
                self._guard(intent)
                # Reserve every primitive before any first byte; there is no partial pair admission.
                reservation._used = True
                self._tasks[intent["task_id"]] = None
                self._task_attempts[intent["task_id"]] = reservation._attempt_id
                consumed = True
                for role, primitive in plan:
                    self._guard(intent)
                    self._require_lease()
                    current = self._binding()
                    self._sequences[role] += 1
                    request = validate_request(
                        {
                            "schema_version": REQUEST_SCHEMA,
                            "binding": current,
                            "binding_digest": content_hash(current),
                            "request_id": secrets.token_hex(32),
                            "sequence": self._sequences[role],
                            "operation": primitive,
                            **{
                                key: intent[key]
                                for key in (
                                    "issued_at_ms",
                                    "expires_at_ms",
                                    "issued_monotonic_ns",
                                    "deadline_ns",
                                )
                            },
                        }
                    )
                    requests.append(request)
                    observed = validate_observation(self._workers[role].exchange(request), request)
                    terminals.append(observed)
                    _require(
                        observed["outcome"] not in ("unknown", "refused")
                        and observed["request_handle_cleanup"] != "unknown"
                        and observed["held_handle_cleanup"] == "retained"
                    )
                    self._guard(intent)
                    self._require_lease()
                    if primitive in ("harden", "rollback"):
                        _require(observed["outcome"] == "mode_changed")
                        self._revision += 1
                        _require(
                            self._binding()["mode"] == ("0600" if primitive == "harden" else "0640")
                        )
                    elif operation in ("baseline", "rollback", "verify_owner"):
                        _require(observed["outcome"] == "allowed")
                    else:
                        _require(observed["outcome"] in ("allowed", "denied"))
                if operation == "baseline":
                    self._revision += 1
                self._state = {
                    "baseline": "baseline_verified",
                    "harden": "hardened",
                    "rollback": "rolled_back",
                }.get(operation, self._state)
                self._guard(intent)
                self._require_lease()
            receipt = self._receipt(intent, requests, terminals, before, True)
            self._require_lease()
            self._guard(intent)
            self._tasks[intent["task_id"]] = receipt
            if operation == "probe":
                self._last_probe = receipt
            elif operation in ("harden", "rollback", "baseline"):
                self._last_probe = None
            return receipt
        except BaseException as error:
            if consumed:
                self._state = "unknown"
                # Never leave a success installed if the unknown fallback cannot serialize.
                if intent is None:
                    raise MacOSFileAccessContractError(
                        "The original Darwin creator operation is unavailable."
                    ) from None
                self._tasks[intent["task_id"]] = None
                receipt = self._receipt(intent, requests, terminals, before, False)
                self._tasks[intent["task_id"]] = receipt
                if not isinstance(error, Exception):
                    raise
                return receipt
            raise
        finally:
            self._lock.release()

    def _baseline(self, reservation: OriginalMacOSTaskReservation) -> OwnedMacOSTaskReceipt:
        return self._perform(
            reservation, "baseline", (("reader", "read_reader"), ("owner", "read_owner"))
        )

    def _harden(self, reservation: OriginalMacOSTaskReservation) -> OwnedMacOSTaskReceipt:
        return self._perform(reservation, "harden", (("control", "harden"),))

    def _probe(self, reservation: OriginalMacOSTaskReservation) -> OwnedMacOSTaskReceipt:
        return self._perform(reservation, "probe", (("reader", "read_reader"),))

    def _verify_owner(self, reservation: OriginalMacOSTaskReservation) -> OwnedMacOSTaskReceipt:
        return self._perform(reservation, "verify_owner", (("owner", "read_owner"),))

    def _rollback(self, reservation: OriginalMacOSTaskReservation) -> OwnedMacOSTaskReceipt:
        return self._perform(
            reservation,
            "rollback",
            (("control", "rollback"), ("reader", "read_reader"), ("owner", "read_owner")),
        )

    def retained_task_receipt(self, task_id: str) -> OwnedMacOSTaskReceipt | None:
        """Read an original retained receipt without observation or task replay."""
        with self._lock:
            return self._tasks.get(task_id)

    def close(self) -> dict[str, Any]:
        """Retire components only. Fixture removal remains explicitly unavailable."""
        _require(os.getpid() == self._creator_pid)
        if not self._lock.acquire(blocking=False):
            _require(False)
        try:
            _require(self._state != "creating")
            self._state = "retired"
            workers_closed = True
            for worker in self._workers.values():
                try:
                    workers_closed = worker.settle() and workers_closed
                except BaseException:
                    workers_closed = False
            for pair_index in range(len(self._workers), len(self._sockets)):
                for stream_index, stream in enumerate(self._sockets[pair_index]):
                    identity = pair_index, stream_index
                    if identity in self._orphan_close_attempted:
                        continue
                    self._orphan_close_attempted.add(identity)
                    try:
                        stream.close()
                    except BaseException:
                        self._local_cleanup_unknown = True
            handles_closed = workers_closed and not self._local_cleanup_unknown
            if handles_closed:
                for namespace in self._namespaces:
                    try:
                        handles_closed = namespace.close_handles() and handles_closed
                    except BaseException:
                        handles_closed = False
            return {
                "scope": "original_component_retirement_only",
                "workers_closed": workers_closed,
                "namespace_handles_closed": handles_closed and not self._local_cleanup_unknown,
                "fixture_removed": False,
                "settled": False,
                "live_ready": False,
            }
        finally:
            self._lock.release()

    def reset(self) -> None:
        # No bool/receipt can grant mutation without the original namespace remover.
        raise MacOSFileAccessContractError(
            "Original receipt-bound namespace removal is unavailable."
        )
