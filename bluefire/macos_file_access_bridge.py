"""Original workspace channel adapter behind existing committed task admission.

Only the protected child emits journal provenance. The privileged half never
opens ProductStore and never reconstructs a lease from saved documents.
Composition and reset remain unavailable on this control-only transport.
"""

from __future__ import annotations

import re
import select
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Mapping, Protocol, cast

from .execution_contracts import execution_task_identity
from .macos_file_access_contract import MAX_OPERATION_NS, MAX_REQUESTS, MacOSFileAccessContractError
from .macos_file_access_creator import (
    MacOSFileAccessCreator,
    OriginalMacOSControllerLease,
    OriginalMacOSTaskReservation,
    ReviewedMacOSTaskIntent,
)
from .macos_file_access_peer import darwin_clock_ns
from .util import content_hash

if TYPE_CHECKING:
    from .macos_file_access_workspace import MacOSWorkspaceOwner
    from .macos_file_access_workspace_bootstrap import OriginalWorkspaceEndpoint

_REQUEST = "bluefire.macos-workspace-request.v1"
_RESPONSE = "bluefire.macos-workspace-response.v1"
_COMMITTED = "bluefire.macos-file-access-committed-task.v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COSTS = {"baseline": 2, "harden": 1, "rollback": 3}


def _require(value: bool) -> None:
    if not value:
        raise MacOSFileAccessContractError("The original committed Darwin task is unavailable.")


def _digest(value: Any) -> None:
    _require(type(value) is str and _DIGEST.fullmatch(value) is not None)


def _identifier(value: Any) -> None:
    _require(
        type(value) is str
        and 0 < len(value) <= 128
        and all(c.isascii() and (c.isalnum() or c in "._-") for c in value)
    )


def _committed(value: Any) -> dict[str, Any]:
    """Validate inactive data; this function never mints native authority."""
    _require(
        type(value) is dict
        and set(value)
        == {
            "schema_version",
            "intent",
            "claim",
            "preparation_digest",
            "dispatch_digest",
            "job_id",
            "attempt",
            "cancelled",
        }
    )
    _require(value["schema_version"] == _COMMITTED and value["cancelled"] is False)
    # The existing capability ledger must commit a full primitive/cleanup
    # reservation and exact prior probe dependency before this can be enabled.
    _require(value["attempt"] is None)
    _identifier(value["job_id"])
    _digest(value["preparation_digest"])
    _digest(value["dispatch_digest"])
    _require(
        value["dispatch_digest"]
        == content_hash({key: item for key, item in value.items() if key != "dispatch_digest"})
    )
    intent = ReviewedMacOSTaskIntent.from_document(value["intent"]).document()
    operation = intent["operation"]
    _require(operation in _COSTS)
    claim = value["claim"]
    _require(
        type(claim) is dict
        and set(claim)
        == {
            "job_id",
            "task_id",
            "step_id",
            "request_hash",
            "transport_request_hash",
            "manifest",
            "runner_profile",
        }
    )
    manifest, profile = claim["manifest"], claim["runner_profile"]
    _require(type(manifest) is dict and type(profile) is dict)
    _require(
        set(manifest)
        == {
            "schema_version",
            "run_id",
            "step_id",
            "action_id",
            "request_hash",
            "params",
            "approval",
        }
        and manifest["schema_version"] == "bluefire.macos-file-access-task.v1"
        and manifest["step_id"] == operation
        and manifest["params"] == {}
        and manifest["action_id"] == "macos.file_access." + operation + ".v1"
        and type(manifest["approval"]) is dict
        and set(manifest["approval"]) == {"review_digest"}
    )
    _identifier(manifest["run_id"])
    _digest(manifest["request_hash"])
    _digest(manifest["approval"]["review_digest"])
    _require(
        set(profile) == {"schema_version", "macos_file_access_binding", "policy_digest"}
        and profile["schema_version"] == "bluefire.macos-file-access-task-profile.v1"
        and profile["policy_digest"]
        == content_hash({key: item for key, item in profile.items() if key != "policy_digest"})
    )
    task_id, transport = execution_task_identity(manifest, profile)
    _require(
        task_id == intent["task_id"] == claim["task_id"]
        and transport == intent["transport_request_hash"] == claim["transport_request_hash"]
        and claim["job_id"] == value["job_id"]
        and claim["step_id"] == operation
        and claim["request_hash"] == manifest["request_hash"]
        and content_hash(profile["macos_file_access_binding"]) == intent["binding_digest"]
    )
    return cast(dict[str, Any], value)


class CommittedMacOSJournal(Protocol):
    def begin_macos_file_access_dispatch(
        self, task_id: str, transport_request_hash: str, *, now_ms: int
    ) -> dict[str, Any]: ...


class MacOSWorkspaceTaskTransport:
    """Existing task hook -> committed journal -> original inherited endpoint."""

    def __init__(self, endpoint: OriginalWorkspaceEndpoint, store: CommittedMacOSJournal):
        self._endpoint, self._store = endpoint, store

    def execute_task(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path | None = None,
    ) -> Mapping[str, Any]:
        original_task, transport = execution_task_identity(manifest, profile)
        _require(task_id == original_task and not cancel_event.is_set())
        self._endpoint.assert_current()
        frame = self._store.begin_macos_file_access_dispatch(
            task_id, transport, now_ms=time.time_ns() // 1_000_000
        )
        frame = _committed(frame)
        _require(
            frame["claim"]["manifest"] == dict(manifest)
            and frame["claim"]["runner_profile"] == dict(profile)
            and not cancel_event.is_set()
        )
        receipt = self._endpoint.dispatch_committed(frame, cancel_event=cancel_event)
        complete = receipt["state"] == "complete"
        # The control journal retains this exact result. No public path supplied
        # to execute_task may redirect the private response into a different file.
        return {
            "schema_version": "bluefire.runner-result.v1",
            "request_hash": manifest["request_hash"],
            "status": "success" if complete else "error",
            "output": {"macos_receipt": receipt},
            "artifacts": {},
            "receipt_ids": [],
            "telemetry": [],
            "error": None if complete else {"code": "macos_request_unknown"},
        }


def exchange(
    endpoint: OriginalWorkspaceEndpoint,
    operation: str,
    payload: dict[str, Any],
    cancel_event: threading.Event | None = None,
) -> dict[str, Any]:
    """Exactly one reader; cancellation closes custody instead of sending a retry."""
    with endpoint._io_lock:
        endpoint.assert_current()
        _require(operation in ("review_context", "dispatch_committed"))
        started_wall = time.time_ns() // 1_000_000
        started_monotonic = endpoint._api.darwin_clock_ns()
        binding = endpoint._recipe["binding"]
        exchange_deadline = min(
            binding["original_deadline_ns"], started_monotonic + MAX_OPERATION_NS
        )
        exchange_expires = min(
            binding["expires_at_ms"], started_wall + MAX_OPERATION_NS // 1_000_000
        )
        endpoint._sequence += 1
        sequence = endpoint._sequence
        request = {
            "schema_version": _REQUEST,
            "sequence": sequence,
            "operation": operation,
            "payload": payload,
        }

        def guard() -> float:
            if cancel_event is not None and cancel_event.is_set():
                endpoint.close()
                _require(False)
            remaining: float = endpoint.assert_current()
            wall, monotonic = time.time_ns() // 1_000_000, endpoint._api.darwin_clock_ns()
            _require(
                started_wall <= wall < exchange_expires
                and started_monotonic <= monotonic < exchange_deadline
            )
            remaining = min(
                remaining, (exchange_expires - wall) / 1000, (exchange_deadline - monotonic) / 1e9
            )
            if operation == "dispatch_committed":
                intent = payload["intent"]
                _require(
                    intent["issued_at_ms"] <= wall < intent["expires_at_ms"]
                    and intent["issued_monotonic_ns"] <= monotonic < intent["deadline_ns"]
                )
                remaining = min(
                    remaining,
                    (intent["expires_at_ms"] - wall) / 1000,
                    (intent["deadline_ns"] - monotonic) / 1e9,
                )
            return min(remaining, 0.025)

        try:
            endpoint._api._send(endpoint._stream, request, guard)
            response = endpoint._api._receive(endpoint._stream, guard)
            _require(
                set(response)
                == {"schema_version", "sequence", "operation", "request_digest", "payload"}
                and response["schema_version"] == _RESPONSE
                and response["sequence"] == sequence
                and response["operation"] == operation
                and response["request_digest"] == content_hash(request)
                and type(response["payload"]) is dict
            )
            guard()
            return cast(dict[str, Any], response["payload"])
        except BaseException:
            endpoint._poisoned = True
            endpoint.close()
            raise


class OriginalMacOSWorkspaceBridge:
    """Sole parent reader on the exact retained normal HOST workspace channel."""

    _owner: MacOSWorkspaceOwner
    _creator: MacOSFileAccessCreator
    _lease: OriginalMacOSControllerLease
    _sequence: int
    _closed: bool
    _in_task: bool
    _pending: dict[str, Any] | None
    _received_request: dict[str, Any] | None
    _thread: threading.Thread

    def __new__(cls, *_args, **_kwargs) -> OriginalMacOSWorkspaceBridge:
        raise TypeError("The original retained workspace is required.")

    @classmethod
    def attach(cls, owner: MacOSWorkspaceOwner) -> OriginalMacOSWorkspaceBridge:
        from .macos_file_access_workspace import MacOSWorkspaceOwner

        _require(
            type(owner) is MacOSWorkspaceOwner and type(owner._creator) is MacOSFileAccessCreator
        )
        with owner._channel_lock, owner._creator._lock:
            return cls._attach_locked(owner)

    @classmethod
    def _attach_locked(cls, owner: MacOSWorkspaceOwner) -> OriginalMacOSWorkspaceBridge:
        owner.assert_current()
        creator = owner._creator
        _require(creator._lease is None)
        if owner._stream is None or owner._process is None or owner._consistency is None:
            raise MacOSFileAccessContractError("The original workspace custody is unavailable.")
        value: OriginalMacOSWorkspaceBridge = object.__new__(cls)
        value._owner, value._creator = owner, creator
        value._sequence = 0
        value._closed = False
        value._in_task = False
        value._pending = None
        value._received_request = None
        lease: OriginalMacOSControllerLease = object.__new__(OriginalMacOSControllerLease)
        lease._creator, lease._runtime = creator, creator._runtime
        lease._workspace_owner = owner
        lease._channel = owner._stream
        lease._workspace_process = owner._process
        lease._workspace_consistency = owner._consistency
        lease._closed = lease._poisoned = False
        lease._check_current = value._task_current
        value._lease = creator._lease = lease
        value._thread = threading.Thread(
            target=value._run, name="macos-original-workspace-channel", daemon=True
        )
        return value

    def start(self) -> None:
        self._thread.start()

    def _task_current(self) -> None:
        _require(not self._closed and not self._lease._poisoned)
        self._owner.assert_current()
        readable, _, _ = select.select([self._lease._channel], [], [], 0)
        # During native work the child only waits for this response. EOF or any
        # unsolicited bytes mean cancellation/loss/uncertain custody, never Go.
        _require(not readable)

    def _reserve_received(self, frame: dict[str, Any]) -> OriginalMacOSTaskReservation:
        creator = self._creator
        _require(self._in_task and self._pending is frame and creator._lease is self._lease)
        intent = ReviewedMacOSTaskIntent.from_document(frame["intent"])
        row = intent.document()
        with creator._lock:
            creator._require_lease()
            binding = creator._binding()
            creator._guard(row)
            _require(
                row["binding_digest"] == content_hash(binding)
                and row["context_digest"]
                == content_hash(creator._context(row["operation"], binding))
                and row["control_revision"] == creator._revision
                and row["task_id"] not in creator._tasks
            )
            cost = _COSTS[row["operation"]]
            _require(creator._used_budget + cost <= MAX_REQUESTS)
            # No refund on a later refusal, exception or uncertain exchange.
            creator._used_budget += cost
            reservation: OriginalMacOSTaskReservation = object.__new__(OriginalMacOSTaskReservation)
            reservation._creator, reservation._lease, reservation._intent = (
                creator,
                self._lease,
                intent,
            )
            reservation._used = False
            reservation._budget_reserved = True
            reservation._attempt_id = None
            reservation._probe_task_id = None
            reservation._probe_receipt_digest = None
            return reservation

    def _received(self, request: dict[str, Any]) -> dict[str, Any]:
        _require(self._received_request is request and not self._closed)
        _require(
            set(request) == {"schema_version", "sequence", "operation", "payload"}
            and request["schema_version"] == _REQUEST
            and type(request["sequence"]) is int
            and request["sequence"] == self._sequence + 1
            and type(request["payload"]) is dict
        )
        self._sequence += 1
        operation, payload = request["operation"], request["payload"]
        if operation == "review_context":
            _require(set(payload) == {"operation"} and payload["operation"] in _COSTS)
            result = self._creator.review_context(payload["operation"])
        else:
            _require(operation == "dispatch_committed")
            frame = _committed(payload)
            self._in_task, self._pending = True, frame
            try:
                reservation = self._reserve_received(frame)
                fixed = {
                    "baseline": self._creator._baseline,
                    "harden": self._creator._harden,
                    "rollback": self._creator._rollback,
                }
                result = fixed[frame["intent"]["operation"]](reservation).document()
                self._task_current()
            finally:
                self._in_task, self._pending = False, None
        return {
            "schema_version": _RESPONSE,
            "sequence": self._sequence,
            "operation": operation,
            "request_digest": content_hash(request),
            "payload": result,
        }

    def _run(self) -> None:
        from .macos_file_access_workspace import _receive, _send

        try:
            while not self._closed:
                with self._owner._channel_lock:
                    self._owner.assert_current()
                    readable, _, _ = select.select([self._lease._channel], [], [], 0.025)
                    if not readable:
                        continue
                    frame_started = time.time_ns() // 1_000_000
                    frame_deadline = darwin_clock_ns() + MAX_OPERATION_NS

                    def guard(
                        frame_started: int = frame_started, frame_deadline: int = frame_deadline
                    ) -> float:
                        self._owner.assert_current()
                        _require(not self._closed)
                        wall = time.time_ns() // 1_000_000
                        _require(
                            frame_started <= wall < frame_started + MAX_OPERATION_NS // 1_000_000
                        )
                        return min(self._owner._guard(frame_deadline), 0.025)

                    request = _receive(self._lease._channel, guard)
                    self._received_request = request
                    try:
                        response = self._received(request)
                        if request["operation"] == "dispatch_committed":
                            intent = request["payload"]["intent"]

                            def terminal_guard(
                                intent: dict[str, Any] = intent,
                                guard: Callable[[], float] = guard,
                            ) -> float:
                                wall = time.time_ns() // 1_000_000
                                expires_at_ms = cast(int, intent["expires_at_ms"])
                                _require(intent["issued_at_ms"] <= wall < expires_at_ms)
                                return min(
                                    guard(),
                                    self._owner._guard(intent["deadline_ns"]),
                                    (expires_at_ms - wall) / 1000,
                                )

                            _send(self._lease._channel, response, terminal_guard)
                        else:
                            _send(self._lease._channel, response, guard)
                    finally:
                        self._received_request = None
        except BaseException:
            self._lease._poisoned = True
            self._owner._state = "unknown"
            self._owner._close_endpoint()
        finally:
            self._closed = True
            self._lease._closed = True

    def close(self) -> None:
        self._closed = True
        self._lease._poisoned = True

    def join(self) -> None:
        self._thread.join(timeout=1)
        _require(not self._thread.is_alive())
