"""Original workspace channel adapter behind existing committed task admission.

Only the protected child emits journal provenance. The privileged half never
opens ProductStore and never reconstructs a lease from saved documents.
Attempt reads use the same channel; reset and whole-enrollment cleanup remain unavailable.
"""

from __future__ import annotations

import re
import select
import socket
import threading
import time
from _thread import RLock as RLockType
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Mapping, Protocol, cast

from . import macos_file_access_workspace as workspace
from .execution_contracts import execution_task_identity
from .macos_file_access_contract import (
    MAX_OPERATION_NS,
    MAX_REQUESTS,
    MacOSFileAccessContractError,
    validate_binding,
)
from .macos_file_access_creator import (
    MacOSFileAccessCreator,
    OriginalMacOSControllerLease,
    OriginalMacOSTaskReservation,
    ReviewedMacOSTaskIntent,
)
from .macos_file_access_peer import darwin_clock_ns
from .util import content_hash, json_clone

_REQUEST = "bluefire.macos-workspace-request.v1"
_RESPONSE = "bluefire.macos-workspace-response.v1"
_OPERATIONS = ("review_context", "reserve_composition_probe_budget", "dispatch_committed")
_COMMITTED = "bluefire.macos-file-access-committed-task.v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COSTS = {"baseline": 2, "harden": 1, "rollback": 3}
_ATTEMPT_ACTIONS = {
    "probe": "macos.file_access.probe.v1",
    "verify_owner": "macos.file_access.verify_owner.v1",
    "close_attempt": "macos.file_access.close_attempt.v1",
}
_ATTEMPT_FIELDS = set(
    "schema_version attempt_id grant_id grant_digest lease_digest compiled_digest job_id run_id control_owner_id workspace_binding_digest dependency_digest probe_step_id owner_step_id cleanup_step_id issued_at_ms business_expires_at_ms cleanup_expires_at_ms issued_monotonic_ns business_deadline_ns cleanup_deadline_ns primitive_budget probe_task_id probe_receipt_digest task_closures cleanup_claim cleanup_claim_digest".split()
)


def _attempt(frame: dict[str, Any], intent: dict[str, Any]) -> dict[str, Any]:
    attempt, claim = frame["attempt"], frame["claim"]
    _require(type(attempt) is dict and set(attempt) == _ATTEMPT_FIELDS)
    _require(attempt["schema_version"] == "bluefire.macos-file-access-attempt-dispatch.v1")
    for key in (
        "attempt_id",
        "grant_id",
        "job_id",
        "run_id",
        "control_owner_id",
        "probe_step_id",
        "owner_step_id",
        "cleanup_step_id",
    ):
        _identifier(attempt[key])
    for key, prefix, width in (
        ("attempt_id", "attempt-", 32),
        ("grant_id", "grant-", 32),
        ("job_id", "job-", 32),
        ("control_owner_id", "file-control-", 64),
    ):
        _require(re.fullmatch(prefix + rf"[0-9a-f]{{{width}}}", attempt[key]) is not None)
    _require(
        len({attempt[key] for key in ("probe_step_id", "owner_step_id", "cleanup_step_id")}) == 3
    )
    for key in (
        "grant_digest",
        "lease_digest",
        "compiled_digest",
        "workspace_binding_digest",
        "dependency_digest",
    ):
        _digest(attempt[key])
    for key in (
        "issued_at_ms",
        "business_expires_at_ms",
        "cleanup_expires_at_ms",
        "issued_monotonic_ns",
        "business_deadline_ns",
        "cleanup_deadline_ns",
    ):
        _require(type(attempt[key]) is int and 0 < attempt[key] < 2**63)
    _require(
        attempt["issued_at_ms"]
        < attempt["business_expires_at_ms"]
        <= attempt["cleanup_expires_at_ms"]
        and attempt["issued_monotonic_ns"]
        < attempt["business_deadline_ns"]
        <= attempt["cleanup_deadline_ns"]
    )
    budget = attempt["primitive_budget"]
    _require(
        type(budget) is dict
        and budget == {"probe": 1, "verify_owner": 1, "total": 2}
        and all(type(value) is int for value in budget.values())
    )
    manifest, profile = claim["manifest"], claim["runner_profile"]
    operation = intent["operation"]
    _require(operation in _ATTEMPT_ACTIONS and manifest["action_id"] == _ATTEMPT_ACTIONS[operation])
    step = attempt[
        {
            "probe": "probe_step_id",
            "verify_owner": "owner_step_id",
            "close_attempt": "cleanup_step_id",
        }[operation]
    ]
    _require(
        manifest["schema_version"] == "bluefire.runner-manifest.v1"
        and profile["schema_version"] == "bluefire.runner-profile.v1"
        and manifest["params"] == {}
        and claim["step_id"] == manifest["step_id"] == step
        and manifest["run_id"] == attempt["run_id"]
        and frame["job_id"] == attempt["job_id"]
        and manifest["policy_digest"] == profile["policy_digest"]
        and manifest["platform"] == profile["platform"] == "macos"
        and manifest["behavior_id"] == manifest["action_id"]
        and manifest["runner_id"] == profile["runner_id"]
        and manifest["runner_profile_id"] == profile["profile_id"]
    )
    body = json_clone(manifest)
    body["request_hash"] = ""
    for key in ("approval", "grant_attempt", "grant_cleanup", "macos_file_access_cleanup"):
        nested = body.get(key)
        if type(nested) is dict and "request_hash" in nested:
            nested["request_hash"] = ""
    profile_body = {**profile, "policy_digest": ""}
    _require(
        manifest["request_hash"] == content_hash(body)
        and profile["policy_digest"] == content_hash(profile_body)
    )
    binding = validate_binding(profile["macos_file_access_binding"])
    cleanup = operation == "close_attempt"
    _require(
        binding["mode"] == "0600"
        and attempt["issued_at_ms"] >= binding["issued_at_ms"]
        and attempt["cleanup_expires_at_ms"] <= binding["expires_at_ms"]
        and attempt["cleanup_deadline_ns"] <= binding["original_deadline_ns"]
        and intent["issued_at_ms"] >= attempt["issued_at_ms"]
        and intent["issued_monotonic_ns"] >= attempt["issued_monotonic_ns"]
        and intent["expires_at_ms"]
        <= attempt["cleanup_expires_at_ms" if cleanup else "business_expires_at_ms"]
        and intent["deadline_ns"]
        <= attempt["cleanup_deadline_ns" if cleanup else "business_deadline_ns"]
    )
    if not cleanup:
        authority = manifest.get("grant_attempt")
        _require(
            type(authority) is dict
            and "macos_file_access_cleanup" not in manifest
            and "grant_cleanup" not in manifest
        )
        _require(
            all(
                authority.get(key) == attempt[key]
                for key in (
                    "attempt_id",
                    "grant_id",
                    "grant_digest",
                    "lease_digest",
                    "compiled_digest",
                    "run_id",
                )
            )
        )
        _require(
            attempt["cleanup_claim"] is None
            and attempt["cleanup_claim_digest"] is None
            and attempt["task_closures"] == []
        )
        if operation == "probe":
            _require(
                attempt["probe_task_id"] == intent["task_id"]
                and attempt["probe_receipt_digest"] is None
            )
        else:
            _identifier(attempt["probe_task_id"])
            _digest(attempt["probe_receipt_digest"])
    else:
        authority = attempt["cleanup_claim"]
        _require(
            type(authority) is dict
            and set(authority)
            == set(
                "schema_version attempt_id lease_digest compiled_digest run_id cleanup_step_id issued_at_ms expires_at_ms issued_monotonic_ns deadline_ns scope".split()
            )
        )
        _require(
            authority["schema_version"] == "bluefire.macos-file-access-artifact-closure-claim.v1"
            and authority["scope"] == "attempt_artifact_closure_only"
            and manifest.get("macos_file_access_cleanup") == authority
            and "grant_attempt" not in manifest
            and "grant_cleanup" not in manifest
            and attempt["cleanup_claim_digest"] == content_hash(authority)
            and all(
                authority[key] == attempt[key]
                for key in (
                    "attempt_id",
                    "lease_digest",
                    "compiled_digest",
                    "run_id",
                    "cleanup_step_id",
                )
            )
        )
        for key in ("issued_at_ms", "expires_at_ms", "issued_monotonic_ns", "deadline_ns"):
            _require(type(authority[key]) is int and authority[key] > 0)
        _require(
            attempt["issued_at_ms"]
            <= authority["issued_at_ms"]
            <= intent["issued_at_ms"]
            < intent["expires_at_ms"]
            <= authority["expires_at_ms"]
            <= attempt["cleanup_expires_at_ms"]
            and attempt["issued_monotonic_ns"]
            <= authority["issued_monotonic_ns"]
            <= intent["issued_monotonic_ns"]
            < intent["deadline_ns"]
            <= authority["deadline_ns"]
            <= attempt["cleanup_deadline_ns"]
        )
        _require(type(attempt["task_closures"]) is list and len(attempt["task_closures"]) <= 2)
        for row in attempt["task_closures"]:
            _require(
                type(row) is dict
                and set(row)
                == {
                    "task_id",
                    "transport_request_hash",
                    "request_hash",
                    "state",
                    "native_receipt_digest",
                }
            )
            _identifier(row["task_id"])
            _digest(row["transport_request_hash"])
            _digest(row["request_hash"])
            _require(
                row["task_id"] == "execute-" + row["transport_request_hash"][7:]
                and row["state"] in ("complete", "not_sent")
            )
            if row["state"] == "complete":
                _digest(row["native_receipt_digest"])
            else:
                _require(row["native_receipt_digest"] is None)
        _require(
            len({row["task_id"] for row in attempt["task_closures"]})
            == len(attempt["task_closures"])
        )
    return cast(dict[str, Any], attempt)


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
    _identifier(value["job_id"])
    _digest(value["preparation_digest"])
    _digest(value["dispatch_digest"])
    _require(
        value["dispatch_digest"]
        == content_hash({key: item for key, item in value.items() if key != "dispatch_digest"})
    )
    intent = ReviewedMacOSTaskIntent.from_document(value["intent"]).document()
    operation = intent["operation"]
    _require(operation in _COSTS if value["attempt"] is None else operation in _ATTEMPT_ACTIONS)
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
    task_id, transport = execution_task_identity(manifest, profile)
    _require(
        task_id == intent["task_id"] == claim["task_id"]
        and transport == intent["transport_request_hash"] == claim["transport_request_hash"]
        and claim["job_id"] == value["job_id"]
        and claim["request_hash"] == manifest["request_hash"]
        and content_hash(profile["macos_file_access_binding"]) == intent["binding_digest"]
    )
    if value["attempt"] is not None:
        _attempt(value, intent)
        return cast(dict[str, Any], value)
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

    def begin_macos_capability_dispatch(
        self,
        task_id: str,
        transport_request_hash: str,
        *,
        now_ms: int,
        now_monotonic_ns: int,
        creator_context: Mapping[str, Any],
    ) -> dict[str, Any]: ...


class MacOSWorkspaceTaskEndpoint(Protocol):
    def assert_current(self) -> float: ...

    def review_context(self, operation: str) -> dict[str, Any]: ...

    def reserve_composition_probe_budget(self, request: dict[str, Any]) -> dict[str, Any]: ...

    def dispatch_committed(
        self, frame: dict[str, Any], *, cancel_event: threading.Event
    ) -> dict[str, Any]: ...


class _MacOSWorkspaceExchangeEndpoint(Protocol):
    _io_lock: RLockType
    _api: ModuleType
    _stream: socket.socket
    _recipe: dict[str, Any]
    _sequence: int
    _poisoned: bool

    def assert_current(self) -> float: ...

    def close(self) -> None: ...


class MacOSWorkspaceTaskTransport:
    """Existing task hook -> committed journal -> original inherited endpoint."""

    def __init__(self, endpoint: MacOSWorkspaceTaskEndpoint, store: CommittedMacOSJournal):
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
        composed = manifest.get("action_id") in _ATTEMPT_ACTIONS.values()
        if composed:
            operation = next(
                key for key, value in _ATTEMPT_ACTIONS.items() if value == manifest["action_id"]
            )
            context = self._endpoint.review_context(operation)
            frame = self._store.begin_macos_capability_dispatch(
                task_id,
                transport,
                now_ms=time.time_ns() // 1_000_000,
                now_monotonic_ns=darwin_clock_ns(),
                creator_context=context,
            )
        else:
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
        if composed:
            from . import macos_file_access_method as method

            closing = frame["intent"]["operation"] == "close_attempt"
            complete = receipt.get("state") == ("closed" if closing else "complete")
            output: dict[str, dict[str, Any] | None]
            if closing:
                output = {"attempt_closure": method.validate_closure(receipt)}
            else:
                output = {
                    "macos_receipt": receipt,
                    "observation": (
                        method.observation(
                            frame, receipt, observed_at_ms=time.time_ns() // 1_000_000
                        )
                        if complete
                        else None
                    ),
                }
            if complete:
                wall, monotonic = time.time_ns() // 1_000_000, darwin_clock_ns()
                intent = frame["intent"]
                _require(
                    intent["issued_at_ms"] <= wall < intent["expires_at_ms"]
                    and intent["issued_monotonic_ns"] <= monotonic < intent["deadline_ns"]
                )
            return {
                "schema_version": "bluefire.runner-result.v1",
                **{
                    key: manifest[key]
                    for key in (
                        "request_id",
                        "run_id",
                        "step_id",
                        "behavior_id",
                        "action_id",
                        "runner_id",
                        "runner_profile_id",
                        "request_hash",
                    )
                },
                "platform": profile["platform"],
                "policy_digest": profile["policy_digest"],
                "status": "success" if complete else "error",
                "output": output,
                "receipt_ids": [],
                "evidence": [],
                "telemetry": [],
                "limitations": [
                    "Original producer evidence only; no whole-enrollment cleanup or independent telemetry."
                ],
                "error": None if complete else {"code": "macos_request_unknown"},
            }
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
    endpoint: _MacOSWorkspaceExchangeEndpoint,
    operation: str,
    payload: dict[str, Any],
    cancel_event: threading.Event | None = None,
) -> dict[str, Any]:
    """Exactly one reader; cancellation closes custody instead of sending a retry."""
    with endpoint._io_lock:
        endpoint.assert_current()
        _require(operation in _OPERATIONS)
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


def start_workspace(owner: workspace.MacOSWorkspaceOwner) -> None:
    """Compose the exact retained host with its sole original-channel bridge."""
    _require(type(owner) is workspace.MacOSWorkspaceOwner)
    owner.start(bridge_factory=OriginalMacOSWorkspaceBridge.attach)


class OriginalMacOSWorkspaceBridge:
    """Sole parent reader on the exact retained normal HOST workspace channel."""

    _owner: workspace.MacOSWorkspaceOwner
    _creator: MacOSFileAccessCreator
    _lease: OriginalMacOSControllerLease
    _sequence: int
    _closed: bool
    _in_task: bool
    _pending: dict[str, Any] | None
    _received_request: dict[str, Any] | None
    _thread: threading.Thread
    _attempts: dict[str, dict[str, Any]]

    def __new__(cls, *_args, **_kwargs) -> OriginalMacOSWorkspaceBridge:
        raise TypeError("The original retained workspace is required.")

    @classmethod
    def attach(cls, owner: workspace.MacOSWorkspaceOwner) -> OriginalMacOSWorkspaceBridge:
        _require(
            type(owner) is workspace.MacOSWorkspaceOwner
            and type(owner._creator) is MacOSFileAccessCreator
        )
        with owner._channel_lock, owner._creator._lock:
            return cls._attach_locked(owner)

    @classmethod
    def _attach_locked(cls, owner: workspace.MacOSWorkspaceOwner) -> OriginalMacOSWorkspaceBridge:
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
        value._attempts = {}
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
        if self._pending is not None and self._pending["attempt"] is not None:
            self._attempt_guard(self._pending)

    def _attempt_guard(self, frame: dict[str, Any]) -> None:
        attempt = frame["attempt"]
        cleanup = frame["intent"]["operation"] == "close_attempt"
        wall, monotonic = time.time_ns() // 1_000_000, darwin_clock_ns()
        _require(
            attempt["issued_at_ms"]
            <= wall
            < attempt["cleanup_expires_at_ms" if cleanup else "business_expires_at_ms"]
            and attempt["issued_monotonic_ns"]
            <= monotonic
            < attempt["cleanup_deadline_ns" if cleanup else "business_deadline_ns"]
        )

    @staticmethod
    def _attempt_identity(frame: dict[str, Any]) -> str:
        transient = {
            "probe_task_id",
            "probe_receipt_digest",
            "task_closures",
            "cleanup_claim",
            "cleanup_claim_digest",
        }
        return content_hash(
            {
                "attempt": {
                    key: value for key, value in frame["attempt"].items() if key not in transient
                },
                "binding_digest": frame["intent"]["binding_digest"],
                "control_revision": frame["intent"]["control_revision"],
            }
        )

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
            attempt = frame["attempt"]
            if attempt is None:
                _require(not any(not item["closed"] for item in self._attempts.values()))
                cost = _COSTS[row["operation"]]
                memo = None
            else:
                self._attempt_guard(frame)
                identity = self._attempt_identity(frame)
                memo = self._attempts.get(attempt["attempt_id"])
                if row["operation"] == "probe":
                    _require(
                        memo is None
                        and len(self._attempts) < MAX_REQUESTS
                        and not any(not item["closed"] for item in self._attempts.values())
                    )
                    creator._consume_composition_probe_budget(attempt, row)
                    cost = 0
                else:
                    _require(row["operation"] == "verify_owner" and memo is not None)
                    if memo is None:
                        raise MacOSFileAccessContractError("The original attempt is unavailable.")
                    _require(
                        memo["identity"] == identity
                        and not memo["closed"]
                        and memo["owner_task_id"] is None
                        and memo["probe_task_id"] == attempt["probe_task_id"]
                    )
                    prior = creator._tasks.get(attempt["probe_task_id"])
                    _require(
                        prior is not None
                        and prior.document()["state"] == "complete"
                        and prior.document()["operation"] == "probe"
                        and content_hash(prior.document()) == attempt["probe_receipt_digest"]
                        and creator._task_attempts.get(attempt["probe_task_id"])
                        == attempt["attempt_id"]
                    )
                    cost = 0
            _require(creator._used_budget + cost <= MAX_REQUESTS)
            # No refund on a later refusal, exception or uncertain exchange.
            creator._used_budget += cost
            if attempt is not None:
                if row["operation"] == "probe":
                    memo = {
                        "identity": self._attempt_identity(frame),
                        "probe_task_id": row["task_id"],
                        "owner_task_id": None,
                        "closed": False,
                        "requests": {row["task_id"]: frame["claim"]["request_hash"]},
                    }
                    self._attempts[attempt["attempt_id"]] = memo
                else:
                    if memo is None:
                        raise MacOSFileAccessContractError("The original attempt is unavailable.")
                    memo["owner_task_id"] = row["task_id"]
                    memo["requests"][row["task_id"]] = frame["claim"]["request_hash"]
            reservation: OriginalMacOSTaskReservation = object.__new__(OriginalMacOSTaskReservation)
            reservation._creator, reservation._lease, reservation._intent = (
                creator,
                self._lease,
                intent,
            )
            reservation._used = False
            reservation._budget_reserved = True
            reservation._attempt_id = None if attempt is None else attempt["attempt_id"]
            reservation._probe_task_id = None if attempt is None else attempt["probe_task_id"]
            reservation._probe_receipt_digest = (
                None if attempt is None else attempt["probe_receipt_digest"]
            )
            return reservation

    def _close_attempt(self, frame: dict[str, Any]) -> dict[str, Any]:
        from .macos_file_access_method import CLOSURE_SCHEMA

        creator, attempt, intent = self._creator, frame["attempt"], frame["intent"]
        _require(self._in_task and self._pending is frame and attempt is not None)
        with creator._lock:
            creator._require_lease()
            creator._guard(intent)
            self._attempt_guard(frame)
            binding = creator._binding()
            _require(
                creator._state == "hardened"
                and intent["task_id"] not in creator._tasks
                and intent["control_revision"] == creator._revision
                and intent["binding_digest"] == content_hash(binding)
                and intent["context_digest"]
                == content_hash(creator._context("close_attempt", binding))
            )
            memo = self._attempts.get(attempt["attempt_id"])
            rows = attempt["task_closures"]
            completed = {row["task_id"] for row in rows if row["state"] == "complete"}
            actual = {
                task
                for task, owner in creator._task_attempts.items()
                if owner == attempt["attempt_id"]
            }
            _require(completed == actual)
            if memo is None:
                _require(
                    not actual
                    and not any(not item["closed"] for item in self._attempts.values())
                    and len(self._attempts) < MAX_REQUESTS
                )
                memo = {
                    "identity": self._attempt_identity(frame),
                    "probe_task_id": None,
                    "owner_task_id": None,
                    "closed": False,
                    "requests": {},
                }
                self._attempts[attempt["attempt_id"]] = memo
            _require(not memo["closed"] and memo["identity"] == self._attempt_identity(frame))
            if memo["probe_task_id"] is not None:
                probe = creator._tasks.get(memo["probe_task_id"])
                _require(probe is not None and attempt["probe_task_id"] == memo["probe_task_id"])
                if probe is None:
                    raise MacOSFileAccessContractError("The original probe is unavailable.")
                _require(attempt["probe_receipt_digest"] == content_hash(probe.document()))
            else:
                _require(attempt["probe_receipt_digest"] is None)
            for row in rows:
                native = creator._tasks.get(row["task_id"])
                if row["state"] == "not_sent":
                    _require(row["task_id"] not in creator._tasks)
                    continue
                _require(native is not None)
                if native is None:
                    raise MacOSFileAccessContractError(
                        "The original native receipt is unavailable."
                    )
                receipt = native.document()
                _require(
                    receipt["state"] == "complete"
                    and receipt["producer_request_usage"] == "settled"
                    and receipt["transport_request_hash"] == row["transport_request_hash"]
                    and memo["requests"].get(row["task_id"]) == row["request_hash"]
                    and content_hash(receipt) == row["native_receipt_digest"]
                    and receipt["original_workers"] == "retained"
                    and all(
                        item["request_handle_cleanup"] != "unknown"
                        and item["held_handle_cleanup"] == "retained"
                        for item in receipt["terminals"]
                    )
                )
            creator._require_lease()
            creator._guard(intent)
            self._attempt_guard(frame)
            memo["closed"] = True
            return {
                "schema_version": CLOSURE_SCHEMA,
                "attempt_id": attempt["attempt_id"],
                "lease_digest": attempt["lease_digest"],
                "compiled_digest": attempt["compiled_digest"],
                "run_id": attempt["run_id"],
                "binding_digest": intent["binding_digest"],
                "control_revision": creator._revision,
                "cleanup_task_id": intent["task_id"],
                "cleanup_transport_request_hash": intent["transport_request_hash"],
                "cleanup_claim_digest": attempt["cleanup_claim_digest"],
                "task_closures": json_clone(rows),
                "state": "closed",
                "producer_request_usage": "settled",
                "attempt_artifacts": "not_created",
                "original_workers": "retained",
                "namespace": "original_creator_held",
                "whole_enrollment_cleanup": False,
                "shared_request_budget_used": creator._used_budget,
            }

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
            _require(
                set(payload) == {"operation"}
                and payload["operation"] in (*_COSTS, *_ATTEMPT_ACTIONS)
            )
            result = self._creator.review_context(payload["operation"])
        elif operation == "reserve_composition_probe_budget":
            result = self._creator.reserve_composition_probe_budget(payload)
        else:
            _require(operation == "dispatch_committed")
            frame = _committed(payload)
            self._in_task, self._pending = True, frame
            try:
                if frame["intent"]["operation"] == "close_attempt":
                    result = self._close_attempt(frame)
                else:
                    reservation = self._reserve_received(frame)
                    fixed = {
                        "baseline": self._creator._baseline,
                        "harden": self._creator._harden,
                        "rollback": self._creator._rollback,
                        "probe": self._creator._probe,
                        "verify_owner": self._creator._verify_owner,
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
        _receive, _send = workspace._receive, workspace._send
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
