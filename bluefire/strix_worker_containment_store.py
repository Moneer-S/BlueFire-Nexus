"""Durable, non-authorizing journal for one Strix worker boundary.

The operating-system launcher owns live descriptors and process authority.  This
module retains the exact intent and receipts in ProductStore before they may be
acknowledged to the controller.  Reopening the journal is useful for cleanup and
evidence reconciliation only; it never grants permission to launch, reconnect,
or resume a worker.
"""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from .strix_worker_containment import (
    StrixWorkerActivationReceipt,
    StrixWorkerCleanupReceipt,
    StrixWorkerCleanupRequest,
    StrixWorkerContainmentError,
    StrixWorkerContainmentPlan,
    StrixWorkerRevalidationReceipt,
)
from .util import content_hash


class StrixWorkerContainmentStoreError(RuntimeError):
    """The worker containment history is unavailable or has changed."""


class ContainmentProductStore(Protocol):
    def _connection(self, *, write: bool = False) -> AbstractContextManager[sqlite3.Connection]: ...


_ATTEMPT = re.compile(r"^engine-attempt-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PLAN_SCHEMA = "bluefire.strix-worker-containment-plan.v1"
_ACTIVATION_SCHEMA = "bluefire.strix-worker-containment-activation.v1"
_REVALIDATION_SCHEMA = "bluefire.strix-worker-containment-revalidation.v1"
_CLEANUP_REQUEST_SCHEMA = "bluefire.strix-worker-containment-cleanup.v1"
_CLEANUP_RECEIPT_SCHEMA = "bluefire.strix-worker-containment-cleanup-receipt.v1"
_EVENT_SCHEMA = "bluefire.strix-worker-containment-journal-event.v1"
_TABLE = "strix_worker_containment_events"
_MAX_EVENTS = 65_536
_MAX_DOCUMENT_BYTES = 256 * 1024
_TRIGGERS = {
    "strix_worker_containment_no_update": (
        "CREATE TRIGGER strix_worker_containment_no_update BEFORE UPDATE ON "
        "strix_worker_containment_events BEGIN SELECT RAISE(ABORT,"
        "'Strix worker containment events are immutable'); END"
    ),
    "strix_worker_containment_no_delete": (
        "CREATE TRIGGER strix_worker_containment_no_delete BEFORE DELETE ON "
        "strix_worker_containment_events BEGIN SELECT RAISE(ABORT,"
        "'Strix worker containment events are immutable'); END"
    ),
    "strix_worker_containment_no_replace": (
        "CREATE TRIGGER strix_worker_containment_no_replace BEFORE INSERT ON "
        "strix_worker_containment_events WHEN EXISTS(SELECT 1 FROM "
        "strix_worker_containment_events WHERE attempt_id=NEW.attempt_id AND "
        "(event_sequence=NEW.event_sequence OR event_key=NEW.event_key)) "
        "BEGIN SELECT RAISE(ABORT,'Strix worker containment events cannot be replaced'); END"
    ),
}


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise StrixWorkerContainmentStoreError(f"{label} is invalid")
    return value


def _attempt(value: Any) -> str:
    if not isinstance(value, str) or _ATTEMPT.fullmatch(value) is None:
        raise StrixWorkerContainmentStoreError("worker containment attempt is invalid")
    return value


def _generation(value: Any) -> int:
    if type(value) is not int or not 1 <= value < 2**31:
        raise StrixWorkerContainmentStoreError("controller generation is invalid")
    return value


def _json(value: Mapping[str, Any]) -> str:
    try:
        result = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise StrixWorkerContainmentStoreError(
            "worker containment document is not canonical JSON"
        ) from exc
    if len(result.encode("utf-8")) > _MAX_DOCUMENT_BYTES:
        raise StrixWorkerContainmentStoreError("worker containment document is too large")
    return result


def _object(text: Any) -> dict[str, Any]:
    if not isinstance(text, str) or len(text.encode("utf-8")) > _MAX_DOCUMENT_BYTES:
        raise StrixWorkerContainmentStoreError("worker containment document is too large")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise StrixWorkerContainmentStoreError(
                    "worker containment document has duplicate keys"
                )
            result[key] = value
        return result

    try:
        result = json.loads(text, object_pairs_hook=pairs)
        if not isinstance(result, dict) or _json(result) != text:
            raise StrixWorkerContainmentStoreError("worker containment document is not canonical")
        return result
    except (TypeError, ValueError, RecursionError) as exc:
        if isinstance(exc, StrixWorkerContainmentStoreError):
            raise
        raise StrixWorkerContainmentStoreError("worker containment document is invalid") from exc


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise StrixWorkerContainmentStoreError(f"{label} is unavailable")
    # The canonical JSON round trip rejects non-JSON objects and detaches caller state.
    return _object(_json(dict(value)))


def _self_ref(document: Mapping[str, Any], name: str, label: str) -> str:
    reference = _digest(document.get(name), label)
    unsigned = dict(document)
    unsigned.pop(name, None)
    if reference != content_hash(unsigned):
        raise StrixWorkerContainmentStoreError(f"{label} does not match its document")
    return reference


def _complete_cleanup(document: Mapping[str, Any]) -> None:
    required_true = {
        "cancellation_requested",
        "pidfd_exit_observed",
        "process_absent",
        "cgroup_empty",
        "cgroup_removed",
        "namespaces_absent",
        "private_roots_absent",
        "relays_closed",
        "input_fds_closed",
        "identity_absent",
        "identity_lease_released",
    }
    if (
        any(document.get(name) is not True for name in required_true)
        or type(document.get("cgroup_kill_used")) is not bool
    ):
        raise StrixWorkerContainmentStoreError(
            "worker cleanup receipt does not prove complete absence"
        )


def _contract(label: str, operation: Any) -> Any:
    try:
        return operation()
    except (StrixWorkerContainmentError, TypeError, ValueError) as exc:
        raise StrixWorkerContainmentStoreError(
            f"{label} failed containment contract validation"
        ) from exc


@dataclass(frozen=True, slots=True)
class PreparedContainmentOperation:
    operation: str
    request_ref: str
    document_digest: str


@dataclass(frozen=True, slots=True)
class ReopenedStrixWorkerContainment:
    """Historical evidence returned without any live process authority."""

    attempt_id: str
    binding_digest: str
    controller_generation: int
    controller_boot_id_digest: str
    plan: Mapping[str, Any] | None
    activation: Mapping[str, Any] | None
    revalidations: tuple[Mapping[str, Any], ...]
    cleanup_request: Mapping[str, Any] | None
    cleanup_requests: tuple[Mapping[str, Any], ...]
    cleanup: Mapping[str, Any] | None
    unresolved_operations: tuple[PreparedContainmentOperation, ...]
    reconciliation_required: bool
    launch_authorized: bool
    reconnect_authorized: bool
    journal_digest: str


class ProductStoreStrixWorkerContainment:
    """Append-only journal for one attempt-bound worker containment lifecycle."""

    def __init__(
        self,
        store: ContainmentProductStore,
        *,
        attempt_id: str,
        binding_digest: str,
        controller_generation: int,
        controller_boot_id_digest: str,
    ) -> None:
        self._store = store
        self._attempt_id = _attempt(attempt_id)
        self._binding_digest = _digest(binding_digest, "worker binding digest")
        self._controller_generation = _generation(controller_generation)
        self._controller_boot_id_digest = _digest(
            controller_boot_id_digest, "controller boot identity"
        )
        binding = {
            "attempt_id": self._attempt_id,
            "binding_digest": self._binding_digest,
            "controller_generation": self._controller_generation,
            "controller_boot_id_digest": self._controller_boot_id_digest,
        }
        with self._store._connection(write=True) as connection:
            self._create_or_verify_storage(connection)
            rows = self._read(connection)
            if not rows:
                self._insert(connection, rows, "binding", "binding", binding)
                rows = self._read(connection)
            reopened = self._reopen_rows(rows)
            if (
                reopened.attempt_id != self._attempt_id
                or reopened.binding_digest != self._binding_digest
                or reopened.controller_generation != self._controller_generation
                or reopened.controller_boot_id_digest != self._controller_boot_id_digest
            ):
                raise StrixWorkerContainmentStoreError(
                    "worker containment journal binds another controller"
                )

    def _create_or_verify_storage(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            f"CREATE TABLE IF NOT EXISTS {_TABLE} ("
            "attempt_id TEXT NOT NULL, event_sequence INTEGER NOT NULL, "
            "event_key TEXT NOT NULL, event_digest TEXT NOT NULL UNIQUE, "
            "document_json TEXT NOT NULL, PRIMARY KEY(attempt_id,event_sequence), "
            "UNIQUE(attempt_id,event_key))"
        )
        for name, statement in _TRIGGERS.items():
            existing = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)
            ).fetchone()
            if existing is None:
                if connection.execute(f"SELECT 1 FROM {_TABLE} LIMIT 1").fetchone():
                    raise StrixWorkerContainmentStoreError(
                        "worker containment immutability guard is missing"
                    )
                connection.execute(statement)

    def _read(self, connection: sqlite3.Connection) -> list[dict[str, Any]]:
        for name, statement in _TRIGGERS.items():
            row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)
            ).fetchone()
            if row is None or row[0] != statement:
                raise StrixWorkerContainmentStoreError(
                    "worker containment immutability guard changed"
                )
        rows = connection.execute(
            f"SELECT event_sequence,event_key,event_digest,document_json FROM {_TABLE} "
            "WHERE attempt_id=? ORDER BY event_sequence LIMIT ?",
            (self._attempt_id, _MAX_EVENTS + 1),
        ).fetchall()
        if len(rows) > _MAX_EVENTS:
            raise StrixWorkerContainmentStoreError(
                "worker containment event history exceeds its bound"
            )
        result: list[dict[str, Any]] = []
        previous: str | None = None
        keys: set[str] = set()
        for ordinal, row in enumerate(rows, 1):
            document = _object(row[3])
            expected_fields = {
                "schema_version",
                "attempt_id",
                "event_sequence",
                "event_key",
                "previous_event_digest",
                "kind",
                "payload",
            }
            if (
                set(document) != expected_fields
                or document["schema_version"] != _EVENT_SCHEMA
                or document["attempt_id"] != self._attempt_id
                or type(document["event_sequence"]) is not int
                or document["event_sequence"] != ordinal
                or row[0] != ordinal
                or document["event_key"] != row[1]
                or row[1] in keys
                or document["previous_event_digest"] != previous
                or content_hash(document) != row[2]
                or not isinstance(document["payload"], dict)
            ):
                raise StrixWorkerContainmentStoreError(
                    "worker containment history failed its chain audit"
                )
            keys.add(row[1])
            previous = row[2]
            result.append(document)
        return result

    def _insert(
        self,
        connection: sqlite3.Connection,
        rows: list[dict[str, Any]],
        kind: str,
        key: str,
        payload: Mapping[str, Any],
    ) -> None:
        checked_payload = _mapping(payload, "worker containment payload")
        existing = next((row for row in rows if row["event_key"] == key), None)
        if existing is not None:
            if existing["kind"] != kind or existing["payload"] != checked_payload:
                raise StrixWorkerContainmentStoreError(
                    "worker containment idempotent append changed"
                )
            return
        if len(rows) >= _MAX_EVENTS:
            raise StrixWorkerContainmentStoreError("worker containment journal is full")
        if connection.execute("PRAGMA synchronous").fetchone()[0] < 2:
            raise StrixWorkerContainmentStoreError(
                "worker containment journal requires durable commits"
            )
        document = {
            "schema_version": _EVENT_SCHEMA,
            "attempt_id": self._attempt_id,
            "event_sequence": len(rows) + 1,
            "event_key": key,
            "previous_event_digest": content_hash(rows[-1]) if rows else None,
            "kind": kind,
            "payload": checked_payload,
        }
        connection.execute(
            f"INSERT INTO {_TABLE} "
            "(attempt_id,event_sequence,event_key,event_digest,document_json) VALUES(?,?,?,?,?)",
            (
                self._attempt_id,
                len(rows) + 1,
                key,
                content_hash(document),
                _json(document),
            ),
        )

    def _bound(self, document: Mapping[str, Any], schema: str, label: str) -> None:
        if (
            document.get("schema_version") != schema
            or document.get("attempt_id") != self._attempt_id
            or document.get("binding_digest") != self._binding_digest
            or document.get("controller_generation") != self._controller_generation
            or document.get("controller_boot_id_digest") != self._controller_boot_id_digest
        ):
            raise StrixWorkerContainmentStoreError(f"{label} binding changed")

    def _reopen_rows(self, rows: list[dict[str, Any]]) -> ReopenedStrixWorkerContainment:
        if not rows or rows[0]["kind"] != "binding" or rows[0]["event_key"] != "binding":
            raise StrixWorkerContainmentStoreError("worker containment binding is missing")
        binding = rows[0]["payload"]
        expected_binding = {
            "attempt_id": self._attempt_id,
            "binding_digest": self._binding_digest,
            "controller_generation": self._controller_generation,
            "controller_boot_id_digest": self._controller_boot_id_digest,
        }
        if binding != expected_binding:
            raise StrixWorkerContainmentStoreError("worker containment binding changed")

        plan: dict[str, Any] | None = None
        plan_object: StrixWorkerContainmentPlan | None = None
        activation: dict[str, Any] | None = None
        activation_object: StrixWorkerActivationReceipt | None = None
        revalidations: list[dict[str, Any]] = []
        cleanup_requests: list[dict[str, Any]] = []
        cleanup_request_objects: dict[str, StrixWorkerCleanupRequest] = {}
        cleanup: dict[str, Any] | None = None
        prepared_activation: PreparedContainmentOperation | None = None
        prepared_cleanup: dict[str, PreparedContainmentOperation] = {}
        completed_cleanup_requests: set[str] = set()

        for event in rows[1:]:
            kind = event["kind"]
            payload = event["payload"]
            if kind == "prepare_activation":
                raw_candidate = _mapping(payload.get("plan"), "worker containment plan")
                plan_object = _contract(
                    "worker containment plan",
                    lambda document=raw_candidate: StrixWorkerContainmentPlan.from_mapping(
                        document
                    ),
                )
                candidate = plan_object.to_dict()
                self._bound(candidate, _PLAN_SCHEMA, "worker containment plan")
                plan_ref = content_hash(candidate)
                if event["event_key"] != f"prepare:activation:{plan_ref}":
                    raise StrixWorkerContainmentStoreError("worker activation intent key changed")
                if plan is not None and plan != candidate:
                    raise StrixWorkerContainmentStoreError("worker activation intent was replaced")
                plan = candidate
                prepared_activation = PreparedContainmentOperation(
                    "activation", plan_ref, content_hash(candidate)
                )
            elif kind == "activation":
                if plan_object is None:
                    raise StrixWorkerContainmentStoreError(
                        "worker activation has no exact prepared intent"
                    )
                raw_candidate = _mapping(payload.get("receipt"), "worker activation receipt")
                activation_object = _contract(
                    "worker activation receipt",
                    lambda document=raw_candidate, plan=plan_object: (
                        StrixWorkerActivationReceipt.from_mapping(document, plan)
                    ),
                )
                candidate = activation_object.to_dict()
                self._bound(candidate, _ACTIVATION_SCHEMA, "worker activation receipt")
                receipt_ref = _self_ref(candidate, "receipt_ref", "worker activation receipt")
                if (
                    plan is None
                    or candidate.get("plan_ref") != content_hash(plan)
                    or event["event_key"] != f"activation:{receipt_ref}"
                    or activation is not None
                    and activation != candidate
                ):
                    raise StrixWorkerContainmentStoreError(
                        "worker activation has no exact prepared intent"
                    )
                activation = candidate
            elif kind == "revalidation":
                if activation_object is None:
                    raise StrixWorkerContainmentStoreError(
                        "worker revalidation is not bound to the live activation"
                    )
                raw_candidate = _mapping(payload.get("receipt"), "worker revalidation receipt")
                revalidation_object = _contract(
                    "worker revalidation receipt",
                    lambda document=raw_candidate, activation=activation_object: (
                        StrixWorkerRevalidationReceipt.from_mapping(document, activation)
                    ),
                )
                candidate = revalidation_object.to_dict()
                self._bound(candidate, _REVALIDATION_SCHEMA, "worker revalidation receipt")
                receipt_ref = _self_ref(candidate, "receipt_ref", "worker revalidation receipt")
                if (
                    activation is None
                    or cleanup is not None
                    or candidate.get("activation_ref") != activation.get("receipt_ref")
                    or candidate.get("plan_ref") != activation.get("plan_ref")
                    or event["event_key"] != f"revalidation:{receipt_ref}"
                ):
                    raise StrixWorkerContainmentStoreError(
                        "worker revalidation is not bound to the live activation"
                    )
                revalidations.append(candidate)
            elif kind == "prepare_cleanup":
                if activation_object is None:
                    raise StrixWorkerContainmentStoreError(
                        "worker cleanup intent is not bound to the activation"
                    )
                raw_candidate = _mapping(payload.get("request"), "worker cleanup request")
                request_object = _contract(
                    "worker cleanup request",
                    lambda document=raw_candidate, activation=activation_object: (
                        StrixWorkerCleanupRequest.from_mapping(document, activation)
                    ),
                )
                candidate = request_object.to_dict()
                self._bound(candidate, _CLEANUP_REQUEST_SCHEMA, "worker cleanup request")
                request_ref = _self_ref(candidate, "request_ref", "worker cleanup request")
                if (
                    activation is None
                    or candidate.get("activation_ref") != activation.get("receipt_ref")
                    or candidate.get("plan_ref") != activation.get("plan_ref")
                    or event["event_key"] != f"prepare:cleanup:{request_ref}"
                    or request_ref in cleanup_request_objects
                ):
                    raise StrixWorkerContainmentStoreError(
                        "worker cleanup intent is not bound to the activation"
                    )
                cleanup_requests.append(candidate)
                cleanup_request_objects[request_ref] = request_object
                prepared_cleanup[request_ref] = PreparedContainmentOperation(
                    "cleanup", request_ref, content_hash(candidate)
                )
            elif kind == "cleanup":
                raw_candidate = _mapping(payload.get("receipt"), "worker cleanup receipt")
                request_ref = _digest(
                    raw_candidate.get("request_ref"), "worker cleanup request reference"
                )
                request_object = cleanup_request_objects.get(request_ref)
                if activation_object is None or request_object is None:
                    raise StrixWorkerContainmentStoreError(
                        "worker cleanup receipt is not bound to its intent"
                    )
                cleanup_object = _contract(
                    "worker cleanup receipt",
                    lambda document=raw_candidate, activation=activation_object, request=request_object: (
                        StrixWorkerCleanupReceipt.from_mapping(document, activation, request)
                    ),
                )
                candidate = cleanup_object.to_dict()
                self._bound(candidate, _CLEANUP_RECEIPT_SCHEMA, "worker cleanup receipt")
                receipt_ref = _self_ref(candidate, "receipt_ref", "worker cleanup receipt")
                _complete_cleanup(candidate)
                if (
                    activation is None
                    or candidate.get("activation_ref") != activation.get("receipt_ref")
                    or candidate.get("request_ref") != request_ref
                    or candidate.get("plan_ref") != activation.get("plan_ref")
                    or event["event_key"] != f"cleanup:{receipt_ref}"
                    or cleanup is not None
                    and cleanup != candidate
                ):
                    raise StrixWorkerContainmentStoreError(
                        "worker cleanup receipt is not bound to its intent"
                    )
                cleanup = candidate
                completed_cleanup_requests.add(request_ref)
            else:
                raise StrixWorkerContainmentStoreError(
                    "worker containment event kind is unsupported"
                )

        unresolved: list[PreparedContainmentOperation] = []
        if prepared_activation is not None and activation is None:
            unresolved.append(prepared_activation)
        unresolved.extend(
            prepared_cleanup[request_ref]
            for request_ref in sorted(prepared_cleanup)
            if request_ref not in completed_cleanup_requests
        )
        # A retained activation without verified cleanup is historical evidence of
        # possible live resources. Reopen therefore always requires reconciliation.
        reconciliation_required = bool(
            prepared_activation is not None
            and activation is None
            or activation is not None
            and cleanup is None
        )
        return ReopenedStrixWorkerContainment(
            attempt_id=self._attempt_id,
            binding_digest=self._binding_digest,
            controller_generation=self._controller_generation,
            controller_boot_id_digest=self._controller_boot_id_digest,
            plan=plan,
            activation=activation,
            revalidations=tuple(revalidations),
            cleanup_request=cleanup_requests[-1] if cleanup_requests else None,
            cleanup_requests=tuple(cleanup_requests),
            cleanup=cleanup,
            unresolved_operations=tuple(unresolved),
            reconciliation_required=reconciliation_required,
            launch_authorized=False,
            reconnect_authorized=False,
            journal_digest=content_hash(rows[-1]),
        )

    def prepare_activation(self, plan: Mapping[str, Any]) -> None:
        candidate = _mapping(plan, "worker containment plan")
        self._bound(candidate, _PLAN_SCHEMA, "worker containment plan")
        plan_ref = content_hash(candidate)
        with self._store._connection(write=True) as connection:
            rows = self._read(connection)
            current = self._reopen_rows(rows)
            if current.plan is not None and current.plan != candidate:
                raise StrixWorkerContainmentStoreError("worker containment plan cannot be replaced")
            self._insert(
                connection,
                rows,
                "prepare_activation",
                f"prepare:activation:{plan_ref}",
                {"plan": candidate},
            )
            self._reopen_rows(self._read(connection))

    def retain_activation(self, receipt: Mapping[str, Any]) -> str:
        candidate = _mapping(receipt, "worker activation receipt")
        self._bound(candidate, _ACTIVATION_SCHEMA, "worker activation receipt")
        receipt_ref = _self_ref(candidate, "receipt_ref", "worker activation receipt")
        with self._store._connection(write=True) as connection:
            rows = self._read(connection)
            current = self._reopen_rows(rows)
            if current.plan is None or candidate.get("plan_ref") != content_hash(current.plan):
                raise StrixWorkerContainmentStoreError(
                    "worker activation has no exact prepared intent"
                )
            self._insert(
                connection,
                rows,
                "activation",
                f"activation:{receipt_ref}",
                {"receipt": candidate},
            )
            self._reopen_rows(self._read(connection))
        return receipt_ref

    def append_revalidation(self, receipt: Mapping[str, Any]) -> str:
        candidate = _mapping(receipt, "worker revalidation receipt")
        self._bound(candidate, _REVALIDATION_SCHEMA, "worker revalidation receipt")
        receipt_ref = _self_ref(candidate, "receipt_ref", "worker revalidation receipt")
        with self._store._connection(write=True) as connection:
            rows = self._read(connection)
            current = self._reopen_rows(rows)
            if candidate in current.revalidations:
                pass
            elif (
                current.activation is None
                or current.cleanup is not None
                or candidate.get("activation_ref") != current.activation.get("receipt_ref")
            ):
                raise StrixWorkerContainmentStoreError(
                    "worker revalidation is not bound to a live activation"
                )
            self._insert(
                connection,
                rows,
                "revalidation",
                f"revalidation:{receipt_ref}",
                {"receipt": candidate},
            )
            self._reopen_rows(self._read(connection))
        return receipt_ref

    def prepare_cleanup(self, request: Mapping[str, Any]) -> None:
        candidate = _mapping(request, "worker cleanup request")
        self._bound(candidate, _CLEANUP_REQUEST_SCHEMA, "worker cleanup request")
        request_ref = _self_ref(candidate, "request_ref", "worker cleanup request")
        with self._store._connection(write=True) as connection:
            rows = self._read(connection)
            current = self._reopen_rows(rows)
            if candidate in current.cleanup_requests:
                pass
            elif (
                current.activation is None
                or current.cleanup is not None
                or candidate.get("activation_ref") != current.activation.get("receipt_ref")
            ):
                raise StrixWorkerContainmentStoreError(
                    "worker cleanup intent is not bound to a live activation"
                )
            self._insert(
                connection,
                rows,
                "prepare_cleanup",
                f"prepare:cleanup:{request_ref}",
                {"request": candidate},
            )
            self._reopen_rows(self._read(connection))

    def retain_cleanup(self, receipt: Mapping[str, Any]) -> str:
        candidate = _mapping(receipt, "worker cleanup receipt")
        self._bound(candidate, _CLEANUP_RECEIPT_SCHEMA, "worker cleanup receipt")
        receipt_ref = _self_ref(candidate, "receipt_ref", "worker cleanup receipt")
        _complete_cleanup(candidate)
        with self._store._connection(write=True) as connection:
            rows = self._read(connection)
            current = self._reopen_rows(rows)
            request_ref = candidate.get("request_ref")
            if (
                current.activation is None
                or candidate.get("activation_ref") != current.activation.get("receipt_ref")
                or not any(
                    request.get("request_ref") == request_ref
                    for request in current.cleanup_requests
                )
            ):
                raise StrixWorkerContainmentStoreError(
                    "worker cleanup receipt has no exact prepared intent"
                )
            self._insert(
                connection,
                rows,
                "cleanup",
                f"cleanup:{receipt_ref}",
                {"receipt": candidate},
            )
            self._reopen_rows(self._read(connection))
        return receipt_ref

    def reopen(self) -> ReopenedStrixWorkerContainment:
        with self._store._connection() as connection:
            return self._reopen_rows(self._read(connection))


__all__ = [
    "PreparedContainmentOperation",
    "ProductStoreStrixWorkerContainment",
    "ReopenedStrixWorkerContainment",
    "StrixWorkerContainmentStoreError",
]
