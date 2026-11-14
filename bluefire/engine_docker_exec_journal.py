"""Durable one-use exec reservations in a controller-owned dedicated database.

The caller supplies an already protected disk-backed connection. It must use
``check_same_thread=False`` when cancellation and dispatch use separate threads.
No admission or database pathname is accepted from a worker. Reservations are
committed with EXTRA synchronous durability before an effectful request is sent;
an unfinished phase is custody requiring reconciliation, never retry authority.
Monotonic deadlines are valid only in the private process incarnation that
reserved them. A new controller process cannot resume an old reservation or
backfill its clock identity; it must reconcile that attempt's owned custody.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from typing import Any, Iterator, Mapping

from .util import content_hash


class DockerExecJournalError(RuntimeError):
    """A durable reservation cannot safely authorize the next operation."""


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_ID = re.compile(r"[0-9a-f]{64}")
_ATTEMPT = re.compile(r"engine-attempt-[0-9a-f]{32}")
_OPERATION = re.compile(r"operation-[0-9a-f]{32}")
_PHASES = {
    "reserved",
    "created",
    "start_reserved",
    "started",
    "inspect_reserved",
    "complete",
    "uncertain",
}


def _new_clock_epoch_ref() -> str:
    return content_hash(
        {
            "schema_version": "bluefire.engine-docker-exec-clock-epoch.v1",
            "process_id": os.getpid(),
            "incarnation_nonce": uuid.uuid4().hex,
        }
    )


_CLOCK_EPOCH_REF = _new_clock_epoch_ref()


def _after_fork_child() -> None:
    global _CLOCK_EPOCH_REF
    _CLOCK_EPOCH_REF = _new_clock_epoch_ref()


_register_at_fork = getattr(os, "register_at_fork", None)
if callable(_register_at_fork):
    _register_at_fork(after_in_child=_after_fork_child)


def _text(value: Any, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise DockerExecJournalError("exec reservation identity is invalid")
    return value


def _identity(admission: Mapping[str, Any]) -> tuple[str, str, str]:
    if admission.get("schema_version") != "bluefire.engine-docker-exec-admission.v2":
        raise DockerExecJournalError("exec reservation schema is invalid")
    attempt = _text(admission.get("attempt_id"), _ATTEMPT)
    operation = _text(admission.get("operation_id"), _OPERATION)
    _text(admission.get("container_id"), _ID)
    _text(admission.get("request_digest"), _DIGEST)
    return attempt, operation, content_hash(dict(admission))


class SQLiteDockerExecOperationJournal:
    """Serialized atomic claims; a fresh instance cannot reopen dispatch rights."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        if type(connection) is not sqlite3.Connection or connection.in_transaction:
            raise DockerExecJournalError("exec journal requires a dedicated connection")
        databases = connection.execute("PRAGMA database_list").fetchall()
        if len(databases) != 1 or databases[0][1] != "main" or not databases[0][2]:
            raise DockerExecJournalError("exec journal must be persistent")
        self._connection = connection
        self._lock = threading.RLock()
        self._clock_epoch_ref = _CLOCK_EPOCH_REF
        mode = connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
        if str(mode).lower() != "delete":
            raise DockerExecJournalError("exec journal atomic rollback is unavailable")
        # DELETE mode needs EXTRA to sync the directory after rollback-journal
        # unlink; FULL alone does not establish that durable commit boundary.
        connection.execute("PRAGMA synchronous=EXTRA")
        durability = connection.execute("PRAGMA synchronous").fetchone()[0]
        if type(durability) is not int or durability != 3:
            raise DockerExecJournalError("exec journal durability is unavailable")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS docker_exec_operations_v2 (
            attempt_id TEXT NOT NULL, operation_id TEXT NOT NULL,
            admission_ref TEXT NOT NULL, admission_json TEXT NOT NULL,
            authority_ref TEXT NOT NULL, create_request_digest TEXT NOT NULL,
            dispatch_request_digest TEXT NOT NULL, deadline_ns INTEGER NOT NULL,
            reservation_ref TEXT NOT NULL UNIQUE, phase TEXT NOT NULL,
            exec_id TEXT, clock_epoch_ref TEXT, PRIMARY KEY(attempt_id, operation_id))"""
        )
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(docker_exec_operations_v2)")
        }
        if "clock_epoch_ref" not in columns:
            # Historical reservations have unknown monotonic-clock continuity.
            # Leave their epoch NULL; they cannot regain dispatch authority.
            connection.execute(
                "ALTER TABLE docker_exec_operations_v2 ADD COLUMN clock_epoch_ref TEXT"
            )
        connection.commit()

    def _require_current_epoch(self) -> None:
        if self._clock_epoch_ref != _CLOCK_EPOCH_REF:
            raise DockerExecJournalError("exec clock epoch continuity is unavailable")

    def _row(self, attempt: str, operation: str) -> dict[str, Any] | None:
        self._require_current_epoch()
        cursor = self._connection.execute(
            "SELECT * FROM docker_exec_operations_v2 WHERE attempt_id=? AND operation_id=?",
            (attempt, operation),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        result = dict(zip((item[0] for item in cursor.description), row, strict=True))
        if result.get("clock_epoch_ref") != self._clock_epoch_ref:
            raise DockerExecJournalError("exec clock epoch continuity is unavailable")
        try:
            saved = json.loads(result["admission_json"])
            identity = _identity(saved)
            if (
                identity != (attempt, operation, result["admission_ref"])
                or result["phase"] not in _PHASES
                or type(result["deadline_ns"]) is not int
                or result["deadline_ns"] <= 0
            ):
                raise ValueError("changed reservation")
            for field in (
                "authority_ref",
                "create_request_digest",
                "dispatch_request_digest",
                "reservation_ref",
            ):
                _text(result[field], _DIGEST)
            if result["exec_id"] is not None:
                _text(result["exec_id"], _ID)
            expected_ref = content_hash(
                {
                    "schema_version": "bluefire.engine-docker-exec-reservation.v2",
                    "attempt_id": attempt,
                    "operation_id": operation,
                    "admission_ref": result["admission_ref"],
                    "authority_ref": result["authority_ref"],
                    "create_request_digest": result["create_request_digest"],
                    "deadline_ns": result["deadline_ns"],
                    "clock_epoch_ref": result["clock_epoch_ref"],
                }
            )
            if result["reservation_ref"] != expected_ref:
                raise ValueError("changed reservation reference")
        except (TypeError, ValueError, KeyError) as exc:
            raise DockerExecJournalError("exec journal integrity differs") from exc
        return result

    def claim_dispatch(
        self,
        *,
        admission: Mapping[str, Any],
        operation: str,
        request_digest: str,
        deadline_monotonic_ns: int,
        authority_ref: str,
        exec_id: str | None = None,
    ) -> Mapping[str, Any]:
        self._require_current_epoch()
        attempt, operation_id, admission_ref = _identity(admission)
        _text(request_digest, _DIGEST)
        _text(authority_ref, _DIGEST)
        if type(deadline_monotonic_ns) is not int or deadline_monotonic_ns <= 0:
            raise DockerExecJournalError("exec reservation deadline is invalid")
        if operation not in {"container_exec_create", "exec_start", "exec_inspect"}:
            raise DockerExecJournalError("exec dispatch operation is invalid")
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                row = self._row(attempt, operation_id)
                if operation == "container_exec_create":
                    if row is not None or exec_id is not None:
                        raise DockerExecJournalError("exec operation was already reserved")
                    unfinished = self._connection.execute(
                        "SELECT operation_id FROM docker_exec_operations_v2 "
                        "WHERE attempt_id=? AND phase != 'complete' LIMIT 1",
                        (attempt,),
                    ).fetchone()
                    count = self._connection.execute(
                        "SELECT COUNT(*) FROM docker_exec_operations_v2 WHERE attempt_id=?",
                        (attempt,),
                    ).fetchone()[0]
                    if unfinished is not None or count >= 1024:
                        raise DockerExecJournalError(
                            "exec attempt has unfinished or exhausted reservations"
                        )
                    reservation_ref = content_hash(
                        {
                            "schema_version": "bluefire.engine-docker-exec-reservation.v2",
                            "attempt_id": attempt,
                            "operation_id": operation_id,
                            "admission_ref": admission_ref,
                            "authority_ref": authority_ref,
                            "create_request_digest": request_digest,
                            "deadline_ns": deadline_monotonic_ns,
                            "clock_epoch_ref": self._clock_epoch_ref,
                        }
                    )
                    self._connection.execute(
                        "INSERT INTO docker_exec_operations_v2 "
                        "(attempt_id,operation_id,admission_ref,admission_json,authority_ref,"
                        "create_request_digest,dispatch_request_digest,deadline_ns,reservation_ref,"
                        "phase,exec_id,clock_epoch_ref) VALUES (?,?,?,?,?,?,?,?,?,?,NULL,?)",
                        (
                            attempt,
                            operation_id,
                            admission_ref,
                            json.dumps(dict(admission), sort_keys=True, separators=(",", ":")),
                            authority_ref,
                            request_digest,
                            request_digest,
                            deadline_monotonic_ns,
                            reservation_ref,
                            "reserved",
                            self._clock_epoch_ref,
                        ),
                    )
                else:
                    _text(exec_id, _ID)
                    expected = "created" if operation == "exec_start" else "started"
                    if (
                        row is None
                        or row["phase"] != expected
                        or row["admission_ref"] != admission_ref
                        or row["authority_ref"] != authority_ref
                        or row["exec_id"] != exec_id
                        or deadline_monotonic_ns > row["deadline_ns"]
                    ):
                        raise DockerExecJournalError(
                            "exec dispatch has no matching durable custody"
                        )
                    self._connection.execute(
                        "UPDATE docker_exec_operations_v2 SET phase=?, dispatch_request_digest=? "
                        "WHERE attempt_id=? AND operation_id=?",
                        (
                            "start_reserved" if operation == "exec_start" else "inspect_reserved",
                            request_digest,
                            attempt,
                            operation_id,
                        ),
                    )
                result = self._row(attempt, operation_id)
                if result is None:
                    raise DockerExecJournalError("exec reservation disappeared")
                self._connection.commit()
                return result
            except BaseException:
                self._connection.rollback()
                raise

    def transition(
        self,
        *,
        admission: Mapping[str, Any],
        authority_ref: str,
        phase: str,
        exec_id: str | None = None,
    ) -> None:
        self._require_current_epoch()
        attempt, operation_id, admission_ref = _identity(admission)
        expected = {
            "created": "reserved",
            "started": "start_reserved",
            "complete": "inspect_reserved",
        }
        if phase not in {*expected, "uncertain"}:
            raise DockerExecJournalError("exec journal transition is invalid")
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                row = self._row(attempt, operation_id)
                if (
                    row is None
                    or row["admission_ref"] != admission_ref
                    or row["authority_ref"] != authority_ref
                ):
                    raise DockerExecJournalError("exec journal transition identity differs")
                if phase != "uncertain" and row["phase"] != expected[phase]:
                    raise DockerExecJournalError("exec journal transition was already consumed")
                if phase == "created":
                    _text(exec_id, _ID)
                else:
                    exec_id = row["exec_id"]
                self._connection.execute(
                    "UPDATE docker_exec_operations_v2 SET phase=?,exec_id=? WHERE attempt_id=? AND operation_id=?",
                    (phase, exec_id, attempt, operation_id),
                )
                self._connection.commit()
            except BaseException:
                self._connection.rollback()
                raise

    @contextmanager
    def hold_send(
        self,
        *,
        admission: Mapping[str, Any],
        operation: str,
        request_digest: str,
        authority_ref: str,
        reservation_ref: str,
    ) -> Iterator[None]:
        """Serialize quarantine against one bounded socket write, never attach I/O."""

        self._require_current_epoch()
        attempt, operation_id, admission_ref = _identity(admission)
        expected = {
            "container_exec_create": "reserved",
            "exec_start": "start_reserved",
            "exec_inspect": "inspect_reserved",
        }.get(operation)
        if expected is None:
            raise DockerExecJournalError("exec send operation is invalid")
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                row = self._row(attempt, operation_id)
                if (
                    row is None
                    or row["admission_ref"] != admission_ref
                    or row["authority_ref"] != authority_ref
                    or row["reservation_ref"] != reservation_ref
                    or row["dispatch_request_digest"] != request_digest
                    or row["phase"] != expected
                ):
                    raise DockerExecJournalError("exec send reservation was revoked or changed")
                yield
                self._connection.commit()
            except BaseException:
                self._connection.rollback()
                raise

    def snapshot(self, *, attempt_id: str, operation_id: str) -> Mapping[str, Any] | None:
        self._require_current_epoch()
        with self._lock:
            return self._row(_text(attempt_id, _ATTEMPT), _text(operation_id, _OPERATION))
