"""One fixed read behind a trusted launcher, not a listener or launch authority.

The caller owns durable admission, authenticated transport and a hard worker
deadline. Wire equality binds a request; it does not authenticate its sender.
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from .runner_transport_errors import RunnerAuthenticationError
from .runner_transport_framing import _decode_json_object
from .util import canonical_json_bytes, content_hash
from .windows_file_access_read import (
    WindowsFileReadError,
    WindowsReadExpectation,
    WindowsReadObservation,
    fresh_windows_read,
)

REQUEST_SCHEMA = "bluefire.windows-file-read-request.v1"
RESULT_SCHEMA = "bluefire.windows-file-read-result.v1"
MAX_MESSAGE_BYTES = 4096
MAX_OPERATION_MS = 5000


class WindowsReadWorkerError(RuntimeError):
    """A worker exchange is unavailable, not an observed access denial."""


def _milliseconds() -> int:
    return time.time_ns() // 1_000_000


def _document(payload: bytes) -> dict[str, Any]:
    if type(payload) is not bytes or not 0 < len(payload) <= MAX_MESSAGE_BYTES:
        raise WindowsReadWorkerError("Windows reader message exceeds its bound")
    try:
        return _decode_json_object(payload)
    except RunnerAuthenticationError:
        raise WindowsReadWorkerError("Windows reader message is invalid") from None


def _hex(value: Any, length: int) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value) is not None


@dataclass(frozen=True)
class WindowsReadOperation:
    """Private immutable original-task inputs, supplied by trusted setup only."""

    expectation: WindowsReadExpectation = field(repr=False)
    operation_id: str
    challenge: str = field(repr=False)
    control_revision: int
    created_at_ms: int
    deadline_ms: int

    def __post_init__(self) -> None:
        if type(self.expectation) is not WindowsReadExpectation:
            raise WindowsReadWorkerError("Windows reader enrollment is invalid")
        try:
            self.expectation.validate()
        except WindowsFileReadError:
            raise WindowsReadWorkerError("Windows reader enrollment is invalid") from None
        if (
            not _hex(self.operation_id, 32)
            or not _hex(self.challenge, 64)
            or type(self.control_revision) is not int
            or not 1 <= self.control_revision <= 2**31 - 1
            or type(self.created_at_ms) is not int
            or type(self.deadline_ms) is not int
            or not 1 <= self.created_at_ms < self.deadline_ms <= 2**63 - 1
            or self.deadline_ms - self.created_at_ms > MAX_OPERATION_MS
        ):
            raise WindowsReadWorkerError("Windows reader original task is invalid")

    def request(self) -> bytes:
        return canonical_json_bytes(
            {
                "schema_version": REQUEST_SCHEMA,
                "operation_id": self.operation_id,
                "challenge": self.challenge,
                "control_revision": self.control_revision,
                "created_at_ms": self.created_at_ms,
                "deadline_ms": self.deadline_ms,
                "enrollment_digest": content_hash(asdict(self.expectation)),
            }
        )

    def require_current(self) -> int:
        current = _milliseconds()
        if not self.created_at_ms <= current < self.deadline_ms:
            raise WindowsReadWorkerError("Windows reader original interval is not current")
        return current


def _result(operation: WindowsReadOperation, observed: WindowsReadObservation) -> dict[str, Any]:
    expected = operation.expectation
    resource = expected.resource
    if (
        type(observed) is not WindowsReadObservation
        or observed.principal != expected.principal
        or observed.file_identity != resource.file_identity
        or type(observed.observed_size) is not int
        or observed.observed_size != resource.size
        or observed.read_handles_closed is not True
        or type(observed.selected_descriptor_sha256) is not str
        or re.fullmatch(r"sha256:[0-9a-f]{64}", observed.selected_descriptor_sha256) is None
    ):
        raise WindowsReadWorkerError("Windows reader observation is not bound to enrollment")
    if observed.outcome == "allowed":
        valid = (
            observed.sha256 == resource.sha256
            and type(observed.record_count) is int
            and observed.record_count == resource.record_count
        )
    elif observed.outcome == "permission_denied":
        valid = observed.sha256 is None and observed.record_count is None
    else:
        valid = False
    if not valid:
        raise WindowsReadWorkerError("Windows reader outcome is inconsistent")
    return {
        "schema_version": RESULT_SCHEMA,
        "request_digest": content_hash(_document(operation.request())),
        "observed_at_ms": operation.require_current(),
        "outcome": observed.outcome,
        "size": observed.observed_size,
        "sha256": observed.sha256,
        "record_count": observed.record_count,
        "selected_descriptor_sha256": observed.selected_descriptor_sha256,
        "read_handles_closed": True,
    }


class OneReadWorker:
    """Consume once even on failure; durable replay protection belongs upstream.

    No process is started here. Cooperative clocks cannot terminate blocked
    native calls. Do not expose this object without the owned worker boundary.
    """

    def __init__(self, operation: WindowsReadOperation):
        if type(operation) is not WindowsReadOperation:
            raise WindowsReadWorkerError("Windows reader original task is invalid")
        current = operation.require_current()
        self._operation = operation
        self._deadline = time.monotonic() + (operation.deadline_ms - current) / 1000
        self._lock = threading.Lock()
        self._consumed = False

    def execute(self, payload: bytes) -> bytes:
        with self._lock:
            if self._consumed:
                raise WindowsReadWorkerError("Windows reader original task was consumed")
            self._consumed = True
        operation = self._operation
        current = operation.require_current()
        deadline = min(self._deadline, time.monotonic() + (operation.deadline_ms - current) / 1000)
        _document(payload)
        if payload != operation.request():
            raise WindowsReadWorkerError("Windows reader request differs from the original task")
        if time.monotonic() >= deadline:
            raise WindowsReadWorkerError("Windows reader operation deadline exceeded")
        try:
            observed = fresh_windows_read(operation.expectation)
        except WindowsFileReadError:
            raise WindowsReadWorkerError("Windows reader observation is unavailable") from None
        if time.monotonic() >= deadline:
            raise WindowsReadWorkerError("Windows reader operation deadline exceeded")
        result = canonical_json_bytes(_result(operation, observed))
        if len(result) > MAX_MESSAGE_BYTES:
            raise WindowsReadWorkerError("Windows reader result exceeds its bound")
        return result


def accept_read_result(operation: WindowsReadOperation, payload: bytes) -> dict[str, Any]:
    """Validate a trusted worker's report, not independent telemetry or identity.

    The caller must separately bind the live peer and complete process cleanup.
    Do not reconstruct an OS observation or claim cleanup of the whole worker
    from this report's read-handle closure field.
    """
    if type(operation) is not WindowsReadOperation:
        raise WindowsReadWorkerError("Windows reader original task is invalid")
    current = operation.require_current()
    row = _document(payload)
    if set(row) != {
        "schema_version",
        "request_digest",
        "observed_at_ms",
        "outcome",
        "size",
        "sha256",
        "record_count",
        "selected_descriptor_sha256",
        "read_handles_closed",
    }:
        raise WindowsReadWorkerError("Windows reader result fields are invalid")
    if (
        row["schema_version"] != RESULT_SCHEMA
        or row["request_digest"] != content_hash(_document(operation.request()))
        or type(row["observed_at_ms"]) is not int
        or not operation.created_at_ms <= row["observed_at_ms"] <= current
        or type(row["size"]) is not int
        or row["size"] != operation.expectation.resource.size
        or row["read_handles_closed"] is not True
        or type(row["selected_descriptor_sha256"]) is not str
        or re.fullmatch(r"sha256:[0-9a-f]{64}", row["selected_descriptor_sha256"]) is None
    ):
        raise WindowsReadWorkerError("Windows reader result does not match the original task")
    if row["outcome"] == "allowed":
        valid = (
            row["sha256"] == operation.expectation.resource.sha256
            and type(row["record_count"]) is int
            and row["record_count"] == operation.expectation.resource.record_count
        )
    elif row["outcome"] == "permission_denied":
        valid = row["sha256"] is None and row["record_count"] is None
    else:
        valid = False
    if not valid:
        raise WindowsReadWorkerError("Windows reader result outcome is inconsistent")
    return row
