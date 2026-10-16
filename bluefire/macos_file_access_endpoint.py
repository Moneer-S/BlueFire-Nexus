"""Original child-local channel endpoint, constructed only by verified bootstrap.

The fixed script imports this module only after complete installation and runtime
inventory verification. No document or ordinary constructor creates an endpoint.
"""

from __future__ import annotations

import os
import select
import socket
import threading
import time
from _thread import LockType
from _thread import RLock as RLockType
from types import ModuleType
from typing import Any, Callable, cast

from .macos_file_access_workspace_validation import _refuse


def _socket_constant(name: str) -> int:
    value = getattr(socket, name, None)
    _refuse(isinstance(value, int) and not isinstance(value, bool))
    return cast(int, value)


class OriginalWorkspaceEndpoint:
    """Child-local retained endpoint, not creator custody or journal authority."""

    _stream: socket.socket
    _recipe: dict[str, Any]
    _api: ModuleType
    _closed: bool
    _poisoned: bool
    local_cleanup_unknown: bool
    _clock: tuple[int, int]
    _child_pid: int
    _fork_guard: LockType
    _io_lock: RLockType
    _sequence: int
    _parent_guard: Callable[[dict[str, Any], socket.socket], None]

    def __new__(cls, *_args, **_kwargs) -> OriginalWorkspaceEndpoint:
        raise TypeError("The original inherited workspace bootstrap is required.")

    def assert_current(self, handshake: bool = False) -> float:
        with self._io_lock:
            return self._assert_current_locked(handshake)

    def _assert_current_locked(self, handshake: bool = False) -> float:
        _refuse(not self._closed and not self._poisoned)
        try:
            _refuse(os.getpid() == self._child_pid)
            wall, monotonic = time.time_ns() // 1_000_000, self._api.darwin_clock_ns()
            binding = self._recipe["binding"]
            limit = (
                self._recipe["handshake_deadline_ns"]
                if handshake
                else binding["original_deadline_ns"]
            )
            _refuse(
                binding["issued_at_ms"] <= wall < binding["expires_at_ms"]
                and monotonic < limit
                and wall >= self._clock[0]
                and monotonic >= self._clock[1]
                and os.getppid() == self._recipe["creator_pid"]
            )
            self._clock = wall, monotonic
            self._parent_guard(self._recipe, self._stream)
            wall, monotonic = time.time_ns() // 1_000_000, self._api.darwin_clock_ns()
            _refuse(
                binding["issued_at_ms"] <= wall < binding["expires_at_ms"]
                and monotonic < limit
                and wall >= self._clock[0]
                and monotonic >= self._clock[1]
            )
            self._clock = wall, monotonic
            return float(min((limit - monotonic) / 1e9, (binding["expires_at_ms"] - wall) / 1000))
        except BaseException:
            self._poisoned = True
            raise

    def _before_fork(self) -> None:
        self._io_lock.acquire()
        self._fork_guard.acquire()

    def _after_fork_parent(self) -> None:
        self._fork_guard.release()
        self._io_lock.release()

    def _after_fork_child(self) -> None:
        self._fork_guard = threading.Lock()
        self._io_lock = threading.RLock()
        try:
            self.close()
        except BaseException:
            self.local_cleanup_unknown = True

    def close(self) -> None:
        with self._io_lock:
            with self._fork_guard:
                self._close_locked()

    def current_setup(self) -> dict[str, Any]:
        self.assert_current()
        from bluefire.util import json_clone

        return {
            "schema_version": "bluefire.macos-file-access-setup.v1",
            "binding": json_clone(self._recipe["binding"]),
        }

    def review_context(self, operation: str) -> dict[str, Any]:
        from bluefire.macos_file_access_bridge import exchange

        return exchange(self, "review_context", {"operation": operation})

    def dispatch_committed(
        self, frame: dict[str, Any], *, cancel_event: threading.Event
    ) -> dict[str, Any]:
        from bluefire.macos_file_access_bridge import _committed, exchange

        frame = _committed(frame)
        receipt = exchange(self, "dispatch_committed", frame, cancel_event)
        intent = frame["intent"]
        try:
            if intent["operation"] == "close_attempt":
                from bluefire.macos_file_access_method import validate_closure

                closure = validate_closure(receipt)
                attempt = frame["attempt"]
                _refuse(
                    closure["cleanup_task_id"] == intent["task_id"]
                    and closure["cleanup_transport_request_hash"]
                    == intent["transport_request_hash"]
                    and closure["binding_digest"] == intent["binding_digest"]
                    and closure["attempt_id"] == attempt["attempt_id"]
                    and closure["lease_digest"] == attempt["lease_digest"]
                    and closure["compiled_digest"] == attempt["compiled_digest"]
                    and closure["run_id"] == attempt["run_id"]
                    and closure["cleanup_claim_digest"] == attempt["cleanup_claim_digest"]
                    and closure["task_closures"] == attempt["task_closures"]
                )
                return closure
            _refuse(
                receipt.get("schema_version") == "bluefire.macos-file-access-task-receipt.v1"
                and receipt.get("task_id") == intent["task_id"]
                and receipt.get("transport_request_hash") == intent["transport_request_hash"]
                and receipt.get("binding_digest") == intent["binding_digest"]
                and receipt.get("context_digest") == intent["context_digest"]
                and receipt.get("operation") == intent["operation"]
                and receipt.get("state") in ("complete", "unknown")
                and receipt.get("whole_enrollment_cleanup") is False
            )
        except BaseException:
            self._poisoned = True
            self.close()
            raise
        return receipt

    def check_idle(self) -> None:
        # Monitor peeking shares framing/timeout/clock/close synchronization with
        # the sole task reader; it never consumes a response or races a reused FD.
        with self._io_lock:
            self.assert_current()
            readable, _, _ = select.select([self._stream], [], [], 0)
            if readable:
                raw = self._stream.recv(1, socket.MSG_PEEK | _socket_constant("MSG_DONTWAIT"))
                _refuse(bool(raw))

    def _close_locked(self) -> None:
        self._poisoned = True
        if self._closed:
            return
        self._closed = True
        try:
            self._stream.close()
        except BaseException:
            self.local_cleanup_unknown = True
            raise
