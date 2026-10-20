"""Single-use exchanges on an original creator's inherited primitive channel.

This transport does not adopt a child, mint authority, or establish custody.
The concrete creator must verify those separately before and after an exchange.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from typing import Any, cast

from .macos_file_access_contract import (
    MAX_MESSAGE,
    MacOSFileAccessContractError,
    decode_request,
    validate_binding,
    validate_observation,
    validate_request,
)
from .macos_file_access_peer import darwin_clock_ns
from .util import canonical_json_bytes, content_hash


def _refuse() -> MacOSFileAccessContractError:
    return MacOSFileAccessContractError("The original Darwin primitive exchange is unavailable.")


def _anchor(binding: dict[str, Any]) -> str:
    return content_hash(
        {key: value for key, value in binding.items() if key not in {"mode", "control_revision"}}
    )


def _decode(raw: bytes, request: dict[str, Any]) -> dict[str, Any]:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise _refuse()
            result[key] = value
        return result

    def reject_constant(_value):
        raise _refuse()

    try:
        return validate_observation(
            json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant), request
        )
    except (ValueError, UnicodeError, RecursionError, TypeError, OverflowError):
        raise _refuse() from None


class MacOSPrimitiveChannel:
    """Own a transferred socket, but never treat its possession as authority.

    Only the fixed creator supplies this channel and its original binding. The
    original child and sealed namespace remain the creator's responsibility.
    """

    def __init__(self, stream: socket.socket, binding: dict[str, Any], *, role: str):
        original = validate_binding(binding)
        if (
            type(role) is not str
            or role not in {"reader", "owner", "control"}
            or not isinstance(stream, socket.socket)
            or stream.family != getattr(socket, "AF_UNIX", None)
            or stream.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
            or stream.fileno() < 3
        ):
            raise _refuse()
        stream.getpeername()
        stream.set_inheritable(False)
        self._stream = stream
        self._anchor = _anchor(original)
        self._role = role
        self._sequence = 0
        self._revision = original["control_revision"]
        self._requests: set[str] = set()
        self._last_clock = (0, 0)
        self._poisoned = False
        self._closed = False
        self._close_attempted = False
        self._local_cleanup_unknown = False
        self._lock = threading.Lock()

    @property
    def usable(self) -> bool:
        return not self._poisoned and not self._closed

    @property
    def local_cleanup_unknown(self) -> bool:
        return self._local_cleanup_unknown

    def _close_transport(self) -> None:
        self._closed = True
        if self._close_attempted:
            return
        # Never retry an ambiguously closed descriptor that may have been reused.
        self._close_attempted = True
        try:
            self._stream.close()
        except BaseException:
            self._local_cleanup_unknown = True
            raise

    def _guard(self, request: dict[str, Any]) -> float:
        wall, monotonic = time.time_ns() // 1_000_000, darwin_clock_ns()
        validate_request(request, now_ms=wall, now_ns=monotonic)
        if wall < self._last_clock[0] or monotonic < self._last_clock[1]:
            raise _refuse()
        self._last_clock = wall, monotonic
        return min(
            (cast(int, request["expires_at_ms"]) - wall) / 1000,
            (cast(int, request["deadline_ns"]) - monotonic) / 1_000_000_000,
        )

    def _send(self, raw: bytes, request: dict[str, Any]) -> None:
        remaining = memoryview(raw)
        while remaining:
            self._stream.settimeout(self._guard(request))
            count = self._stream.send(remaining)
            if type(count) is not int or not 0 < count <= len(remaining):
                raise _refuse()
            remaining = remaining[count:]
        self._guard(request)

    def _receive(self, size: int, request: dict[str, Any]) -> bytes:
        result = bytearray()
        receive = getattr(self._stream, "recvmsg", None)
        if not callable(receive):
            raise _refuse()
        while len(result) < size:
            self._stream.settimeout(self._guard(request))
            raw, ancillary, flags, _address = receive(size - len(result), 0)
            if not raw or len(raw) > size - len(result) or ancillary or flags:
                raise _refuse()
            result.extend(raw)
        self._guard(request)
        return bytes(result)

    def exchange(self, request: dict[str, Any]) -> dict[str, Any]:
        if not self._lock.acquire(blocking=False):
            raise _refuse()
        try:
            if not self.usable:
                raise _refuse()
            # Freeze caller data before consuming the one-time sequence number.
            original = decode_request(canonical_json_bytes(validate_request(request)))
            allowed = {
                "reader": {"read_reader", "close"},
                "owner": {"read_owner", "close"},
                "control": {"harden", "rollback", "close"},
            }[self._role]
            if (
                original["operation"] not in allowed
                or _anchor(original["binding"]) != self._anchor
                or original["sequence"] != self._sequence + 1
                or original["request_id"] in self._requests
                or original["binding"]["control_revision"] < self._revision
            ):
                raise _refuse()
            self._guard(original)
            self._sequence = original["sequence"]
            self._revision = original["binding"]["control_revision"]
            self._requests.add(original["request_id"])
            raw = canonical_json_bytes(original)
            self._send(len(raw).to_bytes(4, "little") + raw, original)
            size = int.from_bytes(self._receive(4, original), "little")
            if not 0 < size <= MAX_MESSAGE:
                raise _refuse()
            observed = _decode(self._receive(size, original), original)
            self._guard(original)
            if (
                observed["outcome"] in {"unknown", "refused"}
                or observed["request_handle_cleanup"] == "unknown"
                or observed["held_handle_cleanup"] == "unknown"
            ):
                self._poisoned = True
            if original["operation"] == "close":
                self._close_transport()
            return observed
        except BaseException:
            self._poisoned = True
            self._close_transport()
            raise
        finally:
            self._lock.release()

    def abandon(self) -> None:
        """Close local transport, making no child or resource cleanup claim."""
        with self._lock:
            self._poisoned = True
            self._close_transport()
