"""Bounded authenticated-transport frame I/O with caller-owned sockets/deadlines."""

from __future__ import annotations

import json
import ssl
import struct
import threading
from typing import Any, Callable, Mapping, Protocol

from .runner_transport_errors import RunnerAuthenticationError, RunnerConnectionError
from .util import canonical_json_bytes


def _duplicates_rejected(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"unsupported JSON constant: {value}")


def _decode_json_object(payload: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_duplicates_rejected,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise RunnerAuthenticationError("Runner message is not valid canonical JSON.") from None
    if not isinstance(value, dict):
        raise RunnerAuthenticationError("Runner message must be a JSON object.")
    try:
        if canonical_json_bytes(value) != payload:
            raise RunnerAuthenticationError("Runner message is not canonical JSON.")
    except (RecursionError, TypeError, ValueError):
        raise RunnerAuthenticationError("Runner message contains unsupported JSON.") from None
    return value


class ReceiveExact(Protocol):
    def __call__(
        self,
        connection: ssl.SSLSocket,
        length: int,
        *,
        deadline: float | None = None,
        abort_event: threading.Event | None = None,
    ) -> bytes: ...


def _receive_exact(
    connection: ssl.SSLSocket,
    length: int,
    *,
    monotonic: Callable[[], float],
    deadline: float | None = None,
    abort_event: threading.Event | None = None,
) -> bytes:
    result = bytearray()
    while len(result) < length:
        if abort_event is not None and abort_event.is_set():
            raise RunnerConnectionError("Runner message wait was cancelled.")
        if deadline is not None:
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise RunnerConnectionError("Runner message deadline expired.")
            connection.settimeout(min(remaining, 0.1) if abort_event is not None else remaining)
        try:
            chunk = connection.recv(length - len(result))
        except TimeoutError:
            if abort_event is not None:
                continue
            raise
        if deadline is not None and monotonic() >= deadline:
            raise RunnerConnectionError("Runner message deadline expired.")
        if not chunk:
            raise RunnerConnectionError("Runner connection closed before the message completed.")
        result.extend(chunk)
    return bytes(result)


def _receive_frame(
    connection: ssl.SSLSocket,
    maximum: int,
    *,
    receive_exact: ReceiveExact,
    decode_json: Callable[[bytes], dict[str, Any]],
    frame_header: struct.Struct,
    deadline: float | None = None,
    abort_event: threading.Event | None = None,
) -> dict[str, Any]:
    header = receive_exact(
        connection,
        frame_header.size,
        deadline=deadline,
        abort_event=abort_event,
    )
    (length,) = frame_header.unpack(header)
    if length == 0 or length > maximum:
        raise RunnerAuthenticationError("Runner message exceeds the framing limit.")
    return decode_json(
        receive_exact(
            connection,
            length,
            deadline=deadline,
            abort_event=abort_event,
        )
    )


def _send_frame(
    connection: ssl.SSLSocket,
    value: Mapping[str, Any],
    maximum: int,
    *,
    frame_header: struct.Struct,
) -> None:
    try:
        payload = canonical_json_bytes(dict(value))
    except (RecursionError, TypeError, ValueError):
        raise RunnerAuthenticationError("Runner message contains unsupported JSON.") from None
    if not payload or len(payload) > maximum:
        raise RunnerAuthenticationError("Runner message exceeds the framing limit.")
    connection.sendall(frame_header.pack(len(payload)) + payload)
