"""Fixed-size frames over an owned child pipe, with an absolute deadline."""

from __future__ import annotations

import os
import select
import time
from typing import Any, Mapping

from .receiver_session_contract import FRAME_LIMIT, ReceiverSessionError, decode_frame, encode_frame


def read_frame(descriptor: int, *, deadline_ns: int) -> Mapping[str, Any]:
    payload = bytearray()
    while len(payload) < FRAME_LIMIT:
        remaining = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if remaining <= 0:
            raise ReceiverSessionError("owned receiver channel expired")
        readable, _, _ = select.select([descriptor], [], [], min(remaining, 0.25))
        if not readable:
            continue
        # One byte prevents reading a later frame before its state transition.
        chunk = os.read(descriptor, 1)
        if not chunk:
            raise ReceiverSessionError("owned receiver channel closed before completion")
        payload.extend(chunk)
        if chunk == b"\n":
            return decode_frame(bytes(payload))
    raise ReceiverSessionError("owned receiver frame exceeded its bound")


def write_frame(descriptor: int, value: Mapping[str, Any]) -> None:
    payload = encode_frame(value)
    deadline_ns = time.monotonic_ns() + 5_000_000_000
    os.set_blocking(descriptor, False)
    while payload:
        remaining = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if remaining <= 0:
            raise ReceiverSessionError("owned receiver channel write expired")
        _, writable, _ = select.select([], [descriptor], [], min(remaining, 0.25))
        if not writable:
            continue
        try:
            written = os.write(descriptor, payload)
        except BlockingIOError:
            continue
        if written <= 0:
            raise ReceiverSessionError("owned receiver channel write failed")
        payload = payload[written:]


def require_eof(descriptor: int) -> None:
    readable, _, _ = select.select([descriptor], [], [], 5.0)
    if not readable or os.read(descriptor, 1):
        raise ReceiverSessionError("owned receiver terminal channel is incomplete")
