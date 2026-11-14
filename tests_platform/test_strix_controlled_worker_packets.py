"""Focused deadline and readiness cleanup checks for worker packets."""

from __future__ import annotations

import time
from typing import Callable

import pytest

from bluefire import strix_controlled_worker_packets as packets


def test_writable_packet_does_not_send_after_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: list[bytes] = []
    monkeypatch.setattr(packets.asyncio, "get_running_loop", lambda: object())

    class WritableConnection:
        def send(self, packet: bytes, _flags: int) -> int:
            sent.append(packet)
            return len(packet)

    operation = packets.write_frame(
        WritableConnection(), b"already expired", time.monotonic_ns() - 1
    )
    with pytest.raises(packets.CredentialedPacketError):
        operation.send(None)
    assert sent == []


def test_readiness_unregisters_original_descriptor_after_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ClosingConnection:
        descriptor = 17

        def fileno(self) -> int:
            return self.descriptor

        def close(self) -> None:
            self.descriptor = -1

    connection = ClosingConnection()
    registered: list[int] = []
    unregistered: list[int] = []

    class ReadyFuture:
        ready = False

        def done(self) -> bool:
            return self.ready

        def set_result(self, _value: None) -> None:
            self.ready = True

    future = ReadyFuture()

    class ReadyLoop:
        def create_future(self) -> ReadyFuture:
            return future

    monkeypatch.setattr(packets.asyncio, "get_running_loop", ReadyLoop)

    async def completed(ready: ReadyFuture, _timeout: float) -> None:
        assert ready.done()

    monkeypatch.setattr(packets.asyncio, "wait_for", completed)

    def register(descriptor: int, available: Callable[[], None]) -> None:
        registered.append(descriptor)
        connection.close()
        available()

    def unregister(descriptor: int) -> bool:
        unregistered.append(descriptor)
        return True

    operation = packets._ready(
        connection,
        time.monotonic_ns() + 1_000_000_000,
        register,
        unregister,
    )
    with pytest.raises(StopIteration):
        operation.send(None)
    assert registered == [17]
    assert unregistered == [17]
