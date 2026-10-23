from __future__ import annotations

from types import SimpleNamespace

import pytest

import bluefire.receiver as receiver_module


class _FakeClock:
    def __init__(self) -> None:
        self.current = 0.0

    def monotonic(self) -> float:
        return self.current


class _ProgressingSocket:
    def __init__(self, clock: _FakeClock, chunks: tuple[bytes, ...]) -> None:
        self._clock = clock
        self._chunks = list(chunks)
        self.timeouts: list[float] = []
        self.recv_calls = 0

    def settimeout(self, timeout: float) -> None:
        self.timeouts.append(timeout)

    def recv(self, _maximum: int) -> bytes:
        self.recv_calls += 1
        if not self._chunks:
            raise AssertionError("the reader received after the fake request deadline")
        self._clock.current += 0.4
        return self._chunks.pop(0)


def test_progressing_partial_reads_share_one_absolute_request_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _FakeClock()
    connection = _ProgressingSocket(clock, (b"P", b"O", b"S"))
    monkeypatch.setattr(receiver_module, "time", SimpleNamespace(monotonic=clock.monotonic))
    reader = receiver_module._DeadlineReader(connection, deadline=1.0)

    with pytest.raises(receiver_module._ProtocolRefusal) as caught:
        reader.readline(16)

    assert caught.value.status == 408
    assert caught.value.code == "request_timeout"
    assert str(caught.value) == "request_timeout"
    assert connection.timeouts == pytest.approx((1.0, 0.6, 0.2))
    assert connection.recv_calls == 3
    assert connection._chunks == []
