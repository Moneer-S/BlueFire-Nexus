"""Serialization and in-memory regressions for the extracted runner boundaries."""

from __future__ import annotations

import hashlib
import hmac
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import runner_bootstrap_record as codec
from bluefire import runner_lifecycle as lifecycle
from bluefire import runner_transport as wire
from bluefire.util import canonical_json_bytes


def test_bootstrap_record_keeps_canonical_fields_authentication_and_private_repr() -> None:
    # Synthetic paths and key; this is serialization only, never enrollment.
    record = lifecycle._BootstrapRecord(
        binary_path=Path("synthetic-runner"),
        sandbox_path=Path("synthetic-sandbox"),
        binary_digest="sha256:" + "a" * 64,
        source="packaged",
        managed_binary=True,
        managed_sandbox=False,
        product_version="3.0.0",
        runner_version="3.0.0",
        platform="windows",
        architecture="x86_64",
        inventory_schema="inventory.v1",
        action_sdk_version="sdk.v1",
        receipt_protocol="receipt.v1",
    )
    assert lifecycle._BootstrapRecord is codec._BootstrapRecord
    expected = {
        "schema_version": "bluefire.runner-lifecycle-bootstrap.v1",
        "runner_id": lifecycle.RUNNER_ID,
        "source": "packaged",
        "managed_binary": True,
        "managed_sandbox": False,
        "binary_path": "synthetic-runner",
        "sandbox_path": "synthetic-sandbox",
        "binary_digest": "sha256:" + "a" * 64,
        "product_version": "3.0.0",
        "runner_version": "3.0.0",
        "platform": "windows",
        "architecture": "x86_64",
        "inventory_schema": "inventory.v1",
        "action_sdk_version": "sdk.v1",
        "receipt_protocol": "receipt.v1",
    }
    payload = lifecycle._bootstrap_record_payload(record)
    assert payload == expected
    key = bytes(range(32))
    enrollment = SimpleNamespace(hmac_key=lambda: key)
    authentication = lifecycle._record_authentication(enrollment, payload)
    assert (
        authentication
        == "sha256:" + hmac.new(key, canonical_json_bytes(expected), hashlib.sha256).hexdigest()
    )
    assert (
        lifecycle._record_authentication(enrollment, {**payload, "managed_binary": False})
        != authentication
    )
    assert "synthetic-runner" not in repr(record)
    assert "synthetic-sandbox" not in repr(record)
    assert record.binary_digest not in repr(record)


def test_frame_dispatch_uses_current_compatibility_reader_and_decoder(monkeypatch) -> None:
    payload = b'{"accepted":true}'
    calls = []
    sentinel = object()

    def read(connection, length, *, deadline=None, abort_event=None):
        assert connection is sentinel
        calls.append((length, deadline, abort_event))
        return wire._FRAME_HEADER.pack(len(payload)) if len(calls) == 1 else payload

    decoded = {"decoded": "through compatibility seam"}
    monkeypatch.setattr(wire, "_receive_exact", read)
    monkeypatch.setattr(
        wire, "_decode_json_object", lambda raw: decoded if raw == payload else None
    )
    assert wire._receive_frame(sentinel, 1024, deadline=12.0) is decoded
    assert calls == [(wire._FRAME_HEADER.size, 12.0, None), (len(payload), 12.0, None)]


@pytest.mark.parametrize("declared", [0, 1025])
def test_invalid_frame_size_never_requests_payload(monkeypatch, declared) -> None:
    calls = []

    def read(_connection, length, **_kwargs):
        calls.append(length)
        assert len(calls) == 1, "rejected frame must not consume payload"
        return wire._FRAME_HEADER.pack(declared)

    monkeypatch.setattr(wire, "_receive_exact", read)
    with pytest.raises(wire.RunnerAuthenticationError, match="framing limit"):
        wire._receive_frame(object(), 1024)
    assert calls == [wire._FRAME_HEADER.size]


def test_frame_send_preserves_canonical_bytes_and_refuses_oversize_before_write() -> None:
    sent = []
    socket = SimpleNamespace(sendall=sent.append)
    wire._send_frame(socket, {"z": 2, "a": 1}, 13)
    assert sent == [wire._FRAME_HEADER.pack(13) + b'{"a":1,"z":2}']
    with pytest.raises(wire.RunnerAuthenticationError, match="framing limit"):
        wire._send_frame(socket, {"z": 2, "a": 1}, 12)
    assert len(sent) == 1


@pytest.mark.parametrize("already_cancelled", [True, False])
def test_frame_receive_cancellation_prevents_additional_reads(monkeypatch, already_cancelled):
    abort = threading.Event()
    if already_cancelled:
        abort.set()
    reads = []
    timeouts = []

    def receive(length):
        reads.append(length)
        abort.set()
        raise TimeoutError

    monkeypatch.setattr(wire, "time", SimpleNamespace(monotonic=lambda: 100.0))
    socket = SimpleNamespace(recv=receive, settimeout=timeouts.append)
    with pytest.raises(wire.RunnerConnectionError, match="cancelled"):
        wire._receive_exact(socket, 4, deadline=101.0, abort_event=abort)
    assert reads == ([] if already_cancelled else [4])
    assert timeouts == ([] if already_cancelled else [0.1])


def test_incomplete_frame_never_reaches_decoder(monkeypatch):
    chunks = iter([wire._FRAME_HEADER.pack(2), b"{", b""])
    requested = []

    def receive(length):
        requested.append(length)
        return next(chunks)

    def decode(_payload):
        pytest.fail("An incomplete frame must not reach the decoder.")

    monkeypatch.setattr(wire, "_decode_json_object", decode)
    with pytest.raises(wire.RunnerConnectionError, match="closed before"):
        wire._receive_frame(SimpleNamespace(recv=receive), 1024)
    assert requested == [wire._FRAME_HEADER.size, 2, 1]


@pytest.mark.parametrize("value", [float("nan"), object()])
def test_unsupported_frame_value_is_refused_before_any_write(value):
    sent = []
    with pytest.raises(wire.RunnerAuthenticationError, match="unsupported JSON"):
        wire._send_frame(SimpleNamespace(sendall=sent.append), {"value": value}, 1024)
    assert not sent
