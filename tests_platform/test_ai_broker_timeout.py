"""Request settlement preserves the ordinary service; no process/isolation claim."""

from __future__ import annotations

import base64
import threading
import time
from dataclasses import replace

import pytest

from bluefire.ai_broker_channel import (
    FramedSocket,
    SocketBrokerChannel,
    cancel_frame,
    response_binding,
)
from bluefire.ai_probe import _SCHEMA
from bluefire.ai_wire import AIProviderCancelled, AIProviderTransportError, structured_request
from bluefire.prepared_lab_enrollment import product_config
from bluefire.runner_lifecycle import ManagedRunnerLifecycle
from bluefire.service import BlueFireService
from bluefire.util import canonical_json_bytes
from tests_platform import test_ai_broker_channel as support

pair = support.pair


def body(provider):
    return canonical_json_bytes(
        structured_request(
            provider,
            instructions="Check",
            input_text="{}",
            name="bluefire_connection_check",
            schema=_SCHEMA,
        )
    )


def test_active_provider_timeout_settles_without_stopping_broker_or_product_service(tmp_path, pair):
    provider, enrollment, access, transport, worker, errors = support.start(pair)
    service = BlueFireService(
        config=product_config(enrollment),
        runs_dir=tmp_path / "runs",
        runner_lifecycle=ManagedRunnerLifecycle(tmp_path / "managed"),
        ai_provider_access=access,
    )
    transport.block = True
    try:
        with pytest.raises(AIProviderTransportError) as caught:
            access.post(provider, body=body(provider), timeout_seconds=0.05)
        assert caught.value.code == "request_timed_out" and caught.value.retryable is True
        assert transport.entered.is_set() and transport.cancellation.is_set()
        assert worker.is_alive() and not access._channel.closed.is_set()
        assert not any(thread.name == "bluefire-broker-request" for thread in threading.enumerate())
        transport.block = False
        checked = service.check_ai_provider({"provider": provider.to_dict(), "connect": True})
        assert checked["code"] == "probe_passed" and len(transport.requests) == 2
        assert worker.is_alive() and errors == []
    finally:
        service.close()
        worker.join(3)
    assert not worker.is_alive() and errors == []


@pytest.mark.parametrize("cancel_during_drain", [False, True])
def test_late_completed_response_is_drained_not_reused_or_returned_as_success(
    pair, cancel_during_drain
):
    channel, server = SocketBrokerChannel(pair[0]), FramedSocket(pair[1])
    request = {
        "kind": "post",
        "session_id": "session",
        "binding_digest": "binding",
        "request_id": "first",
    }
    cancellation, errors = threading.Event(), []

    def peer():
        try:
            original = server.receive(deadline=time.monotonic() + 1)
            # Waiting for the cancel makes the complete-result race deterministic.
            assert server.receive(deadline=time.monotonic() + 1) == cancel_frame(original)
            if cancel_during_drain:
                cancellation.set()
            server.send(
                {
                    "kind": "result",
                    **response_binding(original),
                    "body": base64.b64encode(b'{"late":true}').decode(),
                },
                deadline=time.monotonic() + 1,
            )
            following = server.receive(deadline=time.monotonic() + 1)
            server.send(
                {"kind": "readiness", **response_binding(following), "credential_state": "ready"},
                deadline=time.monotonic() + 1,
            )
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=peer)
    worker.start()
    try:
        with pytest.raises(AIProviderTransportError) as caught:
            channel.exchange(request, cancellation=cancellation, timeout_seconds=0.02)
        if cancel_during_drain:
            assert isinstance(caught.value, AIProviderCancelled)
        else:
            assert caught.value.code == "request_timed_out" and caught.value.retryable is True
        assert not channel.closed.is_set()
        following = {**request, "kind": "readiness", "request_id": "second"}
        result = channel.exchange(following, cancellation=threading.Event(), timeout_seconds=1)
        assert result["request_id"] == "second" and result["kind"] == "readiness"
    finally:
        channel.close()
        worker.join(2)
        server.close()
    assert not worker.is_alive() and errors == []


@pytest.mark.parametrize("fault", ["binding", "kind", "error_type", "invalid_body", "eof"])
@pytest.mark.parametrize("trigger", ["timeout", "cancellation"])
def test_drain_requires_exact_valid_terminal_frame_or_closes(pair, fault, trigger):
    channel, server = SocketBrokerChannel(pair[0]), FramedSocket(pair[1])
    request = {
        "kind": "post",
        "session_id": "session",
        "binding_digest": "binding",
        "request_id": "first",
    }
    errors, cancellation = [], threading.Event()

    def peer():
        try:
            original = server.receive(deadline=time.monotonic() + 1)
            if trigger == "cancellation":
                cancellation.set()
            assert server.receive(deadline=time.monotonic() + 1) == cancel_frame(original)
            response = {
                "kind": "error",
                **response_binding(original),
                "code": "request_cancelled",
                "retryable": False,
            }
            if fault == "binding":
                response["request_id"] = "other"
            elif fault == "kind":
                response["kind"] = "unexpected"
            elif fault == "error_type":
                response["code"] = []
            elif fault == "invalid_body":
                response = {"kind": "result", **response_binding(original), "body": "not base64"}
            if fault != "eof":
                server.send(response, deadline=time.monotonic() + 1)
        except BaseException as exc:
            errors.append(exc)
        finally:
            server.close()

    worker = threading.Thread(target=peer)
    worker.start()
    try:
        with pytest.raises(AIProviderTransportError) as caught:
            channel.exchange(request, cancellation=cancellation, timeout_seconds=0.02)
        if trigger == "cancellation":
            assert isinstance(caught.value, AIProviderCancelled)
        else:
            assert caught.value.code == "broker_unavailable" and caught.value.retryable is False
        assert channel.closed.is_set()
    finally:
        channel.close()
        worker.join(2)
    assert not worker.is_alive() and errors == []


def test_timeout_during_partial_send_closes_instead_of_reusing_ambiguous_boundary(
    pair, monkeypatch
):
    channel = SocketBrokerChannel(pair[0])
    original = pair[0].send
    written = []

    def send(value):
        if written:
            raise BlockingIOError
        written.append(True)
        return original(value)

    monkeypatch.setattr(pair[0], "send", send)
    with pytest.raises(AIProviderTransportError) as caught:
        channel.exchange(
            {"payload": "x" * 4096}, cancellation=threading.Event(), timeout_seconds=0.02
        )
    assert written and channel.closed.is_set() and caught.value.retryable is False


def test_queue_deadline_does_not_close_another_exchange(pair):
    channel = SocketBrokerChannel(pair[0])
    channel.guard.acquire()
    try:
        with pytest.raises(AIProviderTransportError) as caught:
            channel.exchange({}, cancellation=threading.Event(), timeout_seconds=0.02)
        assert caught.value.code == "request_timed_out" and caught.value.retryable is True
        assert not channel.closed.is_set() and not pair[1].data
    finally:
        channel.guard.release()
        channel.close()


def test_enrollment_expiry_during_timeout_drain_still_stops_broker(pair, monkeypatch):
    provider, enrollment, access, transport, worker, errors = support.start(pair)
    transport.block = True
    expired = threading.Event()
    original = type(enrollment).require_current

    def require_current(value, config):
        return original(replace(value, expires_at_ms=1) if expired.is_set() else value, config)

    monkeypatch.setattr(type(enrollment), "require_current", require_current)
    send = access._channel.stream.send

    def expire_on_cancel(value, **kwargs):
        if value.get("kind") == "cancel":
            expired.set()
        return send(value, **kwargs)

    monkeypatch.setattr(access._channel.stream, "send", expire_on_cancel)
    try:
        with pytest.raises(AIProviderTransportError) as caught:
            access.post(provider, body=body(provider), timeout_seconds=0.05)
        assert caught.value.retryable is False and access._channel.closed.is_set()
        worker.join(2)
        assert transport.entered.is_set() and transport.cancellation.is_set()
        assert not worker.is_alive() and len(errors) == 1
        assert errors[0].code == "broker_session_expired"
    finally:
        access.close()
        worker.join(3)
