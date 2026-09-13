"""Real service/parsers and framed broker over memory-only socket substitutes."""

from __future__ import annotations

import base64
import json
import struct
import threading
import time
from dataclasses import replace

import pytest

from bluefire import ai_broker_channel as channel_module
from bluefire.ai_broker import BrokeredAIProviderAccess
from bluefire.ai_broker_channel import FramedSocket, SocketBrokerChannel
from bluefire.ai_broker_contract import body_digest, schema_identity
from bluefire.ai_broker_worker import serve_broker
from bluefire.ai_probe import _SCHEMA
from bluefire.ai_transport import ManagedAIJSONTransport
from bluefire.ai_wire import AIProviderCancelled, AIProviderTransportError, structured_request
from bluefire.config import AIProviderKind
from bluefire.prepared_lab_enrollment import enroll, product_config
from bluefire.runner_lifecycle import ManagedRunnerLifecycle
from bluefire.service import BlueFireService
from bluefire.util import canonical_json_bytes
from tests_platform.ai_live_authorization_support import authorize_broker, authorize_service
from tests_platform.test_ai_drafts import _model_draft
from tests_platform.test_ai_integration import _request as run_request
from tests_platform.test_ai_wire_runtime import _envelope, _provider_config


class MemorySocket:
    def __init__(self):
        self.data = bytearray()
        self.closed = False
        self.inheritable = True
        self.guard = threading.Lock()
        self.peer = None

    def setblocking(self, _value):
        pass

    def set_inheritable(self, value):
        self.inheritable = value

    def send(self, value):
        if self.closed or self.peer.closed:
            raise OSError("closed")
        with self.peer.guard:
            # Force partial frames, including split length headers.
            size = min(len(value), 137)
            self.peer.data.extend(value[:size])
            return size

    def recv(self, size):
        with self.guard:
            if not self.data:
                if self.peer.closed:
                    return b""
                raise BlockingIOError
            result = bytes(self.data[: min(size, 83)])
            del self.data[: len(result)]
            return result

    def shutdown(self, _how):
        self.close()

    def close(self):
        self.closed = True


@pytest.fixture
def pair(monkeypatch):
    left, right = MemorySocket(), MemorySocket()
    left.peer, right.peer = right, left

    def ready(read, write, _error, timeout):
        selected = [item for item in read if item.data or item.peer.closed or item.closed]
        if not selected and not write:
            threading.Event().wait(min(timeout, 0.001))
        return selected, write, []

    monkeypatch.setattr(channel_module.select, "select", ready)
    monkeypatch.setattr(
        "bluefire.ai_transport.subprocess.Popen",
        lambda *_a, **_k: pytest.fail("no process effects"),
    )
    return left, right


class DeterministicTransport(ManagedAIJSONTransport):
    def __init__(self, config):
        super().__init__(enrolled_endpoint=config.endpoint, destination_policy="explicit_endpoint")
        self.config = config
        self.requests = []
        self.entered = threading.Event()
        self.block = False
        self.cancellation = None

    def bind(self, cancellation):
        self.cancellation = cancellation
        return self

    def post(self, url, *, headers, body, timeout_seconds):
        assert url == self.config.endpoint
        assert headers.get("Authorization") == "Bearer synthetic-broker-only"
        self.requests.append(json.loads(body))
        self.entered.set()
        if self.block:
            assert self.cancellation.wait(2)
            raise AIProviderCancelled()
        purpose, _ = schema_identity(body, self.config.kind)
        output = {"ok": True} if purpose == "bluefire_connection_check" else _model_draft()
        if purpose == "bluefire_ai_proposal":
            output = {
                "schema_version": "bluefire.ai-proposal.v2",
                "proposal_type": "no_change",
                "selected_step_id": None,
                "selected_behavior_id": None,
                "selected_action_id": None,
                "selected_edge": None,
                "parameter_changes": [],
                "rationale": "Keep this graph.",
                "alternatives": [],
                "confidence": 0.8,
                "requires_operator_review": True,
            }
        return canonical_json_bytes(_envelope(self.config.kind, output))


def start(pair, kind=AIProviderKind.CHAT_COMPLETIONS):
    provider = replace(_provider_config(kind, authenticated=True), max_retries=0)
    enrollment = enroll(provider, "public_https")
    transport = DeterministicTransport(provider)
    errors = []

    def serve():
        try:
            serve_broker(
                FramedSocket(pair[1]),
                enrollment,
                "synthetic-broker-only",
                transport=transport,
                stop=threading.Event(),
            )
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=serve)
    worker.start()
    access = BrokeredAIProviderAccess(enrollment, SocketBrokerChannel(pair[0]))
    authorize_broker(access, provider)
    return provider, enrollment, access, transport, worker, errors


@pytest.mark.parametrize("kind", [AIProviderKind.CHAT_COMPLETIONS, AIProviderKind.OPENAI_RESPONSES])
def test_setup_graph_and_simulated_proposal_use_actual_broker_frames_and_normal_parsers(
    tmp_path, pair, kind
):
    provider, enrollment, access, transport, worker, errors = start(pair, kind)
    service = BlueFireService(
        config=product_config(enrollment),
        runs_dir=tmp_path / "runs",
        runner_lifecycle=ManagedRunnerLifecycle(tmp_path / "managed"),
        ai_provider_access=access,
    )
    authorize_service(service, provider)
    try:
        checked = service.check_ai_provider({"provider": provider.to_dict(), "connect": True})
        assert checked["code"] == "probe_passed" and checked["credential_owner"] == "broker"
        draft = service.draft_ai_graph(
            {
                "objective": "A bounded collection experiment",
                "provider_id": provider.id,
                "max_nodes": 8,
                "max_edges": 16,
            }
        )
        assert (
            draft["saved"] is False and draft["audit"]["validation"]["execution_authority_absent"]
        )
        result = service.run(run_request("assist", provider.id))
        assert result["status"] == "completed" and result["mode"] == "simulate"
        assert result["ai_proposals"] and all(
            not row["provider"]["used_fallback"] for row in result["ai_proposals"]
        )
        assert len(transport.requests) >= 3
        assert "synthetic-broker-only" not in json.dumps((checked, draft, result))
        assert not pair[0].inheritable and not pair[1].inheritable
    finally:
        service.close()
        worker.join(3)
    assert not worker.is_alive() and errors == []


def test_cancel_drains_exact_response_then_allows_next_request(pair):
    provider, _enrollment, access, transport, worker, errors = start(pair)
    transport.block = True
    cancel = threading.Event()
    outcomes = []
    body = canonical_json_bytes(
        structured_request(
            provider,
            instructions="Check",
            input_text="Synthetic connection test. No scenario or evidence is supplied.",
            name="bluefire_connection_check",
            schema=_SCHEMA,
        )
    )

    def request():
        try:
            access.post(provider, body=body, timeout_seconds=2, cancel_event=cancel)
        except BaseException as error:
            outcomes.append(error)

    request_thread = threading.Thread(target=request)
    try:
        request_thread.start()
        assert transport.entered.wait(2)
        cancel.set()
        request_thread.join(3)
        assert (
            not request_thread.is_alive()
            and len(outcomes) == 1
            and isinstance(outcomes[0], AIProviderCancelled)
        )
        transport.block = False
        assert access.readiness(provider).available
        assert access.post(provider, body=body, timeout_seconds=2)
    finally:
        cancel.set()
        access.close()
        request_thread.join(3)
        worker.join(3)
    assert not worker.is_alive() and errors == []


@pytest.mark.parametrize("encoded", [b'{"x":1,"x":2}', b'{"x":NaN}', b"[]", b"\xff"])
def test_invalid_frames_are_refused_without_importing_payload(pair, encoded):
    pair[0].data.extend(struct.pack("!I", len(encoded)) + encoded)
    with pytest.raises(AIProviderTransportError):
        FramedSocket(pair[0]).receive(deadline=time.monotonic() + 1)


def test_eof_and_oversized_length_fail_without_waiting_for_body(pair):
    pair[1].close()
    with pytest.raises(EOFError):
        FramedSocket(pair[0]).receive(deadline=time.monotonic() + 1)
    pair[0].data.extend(struct.pack("!I", channel_module.FRAME_LIMIT + 1))
    with pytest.raises(AIProviderTransportError):
        FramedSocket(pair[0]).receive(deadline=time.monotonic() + 1)


def test_cancel_during_partial_write_closes_ambiguous_channel_before_next_request(
    pair, monkeypatch
):
    cancel = threading.Event()
    written = threading.Event()
    channel = SocketBrokerChannel(pair[0])
    original = pair[0].send

    def send(value):
        if written.is_set():
            raise BlockingIOError
        count = original(value)
        written.set()
        return count

    monkeypatch.setattr(pair[0], "send", send)
    errors = []

    def exchange():
        try:
            channel.exchange({"payload": "x" * 4096}, cancellation=cancel, timeout_seconds=90)
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=exchange)
    try:
        thread.start()
        assert written.wait(1)
        cancel.set()
        thread.join(1)
        assert (
            not thread.is_alive()
            and len(errors) == 1
            and isinstance(errors[0], AIProviderCancelled)
        )
        assert channel.closed.is_set() and pair[0].closed
        with pytest.raises(AIProviderCancelled):
            channel.exchange({}, cancellation=threading.Event(), timeout_seconds=1)
    finally:
        cancel.set()
        channel.close()
        thread.join(1)


def test_completed_readiness_request_id_cannot_be_reused_for_post(pair):
    provider, enrollment, access, transport, worker, errors = start(pair)
    stream = access._channel.stream
    frame = {
        "kind": "readiness",
        "session_id": enrollment.session_id,
        "binding_digest": enrollment.digest,
        "request_id": "b" * 64,
        "timeout_seconds": 1,
    }
    try:
        stream.send(frame, deadline=time.monotonic() + 1)
        assert stream.receive(deadline=time.monotonic() + 1)["kind"] == "readiness"
        body = canonical_json_bytes(
            structured_request(
                provider,
                instructions="Check",
                input_text="Synthetic connection test. No scenario or evidence is supplied.",
                name="bluefire_connection_check",
                schema=_SCHEMA,
            )
        )
        stream.send(
            {
                **frame,
                "kind": "post",
                "body": base64.b64encode(body).decode(),
                "body_digest": body_digest(body),
            },
            deadline=time.monotonic() + 1,
        )
        with pytest.raises(EOFError):
            stream.receive(deadline=time.monotonic() + 1)
        worker.join(2)
        assert (
            not worker.is_alive()
            and len(errors) == 1
            and isinstance(errors[0], AIProviderTransportError)
        )
        assert transport.requests == []
    finally:
        access.close()
        worker.join(2)


def test_active_request_eof_cancels_transport_and_joins_exact_request_thread(pair):
    provider, _enrollment, access, transport, worker, errors = start(pair)
    transport.block = True
    outcomes = []
    body = canonical_json_bytes(
        structured_request(
            provider,
            instructions="Check",
            input_text="Synthetic connection test. No scenario or evidence is supplied.",
            name="bluefire_connection_check",
            schema=_SCHEMA,
        )
    )

    def request():
        try:
            access.post(provider, body=body, timeout_seconds=90)
        except BaseException as error:
            outcomes.append(error)

    pending = threading.Thread(target=request)
    try:
        pending.start()
        assert transport.entered.wait(2)
        access.close()
        pending.join(2)
        worker.join(2)
        assert not pending.is_alive() and not worker.is_alive()
        assert transport.cancellation.is_set() and errors == []
        assert len(outcomes) == 1 and isinstance(outcomes[0], AIProviderCancelled)
        assert not any(thread.name == "bluefire-broker-request" for thread in threading.enumerate())
    finally:
        access.close()
        pending.join(2)
        worker.join(2)
