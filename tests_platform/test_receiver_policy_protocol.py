"""Exercise real parsing/HMAC/body validation with memory streams only."""

from __future__ import annotations

import hashlib
import io
import json
import time
from types import SimpleNamespace

import pytest

from bluefire import receiver as receiver_module
from bluefire.receiver import LoopbackArtifactReceiver, ReceiverConfig
from bluefire.receiver_auth import (
    derive_receiver_task_key,
    request_authentication,
    request_document,
)
from bluefire.receiver_policy import (
    REDACTED_ONLY_POLICY,
    REVIEWED_RECORDS_POLICY,
    ReceiverContentPolicy,
)
from tests_platform.test_receiver_policy import public_records

TASK = "execute-" + "a" * 64
KEY = bytes(range(32))


def exchange_body(payload, *, policy_id=REDACTED_ONLY_POLICY, supplied_body=None, bad_auth=False):
    digest = hashlib.sha256(payload).hexdigest()
    server = SimpleNamespace(
        config=ReceiverConfig(
            authentication_key=KEY,
            port=4317,
            disposable_peer=True,
            max_connections=8,
            idle_timeout_seconds=240.0,
            max_body_bytes=1024 * 1024,
            content_policy=policy_id,
        ),
        server_address=("127.0.0.1", 4317),
        session_id="b" * 64,
        receiver_process_id=901,
        policy_task_binding=(TASK, digest, len(payload)),
        policy_decisions=[],
        lifecycle_deadline=time.monotonic() + 120,
        challenges={},
        storage=None,
    )
    result = receiver_module._issue_challenge(
        server,
        {
            "host": "127.0.0.1:4317",
            "x-bluefire-task-id": TASK,
            "x-bluefire-sha256": digest,
            "x-bluefire-content-length": str(len(payload)),
        },
    )
    challenge = json.loads(result.response.split(b"\r\n\r\n", 1)[1])
    request = request_document(
        task_id=TASK,
        session_id=server.session_id,
        nonce=challenge["nonce"],
        host="127.0.0.1",
        port=4317,
        sha256=digest,
        content_length=len(payload),
    )
    auth = request_authentication(derive_receiver_task_key(KEY, TASK), request)
    headers = {
        "host": "127.0.0.1:4317",
        "content-type": "application/octet-stream",
        "content-length": str(len(payload)),
        "x-bluefire-sha256": digest,
        "x-bluefire-task-id": TASK,
        "x-bluefire-session-id": server.session_id,
        "x-bluefire-nonce": challenge["nonce"],
        "x-bluefire-authentication": "sha256:" + "0" * 64 if bad_auth else auth,
    }
    return receiver_module._receive_artifact(
        server, io.BytesIO(payload if supplied_body is None else supplied_body), headers
    )


@pytest.mark.parametrize("redacted", [False, True])
def test_authenticated_same_bytes_are_accepted_or_refused_by_the_actual_target_policy(redacted):
    payload = public_records(redacted=redacted)
    baseline = exchange_body(payload, policy_id=REVIEWED_RECORDS_POLICY)
    revised = exchange_body(payload)
    assert baseline.accepted_artifact is True
    assert revised.accepted_artifact is redacted
    assert revised.policy_decision["authenticated"] is True
    assert revised.policy_decision["decision"] == ("accepted" if redacted else "policy_refused")
    assert revised.policy_decision["bytes_received"] == len(payload)
    assert revised.policy_decision["sha256"] == hashlib.sha256(payload).hexdigest()
    assert revised.policy_decision["task_id"] == TASK
    assert revised.policy_decision["receiver_process_id"] == 901
    assert revised.policy_decision["receiver_session_id"] == "b" * 64
    assert b"telemetry-value" not in revised.response


@pytest.mark.parametrize("failure", ["authentication", "digest", "truncated"])
def test_protocol_failures_never_reach_content_policy_or_create_authenticated_decisions(
    monkeypatch, failure
):
    def forbidden(*_args):
        raise AssertionError("policy inspected bytes before authentication and digest verification")

    monkeypatch.setattr(ReceiverContentPolicy, "inspect", forbidden)
    payload = public_records()
    supplied = (
        payload[:-1]
        if failure == "truncated"
        else (b"x" + payload[1:] if failure == "digest" else None)
    )
    with pytest.raises(receiver_module._ProtocolRefusal):
        exchange_body(payload, supplied_body=supplied, bad_auth=failure == "authentication")


def test_authenticated_malformed_schema_is_invalid_content_not_a_defensive_policy_result():
    result = exchange_body(b"{}\n")
    assert result.accepted_artifact is False
    assert result.policy_decision["decision"] == "invalid_content"
    assert result.policy_decision["semantics"] is None


def test_old_default_opaque_receiver_contract_is_preserved():
    result = exchange_body(b"old opaque bytes", policy_id=None)
    assert result.accepted_artifact is True
    assert result.policy_decision is None


def receiver_without_socket():
    receiver = object.__new__(LoopbackArtifactReceiver)
    receiver._config = ReceiverConfig(
        authentication_key=KEY,
        disposable_peer=True,
        max_connections=8,
        content_policy=REDACTED_ONLY_POLICY,
        max_body_bytes=1024 * 1024,
        idle_timeout_seconds=240,
    )
    receiver._server = SimpleNamespace(
        policy_task_binding=None,
        connections_handled=0,
        lifecycle_deadline=time.monotonic() + 200,
        policy_decisions=[],
    )
    receiver._closed = False
    return receiver


def test_exact_task_binding_is_single_use_and_no_unbound_session_can_serve():
    receiver = receiver_without_socket()
    with pytest.raises(ValueError, match="exact task binding"):
        receiver.serve()
    deadline = time.monotonic() + 60
    receiver.bind_policy_task(TASK, "c" * 64, 100, deadline=deadline)
    for task in (TASK, "execute-" + "d" * 64):
        with pytest.raises(ValueError, match="consumed"):
            receiver.bind_policy_task(task, "c" * 64, 100, deadline=deadline)


@pytest.mark.parametrize("change", ["task", "digest", "size", "expired"])
def test_challenge_refuses_any_task_or_body_binding_change(change):
    server = receiver_without_socket()._server
    server.config = SimpleNamespace(content_policy=REDACTED_ONLY_POLICY)
    server.policy_task_binding = (TASK, "c" * 64, 100)
    if change == "expired":
        server.lifecycle_deadline = time.monotonic() - 1
    with pytest.raises(receiver_module._ProtocolRefusal):
        receiver_module._check_policy_task(
            server,
            "wrong" if change == "task" else TASK,
            "d" * 64 if change == "digest" else "c" * 64,
            101 if change == "size" else 100,
        )
