"""No-process contract refusals for future private inference channels."""

from __future__ import annotations

import base64
from dataclasses import replace

import pytest

from bluefire.ai import PROPOSAL_JSON_SCHEMA
from bluefire.ai_broker import BrokeredAIProviderAccess
from bluefire.ai_broker_contract import BrokerEnrollment, body_digest, validate_broker_request
from bluefire.ai_wire import AIProviderTransportError, structured_request
from bluefire.config import AIProviderKind
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_ai_broker_service import DeterministicBroker
from tests_platform.test_ai_wire_runtime import _provider_config


def enrolled(monkeypatch):
    monkeypatch.setattr("bluefire.ai_broker_contract.time.time_ns", lambda: 1_000_000_000)
    config = _provider_config(AIProviderKind.OPENAI_RESPONSES, authenticated=True)
    binding = BrokerEnrollment.create(
        config,
        session_id="a" * 64,
        expires_at_ms=61_000,
        schemas=(("bluefire_ai_proposal", content_hash(PROPOSAL_JSON_SCHEMA)),),
    )
    return config, binding


def request(config, binding):
    body = canonical_json_bytes(
        structured_request(
            config,
            instructions="Bounded test",
            input_text="{}",
            name="bluefire_ai_proposal",
            schema=PROPOSAL_JSON_SCHEMA,
        )
    )
    return {
        "kind": "post",
        "session_id": binding.session_id,
        "binding_digest": binding.digest,
        "request_id": "b" * 64,
        "timeout_seconds": 1.0,
        "body": base64.b64encode(body).decode(),
        "body_digest": body_digest(body),
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("session_id", "c" * 64),
        ("binding_digest", "sha256:" + "d" * 64),
        ("request_id", "short"),
        ("timeout_seconds", True),
        ("timeout_seconds", 91),
        ("body_digest", "sha256:" + "0" * 64),
        ("Authorization", "synthetic-value"),
    ],
)
def test_request_cannot_change_enrollment_or_limits(monkeypatch, field, value):
    config, binding = enrolled(monkeypatch)
    frame = request(config, binding)
    assert validate_broker_request(binding, frame)
    frame[field] = value
    with pytest.raises(AIProviderTransportError):
        validate_broker_request(binding, frame)


def test_exact_body_bytes_are_bound_and_duplicate_json_fields_are_refused(monkeypatch):
    config, binding = enrolled(monkeypatch)
    frame = request(config, binding)
    body = base64.b64decode(frame["body"])
    frame["body"] = base64.b64encode(body + b" ").decode()
    with pytest.raises(AIProviderTransportError):
        validate_broker_request(binding, frame)
    frame["body_digest"] = body_digest(body + b" ")
    assert validate_broker_request(binding, frame) == body + b" "
    duplicated = b'{"model":"ignored",' + body[1:]
    frame.update(body=base64.b64encode(duplicated).decode(), body_digest=body_digest(duplicated))
    with pytest.raises(AIProviderTransportError):
        validate_broker_request(binding, frame)


@pytest.mark.parametrize("after_response", [False, True])
def test_expired_enrollment_never_refreshes_or_delivers_success(monkeypatch, after_response):
    config, binding = enrolled(monkeypatch)
    channel = DeterministicBroker(binding)
    access = BrokeredAIProviderAccess(binding, channel)
    original = channel.exchange

    def exchange(*args, **kwargs):
        result = original(*args, **kwargs)
        monkeypatch.setattr("bluefire.ai_broker_contract.time.time_ns", lambda: 61_000_000_000)
        return result

    if after_response:
        channel.exchange = exchange
    else:
        monkeypatch.setattr("bluefire.ai_broker_contract.time.time_ns", lambda: 61_000_000_000)
    result = access.readiness(config)
    assert not result.available and result.code == "broker_session_expired"
    assert len(channel.requests) == int(after_response)
    assert access.enrollment is binding
    access.close()


@pytest.mark.parametrize(
    "failure", ["malformed_state", "exception", "transport_error", "unbound_response"]
)
def test_channel_diagnostics_are_sanitized_and_not_credential_readiness(monkeypatch, failure):
    config, binding = enrolled(monkeypatch)

    class Channel:
        def exchange(self, frame, **kwargs):
            if failure == "exception":
                raise RuntimeError("private broker diagnostic must not escape")
            if failure == "transport_error":
                raise AIProviderTransportError(
                    "private broker diagnostic must not escape",
                    retryable=False,
                    code="private-code",
                )
            result = DeterministicBroker(binding).exchange(frame, **kwargs)
            if failure == "malformed_state":
                result["credential_state"] = {"private": "invalid"}
            else:
                result["session_id"] = "f" * 64
            return result

        def close(self):
            pass

    access = BrokeredAIProviderAccess(binding, Channel())
    result = access.readiness(config)
    assert not result.available and result.code == "broker_unavailable"
    assert "private" not in result.message
    access.close()


def test_late_response_cannot_extend_request_deadline(monkeypatch):
    config, binding = enrolled(monkeypatch)
    channel = DeterministicBroker(binding)
    access = BrokeredAIProviderAccess(binding, channel)
    original = channel.exchange
    monkeypatch.setattr("bluefire.ai_broker.time.monotonic", lambda: 100.0)

    def exchange(*args, **kwargs):
        result = original(*args, **kwargs)
        monkeypatch.setattr("bluefire.ai_broker.time.monotonic", lambda: 102.0)
        return result

    channel.exchange = exchange
    result = access.readiness(config)
    assert not result.available and result.code == "request_timed_out"
    access.close()


@pytest.mark.parametrize(
    "field,value",
    [
        ("destination_policy", {}),
        ("expires_at_ms", True),
        ("schemas", [["bluefire_ai_proposal", "sha256:" + "f" * 64]]),
    ],
)
def test_malformed_enrollment_fails_closed(monkeypatch, field, value):
    _config, binding = enrolled(monkeypatch)
    with pytest.raises(AIProviderTransportError):
        replace(binding, **{field: value})
