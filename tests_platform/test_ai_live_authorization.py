"""Authored deterministic wire responses; no provider, credential, browser or native calls."""

from __future__ import annotations

import threading
from copy import deepcopy
from dataclasses import replace

import pytest

from bluefire.ai_authorized_access import AuthorizedAIProviderAccess
from bluefire.ai_broker_contract import BrokerEnrollment
from bluefire.ai_broker_live_authorization import BrokerLiveAuthorizations
from bluefire.ai_live_authorization import (
    create_authorization,
    now_ms,
    request_reservation,
    validate_authorization,
)
from bluefire.ai_probe import _SCHEMA
from bluefire.ai_provider_access import ProviderReadiness
from bluefire.ai_wire import AIProviderCancelled, AIProviderTransportError, structured_request
from bluefire.config import AIProviderKind
from bluefire.product_store import ProductStore
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_ai_wire_runtime import _provider_config


class FakeAccess:
    def __init__(self):
        self.calls = []
        self.response = b'{"authored":true}'
        self.callback = None

    def readiness(self, config):
        return ProviderReadiness(True, "ready", "configuration_ready", "Authored readiness")

    def post(self, config, **kwargs):
        if kwargs["cancel_event"].is_set():
            raise AIProviderCancelled()
        self.calls.append((config, kwargs))
        if self.callback:
            return self.callback(**kwargs)
        return self.response

    def close(self):
        pass


def request(config, **changes):
    value = {
        "provider": config.to_dict(),
        "purposes": ["bluefire_connection_check"],
        "data_scope": "reviewed_lab_context",
        "limits": {
            "max_requests": 2,
            "max_request_bytes": 100_000,
            "max_reserved_output_tokens": 1024,
        },
        "expires_in_seconds": 300,
        "approved_by": "authored-test-operator",
        "usage_authorized": True,
        "local_endpoint_authorized": False,
    }
    return {**value, **changes}


def wire(config):
    return canonical_json_bytes(
        structured_request(
            replace(config, max_output_tokens=256),
            instructions='Return exactly {"ok":true} using the supplied schema.',
            input_text="Synthetic connection test. No scenario or evidence is supplied.",
            name="bluefire_connection_check",
            schema=_SCHEMA,
        )
    )


@pytest.fixture
def configured(tmp_path):
    config = _provider_config(AIProviderKind.OPENAI_RESPONSES, authenticated=True)
    access = FakeAccess()
    store = ProductStore(tmp_path / "product.db")
    return config, access, store, AuthorizedAIProviderAccess(access, store)


def test_no_grant_never_dispatches_and_configuration_activation_is_not_consent(configured):
    config, transport, store, access = configured
    assert not access.readiness(config).available
    with pytest.raises(AIProviderTransportError, match="authorization"):
        access.post(config, body=wire(config), timeout_seconds=1)
    assert transport.calls == []
    assert access.list()["authorizations"] == []


def test_each_attempt_reserves_full_cost_and_exhaustion_never_calls(configured):
    config, transport, store, access = configured
    record = access.authorize(request(config))["authorization"]
    body = wire(config)
    for _ in range(2):
        assert access.post(config, body=body, timeout_seconds=1) == transport.response
    with pytest.raises(AIProviderTransportError) as error:
        access.post(config, body=body, timeout_seconds=1)
    assert error.value.code == "live_usage_exhausted"
    assert len(transport.calls) == 2
    history = access.list()["authorizations"][0]
    assert history["usage"] == {
        "requests": 2,
        "request_bytes": 2 * len(body),
        "reserved_output_tokens": 512,
    }
    assert history["authorization_digest"] == record["authorization_digest"]


def test_failed_and_cancelled_attempts_do_not_refund_and_revoke_interrupts(configured):
    config, transport, store, access = configured
    record = access.authorize(request(config))["authorization"]

    def failure(**kwargs):
        raise AIProviderTransportError("Authored transport failure", retryable=True)

    transport.callback = failure
    with pytest.raises(AIProviderTransportError):
        access.post(config, body=wire(config), timeout_seconds=1)

    def cancellation(**kwargs):
        access.revoke(record["authorization_id"])
        assert kwargs["cancel_event"].is_set()
        return b"{}"

    transport.callback = cancellation
    with pytest.raises(AIProviderCancelled):
        access.post(config, body=wire(config), timeout_seconds=1)
    history = access.list()["authorizations"][0]
    assert history["usage"]["requests"] == 2 and history["status"] == "revoked"
    with pytest.raises(AIProviderTransportError):
        access.post(config, body=wire(config), timeout_seconds=1)
    assert len(transport.calls) == 2


def test_cancellation_before_reservation_does_not_dispatch(configured):
    config, transport, store, access = configured
    access.authorize(request(config))
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(AIProviderCancelled):
        access.post(config, body=wire(config), timeout_seconds=1, cancel_event=cancel)
    assert access.list()["authorizations"][0]["usage"]["requests"] == 0
    assert transport.calls == []


def test_restart_preserves_history_without_resuming_authority(configured):
    config, transport, store, access = configured
    access.authorize(request(config))
    access.post(config, body=wire(config), timeout_seconds=1)
    restarted = AuthorizedAIProviderAccess(FakeAccess(), ProductStore(store.path))
    history = restarted.list()["authorizations"][0]
    assert history["status"] == "context_unavailable" and history["usage"]["requests"] == 1
    assert not restarted.readiness(config).available


@pytest.mark.parametrize(
    "field,value",
    [
        ("usage_authorized", False),
        ("data_scope", "raw_logs"),
        ("local_endpoint_authorized", True),
        ("expires_in_seconds", 901),
        ("approved_by", ""),
    ],
)
def test_invalid_grant_is_refused_before_persistence(configured, field, value):
    config, transport, store, access = configured
    with pytest.raises(AIProviderTransportError):
        access.authorize(request(config, **{field: value}))
    assert access.list()["authorizations"] == []


@pytest.mark.parametrize(
    "change",
    ["endpoint", "model", "key_reference", "data_policy", "purpose", "schema", "probe_data"],
)
def test_config_and_actual_body_cannot_widen_grant(configured, change):
    config, transport, store, access = configured
    access.authorize(request(config))
    body = wire(config)
    if change == "endpoint":
        config = replace(config, endpoint="http://127.0.0.1:9999/other")
    elif change == "model":
        config = replace(config, model="other-model")
    elif change == "key_reference":
        config = replace(config, api_key=replace(config.api_key, env="OTHER_EXPLICIT_REFERENCE"))
    elif change == "data_policy":
        config = replace(config, redaction=replace(config.redaction, include_evidence_content=True))
    elif change == "purpose":
        body = body.replace(b"bluefire_connection_check", b"bluefire_method_comparison")
    elif change == "schema":
        body = body.replace(b'"additionalProperties":false', b'"additionalProperties":true')
    else:
        body = body.replace(
            b"Synthetic connection test. No scenario or evidence is supplied.",
            b"Unreviewed context",
        )
    with pytest.raises(AIProviderTransportError):
        access.post(config, body=body, timeout_seconds=1)
    assert transport.calls == []


def test_broker_grant_narrows_existing_enrollment_and_replay_does_not_reset():
    config = _provider_config(AIProviderKind.OPENAI_RESPONSES, authenticated=True)
    enrollment = BrokerEnrollment.create(
        config,
        session_id="a" * 64,
        expires_at_ms=now_ms() + 300_000,
        schemas=(("bluefire_connection_check", content_hash(_SCHEMA)),),
        destination_policy="explicit_endpoint",
    )
    context = {
        "kind": "broker",
        "binding_digest": enrollment.digest,
        "provider": config.to_dict(),
        "expires_at_ms": enrollment.expires_at_ms,
    }
    grant = create_authorization(request(config), context)
    broker = BrokerLiveAuthorizations(enrollment)
    with pytest.raises(AIProviderTransportError):
        broker.reserve(wire(config))
    broker.authorize(grant)
    broker.reserve(wire(config))
    broker.authorize(deepcopy(grant))
    broker.reserve(wire(config))
    with pytest.raises(AIProviderTransportError) as error:
        broker.reserve(wire(config))
    assert error.value.code == "live_usage_exhausted"
    broker.revoke(grant["authorization_id"])
    with pytest.raises(AIProviderTransportError):
        broker.authorize(grant)
    other = create_authorization(
        request(replace(config, model="different")),
        {**context, "provider": replace(config, model="different").to_dict()},
    )
    with pytest.raises(AIProviderTransportError):
        broker.authorize(other)


def test_authorization_expiry_and_digest_tamper_fail_closed(configured, monkeypatch):
    config, transport, store, access = configured
    record = access.authorize(request(config))["authorization"]
    grant = {k: v for k, v in record.items() if k not in {"status", "usage"}}
    changed = deepcopy(grant)
    changed["limits"]["max_requests"] += 1
    with pytest.raises(AIProviderTransportError):
        validate_authorization(changed)
    monkeypatch.setattr("bluefire.ai_live_authorization.now_ms", lambda: grant["expires_at_ms"])
    with pytest.raises(AIProviderTransportError):
        request_reservation(config, wire(config), grant)
    assert transport.calls == []


@pytest.mark.parametrize("timeout", [True, 0, -1, float("inf"), float("nan"), 901])
def test_invalid_attempt_timeout_never_reserves_or_dispatches(configured, timeout):
    config, transport, store, access = configured
    access.authorize(request(config))
    with pytest.raises(AIProviderTransportError):
        access.post(config, body=wire(config), timeout_seconds=timeout)
    assert transport.calls == []
    assert access.list()["authorizations"][0]["usage"]["requests"] == 0


@pytest.mark.parametrize(
    "projection",
    [
        {"stdout": "private raw log"},
        {"password": "private value"},
        {"api_key": {"env": "NOT_DATA"}},
        {"evidence_content": "raw evidence"},
    ],
)
def test_registered_purpose_does_not_allow_raw_evidence_or_credential_fields(
    configured, projection
):
    from bluefire.ai import PROPOSAL_JSON_SCHEMA

    config, transport, store, access = configured
    access.authorize(request(config, purposes=["bluefire_ai_proposal"]))
    body = canonical_json_bytes(
        structured_request(
            config,
            instructions="Review bounded observations.",
            input_text=canonical_json_bytes(projection).decode(),
            name="bluefire_ai_proposal",
            schema=PROPOSAL_JSON_SCHEMA,
        )
    )
    with pytest.raises(AIProviderTransportError) as error:
        access.post(config, body=body, timeout_seconds=1)
    assert error.value.code == "live_request_out_of_scope"
    assert transport.calls == []


def test_revocation_interrupts_an_inflight_attempt_from_another_thread(configured):
    config, transport, store, access = configured
    record = access.authorize(request(config))["authorization"]
    entered, errors = threading.Event(), []

    def held(**kwargs):
        entered.set()
        assert kwargs["cancel_event"].wait(3)
        return b"{}"

    transport.callback = held

    def post():
        try:
            access.post(config, body=wire(config), timeout_seconds=3)
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=post)
    thread.start()
    try:
        assert entered.wait(3)
        access.revoke(record["authorization_id"])
    finally:
        thread.join(timeout=3)
        access.close()
    assert not thread.is_alive() and len(errors) == 1 and isinstance(errors[0], AIProviderCancelled)
    assert access.list()["authorizations"][0]["usage"]["requests"] == 1


@pytest.mark.parametrize("reason", ["purpose", "attempts", "bytes", "tokens"])
def test_connection_check_refusal_does_not_claim_a_wire_attempt(configured, reason):
    from bluefire.ai_probe import check_provider

    config, transport, store, access = configured
    review = request(config)
    if reason == "purpose":
        review["purposes"] = ["bluefire_ai_proposal"]
    if reason == "attempts":
        review["limits"]["max_requests"] = 1
    if reason == "bytes":
        review["limits"]["max_request_bytes"] = 1
    if reason == "tokens":
        review["limits"]["max_reserved_output_tokens"] = 64
    access.authorize(review)
    if reason == "attempts":
        access.post(config, body=wire(config), timeout_seconds=1)
    before = len(transport.calls)
    result = check_provider(config, connect=True, access=access)
    assert result["attempts"] == 0 and result["connectivity"] == "not_tested"
    assert result["structured_output"] == "not_tested"
    assert result["code"] in {"live_usage_exhausted", "live_request_out_of_scope"}
    assert len(transport.calls) == before
