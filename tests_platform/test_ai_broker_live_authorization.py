"""Owned in-process socket pair and fake wire transport; no endpoint or model is contacted."""

from __future__ import annotations

import socket
import threading

import pytest

from bluefire.ai_authorized_access import AuthorizedAIProviderAccess
from bluefire.ai_broker import BrokeredAIProviderAccess
from bluefire.ai_broker_channel import FramedSocket, SocketBrokerChannel
from bluefire.ai_broker_contract import BrokerEnrollment
from bluefire.ai_broker_worker import serve_broker
from bluefire.ai_live_authorization import now_ms
from bluefire.ai_probe import _SCHEMA
from bluefire.ai_wire import AIProviderTransportError
from bluefire.config import AIProviderKind
from bluefire.product_store import ProductStore
from bluefire.util import content_hash
from tests_platform.test_ai_live_authorization import request, wire
from tests_platform.test_ai_wire_runtime import _provider_config


class FakeWireTransport:
    def __init__(self):
        self.calls = 0

    def post(self, url, *, headers, body, timeout_seconds):
        self.calls += 1
        return b'{"authored":true}'


@pytest.fixture
def broker(tmp_path):
    config = _provider_config(AIProviderKind.OPENAI_RESPONSES, authenticated=True)
    binding = BrokerEnrollment.create(
        config,
        session_id="a" * 64,
        expires_at_ms=now_ms() + 300_000,
        schemas=(("bluefire_connection_check", content_hash(_SCHEMA)),),
    )
    client, server = socket.socketpair()
    transport = FakeWireTransport()
    stop = threading.Event()
    errors = []

    def run():
        try:
            serve_broker(
                FramedSocket(server), binding, "authored-test-value", transport=transport, stop=stop
            )
        except Exception as error:
            errors.append(error)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    raw = BrokeredAIProviderAccess(binding, SocketBrokerChannel(client))
    access = AuthorizedAIProviderAccess(raw, ProductStore(tmp_path / "product.db"))
    try:
        yield config, transport, raw, access
    finally:
        stop.set()
        access.close()
        thread.join(timeout=3)
        assert not thread.is_alive()
        assert errors == []


def test_broker_rejects_ungranted_wire_attempt_then_enforces_replayed_grant_quota(broker):
    config, transport, raw, access = broker
    with pytest.raises(AIProviderTransportError) as error:
        raw.post(config, body=wire(config), timeout_seconds=1)
    assert error.value.code == "live_authorization_required"
    assert transport.calls == 0
    record = access.authorize(request(config))["authorization"]
    grant = {k: v for k, v in record.items() if k not in {"usage", "status"}}
    raw.post(config, body=wire(config), timeout_seconds=1)
    raw.authorize_live(grant)
    raw.post(config, body=wire(config), timeout_seconds=1)
    with pytest.raises(AIProviderTransportError) as error:
        raw.post(config, body=wire(config), timeout_seconds=1)
    assert error.value.code == "live_usage_exhausted"
    assert transport.calls == 2


def test_normal_access_accounts_and_revokes_same_enrolled_broker(broker):
    config, transport, raw, access = broker
    record = access.authorize(request(config))["authorization"]
    assert access.post(config, body=wire(config), timeout_seconds=1) == b'{"authored":true}'
    assert access.list()["authorizations"][0]["usage"]["requests"] == 1
    access.revoke(record["authorization_id"])
    with pytest.raises(AIProviderTransportError) as error:
        raw.post(config, body=wire(config), timeout_seconds=1)
    assert error.value.code == "live_authorization_required"
    assert transport.calls == 1


def test_product_restart_with_same_broker_binding_retains_usage_but_requires_new_decision(broker):
    config, transport, raw, access = broker
    access.authorize(request(config))
    access.post(config, body=wire(config), timeout_seconds=1)
    restarted = AuthorizedAIProviderAccess(raw, access.store)
    history = restarted.list()["authorizations"][0]
    assert history["status"] == "context_unavailable" and history["usage"]["requests"] == 1
    with pytest.raises(AIProviderTransportError):
        restarted.post(config, body=wire(config), timeout_seconds=1)
    assert transport.calls == 1
    restarted.authorize(request(config))
    restarted.post(config, body=wire(config), timeout_seconds=1)
    assert transport.calls == 2
    assert len(restarted.list()["authorizations"]) == 2
