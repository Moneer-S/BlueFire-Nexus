"""Shipped provider deadlines tested with a local fake transport and clock."""

from dataclasses import replace

import pytest

from bluefire.ai import AIProviderError, AIProviderTransportError, build_ai_provider
from bluefire.config import AutonomyLevel, load_config
from bluefire.product_store_contracts import safe_document
from bluefire.product_store_errors import ProductStoreError
from bluefire.util import content_hash
from tests_platform.test_ai import CONFIG_PATH, FakeTransport, _proposal, _request, _response


def test_provider_http_timeout_uses_remaining_experiment_budget(monkeypatch):
    monkeypatch.setattr("bluefire.ai.time.monotonic", lambda: 100.0)
    transport = FakeTransport(_response(_proposal()))
    provider = build_ai_provider(
        load_config(CONFIG_PATH).ai,
        provider_id="openai-responses.v1",
        environ={"OPENAI_API_KEY": "unit-test-key-value"},  # pragma: allowlist secret
        transport=transport,
    )
    provider.propose(replace(_request(AutonomyLevel.ASSIST), deadline_monotonic=100.5))
    assert transport.calls[0]["timeout_seconds"] == 0.5
    assert "deadline_monotonic" not in transport.calls[0]["body"].decode()


def test_expired_provider_deadline_never_calls_transport_or_fallback(monkeypatch):
    monkeypatch.setattr("bluefire.ai.time.monotonic", lambda: 100.0)
    transport = FakeTransport(_response(_proposal()))
    provider = build_ai_provider(
        load_config(CONFIG_PATH).ai,
        provider_id="openai-responses.v1",
        environ={"OPENAI_API_KEY": "unit-test-key-value"},  # pragma: allowlist secret
        transport=transport,
    )
    with pytest.raises(AIProviderError, match="deadline expired"):
        provider.propose(replace(_request(AutonomyLevel.ASSIST), deadline_monotonic=99.0))
    assert transport.calls == []


def test_provider_retries_share_one_deadline_and_stop_before_new_request(monkeypatch):
    now = [100.0]
    monkeypatch.setattr("bluefire.ai.time.monotonic", lambda: now[0])

    def sleep(seconds):
        now[0] += seconds

    transport = FakeTransport(
        AIProviderTransportError("temporary", retryable=True), _response(_proposal())
    )
    provider = build_ai_provider(
        load_config(CONFIG_PATH).ai,
        provider_id="openai-responses.v1",
        environ={"OPENAI_API_KEY": "unit-test-key-value"},  # pragma: allowlist secret
        transport=transport,
        sleeper=sleep,
    )
    with pytest.raises(AIProviderError, match="deadline expired"):
        provider.propose(replace(_request(AutonomyLevel.ASSIST), deadline_monotonic=100.1))
    assert len(transport.calls) == 1


def test_public_authorization_hash_is_persistable_but_plaintext_and_nested_credentials_are_refused():
    digest = content_hash("reviewed public body")
    assert safe_document({"authorization_digest": digest}) == {"authorization_digest": digest}
    with pytest.raises(ProductStoreError):
        safe_document({"authorization_digest": "plain-text-value"})
    body = {
        "schema_version": "bluefire.adaptive-authorization.v1",
        "password": "plain-text-value",  # pragma: allowlist secret
    }
    with pytest.raises(ProductStoreError):
        safe_document(
            {"adaptive_authorization": {**body, "authorization_digest": content_hash(body)}}
        )
