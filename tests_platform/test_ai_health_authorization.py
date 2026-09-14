"""Provider health uses inert credential states and local synthetic consent records."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from bluefire import ai_live_authorization, ai_provider_access, product_store_ai_authorizations
from bluefire.ai import ProviderHealthState, build_ai_provider
from bluefire.ai_authorized_access import AuthorizedAIProviderAccess
from bluefire.ai_drafts import build_ai_draft_provider
from bluefire.ai_provider_access import ProviderReadiness
from bluefire.ai_transport import CancellationSignal
from bluefire.ai_wire import AIProviderTransportError
from bluefire.config import AIProviderConfig, load_config
from bluefire.product_store import ProductStore

ROOT = Path(__file__).resolve().parents[1]


class InertAccess:
    def __init__(self, readiness: ProviderReadiness) -> None:
        self.result = readiness
        self.readiness_calls = 0
        self.dispatches = 0

    def readiness(self, config: AIProviderConfig) -> ProviderReadiness:
        self.readiness_calls += 1
        return self.result

    def post(
        self,
        config: AIProviderConfig,
        *,
        body: bytes,
        timeout_seconds: float,
        cancel_event: CancellationSignal | None = None,
    ) -> bytes:
        self.dispatches += 1
        raise AssertionError("Provider dispatch is forbidden in health tests")

    def close(self) -> None:
        pass


def refuse_credential_lookup(*args: object, **kwargs: object) -> None:
    raise AssertionError("Health must use the injected access readiness")


@pytest.mark.parametrize("provider_kind", ["proposal", "draft"])
@pytest.mark.parametrize(
    ("credential_state", "grant_state"),
    [
        ("ready", "missing"),
        ("ready", "expired"),
        ("ready", "active"),
        ("unavailable", "active"),
        ("not_required", "missing"),
        ("not_required", "active"),
    ],
)
def test_health_separates_credentials_from_current_usage_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    provider_kind: str,
    credential_state: str,
    grant_state: str,
) -> None:
    clock = [1_700_000_000_000]
    monkeypatch.setattr(ai_live_authorization, "now_ms", lambda: clock[0])
    monkeypatch.setattr(product_store_ai_authorizations, "now_ms", lambda: clock[0])
    monkeypatch.setattr(ai_provider_access, "credential_value", refuse_credential_lookup)
    ai_config = load_config(ROOT / "config" / "bluefire.example.yaml").ai
    config = ai_config.provider("openai-responses.v1")
    if credential_state == "not_required":
        config = replace(config, api_key=None, endpoint="http://127.0.0.1:8000/v1/responses")
        ai_config = replace(
            ai_config,
            providers=tuple(config if row.id == config.id else row for row in ai_config.providers),
        )
    credential_available = credential_state != "unavailable"
    base = InertAccess(
        ProviderReadiness(
            credential_available,
            credential_state,
            "configuration_ready" if credential_available else "credential_unavailable",
            (
                "Configuration checked; no network request was made."
                if credential_available
                else "The referenced server environment variable is unset or invalid. No network request was made."
            ),
        )
    )
    access = AuthorizedAIProviderAccess(base, ProductStore(tmp_path / "product.db"))
    if grant_state != "missing":
        access.authorize(
            {
                "provider": config.to_dict(),
                "purposes": ["bluefire_ai_proposal", "bluefire_ai_graph_draft"],
                "data_scope": "reviewed_lab_context",
                "limits": {
                    "max_requests": 2,
                    "max_request_bytes": 100_000,
                    "max_reserved_output_tokens": 2048,
                },
                "expires_in_seconds": 1,
                "approved_by": "authored-test-operator",
                "usage_authorized": True,
                "local_endpoint_authorized": credential_state == "not_required",
            }
        )
        if grant_state == "expired":
            clock[0] += 1000
    provider = (
        build_ai_provider(ai_config, provider_id=config.id, access=access, environ={})
        if provider_kind == "proposal"
        else build_ai_draft_provider(
            ai_config, provider_id=config.id, access=access, environ={}, allow_fallback=False
        )
    )
    before = access.list()
    health = provider.health()
    assert base.readiness_calls == 1
    assert access.list() == before
    assert health.credential_available is credential_available
    ready = credential_available and grant_state == "active"
    assert health.state is (ProviderHealthState.READY if ready else ProviderHealthState.DEGRADED)
    assert "fallback" not in health.message and "drafting will be used" not in health.message
    if credential_available and grant_state != "active":
        assert health.message == (
            "Configuration is available; authorize the reviewed model data and usage before sending requests."
        )
        assert "unset" not in health.message
        with pytest.raises(AIProviderTransportError) as error:
            access.post(config, body=b"{}", timeout_seconds=1)
        assert error.value.code == "live_authorization_required"
        if grant_state == "expired":
            assert before["authorizations"][0]["status"] == "expired"
    else:
        assert health.message == base.result.message
    assert base.dispatches == 0
    assert access.list() == before
    assert set(health.to_dict()) == {
        "provider_id",
        "state",
        "credential_available",
        "fallback_provider_id",
        "message",
    }
    access.close()


@pytest.mark.parametrize("provider_kind", ["proposal", "draft"])
def test_broker_readiness_keeps_its_safe_message_without_credential_lookup(
    monkeypatch: pytest.MonkeyPatch, provider_kind: str
) -> None:
    monkeypatch.setattr(ai_provider_access, "credential_value", refuse_credential_lookup)
    config = load_config(ROOT / "config" / "bluefire.example.yaml").ai
    base = InertAccess(
        ProviderReadiness(
            False,
            "unavailable",
            "broker_unavailable",
            "The exact enrolled broker binding is unavailable; no provider request was made.",
            "broker",
            lab_session_expires_at_ms=1_700_000_000_000,
        )
    )
    build = build_ai_provider if provider_kind == "proposal" else build_ai_draft_provider
    health = build(config, provider_id="openai-responses.v1", access=base, environ={}).health()
    assert health.message == base.result.message
    assert health.state is ProviderHealthState.DEGRADED
    assert health.credential_available is False
    if provider_kind == "proposal":
        assert health.lab_session_expires_at_ms == base.result.lab_session_expires_at_ms
    assert base.readiness_calls == 1 and base.dispatches == 0
