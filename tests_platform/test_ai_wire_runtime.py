from __future__ import annotations

import json
from dataclasses import replace
from typing import Any, Mapping

import pytest

from bluefire.ai import (
    AIProviderTransportError,
    ChatCompletionsProvider,
    build_ai_provider,
)
from bluefire.ai_drafts import ChatCompletionsDraftProvider, build_ai_draft_provider
from bluefire.ai_probe import check_provider
from bluefire.ai_wire import AIWireError, response_usage, structured_output
from bluefire.config import (
    AIConfig,
    AIProviderConfig,
    AIProviderKind,
    AutonomyLevel,
    ConfigError,
    load_config,
)
from bluefire.contracts import ContractError
from bluefire.util import canonical_json_bytes
from tests_platform.test_ai import CONFIG_PATH, FakeTransport, _proposal, _request
from tests_platform.test_ai_drafts import _model_draft
from tests_platform.test_ai_drafts import _request as _draft_request

NETWORK_KINDS = (AIProviderKind.OPENAI_RESPONSES, AIProviderKind.CHAT_COMPLETIONS)


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"provider": {}, "connect": "true"},
        {"provider": None, "connect": False},
        {"provider": {}, "connect": False},
    ],
)
def test_service_provider_check_rejects_invalid_configuration_without_network(
    body: Mapping[str, Any],
) -> None:
    from bluefire.api import APIError
    from bluefire.service import BlueFireService

    service = BlueFireService.__new__(BlueFireService)
    with pytest.raises(APIError) as caught:
        service.check_ai_provider(body)
    assert caught.value.status == 400


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_if_called(*args: Any, **kwargs: Any) -> None:
        pytest.fail("Provider runtime tests must never make a real network request")

    monkeypatch.setattr("bluefire.ai_transport.subprocess.Popen", fail_if_called)


def _provider_config(kind: AIProviderKind, *, authenticated: bool = False) -> AIProviderConfig:
    return AIProviderConfig.from_mapping(
        {
            "id": "test-provider.v1",
            "kind": kind.value,
            "model": "explicit-test-model",
            "endpoint": (
                "https://provider.example/v1/custom-route"
                if authenticated
                else "http://127.0.0.1:8080/v1/custom-route"
            ),
            "api_key": {"env": "TEST_PROVIDER_KEY"} if authenticated else None,
            "timeout_seconds": 90,
            "max_retries": 4,
            "max_output_tokens": 1024,
        }
    )


def _ai_config(provider: AIProviderConfig) -> AIConfig:
    original = load_config(CONFIG_PATH).ai
    return replace(original, active_provider=provider.id, providers=(original.fallback, provider))


def _envelope(kind: AIProviderKind, document: Mapping[str, Any]) -> dict[str, Any]:
    text = canonical_json_bytes(document).decode("utf-8")
    common = {"id": "response_test_123", "model": "explicit-test-model"}
    if kind is AIProviderKind.CHAT_COMPLETIONS:
        return {
            **common,
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": text, "refusal": None},
                }
            ],
            "usage": {"prompt_tokens": 20, "completion_tokens": 40, "total_tokens": 60},
        }
    return {
        **common,
        "status": "completed",
        "error": None,
        "output": [
            {"type": "reasoning", "id": "reasoning_test_123", "summary": []},
            {
                "type": "message",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": text, "annotations": []}],
            },
        ],
        "usage": {"input_tokens": 20, "output_tokens": 40, "total_tokens": 60},
    }


@pytest.mark.parametrize("kind", NETWORK_KINDS)
@pytest.mark.parametrize("graph", [False, True], ids=["proposal", "graph-draft"])
def test_explicit_dialects_round_trip_through_real_providers(
    kind: AIProviderKind, graph: bool
) -> None:
    config = _provider_config(kind)
    document = _model_draft() if graph else _proposal()
    transport = FakeTransport(canonical_json_bytes(_envelope(kind, document)))
    if graph:
        provider = build_ai_draft_provider(_ai_config(config), environ={}, transport=transport)
        result = provider.draft(_draft_request())
        assert result.draft.title == document["title"]
    else:
        provider = build_ai_provider(_ai_config(config), environ={}, transport=transport)
        result = provider.propose(_request(AutonomyLevel.ASSIST))
        assert result.proposal.selected_behavior_id == document["selected_behavior_id"]

    assert result.used_fallback is False
    assert result.requested_provider_id == result.effective_provider_id == config.id
    assert result.model == config.model
    assert result.usage == {"input_tokens": 20, "output_tokens": 40, "total_tokens": 60}
    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call["url"] == config.endpoint
    assert "Authorization" not in call["headers"]
    request = json.loads(call["body"])
    assert request["model"] == config.model
    assert request["store"] is False
    if kind is AIProviderKind.CHAT_COMPLETIONS:
        assert isinstance(
            provider, ChatCompletionsDraftProvider if graph else ChatCompletionsProvider
        )
        assert [message["role"] for message in request["messages"]] == ["system", "user"]
        assert request["max_completion_tokens"] == config.max_output_tokens
        assert request["response_format"]["type"] == "json_schema"
        assert request["response_format"]["json_schema"]["strict"] is True
        assert not {"input", "instructions", "text", "max_output_tokens"} & request.keys()
    else:
        assert request["text"]["format"]["type"] == "json_schema"
        assert request["text"]["format"]["strict"] is True
        assert request["max_output_tokens"] == config.max_output_tokens
        assert not {"messages", "response_format", "max_completion_tokens"} & request.keys()


@pytest.mark.parametrize(
    "case", ["refusal", "incomplete", "tool", "messages", "blocks", "direct-conflict"]
)
def test_responses_rejects_untrustworthy_output_items(case: str) -> None:
    response = _envelope(AIProviderKind.OPENAI_RESPONSES, {"ok": True})
    message = response["output"][1]
    expected = "response_invalid"
    if case == "refusal":
        message["content"] = [{"type": "refusal", "refusal": "Request declined"}]
        expected = "provider_refused"
    elif case == "incomplete":
        response["status"] = "incomplete"
        response["incomplete_details"] = {"reason": "max_output_tokens"}
        expected = "response_incomplete"
    elif case == "tool":
        response["output"].append(
            {"type": "function_call", "name": "unexpected", "arguments": "{}"}
        )
    elif case == "messages":
        response["output"].append(message.copy())
    elif case == "blocks":
        message["content"].append({"type": "output_text", "text": "{}"})
    else:
        response["output_text"] = "{}"
    with pytest.raises(AIWireError) as error:
        structured_output(response, AIProviderKind.OPENAI_RESPONSES)
    assert error.value.code == expected


@pytest.mark.parametrize("case", ["refusal", "length", "filtered", "tool", "choices", "wrong-role"])
def test_chat_rejects_untrustworthy_completion_choices(case: str) -> None:
    response = _envelope(AIProviderKind.CHAT_COMPLETIONS, {"ok": True})
    choice = response["choices"][0]
    expected = "response_invalid"
    if case == "refusal":
        choice["message"]["refusal"] = "Request declined"
        expected = "provider_refused"
    elif case in {"length", "filtered"}:
        choice["finish_reason"] = "length" if case == "length" else "content_filter"
        expected = "response_incomplete"
    elif case == "tool":
        choice["message"]["tool_calls"] = [{"type": "function", "function": {"name": "unexpected"}}]
    elif case == "choices":
        response["choices"].append(choice.copy())
    else:
        choice["message"]["role"] = "user"
    with pytest.raises(AIWireError) as error:
        structured_output(response, AIProviderKind.CHAT_COMPLETIONS)
    assert error.value.code == expected


@pytest.mark.parametrize("kind", NETWORK_KINDS)
@pytest.mark.parametrize("tokens", [True, -1, 1.5, 257])
def test_usage_rejects_invalid_or_over_budget_tokens(kind: AIProviderKind, tokens: Any) -> None:
    field = "completion_tokens" if kind is AIProviderKind.CHAT_COMPLETIONS else "output_tokens"
    with pytest.raises(AIWireError):
        response_usage({field: tokens}, 256, kind)


@pytest.mark.parametrize("kind", NETWORK_KINDS)
@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "[::1]"])
def test_loopback_configuration_can_omit_authentication(kind: AIProviderKind, host: str) -> None:
    raw = _provider_config(kind).to_dict()
    raw["endpoint"] = f"http://{host}:8080/custom"
    assert AIProviderConfig.from_mapping(raw).api_key is None


@pytest.mark.parametrize("kind", NETWORK_KINDS)
def test_remote_configuration_requires_a_reference_instead_of_a_literal_secret(
    kind: AIProviderKind,
) -> None:
    raw = _provider_config(kind).to_dict()
    raw["endpoint"] = "https://provider.example/custom"
    with pytest.raises(ConfigError, match="environment reference"):
        AIProviderConfig.from_mapping(raw)
    raw["api_key"] = "literal-value-is-not-a-reference"  # pragma: allowlist secret
    with pytest.raises(ContractError, match="must be a mapping"):
        AIProviderConfig.from_mapping(raw)


@pytest.mark.parametrize("kind", NETWORK_KINDS)
def test_readiness_and_missing_credentials_never_call_network(kind: AIProviderKind) -> None:
    transport = FakeTransport()
    config = _provider_config(kind, authenticated=True)
    readiness = check_provider(
        config, connect=False, environ={"TEST_PROVIDER_KEY": "test-only-value"}, transport=transport
    )
    missing = check_provider(config, connect=True, environ={}, transport=transport)
    assert readiness["credential_state"] == "ready"
    assert readiness["connectivity"] == "not_tested"
    assert readiness["structured_output"] == "not_tested"
    assert readiness["attempts"] == 0
    assert missing["credential_state"] == "unavailable"
    assert missing["code"] == "credential_unavailable"
    assert missing["attempts"] == 0
    assert transport.calls == []
    assert "test-only-value" not in json.dumps(readiness)

    proposal = build_ai_provider(_ai_config(config), environ={}, transport=transport).propose(
        _request(AutonomyLevel.ASSIST)
    )
    draft = build_ai_draft_provider(_ai_config(config), environ={}, transport=transport).draft(
        _draft_request()
    )
    assert proposal.used_fallback and draft.used_fallback
    assert proposal.fallback_reason == draft.fallback_reason == "credential_unavailable"
    assert transport.calls == []


@pytest.mark.parametrize("kind", NETWORK_KINDS)
@pytest.mark.parametrize("configured_timeout,configured_tokens", [(90, 1024), (2, 64)])
def test_live_probe_is_one_small_synthetic_request(
    kind: AIProviderKind, configured_timeout: int, configured_tokens: int
) -> None:
    config = replace(
        _provider_config(kind),
        timeout_seconds=configured_timeout,
        max_output_tokens=configured_tokens,
    )
    transport = FakeTransport(canonical_json_bytes(_envelope(kind, {"ok": True})))
    result = check_provider(config, connect=True, environ={}, transport=transport)
    assert result["code"] == "probe_passed"
    assert result["connectivity"] == result["structured_output"] == "passed"
    assert result["used_fallback"] is False
    assert result["attempts"] == len(transport.calls) == 1
    call = transport.calls[0]
    assert call["timeout_seconds"] == min(configured_timeout, 10)
    request = json.loads(call["body"])
    budget = (
        "max_completion_tokens" if kind is AIProviderKind.CHAT_COMPLETIONS else "max_output_tokens"
    )
    assert request[budget] == min(configured_tokens, 256)
    if kind is AIProviderKind.CHAT_COMPLETIONS:
        format_spec = request["response_format"]["json_schema"]
        model_input = request["messages"][1]["content"]
    else:
        format_spec = request["text"]["format"]
        model_input = request["input"]
    assert format_spec["strict"] is True
    assert format_spec["schema"]["additionalProperties"] is False
    assert format_spec["schema"]["properties"] == {"ok": {"type": "boolean", "enum": [True]}}
    assert "Synthetic connection test" in model_input


@pytest.mark.parametrize("kind", NETWORK_KINDS)
@pytest.mark.parametrize("document", [{"ok": 1}, {"ok": False}, {"ok": True, "extra": 1}, {}])
def test_probe_requires_exact_schema_including_boolean(
    kind: AIProviderKind, document: Mapping[str, Any]
) -> None:
    transport = FakeTransport(canonical_json_bytes(_envelope(kind, document)))
    result = check_provider(_provider_config(kind), connect=True, environ={}, transport=transport)
    assert result["connectivity"] == "passed"
    assert result["structured_output"] == "failed"
    assert result["code"] == "response_invalid"
    assert result["used_fallback"] is False
    assert len(transport.calls) == 1


@pytest.mark.parametrize("kind", NETWORK_KINDS)
def test_probe_transport_failure_never_retries_or_uses_fallback(kind: AIProviderKind) -> None:
    transport = FakeTransport(AIProviderTransportError("Endpoint unavailable", retryable=True))
    result = check_provider(_provider_config(kind), connect=True, environ={}, transport=transport)
    assert result["connectivity"] == "failed"
    assert result["structured_output"] == "not_tested"
    assert result["used_fallback"] is False
    assert result["attempts"] == len(transport.calls) == 1


@pytest.mark.parametrize("kind", NETWORK_KINDS)
@pytest.mark.parametrize("graph", [False, True], ids=["proposal", "graph-draft"])
def test_refusal_fallback_is_identified_to_the_caller(kind: AIProviderKind, graph: bool) -> None:
    config = _provider_config(kind)
    response = _envelope(kind, _model_draft() if graph else _proposal())
    if kind is AIProviderKind.CHAT_COMPLETIONS:
        response["choices"][0]["message"]["refusal"] = "Request declined"
    else:
        response["output"][1]["content"] = [{"type": "refusal", "refusal": "Request declined"}]
    transport = FakeTransport(canonical_json_bytes(response))
    if graph:
        result = build_ai_draft_provider(_ai_config(config), environ={}, transport=transport).draft(
            _draft_request()
        )
    else:
        result = build_ai_provider(_ai_config(config), environ={}, transport=transport).propose(
            _request(AutonomyLevel.ASSIST)
        )
    assert result.used_fallback is True
    assert result.requested_provider_id == config.id
    assert result.effective_provider_id == _ai_config(config).fallback.id
    assert result.fallback_reason == "provider_refused"
    assert len(transport.calls) == 1


def test_deterministic_probe_never_connects() -> None:
    transport = FakeTransport()
    result = check_provider(
        load_config(CONFIG_PATH).ai.fallback, connect=True, environ={}, transport=transport
    )
    assert result["code"] == "deterministic_no_network"
    assert result["connectivity"] == "not_tested"
    assert result["attempts"] == 0
    assert transport.calls == []


@pytest.mark.parametrize("status", [401, 403])
def test_authentication_errors_do_not_expose_remote_body_or_credentials(
    status: int,
) -> None:
    result = check_provider(
        _provider_config(AIProviderKind.CHAT_COMPLETIONS, authenticated=True),
        connect=True,
        environ={"TEST_PROVIDER_KEY": "test-only-value"},
        transport=FakeTransport(
            AIProviderTransportError(
                f"HTTP {status}: private server rejection text; private remote error body",
                retryable=False,
                code="authentication_failed",
            )
        ),
    )
    assert result["code"] == "authentication_failed"
    assert "rejected authentication" in result["message"]
    assert result["connectivity"] == "failed"
    assert result["used_fallback"] is False
    serialized = json.dumps(result)
    assert "private server rejection text" not in serialized
    assert "private remote error body" not in serialized
    assert "test-only-value" not in serialized
