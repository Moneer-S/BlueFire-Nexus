from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire.ai import (
    AIProposal,
    AIProposalRequest,
    AIProviderError,
    AIProviderTransportError,
    DeterministicOfflineProvider,
    OpenAIResponsesProvider,
    ProposalType,
    build_ai_provider,
)
from bluefire.config import AutonomyLevel, load_config
from bluefire.util import canonical_json_bytes, content_hash

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "bluefire.example.yaml"


class FakeTransport:
    def __init__(self, *responses: bytes | Exception) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> bytes:
        self.calls.append(
            {
                "url": url,
                "headers": dict(headers),
                "body": body,
                "timeout_seconds": timeout_seconds,
            }
        )
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _request(
    autonomy: AutonomyLevel,
    *,
    context: Mapping[str, Any] | None = None,
) -> AIProposalRequest:
    state = {"step": "discover", "outcome": "success"}
    return AIProposalRequest(
        objective="Choose only a registered next graph option.",
        current_state_digest=content_hash(state),
        autonomy=autonomy,
        allowed_step_ids=("discover",),
        allowed_behavior_ids=("sandbox.discovery.v1",),
        allowed_action_ids=("sandbox.discovery.list.v1",),
        context=context or state,
    )


def _proposal(*, review: bool = True, behavior_id: str = "sandbox.discovery.v1") -> dict[str, Any]:
    return {
        "schema_version": "bluefire.ai-proposal.v2",
        "proposal_type": "select_registered",
        "selected_step_id": "discover",
        "selected_behavior_id": behavior_id,
        "selected_action_id": None,
        "selected_edge": None,
        "parameter_changes": [],
        "rationale": "This option is already registered in the graph.",
        "alternatives": [],
        "confidence": 0.8,
        "requires_operator_review": review,
    }


def _response(proposal: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(
        {
            "id": "resp_test_123",
            "model": "gpt-4o-mini",
            "status": "completed",
            "error": None,
            "output": [
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": canonical_json_bytes(proposal).decode("utf-8"),
                        }
                    ],
                }
            ],
            "usage": {"input_tokens": 40, "output_tokens": 80, "total_tokens": 120},
        }
    )


@pytest.mark.parametrize("autonomy", list(AutonomyLevel))
def test_deterministic_provider_enforces_off_assist_auto_semantics(
    autonomy: AutonomyLevel,
) -> None:
    config = load_config(CONFIG_PATH).ai
    provider = DeterministicOfflineProvider(config.fallback)

    result = provider.propose(_request(autonomy))

    if autonomy is AutonomyLevel.OFF:
        assert result.proposal.proposal_type is ProposalType.NO_CHANGE
        assert result.proposal.selected_action_id is None
    else:
        assert result.proposal.proposal_type is ProposalType.SELECT_REGISTERED
        assert result.proposal.selected_action_id is None
    assert result.proposal.requires_operator_review is (autonomy is AutonomyLevel.ASSIST)


def test_responses_request_is_bounded_redacted_and_uses_strict_schema() -> None:
    config = load_config(CONFIG_PATH).ai
    transport = FakeTransport(_response(_proposal()))
    provider = build_ai_provider(
        config,
        provider_id="openai-responses.v1",
        environ={"OPENAI_API_KEY": "unit-test-key-value"},  # pragma: allowlist secret
        transport=transport,
    )
    assert isinstance(provider, OpenAIResponsesProvider)
    request = _request(
        AutonomyLevel.ASSIST,
        context={
            "password": "context-password-value",  # pragma: allowlist secret
            "token": "context-token-value",
            "access_token": "nested-token-value",
            "evidence": {"content": "private evidence bytes"},
            "notes": "x" * 4_100,
        },
    )

    result = provider.propose(request)

    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call["url"] == "https://api.openai.com/v1/responses"
    assert call["timeout_seconds"] == 30.0
    assert call["headers"]["Authorization"] == (
        "Bearer unit-test-key-value"  # pragma: allowlist secret
    )
    body = json.loads(call["body"])
    assert body["model"] == "gpt-4o-mini"
    assert body["store"] is False
    assert body["parallel_tool_calls"] is False
    assert body["tools"] == []
    assert body["tool_choice"] == "none"
    assert body["max_output_tokens"] == 800
    assert body["text"]["format"]["type"] == "json_schema"
    assert body["text"]["format"]["strict"] is True
    assert body["text"]["format"]["schema"]["additionalProperties"] is False
    model_input = json.loads(body["input"])
    assert model_input["context"]["password"] == "[REDACTED]"
    assert model_input["context"]["token"] == "[REDACTED]"
    assert model_input["context"]["access_token"] == "[REDACTED]"
    assert model_input["context"]["evidence"] == "[EVIDENCE CONTENT OMITTED]"
    assert model_input["context"]["notes"].endswith("...[TRUNCATED]")
    assert b"context-password-value" not in call["body"]  # pragma: allowlist secret
    assert b"context-token-value" not in call["body"]
    assert result.used_fallback is False
    assert result.proposal.requires_operator_review is True


def test_invalid_structured_response_falls_back_without_applying_untrusted_output() -> None:
    config = load_config(CONFIG_PATH).ai
    invalid = _proposal(behavior_id="unregistered.behavior.v1")
    invalid["command"] = "do-not-run"
    transport = FakeTransport(_response(invalid))
    provider = build_ai_provider(
        config,
        provider_id="openai-responses.v1",
        environ={"OPENAI_API_KEY": "unit-test-key-value"},  # pragma: allowlist secret
        transport=transport,
    )

    result = provider.propose(_request(AutonomyLevel.ASSIST))

    assert result.used_fallback is True
    assert result.fallback_reason == "response_invalid"
    assert result.effective_provider_id == "deterministic-offline.v1"
    assert result.proposal.selected_behavior_id == "sandbox.discovery.v1"
    assert "command" not in result.proposal.to_dict()


@pytest.mark.parametrize("confidence", [10**309, -(10**309)])
def test_oversized_confidence_uses_deterministic_fallback(confidence: int) -> None:
    config = load_config(CONFIG_PATH).ai
    invalid = _proposal()
    invalid["confidence"] = confidence
    transport = FakeTransport(_response(invalid))
    provider = build_ai_provider(
        config,
        provider_id="openai-responses.v1",
        environ={"OPENAI_API_KEY": "unit-test-key-value"},  # pragma: allowlist secret
        transport=transport,
    )

    result = provider.propose(_request(AutonomyLevel.ASSIST))

    assert result.used_fallback is True
    assert result.fallback_reason == "response_invalid"
    assert result.effective_provider_id == "deterministic-offline.v1"
    assert result.proposal.selected_behavior_id == "sandbox.discovery.v1"


def test_retry_budget_and_missing_credential_use_deterministic_fallback() -> None:
    config = load_config(CONFIG_PATH).ai
    retryable = AIProviderTransportError("temporary failure", retryable=True)
    transport = FakeTransport(retryable, _response(_proposal(review=False)))
    sleeps: list[float] = []
    provider = build_ai_provider(
        config,
        provider_id="openai-responses.v1",
        environ={"OPENAI_API_KEY": "unit-test-key-value"},  # pragma: allowlist secret
        transport=transport,
        sleeper=sleeps.append,
    )

    result = provider.propose(_request(AutonomyLevel.AUTO))

    assert result.attempts == 2
    assert result.used_fallback is False
    assert sleeps == [0.25]

    unused_transport = FakeTransport(_response(_proposal()))
    unavailable = build_ai_provider(
        config,
        provider_id="openai-responses.v1",
        environ={},
        transport=unused_transport,
    )
    fallback = unavailable.propose(_request(AutonomyLevel.OFF))
    assert fallback.used_fallback is True
    assert fallback.fallback_reason == "credential_unavailable"
    assert fallback.proposal.proposal_type is ProposalType.NO_CHANGE
    assert unused_transport.calls == []


def test_api_key_value_never_appears_in_config_health_or_result_metadata() -> None:
    secret_value = "unit-test-key-value"  # pragma: allowlist secret
    config = load_config(CONFIG_PATH).ai
    transport = FakeTransport(_response(_proposal()))
    provider = build_ai_provider(
        config,
        provider_id="openai-responses.v1",
        environ={"OPENAI_API_KEY": secret_value},
        transport=transport,
    )

    result = provider.propose(_request(AutonomyLevel.ASSIST))
    persisted_shapes = {
        "config": config.to_dict(),
        "health": provider.health().to_dict(),
        "result": result.metadata(),
    }

    assert secret_value not in json.dumps(persisted_shapes, sort_keys=True)
    assert persisted_shapes["config"]["providers"][1]["api_key"] == {"env": "OPENAI_API_KEY"}


def test_adaptive_proposal_types_are_strictly_bounded_by_registered_options() -> None:
    edge = {"from_step": "current", "outcome": "success", "to_step": "next_step"}
    request = AIProposalRequest(
        objective="Apply one bounded registered adaptation.",
        current_state_digest=content_hash({"step": "current"}),
        autonomy=AutonomyLevel.AUTO,
        allowed_step_ids=("next_step", "current"),
        allowed_behavior_ids=("sandbox.discovery.v1",),
        allowed_action_ids=("sandbox.discovery.list.v1",),
        allowed_edges=(edge,),
        allowed_parameter_schemas={
            "next_step": {
                "record_limit": {
                    "type": "integer",
                    "enum": [],
                    "minimum": 1,
                    "maximum": 100,
                },
                "method": {
                    "type": "string",
                    "enum": ["list", "metadata"],
                    "minimum": None,
                    "maximum": None,
                },
            }
        },
        retryable_step_ids=("current",),
        context={},
    )

    def proposal(
        proposal_type: str,
        *,
        step_id: str,
        action_id: str | None = None,
        selected_edge: Mapping[str, str] | None = None,
        changes: list[Mapping[str, Any]] | None = None,
    ) -> AIProposal:
        return AIProposal.from_mapping(
            {
                "schema_version": "bluefire.ai-proposal.v2",
                "proposal_type": proposal_type,
                "selected_step_id": step_id,
                "selected_behavior_id": "sandbox.discovery.v1",
                "selected_action_id": action_id,
                "selected_edge": dict(selected_edge) if selected_edge else None,
                "parameter_changes": list(changes or []),
                "rationale": "Use only the registered bounded option.",
                "alternatives": [],
                "confidence": 0.9,
                "requires_operator_review": False,
            }
        )

    request.validate_proposal(proposal("select_next_node", step_id="next_step", selected_edge=edge))
    request.validate_proposal(
        proposal(
            "change_parameters",
            step_id="next_step",
            changes=[{"name": "record_limit", "value": 20}],
        )
    )
    request.validate_proposal(
        proposal(
            "select_registered_action",
            step_id="next_step",
            action_id="sandbox.discovery.list.v1",
        )
    )
    request.validate_proposal(proposal("retry_registered", step_id="current"))

    with pytest.raises(AIProviderError, match="maximum"):
        request.validate_proposal(
            proposal(
                "change_parameters",
                step_id="next_step",
                changes=[{"name": "record_limit", "value": 101}],
            )
        )
    with pytest.raises(AIProviderError, match="enum"):
        request.validate_proposal(
            proposal(
                "change_parameters",
                step_id="next_step",
                changes=[{"name": "method", "value": "C:\\unsafe\\payload.exe"}],
            )
        )
    with pytest.raises(AIProviderError, match="retry allowlist"):
        request_without_retry = AIProposalRequest(
            objective=request.objective,
            current_state_digest=request.current_state_digest,
            autonomy=request.autonomy,
            allowed_step_ids=request.allowed_step_ids,
            allowed_behavior_ids=request.allowed_behavior_ids,
            allowed_action_ids=request.allowed_action_ids,
            allowed_edges=request.allowed_edges,
            allowed_parameter_schemas=request.allowed_parameter_schemas,
            retryable_step_ids=(),
            context={},
        )
        request_without_retry.validate_proposal(proposal("retry_registered", step_id="current"))


def test_free_form_string_parameter_schema_is_not_exposed_to_runtime_ai() -> None:
    with pytest.raises(AIProviderError, match="closed enum"):
        AIProposalRequest(
            objective="Reject free-form strings.",
            current_state_digest=content_hash({"step": "current"}),
            autonomy=AutonomyLevel.AUTO,
            allowed_step_ids=("next_step",),
            allowed_behavior_ids=("sandbox.discovery.v1",),
            allowed_action_ids=(),
            allowed_parameter_schemas={
                "next_step": {
                    "path": {
                        "type": "string",
                        "enum": [],
                        "minimum": None,
                        "maximum": None,
                    }
                }
            },
            context={},
        )
