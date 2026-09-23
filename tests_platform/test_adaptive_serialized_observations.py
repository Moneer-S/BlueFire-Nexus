"""Authored metadata and fake HTTP transport; no live model or host permission proof."""

import json
from dataclasses import replace

import pytest

from bluefire.adaptive_record_validation import validate_v4_attempt_record
from bluefire.adaptive_runtime import propose_reviewed_method
from bluefire.ai import AIProviderError, build_ai_provider
from bluefire.ai_authorized_access import AuthorizedAIProviderAccess
from bluefire.ai_observation_summary import RuntimeObservationSummary
from bluefire.ai_provider_access import DirectAIProviderAccess
from bluefire.config import AIProviderKind, AIRedactionPolicy
from bluefire.evidence import EvidenceProvenance
from bluefire.product_store import ProductStore
from bluefire.util import canonical_json_bytes
from tests_platform.test_adaptive_combined_observations import _permissions, _record
from tests_platform.test_adaptive_runtime import Provider
from tests_platform.test_adaptive_runtime import runtime as runtime
from tests_platform.test_ai_live_authorization import request as authorization_request
from tests_platform.test_ai_wire_runtime import _ai_config, _envelope, _provider_config


def _inputs(runtime, *, writable=True, provenance=EvidenceProvenance.OBSERVED):
    kwargs, config = runtime
    fields = _permissions(group_writable=writable)
    record = _record(
        kwargs,
        {
            "artifact_type": "collector_observation",
            "observation_kind": "filesystem",
            **fields,
            "observed_fields": fields,
            "path": "/private/operator/path",
            "raw_log": "private raw content",
            "untrusted_extra": "untrusted freeform payload",
            "secret": "private secret value",  # pragma: allowlist secret -- authored redaction sentinel
        },
        provenance,
    )
    return (
        {
            **kwargs,
            "steps": [
                {
                    **kwargs["steps"][0],
                    "error": {"code": "collection_timeout"},
                    "evidence_ids": [record.evidence_id, "missing-reference"],
                }
            ],
            "evidence": [record],
        },
        config,
        record,
    )


def _captured(runtime, **options):
    kwargs, config, record = _inputs(runtime, **options)
    provider = Provider(config)
    result = propose_reviewed_method(**kwargs, provider=provider)
    validate_v4_attempt_record(result.record)
    assert "observation_summary" not in result.record["planner_state"]
    return provider.requests[0], record


def _assert_wire(projected, record, *, writable):
    assert (
        projected["context"]["observations"]["attempts"][0]["evidence"]
        == "[EVIDENCE CONTENT OMITTED]"
    )
    failure = projected["context"]["observations"]["attempts"][0]["failure"]
    assert failure["classification"] == "execution_timeout"
    assert failure["telemetry_gap"] is True
    rows = projected["observation_summary"]["records"]
    assert len(rows) == 1
    assert rows[0]["record_id"] == record.evidence_id
    assert rows[0]["record_hash"] == record.record_hash
    assert rows[0]["provenance"] == "observed"
    assert rows[0]["facts"] == {
        "artifact_type": "collector_observation",
        "observation_kind": "filesystem",
        **_permissions(group_writable=writable),
    }
    encoded = canonical_json_bytes(projected)
    for private in [
        b"/private/operator/path",
        b"private raw content",
        b"untrusted freeform payload",
        b"private secret value",
    ]:
        assert private not in encoded


def test_serialized_request_keeps_closed_facts_and_raw_evidence_redaction(runtime):
    request, record = _captured(runtime)
    wire = request.to_dict(AIRedactionPolicy())
    _assert_wire(wire, record, writable=True)
    # Redaction remains key-based everywhere else; a name is not an exemption.
    request = replace(
        request,
        context={
            **request.context,
            "evidence": {"observation_summary": {"facts": "private raw content"}},
            "secret": "private secret value",  # pragma: allowlist secret -- authored redaction sentinel
        },
    )
    wire = request.to_dict(AIRedactionPolicy())
    assert wire["context"]["evidence"] == "[EVIDENCE CONTENT OMITTED]"
    assert wire["context"]["secret"] == "[REDACTED]"
    custom = replace(AIRedactionPolicy(), redact_keys=("facts",))
    assert request.to_dict(custom)["observation_summary"]["records"][0]["facts"] == "[REDACTED]"
    custom = replace(AIRedactionPolicy(), redact_keys=("observation_summary",))
    assert request.to_dict(custom)["observation_summary"] == "[REDACTED]"


@pytest.mark.parametrize("kind", [AIProviderKind.OPENAI_RESPONSES, AIProviderKind.CHAT_COMPLETIONS])
@pytest.mark.parametrize("writable", [False, True])
def test_shipped_provider_receives_facts_through_authorized_wire(
    runtime, tmp_path, monkeypatch, kind, writable
):
    def no_network(*args, **kwargs):
        pytest.fail("This regression must not start network transport")

    monkeypatch.setattr("bluefire.ai_transport.subprocess.Popen", no_network)
    kwargs, _, record = _inputs(runtime, writable=writable)
    config = replace(_provider_config(kind, authenticated=True), max_retries=0)
    calls = []

    class Transport:
        def post(self, url, *, headers, body, timeout_seconds):
            wire = json.loads(body)
            projected = json.loads(
                wire["input"]
                if kind is AIProviderKind.OPENAI_RESPONSES
                else wire["messages"][1]["content"]
            )
            _assert_wire(projected, record, writable=writable)
            calls.append(projected)
            selected = projected["allowed_action_ids"][
                int(projected["observation_summary"]["records"][0]["facts"]["non_owner_write_bit"])
            ]
            return canonical_json_bytes(
                _envelope(
                    kind,
                    {
                        "schema_version": "bluefire.ai-proposal.v2",
                        "proposal_type": "select_registered_action",
                        "selected_step_id": projected["allowed_step_ids"][0],
                        "selected_behavior_id": projected["allowed_behavior_ids"][0],
                        "selected_action_id": selected,
                        "selected_edge": None,
                        "parameter_changes": [],
                        "rationale": "Authored choice from serialized permission metadata.",
                        "alternatives": [],
                        "confidence": 0.8,
                        "requires_operator_review": False,
                    },
                )
            )

    access = AuthorizedAIProviderAccess(
        DirectAIProviderAccess(
            transport=Transport(), environ={"TEST_PROVIDER_KEY": "authored-test-value"}
        ),
        ProductStore(tmp_path / "product.db"),
    )
    access.authorize(authorization_request(config, purposes=["bluefire_ai_proposal"]))
    provider = build_ai_provider(_ai_config(config), provider_id=config.id, access=access)
    try:
        result = propose_reviewed_method(**kwargs, provider=provider)
        assert len(calls) == 1
        assert result.record["application_status"] == "applied_reviewed_method"
        assert result.record["provider"]["used_fallback"] is False
        assert result.selected_step.action_id == calls[0]["allowed_action_ids"][int(writable)]
        assert access.list()["authorizations"][0]["usage"]["requests"] == 1
    finally:
        access.close()


@pytest.mark.parametrize("provenance", [EvidenceProvenance.EXECUTED, EvidenceProvenance.UNKNOWN])
def test_unobserved_permission_claims_do_not_reach_serialized_summary(runtime, provenance):
    request, _ = _captured(runtime, provenance=provenance)
    facts = request.to_dict(AIRedactionPolicy())["observation_summary"]["records"][0]["facts"]
    assert "permission_status" not in facts
    assert "non_owner_write_bit" not in facts


@pytest.mark.parametrize("invalid", [False, True])
def test_unknown_permission_metadata_remains_explicit_on_wire(runtime, invalid):
    kwargs, config = runtime
    fields = (
        (_permissions(group_writable=True) | {"permission_mode_octal": "0640"})
        if invalid
        else {"permission_status": "unavailable_windows", "effective_access": "not_evaluated"}
    )
    record = _record(kwargs, {"artifact_type": "file_observation", **fields})
    provider = Provider(config)
    propose_reviewed_method(
        **{
            **kwargs,
            "steps": [{**kwargs["steps"][0], "evidence_ids": [record.evidence_id]}],
            "evidence": [record],
        },
        provider=provider,
    )
    facts = provider.requests[0].to_dict(AIRedactionPolicy())["observation_summary"]["records"][0][
        "facts"
    ]
    assert facts == {
        "artifact_type": "file_observation",
        "permission_status": "invalid_metadata" if invalid else "unavailable_windows",
        "effective_access": "not_evaluated",
    }


@pytest.mark.parametrize(
    "mutation", ["extra", "path", "bool_count", "inconsistent_mode", "unobserved", "reference"]
)
def test_closed_summary_rejects_untrusted_shapes(runtime, mutation):
    request, _ = _captured(runtime)
    rows = json.loads(request.observation_summary.encoded)
    row = rows[0]
    if mutation == "extra":
        row["untrusted_extra"] = "private raw content"
    elif mutation == "path":
        row["facts"]["path"] = "/private/operator/path"
    elif mutation == "bool_count":
        row["facts"]["record_count"] = True
    elif mutation == "inconsistent_mode":
        row["facts"]["permission_mode_octal"] = "0640"
    elif mutation == "unobserved":
        row["provenance"] = "unknown"
    else:
        row["record_id"] = "/private/operator/path"
    with pytest.raises(ValueError):
        RuntimeObservationSummary(json.dumps(rows))
    with pytest.raises(AIProviderError, match="closed metadata"):
        replace(request, observation_summary={"records": rows})
