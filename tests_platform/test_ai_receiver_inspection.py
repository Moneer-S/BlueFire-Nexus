"""Pure receiver inspection contracts with in-memory responses; no provider/network effects."""

import copy
import json
import threading
from dataclasses import replace

import pytest

from bluefire.ai_provider_access import ProviderReadiness
from bluefire.ai_receiver_inspection import (
    OUTPUT_SCHEMA,
    PURPOSE,
    format_request,
    inspect,
    phase_context,
    validate_output,
)
from bluefire.ai_wire import AIProviderCancelled, AIProviderError
from bluefire.config import AIProviderConfig, AIProviderKind
from bluefire.util import content_hash


def phases():
    return [
        {
            "phase": "baseline",
            "evidence_ref": "receiver:baseline:unit",
            "result_digest": "sha256:" + "a" * 64,
            "decision": "accepted",
            "transport_state": "completed",
            "receiver_cleanup": "verified_closed",
            "run_cleanup": "complete",
            "artifact_matches_baseline": None,
            "record_count": 3,
            "retained_record_count": 1,
            "redacted_record_count": 2,
        }
    ]


def output():
    return {
        "summary": "Baseline receiver accepted the reviewed records.",
        "findings": [
            {"claim": "One record was retained.", "evidence_refs": ["receiver:baseline:unit"]}
        ],
        "limitations": ["Controlled development evidence only."],
        "next_phase": "protected",
        "reason": "Review the offered protected phase in native controls.",
    }


@pytest.fixture(params=["chat_completions", "openai_responses"])
def provider(request):
    return AIProviderConfig.from_mapping(
        {
            "id": "inspection.unit.v1",
            "kind": request.param,
            "model": "unit-model",
            "endpoint": "http://127.0.0.1:8765/v1/test",
        }
    )


class Access:
    def __init__(self, *, ready=True, value=None, raw=None, after=None):
        self.ready, self.value, self.raw, self.after = ready, value, raw, after
        self.calls = []

    def readiness(self, config):
        return ProviderReadiness(self.ready, "not_required", "unit", "In-memory test only")

    def post(self, config, *, body, timeout_seconds, cancel_event):
        self.calls.append((config.id, body, timeout_seconds, cancel_event))
        if self.after:
            self.after()
        if self.raw is not None:
            return self.raw
        value = output() if self.value is None else self.value
        if config.kind.value == "chat_completions":
            response = {
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": json.dumps(value)},
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 20},
            }
        else:
            response = {
                "status": "completed",
                "output_text": json.dumps(value),
                "usage": {"input_tokens": 10, "output_tokens": 20},
            }
        return json.dumps(response).encode()


def test_both_dialects_bind_exact_schema_facts_and_return_advice_only(provider):
    values = phases()
    before = copy.deepcopy(values)
    body = json.loads(format_request(provider, phases=values, offered_next_phase="protected"))
    schema = body.get("text", {}).get("format") or body["response_format"]["json_schema"]
    assert (
        schema["name"] == PURPOSE and schema["schema"] == OUTPUT_SCHEMA and schema["strict"] is True
    )
    supplied = json.loads(body.get("input") or body["messages"][1]["content"])
    assert supplied == {"phases": values, "offered_next_phase": "protected"}
    assert body.get("tools", []) == [] and body.get("tool_choice", "none") == "none"
    access, cancel = Access(), threading.Event()
    report = inspect(
        config=provider, access=access, cancel=cancel, phases=values, offered_next_phase="protected"
    )
    assert report["next_phase"] == "protected" and report["model_interpretation"] is True
    assert report["context_digest"] == content_hash(supplied)
    assert report["provider"]["provider_id"] == provider.id
    assert len(access.calls) == 1 and access.calls[0][2:] == (provider.timeout_seconds, cancel)
    assert not {"approval", "execution", "policy", "actions", "status"}.intersection(report)
    assert values == before


@pytest.mark.parametrize(
    "field", ["records", "raw_body", "path", "token", "process_id", "session", "endpoint"]
)
def test_private_or_live_context_fields_are_rejected_before_transport(provider, field):
    values, access = phases(), Access()
    values[0][field] = "private unit sentinel"
    with pytest.raises(AIProviderError, match="unsupported fields"):
        inspect(
            config=provider,
            access=access,
            cancel=threading.Event(),
            phases=values,
            offered_next_phase=None,
        )
    assert access.calls == []


@pytest.mark.parametrize(
    "edit",
    [
        {"summary": " " * 2001 + "x"},
        {"summary": "\x00"},
        {"reason": "\x1bcommand"},
        {"limitations": ["x"] * 9},
        {"limitations": [""]},
        {"findings": [{}] * 9},
        {"findings": [{"claim": "x", "evidence_refs": []}]},
        {"findings": [{"claim": "x", "evidence_refs": ["invented"]}]},
        {"findings": [{"claim": "x", "evidence_refs": ["receiver:baseline:unit"] * 2}]},
        {"findings": [{"claim": "x", "evidence_refs": ["receiver:baseline:unit"], "command": "x"}]},
        {"next_phase": "restored"},
        {"next_phase": "baseline"},
        {"next_phase": {"execute": True}},
        {"approval": True},
    ],
)
def test_invalid_model_fields_bounds_refs_and_phase_are_refused(edit):
    with pytest.raises(AIProviderError):
        validate_output(
            {**output(), **edit},
            evidence_refs=["receiver:baseline:unit"],
            offered_next_phase="protected",
        )


@pytest.mark.parametrize("offered", [None, "protected", "restored"])
def test_only_current_offered_phase_or_no_phase_is_accepted(offered):
    for chosen in (None, offered):
        result = validate_output(
            {**output(), "next_phase": chosen},
            evidence_refs=["receiver:baseline:unit"],
            offered_next_phase=offered,
        )
        assert result["next_phase"] == chosen
    if offered is None:
        with pytest.raises(AIProviderError):
            validate_output(
                output(), evidence_refs=["receiver:baseline:unit"], offered_next_phase=None
            )


@pytest.mark.parametrize(
    "edit",
    [
        {"record_count": True},
        {"record_count": -1},
        {"record_count": 2**53},
        {"phase": "protected"},
        {"evidence_ref": "/private/path"},
        {"result_digest": "changed"},
        {"receiver_cleanup": "restored"},
    ],
)
def test_invalid_phase_facts_are_not_formatted(provider, edit):
    with pytest.raises(AIProviderError):
        format_request(provider, phases=[{**phases()[0], **edit}], offered_next_phase=None)


def test_unknown_evidence_and_failed_transport_remain_distinct_facts(provider):
    rows = phases()
    rows.append(
        {
            **rows[0],
            "phase": "protected",
            "evidence_ref": "receiver:protected:unit",
            "decision": "policy_refused",
            "transport_state": "failed",
            "artifact_matches_baseline": True,
        }
    )
    context = phase_context(rows, "restored")
    assert context["phases"][1]["decision"] == "policy_refused"
    assert context["phases"][1]["transport_state"] == "failed"
    rows[1].update(
        decision="insufficient_evidence",
        receiver_cleanup="uncertain",
        run_cleanup="unknown",
        record_count=None,
        retained_record_count=None,
        redacted_record_count=None,
    )
    wire = format_request(provider, phases=rows, offered_next_phase=None)
    assert b"insufficient_evidence" in wire and b"uncertain" in wire


@pytest.mark.parametrize("when", ["before", "during"])
def test_cancellation_never_returns_late_interpretation(provider, when):
    cancel = threading.Event()
    access = Access(after=cancel.set if when == "during" else None)
    if when == "before":
        cancel.set()
    with pytest.raises(AIProviderCancelled):
        inspect(
            config=provider,
            access=access,
            cancel=cancel,
            phases=phases(),
            offered_next_phase="protected",
        )
    assert len(access.calls) == int(when == "during")


@pytest.mark.parametrize(
    "raw", [b"[]", b"not-json", b"x" * 1048577], ids=["non-object", "malformed", "oversized"]
)
def test_malformed_or_oversized_transport_output_does_not_retry(provider, raw):
    access = Access(raw=raw)
    with pytest.raises(AIProviderError):
        inspect(
            config=provider,
            access=access,
            cancel=threading.Event(),
            phases=phases(),
            offered_next_phase="protected",
        )
    assert len(access.calls) == 1


def test_unavailable_provider_never_posts_or_falls_back(provider):
    access = Access(ready=False)
    with pytest.raises(AIProviderError, match="unavailable"):
        inspect(
            config=provider,
            access=access,
            cancel=threading.Event(),
            phases=phases(),
            offered_next_phase=None,
        )
    assert access.calls == []


def test_validated_output_is_detached():
    value = output()
    saved = validate_output(
        value, evidence_refs=["receiver:baseline:unit"], offered_next_phase="protected"
    )
    value["findings"][0]["evidence_refs"].clear()
    assert saved["findings"][0]["evidence_refs"] == ["receiver:baseline:unit"]


@pytest.mark.parametrize("values", [None, [], "receiver:baseline:unit", ["same", "same"]])
def test_invalid_supplied_reference_container_refuses(values):
    with pytest.raises(AIProviderError):
        validate_output(output(), evidence_refs=values, offered_next_phase="protected")


@pytest.mark.parametrize("values", [None, [], "baseline"])
def test_invalid_phase_container_refuses_before_transport(provider, values):
    access = Access()
    with pytest.raises(AIProviderError):
        inspect(
            config=provider,
            access=access,
            cancel=threading.Event(),
            phases=values,
            offered_next_phase=None,
        )
    assert access.calls == []


def test_readiness_cancellation_prevents_request(provider):
    cancel = threading.Event()

    class CancelDuringReadiness(Access):
        def readiness(self, config):
            cancel.set()
            return super().readiness(config)

    access = CancelDuringReadiness()
    with pytest.raises(AIProviderCancelled):
        inspect(
            config=provider,
            access=access,
            cancel=cancel,
            phases=phases(),
            offered_next_phase="protected",
        )
    assert access.calls == []


def test_deterministic_provider_cannot_claim_model_interpretation(provider):
    access = Access()
    with pytest.raises(AIProviderError, match="explicit model"):
        inspect(
            config=replace(provider, kind=AIProviderKind.DETERMINISTIC),
            access=access,
            cancel=threading.Event(),
            phases=phases(),
            offered_next_phase=None,
        )
    assert access.calls == []
