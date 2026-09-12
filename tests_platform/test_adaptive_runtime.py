"""Deterministic software evidence only; these tests are not live-provider proof."""

from dataclasses import replace
from pathlib import Path

import pytest

from bluefire.adaptive_observations import project_runtime_observations
from bluefire.adaptive_record_validation import validate_v4_attempt_record
from bluefire.adaptive_runtime import propose_reviewed_method
from bluefire.ai import (
    AIProposal,
    AIProviderCancelled,
    AIProviderError,
    AIProviderResult,
    validate_persisted_proposal_record,
)
from bluefire.config import AutonomyLevel, load_config
from bluefire.contracts import ExecutionMode, StepOutcome, load_scenario
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.planner import DeterministicPlanner
from bluefire.registry import load_builtin_registry
from bluefire.util import canonical_json_bytes, content_hash

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def runtime():
    registry = load_builtin_registry()
    planner = DeterministicPlanner(registry)
    scenario = load_scenario(ROOT / "bluefire/data/ai_adaptive_safe_chain.yaml")
    config = load_config(ROOT / "config/bluefire.example.yaml")
    provider_config = config.ai.providers[0]
    plan = planner.compile(scenario, mode=ExecutionMode.SIMULATE, autonomy=AutonomyLevel.AUTO)
    first = replace(plan.steps[0], action_id="sandbox.fixture.create.v1", simulation_id=None)
    # The selector consumes an already validated authority. Contract compilation
    # tests separately establish compatible real registry methods and bounds.
    methods = [
        first,
        replace(first, action_id="sandbox.fixture.transform.v1"),
        replace(first, action_id="sandbox.discovery.list.v1"),
    ]
    row = {
        "step_id": first.step_id,
        "behavior_id": first.behavior_id,
        "action_id": first.action_id,
        "status": "failed",
        "evidence_ids": [],
    }
    decision = planner.decide_next(
        run_id="run-20260912T000000Z-0000000000000001",
        scenario=scenario,
        plan=plan,
        current_step_id=first.step_id,
        outcome=StepOutcome.FAILED,
        state={"steps": [row], "artifacts": {}},
        completed_steps=1,
    )
    kwargs = dict(
        run_id=decision.run_id,
        plan=replace(plan, mode=ExecutionMode.EXECUTE),
        current_step=first,
        outcome="failed",
        decision=decision,
        authorization={
            "authorization_digest": content_hash("reviewed"),
            "steps": [
                {
                    "step_id": first.step_id,
                    "methods": [{"plan_step": step.to_dict()} for step in methods],
                }
            ],
        },
        policy={"on_provider_failure": "stop"},
        steps=[row],
        evidence=[],
        artifacts={},
        platform="linux",
        remaining_steps=4,
        remaining_seconds=30.0,
        retries_used=0,
        validate_choice=lambda step: None,
        check_cancelled=lambda: None,
    )
    return kwargs, provider_config


class Provider:
    def __init__(self, config, choose=None, *, proposal_type="select_registered_action"):
        self.config, self.choose, self.proposal_type = config, choose, proposal_type
        self.requests = []

    def propose(self, request):
        self.requests.append(request)
        action = self.choose(request) if self.choose else request.allowed_action_ids[0]
        selecting = self.proposal_type == "select_registered_action"
        proposal = AIProposal.from_mapping(
            {
                "schema_version": "bluefire.ai-proposal.v2",
                "proposal_type": self.proposal_type,
                "selected_step_id": request.allowed_step_ids[0] if selecting else None,
                "selected_behavior_id": request.allowed_behavior_ids[0] if selecting else None,
                "selected_action_id": action if selecting else None,
                "selected_edge": None,
                "parameter_changes": [],
                "rationale": "Use the observed result to choose a reviewed method.",
                "alternatives": [],
                "confidence": 0.8,
                "requires_operator_review": request.autonomy is AutonomyLevel.ASSIST,
            }
        )
        return AIProviderResult(
            self.config.id,
            self.config.id,
            self.config.model,
            proposal,
            "deterministic-test",
            1,
            False,
            None,
            {},
        )


def test_different_observed_failures_select_different_reviewed_methods(runtime):
    kwargs, config = runtime

    def choose(request):
        failure = request.context["observations"]["attempts"][-1]["failure"]["classification"]
        return request.allowed_action_ids[0 if failure == "execution_failure" else 1]

    provider = Provider(config, choose)
    a = propose_reviewed_method(**kwargs, provider=provider)
    row = {**kwargs["steps"][0], "error": {"code": "platform_blocked"}}
    b = propose_reviewed_method(**{**kwargs, "steps": [row]}, provider=provider)
    assert a.selected_step.action_id != b.selected_step.action_id
    assert (
        a.record["application_status"]
        == b.record["application_status"]
        == "applied_reviewed_method"
    )
    assert not a.stop and not b.stop
    for request, result in zip(provider.requests, (a, b), strict=True):
        contract = request.context["decision_contract"]
        assert contract["allowed_proposal_types"] == [
            "select_registered_action",
            "stop",
            "request_approval",
        ]
        assert len(request.context["registered_options"]) == 2
        assert result.record["planner_state"]["decision_contract"] == contract
        validate_v4_attempt_record(result.record)


def test_out_of_scope_choice_never_reaches_authority_callback(runtime):
    kwargs, config = runtime
    seen = []
    result = propose_reviewed_method(
        **{**kwargs, "validate_choice": seen.append},
        provider=Provider(config, lambda request: "sandbox.network.loopback.v1"),
    )
    assert result.stop and result.selected_step is None and seen == []
    assert result.record["application_status"] == "rejected_policy"
    assert result.record["provider"]["requested_provider_id"] == config.id
    assert result.record["proposal"]["selected_action_id"] == "sandbox.network.loopback.v1"
    validate_v4_attempt_record(result.record)


def test_stop_is_explicit_and_does_not_select_deterministic_successor(runtime):
    kwargs, config = runtime
    result = propose_reviewed_method(**kwargs, provider=Provider(config, proposal_type="stop"))
    assert result.stop and result.selected_step is None
    assert result.record["stop_requested"] is True


def test_assist_records_exact_choice_for_review(runtime):
    kwargs, config = runtime
    result = propose_reviewed_method(
        **{**kwargs, "plan": replace(kwargs["plan"], autonomy=AutonomyLevel.ASSIST)},
        provider=Provider(config),
    )
    assert result.stop and result.selected_step is None
    assert result.record["application_status"] == "awaiting_operator_approval"
    assert result.record["registered_step"]["action_id"] == "sandbox.fixture.transform.v1"
    assert (
        validate_persisted_proposal_record(result.record).selected_action_id
        == "sandbox.fixture.transform.v1"
    )


def test_durable_applied_choice_is_validated_and_method_tampering_rejected(runtime):
    kwargs, config = runtime
    result = propose_reviewed_method(**kwargs, provider=Provider(config))
    assert (
        validate_persisted_proposal_record(result.record).selected_action_id
        == result.selected_step.action_id
    )
    result.record["applied_step"] = {
        **result.record["applied_step"],
        "parameters": {"arbitrary": "value"},
    }
    with pytest.raises(AIProviderError, match="exact reviewed method"):
        validate_persisted_proposal_record(result.record)


def test_legacy_record_version_cannot_silently_gain_adaptive_authority(runtime):
    kwargs, config = runtime
    result = propose_reviewed_method(**kwargs, provider=Provider(config))
    result.record["schema_version"] = "bluefire.ai-proposal-record.v3"
    with pytest.raises(AIProviderError):
        validate_persisted_proposal_record(result.record)


def test_expiry_after_provider_latency_refuses_choice(runtime):
    kwargs, config = runtime

    def expired(step):
        raise ValueError("approval expired")

    result = propose_reviewed_method(
        **{**kwargs, "validate_choice": expired}, provider=Provider(config)
    )
    assert result.stop and result.selected_step is None


def test_cancellation_after_provider_return_never_applies(runtime):
    kwargs, config = runtime
    calls = []

    def cancelled():
        calls.append(True)
        if len(calls) > 1:
            raise AIProviderCancelled()

    with pytest.raises(AIProviderCancelled):
        propose_reviewed_method(
            **{**kwargs, "check_cancelled": cancelled}, provider=Provider(config)
        )


def test_configured_fallback_is_explicit_and_never_an_adaptive_choice(runtime):
    kwargs, config = runtime
    result = propose_reviewed_method(
        **{**kwargs, "policy": {"on_provider_failure": "deterministic"}},
        provider=Provider(config, proposal_type="no_change"),
    )
    assert result.selected_step is None and not result.stop
    assert result.record["decision_source"] == "configured_deterministic_fallback"
    assert result.record["application_status"] == "configured_fallback"


def test_missing_input_and_already_attempted_methods_are_not_offered(runtime):
    kwargs, config = runtime
    methods = kwargs["authorization"]["steps"][0]["methods"]
    for method in methods[1:]:
        method["plan_step"]["inputs"] = {"fixture": {"from_step": "missing", "artifact": "fixture"}}
    provider = Provider(config)
    result = propose_reviewed_method(**kwargs, provider=provider)
    assert result.stop and provider.requests == []
    validate_v4_attempt_record(result.record)
    with pytest.raises(AIProviderError, match="not a replayable proposal"):
        validate_persisted_proposal_record(result.record)


@pytest.mark.parametrize(
    "field,value", [("remaining_steps", 0), ("remaining_seconds", 0.0), ("retries_used", 1)]
)
def test_exhausted_budget_never_calls_provider(runtime, field, value):
    kwargs, config = runtime
    provider = Provider(config)
    result = propose_reviewed_method(**{**kwargs, field: value}, provider=provider)
    assert result.stop and provider.requests == []
    assert result.record["provider_called"] is False
    assert result.record["application_status"] == "stopped_budget_exhausted"
    validate_v4_attempt_record(result.record)


def test_failed_provider_call_retains_attempt_identity_without_a_replay_command(runtime):
    kwargs, config = runtime

    class Unavailable(Provider):
        def propose(self, request):
            raise AIProviderError("unavailable")

    result = propose_reviewed_method(**kwargs, provider=Unavailable(config))
    assert (
        result.record["provider_called"] is True
        and result.record["provider_attempt"]["provider_id"] == config.id
    )
    assert result.record["proposal"] is None and result.stop
    validate_v4_attempt_record(result.record)
    with pytest.raises(AIProviderError, match="not a replayable proposal"):
        validate_persisted_proposal_record(result.record)


def test_projection_preserves_observed_counts_without_logs_credentials_or_paths(runtime):
    kwargs, _ = runtime
    step = kwargs["current_step"]
    record = EvidenceRecord.create(
        run_id=kwargs["run_id"],
        step_id=step.step_id,
        behavior_id=step.behavior_id,
        provenance=EvidenceProvenance.OBSERVED,
        producer="test",
        target_scope_ref="sandbox.workspace",
        content={
            "record_count": 8,
            "retained_record_count": 0,
            "redacted_record_count": 8,
            "container": "gzip",
            "stdout": "private-log-secret",
            "path": "/private/data",
            "credential": "private-key-secret",
        },
    )
    projection = project_runtime_observations(
        steps=[{**kwargs["steps"][0], "evidence_ids": [record.evidence_id]}],
        records=[record],
        alternatives=[step],
        artifacts={},
        platform="linux",
        remaining_steps=3,
        remaining_seconds=12.0,
        retries_remaining=1,
    )
    facts = projection["attempts"][0]["evidence"][0]["facts"]
    assert facts["record_count"] == 8 and facts["redacted_record_count"] == 8
    assert facts["container"] == "gzip"
    assert projection["attempts"][0]["evidence"][0]["provenance"] == "observed"
    encoded = canonical_json_bytes(projection)
    assert b"private" not in encoded and b"stdout" not in encoded and b"credential" not in encoded


@pytest.mark.parametrize("provenance", [EvidenceProvenance.OBSERVED, EvidenceProvenance.EXECUTED])
def test_projection_separates_nested_observations_from_reported_output(runtime, provenance):
    kwargs, _ = runtime
    step = kwargs["current_step"]
    record = EvidenceRecord.create(
        run_id=kwargs["run_id"],
        step_id=step.step_id,
        behavior_id=step.behavior_id,
        provenance=provenance,
        producer="test",
        target_scope_ref="sandbox.workspace",
        content={
            "artifact_type": "collector_observation",
            "observed_fields": {
                "size_bytes": 700,
                "record_count": 8,
                "retained_record_count": 8,
                "empty_record_count": 0,
                "container": "jsonl",
                "path": "/private/file",
            },
            "output": {"size": 150, "stdout": "private-value", "credential": "private-value"},
        },
    )
    projection = project_runtime_observations(
        steps=[{**kwargs["steps"][0], "evidence_ids": [record.evidence_id]}],
        records=[record],
        alternatives=[step],
        artifacts={},
        platform="linux",
        remaining_steps=3,
        remaining_seconds=12.0,
        retries_remaining=1,
    )
    projected = projection["attempts"][0]["evidence"][0]
    assert projected["evidence_id"] == record.evidence_id
    assert projected["record_hash"] == record.record_hash
    assert projected["provenance"] == provenance.value
    if provenance is EvidenceProvenance.OBSERVED:
        assert projected["facts"] == {
            "artifact_type": "collector_observation",
            "size_bytes": 700,
            "record_count": 8,
            "retained_record_count": 8,
            "empty_record_count": 0,
            "container": "jsonl",
        }
    else:
        assert projected["facts"] == {
            "artifact_type": "collector_observation",
            "reported_size_bytes": 150,
        }
    assert b"private" not in canonical_json_bytes(projection)


@pytest.mark.parametrize(
    "code,policy,expected",
    [
        ("platform_blocked", "refused", "platform_mismatch"),
        ("target_scope_refused", "refused", "bluefire_authorization_refusal"),
        ("action_control_blocked", "control_blocked", "bluefire_control_refusal"),
        ("collection_output_limit", "allowed", "resource_limit"),
        ("artifact_limit_blocked", "allowed", "resource_limit"),
        ("adapter_refused", "allowed", "prerequisite_failure"),
        ("atomic_gzip_unavailable", "allowed", "prerequisite_failure"),
        ("unrecognized_failure", "allowed", "execution_failure"),
    ],
)
def test_product_refusal_never_claims_target_prevention(runtime, code, policy, expected):
    kwargs, _ = runtime
    projection = project_runtime_observations(
        steps=[{**kwargs["steps"][0], "error": {"code": code}, "policy": {"status": policy}}],
        records=[],
        alternatives=[],
        artifacts={},
        platform="linux",
        remaining_steps=3,
        remaining_seconds=12.0,
        retries_remaining=1,
    )
    failure = projection["attempts"][0]["failure"]
    assert failure["classification"] == expected
    assert failure["target_prevention"] == "not_established"
