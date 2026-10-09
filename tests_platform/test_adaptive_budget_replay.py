"""Replay budget continuity using compiler and authored provider fixtures only."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from bluefire.adaptive_budget import new_budget, record_attempt, reserve_method
from bluefire.adaptive_execution import compile_adaptive_authorization
from bluefire.adaptive_replay import validate_review_source
from bluefire.adaptive_runtime import propose_reviewed_method, reviewed_methods
from bluefire.approvals import execution_approval_binding
from bluefire.config import AutonomyLevel, load_config
from bluefire.contracts import ScenarioDefinition, StepOutcome
from bluefire.registry import load_builtin_registry
from bluefire.replay import ReplayError, ReplayRequest, prepare_replay
from bluefire.util import content_hash
from tests_platform.test_adaptive_authorization import POLICY, ROOT, SCOPE, setup
from tests_platform.test_adaptive_budget_authorization import compiled
from tests_platform.test_adaptive_runtime import Provider
from tests_platform.test_replay_selection import _install_checkpoint_stubs, _source, _Store


def replay_source():
    source = _source()
    policy = deepcopy(POLICY)
    policy["schema_version"] = "bluefire.adaptive-execution.v2"
    policy["steps"][0]["max_retries"] = 1
    source["scenario"]["adaptive_execution"] = policy
    authored = ScenarioDefinition.from_mapping(source["scenario"]).adaptive_execution
    primary, alternate = policy["steps"][0]["methods"]
    budget = record_attempt(
        new_budget(authored), authored, {"step_id": "discover_records", **primary}
    )
    source["adaptive_retry"] = reserve_method(
        budget, authored, {"step_id": "discover_records", **alternate}
    )
    return source


@pytest.mark.parametrize("kind", ["exact", "variant", "checkpoint"])
def test_replay_preserves_all_consumed_allowance_and_history_without_mutating_source(
    monkeypatch, kind
):
    source = replay_source()
    options = (
        {"exact": True} if kind != "variant" else {"defense_change": "Reviewed control change"}
    )
    if kind == "checkpoint":
        _install_checkpoint_stubs(monkeypatch, source)
        options["from_step_id"] = "discover_records"
    store = _Store(source)
    original = deepcopy(store.source)
    prepared = prepare_replay(
        store, load_builtin_registry(), ReplayRequest(source_run_id=source["run_id"], **options)
    )
    retained = prepared.lineage["adaptive_budget"]
    assert retained == original["adaptive_retry"]
    assert retained["used"] == 1 and retained["remaining"] == 0
    assert retained["per_step"]["discover_records"] == {"maximum": 1, "used": 1, "remaining": 0}
    assert len(retained["attempted_methods"]) == 2
    assert (
        prepared.scenario.to_dict()["adaptive_execution"]
        == source["scenario"]["adaptive_execution"]
    )
    assert (prepared.checkpoint is not None) is (kind == "checkpoint")
    assert store.source == original
    retained["attempted_methods"].clear()
    assert store.source == original


@pytest.mark.parametrize("change", ["missing", "bool_count", "refund", "policy"])
def test_execute_v2_replay_refuses_missing_or_inconsistent_source_ledger(change):
    source = replay_source()
    if change == "missing":
        source.pop("adaptive_retry")
    elif change == "bool_count":
        source["adaptive_retry"]["used"] = True
    elif change == "refund":
        source["adaptive_retry"]["used"] = 0
        source["adaptive_retry"]["remaining"] = 1
    else:
        source["adaptive_retry"]["policy_digest"] = content_hash("different policy")
    with pytest.raises(ReplayError, match="source adaptive pivot budget"):
        prepare_replay(
            _Store(source), load_builtin_registry(), ReplayRequest(source_run_id=source["run_id"])
        )


def test_replay_rejects_invalid_bundle_before_reading_its_ledger(monkeypatch):
    source = replay_source()
    store = _Store(source)
    monkeypatch.setattr(store, "validate_bundle", lambda _run_id: {"valid": False})
    monkeypatch.setattr(store, "get_run", lambda _run_id: pytest.fail("invalid source was read"))
    with pytest.raises(ReplayError, match="integrity validation"):
        prepare_replay(
            store, load_builtin_registry(), ReplayRequest(source_run_id=source["run_id"])
        )


def test_v1_replay_lineage_does_not_acquire_v2_fields():
    source = _source()
    source["scenario"]["adaptive_execution"] = deepcopy(POLICY)
    source["adaptive_retry"] = {"maximum": 1, "used": 1, "remaining": 0}
    prepared = prepare_replay(
        _Store(source),
        load_builtin_registry(),
        ReplayRequest(source_run_id=source["run_id"], exact=True),
    )
    assert "adaptive_budget" not in prepared.lineage
    assert prepared.scenario.to_dict()["adaptive_execution"] == POLICY
    assert source["adaptive_retry"] == {"maximum": 1, "used": 1, "remaining": 0}


def review_source(*, version=2):
    arguments, _ = compiled() if version == 2 else setup()
    plan = replace(arguments["plan"], autonomy=AutonomyLevel.ASSIST)
    arguments["plan"] = plan
    authority = compile_adaptive_authorization(**arguments)
    scenario = arguments["scenario"]
    policy = scenario.adaptive_execution
    groups = authority["steps"]
    step_id = "stage_collection" if version == 2 else "discover_records"
    current = reviewed_methods(authority, step_id)[0]
    row = {**current.to_dict(), "status": "failed", "evidence_ids": []}
    artifacts = {
        binding["from_step"]: {binding["artifact"]: {}} for binding in current.inputs.values()
    }
    run_id = "run-20261002T000000Z-0123456789abcdef"
    source = {
        "run_id": run_id,
        "mode": "execute",
        "scenario": scenario.to_dict(),
        "plan": plan.to_dict(),
        "profile": arguments["profile"].to_dict(),
        "autonomy": "assist",
        "ai_provider": plan.ai_provider,
        "runner_profile_id": arguments["profile"].id,
        "steps": [row],
        "policy": {
            "adaptive_authorization": authority,
            "authorized_target_scope": SCOPE,
            "approval_context": {},
        },
    }
    bound = execution_approval_binding(
        registry=arguments["registry"],
        scenario=scenario,
        plan=plan.to_dict(),
        profile=arguments["profile"],
        target_scope=SCOPE,
        autonomy=AutonomyLevel.ASSIST,
        ai_provider=plan.ai_provider,
        context={},
        adaptive_authorization=authority,
    )
    source["policy"]["approval_binding"] = bound
    consumed = {**bound, "status": "claimed"}
    budget_arguments = {}
    if version == 2:
        budget = record_attempt(new_budget(policy), policy, groups[0]["methods"][0]["plan_step"])
        budget = reserve_method(budget, policy, groups[0]["methods"][1]["plan_step"])
        budget = record_attempt(budget, policy, current.to_dict())
        source["adaptive_retry"] = budget
        budget_arguments = {
            "step_retries_used": 0,
            "attempted_methods": budget["attempted_methods"],
        }
    else:
        source["adaptive_retry"] = {"maximum": 1, "used": 0, "remaining": 1}
    used = source["adaptive_retry"]["used"]
    decision = arguments["planner"].decide_next(
        run_id=run_id,
        scenario=scenario,
        plan=plan,
        current_step_id=step_id,
        outcome=StepOutcome.FAILED,
        state={"steps": [row], "artifacts": artifacts},
        completed_steps=1,
        retries_used=used,
    )
    provider = Provider(load_config(ROOT / "config/bluefire.example.yaml").ai.providers[0])
    result = propose_reviewed_method(
        run_id=run_id,
        plan=plan,
        current_step=current,
        outcome="failed",
        decision=decision,
        authorization=authority,
        policy=policy.to_dict(),
        provider=provider,
        steps=[row],
        evidence=[],
        artifacts=artifacts,
        platform=arguments["platform"],
        remaining_steps=4,
        remaining_seconds=30.0,
        retries_used=used,
        validate_choice=lambda _step: None,
        check_cancelled=lambda: None,
        **budget_arguments,
    )
    assert result.record["application_status"] == "awaiting_operator_approval"
    return {
        "source": source,
        "record": result.record,
        "registry": arguments["registry"],
        "consumed_approval": consumed,
    }


def match_policy_to_ledger(values):
    budget = values["source"]["adaptive_retry"]
    record = values["record"]
    limit = budget["per_step"][record["current_step_id"]]
    record["proposal_policy"].update(
        adaptive_retries_used=budget["used"],
        step_retries_used=limit["used"],
        attempted_methods=deepcopy(budget["attempted_methods"]),
    )
    record["proposal_policy_digest"] = content_hash(record["proposal_policy"])


def test_assist_review_returns_detached_source_ledger_for_one_explicit_service_reservation():
    values = review_source()
    original = deepcopy(values["source"])
    budget = validate_review_source(**values)
    assert budget == original["adaptive_retry"]
    assert budget["used"] == 1
    policy = ScenarioDefinition.from_mapping(original["scenario"]).adaptive_execution
    reserved = reserve_method(budget, policy, values["record"]["registered_step"])
    assert reserved["used"] == 2
    assert reserved["per_step"]["stage_collection"]["used"] == 1
    assert values["source"] == original
    budget["attempted_methods"].clear()
    assert values["source"] == original


@pytest.mark.parametrize(
    "field,value",
    [
        ("adaptive_retries_used", 0),
        ("adaptive_retries_used", True),
        ("step_retries_used", 1),
        ("maximum_adaptive_retries", 2),
        ("maximum_step_retries", 1),
        ("adaptive_policy_digest", content_hash("another policy")),
        ("attempted_methods", []),
        ("on_provider_failure", "deterministic"),
    ],
)
def test_assist_review_rejects_rehashed_policy_counters_or_history_different_from_source(
    field, value
):
    values = review_source()
    values["record"]["proposal_policy"][field] = value
    values["record"]["proposal_policy_digest"] = content_hash(values["record"]["proposal_policy"])
    with pytest.raises(ValueError, match="retained source budget"):
        validate_review_source(**values)


@pytest.mark.parametrize("boundary", ["attempted", "exhausted"])
def test_assist_review_rejects_already_reserved_method_and_exhausted_allowance(boundary):
    values = review_source()
    source, record = values["source"], values["record"]
    policy = ScenarioDefinition.from_mapping(source["scenario"]).adaptive_execution
    source["adaptive_retry"] = reserve_method(
        source["adaptive_retry"], policy, record["registered_step"]
    )
    if boundary == "exhausted":
        last = source["policy"]["adaptive_authorization"]["steps"][1]["methods"][2]["plan_step"]
        source["adaptive_retry"] = reserve_method(source["adaptive_retry"], policy, last)
    match_policy_to_ledger(values)
    with pytest.raises(ValueError, match="exhausted or the method was already attempted"):
        validate_review_source(**values)


@pytest.mark.parametrize("boundary", ["unclaimed", "approval", "caps", "run", "method", "version"])
def test_assist_review_preserves_consumed_authority_and_source_identity(boundary):
    values = review_source()
    if boundary == "unclaimed":
        values["consumed_approval"]["status"] = "approved"
    elif boundary == "approval":
        values["consumed_approval"]["state_digest"] = content_hash("different approval")
    elif boundary == "caps":
        values["source"]["scenario"]["adaptive_execution"]["max_retries"] = 2
    elif boundary == "run":
        values["record"]["run_id"] = "run-20261002T000001Z-fedcba9876543210"
    elif boundary == "method":
        values["record"]["registered_step"]["parameters"] = {"stage_variant": "heldout"}
    else:
        values["record"]["schema_version"] = "bluefire.ai-proposal-record.v4"
    with pytest.raises(ValueError):
        validate_review_source(**values)


def test_v4_review_keeps_original_none_return_and_single_retry_rule():
    values = review_source(version=1)
    assert values["record"]["schema_version"] == "bluefire.ai-proposal-record.v4"
    assert validate_review_source(**values) is None
    values["source"]["adaptive_retry"] = {"maximum": 1, "used": 1, "remaining": 0}
    with pytest.raises(ValueError, match="one-retry lineage"):
        validate_review_source(**values)
