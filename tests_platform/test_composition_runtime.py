"""Controlled controller boundary tests, not native/provider execution evidence."""

import threading
import uuid
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import composition_context
from bluefire.capability_composition import compile_initial_graph
from bluefire.capability_facts import seal_facts
from bluefire.capability_resources import CapabilityContractError
from bluefire.composition_authority import GrantExecution, native_envelope
from bluefire.composition_jobs import CompositionJobs
from bluefire.config import load_config
from bluefire.contracts import ExecutionMode, ScenarioDefinition
from bluefire.job_runtime import JobCancelled
from bluefire.orchestrator import Orchestrator
from bluefire.planner import DeterministicPlanner
from bluefire.policy import ApprovalState, GrantPolicyState, PolicyEngine
from bluefire.product_store_errors import ProductStoreError
from bluefire.run_store import RunStore, RunStoreError
from bluefire.runner_contracts import _verified_grant_attempt, build_runner_profile
from bluefire.runner_inventory import (
    BUILTIN_RUNNER_ACTION_VERSIONS,
    RUNNER_ACTION_SDK_SCHEMA_VERSION,
)
from bluefire.service import BlueFireService
from bluefire.util import content_hash
from tests_platform.test_capability_composition import proposal, revision_state
from tests_platform.test_capability_composition import state as state
from tests_platform.test_orchestrator import StructuredFakeRunner
from tests_platform.test_product_store_capability_grants import reservation_args
from tests_platform.test_product_store_capability_grants import saved as saved


def profile():
    config = load_config(Path(__file__).resolve().parents[1] / "config/bluefire.example.yaml")
    return next(row for row in config.runner_profiles if row.mode is ExecutionMode.EXECUTE)


def compiled_plan(state):
    compiled = compile_initial_graph(proposal(), **state)
    plan = DeterministicPlanner(state["registry"]).compile(
        ScenarioDefinition.from_mapping(compiled["scenario"]),
        mode=ExecutionMode.EXECUTE,
        profile=profile(),
        autonomy="off",
        ai_enabled=False,
        action_implementations=compiled["action_implementations"],
    )
    return compiled, plan


def test_native_envelope_is_canonical_without_reordering_actual_plan(state, tmp_path):
    compiled, plan = compiled_plan(state)
    before = plan.to_dict()
    envelope = native_envelope(plan, compiled)
    native = build_runner_profile(profile(), sandbox_root=tmp_path, reviewed_execution=envelope)
    assert native["reviewed_execution"] == envelope
    assert [row["step_id"] for row in envelope["operations"]] != [s.step_id for s in plan.steps]
    document = {
        "schema_version": "bluefire.runner-grant-attempt.v1",
        "issuer": "capability-grant-controller.v1",
        "grant_id": state["grant"]["grant_id"],
        "grant_digest": state["grant"]["grant_digest"],
        "attempt_id": "attempt-" + "b" * 32,
        "lease_digest": content_hash("lease"),
        "compiled_digest": compiled["compiled_digest"],
        "plan_digest": content_hash(before),
        "native_envelope_digest": content_hash(envelope),
        "run_id": "run-test",
        "issued_at": "2026-10-03T00:00:00Z",
        "expires_at": "2026-10-03T00:01:00Z",
    }
    execution = GrantExecution(
        _verified_grant_attempt(document, expected_document_digest=content_hash(document)),
        envelope,
        lambda: None,
        lambda _: None,
        lambda *_: None,
        lambda *_: None,
        lambda *_: None,
    )
    assert execution.validate_plan(plan) == document
    assert plan.to_dict() == before
    with pytest.raises(ValueError, match="exact plan"):
        execution.validate_plan(replace(plan, steps=tuple(reversed(plan.steps))))


def test_credential_behavior_resolves_registered_handoff_without_alias_authority(state):
    compiled, _ = compiled_plan(state)
    source = deepcopy(compiled["scenario"])
    handoff = next(s for s in source["steps"] if s["behavior_id"] == "sandbox.peer.handoff.v1")
    handoff["behavior_id"] = "sandbox.credential.peer-challenge.v1"
    plan = DeterministicPlanner(state["registry"]).compile(
        ScenarioDefinition.from_mapping(source),
        mode=ExecutionMode.EXECUTE,
        profile=profile(),
        autonomy="off",
        ai_enabled=False,
    )
    actual = next(s for s in plan.steps if s.step_id == handoff["id"])
    assert actual.behavior_id == "sandbox.credential.peer-challenge.v1"
    assert actual.action_id == "sandbox.peer.handoff.v1"


def test_real_orchestrator_dispatches_exact_grant_manifest_without_ordinary_approval(
    state, tmp_path
):
    compiled, plan = compiled_plan(state)
    store = RunStore(tmp_path / "runs")
    root = tmp_path / "fresh-workspace"
    root.mkdir()
    envelope = native_envelope(plan, compiled)
    now = datetime.now(timezone.utc)
    document = {
        "schema_version": "bluefire.runner-grant-attempt.v1",
        "issuer": "capability-grant-controller.v1",
        "grant_id": state["grant"]["grant_id"],
        "grant_digest": state["grant"]["grant_digest"],
        "attempt_id": "attempt-" + "c" * 32,
        "lease_digest": content_hash("owned-lease"),
        "compiled_digest": compiled["compiled_digest"],
        "plan_digest": content_hash(plan.to_dict()),
        "native_envelope_digest": content_hash(envelope),
        "run_id": store._new_run_id(),
        "issued_at": (now - timedelta(seconds=2)).isoformat(),
        "expires_at": (now + timedelta(seconds=60)).isoformat(),
    }
    registered, terminals, profiles = [], [], []

    class Runner(StructuredFakeRunner):
        def inventory(self):
            result = super().inventory()
            result["actions"].append(
                {
                    "schema_version": RUNNER_ACTION_SDK_SCHEMA_VERSION,
                    "action_id": "sandbox.peer.handoff.v1",
                    "action_version": BUILTIN_RUNNER_ACTION_VERSIONS["sandbox.peer.handoff.v1"],
                    "readiness": "ready",
                }
            )
            return result

        def execute_task(self, manifest, runner_profile, *, task_id, **kwargs):
            assert registered == [task_id]
            assert manifest["approval"] is None
            assert manifest["grant_attempt"]["attempt_id"] == document["attempt_id"]
            assert "grant_cleanup" not in manifest
            assert (
                content_hash(runner_profile["reviewed_execution"])
                == document["native_envelope_digest"]
            )
            self.calls.append((manifest, runner_profile))
            return {
                "schema_version": "bluefire.runner-result.v1",
                **{
                    key: manifest[key]
                    for key in (
                        "request_id",
                        "run_id",
                        "step_id",
                        "behavior_id",
                        "action_id",
                        "runner_id",
                        "runner_profile_id",
                        "request_hash",
                    )
                },
                "policy_digest": runner_profile["policy_digest"],
                "platform": runner_profile["platform"],
                "status": "control_blocked",
                "output": None,
                "stdout": {"bytes": 0, "truncated": False},
                "stderr": {"bytes": 0, "truncated": False},
                "evidence": [],
                "receipt_ids": [],
                "cleanup": None,
                "error": {
                    "code": "controlled_test_refusal",
                    "message": "Controlled boundary test; no native effects.",
                },
                "limitations": [],
            }

        def execute(self, *_):
            raise AssertionError("Grant cannot use legacy transport")

    runner = Runner()
    execution = GrantExecution(
        _verified_grant_attempt(document, expected_document_digest=content_hash(document)),
        envelope,
        lambda: None,
        profiles.append,
        lambda step, inputs, manifest, task_id: registered.append(task_id),
        lambda step, manifest, task_id, result, **kwargs: terminals.append(
            (task_id, result, kwargs)
        ),
        lambda *_: (_ for _ in ()).throw(AssertionError("No effects need no cleanup authority")),
    )
    result = Orchestrator(state["registry"], store, runner=runner, grant_execution=execution).run(
        ScenarioDefinition.from_mapping(compiled["scenario"]),
        mode=ExecutionMode.EXECUTE,
        profile=profile(),
        sandbox_root=root,
        target_scope={"scope_refs": ["sandbox.workspace", "network.loopback"]},
        autonomy="off",
        ai_enabled=False,
        action_implementations=compiled["action_implementations"],
    )
    assert len(runner.calls) == len(registered) == len(terminals) == len(profiles) == 1
    assert terminals[0][2] == {"observed_receipt_ids": ()}
    assert result["run_id"] == document["run_id"]
    assert store.get_run(result["run_id"])["policy"]["grant_attempt"] == execution.document()


@pytest.mark.parametrize("approval_required", [True, False])
@pytest.mark.parametrize("invalid", ["expired", "action", "kind", "approval_conflict"])
def test_delegated_policy_is_exact_even_without_ordinary_approval_threshold(
    state, approval_required, invalid
):
    _, plan = compiled_plan(state)
    step = plan.steps[0]
    selected = replace(profile(), approval_required=approval_required)
    scope = {"scope_refs": ["sandbox.workspace"]}
    now = datetime.now(timezone.utc)
    issued, expires = (now - timedelta(seconds=10)).isoformat(), (
        now + timedelta(seconds=30)
    ).isoformat()
    grant = GrantPolicyState(
        "capability_grant_attempt",
        issued,
        expires,
        content_hash("request"),
        step.action_id,
        selected.id,
        content_hash(scope),
    )
    if invalid == "expired":
        grant = replace(grant, expires_at=(now - timedelta(seconds=1)).isoformat())
    elif invalid == "action":
        grant = replace(grant, action_id="sandbox.cleanup.v1")
    elif invalid == "kind":
        grant = replace(grant, authority_kind="operator")
    approval = None
    if invalid == "approval_conflict":
        approval = ApprovalState(
            "bluefire.approval.v1",
            "operator",
            issued,
            expires,
            grant.request_hash,
            step.action_id,
            selected.id,
            content_hash(scope),
            "nonce",
        )
    decision = PolicyEngine().evaluate(
        step=step,
        action=state["registry"].get_action(step.action_id),
        mode=ExecutionMode.EXECUTE,
        profile=selected,
        platform="linux",
        target_scope=scope,
        request_hash=grant.request_hash,
        approval=approval,
        grant=grant,
    )
    assert not decision.allowed
    assert any("delegat" in reason or "cannot combine" in reason for reason in decision.reasons)


def test_reserved_run_id_is_exclusive_and_cannot_adopt_existing_folder(tmp_path):
    store = RunStore(tmp_path / "runs")
    identifier = store._new_run_id()
    args = dict(scenario={"id": "test"}, plan={"steps": []}, policy={}, profile=None)
    handle = store.create_run(**args, _reserved_run_id=identifier)
    assert handle.run_id == identifier
    before = (handle.path / "scenario.json").read_bytes()
    with pytest.raises(RunStoreError):
        store.create_run(**args, _reserved_run_id=identifier)
    assert (handle.path / "scenario.json").read_bytes() == before
    with pytest.raises(RunStoreError):
        store.create_run(**args, _reserved_run_id="../outside")


@pytest.fixture
def controller(saved, tmp_path, monkeypatch):
    store, state, compiled, _ = saved
    current = {
        **state,
        "profile": profile(),
        "sandbox": tmp_path / "sandbox",
        "collector_runtime": None,
        "collector_ids": [],
        "runner_readiness": {},
        "run_intent": {"target_scope": {"scope_refs": ["sandbox.workspace", "network.loopback"]}},
    }
    clock = [3000]

    class Jobs:
        def __init__(self):
            self.cancelled = []

        def submit(self, kind, request, *, submission_id, intent_digest, callback):
            return store.create_idempotent_job(
                kind, request, submission_id=submission_id, intent_digest=intent_digest
            )[0]

        def cancel(self, job_id):
            self.cancelled.append(job_id)

    service = SimpleNamespace(
        product_store=store,
        job_controller=Jobs(),
        store=RunStore(tmp_path / "runs"),
        _isolated_owned_sandbox=lambda root, attempt: root / attempt,
        _index_run=lambda result: None,
        composition_ai=SimpleNamespace(stop_owner=lambda owner_id: None),
    )
    jobs = CompositionJobs(service, clock=lambda: clock[0])
    monkeypatch.setattr(composition_context, "resolve", lambda *_: current)
    return jobs, state, compiled, current, clock


def test_initial_validation_has_no_reservation_and_retry_does_not_create_second_attempt(controller):
    jobs, state, _, _, _ = controller
    owner_id = state["parent_job_id"]
    compiled = jobs.validate_proposal(owner_id, proposal())
    assert compiled["revision_kind"] == "initial"
    assert jobs.read(owner_id)["attempts"] == []
    request = {"submission_id": str(uuid.uuid4()), "proposal": proposal(), "prior_attempt_id": None}
    first = jobs.attempt(owner_id, request)
    repeated = jobs.attempt(owner_id, request)
    assert len(first["attempts"]) == len(repeated["attempts"]) == 1
    with pytest.raises(ProductStoreError, match="not settled"):
        jobs.validate_proposal(owner_id, proposal())


def test_authorize_recovers_same_grant_after_parent_publication_failure(controller, monkeypatch):
    jobs, state, _, _, _ = controller
    reviewed = {
        key: state["grant"][key] for key in ("objective", "environment", "limits", "snapshot")
    }
    reviewed["review_digest"] = content_hash(reviewed)
    monkeypatch.setattr(jobs, "review", lambda request: reviewed)
    monkeypatch.setattr(
        jobs.store,
        "save_capability_grant",
        lambda *_, **__: (_ for _ in ()).throw(
            AssertionError("Existing immutable grant cannot be resaved")
        ),
    )
    result = jobs.authorize(
        {
            "submission_id": str(uuid.UUID(state["grant"]["grant_id"][6:])),
            "review": {
                "control_owner_id": state["grant"]["environment"]["control_owner_id"],
                "question": state["grant"]["objective"]["question"],
                "limits": state["grant"]["limits"],
            },
            "reviewed_by": state["grant"]["approved_by"],
            "review_digest": reviewed["review_digest"],
        }
    )
    assert result["owner"]["job_id"] == "job-" + state["grant"]["grant_id"][6:]
    assert result["grant"]["document"] == state["grant"]


def test_context_refuses_unadmitted_parent_before_provider_access(controller):
    jobs, state, _, _, _ = controller
    jobs._publish(state["parent_job_id"], {"admission": {"accepted": False, "problem": "changed"}})
    with pytest.raises(ProductStoreError, match="not admitted"):
        jobs.proposal_context(state["parent_job_id"])


@pytest.mark.parametrize("change", ["accepted", "cleanup", "count"])
def test_revision_context_rejects_unusable_prior_before_model_access(
    controller, monkeypatch, change
):
    jobs, state, _, _, _ = controller
    facts = revision_state({key: value for key, value in state.items() if key != "parent_job_id"})[
        "facts"
    ]
    result = next(row for row in facts["facts"] if row["kind"] == "receiver_result")
    if change == "accepted":
        result["value"]["decision"] = "accepted"
    elif change == "cleanup":
        next(row for row in facts["facts"] if row["kind"] == "cleanup")["value"]["run"] = "unknown"
    else:
        result["value"]["record_count"] = 7
        result["value"]["retained_record_count"] = 7
    facts = seal_facts({key: value for key, value in facts.items() if key != "facts_digest"})
    monkeypatch.setattr(jobs, "_facts", lambda *_: facts)
    with pytest.raises(CapabilityContractError, match="observed refusal and settled"):
        jobs.proposal_context(state["parent_job_id"], prior_attempt_id=facts["prior_attempt_id"])


def test_fresh_policy_fact_projection_is_stable_across_review_submit_clock_ticks(controller):
    jobs, state, _, _, clock = controller
    first = jobs._facts(state["grant"])
    clock[0] += 1234
    assert jobs._facts(state["grant"]) == first


def test_prior_evidence_cannot_be_borrowed_from_another_grant(controller, saved, monkeypatch):
    jobs, state, compiled, _, _ = controller
    args = reservation_args(saved)
    jobs.store.reserve_capability_attempt(state["grant"]["grant_id"], compiled, **args)
    other = deepcopy(state["grant"])
    other["grant_id"] = "grant-" + "f" * 32
    monkeypatch.setattr(
        jobs,
        "_verified_result",
        lambda *_: (_ for _ in ()).throw(
            AssertionError("Must reject before reading unrelated evidence")
        ),
    )
    with pytest.raises(ProductStoreError, match="another delegated objective"):
        jobs._facts(other, args["attempt_id"])


def test_stop_persists_revocation_before_cancelling_owned_jobs(controller):
    jobs, state, _, _, _ = controller
    owner_id = state["parent_job_id"]
    jobs.stop(owner_id, revoke=True)
    assert jobs.read(owner_id)["grant"]["status"] == "revoked"
    with pytest.raises(ProductStoreError):
        jobs.validate_proposal(owner_id, proposal())


def test_model_cancellation_failure_does_not_skip_native_cancellation(controller, saved):
    jobs, state, compiled, _, _ = controller
    args = reservation_args(saved)
    jobs.store.reserve_capability_attempt(state["grant"]["grant_id"], compiled, **args)
    jobs.service.composition_ai.stop_owner = lambda *_: (_ for _ in ()).throw(
        RuntimeError("model stop failed")
    )
    with pytest.raises(RuntimeError, match="model stop failed"):
        jobs.stop(state["parent_job_id"])
    assert jobs.service.job_controller.cancelled == [args["job_id"]]
    assert jobs.read(state["parent_job_id"])["grant"]["status"] == "paused"


def exercise_attempt(controller, saved, monkeypatch, *, mode):
    jobs, state, compiled, current, clock = controller
    args = reservation_args(saved)
    lease = jobs.store.reserve_capability_attempt(state["grant"]["grant_id"], compiled, **args)
    claim = jobs.store.claim_capability_attempt(
        args["attempt_id"],
        lease_digest=lease["lease_digest"],
        current_environment=state["current_environment"],
        now_ms=clock[0],
    )
    marker = jobs.store.get_job(args["job_id"])["request"]["composition_attempt"]
    session = {"receiver_session_id": "session-generation", "review_digest": content_hash("review")}

    class Owners:
        def prepare(self, *_):
            return session

        def observe_bound(self, *_):
            return {"state": "insufficient", "reason": "Controlled no-provider boundary test."}

        def close(self, job_id):
            jobs._publish(job_id, {"receiver_cleanup_receipt": {"test_owned_close": True}})
            return True

    jobs.owners = Owners()
    step = SimpleNamespace(
        step_id=compiled["scenario"]["steps"][0]["id"], action_id="sandbox.fixture.create.v1"
    )
    native_profile = {
        "policy_digest": content_hash("sealed-profile"),
        "sandbox_root": str(current["sandbox"] / args["attempt_id"]),
    }
    request_hash = content_hash("business-request")
    task_id = "task-boundary-1"
    manifest = {"action_id": step.action_id, "request_hash": request_hash}
    seen = {}

    class Run:
        def run(self, *_, **kwargs):
            execution = seen["execution"]
            execution.bind_profile(native_profile)
            execution.before_task(step, {}, manifest, task_id)
            assert (
                jobs.store.get_capability_attempt(args["attempt_id"])["tasks"][0]["task_id"]
                == task_id
            )
            if mode == "unknown":
                raise RuntimeError("unverified transport")
            if mode in {"not_sent", "blocked"}:
                terminal = (
                    {
                        "schema_version": "bluefire.task-not-sent.v1",
                        "task_id": task_id,
                        "request_hash": request_hash,
                    }
                    if mode == "not_sent"
                    else {"status": "control_blocked", "receipt_ids": []}
                )
                execution.after_task(step, manifest, task_id, terminal, observed_receipt_ids=())
                if mode == "blocked":
                    assert (
                        execution.cleanup_authority(native_profile, {"receipt_ids": []}, {}) is None
                    )
                raise JobCancelled("controlled stop before graph cleanup")
            execution.after_task(
                step, manifest, task_id, {"status": "success", "receipt_ids": ["c" * 64]}
            )
            if mode == "cleanup_expired":
                clock[0] = lease["attempt_expires_at_ms"] + 1
            elif mode == "expired":
                clock[0] = lease["business_expires_at_ms"] + 1
            else:
                jobs.store.change_capability_grant_state(
                    state["grant"]["grant_id"], status="revoked", now_ms=clock[0]
                )
            with pytest.raises((JobCancelled, ProductStoreError)):
                execution.check()
            assert kwargs["cancel_event"].wait(1)
            discovered = {"c" * 64: {"request_hash": request_hash, "workspace_id": "d" * 64}}
            if mode == "omitted_receipt":
                discovered["e" * 64] = {"request_hash": request_hash, "workspace_id": "d" * 64}
            cleanup = execution.cleanup_authority(
                native_profile,
                {"receipt_ids": ["c" * 64]},
                discovered,
            )
            cleanup_manifest = {
                "grant_cleanup": cleanup.to_dict(),
                "request_hash": content_hash("cleanup-request"),
            }
            cleanup_step = SimpleNamespace(step_id="clean", action_id="sandbox.cleanup.v1")
            execution.before_task(cleanup_step, {}, cleanup_manifest, "task-cleanup")
            execution.after_task(
                cleanup_step,
                cleanup_manifest,
                "task-cleanup",
                {"status": "success", "cleanup": {"verification_performed": True}},
            )
            seen["cleanup"] = cleanup
            raise JobCancelled("controlled stop after separate cleanup")

    def orchestrator(current, **kwargs):
        seen.update(execution=kwargs["grant_execution"])
        return Run()

    monkeypatch.setattr(jobs, "_orchestrator", orchestrator)
    ctx = SimpleNamespace(
        job_id=args["job_id"], cancellation_event=threading.Event(), checkpoint=lambda: None
    )
    with pytest.raises((JobCancelled, RuntimeError, ProductStoreError)):
        jobs._run_attempt(
            ctx,
            marker,
            compiled,
            state["grant"],
            current,
            ScenarioDefinition.from_mapping(compiled["scenario"]),
            {},
            lease,
            claim,
        )
    return (
        jobs.store.get_capability_attempt(args["attempt_id"]),
        jobs.store.get_job(args["job_id"])["progress"],
        seen,
    )


@pytest.mark.parametrize("mode", ["not_sent", "blocked"])
def test_verified_no_effects_settle_without_fake_native_cleanup(
    controller, saved, monkeypatch, mode
):
    attempt, progress, seen = exercise_attempt(controller, saved, monkeypatch, mode=mode)
    assert attempt["state"] == "settled"
    assert progress["native_cleanup"]["no_effects"]["terminals"]
    assert "report" not in progress["native_cleanup"]
    assert "cleanup" not in seen


@pytest.mark.parametrize("mode", ["revoked", "expired"])
def test_separate_receipt_cleanup_can_finish_after_business_authority_ends(
    controller, saved, monkeypatch, mode
):
    attempt, progress, seen = exercise_attempt(controller, saved, monkeypatch, mode=mode)
    assert attempt["state"] == "settled"
    assert seen["cleanup"].to_dict()["runner_policy_digest"] == content_hash("sealed-profile")
    assert progress["native_cleanup"]["report"]["verification_performed"] is True


def test_unknown_transport_stays_unsettled_despite_receiver_close(controller, saved, monkeypatch):
    attempt, progress, _ = exercise_attempt(controller, saved, monkeypatch, mode="unknown")
    assert attempt["state"] == "claimed"
    assert progress["settlement"] == "pending_cleanup"


def test_cleanup_deadline_is_not_extended_to_close_a_late_attempt(controller, saved, monkeypatch):
    attempt, progress, seen = exercise_attempt(
        controller, saved, monkeypatch, mode="cleanup_expired"
    )
    assert attempt["state"] == "claimed"
    assert progress["settlement"] == "pending_cleanup"
    assert "cleanup" not in seen


def test_cleanup_cannot_omit_an_independently_discovered_same_task_receipt(
    controller, saved, monkeypatch
):
    attempt, progress, seen = exercise_attempt(
        controller, saved, monkeypatch, mode="omitted_receipt"
    )
    assert attempt["state"] == "claimed"
    assert progress["settlement"] == "pending_cleanup"
    assert "cleanup" not in seen


@pytest.mark.parametrize("action", ["stop", "revoke", "continue"])
def test_service_controls_reject_extra_authority_input(action):
    with pytest.raises(ProductStoreError, match="empty"):
        BlueFireService.control_composition(SimpleNamespace(), "owner", action, {"grant": {}})


def test_service_proposal_context_requires_explicit_prior_attempt_field():
    with pytest.raises(ProductStoreError, match="prior attempt"):
        BlueFireService.composition_proposal_context(SimpleNamespace(), "owner", {})


def test_objective_list_reopens_saved_work_without_mutation(controller):
    jobs, state, _, _, _ = controller
    listed = jobs.objectives(state["grant"]["environment"]["control_owner_id"])
    assert listed["objectives"] == [
        {
            "owner_id": state["parent_job_id"],
            "title": state["grant"]["objective"]["question"],
            "status": "active",
            "job_state": "completed",
        }
    ]
    assert jobs.objectives("unrelated")["objectives"] == []
    assert jobs.read(state["parent_job_id"])["attempts"] == []
