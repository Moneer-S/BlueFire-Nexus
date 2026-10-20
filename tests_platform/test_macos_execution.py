"""Existing executor/closure lifecycle with in-memory transports and storage only."""

from datetime import datetime, timezone
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

from bluefire import composition_dispatch, macos_execution, orchestrator
from bluefire.config import AutonomyLevel
from bluefire.contracts import ExecutionMode, SafetyTier, StepOutcome
from bluefire.evidence import EvidenceGraph
from bluefire.planner import ExecutionDisposition, PlanStep
from bluefire.policy import GrantPolicyState, PolicyError
from bluefire.product_store_errors import ProductStoreError
from bluefire.runner_adapter import AdaptedAction
from bluefire.runner_client import RunnerTransportError
from bluefire.runner_contracts import _verified_macos_file_access_cleanup
from bluefire.util import content_hash

CLOSE = macos_execution.CLOSE_ACTION
WALL = 1_800_000_000_000
SCOPE = {"scope_refs": ["sandbox.workspace"]}


def cleanup_authority():
    claim = {
        "schema_version": "bluefire.macos-file-access-artifact-closure-claim.v1",
        "attempt_id": "attempt-" + "a" * 32,
        "lease_digest": "sha256:" + "b" * 64,
        "compiled_digest": "sha256:" + "c" * 64,
        "run_id": "run-test",
        "cleanup_step_id": "close",
        "issued_at_ms": WALL,
        "expires_at_ms": WALL + 10_000,
        "issued_monotonic_ns": 100,
        "deadline_ns": 10_000_000_100,
        "scope": "attempt_artifact_closure_only",
    }
    return _verified_macos_file_access_cleanup(claim, expected_document_digest=content_hash(claim))


def step(action=CLOSE, identity="close"):
    return PlanStep(
        step_id=identity,
        behavior_id=action,
        action_id=action,
        simulation_id=None,
        parameters={},
        inputs={},
        expected_outputs=("closure",),
        required_capabilities=("cleanup",),
        safety_tier=SafetyTier.CONTROLLED,
        alternates=(),
    )


def test_mac_policy_keeps_original_claim_dates_and_distinct_authority_kind():
    original = cleanup_authority().to_dict()
    manifest = {"macos_file_access_cleanup": original, "request_hash": "sha256:" + "d" * 64}
    state = composition_dispatch.policy_state(object(), manifest, CLOSE, "profile", SCOPE)
    assert state.authority_kind == "macos_file_access_cleanup"
    assert int(datetime.fromisoformat(state.issued_at).timestamp() * 1000) == WALL
    assert int(datetime.fromisoformat(state.expires_at).timestamp() * 1000) == WALL + 10_000
    state.validate(
        request_hash=manifest["request_hash"],
        action_id=CLOSE,
        runner_profile_id="profile",
        target_scope_digest=content_hash(SCOPE),
        now=datetime.fromtimestamp((WALL + 1) / 1000, timezone.utc),
    )
    with pytest.raises(PolicyError, match="not currently valid"):
        state.validate(
            request_hash=manifest["request_hash"],
            action_id=CLOSE,
            runner_profile_id="profile",
            target_scope_digest=content_hash(SCOPE),
            now=datetime.fromtimestamp((WALL + 10_000) / 1000, timezone.utc),
        )


@pytest.mark.parametrize(
    "kind,action",
    [
        ("macos_file_access_cleanup", "sandbox.cleanup.v1"),
        ("macos_file_access_cleanup", "macos.file_access.probe.v1"),
        ("capability_grant_cleanup", "macos.file_access.close_attempt.v1"),
        ("capability_grant_attempt", "macos.file_access.close_attempt.v1"),
    ],
)
def test_cleanup_authority_cannot_cross_native_or_business_operations(kind, action):
    state = GrantPolicyState(
        kind, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z", "hash", action, "profile", "scope"
    )
    with pytest.raises(PolicyError):
        state.validate(
            request_hash="hash",
            action_id=action,
            runner_profile_id="profile",
            target_scope_digest="scope",
        )


@pytest.fixture
def executor(monkeypatch):
    engine = object.__new__(orchestrator.Orchestrator)
    engine.macos_file_access_binding = object()
    engine._macos_close_attempted = False
    engine.before_receiver_task = None
    engine._execution_task_id = lambda manifest, profile: "execute-" + "e" * 64
    calls = []
    original = cleanup_authority()
    profile = SimpleNamespace(id="profile", environment_type=SimpleNamespace(value="disposable"))
    sealed = {"platform": "macos", "policy_digest": "sha256:" + "f" * 64}

    def business_check():
        pytest.fail("attempt closure consulted business authority")

    def claim(runner_profile, params, receipts):
        assert runner_profile is sealed and params == {} and receipts == {}
        calls.append("claim")
        return original

    def before_task(row, inputs, manifest, task_id):
        assert (
            row.action_id == CLOSE and manifest["macos_file_access_cleanup"] == original.to_dict()
        )
        calls.append("register")

    engine.grant_execution = SimpleNamespace(
        check=business_check,
        cleanup_authority=claim,
        before_task=before_task,
        after_task=lambda *args, **kwargs: calls.append("terminal"),
    )
    engine.registry = SimpleNamespace(
        get_action=lambda action: SimpleNamespace(id=action),
        get_behavior=lambda behavior: SimpleNamespace(telemetry=("attempt.closed",)),
    )
    engine.adapter = SimpleNamespace(
        adapt=lambda *args, **kwargs: AdaptedAction(params={}, filesystem_scope=()),
        logical_outputs=lambda *args, **kwargs: {"closure": {"type": "fake-closure"}},
    )

    def manifest(**kwargs):
        assert kwargs["macos_file_access_cleanup"] is original
        assert kwargs["now_monotonic_ns"] == 101
        assert "grant_attempt" not in kwargs and "grant_cleanup" not in kwargs
        assert kwargs["timeout_ms"] is None
        calls.append("manifest")
        return {
            "request_id": "request",
            "run_id": "run-test",
            "step_id": "close",
            "behavior_id": CLOSE,
            "action_id": CLOSE,
            "runner_id": "original",
            "runner_profile_id": "profile",
            "request_hash": "sha256:" + "d" * 64,
            "macos_file_access_cleanup": original.to_dict(),
            "limits": {"max_files": 1, "max_artifact_bytes": 1},
        }

    def policy(**kwargs):
        assert kwargs["grant"].authority_kind == "macos_file_access_cleanup"
        return SimpleNamespace(allowed=True, to_dict=lambda: {"status": "allowed"})

    def execute_task(manifest, runner_profile, *, cancel_event, **kwargs):
        assert not cancel_event.is_set()
        calls.append("dispatch")
        return {
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
            "schema_version": "bluefire.runner-result.v1",
            "platform": "macos",
            "policy_digest": sealed["policy_digest"],
            "status": "success",
            "receipt_ids": [],
            "output": {"attempt_closure": {"synthetic": True}},
        }

    class MemoryStore:
        root = Path("/synthetic/runs")

        def __init__(self):
            self.documents = {"result.json": {}, "evidence.json": {"records": []}}
            self.events = []

        def read_json(self, run_id, name):
            return self.documents[name]

        def write_json(self, run_id, name, value):
            self.documents[name] = value

        def append_event(self, run_id, name, value):
            self.events.append((name, value))

    engine.store = MemoryStore()
    engine.policy = SimpleNamespace(evaluate=policy)
    engine.runner = SimpleNamespace(execute_task=execute_task)
    engine._discover_runner_receipts = lambda *args, **kwargs: pytest.fail(
        "Mac task scanned native filesystem receipts"
    )
    monkeypatch.setattr(orchestrator, "build_execution_manifest", manifest)
    monkeypatch.setattr(orchestrator, "reviewed_operation", lambda *args: None)
    monkeypatch.setattr(orchestrator, "service_grant_kwargs", lambda *args: {})
    from bluefire import macos_file_access_peer

    monkeypatch.setattr(macos_file_access_peer, "darwin_clock_ns", lambda: 101)
    arguments = {
        "profile": profile,
        "runner_profile": sealed,
        "observer": SimpleNamespace(root=Path("/synthetic/attempt")),
        "approved_by": None,
        "approval_record": None,
        "authorized_target_scope": SCOPE,
    }
    return SimpleNamespace(engine=engine, calls=calls, arguments=arguments, original=original)


def test_existing_step_executor_closes_with_separate_event_after_business_cancel(executor):
    cancelled = Event()
    cancelled.set()
    row, records, _, receipts = executor.engine._execute_step(
        run_id="run-test",
        step=step(),
        bound_inputs={},
        parent_ids=(),
        receipt_ids=[],
        cancel_event=cancelled,
        action_timeout_ms=0,
        reviewed_step_check=lambda: pytest.fail("closure used business deadline check"),
        **executor.arguments,
    )
    assert row["status"] == "success" and receipts == () and row["cleanup"] is None
    assert executor.calls == ["claim", "manifest", "register", "dispatch", "terminal"]
    assert records[0].producer == "bluefire-macos-original-workspace"
    assert "whole enrollment cleanup" in records[0].limitations[-1]
    macos_execution.emergency_attempt_close(
        executor.engine,
        plan=SimpleNamespace(steps=[step()]),
        run_id="run-test",
        **executor.arguments,
    )
    with pytest.raises(orchestrator.OrchestrationError, match="already attempted"):
        executor.engine._execute_step(
            run_id="run-test",
            step=step(),
            bound_inputs={},
            parent_ids=(),
            receipt_ids=[],
            **executor.arguments,
        )
    assert executor.calls.count("claim") == 1


@pytest.mark.parametrize("boundary", ["claim", "registration", "transport"])
def test_any_close_attempt_failure_has_no_emergency_replay(executor, boundary):
    def fail(*args, **kwargs):
        raise RunnerTransportError("synthetic " + boundary)

    if boundary == "claim":
        executor.engine.grant_execution.cleanup_authority = fail
    elif boundary == "registration":
        executor.engine.grant_execution.before_task = fail
    else:
        executor.engine.runner.execute_task = fail
    try:
        executor.engine._execute_step(
            run_id="run-test",
            step=step(),
            bound_inputs={},
            parent_ids=(),
            receipt_ids=[],
            **executor.arguments,
        )
    except RunnerTransportError:
        pass
    before = list(executor.calls)
    macos_execution.emergency_attempt_close(
        executor.engine,
        plan=SimpleNamespace(steps=[step()]),
        run_id="run-test",
        **executor.arguments,
    )
    assert executor.engine._macos_close_attempted is True
    assert executor.calls == before


def test_unknown_read_prevents_claim_and_never_dispatches_a_close(executor):
    def deny(*args):
        raise ValueError("unknown dispatched read has no close authority")

    executor.engine.grant_execution.cleanup_authority = deny
    macos_execution.emergency_attempt_close(
        executor.engine,
        plan=SimpleNamespace(steps=[step()]),
        run_id="run-test",
        **executor.arguments,
    )
    assert executor.calls == []
    assert executor.engine.store.documents["result.json"]["attempt_closure"]["success"] is False
    assert executor.engine._macos_close_attempted is True


def test_interruption_without_receipts_uses_same_step_executor_and_scoped_summary(executor):
    executor.engine._attempt_emergency_cleanup(
        run_id="run-test",
        plan=SimpleNamespace(steps=[step()]),
        receipt_ids=[],
        **executor.arguments,
    )
    assert executor.calls == ["claim", "manifest", "register", "dispatch", "terminal"]
    assert executor.engine.store.documents["result.json"]["attempt_closure"] == {
        "attempted": True,
        "success": True,
        "scope": "attempt_request_usage_only",
        "native_filesystem_receipts": False,
        "whole_enrollment_cleanup": False,
    }
    assert "cleanup" not in executor.engine.store.documents["result.json"]


@pytest.mark.parametrize(
    "authority",
    [None, {}, {"schema_version": "bluefire.macos-file-access-artifact-closure-claim.v1"}],
)
def test_caller_cleanup_documents_cannot_replace_verified_claim(executor, authority):
    executor.engine.grant_execution.cleanup_authority = lambda *args: authority
    row, records, decision, receipts = executor.engine._execute_step(
        run_id="run-test",
        step=step(),
        bound_inputs={},
        parent_ids=(),
        receipt_ids=[],
        **executor.arguments,
    )
    assert row["status"] == "blocked" and row["execution_disposition"] == "not_dispatched"
    assert row["artifacts"] == {} and row["receipts"] == [] and receipts == ()
    assert row["telemetry"] == ["macos_file_access.closure_authority_unavailable"]
    assert decision.allowed is False and records[0].content["side_effects_started"] is False
    assert executor.calls == []
    assert executor.engine._macos_close_attempted is True


@pytest.mark.parametrize("failure", ["validation", "store"])
def test_expected_close_authority_refusal_is_blocked_without_dispatch_or_replay(executor, failure):
    attempts = []

    def deny(*args):
        attempts.append("claim")
        error = ProductStoreError if failure == "store" else ValueError
        raise error("unknown original read")

    executor.engine.grant_execution.cleanup_authority = deny
    row, records, decision, receipts = executor.engine._execute_step(
        run_id="run-test",
        step=step(),
        bound_inputs={},
        parent_ids=(),
        receipt_ids=[],
        **executor.arguments,
    )

    assert row["status"] == "blocked" and row["execution_disposition"] == "not_dispatched"
    assert row["artifacts"] == {} and row["receipts"] == [] and receipts == ()
    assert row["telemetry"] == ["macos_file_access.closure_authority_unavailable"]
    assert "cleanup" not in row and "runner_task_id" not in row
    assert decision.allowed is False and records[0].content["side_effects_started"] is False
    assert executor.calls == [] and attempts == ["claim"]
    macos_execution.emergency_attempt_close(
        executor.engine,
        plan=SimpleNamespace(steps=[step()]),
        run_id="run-test",
        **executor.arguments,
    )
    assert executor.engine._macos_close_attempted is True
    assert executor.calls == [] and attempts == ["claim"]


@pytest.mark.parametrize("failure", ["runtime", "interrupt"])
def test_unexpected_close_authority_failures_still_propagate(executor, failure):
    error = RuntimeError if failure == "runtime" else KeyboardInterrupt

    def fail(*args):
        raise error("synthetic unexpected failure")

    executor.engine.grant_execution.cleanup_authority = fail
    with pytest.raises(error, match="synthetic unexpected failure"):
        executor.engine._execute_step(
            run_id="run-test",
            step=step(),
            bound_inputs={},
            parent_ids=(),
            receipt_ids=[],
            **executor.arguments,
        )
    assert executor.calls == [] and executor.engine._macos_close_attempted is True


@pytest.mark.parametrize("mode", ["normal", "stopped", "budget"])
def test_existing_graph_loop_routes_mac_closure_without_native_receipts(
    executor, monkeypatch, mode
):
    engine = executor.engine
    methods = [
        step("macos.file_access.probe.v1", "probe"),
        step("macos.file_access.verify_owner.v1", "owner"),
        step(),
    ]
    bindings = {
        "probe": {},
        "owner": {"probe": SimpleNamespace(from_step="probe", artifact="probe")},
        "close": {"workspace": SimpleNamespace(from_step="probe", artifact="workspace")},
    }
    scenario = SimpleNamespace(
        start="probe",
        id="scenario.synthetic.v1",
        purpose="Synthetic lifecycle only",
        adaptive_execution=None,
        limitations=(),
        step=lambda identity: SimpleNamespace(inputs=bindings[identity]),
    )
    plan = SimpleNamespace(
        steps=methods,
        autonomy=AutonomyLevel.OFF,
        ai_enabled=False,
        ai_provider={},
        to_dict=lambda: {"synthetic": "loop"},
    )
    engine.catalog_authority = None
    engine._adaptive_retry_count = lambda replay: 0
    engine._propose_next_step = lambda **kwargs: (None, None, None, False)
    engine._approved_replay_transition = lambda **kwargs: (False, None)
    engine._build_detections = lambda records: []
    engine.grant_execution.document = lambda: {}
    clock = {"now": 0.0}
    monkeypatch.setattr(orchestrator, "time", SimpleNamespace(monotonic=lambda: clock["now"]))
    monkeypatch.setattr(orchestrator, "persist_progress", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        orchestrator, "evaluate_observation_integrity", lambda *args, **kwargs: {"satisfied": True}
    )
    engine.registry.get_action = lambda action: SimpleNamespace(
        id=action, cleanup_action_id=None if action == CLOSE else CLOSE
    )
    order = []

    def execute(**kwargs):
        row = kwargs["step"]
        order.append((row.step_id, kwargs["bound_inputs"], kwargs["action_timeout_ms"]))
        artifacts = (
            {"probe": {"synthetic": True}, "workspace": {"synthetic": True}}
            if row.step_id == "probe"
            else {}
        )
        if row.action_id == CLOSE:
            engine._macos_close_attempted = True
        if mode == "budget" and row.step_id == "probe":
            clock["now"] = 10.0
        outcome = StepOutcome.BLOCKED if kwargs["action_timeout_ms"] < 1 else StepOutcome.SUCCESS
        return (
            engine._row(
                row,
                outcome,
                artifacts=artifacts,
                telemetry=(),
                evidence_ids=(),
                execution_disposition="execute",
            ),
            (),
            SimpleNamespace(to_dict=lambda: {}),
            (),
        )

    def decide(**kwargs):
        identity = kwargs["current_step_id"]
        selected = (
            None
            if identity == "close" or (mode == "stopped" and identity == "probe")
            else "owner" if identity == "probe" else "close"
        )
        return SimpleNamespace(
            selected_step_id=selected,
            execution_disposition=ExecutionDisposition.EXECUTE,
            decision_id="decision-" + identity,
            to_dict=lambda: {},
        )

    engine._execute_step = execute
    engine.planner = SimpleNamespace(decide_next=decide)

    def finalize(run_id, *, result, evidence, detections):
        engine.store.documents["result.json"] = result

    engine.store.finalize = finalize
    engine.store.get_run = lambda run_id: engine.store.documents["result.json"]
    executor.arguments["profile"].budgets = SimpleNamespace(max_steps=3, max_seconds=10)
    result = engine._run_prepared(
        scenario=scenario,
        mode=ExecutionMode.EXECUTE,
        handle=SimpleNamespace(run_id="run-test", created_at="synthetic"),
        approval_binding=None,
        approval_context={},
        runner_readiness=None,
        replay=None,
        resume_from_step_id=None,
        seed_artifacts=None,
        replay_checkpoint=None,
        restoration_plan=None,
        preflight=SimpleNamespace(to_dict=lambda: {}),
        plan=plan,
        receipt_ids=[],
        execution_started=0.0,
        checkpoint=None,
        cancel_event=Event(),
        **executor.arguments,
    )
    assert [row[0] for row in order] == (
        ["probe", "close"] if mode == "stopped" else ["probe", "owner", "close"]
    )
    assert order[-1][1] == ({} if mode != "normal" else {"workspace": {"synthetic": True}})
    assert result["cleanup"] == {
        "attempted": False,
        "success": None,
        "outstanding_receipt_count": 0,
    }
    assert (
        result["attempt_closure"]["attempted"] is True
        and result["attempt_closure"]["success"] is True
    )
    assert result["objective_evaluation"]["terminal_step_id"] == (
        "probe" if mode == "stopped" else "owner"
    )
    assert result["objective_reached"] is (mode == "normal")
    assert result["replay_checkpoints"] == []


def test_missing_probe_input_can_abort_but_empty_close_still_requires_its_claim(executor):
    with pytest.raises(orchestrator.OrchestrationError, match="required artifact is unavailable"):
        executor.engine._bind_inputs(
            {"probe": SimpleNamespace(from_step="probe", artifact="probe")}, {}, EvidenceGraph()
        )
    executor.engine._attempt_emergency_cleanup(
        run_id="run-test",
        plan=SimpleNamespace(steps=[step()]),
        receipt_ids=[],
        **executor.arguments,
    )
    assert executor.calls == ["claim", "manifest", "register", "dispatch", "terminal"]
