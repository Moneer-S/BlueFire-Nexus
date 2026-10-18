"""Real store/grant/task joins with an explicitly fake original Darwin boundary."""

import json
import sqlite3
import uuid
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
from threading import Event
from types import SimpleNamespace

import pytest

from bluefire import composition_macos_file_access, file_access_context
from bluefire import macos_file_access_bridge as bridge
from bluefire import macos_file_access_clock as clock
from bluefire import macos_file_access_control as macos_application
from bluefire import macos_file_access_method as method
from bluefire import macos_file_access_peer as peer
from bluefire import product_store_macos_composition as macos_store
from bluefire import product_store_macos_file_access as macos_control
from bluefire import product_store_macos_settlement as settlement
from bluefire import product_store_macos_workspace as workspace_store
from bluefire.capability_grant import create_grant
from bluefire.capability_packs import MACOS_FILE_ACCESS_METHODS, MACOS_FILE_ACCESS_PACK
from bluefire.contracts import SafetyTier
from bluefire.execution_contracts import execution_task_identity
from bluefire.file_access_control import FileAccessControl
from bluefire.planner import PlanStep
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.product_store_serialization import canonical_json
from bluefire.runner_adapter import RunnerActionAdapter
from bluefire.runner_contracts import (
    _verified_grant_attempt,
    _verified_macos_file_access_cleanup,
    build_execution_manifest,
    build_runner_profile,
    grant_attempt_authorization_digest,
    verify_macos_file_access_binding,
)
from bluefire.runner_reviewed_execution import canonical_reviewed_execution
from bluefire.service import BlueFireService
from bluefire.util import content_hash
from tests_platform import test_capability_macos_file_access as pack_cases
from tests_platform import test_macos_file_access_bridge as bridge_cases
from tests_platform.test_product_store_capability_grants import reservation_args
from tests_platform.test_runner_contracts import _execute_profile

creator_fake = bridge_cases.creator_fake
original = bridge_cases.original
pack_state = pack_cases.state


@pytest.fixture
def connected(original, pack_state, tmp_path, monkeypatch):
    store = ProductStore(tmp_path / "connected.sqlite3")
    producer, parent, state = original.producer, original.value, original.state
    initial = producer._binding()
    frames = []
    failures = {"close_lost": False}
    monkeypatch.setattr(
        bridge,
        "select",
        SimpleNamespace(
            select=lambda *_args: (
                ([], [], [])
                if parent._received_request is not None or parent._in_task
                else ([parent._stream], [], [])
            )
        ),
    )

    def advance(wall):
        state.update(wall=wall, clock=1000 + (wall - 1000) * 1_000_000)

    monkeypatch.setattr(peer, "darwin_clock_ns", lambda: state["clock"])
    monkeypatch.setattr(clock, "darwin_clock_ns", lambda: state["clock"])
    monkeypatch.setattr(macos_store, "_acceptance_clock", lambda: (state["wall"], state["clock"]))
    monkeypatch.setattr(file_access_context, "is_macos_host", lambda: True)

    class Endpoint:
        def assert_current(self):
            original.owner.assert_current()
            return 1.0

        def current_setup(self):
            return {"schema_version": macos_control.SETUP_SCHEMA, "binding": deepcopy(initial)}

        def review_context(self, operation):
            return producer.review_context(operation)

        def reserve_composition_probe_budget(self, request):
            channel_request = {
                "schema_version": "bluefire.macos-workspace-request.v1",
                "sequence": parent._sequence + 1,
                "operation": "reserve_composition_probe_budget",
                "payload": request,
            }
            parent._received_request = channel_request
            try:
                return parent._received(channel_request)["payload"]
            finally:
                parent._received_request = None

        def dispatch_committed(self, frame, *, cancel_event):
            assert not cancel_event.is_set()
            task_id = frame["intent"]["task_id"]
            # These are separate real connections, not the writer's transaction.
            with sqlite3.connect(store.path) as independent:
                if frame["attempt"] is None:
                    assert independent.execute(
                        "SELECT 1 FROM file_access_task_claims WHERE task_id=?", (task_id,)
                    ).fetchone()
                    assert independent.execute(
                        "SELECT 1 FROM file_access_task_evidence WHERE task_id=? AND stage='macos_dispatch'",
                        (task_id,),
                    ).fetchone()
                else:
                    assert independent.execute(
                        "SELECT 1 FROM capability_task_claims WHERE task_id=?", (task_id,)
                    ).fetchone()
                    assert independent.execute(
                        "SELECT 1 FROM capability_task_payloads WHERE task_id=?", (task_id,)
                    ).fetchone()
                    assert independent.execute(
                        "SELECT 1 FROM capability_macos_file_access_events WHERE event_type='dispatch' AND event_key=?",
                        (task_id,),
                    ).fetchone()
            frames.append(deepcopy(frame))
            if failures["close_lost"] and frame["intent"]["operation"] == "close_attempt":
                raise OSError("Fake original close response was lost after committed dispatch")
            request = {
                "schema_version": "bluefire.macos-workspace-request.v1",
                "sequence": parent._sequence + 1,
                "operation": "dispatch_committed",
                "payload": frame,
            }
            parent._received_request = request
            try:
                return parent._received(request)["payload"]
            finally:
                parent._received_request = None

    endpoint = Endpoint()
    monkeypatch.setattr(macos_application, "endpoint", lambda service: endpoint)
    service = SimpleNamespace(
        product_store=store,
        store=SimpleNamespace(_new_run_id=lambda: "control-run-" + uuid.uuid4().hex),
    )

    class Jobs:
        def submit(self, kind, request, *, submission_factory, callback, **options):
            job, _ = submission_factory()
            store.transition_job(job["job_id"], "planning")
            store.transition_job(job["job_id"], "running")
            cancel = Event()
            ctx = SimpleNamespace(
                job_id=job["job_id"], cancellation_event=cancel, checkpoint=lambda: None
            )
            callback(ctx, None)
            store.transition_job(job["job_id"], "completed")

    service.job_controller = Jobs()
    control = FileAccessControl(service, clock=lambda: state["wall"])
    setup = endpoint.current_setup()
    imported = control.import_setup(
        {
            "enrollment_id": initial["enrollment_id"],
            "enrollment_digest": content_hash(macos_control.enrollment_document(setup)),
        }
    )
    for operation in ("baseline", "harden"):
        review_request = {"operation": operation, "control_owner_id": imported["control_owner_id"]}
        review = control.review(review_request)
        result = control.submit(
            {
                "submission_id": str(uuid.uuid4()),
                "review": review_request,
                "review_digest": review["review_digest"],
                "reviewed_by": "Connected fake operator",
            }
        )
        assert result["control"]["status"] == (
            "baseline_verified" if operation == "baseline" else "hardened"
        )
    assert producer._used_budget == 3
    view = store.get_file_access_control(imported["control_owner_id"])
    document, binding = view["document"], producer._binding()
    assert document["binding"] == binding and document["revision"] == 3
    enrolled = store.get_file_access_enrollment(binding["enrollment_id"])
    environment = {
        "environment_id": "environment-" + binding["custody_digest"][7:],
        "environment_generation": binding["generation"],
        "runner_id": "bluefire-macos-workspace.v1",
        "enrollment_digest": content_hash("fake original transport"),
        "profile_digest": content_hash("configured Mac profile"),
        "target_scope_digest": content_hash("no effect scopes"),
        "collector_digest": content_hash("no collectors"),
        "control_owner_id": document["control_owner_id"],
        "control_digest": view["document_digest"],
        "resource_id": "file-resource-" + content_hash(binding["resource"])[7:39],
        "resource_generation": binding["generation"],
        "resource_digest": content_hash(binding["resource"]),
        "probe_enrollment_digest": enrolled["document_digest"],
        "baseline_digest": document["baseline"]["baseline_digest"],
        "control_revision": 3,
        "mode": "0600",
        "workspace_custody_digest": binding["custody_digest"],
        "binding_digest": content_hash(binding),
    }
    advance(2000)
    grant = create_grant(
        registry=pack_state["registry"],
        implementation_digests=pack_state["implementations"],
        objective={
            "question": "Verify the retained generated records without changing them.",
            "predicate": {
                "kind": "non_owner_denied_owner_preserves_records",
                "record_count": 8,
                "data_class": "generated_public_jsonl",
                "sha256": binding["resource"]["sha256"],
            },
        },
        environment=environment,
        limits=pack_state["limits"],
        grant_id="grant-" + "d" * 32,
        approved_by="Connected fake operator",
        created_at_ms=1000,
        expires_at_ms=binding["expires_at_ms"],
        pack=MACOS_FILE_ACCESS_PACK,
    )
    state_for_compile = {**pack_state, "grant": grant, "environment": environment}
    compiled = pack_cases.compiled(state_for_compile)
    store.save_capability_grant(
        grant,
        lineage_id="connected-lineage",
        registry=pack_state["registry"],
        implementation_digests=pack_state["implementations"],
        current_environment=environment,
        now_ms=state["wall"],
    )
    objective_request = {
        "schema_version": "bluefire.composition-objective-request.v1",
        "grant_id": grant["grant_id"],
        "grant_digest": grant["grant_digest"],
    }
    objective, _ = store.create_idempotent_job(
        "composition.objective",
        objective_request,
        submission_id=str(uuid.uuid4()),
        intent_digest=content_hash(objective_request),
    )
    with store._connection(write=True) as connection:
        connection.execute(
            "UPDATE jobs SET state='completed',progress_json=? WHERE job_id=?",
            (
                canonical_json({"admission": {"accepted": True, "problem": None}}),
                objective["job_id"],
            ),
        )
    saved = (
        store,
        {"grant": grant, "current_environment": environment, "parent_job_id": objective["job_id"]},
        compiled,
        {},
    )
    plan_digest = content_hash({"exact_compiled_steps": compiled["scenario"]["steps"]})
    envelope = canonical_reviewed_execution(
        {
            "schema_version": "bluefire.reviewed-execution.v1",
            "authorization_digest": grant_attempt_authorization_digest(
                compiled["compiled_digest"], plan_digest
            ),
            "operations": [
                {
                    "step_id": step["id"],
                    "behavior_id": step["behavior_id"],
                    "action_id": compiled["action_implementations"][step["id"]],
                    "execution_binding_digest": None,
                }
                for step in compiled["scenario"]["steps"]
            ],
        }
    )
    args = reservation_args(saved)
    args.update(plan_digest=plan_digest, native_envelope_digest=content_hash(envelope))
    advance(3000)
    budget = endpoint.reserve_composition_probe_budget(
        {
            "schema_version": "bluefire.macos-composition-budget-request.v1",
            "attempt_id": args["attempt_id"],
            "compiled_digest": compiled["compiled_digest"],
            "control_owner_id": environment["control_owner_id"],
            "binding_digest": environment["binding_digest"],
            "control_revision": environment["control_revision"],
        }
    )
    assert budget["idempotent"] is False and budget["units"] == 2
    assert producer._used_budget == 5
    lease = store.reserve_capability_attempt(grant["grant_id"], compiled, **args)
    advance(4000)
    claim = store.claim_capability_attempt(
        lease["attempt_id"],
        lease_digest=lease["lease_digest"],
        now_ms=state["wall"],
        current_environment=environment,
    )
    advance(4500)
    store.start_capability_preparation(
        lease["attempt_id"], now_ms=state["wall"], current_environment=environment
    )
    store.bind_macos_capability_file_access(lease["attempt_id"])
    guard_phases = []

    class FakeGuard:
        def __init__(self, workspace, *, attempt_id, lease_digest, compiled_digest):
            self.workspace, self.attempt_id, self.lease_digest, self.compiled_digest = (
                workspace,
                attempt_id,
                lease_digest,
                compiled_digest,
            )
            self.closed = False

        def validate_binding(self, workspace, *, attempt_id, lease_digest, compiled_digest):
            assert not self.closed
            assert (workspace, attempt_id, lease_digest, compiled_digest) == (
                self.workspace,
                self.attempt_id,
                self.lease_digest,
                self.compiled_digest,
            )

        def attest(self, phase):
            assert not self.closed
            guard_phases.append(phase)
            return {
                "schema_version": "bluefire.macos-file-access-empty-workspace.v1",
                "attempt_id": self.attempt_id,
                "lease_digest": self.lease_digest,
                "compiled_digest": self.compiled_digest,
                "workspace_path_digest": content_hash(
                    {"sandbox_root": str(self.workspace.resolve())}
                ),
                "workspace_identity_digest": content_hash("fake original directory"),
                "phase": phase,
                "entry_count": 0,
                "state": "verified_empty",
            }

        def close(self):
            self.closed = True

    monkeypatch.setattr(workspace_store, "MacOSAttemptWorkspaceGuard", FakeGuard)
    monkeypatch.setattr(composition_macos_file_access, "MacOSAttemptWorkspaceGuard", FakeGuard)
    monkeypatch.setattr(
        BlueFireService,
        "_isolated_owned_sandbox",
        staticmethod(lambda root, attempt_id: root / attempt_id),
    )
    sandbox = composition_macos_file_access.create_workspace(
        SimpleNamespace(store=store, service=BlueFireService, clock=lambda: state["wall"]),
        lease["attempt_id"],
        {"sandbox": tmp_path / "attempts", "current_environment": environment},
    )
    assert guard_phases == []
    config_profile = replace(
        _execute_profile(),
        platforms=("macos",),
        enabled_actions=MACOS_FILE_ACCESS_METHODS,
        native_tool_installations=(),
    )
    verified_binding = verify_macos_file_access_binding(
        binding,
        expected_document_digest=document["binding_digest"],
        now_ms=state["wall"],
        now_monotonic_ns=state["clock"],
    )
    profile = build_runner_profile(
        config_profile,
        sandbox_root=sandbox,
        platform="macos",
        filesystem_scope=(),
        reviewed_execution=envelope,
        macos_file_access_binding=verified_binding,
    )
    store.bind_capability_workspace(
        lease["attempt_id"],
        runner_policy_digest=profile["policy_digest"],
        workspace_path_digest=content_hash({"sandbox_root": profile["sandbox_root"]}),
        now_ms=state["wall"],
        current_environment=environment,
    )
    store.reserve_macos_capability_attempt(
        lease["attempt_id"],
        now_ms=state["wall"],
        monotonic_ns=state["clock"],
        business_deadline_ns=state["clock"]
        + (lease["business_expires_at_ms"] - state["wall"]) * 1_000_000,
        cleanup_deadline_ns=state["clock"]
        + (lease["attempt_expires_at_ms"] - state["wall"]) * 1_000_000,
    )
    adapter, transport, artifacts, dispatched = (
        RunnerActionAdapter(),
        bridge.MacOSWorkspaceTaskTransport(endpoint, store),
        {},
        [],
    )

    def execute(index):
        advance(5000 + index * 100)
        step_doc = compiled["scenario"]["steps"][index]
        action_id = compiled["action_implementations"][step_doc["id"]]
        step = PlanStep(
            step_id=step_doc["id"],
            behavior_id=step_doc["behavior_id"],
            action_id=action_id,
            simulation_id=None,
            parameters=step_doc["parameters"],
            inputs={},
            expected_outputs=(),
            required_capabilities=(),
            safety_tier=SafetyTier.CONTROLLED,
            alternates=(),
        )
        inputs = (
            {}
            if index == 0
            else {
                "probe" if index == 1 else "workspace": artifacts[
                    "probe" if index == 1 else "workspace"
                ]
            }
        )
        adapted = adapter.adapt(step, bound_inputs=inputs, receipt_ids=[])
        operation = next(
            value for value in envelope["operations"] if value["step_id"] == step.step_id
        )
        authorization = {
            "grant_attempt": _verified_grant_attempt(
                claim["document"], expected_document_digest=claim["document_digest"]
            )
        }
        cleanup = None
        if index == 2:
            cleanup = store.claim_macos_capability_cleanup(
                lease["attempt_id"], now_ms=state["wall"], now_monotonic_ns=state["clock"]
            )
            authorization = {
                "macos_file_access_cleanup": _verified_macos_file_access_cleanup(
                    cleanup["document"], expected_document_digest=cleanup["document_digest"]
                )
            }
        manifest = build_execution_manifest(
            run_id=lease["run_id"],
            step_id=step.step_id,
            behavior_id=step.behavior_id,
            action=pack_state["registry"].get_action(action_id),
            runner_profile=profile,
            params=adapted.params,
            filesystem_scope=adapted.filesystem_scope,
            approval_record=None,
            reviewed_operation={
                **operation,
                "authorization_digest": envelope["authorization_digest"],
            },
            resolved_cleanup_action_id=method.CLOSE_ACTION,
            now=datetime.fromtimestamp(state["wall"] / 1000, timezone.utc),
            now_monotonic_ns=state["clock"],
            **authorization,
        )
        task_id, request_hash = execution_task_identity(manifest, profile)
        if cleanup is None:
            store.register_capability_task(
                lease["attempt_id"],
                task_id=task_id,
                step_id=step.step_id,
                request_hash=manifest["request_hash"],
                now_ms=state["wall"],
                current_environment=environment,
                manifest=manifest,
                runner_profile=profile,
            )
            payload = store.get_capability_task_payload(task_id, request_hash)["payload"]
        else:
            store.register_macos_capability_cleanup_task(
                lease["attempt_id"],
                task_id=task_id,
                step_id=step.step_id,
                request_hash=manifest["request_hash"],
                expected_document_digest=cleanup["document_digest"],
                now_ms=state["wall"],
                now_monotonic_ns=state["clock"],
                manifest=manifest,
                runner_profile=profile,
            )
            payload = store.get_macos_capability_cleanup_task_payload(task_id, request_hash)[
                "payload"
            ]
        assert payload["manifest"] == manifest and payload["runner_profile"] == profile
        assert payload["purpose"] == ("macos_cleanup" if cleanup else "business")
        result = transport.execute_task(manifest, profile, task_id=task_id, cancel_event=Event())
        store.record_capability_task_terminal(
            task_id, request_hash=manifest["request_hash"], terminal_digest=content_hash(result)
        )
        store.record_macos_capability_terminal(task_id, result=result)
        dispatched.append((manifest, task_id, result))
        if result["status"] == "success":
            artifacts.update(
                adapter.logical_outputs(
                    step, bound_inputs=inputs, runner_output=result["output"], receipt_ids=[]
                )
            )
        if cleanup is not None:
            store.close_macos_capability_attempt(
                lease["attempt_id"], cleanup_task_id=task_id, result=result
            )
        return result

    return SimpleNamespace(
        store=store,
        producer=producer,
        state=state,
        lease=lease,
        compiled=compiled,
        profile=profile,
        execute=execute,
        artifacts=artifacts,
        frames=frames,
        failures=failures,
        guard_phases=guard_phases,
        dispatched=dispatched,
    )


def test_actual_store_compiled_grant_and_original_fake_bridge_settle_complete_chain(connected):
    context = connected
    assert context.store.schema_version == 13
    assert context.execute(0)["status"] == "success"
    assert context.producer._used_budget == 5
    assert context.execute(1)["status"] == "success"
    assert context.execute(2)["status"] == "success"
    receipt = settlement.receipt(context.store, context.lease["attempt_id"])
    original_frames = len(context.frames)
    context.store.settle_capability_attempt(context.lease["attempt_id"], receipt)
    assert context.store.get_capability_attempt(context.lease["attempt_id"])["state"] == "settled"
    context.store.settle_capability_attempt(context.lease["attempt_id"], receipt)
    assert context.store.get_capability_attempt(context.lease["attempt_id"])["state"] == "settled"
    assert settlement.receipt(context.store, context.lease["attempt_id"]) == receipt
    assert (
        context.store.get_file_access_control(context.lease["control_owner_id"])["usages_settled"]
        is True
    )
    assert len(context.frames) == original_frames
    assert context.producer._used_budget == 5 and len(context.state["calls"]) == 5
    assert context.guard_phases == ["reserve", "pre_close", "post_close"]
    assert set(context.artifacts) == {"probe", "workspace", "verification", "closure"}
    assert context.artifacts["closure"]["attempt_closure"]["original_workers"] == "retained"
    assert not context.artifacts["closure"]["attempt_closure"]["whole_enrollment_cleanup"]
    attempt_frames = [frame for frame in context.frames if frame["attempt"] is not None]
    assert len(attempt_frames) == 3
    probe, owner, close = attempt_frames
    assert (
        owner["attempt"]["probe_receipt_digest"]
        == context.artifacts["probe"]["native_receipt_digest"]
    )
    assert (
        close["claim"]["manifest"]["macos_file_access_cleanup"] == close["attempt"]["cleanup_claim"]
    )
    assert all(
        frame["attempt"]["primitive_budget"] == {"probe": 1, "verify_owner": 1, "total": 2}
        for frame in attempt_frames
    )
    assert probe["claim"]["task_id"] != owner["claim"]["task_id"] != close["claim"]["task_id"]
    with context.store._connection() as connection:
        settlements = connection.execute(
            "SELECT document_json,document_digest FROM capability_attempt_settlements WHERE attempt_id=?",
            (context.lease["attempt_id"],),
        ).fetchall()
        assert len(settlements) == 1
        assert json.loads(settlements[0]["document_json"]) == receipt
        assert settlements[0]["document_json"] == canonical_json(receipt)
        assert settlements[0]["document_digest"] == content_hash(receipt)
        assert (
            connection.execute("SELECT COUNT(*) FROM capability_task_payloads").fetchone()[0] == 3
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM capability_cleanup_task_claims").fetchone()[0]
            == 0
        )


@pytest.mark.parametrize("failure", ["owner_unknown", "close_lost"])
def test_unknown_or_lost_original_close_never_becomes_settled_or_replayed(connected, failure):
    context = connected
    context.execute(0)
    if failure == "owner_unknown":
        context.state["fail_role"] = "owner"
        result = context.execute(1)
        assert (
            result["status"] == "error" and result["output"]["macos_receipt"]["state"] == "unknown"
        )
        with pytest.raises(ProductStoreError, match="Unknown Darwin dispatch"):
            context.execute(2)
    else:
        context.execute(1)
        context.failures["close_lost"] = True
        with pytest.raises(OSError, match="close response was lost"):
            context.execute(2)
    with pytest.raises(ProductStoreError):
        settlement.receipt(context.store, context.lease["attempt_id"])
    prior_frames, prior_calls = len(context.frames), len(context.state["calls"])
    with pytest.raises(ProductStoreError):
        context.execute(2)
    assert len(context.frames) == prior_frames and len(context.state["calls"]) == prior_calls
    assert context.store.get_capability_attempt(context.lease["attempt_id"])["state"] == "claimed"
    assert context.producer._used_budget == 5
    with context.store._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM capability_attempt_settlements").fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM capability_macos_file_access_closures"
            ).fetchone()[0]
            == 0
        )
