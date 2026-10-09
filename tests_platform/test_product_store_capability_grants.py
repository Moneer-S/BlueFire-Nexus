"""Authored storage/authority fixtures; no receiver, native runner or model effects."""

import sqlite3
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from types import SimpleNamespace

import pytest

from bluefire import product_store as store_module
from bluefire import product_store_capability_api as schema_api
from bluefire import product_store_capability_grants as records
from bluefire import product_store_receiver_defense as receiver
from bluefire import receiver_defense_control
from bluefire.capability_composition import compile_initial_graph
from bluefire.capability_facts import seal_facts
from bluefire.capability_grant import create_grant
from bluefire.capability_resources import CapabilityContractError
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.product_store_serialization import canonical_json
from bluefire.receiver_defense_workflow import control_descriptor
from bluefire.util import content_hash
from tests_platform.test_capability_composition import proposal
from tests_platform.test_capability_composition import state as state


@pytest.fixture
def saved(state, tmp_path):
    store = ProductStore(tmp_path / "product.sqlite3")
    environment = state["current_environment"]
    context = {
        "workflow": "retained_redaction",
        "selection": {
            "kind": "saved_scenario",
            "scenario_id": "fixture.v1",
            "version": 1,
            "digest": content_hash("scenario"),
        },
        "run_intent": {"target_scope": {"scope_refs": ["sandbox.workspace", "network.loopback"]}},
        "profile_digest": environment["profile_digest"],
        "catalog_binding": {"catalog_digest": content_hash("catalog")},
        "collector_binding": {"collectors": ["collector.filesystem.sandbox.v1"]},
    }
    context["control"] = control_descriptor(context, "prepare")
    owner = store.create_job("receiver.defense", {"context": context})
    phases = {}
    for phase in ("baseline", "protected", "legitimate"):
        child = store.create_job("receiver.prepare", {})
        result = {
            "cleanup": {"receiver": "verified_closed", "run": "complete"},
            "decision": "policy_refused" if phase == "protected" else "accepted",
            "receiver_observation": {
                "terminal": {
                    "decision": {
                        "semantics": {
                            "record_count": 8,
                            "retained_record_count": 8 if phase == "baseline" else 0,
                        }
                    }
                }
            },
            "legitimate_use": {"established": phase == "legitimate"},
        }
        progress = {
            "result": result,
            "result_digest": content_hash(result),
            "receiver_closed": True,
            "decision": {"decision": "accept"},
        }
        with store._connection(write=True) as connection:
            connection.execute(
                "UPDATE jobs SET state='completed',progress_json=? WHERE job_id=?",
                (canonical_json(progress), child["job_id"]),
            )
        phases[phase] = {"receiver_job_id": child["job_id"]}
    with store._connection(write=True) as connection:
        connection.execute(
            "UPDATE jobs SET state='completed',progress_json=? WHERE job_id=?",
            (
                canonical_json(
                    {
                        "admission": {"accepted": True, "problem": None},
                        "receiver_completed": True,
                        "receiver_settled": True,
                        "phases": phases,
                    }
                ),
                owner["job_id"],
            ),
        )
    environment.update(
        control_owner_id=owner["job_id"],
        control_digest=context["control"]["control_digest"],
        collector_digest=content_hash(context["collector_binding"]),
        target_scope_digest=content_hash(context["run_intent"]["target_scope"]),
    )
    grant = state["grant"]
    state["grant"] = create_grant(
        registry=state["registry"],
        implementation_digests=state["implementation_digests"],
        **{
            key: grant[key]
            for key in (
                "objective",
                "limits",
                "grant_id",
                "approved_by",
                "created_at_ms",
                "expires_at_ms",
            )
        },
        environment=environment,
    )
    state["expected_grant_digest"] = state["grant"]["grant_digest"]
    facts = {key: value for key, value in state["facts"].items() if key != "facts_digest"}
    facts.update(
        environment_digest=content_hash(environment), control_digest=environment["control_digest"]
    )
    for fact in facts["facts"]:
        fact.update(
            environment_digest=content_hash(environment),
            control_digest=environment["control_digest"],
        )
    state["facts"] = seal_facts(facts)
    state["expected_facts_digest"] = state["facts"]["facts_digest"]
    compiled = compile_initial_graph(proposal(), **state)
    args = {
        key: state[key]
        for key in ("registry", "implementation_digests", "current_environment", "now_ms")
    }
    store.save_capability_grant(state["grant"], lineage_id="lineage-1", **args)
    request = {
        "schema_version": "bluefire.composition-objective-request.v1",
        "grant_id": state["grant"]["grant_id"],
        "grant_digest": state["grant"]["grant_digest"],
    }
    parent, _ = store.create_idempotent_job(
        "composition.objective",
        request,
        submission_id=str(uuid.uuid4()),
        intent_digest=content_hash(request),
    )
    with store._connection(write=True) as connection:
        connection.execute(
            "UPDATE jobs SET state='completed',progress_json=? WHERE job_id=?",
            (canonical_json({"admission": {"accepted": True, "problem": None}}), parent["job_id"]),
        )
    state["parent_job_id"] = parent["job_id"]
    return store, state, compiled, args


def reservation_args(saved, *, store=None, compiled=None, now_ms=3000):
    original, state, prepared, _ = saved
    store = store or original
    compiled = compiled or prepared
    submission = uuid.uuid4()
    token = submission.hex
    marker = {
        "parent_job_id": state["parent_job_id"],
        "grant_id": state["grant"]["grant_id"],
        "grant_digest": state["grant"]["grant_digest"],
        "attempt_id": "attempt-" + token,
        "compiled_digest": compiled["compiled_digest"],
        "run_id": "run-" + token,
    }
    request = {"composition_attempt": marker}
    store.create_idempotent_job(
        "composition.attempt",
        request,
        submission_id=str(submission),
        intent_digest=content_hash(request),
    )
    return dict(
        expected_compiled_digest=compiled["compiled_digest"],
        attempt_id="attempt-" + token,
        job_id="job-" + token,
        run_id="run-" + token,
        plan_digest=content_hash("exact-plan"),
        native_envelope_digest=content_hash("exact-envelope"),
        current_environment=state["current_environment"],
        now_ms=now_ms,
    )


def reserve(saved, *, store=None, compiled=None, now_ms=3000):
    return (store or saved[0]).reserve_capability_attempt(
        saved[1]["grant"]["grant_id"],
        compiled or saved[2],
        **reservation_args(saved, store=store, compiled=compiled, now_ms=now_ms),
    )


def claim(saved, lease, *, store=None, now_ms=4000):
    return (store or saved[0]).claim_capability_attempt(
        lease["attempt_id"],
        lease_digest=lease["lease_digest"],
        now_ms=now_ms,
        current_environment=saved[1]["current_environment"],
    )


def unused(lease):
    return {
        "schema_version": "bluefire.capability-attempt-settlement.v1",
        "attempt_id": lease["attempt_id"],
        "lease_digest": lease["lease_digest"],
        "receiver": {"state": "not_started"},
        "native": {"state": "not_started", "run_id": lease["run_id"]},
    }


def start(saved, lease):
    store, state, _, _ = saved
    claim(saved, lease)
    store.start_capability_preparation(
        lease["attempt_id"], now_ms=4500, current_environment=state["current_environment"]
    )
    store.bind_capability_receiver(
        lease["attempt_id"],
        session_generation="generation-" + lease["attempt_id"],
        review_digest=content_hash("session-review"),
    )
    store.bind_capability_workspace(
        lease["attempt_id"],
        runner_policy_digest=content_hash("sealed-profile"),
        workspace_path_digest=content_hash("owned-workspace-path"),
        now_ms=4500,
        current_environment=state["current_environment"],
    )


def register(saved, lease, *, task_id="task-one", step_id="seed", now_ms=5000):
    return saved[0].register_capability_task(
        lease["attempt_id"],
        task_id=task_id,
        step_id=step_id,
        request_hash=content_hash(task_id),
        now_ms=now_ms,
        current_environment=saved[1]["current_environment"],
    )


def closed(lease, tasks=()):
    return {
        **unused(lease),
        "receiver": {
            "state": "verified_closed",
            "session_generation": "generation-" + lease["attempt_id"],
            "review_digest": content_hash("session-review"),
            "receipt_digest": content_hash("verified-close"),
        },
        "native": (
            {
                "state": "complete",
                "run_id": lease["run_id"],
                "task_ids": sorted(tasks),
                "cleanup_digest": content_hash("verified-native-cleanup"),
            }
            if tasks
            else {"state": "not_started", "run_id": lease["run_id"]}
        ),
    }


def cleanup_ready(saved, lease):
    store = saved[0]
    store.record_capability_task_terminal(
        "task-one", request_hash=content_hash("task-one"), terminal_digest=content_hash("terminal")
    )
    receipts = [
        {
            "receipt_id": content_hash("owned-native-receipt").removeprefix("sha256:"),
            "source_task_id": "task-one",
            "source_request_hash": content_hash("task-one"),
        }
    ]
    return store.record_capability_cleanup_obligation(
        lease["attempt_id"],
        workspace_id=content_hash("native-workspace").removeprefix("sha256:"),
        receipts=receipts,
    )


def cleanup_complete(saved, lease, *, now_ms=6000):
    store = saved[0]
    cleanup_ready(saved, lease)
    authority = store.claim_capability_cleanup(lease["attempt_id"], now_ms=now_ms, timeout_ms=1000)
    store.register_capability_cleanup_task(
        lease["attempt_id"],
        task_id="cleanup-one",
        request_hash=content_hash("cleanup-request"),
        expected_document_digest=authority["document_digest"],
        now_ms=now_ms,
    )
    store.record_capability_cleanup_terminal(
        "cleanup-one",
        request_hash=content_hash("cleanup-request"),
        terminal_digest=content_hash("verified-native-cleanup"),
    )
    return authority


@pytest.mark.parametrize("environment", [None, [], {}, {"environment_id": "wrong"}])
@pytest.mark.parametrize("boundary", ["reserve", "claim", "prepare", "task"])
def test_business_boundaries_require_exact_current_environment(saved, environment, boundary):
    store, state, compiled, _ = saved
    args = reservation_args(saved)
    if boundary == "reserve":
        args["current_environment"] = environment
        with pytest.raises(ProductStoreError):
            store.reserve_capability_attempt(state["grant"]["grant_id"], compiled, **args)
    else:
        lease = store.reserve_capability_attempt(state["grant"]["grant_id"], compiled, **args)
        if boundary == "prepare":
            claim(saved, lease)
        if boundary == "task":
            start(saved, lease)
        with pytest.raises(ProductStoreError):
            if boundary == "claim":
                store.claim_capability_attempt(
                    lease["attempt_id"],
                    lease_digest=lease["lease_digest"],
                    now_ms=5000,
                    current_environment=environment,
                )
            elif boundary == "prepare":
                store.start_capability_preparation(
                    lease["attempt_id"],
                    now_ms=5000,
                    current_environment=environment,
                )
            else:
                store.register_capability_task(
                    lease["attempt_id"],
                    task_id="task-rejected",
                    step_id="seed",
                    request_hash=content_hash("rejected"),
                    now_ms=5000,
                    current_environment=environment,
                )
    with store._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM capability_task_claims").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM capability_attempts").fetchone()[0] == (
            0 if boundary == "reserve" else 1
        )


@pytest.mark.parametrize(
    "defect",
    [
        "child_kind",
        "child_terminal",
        "child_stopped",
        "parent_kind",
        "parent_running",
        "parent_stopped",
        "parent_unadmitted",
        "parent_grant",
        "attempt_id",
        "compiled_digest",
        "run_id",
        "extra_marker",
        "submission_digest",
    ],
)
def test_reservation_requires_exact_admitted_job_ownership(saved, defect):
    store, state, compiled, _ = saved
    args = reservation_args(saved)
    child = store.get_job(args["job_id"])
    parent = store.get_job(state["parent_job_id"])
    target = parent if defect.startswith("parent_") else child
    request = deepcopy(target["request"])
    progress = deepcopy(target["progress"])
    kind, status = target["kind"], target["state"]
    if defect.endswith("_kind"):
        kind = "scenario.run"
    elif defect == "child_terminal":
        status = "completed"
    elif defect == "parent_running":
        status = "running"
    elif defect.endswith("_stopped"):
        progress["stopped"] = True
    elif defect == "parent_unadmitted":
        progress["admission"] = {"accepted": False, "problem": None}
    elif defect == "parent_grant":
        request["grant_id"] = "grant-" + "f" * 32
    elif defect == "submission_digest":
        request["_submission"]["intent_digest"] = content_hash("changed")
    elif defect == "extra_marker":
        request["composition_attempt"]["extra"] = True
    else:
        request["composition_attempt"][defect] = "changed"
    if defect != "submission_digest":
        request["_submission"]["intent_digest"] = content_hash(
            {key: value for key, value in request.items() if key != "_submission"}
        )
    with store._connection(write=True) as connection:
        connection.execute(
            "UPDATE jobs SET kind=?,state=?,request_json=?,progress_json=? WHERE job_id=?",
            (kind, status, canonical_json(request), canonical_json(progress), target["job_id"]),
        )
    with pytest.raises(ProductStoreError):
        store.reserve_capability_attempt(state["grant"]["grant_id"], compiled, **args)


def test_claim_rechecks_job_admission_and_control_view_requires_settlement(saved):
    store, state, _, _ = saved
    parent = store.get_job(state["current_environment"]["control_owner_id"])

    def view():
        return receiver_defense_control.view(
            SimpleNamespace(store=store),
            parent,
            [{"phase": "protected", "status": "completed", "decision": {"decision": "accept"}}],
            True,
        )

    assert view()["can_retest"] and view()["can_rollback"]
    lease = reserve(saved)
    current = view()
    assert current["status"] == "retained"
    assert current["receiver_state"] == "unknown"
    assert not current["can_retest"] and not current["can_rollback"]
    with store._connection(write=True) as connection:
        connection.execute("UPDATE jobs SET state='interrupted' WHERE job_id=?", (lease["job_id"],))
    with pytest.raises(ProductStoreError):
        claim(saved, lease)
    store.settle_capability_attempt(lease["attempt_id"], unused(lease))
    assert view()["receiver_state"] == "stopped"
    assert view()["can_retest"] and view()["can_rollback"]


@pytest.mark.parametrize("stop", ["revoked", "paused", "expired"])
def test_cleanup_authority_is_receipt_scoped_after_business_stops(saved, stop):
    from bluefire.runner_contracts import _verified_grant_cleanup

    store, state, _, _ = saved
    lease = reserve(saved)
    start(saved, lease)
    register(saved, lease)
    now = lease["business_expires_at_ms"] if stop == "expired" else 6000
    if stop != "expired":
        store.change_capability_grant_state(state["grant"]["grant_id"], status=stop, now_ms=now)
    with pytest.raises(ProductStoreError):
        register(saved, lease, task_id="late-business", step_id="prepare", now_ms=now)
    authority = cleanup_complete(saved, lease, now_ms=now)
    assert authority == {
        key: value
        for key, value in ProductStore(store.path)
        .get_capability_cleanup(lease["attempt_id"])
        .items()
        if key != "task"
    }
    document = authority["document"]
    _verified_grant_cleanup(document, expected_document_digest=authority["document_digest"])
    assert document["schema_version"] == "bluefire.runner-grant-cleanup.v1"
    assert document["runner_policy_digest"] == content_hash("sealed-profile")
    assert document["receipts"][0]["source_task_id"] == "task-one"
    with pytest.raises(ProductStoreError):
        store.claim_capability_cleanup(lease["attempt_id"], now_ms=now, timeout_ms=1000)
    with pytest.raises(ProductStoreError):
        store.register_capability_cleanup_task(
            lease["attempt_id"],
            task_id="cleanup-two",
            request_hash=content_hash("second"),
            expected_document_digest=authority["document_digest"],
            now_ms=now,
        )
    store.settle_capability_attempt(lease["attempt_id"], closed(lease, ["task-one"]))
    assert store.get_capability_attempt(lease["attempt_id"])["state"] == "settled"


@pytest.mark.parametrize(
    "defect", ["source_task", "source_request", "duplicate", "missing_terminal"]
)
def test_cleanup_obligation_refuses_unbound_or_unreconciled_receipts(saved, defect):
    store = saved[0]
    lease = reserve(saved)
    start(saved, lease)
    register(saved, lease)
    if defect != "missing_terminal":
        store.record_capability_task_terminal(
            "task-one",
            request_hash=content_hash("task-one"),
            terminal_digest=content_hash("terminal"),
        )
    receipts = [
        {
            "receipt_id": content_hash("receipt").removeprefix("sha256:"),
            "source_task_id": "task-one",
            "source_request_hash": content_hash("task-one"),
        }
    ]
    if defect == "source_task":
        receipts[0]["source_task_id"] = "unregistered"
    elif defect == "source_request":
        receipts[0]["source_request_hash"] = content_hash("unregistered")
    elif defect == "duplicate":
        receipts.append(deepcopy(receipts[0]))
    with pytest.raises(ProductStoreError):
        store.record_capability_cleanup_obligation(
            lease["attempt_id"],
            workspace_id=content_hash("native-workspace").removeprefix("sha256:"),
            receipts=receipts,
        )


@pytest.mark.parametrize(
    "boundary", ["deadline", "excess_timeout", "clock_backwards", "delayed_dispatch"]
)
def test_cleanup_cannot_reset_reserved_time_or_dispatch_after_expiry(saved, boundary):
    store = saved[0]
    lease = reserve(saved)
    start(saved, lease)
    register(saved, lease)
    cleanup_ready(saved, lease)
    now, timeout = 6000, 1000
    if boundary == "deadline":
        now = lease["attempt_expires_at_ms"]
    elif boundary == "clock_backwards":
        now = 4999
    elif boundary == "excess_timeout":
        timeout = lease["reservation"]["cleanup_reserve_ms"] + 1
    if boundary != "delayed_dispatch":
        with pytest.raises(ProductStoreError):
            store.claim_capability_cleanup(lease["attempt_id"], now_ms=now, timeout_ms=timeout)
    else:
        authority = store.claim_capability_cleanup(
            lease["attempt_id"], now_ms=now, timeout_ms=timeout
        )
        with pytest.raises(ProductStoreError):
            ProductStore(store.path).register_capability_cleanup_task(
                lease["attempt_id"],
                task_id="cleanup-late",
                request_hash=content_hash("late"),
                expected_document_digest=authority["document_digest"],
                now_ms=now + lease["reservation"]["cleanup_reserve_ms"],
            )
    with pytest.raises(ProductStoreError):
        register(saved, lease, task_id="resumed-business", step_id="prepare", now_ms=6500)
    assert store.get_capability_attempt(lease["attempt_id"])["state"] == "claimed"


@pytest.mark.parametrize(
    "defect", ["missing_terminal", "wrong_terminal", "changed_claim", "missing_obligation"]
)
def test_cleanup_settlement_requires_exact_persisted_provenance(saved, defect):
    store, state, _, _ = saved
    lease = reserve(saved)
    start(saved, lease)
    register(saved, lease)
    cleanup_complete(saved, lease)
    receipt = closed(lease, ["task-one"])
    if defect == "wrong_terminal":
        receipt["native"]["cleanup_digest"] = content_hash("unrelated-terminal")
    else:
        with store._connection(write=True) as connection:
            if defect == "missing_terminal":
                connection.execute("DROP TRIGGER capability_cleanup_terminals_no_delete")
                connection.execute("DELETE FROM capability_cleanup_terminals")
            elif defect == "missing_obligation":
                connection.execute("DROP TRIGGER capability_cleanup_obligations_no_delete")
                connection.execute("DELETE FROM capability_cleanup_obligations")
            else:
                row = connection.execute("SELECT * FROM capability_cleanup_claims").fetchone()
                claim = records._document(row)
                claim["workspace_id"] = content_hash("another-workspace")
                connection.execute("DROP TRIGGER capability_cleanup_claims_no_update")
                connection.execute(
                    "UPDATE capability_cleanup_claims SET document_json=?,document_digest=?",
                    (canonical_json(claim), content_hash(claim)),
                )
    with pytest.raises(ProductStoreError):
        store.settle_capability_attempt(lease["attempt_id"], receipt)
    assert (
        store.change_capability_grant_state(
            state["grant"]["grant_id"], status="revoked", now_ms=7000
        )["status"]
        == "revoked"
    )


def test_workspace_binding_is_required_immutable_and_not_authorized_after_stop(saved):
    store, state, _, _ = saved
    lease = reserve(saved)
    claim(saved, lease)
    store.start_capability_preparation(
        lease["attempt_id"], now_ms=4500, current_environment=state["current_environment"]
    )
    store.bind_capability_receiver(
        lease["attempt_id"],
        session_generation="generation-" + lease["attempt_id"],
        review_digest=content_hash("session-review"),
    )
    with pytest.raises(ProductStoreError):
        register(saved, lease)
    args = dict(
        runner_policy_digest=content_hash("profile"),
        workspace_path_digest=content_hash("path"),
        now_ms=5000,
        current_environment=state["current_environment"],
    )
    store.bind_capability_workspace(lease["attempt_id"], **args)
    with pytest.raises(ProductStoreError):
        store.bind_capability_workspace(lease["attempt_id"], **args)
    store.change_capability_grant_state(state["grant"]["grant_id"], status="revoked", now_ms=5000)
    with pytest.raises(ProductStoreError):
        store.bind_capability_workspace(lease["attempt_id"], **args)


@pytest.mark.parametrize("first", ["business", "obligation"])
def test_cleanup_freeze_and_new_task_are_serialized_in_both_orders(saved, first):
    lease = reserve(saved)
    start(saved, lease)
    register(saved, lease)
    if first == "business":
        register(saved, lease, task_id="task-two", step_id="prepare", now_ms=5500)
        with pytest.raises(ProductStoreError):
            cleanup_ready(saved, lease)
    else:
        cleanup_ready(saved, lease)
        with pytest.raises(ProductStoreError):
            register(saved, lease, task_id="task-two", step_id="prepare", now_ms=5500)


def test_cleanup_freeze_and_business_task_have_one_atomic_winner(saved):
    store, state, _, _ = saved
    lease = reserve(saved)
    start(saved, lease)
    register(saved, lease)
    store.record_capability_task_terminal(
        "task-one", request_hash=content_hash("task-one"), terminal_digest=content_hash("terminal")
    )
    stores = [ProductStore(store.path), ProductStore(store.path)]
    barrier = threading.Barrier(2)

    def business():
        barrier.wait()
        try:
            stores[0].register_capability_task(
                lease["attempt_id"],
                task_id="raced-business",
                step_id="prepare",
                request_hash=content_hash("raced"),
                now_ms=5500,
                current_environment=state["current_environment"],
            )
            return True
        except ProductStoreError:
            return False

    def obligation():
        barrier.wait()
        try:
            stores[1].record_capability_cleanup_obligation(
                lease["attempt_id"],
                workspace_id="a" * 64,
                receipts=[
                    {
                        "receipt_id": "b" * 64,
                        "source_task_id": "task-one",
                        "source_request_hash": content_hash("task-one"),
                    }
                ],
            )
            return True
        except ProductStoreError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs = [pool.submit(business), pool.submit(obligation)]
        assert sum(job.result() for job in jobs) == 1


def test_reservation_claim_provenance_and_cleanup_survive_reopen(saved):
    store, state, compiled, _ = saved
    lease = reserve(saved)
    assert lease["reservation"] == compiled["reservation"]
    reopened = ProductStore(store.path)
    authority = claim(saved, lease, store=reopened)
    assert authority["document_digest"] == content_hash(authority["document"])
    assert "approved_by" not in authority["document"]
    assert authority["document"]["issuer"] == records.ISSUER
    assert authority["document"]["lease_digest"] == lease["lease_digest"]
    with pytest.raises(ProductStoreError, match="already claimed"):
        claim(saved, lease)
    reopened.settle_capability_attempt(lease["attempt_id"], unused(lease))
    assert store.get_capability_attempt(lease["attempt_id"])["state"] == "settled"
    assert (
        store.get_capability_grant(state["grant"]["grant_id"], now_ms=5000)["usage"]["attempts"]
        == 1
    )


def test_failed_cancelled_unused_attempts_never_refund_and_new_grant_ids_do_not_reset(saved):
    store, state, _, args = saved
    for index in range(3):
        lease = reserve(saved, now_ms=3000 + index)
        store.settle_capability_attempt(lease["attempt_id"], unused(lease))
    grant = deepcopy(state["grant"])
    grant["grant_id"] = "grant-" + "c" * 32
    grant["grant_digest"] = content_hash(
        {key: value for key, value in grant.items() if key != "grant_digest"}
    )
    with pytest.raises(ProductStoreError, match="existing capability lineage"):
        store.save_capability_grant(grant, lineage_id="new-lineage-reset", **args)
    store.save_capability_grant(grant, lineage_id="lineage-1", **{**args, "now_ms": 4000})
    assert store.get_capability_grant(grant["grant_id"], now_ms=5000)["usage"]["attempts"] == 3
    with pytest.raises(CapabilityContractError):
        reserve(saved, now_ms=6000)
    assert len(store.get_capability_attempt(lease["attempt_id"])["tasks"]) == 0


def test_full_reservation_is_atomic_with_control_usage(saved):
    store, state, _, _ = saved
    with store._connection(write=True) as connection:
        connection.execute(
            "CREATE TRIGGER fail_usage BEFORE INSERT ON capability_control_usages BEGIN SELECT RAISE(ABORT,'fixture interruption'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="fixture interruption"):
        reserve(saved)
    assert (
        store.get_capability_grant(state["grant"]["grant_id"], now_ms=5000)["usage"]["attempts"]
        == 0
    )
    with store._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM capability_attempts").fetchone()[0] == 0


def test_concurrent_one_use_claim_has_one_winner(saved):
    lease = reserve(saved)
    stores = [ProductStore(saved[0].path), ProductStore(saved[0].path)]
    barrier = threading.Barrier(2)

    def attempt(store):
        barrier.wait()
        try:
            return claim(saved, lease, store=store)
        except ProductStoreError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, stores))
    assert sum(result is not None for result in results) == 1


def test_revoke_before_claim_and_task_send_refuses_new_work(saved):
    store, state, _, _ = saved
    lease = reserve(saved)
    stopped = store.change_capability_grant_state(
        state["grant"]["grant_id"], status="revoked", now_ms=3500
    )
    assert stopped["attempts"][0]["attempt_id"] == lease["attempt_id"]
    with pytest.raises(ProductStoreError):
        claim(saved, lease)
    with pytest.raises(ProductStoreError):
        reserve(saved, now_ms=5000)
    store.settle_capability_attempt(lease["attempt_id"], unused(lease))
    with pytest.raises(ProductStoreError, match="terminal"):
        store.change_capability_grant_state(
            state["grant"]["grant_id"],
            status="active",
            now_ms=6000,
            current_environment=state["current_environment"],
        )


def test_registered_task_remains_cancellation_obligation_after_revoke(saved):
    store, state, _, _ = saved
    lease = reserve(saved)
    start(saved, lease)
    register(saved, lease)
    stopped = store.change_capability_grant_state(
        state["grant"]["grant_id"], status="revoked", now_ms=6000
    )
    assert stopped["tasks"] == [
        {
            "task_id": "task-one",
            "request_hash": content_hash("task-one"),
            "attempt_id": lease["attempt_id"],
        }
    ]
    with pytest.raises(ProductStoreError):
        register(saved, lease, task_id="task-two", step_id="prepare", now_ms=7000)
    with pytest.raises(ProductStoreError):
        store.settle_capability_attempt(lease["attempt_id"], closed(lease, ["task-one"]))
    store.record_capability_task_terminal(
        "task-one",
        request_hash=content_hash("task-one"),
        terminal_digest=content_hash("authenticated-terminal"),
    )
    store.settle_capability_attempt(lease["attempt_id"], closed(lease, ["task-one"]))
    assert store.get_capability_attempt(lease["attempt_id"])["state"] == "settled"


def test_exact_tasks_and_receiver_generation_cannot_be_rebound(saved):
    store, _, _, _ = saved
    lease = reserve(saved)
    start(saved, lease)
    register(saved, lease)
    with pytest.raises(ProductStoreError, match="already claimed"):
        register(saved, lease, task_id="task-two")
    with pytest.raises(ProductStoreError, match="outside"):
        register(saved, lease, task_id="task-two", step_id="unregistered")
    with pytest.raises(ProductStoreError, match="another receiver"):
        store.bind_capability_receiver(
            lease["attempt_id"],
            session_generation="different",
            review_digest=content_hash("session-review"),
        )


def test_preparation_interruption_is_not_settled_without_exact_close(saved):
    store, state, _, _ = saved
    lease = reserve(saved)
    claim(saved, lease)
    store.start_capability_preparation(
        lease["attempt_id"], now_ms=4500, current_environment=state["current_environment"]
    )
    store.interrupt_active_capability_grants(now_ms=5000)
    with pytest.raises(ProductStoreError):
        store.settle_capability_attempt(lease["attempt_id"], unused(lease))
    with pytest.raises(ProductStoreError, match="Settle"):
        store.change_capability_grant_state(
            state["grant"]["grant_id"],
            status="active",
            now_ms=5500,
            current_environment=state["current_environment"],
        )
    store.bind_capability_receiver(
        lease["attempt_id"],
        session_generation="generation-" + lease["attempt_id"],
        review_digest=content_hash("session-review"),
    )
    store.settle_capability_attempt(lease["attempt_id"], closed(lease))
    store.change_capability_grant_state(
        state["grant"]["grant_id"],
        status="active",
        now_ms=6000,
        current_environment=state["current_environment"],
    )
    with pytest.raises(ProductStoreError):
        claim(saved, lease, now_ms=6500)


@pytest.mark.parametrize("boundary", ["grant", "attempt", "clock_backwards", "environment"])
def test_deadlines_clock_and_context_are_rechecked(saved, boundary):
    lease = reserve(saved)
    now = 4000
    environment = deepcopy(saved[1]["current_environment"])
    if boundary == "grant":
        now = saved[1]["grant"]["expires_at_ms"]
    elif boundary == "attempt":
        now = lease["business_expires_at_ms"]
    elif boundary == "clock_backwards":
        now = 2999
    else:
        environment["environment_generation"] = "changed"
    with pytest.raises(ProductStoreError):
        saved[0].claim_capability_attempt(
            lease["attempt_id"],
            lease_digest=lease["lease_digest"],
            now_ms=now,
            current_environment=environment,
        )


def test_control_usage_blocks_rollback_and_retest_until_settled(saved):
    store, state, _, _ = saved
    lease = reserve(saved)
    owner_id = state["current_environment"]["control_owner_id"]
    rollback = {
        "decision": "rollback",
        "control_digest": state["current_environment"]["control_digest"],
    }
    with pytest.raises(ProductStoreError, match="Settle"):
        receiver.rollback_control(store, owner_id, rollback)
    with store._connection(write=True) as connection:
        owner = receiver.owner_at(store, connection, owner_id)
        linked = deepcopy(owner)
        linked["request"]["context"]["source_control"] = {
            "job_id": owner_id,
            "control_digest": state["current_environment"]["control_digest"],
        }
        with pytest.raises(ProductStoreError, match="Settle"):
            receiver.guard_source(store, connection, linked, publication=True)
    store.settle_capability_attempt(lease["attempt_id"], unused(lease))
    receiver.rollback_control(store, owner_id, rollback)
    with pytest.raises(ProductStoreError, match="retained control changed"):
        reserve(saved, now_ms=5000)


@pytest.mark.parametrize("other", ["rollback", "retest"])
def test_receiver_and_composition_admission_share_one_writer_barrier(saved, other):
    store, state, _, _ = saved
    stores = [ProductStore(store.path), ProductStore(store.path)]
    barrier = threading.Barrier(2)
    environment = state["current_environment"]
    owner_id = environment["control_owner_id"]

    def composition():
        barrier.wait()
        try:
            reserve(saved, store=stores[0])
            return True
        except ProductStoreError:
            return False

    def receiver_operation():
        barrier.wait()
        try:
            if other == "rollback":
                receiver.rollback_control(
                    stores[1],
                    owner_id,
                    {"decision": "rollback", "control_digest": environment["control_digest"]},
                )
            else:
                with stores[1]._connection(write=True) as connection:
                    parent = receiver.owner_at(stores[1], connection, owner_id)
                    linked = deepcopy(parent)
                    linked["request"]["context"]["source_control"] = {
                        "job_id": owner_id,
                        "control_digest": environment["control_digest"],
                    }
                    receiver.guard_source(stores[1], connection, linked, publication=True)
                    connection.execute(
                        "INSERT INTO jobs(job_id,kind,state,request_json,progress_json,created_at,updated_at) VALUES(?,'receiver.defense','queued',?,'{}','fixture','fixture')",
                        ("job-" + uuid.uuid4().hex, canonical_json(linked["request"])),
                    )
            return True
        except ProductStoreError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(composition), pool.submit(receiver_operation)]
        winners = [future.result() for future in futures]
    assert sum(winners) == 1


def test_task_claim_and_revocation_linearize_without_losing_cancel_identity(saved):
    store, state, _, _ = saved
    lease = reserve(saved)
    start(saved, lease)
    stores = [ProductStore(store.path), ProductStore(store.path)]
    barrier = threading.Barrier(2)

    def task():
        barrier.wait()
        try:
            stores[0].register_capability_task(
                lease["attempt_id"],
                task_id="raced-task",
                step_id="seed",
                request_hash=content_hash("raced-task"),
                now_ms=5000,
                current_environment=state["current_environment"],
            )
            return True
        except ProductStoreError:
            return False

    def revoke():
        barrier.wait()
        return stores[1].change_capability_grant_state(
            state["grant"]["grant_id"], status="revoked", now_ms=5000
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        claimed = pool.submit(task)
        stopped = pool.submit(revoke)
        won, state_after = claimed.result(), stopped.result()
    assert bool(state_after["tasks"]) is won
    if won:
        assert state_after["tasks"][0]["task_id"] == "raced-task"
    assert store.get_capability_attempt(lease["attempt_id"])["state"] == "claimed"


def test_clock_cannot_move_backwards_between_task_claims_or_grant_versions(saved):
    store, state, _, args = saved
    lease = reserve(saved)
    start(saved, lease)
    register(saved, lease, now_ms=7000)
    assert (
        store.get_capability_grant(state["grant"]["grant_id"], now_ms=6500)["status"]
        == "clock_uncertain"
    )
    with pytest.raises(ProductStoreError):
        register(saved, lease, task_id="later", step_id="prepare", now_ms=6500)
    grant = deepcopy(state["grant"])
    grant["grant_id"] = "grant-" + "e" * 32
    grant["grant_digest"] = content_hash(
        {key: value for key, value in grant.items() if key != "grant_digest"}
    )
    with pytest.raises(ProductStoreError, match="clock moved backwards"):
        store.save_capability_grant(grant, lineage_id="lineage-1", **{**args, "now_ms": 6000})
    assert (
        store.change_capability_grant_state(
            state["grant"]["grant_id"], status="paused", now_ms=6000
        )["status"]
        == "paused"
    )


def test_reenrollment_or_generation_change_does_not_hide_busy_endpoint(saved):
    store, state, _, _ = saved
    lease = reserve(saved)
    environment = {
        **state["current_environment"],
        "environment_generation": "new-generation",
        "runner_id": "new-runner",
    }
    with store._connection() as connection:
        with pytest.raises(ProductStoreError, match="unsettled attempt"):
            records._endpoint_settled(store, connection, environment)
        records._endpoint_settled(
            store, connection, {**environment, "environment_id": "another-isolated-lab"}
        )
    store.settle_capability_attempt(lease["attempt_id"], unused(lease))
    with store._connection() as connection:
        records._endpoint_settled(store, connection, environment)


@pytest.mark.parametrize("damage", ["missing", "rehashed_provenance"])
def test_damaged_authority_claim_never_settles_effects_but_stop_still_works(saved, damage):
    store, state, _, _ = saved
    lease = reserve(saved)
    start(saved, lease)
    register(saved, lease)
    with store._connection(write=True) as connection:
        if damage == "missing":
            connection.execute("DROP TRIGGER capability_attempt_claims_no_delete")
            connection.execute("DELETE FROM capability_attempt_claims")
        else:
            row = connection.execute("SELECT * FROM capability_attempt_claims").fetchone()
            value = records._document(row)
            value["issuer"] = "forged-issuer"
            connection.execute("DROP TRIGGER capability_attempt_claims_no_update")
            connection.execute(
                "UPDATE capability_attempt_claims SET document_json=?,document_digest=?",
                (canonical_json(value), content_hash(value)),
            )
    with pytest.raises(ProductStoreError):
        store.get_capability_attempt(lease["attempt_id"])
    stopped = store.change_capability_grant_state(
        state["grant"]["grant_id"], status="revoked", now_ms=6000
    )
    assert stopped["status"] == "revoked"
    assert stopped["cleanup_state"] == "pending_cleanup"
    assert stopped["tasks"][0]["task_id"] == "task-one"


def test_missing_task_relation_does_not_roll_back_stop(saved):
    store, state, _, _ = saved
    lease = reserve(saved)
    start(saved, lease)
    with store._connection(write=True) as connection:
        connection.execute("DROP TABLE capability_task_claims")
    stopped = store.change_capability_grant_state(
        state["grant"]["grant_id"], status="revoked", now_ms=6000
    )
    assert stopped["status"] == "revoked"
    assert stopped["cancellation_enumeration_complete"] is False
    assert stopped["cleanup_state"] == "unknown"
    with store._connection() as connection:
        assert (
            connection.execute(
                "SELECT status FROM capability_grant_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()[0]
            == "revoked"
        )


@pytest.mark.parametrize("damage", ["missing_usage", "corrupt_usage", "missing_settlement"])
def test_missing_or_corrupt_relations_block_reuse_but_stop_remains_available(saved, damage):
    store, state, _, _ = saved
    lease = reserve(saved)
    store.settle_capability_attempt(lease["attempt_id"], unused(lease))
    table = (
        "capability_attempt_settlements"
        if damage == "missing_settlement"
        else "capability_control_usages"
    )
    with store._connection(write=True) as connection:
        if damage == "corrupt_usage":
            connection.execute(f"DROP TRIGGER {table}_no_update")
            connection.execute(f"UPDATE {table} SET document_json='{{}}'")
        else:
            connection.execute(f"DROP TRIGGER {table}_no_delete")
            connection.execute(f"DELETE FROM {table}")
    owner_id = state["current_environment"]["control_owner_id"]
    with store._connection() as connection:
        assert not records.control_usages_settled(store, connection, owner_id)
    with pytest.raises(ProductStoreError):
        reserve(saved, now_ms=6000)
    assert (
        store.change_capability_grant_state(
            state["grant"]["grant_id"], status="paused", now_ms=7000
        )["status"]
        == "paused"
    )
    assert (
        store.change_capability_grant_state(
            state["grant"]["grant_id"], status="revoked", now_ms=8000
        )["status"]
        == "revoked"
    )


@pytest.mark.parametrize("table", list(schema_api._TABLES))
def test_authority_history_tables_are_append_only(saved, table):
    store = saved[0]
    lease = reserve(saved)
    start(saved, lease)
    register(saved, lease)
    cleanup_complete(saved, lease)
    store.settle_capability_attempt(lease["attempt_id"], closed(lease, ["task-one"]))
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        with store._connection(write=True) as connection:
            connection.execute(f"DELETE FROM {table}")


def test_changed_compiled_reservation_and_baseline_count_refused(saved):
    store, state, compiled, args = saved
    changed = deepcopy(compiled)
    changed["reservation"]["generated_bytes"] = 0
    changed["compiled_digest"] = content_hash(
        {key: value for key, value in changed.items() if key != "compiled_digest"}
    )
    with pytest.raises(ProductStoreError, match="resource reservation"):
        reserve(saved, compiled=changed)
    changed_grant = deepcopy(state["grant"])
    changed_grant["objective"]["predicate"]["record_count"] = 1
    regenerated = create_grant(
        registry=state["registry"],
        implementation_digests=state["implementation_digests"],
        **{
            key: changed_grant[key]
            for key in (
                "objective",
                "environment",
                "limits",
                "approved_by",
                "created_at_ms",
                "expires_at_ms",
            )
        },
        grant_id="grant-" + "d" * 32,
    )
    with pytest.raises(ProductStoreError, match="original synthetic record count"):
        store.save_capability_grant(regenerated, lineage_id="count-change", **args)


@pytest.mark.parametrize("fail", [False, True])
def test_schema8_upgrade_preserves_history_and_is_transactional(tmp_path, monkeypatch, fail):
    path = tmp_path / "prior.sqlite3"
    with monkeypatch.context() as prior:
        prior.setattr(store_module, "SCHEMA_VERSION", 8)
        prior.setattr(schema_api, "initialize_schema", lambda _connection: None)
        store = ProductStore(path)
        store.set_setting("unit.preserved", {"value": "preserved"})
        original_job = store.create_job("unit.job", {"purpose": "preserved"})
        assert store.schema_version == 8
    initialize = schema_api.initialize_schema

    def interrupted(connection):
        initialize(connection)
        raise sqlite3.OperationalError("fixture interrupted schema")

    if fail:
        monkeypatch.setattr(schema_api, "initialize_schema", interrupted)
        with pytest.raises(ProductStoreError, match="migration failed"):
            ProductStore(path)
        with sqlite3.connect(path) as connection:
            assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone() == (
                8,
            )
            assert (
                connection.execute(
                    "SELECT name FROM sqlite_master WHERE name LIKE 'capability_%'"
                ).fetchall()
                == []
            )
    else:
        upgraded = ProductStore(path)
        assert upgraded.schema_version == 9
        assert upgraded.get_setting("unit.preserved") == {"value": "preserved"}
        assert upgraded.get_job(original_job["job_id"]) == original_job
