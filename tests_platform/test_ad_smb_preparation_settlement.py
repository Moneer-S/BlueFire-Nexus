"""Control-plane settlement for AD stages that never retained an original run."""

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from types import SimpleNamespace

import pytest

from bluefire import ad_smb_results as results
from bluefire import product_store_ad_smb as records
from bluefire.ad_smb_contract import AdSmbError
from bluefire.ad_smb_jobs import AdSmbJobs
from bluefire.job_runtime import JobState
from bluefire.product_store import ProductStore
from bluefire.run_store import RunStore
from bluefire.util import content_hash
from tests_platform.test_ad_smb_contract import NOW
from tests_platform.test_ad_smb_jobs import create, submit, wait_for_ad_job
from tests_platform.test_ad_smb_jobs import workspace as workspace


def _hold_worker(controller):
    entered = threading.Event()
    release = threading.Event()

    def hold(context, _request):
        entered.set()
        while not release.is_set():
            context.cooperative_wait(0.01)

    job = controller.submit(
        "scenario.run",
        {"hold_id": str(uuid.uuid4())},
        callback=hold,
    )
    controller.wait_for_state(job["job_id"], {JobState.RUNNING}, timeout=5)
    assert entered.wait(5)
    return job["job_id"], release


def _request(jobs, identifier, phase):
    review = jobs.review(identifier, phase)
    submission_id = str(uuid.uuid4())
    return submission_id, {
        "submission_id": submission_id,
        "phase": phase,
        "review_digest": review["review_digest"],
        "reviewed_by": "fixture-operator",
    }


def _assert_preparation_settlement(recovered, service, child, phase, state):
    progress = recovered["workflow"]["progress"]
    assert progress["pending_operation"] is None
    settlement = progress["preparation_history"][-1]
    assert settlement == {
        "schema_version": "bluefire.ad-smb-preparation-settlement.v1",
        "operation_job_id": child["job_id"],
        "phase": phase,
        "terminal_state": state,
        "reserved_at": child["created_at"],
        "settled_at": child["updated_at"],
        "request_digest": content_hash(child["request"]),
        "boundary": "before_run_retained",
        "producer": "bluefire.ad-smb-controller",
    }
    saved = service.product_store.get_job(child["job_id"])
    assert saved["progress"]["preparation_settlement"] == settlement
    assert saved["result_ref"] is None
    assert saved["progress"]["run_id"] is None
    assert saved["progress"]["tasks"] == []
    return settlement


def test_queued_cancellation_settles_without_dispatch_and_keeps_reserved_budget(
    workspace,
):
    jobs, executor, service = workspace
    identifier = create(jobs)
    assert submit(jobs, identifier, "inspect")[0]["state"] == "completed"
    remaining_before = jobs.read(identifier)["remaining"]
    calls_before = deepcopy(executor.calls)
    runs_before = {path.name for path in service.store.root.iterdir()}
    held_id, release = _hold_worker(service.job_controller)
    child, _ = submit(jobs, identifier, "baseline", wait=False)
    assert child["state"] == "queued"
    terminal = service.job_controller.cancel(child["job_id"])
    assert terminal["state"] == "cancelled"
    remaining_reserved = jobs.read(identifier)["remaining"]
    budget = results.phase_budget("baseline")
    assert remaining_reserved == {
        key: remaining_before[key] - amount for key, amount in budget.items()
    }
    release.set()
    wait_for_ad_job(service.job_controller, held_id)

    recovered = jobs.recover(identifier)

    _assert_preparation_settlement(recovered, service, terminal, "baseline", "cancelled")
    assert recovered["remaining"] == remaining_reserved
    assert recovered["workflow"]["progress"]["reserved"] == budget
    assert [row["phase"] for row in recovered["workflow"]["progress"]["operations"]] == ["inspect"]
    assert executor.calls == calls_before
    assert executor.recovered == []
    assert {path.name for path in service.store.root.iterdir()} == runs_before
    assert "baseline" in recovered["allowed_phases"]

    retried, _ = submit(jobs, identifier, "baseline")
    assert retried["state"] == "completed"
    continued = jobs.read(identifier)
    assert [row["phase"] for row in continued["workflow"]["progress"]["operations"]] == [
        "inspect",
        "baseline",
    ]
    assert (
        continued["workflow"]["progress"]["preparation_history"]
        == recovered["workflow"]["progress"]["preparation_history"]
    )
    assert len(executor.calls) == len(calls_before) + 3


def test_planning_cancellation_uses_the_same_exact_preparation_boundary(workspace):
    jobs, executor, service = workspace
    identifier = create(jobs)
    held_id, release = _hold_worker(service.job_controller)
    child, _ = submit(jobs, identifier, "inspect", wait=False)
    planning = service.product_store.transition_job(
        child["job_id"],
        "planning",
        progress={**child["progress"], "phase": "planning"},
    )
    assert planning["progress"] == {"tasks": [], "run_id": None, "phase": "planning"}
    terminal = service.job_controller.cancel(child["job_id"])
    assert terminal["state"] == "cancelled"
    release.set()
    wait_for_ad_job(service.job_controller, held_id)

    recovered = jobs.recover(identifier)

    _assert_preparation_settlement(recovered, service, terminal, "inspect", "cancelled")
    assert recovered["workflow"]["progress"]["operations"] == []
    assert executor.calls == [] and executor.recovered == []


def test_scheduling_failure_after_reservation_is_discoverable_and_not_retried(
    workspace, monkeypatch
):
    jobs, executor, service = workspace
    identifier = create(jobs)
    submission_id, request = _request(jobs, identifier, "inspect")

    def refuse_schedule(*_args, **_kwargs):
        raise RuntimeError("authored scheduler refusal")

    monkeypatch.setattr(service.job_controller._executor, "submit", refuse_schedule)
    with pytest.raises(RuntimeError, match="scheduler refusal"):
        jobs.submit(identifier, request)
    child_id = "job-" + uuid.UUID(submission_id).hex
    terminal = service.product_store.get_job(child_id)
    assert terminal["state"] == "failed"
    assert terminal["error"] == {
        "code": "job_scheduling_failed",
        "message": "background job could not be scheduled",
    }

    recovered = jobs.recover(identifier)

    _assert_preparation_settlement(recovered, service, terminal, "inspect", "failed")
    assert jobs.recover(identifier) == recovered
    assert executor.calls == [] and executor.recovered == []
    assert service.store.list_runs() == []


def test_restart_interrupted_queued_preparation_settles_without_a_callback(workspace):
    jobs, executor, service = workspace
    identifier = create(jobs)
    _held_id, release = _hold_worker(service.job_controller)
    child, _ = submit(jobs, identifier, "inspect", wait=False)
    assert child["state"] == "queued"
    restarted_store = ProductStore(service.product_store.path)
    assert restarted_store.recover_interrupted_jobs() >= 1
    terminal = restarted_store.get_job(child["job_id"])
    assert terminal["state"] == "interrupted"
    # A real restart has no old in-process future. Cancel this deliberately
    # queued fixture future so it models that boundary before local recovery.
    assert service.job_controller._controls[child["job_id"]].future.cancel()

    recovered = AdSmbJobs(
        SimpleNamespace(
            product_store=restarted_store,
            store=RunStore(service.store.root),
            job_controller=service.job_controller,
        ),
        executor,
        clock=lambda: NOW,
    ).recover(identifier)
    release.set()

    _assert_preparation_settlement(recovered, service, terminal, "inspect", "interrupted")
    assert executor.calls == [] and executor.recovered == []
    assert service.store.list_runs() == []


def test_failure_after_run_folder_creation_never_links_or_reads_the_orphan(workspace, monkeypatch):
    jobs, executor, service = workspace
    identifier = create(jobs)

    def refuse_retain(*_args, **_kwargs):
        raise AdSmbError("authored refusal before run retention")

    monkeypatch.setattr(records, "retain_run", refuse_retain)
    terminal, _ = submit(jobs, identifier, "inspect")
    assert terminal["state"] == "failed"
    assert terminal["progress"]["run_id"] is None
    orphaned = {path.name for path in service.store.root.iterdir()}
    assert len(orphaned) == 1

    def no_run_or_executor_access(*_args, **_kwargs):
        pytest.fail("preparation settlement must remain local to the product store")

    for name in ("create_run", "read_json", "read_events", "write_json", "append_event"):
        monkeypatch.setattr(service.store, name, no_run_or_executor_access)
    for name in ("environments", "readiness", "execute", "recover_original"):
        monkeypatch.setattr(executor, name, no_run_or_executor_access)

    recovered = jobs.recover(identifier)

    settlement = _assert_preparation_settlement(recovered, service, terminal, "inspect", "failed")
    assert "run_id" not in settlement
    assert recovered["workflow"]["progress"]["operations"] == []
    assert {path.name for path in service.store.root.iterdir()} == orphaned


def test_concurrent_preparation_recovery_appends_once_and_is_idempotent(workspace, monkeypatch):
    jobs, executor, service = workspace
    identifier = create(jobs)
    monkeypatch.setattr(
        service.store,
        "create_run",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("authored pre-run failure")),
    )
    terminal, _ = submit(jobs, identifier, "inspect")
    assert terminal["state"] == "failed"
    first = AdSmbJobs(
        SimpleNamespace(
            product_store=ProductStore(service.product_store.path),
            store=RunStore(service.store.root),
            job_controller=service.job_controller,
        ),
        executor,
        clock=lambda: NOW,
    )
    second = AdSmbJobs(
        SimpleNamespace(
            product_store=ProductStore(service.product_store.path),
            store=RunStore(service.store.root),
            job_controller=service.job_controller,
        ),
        executor,
        clock=lambda: NOW,
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        values = [
            future.result(timeout=10)
            for future in (
                pool.submit(first.recover, identifier),
                pool.submit(second.recover, identifier),
            )
        ]

    assert values[0] == values[1]
    history = values[0]["workflow"]["progress"]["preparation_history"]
    assert len(history) == 1 and history[0]["operation_job_id"] == terminal["job_id"]
    assert first.recover(identifier) == values[0]
    assert executor.calls == [] and executor.recovered == []


@pytest.mark.parametrize(
    "changed_progress",
    [
        {"tasks": [{"index": 0}], "run_id": None, "phase": "failed"},
        {"tasks": [], "run_id": None, "phase": "failed", "initial_run": {}},
        {"tasks": [], "run_id": None, "phase": "completed"},
    ],
)
def test_changed_preparation_context_keeps_the_reservation(
    workspace, monkeypatch, changed_progress
):
    jobs, _executor, service = workspace
    identifier = create(jobs)
    monkeypatch.setattr(
        service.store,
        "create_run",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("authored pre-run failure")),
    )
    terminal, _ = submit(jobs, identifier, "inspect")
    service.product_store.transition_job(
        terminal["job_id"], terminal["state"], progress=changed_progress
    )

    with pytest.raises(AdSmbError, match="untouched operation"):
        jobs.recover(identifier)

    progress = service.product_store.get_job(identifier)["progress"]
    assert progress["pending_operation"] == terminal["job_id"]
    assert "preparation_history" not in progress


def test_result_reference_without_a_retained_run_cannot_be_settled(workspace, monkeypatch):
    jobs, _executor, service = workspace
    identifier = create(jobs)
    monkeypatch.setattr(
        service.store,
        "create_run",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("authored pre-run failure")),
    )
    terminal, _ = submit(jobs, identifier, "inspect")
    service.product_store.transition_job(
        terminal["job_id"], terminal["state"], result_ref="run-untrusted"
    )

    with pytest.raises(AdSmbError, match="untouched operation"):
        jobs.recover(identifier)

    progress = service.product_store.get_job(identifier)["progress"]
    assert progress["pending_operation"] == terminal["job_id"]
    assert "preparation_history" not in progress


def test_retained_original_task_recovery_stays_execution_history_only(workspace):
    jobs, executor, service = workspace
    identifier = create(jobs)
    executor.crash = True
    terminal, _ = submit(jobs, identifier, "inspect")
    assert terminal["state"] == "failed"
    assert terminal["progress"]["run_id"] is not None
    assert terminal["progress"]["tasks"][0]["context"] is not None

    recovered = jobs.recover(identifier)

    progress = recovered["workflow"]["progress"]
    assert "preparation_history" not in progress
    assert len(progress["operations"]) == 1
    assert progress["operations"][0]["job_id"] == terminal["job_id"]
    assert service.store.validate_bundle(progress["operations"][0]["run_id"])["valid"]


def test_preparation_history_keeps_all_six_pointers_and_closes_new_admission(
    workspace, monkeypatch
):
    jobs, executor, service = workspace
    identifier = create(jobs)
    monkeypatch.setattr(
        service.store,
        "create_run",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("authored pre-run failure")),
    )
    identifiers = []
    for _ in range(results.PREPARATION_HISTORY_LIMIT):
        terminal, _request_row = submit(jobs, identifier, "inspect")
        identifiers.append(terminal["job_id"])
        jobs.recover(identifier)

    saved = jobs.read(identifier)
    history = saved["workflow"]["progress"]["preparation_history"]
    assert [row["operation_job_id"] for row in history] == identifiers
    assert saved["allowed_phases"] == []
    with pytest.raises(AdSmbError, match="history is full; start a new saved exercise"):
        jobs.review(identifier, "inspect")
    assert executor.calls == [] and executor.recovered == []
    assert service.store.list_runs() == []


def test_hardened_owner_reserves_the_last_preparation_pointer_for_rollback(workspace, monkeypatch):
    jobs, executor, service = workspace
    identifier = create(jobs)
    for phase in ("inspect", "baseline", "harden"):
        terminal, _ = submit(jobs, identifier, phase)
        assert terminal["state"] == "completed"
    calls_before = deepcopy(executor.calls)
    monkeypatch.setattr(
        service.store,
        "create_run",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("authored pre-run failure")),
    )

    for _ in range(results.PREPARATION_HISTORY_LIMIT - 1):
        terminal, _ = submit(jobs, identifier, "audit")
        assert terminal["state"] == "failed"
        jobs.recover(identifier)

    saved = jobs.read(identifier)
    assert saved["workflow"]["progress"]["policy_state"] == "hardened"
    assert len(saved["workflow"]["progress"]["preparation_history"]) == 5
    assert saved["allowed_phases"] == ["rollback"]
    with pytest.raises(AdSmbError, match="needs settled original evidence"):
        jobs.review(identifier, "audit")

    terminal, _ = submit(jobs, identifier, "rollback")
    assert terminal["state"] == "failed"
    settled = jobs.recover(identifier)
    history = settled["workflow"]["progress"]["preparation_history"]
    assert len(history) == results.PREPARATION_HISTORY_LIMIT
    assert history[-1]["phase"] == "rollback"
    assert settled["allowed_phases"] == []
    assert executor.calls == calls_before
    assert executor.recovered == []


def test_changed_owner_reservation_or_history_marker_is_refused(workspace, monkeypatch):
    jobs, _executor, service = workspace
    identifier = create(jobs)
    monkeypatch.setattr(
        service.store,
        "create_run",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("authored pre-run failure")),
    )
    terminal, _ = submit(jobs, identifier, "inspect")
    with service.product_store._connection(write=True) as connection:
        owner = records.owner_at(service.product_store, connection, identifier)
        records.patch(connection, owner, {"pending_operation": "job-" + "f" * 32})
    with pytest.raises(AdSmbError, match="no longer the exact reserved stage"):
        records.settle_preparation(service.product_store, terminal["job_id"])
    with service.product_store._connection(write=True) as connection:
        owner = records.owner_at(service.product_store, connection, identifier)
        records.patch(connection, owner, {"pending_operation": terminal["job_id"]})
    jobs.recover(identifier)

    saved_child = service.product_store.get_job(terminal["job_id"])
    changed = {
        **saved_child["progress"]["preparation_settlement"],
        "terminal_state": "interrupted",
    }
    with service.product_store._connection(write=True) as connection:
        saved_child = records.job_at(service.product_store, connection, terminal["job_id"])
        records.patch(connection, saved_child, {"preparation_settlement": changed})
    with pytest.raises(AdSmbError, match="terminal child marker"):
        jobs.read(identifier)


def test_preparation_child_cannot_also_be_retained_execution_history(workspace, monkeypatch):
    jobs, _executor, service = workspace
    identifier = create(jobs)
    monkeypatch.setattr(
        service.store,
        "create_run",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("authored pre-run failure")),
    )
    terminal, _ = submit(jobs, identifier, "inspect")
    jobs.recover(identifier)

    with service.product_store._connection(write=True) as connection:
        owner = records.owner_at(service.product_store, connection, identifier)
        records.patch(connection, owner, {"operations": [{"job_id": terminal["job_id"]}]})

    with pytest.raises(AdSmbError, match="cannot also be retained execution history"):
        jobs.read(identifier)


def test_explicit_null_preparation_history_is_not_legacy_absence(workspace):
    jobs, executor, service = workspace
    identifier = create(jobs)
    assert "preparation_history" not in jobs.read(identifier)["workflow"]["progress"]
    with service.product_store._connection(write=True) as connection:
        owner = records.owner_at(service.product_store, connection, identifier)
        records.patch(connection, owner, {"preparation_history": None})
    calls = deepcopy(executor.calls)

    for operation in (
        lambda: jobs.read(identifier),
        jobs.list,
        lambda: jobs.recover(identifier),
    ):
        with pytest.raises(AdSmbError, match="history exceeds its closed bound"):
            operation()

    assert executor.calls == calls
    assert service.store.list_runs() == []
