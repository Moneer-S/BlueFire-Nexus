"""Public correction lifecycle with real SQLite/jobs and fake native boundaries."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from bluefire import file_access_context
from bluefire import windows_file_access_context as windows_context
from bluefire import windows_file_access_correction_observation as observation
from bluefire.file_access_contract import FileAccessContractError
from bluefire.file_access_control import FileAccessControl
from bluefire.job_runtime import RunJobController
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.service import BlueFireService
from tests_platform import test_windows_file_access_correction_execution as native_fake
from tests_platform.test_windows_file_access_baseline_publication import at_ms
from tests_platform.test_windows_file_access_baseline_publication import saved as saved
from tests_platform.test_windows_file_access_correction_reservation import reviewed as reviewed
from tests_platform.test_windows_file_access_execution import occupied_controller
from tests_platform.test_windows_file_access_pair_provenance import paired as paired
from tests_platform.test_windows_file_access_setup_lifecycle import ISSUED
from tests_platform.test_windows_file_access_setup_lifecycle import lifecycle as lifecycle


def forbidden(*args, **kwargs):
    pytest.fail("Public reads/recovery must not observe, decrypt, or launch native work")


def assert_no_job(store, job_id):
    with pytest.raises(ProductStoreError, match="job was not found"):
        store.get_job(job_id)


@pytest.fixture
def connected(reviewed, paired, monkeypatch):
    # Defer only the fake harness's initial reservation. Public submit below owns
    # the actual SQLite reservation and scheduling; no store guard is replaced.
    expected_job = "job-" + reviewed.original["submitted_request"]["submission_id"].replace("-", "")
    with monkeypatch.context() as initializing:
        initializing.setattr(native_fake, "reserve", lambda _: ({"job_id": expected_job}, True))
        value = native_fake.execution.__wrapped__(reviewed, paired, monkeypatch)
    service = object.__new__(BlueFireService)
    service.product_store = value.store
    service.runner_lifecycle = value.control.service.runner_lifecycle
    service.job_controller = RunJobController(value.store, recover_on_start=False, max_workers=1)
    service._file_access = FileAccessControl(service, clock=lambda: value.state.wall)
    control = service.file_access
    control.windows_correction = value.runtime
    value.runtime.control = control
    monkeypatch.setattr(file_access_context, "is_macos_host", lambda: False)
    monkeypatch.setattr(file_access_context, "is_windows_host", lambda: True)
    monkeypatch.setattr(windows_context, "_clock", lambda: at_ms(value.state.wall))
    monkeypatch.setattr(control.windows, "execute", forbidden)
    monkeypatch.setattr(control.windows, "recover", forbidden)
    value.service, value.control = service, control
    value.owner = reviewed.saved["imported"]["control_owner_id"]
    assert (
        value.store.file_access_operation_records(reviewed.saved["job"])["outcome"]["state"]
        == "complete"
    )
    assert_no_job(value.store, expected_job)
    try:
        yield value
    finally:
        service.job_controller.shutdown()


def request_for(value, *, submission_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"):
    selector = {"operation": "harden", "control_owner_id": value.owner}
    review = value.service.file_access_review(selector)
    return {
        "submission_id": submission_id,
        "review": selector,
        "review_digest": review["review_digest"],
        "reviewed_by": "synthetic-operator",
    }, review


def submit(value, request=None):
    request = request or request_for(value)[0]
    response = value.service.submit_file_access_operation(request)
    job_id = response["job"]["job_id"]
    terminal = value.service.job_controller.wait(job_id, timeout=20)
    return request, job_id, terminal


def records(value, job_id=None):
    return value.store.file_access_operation_records(job_id or value.job)


def reconciliation(value, digest, *, submission_id="dddddddd-dddd-4ddd-8ddd-dddddddddddd"):
    return {
        "submission_id": submission_id,
        "expected_outcome_digest": digest,
        "reviewed_by": "synthetic-operator",
    }


def no_new_work(value):
    native_fake._forbid_new_work(value)
    value.monkeypatch.setattr(value.control.windows, "recover", forbidden)


def test_public_review_submit_and_exact_replay_publish_one_correction(connected):
    v = connected
    initial = v.service.file_access_control(v.owner)
    assert initial["schema_version"] == "bluefire.windows-file-access-control.v3"
    assert initial["revision"] == 2 and initial["allowed_operations"] == ["harden"]
    request, review = request_for(v)
    assert "protected DACL" in review["effect"] and "not renewed" in review["effect"]
    assert "0640" not in review["effect"] and "independently" not in review["effect"]
    assert review["control_digest"] == initial["control_digest"]
    assert review["expires_at_ms"] == initial["expires_at_ms"]
    _, job_id, terminal = submit(v, request)
    assert terminal["state"] == "completed"
    original = records(v)
    public = v.service.file_access_operation(job_id)
    assert public["reconciliation"]["state"] == "complete"
    assert public["control"]["schema_version"] == "bluefire.windows-file-access-control.v3"
    assert public["control"]["status"] == "hardened" and public["control"]["revision"] == 3
    assert public["control"]["allowed_operations"] == []
    assert public["control"]["baseline"] == initial["baseline"]
    assert public["control"]["retest"]["non_owner"] == "data_access_denied"
    assert public["control"]["retest"]["owner"] == "allowed"
    no_new_work(v)
    assert v.service.submit_file_access_operation(request)["job"]["job_id"] == job_id
    assert records(v) == original
    listing = v.service.list_file_access_controls({})["controls"]
    assert listing == [
        {"control_owner_id": v.owner, "status": "hardened", "revision": 3, "platform": "windows"}
    ]
    assert len(v.state.controls) == len(v.state.launches) == 1
    assert v.state.buffers and all(not any(buffer) for buffer in v.state.buffers)


@pytest.mark.parametrize("fault", ["descriptor", "digest", "expired", "platform"])
def test_changed_review_refuses_before_reservation_or_dispatch(connected, fault):
    v = connected
    request, review = request_for(v)
    if fault == "descriptor":
        v.value.original["review_context"]["previous_descriptor_sha256"] = "sha256:" + "8" * 64
    elif fault == "digest":
        request["review_digest"] = "sha256:" + "9" * 64
    elif fault == "expired":
        v.state.wall = review["expires_at_ms"]
    else:
        v.monkeypatch.setattr(file_access_context, "is_windows_host", lambda: False)

        def unavailable(*args, **kwargs):
            raise FileAccessContractError("Synthetic unavailable Linux enrollment")

        v.monkeypatch.setattr(file_access_context, "enrollment", unavailable)
    with pytest.raises((ProductStoreError, FileAccessContractError)):
        v.service.submit_file_access_operation(request)
    assert_no_job(v.store, v.job)
    assert v.state.controls == v.state.launches == []


@pytest.mark.parametrize("operation", ["create", "baseline", "rollback", "reset"])
def test_completed_windows_baseline_offers_only_harden(connected, operation):
    v = connected
    selector = {
        "operation": operation,
        "control_owner_id": None if operation == "create" else v.owner,
    }
    with pytest.raises((ProductStoreError, FileAccessContractError)):
        v.service.file_access_review(selector)
    assert_no_job(v.store, v.job)
    assert v.state.controls == v.state.launches == []


def test_uncompleted_pair_cannot_review_harden(saved, paired, monkeypatch):
    store = saved["store"]
    service = SimpleNamespace(product_store=store)
    control = FileAccessControl(service, clock=lambda: ISSUED + 2501)
    monkeypatch.setattr(file_access_context, "is_macos_host", lambda: False)
    monkeypatch.setattr(file_access_context, "is_windows_host", lambda: True)
    monkeypatch.setattr(windows_context, "read_windows_file_setup_status", lambda **_: paired[1])
    monkeypatch.setattr(
        observation, "observe_correction_preimage", lambda *_, **__: "sha256:" + "7" * 64
    )
    with pytest.raises((ProductStoreError, ValueError)):
        control.review(
            {"operation": "harden", "control_owner_id": saved["imported"]["control_owner_id"]}
        )
    assert store.file_access_operation_records(saved["job"])["outcome"] is None
    with store._connection() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM file_access_windows_control_evidence"
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM file_access_operations WHERE operation='harden'"
            ).fetchone()[0]
            == 0
        )


def test_interrupted_dispatch_without_tasks_is_unknown_and_get_never_replays(connected):
    v = connected
    request, review = request_for(v)
    current = v.control._context("harden", v.owner)
    job, created = v.store.create_file_access_operation(
        request,
        review_document=review,
        review_context=current["review_context"],
        enrollment_id=current["enrollment"]["document"]["enrollment_id"],
        now_ms=v.state.wall,
    )
    assert created and job["job_id"] == v.job
    original = records(v)["document"]
    prepared = native_fake.module.admission.build_preparation(
        v.job,
        original,
        current["_imported"],
        current["control"]["document"],
        issued_at_ms=v.state.wall,
    )
    v.store.prepare_file_access_operation(v.job, prepared, now_ms=v.state.wall)
    native_fake.module.journal.begin_dispatch(
        v.store,
        v.job,
        binding_digest=prepared["binding_digest"],
        now_ms=v.state.wall,
        revalidate=lambda: None,
    )
    reopened = ProductStore(v.store.path)
    assert reopened.recover_interrupted_jobs() >= 1
    before = records(v)
    assert before["tasks"] == [] and before["outcome"] is None
    no_new_work(v)
    public = v.service.file_access_operation(v.job)
    assert public["job"]["state"] == "interrupted"
    assert public["reconciliation"]["state"] == "unknown" and public["reconciliation"]["available"]
    assert public["control"]["status"] == "uncertain"
    assert public["control"]["allowed_operations"] == []
    after = records(v)
    assert after["preparation"] == before["preparation"] and after["tasks"] == []
    assert set(native_fake.module.journal.control_evidence(v.store, v.job)) == {"dispatch"}
    assert v.service.file_access_operation(v.job) == public
    assert records(v) == after
    recovered = v.service.reconcile_file_access_operation(
        v.job, reconciliation(v, after["outcome_digest"])
    )
    assert recovered["reconciliation"]["state"] == "unknown"
    assert (
        recovered["reconciliation_receipt"]["problem"]["code"]
        == "file_access_reconciliation_unresolved"
    )
    assert records(v)["outcome_digest"] == after["outcome_digest"]
    assert v.state.controls == v.state.launches == []


def test_no_dispatch_interruption_is_no_effect_and_allows_a_fresh_review(connected):
    v = connected
    request, review = request_for(v)
    current = v.control._context("harden", v.owner)
    v.store.create_file_access_operation(
        request,
        review_document=review,
        review_context=current["review_context"],
        enrollment_id=current["enrollment"]["document"]["enrollment_id"],
        now_ms=v.state.wall,
    )
    v.store.recover_interrupted_jobs()
    public = v.service.file_access_operation(v.job)
    assert public["reconciliation"]["state"] == "refused_no_effect"
    assert not native_fake.module.journal.has_dispatch(v.store, v.job)
    assert records(v)["tasks"] == [] and v.state.controls == []
    fresh, _ = request_for(v, submission_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc")
    assert fresh["review_digest"] == request["review_digest"]
    # Public submission can reserve a genuinely new review. Hold its worker and
    # cancel the queued retry so the original-bound native fakes never run it.
    with occupied_controller(v):
        queued = v.service.submit_file_access_operation(fresh)["job"]
        assert queued["state"] == "queued" and queued["job_id"] != v.job
        assert v.service.job_controller.cancel(queued["job_id"])["state"] == "cancelled"
        retry = v.service.file_access_operation(queued["job_id"])
        assert retry["reconciliation"]["state"] == "refused_no_effect"
        assert not native_fake.module.journal.has_dispatch(v.store, queued["job_id"])
    assert v.state.controls == v.state.launches == []


def test_expired_public_recovery_uses_only_existing_closure_and_evidence(connected):
    v = connected
    v.state.fault = "retest_cleanup"
    request, job_id, terminal = submit(v)
    assert terminal["state"] == "failed"
    before = records(v)
    assert before["outcome"]["state"] == "unknown" and len(before["tasks"]) == 1
    owner = v.state.retest_owner
    assert owner is not None
    owner.containment.finish_failure = False
    v.state.fault = None
    v.state.wall = before["preparation"]["expires_at_ms"] + 86400000
    v.state.mono = 90000.0
    no_new_work(v)
    recovery = reconciliation(v, before["outcome_digest"])
    result = v.service.reconcile_file_access_operation(job_id, recovery)
    assert result["reconciliation"]["state"] == "complete"
    assert result["reconciliation_receipt"]["state"] == "completed"
    assert result["control"]["status"] == "hardened" and result["control"]["revision"] == 3
    assert result["control"]["allowed_operations"] == []
    assert records(v)["tasks"] == before["tasks"]
    assert job_id not in v.runtime._retest_owners
    assert owner.process._handle.closed and all(
        getattr(owner.process, name).closed for name in ("stdin", "stdout", "stderr")
    )
    assert v.service.reconcile_file_access_operation(job_id, recovery) == result
    assert v.service.submit_file_access_operation(request)["job"]["job_id"] == job_id
    assert len(v.state.controls) == len(v.state.launches) == 1
    assert v.state.buffers and all(not any(buffer) for buffer in v.state.buffers)


def test_reconstructed_runtime_recovers_only_durable_original_terminal_and_cleanup(connected):
    v = connected
    native_fake._abort(v, "publication")
    request, job_id, terminal = submit(v)
    assert terminal["state"] == "failed"
    before = records(v, job_id)
    assert before["outcome"]["state"] == "unknown" and len(before["tasks"]) == 1
    assert job_id not in v.runtime._control_owners
    assert job_id not in v.runtime._retest_owners
    with v.store._connection(write=True) as connection:
        connection.execute("DROP TRIGGER synthetic_publication_failure")

    reopened = FileAccessControl(v.service, clock=lambda: v.state.wall)
    v.service._file_access = reopened
    v.control = reopened
    v.runtime = reopened.windows_correction
    v.monkeypatch.setattr(reopened.windows, "execute", forbidden)
    v.monkeypatch.setattr(reopened.windows, "recover", forbidden)
    no_new_work(v)

    recovery = reconciliation(v, before["outcome_digest"])
    result = v.service.reconcile_file_access_operation(job_id, recovery)
    assert result["reconciliation"]["state"] == "complete"
    assert result["control"]["status"] == "hardened"
    assert result["control"]["retest"]["non_owner"] == "data_access_denied"
    assert result["control"]["retest"]["owner"] == "allowed"
    assert records(v, job_id)["tasks"] == before["tasks"]
    assert v.service.submit_file_access_operation(request)["job"]["job_id"] == job_id
    assert len(v.state.controls) == len(v.state.launches) == 1


def test_reconstructed_runtime_keeps_completed_terminal_unknown_without_original_cleanup(connected):
    v = connected
    v.state.fault = "retest_persistence"
    native_fake._abort(v, "retest")
    _, job_id, terminal = submit(v)
    assert terminal["state"] == "failed"
    before = records(v, job_id)
    assert before["outcome"]["state"] == "unknown" and len(before["tasks"]) == 1
    assert job_id not in v.runtime._retest_owners
    # Model a completed public terminal whose original watchdog cleanup result
    # was never durably published. A reconstructed runtime may not infer it.
    v.state.remote_client.result = None
    v.state.retest_owner = None
    with v.store._connection(write=True) as connection:
        connection.execute("DROP TRIGGER synthetic_retest_failure")
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM file_access_owned_process_closures "
                "WHERE task_id=?",
                (before["tasks"][0]["task"]["task_id"],),
            ).fetchone()[0]
            == 0
        )

    reopened = FileAccessControl(v.service, clock=lambda: v.state.wall)
    v.service._file_access = reopened
    v.control = reopened
    v.runtime = reopened.windows_correction
    v.monkeypatch.setattr(reopened.windows, "execute", forbidden)
    v.monkeypatch.setattr(reopened.windows, "recover", forbidden)
    no_new_work(v)

    result = v.service.reconcile_file_access_operation(
        job_id, reconciliation(v, before["outcome_digest"])
    )
    assert result["reconciliation"]["state"] == "unknown"
    assert (
        result["reconciliation_receipt"]["problem"]["code"]
        == "file_access_reconciliation_unresolved"
    )
    assert records(v, job_id) == before
    assert len(v.state.controls) == len(v.state.launches) == 1
