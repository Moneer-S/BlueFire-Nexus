"""Saved fixture journeys use real stores and only an explicit synthetic executor."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from bluefire.job_runtime import RunJobController
from bluefire.product_store import ProductStore
from bluefire.run_store import RunStore
from bluefire.s3_access_contract import S3AccessError, S3AccessScope
from bluefire.s3_access_jobs import S3AccessJobs
from bluefire.s3_access_results import environment
from tests_platform.test_s3_access_jobs import NOW, SyntheticExecutor, create, stage
from tests_platform.test_s3_fixture_sdk import fixture_request, run


class FixtureExecutor(SyntheticExecutor):
    def __init__(self, api_calls=100):
        super().__init__()
        request, self.descriptor = fixture_request()
        scope = request.to_dict()["scope"]
        scope["limits"]["api_calls"] = api_calls
        self.scope = S3AccessScope.from_mapping(scope)
        self.descriptor["scope_digest"] = self.scope.digest
        self.objects = {}
        self.fail_after = None
        self.fail_health_start = False

    def environments(self):
        entry = super().environments()[0]
        entry.update(
            exclusive_writer_digest=self.descriptor["exclusive_writer_digest"],
            fixture_lifecycle=deepcopy(self.descriptor),
        )
        return [entry]

    def execute(self, request, *, authorization, cancellation_event, before_dispatch=None):
        row = request.to_dict()
        if row["schema_version"] != "bluefire.s3-worker-request.v2":
            return super().execute(
                request,
                authorization=authorization,
                cancellation_event=cancellation_event,
                before_dispatch=before_dispatch,
            )
        self.calls.append((row, deepcopy(authorization)))
        assert authorization["schema_version"] == "bluefire.s3-workflow-approval.v2"
        assert authorization["fixture_intent_id"] == row["fixture"]["intent_id"]
        if (
            self.fail_health_start
            and row["operation"] == "cleanup_fixture"
            and row["fixture"]["purpose"] == "health"
        ):
            return {
                "schema_version": "bluefire.s3-execution.v1",
                "request_digest": request.digest,
                "admission": {"accepted": True, "problem": None},
                "dispatch": "not_started",
                "send_debits": 0,
                "result": None,
                "cleanup": "verified",
                "provenance": "synthetic",
                "reservation_digest": "sha256:" + "a" * 64,
            }
        worker, factory = run(request, objects=self.objects, fail_after=self.fail_after)
        self.objects = factory.objects
        return {
            "schema_version": "bluefire.s3-execution.v1",
            "request_digest": request.digest,
            "admission": {"accepted": True, "problem": None},
            "dispatch": "unknown" if worker["outcome"] == "reconcile_required" else "permit_issued",
            "send_debits": worker["send_permits_consumed"],
            "result": worker,
            "cleanup": self.cleanup,
            "provenance": "synthetic",
            "reservation_digest": "sha256:" + "a" * 64,
        }


@pytest.fixture
def app(tmp_path):
    store = ProductStore(tmp_path / "product.db")
    runs = RunStore(tmp_path / "runs")
    with RunJobController(store, max_workers=1) as controller:
        executor = FixtureExecutor()
        service = SimpleNamespace(product_store=store, store=runs, job_controller=controller)
        yield S3AccessJobs(service, executor, clock=lambda: NOW), executor


def test_saved_prepare_harden_and_cleanup_retains_accepted_policy(app):
    jobs, executor = app
    initial = create(jobs)
    owner = initial["workflow_job_id"]
    assert initial["schema_version"] == "bluefire.s3-exercise.v2"
    assert initial["allowed_phases"] == ["prepare"]
    assert initial["fixture_state"] == "not_prepared"
    review = jobs.review(owner, {"phase": "prepare"})
    assert review["schema_version"] == "bluefire.s3-stage-review.v2"
    assert review["required_remaining"]["api_calls"] == 70
    assert review["fixture_lifecycle"]["policy_disposition"] == "retain_current"
    prepared, _ = stage(jobs, owner, "prepare")
    assert prepared["fixture_state"] == "owned"
    assert len(executor.objects) == 2
    assert {row["provenance"] for row in prepared["fixtures"]} == {"synthetic"}
    assert all(row["request_ids"] for row in prepared["fixtures"])
    for phase in ("inspect", "baseline", "apply", "retest"):
        value, _ = stage(jobs, owner, phase)
    assert value["policy_state"] == "hardened"
    before_policy = executor.hardened
    review = jobs.review(owner, {"phase": "cleanup"})
    assert review["fixture_lifecycle"]["policy_state"] == "hardened"
    cleaned, submission = stage(jobs, owner, "cleanup")
    assert cleaned["fixture_state"] == "absent"
    assert cleaned["resource_disposition"] == "removed"
    assert cleaned["policy_state"] == "hardened"
    assert executor.hardened == before_policy
    assert cleaned["policy_retention"]["review_digest"] == submission["review_digest"]
    assert not executor.objects
    assert cleaned["allowed_phases"] == []
    count = len(executor.calls)
    assert jobs.read(owner) == cleaned
    reopened = S3AccessJobs(jobs.service, executor, clock=lambda: NOW)
    assert reopened.read(owner) == cleaned
    assert len(executor.calls) == count


def test_minimum_prepare_budget_handles_both_uncertain_writes_without_replay(app):
    jobs, executor = app
    executor.__init__(api_calls=70)
    owner = create(jobs)["workflow_job_id"]
    executor.fail_after = "PutObject"
    uncertain, _ = stage(jobs, owner, "prepare")
    assert uncertain["fixture_state"] == "uncertain"
    assert uncertain["allowed_phases"] == ["reconcile_fixtures"]
    assert uncertain["remaining"]["api_calls"] == 58
    with pytest.raises(S3AccessError):
        jobs.review(owner, {"phase": "prepare"})
    executor.fail_after = None
    partial, _ = stage(jobs, owner, "reconcile_fixtures")
    assert partial["fixture_state"] == "partial"
    assert partial["allowed_phases"] == ["cleanup"]
    executor.fail_after = "DeleteObject"
    deleted, _ = stage(jobs, owner, "cleanup")
    assert deleted["fixture_state"] == "uncertain"
    assert deleted["allowed_phases"] == ["reconcile_fixtures"]
    assert deleted["remaining"]["api_calls"] == 34
    with pytest.raises(S3AccessError):
        jobs.review(owner, {"phase": "cleanup"})
    executor.fail_after = None
    final, _ = stage(jobs, owner, "reconcile_fixtures")
    assert final["fixture_state"] == "absent"
    assert final["remaining"]["api_calls"] == 24
    assert final["allowed_phases"] == []
    assert len([row for row, _ in executor.calls if row["operation"] == "prepare_fixture"]) == 1
    assert len([row for row, _ in executor.calls if row["operation"] == "cleanup_fixture"]) == 1


def test_stop_preserves_explicit_cleanup_and_review_staleness(app):
    jobs, executor = app
    owner = create(jobs)["workflow_job_id"]
    stage(jobs, owner, "prepare")
    review = jobs.review(owner, {"phase": "cleanup"})
    stopped = jobs.stop(owner, {})
    assert stopped["allowed_phases"] == ["cleanup", "reconcile_fixtures"]
    assert jobs.review(owner, {"phase": "cleanup"})["review_digest"] != review["review_digest"]
    cleaned, _ = stage(jobs, owner, "cleanup")
    assert cleaned["stopped"] and cleaned["fixture_state"] == "absent"
    assert not executor.objects


def test_legacy_environment_remains_closed_and_fixture_scope_is_canonical():
    old = SyntheticExecutor().environments()[0]
    assert environment(old) == old
    bad = deepcopy(old)
    bad["fixture_lifecycle"] = FixtureExecutor().descriptor
    with pytest.raises(S3AccessError):
        environment(bad)


def test_undersized_scope_never_offers_prepare(app):
    jobs, executor = app
    executor.__init__(api_calls=69)
    assert create(jobs)["allowed_phases"] == []


def test_partial_delete_can_cleanup_only_untouched_health_after_reconciliation(app):
    jobs, executor = app
    executor.__init__(api_calls=70)
    owner = create(jobs)["workflow_job_id"]
    stage(jobs, owner, "prepare")
    executor.fail_after = "DeleteObject"
    first, _ = stage(jobs, owner, "cleanup")
    assert first["fixture_state"] == "uncertain"
    assert len(executor.objects) == 1
    executor.fail_after = None
    reconciled, _ = stage(jobs, owner, "reconcile_fixtures")
    assert reconciled["fixture_state"] == "partial"
    assert "cleanup" in reconciled["allowed_phases"]
    assert [row["state"] for row in reconciled["fixtures"]] == ["absent", "owned"]
    executor.fail_after = "DeleteObject"
    second, _ = stage(jobs, owner, "cleanup")
    assert second["fixture_state"] == "uncertain"
    assert not executor.objects
    deletes = [
        (row["fixture"]["purpose"], row["fixture"]["expected_etag"])
        for row, _ in executor.calls
        if row["operation"] == "cleanup_fixture"
    ]
    assert deletes == [("primary", '"owned-token"'), ("primary", None), ("health", '"owned-token"')]
    executor.fail_after = None
    final, _ = stage(jobs, owner, "reconcile_fixtures")
    assert final["fixture_state"] == "absent"
    assert final["allowed_phases"] == []


def product_corpus(root):
    """Return actual saved-store public projections for cross-language UI checks."""
    store = ProductStore(root / "product.db")
    runs = RunStore(root / "runs")
    with RunJobController(store, max_workers=1) as controller:
        executor = FixtureExecutor()
        service = SimpleNamespace(product_store=store, store=runs, job_controller=controller)
        jobs = S3AccessJobs(service, executor, clock=lambda: NOW)
        initial = create(jobs)
        identifier = initial["workflow_job_id"]
        snapshots = [
            {
                "name": "initial",
                "exercise": initial,
                "review": jobs.review(identifier, {"phase": "prepare"}),
            }
        ]
        for phase in ("prepare", "inspect", "baseline", "apply", "retest"):
            current, _ = stage(jobs, identifier, phase)
        snapshots.append(
            {
                "name": "owned",
                "exercise": current,
                "review": jobs.review(identifier, {"phase": "cleanup"}),
            }
        )
        executor.fail_after = "DeleteObject"
        current, _ = stage(jobs, identifier, "cleanup")
        snapshots.append(
            {
                "name": "uncertain",
                "exercise": current,
                "review": jobs.review(identifier, {"phase": "reconcile_fixtures"}),
            }
        )
        executor.fail_after = None
        current, _ = stage(jobs, identifier, "reconcile_fixtures")
        snapshots.append(
            {
                "name": "partial_cleanup",
                "exercise": current,
                "review": jobs.review(identifier, {"phase": "cleanup"}),
            }
        )
        current, _ = stage(jobs, identifier, "cleanup")
        snapshots.append({"name": "absent_retained_policy", "exercise": current, "review": None})
        assert not executor.objects and executor.hardened
        assert current["fixture_state"] == "absent" and current["policy_state"] == "hardened"
        assert all(row["exercise"]["active_job"] is None for row in snapshots)
        return {
            "schema_version": "bluefire.s3-fixture-product-golden.v2",
            "provenance": "synthetic",
            "snapshots": snapshots,
        }


def test_zero_send_accepted_cleanup_reservation_is_not_offered_for_replay(app):
    jobs, executor = app
    owner = create(jobs)["workflow_job_id"]
    stage(jobs, owner, "prepare")
    executor.fail_health_start = True
    partial, _ = stage(jobs, owner, "cleanup")
    assert partial["fixture_state"] == "partial"
    assert partial["allowed_phases"] == ["reconcile_fixtures"]
    executor.fail_health_start = False
    reconciled, _ = stage(jobs, owner, "reconcile_fixtures")
    assert reconciled["fixture_state"] == "partial"
    assert reconciled["allowed_phases"] == ["reconcile_fixtures"]
    with pytest.raises(S3AccessError):
        jobs.review(owner, {"phase": "cleanup"})


def test_uncertain_or_drifted_policy_must_reconcile_before_fixture_stages(app):
    jobs, executor = app
    owner = create(jobs)["workflow_job_id"]
    for phase in ("prepare", "inspect", "baseline"):
        stage(jobs, owner, phase)
    executor.uncertain_write = True
    uncertain, _ = stage(jobs, owner, "apply")
    assert uncertain["policy_state"] == "uncertain"
    assert uncertain["allowed_phases"] == ["reconcile"]
    for phase in ("cleanup", "reconcile_fixtures"):
        with pytest.raises(S3AccessError):
            jobs.review(owner, {"phase": phase})
    executor.drift = True
    drifted, _ = stage(jobs, owner, "reconcile")
    assert drifted["policy_state"] == "drift"
    assert drifted["allowed_phases"] == ["reconcile"]
    executor.drift = False
    settled, _ = stage(jobs, owner, "reconcile")
    assert settled["policy_state"] == "hardened"
    assert "cleanup" in settled["allowed_phases"]
