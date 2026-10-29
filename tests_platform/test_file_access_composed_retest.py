"""Historical Linux linkage uses original observations and a selected attempt."""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from bluefire.application_errors import APIError
from bluefire.capability_file_access import objective_result
from bluefire.file_access_composed_retest import projection
from bluefire.file_access_observation import baseline_record, control_observation
from bluefire.file_access_plan import recipe
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.product_store_serialization import canonical_json
from bluefire.run_store import RunStoreError
from bluefire.service import BlueFireService
from bluefire.util import content_hash
from tests_platform.file_access_fixtures import binding, observation


def _id(prefix: str, character: str) -> str:
    return prefix + "-" + character * 32


def _operation(kind, job_id, owner_id, control, prior, tasks, *, observed=None):
    review_body = {
        "operation": kind,
        "control_owner_id": owner_id,
        "control_digest": content_hash(prior),
    }
    review = {**review_body, "review_digest": content_hash(review_body)}
    preparation = {
        "job_id": job_id,
        "revision": control["revision"],
        "target_binding": control["binding"],
        "target_binding_digest": control["binding_digest"],
        "recipe": recipe(kind, prior),
        "prior": prior,
        "source": prior["source"],
    }
    outcome = {
        "state": "complete",
        "control_digest": content_hash(control),
        "evidence_digest": content_hash(tasks),
    }
    if observed is not None:
        outcome["verified_observation"] = observed
    return {
        "control_owner_id": owner_id,
        "document": {
            "review": review,
            "submitted_request": {
                "review": {"operation": kind, "control_owner_id": owner_id},
                "review_digest": review["review_digest"],
            },
        },
        "preparation": preparation,
        "tasks": tasks,
        "outcome": outcome,
    }


def _tasks(bound, kind, job_id):
    rows = []
    for step in recipe(kind):
        name = step["step_id"]
        observed = observation(bound, owner=name == "owner") if name in {"probe", "owner"} else None
        request_hash = content_hash(name) if observed is None else observed["request_hash"]
        result = {"status": "success"}
        if observed is not None:
            result["output"] = {"observation": observed}
        task_id = f"task-{job_id[-32:]}-{name}"
        rows.append(
            {
                "task": {
                    "job_id": job_id,
                    "task_id": task_id,
                    "step_id": name,
                    "request_hash": request_hash,
                    "manifest": {
                        "action_id": step["action_id"],
                        "requested_at": "1970-01-01T00:16:39Z",
                        "expires_at": "1970-01-01T00:17:00Z",
                    },
                },
                "terminal": {
                    "task_id": task_id,
                    "request_hash": request_hash,
                    "result": result,
                },
            }
        )
    return rows


@pytest.fixture
def saved_linkage():
    control_id = _id("job", "1")
    baseline_job = _id("job", "2")
    change_job = _id("job", "3")
    objective_id = _id("job", "4")
    attempt_id = _id("attempt", "5")
    attempt_job = _id("job", "6")
    grant_id = _id("grant", "7")
    run_id = "run-20261028T100000Z-0123456789abcdef"
    original = {**binding(), "control_revision": 2}
    changed = {**original, "control_revision": 3, "mode": "0600"}
    source = {"fixture": "saved synthetic generated file"}
    created = {
        "schema_version": "bluefire.retained-file-control.v1",
        "control_owner_id": control_id,
        "enrollment_id": original["enrollment_id"],
        "revision": 1,
        "status": "created",
        "binding": {**original, "control_revision": 1},
        "source": source,
        "baseline": None,
    }
    baseline_tasks = _tasks(original, "baseline", baseline_job)
    observed = control_observation("baseline", baseline_tasks, binding=original, now_ms=1_000_002)
    baseline = baseline_record(baseline_job, observed)
    base_control = {
        **created,
        "revision": 2,
        "status": "baseline_verified",
        "binding": original,
        "binding_digest": content_hash(original),
        "baseline": baseline,
    }
    hard_control = {
        **base_control,
        "revision": 3,
        "status": "hardened",
        "binding": changed,
        "binding_digest": content_hash(changed),
    }
    revisions = {
        2: {
            "job_id": baseline_job,
            "document": base_control,
            "document_digest": content_hash(base_control),
        },
        3: {
            "job_id": change_job,
            "document": hard_control,
            "document_digest": content_hash(hard_control),
        },
    }
    operations = {
        baseline_job: _operation(
            "baseline",
            baseline_job,
            control_id,
            base_control,
            created,
            baseline_tasks,
            observed=observed,
        ),
        change_job: _operation(
            "harden",
            change_job,
            control_id,
            hard_control,
            base_control,
            _tasks(changed, "harden", change_job),
        ),
    }
    environment = {
        "environment_id": _id("environment", "a"),
        "environment_generation": _id("generation", "b"),
        "runner_id": _id("runner", "c"),
        "enrollment_digest": content_hash("runner enrollment"),
        "profile_digest": content_hash("runner profile"),
        "target_scope_digest": content_hash("sandbox scope"),
        "collector_digest": content_hash("filesystem collector"),
        "control_owner_id": control_id,
        "control_revision": 3,
        "control_digest": content_hash(hard_control),
        "baseline_digest": baseline["baseline_digest"],
        "resource_id": changed["resource_id"],
        "resource_generation": changed["resource_generation"],
        "resource_digest": content_hash(changed["resource"]),
        "probe_enrollment_digest": changed["enrollment_digest"],
        "mode": "0600",
    }
    grant = {
        "schema_version": "bluefire.capability-grant.v2",
        "pack": "bluefire.linux-file-access-pack.v1",
        "snapshot": {"pack": "bluefire.linux-file-access-pack.v1"},
        "grant_id": grant_id,
        "grant_digest": content_hash("grant"),
        "environment": environment,
        "objective": {
            "question": "Can the non-owner still read the generated file?",
            "predicate": {
                "kind": "non_owner_denied_owner_preserves_records",
                "record_count": baseline["record_count"],
                "data_class": "generated_public_jsonl",
                "sha256": baseline["sha256"],
            },
        },
    }
    marker = {
        "parent_job_id": objective_id,
        "attempt_id": attempt_id,
        "grant_id": grant_id,
        "grant_digest": grant["grant_digest"],
        "run_id": run_id,
        "compiled_digest": content_hash("compiled"),
    }
    attempt = {
        "state": "settled",
        "lease": {
            "attempt_id": attempt_id,
            "job_id": attempt_job,
            "grant_id": grant_id,
            "grant_digest": grant["grant_digest"],
            "run_id": run_id,
        },
        "compiled": {
            "compiled_digest": marker["compiled_digest"],
            "file_access": {
                key: environment[key]
                for key in (
                    "control_owner_id",
                    "control_digest",
                    "baseline_digest",
                    "control_revision",
                    "resource_generation",
                )
            },
        },
    }
    verified = {
        "run_id": run_id,
        "file_access_result": {
            "probe_verified": True,
            "owner_verified": True,
            "resource_generation": changed["resource_generation"],
            "resource_digest": environment["resource_digest"],
            "control_revision": 3,
            "probe_enrollment_digest": environment["probe_enrollment_digest"],
            "mode": "0600",
            "non_owner_decision": "permission_denied",
            "owner_decision": "allowed",
            "sha256": baseline["sha256"],
            "record_count": baseline["record_count"],
            "identity_unchanged": True,
            "parents_unchanged": True,
            "acl_unchanged": True,
        },
        "cleanup": {"run": "complete", "request": "verified_closed"},
    }
    verified["objective"] = objective_result(
        grant,
        {
            **verified["file_access_result"],
            "run_cleanup": verified["cleanup"]["run"],
            "request_cleanup": verified["cleanup"]["request"],
        },
    )

    class Store:
        def get_linux_file_access_revision_record(self, owner, revision):
            assert owner == control_id
            return deepcopy(revisions[revision])

        def file_access_operation_records(self, job_id):
            return deepcopy(operations[job_id])

        def get_capability_attempt(self, selected):
            assert selected == attempt_id
            if self.attempt is None:
                raise ProductStoreError("No original lease")
            return deepcopy(self.attempt)

    class Composition:
        def read(self, selected):
            assert selected == objective_id
            return {
                "grant": {"document": grant},
                "attempts": [{"job_id": attempt_job, "request": {"composition_attempt": marker}}],
            }

        def clock(self):
            return 1_000_002

        def _verified_result(self, selected):
            assert selected == store.attempt
            if isinstance(self.verified, BaseException):
                raise self.verified
            return deepcopy(self.verified)

    store = Store()
    store.attempt = attempt
    composition = Composition()
    composition.verified = verified
    service = SimpleNamespace(product_store=store, composition=composition)
    return SimpleNamespace(
        service=service,
        store=store,
        composition=composition,
        revisions=revisions,
        operations=operations,
        grant=grant,
        marker=marker,
        attempt=attempt,
        verified=verified,
        objective_id=objective_id,
        attempt_id=attempt_id,
        control_id=control_id,
    )


def test_verified_linkage_reopens_from_historical_controls(saved_linkage):
    value = saved_linkage
    first = projection(value.service, value.objective_id, value.attempt_id)
    assert first["baseline"]["mode"] == "0640"
    assert first["change"]["mode"] == "0600"
    assert first["comparison"] == {
        "state": "established",
        "non_owner_change": "allowed_to_denied",
        "owner_preserved": True,
        "content_preserved": True,
        "cleanup_verified": True,
    }
    assert first["retest"]["run_cleanup"] == "complete"
    assert first["retest"]["request_cleanup"] == "verified_closed"
    assert first["linkage_digest"] == content_hash(
        {key: item for key, item in first.items() if key != "linkage_digest"}
    )
    assert projection(value.service, value.objective_id, value.attempt_id) == first


def test_unsettled_or_missing_original_attempt_remains_unknown(saved_linkage):
    value = saved_linkage
    value.store.attempt = None
    result = projection(value.service, value.objective_id, value.attempt_id)
    assert result["retest"]["state"] == "unknown"
    assert result["retest"]["objective_established"] is None
    assert result["comparison"]["owner_preserved"] is None
    assert result["comparison"]["cleanup_verified"] is None


@pytest.mark.parametrize(
    "failure",
    [
        RunStoreError("original finalized run unavailable"),
        APIError(422, "detection_evaluation_source_invalid", "Finalized run unavailable."),
    ],
)
def test_unavailable_finalized_run_remains_unknown(saved_linkage, failure):
    value = saved_linkage
    value.composition.verified = failure
    result = projection(value.service, value.objective_id, value.attempt_id)
    assert result["retest"]["state"] == "unknown"
    assert result["comparison"]["state"] == "unknown"


@pytest.mark.parametrize("failed_condition", ["still_allowed", "run_cleanup_incomplete"])
def test_verified_counterexample_never_claims_protection(saved_linkage, failed_condition):
    value = saved_linkage
    if failed_condition == "still_allowed":
        value.composition.verified["file_access_result"]["non_owner_decision"] = "allowed"
    else:
        value.composition.verified["cleanup"]["run"] = "incomplete"
    verified = value.composition.verified
    verified["objective"] = objective_result(
        value.grant,
        {
            **verified["file_access_result"],
            "run_cleanup": verified["cleanup"]["run"],
            "request_cleanup": verified["cleanup"]["request"],
        },
    )
    result = projection(value.service, value.objective_id, value.attempt_id)
    assert result["retest"]["state"] == "verified"
    assert result["comparison"]["state"] == "not_established"
    assert result["comparison"]["non_owner_change"] == (
        "still_allowed" if failed_condition == "still_allowed" else "allowed_to_denied"
    )
    assert result["comparison"]["cleanup_verified"] is (failed_condition == "still_allowed")


def test_service_exposes_mismatched_lineage_as_conflict(saved_linkage):
    value = saved_linkage
    value.marker["grant_id"] = _id("grant", "8")
    with pytest.raises(APIError) as caught:
        BlueFireService.file_access_composed_retest_linkage(
            value.service, value.objective_id, value.attempt_id
        )
    assert caught.value.status == 409
    assert caught.value.code == "file_access_linkage_unavailable"


def test_service_exposes_invalid_direct_attempt_identity_as_conflict(saved_linkage):
    value = saved_linkage
    with pytest.raises(APIError) as caught:
        BlueFireService.file_access_composed_retest_linkage(
            value.service, value.objective_id, "attempt-not-canonical"
        )
    assert caught.value.status == 409
    assert caught.value.code == "file_access_linkage_unavailable"


def test_historical_revision_lookup_survives_store_reopen(tmp_path):
    path = tmp_path / "file-access-linkage.db"
    store = ProductStore(path)
    owner = store.create_job("file_access.operation", {})["job_id"]
    baseline_job = store.create_job("file_access.operation", {})["job_id"]
    change_job = store.create_job("file_access.operation", {})["job_id"]
    control = {
        "schema_version": "bluefire.retained-file-control.v1",
        "control_owner_id": owner,
        "revision": 3,
        "status": "hardened",
    }
    enrollment = _id("file-enrollment", "b")
    with store._connection(write=True) as connection:
        for job_id, kind in ((baseline_job, "baseline"), (change_job, "harden")):
            document = {"operation": kind, "control_owner_id": owner}
            connection.execute(
                "INSERT INTO file_access_operations VALUES(?,?,?,?,?,?)",
                (job_id, owner, enrollment, kind, canonical_json(document), content_hash(document)),
            )
        for revision, job_id in ((2, baseline_job), (3, change_job)):
            document = {**control, "revision": revision}
            connection.execute(
                "INSERT INTO file_access_revisions VALUES(?,?,?,?,?)",
                (owner, revision, job_id, canonical_json(document), content_hash(document)),
            )
    reopened = ProductStore(path)
    record = reopened.get_linux_file_access_revision_record(owner, 3)
    assert record == {
        "job_id": change_job,
        "document": control,
        "document_digest": content_hash(control),
    }
    with pytest.raises(ProductStoreError):
        reopened.get_linux_file_access_revision_record(_id("job", "f"), 3)
    with pytest.raises(ProductStoreError):
        reopened.get_linux_file_access_revision_record(owner, True)


@pytest.mark.parametrize(
    "change",
    [
        "foreign_attempt",
        "baseline_evidence",
        "change_preimage",
        "resource_generation",
        "missing_change_task",
        "duplicate_change_task",
        "reordered_baseline_tasks",
        "foreign_terminal_binding",
    ],
)
def test_foreign_or_changed_lineage_cannot_be_compared(saved_linkage, change):
    value = saved_linkage
    if change == "foreign_attempt":
        value.marker["grant_id"] = _id("grant", "8")
    elif change == "baseline_evidence":
        value.operations[_id("job", "2")]["outcome"]["verified_observation"]["source_digest"] = (
            content_hash("foreign evidence")
        )
    elif change == "change_preimage":
        value.operations[_id("job", "3")]["document"]["review"]["control_digest"] = content_hash(
            "unreviewed parent"
        )
    elif change == "missing_change_task":
        value.operations[_id("job", "3")]["tasks"].clear()
    elif change == "duplicate_change_task":
        rows = value.operations[_id("job", "3")]["tasks"]
        rows.append(deepcopy(rows[0]))
    elif change == "reordered_baseline_tasks":
        value.operations[_id("job", "2")]["tasks"].reverse()
    elif change == "foreign_terminal_binding":
        value.operations[_id("job", "3")]["tasks"][0]["terminal"]["request_hash"] = content_hash(
            "foreign task request"
        )
    else:
        value.grant["environment"]["resource_generation"] = _id("file-generation", "b")
    if change in {
        "missing_change_task",
        "duplicate_change_task",
        "reordered_baseline_tasks",
        "foreign_terminal_binding",
    }:
        job_id = _id("job", "2" if change == "reordered_baseline_tasks" else "3")
        records = value.operations[job_id]
        records["outcome"]["evidence_digest"] = content_hash(records["tasks"])
    with pytest.raises(ProductStoreError):
        projection(value.service, value.objective_id, value.attempt_id)
