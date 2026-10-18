"""Actual saved synthetic S3 runs consumed by the shared comparison service."""

from __future__ import annotations

import itertools
import uuid
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import evidence, product_store_serialization, run_store
from bluefire.comparison import compare_runs
from bluefire.comparison_s3 import project_s3_access
from bluefire.config import load_config
from bluefire.service import BlueFireService
from bluefire.util import content_hash
from tests_platform.test_comparison import _run
from tests_platform.test_s3_access_jobs import NOW, SyntheticExecutor, stage, through_baseline


class FixedDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW if tz is not None else NOW.replace(tzinfo=None)


@pytest.fixture
def stable_identities(monkeypatch):
    counter = itertools.count(1)
    monkeypatch.setattr(uuid, "uuid4", lambda: uuid.UUID(int=next(counter) << 64))
    for module in (run_store, evidence, product_store_serialization):
        monkeypatch.setattr(module, "datetime", FixedDateTime)


def forbidden(*_args, **_kwargs):
    raise AssertionError("Saved comparison must not discover a runner or perform effects.")


@contextmanager
def comparison_service(root: Path, *, executor=None):
    executor = executor or SyntheticExecutor()
    project_root = Path(__file__).resolve().parents[1]
    config = load_config(project_root / "config" / "bluefire.example.yaml")
    config = replace(
        config,
        ai=replace(
            config.ai,
            providers=tuple(
                provider
                for provider in config.ai.providers
                if provider.id == "deterministic-offline.v1"
            ),
        ),
    )
    service = BlueFireService(
        project_root=project_root,
        config=config,
        runs_dir=root / "runs",
        product_db_path=root / "product.db",
        runner_factory=forbidden,
        runner_lifecycle=SimpleNamespace(client_for_profile=forbidden),
        ai_provider_factory=forbidden,
        ai_draft_provider_factory=forbidden,
        s3_access_executor=executor,
    )
    service.s3_access.clock = lambda: NOW
    try:
        yield service, executor
    finally:
        service.close()


@pytest.fixture
def service(tmp_path, stable_identities):
    with comparison_service(tmp_path) as value:
        yield value


def journey(service, executor, mode="paired_denied"):
    jobs = service.s3_access
    owner = through_baseline(jobs)
    stage(jobs, owner, "apply")
    if mode == "unchanged_probe":
        executor.probe_always_reads = True
    elif mode == "unknown_cleanup":
        executor.cleanup = "unknown"
    original = executor.execute

    def changed(request, **kwargs):
        if mode == "mixed_provenance":
            from tests_platform.test_s3_access_original_results import context_for

            kwargs["before_dispatch"](context_for(request, kwargs["authorization"]))
        value = original(request, **kwargs)
        if mode == "mixed_provenance":
            value["provenance"] = "runner_reported"
        if request.to_dict()["operation"] != "legitimate_read":
            return value
        result = value["result"]
        if mode == "legitimate_denied":
            result["data"]["objects"][0] = {"purpose": "primary", "result": "service_denied"}
            result["calls"][3].update(http_status=403, error_code="AccessDenied")
        elif mode in {"failed_legitimate", "failed_assume_role"}:
            count = 1 if mode == "failed_legitimate" else 2
            calls = deepcopy(result["calls"][:count])
            calls[-1].update(http_status=500, error_code="InternalError")
            result.update(
                outcome="failed",
                data=None,
                problem="scoped_operation_failed",
                calls=calls,
                send_permits_consumed=count,
            )
            value["send_debits"] = count
        elif mode == "not_started":
            value.update(
                admission={"accepted": False, "problem": "runtime_unavailable"},
                dispatch="not_started",
                send_debits=0,
                result=None,
                reservation_digest=None,
            )
        return value

    executor.execute = changed
    final, _ = stage(jobs, owner, "retest")
    executor.execute = original
    reads = {
        row["phase"]: row["run_ids"]
        for row in final["operations"]
        if row["phase"] in {"baseline", "retest"}
    }
    return owner, reads, [*reads["baseline"], *reads["retest"]]


def saved_state(service, owner):
    jobs = service.s3_access
    value = jobs.store.get_job(owner)
    operations = value["progress"]["operations"]
    return deepcopy(
        {
            "owner": value,
            "jobs": [jobs.store.get_job(row["operation_job_id"]) for row in operations],
            "runs": [
                jobs.runs.get_run(identifier) for row in operations for identifier in row["run_ids"]
            ],
        }
    )


def test_actual_producer_service_comparison_reports_access_change_not_step_success(
    service, monkeypatch
):
    app, executor = service
    owner, reads, identifiers = journey(app, executor)
    before, calls = saved_state(app, owner), deepcopy(executor.calls)
    monkeypatch.setattr(executor, "environments", forbidden)
    monkeypatch.setattr(executor, "readiness", forbidden)
    monkeypatch.setattr(executor, "execute", forbidden)
    response = app.compare({"run_ids": identifiers})
    value = response["s3_access"]
    assert value["state"] == "paired" and value["change_state"] == "changed"
    assert value["gaps"] == []
    assert value["baseline"]["run_ids"] == reads["baseline"]
    assert value["retest"]["run_ids"] == reads["retest"]
    assert [row["changed"] for row in value["rows"]] == [True, False, False]
    assert value["rows"][0]["retest"]["state"] == "service_denied"
    assert all(row["baseline"]["state"] == "read" for row in value["rows"])
    assert value["effective_access_claim"] is value["defensive_effectiveness_claim"] is False
    assert all(row["objective_reached"] is False for row in response["summaries"])
    assert all(row["outcomes"] == {"s3-operation": "success"} for row in response["summaries"])
    body = {
        key: item
        for key, item in response.items()
        if key not in {"comparison_id", "saved_snapshot"}
    }
    assert response["comparison_id"] == "comparison-" + content_hash(body)[7:27]
    assert set(response["saved_snapshot"]) == {"snapshot_id", "digest", "created_at"}
    assert saved_state(app, owner) == before and executor.calls == calls


@pytest.mark.parametrize(
    "selection,state",
    [
        ("baseline", "baseline_only"),
        ("retest", "retest_only"),
        ("partial", "partial"),
        ("reversed", "paired"),
    ],
)
def test_selected_read_boundaries_and_order(service, selection, state):
    app, executor = service
    _, reads, identifiers = journey(app, executor)
    selected = (
        reads[selection]
        if selection in reads
        else (
            [reads["baseline"][0], reads["retest"][0]]
            if selection == "partial"
            else list(reversed(identifiers))
        )
    )
    value = app.compare({"run_ids": selected})["s3_access"]
    assert value["state"] == state
    for row in value["rows"]:
        for phase in ("baseline", "retest"):
            cell = row[phase]
            assert cell["run_id"] is None or cell["run_id"] in selected
    if selection == "partial":
        assert value["rows"][1]["baseline"] == {
            "run_id": None,
            "state": "not_selected",
            "provenance": None,
            "cleanup": None,
        }
        assert value["change_state"] == "unknown" and all(
            row["changed"] is None for row in value["rows"]
        )


@pytest.mark.parametrize(
    "mode,state,change",
    [
        ("unchanged_probe", "paired", "unchanged"),
        ("legitimate_denied", "paired", "changed"),
        ("failed_legitimate", "partial", "unknown"),
        ("failed_assume_role", "partial", "unknown"),
        ("not_started", "partial", "unknown"),
        ("unknown_cleanup", "partial", "unknown"),
        ("mixed_provenance", "unavailable", None),
    ],
)
def test_nonideal_actual_results_remain_distinct(service, mode, state, change):
    app, executor = service
    owner, reads, identifiers = journey(app, executor, mode)
    value = app.compare({"run_ids": identifiers})["s3_access"]
    assert value["state"] == state
    if change is None:
        assert value["reason"] == "incompatible_context"
        operation = next(
            row
            for row in app.s3_access.store.get_job(owner)["progress"]["operations"]
            if row["phase"] == "retest"
        )
        child = app.s3_access.store.get_job(operation["operation_job_id"])
        assert set(child["progress"]["original_tasks"]) == set(reads["retest"])
    else:
        assert value["change_state"] == change
        if mode.startswith("failed_") or mode == "not_started":
            assert value["rows"][1]["retest"]["state"] == "unreported"
        if mode == "unknown_cleanup":
            assert "cleanup_unresolved" in value["gaps"]
            assert value["rows"][1]["retest"]["state"] == "not_recorded"


def test_stop_expiry_and_unrelated_rollback_leave_selected_projection_identical(service):
    app, executor = service
    owner, _, identifiers = journey(app, executor)
    before = app.compare({"run_ids": identifiers})
    stage(app.s3_access, owner, "rollback")
    app.s3_access.stop(owner, {})
    app.s3_access.clock = lambda: NOW + timedelta(days=3)
    assert app.compare({"run_ids": identifiers}) == before


@pytest.mark.parametrize("mutation", ["request", "execution", "operation", "profile", "policy"])
def test_substituted_selected_snapshot_cannot_borrow_retained_facts(service, mutation):
    app, executor = service
    _, _, identifiers = journey(app, executor)
    snapshots = [deepcopy(app.store.get_run(item)) for item in identifiers]
    row = snapshots[0]
    if mutation == "request":
        row["plan"]["request"]["deadline"] = "2026-10-10T00:00:00Z"
        row["s3_request_digest"] = content_hash(row["plan"]["request"])
    elif mutation == "execution":
        row["s3_execution"]["cleanup"] = "unknown"
    elif mutation == "operation":
        row["s3_operation_job_id"] = "job-" + "f" * 32
    elif mutation == "profile":
        row["profile"]["id"] = "different-profile"
    else:
        row["policy"]["review_digest"] = "sha256:" + "f" * 64
    assert project_s3_access(snapshots, app.s3_access)["state"] == "unavailable"


def test_missing_context_is_explicit_and_generic_fields_unchanged(service):
    app, executor = service
    _, _, identifiers = journey(app, executor)
    generic = compare_runs(app.store, identifiers)
    actual = app.compare({"run_ids": identifiers})
    assert generic["s3_access"]["reason"] == "saved_context_unavailable"
    assert {
        key: value for key, value in generic.items() if key not in {"s3_access", "comparison_id"}
    } == {
        key: value
        for key, value in actual.items()
        if key not in {"s3_access", "comparison_id", "saved_snapshot"}
    }


def test_selected_join_change_during_projection_refuses_without_writes(service, monkeypatch):
    app, executor = service
    owner, _, identifiers = journey(app, executor)
    before = saved_state(app, owner)
    original = app.s3_access.retained_operations
    count = 0

    def raced(identifier):
        nonlocal count
        result = deepcopy(original(identifier))
        count += 1
        if count == 2:
            result[0]["request"]["runtime"]["worker_generation"] = "sha256:" + "f" * 64
        return result

    monkeypatch.setattr(app.s3_access, "retained_operations", raced)
    assert app.compare({"run_ids": identifiers})["s3_access"]["reason"] == "saved_binding_invalid"
    assert saved_state(app, owner) == before


def test_unsupported_policy_run_is_not_borrowed_as_a_read(service):
    app, executor = service
    owner, _, identifiers = journey(app, executor)
    inspect_id = app.s3_access.store.get_job(owner)["progress"]["operations"][0]["run_ids"][0]
    value = app.compare({"run_ids": [inspect_id, identifiers[0]]})["s3_access"]
    assert value["reason"] == "unsupported_operation"


def generic_run(store):
    return _run(
        store, objective=True, observed=1, detection_matches=0, benign_matches=0, autonomy="off"
    )


def test_non_s3_output_and_identifier_are_identical_with_context_provider(service):
    app, _ = service
    identifiers = [generic_run(app.store), generic_run(app.store)]
    expected = compare_runs(app.store, identifiers)
    assert "s3_access" not in expected
    actual = app.compare({"run_ids": identifiers})
    assert actual["comparison_id"] == expected["comparison_id"]
    assert {key: value for key, value in actual.items() if key != "saved_snapshot"} == expected
    assert set(actual["saved_snapshot"]) == {"snapshot_id", "digest", "created_at"}


def test_mixed_objective_does_not_borrow_cloud_context(service):
    app, executor = service
    _, _, identifiers = journey(app, executor)
    value = app.compare({"run_ids": [identifiers[0], generic_run(app.store)]})["s3_access"]
    assert value["reason"] == "mixed_selection"


def test_cross_owner_is_incompatible_before_loading_either_history(service, monkeypatch):
    app, executor = service
    _, _, identifiers = journey(app, executor)
    snapshots = [deepcopy(app.store.get_run(item)) for item in identifiers]
    snapshots[-1]["s3_workflow_job_id"] = "job-" + "f" * 32
    monkeypatch.setattr(app.s3_access, "retained_operations", forbidden)
    assert project_s3_access(snapshots, app.s3_access)["reason"] == "incompatible_context"


@pytest.mark.parametrize("version", [2, 3])
def test_fixture_and_audited_saved_schema_reads_use_same_projection(
    tmp_path, stable_identities, version
):
    from tests_platform.test_s3_access_jobs import create
    from tests_platform.test_s3_audit_workflow_jobs import ReceiptExecutor
    from tests_platform.test_s3_fixture_jobs import FixtureExecutor

    executor = FixtureExecutor() if version == 2 else ReceiptExecutor()
    with comparison_service(tmp_path, executor=executor) as (app, _):
        jobs = app.s3_access
        owner = create(jobs)["workflow_job_id"]
        assert jobs.read(owner)["schema_version"] == f"bluefire.s3-exercise.v{version}"
        if version == 2:
            stage(jobs, owner, "prepare")
        for phase in ("inspect", "baseline", "apply", "retest"):
            final, _ = stage(jobs, owner, phase)
        identifiers = [
            identifier
            for row in final["operations"]
            if row["phase"] in {"baseline", "retest"}
            for identifier in row["run_ids"]
        ]
        value = app.compare({"run_ids": identifiers})["s3_access"]
        assert value["state"] == "paired" and value["change_state"] == "changed"
        expected = "synthetic" if version == 2 else "runner_reported"
        assert value["rows"][0]["baseline"]["provenance"] == expected


def test_reopened_service_compares_saved_runs_without_host(tmp_path, stable_identities):
    with comparison_service(tmp_path) as (app, executor):
        _, _, identifiers = journey(app, executor)
        expected = app.compare({"run_ids": identifiers})
    executor.environments = forbidden
    executor.readiness = forbidden
    executor.execute = forbidden
    with comparison_service(tmp_path, executor=executor) as (reopened, _):
        assert reopened.compare({"run_ids": identifiers}) == expected


def test_repeated_baseline_attempts_cannot_be_combined_into_one_phase(service):
    from tests_platform.test_s3_access_jobs import create

    app, executor = service
    jobs = app.s3_access
    owner = create(jobs)["workflow_job_id"]
    stage(jobs, owner, "inspect")
    original = executor.execute

    def failed(request, **kwargs):
        value = original(request, **kwargs)
        if request.to_dict()["operation"] == "legitimate_read":
            calls = deepcopy(value["result"]["calls"][:1])
            calls[0].update(http_status=500, error_code="InternalError")
            value["result"].update(
                outcome="failed",
                data=None,
                problem="scoped_operation_failed",
                calls=calls,
                send_permits_consumed=1,
            )
            value["send_debits"] = 1
        return value

    executor.execute = failed
    first, _ = stage(jobs, owner, "baseline")
    executor.execute = original
    second, _ = stage(jobs, owner, "baseline")
    identifiers = [first["operations"][-1]["run_ids"][0], second["operations"][-1]["run_ids"][1]]
    assert app.compare({"run_ids": identifiers})["s3_access"]["reason"] == "ambiguous_phase"
