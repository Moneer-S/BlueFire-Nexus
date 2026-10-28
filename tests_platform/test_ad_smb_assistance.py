"""Saved AD linkage and durable Assistant paths with authored execution only."""

import json
import uuid
from copy import deepcopy

import pytest

from bluefire.ad_smb_audit import normalize_events
from bluefire.ad_smb_contract import AdSmbScope
from bluefire.ad_smb_jobs import AdSmbJobs
from bluefire.assistance_ad_smb_context import context, selection
from bluefire.product_store_errors import ProductStoreError
from bluefire.util import content_hash
from tests_platform.test_ad_smb_api_workflow import WorkflowService
from tests_platform.test_ad_smb_audit import event as audit_event
from tests_platform.test_ad_smb_contract import NOW
from tests_platform.test_ad_smb_jobs import FakeExecutor, create, large_audit_observation, submit
from tests_platform.test_ad_smb_jobs import workspace as workspace
from tests_platform.test_api import json_body, request, running_server
from tests_platform.test_file_access_retest_assistance import _finish_turn, _mock_explanation
from tests_platform.test_graph_ai_jobs import setup as setup


def saved(workspace, phases=("inspect", "baseline", "harden", "retest", "audit")):
    jobs, executor, service = workspace
    service.ad_smb = jobs
    identifier = create(jobs)
    for phase in phases:
        assert submit(jobs, identifier, phase)[0]["state"] == "completed"
    return jobs, executor, service, identifier


def _update(store, identifier, column, mutate):
    value = deepcopy(store.get_job(identifier)[column])
    mutate(value)
    with store._connection(write=True) as connection:
        connection.execute(
            f"UPDATE jobs SET {column}_json = ? WHERE job_id = ?",
            (json.dumps(value), identifier),
        )


def test_bound_context_reuses_saved_results_without_native_or_credential_access(workspace):
    jobs, executor, service, identifier = saved(workspace)
    calls = deepcopy(executor.calls)
    executor.environments = lambda: pytest.fail("No live discovery")
    executor.execute = lambda *_args, **_kwargs: pytest.fail("No dispatch")
    executor.recover_original = lambda *_args: pytest.fail("No original recovery")
    captured = context(service, workflow_job_id=identifier)
    assert context(service, captured["selected"]) == captured
    assert captured["analysis_only"] is True and captured["capabilities"] == []
    assert captured["context_digest"] == content_hash(
        {key: value for key, value in captured.items() if key != "context_digest"}
    )
    summary = captured["reference_summary"]
    assert summary["provenance"] == "synthetic_fixture"
    baseline, harden, retest, audit = summary["operations"][1:]
    assert all(row["observation"]["state"] == "bytes_matched" for row in baseline["tasks"])
    assert harden["tasks"][0]["observation"]["state"] == "readback_matched"
    assert [row["observation"]["state"] for row in retest["tasks"]] == [
        "open_access_denied",
        "bytes_matched",
        "bytes_matched",
    ]
    assert audit["tasks"][0]["observation"]["normalization"] is None
    assert summary["effective_access_claim"] is False
    assert all(
        task["original_digest"] and task["execution_digest"]
        for row in summary["operations"]
        for task in row["tasks"]
    )
    wire = json.dumps(captured)
    for forbidden in (
        "expected_remote_sid",
        "local_user_sid",
        "local_authentication_id",
        "credential",
        "raw_events",
        "<Event",
        "transport_identity",
        "sandbox_root",
        "volume_serial",
        "scope_digest",
        "fqdn",
        '"unc"',
    ):
        assert forbidden not in json.dumps(summary)
    assert executor.scope.to_dict()["hosts"]["member"]["fqdn"] not in wire
    assert executor.calls == calls and executor.recovered == []
    jobs.stop(identifier)
    with pytest.raises(ProductStoreError):
        context(service, captured["selected"])


@pytest.mark.parametrize(
    "bad",
    [
        None,
        [],
        ["kind"],
        {},
        {"kind": "ad_smb_workflow"},
        {"kind": "ad_smb_workflow", "workflow_job_id": [], "result_digest": "sha256:" + "a" * 64},
    ],
)
def test_selection_rejects_malformed_inputs(bad):
    with pytest.raises(ProductStoreError):
        selection(bad)


@pytest.mark.parametrize(
    "tamper",
    [
        "missing_child",
        "foreign_child",
        "missing_original",
        "changed_request",
        "changed_terminal",
        "missing_run",
        "changed_run",
        "unsealed_run",
    ],
)
def test_changed_or_missing_original_child_and_bundle_refused(workspace, tamper):
    jobs, _executor, service, identifier = saved(workspace, ("inspect",))
    captured = context(service, workflow_job_id=identifier)
    operation = jobs._owner(identifier)["progress"]["operations"][0]
    child_id, run_id = operation["job_id"], operation["run_id"]
    if tamper == "missing_child":
        with jobs.store._connection(write=True) as connection:
            connection.execute("DELETE FROM jobs WHERE job_id = ?", (child_id,))
    elif tamper == "foreign_child":
        _update(
            jobs.store,
            child_id,
            "request",
            lambda row: row["ad_smb"].update(workflow_job_id="job-" + "f" * 32),
        )
    elif tamper == "missing_original":
        _update(jobs.store, child_id, "progress", lambda row: row["tasks"][0].update(context=None))
    elif tamper == "changed_request":
        _update(
            jobs.store,
            child_id,
            "request",
            lambda row: row["requests"][0].update(request_id="altered"),
        )
    elif tamper == "changed_terminal":
        _update(
            jobs.store,
            child_id,
            "progress",
            lambda row: row["tasks"][0]["execution"].update(provenance="runner_reported"),
        )
    else:
        path = service.store._run_path(run_id, must_exist=True)
        if tamper == "missing_run":
            (path / "result.json").unlink()
        elif tamper == "unsealed_run":
            (path / "manifest.json").unlink()
        else:
            (path / "result.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ProductStoreError):
        context(service, captured["selected"])
    assert service.store.list_runs()  # The adapter never republished or recovered missing data.


@pytest.mark.parametrize(
    "scenario",
    [
        "still_allowed",
        "legitimate_denied",
        "unknown_cleanup",
        "missing_original_result",
        "truncated_audit",
    ],
)
def test_individual_outcomes_and_uncertainty_remain_separate(workspace, scenario):
    jobs, executor, service = workspace
    service.ad_smb = jobs
    identifier = create(jobs)
    original = executor.terminal

    def terminal(request):
        row = original(request)
        if scenario == "truncated_audit" and request["step"] == "collect_audit":
            row["observation"]["truncated"] = True
        elif request["phase"] == "retest":
            if scenario == "still_allowed" and request["target"]["reader"] == "probe":
                row["observation"] = original({**request, "phase": "baseline"})["observation"]
            elif scenario == "legitimate_denied" and request["target"]["reader"] == "legitimate":
                observation = row["observation"]
                observation.update(
                    state="open_access_denied",
                    bytes_read=0,
                    volume_serial=None,
                    file_id=None,
                    sha256=None,
                )
            elif scenario == "unknown_cleanup":
                row["cleanup"] = "unknown"
        return row

    executor.terminal = terminal
    for phase in ("inspect", "baseline", "harden"):
        assert submit(jobs, identifier, phase)[0]["state"] == "completed"
    executor.crash = scenario == "missing_original_result"
    child, _ = submit(jobs, identifier, "retest")
    assert child["state"] == (
        "failed" if scenario in {"unknown_cleanup", "missing_original_result"} else "completed"
    )
    if scenario == "truncated_audit":
        assert submit(jobs, identifier, "audit")[0]["state"] == "completed"
    summary = context(service, workflow_job_id=identifier)["reference_summary"]
    retest = summary["operations"][3]
    assert retest["outcome"]["effective_access_claim"] is False
    if scenario in {"still_allowed", "legitimate_denied"}:
        assert retest["outcome"]["read_expectation"] == "not_met"
        assert retest["outcome"]["state"] == "complete"
    elif scenario in {"unknown_cleanup", "missing_original_result"}:
        assert retest["outcome"]["state"] == "unknown"
        assert retest["outcome"]["cleanup"] == "unknown"
    else:
        assert summary["operations"][-1]["outcome"]["audit_complete"] is False
    assert executor.recovered == []


def test_api_context_uses_existing_authenticated_read_boundary(workspace):
    jobs, executor, _service, identifier = saved(workspace, ("inspect",))
    path = f"/api/v1/ad-smb/workflows/{identifier}/assistance-context"
    calls = deepcopy(executor.calls)
    with running_server(WorkflowService(jobs), authenticate=False) as (server, _):
        assert request(server, "GET", path)[0] == 401
    with running_server(WorkflowService(jobs)) as (server, _):
        status, _, body = request(server, "GET", path)
        assert status == 200 and json_body(body)["selected"]["workflow_job_id"] == identifier
        assert request(server, "POST", path, body={})[0] == 405
        assert request(server, "GET", path + "?result_digest=ignored")[0] == 400
    assert executor.calls == calls and executor.recovered == []


@pytest.mark.parametrize("event_count", [600, 1000])
def test_normalized_audit_exposes_only_classifications_and_reported_completeness(
    workspace, event_count
):
    from datetime import timedelta

    jobs, executor, service, identifier = saved(workspace, ("inspect",))
    original = executor.terminal

    def terminal(request):
        row = original(request)
        if request["step"] == "collect_audit":
            row["observation"] = large_audit_observation(request)
            source = row["observation"]["normalized_observation"]
            raw_events = []
            for index in range(event_count):
                fields = (
                    {},
                    {"SubjectUserSid": None, "TargetUserSid": None},
                    {"IpAddress": "10.44.0.99"},
                )[index % 3]
                event = audit_event(
                    4624 if index % 2 else 5145,
                    record_id=index + 1,
                    outcome="failure" if index % 5 else "success",
                    when="2026-10-09T00:00:00.5000000Z",
                    fields=fields,
                )
                if index % 7 == 0:
                    event = event.replace(b"0x8020000000000000", b"0x0").replace(
                        b"0x8010000000000000", b"0x0"
                    )
                raw_events.append(event)
            normalized = normalize_events(
                AdSmbScope.from_mapping(request["scope"]),
                raw_events,
                source_host_id=source["source_host_id"],
                source_receipt_digest=source["source_receipt_digest"],
                capture_batch_digest=source["capture_batch_digest"],
                window_start=source["window_start"],
                window_end=source["window_end"],
                completeness="complete",
            )
            normalized["capture_state"] = "query_exhausted"
            row["observation"].update(events=event_count, normalized_observation=normalized)
        return row

    executor.terminal = terminal
    jobs.clock = lambda: NOW + timedelta(seconds=2)
    assert submit(jobs, identifier, "audit")[0]["state"] == "completed"
    captured = context(service, workflow_job_id=identifier)
    normalized = captured["reference_summary"]["operations"][-1]["tasks"][0]["observation"][
        "normalization"
    ]
    assert normalized["reported_completeness"] == "complete"
    assert normalized["capture_state"] == "query_exhausted"
    counts = normalized["classification_counts"]
    assert 1 <= len(counts) <= 18
    assert set(counts[0]) == {"event_id", "audit_outcome", "binding", "count"}
    assert sum(row["count"] for row in counts) == event_count
    assert normalized["input_events"] == event_count
    assert normalized["duplicate_events"] == 0
    assert any(row["audit_outcome"] == "unknown" and row["count"] > 0 for row in counts)
    assert {row["binding"] for row in counts} == {"matched", "incomplete", "outside_scope"}
    assert len(json.dumps(captured["reference_summary"])) < 64 * 1024
    for forbidden in (
        "raw_sha256",
        "source_host_id",
        "principal_sid",
        "client_ip",
        "relative_target",
        "logon_id",
        "computer",
        "raw_events",
    ):
        assert forbidden not in json.dumps(captured)


@pytest.mark.parametrize("timestamp", [None, "2026-10-08T00:00:00+00:00"])
def test_missing_or_stale_snapshot_time_is_refused(workspace, timestamp):
    jobs, _executor, service, identifier = saved(workspace, ("inspect",))
    child_id = jobs._owner(identifier)["progress"]["operations"][0]["job_id"]
    _update(
        jobs.store,
        child_id,
        "progress",
        lambda row: row["tasks"][0]["execution"]["observation"]["snapshot"].update(
            observed_at=timestamp
        ),
    )
    with pytest.raises(ProductStoreError):
        context(service, workflow_job_id=identifier)


def test_runner_reported_label_is_preserved_without_authentication_claim(workspace):
    jobs, executor, service = workspace
    service.ad_smb = jobs
    # Authored label coverage, deliberately no installed receiver or external call.
    executor.selected["provenance"] = "runner_reported"
    original = executor.terminal

    def terminal(request):
        return {**original(request), "provenance": "runner_reported"}

    executor.terminal = terminal
    identifier = create(jobs)
    assert submit(jobs, identifier, "inspect")[0]["state"] == "completed"
    captured = context(service, workflow_job_id=identifier)
    assert captured["reference_summary"]["provenance"] == "runner_reported"
    assert (
        captured["reference_summary"]["operations"][0]["tasks"][0]["provenance"]
        == "runner_reported"
    )
    assert captured["reference_summary"]["effective_access_claim"] is False
    assert any("do not authenticate" in value for value in captured["limitations"])


def test_denied_baseline_keeps_later_missing_stages_unknown(workspace):
    jobs, executor, service = workspace
    service.ad_smb = jobs
    original = executor.terminal

    def terminal(request):
        row = original(request)
        if request["phase"] == "baseline" and request["target"]["reader"] == "probe":
            row["observation"] = original({**request, "phase": "retest"})["observation"]
        return row

    executor.terminal = terminal
    identifier = create(jobs)
    assert submit(jobs, identifier, "inspect")[0]["state"] == "completed"
    assert submit(jobs, identifier, "baseline")[0]["state"] == "completed"
    captured = context(service, workflow_job_id=identifier)
    summary = captured["reference_summary"]
    assert summary["operations"][-1]["outcome"]["read_expectation"] == "not_met"
    assert summary["missing_phases"] == ["harden", "retest", "rollback", "audit"]
    for key, replacement in (
        ("workflow_job_id", "job-" + "f" * 32),
        ("result_digest", "sha256:" + "f" * 64),
    ):
        with pytest.raises(ProductStoreError):
            context(service, {**captured["selected"], key: replacement})
    # Presentation/update timestamps are excluded from the exact saved result binding.
    with jobs.store._connection(write=True) as connection:
        connection.execute("UPDATE jobs SET updated_at = ?", ("2026-10-28T00:00:00+00:00",))
    assert context(service, captured["selected"]) == captured


def _assistance(setup):
    service, access, body = setup
    jobs = AdSmbJobs(service, FakeExecutor(), clock=lambda: NOW)
    service.ad_smb = jobs
    identifier = create(jobs)
    assert submit(jobs, identifier, "inspect")[0]["state"] == "completed"
    captured = context(service, workflow_job_id=identifier)
    body.update(
        submission_id=str(uuid.uuid4()),
        selection=captured["selected"],
        context_digest=captured["context_digest"],
        message="Explain the saved AD result.",
    )
    return service, access, body, jobs, identifier


def test_assistant_has_no_plan_children_or_ad_dispatch(setup):
    service, access, body, jobs, _identifier = _assistance(setup)
    calls = deepcopy(jobs.executor.calls)
    _mock_explanation(access)
    result = _finish_turn(service, body)
    assert result["job"]["state"] == "completed"
    assert result["turn"]["plan"] == result["turn"]["results"] == []
    assert result["turn"]["active_child"] is None
    assert jobs.executor.calls == calls and jobs.executor.recovered == []


@pytest.mark.parametrize("when", ["before_provider", "after_provider"])
def test_stale_source_blocks_provider_or_answer_publication(setup, monkeypatch, when):
    service, access, body, jobs, identifier = _assistance(setup)
    if when == "before_provider":
        original = service.assistance._plan

        def drift(ctx, payload):
            jobs.stop(identifier)
            return original(ctx, payload)

        monkeypatch.setattr(service.assistance, "_plan", drift)
        _mock_explanation(access)
    else:
        _mock_explanation(access, after=lambda: jobs.stop(identifier))
    result = _finish_turn(service, body)
    assert result["job"]["state"] == "failed"
    assert result["turn"]["status"] == "blocked"
    assert result["turn"]["active_child"] is None
    assert "provider explanation only" not in json.dumps(result["job"]["progress"])
    assert len(access.calls) == (0 if when == "before_provider" else 1)


def test_snapshot_capture_rechecks_source(workspace, monkeypatch):
    jobs, _executor, service, identifier = saved(workspace, ("inspect",))
    from bluefire import assistance_ad_smb_context as adapter

    original = adapter._capture
    calls = []

    def capture(selected_jobs, owner):
        result = original(selected_jobs, owner)
        calls.append(owner)
        if len(calls) == 1:
            jobs.stop(identifier)
        return result

    monkeypatch.setattr(adapter, "_capture", capture)
    with pytest.raises(ProductStoreError):
        context(service, workflow_job_id=identifier)
    assert len(calls) == 2
