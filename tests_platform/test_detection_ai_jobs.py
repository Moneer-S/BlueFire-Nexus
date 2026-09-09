from __future__ import annotations

import json
import threading
import uuid
from dataclasses import replace
from pathlib import Path

import pytest

from bluefire.ai_provider_access import ProviderReadiness
from bluefire.ai_wire import AIProviderCancelled
from bluefire.application_errors import APIError
from bluefire.config import AIConfig, AIProviderConfig, AutonomyLevel
from bluefire.product_store import ProductStore
from bluefire.service import BlueFireService
from tests_platform.test_detection_evaluations import observed_run, query_candidate

ROOT = Path(__file__).resolve().parents[1]
SQL = "SELECT fixture_id FROM logs WHERE artifact_type = 'collector_observation'"


class Access:
    def __init__(self):
        self.calls = []
        self.entered = threading.Event()
        self.release = None
        self.transform = lambda value: value

    def readiness(self, config):
        return ProviderReadiness(
            True, "not_required", "ready", "Test provider ready", source="test-broker"
        )

    def post(self, config, *, body, timeout_seconds, cancel_event=None):
        request = json.loads(body)
        self.calls.append(request)
        self.entered.set()
        if self.release is not None:
            assert self.release.wait(10)
        if cancel_event is not None and cancel_event.is_set():
            raise AIProviderCancelled()
        context = json.loads(request.get("input") or request["messages"][1]["content"])
        output = self.transform(
            {
                "source": SQL,
                "reason": "Use the observed record schema.",
                "evidence_refs": [context["observations"][0]["evidence_id"]],
                "limitations": ["Field shape alone cannot establish useful discrimination."],
            }
        )
        if config.kind.value == "chat_completions":
            return json.dumps(
                {
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"role": "assistant", "content": json.dumps(output)},
                        }
                    ],
                    "usage": {"prompt_tokens": 20, "completion_tokens": 30},
                }
            ).encode()
        return json.dumps(
            {
                "status": "completed",
                "output_text": json.dumps(output),
                "usage": {"input_tokens": 20, "output_tokens": 30},
            }
        ).encode()

    def close(self):
        pass


@pytest.fixture
def setup(tmp_path):
    access = Access()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
        ai_provider_access=access,
    )
    provider = AIProviderConfig.from_mapping(
        {
            "id": "provider.test.v1",
            "kind": "openai_responses",
            "model": "explicit-test-model",
            "endpoint": "http://127.0.0.1:8765/v1/responses",
        }
    )
    service._runtime_ai_config = AIConfig(
        AutonomyLevel.ASSIST,
        provider.id,
        service.config.ai.fallback_provider,
        (provider, *service.config.ai.providers),
    )
    candidate_id = query_candidate(service)
    run_id, records = observed_run(service, tmp_path)
    body = {
        "submission_id": str(uuid.uuid4()),
        "run_id": run_id,
        "parent_resource_digest": service.detection_candidate(candidate_id)["candidate"]["digest"],
        "question": "Revise using the observed field schema.",
        "case_role": "attack",
        "provider_id": provider.id,
    }
    yield service, access, candidate_id, body, records
    if access.release is not None:
        access.release.set()
    service.close()


def proposal(setup):
    service, access, candidate_id, body, _ = setup
    job = service.submit_detection_ai_revision(candidate_id, body)["job"]
    done = service.job_controller.wait(job["job_id"], timeout=15)
    assert done["state"] == "completed", done
    return done


def decision_body(job):
    value = job["progress"]["proposal"]
    return {
        "proposal_digest": value["proposal_digest"],
        "parent_resource_digest": value["parent"]["resource_digest"],
        "decision": "accept",
        "reviewed_by": "operator",
    }


@pytest.mark.parametrize("kind", ["openai_responses", "chat_completions"])
def test_real_provider_revision_evaluation_and_idempotent_reconnect(setup, kind):
    service, access, candidate_id, body, records = setup
    provider = service._runtime_ai_config.provider(body["provider_id"])
    service._runtime_ai_config = replace(
        service._runtime_ai_config, providers=(replace(provider, kind=type(provider.kind)(kind)),)
    )
    parent = service.detection_candidate(candidate_id)
    job = proposal(setup)
    assert service.detection_candidate(candidate_id) == parent
    assert not service.detection_run_evaluations(candidate_id)["evaluations"]
    assert (
        service.submit_detection_ai_revision(candidate_id, body)["job"]["job_id"] == job["job_id"]
    )
    assert len(access.calls) == 1
    sent = json.dumps(access.calls)
    assert "public unit bytes" not in sent and "staged/bundle.jsonl" not in sent
    assert "explicit-test-model" in sent
    accepted = service.decide_detection_ai_revision(job["job_id"], decision_body(job))
    completed = service.job_controller.wait(accepted["application_job"]["job_id"], timeout=15)
    assert completed["state"] == "completed", completed
    receipt = completed["progress"]["application"]
    child = service.detection_candidate(receipt["candidate_id"])["candidate"]
    assert child["document"]["rule_source"] == SQL
    assert child["document"]["parent_candidate_id"] == candidate_id
    assert child["document"]["provenance"] == parent["candidate"]["document"]["provenance"]
    assert job["progress"]["proposal"]["evidence_refs"] == [records[0].evidence_id]
    reports = service.detection_run_evaluations(child["id"])["evaluations"]
    assert len(reports) == 1 and reports[0]["evaluation_id"] == receipt["evaluation_id"]
    assert reports[0]["result"]["state"] == "matched"
    # The proposal used these observations: this is development data regardless
    # of the operator's activity label or the wording of the limitations text.
    report = reports[0]
    assert report["source"]["run_id"] == body["run_id"]
    assert report["development_case"] is True
    classification = report["classification"]
    assert classification["activity_label"] == "attack"
    assert classification["evaluation_use"] == "development"
    assert classification["requested_use"] == "unspecified"
    assert classification["use_basis"] == "recorded_development"
    assert "proposal_source" in classification["development_reasons"]
    assert classification["independence_verified"] is False
    assert service.detection_candidate(candidate_id) == parent
    again = service.decide_detection_ai_revision(job["job_id"], decision_body(job))
    assert again["application_job"]["job_id"] == completed["job_id"]
    assert again["proposal_job"]["progress"]["application"] == receipt
    assert len(access.calls) == 1


@pytest.mark.parametrize(
    "change",
    ["off", "explicit_off", "auto", "unknown_ref", "extra_authority", "unchanged", "invalid_sql"],
)
def test_refusals_never_create_child(setup, change):
    service, access, candidate_id, body, _ = setup
    before = service.product_store.list_resources("detection")
    if change == "off":
        service._runtime_ai_config = replace(service._runtime_ai_config, autonomy=AutonomyLevel.OFF)
    if change == "explicit_off":
        body["autonomy"] = "off"
    if change == "auto":
        body["autonomy"] = "auto"
    if change in {"off", "explicit_off", "auto"}:
        job = service.submit_detection_ai_revision(candidate_id, body)["job"]
        done = service.job_controller.wait(job["job_id"], timeout=15)
        assert done["state"] == "failed" and "operation_error" in done["progress"]
        assert done["request"]["submitted_request"] == body
        assert not access.calls
        return
    patches = {
        "unknown_ref": {"evidence_refs": ["invented"]},
        "extra_authority": {"case_role": "benign"},
        "unchanged": {
            "source": service.detection_candidate(candidate_id)["candidate"]["document"][
                "rule_source"
            ]
        },
        "invalid_sql": {"source": "DELETE FROM logs"},
    }
    access.transform = lambda value: {**value, **patches[change]}
    job = service.submit_detection_ai_revision(candidate_id, body)["job"]
    done = service.job_controller.wait(job["job_id"], timeout=15)
    if change == "invalid_sql" and done["state"] == "completed":
        accepted = service.decide_detection_ai_revision(done["job_id"], decision_body(done))
        done = service.job_controller.wait(accepted["application_job"]["job_id"], timeout=15)
    assert done["state"] == "failed"
    assert service.product_store.list_resources("detection") == before


def test_cancel_provider_stale_parent_and_first_decision(setup):
    service, access, candidate_id, body, _ = setup
    access.release = threading.Event()
    started = service.submit_detection_ai_revision(candidate_id, body)["job"]
    assert access.entered.wait(10)
    assert service.active_jobs()["jobs"] == []
    service.cancel_job(started["job_id"])
    access.release.set()
    assert service.job_controller.wait(started["job_id"], timeout=15)["state"] == "cancelled"
    assert len(access.calls) == 1
    body["submission_id"] = str(uuid.uuid4())
    done = proposal(setup)
    rejected = {**decision_body(done), "decision": "reject"}
    assert service.decide_detection_ai_revision(done["job_id"], rejected)["application_job"] is None
    assert service.decide_detection_ai_revision(done["job_id"], rejected)["application_job"] is None
    with pytest.raises(APIError):
        service.decide_detection_ai_revision(done["job_id"], decision_body(done))
    body["submission_id"] = str(uuid.uuid4())
    fresh = proposal(setup)
    service.exercise_detection_observed(candidate_id, {"run_id": body["run_id"]})
    with pytest.raises(APIError, match="parent changed"):
        service.decide_detection_ai_revision(fresh["job_id"], decision_body(fresh))


@pytest.mark.parametrize("fault", ["report", "link", "before_commit"])
def test_atomic_application_rolls_back_child_report_and_links(setup, monkeypatch, fault):
    from bluefire import product_store_detection_ai as atomic

    service, _, candidate_id, _, _ = setup
    done = proposal(setup)
    before = service.product_store.list_resources("detection")
    if fault == "report":
        monkeypatch.setattr(
            atomic,
            "save_report",
            lambda *args: (_ for _ in ()).throw(RuntimeError("injected report fault")),
        )
    if fault == "link":
        original = atomic._progress

        def update(connection, job, patch, **kwargs):
            original(connection, job, patch, **kwargs)
            if "application" in patch:
                raise RuntimeError("injected link fault")

        monkeypatch.setattr(atomic, "_progress", update)
    if fault == "before_commit":
        original = atomic.apply_revision

        def apply(store, **kwargs):
            calls = 0

            def cancel():
                nonlocal calls
                calls += 1
                if calls == 2:
                    from bluefire.job_runtime import JobCancelled

                    raise JobCancelled("injected last cancellation")

            return original(store, **{**kwargs, "check_cancelled": cancel})

        monkeypatch.setattr("bluefire.detection_ai_jobs.apply_revision", apply)
    accepted = service.decide_detection_ai_revision(done["job_id"], decision_body(done))
    failed = service.job_controller.wait(accepted["application_job"]["job_id"], timeout=15)
    assert failed["state"] in {"failed", "cancelled"}
    assert service.product_store.list_resources("detection") == before
    assert "application" not in service.product_store.get_job(done["job_id"])["progress"]
    with service.product_store._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM detection_run_evaluations").fetchone()[0] == 0
        )


def test_postcommit_interruption_retry_returns_exact_committed_child_and_report(setup, monkeypatch):
    from bluefire import detection_ai_jobs as jobs

    service, _, _, _, _ = setup
    done = proposal(setup)
    original = jobs.apply_revision

    def interrupted(store, **kwargs):
        original(store, **kwargs)
        raise RuntimeError("injected postcommit process interruption")

    monkeypatch.setattr(jobs, "apply_revision", interrupted)
    accepted = service.decide_detection_ai_revision(done["job_id"], decision_body(done))
    application_id = accepted["application_job"]["job_id"]
    assert service.job_controller.wait(application_id, timeout=15)["state"] == "failed"
    committed = service.product_store.get_job(done["job_id"])["progress"]["application"]
    # Emulate restart recovery after an actual process exits between commit and
    # controller completion, rather than giving failed jobs automatic retry.
    with service.product_store._connection(write=True) as connection:
        connection.execute(
            "UPDATE jobs SET state = 'interrupted' WHERE job_id = ?", (application_id,)
        )
    monkeypatch.setattr(jobs, "apply_revision", original)
    retried = service.retry_job(application_id)["job"]
    again = service.retry_job(application_id)["job"]
    assert again["job_id"] == retried["job_id"]
    completed = service.job_controller.wait(retried["job_id"], timeout=15)
    assert completed["state"] == "completed", completed
    assert completed["progress"]["application"] == committed
    source = service.product_store.get_job(application_id)
    source_progress = {
        key: value for key, value in source["progress"].items() if key != "retry_job_id"
    }
    service.product_store.transition_job(application_id, "interrupted", progress=source_progress)
    assert (
        service.decide_detection_ai_revision(done["job_id"], decision_body(done))[
            "application_job"
        ]["job_id"]
        == completed["job_id"]
    )
    assert len(service.detection_run_evaluations(committed["candidate_id"])["evaluations"]) == 1
    with service.product_store._connection() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM detection_revisions WHERE revision > 1"
            ).fetchone()[0]
            == 1
        )
    corrupted = {**completed["request"], "proposal_digest": "sha256:" + "0" * 64}
    with service.product_store._connection(write=True) as connection:
        connection.execute(
            "UPDATE jobs SET request_json = ? WHERE job_id = ?",
            (json.dumps(corrupted), completed["job_id"]),
        )
    with pytest.raises(APIError, match="retry lineage"):
        service.decide_detection_ai_revision(done["job_id"], decision_body(done))


def test_semantic_admission_rejection_is_durable_and_same_uuid_never_restarts(setup):
    service, access, candidate_id, body, _ = setup
    stale = {**body, "parent_resource_digest": "sha256:" + "0" * 64}
    job = service.submit_detection_ai_revision(candidate_id, stale)["job"]
    done = service.job_controller.wait(job["job_id"], timeout=15)
    assert done["state"] == "failed"
    assert done["request"]["candidate_id"] == candidate_id
    assert done["request"]["submitted_request"] == stale
    assert "parent changed" in done["progress"]["operation_error"]["message"]
    assert (
        service.submit_detection_ai_revision(candidate_id, stale)["job"]["job_id"] == done["job_id"]
    )
    with pytest.raises(APIError):
        service.submit_detection_ai_revision(candidate_id, body)
    assert not access.calls


@pytest.mark.parametrize("explicit_assist", [False, True])
def test_retry_preserves_resolved_assist_without_changing_default(
    setup, monkeypatch, explicit_assist
):
    service, access, candidate_id, body, _ = setup
    if explicit_assist:
        body["autonomy"] = "assist"
        service._runtime_ai_config = replace(service._runtime_ai_config, autonomy=AutonomyLevel.OFF)
    original = access.post

    def interrupted(*args, **kwargs):
        raise RuntimeError("unit process interruption before provider response")

    monkeypatch.setattr(access, "post", interrupted)
    started = service.submit_detection_ai_revision(candidate_id, body)["job"]
    failed = service.job_controller.wait(started["job_id"], timeout=15)
    assert failed["state"] == "failed" and failed["request"]["autonomy"] == "assist"
    # Emulate the existing restart recovery state in this unit database only.
    with service.product_store._connection(write=True) as connection:
        connection.execute(
            "UPDATE jobs SET state = 'interrupted' WHERE job_id = ?", (failed["job_id"],)
        )
    service._runtime_ai_config = replace(service._runtime_ai_config, autonomy=AutonomyLevel.OFF)
    monkeypatch.setattr(access, "post", original)
    retry = service.retry_job(failed["job_id"])["job"]
    completed = service.job_controller.wait(retry["job_id"], timeout=15)
    assert completed["state"] == "completed", completed
    assert completed["request"]["autonomy"] == "assist"
    assert completed["request"]["submitted_request"] == body
    assert service._runtime_ai_config.autonomy is AutonomyLevel.OFF and len(access.calls) == 1


def test_authenticated_http_create_review_and_method_query_guards(setup):
    from tests_platform.test_api import request, running_server

    service, _, candidate_id, body, _ = setup
    path = f"/api/v1/detections/{candidate_id}/ai-revision-jobs"
    with running_server(service) as (server, _):
        assert request(server, "POST", path, body=body, authenticated=False)[0] == 401
        assert request(server, "GET", path)[0] == 405
        assert request(server, "POST", path + "?other=1", body=body)[0] == 400
        status, _, raw = request(server, "POST", path, body=body)
        assert status == 202
        job = service.job_controller.wait(json.loads(raw)["job"]["job_id"], timeout=15)
        assert job["state"] == "completed"
        decision_path = f"/api/v1/jobs/{job['job_id']}/detection-revision-decisions"
        assert request(server, "GET", decision_path)[0] == 405
        assert (
            request(server, "POST", decision_path + "?other=1", body=decision_body(job))[0] == 400
        )
        assert (
            request(server, "POST", decision_path, body=decision_body(job), authenticated=False)[0]
            == 401
        )
        status, _, raw = request(server, "POST", decision_path, body=decision_body(job))
        assert status == 202
        completed = service.job_controller.wait(
            json.loads(raw)["application_job"]["job_id"], timeout=15
        )
        assert completed["state"] == "completed", completed


def test_cross_controller_concurrent_application_attempts_commit_one_child_report(setup):
    from concurrent.futures import ThreadPoolExecutor

    from bluefire.detection_ai_jobs import DetectionAIJobs
    from bluefire.detection_lab import DetectionLabService
    from bluefire.job_runtime import RunJobController
    from bluefire.product_store_detection_ai import APPLY_KIND, decide

    service, access, _, _, _ = setup
    done = proposal(setup)
    decide(service.product_store, done["job_id"], decision_body(done))
    second_store = ProductStore(service.product_store.path)
    second_lab = DetectionLabService(
        product_store=second_store, run_store=service.store, registry=service.registry
    )
    second_controller = RunJobController(second_store, max_workers=1, recover_on_start=False)
    helper = DetectionAIJobs(
        lab=second_lab, controller=second_controller, ai_config=service._runtime_ai, access=access
    )
    body = {
        "schema_version": "bluefire.detection-ai-apply-request.v1",
        "proposal_job_id": done["job_id"],
        "proposal_digest": done["progress"]["proposal"]["proposal_digest"],
    }
    gate = threading.Barrier(2)

    def start(controller, callback):
        gate.wait(10)
        created = controller.submit(APPLY_KIND, body, callback=callback)
        return controller.wait(created["job_id"], timeout=15)

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(start, service.job_controller, service.detection_ai._apply)
            second = pool.submit(start, second_controller, helper._apply)
            results = [first.result(20), second.result(20)]
        assert all(row["state"] == "completed" for row in results), results
        assert results[0]["progress"]["application"] == results[1]["progress"]["application"]
        with second_store._connection() as connection:
            assert (
                connection.execute("SELECT COUNT(*) FROM detection_run_evaluations").fetchone()[0]
                == 1
            )
            assert (
                connection.execute(
                    "SELECT COUNT(*) FROM detection_revisions WHERE revision > 1"
                ).fetchone()[0]
                == 1
            )
    finally:
        second_controller.shutdown()


def test_parent_change_between_freshness_and_atomic_commit_refuses_child(setup, monkeypatch):
    from bluefire import detection_ai_jobs as jobs

    service, _, candidate_id, body, _ = setup
    done = proposal(setup)
    original = jobs.apply_revision

    def change_then_apply(store, **kwargs):
        service.exercise_detection_observed(candidate_id, {"run_id": body["run_id"]})
        return original(store, **kwargs)

    monkeypatch.setattr(jobs, "apply_revision", change_then_apply)
    accepted = service.decide_detection_ai_revision(done["job_id"], decision_body(done))
    failed = service.job_controller.wait(accepted["application_job"]["job_id"], timeout=15)
    assert failed["state"] == "failed"
    with service.product_store._connection() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM detection_revisions WHERE revision > 1"
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM detection_run_evaluations").fetchone()[0] == 0
        )


def test_provider_metadata_projection_never_sends_raw_logs_even_when_content_enabled(setup):
    from bluefire.ai_detection_revision import observed_context
    from bluefire.evidence import EvidenceRecord

    service, _, _, _, records = setup
    provider = service._runtime_ai_config.provider()
    provider = replace(
        provider, redaction=replace(provider.redaction, include_evidence_content=True)
    )
    record = records[0]
    credential_value = uuid.uuid4().hex
    altered = EvidenceRecord.create(
        run_id=record.run_id,
        step_id=record.step_id,
        behavior_id=record.behavior_id,
        provenance=record.provenance,
        producer=record.producer,
        content={
            **record.content,
            "stdout": "private-process-output",
            "command": "private-command",
            "password": credential_value,
        },
        target_scope_ref=record.target_scope_ref,
    )
    sent = observed_context([altered], provider)
    encoded = json.dumps(sent)
    assert (
        "private-process-output" not in encoded
        and "private-command" not in encoded
        and credential_value not in encoded
    )
    assert sent[0]["evidence_metadata"]["artifact_type"] == record.content["artifact_type"]


def test_source_case_with_evidence_gap_retains_unknown_instead_of_false_zero(setup, tmp_path):
    service, _, candidate_id, body, _ = setup
    run_id, _ = observed_run(service, tmp_path, missing=True)
    body["run_id"] = run_id
    done = proposal(setup)
    accepted = service.decide_detection_ai_revision(done["job_id"], decision_body(done))
    completed = service.job_controller.wait(accepted["application_job"]["job_id"], timeout=15)
    assert completed["state"] == "completed", completed
    report = service.detection_run_evaluations(completed["result_ref"])["evaluations"][0]
    assert report["development_case"] is True
    assert report["result"]["state"] == "insufficient_evidence"
    assert report["result"]["match_count"] is None
    assert report["backend"]["executed"] is False


def test_provider_redaction_bound_refuses_incomplete_source_without_network_call(setup):
    service, access, candidate_id, body, _ = setup
    provider = service._runtime_ai_config.provider()
    provider = replace(provider, redaction=replace(provider.redaction, max_string_chars=10))
    service._runtime_ai_config = replace(service._runtime_ai_config, providers=(provider,))
    job = service.submit_detection_ai_revision(candidate_id, body)["job"]
    done = service.job_controller.wait(job["job_id"], timeout=15)
    assert done["state"] == "failed"
    assert not access.calls


def test_installed_sigma_provider_revision_uses_existing_conversion_and_evaluation(setup):
    service, access, _, body, _ = setup
    if not service.detection_health()["languages"]["sigma"]["ready"]:
        pytest.skip("The pinned pySigma SQLite adapter is unavailable.")
    candidate_id = query_candidate(service, language="sigma")
    sigma = """title: Bounded Observed Metadata
id: 11111111-1111-4111-8111-111111111111
status: test
logsource:
  category: file_event
detection:
  selection:
    artifact_type: collector_observation
    path|startswith: staged/
  condition: selection
level: low
"""
    parent = service.parse_detection_candidate(candidate_id, {"source": sigma})["candidate"]
    revised = sigma.replace("    path|startswith: staged/\n", "")
    access.transform = lambda value: {**value, "source": revised}
    body["parent_resource_digest"] = parent["digest"]
    job = service.submit_detection_ai_revision(candidate_id, body)["job"]
    done = service.job_controller.wait(job["job_id"], timeout=15)
    assert done["state"] == "completed", done
    accepted = service.decide_detection_ai_revision(done["job_id"], decision_body(done))
    completed = service.job_controller.wait(accepted["application_job"]["job_id"], timeout=15)
    assert completed["state"] == "completed", completed
    report = service.detection_run_evaluations(completed["result_ref"])["evaluations"][0]
    assert report["candidate"]["parser_backend"]["name"] == "pySigma"
    assert report["result"]["state"] == "matched"
