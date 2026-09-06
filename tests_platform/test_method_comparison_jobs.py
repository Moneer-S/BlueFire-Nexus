"""Fixture-owned connected operation tests; no native runner effects."""

from __future__ import annotations

import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from bluefire.ai_provider_access import ProviderReadiness
from bluefire.application_errors import APIError
from bluefire.collectors import CollectionRequest, FilesystemCollector
from bluefire.config import AIConfig, AIProviderConfig, AutonomyLevel
from bluefire.contracts import ExecutionMode
from bluefire.orchestrator import Orchestrator
from bluefire.service import BlueFireService
from tests_platform.test_detection_evaluations import query_candidate

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = "scenario.endpoint.lab-collection-methods.v1"


class Access:
    def __init__(self):
        self.calls = []
        self.transform = lambda value: value

    def readiness(self, config):
        return ProviderReadiness(True, "not_required", "ready", "Unit provider")

    def post(self, config, *, body, timeout_seconds, cancel_event=None):
        value = json.loads(body)
        self.calls.append(value)
        context = json.loads(value.get("input") or value["messages"][1]["content"])
        result = self.transform(
            {
                "option_id": context["options"][0]["option_id"],
                "reason": "Compare records and archive over the same transformed input.",
                "evidence_refs": [context["observations"][0]["evidence_id"]],
                "limitations": ["Unit observed fixture; not native or installed proof."],
            }
        )
        if config.kind.value == "chat_completions":
            return json.dumps(
                {
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"role": "assistant", "content": json.dumps(result)},
                        }
                    ],
                    "usage": {"prompt_tokens": 20, "completion_tokens": 30},
                }
            ).encode()
        return json.dumps(
            {
                "status": "completed",
                "output_text": json.dumps(result),
                "usage": {"input_tokens": 20, "output_tokens": 30},
            }
        ).encode()

    def close(self):
        pass


def source_run(service, tmp_path, *, execute=False, record_collectors=True):
    scenario = next(row for row in service._scenarios if row.id == SCENARIO)
    preflight = service.preflight({"scenario_id": SCENARIO, "mode": "simulate", "autonomy": "off"})
    profile = service._profile("sandbox-execute.v1", ExecutionMode.EXECUTE) if execute else None
    if execute:
        preflight["plan"] = (
            Orchestrator(service.registry, service.store)
            .planner.compile(
                scenario,
                mode=ExecutionMode.EXECUTE,
                profile=profile,
                autonomy=AutonomyLevel.OFF,
                ai_provider=service._ai_provider_metadata(
                    AutonomyLevel.OFF, "deterministic-offline.v1"
                ),
            )
            .to_dict()
        )
    handle = service.store.create_run(
        scenario=scenario.to_dict(),
        plan=preflight["plan"],
        policy={
            "preflight": preflight,
            "autonomy": "off",
            **(
                {
                    "approval_context": {
                        "collector_binding": service._collector_binding(
                            ("collector.filesystem.sandbox.v1",) if execute else ()
                        )
                    }
                }
                if record_collectors
                else {}
            ),
        },
        profile=profile.to_dict() if profile else None,
    )
    workspace = tmp_path / "source-observer"
    workspace.mkdir()
    (workspace / "public.jsonl").write_text('{"public_lab":true}\n', encoding="utf-8")
    records = (
        FilesystemCollector(workspace)
        .collect(
            CollectionRequest(
                run_id=handle.run_id,
                step_id="stage_collection",
                behavior_id="sandbox.collection.records.v1",
                runner_profile_id="profile.fixture",
                target_scope_ref="runner-profile:profile.fixture",
                settings={"paths": ["public.jsonl"]},
            )
        )
        .records
    )
    service.store.finalize(
        handle.run_id,
        result={
            "status": "completed",
            "mode": "execute" if execute else "simulate",
            **(
                {
                    "authorized_target_scope": {"scope_refs": ["sandbox.workspace"]},
                    "runner_profile_id": profile.id,
                }
                if profile
                else {}
            ),
            "autonomy": "off",
            "steps": [],
            "cleanup": {"success": True},
        },
        evidence=[record.to_dict() for record in records],
        detections=[],
    )
    return handle.run_id


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
            "model": "unit-model",
            "endpoint": "http://127.0.0.1:8765/v1/responses",
        }
    )
    service._runtime_ai_config = AIConfig(
        AutonomyLevel.OFF,
        provider.id,
        service.config.ai.fallback_provider,
        (provider, *service.config.ai.providers),
    )
    candidate_id = query_candidate(service, "size_bytes > 0")
    run_id = source_run(service, tmp_path)
    context = service.method_comparison_context(run_id)
    request = {
        "submission_id": str(uuid.uuid4()),
        "source_binding_digest": context["source_binding_digest"],
        "selected_step_id": "stage_collection",
        "candidate_id": candidate_id,
        "candidate_resource_digest": service.detection_candidate(candidate_id)["candidate"][
            "digest"
        ],
        "question": "Does this saved rule detect the other collection method in the same scope?",
        "source_case_role": "attack",
        "provider_id": provider.id,
        "autonomy": "assist",
    }
    yield service, access, run_id, request, context
    service.close()


def proposal(setup):
    service, _, run_id, request, _ = setup
    job = service.submit_method_comparison(run_id, request)["job"]
    result = service.job_controller.wait(job["job_id"], timeout=15)
    assert result["state"] == "completed", result
    return result


def decision(job):
    return {
        "proposal_digest": job["progress"]["proposal"]["proposal_digest"],
        "decision": "accept",
        "reviewed_by": "unit operator",
    }


@pytest.mark.parametrize("kind", ["openai_responses", "chat_completions"])
def test_packaged_method_replay_and_durable_comparison(setup, kind):
    service, access, source, request, context = setup
    provider = service._runtime_ai_config.provider(request["provider_id"])
    service._runtime_ai_config = replace(
        service._runtime_ai_config,
        providers=(replace(provider, kind=type(provider.kind)(kind)), *service.config.ai.providers),
    )
    assert context["options"][0]["behavior_to"] == "sandbox.collection.archive.v1"
    job = proposal(setup)
    accepted = service.decide_method_comparison(job["job_id"], decision(job))
    child = service.job_controller.wait(accepted["replay_job"]["job_id"], timeout=15)
    assert child["state"] == "completed", child
    receipt = child["progress"]["comparison"]
    run = service.store.get_run(receipt["child_run_id"])
    step = next(row for row in run["scenario"]["steps"] if row["id"] == "stage_collection")
    assert step["behavior_id"] == "sandbox.collection.archive.v1"
    assert run["replay"]["source_run_id"] == source
    reports = service.detection_run_evaluations(request["candidate_id"])["evaluations"]
    assert len(reports) == 2
    assert {row["source"]["run_id"] for row in reports} == {source, run["run_id"]}
    assert (
        next(row for row in reports if row["source"]["run_id"] == run["run_id"])["result"][
            "match_count"
        ]
        is None
    )
    again = service.decide_method_comparison(job["job_id"], decision(job))
    assert again["replay_job"]["job_id"] == child["job_id"] and len(access.calls) == 1
    assert service.submit_method_comparison(source, request)["job"]["job_id"] == job["job_id"]


def test_stop_before_publication_prevents_child(setup):
    service, _, _, _, _ = setup
    job = proposal(setup)
    service.cancel_job(job["job_id"])
    with pytest.raises(APIError, match="stopped"):
        service.decide_method_comparison(job["job_id"], decision(job))
    assert not [
        row for row in service.product_store.list_jobs() if row["kind"] == "scenario.replay"
    ]


def test_stop_wins_publication_race(setup, monkeypatch):
    service, _, _, _, _ = setup
    job = proposal(setup)
    entered, release = threading.Event(), threading.Event()
    create = service.product_store.create_idempotent_job

    def held(kind, request, **kwargs):
        if kind == "scenario.replay":
            entered.set()
            assert release.wait(10)
        return create(kind, request, **kwargs)

    monkeypatch.setattr(service.product_store, "create_idempotent_job", held)
    with ThreadPoolExecutor(max_workers=1) as pool:
        attempt = pool.submit(service.decide_method_comparison, job["job_id"], decision(job))
        try:
            assert entered.wait(10)
            service.cancel_job(job["job_id"])
        finally:
            release.set()
        with pytest.raises(APIError, match="publication"):
            attempt.result(timeout=10)
    assert not [
        row for row in service.product_store.list_jobs() if row["kind"] == "scenario.replay"
    ]


@pytest.mark.parametrize("fault", ["build", "second_save"])
def test_analysis_failure_recovers_without_another_replay(setup, monkeypatch, fault):
    service, _, _, body, _ = setup
    job = proposal(setup)
    import bluefire.method_comparison_jobs as jobs
    import bluefire.product_store_method_comparison as persistence

    execute = service._execute_replay_job
    calls = []

    def counted(*args):
        calls.append(True)
        return execute(*args)

    monkeypatch.setattr(service, "_execute_replay_job", counted)
    original = jobs.build_run_evaluation if fault == "build" else persistence.save_report
    count = 0

    def broken(*args, **kwargs):
        nonlocal count
        count += 1
        if fault == "build" or count == 2:
            raise RuntimeError("injected interruption after replay receipt")
        return original(*args, **kwargs)

    monkeypatch.setattr(
        jobs if fault == "build" else persistence,
        "build_run_evaluation" if fault == "build" else "save_report",
        broken,
    )
    accepted = service.decide_method_comparison(job["job_id"], decision(job))
    failed = service.job_controller.wait(accepted["replay_job"]["job_id"], timeout=15)
    assert failed["state"] == "failed" and failed["result_ref"]
    assert service.product_store.detection_evaluations(body["candidate_id"]) == []
    parent = service.product_store.get_job(job["job_id"])
    assert parent["progress"]["replay_result"]["source"]["run_id"] == failed["result_ref"]
    monkeypatch.setattr(
        jobs if fault == "build" else persistence,
        "build_run_evaluation" if fault == "build" else "save_report",
        original,
    )
    recovery = service.retry_job(failed["job_id"])["job"]
    complete = service.job_controller.wait(recovery["job_id"], timeout=15)
    assert complete["state"] == "completed", complete
    assert complete["result_ref"] == failed["result_ref"]
    assert service.retry_job(failed["job_id"])["job"]["job_id"] == recovery["job_id"]
    assert (
        len(calls) == 1
        and len(service.product_store.detection_evaluations(body["candidate_id"])) == 2
    )


@pytest.mark.parametrize(
    "invalid", ["off", "default_off", "option", "reference", "authority", "stale"]
)
def test_refusal_has_no_replay_and_retains_exact_admission(setup, invalid):
    service, access, run_id, body, _ = setup
    if invalid == "off":
        body["autonomy"] = "off"
    if invalid == "default_off":
        body.pop("autonomy")
    if invalid == "stale":
        body["candidate_resource_digest"] = "sha256:" + "a" * 64
    if invalid in {"option", "reference", "authority"}:
        access.transform = lambda value: {
            **value,
            **(
                {"option_id": "invented"}
                if invalid == "option"
                else (
                    {"evidence_refs": ["invented"]}
                    if invalid == "reference"
                    else {"target_scope": {"scope_refs": ["different"]}}
                )
            ),
        }
    job = service.submit_method_comparison(run_id, body)["job"]
    failed = service.job_controller.wait(job["job_id"], timeout=15)
    assert failed["state"] == "failed", failed
    assert failed["request"]["submitted_request"] == body
    assert not [
        row for row in service.product_store.list_jobs() if row["kind"] == "scenario.replay"
    ]
    if invalid in {"off", "default_off", "stale"}:
        assert not access.calls


def test_auto_continues_fixed_simulate_sequence(setup):
    service, access, run_id, body, _ = setup
    body["autonomy"] = "auto"
    job = service.submit_method_comparison(run_id, body)["job"]
    done = service.job_controller.wait(job["job_id"], timeout=15)
    assert done["state"] == "completed", done
    assert done["progress"]["decision"]["basis"] == "bounded_auto_policy"
    child = service.job_controller.wait(done["progress"]["replay_job_id"], timeout=15)
    assert child["state"] == "completed" and "comparison" in child["progress"]
    assert len(access.calls) == 1


def test_auto_execute_stops_at_fresh_exact_approval(setup, tmp_path, monkeypatch):
    from tests_platform.test_replay_jobs import awaiting
    from tests_platform.test_service import ReadyInventoryRunner

    service, access, _, body, _ = setup
    runner = ReadyInventoryRunner(actions=set(service.registry.action_ids))
    sandbox = tmp_path / "fake-runner-root"
    sandbox.mkdir()
    monkeypatch.setattr(service, "runner_factory", lambda profile: (runner, sandbox))
    source_root = tmp_path / "execute-source-fixture"
    source_root.mkdir()
    run_id = source_run(service, source_root, execute=True)
    context = service.method_comparison_context(run_id)
    body.update(
        submission_id=str(uuid.uuid4()),
        source_binding_digest=context["source_binding_digest"],
        autonomy="auto",
    )
    job = service.submit_method_comparison(run_id, body)["job"]
    done = service.job_controller.wait(job["job_id"], timeout=15)
    assert done["state"] == "completed", done
    child = awaiting(service, done["progress"]["replay_job_id"])
    assert child["state"] == "awaiting_approval" and runner.execute_calls == 0
    approval = service.product_store.get_approval_request(child["request"]["approval_request_id"])
    assert approval["status"] == "pending"
    assert child["request"]["target_scope"] == {"scope_refs": ["sandbox.workspace"]}
    assert (
        child["request"]["replay_preparation"]["preflight"]["approval_binding"][
            "target_scope_digest"
        ]
        == approval["target_scope_digest"]
    )
    assert child["request"]["autonomy"] == "off" and len(access.calls) == 1
    service.cancel_job(job["job_id"])
    assert service.product_store.get_job(child["job_id"])["state"] == "cancelled"
    assert runner.execute_calls == 0


@pytest.mark.parametrize("boundary", ["before_link", "after_commit", "cancel_before_commit"])
def test_interruptions_preserve_one_run_and_resume_only_analysis(setup, monkeypatch, boundary):
    import bluefire.method_comparison_jobs as jobs
    import bluefire.product_store_method_comparison as persistence

    service, _, _, body, _ = setup
    job = proposal(setup)
    runs_before = len(service.store.list_runs())
    target, name = (
        (jobs, "retain_run")
        if boundary == "before_link"
        else (
            (jobs, "commit_comparison")
            if boundary == "after_commit"
            else (persistence, "save_report")
        )
    )
    original = getattr(target, name)

    def fail(*args, **kwargs):
        if boundary == "before_link":
            raise RuntimeError("unit crash before result link")
        result = original(*args, **kwargs)
        if boundary == "after_commit":
            raise RuntimeError("unit crash after atomic comparison receipt")
        child_id = service.method_comparison._job_id(job["request"]["replay_submission_id"])
        service.job_controller._controls[child_id].cancel_event.set()
        return result

    monkeypatch.setattr(target, name, fail)
    accepted = service.decide_method_comparison(job["job_id"], decision(job))
    failed = service.job_controller.wait(accepted["replay_job"]["job_id"], timeout=15)
    assert failed["state"] in {"failed", "cancelled"}, failed
    assert len(service.store.list_runs()) == runs_before + 1
    assert len(service.product_store.detection_evaluations(body["candidate_id"])) == (
        2 if boundary == "after_commit" else 0
    )
    monkeypatch.setattr(target, name, original)
    retry = service.retry_job(failed["job_id"])["job"]
    recovered = service.job_controller.wait(retry["job_id"], timeout=15)
    assert recovered["state"] == "completed", recovered
    assert len(service.store.list_runs()) == runs_before + 1
    assert len(service.product_store.detection_evaluations(body["candidate_id"])) == 2


def test_manual_detector_change_stales_review(setup):
    service, _, source, body, _ = setup
    job = proposal(setup)
    service.exercise_detection_observed(body["candidate_id"], {"run_id": source})
    with pytest.raises(APIError, match="detector changed"):
        service.decide_method_comparison(job["job_id"], decision(job))
    assert not [
        row for row in service.product_store.list_jobs() if row["kind"] == "scenario.replay"
    ]


def test_concurrent_accepts_publish_one_replay(setup):
    service, _, _, _, _ = setup
    job = proposal(setup)
    with ThreadPoolExecutor(max_workers=2) as pool:
        attempts = [
            pool.submit(service.decide_method_comparison, job["job_id"], decision(job))
            for _ in range(2)
        ]
        results = [attempt.result(timeout=15) for attempt in attempts]
    assert results[0]["replay_job"]["job_id"] == results[1]["replay_job"]["job_id"]
    service.job_controller.wait(results[0]["replay_job"]["job_id"], timeout=15)
    assert (
        len([row for row in service.product_store.list_jobs() if row["kind"] == "scenario.replay"])
        == 1
    )


def test_stop_cancels_analysis_and_explicit_recovery_never_reopens_replay(setup, monkeypatch):
    import bluefire.method_comparison_jobs as jobs

    service, _, _, _, _ = setup
    job = proposal(setup)
    original_build = jobs.build_run_evaluation
    monkeypatch.setattr(
        jobs,
        "build_run_evaluation",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("unit analysis interruption")),
    )
    accepted = service.decide_method_comparison(job["job_id"], decision(job))
    failed = service.job_controller.wait(accepted["replay_job"]["job_id"], timeout=15)
    assert failed["state"] == "failed"
    monkeypatch.setattr(jobs, "build_run_evaluation", original_build)
    original_recover = service.method_comparison._recover
    entered, release = threading.Event(), threading.Event()

    def held(context, request):
        entered.set()
        assert release.wait(10)
        return original_recover(context, request)

    monkeypatch.setattr(service.method_comparison, "_recover", held)
    first = service.retry_job(failed["job_id"])
    assert (
        first["schema_version"] == "bluefire.job-retry.v1"
        and first["retry_of_job_id"] == failed["job_id"]
    )
    assert entered.wait(10)
    assert service.active_jobs()["jobs"] == []
    try:
        service.cancel_job(job["job_id"])
    finally:
        release.set()
    cancelled = service.job_controller.wait(first["job"]["job_id"], timeout=15)
    assert cancelled["state"] == "cancelled"
    next_attempt = service.retry_job(cancelled["job_id"])["job"]
    done = service.job_controller.wait(next_attempt["job_id"], timeout=15)
    assert done["state"] == "completed", done
    assert done["request"]["stop_generation"] == 1
    assert service.product_store.get_job(job["job_id"])["progress"]["stopped"] is True
    assert (
        len([row for row in service.product_store.list_jobs() if row["kind"] == "scenario.replay"])
        == 1
    )
    retained = service.cancel_job(job["job_id"])
    assert retained["progress"]["comparison"] == done["progress"]["comparison"]
    assert service.retry_job(failed["job_id"])["job"]["job_id"] == cancelled["job_id"]


def test_provider_job_keeps_runs_inventory_usable(setup):
    service, access, source, body, _ = setup
    entered, release = threading.Event(), threading.Event()

    def hold(value):
        entered.set()
        assert release.wait(10)
        return value

    access.transform = hold
    job = service.submit_method_comparison(source, body)["job"]
    assert entered.wait(10)
    try:
        assert service.active_jobs()["jobs"] == []
        service.cancel_job(job["job_id"])
    finally:
        release.set()
    assert service.job_controller.wait(job["job_id"], timeout=15)["state"] == "cancelled"


def test_missing_recorded_collector_authority_does_not_inherit_defaults(setup, tmp_path):
    service, access, _, _, _ = setup
    directory = tmp_path / "legacy-unknown-collectors"
    directory.mkdir()
    run_id = source_run(service, directory, record_collectors=False)
    with pytest.raises(APIError, match="recorded collector binding"):
        service.method_comparison_context(run_id)
    assert not access.calls
