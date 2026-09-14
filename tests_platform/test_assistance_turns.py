"""Connected portable fixtures: real jobs/reviews/evaluations, no network or native effects."""

import copy
import json
import threading
import uuid
from pathlib import Path

import pytest

from bluefire.ai_assistance import COMPARE, PURPOSE, REVISE
from bluefire.ai_provider_access import ProviderReadiness
from bluefire.ai_wire import AIProviderCancelled
from bluefire.application_errors import APIError
from bluefire.config import AIConfig, AIProviderConfig, AutonomyLevel
from bluefire.service import BlueFireService
from tests_platform.ai_live_authorization_support import authorize_service
from tests_platform.test_detection_ai_jobs import decision_body
from tests_platform.test_detection_evaluations import query_candidate
from tests_platform.test_method_comparison_jobs import source_run

ROOT = Path(__file__).resolve().parents[1]


class Access:
    def __init__(self):
        self.calls = []
        self.entered = threading.Event()
        self.release = None
        self.transform = lambda value: value

    def readiness(self, config):
        return ProviderReadiness(True, "not_required", "ready", "Pure assistance fixture")

    def post(self, config, *, body, timeout_seconds, cancel_event=None):
        payload = json.loads(body)
        purpose = (
            payload.get("text", {}).get("format") or payload["response_format"]["json_schema"]
        )["name"]
        context = json.loads(payload.get("input") or payload["messages"][1]["content"])
        self.calls.append(purpose)
        if purpose == PURPOSE:
            self.entered.set()
            if self.release is not None:
                assert self.release.wait(10)
            if cancel_event is not None and cancel_event.is_set():
                raise AIProviderCancelled()
            output = self.transform(
                {
                    "message": "Review a rule revision, then compare that saved rule on the alternative method.",
                    "steps": [
                        {
                            "capability_id": REVISE,
                            "detector_ref": "selected",
                            "reason": "Use the selected source observations.",
                        },
                        {
                            "capability_id": COMPARE,
                            "detector_ref": "revised",
                            "reason": "Compare the accepted rule without changing its definition.",
                        },
                    ],
                }
            )
        elif purpose == "bluefire_detection_source_revision":
            output = {
                "source": "SELECT fixture_id FROM logs WHERE artifact_type = 'collector_observation'",
                "reason": "Use supplied observed metadata.",
                "evidence_refs": [context["observations"][0]["evidence_id"]],
                "limitations": ["Portable fixture; no independent defense validation."],
            }
        elif purpose == "bluefire_method_comparison":
            output = {
                "option_id": context["options"][0]["option_id"],
                "reason": "Use the supplied compatible method.",
                "evidence_refs": [context["observations"][0]["evidence_id"]],
                "limitations": ["Portable fixture; no native result claim."],
            }
        else:
            raise AssertionError(purpose)
        if config.kind.value == "chat_completions":
            return json.dumps(
                {
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"role": "assistant", "content": json.dumps(output)},
                        }
                    ],
                    "usage": {"prompt_tokens": 20, "completion_tokens": 40},
                }
            ).encode()
        return json.dumps(
            {
                "status": "completed",
                "output_text": json.dumps(output),
                "usage": {"input_tokens": 20, "output_tokens": 40},
            }
        ).encode()

    def close(self):
        pass


@pytest.fixture(params=["openai_responses", "chat_completions"])
def setup(tmp_path, request):
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
            "kind": request.param,
            "model": "unit-model",
            "endpoint": (
                "http://127.0.0.1:8765/v1/responses"
                if request.param == "openai_responses"
                else "http://127.0.0.1:8765/v1/chat/completions"
            ),
        }
    )
    service._runtime_ai_config = AIConfig(
        AutonomyLevel.OFF,
        provider.id,
        service.config.ai.fallback_provider,
        (provider, *service.config.ai.providers),
    )
    authorize_service(service, service._runtime_ai_config.provider())
    candidate_id = query_candidate(service, "size_bytes > 0")
    run_id = source_run(service, tmp_path)
    context = service.assistance_context(run_id, candidate_id)
    body = {
        "submission_id": str(uuid.uuid4()),
        "context_digest": context["context_digest"],
        "run_id": run_id,
        "candidate_id": candidate_id,
        "candidate_resource_digest": context["selected"]["candidate_resource_digest"],
        "message": "Improve this rule from the selected run, evaluate it, then try the other method and compare detections.",
        "case_role": "attack",
        "provider_id": provider.id,
        "autonomy": "assist",
    }
    yield service, access, body
    if access.release:
        access.release.set()
    service.close()


def planned(setup):
    service, _, body = setup
    submitted = service.submit_assistance_turn(body)
    job = service.job_controller.wait(submitted["job"]["job_id"], timeout=15)
    assert job["state"] == "completed", job
    child = service.job_controller.wait(job["progress"]["children"]["step-1"]["job_id"], timeout=15)
    assert child["state"] == "completed", child
    return job, child


def apply(service, proposal):
    decision = service.decide_detection_ai_revision(proposal["job_id"], decision_body(proposal))
    application = service.job_controller.wait(decision["application_job"]["job_id"], timeout=15)
    assert application["state"] == "completed", application
    return application


def test_additive_detection_selection_preserves_exact_submission_and_native_children(setup):
    service, access, original = setup
    body = {
        key: value
        for key, value in original.items()
        if key not in {"run_id", "candidate_id", "candidate_resource_digest", "case_role"}
    }
    body["message"] = "Improve the selected rule.\r\n\tEvaluate it, then compare the other method."
    body["selection"] = {
        "kind": "detection",
        **{
            key: original[key]
            for key in ("run_id", "candidate_id", "candidate_resource_digest", "case_role")
        },
    }
    parent, child = planned((service, access, body))
    assert parent["request"]["submitted_request"] == body
    assert child["request"]["submitted_request"]["question"] == " ".join(body["message"].split())
    assert service.submit_assistance_turn(body)["job"]["job_id"] == parent["job_id"]
    assert (
        service.assistance_turn(parent["job_id"])["turn"]["next_action"]["kind"]
        == "review_detection"
    )
    apply(service, child)
    parent = service.product_store.get_job(parent["job_id"])
    method = service.job_controller.wait(
        parent["progress"]["children"]["step-2"]["job_id"], timeout=15
    )
    assert method["state"] == "completed", method
    assert access.calls == [
        PURPOSE,
        "bluefire_detection_source_revision",
        "bluefire_method_comparison",
    ]


def test_connected_turn_uses_native_reviews_and_same_revised_detector(setup):
    service, access, body = setup
    parent, revision = planned(setup)
    view = service.assistance_turn(parent["job_id"])["turn"]
    assert view["status"] == "awaiting_review" and view["next_action"]["kind"] == "review_detection"
    assert view["results"] == [] and access.calls == [
        PURPOSE,
        "bluefire_detection_source_revision",
    ]
    application = apply(service, revision)
    parent = service.product_store.get_job(parent["job_id"])
    method = service.job_controller.wait(
        parent["progress"]["children"]["step-2"]["job_id"], timeout=15
    )
    assert method["state"] == "completed", method
    revised = application["progress"]["application"]["candidate_id"]
    assert method["request"]["submitted_request"]["candidate_id"] == revised != body["candidate_id"]
    assert method["request"]["autonomy"] == "assist"
    assert "decision" not in method["progress"]
    assert (
        service.assistance_turn(parent["job_id"])["turn"]["next_action"]["kind"] == "review_method"
    )
    approved = service.decide_method_comparison(
        method["job_id"],
        {
            "proposal_digest": method["progress"]["proposal"]["proposal_digest"],
            "decision": "accept",
            "reviewed_by": "fixture-operator",
        },
    )
    replay = service.job_controller.wait(approved["replay_job"]["job_id"], timeout=15)
    assert replay["state"] == "completed", replay
    final = service.assistance_turn(parent["job_id"])
    assert final["turn"]["status"] == "completed", final
    assert [row["kind"] for row in final["turn"]["results"]] == [
        "detection_revision",
        "method_comparison",
    ]
    assert all(row["candidate_id"] == revised for row in final["turn"]["results"])
    comparison = final["turn"]["results"][1]
    reports = service.detection_run_evaluations(revised)["evaluations"]
    child_report = next(
        row for row in reports if row["evaluation_id"] == comparison["evaluation_ids"][1]
    )
    assert (
        child_report["result"]["state"] == "insufficient_evidence"
        and child_report["backend"]["executed"] is False
    )
    assert access.calls == [
        PURPOSE,
        "bluefire_detection_source_revision",
        "bluefire_method_comparison",
    ]
    assert service.submit_assistance_turn(body)["job"]["job_id"] == parent["job_id"]
    assert service.assistance_turn(parent["job_id"])["turn"] == final["turn"]
    assert len(access.calls) == 3


@pytest.mark.parametrize("autonomy", ["off", "auto"])
def test_off_and_unsupported_auto_send_no_model_requests(setup, autonomy):
    service, access, body = setup
    body = {**body, "autonomy": autonomy}
    if autonomy == "off":
        body.pop("provider_id")
    parent = service.submit_assistance_turn(body)["job"]
    service.job_controller.wait(parent["job_id"], timeout=15)
    result = service.assistance_turn(parent["job_id"])
    assert result["turn"]["status"] == ("off" if autonomy == "off" else "blocked")
    assert result["turn"]["active_child"] is None and access.calls == []


@pytest.mark.parametrize("change", ["capability", "reference", "duplicate", "extra"])
def test_model_cannot_select_unregistered_authority_or_result_references(setup, change):
    service, access, body = setup

    def invalid(value):
        if change == "capability":
            value["steps"][0]["capability_id"] = "execute.arbitrary"
        elif change == "reference":
            value["steps"][1]["detector_ref"] = "selected"
        elif change == "duplicate":
            value["steps"][1] = copy.deepcopy(value["steps"][0])
        else:
            value["steps"][0]["approval"] = True
        return value

    access.transform = invalid
    job = service.submit_assistance_turn(body)["job"]
    done = service.job_controller.wait(job["job_id"], timeout=15)
    assert done["state"] == "failed" and not done["progress"].get("children")
    assert access.calls == [PURPOSE]
    assert service.assistance_turn(job["job_id"])["turn"]["status"] == "blocked"


def test_submission_and_manual_source_changes_cannot_reinterpret_saved_intent(setup):
    service, access, body = setup
    parent, _ = planned(setup)
    with pytest.raises(APIError):
        service.submit_assistance_turn({**body, "message": "Different intent"})
    service.reject_detection_candidate(
        body["candidate_id"], {"reason": "Operator changed the selected candidate lifecycle."}
    )
    assert service.submit_assistance_turn(body)["job"]["job_id"] == parent["job_id"]
    stale = service.submit_assistance_turn({**body, "submission_id": str(uuid.uuid4())})["job"]
    assert service.job_controller.wait(stale["job_id"], timeout=15)["state"] == "failed"
    assert access.calls == [PURPOSE, "bluefire_detection_source_revision"]


def test_cancel_during_model_call_never_publishes_child(setup):
    service, access, body = setup
    access.release = threading.Event()
    parent = service.submit_assistance_turn(body)["job"]
    assert access.entered.wait(5)
    service.cancel_job(parent["job_id"])
    access.release.set()
    done = service.job_controller.wait(parent["job_id"], timeout=15)
    assert done["state"] == "cancelled" and not done["progress"].get("children")
    assert service.assistance_turn(parent["job_id"])["turn"]["status"] == "cancelled"


def test_cancelled_parent_blocks_native_acceptance(setup):
    service, access, _ = setup
    parent, proposal = planned(setup)
    service.cancel_job(parent["job_id"])
    with pytest.raises(APIError):
        service.decide_detection_ai_revision(proposal["job_id"], decision_body(proposal))
    assert len(access.calls) == 2
    assert service.assistance_turn(parent["job_id"])["turn"]["status"] == "cancelled"


def test_post_commit_handoff_recovers_without_repeating_revision(setup, monkeypatch):
    service, access, body = setup
    parent, proposal = planned(setup)
    original = service.method_comparison.context

    def unavailable(run_id):
        raise APIError(409, "runner_stopped", "Start the native runner before method review.")

    monkeypatch.setattr(service.method_comparison, "context", unavailable)
    application = apply(service, proposal)
    view = service.assistance_turn(parent["job_id"])["turn"]
    assert view["status"] == "ready_to_continue"
    assert view["recovery"]["code"] == "native_review_required"
    assert "Start the native runner" not in view["message"]
    assert len(view["results"]) == 1
    monkeypatch.setattr(service.method_comparison, "context", original)
    retry = {"submission_id": str(uuid.uuid4()), "context_digest": body["context_digest"]}
    service.continue_assistance_turn(parent["job_id"], retry)
    service.job_controller.wait("job-" + retry["submission_id"].replace("-", ""), timeout=15)
    latest = service.product_store.get_job(parent["job_id"])
    method_id = latest["progress"]["children"]["step-2"]["job_id"]
    assert service.job_controller.wait(method_id, timeout=15)["state"] == "completed"
    service.continue_assistance_turn(parent["job_id"], retry)
    assert service.assistance_turn(parent["job_id"])["turn"]["continuation"]["state"] == "completed"
    assert (
        service.product_store.get_job(proposal["job_id"])["progress"]["application"]
        == application["progress"]["application"]
    )
    assert access.calls == [
        PURPOSE,
        "bluefire_detection_source_revision",
        "bluefire_method_comparison",
    ]


@pytest.mark.parametrize("admission", ["context", "resource", "provider", "source"])
def test_failed_admission_is_a_durable_closed_submission(setup, admission):
    service, access, body = setup
    changed = dict(body)
    if admission == "context":
        changed["context_digest"] = "sha256:" + "f" * 64
    elif admission == "resource":
        changed["candidate_resource_digest"] = "sha256:" + "f" * 64
    elif admission == "provider":
        changed["provider_id"] = "provider.not-configured.v1"
    else:
        changed["run_id"] = "run-20260906T120000Z-" + "f" * 16
    parent = service.submit_assistance_turn(changed)["job"]
    terminal = service.job_controller.wait(parent["job_id"], timeout=15)
    assert terminal["state"] == "failed"
    assert terminal["request"]["submitted_request"] == changed
    assert service.assistance_turn(parent["job_id"])["turn"]["next_action"]["kind"] == "new_turn"
    assert service.submit_assistance_turn(changed)["job"]["job_id"] == parent["job_id"]
    assert access.calls == []


def test_stale_continuation_is_closed_without_advancing(setup):
    service, access, body = setup
    parent, _ = planned(setup)
    request = {"submission_id": str(uuid.uuid4()), "context_digest": "sha256:" + "f" * 64}
    service.continue_assistance_turn(parent["job_id"], request)
    identifier = "job-" + request["submission_id"].replace("-", "")
    assert service.job_controller.wait(identifier, timeout=15)["state"] == "failed"
    service.continue_assistance_turn(parent["job_id"], request)
    with pytest.raises(APIError):
        service.continue_assistance_turn(
            parent["job_id"], {**request, "context_digest": body["context_digest"]}
        )
    assert service.assistance_turn(parent["job_id"])["turn"]["continuation"]["job_id"] == identifier
    assert access.calls == [PURPOSE, "bluefire_detection_source_revision"]


def test_cancel_competes_with_post_commit_method_publication(setup, monkeypatch):
    service, access, _ = setup
    parent, proposal = planned(setup)
    original = service.method_comparison.submit
    entered, release = threading.Event(), threading.Event()

    def paused(*args, **kwargs):
        entered.set()
        assert release.wait(10)
        return original(*args, **kwargs)

    monkeypatch.setattr(service.method_comparison, "submit", paused)
    decision = service.decide_detection_ai_revision(proposal["job_id"], decision_body(proposal))
    assert entered.wait(10)
    service.cancel_job(parent["job_id"])
    release.set()
    applied = service.job_controller.wait(decision["application_job"]["job_id"], timeout=15)
    assert applied["state"] == "completed", applied
    final = service.assistance_turn(parent["job_id"])
    assert final["turn"]["status"] == "cancelled"
    assert final["turn"]["results"][0]["kind"] == "detection_revision"
    assert access.calls == [PURPOSE, "bluefire_detection_source_revision"]


def test_explicit_native_detection_retry_keeps_parent_lineage(setup, monkeypatch):
    service, access, body = setup
    original = access.post

    def interrupted(config, *, body, timeout_seconds, cancel_event=None):
        payload = json.loads(body)
        purpose = (
            payload.get("text", {}).get("format") or payload["response_format"]["json_schema"]
        )["name"]
        if purpose == "bluefire_detection_source_revision":
            raise RuntimeError("Unit process loss before the child response")
        return original(
            config, body=body, timeout_seconds=timeout_seconds, cancel_event=cancel_event
        )

    monkeypatch.setattr(access, "post", interrupted)
    parent = service.submit_assistance_turn(body)["job"]
    parent = service.job_controller.wait(parent["job_id"], timeout=15)
    child_id = parent["progress"]["children"]["step-1"]["job_id"]
    assert service.job_controller.wait(child_id, timeout=15)["state"] == "failed"
    # Unit-only restart-state witness; no installed database is imported or changed.
    with service.product_store._connection(write=True) as connection:
        connection.execute("UPDATE jobs SET state='interrupted' WHERE job_id=?", (child_id,))
    monkeypatch.setattr(access, "post", original)
    retry = service.retry_job(child_id)["job"]
    retried = service.job_controller.wait(retry["job_id"], timeout=15)
    assert retried["state"] == "completed", retried
    assert (
        service.assistance_turn(parent["job_id"])["turn"]["active_child"]["job_id"]
        == retried["job_id"]
    )
    apply(service, retried)
    latest = service.product_store.get_job(parent["job_id"])
    method = service.job_controller.wait(
        latest["progress"]["children"]["step-2"]["job_id"], timeout=15
    )
    assert method["state"] == "completed", method
    assert access.calls == [
        PURPOSE,
        "bluefire_detection_source_revision",
        "bluefire_method_comparison",
    ]


def test_get_does_not_recover_missing_handoff_or_make_provider_calls(setup, monkeypatch):
    service, access, _ = setup
    parent, proposal = planned(setup)
    monkeypatch.setattr(service.assistance, "application_committed", lambda child: None)
    # Simulate a process ending after the native application commit, before its hook.
    service.detection_ai.on_application = service.assistance.application_committed
    apply(service, proposal)
    before = list(access.calls)
    for _ in range(3):
        view = service.assistance_turn(parent["job_id"])["turn"]
        assert view["status"] == "ready_to_continue"
    assert access.calls == before
    assert "step-2" not in service.product_store.get_job(parent["job_id"])["progress"]["children"]


def test_committed_revision_survives_unavailable_handoff_diagnostic(setup, monkeypatch):
    import bluefire.assistance_turns as turns
    from bluefire.product_store_errors import ProductStoreError

    service, access, _ = setup
    parent, proposal = planned(setup)

    def unavailable(run_id):
        raise APIError(409, "runner_stopped", "Runner is stopped.")

    def unavailable_diagnostic(*args, **kwargs):
        raise ProductStoreError("Unit diagnostic persistence failure")

    monkeypatch.setattr(service.method_comparison, "context", unavailable)
    monkeypatch.setattr(turns, "update", unavailable_diagnostic)
    application = apply(service, proposal)
    assert application["state"] == "completed"
    view = service.assistance_turn(parent["job_id"])["turn"]
    assert view["status"] == "ready_to_continue"
    assert len(view["results"]) == 1
    assert access.calls == [PURPOSE, "bluefire_detection_source_revision"]


def test_planning_respects_selected_object_redaction_policy(setup, monkeypatch):
    from dataclasses import replace

    from bluefire.ai_assistance import suggest_plan
    from bluefire.config import AIRedactionPolicy

    service, access, body = setup
    context = service.assistance_context(body["run_id"], body["candidate_id"])
    provider = replace(
        service._runtime_ai().provider(body["provider_id"]),
        redaction=AIRedactionPolicy(redact_keys=("title",)),
    )
    captured = []
    original = access.post

    def observe(config, *, body, timeout_seconds, cancel_event=None):
        payload = json.loads(body)
        captured.append(json.loads(payload.get("input") or payload["messages"][1]["content"]))
        return original(
            config, body=body, timeout_seconds=timeout_seconds, cancel_event=cancel_event
        )

    monkeypatch.setattr(access, "post", observe)
    suggest_plan(
        config=provider,
        access=access,
        context=context,
        message=body["message"],
        cancel=threading.Event(),
    )
    assert captured[0]["selected"]["title"] != context["selected"]["title"]
    assert captured[0]["selected"]["candidate_id"] == body["candidate_id"]
    assert "evidence_metadata" not in json.dumps(captured)


def test_integrity_block_keeps_live_child_until_verified_cancellation(setup, monkeypatch):
    service, access, _ = setup
    parent, proposal = planned(setup)
    original = access.post
    entered, release = threading.Event(), threading.Event()

    def held(config, *, body, timeout_seconds, cancel_event=None):
        payload = json.loads(body)
        purpose = (
            payload.get("text", {}).get("format") or payload["response_format"]["json_schema"]
        )["name"]
        if purpose == "bluefire_method_comparison":
            entered.set()
            assert release.wait(10)
            if cancel_event is not None and cancel_event.is_set():
                raise AIProviderCancelled()
        return original(
            config, body=body, timeout_seconds=timeout_seconds, cancel_event=cancel_event
        )

    monkeypatch.setattr(access, "post", held)
    try:
        application = apply(service, proposal)
        assert entered.wait(10)
        candidate_id = application["progress"]["application"]["candidate_id"]
        service.reject_detection_candidate(candidate_id, {"reason": "Unit changed saved candidate"})
        blocked = service.assistance_turn(parent["job_id"])["turn"]
        assert blocked["status"] == "blocked" and not blocked["can_start_new_turn"]
        assert blocked["next_action"] is None and blocked["results"] == []
        service.cancel_job(parent["job_id"])
        waiting = service.assistance_turn(parent["job_id"])["turn"]
        assert waiting["status"] == "cancelling" and not waiting["can_start_new_turn"]
        release.set()
        latest = service.product_store.get_job(parent["job_id"])
        child_id = latest["progress"]["children"]["step-2"]["job_id"]
        assert service.job_controller.wait(child_id, timeout=15)["state"] == "cancelled"
        settled = service.assistance_turn(parent["job_id"])["turn"]
        assert settled["status"] == "cancelled" and settled["can_start_new_turn"]
        assert settled["results"] == []
    finally:
        release.set()


def test_comparison_only_recovery_remains_active_until_cancel_settles(setup, monkeypatch):
    import bluefire.method_comparison_jobs as jobs

    service, access, _ = setup
    parent, proposal = planned(setup)
    apply(service, proposal)
    latest = service.product_store.get_job(parent["job_id"])
    method = service.job_controller.wait(
        latest["progress"]["children"]["step-2"]["job_id"], timeout=15
    )
    original_build = jobs.build_run_evaluation

    def failed_build(*args, **kwargs):
        raise APIError(
            409, "unit_analysis_unavailable", "Unit analysis failure after Simulate replay"
        )

    monkeypatch.setattr(jobs, "build_run_evaluation", failed_build)
    approved = service.decide_method_comparison(
        method["job_id"],
        {
            "proposal_digest": method["progress"]["proposal"]["proposal_digest"],
            "decision": "accept",
            "reviewed_by": "fixture-operator",
        },
    )
    failed = service.job_controller.wait(approved["replay_job"]["job_id"], timeout=15)
    assert failed["state"] == "failed"
    monkeypatch.setattr(jobs, "build_run_evaluation", original_build)
    entered, release = threading.Event(), threading.Event()
    original_recover = service.method_comparison._recover

    def held(context, request):
        entered.set()
        assert release.wait(10)
        return original_recover(context, request)

    monkeypatch.setattr(service.method_comparison, "_recover", held)
    try:
        recovery = service.retry_job(failed["job_id"])["job"]
        assert entered.wait(10)
        view = service.assistance_turn(parent["job_id"])["turn"]
        assert view["status"] == "working" and not view["can_start_new_turn"]
        assert view["active_child"]["job_id"] == recovery["job_id"]
        service.cancel_job(parent["job_id"])
        assert service.assistance_turn(parent["job_id"])["turn"]["status"] == "cancelling"
        release.set()
        assert service.job_controller.wait(recovery["job_id"], timeout=15)["state"] == "cancelled"
        settled = service.assistance_turn(parent["job_id"])["turn"]
        assert settled["status"] == "cancelled" and settled["can_start_new_turn"]
        assert len(service.store.list_runs()) == 2
        assert len(access.calls) == 3
    finally:
        release.set()


@pytest.mark.parametrize("cancel_target", ["parent", "older_continuation"])
def test_cancel_held_continuation_stops_parent_and_all_recovery_publication(
    setup, monkeypatch, cancel_target
):
    service, access, body = setup
    parent, proposal = planned(setup)
    original = service.method_comparison.context

    def unavailable(run_id):
        raise APIError(409, "runner_stopped", "Unit readiness unavailable")

    monkeypatch.setattr(service.method_comparison, "context", unavailable)
    apply(service, proposal)
    entered, release = threading.Event(), threading.Event()
    entered_lock = threading.Lock()
    count = 0

    def held(run_id):
        nonlocal count
        with entered_lock:
            count += 1
            if count == 2:
                entered.set()
        assert release.wait(10)
        return original(run_id)

    monkeypatch.setattr(service.method_comparison, "context", held)
    requests = [
        {"submission_id": str(uuid.uuid4()), "context_digest": body["context_digest"]}
        for _ in range(2)
    ]
    identifiers = ["job-" + request["submission_id"].replace("-", "") for request in requests]
    try:
        for request in requests:
            service.continue_assistance_turn(parent["job_id"], request)
        assert entered.wait(10)
        target = parent["job_id"] if cancel_target == "parent" else identifiers[0]
        cancelled = service.cancel_job(target)
        assert cancelled["job_id"] == target
        waiting = service.assistance_turn(parent["job_id"])
        assert waiting["job"]["progress"]["stopped"] is True
        assert waiting["turn"]["status"] == "cancelling"
        assert not waiting["turn"]["can_start_new_turn"]
        assert all(
            service.product_store.get_job(identifier)["state"] == "cancelling"
            for identifier in identifiers
        )
        release.set()
        for identifier in identifiers:
            assert service.job_controller.wait(identifier, timeout=15)["state"] == "cancelled"
        final = service.assistance_turn(parent["job_id"])
        assert final["turn"]["status"] == "cancelled" and final["turn"]["can_start_new_turn"]
        assert set(final["job"]["progress"]["children"]) == {"step-1"}
        assert access.calls == [PURPOSE, "bluefire_detection_source_revision"]
    finally:
        release.set()


def test_validated_empty_plan_retains_explanation_without_claiming_work_completed(setup):
    service, access, body = setup
    access.transform = lambda value: {
        "message": "This request is outside the selected capabilities.",
        "steps": [],
    }
    submitted = service.submit_assistance_turn(body)
    service.job_controller.wait(submitted["job"]["job_id"], timeout=15)
    view = service.assistance_turn(submitted["job"]["job_id"])["turn"]
    assert view["status"] == "blocked" and view["can_start_new_turn"]
    assert view["next_action"]["kind"] == "new_turn"
    assert view["message"] == "This request is outside the selected capabilities."
    assert view["plan"] == [] and view["results"] == [] and view["active_child"] is None
    assert access.calls == [PURPOSE]


def test_runner_guidance_uses_safe_typed_refusal_and_keeps_context_immutable(
    setup, tmp_path, monkeypatch
):
    service, access, body = setup
    execution_fixture = tmp_path / "execution-fixture"
    execution_fixture.mkdir()
    # Portable observed fixture only; no Execute job or target process is started.
    source_id = source_run(service, execution_fixture, execute=True)
    context = service.assistance_context(source_id, body["candidate_id"])
    request = {**body, "run_id": source_id, "context_digest": context["context_digest"]}
    parent, proposal = planned((service, access, request))
    calls = []

    def unavailable(profile):
        calls.append(profile.id)
        raise OSError("private-path-must-not-be-retained")

    monkeypatch.setattr(service, "runner_factory", unavailable)
    application = apply(service, proposal)
    view = service.assistance_turn(parent["job_id"])["turn"]
    assert application["state"] == "completed"
    assert view["status"] == "ready_to_continue"
    assert view["recovery"]["code"] == "runner_readiness_required"
    assert view["recovery"]["profile_id"] == "sandbox-execute.v1"
    assert view["recovery"]["action"]["native_path"] == "/runs?setup=execute"
    assert len(view["results"]) == 1
    assert "private-path-must-not-be-retained" not in json.dumps(
        service.product_store.get_job(parent["job_id"])
    )
    assert service.assistance_context(source_id, body["candidate_id"]) == context
    count = len(calls)
    assert count > 0
    for _ in range(3):
        assert service.assistance_turn(parent["job_id"])["turn"]["recovery"] == view["recovery"]
    assert len(calls) == count
    assert access.calls == [PURPOSE, "bluefire_detection_source_revision"]


def test_arbitrary_error_details_cannot_create_runner_setup_guidance(setup):
    service, _, _ = setup
    parent, _ = planned(setup)
    problem = service.assistance._handoff_problem(
        parent["job_id"],
        APIError(
            409,
            "replay_preparation_refused",
            "private-message",
            ["runner stopped", "private-path"],
        ),
    )
    assert problem["code"] == "detection_review_required"
    assert problem["action"]["native_path"].startswith("/detection-lab?")
    assert "private" not in json.dumps(problem)


def test_detector_only_plan_stale_during_planning_links_its_native_review(setup):
    service, access, body = setup
    access.release = threading.Event()
    access.transform = lambda value: {**value, "steps": value["steps"][:1]}
    parent = service.submit_assistance_turn(body)["job"]
    assert access.entered.wait(10)
    service.reject_detection_candidate(
        body["candidate_id"], {"reason": "Unit saved rule changed during planning"}
    )
    access.release.set()
    service.job_controller.wait(parent["job_id"], timeout=15)
    view = service.assistance_turn(parent["job_id"])["turn"]
    assert view["status"] == "ready_to_continue"
    assert view["recovery"]["code"] == "detection_review_required"
    assert view["recovery"]["action"]["native_path"].startswith("/detection-lab?")
    assert "compare" not in view["recovery"]["action"]["native_path"]
    assert access.calls == [PURPOSE]
