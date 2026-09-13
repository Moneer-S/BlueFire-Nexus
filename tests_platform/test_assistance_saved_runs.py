"""Connected saved graph through ordinary native run and immutable inspection."""

import json
import uuid

import pytest

from bluefire.ai_assistance import PURPOSE
from bluefire.assistance_run_context import CAPABILITY
from tests_platform.test_graph_ai_jobs import acceptance, proposed
from tests_platform.test_graph_ai_jobs import setup as setup


def run_context(service, access, body, *, executable=False):
    _, child, proposal = proposed(service, body)
    scenario = None
    if executable:
        scenario = service._scenario(
            {"scenario_id": "scenario.sandbox.research.chain.v1"}
        ).to_dict()
        scenario["id"] = proposal["scenario"]["id"]
    app = service.review_graph_ai(child["job_id"], acceptance(proposal, scenario))["application"]
    selected = {
        "kind": "saved_graph",
        "proposal_job_id": child["job_id"],
        "application": app,
        "run_intent": {
            "mode": "simulate",
            "autonomy": "off",
            "ai_provider_id": None,
            "runner_profile_id": None,
            "target_scope": {"scope_refs": ["workspace"]},
        },
    }
    context = service.assistance_run_context({"selection": selected})
    original = access.post

    def planned(config, **kwargs):
        wire = json.loads(kwargs["body"])
        purpose = (wire.get("text", {}).get("format") or wire["response_format"]["json_schema"])[
            "name"
        ]
        if purpose != PURPOSE:
            return original(config, **kwargs)
        access.calls.append(purpose)
        output = {
            "message": "Run the exact reviewed graph then inspect its retained evidence.",
            "steps": [
                {
                    "capability_id": CAPABILITY,
                    "detector_ref": "none",
                    "reason": "Use explicit native settings.",
                }
            ],
        }
        response = {"model": config.model}
        if config.kind.value == "chat_completions":
            response.update(
                choices=[
                    {
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": json.dumps(output)},
                    }
                ],
                usage={"prompt_tokens": 20, "completion_tokens": 40},
            )
        else:
            response.update(
                status="completed",
                output_text=json.dumps(output),
                usage={"input_tokens": 20, "output_tokens": 40},
            )
        return json.dumps(response).encode()

    access.post = planned
    request = {
        **body,
        "submission_id": str(uuid.uuid4()),
        "selection": selected,
        "context_digest": context["context_digest"],
        "message": "Run the saved experiment and inspect its actual evidence.",
    }
    return request


@pytest.mark.parametrize("autonomy", ["assist", "auto"])
def test_saved_graph_simulation_retains_truthful_result_and_exact_native_retry(setup, autonomy):
    service, access, body = setup
    request = run_context(service, access, body)
    request["autonomy"] = autonomy
    parent = service.submit_assistance_turn(request)["job"]
    parent = service.job_controller.wait(parent["job_id"], timeout=20)
    assert parent["state"] == "completed", parent
    child = service.job_controller.wait(
        parent["progress"]["children"]["step-1"]["job_id"], timeout=20
    )
    assert child["state"] == "completed", (
        child,
        service.preflight(
            {
                "scenario": service.scenario_version(
                    request["selection"]["application"]["scenario_id"], version=1
                )["scenario"]["document"],
                **request["selection"]["run_intent"],
            }
        )["problems"],
    )
    envelope = service.assistance_run_job(child["job_id"])
    if autonomy == "assist":
        assert envelope["review_ready"] and not service.store.list_runs()
        decision = {
            "decision": "accept",
            "preparation_digest": envelope["preparation"]["preparation_digest"],
        }
        envelope = service.review_assistance_run(child["job_id"], decision)
    else:
        assert envelope["decision"]["decision"] == "policy"
    run = service.job_controller.wait(envelope["job"]["progress"]["run_job_id"], timeout=20)
    assert run["state"] == "completed", run
    envelope = service.assistance_run_job(child["job_id"])
    assert envelope["inspection_job"], envelope
    inspection = service.job_controller.wait(envelope["inspection_job"]["job_id"], timeout=20)
    assert inspection["state"] == "completed", inspection
    view = service.assistance_turn(parent["job_id"])["turn"]
    assert view["status"] == "completed", view
    assert view["results"][0]["inspection_status"] == "insufficient"
    assert view["results"][0]["cleanup_state"] == "simulated"
    assert view["results"][0]["observed_records"] == 0
    assert len(service.store.list_runs()) == 1
    assert access.calls == [PURPOSE, "bluefire_ai_graph_draft", PURPOSE]
    if autonomy == "assist":
        assert (
            service.review_assistance_run(child["job_id"], decision)["result"]
            == service.assistance_run_job(child["job_id"])["result"]
        )
    assert len(service.store.list_runs()) == 1
    assert run["request"]["_run_submission_request"] == envelope["preparation"]["run_request"]
    assert run["request"]["assistance_run"]["operation_job_id"] == child["job_id"]


def test_saved_graph_off_never_plans_prepares_or_runs(setup):
    service, access, body = setup
    request = run_context(service, access, body)
    request["autonomy"] = "off"
    before = list(access.calls)
    parent = service.submit_assistance_turn(request)["job"]
    service.job_controller.wait(parent["job_id"], timeout=20)
    assert service.assistance_turn(parent["job_id"])["turn"]["status"] == "off"
    assert access.calls == before and service.store.list_runs() == []


def prepared(service, request):
    parent = service.submit_assistance_turn(request)["job"]
    parent = service.job_controller.wait(parent["job_id"], timeout=20)
    assert parent["state"] == "completed", parent
    child = service.job_controller.wait(
        parent["progress"]["children"]["step-1"]["job_id"], timeout=20
    )
    assert child["state"] == "completed", child
    return parent, child, service.assistance_run_job(child["job_id"])


@pytest.mark.parametrize("autonomy", ["assist", "auto"])
def test_execute_has_one_fresh_pending_approval_and_stop_cancels_without_effects(
    setup, tmp_path, autonomy
):
    from bluefire.contracts import ExecutionMode
    from bluefire.job_runtime import JobState
    from tests_platform.test_service import ReadyInventoryRunner

    service, access, body = setup
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    service.runner_factory = lambda profile: (ReadyInventoryRunner(), sandbox)
    request = run_context(service, access, body, executable=True)
    profile = next(
        row for row in service.config.runner_profiles if row.mode is ExecutionMode.EXECUTE
    )
    request["selection"]["run_intent"].update(
        mode="execute",
        runner_profile_id=profile.id,
        target_scope={"scope_refs": list(profile.scope)},
    )
    request["context_digest"] = service.assistance_run_context({"selection": request["selection"]})[
        "context_digest"
    ]
    request["autonomy"] = autonomy
    parent, child, envelope = prepared(service, request)
    if autonomy == "assist":
        decision = {
            "decision": "accept",
            "preparation_digest": envelope["preparation"]["preparation_digest"],
        }
        envelope = service.review_assistance_run(child["job_id"], decision)
        assert (
            service.review_assistance_run(child["job_id"], decision)["run_job"]["job_id"]
            == envelope["run_job"]["job_id"]
        )
    job = service.job_controller.wait_for_state(
        envelope["job"]["progress"]["run_job_id"], {JobState.AWAITING_APPROVAL}, timeout=10
    )
    assert (
        service.assistance_turn(parent["job_id"])["turn"]["status"] == "awaiting_execute_approval"
    )
    with service.product_store._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0] == 1
    assert service.store.list_runs() == [] and list(sandbox.iterdir()) == []
    service.cancel_job(job["job_id"])
    service.job_controller.wait(job["job_id"], timeout=10)
    assert service.assistance_turn(parent["job_id"])["turn"]["status"] == "cancelled"
    assert service.store.list_runs() == [] and len(access.calls) == 3


def test_stop_while_native_publication_prepares_cannot_release_run(setup, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    service, access, body = setup
    request = run_context(service, access, body)
    parent, child, envelope = prepared(service, request)
    decision = {
        "decision": "accept",
        "preparation_digest": envelope["preparation"]["preparation_digest"],
    }
    entered, release = threading.Event(), threading.Event()
    original = service.preflight

    def hold(request):
        entered.set()
        assert release.wait(10)
        return original(request)

    monkeypatch.setattr(service, "preflight", hold)
    with ThreadPoolExecutor(max_workers=1) as workers:
        pending = workers.submit(service.review_assistance_run, child["job_id"], decision)
        assert entered.wait(10)
        service.cancel_job(parent["job_id"])
        release.set()
        receipt = pending.result(10)
    assert receipt["decision"] == decision
    assert receipt["run_job"]["state"] == "failed"
    assert receipt["run_job"]["progress"]["effects_started"] is False
    assert service.store.list_runs() == [] and len(access.calls) == 3
    assert service.review_assistance_run(child["job_id"], decision)["run_job"] == receipt["run_job"]


def test_lost_inspection_handoff_recovers_same_run_without_dispatching_another(setup, monkeypatch):
    from bluefire.application_errors import APIError

    service, access, body = setup
    request = run_context(service, access, body)
    parent, child, envelope = prepared(service, request)
    original = service.assistance_runs._start_inspection
    monkeypatch.setattr(
        service.assistance_runs,
        "_start_inspection",
        lambda *_a, **_k: (_ for _ in ()).throw(APIError(409, "held", "held handoff")),
    )
    accepted = service.review_assistance_run(
        child["job_id"],
        {"decision": "accept", "preparation_digest": envelope["preparation"]["preparation_digest"]},
    )
    run = service.job_controller.wait(accepted["job"]["progress"]["run_job_id"], timeout=15)
    assert run["state"] == "completed"
    assert service.assistance_turn(parent["job_id"])["turn"]["status"] == "ready_to_continue"
    monkeypatch.setattr(service.assistance_runs, "_start_inspection", original)
    monkeypatch.setattr(
        service, "submit_run", lambda *_a, **_k: pytest.fail("Recovery cannot resubmit the run")
    )
    recovery = service.continue_assistance_turn(
        parent["job_id"],
        {"submission_id": str(uuid.uuid4()), "context_digest": request["context_digest"]},
    )
    continuation = recovery["turn"]["continuation"]
    service.job_controller.wait(continuation["job_id"], timeout=15)
    envelope = service.assistance_run_job(child["job_id"])
    service.job_controller.wait(envelope["inspection_job"]["job_id"], timeout=15)
    assert service.assistance_turn(parent["job_id"])["turn"]["status"] == "completed"
    assert len(service.store.list_runs()) == 1 and envelope["run_job"]["job_id"] == run["job_id"]


def test_changed_native_intent_cannot_accept_existing_preparation(setup):
    from bluefire.application_errors import APIError

    service, access, body = setup
    request = run_context(service, access, body)
    parent, child, envelope = prepared(service, request)
    with pytest.raises(APIError):
        service.review_assistance_run(
            child["job_id"], {"decision": "accept", "preparation_digest": "sha256:" + "0" * 64}
        )
    assert service.store.list_runs() == []
    assert service.active_jobs()["jobs"] == []


def test_native_decline_is_settled_and_never_reports_a_failed_run(setup):
    service, access, body = setup
    request = run_context(service, access, body)
    parent, child, envelope = prepared(service, request)
    decision = {
        "decision": "reject",
        "preparation_digest": envelope["preparation"]["preparation_digest"],
    }
    response = service.review_assistance_run(child["job_id"], decision)
    assert response["run_job"] is None and response["inspection_job"] is None
    view = service.assistance_turn(parent["job_id"])["turn"]
    assert (
        view["can_start_new_turn"] and "declined" in view["message"] and "No run" in view["message"]
    )


def test_actual_runtime_assist_review_binds_changed_final_scenario_and_inspects(setup, monkeypatch):
    from bluefire.job_runtime import JobState
    from tests_platform.test_ai_integration import AlternateProposalProvider

    service, access, body = setup
    request = run_context(service, access, body, executable=True)

    def runtime_provider(config, identifier):
        from bluefire.config import AIProviderConfig

        provider = AlternateProposalProvider(
            AIProviderConfig.from_mapping(
                {"id": identifier, "kind": "deterministic", "model": "unit-model"}
            )
        )
        provider.config = config.provider(identifier)
        return provider

    service.ai_provider_factory = runtime_provider
    request["selection"]["run_intent"].update(autonomy="assist", ai_provider_id=body["provider_id"])
    request["context_digest"] = service.assistance_run_context({"selection": request["selection"]})[
        "context_digest"
    ]
    parent, child, envelope = prepared(service, request)
    accepted = service.review_assistance_run(
        child["job_id"],
        {"decision": "accept", "preparation_digest": envelope["preparation"]["preparation_digest"]},
    )
    run_id = accepted["job"]["progress"]["run_job_id"]
    awaiting = service.job_controller.wait_for_state(
        run_id, {JobState.AWAITING_APPROVAL}, timeout=15
    )
    record_id = awaiting["progress"]["proposal_record_id"]
    view = service.assistance_turn(parent["job_id"])["turn"]
    assert (
        view["status"] == "awaiting_review"
        and view["next_action"]["label"] == "Review runtime proposal"
    )
    review = service.proposal_review(run_id, record_id)
    decision = {
        "decided_by": "unit-native-review",
        **{key: review[key] for key in ("state_digest", "plan_digest", "proposal_digest")},
    }
    service.accept_proposal_review(run_id, record_id, decision)
    run = service.job_controller.wait(run_id, timeout=15)
    assert run["state"] == "completed", run
    envelope = service.assistance_run_job(child["job_id"])
    assert envelope["inspection_job"], envelope
    service.job_controller.wait(envelope["inspection_job"]["job_id"], timeout=15)
    envelope = service.assistance_run_job(child["job_id"])
    result = envelope["result"]
    assert result and result["runtime_modified"] is True
    assert result["runtime_proposal_record_ids"] == [record_id]
    actual = service.store.get_run(result["run_id"])
    assert actual["scenario"] != envelope["preparation"]["scenario"]
    assert service.assistance_turn(parent["job_id"])["turn"]["status"] == "completed"
    from bluefire.application_errors import APIError

    with pytest.raises(APIError, match="retained Assistant"):
        service.retry_job(run_id)
    original = service.product_store.get_ai_proposal_review
    monkeypatch.setattr(
        service.product_store,
        "get_ai_proposal_review",
        lambda identifier: {**original(identifier), "proposal_digest": "sha256:" + "0" * 64},
    )
    with pytest.raises(APIError):
        service.assistance_run_job(child["job_id"])
    assert service.assistance_turn(parent["job_id"])["turn"]["can_start_new_turn"] is False


def test_durable_parent_stop_wins_concurrent_native_execute_approval(setup, tmp_path, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from bluefire.application_errors import APIError
    from bluefire.contracts import ExecutionMode
    from bluefire.job_runtime import JobState
    from tests_platform.test_service import ReadyInventoryRunner

    service, access, body = setup
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    runner = ReadyInventoryRunner()
    service.runner_factory = lambda profile: (runner, sandbox)
    request = run_context(service, access, body, executable=True)
    profile = next(
        row for row in service.config.runner_profiles if row.mode is ExecutionMode.EXECUTE
    )
    request["selection"]["run_intent"].update(
        mode="execute",
        runner_profile_id=profile.id,
        target_scope={"scope_refs": list(profile.scope)},
    )
    request["context_digest"] = service.assistance_run_context({"selection": request["selection"]})[
        "context_digest"
    ]
    parent, child, envelope = prepared(service, request)
    envelope = service.review_assistance_run(
        child["job_id"],
        {"decision": "accept", "preparation_digest": envelope["preparation"]["preparation_digest"]},
    )
    run_id = envelope["job"]["progress"]["run_job_id"]
    service.job_controller.wait_for_state(run_id, {JobState.AWAITING_APPROVAL}, timeout=10)
    entered, release = threading.Event(), threading.Event()
    original = service.assistance_runs.cancel

    def held_cancel(identifier):
        entered.set()
        assert release.wait(10)
        return original(identifier)

    monkeypatch.setattr(service.assistance_runs, "cancel", held_cancel)
    with ThreadPoolExecutor(max_workers=1) as workers:
        stopped = workers.submit(service.cancel_job, parent["job_id"])
        assert entered.wait(10)
        try:
            with pytest.raises(APIError) as error:
                service.approve_job(run_id, {"approved_by": "unit-native-review"})
            assert error.value.code == "approval_refused"
            assert service.job(run_id)["state"] == "awaiting_approval"
        finally:
            release.set()
        stopped.result(10)
    service.job_controller.wait(run_id, timeout=10)
    assert service.store.list_runs() == [] and runner.execute_calls == 0
