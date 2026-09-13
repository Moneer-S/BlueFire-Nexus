"""Saved manual experiments use the same reviewed preparation and approval services."""

import copy

import pytest

from bluefire.application_errors import APIError
from bluefire.product_store_errors import ProductStoreError
from tests_platform.test_assistance_saved_runs import prepared, run_context
from tests_platform.test_graph_ai_jobs import setup as setup


def manual_request(service, access, body):
    # This existing fixture installs a scripted protocol provider. The source below
    # is saved independently and must never resolve the unrelated graph receipt.
    request = run_context(service, access, body)
    document = service._scenario({"scenario_id": "scenario.sandbox.research.chain.v1"}).to_dict()
    document["id"] = "scenario.manual.assistant.v1"
    saved = service.save_scenario_version({"scenario": document})["scenario"]
    request["selection"] = {
        "kind": "saved_scenario",
        "scenario": {key: saved[key] for key in ("scenario_id", "version", "digest")},
        "run_intent": request["selection"]["run_intent"],
    }
    request["context_digest"] = service.assistance_run_context({"selection": request["selection"]})[
        "context_digest"
    ]
    return request, document


def test_manual_saved_version_runs_and_inspects_without_graph_receipt(setup, monkeypatch):
    service, access, body = setup
    request, document = manual_request(service, access, body)
    monkeypatch.setattr(
        service,
        "graph_ai_job",
        lambda *_: pytest.fail("Manual source cannot require an AI graph receipt"),
    )
    # A newer edit must not silently replace the exact version selected earlier.
    newer = {**document, "title": "Newer independent manual edit"}
    service.save_scenario_version({"scenario": newer})
    parent, child, envelope = prepared(service, request)
    assert envelope["preparation"]["scenario"] == document
    assert envelope["review_ready"] and not service.store.list_runs()
    decision = {
        "decision": "accept",
        "preparation_digest": envelope["preparation"]["preparation_digest"],
    }
    envelope = service.review_assistance_run(child["job_id"], decision)
    run = service.job_controller.wait(envelope["job"]["progress"]["run_job_id"], timeout=20)
    assert run["state"] == "completed", run
    envelope = service.assistance_run_job(child["job_id"])
    service.job_controller.wait(envelope["inspection_job"]["job_id"], timeout=20)
    result = service.assistance_turn(parent["job_id"])["turn"]["results"][0]
    assert result["version"] == 1 and result["digest"] == request["selection"]["scenario"]["digest"]
    assert result["observed_records"] == 0 and result["cleanup_state"] == "simulated"
    service.review_assistance_run(child["job_id"], decision)
    assert len(service.store.list_runs()) == 1


@pytest.mark.parametrize("change", ["digest", "version", "settings", "extra_authority"])
def test_manual_saved_selection_refuses_stale_or_extra_authority(setup, change):
    service, access, body = setup
    request, _ = manual_request(service, access, body)
    bad = copy.deepcopy(request)
    if change == "digest":
        bad["selection"]["scenario"]["digest"] = "sha256:" + "0" * 64
    elif change == "version":
        bad["selection"]["scenario"]["version"] += 1
    elif change == "settings":
        bad["selection"]["run_intent"]["target_scope"]["scope_refs"] = ["different-scope"]
    else:
        bad["selection"]["approved"] = True
    before = len(access.calls)
    if change == "extra_authority":
        with pytest.raises((APIError, ProductStoreError)):
            service.submit_assistance_turn(bad)
    else:
        job = service.submit_assistance_turn(bad)["job"]
        settled = service.job_controller.wait(job["job_id"], timeout=20)
        assert settled["state"] == "failed", settled
        assert not settled["progress"].get("children")
    assert len(access.calls) == before and not service.store.list_runs()


@pytest.mark.parametrize("autonomy", ["assist", "auto"])
def test_manual_execute_waits_for_its_own_approval_without_effects(setup, tmp_path, autonomy):
    from bluefire.contracts import ExecutionMode
    from bluefire.job_runtime import JobState
    from tests_platform.test_service import ReadyInventoryRunner

    service, access, body = setup
    request, _ = manual_request(service, access, body)
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    service.runner_factory = lambda profile: (ReadyInventoryRunner(), sandbox)
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
    _, child, envelope = prepared(service, request)
    if autonomy == "assist":
        with pytest.raises((APIError, ProductStoreError)):
            service.review_assistance_run(
                child["job_id"], {"decision": "accept", "preparation_digest": "sha256:" + "0" * 64}
            )
        assert not service.store.list_runs()
        envelope = service.review_assistance_run(
            child["job_id"],
            {
                "decision": "accept",
                "preparation_digest": envelope["preparation"]["preparation_digest"],
            },
        )
    run = service.job_controller.wait_for_state(
        envelope["job"]["progress"]["run_job_id"], {JobState.AWAITING_APPROVAL}, timeout=10
    )
    with service.product_store._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0] == 1
    assert not service.store.list_runs() and not list(sandbox.iterdir())
    service.cancel_job(run["job_id"])
    service.job_controller.wait(run["job_id"], timeout=10)
    assert not service.store.list_runs() and not list(sandbox.iterdir())


@pytest.mark.parametrize("kind", [[], {}])
@pytest.mark.parametrize("endpoint", ["context", "turn"])
def test_malformed_saved_kind_has_a_structured_refusal(setup, kind, endpoint):
    service, access, body = setup
    before = list(access.calls)
    with pytest.raises(APIError) as caught:
        if endpoint == "context":
            service.assistance_run_context({"selection": {"kind": kind}})
        else:
            service.submit_assistance_turn({**body, "selection": {"kind": kind}})
    assert caught.value.code == (
        "assistance_run_context_invalid" if endpoint == "context" else "assistance_turn_refused"
    )
    assert access.calls == before and not service.store.list_runs()
