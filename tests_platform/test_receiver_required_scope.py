"""Receiver admission scope checks with the existing portable, non-native fixture."""

import copy
import uuid

import pytest

from bluefire import receiver_defense_jobs
from bluefire.application_errors import APIError
from bluefire.util import content_hash
from tests_platform.test_receiver_defense_jobs import setup as setup


@pytest.mark.parametrize(
    ("references", "missing"),
    [
        (["sandbox.workspace"], ["network.loopback"]),
        (["network.loopback"], ["sandbox.workspace"]),
        (["export.local"], ["sandbox.workspace", "network.loopback"]),
    ],
)
def test_missing_receiver_scope_refuses_admission_and_prepare_until_explicitly_corrected(
    setup, references, missing
):
    service, access, runner, sessions, request = setup
    request["run_intent"]["target_scope"] = {"scope_refs": references}
    original = copy.deepcopy(request)
    current = service.receiver_defense_context(request)
    assert not current["eligible"]
    reason = next(item for item in current["reasons"] if item["code"] == "receiver_scope_required")
    assert "Environment and run settings" in reason["message"]
    assert "Target scope" in reason["message"]
    assert "include: " + ", ".join(missing) + "." in reason["message"]
    assert current["run_intent"] == request["run_intent"] and request == original
    assert not service.product_store.list_jobs()
    submitted = {
        **copy.deepcopy(request),
        "submission_id": str(uuid.uuid4()),
        "context_digest": current["context_digest"],
    }
    refused = service.submit_receiver_defense(submitted)
    assert refused["job"]["state"] == "failed"
    assert not refused["admission"]["accepted"]
    assert refused["job"]["request"]["submitted_request"] == submitted
    assert all(
        not phase["prepare_allowed"] and phase["receiver_job"] is None
        for phase in refused["phases"]
    )
    assert service.submit_receiver_defense(submitted) == refused
    with pytest.raises(APIError):
        service.prepare_receiver_defense(
            refused["job"]["job_id"],
            {"submission_id": str(uuid.uuid4()), "phase": "baseline", "reviewed_by": "Reviewer"},
        )
    assert len(service.product_store.list_jobs()) == 1
    assert not sessions and not access.calls and runner.execute_calls == 0

    corrected = copy.deepcopy(request)
    corrected["run_intent"]["target_scope"] = {
        "scope_refs": ["network.loopback", "sandbox.workspace"]
    }
    ready = service.receiver_defense_context(corrected)
    assert ready["eligible"]
    assert ready["run_intent"]["target_scope"] == corrected["run_intent"]["target_scope"]
    assert request == original
    accepted = service.submit_receiver_defense(
        {**corrected, "submission_id": str(uuid.uuid4()), "context_digest": ready["context_digest"]}
    )
    owner_id = accepted["job"]["job_id"]
    assert service.job_controller.wait(owner_id, timeout=10)["state"] == "completed"
    prepare_id = str(uuid.uuid4())
    service.prepare_receiver_defense(
        owner_id, {"submission_id": prepare_id, "phase": "baseline", "reviewed_by": "Reviewer"}
    )
    child = service.job_controller.wait("job-" + uuid.UUID(prepare_id).hex, timeout=10)
    assert child["state"] == "completed", child
    phase = service.receiver_defense_job(owner_id)["phases"][0]
    assert phase["review_ready"] and phase["execution_job"] is None
    assert (
        phase["preparation"]["run_request"]["target_scope"]
        == corrected["run_intent"]["target_scope"]
    )
    assert len(sessions) == 1 and not sessions[0].tasks
    assert not access.calls and runner.execute_calls == 0
    assert service.receiver_defense_job(refused["job"]["job_id"])["job"] == refused["job"]


@pytest.mark.parametrize(
    "scope",
    [
        None,
        {},
        {"scope_refs": []},
        {"scope_refs": "network.loopback"},
        {"scope_refs": [1]},
        {"scope_refs": ["sandbox.workspace", "network.loopback", "outside.profile"]},
    ],
)
def test_malformed_or_profile_expanding_scope_remains_refused(setup, scope):
    service, access, runner, sessions, request = setup
    request["run_intent"]["target_scope"] = scope
    original = copy.deepcopy(request)
    current = service.receiver_defense_context(request)
    assert not current["eligible"]
    assert any(item["code"] == "scope_required" for item in current["reasons"])
    assert not any(item["code"] == "receiver_scope_required" for item in current["reasons"])
    assert request == original
    assert not sessions and not access.calls and runner.execute_calls == 0
    assert not service.product_store.list_jobs()


def test_missing_execute_profile_still_refuses_before_receiver_admission(setup):
    service, access, runner, sessions, request = setup
    request["run_intent"]["runner_profile_id"] = "profile.does-not-exist.v1"
    with pytest.raises(APIError):
        service.receiver_defense_context(request)
    assert not service.product_store.list_jobs()
    assert not sessions and not access.calls and runner.execute_calls == 0


def test_previously_admitted_incomplete_scope_cannot_prepare_after_context_recheck(
    setup, monkeypatch
):
    service, access, runner, sessions, request = setup
    request["run_intent"]["target_scope"] = {"scope_refs": ["sandbox.workspace"]}
    context = receiver_defense_jobs.context

    def former_context(service, request):
        value = dict(context(service, request))
        value.pop("context_digest")
        value["reasons"] = [
            reason for reason in value["reasons"] if reason["code"] != "receiver_scope_required"
        ]
        value["eligible"] = not value["reasons"]
        return {**value, "context_digest": content_hash(value)}

    # Persist the actual formerly admitted shape, then restore today's check.
    with monkeypatch.context() as old:
        old.setattr(receiver_defense_jobs, "context", former_context)
        current = service.receiver_defense_context(request)
        parent = service.submit_receiver_defense(
            {
                **request,
                "submission_id": str(uuid.uuid4()),
                "context_digest": current["context_digest"],
            }
        )["job"]
        assert service.job_controller.wait(parent["job_id"], timeout=10)["state"] == "completed"
    retained = service.receiver_defense_job(parent["job_id"])
    assert retained["admission"]["accepted"]
    with pytest.raises(APIError):
        service.prepare_receiver_defense(
            parent["job_id"],
            {"submission_id": str(uuid.uuid4()), "phase": "baseline", "reviewed_by": "Reviewer"},
        )
    assert len(service.product_store.list_jobs()) == 1
    assert service.receiver_defense_job(parent["job_id"])["job"] == retained["job"]
    assert not sessions and not access.calls and runner.execute_calls == 0
