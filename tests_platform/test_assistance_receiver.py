"""Connected existing controller/native protocol doubles; no receiver process or provider I/O."""

import json
import threading
import uuid

import pytest

from bluefire.ai_assistance import PURPOSE, RECEIVER_INSPECT, RECEIVER_TEST
from bluefire.ai_provider_access import ProviderReadiness
from bluefire.ai_receiver_inspection import PURPOSE as INSPECTION
from bluefire.ai_wire import AIProviderCancelled
from bluefire.config import AIConfig, AIProviderConfig, AutonomyLevel
from bluefire.job_runtime import JobState
from bluefire.product_store_errors import ProductStoreError
from tests_platform.test_receiver_defense_jobs import FixtureRunner
from tests_platform.test_receiver_defense_jobs import setup as receiver_setup  # noqa: F401


class Access:
    def __init__(self):
        self.calls = []
        self.hold = None
        self.entered = threading.Event()
        self.invalid = False

    def readiness(self, config):
        return ProviderReadiness(True, "not_required", "ready", "Portable protocol double")

    def post(self, config, *, body, timeout_seconds, cancel_event=None):
        payload = json.loads(body)
        purpose = (
            payload.get("text", {}).get("format") or payload["response_format"]["json_schema"]
        )["name"]
        supplied = json.loads(payload.get("input") or payload["messages"][1]["content"])
        self.calls.append(purpose)
        if purpose == PURPOSE:
            output = {
                "message": "Coordinate the selected native receiver work.",
                "steps": [
                    {
                        "capability_id": (
                            RECEIVER_TEST
                            if supplied["selected"]["kind"] == "receiver_scenario"
                            else RECEIVER_INSPECT
                        ),
                        "detector_ref": "none",
                        "reason": "Use the authoritative selected capability.",
                    }
                ],
            }
        else:
            assert purpose == INSPECTION
            self.entered.set()
            if self.hold:
                assert self.hold.wait(10)
            if cancel_event and cancel_event.is_set():
                raise AIProviderCancelled()
            output = {
                "summary": "Controlled receiver evidence only.",
                "findings": [
                    {
                        "claim": "The exact supplied receiver decision is retained.",
                        "evidence_refs": [supplied["phases"][0]["evidence_ref"]],
                    }
                ],
                "limitations": ["Portable integration test, not deployed defense proof."],
                "next_phase": supplied["offered_next_phase"],
                "reason": "Next preparation and Execute approval remain explicit.",
            }
            if self.invalid:
                output["findings"][0]["evidence_refs"] = ["receiver:invented"]
        if config.kind.value == "chat_completions":
            response = {
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": json.dumps(output)},
                    }
                ],
                "usage": {"prompt_tokens": 20, "completion_tokens": 40},
            }
        else:
            response = {
                "status": "completed",
                "output_text": json.dumps(output),
                "usage": {"input_tokens": 20, "output_tokens": 40},
            }
        return json.dumps(response).encode()

    def close(self):
        if self.hold:
            self.hold.set()


@pytest.fixture(params=["openai_responses", "chat_completions"])
def configured(receiver_setup, request):  # noqa: F811
    service, _, oldrunner, sessions, native = receiver_setup
    access = Access()
    service._provider_access = access
    provider = AIProviderConfig.from_mapping(
        {
            "id": "provider.test.v1",
            "kind": request.param,
            "model": "unit-model",
            "endpoint": "http://127.0.0.1:8765/v1/"
            + ("responses" if request.param == "openai_responses" else "chat/completions"),
        }
    )
    service._runtime_ai_config = AIConfig(
        AutonomyLevel.OFF,
        provider.id,
        service.config.ai.fallback_provider,
        (provider, *service.config.ai.providers),
    )
    selected = {"kind": "receiver_scenario", **native}
    context = service.assistance_receiver_context({"selection": selected})
    body = {
        "submission_id": str(uuid.uuid4()),
        "selection": selected,
        "context_digest": context["context_digest"],
        "message": "Test the reviewed records, protect the receiver and verify restored baseline behavior.",
        "autonomy": "assist",
        "provider_id": provider.id,
    }
    yield service, access, sessions, body
    access.close()


def planned(configured):
    service, _, _, body = configured
    initial = service.submit_assistance_turn(body)
    parent = service.job_controller.wait(initial["job"]["job_id"], timeout=15)
    assert parent["state"] == "completed", parent
    owner_id = parent["progress"]["children"]["step-1"]["job_id"]
    owner = service.job_controller.wait(owner_id, timeout=15)
    assert owner["state"] == "completed", owner
    return parent, owner


def run_phase(service, owner_id, phase):
    submit = {
        "submission_id": str(uuid.uuid4()),
        "phase": phase,
        "reviewed_by": "Portable reviewer",
    }
    service.prepare_receiver_defense(owner_id, submit)
    prepared = service.job_controller.wait(
        "job-" + uuid.UUID(submit["submission_id"]).hex, timeout=15
    )
    assert prepared["state"] == "completed", prepared
    current = next(
        row for row in service.receiver_defense_job(owner_id)["phases"] if row["phase"] == phase
    )
    reviewed = service.review_receiver_defense(
        owner_id,
        {
            "submission_id": str(uuid.uuid4()),
            "phase": phase,
            "preparation_digest": current["preparation"]["preparation_digest"],
            "decision": "accept",
            "reviewed_by": "Portable reviewer",
        },
    )
    execution = next(row for row in reviewed["phases"] if row["phase"] == phase)["execution_job"]
    service.job_controller.wait_for_state(
        execution["job_id"], {JobState.AWAITING_APPROVAL}, timeout=10
    )
    marker = service.product_store.get_job(owner_id)["request"].get("assistance_turn")
    if marker:
        turn = service.assistance_turn(marker["parent_job_id"])["turn"]
        assert turn["status"] == "awaiting_execute_approval", turn
        assert turn["active_child"]["job_id"] == execution["job_id"]
        assert turn["next_action"] == {
            "kind": "review_execute",
            "label": "Review Execute approval",
            "native_path": "/runs?job=" + execution["job_id"],
        }
        (
            service.store.root.parent / ("receiver-assistance-approval-" + phase + ".json")
        ).write_text(json.dumps(service.assistance_turn(marker["parent_job_id"])), encoding="utf-8")
    service.approve_job(execution["job_id"], {"approved_by": "Portable reviewer"})
    result = service.job_controller.wait(execution["job_id"], timeout=20)
    assert result["state"] == "completed", result
    return result


def protocol_runner(service, sessions):
    sandbox = service.runner_factory(None)[1]
    runner = FixtureRunner(sessions)
    service.runner_factory = lambda _profile: (runner, sandbox)
    return runner


def test_off_and_explicit_owner_are_no_effect_and_get_never_advances(configured):
    service, access, sessions, body = configured
    off = service.submit_assistance_turn({**body, "autonomy": "off"})
    service.job_controller.wait(off["job"]["job_id"], timeout=10)
    assert service.assistance_turn(off["job"]["job_id"])["turn"]["status"] == "off"
    assert not access.calls and not sessions
    body["submission_id"] = str(uuid.uuid4())
    parent, owner = planned(configured)
    for _ in range(3):
        view = service.assistance_turn(parent["job_id"])
        assert view["turn"]["status"] == "awaiting_review"
        assert not view["turn"]["can_start_new_turn"]
        assert view["turn"]["receiver_test"]["owns_lifecycle"]
        assert service.submit_assistance_turn(body)["job"]["job_id"] == parent["job_id"]
    assert access.calls == [PURPOSE] and not sessions
    service.cancel_job(parent["job_id"])
    assert service.receiver_defense_job(owner["job_id"])["status"] == "stopped"
    assert service.assistance_turn(parent["job_id"])["turn"]["status"] == "cancelled"


def test_three_phases_auto_coordination_retains_exact_analyses_without_automatic_effects(
    configured,
):
    service, access, sessions, body = configured
    body["autonomy"] = "auto"
    runner = protocol_runner(service, sessions)
    parent, owner = planned(configured)
    snapshots = []
    for index, phase in enumerate(("baseline", "protected", "restored")):
        assert len(sessions) == index
        run_phase(service, owner["job_id"], phase)
        parent = service.product_store.get_job(parent["job_id"])
        assert len(parent["progress"].get("receiver_inspections", [])) == index + 1, parent
        analysis = service.job_controller.wait(
            parent["progress"]["receiver_inspections"][-1]["job_id"], timeout=15
        )
        assert analysis["state"] == "completed", analysis
        view = service.assistance_turn(parent["job_id"])
        assert view["turn"]["status"] == ("completed" if index == 2 else "awaiting_review"), view
        assert len(sessions) == index + 1
        snapshots.append(view)
    assert access.calls == [PURPOSE, INSPECTION, INSPECTION, INSPECTION]
    facts = snapshots[-1]["turn"]["receiver_test"]["inspections"][-1]["phases"]
    assert [row["transport_state"] for row in facts] == ["completed", "failed", "completed"]
    assert all(row["record_count"] > 0 and row["retained_record_count"] > 0 for row in facts)
    assert len(service.store.list_runs()) == 3 and runner.execute_calls > 0
    assert [
        row["decision"]
        for row in snapshots[-1]["turn"]["receiver_test"]["inspections"][-1]["phases"]
    ] == ["accepted", "policy_refused", "accepted"]
    (service.store.root.parent / "receiver-assistance-contract.json").write_text(
        json.dumps(
            {
                "fixture_kind": "Portable protocol doubles only",
                "context": service.assistance_receiver_context({"selection": body["selection"]}),
                "phases": snapshots,
            }
        ),
        encoding="utf-8",
    )


def test_ancestor_stop_refuses_native_preparation_before_factory(configured):
    service, _, sessions, _ = configured
    parent, owner = planned(configured)
    from bluefire.product_store_assistance import stop

    stop(service.product_store, parent["job_id"])
    with pytest.raises((ProductStoreError, ValueError)):
        service.receiver_defense.prepare(
            owner["job_id"],
            {
                "submission_id": str(uuid.uuid4()),
                "phase": "baseline",
                "reviewed_by": "Portable reviewer",
            },
        )
    assert not sessions
    service.cancel_job(parent["job_id"])


def existing_baseline(configured):
    service, access, sessions, body = configured
    protocol_runner(service, sessions)
    native = {key: body["selection"][key] for key in ("selection", "run_intent")}
    context = service.receiver_defense_context(native)
    owner = service.submit_receiver_defense(
        {**native, "submission_id": str(uuid.uuid4()), "context_digest": context["context_digest"]}
    )["job"]
    service.job_controller.wait(owner["job_id"], timeout=10)
    run_phase(service, owner["job_id"], "baseline")
    assert not access.calls
    selected = {
        "kind": "receiver_test",
        "receiver_job_id": owner["job_id"],
        "receiver_context_digest": context["context_digest"],
    }
    current = service.assistance_receiver_context({"selection": selected})
    body.update(selection=selected, context_digest=current["context_digest"])
    return owner


def test_existing_test_analysis_stop_does_not_adopt_receiver_authority(configured):
    service, access, sessions, body = configured
    owner = existing_baseline(configured)
    access.hold = threading.Event()
    parent = service.submit_assistance_turn(body)["job"]
    assert access.entered.wait(10)
    service.job_controller.wait(parent["job_id"], timeout=10)
    before = service.receiver_defense_job(owner["job_id"])
    assert not service.assistance_turn(parent["job_id"])["turn"]["receiver_test"]["owns_lifecycle"]
    service.cancel_job(parent["job_id"])
    assert service.receiver_defense_job(owner["job_id"])["status"] == before["status"] == "active"
    assert not service.product_store.get_job(owner["job_id"])["progress"].get("stopped")
    access.hold.set()
    inspection = service.product_store.get_job(parent["job_id"])["progress"][
        "receiver_inspections"
    ][0]["job_id"]
    assert service.job_controller.wait(inspection, timeout=10)["state"] == "cancelled"
    assert service.assistance_turn(parent["job_id"])["turn"]["status"] == "cancelled"
    assert len(sessions) == 1 and len(service.store.list_runs()) == 1


def test_invalid_analysis_requires_explicit_idempotent_recovery_no_repeated_run(configured):
    service, access, sessions, body = configured
    owner = existing_baseline(configured)
    access.invalid = True
    parent = service.submit_assistance_turn(body)["job"]
    service.job_controller.wait(parent["job_id"], timeout=10)
    parent = service.product_store.get_job(parent["job_id"])
    first = parent["progress"]["receiver_inspections"][0]["job_id"]
    assert service.job_controller.wait(first, timeout=10)["state"] == "failed"
    for _ in range(3):
        assert service.assistance_turn(parent["job_id"])["turn"]["status"] == "ready_to_continue"
    assert access.calls == [PURPOSE, INSPECTION]
    access.invalid = False
    recover = {"submission_id": str(uuid.uuid4()), "context_digest": body["context_digest"]}
    service.continue_assistance_turn(parent["job_id"], recover)
    continuation = "job-" + uuid.UUID(recover["submission_id"]).hex
    assert service.job_controller.wait(continuation, timeout=10)["state"] == "completed"
    second = service.product_store.get_job(parent["job_id"])["progress"]["receiver_inspections"][
        -1
    ]["job_id"]
    assert second != first
    assert service.job_controller.wait(second, timeout=10)["state"] == "completed"
    service.continue_assistance_turn(parent["job_id"], recover)
    view = service.assistance_turn(parent["job_id"])
    assert view["turn"]["status"] == "completed", view
    assert view["turn"]["receiver_test"]["status"] == "active"
    assert access.calls == [PURPOSE, INSPECTION, INSPECTION]
    assert len(sessions) == 1 and len(service.store.list_runs()) == 1
    # A later native phase never retroactively changes this one-prefix analysis.
    run_phase(service, owner["job_id"], "protected")
    assert service.assistance_turn(parent["job_id"])["turn"]["status"] == "completed"
    assert access.calls == [PURPOSE, INSPECTION, INSPECTION]


def test_lost_analysis_submission_response_recovers_original_job_without_model_repeat(
    configured, monkeypatch
):
    service, access, _, body = configured
    existing_baseline(configured)
    submit = service.job_controller.submit
    lost = []

    def lose(kind, *args, **kwargs):
        job = submit(kind, *args, **kwargs)
        if kind == "receiver.defense.inspect" and not lost:
            lost.append(job["job_id"])
            raise ProductStoreError("Portable lost submission response")
        return job

    monkeypatch.setattr(service.job_controller, "submit", lose)
    parent = service.submit_assistance_turn(body)["job"]
    assert service.job_controller.wait(parent["job_id"], timeout=10)["state"] == "failed"
    assert service.job_controller.wait(lost[0], timeout=10)["state"] == "completed"
    assert service.submit_assistance_turn(body)["job"]["job_id"] == parent["job_id"]
    recovery = {"submission_id": str(uuid.uuid4()), "context_digest": body["context_digest"]}
    service.continue_assistance_turn(parent["job_id"], recovery)
    service.job_controller.wait("job-" + uuid.UUID(recovery["submission_id"]).hex, timeout=10)
    view = service.assistance_turn(parent["job_id"])
    assert view["turn"]["status"] == "completed", view
    assert view["turn"]["receiver_test"]["inspections"][0]["job"]["job_id"] == lost[0]
    assert access.calls == [PURPOSE, INSPECTION]


def test_refused_native_owner_admission_remains_readable_without_effects(configured, monkeypatch):
    service, access, sessions, body = configured
    original = service.receiver_defense.context
    monkeypatch.setattr(
        service.receiver_defense,
        "context",
        lambda request: {**original(request), "eligible": False},
    )
    parent = service.submit_assistance_turn(body)["job"]
    service.job_controller.wait(parent["job_id"], timeout=10)
    view = service.assistance_turn(parent["job_id"])
    assert view["turn"]["status"] == "blocked", view
    assert view["turn"]["can_start_new_turn"]
    assert view["turn"]["receiver_test"]["phases"][0]["receiver_job"] is None
    assert not sessions and access.calls == [PURPOSE]


def test_ancestor_stop_during_prepare_closes_exact_late_factory(configured):
    service, _, sessions, _ = configured
    parent, owner = planned(configured)
    factory = service.receiver_defense.owners.factory
    entered, release = threading.Event(), threading.Event()

    def held(*args, **kwargs):
        entered.set()
        assert release.wait(10)
        return factory(*args, **kwargs)

    service.receiver_defense.owners.factory = held
    request = {
        "submission_id": str(uuid.uuid4()),
        "phase": "baseline",
        "reviewed_by": "Portable reviewer",
    }
    try:
        service.prepare_receiver_defense(owner["job_id"], request)
        assert entered.wait(10)
        assert service.assistance_turn(parent["job_id"])["turn"]["status"] == "working"
        from bluefire.product_store_assistance import stop

        stop(service.product_store, parent["job_id"])
    finally:
        release.set()
    job = service.job_controller.wait("job-" + uuid.UUID(request["submission_id"]).hex, timeout=10)
    assert job["state"] == "failed", job
    assert "preparation" not in job["progress"] and sessions[0].closed
    service.cancel_job(parent["job_id"])


def test_committed_interpretation_survives_callback_failure_without_second_request(
    configured, monkeypatch
):
    service, access, _, body = configured
    existing_baseline(configured)
    from bluefire import product_store_assistance_receiver as records

    original = records.retain

    def interrupted(*args, **kwargs):
        original(*args, **kwargs)
        raise ProductStoreError("Portable callback fault after durable interpretation")

    monkeypatch.setattr(records, "retain", interrupted)
    parent = service.submit_assistance_turn(body)["job"]
    service.job_controller.wait(parent["job_id"], timeout=10)
    identifier = service.product_store.get_job(parent["job_id"])["progress"][
        "receiver_inspections"
    ][0]["job_id"]
    assert service.job_controller.wait(identifier, timeout=10)["state"] == "failed"
    before = service.assistance_turn(parent["job_id"])
    assert before["turn"]["status"] == "completed"
    retained = service.product_store.get_job(parent["job_id"])
    publishing_view = {"results": [], "continuation": None}
    service.assistance_receiver.apply_view(
        {**retained, "state": "running"}, retained["progress"]["plan"][0], publishing_view
    )
    assert publishing_view["status"] == "working"
    recovery = {"submission_id": str(uuid.uuid4()), "context_digest": body["context_digest"]}
    service.continue_assistance_turn(parent["job_id"], recovery)
    service.job_controller.wait("job-" + uuid.UUID(recovery["submission_id"]).hex, timeout=10)
    assert service.assistance_turn(parent["job_id"])["turn"]["results"] == before["turn"]["results"]
    assert access.calls == [PURPOSE, INSPECTION]


def replace_request(service, identifier, request):
    # Deliberately damage only the portable test database to model a bad receipt.
    with service.product_store._connection(write=True) as connection:
        connection.execute(
            "UPDATE jobs SET request_json = ? WHERE job_id = ?", (json.dumps(request), identifier)
        )


@pytest.mark.parametrize("native_child", ["owner", "preparation", "execution"])
def test_reverse_cancellation_refuses_substituted_owner_before_any_parent_stop(
    configured, native_child
):
    service, _, sessions, body = configured
    parent_a, owner_a = planned(configured)
    body["submission_id"] = str(uuid.uuid4())
    parent_b, owner_b = planned(configured)
    target = owner_a
    if native_child != "owner":
        prepare = {
            "submission_id": str(uuid.uuid4()),
            "phase": "baseline",
            "reviewed_by": "Portable reviewer",
        }
        service.prepare_receiver_defense(owner_a["job_id"], prepare)
        target = service.job_controller.wait(
            "job-" + uuid.UUID(prepare["submission_id"]).hex, timeout=10
        )
        assert target["state"] == "completed"
        if native_child == "execution":
            current = service.receiver_defense_job(owner_a["job_id"])["phases"][0]
            reviewed = service.review_receiver_defense(
                owner_a["job_id"],
                {
                    "submission_id": str(uuid.uuid4()),
                    "phase": "baseline",
                    "preparation_digest": current["preparation"]["preparation_digest"],
                    "decision": "accept",
                    "reviewed_by": "Portable reviewer",
                },
            )
            target = service.job_controller.wait_for_state(
                reviewed["phases"][0]["execution_job"]["job_id"],
                {JobState.AWAITING_APPROVAL},
                timeout=10,
            )
    altered = json.loads(json.dumps(target["request"]))
    if native_child != "owner":
        altered["receiver_defense"]["parent_job_id"] = owner_b["job_id"]
    else:
        altered["assistance_turn"]["parent_job_id"] = parent_b["job_id"]
    replace_request(service, target["job_id"], altered)
    try:
        with pytest.raises(ProductStoreError):
            service.cancel_job(target["job_id"])
        for job in (parent_a, parent_b, owner_a, owner_b):
            assert not service.product_store.get_job(job["job_id"])["progress"].get("stopped")
    finally:
        replace_request(service, target["job_id"], target["request"])
    service.cancel_job(target["job_id"])
    assert service.product_store.get_job(parent_a["job_id"])["progress"]["stopped"]
    assert not service.product_store.get_job(parent_b["job_id"])["progress"].get("stopped")
    assert all(session.closed for session in sessions)


def test_reverse_inspection_cancel_validates_parent_reservation_without_source_read(
    configured, monkeypatch
):
    service, _, _, body = configured
    owner = existing_baseline(configured)
    parent = service.submit_assistance_turn(body)["job"]
    service.job_controller.wait(parent["job_id"], timeout=10)
    parent = service.product_store.get_job(parent["job_id"])
    analysis = service.job_controller.wait(
        parent["progress"]["receiver_inspections"][0]["job_id"], timeout=10
    )
    other = service.submit_assistance_turn(
        {**body, "submission_id": str(uuid.uuid4()), "autonomy": "off"}
    )["job"]
    service.job_controller.wait(other["job_id"], timeout=10)
    altered = json.loads(json.dumps(analysis["request"]))
    altered["assistance_receiver"]["parent_job_id"] = other["job_id"]
    replace_request(service, analysis["job_id"], altered)
    try:
        with pytest.raises(ProductStoreError):
            service.cancel_job(analysis["job_id"])
        assert not service.product_store.get_job(other["job_id"])["progress"].get("stopped")
    finally:
        replace_request(service, analysis["job_id"], analysis["request"])
    # Cancellation must not depend on validating model interpretations or sources.
    monkeypatch.setattr(
        service.assistance_receiver,
        "inspections",
        lambda *a, **k: (_ for _ in ()).throw(ProductStoreError("Portable damaged interpretation")),
    )
    service.cancel_job(analysis["job_id"])
    assert service.product_store.get_job(parent["job_id"])["progress"]["stopped"]
    assert not service.product_store.get_job(owner["job_id"])["progress"].get("stopped")
