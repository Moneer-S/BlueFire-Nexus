"""Fresh native-protocol fixture runs; no receiver processes or model calls."""

import copy
import uuid

import pytest

from bluefire import product_store_receiver_defense as records
from bluefire.application_errors import APIError
from bluefire.config import ExecutionMode
from bluefire.job_runtime import JobState
from bluefire.product_store_errors import ProductStoreError
from bluefire.receiver_defense_jobs import ReceiverDefenseJobs
from bluefire.receiver_defense_workflow import legitimate_semantics
from bluefire.receiver_policy import ReceiverContentPolicy
from bluefire.service import BlueFireService
from tests_platform.test_receiver_defense_jobs import ROOT, FixtureRunner, Session
from tests_platform.test_receiver_defense_jobs import setup as setup
from tests_platform.test_receiver_policy import public_records


def submit(service, request):
    current = service.receiver_defense_context(request)
    assert current["eligible"], current["reasons"]
    value = service.submit_receiver_defense(
        {
            **request,
            "submission_id": str(uuid.uuid4()),
            "context_digest": current["context_digest"],
        }
    )
    owner_id = value["job"]["job_id"]
    assert service.job_controller.wait(owner_id, timeout=10)["state"] == "completed"
    return owner_id


def prepare(service, owner_id, phase):
    request = {
        "submission_id": str(uuid.uuid4()),
        "phase": phase,
        "reviewed_by": "Fixture reviewer",
    }
    service.prepare_receiver_defense(owner_id, request)
    child = service.job_controller.wait(
        "job-" + uuid.UUID(request["submission_id"]).hex, timeout=15
    )
    assert child["state"] == "completed", child
    envelope = service.receiver_defense_job(owner_id)
    return next(item for item in envelope["phases"] if item["phase"] == phase)


def execute(service, owner_id, phase, *, current=None):
    current = current or prepare(service, owner_id, phase)
    reviewed = service.review_receiver_defense(
        owner_id,
        {
            "submission_id": str(uuid.uuid4()),
            "phase": phase,
            "preparation_digest": current["preparation"]["preparation_digest"],
            "decision": "accept",
            "reviewed_by": "Fixture reviewer",
        },
    )
    execution = next(item for item in reviewed["phases"] if item["phase"] == phase)["execution_job"]
    waiting = service.job_controller.wait_for_state(
        execution["job_id"],
        {JobState.AWAITING_APPROVAL},
        timeout=10,
    )
    assert waiting["state"] == "awaiting_approval"
    service.approve_job(execution["job_id"], {"approved_by": "Fixture reviewer"})
    terminal = service.job_controller.wait(execution["job_id"], timeout=20)
    assert terminal["state"] == "completed", terminal
    return service.receiver_defense_job(owner_id)


def retained_setup(setup):
    service, access, _, sessions, request = setup
    runner = FixtureRunner(sessions)
    sandbox = service.runner_factory(None)[1]
    service.runner_factory = lambda _profile: (runner, sandbox)
    request = {**request, "workflow": "retained_redaction"}
    return service, access, runner, sessions, request, sandbox


def complete(service, request):
    owner_id = submit(service, request)
    for phase in ("baseline", "protected", "legitimate"):
        envelope = execute(service, owner_id, phase)
        assert (
            next(item for item in envelope["phases"] if item["phase"] == phase)["status"]
            == "completed"
        ), envelope
    assert envelope["status"] == "completed", envelope
    return owner_id, envelope


def rollback_request(envelope):
    return {
        "submission_id": str(uuid.uuid4()),
        "control_digest": envelope["control"]["control_digest"],
        "decision": "rollback",
        "reviewed_by": "Fixture reviewer",
    }


def test_retained_control_blocks_original_and_accepts_fresh_redacted_use(setup):
    service, access, runner, sessions, request, _ = retained_setup(setup)
    owner_id, envelope = complete(service, request)
    assert envelope["schema_version"] == "bluefire.receiver-defense.v2"
    assert [item["phase"] for item in envelope["phases"]] == ["baseline", "protected", "legitimate"]
    baseline, protected, legitimate = (item["result"] for item in envelope["phases"])
    assert [item["decision"] for item in (baseline, protected, legitimate)] == [
        "accepted",
        "policy_refused",
        "accepted",
    ]
    assert protected["artifact"] == baseline["artifact"]
    assert legitimate["artifact"] != baseline["artifact"]
    assert legitimate["legitimate_use"] == {
        "baseline_run_id": baseline["run_id"],
        "established": True,
    }
    prepared = envelope["phases"][2]["preparation"]
    assert prepared["baseline_artifact"] is None
    assert prepared["replay_preparation"]["replay_request"]["parameter_overrides"] == {
        "transform_fixture": {"redact_values": True},
    }
    assert all(session.closed and len(session.tasks) == 1 for session in sessions)
    assert envelope["control"]["status"] == "retained"
    assert envelope["control"]["desired_policy_id"] == "receiver.redacted-only.v1"
    assert envelope["control"]["receiver_state"] == "stopped"
    assert envelope["control"]["can_retest"] and envelope["control"]["can_rollback"]
    assert len(service.store.list_runs()) == 3 and not access.calls
    assert service.receiver_defense_job(owner_id)["control"] == envelope["control"]
    for independent in (
        request,
        {key: value for key, value in request.items() if key != "workflow"},
    ):
        independent_id = submit(service, independent)
        baseline_review = prepare(service, independent_id, "baseline")
        assert baseline_review["policy_id"] == "receiver.reviewed-records.v1"
        assert sessions[-1].review_binding["policy"]["policy_id"] == "receiver.reviewed-records.v1"
        service.cancel_job(independent_id)
    assert all(session.closed for session in sessions)
    assert service.receiver_defense_job(owner_id)["control"] == envelope["control"]


def test_restart_retains_policy_and_retest_executes_only_two_fresh_phases(setup, monkeypatch):
    service, access, runner, sessions, request, sandbox = retained_setup(setup)
    owner_id, original = complete(service, request)
    root, database = service.store.root, service.product_store.path
    service.close()
    restarted = BlueFireService(
        project_root=ROOT,
        runs_dir=root,
        product_db_path=database,
        ai_provider_access=access,
        runner_factory=lambda _profile: (runner, sandbox),
    )
    profile = next(
        row for row in restarted.config.runner_profiles if row.mode is ExecutionMode.EXECUTE
    )
    monkeypatch.setattr(
        restarted, "runner_status", lambda **_kwargs: {"state": "ready", "profile_id": profile.id}
    )

    def factory(policy_id, *, port):
        session = Session(policy_id, port=port)
        sessions.append(session)
        return session

    restarted.receiver_defense = ReceiverDefenseJobs(restarted, factory=factory)
    try:
        assert restarted.receiver_defense_job(owner_id)["control"]["status"] == "retained"
        linked = {
            **request,
            "source_control": {
                "job_id": owner_id,
                "control_digest": original["control"]["control_digest"],
            },
        }
        child_id = submit(restarted, linked)
        assert [item["phase"] for item in restarted.receiver_defense_job(child_id)["phases"]] == [
            "protected",
            "legitimate",
        ]
        decision = rollback_request(original)
        with pytest.raises(APIError):
            restarted.decide_receiver_control(owner_id, decision)
        current = prepare(restarted, child_id, "protected")
        assert restarted.receiver_defense_job(owner_id)["control"]["receiver_state"] == "active"
        with pytest.raises(APIError):
            submit(restarted, linked)
        execute(restarted, child_id, "protected", current=current)
        envelope = execute(restarted, child_id, "legitimate")
        assert envelope["status"] == "completed"
        assert (
            envelope["context"]["source_baseline"]["run_id"]
            == original["phases"][0]["result"]["run_id"]
        )
        assert len(restarted.store.list_runs()) == 5
        assert all(
            session.review_binding["policy"]["policy_id"] == "receiver.redacted-only.v1"
            for session in sessions[3:]
        )
        prior_context = restarted.receiver_defense_context(linked)
        competing = {
            **linked,
            "submission_id": str(uuid.uuid4()),
            "context_digest": prior_context["context_digest"],
        }
        publish = restarted.job_controller.submit
        rolled = None

        def rollback_before_publication(kind, document, **kwargs):
            nonlocal rolled
            assert kind == "receiver.defense" and document["context"]["source_control"]
            rolled = restarted.decide_receiver_control(owner_id, decision)
            return publish(kind, document, **kwargs)

        with monkeypatch.context() as race:
            race.setattr(restarted.job_controller, "submit", rollback_before_publication)
            with pytest.raises(APIError):
                restarted.submit_receiver_defense(competing)
        with pytest.raises(ProductStoreError):
            restarted.product_store.get_job("job-" + uuid.UUID(competing["submission_id"]).hex)
        assert rolled is not None
        assert rolled["control"]["status"] == "rolled_back"
        assert rolled["control"]["desired_policy_id"] == "receiver.reviewed-records.v1"
        assert not rolled["control"]["can_retest"]
        assert restarted.decide_receiver_control(owner_id, decision)["control"] == rolled["control"]
        with pytest.raises(APIError):
            restarted.receiver_defense_context(linked)
        refused = restarted.submit_receiver_defense(competing)
        assert refused["admission"]["accepted"] is False and refused["admission"]["problem"]
        assert not any(phase["prepare_allowed"] for phase in refused["phases"])
        assert len(sessions) == 5 and all(session.closed for session in sessions)
    finally:
        restarted.close()


def test_v2_context_refuses_unrelated_or_already_redacted_transform(setup):
    service, _, _, _, request, _ = retained_setup(setup)
    graph = service.scenario_version(
        request["selection"]["scenario_id"], version=request["selection"]["version"]
    )["scenario"]["document"]
    graph = copy.deepcopy(graph)
    next(step for step in graph["steps"] if step["id"] == "transform_fixture")["parameters"][
        "redact_values"
    ] = True
    saved = service.save_scenario_version({"scenario": graph})["scenario"]
    request["selection"] = {
        "kind": "saved_scenario",
        "scenario_id": saved["scenario_id"],
        "version": saved["version"],
        "digest": saved["digest"],
    }
    current = service.receiver_defense_context(request)
    assert not current["eligible"] and current["control"] is None
    assert any(item["code"] == "receiver_redaction_ineligible" for item in current["reasons"])


@pytest.mark.parametrize("linked", [False, True])
def test_unpublished_reserved_phase_remains_readable_and_unsettled(setup, linked):
    service, _, _, _, request, _ = retained_setup(setup)
    if linked:
        original_id, original = complete(service, request)
        request = {
            **request,
            "source_control": {
                "job_id": original_id,
                "control_digest": original["control"]["control_digest"],
            },
        }
    owner_id = submit(service, request)
    records.reserve(
        service.product_store,
        owner_id,
        {
            "submission_id": str(uuid.uuid4()),
            "phase": "protected" if linked else "baseline",
            "reviewed_by": "Fixture reviewer",
        },
    )
    envelope = service.receiver_defense_job(owner_id)
    assert envelope["phases"][0]["problem"]["code"] == "receiver_publication_uncertain"
    assert envelope["control"]["receiver_state"] == "unknown"
    assert not envelope["control"]["can_retest"]
    assert not envelope["control"]["can_rollback"]
    with service.product_store._connection(write=True) as connection:
        parent = records.owner_at(service.product_store, connection, owner_id)
        records.safe_patch(connection, parent, {"receiver_settled": True})
        parent = records.owner_at(service.product_store, connection, owner_id)
        assert records.control_settled(service.product_store, connection, parent) is False
    if linked:
        assert service.receiver_defense_job(original_id)["control"] == envelope["control"]
        with pytest.raises(APIError):
            service.decide_receiver_control(original_id, rollback_request(original))


def test_v1_rejects_legitimate_phase_and_retained_options_require_explicit_workflow(setup):
    service, _, _, _, request = setup
    owner_id = submit(service, request)
    with pytest.raises(APIError):
        prepare(service, owner_id, "legitimate")
    with pytest.raises(APIError):
        service.receiver_defense_context(
            {
                **request,
                "source_control": {"job_id": owner_id, "control_digest": "sha256:" + "0" * 64},
            }
        )
    assert (
        service.receiver_defense_job(owner_id)["schema_version"] == "bluefire.receiver-defense.v1"
    )


@pytest.mark.parametrize("count,redacted", [(3, True), (4, False)])
def test_legitimate_use_needs_the_original_nonzero_count_and_redacted_records(count, redacted):
    def observation(payload, policy):
        return {
            "receiver_observation": {
                "terminal": {"decision": ReceiverContentPolicy(policy).inspect(payload)}
            }
        }

    baseline = observation(public_records(count=4), "receiver.reviewed-records.v1")
    changed = observation(
        public_records(count=count, redacted=redacted), "receiver.redacted-only.v1"
    )
    assert not legitimate_semantics(changed, baseline)
