"""Portable native service/controller checks; no receiver or target process is launched."""

import copy
import hashlib
import json
import threading
import time
import traceback
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import product_store_receiver_defense as records
from bluefire import receiver_defense_context as contexts
from bluefire.application_errors import APIError
from bluefire.config import ExecutionMode
from bluefire.job_runtime import JobState
from bluefire.product_store_errors import ProductStoreError
from bluefire.receiver_defense_jobs import ReceiverDefenseJobs
from bluefire.receiver_policy import ReceiverContentPolicy
from bluefire.receiver_session_contract import prepare_frame, ready_binding
from bluefire.service import BlueFireService
from bluefire.util import content_hash
from tests_platform.test_graph_ai_jobs import Access
from tests_platform.test_orchestrator import StructuredFakeRunner
from tests_platform.test_receiver_policy import public_records
from tests_platform.test_service import ReadyInventoryRunner

ROOT = Path(__file__).resolve().parents[1]


class Session:
    def __init__(self, policy_id, *, port):
        self.closed = False
        self.tasks = []
        frame = prepare_frame(
            launch_id=uuid.uuid4().hex * 2,
            policy_id=policy_id,
            port=port,
            generation="sha256:" + "a" * 64,
            deadline_ns=time.monotonic_ns() + 240_000_000_000,
            expires_at_ms=time.time_ns() // 1_000_000 + 240_000,
        )
        self.review_binding = ready_binding(
            frame, session_id=uuid.uuid4().hex * 2, process_id=123, creation_identity="12345"
        )

    def require_current(self, digest):
        if (
            self.closed
            or getattr(self, "expired", False)
            or time.monotonic_ns() >= self.review_binding["deadline_ns"]
        ):
            raise ValueError("session expired")
        assert digest == self.review_binding["review_digest"]

    def close(self):
        self.closed = True
        return True

    def bind_task(self, task_id, **kwargs):
        assert not self.closed and not self.tasks
        self.tasks.append((task_id, kwargs))

    def wait_observation(self, **kwargs):
        return getattr(
            self,
            "observation",
            {
                "schema_version": "bluefire.owned-receiver-observation.v1",
                "state": "insufficient_evidence",
                "reason": "Portable test did not dispatch a target.",
            },
        )


class FixtureRunner(ReadyInventoryRunner):
    """Normal manifest/result protocol with synthetic outputs, no native process."""

    def __init__(self, sessions):
        super().__init__()
        self.delegate, self.sessions = StructuredFakeRunner(), sessions

    def execute(self, manifest, profile):
        self.execute_calls += 1
        return self.delegate.execute(manifest, profile)

    def execute_task(self, manifest, profile, *, task_id, cancel_event, durable_result_path):
        result = self.execute(manifest, profile)
        payload = public_records(count=self.delegate.record_count)
        digest = hashlib.sha256(payload).hexdigest()
        if manifest["action_id"] == "sandbox.collection.stage.v1":
            result["output"].update(sha256=digest, size=len(payload))
        if manifest["action_id"] == "sandbox.peer.handoff.v1":
            session = self.sessions[-1]
            assert session.tasks and session.tasks[0][0] == task_id
            binding = session.review_binding
            task = {
                "kind": "bind",
                "review_digest": binding["review_digest"],
                "task_id": task_id,
                "sha256": digest,
                "size_bytes": len(payload),
            }
            content = {
                **ReceiverContentPolicy(binding["policy"]["policy_id"]).inspect(payload),
                "schema_version": "bluefire.receiver-content-decision.v1",
                "task_id": task_id,
                "receiver_session_id": binding["receiver_session_id"],
                "receiver_process_id": binding["receiver_process_id"],
                "authenticated": True,
            }
            accepted = content["decision"] == "accepted"
            session.observation = {
                "schema_version": "bluefire.owned-receiver-observation.v1",
                "state": "verified",
                "review_binding": binding,
                "task_binding": task,
                "terminal": {
                    "kind": "terminal",
                    "review_digest": binding["review_digest"],
                    "task_digest": content_hash(task),
                    "summary": {
                        "schema_version": "bluefire.loopback-receiver-summary.v1",
                        "reason": "content_policy_decision",
                        "connections_handled": 2,
                        "challenges_issued": 1,
                        "requests_accepted": int(accepted),
                        "requests_refused": int(not accepted),
                    },
                    "decision": content,
                },
                "process_exit": {
                    "process_id": binding["receiver_process_id"],
                    "creation_identity": binding["creation_identity"],
                    "returncode": 0,
                    "observed_at_ms": time.time_ns() // 1_000_000,
                },
            }
            if not accepted:
                result.update(
                    status="failed",
                    output={},
                    error={
                        "code": "peer_http_refused",
                        "message": "Portable protocol fixture: receiver returned HTTP403 policy_refused.",
                    },
                )
            else:
                result["output"] = {
                    "destination": {"host": "127.0.0.1", "port": binding["port"]},
                    "artifact": "staged/bundle.jsonl",
                    "bytes_sent": len(payload),
                    "sha256": digest,
                    "http_status": 200,
                    "receiver_acknowledged": True,
                    "receiver_stored": False,
                    "lab_authorization": {
                        "scope": "approved_task",
                        "credential_kind": "managed_one_task_hmac_capability",
                        "credential_handle": "a" * 64,
                        "challenge_verified": True,
                        "raw_credential_exposed": False,
                    },
                    "lab_peers": {
                        "scope": "authorized_disposable_loopback_lab",
                        "source_kind": "rust_runner_process",
                        "destination_kind": "managed_loopback_receiver_process",
                        "source_process_id": 456,
                        "destination_process_id": 123,
                        "source_handle": "b" * 64,
                        "destination_handle": "c" * 64,
                        "distinct_processes": True,
                        "receiver_mode": "disposable_peer",
                        "accepted_artifact_limit": 1,
                        "storage_mode": "memory_only",
                        "exit_after_accept": True,
                        "transfer_acknowledged": True,
                    },
                }
        return result


@pytest.fixture
def setup(tmp_path, monkeypatch):
    access, runner, sessions = Access(), ReadyInventoryRunner(), []
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
        ai_provider_access=access,
        runner_factory=lambda _profile: (runner, sandbox),
    )
    profile = next(
        row for row in service.config.runner_profiles if row.mode is ExecutionMode.EXECUTE
    )
    monkeypatch.setattr(contexts, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(
        service, "runner_status", lambda **_kwargs: {"state": "ready", "profile_id": profile.id}
    )

    def factory(policy_id, *, port):
        session = Session(policy_id, port=port)
        sessions.append(session)
        return session

    service.receiver_defense = ReceiverDefenseJobs(service, factory=factory)
    graph = service._scenario({"scenario_id": "scenario.endpoint.deep-behavior-lab.v1"}).to_dict()
    keep = {
        "create_fixture",
        "transform_fixture",
        "inspect_fixture_metadata",
        "stage_records",
        "authorized_peer_handoff",
        "cleanup_workspace",
    }
    graph["steps"] = [step for step in graph["steps"] if step["id"] in keep]
    graph["start"] = "create_fixture"
    graph["edges"] = [
        edge for edge in graph["edges"] if edge["from_step"] in keep and edge["to_step"] in keep
    ]
    graph["edges"].append(
        {"from_step": "stage_records", "outcome": "success", "to_step": "authorized_peer_handoff"}
    )
    next(step for step in graph["steps"] if step["id"] == "transform_fixture")["parameters"][
        "redact_values"
    ] = False
    saved = service.save_scenario_version({"scenario": graph})["scenario"]
    request = {
        "selection": {
            "kind": "saved_scenario",
            "scenario_id": saved["scenario_id"],
            "version": saved["version"],
            "digest": saved["digest"],
        },
        "run_intent": {
            "mode": "execute",
            "autonomy": "off",
            "ai_provider_id": None,
            "runner_profile_id": profile.id,
            "target_scope": {"scope_refs": list(profile.scope)},
        },
    }
    yield service, access, runner, sessions, request
    service.close()


def prepared(setup):
    service, access, runner, sessions, request = setup
    current = service.receiver_defense_context(request)
    assert current["eligible"], current
    submitted = {
        **request,
        "submission_id": str(uuid.uuid4()),
        "context_digest": current["context_digest"],
    }
    parent = service.submit_receiver_defense(submitted)["job"]
    assert service.job_controller.wait(parent["job_id"], timeout=10)["state"] == "completed"
    prepare_request = {
        "submission_id": str(uuid.uuid4()),
        "phase": "baseline",
        "reviewed_by": "Portable native review",
    }
    service.prepare_receiver_defense(parent["job_id"], prepare_request)
    child = service.job_controller.wait(
        "job-" + uuid.UUID(prepare_request["submission_id"]).hex, timeout=10
    )
    assert child["state"] == "completed", child
    envelope = service.receiver_defense_job(parent["job_id"])
    assert envelope["phases"][0]["review_ready"], envelope
    return parent, prepare_request, envelope


def test_context_and_parent_do_not_start_receiver_or_model(setup):
    service, access, runner, sessions, request = setup
    current = service.receiver_defense_context(request)
    assert current["eligible"] and current["handoff"]["container"] == "jsonl"
    assert not sessions and not access.calls and runner.execute_calls == 0
    request["run_intent"]["mode"] = "simulate"
    current = service.receiver_defense_context(request)
    assert not current["eligible"] and not current["availability"]["supported"]
    assert not sessions


def test_prepare_then_native_review_creates_one_fresh_approval_no_target_effects(setup):
    service, access, runner, sessions, request = setup
    parent, prepare_request, envelope = prepared(setup)
    assert len(sessions) == 1 and runner.execute_calls == 0 and not access.calls
    service.prepare_receiver_defense(parent["job_id"], prepare_request)
    assert len(sessions) == 1
    decision = {
        "submission_id": str(uuid.uuid4()),
        "phase": "baseline",
        "preparation_digest": envelope["phases"][0]["preparation"]["preparation_digest"],
        "decision": "accept",
        "reviewed_by": "Portable native review",
    }
    reviewed = service.review_receiver_defense(parent["job_id"], decision)
    execution = reviewed["phases"][0]["execution_job"]
    assert execution is not None, reviewed
    execution = service.job_controller.wait_for_state(
        execution["job_id"], {JobState.AWAITING_APPROVAL}, timeout=10
    )
    assert execution["state"] == "awaiting_approval", execution
    assert (
        service.review_receiver_defense(parent["job_id"], decision)["phases"][0]["execution_job"][
            "job_id"
        ]
        == execution["job_id"]
    )
    assert len(sessions) == 1 and runner.execute_calls == 0 and not access.calls
    assert service.active_jobs()["jobs"][0]["job_id"] == execution["job_id"]
    # Runs must review the retained submission report. Posting this public job's
    # request to generic preflight does not adopt its private receiver authority.
    public_job = service.job(execution["job_id"])
    stored = public_job["request"]["_run_submission_preflight"]
    assert stored == envelope["phases"][0]["preparation"]["preflight"]
    binding_fields = (
        "state_digest",
        "plan_digest",
        "profile_id",
        "target_scope_digest",
        "maximum_tier",
    )
    approval_binding = {key: public_job["approval_request"][key] for key in binding_fields}
    assert {key: stored["approval_binding"][key] for key in binding_fields} == approval_binding
    ordinary = service.preflight(public_job["request"])
    assert ordinary["approval_binding"]["state_digest"] != approval_binding["state_digest"]
    assert all(
        ordinary["approval_binding"][key] == approval_binding[key]
        for key in binding_fields
        if key != "state_digest"
    )
    # The server-side approval path supplies the exact retained marker and
    # revalidates the live session, reproducing the original reviewed binding.
    canonical = service.preflight(
        public_job["request"], _receiver_defense=public_job["request"]["receiver_defense"]
    )
    assert canonical["approval_binding"] == stored["approval_binding"]
    assert service.job(execution["job_id"])["request"]["_run_submission_preflight"] == stored
    assert not sessions[0].tasks and runner.execute_calls == 0 and not access.calls
    (service.store.root.parent / "receiver-approval-projection.json").write_text(
        json.dumps({"job": public_job, "ordinary": ordinary, "canonical": canonical}),
        encoding="utf-8",
    )
    (service.store.root.parent / "native-contract.json").write_text(
        json.dumps(
            {
                "fixture_kind": "portable service/controller with owned-process test double; no effects or model",
                "context": service.receiver_defense_context(request),
                "prepare_request": prepare_request,
                "ready": envelope,
                "decision": decision,
                "awaiting_approval": service.receiver_defense_job(parent["job_id"]),
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    service.cancel_job(parent["job_id"])
    service.job_controller.wait(execution["job_id"], timeout=10)
    assert sessions[0].closed and runner.execute_calls == 0


def test_explicit_decline_closes_owned_receiver_without_creating_run(setup):
    service, access, runner, sessions, request = setup
    parent, _, envelope = prepared(setup)
    decision = {
        "submission_id": str(uuid.uuid4()),
        "phase": "baseline",
        "preparation_digest": envelope["phases"][0]["preparation"]["preparation_digest"],
        "decision": "reject",
        "reviewed_by": "Portable native review",
    }
    declined = service.review_receiver_defense(parent["job_id"], decision)
    assert declined["phases"][0]["status"] == "declined"
    assert declined["phases"][0]["execution_job"] is None and sessions[0].closed
    assert not service.store.list_runs() and not access.calls


def test_saved_graph_change_is_refused_without_receiver_prepare(setup):
    service, access, runner, sessions, request = setup
    stale = copy.deepcopy(request)
    stale["selection"]["digest"] = "sha256:" + "0" * 64
    with pytest.raises(APIError):
        service.receiver_defense_context(stale)
    assert not sessions and not access.calls


def test_full_three_phase_ordinary_run_replay_retains_independent_policy_results(
    setup, monkeypatch
):
    service, access, _, sessions, request = setup
    runner = FixtureRunner(sessions)
    original_factory = service.runner_factory
    sandbox = original_factory(None)[1]
    service.runner_factory = lambda _profile: (runner, sandbox)
    errors = []
    from bluefire import receiver_defense_native, receiver_defense_view

    before_publish, publish, published, finish = (threading.Event() for _ in range(4))
    original_update = records.update

    def hold_final_publication(store, child_id, values, **kwargs):
        final = values.get("result", {}).get("phase") == "restored"
        if final:
            before_publish.set()
            assert publish.wait(10), "Final result publication was not released."
        result = original_update(store, child_id, values, **kwargs)
        if final:
            published.set()
            assert finish.wait(10), "Final execution callback was not released."
        return result

    monkeypatch.setattr(records, "update", hold_final_publication)

    original_execute = receiver_defense_native.finish

    def execute(*args):
        try:
            return original_execute(*args)
        except Exception:
            errors.append(traceback.format_exc())
            (service.store.root.parent / "execution-error.txt").write_text(
                errors[-1], encoding="utf-8"
            )
            raise

    monkeypatch.setattr(receiver_defense_native, "finish", execute)
    parent, _, envelope = prepared(setup)
    snapshots = []
    publication_windows = {}
    for index, phase in enumerate(("baseline", "protected", "restored")):
        if index:
            submit = {
                "submission_id": str(uuid.uuid4()),
                "phase": phase,
                "reviewed_by": "Portable native review",
            }
            service.prepare_receiver_defense(parent["job_id"], submit)
            child = service.job_controller.wait(
                "job-" + uuid.UUID(submit["submission_id"]).hex, timeout=15
            )
            assert child["state"] == "completed", child
            envelope = service.receiver_defense_job(parent["job_id"])
        current = envelope["phases"][index]
        reviewed = service.review_receiver_defense(
            parent["job_id"],
            {
                "submission_id": str(uuid.uuid4()),
                "phase": phase,
                "preparation_digest": current["preparation"]["preparation_digest"],
                "decision": "accept",
                "reviewed_by": "Portable native review",
            },
        )
        execution = reviewed["phases"][index]["execution_job"]
        execution = service.job_controller.wait_for_state(
            execution["job_id"], {JobState.AWAITING_APPROVAL}, timeout=10
        )
        service.approve_job(execution["job_id"], {"approved_by": "Portable native review"})
        if phase == "restored":
            try:
                assert before_publish.wait(10), errors
                child_id = current["receiver_job"]["job_id"]
                original_visible = receiver_defense_view.visible_job

                def publish_after_child_read(
                    coordinator, identifier, *, read=original_visible, target=child_id
                ):
                    snapshot = read(coordinator, identifier)
                    if identifier == target:
                        assert snapshot["progress"].get("result") is None
                        publish.set()
                        assert published.wait(10)
                    return snapshot

                with monkeypatch.context() as window:
                    window.setattr(receiver_defense_view, "visible_job", publish_after_child_read)
                    publication_windows["old_child_after_publication"] = (
                        service.receiver_defense_job(parent["job_id"])
                    )
                assert (
                    publication_windows["old_child_after_publication"]["phases"][2]["result"]
                    is None
                )
                publication_windows["published_before_terminal"] = service.receiver_defense_job(
                    parent["job_id"]
                )
                pending = publication_windows["published_before_terminal"]
                assert pending["status"] == "active" and not pending["can_start_new_test"]
                assert pending["phases"][2]["result"] is not None
                assert pending["phases"][2]["execution_job"]["state"] == "running"

                def finish_after_execution_read(
                    coordinator, identifier, *, read=original_visible, target=execution["job_id"]
                ):
                    snapshot = read(coordinator, identifier)
                    if identifier == target:
                        assert snapshot["state"] == "running"
                        finish.set()
                        assert (
                            service.job_controller.wait(identifier, timeout=10)["state"]
                            == "completed"
                        )
                    return snapshot

                with monkeypatch.context() as window:
                    window.setattr(
                        receiver_defense_view, "visible_job", finish_after_execution_read
                    )
                    publication_windows["old_execution_after_terminal"] = (
                        service.receiver_defense_job(parent["job_id"])
                    )
                mixed = publication_windows["old_execution_after_terminal"]
                assert mixed["status"] == "active" and not mixed["can_start_new_test"]
                assert mixed["phases"][2]["execution_job"]["state"] == "running"
            finally:
                publish.set()
                finish.set()
        terminal = service.job_controller.wait(execution["job_id"], timeout=20)
        assert terminal["state"] == "completed", (terminal["error"], errors)
        envelope = service.receiver_defense_job(parent["job_id"])
        assert envelope["phases"][index]["status"] == "completed", envelope
        snapshots.append(envelope)
    assert envelope["status"] == "completed" and envelope["can_start_new_test"]
    assert [item["result"]["decision"] for item in envelope["phases"]] == [
        "accepted",
        "policy_refused",
        "accepted",
    ]
    assert len({item["result"]["artifact"]["sha256"] for item in envelope["phases"]}) == 1
    assert all(session.closed and len(session.tasks) == 1 for session in sessions)
    assert len(service.store.list_runs()) == 3 and not access.calls
    (service.store.root.parent / "native-three-phase-contract.json").write_text(
        json.dumps(
            {
                "fixture_kind": "portable native protocol doubles; no real receiver process, transport, or defense proof",
                "context": service.receiver_defense_context(request),
                "phases": snapshots,
                "publication_windows": publication_windows,
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


@pytest.mark.parametrize("missing", [False, True])
def test_stale_admission_is_durable_readable_and_cannot_prepare(setup, missing):
    service, access, runner, sessions, request = setup
    current = service.receiver_defense_context(request)
    submitted = {
        **copy.deepcopy(request),
        "submission_id": str(uuid.uuid4()),
        "context_digest": current["context_digest"],
    }
    if missing:
        submitted["selection"]["scenario_id"] = "scenario.absent.v1"
    else:
        submitted["context_digest"] = "sha256:" + "0" * 64
    refused = service.submit_receiver_defense(submitted)
    assert refused["job"]["state"] == "failed" and refused["status"] == "blocked"
    assert refused["admission"] == refused["job"]["progress"]["admission"]
    assert not refused["admission"]["accepted"] and refused["admission"]["problem"]
    assert refused["job"]["request"]["submitted_request"] == submitted
    assert (refused["context"] is None) == missing
    assert refused["can_start_new_test"]
    assert all(
        not row["prepare_allowed"] and row["receiver_job"] is None for row in refused["phases"]
    )
    assert service.submit_receiver_defense(submitted) == refused
    with pytest.raises(APIError):
        service.prepare_receiver_defense(
            refused["job"]["job_id"],
            {"submission_id": str(uuid.uuid4()), "phase": "baseline", "reviewed_by": "Reviewer"},
        )
    assert not sessions and not access.calls and runner.execute_calls == 0
    (service.store.root.parent / "native-refused-contract.json").write_text(
        json.dumps(refused), encoding="utf-8"
    )


def test_stop_wins_native_approval_release_without_dispatch(setup):
    service, access, runner, sessions, request = setup
    parent, _, envelope = prepared(setup)
    decision = {
        "submission_id": str(uuid.uuid4()),
        "phase": "baseline",
        "preparation_digest": envelope["phases"][0]["preparation"]["preparation_digest"],
        "decision": "accept",
        "reviewed_by": "Reviewer",
    }
    execution = service.review_receiver_defense(parent["job_id"], decision)["phases"][0][
        "execution_job"
    ]
    service.job_controller.wait_for_state(
        execution["job_id"], {JobState.AWAITING_APPROVAL}, timeout=10
    )
    records.stop(service.product_store, parent["job_id"])
    with pytest.raises((APIError, ProductStoreError)):
        service.approve_job(execution["job_id"], {"approved_by": "Reviewer"})
    service.cancel_job(parent["job_id"])
    assert runner.execute_calls == 0 and not sessions[0].tasks and not access.calls


def test_stop_during_owned_prepare_closes_late_owner_without_publication(setup):
    service, access, runner, sessions, request = setup
    entered, release = threading.Event(), threading.Event()
    factory = service.receiver_defense.owners.factory

    def held(*args, **kwargs):
        entered.set()
        assert release.wait(10)
        return factory(*args, **kwargs)

    service.receiver_defense.owners.factory = held
    current = service.receiver_defense_context(request)
    parent = service.submit_receiver_defense(
        {**request, "submission_id": str(uuid.uuid4()), "context_digest": current["context_digest"]}
    )["job"]
    service.job_controller.wait(parent["job_id"], timeout=10)
    submit = {"submission_id": str(uuid.uuid4()), "phase": "baseline", "reviewed_by": "Reviewer"}
    try:
        service.prepare_receiver_defense(parent["job_id"], submit)
        assert entered.wait(5)
        service.cancel_job(parent["job_id"])
        stopped = service.receiver_defense_job(parent["job_id"])
        assert not stopped["can_start_new_test"] and stopped["status"] == "stopping"
    finally:
        release.set()
    service.job_controller.wait("job-" + uuid.UUID(submit["submission_id"]).hex, timeout=10)
    stopped = service.receiver_defense_job(parent["job_id"])
    assert stopped["status"] == "stopped" and stopped["can_start_new_test"]
    assert sessions[0].closed and stopped["phases"][0]["preparation"] is None
    assert runner.execute_calls == 0 and not access.calls


def test_expired_unused_attempt_needs_explicit_prepare_and_retains_old_exact_decision(setup):
    service, access, runner, sessions, request = setup
    parent, _, envelope = prepared(setup)
    decision = {
        "submission_id": str(uuid.uuid4()),
        "phase": "baseline",
        "preparation_digest": envelope["phases"][0]["preparation"]["preparation_digest"],
        "decision": "accept",
        "reviewed_by": "Reviewer",
    }
    execution = service.review_receiver_defense(parent["job_id"], decision)["phases"][0][
        "execution_job"
    ]
    service.job_controller.wait_for_state(
        execution["job_id"], {JobState.AWAITING_APPROVAL}, timeout=10
    )
    sessions[0].expired = True
    with pytest.raises((APIError, ValueError)):
        service.approve_job(execution["job_id"], {"approved_by": "Reviewer"})
    submit = {"submission_id": str(uuid.uuid4()), "phase": "baseline", "reviewed_by": "Reviewer"}
    service.prepare_receiver_defense(parent["job_id"], submit)
    service.job_controller.wait("job-" + uuid.UUID(submit["submission_id"]).hex, timeout=10)
    current = service.receiver_defense_job(parent["job_id"])
    assert len(current["phases"][0]["attempts"]) == 1 and sessions[0].closed
    assert len(sessions) == 2 and not sessions[1].closed
    assert service.review_receiver_defense(parent["job_id"], decision) == current
    assert not access.calls and runner.execute_calls == 0


def test_lost_ownership_never_adopts_durable_pid_or_repeats_prepare(setup):
    service, access, runner, sessions, request = setup
    parent, prepare_request, envelope = prepared(setup)
    owners = service.receiver_defense.owners
    retained = owners._owners.pop(envelope["phases"][0]["receiver_job"]["job_id"])
    try:
        view = service.receiver_defense_job(parent["job_id"])
        assert not view["phases"][0]["review_ready"] and not view["can_start_new_test"]
        service.prepare_receiver_defense(parent["job_id"], prepare_request)
        with pytest.raises(APIError):
            service.prepare_receiver_defense(
                parent["job_id"], {**prepare_request, "submission_id": str(uuid.uuid4())}
            )
        assert len(sessions) == 1 and runner.execute_calls == 0
    finally:
        owners._owners[envelope["phases"][0]["receiver_job"]["job_id"]] = retained


def test_shutdown_reports_failed_cleanup_and_attempts_every_exact_owner(setup, monkeypatch):
    service, access, runner, sessions, request = setup
    parent, _, first = prepared(setup)
    second_parent, _, second = prepared(setup)
    original_close = sessions[0].close
    monkeypatch.setattr(sessions[0], "close", lambda: False)
    with pytest.raises(ProductStoreError, match="verified cleanup"):
        service.close()
    assert sessions[1].closed and not sessions[0].closed
    assert first["phases"][0]["receiver_job"]["job_id"] in service.receiver_defense.owners._owners
    assert (
        second["phases"][0]["receiver_job"]["job_id"] not in service.receiver_defense.owners._owners
    )
    monkeypatch.setattr(sessions[0], "close", original_close)


def baseline_execution(setup, *, configure=None):
    service, access, _, sessions, request = setup
    runner = FixtureRunner(sessions)
    sandbox = service.runner_factory(None)[1]
    service.runner_factory = lambda _profile: (runner, sandbox)
    parent, _, ready = prepared(setup)
    if configure:
        configure(runner, sessions[0])
    reviewed = service.review_receiver_defense(
        parent["job_id"],
        {
            "submission_id": str(uuid.uuid4()),
            "phase": "baseline",
            "preparation_digest": ready["phases"][0]["preparation"]["preparation_digest"],
            "decision": "accept",
            "reviewed_by": "Reviewer",
        },
    )
    identifier = reviewed["phases"][0]["execution_job"]["job_id"]
    service.job_controller.wait_for_state(identifier, {JobState.AWAITING_APPROVAL}, timeout=10)
    service.approve_job(identifier, {"approved_by": "Reviewer"})
    terminal = service.job_controller.wait(identifier, timeout=20)
    return parent, terminal, service.receiver_defense_job(parent["job_id"])


def test_later_exact_cleanup_preserves_initial_result_and_allows_read(setup):
    service, access, runner, sessions, request = setup
    original = []

    def configure(_runner, session):
        original.append(session.close)
        session.close = lambda: False

    parent, terminal, initial = baseline_execution(setup, configure=configure)
    phase = initial["phases"][0]
    assert terminal["state"] == "completed" and phase["result"]["decision"] == "accepted"
    assert phase["cleanup"]["receiver"] == "uncertain" and not initial["can_start_new_test"]
    child_id = phase["receiver_job"]["job_id"]
    retained = service.product_store.get_job(child_id)["progress"]["result"]
    sessions[0].close = original[0]
    service.cancel_job(parent["job_id"])
    settled = service.receiver_defense_job(parent["job_id"])
    assert settled["status"] == "stopped" and settled["can_start_new_test"]
    assert settled["phases"][0]["cleanup"]["receiver"] == "verified_closed"
    assert settled["phases"][0]["result"]["cleanup_at_finalization"]["receiver"] == "uncertain"
    assert service.product_store.get_job(child_id)["progress"]["result"] == retained
    assert len(service.store.list_runs()) == 1 and not access.calls


@pytest.mark.parametrize("reason", ["invalid_content", "lifecycle_timeout"])
def test_honest_insufficient_terminal_keeps_finalized_native_run(setup, reason):
    service, access, runner, sessions, request = setup

    def configure(_runner, session):
        original = session.wait_observation

        def observation(**kwargs):
            value = copy.deepcopy(original(**kwargs))
            value["state"] = "insufficient_evidence"
            value["terminal"]["summary"]["requests_accepted"] = 0
            if reason == "invalid_content":
                value["terminal"]["summary"]["requests_refused"] = 1
                value["terminal"]["decision"].update(
                    decision="invalid_content",
                    reason="malformed_unsupported_or_incomplete",
                    semantics=None,
                )
            else:
                value["terminal"]["summary"]["reason"] = reason
                value["terminal"]["decision"] = None
            return value

        session.wait_observation = observation

    parent, terminal, result = baseline_execution(setup, configure=configure)
    assert terminal["state"] == "completed" and terminal["result_ref"]
    phase = result["phases"][0]
    assert phase["result"]["run_id"] == terminal["result_ref"]
    assert (
        phase["result"]["decision"] == "insufficient_evidence"
        and phase["result"]["artifact"] is None
    )
    assert not result["phases"][1]["prepare_allowed"]
    assert len(service.store.list_runs()) == 1 and not access.calls


def test_result_tampering_refuses_read_without_repeating_effects(setup):
    service, access, runner, sessions, request = setup
    parent, terminal, result = baseline_execution(setup)
    child = result["phases"][0]["receiver_job"]
    stored = service.product_store.get_job(child["job_id"])["progress"]["result"]
    changed = copy.deepcopy(stored)
    changed["artifact"]["sha256"] = "0" * 64
    records.update(
        service.product_store,
        child["job_id"],
        {"result": changed, "result_digest": content_hash(changed)},
    )
    with pytest.raises(APIError):
        service.receiver_defense_job(parent["job_id"])
    assert len(service.store.list_runs()) == 1 and len(sessions) == 1 and not access.calls


def test_receiver_closed_does_not_hide_unknown_run_cleanup(setup):
    service, access, runner, sessions, request = setup
    parent, _, ready = prepared(setup)
    child = ready["phases"][0]["receiver_job"]
    records.update(service.product_store, child["job_id"], {"execution_started": True})
    service.cancel_job(parent["job_id"])
    stopped = service.receiver_defense_job(parent["job_id"])
    assert sessions[0].closed and stopped["phases"][0]["cleanup"]["receiver"] == "verified_closed"
    assert stopped["phases"][0]["cleanup"]["run"] == "pending"
    assert stopped["status"] == "stopping" and not stopped["can_start_new_test"]


@pytest.mark.parametrize("fail", [False, True])
def test_pending_and_callback_admission_refusal_are_canonically_bound(setup, monkeypatch, fail):
    service, access, runner, sessions, request = setup
    entered, release = threading.Event(), threading.Event()
    original = service.receiver_defense._fresh

    def held(parent):
        entered.set()
        assert release.wait(10)
        if fail:
            raise ProductStoreError("Private changed-context fixture")
        return original(parent)

    monkeypatch.setattr(service.receiver_defense, "_fresh", held)
    current = service.receiver_defense_context(request)
    submitted = {
        **request,
        "submission_id": str(uuid.uuid4()),
        "context_digest": current["context_digest"],
    }
    try:
        pending = service.submit_receiver_defense(submitted)
        assert entered.wait(5)
        assert (
            pending["admission"]
            == pending["job"]["progress"]["admission"]
            == {"accepted": False, "problem": None}
        )
        assert not any(item["prepare_allowed"] for item in pending["phases"])
        (service.store.root.parent / "native-pending-contract.json").write_text(
            json.dumps(pending), encoding="utf-8"
        )
    finally:
        release.set()
    service.job_controller.wait(pending["job"]["job_id"], timeout=10)
    settled = service.receiver_defense_job(pending["job"]["job_id"])
    assert settled["job"]["state"] == ("failed" if fail else "completed")
    assert settled["admission"]["accepted"] is (not fail)
    assert not sessions and not access.calls
    (service.store.root.parent / "native-admission-contract.json").write_text(
        json.dumps(settled), encoding="utf-8"
    )


def test_partial_factory_failure_retains_exact_attempt_and_verified_cleanup(setup, monkeypatch):
    from bluefire import receiver_session as session_module

    service, access, runner, sessions, request = setup
    monkeypatch.setattr(session_module, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(session_module.LinuxPrivateProcessContainment, "available", lambda: True)

    def refused(_launch, _sink):
        raise RuntimeError("Portable failure before process construction")

    monkeypatch.setattr(session_module, "_spawn_owned_worker", refused)
    service.receiver_defense = ReceiverDefenseJobs(service)
    current = service.receiver_defense_context(request)
    parent = service.submit_receiver_defense(
        {**request, "submission_id": str(uuid.uuid4()), "context_digest": current["context_digest"]}
    )["job"]
    service.job_controller.wait(parent["job_id"], timeout=10)
    submit = {"submission_id": str(uuid.uuid4()), "phase": "baseline", "reviewed_by": "Reviewer"}
    service.prepare_receiver_defense(parent["job_id"], submit)
    child = service.job_controller.wait("job-" + uuid.UUID(submit["submission_id"]).hex, timeout=10)
    assert child["state"] == "failed" and child["progress"]["startup_cleanup_verified"]
    view = service.receiver_defense_job(parent["job_id"])
    assert view["phases"][0]["cleanup"]["receiver"] == "verified_closed"
    assert view["phases"][0]["prepare_allowed"]
    assert not service.receiver_defense.owners._owners and not access.calls


def test_shutdown_includes_failed_construction_retained_pool(setup, monkeypatch):
    from bluefire import receiver_defense_ownership as ownership

    service, *_ = setup
    calls = []
    monkeypatch.setattr(
        ownership,
        "reconcile_retained_receiver_sessions",
        lambda: calls.append(True) or {"reconciled": 0, "remaining": 1},
    )
    with pytest.raises(ProductStoreError, match="verified cleanup"):
        service.close()
    assert calls == [True]
    monkeypatch.setattr(
        ownership, "reconcile_retained_receiver_sessions", lambda: {"reconciled": 1, "remaining": 0}
    )


def test_cancelled_native_run_without_finalization_keeps_cleanup_uncertain(setup):
    service, access, _, sessions, request = setup
    runner = FixtureRunner(sessions)
    entered, release = threading.Event(), threading.Event()
    original = runner.execute_task

    def held(manifest, profile, **kwargs):
        result = original(manifest, profile, **kwargs)
        if manifest["action_id"] == "sandbox.collection.stage.v1":
            entered.set()
            assert release.wait(10)
        return result

    runner.execute_task = held
    sandbox = service.runner_factory(None)[1]
    service.runner_factory = lambda _profile: (runner, sandbox)
    parent, _, ready = prepared(setup)
    accepted = service.review_receiver_defense(
        parent["job_id"],
        {
            "submission_id": str(uuid.uuid4()),
            "phase": "baseline",
            "preparation_digest": ready["phases"][0]["preparation"]["preparation_digest"],
            "decision": "accept",
            "reviewed_by": "Reviewer",
        },
    )
    identifier = accepted["phases"][0]["execution_job"]["job_id"]
    service.job_controller.wait_for_state(identifier, {JobState.AWAITING_APPROVAL}, timeout=10)
    try:
        service.approve_job(identifier, {"approved_by": "Reviewer"})
        assert entered.wait(10)
        service.cancel_job(parent["job_id"])
    finally:
        release.set()
    terminal = service.job_controller.wait(identifier, timeout=20)
    assert terminal["state"] == "cancelled" and terminal["result_ref"] is None
    current = service.receiver_defense_job(parent["job_id"])
    phase = current["phases"][0]
    assert phase["result"] is None and phase["cleanup"]["run"] == "pending"
    assert current["status"] == "stopping" and not current["can_start_new_test"]
    assert not phase["prepare_allowed"] and len(service.store.list_runs()) == 1
    assert not sessions[0].tasks and sessions[0].closed and not access.calls
    (service.store.root.parent / "native-cancelled-contract.json").write_text(
        json.dumps(current), encoding="utf-8"
    )


def test_competing_prepare_cannot_mark_running_attempt_closed(setup, monkeypatch):
    service, access, runner, sessions, request = setup
    entered, release = threading.Event(), threading.Event()
    original = service.preflight

    def held(*args, **kwargs):
        entered.set()
        assert release.wait(10)
        return original(*args, **kwargs)

    monkeypatch.setattr(service, "preflight", held)
    current = service.receiver_defense_context(request)
    parent = service.submit_receiver_defense(
        {**request, "submission_id": str(uuid.uuid4()), "context_digest": current["context_digest"]}
    )["job"]
    service.job_controller.wait(parent["job_id"], timeout=10)
    submit = {"submission_id": str(uuid.uuid4()), "phase": "baseline", "reviewed_by": "Reviewer"}
    identifier = "job-" + uuid.UUID(submit["submission_id"]).hex
    try:
        service.prepare_receiver_defense(parent["job_id"], submit)
        assert entered.wait(5)
        with pytest.raises(APIError):
            service.prepare_receiver_defense(
                parent["job_id"], {**submit, "submission_id": str(uuid.uuid4())}
            )
        assert not service.product_store.get_job(identifier)["progress"].get("receiver_closed")
        assert not sessions
    finally:
        release.set()
    child = service.job_controller.wait(identifier, timeout=10)
    assert child["state"] == "completed" and not child["progress"].get("receiver_closed")
    assert len(sessions) == 1 and not sessions[0].closed and not access.calls


def test_saved_owner_listing_prioritizes_unfinished_and_pages_all_history(setup):
    service, access, runner, sessions, request = setup
    current = service.receiver_defense_context(request)
    submitted = {
        **request,
        "submission_id": str(uuid.uuid4()),
        "context_digest": current["context_digest"],
    }
    active = service.submit_receiver_defense(submitted)["job"]
    service.job_controller.wait(active["job_id"], timeout=10)
    for _ in range(129):
        rejected = {
            **submitted,
            "submission_id": str(uuid.uuid4()),
            "context_digest": "sha256:" + "0" * 64,
        }
        records.refuse_admission(
            service.product_store,
            {
                "submitted_request": rejected,
                "context": current,
                "context_digest": rejected["context_digest"],
            },
            rejected["submission_id"],
            content_hash(rejected),
        )
    first = service.receiver_defense_jobs()
    assert len(first["jobs"]) == 128 and first["jobs"][0]["job_id"] == active["job_id"]
    assert first["truncated"] and first["next_cursor"] == first["jobs"][-1]["job_id"]
    second = service.receiver_defense_jobs(cursor=first["next_cursor"])
    assert len(second["jobs"]) == 2 and not second["truncated"] and second["next_cursor"] is None
    assert len({item["job_id"] for item in first["jobs"] + second["jobs"]}) == 130
    assert not sessions and not access.calls and runner.execute_calls == 0
