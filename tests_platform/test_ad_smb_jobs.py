"""Real local stores/controller with only synthetic AD executors, no Windows calls."""

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace

import pytest

from bluefire import ad_smb_results as results
from bluefire import product_store_ad_smb as records
from bluefire.ad_smb_contract import AdSmbError
from bluefire.ad_smb_execution import UnavailableAdSmbExecutor
from bluefire.ad_smb_jobs import AdSmbJobs
from bluefire.execution_contracts import execution_task_identity
from bluefire.job_runtime import JobWaitTimeout, RunJobController
from bluefire.product_store import ProductStore
from bluefire.run_store import RunStore
from bluefire.runner_contracts import seal_profile
from bluefire.util import content_hash
from tests_platform.test_ad_smb_acl import fixture, observe
from tests_platform.test_ad_smb_contract import NOW, pin

JOB_WAIT_TIMEOUT = 30
_SAFE_JOB_STATES = frozenset(
    {
        "queued",
        "planning",
        "running",
        "awaiting_approval",
        "paused",
        "cancelling",
        "completed",
        "failed",
        "cancelled",
        "interrupted",
    }
)
_SAFE_AD_PHASES = frozenset({"inspect", "baseline", "harden", "retest", "rollback", "audit"})


def wait_for_ad_job(controller, job_id):
    try:
        return controller.wait(job_id, timeout=JOB_WAIT_TIMEOUT)
    except JobWaitTimeout:
        snapshot = controller.snapshot(job_id)
        state = snapshot.get("state")
        state = state if isinstance(state, str) and state in _SAFE_JOB_STATES else "unknown"
        progress = snapshot.get("progress")
        phase = progress.get("phase") if isinstance(progress, dict) else None
        phase = phase if isinstance(phase, str) and phase in _SAFE_AD_PHASES else "unknown"
        raise AssertionError(
            f"AD test job did not reach a terminal state within {JOB_WAIT_TIMEOUT}s "
            f"(state={state!r}, phase={phase!r})"
        ) from None


class FakeExecutor:
    def __init__(self):
        self.scope, self.before, self.after = fixture()
        self.profiles = {
            role: seal_profile(
                {
                    "schema_version": "bluefire.runner-profile.v1",
                    "profile_id": "ad-" + role,
                    "runner_id": "bluefire-rust-runner.v1",
                    "platform": "windows",
                    "sandbox_root": "C:\\BlueFire\\owned",
                    "allowed_actions": [results.ACTION],
                    "control_blocked_actions": [],
                    "capabilities": ["ad_smb_access"],
                    "max_safety_tier": "controlled",
                    "approval_required_at_or_above": "safe",
                    "target_scope": {"filesystem": [], "network": []},
                    "limits": {
                        "timeout_ms": 60000,
                        "output_bytes": 65536,
                        "files": 2,
                        "bytes": 1024,
                    },
                    "policy_digest": "",
                }
            )
            for role in ("member", "client")
        }
        self.selected = {
            "environment_id": "ad-env-" + "a" * 32,
            "scope": self.scope.to_dict(),
            "principal_binding_digest": pin("9"),
            "provenance": "synthetic_fixture",
            **{
                role: {
                    "runner_profile_id": profile["profile_id"],
                    "host_id": self.scope.to_dict()["hosts"][role]["host_id"],
                    "native_generation": pin("8"),
                    "profile_digest": profile["policy_digest"],
                    "channel_digest": pin("7"),
                }
                for role, profile in self.profiles.items()
            },
        }
        self.ready = {
            "available": True,
            "member_observation": True,
            "client_read_admission": True,
            "secret_channel_available": True,
            "problem": None,
            "binding_digest": pin("6"),
        }
        self.calls = []
        self.recovered = []
        self.originals = {}
        self.crash = False
        self.entered = threading.Event()
        self.release = threading.Event()
        self.hold = False
        self.luid = 0

    def environments(self):
        return [deepcopy(self.selected)]

    def readiness(self, scope):
        assert scope.digest == self.scope.digest
        return deepcopy(self.ready)

    def original(self, request):
        profile = self.profiles["client" if request["target"] else "member"]
        manifest = results.execution_manifest(request, profile)
        task, request_hash = execution_task_identity(manifest, profile)
        return {
            "schema_version": "bluefire.ad-smb-original-task.v1",
            "request_digest": content_hash(request),
            "task_id": task,
            "transport_request_hash": request_hash,
            "manifest": manifest,
            "profile": profile,
            "transport_identity": request["host"],
        }

    def terminal(self, request):
        step = request["step"]
        if step == "inspect_member":
            observation = {"snapshot": self.before, "after_descriptor": self.after}
        elif step in {"harden_share", "rollback_share"}:
            observation = {
                "state": "readback_matched",
                "snapshot": observe(
                    self.scope, self.after if step == "harden_share" else self.before["descriptor"]
                ),
            }
        elif step == "collect_audit":
            observation = {
                "source_digest": pin("e"),
                "events": 9,
                "truncated": False,
                "authenticated_source": False,
                "independent_observation": False,
                "effective_access_claim": False,
            }
        else:
            self.luid += 1
            target = request["target"]
            denied = request["phase"] == "retest" and target["reader"] == "probe"
            observation = {
                "request_id": request["request_id"],
                "scope_digest": request["scope_digest"],
                "reader": target["reader"],
                "purpose": target["file"]["purpose"],
                "expected_remote_sid": target["expected_remote_sid"],
                "state": "open_access_denied" if denied else "bytes_matched",
                **{
                    key: None if denied else target["file"][key]
                    for key in ("volume_serial", "file_id", "sha256")
                },
                "bytes_read": 0 if denied else target["file"]["size_bytes"],
                "local_user_sid": "S-1-5-18",
                "local_authentication_id": f"{self.luid:016x}",
                "local_cleanup": "verified",
                "server_session_closed": None,
                "authenticated_remote_reader": False,
                "fresh_server_logon": False,
                "independent_observation": False,
                "effective_access_claim": False,
            }
        return {
            "schema_version": "bluefire.ad-smb-execution.v1",
            "request_digest": content_hash(request),
            "provenance": "synthetic_fixture",
            "dispatch": "attempted",
            "cleanup": "verified",
            "observation": observation,
        }

    def execute(self, request, *, cancellation_event, before_dispatch):
        self.entered.set()
        if self.hold:
            assert self.release.wait(5)
        if cancellation_event.is_set():
            return {
                "schema_version": "bluefire.ad-smb-execution.v1",
                "request_digest": content_hash(request),
                "provenance": "synthetic_fixture",
                "dispatch": "not_started",
                "cleanup": "verified",
                "observation": None,
            }
        before_dispatch(self.original(request))
        self.calls.append(deepcopy(request))
        execution = self.terminal(request)
        self.originals[request["request_id"]] = deepcopy(execution)
        if self.crash:
            raise RuntimeError("Authored loss of terminal delivery after original checkpoint")
        return execution

    def recover_original(self, request, context):
        assert context == self.original(request)
        self.recovered.append(deepcopy(request))
        return {"status": "terminal", "execution": deepcopy(self.originals[request["request_id"]])}


@pytest.fixture
def workspace(tmp_path):
    store = ProductStore(tmp_path / "product.db")
    runs = RunStore(tmp_path / "runs")
    controller = RunJobController(store, max_workers=1)
    service = SimpleNamespace(product_store=store, store=runs, job_controller=controller)
    executor = FakeExecutor()
    jobs = AdSmbJobs(service, executor, clock=lambda: NOW)
    yield jobs, executor, service
    executor.release.set()
    controller.shutdown()


def create(jobs):
    return jobs.create(
        {"submission_id": str(uuid.uuid4()), "environment_id": "ad-env-" + "a" * 32}
    )["workflow"]["job_id"]


def submit(jobs, identifier, phase, *, wait=True):
    review = jobs.review(identifier, phase)
    request = {
        "submission_id": str(uuid.uuid4()),
        "phase": phase,
        "review_digest": review["review_digest"],
        "reviewed_by": "fixture-operator",
    }
    child = jobs.submit(identifier, request)
    if wait:
        child = wait_for_ad_job(jobs.controller, child["job_id"])
    return child, request


def test_unavailable_production_path_has_no_fake_readiness(workspace):
    _jobs, _executor, service = workspace
    jobs = AdSmbJobs(service, clock=lambda: NOW)
    assert isinstance(jobs.executor, UnavailableAdSmbExecutor)
    assert jobs.environments() == {"environments": [], "native_execution_available": False}
    with pytest.raises(AdSmbError, match="prerequisites"):
        create(jobs)


def test_full_saved_workflow_preserves_truthful_fixture_evidence(workspace):
    jobs, executor, service = workspace
    identifier = create(jobs)
    assert jobs.read(identifier)["allowed_phases"] == ["inspect"]
    for phase in ("inspect", "baseline", "harden", "retest", "rollback", "audit"):
        child, request = submit(jobs, identifier, phase)
        assert child["state"] == "completed", child
        assert jobs.submit(identifier, request)["job_id"] == child["job_id"]
        run_id = child["result_ref"]
        assert service.store.validate_bundle(run_id)["valid"]
        final = service.store.read_json(run_id, "result.json")
        assert (
            final["objective_reached"] is False
            and final["ad_outcome"]["effective_access_claim"] is False
        )
        assert final["mode"] == "simulate"
        evidence = service.store.read_json(run_id, "evidence.json")["records"]
        assert all(row["provenance"] == "synthetic" for row in evidence)
    owner = jobs.read(identifier)
    assert owner["workflow"]["progress"]["policy_state"] == "baseline"
    assert owner["workflow"]["progress"]["pending_operation"] is None
    assert owner["remaining"] == {
        "business_attempts": 0,
        "sessions": 0,
        "share_changes": 0,
        "rollbacks": 0,
    }
    assert len(executor.calls) == 10


def test_original_result_recovery_does_not_rediscover_or_redispatch(workspace):
    jobs, executor, service = workspace
    identifier = create(jobs)
    executor.crash = True
    child, _ = submit(jobs, identifier, "inspect")
    assert child["state"] == "failed"
    assert child["progress"]["tasks"][0]["execution"] is None
    service.store.recover_interrupted_runs()
    jobs.clock = lambda: NOW + timedelta(days=10)
    executor.environments = lambda: pytest.fail("Recovery must not rediscover admission")
    recovered = jobs.recover(identifier)
    assert len(executor.calls) == 1 and len(executor.recovered) == 1
    assert recovered["workflow"]["progress"]["operations"][0]["outcome"]["state"] == "complete"
    run_id = child["progress"]["run_id"]
    assert service.store.validate_bundle(run_id)["valid"]
    assert [row["event_type"] for row in service.store.read_events(run_id)] == [
        "run.created",
        "run.interrupted",
        "run.finalized",
    ]
    assert jobs.recover(identifier) == recovered


@pytest.mark.parametrize(
    "name", ["evidence.json", "detections.json", "result.json", "manifest.json"]
)
def test_partial_publication_is_retained_not_overwritten(workspace, monkeypatch, name):
    jobs, _executor, service = workspace
    identifier = create(jobs)
    real = service.store.write_json
    tripped = False

    def fail_after_write(run_id, filename, value):
        nonlocal tripped
        result = real(run_id, filename, value)
        if filename == name and (name != "result.json" or value.get("ad_outcome")) and not tripped:
            # Initial empty files must be created before injecting publication loss.
            if (
                filename in {"evidence.json", "detections.json"}
                and not service.product_store.get_job(identifier)["progress"]["pending_operation"]
            ):
                return result
            if filename == "evidence.json" and not value.get("records"):
                return result
            if (
                filename == "detections.json"
                and not service.store.read_json(run_id, "evidence.json")["records"]
            ):
                return result
            tripped = True
            raise OSError("Authored publication interruption")
        return result

    monkeypatch.setattr(service.store, "write_json", fail_after_write)
    child, _ = submit(jobs, identifier, "inspect")
    assert child["state"] == "failed" and tripped
    monkeypatch.setattr(service.store, "write_json", real)
    if name == "manifest.json":
        assert jobs.recover(identifier)["workflow"]["progress"]["pending_operation"] is None
    else:
        path = service.store._run_path(child["progress"]["run_id"], must_exist=True)
        before = {item.name: item.read_bytes() for item in path.iterdir()}
        with pytest.raises(AdSmbError, match="partial|changed"):
            jobs.recover(identifier)
        assert {item.name: item.read_bytes() for item in path.iterdir()} == before


def test_stale_review_and_changed_enrollment_refuse_before_dispatch(workspace):
    jobs, executor, _service = workspace
    identifier = create(jobs)
    review = jobs.review(identifier, "inspect")
    request = {
        "submission_id": str(uuid.uuid4()),
        "phase": "inspect",
        "review_digest": pin("0"),
        "reviewed_by": "fixture",
    }
    with pytest.raises(AdSmbError, match="changed AD stage"):
        jobs.submit(identifier, request)
    request["review_digest"] = review["review_digest"]
    executor.selected["member"]["native_generation"] = pin("1")
    with pytest.raises(AdSmbError, match="changed after"):
        jobs.submit(identifier, request)
    assert executor.calls == []


def test_two_workspaces_share_resource_interlock_and_stop(workspace):
    jobs, executor, _service = workspace
    first, second = create(jobs), create(jobs)
    executor.hold = True
    child, _ = submit(jobs, first, "inspect", wait=False)
    assert executor.entered.wait(5)
    with pytest.raises(AdSmbError, match="Another saved AD"):
        submit(jobs, second, "inspect", wait=False)
    jobs.stop(first)
    executor.release.set()
    settled = jobs.controller.wait(child["job_id"], timeout=10)
    assert settled["state"] in {"completed", "cancelled"}
    assert executor.calls == []
    assert jobs.read(first)["workflow"]["progress"]["pending_operation"] is None


def test_original_task_context_mutation_refused_before_store_commit(workspace):
    jobs, executor, _service = workspace
    identifier = create(jobs)
    real = executor.original

    def changed(request):
        value = real(request)
        value["transport_identity"] = {**value["transport_identity"], "channel_digest": pin("0")}
        return value

    executor.original = changed
    child, _ = submit(jobs, identifier, "inspect")
    assert child["state"] == "failed"
    assert child["progress"]["tasks"] == [] and executor.calls == []


def test_store_negative_step_indexes_and_boolean_indexes_refused(workspace):
    jobs, executor, service = workspace
    identifier = create(jobs)
    executor.crash = True
    child, _ = submit(jobs, identifier, "inspect")
    execution = executor.originals[child["request"]["requests"][0]["request_id"]]
    for index in (-1, True, 1):
        with pytest.raises(AdSmbError, match="index"):
            records.record_terminal(service.product_store, child["job_id"], index, execution)


def test_dispatch_checkpoint_rechecks_deadline_after_executor_preparation(workspace):
    jobs, executor, _service = workspace
    identifier = create(jobs)
    original = executor.execute

    def delayed(request, **kwargs):
        jobs.clock = lambda: NOW + timedelta(seconds=61)
        return original(request, **kwargs)

    executor.execute = delayed
    child, _ = submit(jobs, identifier, "inspect")
    assert child["state"] == "failed"
    assert child["progress"]["tasks"] == [] and executor.calls == []


def test_two_instances_recovery_publication_does_not_overwrite(workspace):
    jobs, executor, service = workspace
    identifier = create(jobs)
    executor.crash = True
    child, _ = submit(jobs, identifier, "inspect")
    barrier = threading.Barrier(2)
    original = executor.recover_original

    def synchronized(request, context):
        value = original(request, context)
        barrier.wait(5)
        return value

    executor.recover_original = synchronized
    other_store = ProductStore(service.product_store.path)
    other_runs = RunStore(service.store.root)
    other = AdSmbJobs(
        SimpleNamespace(
            product_store=other_store, store=other_runs, job_controller=service.job_controller
        ),
        executor,
        clock=lambda: NOW,
    )

    def recover(instance):
        try:
            return instance.recover(identifier)
        except AdSmbError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(recover, instance) for instance in (jobs, other)]
        values = [future.result(timeout=10) for future in futures]
    assert any(value is not None for value in values)
    assert len(executor.calls) == 1
    owner = jobs.read(identifier)["workflow"]
    assert len(owner["progress"]["operations"]) == 1
    run_id = child["progress"]["run_id"]
    assert [event["event_type"] for event in service.store.read_events(run_id)] == [
        "run.created",
        "run.finalized",
    ]
    assert service.store.validate_bundle(run_id)["valid"]


def test_unknown_original_terminal_is_not_upgraded_by_a_second_result(workspace):
    jobs, executor, service = workspace
    identifier = create(jobs)
    original = executor.terminal

    def unknown(request):
        value = original(request)
        value["observation"] = None
        return value

    executor.terminal = unknown
    child, _ = submit(jobs, identifier, "inspect")
    assert child["state"] == "failed"
    request = child["request"]["requests"][0]
    with pytest.raises(AdSmbError, match="cannot be replaced"):
        records.record_recovery(
            service.product_store, child["job_id"], 0, executor.original(request), original(request)
        )
    with pytest.raises(AdSmbError, match="unsettled"):
        jobs.recover(identifier)
    assert jobs.read(identifier)["workflow"]["progress"]["pending_operation"] == child["job_id"]


def test_stop_preserves_explicit_rollback_after_change(workspace):
    jobs, _executor, _service = workspace
    identifier = create(jobs)
    for phase in ("inspect", "baseline", "harden"):
        assert submit(jobs, identifier, phase)[0]["state"] == "completed"
    stopped = jobs.stop(identifier)
    assert "retest" not in stopped["allowed_phases"]
    assert "rollback" in stopped["allowed_phases"]
    child, _ = submit(jobs, identifier, "rollback")
    assert child["state"] == "completed"
    assert jobs.read(identifier)["workflow"]["progress"]["policy_state"] == "baseline"


@pytest.mark.parametrize(
    "field,value",
    [
        ("effective_access_claim", True),
        ("authenticated_remote_reader", True),
        ("fresh_server_logon", True),
        ("independent_observation", True),
        ("server_session_closed", True),
        ("volume_serial", "0000000000000001"),
        ("volume_serial", 2**53 + 1),
        ("file_id", "9" * 32),
        ("bytes_read", 127),
        ("local_user_sid", "BA"),
        ("local_authentication_id", "0" * 16),
    ],
)
def test_normalized_read_projection_never_invents_effectiveness_or_identity(
    workspace, field, value
):
    jobs, executor, _service = workspace
    identifier = create(jobs)
    assert submit(jobs, identifier, "inspect")[0]["state"] == "completed"
    owner = jobs.read(identifier)["workflow"]
    review = results.review_document(owner, "baseline")
    request = results.request_for(
        owner,
        "baseline",
        "job-" + "1" * 32,
        0,
        NOW.isoformat(),
        (NOW + timedelta(seconds=60)).isoformat(),
        review,
        "fixture",
    )
    execution = executor.terminal(request)
    execution["observation"][field] = value
    with pytest.raises(AdSmbError):
        results.validate_execution(request, execution)


@pytest.mark.parametrize(
    "counterexample", ["probe_still_reads", "legitimate_denied", "reused_local_context"]
)
def test_known_retest_counterexample_is_published_and_allows_rollback(workspace, counterexample):
    jobs, executor, service = workspace
    identifier = create(jobs)
    for phase in ("inspect", "baseline", "harden"):
        assert submit(jobs, identifier, phase)[0]["state"] == "completed"
    original = executor.terminal

    def terminal(request):
        value = original(request)
        if request["phase"] != "retest":
            return value
        row, target = value["observation"], request["target"]
        if counterexample == "probe_still_reads" and target["reader"] == "probe":
            row.update(
                state="bytes_matched",
                bytes_read=target["file"]["size_bytes"],
                **{key: target["file"][key] for key in ("volume_serial", "file_id", "sha256")},
            )
        elif counterexample == "legitimate_denied" and target["reader"] == "legitimate":
            row.update(
                state="open_access_denied",
                bytes_read=0,
                volume_serial=None,
                file_id=None,
                sha256=None,
            )
        elif counterexample == "reused_local_context":
            row["local_authentication_id"] = "0000000000000001"
        return value

    executor.terminal = terminal
    child, _ = submit(jobs, identifier, "retest")
    assert child["state"] == "completed"
    outcome = child["progress"]["ad_outcome"]
    assert outcome["state"] == "complete"
    assert outcome["effective_access_claim"] is False
    if counterexample == "reused_local_context":
        assert outcome["distinct_local_contexts"] is False
    else:
        assert outcome["read_expectation"] == "not_met"
    assert service.store.validate_bundle(child["result_ref"])["valid"]
    assert "rollback" in jobs.read(identifier)["allowed_phases"]
    assert submit(jobs, identifier, "rollback")[0]["state"] == "completed"


def test_known_baseline_denial_is_not_unknown_and_cannot_authorize_hardening(workspace):
    jobs, executor, _service = workspace
    identifier = create(jobs)
    assert submit(jobs, identifier, "inspect")[0]["state"] == "completed"
    original = executor.terminal

    def denied(request):
        value = original(request)
        if request["step"] == "read_probe_primary":
            value["observation"].update(
                state="open_access_denied",
                bytes_read=0,
                volume_serial=None,
                file_id=None,
                sha256=None,
            )
        return value

    executor.terminal = denied
    child, _ = submit(jobs, identifier, "baseline")
    assert child["state"] == "completed"
    assert child["progress"]["ad_outcome"]["read_expectation"] == "not_met"
    owner = jobs.read(identifier)
    assert owner["workflow"]["progress"]["pending_operation"] is None
    assert "harden" not in owner["allowed_phases"]
