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
from bluefire.ad_smb_audit import normalize_events
from bluefire.ad_smb_contract import (
    MAX_AUDIT_EXECUTION_BYTES,
    MAX_DOCUMENT_BYTES,
    AdSmbError,
    AdSmbScope,
    timestamp,
)
from bluefire.ad_smb_execution import (
    AdSmbPreDispatchCancelled,
    AdSmbPreDispatchFailure,
    InstalledAdSmbExecutor,
    UnavailableAdSmbExecutor,
)
from bluefire.ad_smb_jobs import AdSmbJobs
from bluefire.execution_contracts import execution_task_identity
from bluefire.job_runtime import TERMINAL_JOB_STATES, JobCancelled, JobWaitTimeout, RunJobController
from bluefire.product_store import ProductStore
from bluefire.run_store import RunStore
from bluefire.runner_contracts import seal_profile
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_ad_smb_acl import fixture, observe
from tests_platform.test_ad_smb_audit import event as audit_event
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
_TERMINAL_JOB_STATE_NAMES = frozenset(state.value for state in TERMINAL_JOB_STATES)


def wait_for_ad_job(controller, job_id):
    try:
        return controller.wait(job_id, timeout=JOB_WAIT_TIMEOUT)
    except JobWaitTimeout:
        snapshot = controller.snapshot(job_id)
        state = snapshot.get("state")
        if isinstance(state, str) and state in _TERMINAL_JOB_STATE_NAMES:
            return snapshot
        state = state if isinstance(state, str) and state in _SAFE_JOB_STATES else "unknown"
        request = snapshot.get("request")
        ad_smb = request.get("ad_smb") if isinstance(request, dict) else None
        phase = ad_smb.get("phase") if isinstance(ad_smb, dict) else None
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


def installed_checkpoint_executor(fixture_executor, root):
    calls = []

    def execute_task(*_args, **_kwargs):
        calls.append("execute")
        raise AssertionError("Installed transport must not run before its durable checkpoint")

    client = SimpleNamespace(execute_task=execute_task)
    entry = SimpleNamespace(
        digest=pin("d"),
        client=lambda role: calls.append(("client", role)) or client,
        to_dict=lambda: {"profiles": fixture_executor.profiles},
    )
    installed = object.__new__(InstalledAdSmbExecutor)
    installed.root = root
    installed.environments = fixture_executor.environments
    installed.readiness = fixture_executor.readiness
    installed._identity = lambda _entry, role, _client: calls.append(("identity", role))
    installed._selected = lambda request: (
        calls.append("selected")
        or (entry, "client" if request["step"].startswith("read_") else "member")
    )
    installed.recover_original = lambda *_args, **_kwargs: calls.append("recover") or pytest.fail(
        "Controller-local recovery must not contact the installed receiver"
    )
    return installed, entry, calls


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
    assert "pre_dispatch_failure" not in child["progress"]
    request = child["request"]["requests"][0]
    task = child["progress"]["tasks"][0]
    controller_local = {
        "schema_version": "bluefire.ad-smb-execution.v1",
        "request_digest": content_hash(request),
        "provenance": "controller_local",
        "dispatch": "not_started",
        "cleanup": "verified",
        "observation": None,
    }
    with pytest.raises(AdSmbError, match="identity or state"):
        records.record_terminal(service.product_store, child["job_id"], 0, controller_local)
    with pytest.raises(AdSmbError, match="identity or state"):
        records.record_recovery(
            service.product_store, child["job_id"], 0, task["context"], controller_local
        )
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


def large_audit_observation(request):
    start = "2026-10-09T00:00:00.0000000Z"
    end = "2026-10-09T00:00:02.0000000Z"
    source_receipt = pin("c")
    raw_events = [
        audit_event(record_id=index + 1, when="2026-10-09T00:00:00.5000000Z")
        for index in range(600)
    ]
    scope = AdSmbScope.from_mapping(request["scope"])
    normalized = normalize_events(
        scope,
        raw_events,
        source_host_id=scope.to_dict()["hosts"]["member"]["host_id"],
        source_receipt_digest=source_receipt,
        capture_batch_digest=content_hash(
            {
                "source_receipt_digest": source_receipt,
                "channel": "Security",
                "window_start": start,
                "window_end": end,
            }
        ),
        window_start=start,
        window_end=end,
        completeness="complete",
    )
    normalized["capture_state"] = "query_exhausted"
    return {
        "source_digest": pin("e"),
        "events": len(raw_events),
        "truncated": False,
        "authenticated_source": False,
        "independent_observation": False,
        "effective_access_claim": False,
        "normalized_observation": normalized,
    }


def test_summary_list_omits_large_audit_without_changing_detail_or_saved_evidence(
    workspace, monkeypatch
):
    jobs, executor, service = workspace
    identifier = create(jobs)
    assert submit(jobs, identifier, "inspect")[0]["state"] == "completed"
    jobs.clock = lambda: NOW + timedelta(seconds=2)
    terminal = executor.terminal

    def audit_terminal(request):
        execution = terminal(request)
        execution["observation"] = large_audit_observation(request)
        return execution

    executor.terminal = audit_terminal
    assert submit(jobs, identifier, "audit")[0]["state"] == "completed"
    detail = jobs.read(identifier)
    stored = service.product_store.get_job(identifier)
    assert len(canonical_json_bytes(detail)) > MAX_DOCUMENT_BYTES
    observation = detail["workflow"]["progress"]["operations"][-1]["executions"][0]["observation"]
    assert len(observation["normalized_observation"]["events"]) == 600
    read = jobs.read

    def no_detail_or_host_work(*_args, **_kwargs):
        pytest.fail("Summary listing must not read detail, discover hosts or dispatch work")

    monkeypatch.setattr(jobs, "read", no_detail_or_host_work)
    for method in ("environments", "readiness", "execute", "recover_original"):
        monkeypatch.setattr(executor, method, no_detail_or_host_work)

    listed = jobs.list()

    selected = detail["workflow"]["request"]["environment"]
    progress = detail["workflow"]["progress"]
    assert listed == {
        "schema_version": "bluefire.ad-smb-workflow-list.v1",
        "effective_access_claim": False,
        "workflows": [
            {
                "workflow_job_id": identifier,
                "member": selected["scope"]["hosts"]["member"]["fqdn"],
                "provenance": selected["provenance"],
                "revision": progress["revision"],
                "stopped": progress["stopped"],
                "pending_operation": progress["pending_operation"],
                "policy_state": progress["policy_state"],
            }
        ],
    }
    assert len(canonical_json_bytes(listed)) < 1024
    assert canonical_json_bytes(read(identifier)) == canonical_json_bytes(detail)
    assert service.product_store.get_job(identifier) == stored


def test_summary_list_preserves_owner_order_and_pending_stopped_state(workspace):
    jobs, executor, _service = workspace
    first = create(jobs)
    second = create(jobs)
    jobs.stop(first)
    executor.crash = True
    child, _ = submit(jobs, second, "inspect")
    assert child["state"] == "failed"
    expected = records.list_owners(jobs.store)

    listed = jobs.list()["workflows"]

    assert [row["workflow_job_id"] for row in listed] == [row["job_id"] for row in expected]
    assert next(row for row in listed if row["workflow_job_id"] == first)["stopped"] is True
    assert next(row for row in listed if row["workflow_job_id"] == second)["stopped"] is False
    assert (
        next(row for row in listed if row["workflow_job_id"] == first)["pending_operation"] is None
    )
    assert (
        next(row for row in listed if row["workflow_job_id"] == second)["pending_operation"]
        == child["job_id"]
    )


def test_large_normalized_audit_recovery_after_restart_stays_read_only(workspace):
    jobs, executor, service = workspace
    identifier = create(jobs)
    assert submit(jobs, identifier, "inspect")[0]["state"] == "completed"
    jobs.clock = lambda: NOW + timedelta(seconds=2)
    terminal = executor.terminal

    def audit_terminal(request):
        execution = terminal(request)
        execution["observation"] = large_audit_observation(request)
        return execution

    executor.terminal = audit_terminal
    executor.crash = True
    child, _ = submit(jobs, identifier, "audit")
    assert child["state"] == "failed"
    assert child["progress"]["tasks"][0]["execution"] is None
    request = child["request"]["requests"][0]
    execution = executor.originals[request["request_id"]]
    assert MAX_DOCUMENT_BYTES < len(canonical_json_bytes(execution)) <= MAX_AUDIT_EXECUTION_BYTES
    assert results.validate_execution(request, execution) == execution
    calls = deepcopy(executor.calls)

    def no_new_work(*_args, **_kwargs):
        pytest.fail("Recovery must not rediscover admission or dispatch work")

    executor.environments = executor.readiness = executor.execute = no_new_work
    reopened_store = ProductStore(service.product_store.path)
    reopened_runs = RunStore(service.store.root)
    reopened_runs.recover_interrupted_runs()
    reopened = AdSmbJobs(
        SimpleNamespace(
            product_store=reopened_store,
            store=reopened_runs,
            job_controller=service.job_controller,
        ),
        executor,
        clock=lambda: NOW + timedelta(days=10),
    )

    recovered = reopened.recover(identifier)

    assert executor.calls == calls and len(executor.recovered) == 1
    operation = recovered["workflow"]["progress"]["operations"][-1]
    assert operation["outcome"]["state"] == "complete"
    assert operation["executions"] == [execution]
    observation = operation["executions"][0]["observation"]
    assert len(observation["normalized_observation"]["events"]) == 600
    assert observation["authenticated_source"] is False
    assert observation["independent_observation"] is False
    assert observation["effective_access_claim"] is False
    assert recovered["workflow"]["progress"]["pending_operation"] is None
    assert reopened_runs.validate_bundle(child["progress"]["run_id"])["valid"]
    assert reopened.recover(identifier) == recovered


@pytest.mark.parametrize("boundary", ["envelope", "execution"])
def test_audit_recovery_rejects_oversized_original_without_releasing_reservation(
    workspace, monkeypatch, boundary
):
    jobs, executor, service = workspace
    identifier = create(jobs)
    assert submit(jobs, identifier, "inspect")[0]["state"] == "completed"
    executor.crash = True
    child, _ = submit(jobs, identifier, "audit")
    assert child["state"] == "failed"
    request = child["request"]["requests"][0]
    execution = deepcopy(executor.originals[request["request_id"]])
    execution["padding"] = ""
    target_bytes = MAX_AUDIT_EXECUTION_BYTES + (65 if boundary == "envelope" else 1)
    execution["padding"] = "x" * (target_bytes - len(canonical_json_bytes(execution)))
    envelope = {"status": "terminal", "execution": execution}
    assert len(canonical_json_bytes(envelope)) - len(canonical_json_bytes(execution)) == 34
    if boundary == "execution":
        assert len(canonical_json_bytes(envelope)) <= MAX_AUDIT_EXECUTION_BYTES + 64
    executor.originals[request["request_id"]] = execution
    recorded = []
    record_recovery = records.record_recovery

    def record(*args):
        recorded.append(True)
        return record_recovery(*args)

    monkeypatch.setattr(records, "record_recovery", record)

    with pytest.raises(AdSmbError, match="^document is not supported bounded JSON$"):
        jobs.recover(identifier)

    assert bool(recorded) is (boundary == "execution")
    current = service.product_store.get_job(child["job_id"])
    assert current["progress"]["tasks"][0]["recovery"] is None
    assert jobs.read(identifier)["workflow"]["progress"]["pending_operation"] == child["job_id"]
    assert len(executor.calls) == 2


def test_non_audit_recovery_keeps_default_outer_document_bound(workspace):
    jobs, executor, service = workspace
    identifier = create(jobs)
    executor.crash = True
    child, _ = submit(jobs, identifier, "inspect")
    assert child["state"] == "failed"
    original_recovery = executor.recover_original

    def oversized_recovery(request, context):
        return {**original_recovery(request, context), "padding": "x" * MAX_DOCUMENT_BYTES}

    executor.recover_original = oversized_recovery
    with pytest.raises(AdSmbError, match="^document is not supported bounded JSON$"):
        jobs.recover(identifier)

    current = service.product_store.get_job(child["job_id"])
    assert current["progress"]["tasks"][0]["recovery"] is None
    assert jobs.read(identifier)["workflow"]["progress"]["pending_operation"] == child["job_id"]
    assert len(executor.calls) == 1


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
    jobs, executor, service = workspace
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
    assert "pre_dispatch_failure" not in service.product_store.get_job(child["job_id"])["progress"]
    assert jobs.read(first)["workflow"]["progress"]["pending_operation"] is None


def test_original_task_context_mutation_refused_before_store_commit(workspace):
    jobs, executor, service = workspace
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

    reopened_store = ProductStore(service.product_store.path)
    reopened_runs = RunStore(service.store.root)
    reopened_runs.recover_interrupted_runs()
    reopened = AdSmbJobs(
        SimpleNamespace(
            product_store=reopened_store,
            store=reopened_runs,
            job_controller=service.job_controller,
        ),
        executor,
        clock=lambda: NOW + timedelta(days=10),
    )
    executor.recover_original = lambda *_args, **_kwargs: pytest.fail(
        "No remote task exists before the durable dispatch checkpoint"
    )
    with pytest.raises(AdSmbError, match="exact installed-executor failure marker"):
        reopened.recover(identifier)

    retained = reopened_store.get_job(child["job_id"])
    assert retained["progress"]["tasks"] == []
    assert "pre_dispatch_failure" not in retained["progress"]
    assert reopened.read(identifier)["workflow"]["progress"]["pending_operation"] == child["job_id"]


@pytest.mark.parametrize(
    ("exception_type", "terminal_state"),
    [
        (AdSmbPreDispatchFailure, "failed"),
        (AdSmbPreDispatchCancelled, "cancelled"),
    ],
)
def test_custom_executor_cannot_claim_installed_pre_dispatch_recovery(
    workspace, exception_type, terminal_state
):
    jobs, executor, _service = workspace
    identifier = create(jobs)

    def forged_failure(*_args, **_kwargs):
        raise exception_type("authored custom executor claim")

    executor.execute = forged_failure
    child, _ = submit(jobs, identifier, "inspect")

    assert child["state"] == terminal_state
    assert child["progress"]["tasks"] == []
    assert "pre_dispatch_failure" not in child["progress"]
    with pytest.raises(AdSmbError, match="exact installed-executor failure marker"):
        jobs.recover(identifier)


def test_installed_pre_dispatch_cancellation_recovers_locally_and_keeps_budget(workspace):
    jobs, fixture_executor, service = workspace
    fixture_executor.selected["provenance"] = "runner_reported"
    terminal = fixture_executor.terminal
    fixture_executor.terminal = lambda request: {
        **terminal(request),
        "provenance": "runner_reported",
    }
    identifier = create(jobs)
    assert submit(jobs, identifier, "inspect")[0]["state"] == "completed"
    remaining_before = jobs.read(identifier)["remaining"]
    installed, entry, calls = installed_checkpoint_executor(fixture_executor, service.store.root)
    entered, release = threading.Event(), threading.Event()

    def selected(request):
        calls.append("selected")
        entered.set()
        assert release.wait(5)
        return entry, "client" if request["step"].startswith("read_") else "member"

    installed._selected = selected
    jobs._executor = installed
    child, _ = submit(jobs, identifier, "baseline", wait=False)
    assert entered.wait(5)
    jobs.stop(identifier)
    release.set()
    child = wait_for_ad_job(jobs.controller, child["job_id"])

    assert child["state"] == "cancelled"
    assert child["progress"]["tasks"] == []
    assert child["progress"]["pre_dispatch_failure"]["request_index"] == 0
    remaining_reserved = jobs.read(identifier)["remaining"]
    assert remaining_reserved == {
        key: remaining_before[key] - value
        for key, value in results.phase_budget("baseline").items()
    }
    calls_before_recovery = list(calls)
    recovered = jobs.recover(identifier)
    operation = recovered["workflow"]["progress"]["operations"][-1]
    assert operation["job_id"] == child["job_id"]
    assert operation["outcome"]["state"] == "not_started"
    assert operation["outcome"]["distinct_local_contexts"] is None
    assert operation["executions"][0]["provenance"] == "controller_local"
    assert recovered["workflow"]["progress"]["pending_operation"] is None
    assert recovered["remaining"] == remaining_reserved
    assert calls == calls_before_recovery
    assert "execute" not in calls and "recover" not in calls
    assert service.store.validate_bundle(child["progress"]["run_id"])["valid"]
    assert jobs.recover(identifier) == recovered


def test_installed_cancel_after_job_checkpoint_before_executor_check_stays_cancelled(
    workspace,
):
    jobs, fixture_executor, service = workspace
    fixture_executor.selected["provenance"] = "runner_reported"
    identifier = create(jobs)
    remaining_before = jobs.read(identifier)["remaining"]
    installed, _entry, calls = installed_checkpoint_executor(fixture_executor, service.store.root)
    execute = installed.execute
    entered, release = threading.Event(), threading.Event()

    def wait_before_executor_check(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return execute(*args, **kwargs)

    installed.execute = wait_before_executor_check
    jobs._executor = installed
    child, _ = submit(jobs, identifier, "inspect", wait=False)
    assert entered.wait(5)
    jobs.stop(identifier)
    release.set()
    child = wait_for_ad_job(jobs.controller, child["job_id"])

    assert child["state"] == "cancelled"
    assert child["progress"]["tasks"] == []
    run_id = child["progress"]["run_id"]
    marker = child["progress"]["pre_dispatch_failure"]
    assert marker["request_index"] == 0
    assert marker["run_id"] == run_id
    assert marker["request_digest"] == content_hash(child["request"]["requests"][0])
    remaining_reserved = jobs.read(identifier)["remaining"]
    assert remaining_reserved == {
        key: remaining_before[key] - value for key, value in results.phase_budget("inspect").items()
    }
    recovered = jobs.recover(identifier)
    operation = recovered["workflow"]["progress"]["operations"][-1]
    assert operation["job_id"] == child["job_id"]
    assert operation["outcome"]["state"] == "not_started"
    assert operation["executions"][0]["provenance"] == "controller_local"
    assert recovered["workflow"]["progress"]["pending_operation"] is None
    assert recovered["remaining"] == remaining_reserved
    assert calls == []
    assert service.store.validate_bundle(run_id)["valid"]
    assert jobs.recover(identifier) == recovered


def test_retained_run_checkpoint_cancellation_recovers_locally_without_dispatch(
    workspace, monkeypatch
):
    jobs, fixture_executor, service = workspace
    fixture_executor.selected["provenance"] = "runner_reported"
    identifier = create(jobs)
    remaining_before = jobs.read(identifier)["remaining"]
    installed, _entry, calls = installed_checkpoint_executor(fixture_executor, service.store.root)
    jobs._executor = installed
    entered, release = threading.Event(), threading.Event()
    retain_run = records.retain_run

    def retain_then_block(*args):
        retained = retain_run(*args)
        entered.set()
        assert release.wait(5)
        return retained

    monkeypatch.setattr(records, "retain_run", retain_then_block)
    child, _ = submit(jobs, identifier, "inspect", wait=False)
    assert entered.wait(5)
    jobs.stop(identifier)
    release.set()
    child = wait_for_ad_job(jobs.controller, child["job_id"])

    assert child["state"] == "cancelled"
    assert child["progress"]["tasks"] == []
    assert child["progress"]["pre_dispatch_failure"]["request_index"] == 0
    remaining_reserved = jobs.read(identifier)["remaining"]
    assert remaining_reserved == {
        key: remaining_before[key] - value for key, value in results.phase_budget("inspect").items()
    }
    recovered = jobs.recover(identifier)
    operation = recovered["workflow"]["progress"]["operations"][-1]
    assert operation["job_id"] == child["job_id"]
    assert operation["outcome"]["state"] == "not_started"
    assert operation["executions"] == [
        {
            "schema_version": "bluefire.ad-smb-execution.v1",
            "request_digest": content_hash(child["request"]["requests"][0]),
            "provenance": "controller_local",
            "dispatch": "not_started",
            "cleanup": "verified",
            "observation": None,
        }
    ]
    assert recovered["workflow"]["progress"]["pending_operation"] is None
    assert recovered["remaining"] == remaining_reserved
    assert calls == []
    assert service.store.validate_bundle(child["progress"]["run_id"])["valid"]
    assert jobs.recover(identifier) == recovered


def test_owner_stop_race_admission_refusal_recovers_local_no_dispatch(workspace, monkeypatch):
    jobs, fixture_executor, service = workspace
    fixture_executor.selected["provenance"] = "runner_reported"
    identifier = create(jobs)
    remaining_before = jobs.read(identifier)["remaining"]
    installed, _entry, calls = installed_checkpoint_executor(fixture_executor, service.store.root)
    jobs._executor = installed
    retained, release_run = threading.Event(), threading.Event()
    retain_run = records.retain_run

    def retain_then_block(*args):
        value = retain_run(*args)
        retained.set()
        assert release_run.wait(5)
        return value

    monkeypatch.setattr(records, "retain_run", retain_then_block)
    cancel_entered, release_cancel = threading.Event(), threading.Event()
    cancel = jobs.controller.cancel

    def delayed_cancel(job_id):
        cancel_entered.set()
        assert release_cancel.wait(5)
        return cancel(job_id)

    monkeypatch.setattr(jobs.controller, "cancel", delayed_cancel)
    child, _ = submit(jobs, identifier, "inspect", wait=False)
    assert retained.wait(5)
    installed.environments = lambda: []
    with ThreadPoolExecutor(max_workers=1) as pool:
        stopping = pool.submit(jobs.stop, identifier)
        assert cancel_entered.wait(5)
        release_run.set()
        child = wait_for_ad_job(jobs.controller, child["job_id"])
        release_cancel.set()
        stopped = stopping.result(timeout=10)

    assert child["state"] == "failed"
    assert child["progress"]["tasks"] == []
    assert child["progress"]["pre_dispatch_failure"]["request_index"] == 0
    assert stopped["workflow"]["progress"]["stopped"] is True
    remaining_reserved = jobs.read(identifier)["remaining"]
    assert remaining_reserved == {
        key: remaining_before[key] - value for key, value in results.phase_budget("inspect").items()
    }
    recovered = jobs.recover(identifier)
    operation = recovered["workflow"]["progress"]["operations"][-1]
    assert operation["job_id"] == child["job_id"]
    assert operation["outcome"]["state"] == "not_started"
    assert operation["executions"][0]["provenance"] == "controller_local"
    assert recovered["workflow"]["progress"]["pending_operation"] is None
    assert recovered["remaining"] == remaining_reserved
    assert calls == []


def test_saved_deadline_refusal_recovers_local_no_dispatch(workspace, monkeypatch):
    jobs, fixture_executor, service = workspace
    fixture_executor.selected["provenance"] = "runner_reported"
    clock = [NOW]
    jobs.clock = lambda: clock[0]
    identifier = create(jobs)
    remaining_before = jobs.read(identifier)["remaining"]
    installed, _entry, calls = installed_checkpoint_executor(fixture_executor, service.store.root)
    jobs._executor = installed
    retained, release = threading.Event(), threading.Event()
    retain_run = records.retain_run

    def retain_then_block(*args):
        value = retain_run(*args)
        retained.set()
        assert release.wait(5)
        return value

    monkeypatch.setattr(records, "retain_run", retain_then_block)
    child, _ = submit(jobs, identifier, "inspect", wait=False)
    assert retained.wait(5)
    clock[0] = timestamp(child["request"]["requests"][0]["deadline"]) + timedelta(microseconds=1)
    release.set()
    child = wait_for_ad_job(jobs.controller, child["job_id"])

    assert child["state"] == "failed"
    assert child["progress"]["tasks"] == []
    assert child["progress"]["pre_dispatch_failure"]["request_index"] == 0
    remaining_reserved = jobs.read(identifier)["remaining"]
    assert remaining_reserved == {
        key: remaining_before[key] - value for key, value in results.phase_budget("inspect").items()
    }
    recovered = jobs.recover(identifier)
    operation = recovered["workflow"]["progress"]["operations"][-1]
    assert operation["job_id"] == child["job_id"]
    assert operation["outcome"]["state"] == "not_started"
    assert operation["executions"][0]["provenance"] == "controller_local"
    assert recovered["workflow"]["progress"]["pending_operation"] is None
    assert recovered["remaining"] == remaining_reserved
    assert calls == []


def test_retained_run_ownership_refusal_remains_unmarked(workspace, monkeypatch):
    jobs, fixture_executor, service = workspace
    fixture_executor.selected["provenance"] = "runner_reported"
    identifier = create(jobs)
    installed, _entry, calls = installed_checkpoint_executor(fixture_executor, service.store.root)
    jobs._executor = installed
    retained, release = threading.Event(), threading.Event()
    retain_run = records.retain_run

    def retain_then_block(*args):
        value = retain_run(*args)
        retained.set()
        assert release.wait(5)
        return value

    monkeypatch.setattr(records, "retain_run", retain_then_block)
    child, _ = submit(jobs, identifier, "inspect", wait=False)
    assert retained.wait(5)
    active = records.active

    def refuse_ownership(*_args, **_kwargs):
        raise AdSmbError("authored exact ownership refusal")

    monkeypatch.setattr(records, "active", refuse_ownership)
    release.set()
    child = wait_for_ad_job(jobs.controller, child["job_id"])

    assert child["state"] == "failed"
    assert child["progress"]["tasks"] == []
    assert "pre_dispatch_failure" not in child["progress"]
    assert calls == []
    monkeypatch.setattr(records, "active", active)
    with pytest.raises(AdSmbError, match="exact installed-executor failure marker"):
        jobs.recover(identifier)
    assert jobs.read(identifier)["workflow"]["progress"]["pending_operation"] == child["job_id"]


def test_retained_checkpoint_cancellation_cannot_be_adopted_as_controller_local(
    workspace, monkeypatch
):
    jobs, fixture_executor, service = workspace
    fixture_executor.selected["provenance"] = "runner_reported"
    identifier = create(jobs)
    installed, _entry, calls = installed_checkpoint_executor(fixture_executor, service.store.root)
    jobs._executor = installed
    retain = records.retain_original

    def retain_then_cancel(*args):
        retain(*args)
        raise JobCancelled("authored cancellation after the durable checkpoint")

    monkeypatch.setattr(records, "retain_original", retain_then_cancel)
    child, _ = submit(jobs, identifier, "inspect")

    assert child["state"] == "cancelled"
    assert len(child["progress"]["tasks"]) == 1
    assert child["progress"]["tasks"][0]["context"] is not None
    assert child["progress"]["tasks"][0]["execution"] is None
    assert "pre_dispatch_failure" not in child["progress"]
    assert "execute" not in calls
    installed.recover_original = lambda *_args, **_kwargs: calls.append("recover") or {
        "status": "unavailable",
        "execution": None,
    }
    with pytest.raises(AdSmbError, match="terminal remains unavailable"):
        jobs.recover(identifier)
    assert calls.count("recover") == 1
    assert jobs.read(identifier)["workflow"]["progress"]["pending_operation"] == child["job_id"]


def test_installed_pre_dispatch_failure_recovers_after_restart_without_new_work(
    workspace, monkeypatch
):
    jobs, fixture_executor, service = workspace
    fixture_executor.selected["provenance"] = "runner_reported"
    terminal = fixture_executor.terminal

    def runner_terminal(request):
        return {**terminal(request), "provenance": "runner_reported"}

    fixture_executor.terminal = runner_terminal
    identifier = create(jobs)
    assert submit(jobs, identifier, "inspect")[0]["state"] == "completed"
    remaining_before = jobs.read(identifier)["remaining"]
    local_checks = []
    installed = object.__new__(InstalledAdSmbExecutor)
    installed.environments = fixture_executor.environments
    installed.readiness = fixture_executor.readiness

    def fail_local_precheck(_request):
        local_checks.append("precheck")
        raise AdSmbError("authored local installed precheck failure")

    installed._selected = fail_local_precheck
    installed.recover_original = lambda *_args, **_kwargs: pytest.fail(
        "Marked pre-dispatch recovery must not contact the receiver"
    )
    jobs._executor = installed
    child, _ = submit(jobs, identifier, "baseline")

    assert child["state"] == "failed"
    assert child["progress"]["tasks"] == []
    run_id = child["progress"]["run_id"]
    first_request = child["request"]["requests"][0]
    assert child["progress"]["pre_dispatch_failure"] == {
        "schema_version": "bluefire.ad-smb-pre-dispatch-failure.v1",
        "operation_job_id": child["job_id"],
        "run_id": run_id,
        "request_index": 0,
        "request_digest": content_hash(first_request),
        "boundary": "before_durable_original_checkpoint",
        "producer": "bluefire.ad-smb-controller",
    }
    remaining_reserved = jobs.read(identifier)["remaining"]
    budget = results.phase_budget("baseline")
    assert remaining_reserved == {
        key: remaining_before[key] - value for key, value in budget.items()
    }
    assert local_checks == ["precheck"]
    assert len(fixture_executor.calls) == 1
    assert fixture_executor.calls[0]["phase"] == "inspect"

    first_store = ProductStore(service.product_store.path)
    second_store = ProductStore(service.product_store.path)
    first_runs = RunStore(service.store.root)
    second_runs = RunStore(service.store.root)
    first_runs.recover_interrupted_runs()
    first = AdSmbJobs(
        SimpleNamespace(
            product_store=first_store, store=first_runs, job_controller=service.job_controller
        ),
        installed,
        clock=lambda: NOW + timedelta(days=10),
    )
    second = AdSmbJobs(
        SimpleNamespace(
            product_store=second_store, store=second_runs, job_controller=service.job_controller
        ),
        installed,
        clock=lambda: NOW + timedelta(days=10),
    )
    exact_marker = deepcopy(child["progress"]["pre_dispatch_failure"])
    changed_marker = {**exact_marker, "request_digest": pin("0")}
    with first_store._connection(write=True) as connection:
        persisted = records.job_at(first_store, connection, child["job_id"])
        records.patch(connection, persisted, {"pre_dispatch_failure": changed_marker})
    with pytest.raises(AdSmbError, match="exact installed-executor failure marker"):
        first.recover(identifier)
    assert first.read(identifier)["workflow"]["progress"]["pending_operation"] == child["job_id"]
    with first_store._connection(write=True) as connection:
        persisted = records.job_at(first_store, connection, child["job_id"])
        records.patch(connection, persisted, {"pre_dispatch_failure": exact_marker})
    barrier = threading.Barrier(2)
    adopt = records.adopt_installed_pre_dispatch_failure

    def synchronized_adopt(*args):
        barrier.wait(5)
        return adopt(*args)

    monkeypatch.setattr(records, "adopt_installed_pre_dispatch_failure", synchronized_adopt)

    def recover(instance):
        try:
            return instance.recover(identifier)
        except AdSmbError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        values = [
            future.result(timeout=10)
            for future in [pool.submit(recover, instance) for instance in (first, second)]
        ]
    assert any(value is not None for value in values)
    settled = first.read(identifier)
    operation = settled["workflow"]["progress"]["operations"][-1]
    assert operation["job_id"] == child["job_id"]
    assert operation["outcome"]["state"] == "not_started"
    assert operation["outcome"]["cleanup"] == "verified"
    assert operation["executions"] == [
        {
            "schema_version": "bluefire.ad-smb-execution.v1",
            "request_digest": content_hash(first_request),
            "provenance": "controller_local",
            "dispatch": "not_started",
            "cleanup": "verified",
            "observation": None,
        }
    ]
    local_execution = operation["executions"][0]
    with pytest.raises(AdSmbError, match="identity or state"):
        results.validate_execution(first_request, local_execution)
    assert (
        results.validate_controller_local_execution(first_request, local_execution)
        == local_execution
    )
    for provenance in ("runner_reported", "synthetic_fixture"):
        with pytest.raises(AdSmbError, match="identity or state"):
            results.validate_controller_local_execution(
                first_request,
                {**local_execution, "provenance": provenance},
            )
    for field, value in (
        ("dispatch", "attempted"),
        ("cleanup", "unknown"),
        ("observation", {}),
    ):
        with pytest.raises(AdSmbError, match="identity or state"):
            results.validate_controller_local_execution(
                first_request,
                {**local_execution, field: value},
            )
    assert settled["remaining"] == remaining_reserved
    assert local_checks == ["precheck"]
    evidence = first_runs.read_json(run_id, "evidence.json")["records"]
    assert len(evidence) == 1
    assert evidence[0]["provenance"] == "control_blocked"
    assert evidence[0]["producer"] == "bluefire.ad-smb-controller"
    assert evidence[0]["content"]["observation"] is None
    assert first_runs.validate_bundle(run_id)["valid"]
    assert first.recover(identifier) == settled


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
