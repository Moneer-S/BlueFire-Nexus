from __future__ import annotations

import copy
import errno
import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from tools import verify_installed_macos_native as verifier


def report() -> dict:
    return {
        "schema_version": "bluefire.installed-macos-native-desktop.v1",
        "status": "passed",
        "real_service": True,
        "mocked_responses": False,
        "native_execution": True,
        "live_model_inference": False,
        "effective_access": False,
        "errors": [],
        "blocked_requests": [],
        "cleanup": {"runner_stopped": True, "job_settled": True},
        "observed": {"filesystem_records": 1, "executed_steps": 2, "generated_records": 1},
        "checks": sorted(verifier.REQUIRED_CHECKS),
        "screenshots": [
            {"name": name, "sha256": "a" * 64}
            for name in (
                "macos-native-result",
                "macos-native-evidence",
                "macos-native-cleanup",
                "macos-native-reopened",
            )
        ],
    }


def test_accepts_complete_native_generated_scope() -> None:
    assert verifier.driver_passed(report())


def test_installed_browser_navigations_use_service_hash_routes() -> None:
    from bluefire.api import _STATIC_ROUTES

    driver = (
        Path(__file__).resolve().parents[1] / "frontend/tests/installed/installed-macos-native.mjs"
    ).read_text(encoding="utf-8")
    navigations = re.findall(r"page\.goto\(`([^`]+)`", driver)
    assert navigations == ["${origin}/#/scenarios", "${origin}/#/runs/${runId}"]
    for template in navigations:
        url = urlsplit(
            template.replace("${origin}", "http://127.0.0.1:4317").replace(
                "${runId}", "run-generated"
            )
        )
        assert url.path in _STATIC_ROUTES
        assert url.fragment in {"/scenarios", "/runs/run-generated"}
        assert not url.query
    assert "assert.equal(new URL(page.url()).hash, `#/runs/${runId}`);" in driver


@pytest.mark.parametrize(
    "field,value",
    [
        ("native_execution", False),
        ("effective_access", True),
        ("live_model_inference", True),
        ("mocked_responses", True),
        ("real_service", False),
        ("status", "failed_or_incomplete"),
        ("blocked_requests", ["unexpected"]),
        ("errors", ["TypeError"]),
        ("checks", []),
        ("screenshots", []),
        ("cleanup", {"runner_stopped": False, "job_settled": True}),
        ("observed", {"filesystem_records": True, "executed_steps": 2, "generated_records": 1}),
        ("observed", {"filesystem_records": 0, "executed_steps": 2, "generated_records": 1}),
        ("observed", {"filesystem_records": 1, "executed_steps": 1, "generated_records": 1}),
    ],
)
def test_rejects_incomplete_or_false_scope(field, value) -> None:
    candidate = report()
    candidate[field] = value
    assert not verifier.driver_passed(candidate)


def test_child_environment_does_not_inherit_credentials(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "test-token-not-to-inherit")
    monkeypatch.setenv("OPENAI_API_KEY", "test-provider-not-to-inherit")
    environment = verifier.isolated_environment(
        tmp_path, Path("/usr/local/bin/node"), tmp_path / "cache"
    )
    assert "GITHUB_TOKEN" not in environment and "OPENAI_API_KEY" not in environment
    assert environment["HOME"] == str(tmp_path / "home")
    assert environment["PLAYWRIGHT_BROWSERS_PATH"] == str(tmp_path / "cache")
    assert "BLUEFIRE_RUNNER_BINARY" not in environment


def test_report_reader_refuses_duplicates_and_overlong_files(tmp_path) -> None:
    path = tmp_path / "report.json"
    path.write_text('{"status":"passed","status":"failed"}', encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate"):
        verifier.read_report(path)
    path.write_bytes(b" " * (verifier.MAX_REPORT_BYTES + 1))
    with pytest.raises(ValueError, match="bounded"):
        verifier.read_report(path)


def wheel(tmp_path: Path, *, extra: tuple[str, bytes] | None = None):
    package = tmp_path / "site" / "bluefire"
    package.mkdir(parents=True)
    (package / "__init__.py").write_bytes(b"__version__ = '3.0.0rc2'\n")
    (package / "ui").mkdir()
    (package / "ui" / "app.js").write_bytes(b"installed real application\n")
    destination = tmp_path / "bluefire_nexus-3.0.0rc2-py3-none-macosx_11_0_x86_64.whl"
    with zipfile.ZipFile(destination, "w") as archive:
        archive.writestr(
            "bluefire_nexus-3.0.0rc2.dist-info/METADATA",
            "Name: bluefire-nexus\nVersion: 3.0.0rc2\n",
        )
        archive.writestr("bluefire/__init__.py", (package / "__init__.py").read_bytes())
        archive.writestr("bluefire/ui/app.js", (package / "ui" / "app.js").read_bytes())
        if extra:
            archive.writestr(*extra)
    return destination, package


def test_exact_installed_package_bytes_include_browser_assets(tmp_path) -> None:
    archive, package = wheel(tmp_path)
    assert verifier.installed_package_matches_wheel(archive, package, "3.0.0rc2")
    (package / "ui" / "app.js").write_bytes(b"changed")
    assert not verifier.installed_package_matches_wheel(archive, package, "3.0.0rc2")


@pytest.mark.parametrize("name", ["bluefire/../escape.py", "bluefire/ui/extra.js"])
def test_package_match_rejects_escape_or_missing_installed_resource(tmp_path, name) -> None:
    archive, package = wheel(tmp_path, extra=(name, b"not installed"))
    assert not verifier.installed_package_matches_wheel(archive, package, "3.0.0rc2")


class Service:
    def __init__(self, jobs):
        self.jobs = copy.deepcopy(jobs)
        self.product_store = self
        self.cancelled = []

    def list_jobs(self):
        return list(self.jobs)

    def cancel_job(self, job_id):
        self.cancelled.append(job_id)
        self.job(job_id)["state"] = "cancelled"

    def job(self, job_id):
        return next(job for job in self.jobs if job["job_id"] == job_id)


def owned_job(state="running"):
    return {
        "job_id": "job-" + "a" * 32,
        "kind": "scenario.run",
        "state": state,
        "request": {
            "scenario": {
                "id": "scenario.installed-macos-native.00000000-0000-4000-8000-000000000000.v1"
            },
            "mode": "execute",
            "runner_profile_id": verifier.PROFILE,
        },
    }


def test_failure_cleanup_cancels_only_private_owned_job() -> None:
    service = Service([owned_job()])
    assert verifier.settle_owned_jobs(service, timeout=0)
    assert service.cancelled == [owned_job()["job_id"]]


def test_unknown_job_refuses_cleanup_before_any_cancellation() -> None:
    foreign = owned_job()
    foreign["request"]["scenario"]["id"] = "scenario.not-owned.v1"
    service = Service([owned_job(), foreign])
    assert not verifier.settle_owned_jobs(service, timeout=0)
    assert service.cancelled == []


def test_completed_job_is_not_replayed_or_cancelled() -> None:
    service = Service([owned_job("completed")])
    assert verifier.settle_owned_jobs(service, timeout=0)
    assert service.cancelled == []


def test_receipt_write_never_overwrites_existing_evidence(tmp_path) -> None:
    path = tmp_path / "receipt.json"
    verifier.write_new(path, {"status": "failed"})
    with pytest.raises(FileExistsError):
        verifier.write_new(path, {"status": "passed"})
    assert json.loads(path.read_text()) == {"status": "failed"}


def test_screenshot_bytes_are_bound_to_each_expected_record(tmp_path) -> None:
    candidate = report()
    raw = b"\x89PNG\r\n\x1a\nowned-generated-pixels"
    for item in candidate["screenshots"]:
        item["sha256"] = hashlib.sha256(raw).hexdigest()
        (tmp_path / (item["name"] + ".png")).write_bytes(raw)
    assert verifier.screenshots_verified(tmp_path, candidate)
    (tmp_path / "macos-native-result.png").write_bytes(b"modified")
    assert not verifier.screenshots_verified(tmp_path, candidate)


class WorkspaceService:
    def __init__(self, workspace, *, run_id="run-owned"):
        self.product_store = self
        self.binding = {
            "state": "completed",
            "profile_id": verifier.PROFILE,
            "run_id": run_id,
            "workspace_path": str(workspace),
        }

    def list_execution_workspaces(self):
        return [self.binding]


def test_inspects_only_bound_owned_workspace_and_requires_empty_generated_files(tmp_path) -> None:
    runtime = tmp_path / "runtime"
    workspace = runtime / "workspace"
    workspace.mkdir(parents=True)
    (workspace / ".bluefire").mkdir()
    (workspace / ".bluefire" / "receipts.json").write_text("{}")
    service = WorkspaceService(workspace)
    assert verifier.workspace_clean(service, runtime, "run-owned")
    (workspace / "fixtures").mkdir()
    (workspace / "fixtures" / "input.jsonl").write_text("owned generated fixture")
    assert not verifier.workspace_clean(service, runtime, "run-owned")


def test_workspace_binding_mismatch_or_outside_path_is_refused(tmp_path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    foreign = tmp_path / "outside"
    foreign.mkdir()
    assert not verifier.workspace_clean(WorkspaceService(foreign), runtime, "run-owned")
    assert not verifier.workspace_clean(WorkspaceService(runtime), runtime, "another-run")


def test_workspace_traversal_error_cannot_claim_generated_cleanup(tmp_path, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    workspace = runtime / "workspace"
    workspace.mkdir(parents=True)

    def unreadable(_path, *, followlinks, onerror):
        assert followlinks is False
        onerror(PermissionError("generated subtree unreadable"))
        return iter(())

    monkeypatch.setattr(verifier.os, "walk", unreadable)
    with pytest.raises(PermissionError):
        verifier.workspace_clean(WorkspaceService(workspace), runtime, "run-owned")


def test_waiting_does_not_reap_original_child_or_adopt_another_pid() -> None:
    class Child:
        pid = 6543

        def poll(self):
            raise AssertionError("Do not reap before stopping the original process group")

    observed = []
    verifier.wait_driver_exit(Child(), lambda pid: observed.append(pid) or True, timeout=0)
    assert observed == [6543]
    with pytest.raises(subprocess.TimeoutExpired):
        verifier.wait_driver_exit(Child(), lambda pid: False, timeout=0)


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class SupervisedChild:
    pid = 6543
    returncode = None

    def poll(self):
        raise AssertionError("Supervisor must preserve original child custody")


def test_unresponsive_service_close_is_terminated_at_its_own_deadline(tmp_path) -> None:
    verifier.write_new(tmp_path / "service-close-started.json", {"status": "failed_or_incomplete"})
    clock = Clock()
    child = SupervisedChild()
    stopped = []

    def stop(process):
        stopped.append(process.pid)
        process.returncode = -9
        return True

    outcome = verifier.supervise_owned_child(
        child,
        lambda _pid: False,
        tmp_path,
        close_timeout=0.3,
        stop=stop,
        clock=clock,
        sleep=clock.sleep,
    )
    assert 0.3 <= clock.now <= 0.4
    assert stopped == [child.pid]
    assert outcome["worker_timeout_stage"] == "service_close"
    assert outcome["worker_exit_observed"] is False
    assert outcome["worker_process_group_stopped"] is True
    assert outcome["worker_returncode"] == -9


def test_unresponsive_worker_without_close_marker_has_overall_deadline(tmp_path) -> None:
    clock = Clock()
    outcome = verifier.supervise_owned_child(
        SupervisedChild(),
        lambda _pid: False,
        tmp_path,
        timeout=0.2,
        stop=lambda _child: False,
        clock=clock,
        sleep=clock.sleep,
    )
    assert clock.now == 0.2
    assert outcome["worker_timeout_stage"] == "journey"
    assert outcome["worker_process_group_stopped"] is False


def test_supervisor_does_not_claim_termination_when_group_stop_raises(tmp_path) -> None:
    def stop(_child):
        raise subprocess.TimeoutExpired("owned group", 10)

    outcome = verifier.supervise_owned_child(
        SupervisedChild(), lambda _pid: True, tmp_path, stop=stop
    )
    assert outcome["worker_exit_observed"] is True
    assert outcome["worker_process_group_stopped"] is False
    assert outcome["worker_stop_error_type"] == "TimeoutExpired"


@pytest.fixture
def darwin_group_stop(monkeypatch):
    from bluefire import runner_lifecycle

    events = []
    clock = Clock()

    class Child(SupervisedChild):
        def wait(self, *, timeout):
            events.append(("wait", timeout))
            self.returncode = 0
            return self.returncode

    def signal_group(pid, signum):
        assert pid == Child.pid
        assert child.returncode is None
        events.append(("signal", signum))

    def inventory(*_identity):
        assert child.returncode is None
        events.append(("inventory", Child.pid))
        return {Child.pid}

    child = Child()
    monkeypatch.setattr(runner_lifecycle, "_GET_PROCESS_GROUP_ID", lambda _pid: Child.pid)
    monkeypatch.setattr(runner_lifecycle, "_GET_SESSION_ID", lambda _pid: Child.pid)
    monkeypatch.setattr(runner_lifecycle, "_darwin_child_exited_without_reap", lambda _pid: True)
    monkeypatch.setattr(runner_lifecycle, "_darwin_private_process_group_members", inventory)
    monkeypatch.setattr(runner_lifecycle, "_darwin_private_session_members", inventory)
    monkeypatch.setattr(runner_lifecycle, "_kill_process_group", signal_group)
    monkeypatch.setattr(runner_lifecycle.time, "monotonic", clock)
    monkeypatch.setattr(runner_lifecycle.time, "sleep", clock.sleep)
    return runner_lifecycle, child, events, clock


def test_group_stop_reaps_only_after_two_empty_inventories(darwin_group_stop) -> None:
    _lifecycle, child, events, _clock = darwin_group_stop
    assert verifier.stop_group(child)
    assert events == [
        ("inventory", child.pid),
        ("inventory", child.pid),
        ("inventory", child.pid),
        ("inventory", child.pid),
        ("wait", 5.0),
    ]
    assert child.returncode == 0
    before = list(events)
    assert verifier.stop_group(child) is False
    assert events == before


def test_group_stop_proves_absence_after_permission_race(monkeypatch, darwin_group_stop) -> None:
    lifecycle, child, events, _clock = darwin_group_stop
    observations = iter((False, True, True))
    monkeypatch.setattr(
        lifecycle, "_darwin_child_exited_without_reap", lambda _pid: next(observations)
    )

    def denied_signal(pid, signum):
        assert pid == child.pid and child.returncode is None
        events.append(("signal", signum))
        raise PermissionError(errno.EPERM, "No live group member")

    monkeypatch.setattr(lifecycle, "_kill_process_group", denied_signal)
    assert verifier.stop_group(child)
    assert events == [
        ("inventory", child.pid),
        ("inventory", child.pid),
        ("signal", int(lifecycle.signal.SIGTERM)),
        ("inventory", child.pid),
        ("inventory", child.pid),
        ("inventory", child.pid),
        ("inventory", child.pid),
        ("wait", 5.0),
    ]


@pytest.mark.parametrize(
    "inventory_name",
    ["_darwin_private_process_group_members", "_darwin_private_session_members"],
)
@pytest.mark.parametrize("inventory_unknown", [False, True])
def test_group_stop_never_accepts_live_or_unknown_members(
    monkeypatch, darwin_group_stop, inventory_name, inventory_unknown
) -> None:
    lifecycle, child, events, clock = darwin_group_stop
    members = None if inventory_unknown else {child.pid, child.pid + 1}
    monkeypatch.setattr(lifecycle, inventory_name, lambda *_identity: members)

    def denied_signal(pid, signum):
        assert pid == child.pid and child.returncode is None
        events.append(("signal", signum))
        raise PermissionError(errno.EPERM, "Group signalling unavailable")

    monkeypatch.setattr(lifecycle, "_kill_process_group", denied_signal)
    assert verifier.stop_group(child) is False
    assert child.returncode is None
    assert not any(event[0] == "wait" for event in events)
    assert [event for event in events if event[0] == "signal"] == [
        ("signal", int(lifecycle.signal.SIGTERM)),
        ("signal", int(getattr(lifecycle.signal, "SIGKILL", 9))),
    ]
    assert 6.0 <= clock.now < 6.1


@pytest.mark.parametrize("identity_name", ["_GET_PROCESS_GROUP_ID", "_GET_SESSION_ID"])
def test_group_stop_rejects_live_child_identity_mismatch(
    monkeypatch, darwin_group_stop, identity_name
) -> None:
    lifecycle, child, events, clock = darwin_group_stop
    monkeypatch.setattr(lifecycle, "_darwin_child_exited_without_reap", lambda _pid: False)
    monkeypatch.setattr(lifecycle, identity_name, lambda _pid: child.pid + 1)
    assert verifier.stop_group(child) is False
    assert events == []
    assert clock.now == 0.0
    assert child.returncode is None


def test_group_stop_rejects_lost_child_custody(monkeypatch, darwin_group_stop) -> None:
    lifecycle, child, events, _clock = darwin_group_stop

    def no_child(_pid):
        raise ChildProcessError

    monkeypatch.setattr(lifecycle, "_darwin_child_exited_without_reap", no_child)
    assert verifier.stop_group(child) is False
    assert events == []
    assert child.returncode is None


def test_group_stop_wait_failure_remains_unverified(monkeypatch, darwin_group_stop) -> None:
    _lifecycle, child, events, _clock = darwin_group_stop

    def wait_timeout(*, timeout):
        events.append(("wait", timeout))
        raise subprocess.TimeoutExpired("owned child", timeout)

    monkeypatch.setattr(child, "wait", wait_timeout)
    assert verifier.stop_group(child) is False
    assert child.returncode is None
    assert events[-1] == ("wait", 5.0)
    assert not any(event[0] == "signal" for event in events)


def worker_result():
    return {
        "schema_version": "bluefire.installed-macos-native-receipt.v1",
        "status": "ready_for_finalization",
        "scope": "owned_generated_fixture_native_desktop",
        "native_desktop_verified": True,
        "effective_access": False,
        "temporary_state_removed": False,
        "browser_returncode": 0,
        "cleanup_errors": [],
        **dict.fromkeys(verifier.WORKER_CLEANUP_CHECKS, True),
    }


def supervision_result():
    return {
        "worker_exit_observed": True,
        "worker_process_group_stopped": True,
        "worker_timeout_stage": None,
        "worker_returncode": 0,
    }


def test_browser_success_before_hung_close_cannot_promote_or_delete_runtime(tmp_path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "retained.txt").write_text("owned generated state")
    partial = worker_result()
    partial["status"] = "failed_or_incomplete"
    del partial["service_closed"]
    del partial["service_thread_stopped"]
    verifier.write_new(tmp_path / "service-close-started.json", partial)
    supervision = supervision_result()
    supervision.update(
        worker_timeout_stage="service_close", worker_returncode=-9, worker_exit_observed=False
    )
    result = verifier.finalize_supervised_receipt(tmp_path, supervision)
    assert result["status"] == "failed_or_incomplete"
    assert result["native_desktop_verified"] is False
    assert result["service_closed"] is False
    assert result["service_thread_stopped"] is False
    assert result["temporary_state_removed"] is False
    assert (runtime / "retained.txt").read_text() == "owned generated state"
    assert "worker_shutdown_unverified" in result["cleanup_errors"]
    assert (tmp_path / "receipt.json").is_file()


@pytest.mark.parametrize(
    "scope,field,value",
    [
        ("worker", "service_closed", False),
        ("worker", "owned_jobs_settled", False),
        ("worker", "status", "passed"),
        ("worker", "schema_version", "unrecognized"),
        ("worker", "scope", "unrecognized"),
        ("worker", "effective_access", True),
        ("supervision", "worker_returncode", 1),
        ("supervision", "worker_process_group_stopped", False),
        ("supervision", "worker_exit_observed", False),
        ("supervision", "worker_timeout_stage", "service_close"),
    ],
)
def test_incomplete_shutdown_cannot_remove_runtime(tmp_path, scope, field, value) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    worker = worker_result()
    supervision = supervision_result()
    (worker if scope == "worker" else supervision)[field] = value
    verifier.write_new(tmp_path / "worker-result.json", worker)
    result = verifier.finalize_supervised_receipt(tmp_path, supervision)
    assert result["status"] == "failed_or_incomplete"
    assert result["native_desktop_verified"] is False
    assert result["effective_access"] is False
    assert result["scope"] == "owned_generated_fixture_native_desktop"
    assert result["schema_version"] == "bluefire.installed-macos-native-receipt.v1"
    assert result["temporary_state_removed"] is False
    assert runtime.is_dir()


def test_missing_worker_result_writes_failed_receipt(tmp_path) -> None:
    result = verifier.finalize_supervised_receipt(tmp_path, supervision_result())
    assert result["status"] == "failed_or_incomplete"
    assert result["native_desktop_verified"] is False
    assert result["worker_result_error_type"] == "FileNotFoundError"
    assert "worker_shutdown_unverified" in result["cleanup_errors"]


def test_only_completed_worker_and_verified_group_cleanup_finalize_success(tmp_path) -> None:
    (tmp_path / "runtime").mkdir()
    verifier.write_new(tmp_path / "worker-result.json", worker_result())
    result = verifier.finalize_supervised_receipt(tmp_path, supervision_result())
    assert result["status"] == "passed"
    assert result["native_desktop_verified"] is True
    assert result["temporary_state_removed"] is True
    assert not (tmp_path / "runtime").exists()
    assert (tmp_path / "worker-result.json").is_file()
