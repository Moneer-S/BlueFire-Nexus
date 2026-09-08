"""Bounded runner deadlines with fake clocks and Python-only process fixtures."""

import threading
from types import SimpleNamespace

import pytest

from bluefire import runner_client, runner_lifecycle
from bluefire.runner_client import RunnerTransportError, SubprocessRustRunner
from bluefire.runner_lifecycle import ManagedRunnerLifecycle, RunnerLifecycleError


class CapturedLaunch(Exception):
    pass


def manager(tmp_path, monkeypatch, *, override=None, health_timeout=125.0):
    timeouts = []
    kwargs = {} if override is None else {"runner_timeout_seconds": override}
    lifecycle = ManagedRunnerLifecycle(
        tmp_path / "managed",
        start_timeout_seconds=2,
        client_factory=lambda *_args, **options: timeouts.append(options["socket_timeout_seconds"])
        or SimpleNamespace(**options),
        **kwargs,
    )
    enrollment = SimpleNamespace(
        root=tmp_path / "enrollment", allowed_profile_ids=("profile.test.v1",)
    )
    bootstrap = SimpleNamespace(
        binary_digest="sha256:" + "a" * 64,
        binary_path=tmp_path / "runner",
        sandbox_path=tmp_path / "sandbox",
    )
    monkeypatch.setattr(lifecycle, "_load_active_enrollment", lambda: enrollment)
    monkeypatch.setattr(lifecycle, "_load_bootstrap", lambda _: bootstrap)
    monkeypatch.setattr(lifecycle, "_ledger_lock_state", lambda: "free")
    monkeypatch.setattr(lifecycle, "_reap_owned_processes", lambda: True)
    monkeypatch.setattr(
        runner_lifecycle, "read_process_record", lambda *_args, **_kwargs: {"port": 43123}
    )
    health = {"ledger": {"accepting_execute": True}, "execution_timeout_seconds": health_timeout}

    def probe(*_args):
        client = lifecycle._new_client(enrollment, "profile.test.v1", port=43123)
        return client, health

    monkeypatch.setattr(lifecycle, "_authenticated_health", probe)
    return lifecycle, timeouts, health


def test_launch_and_reopened_client_cover_profile_budget_without_expanding_control(
    tmp_path, monkeypatch
):
    lifecycle, timeouts, health = manager(tmp_path, monkeypatch)
    captured = []

    def command(spec):
        captured.append(spec)
        raise CapturedLaunch

    lifecycle.host_command_factory = command
    with pytest.raises(CapturedLaunch):
        lifecycle._start_locked(profile_id="profile.test.v1", profile_budget_seconds=120)
    assert captured[0].runner_timeout_seconds == 125
    # A reopened manager retains its default35, but uses authenticated actual host bounds.
    assert lifecycle.runner_timeout_seconds == 35
    client, _ = lifecycle.client_for_profile("profile.test.v1", profile_budget_seconds=120)
    assert client.socket_timeout_seconds == 135 and timeouts == [2, 135]
    health["execution_timeout_seconds"] = 185
    client, _ = lifecycle.client_for_profile("profile.test.v1", profile_budget_seconds=180)
    assert client.socket_timeout_seconds == 195 and timeouts[-2:] == [2, 195]


@pytest.mark.parametrize("reported", [None, True, "125", 35, float("nan"), 86401])
def test_profile_outgrowing_or_unknown_host_refuses_without_execution_client(
    tmp_path, monkeypatch, reported
):
    lifecycle, timeouts, _ = manager(tmp_path, monkeypatch, health_timeout=reported)
    with pytest.raises(RunnerLifecycleError, match="stop and start"):
        lifecycle.client_for_profile("profile.test.v1", profile_budget_seconds=120)
    assert timeouts == [2]


def test_budget_growth_requires_explicit_restart_and_does_not_replace_live_host(
    tmp_path, monkeypatch
):
    lifecycle, _, _ = manager(tmp_path, monkeypatch)
    lifecycle.process_record_path.parent.mkdir(parents=True)
    lifecycle.process_record_path.write_text("fixture")
    monkeypatch.setattr(
        lifecycle,
        "status",
        lambda **_: {"state": "ready", "health": {"execution_timeout_seconds": 125}},
    )
    monkeypatch.setattr(
        lifecycle, "host_command_factory", lambda _: pytest.fail("must not replace a live host")
    )
    with pytest.raises(RunnerLifecycleError, match="stop and start"):
        lifecycle._start_locked(profile_id="profile.test.v1", profile_budget_seconds=180)


def test_explicit_outer_override_and_existing_maximum_remain_bounded(tmp_path, monkeypatch):
    automatic, _, _ = manager(tmp_path, monkeypatch)
    assert automatic._timeout_for_profile(86395) == 86400
    with pytest.raises(RunnerLifecycleError, match="completion margin"):
        automatic._timeout_for_profile(86400)
    fixed, _, _ = manager(tmp_path, monkeypatch, override=2, health_timeout=2)
    assert fixed._timeout_for_profile(120) == 2
    client, _ = fixed.client_for_profile("profile.test.v1", profile_budget_seconds=120)
    assert client.socket_timeout_seconds == 15


@pytest.mark.parametrize("reported", [35, None])
def test_default_service_status_refuses_old_host_for_current_profiles(
    tmp_path, monkeypatch, reported
):
    from bluefire.contracts import ExecutionMode
    from bluefire.runner_management_service import RunnerManagementServiceMixin

    lifecycle, _, health = manager(tmp_path, monkeypatch, health_timeout=reported)
    requested = []

    def status(*, profile_id, profile_budget_seconds):
        requested.append((profile_id, profile_budget_seconds))
        supported = lifecycle._supports_profile_budget(health, profile_budget_seconds)
        return {
            "state": "ready" if supported else "unavailable",
            "health": {"profile_budget_supported": supported},
        }

    monkeypatch.setattr(lifecycle, "status", status)

    class Service(RunnerManagementServiceMixin):
        runner_lifecycle = lifecycle

        def _runner_lifecycle_profile(self, profile_id):
            assert profile_id is None
            return None

        def _runner_profiles(self):
            return (
                SimpleNamespace(
                    mode=ExecutionMode.EXECUTE, budgets=SimpleNamespace(max_seconds=120)
                ),
                SimpleNamespace(
                    mode=ExecutionMode.SIMULATE, budgets=SimpleNamespace(max_seconds=999)
                ),
            )

    result = Service().runner_status()
    assert requested == [(None, 120)]
    assert result == {"state": "unavailable", "health": {"profile_budget_supported": False}}


@pytest.mark.parametrize(
    "finish_at,cancel_at,expected",
    [(40, None, "completed"), (130, None, "timed out"), (40, 10, "cancelled")],
)
def test_actual_process_monitor_respects_approved_budget_and_stop(
    tmp_path, monkeypatch, finish_at, cancel_at, expected
):
    lifecycle, _, _ = manager(tmp_path, monkeypatch)
    clock = [0.0]
    process = SimpleNamespace(returncode=None)
    stopped = []
    transport = SubprocessRustRunner.__new__(SubprocessRustRunner)
    transport.timeout_seconds = lifecycle._timeout_for_profile(120)
    transport._kill_child_on_job_close = True
    transport._windows_containment = SimpleNamespace(finish=lambda _: True)
    transport._finish_posix_process_group = lambda _: True

    def exited(_):
        if clock[0] >= finish_at:
            process.returncode = 0
            return True
        return False

    transport._process_exited_without_reap = exited
    transport._stop_process_tree = lambda _: stopped.append(clock[0]) or True
    cancellation = threading.Event()

    def tick(_):
        clock[0] += 1
        if cancel_at is not None and clock[0] >= cancel_at:
            cancellation.set()

    monkeypatch.setattr(runner_client.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(runner_client.time, "sleep", tick)
    if expected == "completed":
        assert (
            transport._monitor_process(
                process, cancel_event=cancellation, overflow=threading.Event()
            )
            == 0
        )
        assert clock[0] == 40 and not stopped
    else:
        with pytest.raises(RunnerTransportError, match=expected):
            transport._monitor_process(
                process, cancel_event=cancellation, overflow=threading.Event()
            )
        assert stopped == [10 if cancel_at else 125]


def test_host_separates_native_deadline_from_short_socket_ingress(tmp_path, monkeypatch):
    from bluefire import runner_host

    binary = tmp_path / "runner"
    binary.write_bytes(b"non executable fixture")
    captured = {}
    monkeypatch.setattr(
        runner_host,
        "load_local_enrollment",
        lambda *a, **k: SimpleNamespace(root=tmp_path / "trust"),
    )

    def transport(*args, **kwargs):
        captured["native"] = kwargs["timeout_seconds"]
        return SimpleNamespace(timeout_seconds=kwargs["timeout_seconds"])

    def server(*args, **kwargs):
        captured["socket"] = kwargs["socket_timeout_seconds"]
        raise CapturedLaunch

    monkeypatch.setattr(runner_host, "SubprocessRustRunner", transport)
    monkeypatch.setattr(runner_host, "AuthenticatedRunnerServer", server)
    with pytest.raises(runner_host.RunnerHostError):
        runner_host.serve_managed_runner(
            enrollment_root=tmp_path / "trust",
            runner_binary=binary,
            work_root=tmp_path / "work",
            state_path=tmp_path / "db",
            process_record_path=tmp_path / "process.json",
            launch_id="a" * 64,
            runner_timeout_seconds=125,
        )
    assert captured == {"native": 125, "socket": 10}


def test_service_uses_activated_current_profile_budget_for_start_status_and_client(tmp_path):
    from bluefire.contracts import ExecutionMode
    from bluefire.service import BlueFireService
    from tests_platform.test_service import ROOT, ReadyInventoryRunner, RecordingRunnerLifecycle

    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    lifecycle = RecordingRunnerLifecycle(ReadyInventoryRunner(), sandbox)
    service = BlueFireService(
        project_root=ROOT, runs_dir=tmp_path / "runs", runner_lifecycle=lifecycle
    )
    try:
        selected = next(p for p in service._runner_profiles() if p.mode is ExecutionMode.EXECUTE)
        original = selected.budgets.max_seconds
        document = selected.to_dict()
        document["budgets"]["max_seconds"] = 180
        service.save_resource("runner_profile", selected.id, {"document": document})
        service.activate_resource("runner_profile", selected.id, {})
        current = next(p for p in service._runner_profiles() if p.id == selected.id)
        assert selected.budgets.max_seconds == original and current.budgets.max_seconds == 180
        service.runner_status(profile_id=current.id)
        service.start_runner(profile_id=current.id)
        service._managed_runner(current)
        assert ("status", 180) in lifecycle.profile_budgets
        assert ("start", 180) in lifecycle.profile_budgets
        assert ("client_for_profile", 180) in lifecycle.profile_budgets
        assert lifecycle.runner.execute_calls == 0
    finally:
        service.close()


@pytest.mark.parametrize("mode", ["automatic", "lower_override", "cancel"])
def test_managed_host_real_watchdog_respects_scaled_deadlines(tmp_path, mode):
    import socket
    import time
    from concurrent.futures import ThreadPoolExecutor

    from bluefire.runner_client import RunnerTaskCancelled, RunnerTaskTimedOut
    from tests_platform.runner_lifecycle_host_helper import ProcessTestSecretProvider
    from tests_platform.test_authenticated_runner_transport import _result
    from tests_platform.test_runner_cancellation import _full_manifest, _full_profile
    from tests_platform.test_runner_lifecycle import PROFILE_ID, _fake_bootstrap, _host_command

    def command(spec):
        values = list(_host_command(spec))
        values[2] = "tests_platform.runner_deadline_host_helper"
        return values

    provider = ProcessTestSecretProvider()
    options = {"runner_timeout_seconds": 0.5} if mode == "lower_override" else {}
    lifecycle = ManagedRunnerLifecycle(
        tmp_path / "m",
        secret_provider=provider,
        bootstrap_factory=_fake_bootstrap,
        host_command_factory=command,
        start_timeout_seconds=10,
        stop_timeout_seconds=10,
        **options,
    )
    try:
        lifecycle.bootstrap(allowed_profile_ids=(PROFILE_ID,))
        ready = lifecycle.start(profile_id=PROFILE_ID, profile_budget_seconds=2)
        assert ready["state"] == "ready"
        actual = 0.5 if mode == "lower_override" else 7
        assert ready["health"]["execution_timeout_seconds"] == actual
        client, sandbox = lifecycle.client_for_profile(PROFILE_ID, profile_budget_seconds=2)
        assert client.socket_timeout_seconds == max(actual + 5, 10) + 5
        if mode == "automatic":
            ingress_started = time.monotonic()
            with socket.create_connection((client.host, client.port), timeout=3) as withheld:
                # This peer never sends a TLS handshake. A long native budget
                # must not keep its ingress slot occupied for that budget.
                try:
                    assert withheld.recv(1) == b""
                except ConnectionResetError:
                    pass
            assert 0.3 <= time.monotonic() - ingress_started < 3
        manifest = _full_manifest("sleep")
        profile = _full_profile()
        limits = {"timeout_ms": 2000, "max_artifact_bytes": 1024, "max_files": 8}
        manifest["limits"] = limits
        profile.update(sandbox_root=str(sandbox), limits=limits)
        manifest["result_override"] = _result(manifest, profile)
        started = time.monotonic()
        if mode == "automatic":
            assert client.execute(manifest, profile)["status"] == "success"
            assert time.monotonic() - started > 0.5
        elif mode == "lower_override":
            with pytest.raises(RunnerTaskTimedOut):
                client.execute(manifest, profile)
        else:
            task_id, _ = client.execution_identity(manifest, profile)
            cancellation = threading.Event()
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    client.execute_task,
                    manifest,
                    profile,
                    task_id=task_id,
                    cancel_event=cancellation,
                    durable_result_path=tmp_path / "unused-result.json",
                )
                try:
                    deadline = time.monotonic() + 10
                    while not (sandbox / "fixture-started").is_file():
                        assert not future.done(), "fixture failed before its actual process started"
                        assert time.monotonic() < deadline
                        cancellation.wait(0.01)
                    cancellation.set()
                    with pytest.raises(RunnerTaskCancelled):
                        future.result(timeout=10)
                finally:
                    cancellation.set()
        assert time.monotonic() - started < 12
        assert lifecycle.stop(profile_id=PROFILE_ID)["state"] == "stopped"
        assert not lifecycle._owned_processes
    finally:
        lifecycle.stop(profile_id=PROFILE_ID)
