from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import runner_lifecycle as lifecycle
from bluefire.runner_transport_errors import RunnerTransportError


@pytest.fixture
def fake_launch(monkeypatch):
    calls = []
    process = SimpleNamespace(
        pid=42,
        kill=lambda: calls.append("kill"),
        wait=lambda **kwargs: calls.append("wait"),
    )

    def popen(command, **options):
        assert command == ["fixed-test-host"]
        assert options["shell"] is False
        assert options["creationflags"] & 4
        assert options["creationflags"] & 0x08000000
        calls.append("spawn_suspended")
        return process

    def create():
        calls.append("create")
        return 123

    monkeypatch.setattr(lifecycle, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        lifecycle,
        "subprocess",
        SimpleNamespace(
            Popen=popen,
            DEVNULL=-3,
            CREATE_NO_WINDOW=0x08000000,
            TimeoutExpired=subprocess.TimeoutExpired,
        ),
    )
    monkeypatch.setattr(lifecycle, "_windows_create_kill_job", create)
    monkeypatch.setattr(lifecycle, "_windows_assign_process", lambda *args: calls.append("assign"))
    monkeypatch.setattr(
        lifecycle.WindowsJobContainment, "resume_suspended", lambda process: calls.append("resume")
    )
    monkeypatch.setattr(lifecycle, "_windows_terminate_job", lambda job: calls.append("terminate"))
    monkeypatch.setattr(
        lifecycle, "_windows_wait_job_empty", lambda *args, **kwargs: calls.append("drain")
    )
    monkeypatch.setattr(lifecycle, "_windows_close_handle", lambda job: calls.append("close"))
    return calls, process


def test_host_cannot_run_before_assignment(fake_launch):
    calls, process = fake_launch
    launch = lifecycle._spawn_contained_host(["fixed-test-host"])
    assert launch.process is process and launch.containment == 123
    assert calls == ["create", "spawn_suspended", "assign", "resume"]


@pytest.mark.parametrize("stage", ["spawn", "assign", "resume"])
@pytest.mark.parametrize("exception_type", [OSError, KeyboardInterrupt])
def test_failed_host_start_cleans_owned_handles_without_masking_failure(
    fake_launch, monkeypatch, stage, exception_type
):
    calls, _ = fake_launch
    error = exception_type("injected start failure")

    def fail(*args, **kwargs):
        calls.append("failed_" + stage)
        raise error

    if stage == "spawn":
        monkeypatch.setattr(lifecycle.subprocess, "Popen", fail)
    elif stage == "assign":
        monkeypatch.setattr(lifecycle, "_windows_assign_process", fail)
    else:
        monkeypatch.setattr(lifecycle.WindowsJobContainment, "resume_suspended", fail)
    with pytest.raises(exception_type) as caught:
        lifecycle._spawn_contained_host(["fixed-test-host"])
    assert caught.value is error
    assert calls.count("close") == 1
    assert calls[-2:] == ["drain", "close"]
    assert ("kill" in calls) is (stage != "spawn")
    assert ("wait" in calls) is (stage != "spawn")
    if stage != "resume":
        assert "resume" not in calls


def test_job_creation_failure_never_spawns(fake_launch, monkeypatch):
    calls, _ = fake_launch

    def fail():
        raise OSError("job creation failed")

    monkeypatch.setattr(lifecycle, "_windows_create_kill_job", fail)
    with pytest.raises(OSError, match="job creation failed"):
        lifecycle._spawn_contained_host(["fixed-test-host"])
    assert calls == []


def test_resume_transport_failure_uses_lifecycle_start_failure_contract(fake_launch, monkeypatch):
    calls, _ = fake_launch

    def fail(process):
        raise RunnerTransportError("private helper failure")

    monkeypatch.setattr(lifecycle.WindowsJobContainment, "resume_suspended", fail)
    with pytest.raises(OSError, match="host thread could not be resumed"):
        lifecycle._spawn_contained_host(["fixed-test-host"])
    assert calls[-5:] == ["terminate", "kill", "wait", "drain", "close"]


@pytest.mark.skipif(os.name != "nt", reason="Windows suspended launch")
def test_resume_failure_removes_start_gate_and_reaps_real_process(tmp_path, monkeypatch):
    from tests_platform.runner_lifecycle_host_helper import ProcessTestSecretProvider
    from tests_platform.test_runner_lifecycle import PROFILE_ID, _fake_bootstrap, _host_command

    manager = lifecycle.ManagedRunnerLifecycle(
        tmp_path / "managed",
        secret_provider=ProcessTestSecretProvider(),
        bootstrap_factory=_fake_bootstrap,
        host_command_factory=_host_command,
    )
    manager.bootstrap(allowed_profile_ids=(PROFILE_ID,))
    processes = []

    def fail(process):
        processes.append(process)
        raise RunnerTransportError("private helper failure")

    monkeypatch.setattr(lifecycle.WindowsJobContainment, "resume_suspended", fail)
    with pytest.raises(lifecycle.RunnerLifecycleError, match="could not be started"):
        manager.start(profile_id=PROFILE_ID)
    assert len(processes) == 1 and processes[0].poll() is not None
    assert not list(manager.control_root.glob(".host-start-*.gate"))
    assert not manager.process_record_path.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows suspended launch")
def test_real_host_remains_inert_until_job_assignment(tmp_path, monkeypatch):
    marker = tmp_path / "started.txt"
    original = lifecycle._windows_assign_process

    def delayed_assignment(job, process):
        deadline = time.monotonic() + 0.3
        while time.monotonic() < deadline:
            assert not marker.exists()
            time.sleep(0.01)
        original(job, process)

    monkeypatch.setattr(lifecycle, "_windows_assign_process", delayed_assignment)
    launch = lifecycle._spawn_contained_host(
        [
            str(Path(sys.executable).absolute()),
            "-c",
            f"from pathlib import Path; import time; Path({str(marker)!r}).write_bytes(b'ready'); time.sleep(30)",
        ]
    )
    try:
        deadline = time.monotonic() + 5
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert marker.read_bytes() == b"ready"
    finally:
        assert lifecycle._terminate_contained_launch(launch)
    assert launch.process.poll() is not None
