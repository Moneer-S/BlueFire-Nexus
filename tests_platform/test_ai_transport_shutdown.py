from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from bluefire import ai_transport
from bluefire.ai_transport import ManagedAIJSONTransport, UrllibAIJSONTransport
from bluefire.ai_wire import AIProviderTransportError
from bluefire.config import AIProviderKind
from bluefire.runner_lifecycle import ManagedRunnerLifecycle
from bluefire.service import BlueFireService
from tests_platform.test_ai_transport_deadline import endpoint as endpoint
from tests_platform.test_ai_transport_deadline import workers as workers
from tests_platform.test_ai_wire_runtime import _provider_config

ROOT = Path(__file__).resolve().parents[1]


def test_service_close_cancels_its_pending_checks_and_waits_for_worker_cleanup(
    tmp_path: Path,
    endpoint: tuple[str, threading.Event, list[str]],
    workers: list[subprocess.Popen[bytes]],
) -> None:
    url, entered, _ = endpoint
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "first-runs",
        runner_lifecycle=ManagedRunnerLifecycle(tmp_path / "first-managed"),
    )
    other = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "second-runs",
        runner_lifecycle=ManagedRunnerLifecycle(tmp_path / "second-managed"),
    )
    provider = replace(
        _provider_config(AIProviderKind.OPENAI_RESPONSES), endpoint=f"{url}/slow-body"
    )
    results: list[Any] = []
    thread = threading.Thread(
        target=lambda: results.append(
            service.check_ai_provider({"provider": provider.to_dict(), "connect": True})
        ),
        daemon=True,
    )
    try:
        thread.start()
        assert entered.wait(3)
        start = time.monotonic()
        service.close()
        assert time.monotonic() - start < 2
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert results[0]["code"] == "request_cancelled"
        assert results[0]["connectivity"] == "failed"
        assert results[0]["attempts"] == 1
        assert results[0]["used_fallback"] is False
        assert len(workers) == 1 and workers[0].poll() is not None
        assert not any(t.name == "bluefire-ai-request-writer" for t in threading.enumerate())
        success = other.check_ai_provider(
            {"provider": replace(provider, endpoint=f"{url}/success").to_dict(), "connect": True}
        )
        assert success["code"] == "probe_passed"
        refused = service.check_ai_provider({"provider": provider.to_dict(), "connect": True})
        assert refused["code"] == "request_cancelled"
        assert len(workers) == 2
    finally:
        service.close()
        other.close()
        thread.join(timeout=2)


def test_closed_owner_never_spawns_another_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    owner = ManagedAIJSONTransport()
    owner.close()
    monkeypatch.setattr(
        ai_transport.subprocess,
        "Popen",
        lambda *a, **k: pytest.fail("closed owner spawned a worker"),
    )
    with pytest.raises(AIProviderTransportError) as caught:
        owner.post("http://127.0.0.1:1/unused", headers={}, body=b"{}", timeout_seconds=1)
    assert caught.value.code == "request_cancelled"


def test_blocking_dns_is_bounded_and_reaped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, workers: list[subprocess.Popen[bytes]]
) -> None:
    worker = tmp_path / "blocked_dns.py"
    worker.write_text(
        "import socket, time, runpy\n"
        "def blocked(*args, **kwargs):\n    time.sleep(30)\n"
        "socket.getaddrinfo = blocked\n"
        f"runpy.run_path({str(ai_transport._WORKER)!r}, run_name='__main__')\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(ai_transport, "_WORKER", worker)
    started = time.monotonic()
    with pytest.raises(AIProviderTransportError) as caught:
        UrllibAIJSONTransport().post(
            "http://127.0.0.1:1/unused", headers={}, body=b"{}", timeout_seconds=0.6
        )
    assert caught.value.code == "request_timed_out"
    assert time.monotonic() - started < 1.5
    assert len(workers) == 1


@pytest.mark.parametrize("timeout", [301, float("inf"), float("nan"), 0, -1])
def test_transport_rejects_an_unbounded_worker_lifetime(timeout: float) -> None:
    with pytest.raises(AIProviderTransportError):
        UrllibAIJSONTransport().post(
            "http://127.0.0.1:1/unused", headers={}, body=b"{}", timeout_seconds=timeout
        )


def test_worker_deadline_applies_before_stdin_closes() -> None:
    started = time.monotonic()
    worker = subprocess.Popen(
        [sys._base_executable, "-I", "-B", str(ai_transport._WORKER), str(started + 0.6)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=ai_transport._worker_environment(),
        close_fds=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    try:
        assert worker.wait(timeout=2) == 124
        assert time.monotonic() - started < 1.5
    finally:
        if worker.poll() is None:
            worker.kill()
        worker.communicate(timeout=2)
        for stream in (worker.stdin, worker.stdout, worker.stderr):
            if stream is not None:
                stream.close()


def _windows_process_handle(pid: int) -> tuple[Any, Any]:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel.WaitForSingleObject.restype = ctypes.c_uint32
    kernel.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel.TerminateProcess.restype = ctypes.c_int
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel.OpenProcess(0x100000 | 0x1, False, pid)
    assert handle
    return kernel, handle


@pytest.mark.skipif(
    os.name != "nt" and sys.platform != "linux",
    reason="process lifetime checks use Windows handles or Linux procfs",
)
def test_daemon_parent_exit_does_not_leave_a_worker_past_its_deadline(
    endpoint: tuple[str, threading.Event, list[str]],
) -> None:
    url, entered, _ = endpoint
    # API request handlers are daemon threads. The parent exits normally once
    # the real worker has reached the local slow-drip response, so no parent
    # finally block or console signal can account for the worker's own exit.
    parent_source = """
import json, sys, threading
sys.path.insert(0, sys.argv[1])
from bluefire import ai_transport
original = ai_transport.subprocess.Popen
def capture(*args, **kwargs):
    worker = original(*args, **kwargs)
    print(json.dumps({'worker_pid': worker.pid}), flush=True)
    return worker
ai_transport.subprocess.Popen = capture
def request():
    ai_transport.UrllibAIJSONTransport().post(sys.argv[2], headers={}, body=b'{}', timeout_seconds=1.5)
threading.Thread(target=request, daemon=True).start()
sys.stdin.readline()
"""
    parent = subprocess.Popen(
        [sys._base_executable, "-I", "-c", parent_source, str(ROOT), f"{url}/slow-body"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    kernel = handle = None
    worker_pid = None
    worker_start = None
    identity: list[bytes] = []
    reader = threading.Thread(target=lambda: identity.append(parent.stdout.readline()), daemon=True)
    try:
        assert parent.stdout is not None
        reader.start()
        reader.join(timeout=3)
        assert not reader.is_alive() and identity
        worker_pid = json.loads(identity[0])["worker_pid"]
        if os.name == "nt":
            kernel, handle = _windows_process_handle(worker_pid)
        else:
            worker_start = Path(f"/proc/{worker_pid}/stat").read_text().split(")", 1)[1].split()[19]
        assert entered.wait(2)
        assert parent.stdin is not None
        parent.stdin.write(b"exit\n")
        parent.stdin.flush()
        parent.communicate(timeout=2)
        assert parent.returncode == 0
        if kernel is not None:
            assert kernel.WaitForSingleObject(handle, 2500) == 0
        else:
            # On Linux a dead orphan may remain a zombie under a test PID 1;
            # that process owns no socket or running code and is already done.
            end = time.monotonic() + 2.5
            while time.monotonic() < end:
                try:
                    state = Path(f"/proc/{worker_pid}/stat").read_text().split(")", 1)[1].split()[0]
                except FileNotFoundError:
                    break
                if state == "Z":
                    break
                time.sleep(0.02)
            else:
                pytest.fail("orphaned HTTP worker survived its deadline")
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.communicate(timeout=2)
        for stream in (parent.stdin, parent.stdout, parent.stderr):
            if stream is not None:
                stream.close()
        reader.join(timeout=2)
        if kernel is not None:
            if kernel.WaitForSingleObject(handle, 0) == 258:
                kernel.TerminateProcess(handle, 143)
                kernel.WaitForSingleObject(handle, 2000)
            kernel.CloseHandle(handle)
        elif worker_pid is not None:
            try:
                fields = Path(f"/proc/{worker_pid}/stat").read_text().split(")", 1)[1].split()
                if fields[19] == worker_start and fields[0] != "Z":
                    os.kill(worker_pid, 9)
            except (FileNotFoundError, ProcessLookupError):
                pass
