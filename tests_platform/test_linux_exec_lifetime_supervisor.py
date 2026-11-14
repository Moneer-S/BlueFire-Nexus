from __future__ import annotations

import json
import multiprocessing
import os
import signal
import socket
import sys
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest

from bluefire.engine_docker_transport import LinuxDockerDaemonEndpoint
from bluefire.engine_exec_operation_supervisor import (
    ExecLifetimeOperationRequestV2,
    ExecLifetimeSupervisorBindingV2,
)
from bluefire.linux_exec_lifetime_supervisor import (
    LinuxExecLifetimeSupervisorError,
    LinuxExecLifetimeSupervisorProfileV2,
    LinuxExecSupervisorContainerV2,
    LinuxExternalExecLifetimeSupervisorV2,
)
from bluefire.util import content_hash

ATTEMPT = "engine-attempt-" + "1" * 32
OPERATION = "operation-" + "2" * 32
CONTAINER = "3" * 64


def _digest(label: str) -> str:
    return content_hash(label)


def _binding() -> ExecLifetimeSupervisorBindingV2:
    return ExecLifetimeSupervisorBindingV2(
        attempt_id=ATTEMPT,
        claim_ref=_digest("claim"),
        controller_fence=_digest("fence"),
        custody_plan_digest=_digest("custody"),
        network_policy_digest=_digest("network"),
        controller_instance_ref=_digest("logical controller"),
        supervisor_qualification_ref=_digest("supervisor qualification"),
    )


class _DockerFixture:
    def __init__(self, root: Path, identity: LinuxExecSupervisorContainerV2) -> None:
        self.identity = identity
        self.path = root / "docker.sock"
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.path))
        self.listener.listen(8)
        self.listener.settimeout(0.1)
        self.running = True
        self.absent = False
        self.requests: list[str] = []
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    @property
    def endpoint(self) -> LinuxDockerDaemonEndpoint:
        info = self.path.lstat()
        return LinuxDockerDaemonEndpoint(
            socket_path=str(self.path),
            daemon_instance_digest=_digest("fixture daemon"),
            socket_device=info.st_dev,
            socket_inode=info.st_ino,
            peer_uid=os.geteuid(),
            peer_gid=os.getegid(),
            peer_pid=os.getpid(),
        )

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                channel, _address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with channel:
                channel.settimeout(1)
                value = bytearray()
                while b"\r\n\r\n" not in value and len(value) <= 16 * 1024:
                    block = channel.recv(4096)
                    if not block:
                        break
                    value.extend(block)
                line = bytes(value).split(b"\r\n", 1)[0].decode("ascii")
                with self.lock:
                    self.requests.append(line)
                    response = self._response(line)
                channel.sendall(response)

    def _response(self, line: str) -> bytes:
        inspect = f"GET /v1.43/containers/{CONTAINER}/json HTTP/1.1"
        stop = f"POST /v1.43/containers/{CONTAINER}/stop?t=10 HTTP/1.1"
        remove = f"DELETE /v1.43/containers/{CONTAINER}?force=1&v=1 HTTP/1.1"
        if line == inspect:
            if self.absent:
                return self._json(404, {"message": f"No such container: {CONTAINER}"})
            return self._json(
                200,
                {
                    "Id": CONTAINER,
                    "Name": "/" + self.identity.container_name,
                    "Image": self.identity.image_config_digest,
                    "Config": {
                        "Image": self.identity.image_reference,
                        "Labels": dict(self.identity.required_labels),
                    },
                    "State": {"Running": self.running},
                },
            )
        if line == stop:
            self.running = False
            return b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
        if line == remove:
            self.running = False
            self.absent = True
            return b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
        return self._json(404, {"message": "unrecognized"})

    @staticmethod
    def _json(status: int, value: object) -> bytes:
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        reason = "OK" if status == 200 else "Not Found"
        return (
            f"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("ascii") + body

    def close(self) -> None:
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=2)


def _identity() -> LinuxExecSupervisorContainerV2:
    policy = _digest("policy")
    execution = _digest("execution")
    profile = _digest("profile")
    labels = tuple(
        sorted(
            {
                "bluefire.engine.attempt": ATTEMPT,
                "bluefire.engine.image-identity": _digest("image identity"),
                "strix-run-id": ATTEMPT,
                "strix-run-type": "bluefire",
            }.items()
        )
    )
    return LinuxExecSupervisorContainerV2(
        container_id=CONTAINER,
        container_name="strix-sandbox-supervisor-test",
        image_config_digest="sha256:" + "4" * 64,
        image_reference="ghcr.io/usestrix/strix-sandbox@sha256:" + "5" * 64,
        required_labels=labels,
        policy_digest=policy,
        execution_identity_digest=execution,
        profile_digest=profile,
    )


def _profile(
    state: Path,
    endpoint: LinuxDockerDaemonEndpoint,
    identity: LinuxExecSupervisorContainerV2,
) -> LinuxExecLifetimeSupervisorProfileV2:
    return LinuxExecLifetimeSupervisorProfileV2(
        state_directory=state,
        daemon_endpoint=endpoint,
        api_version="v1.43",
        containers=(identity,),
        supervisor_qualification_ref=_binding().supervisor_qualification_ref,
        heartbeat_interval_milliseconds=50,
        controller_loss_grace_milliseconds=300,
        cleanup_timeout_milliseconds=3_000,
        startup_timeout_milliseconds=5_000,
    )


def _controller(profile: LinuxExecLifetimeSupervisorProfileV2, ready: Path) -> None:
    binding = _binding()
    backend = LinuxExternalExecLifetimeSupervisorV2.new(profile)
    activation = backend.activate_new(binding)
    request = ExecLifetimeOperationRequestV2(
        admission_digest=_digest("admission"),
        attempt_id=binding.attempt_id,
        operation_id=OPERATION,
        container_id=CONTAINER,
        claim_ref=binding.claim_ref,
        controller_fence=binding.controller_fence,
        custody_plan_digest=binding.custody_plan_digest,
        network_policy_digest=binding.network_policy_digest,
        operation_deadline_monotonic_ns=time.monotonic_ns() + 20_000_000_000,
        controller_instance_ref=binding.controller_instance_ref,
        supervisor_instance_ref=activation.supervisor_instance_ref,
    )
    proof = backend.arm(request)
    process = backend._process  # protected-process identity is test evidence only
    ready.write_text(
        json.dumps(
            {
                "broker_pid": None if process is None else process.pid,
                "request_ref": request.request_ref,
                "lease_ref": proof.lease_ref,
            }
        ),
        encoding="utf-8",
    )
    while True:
        time.sleep(1)


def _controller_capture(profile: LinuxExecLifetimeSupervisorProfileV2, ready: Path) -> None:
    try:
        _controller(profile, ready)
    except BaseException as exc:
        ready.with_suffix(".error").write_text(f"{type(exc).__name__}: {exc}", encoding="utf-8")
        raise


def _reopen(
    profile: LinuxExecLifetimeSupervisorProfileV2,
    *,
    timeout: float = 10,
) -> tuple[LinuxExternalExecLifetimeSupervisorV2, Any]:
    deadline = time.monotonic() + timeout
    error: Exception | None = None
    while time.monotonic() < deadline:
        backend = LinuxExternalExecLifetimeSupervisorV2.reconcile(profile)
        try:
            return backend, backend.reopen_existing(_binding())
        except Exception as exc:  # old broker may still hold the process lock
            error = exc
            time.sleep(0.05)
    raise AssertionError("supervisor did not become recoverable") from error


@pytest.mark.skipif(sys.platform != "linux", reason="Linux pidfd/peer proof")
def test_controller_and_recovery_crashes_replay_exact_terminal_until_ack(
    tmp_path: Path,
) -> None:
    identity = _identity()
    docker = _DockerFixture(tmp_path, identity)
    state = tmp_path / "supervisor-state"
    ready = tmp_path / "controller-ready.json"
    profile = _profile(state, docker.endpoint, identity)
    context = multiprocessing.get_context("fork")
    controller = context.Process(target=_controller_capture, args=(profile, ready))
    controller.start()
    first_recovery: LinuxExternalExecLifetimeSupervisorV2 | None = None
    second_recovery: LinuxExternalExecLifetimeSupervisorV2 | None = None
    broker_pid: int | None = None
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not ready.exists():
            time.sleep(0.02)
        error_path = ready.with_suffix(".error")
        assert ready.exists(), (
            error_path.read_text(encoding="utf-8")
            if error_path.exists()
            else f"controller exited {controller.exitcode}"
        )
        broker_pid = json.loads(ready.read_text(encoding="utf-8"))["broker_pid"]

        os.kill(controller.pid, signal.SIGKILL)
        controller.join(timeout=5)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not docker.absent:
            time.sleep(0.02)
        assert docker.absent is True

        first_recovery, first_activation = _reopen(profile)
        assert len(first_activation.terminal_receipts) == 1
        first_receipt = first_activation.terminal_receipts[0]
        assert first_receipt.outcome == "verified_absent"
        first_events = first_recovery.terminal_events()
        assert len(first_events) == 1
        first_process = first_recovery._process
        assert first_process is not None
        os.kill(first_process.pid, signal.SIGKILL)
        first_process.wait(timeout=5)
        first_recovery.detach()

        second_recovery, second_activation = _reopen(profile)
        assert second_activation.terminal_receipts[0].receipt_ref == first_receipt.receipt_ref
        second_events = second_recovery.terminal_events()
        assert second_events[0].cursor == first_events[0].cursor
        assert second_events[0].receipt.receipt_ref == first_receipt.receipt_ref
        second_recovery.acknowledge_terminal(
            cursor=second_events[0].cursor,
            receipt_ref=second_events[0].receipt.receipt_ref,
        )
        assert second_recovery.terminal_events() == ()
        second_recovery.close()
        second_recovery = None

        allowed = (
            f"GET /v1.43/containers/{CONTAINER}/json HTTP/1.1",
            f"POST /v1.43/containers/{CONTAINER}/stop?t=10 HTTP/1.1",
            f"DELETE /v1.43/containers/{CONTAINER}?force=1&v=1 HTTP/1.1",
        )
        assert docker.requests
        assert all(item in allowed for item in docker.requests)
        assert any(item.startswith("DELETE ") for item in docker.requests)
    finally:
        if controller.is_alive():
            controller.kill()
            controller.join(timeout=5)
        for backend in (first_recovery, second_recovery):
            if backend is not None:
                process = backend._process
                if process is not None and process.poll() is None:
                    os.kill(process.pid, signal.SIGKILL)
        if broker_pid is not None:
            try:
                os.kill(broker_pid, 0)
            except ProcessLookupError:
                pass
        docker.close()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux pidfd/peer proof")
def test_broker_crash_while_controller_lives_still_cleans_owned_container(
    tmp_path: Path,
) -> None:
    identity = _identity()
    docker = _DockerFixture(tmp_path, identity)
    state = tmp_path / "supervisor-state"
    ready = tmp_path / "controller-ready.json"
    profile = _profile(state, docker.endpoint, identity)
    controller = multiprocessing.get_context("fork").Process(
        target=_controller_capture, args=(profile, ready)
    )
    controller.start()
    broker_pid: int | None = None
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not ready.exists():
            time.sleep(0.02)
        error_path = ready.with_suffix(".error")
        assert ready.exists(), (
            error_path.read_text(encoding="utf-8")
            if error_path.exists()
            else f"controller exited {controller.exitcode}"
        )
        broker_pid = json.loads(ready.read_text(encoding="utf-8"))["broker_pid"]
        assert isinstance(broker_pid, int) and broker_pid > 0
        assert controller.is_alive()

        os.kill(broker_pid, signal.SIGKILL)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not docker.absent:
            time.sleep(0.02)
        assert docker.absent is True
        assert controller.is_alive()
        assert any(item.startswith("DELETE ") for item in docker.requests)
    finally:
        if controller.is_alive():
            controller.kill()
        controller.join(timeout=5)
        docker.close()


def test_profile_ref_binds_docker_endpoint_and_exact_container_identity(tmp_path: Path) -> None:
    identity = _identity()
    endpoint = LinuxDockerDaemonEndpoint(
        socket_path="/tmp/bluefire-test-docker.sock",
        daemon_instance_digest=_digest("daemon"),
        socket_device=1,
        socket_inode=2,
        peer_uid=3,
        peer_gid=4,
        peer_pid=5,
    )
    profile = _profile(tmp_path / "state", endpoint, identity)
    changed_endpoint = LinuxDockerDaemonEndpoint(**{**asdict(endpoint), "socket_inode": 9})
    assert (
        profile.profile_ref != _profile(tmp_path / "state", changed_endpoint, identity).profile_ref
    )


def test_profile_rejects_api_version_without_fixed_cleanup_support(tmp_path: Path) -> None:
    identity = _identity()
    endpoint = LinuxDockerDaemonEndpoint(
        socket_path="/tmp/bluefire-test-docker.sock",
        daemon_instance_digest=_digest("daemon"),
        socket_device=1,
        socket_inode=2,
        peer_uid=3,
        peer_gid=4,
        peer_pid=5,
    )
    with pytest.raises(LinuxExecLifetimeSupervisorError, match="API version"):
        LinuxExecLifetimeSupervisorProfileV2(
            state_directory=tmp_path / "state",
            daemon_endpoint=endpoint,
            api_version="v1.44",
            containers=(identity,),
            supervisor_qualification_ref=_binding().supervisor_qualification_ref,
        )
