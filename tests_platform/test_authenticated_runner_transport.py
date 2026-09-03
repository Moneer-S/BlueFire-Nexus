from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import socket
import sqlite3
import ssl
import threading
import time
from pathlib import Path
from typing import Any, Mapping

import pytest

import bluefire.runner_transport as wire
from bluefire.orchestrator import Orchestrator
from bluefire.runner_client import (
    InventoryBoundRunner,
    RunnerReadinessError,
    RunnerTaskCancelled,
    RunnerTaskTimedOut,
    RunnerTransportError,
    SubprocessRustRunner,
    canonical_runner_inventory,
    request_runner_task_cancel,
    runner_pending_result_path,
    runner_transport_identity,
    runner_watchdog_cancel_path,
    runner_watchdog_control_root,
)
from bluefire.runner_inventory import (
    BUILTIN_RUNNER_ACTION_VERSIONS,
    RUNNER_ACTION_SDK_SCHEMA_VERSION,
)
from bluefire.runner_transport import (
    AuthenticatedRunnerClient,
    AuthenticatedRunnerServer,
    AuthenticatedRunnerTransportError,
    RunnerAuthenticationError,
    RunnerConnectionError,
    RunnerRemoteError,
    audit_runner_ledger,
    read_runner_ledger_generation,
    runner_result_namespace_path,
)
from bluefire.runner_trust import (
    RunnerEnrollment,
    create_local_enrollment,
    load_local_enrollment,
    remove_local_enrollment,
    revoke_local_enrollment,
)
from bluefire.secret_store import InMemorySecretProvider
from bluefire.util import canonical_json_bytes, content_hash, file_hash

PROFILE_ID = "sandbox-execute.v1"
RUNNER_ID = "bluefire-rust-runner.v1"
POLICY_DIGEST = "sha256:" + "2" * 64


def _inventory() -> Mapping[str, Any]:
    return {
        "schema_version": "bluefire.runner-inventory.v1",
        "runner_id": "bluefire-rust-runner.v1",
        "runner_version": "0.1.0",
        "action_sdk_version": RUNNER_ACTION_SDK_SCHEMA_VERSION,
        "receipt_protocol": "bluefire.runner-receipt-wal.v2",
        "platform": "windows",
        "actions": [
            {
                "schema_version": RUNNER_ACTION_SDK_SCHEMA_VERSION,
                "action_id": "sandbox.fixture.create.v1",
                "action_version": BUILTIN_RUNNER_ACTION_VERSIONS["sandbox.fixture.create.v1"],
                "readiness": "ready",
            }
        ],
    }


def _result(
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    *,
    call: int = 1,
    output_text: str = "",
    receipt_ids: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "bluefire.runner-result.v1",
        "request_id": manifest["request_id"],
        "run_id": manifest["run_id"],
        "step_id": manifest["step_id"],
        "behavior_id": manifest["behavior_id"],
        "action_id": manifest["action_id"],
        "status": "success",
        "runner_id": manifest["runner_id"],
        "runner_profile_id": manifest["runner_profile_id"],
        "platform": manifest["platform"],
        "request_hash": manifest["request_hash"],
        "policy_digest": profile["policy_digest"],
        "started_at": "2026-08-25T12:00:00Z",
        "finished_at": "2026-08-25T12:00:01Z",
        "output": {"call": call, "text": output_text},
        "stdout": {"text": "", "total_bytes": 0, "truncated": False},
        "stderr": {"text": "", "total_bytes": 0, "truncated": False},
        "receipt_ids": list(receipt_ids or []),
        "cleanup": None,
        "evidence": [],
        "error": None,
        "limitations": ["deterministic test runner"],
    }


def _write_receipt(
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    *,
    action_id: str | None = None,
) -> str:
    sandbox = Path(str(profile["sandbox_root"])).resolve(strict=True)
    artifact = sandbox / "fixtures" / "effect.txt"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_bytes(b"x")
    workspace_id = hashlib.sha256(str(sandbox).replace("\\", "/").encode("utf-8")).hexdigest()
    paths = [
        {
            "relative_path": "fixtures/effect.txt",
            "kind": "file",
            "sha256": hashlib.sha256(b"x").hexdigest(),
            "size": 1,
        }
    ]
    identity = {
        "schema_version": "bluefire.receipt/v1",
        "request_hash": manifest["request_hash"],
        "action_id": action_id or manifest["action_id"],
        "runner_profile_id": profile["profile_id"],
        "workspace_id": workspace_id,
        "created_at": "2026-08-25T12:00:00Z",
        "paths": paths,
    }
    receipt_id = hashlib.sha256(canonical_json_bytes(identity)).hexdigest()
    receipt = {**identity, "receipt_id": receipt_id}
    commit = {
        "schema_version": "bluefire.receipt-commit/v1",
        "receipt_id": receipt_id,
        "runner_profile_id": profile["profile_id"],
        "workspace_id": workspace_id,
        "committed_at": "2026-08-25T12:00:01Z",
    }
    receipts = sandbox / ".bluefire" / "receipts"
    commits = sandbox / ".bluefire" / "receipt-commits"
    receipts.mkdir(parents=True, exist_ok=True)
    commits.mkdir(parents=True, exist_ok=True)
    (receipts / f"{receipt_id}.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    (commits / f"{receipt_id}.json").write_text(json.dumps(commit, indent=2), encoding="utf-8")
    return receipt_id


class RecordingRunner:
    def __init__(self) -> None:
        self.calls = 0

    def inventory(self) -> Mapping[str, Any]:
        return _inventory()

    def execute(self, manifest: Mapping[str, Any], profile: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls += 1
        return _result(manifest, profile, call=self.calls)


class DelayedRunner(RecordingRunner):
    def __init__(self, delay_seconds: float) -> None:
        super().__init__()
        self.delay_seconds = delay_seconds

    def execute(self, manifest: Mapping[str, Any], profile: Mapping[str, Any]) -> Mapping[str, Any]:
        time.sleep(self.delay_seconds)
        return super().execute(manifest, profile)


class BlockingRunner(RecordingRunner):
    def __init__(self) -> None:
        super().__init__()
        self.started = threading.Event()
        self.release = threading.Event()

    def execute(self, manifest: Mapping[str, Any], profile: Mapping[str, Any]) -> Mapping[str, Any]:
        self.started.set()
        if not self.release.wait(timeout=30):
            raise RuntimeError("test release timed out")
        return super().execute(manifest, profile)


class SaturatingBlockingRunner(RecordingRunner):
    def __init__(self) -> None:
        super().__init__()
        self.started_count = 0
        self.started = threading.Condition()
        self.release = threading.Event()

    def execute(self, manifest: Mapping[str, Any], profile: Mapping[str, Any]) -> Mapping[str, Any]:
        with self.started:
            self.started_count += 1
            self.started.notify_all()
        if not self.release.wait(timeout=30):
            raise RuntimeError("test release timed out")
        return super().execute(manifest, profile)

    def wait_for_started(self, expected: int) -> bool:
        deadline = time.monotonic() + 15
        with self.started:
            while self.started_count < expected:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self.started.wait(timeout=remaining)
        return True


class SlowInventoryCancellationRunner(RecordingRunner):
    def __init__(self) -> None:
        super().__init__()
        self.inventory_started = threading.Event()
        self.release_inventory = threading.Event()

    def inventory(self) -> Mapping[str, Any]:
        self.inventory_started.set()
        if not self.release_inventory.wait(timeout=30):
            raise RuntimeError("test inventory release timed out")
        return _inventory()

    def execute_task(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
    ) -> Mapping[str, Any]:
        self.calls += 1
        raise AssertionError("pre-effect cancelled task was launched")


class BinaryReplacingInventoryRunner(RecordingRunner):
    def __init__(self, runner_binary: Path) -> None:
        super().__init__()
        self.runner_binary = runner_binary
        self.inventory_calls = 0

    def inventory(self) -> Mapping[str, Any]:
        self.inventory_calls += 1
        try:
            self.runner_binary.write_bytes(b"runner-v2")
        finally:
            raise RuntimeError("inventory failed after binary mutation")


class BlockingInventoryRunner(RecordingRunner):
    def __init__(self) -> None:
        super().__init__()
        self.block_inventory = False
        self.inventory_count = 0
        self.inventory_entered = threading.Condition()
        self.release_inventory = threading.Event()

    def inventory(self) -> Mapping[str, Any]:
        if self.block_inventory:
            with self.inventory_entered:
                self.inventory_count += 1
                self.inventory_entered.notify_all()
            if not self.release_inventory.wait(timeout=30):
                raise RuntimeError("test inventory release timed out")
        return _inventory()

    def wait_for_inventory(self, expected: int) -> bool:
        deadline = time.monotonic() + 15
        with self.inventory_entered:
            while self.inventory_count < expected:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self.inventory_entered.wait(timeout=remaining)
        return True


class TaskAwareCancellationRunner(RecordingRunner):
    def __init__(self) -> None:
        super().__init__()
        self.started = threading.Event()
        self.cancel_event: threading.Event | None = None
        self.durable_result_path: Path | None = None

    def execute_task(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
    ) -> Mapping[str, Any]:
        self.calls += 1
        self.cancel_event = cancel_event
        self.durable_result_path = Path(durable_result_path)
        self.started.set()
        if not cancel_event.wait(timeout=30):
            raise RuntimeError("test cancellation timed out")
        raise RunnerTaskCancelled("test process tree stopped")


class TaskAwareReceiptCancellationRunner(TaskAwareCancellationRunner):
    def __init__(self) -> None:
        super().__init__()
        self.receipt_id: str | None = None

    def execute_task(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
    ) -> Mapping[str, Any]:
        self.calls += 1
        self.cancel_event = cancel_event
        self.durable_result_path = Path(durable_result_path)
        self.started.set()
        if not cancel_event.wait(timeout=30):
            raise RuntimeError("test cancellation timed out")
        self.receipt_id = _write_receipt(manifest, profile)
        raise RunnerTaskCancelled("test process tree stopped after committed effect")


class TaskAwareTimeoutRunner(RecordingRunner):
    def execute_task(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
    ) -> Mapping[str, Any]:
        self.calls += 1
        raise RunnerTaskTimedOut("test process tree stopped after timeout")


class TaskAwareCompletionRunner(RecordingRunner):
    def __init__(self) -> None:
        super().__init__()
        self.started = threading.Event()
        self.release = threading.Event()
        self.cancel_event: threading.Event | None = None

    def execute_task(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
    ) -> Mapping[str, Any]:
        self.calls += 1
        self.cancel_event = cancel_event
        self.started.set()
        if not self.release.wait(timeout=30):
            raise RuntimeError("test completion release timed out")
        return _result(manifest, profile, call=self.calls)


class EffectThenRaiseRunner(RecordingRunner):
    def __init__(self, *, write_receipt: bool = False, receipt_matches: bool = True) -> None:
        super().__init__()
        self.write_receipt = write_receipt
        self.receipt_matches = receipt_matches
        self.receipt_id: str | None = None

    def execute(self, manifest: Mapping[str, Any], profile: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls += 1
        if self.write_receipt:
            self.receipt_id = _write_receipt(
                manifest,
                profile,
                action_id=(
                    str(manifest["action_id"])
                    if self.receipt_matches
                    else "sandbox.fixture.transform.v1"
                ),
            )
        raise RuntimeError("effect completed before runner transport failed")


class OversizedResultRunner(RecordingRunner):
    def execute(self, manifest: Mapping[str, Any], profile: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls += 1
        return _result(manifest, profile, call=self.calls, output_text="x" * 8192)


class MismatchedResultRunner(RecordingRunner):
    def execute(self, manifest: Mapping[str, Any], profile: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls += 1
        result = _result(manifest, profile, call=self.calls)
        result["runner_id"] = "different-runner.v1"
        return result


class MismatchedInventoryRunner(RecordingRunner):
    def inventory(self) -> Mapping[str, Any]:
        return {**dict(_inventory()), "runner_id": "different-runner.v1"}


class FailFirstExecuteCompletionServer(AuthenticatedRunnerServer):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.failed_completion = False

    def _complete_request(self, task_id: str, payload: Mapping[str, Any]) -> None:
        if task_id.startswith("execute-") and not self.failed_completion:
            self.failed_completion = True
            raise sqlite3.OperationalError("synthetic completion write failure")
        super()._complete_request(task_id, payload)


class TamperingServer(AuthenticatedRunnerServer):
    def _success_response(
        self,
        request: Mapping[str, Any],
        enrollment: RunnerEnrollment,
        payload: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        response = dict(super()._success_response(request, enrollment, payload))
        authentication = str(response["authentication"])
        response["authentication"] = authentication[:-1] + (
            "0" if authentication[-1] != "0" else "1"
        )
        return response


class DropFirstExecutionResponseServer(AuthenticatedRunnerServer):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.dropped = False

    def _dispatch(
        self,
        request: Mapping[str, Any],
        enrollment: RunnerEnrollment,
        peer_fingerprint: str,
    ) -> Mapping[str, Any]:
        response = super()._dispatch(request, enrollment, peer_fingerprint)
        if request.get("operation") == "execute" and not self.dropped:
            self.dropped = True
            raise RunnerConnectionError("synthetic lost response")
        return response


class DropFirstCancelResponseServer(AuthenticatedRunnerServer):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.dropped_cancel = False

    def _dispatch(
        self,
        request: Mapping[str, Any],
        enrollment: RunnerEnrollment,
        peer_fingerprint: str,
    ) -> Mapping[str, Any]:
        response = super()._dispatch(request, enrollment, peer_fingerprint)
        if request.get("operation") == "cancel" and not self.dropped_cancel:
            self.dropped_cancel = True
            raise RunnerConnectionError("synthetic lost cancellation response")
        return response


@pytest.fixture
def secret_provider() -> InMemorySecretProvider:
    return InMemorySecretProvider()


@pytest.fixture
def enrollment_root(tmp_path: Path, secret_provider: InMemorySecretProvider) -> Path:
    root = tmp_path / "trust"
    create_local_enrollment(
        root,
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=[PROFILE_ID],
        secret_provider=secret_provider,
    )
    return root


@pytest.fixture
def manifest() -> Mapping[str, Any]:
    return {
        "schema_version": "bluefire.runner-manifest.v1",
        "request_id": "request-1",
        "request_hash": "sha256:" + "1" * 64,
        "run_id": "run-1",
        "step_id": "step-1",
        "behavior_id": "sandbox.fixture.create.v1",
        "action_id": "sandbox.fixture.create.v1",
        "runner_id": RUNNER_ID,
        "runner_profile_id": PROFILE_ID,
        "platform": "windows",
        "policy_digest": POLICY_DIGEST,
        "limits": {"max_artifact_bytes": 1024, "max_files": 8},
    }


@pytest.fixture
def profile(tmp_path: Path) -> Mapping[str, Any]:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    return {
        "schema_version": "bluefire.runner-profile.v1",
        "profile_id": PROFILE_ID,
        "runner_id": RUNNER_ID,
        "platform": "windows",
        "sandbox_root": str(sandbox.resolve(strict=True)),
        "policy_digest": POLICY_DIGEST,
        "limits": {"max_artifact_bytes": 1024, "max_files": 8},
    }


def _client(
    root: Path,
    server: AuthenticatedRunnerServer,
    secret_provider: InMemorySecretProvider,
    *,
    profile_id: str = PROFILE_ID,
    timeout_seconds: float = 2,
) -> AuthenticatedRunnerClient:
    host, port = server.server_address
    return AuthenticatedRunnerClient(
        root,
        profile_id=profile_id,
        host=host,
        port=port,
        socket_timeout_seconds=timeout_seconds,
        recovery_delay_seconds=0.01,
        secret_provider=secret_provider,
    )


def _unsigned_request(
    enrollment: RunnerEnrollment,
    *,
    operation: str = "health",
    profile_id: str = PROFILE_ID,
    task_id: str = "health-raw",
    payload: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    body = dict(payload or {})
    return {
        "schema_version": wire.TRANSPORT_SCHEMA_VERSION,
        "kind": "request",
        "operation": operation,
        "runner_id": enrollment.runner_id,
        "client_id": enrollment.client_id,
        "profile_id": profile_id,
        "task_id": task_id,
        "nonce": secrets.token_hex(32),
        "request_hash": content_hash(body),
        "payload": body,
    }


def _raw_exchange(
    root: Path,
    server: AuthenticatedRunnerServer,
    request: Mapping[str, Any],
    secret_provider: InMemorySecretProvider,
) -> Mapping[str, Any]:
    enrollment = load_local_enrollment(root, secret_provider=secret_provider)
    return _raw_exchange_enrollment(enrollment, server, request)


def _raw_exchange_enrollment(
    enrollment: RunnerEnrollment,
    server: AuthenticatedRunnerServer,
    request: Mapping[str, Any],
) -> Mapping[str, Any]:
    context = wire._client_context(enrollment)
    host, port = server.server_address
    with socket.create_connection((host, port), timeout=2) as raw:
        raw.settimeout(2)
        with context.wrap_socket(raw, server_hostname=host) as connection:
            wire._verify_peer(
                connection,
                expected_fingerprint=str(enrollment.metadata["server_fingerprint"]),
                expected_common_name=enrollment.runner_id,
            )
            wire._send_frame(connection, request, wire.DEFAULT_MAX_FRAME_BYTES)
            return wire._receive_frame(connection, wire.DEFAULT_MAX_FRAME_BYTES)


def _write_watchdog_status(
    root: Path,
    task_id: str,
    *,
    state: str,
    error_code: str | None,
    result_path: Path | None = None,
) -> None:
    status: dict[str, Any] = {
        "schema_version": "bluefire.runner-watchdog-status.v2",
        "task_id": task_id,
        "state": state,
        "error_code": error_code,
        "watchdog_pid": 4242,
    }
    if state == "cancelled":
        status.update(
            {
                "cooperative_requested": False,
                "cooperative_acknowledged": False,
                "forced_tree_termination": True,
                "control_cleanup_verified": True,
            }
        )
    if state == "succeeded":
        if result_path is None:
            raise AssertionError("succeeded watchdog status requires a result")
        status["result_digest"] = file_hash(result_path)
    (root / "status.json").write_bytes(canonical_json_bytes(status))


def test_mutual_tls_health_inventory_execute_and_exact_duplicate_recovery(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    runner = RecordingRunner()
    with AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        client = _client(enrollment_root, server, secret_provider)
        health = client.health()
        assert {
            key: health[key]
            for key in (
                "schema_version",
                "status",
                "runner_id",
                "profile_id",
                "transport",
                "tls",
                "runner_binary_digest",
            )
        } == {
            "schema_version": "bluefire.runner-health.v1",
            "status": "ready",
            "runner_id": "bluefire-rust-runner.v1",
            "profile_id": PROFILE_ID,
            "transport": "mutual-tls-loopback",
            "tls": "TLSv1.3",
            "runner_binary_digest": None,
        }
        assert str(health["server_fingerprint"]).startswith("sha256:")
        assert str(health["client_fingerprint"]).startswith("sha256:")
        assert health["authenticated_peer_fingerprint"] == health["client_fingerprint"]
        assert str(health["inventory_digest"]).startswith("sha256:")
        assert health["ledger"]["accepting_execute"] is True
        assert client.inventory()["runner_id"] == "bluefire-rust-runner.v1"

        first = client.execute(manifest, profile)
        second = client.execute(manifest, profile)

    assert first == second
    assert first["output"]["call"] == 1
    assert runner.calls == 1


def test_client_recovers_exact_result_when_execution_response_is_lost(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    runner = RecordingRunner()
    server = DropFirstExecutionResponseServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    )
    with server:
        result = _client(enrollment_root, server, secret_provider).execute(manifest, profile)

    assert server.dropped is True
    assert result["output"]["call"] == 1
    assert runner.calls == 1


def test_budgeted_execution_accepts_a_valid_response_after_five_seconds(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    runner = DelayedRunner(5.25)
    with AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        socket_timeout_seconds=5,
        secret_provider=secret_provider,
    ) as server:
        client = _client(
            enrollment_root,
            server,
            secret_provider,
            timeout_seconds=10,
        )
        started = time.monotonic()
        result = client.execute(manifest, profile)

    assert time.monotonic() - started >= 5.0
    assert result["status"] == "success"
    assert result["output"]["call"] == 1
    assert runner.calls == 1


def test_decoder_rejects_noncanonical_and_duplicate_key_json() -> None:
    with pytest.raises(RunnerAuthenticationError, match="canonical JSON"):
        wire._decode_json_object(b'{"b":2, "a":1}')
    with pytest.raises(RunnerAuthenticationError, match="canonical JSON"):
        wire._decode_json_object(b'{"a":1,"a":2}')


def test_receive_deadline_rejects_slow_trickle_even_when_each_read_progresses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Clock:
        now = 100.0

        def monotonic(self) -> float:
            return self.now

    clock = Clock()

    class SlowTrickle:
        def __init__(self) -> None:
            self.reads = 0
            self.timeouts: list[float] = []

        def settimeout(self, value: float) -> None:
            self.timeouts.append(value)

        def recv(self, _length: int) -> bytes:
            self.reads += 1
            clock.now += 0.03
            return b"x"

    monkeypatch.setattr(wire, "time", clock)
    trickle = SlowTrickle()
    with pytest.raises(RunnerConnectionError, match="deadline"):
        wire._receive_exact(
            trickle,  # type: ignore[arg-type]
            3,
            deadline=clock.monotonic() + 0.08,
        )
    assert trickle.reads == 3
    assert trickle.timeouts == pytest.approx([0.08, 0.05, 0.02])


def test_authenticated_client_cannot_dispatch_same_payload_under_alternate_task_id(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    runner = RecordingRunner()
    with AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        enrollment = load_local_enrollment(enrollment_root, secret_provider=secret_provider)
        unsigned = _unsigned_request(
            enrollment,
            operation="execute",
            task_id="execute-attacker-selected",
            payload={"manifest": manifest, "profile": profile},
        )
        request = wire._sign_request(enrollment, unsigned)
        response = _raw_exchange_enrollment(enrollment, server, request)
        with pytest.raises(RunnerRemoteError, match="invalid") as error:
            AuthenticatedRunnerClient._validated_response(response, request, enrollment)

    assert error.value.code == "request_invalid"
    assert runner.calls == 0


def test_orchestrator_identity_dispatches_through_inventory_bound_authenticated_client(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    runner = RecordingRunner()
    with AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        client = _client(enrollment_root, server, secret_provider)
        inventory = client.inventory()
        bound = InventoryBoundRunner(
            client,
            expected_inventory_digest=content_hash(canonical_runner_inventory(inventory)),
            expected_identity_digest=content_hash(runner_transport_identity(client, inventory)),
            recovery_identity={},
        )
        task_id = Orchestrator._execution_task_id(manifest, profile)
        result = bound.execute_task(
            manifest,
            profile,
            task_id=task_id,
            cancel_event=threading.Event(),
            durable_result_path=(tmp_path / "caller-result.json").resolve(),
        )
        request_hash = content_hash({"manifest": dict(manifest), "profile": dict(profile)})
        recovered = client.recover(task_id, request_hash)

    assert result["status"] == "success"
    assert runner.calls == 1
    assert client.last_execution_identity == (task_id, request_hash)
    assert recovered["state"] == "completed"


def test_second_live_server_for_same_ledger_is_refused(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "transport.sqlite3"
    first = AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        state_path,
        secret_provider=secret_provider,
    )
    try:
        with pytest.raises(AuthenticatedRunnerTransportError, match="already owned"):
            AuthenticatedRunnerServer(
                enrollment_root,
                RecordingRunner(),
                state_path,
                secret_provider=secret_provider,
            )
    finally:
        first.shutdown()


def test_hmac_failure_profile_refusal_and_wire_replay_are_authenticated(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
) -> None:
    with AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        enrollment = load_local_enrollment(enrollment_root, secret_provider=secret_provider)

        unsigned = _unsigned_request(enrollment, task_id="bad-hmac")
        bad_hmac = wire._sign_request(enrollment, unsigned)
        bad_hmac["authentication"] = "sha256:" + "0" * 64
        response = _raw_exchange(enrollment_root, server, bad_hmac, secret_provider)
        with pytest.raises(RunnerRemoteError, match="authentication failed") as error:
            AuthenticatedRunnerClient._validated_response(response, bad_hmac, enrollment)
        assert error.value.code == "authentication_failed"

        unsigned = _unsigned_request(
            enrollment, profile_id="not-enrolled.v1", task_id="wrong-profile"
        )
        wrong_profile = wire._sign_request(enrollment, unsigned)
        response = _raw_exchange(enrollment_root, server, wrong_profile, secret_provider)
        with pytest.raises(RunnerRemoteError, match="not enrolled") as error:
            AuthenticatedRunnerClient._validated_response(response, wrong_profile, enrollment)
        assert error.value.code == "profile_not_allowed"

        unsigned = _unsigned_request(enrollment, task_id="replayed-task")
        replayed = wire._sign_request(enrollment, unsigned)
        first = _raw_exchange(enrollment_root, server, replayed, secret_provider)
        assert (
            AuthenticatedRunnerClient._validated_response(first, replayed, enrollment)["status"]
            == "ready"
        )
        second = _raw_exchange(enrollment_root, server, replayed, secret_provider)
        with pytest.raises(RunnerRemoteError, match="replayed") as error:
            AuthenticatedRunnerClient._validated_response(second, replayed, enrollment)
        assert error.value.code == "replay_detected"


def test_wrong_certificate_and_tampered_response_are_rejected(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
) -> None:
    wrong_root = tmp_path / "wrong-trust"
    create_local_enrollment(
        wrong_root,
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=[PROFILE_ID],
        secret_provider=secret_provider,
    )
    with AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        with pytest.raises(AuthenticatedRunnerTransportError):
            _client(wrong_root, server, secret_provider).health()

    with TamperingServer(
        enrollment_root,
        RecordingRunner(),
        tmp_path / "tampered.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        with pytest.raises(RunnerAuthenticationError, match="authentication is invalid"):
            _client(enrollment_root, server, secret_provider).health()


def test_completed_result_is_recoverable_after_server_restart(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    state_path = tmp_path / "transport.sqlite3"
    first_runner = RecordingRunner()
    first_server = AuthenticatedRunnerServer(
        enrollment_root,
        first_runner,
        state_path,
        secret_provider=secret_provider,
    ).start()
    host, port = first_server.server_address
    client = _client(enrollment_root, first_server, secret_provider)
    expected = client.execute(manifest, profile)
    task_id, request_hash = client.execution_identity(manifest, profile)
    durable_path = first_server._durable_result_path(task_id)
    assert durable_path.is_file()
    first_server.shutdown()
    watchdog_root = runner_watchdog_control_root(durable_path, task_id)
    watchdog_root.mkdir()
    (watchdog_root / "status.json").write_bytes(
        canonical_json_bytes(
            {
                "schema_version": "bluefire.runner-watchdog-status.v2",
                "task_id": task_id,
                "state": "succeeded",
                "error_code": None,
                "watchdog_pid": 4242,
                "result_digest": file_hash(durable_path),
            }
        )
    )
    with sqlite3.connect(state_path) as database:
        database.execute(
            """
            UPDATE transport_tasks
            SET state = 'running', result_json = NULL, executor_instance = 'crashed-host',
                effect_dispatched = 1, error_code = NULL
            WHERE task_id = ?
            """,
            (task_id,),
        )

    second_runner = RecordingRunner()
    with AuthenticatedRunnerServer(
        enrollment_root,
        second_runner,
        state_path,
        host=host,
        port=port,
        secret_provider=secret_provider,
    ) as second_server:
        recovered = _client(enrollment_root, second_server, secret_provider).recover(
            task_id, request_hash
        )

    assert recovered["state"] == "completed"
    assert recovered["result"] == expected
    assert not watchdog_root.exists()
    assert second_runner.calls == 0


def test_unrecoverable_completed_row_transitions_to_indeterminate(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    state_path = tmp_path / "transport.sqlite3"
    with AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        state_path,
        secret_provider=secret_provider,
    ) as server:
        client = _client(enrollment_root, server, secret_provider)
        client.execute(manifest, profile)
        task_id, request_hash = client.execution_identity(manifest, profile)
        server.durable_result_path(task_id).unlink()
        with sqlite3.connect(state_path) as database:
            database.execute(
                "UPDATE transport_tasks SET result_json = ? WHERE task_id = ?",
                (b"{}", task_id),
            )

        recovered = client.recover(task_id, request_hash)

    assert recovered["state"] == "indeterminate"
    assert recovered["error_code"] == "outcome_indeterminate"


def test_complete_pending_result_is_promoted_and_recovered_after_restart(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    state_path = tmp_path / "transport.sqlite3"
    first_server = AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        state_path,
        secret_provider=secret_provider,
    ).start()
    client = _client(enrollment_root, first_server, secret_provider)
    expected = client.execute(manifest, profile)
    task_id, request_hash = client.execution_identity(manifest, profile)
    durable_path = first_server._durable_result_path(task_id)
    pending_path = runner_pending_result_path(durable_path, task_id)
    first_server.shutdown()

    durable_path.unlink()
    pending_path.write_text(json.dumps(expected, indent=2), encoding="utf-8")
    with sqlite3.connect(state_path) as database:
        database.execute(
            """
            UPDATE transport_tasks
            SET state = 'running', result_json = NULL, executor_instance = 'crashed-host',
                effect_dispatched = 1, error_code = NULL
            WHERE task_id = ?
            """,
            (task_id,),
        )

    second_runner = RecordingRunner()
    with AuthenticatedRunnerServer(
        enrollment_root,
        second_runner,
        state_path,
        secret_provider=secret_provider,
    ) as second_server:
        recovered = _client(enrollment_root, second_server, secret_provider).recover(
            task_id, request_hash
        )

    assert recovered["state"] == "completed"
    assert recovered["result"] == expected
    assert durable_path.is_file()
    assert not pending_path.exists()
    assert second_runner.calls == 0


def test_fresh_ledger_in_same_parent_cannot_adopt_another_ledgers_result(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    first_runner = RecordingRunner()
    first_state = tmp_path / "first.sqlite3"
    first_server = AuthenticatedRunnerServer(
        enrollment_root,
        first_runner,
        first_state,
        secret_provider=secret_provider,
    ).start()
    first_client = _client(enrollment_root, first_server, secret_provider)
    first_client.execute(manifest, profile)
    task_id, _request_hash = first_client.execution_identity(manifest, profile)
    first_result = first_server.durable_result_path(task_id)
    first_server.shutdown()

    second_runner = RecordingRunner()
    second_state = tmp_path / "second.sqlite3"
    with AuthenticatedRunnerServer(
        enrollment_root,
        second_runner,
        second_state,
        secret_provider=secret_provider,
    ) as second_server:
        second_result = _client(enrollment_root, second_server, secret_provider).execute(
            manifest, profile
        )
        second_path = second_server.durable_result_path(task_id)

    assert first_result != second_path
    assert first_result.is_file() and second_path.is_file()
    assert first_result.parent != second_path.parent
    assert second_result["output"]["call"] == 1
    assert second_runner.calls == 1


def test_recreated_ledger_at_same_path_gets_new_result_namespace(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    state_path = tmp_path / "transport.sqlite3"
    first_server = AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        state_path,
        secret_provider=secret_provider,
    ).start()
    first_client = _client(enrollment_root, first_server, secret_provider)
    first_client.execute(manifest, profile)
    task_id, _request_hash = first_client.execution_identity(manifest, profile)
    first_generation = first_server.ledger_generation
    first_result = first_server.durable_result_path(task_id)
    first_namespace = first_server.result_root
    first_server.shutdown()

    old_control = runner_watchdog_control_root(first_result, task_id)
    old_control.mkdir()
    (old_control / "cancel").write_bytes(b"")
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = state_path.with_name(state_path.name + suffix)
        if sidecar.exists():
            sidecar.unlink()
    state_path.unlink()
    assert read_runner_ledger_generation(state_path) is None

    second_runner = RecordingRunner()
    with AuthenticatedRunnerServer(
        enrollment_root,
        second_runner,
        state_path,
        secret_provider=secret_provider,
    ) as second_server:
        second_result = _client(enrollment_root, second_server, secret_provider).execute(
            manifest, profile
        )
        second_path = second_server.durable_result_path(task_id)
        second_generation = second_server.ledger_generation

    assert first_generation != second_generation
    assert read_runner_ledger_generation(state_path) == second_generation
    assert first_namespace != second_path.parent
    assert first_result.is_file() and second_path.is_file()
    assert old_control.is_dir()
    assert second_result["output"]["call"] == 1
    assert second_runner.calls == 1


def test_foreign_fresh_ledger_schema_and_trigger_are_refused_without_upgrade(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "foreign.sqlite3"
    foreign_sql = wire._TRANSPORT_TASKS_SQL.replace(
        "task_id TEXT PRIMARY KEY", "task_id TEXT"
    ).replace("nonce TEXT NOT NULL UNIQUE", "nonce TEXT NOT NULL")
    with sqlite3.connect(state_path) as database:
        database.execute(foreign_sql)
        database.execute("""
            CREATE TRIGGER erase_effect_edge
            AFTER UPDATE OF effect_dispatched ON transport_tasks
            WHEN NEW.effect_dispatched = 1
            BEGIN
                DELETE FROM transport_tasks WHERE rowid = NEW.rowid;
            END
            """)

    with pytest.raises(AuthenticatedRunnerTransportError, match="could not be initialized"):
        AuthenticatedRunnerServer(
            enrollment_root,
            RecordingRunner(),
            state_path,
            secret_provider=secret_provider,
        )

    with sqlite3.connect(state_path) as database:
        assert database.execute("PRAGMA user_version").fetchone()[0] == 0
        assert (
            database.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'runner_ledger_metadata'"
            ).fetchone()[0]
            == 0
        )
        assert (
            database.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger'"
            ).fetchone()[0]
            == 1
        )


def test_generation_inspection_refuses_same_path_replacement_race(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = tmp_path / "inspected.sqlite3"
    replacement = tmp_path / "replacement.sqlite3"
    saved = tmp_path / "validated-original.sqlite3"
    first = AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        state_path,
        secret_provider=secret_provider,
    )
    first_generation = first.ledger_generation
    first.shutdown()
    second = AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        replacement,
        secret_provider=secret_provider,
    )
    assert second.ledger_generation != first_generation
    second.shutdown()

    original_connect = wire.sqlite3.connect
    attempted = False

    def racing_connect(database: object, *args: object, **kwargs: object) -> sqlite3.Connection:
        nonlocal attempted
        if not attempted:
            attempted = True
            state_path.replace(saved)
            replacement.replace(state_path)
        return original_connect(database, *args, **kwargs)

    monkeypatch.setattr(wire.sqlite3, "connect", racing_connect)
    with pytest.raises(AuthenticatedRunnerTransportError, match="inspected safely"):
        read_runner_ledger_generation(state_path)
    assert attempted is True
    if saved.exists():
        assert read_runner_ledger_generation(saved) == first_generation


@pytest.mark.parametrize("same_generation", [False, True])
def test_live_server_never_adopts_replaced_ledger_path(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    same_generation: bool,
) -> None:
    state_path = tmp_path / "live.sqlite3"
    replacement = tmp_path / "live-replacement.sqlite3"
    saved = tmp_path / "live-original.sqlite3"
    runner = RecordingRunner()
    server = AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        state_path,
        secret_provider=secret_provider,
    ).start()
    client = _client(enrollment_root, server, secret_provider)
    client.execute(manifest, profile)
    shutil.copy2(state_path, replacement)
    database = sqlite3.connect(replacement)
    try:
        database.execute("DELETE FROM transport_tasks")
        if not same_generation:
            database.execute(
                "UPDATE runner_ledger_metadata SET ledger_generation = ? WHERE singleton = 1",
                ("c" * 64,),
            )
        database.commit()
    finally:
        database.close()

    swapped = False
    try:
        state_path.replace(saved)
        replacement.replace(state_path)
        swapped = True
    except PermissionError:
        assert os.name == "nt"

    try:
        if swapped:
            with pytest.raises((RunnerConnectionError, RunnerRemoteError)):
                client.execute(manifest, profile)
        else:
            assert client.execute(manifest, profile)["output"]["call"] == 1
    finally:
        server.shutdown()
    assert runner.calls == 1


def test_strict_ledger_audit_rejects_foreign_rows_schema_sidecars_and_oversize(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    state_path = tmp_path / "audited.sqlite3"
    server = AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        state_path,
        secret_provider=secret_provider,
    ).start()
    _client(enrollment_root, server, secret_provider).execute(manifest, profile)
    server.shutdown()
    enrollment = load_local_enrollment(enrollment_root, secret_provider=secret_provider)

    assert audit_runner_ledger(state_path, enrollment) == {
        "schema_version": "bluefire.runner-ledger-audit.v1",
        "ledger_generation": server.ledger_generation,
        "total_rows": 1,
        "execute_rows": 1,
        "unresolved_rows": 0,
        "active_rows": 0,
        "cleanup_required_rows": 0,
    }
    with pytest.raises(AuthenticatedRunnerTransportError, match="inspected safely"):
        audit_runner_ledger(
            state_path,
            enrollment,
            maximum_bytes=max(4096, state_path.stat().st_size - 1),
        )

    sidecar = state_path.with_name(state_path.name + "-wal")
    sidecar.write_bytes(b"foreign")
    with pytest.raises(AuthenticatedRunnerTransportError, match="inspected safely"):
        audit_runner_ledger(state_path, enrollment)
    sidecar.unlink()

    with sqlite3.connect(state_path) as database:
        database.execute(
            "CREATE TRIGGER foreign_trigger AFTER DELETE ON transport_tasks BEGIN SELECT 1; END"
        )
    database.close()
    with pytest.raises(AuthenticatedRunnerTransportError):
        audit_runner_ledger(state_path, enrollment)
    with pytest.raises(AuthenticatedRunnerTransportError):
        read_runner_ledger_generation(state_path)


def test_strict_ledger_audit_rejects_foreign_enrollment_row(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    state_path = tmp_path / "foreign-row.sqlite3"
    server = AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        state_path,
        secret_provider=secret_provider,
    ).start()
    _client(enrollment_root, server, secret_provider).execute(manifest, profile)
    server.shutdown()
    with sqlite3.connect(state_path) as database:
        database.execute("UPDATE transport_tasks SET runner_id = 'foreign-runner.v1'")
    database.close()
    enrollment = load_local_enrollment(enrollment_root, secret_provider=secret_provider)
    with pytest.raises(AuthenticatedRunnerTransportError, match="audit"):
        audit_runner_ledger(state_path, enrollment)


def test_transport_result_reads_reject_hardlinks_and_oversize_without_touching_victim(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
) -> None:
    with AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        hardlinked = server.durable_result_path("task-hardlinked-result-01")
        victim = tmp_path / "result-victim.json"
        victim_payload = b'{"victim":true}'
        victim.write_bytes(victim_payload)
        os.link(victim, hardlinked)

        with pytest.raises(RunnerTransportError, match="unavailable or unsafe"):
            server._read_private_result(hardlinked)

        assert victim.read_bytes() == victim_payload
        assert hardlinked.read_bytes() == victim_payload
        hardlinked.unlink()

        oversized = server.durable_result_path("task-oversized-result-01")
        with oversized.open("wb") as handle:
            handle.truncate(server.max_frame_bytes + 1)
        with pytest.raises(RunnerTransportError, match="unavailable or unsafe"):
            server._read_private_result(oversized)
        assert oversized.stat().st_size == server.max_frame_bytes + 1


def test_reenrolled_identity_cannot_recover_prior_enrollments_task(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    state_path = tmp_path / "transport.sqlite3"
    first_server = AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        state_path,
        secret_provider=secret_provider,
    ).start()
    first_enrollment = load_local_enrollment(enrollment_root, secret_provider=secret_provider)
    first_client = _client(enrollment_root, first_server, secret_provider)
    first_client.execute(manifest, profile)
    task_id, request_hash = first_client.execution_identity(manifest, profile)
    first_namespace = first_server.result_root
    first_server.shutdown()

    remove_local_enrollment(enrollment_root, secret_provider=secret_provider)
    second_enrollment = create_local_enrollment(
        enrollment_root,
        runner_id="bluefire-rust-runner.v1",
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=[PROFILE_ID],
        secret_provider=secret_provider,
    )
    assert (
        second_enrollment.metadata["client_fingerprint"]
        != first_enrollment.metadata["client_fingerprint"]
    )

    with AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        state_path,
        secret_provider=secret_provider,
    ) as second_server:
        assert second_server.result_root != first_namespace
        assert second_server.result_root == runner_result_namespace_path(
            state_path,
            second_enrollment,
            ledger_generation=second_server.ledger_generation,
        )
        with pytest.raises(RunnerRemoteError, match="identity does not match") as error:
            _client(enrollment_root, second_server, secret_provider).recover(task_id, request_hash)

    assert error.value.code == "task_identity_mismatch"


def test_cancellation_records_intent_without_claiming_termination(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    runner = BlockingRunner()
    with AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        client = _client(enrollment_root, server, secret_provider, timeout_seconds=30)
        task_id, request_hash = client.execution_identity(manifest, profile)
        result: list[Mapping[str, Any]] = []

        execution = threading.Thread(
            target=lambda: result.append(client.execute(manifest, profile)), daemon=True
        )
        execution.start()
        assert runner.started.wait(timeout=15)

        cancellation = client.cancel(task_id, request_hash)
        assert cancellation["state"] == "cancellation_requested"
        assert cancellation["cancellation_requested"] is True
        assert cancellation["cancelled"] is False

        runner.release.set()
        execution.join(timeout=3)
        assert not execution.is_alive()
        recovered = client.recover(task_id, request_hash)

    assert result[0]["output"]["call"] == 1
    assert recovered["state"] == "completed"
    assert recovered["cancellation_requested"] is True


def test_pre_effect_cancellation_during_slow_inventory_prevents_launch(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    runner = SlowInventoryCancellationRunner()
    errors: list[BaseException] = []
    with AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        client = _client(enrollment_root, server, secret_provider, timeout_seconds=30)
        task_id, request_hash = client.execution_identity(manifest, profile)

        def execute() -> None:
            try:
                client.execute(manifest, profile)
            except BaseException as exc:
                errors.append(exc)

        execution = threading.Thread(target=execute, daemon=True)
        execution.start()
        assert runner.inventory_started.wait(timeout=15)
        cancellation = client.cancel(task_id, request_hash)
        runner.release_inventory.set()
        execution.join(timeout=5)
        recovered = client.recover(task_id, request_hash)

    assert not execution.is_alive()
    assert runner.calls == 0
    assert cancellation["state"] == "cancelled"
    assert cancellation["cancelled"] is True
    assert len(errors) == 1 and isinstance(errors[0], RunnerTaskCancelled)
    assert recovered["state"] == "cancelled"


def test_saturated_execute_workers_leave_control_responsive_and_shutdown_drains(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    runner = SaturatingBlockingRunner()
    server = AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        max_workers=3,
        control_worker_reserve=1,
        secret_provider=secret_provider,
    ).start()
    client = _client(enrollment_root, server, secret_provider, timeout_seconds=30)
    manifests = [
        {
            **dict(manifest),
            "request_id": f"saturated-request-{index}",
            "run_id": f"saturated-run-{index}",
            "step_id": f"saturated-step-{index}",
            "request_hash": "sha256:" + str(index + 7) * 64,
        }
        for index in range(3)
    ]
    results: list[Mapping[str, Any]] = []
    errors: list[BaseException] = []

    def execute(current: Mapping[str, Any]) -> None:
        try:
            results.append(client.execute(current, profile))
        except BaseException as exc:
            errors.append(exc)

    workers = [
        threading.Thread(target=execute, args=(current,), daemon=True) for current in manifests[:2]
    ]
    for worker in workers:
        worker.start()
    assert runner.wait_for_started(2)

    started = time.monotonic()
    health = client.health()
    first_identity = client.execution_identity(manifests[0], profile)
    cancellation = client.cancel(*first_identity)
    with pytest.raises(RunnerRemoteError) as shutdown_error:
        client.shutdown()
    with pytest.raises(RunnerRemoteError) as draining_error:
        client.execute(manifests[2], profile)
    assert time.monotonic() - started < 5
    assert health["status"] == "ready"
    assert cancellation["state"] == "cancellation_requested"
    assert shutdown_error.value.code == "active_tasks"
    assert draining_error.value.code == "runner_draining"
    assert client.health()["ledger"]["accepting_execute"] is False

    runner.release.set()
    for worker in workers:
        worker.join(timeout=5)
    acknowledgement = client.shutdown()
    if server._serve_thread is not None:
        server._serve_thread.join(timeout=5)
    server.shutdown()

    assert all(not worker.is_alive() for worker in workers)
    assert errors == []
    assert len(results) == 2
    assert acknowledgement["status"] == "shutdown_acknowledged"


def test_task_aware_cancellation_is_true_only_after_confirmed_runner_transition(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    runner = TaskAwareCancellationRunner()
    with AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        cancel_confirmation_seconds=5,
        secret_provider=secret_provider,
    ) as server:
        client = _client(enrollment_root, server, secret_provider, timeout_seconds=30)
        task_id, request_hash = client.execution_identity(manifest, profile)
        errors: list[RunnerTaskCancelled] = []

        def execute() -> None:
            try:
                client.execute(manifest, profile)
            except RunnerTaskCancelled as exc:
                errors.append(exc)

        execution = threading.Thread(target=execute, daemon=True)
        execution.start()
        assert runner.started.wait(timeout=15)
        cancellation = client.cancel(task_id, request_hash)
        execution.join(timeout=5)
        recovered = client.recover(task_id, request_hash)

    assert not execution.is_alive()
    assert runner.cancel_event is not None and runner.cancel_event.is_set()
    assert runner.durable_result_path is not None
    assert runner.durable_result_path.parent.parent.name == ".bluefire-runner-results"
    assert cancellation == {
        "original_task_id": task_id,
        "original_request_hash": request_hash,
        "state": "cancelled",
        "cancellation_requested": True,
        "cancelled": True,
    }
    assert len(errors) == 1
    assert recovered["state"] == "cancelled"
    assert recovered["error_code"] == "task_cancelled"


def test_authenticated_client_execute_task_cancel_wins_without_redirect_or_thread_leak(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    runner = TaskAwareCancellationRunner()
    caller_path = (tmp_path / "caller-owned-result.json").resolve()
    caller_path.write_bytes(b"caller-owned")
    cancel_event = threading.Event()
    outcomes: list[BaseException | Mapping[str, Any]] = []
    with AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        client = _client(enrollment_root, server, secret_provider, timeout_seconds=10)
        task_id, _request_hash = client.execution_identity(manifest, profile)

        def execute() -> None:
            try:
                outcomes.append(
                    client.execute_task(
                        manifest,
                        profile,
                        task_id=task_id,
                        cancel_event=cancel_event,
                        durable_result_path=caller_path,
                    )
                )
            except BaseException as exc:
                outcomes.append(exc)

        execution = threading.Thread(target=execute, name="execute-task-cancel-wins")
        execution.start()
        assert runner.started.wait(timeout=15)
        cancel_event.set()
        execution.join(timeout=15)

    assert not execution.is_alive()
    assert len(outcomes) == 1 and isinstance(outcomes[0], RunnerTaskCancelled)
    assert caller_path.read_bytes() == b"caller-owned"
    assert not any(
        thread.name == f"bluefire-runner-cancel-{task_id[-12:]}" for thread in threading.enumerate()
    )


def test_authenticated_client_execute_task_authenticated_completion_wins_cancel_race(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    runner = TaskAwareCompletionRunner()
    cancel_event = threading.Event()
    outcomes: list[BaseException | Mapping[str, Any]] = []
    with AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        client = _client(enrollment_root, server, secret_provider, timeout_seconds=10)
        task_id, _request_hash = client.execution_identity(manifest, profile)

        def execute() -> None:
            try:
                outcomes.append(
                    client.execute_task(
                        manifest,
                        profile,
                        task_id=task_id,
                        cancel_event=cancel_event,
                        durable_result_path=(tmp_path / "ignored.json").resolve(),
                    )
                )
            except BaseException as exc:
                outcomes.append(exc)

        execution = threading.Thread(target=execute, name="execute-task-completion-wins")
        execution.start()
        assert runner.started.wait(timeout=15)
        cancel_event.set()
        deadline = time.monotonic() + 10
        while (
            runner.cancel_event is not None
            and not runner.cancel_event.is_set()
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        assert runner.cancel_event is not None and runner.cancel_event.is_set()
        runner.release.set()
        execution.join(timeout=15)

    assert not execution.is_alive()
    assert len(outcomes) == 1
    outcome = outcomes[0]
    assert isinstance(outcome, Mapping)
    assert outcome["status"] == "success"
    assert not (tmp_path / "ignored.json").exists()
    assert not any(
        thread.name == f"bluefire-runner-cancel-{task_id[-12:]}" for thread in threading.enumerate()
    )


def test_authenticated_client_execute_task_recovers_when_cancel_response_is_lost(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    runner = TaskAwareCancellationRunner()
    cancel_event = threading.Event()
    server = DropFirstCancelResponseServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    )
    with server:
        client = _client(enrollment_root, server, secret_provider, timeout_seconds=10)
        task_id, _request_hash = client.execution_identity(manifest, profile)
        outcomes: list[BaseException | Mapping[str, Any]] = []

        def execute() -> None:
            try:
                outcomes.append(
                    client.execute_task(
                        manifest,
                        profile,
                        task_id=task_id,
                        cancel_event=cancel_event,
                        durable_result_path=(tmp_path / "ignored.json").resolve(),
                    )
                )
            except BaseException as exc:
                outcomes.append(exc)

        execution = threading.Thread(target=execute, name="execute-task-lost-cancel")
        execution.start()
        assert runner.started.wait(timeout=15)
        cancel_event.set()
        execution.join(timeout=15)

    assert server.dropped_cancel is True
    assert not execution.is_alive()
    assert len(outcomes) == 1 and isinstance(outcomes[0], RunnerTaskCancelled)
    assert not any(
        thread.name == f"bluefire-runner-cancel-{task_id[-12:]}" for thread in threading.enumerate()
    )


def test_confirmed_runner_timeout_records_terminal_state_and_maps_typed_error(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    runner = TaskAwareTimeoutRunner()
    with AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        client = _client(enrollment_root, server, secret_provider, timeout_seconds=30)
        task_id, request_hash = client.execution_identity(manifest, profile)

        with pytest.raises(RunnerTaskTimedOut, match="timed out"):
            client.execute(manifest, profile)
        recovered = client.recover(task_id, request_hash)

    assert runner.calls == 1
    assert recovered["state"] == "timed_out"
    assert recovered["error_code"] == "task_timed_out"


def test_confirmed_cancellation_with_committed_receipt_requires_cleanup_recovery(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    runner = TaskAwareReceiptCancellationRunner()
    with AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        cancel_confirmation_seconds=5,
        secret_provider=secret_provider,
    ) as server:
        client = _client(enrollment_root, server, secret_provider, timeout_seconds=30)
        task_id, request_hash = client.execution_identity(manifest, profile)
        errors: list[RunnerRemoteError] = []

        def execute() -> None:
            try:
                client.execute(manifest, profile)
            except RunnerRemoteError as exc:
                errors.append(exc)

        execution = threading.Thread(target=execute, daemon=True)
        execution.start()
        assert runner.started.wait(timeout=15)
        cancellation = client.cancel(task_id, request_hash)
        execution.join(timeout=5)
        recovered = client.recover(task_id, request_hash)

    assert not execution.is_alive()
    assert cancellation["state"] == "recovery_required"
    assert cancellation["cancellation_requested"] is True
    assert cancellation["cancelled"] is False
    assert [error.code for error in errors] == ["recovery_required"]
    assert recovered["state"] == "recovery_required"
    assert recovered["receipt_ids"] == [runner.receipt_id]
    assert recovered["cleanup_required"] is True


def test_restart_cancel_reaches_live_durable_watchdog_and_waits_for_confirmation(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    state_path = tmp_path / "transport.sqlite3"
    first_server = AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        state_path,
        secret_provider=secret_provider,
    ).start()
    first_client = _client(enrollment_root, first_server, secret_provider)
    first_client.execute(manifest, profile)
    task_id, request_hash = first_client.execution_identity(manifest, profile)
    durable_path = first_server.durable_result_path(task_id)
    first_server.shutdown()
    durable_path.unlink()
    control_root = runner_watchdog_control_root(durable_path, task_id)
    control_root.mkdir()
    with sqlite3.connect(state_path) as database:
        database.execute(
            """
            UPDATE transport_tasks
            SET state = 'running', result_json = NULL, executor_instance = 'crashed-host',
                effect_dispatched = 1, error_code = NULL, cancellation_requested = 0
            WHERE task_id = ?
            """,
            (task_id,),
        )

    marker_seen = threading.Event()
    watchdog_errors: list[BaseException] = []

    def finish_watchdog() -> None:
        try:
            cancel_path = runner_watchdog_cancel_path(durable_path, task_id)
            deadline = time.monotonic() + 15
            while not cancel_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            if not cancel_path.exists():
                raise AssertionError("durable cancellation marker was not delivered")
            marker_seen.set()
            for entry in tuple(control_root.iterdir()):
                unlink_deadline = time.monotonic() + 2
                while True:
                    try:
                        entry.unlink()
                        break
                    except PermissionError:
                        if time.monotonic() >= unlink_deadline:
                            raise
                        time.sleep(0.01)
            _write_watchdog_status(
                control_root,
                task_id,
                state="cancelled",
                error_code="cancelled",
            )
        except BaseException as exc:
            watchdog_errors.append(exc)

    with AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        state_path,
        cancel_confirmation_seconds=5,
        secret_provider=secret_provider,
    ) as second_server:
        watchdog = threading.Thread(target=finish_watchdog, daemon=True)
        watchdog.start()
        client = _client(enrollment_root, second_server, secret_provider, timeout_seconds=30)
        cancellation = client.cancel(task_id, request_hash)
        watchdog.join(timeout=5)
        recovered = client.recover(task_id, request_hash)

    assert marker_seen.is_set()
    assert not watchdog.is_alive()
    assert watchdog_errors == []
    assert cancellation["state"] == "cancelled"
    assert cancellation["cancelled"] is True
    assert recovered["state"] == "cancelled"
    assert not control_root.exists()


@pytest.mark.parametrize(
    ("watchdog_state", "watchdog_error", "expected_state", "expected_error"),
    [
        ("cancelled", "cancelled", "cancelled", "task_cancelled"),
        ("failed", "timed_out", "timed_out", "task_timed_out"),
    ],
)
def test_restart_reconciles_confirmed_watchdog_terminal_status(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    watchdog_state: str,
    watchdog_error: str,
    expected_state: str,
    expected_error: str,
) -> None:
    state_path = tmp_path / "transport.sqlite3"
    first_server = AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        state_path,
        secret_provider=secret_provider,
    ).start()
    first_client = _client(enrollment_root, first_server, secret_provider)
    first_client.execute(manifest, profile)
    task_id, request_hash = first_client.execution_identity(manifest, profile)
    durable_path = first_server.durable_result_path(task_id)
    first_server.shutdown()
    durable_path.unlink()
    control_root = runner_watchdog_control_root(durable_path, task_id)
    control_root.mkdir()
    _write_watchdog_status(
        control_root,
        task_id,
        state=watchdog_state,
        error_code=watchdog_error,
    )
    with sqlite3.connect(state_path) as database:
        database.execute(
            """
            UPDATE transport_tasks
            SET state = 'running', result_json = NULL, executor_instance = 'crashed-host',
                effect_dispatched = 1, error_code = NULL
            WHERE task_id = ?
            """,
            (task_id,),
        )

    second_runner = RecordingRunner()
    with AuthenticatedRunnerServer(
        enrollment_root,
        second_runner,
        state_path,
        secret_provider=secret_provider,
    ) as second_server:
        client = _client(enrollment_root, second_server, secret_provider)
        recovered = client.recover(task_id, request_hash)
        if expected_state == "cancelled":
            with pytest.raises(RunnerTaskCancelled):
                client.execute(manifest, profile)
        else:
            with pytest.raises(RunnerTaskTimedOut, match="timed out"):
                client.execute(manifest, profile)

    assert recovered["state"] == expected_state
    assert recovered["error_code"] == expected_error
    assert second_runner.calls == 0
    assert not control_root.exists()


@pytest.mark.parametrize(
    "mutation",
    ["missing", "non_boolean", "ack_without_request", "cleanup_unverified", "extra"],
)
def test_current_watchdog_cancellation_requires_exact_proof_fields(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    mutation: str,
) -> None:
    task_id = "execute-" + "a" * 64
    with AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        control_root = runner_watchdog_control_root(server.durable_result_path(task_id), task_id)
        control_root.mkdir()
        status: dict[str, Any] = {
            "schema_version": "bluefire.runner-watchdog-status.v2",
            "task_id": task_id,
            "state": "cancelled",
            "error_code": "cancelled",
            "watchdog_pid": 4242,
            "cooperative_requested": False,
            "cooperative_acknowledged": False,
            "forced_tree_termination": True,
            "control_cleanup_verified": True,
        }
        if mutation == "missing":
            del status["forced_tree_termination"]
        elif mutation == "non_boolean":
            status["forced_tree_termination"] = 1
        elif mutation == "ack_without_request":
            status["cooperative_acknowledged"] = True
        elif mutation == "cleanup_unverified":
            status["control_cleanup_verified"] = False
        else:
            status["claim_only"] = True
        status_path = control_root / "status.json"
        status_path.write_bytes(canonical_json_bytes(status))

        with pytest.raises(RunnerTransportError, match="watchdog status is invalid"):
            server._read_watchdog_status(task_id)
        status_path.unlink()
        control_root.rmdir()


def test_terminal_watchdog_status_survives_an_exact_late_cancel_marker(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task_id = "execute-" + "b" * 64
    with AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        durable = server.durable_result_path(task_id)
        control_root = runner_watchdog_control_root(durable, task_id)
        control_root.mkdir()
        _write_watchdog_status(
            control_root,
            task_id,
            state="cancelled",
            error_code="cancelled",
        )
        request_runner_task_cancel(durable, task_id)
        real_names = wire._PinnedPrivateDirectory.names

        def status_first_names(
            pinned: wire._PinnedPrivateDirectory,
            *,
            maximum: int | None = None,
        ) -> tuple[str, ...]:
            names = real_names(pinned, maximum=maximum)
            return tuple(sorted(names, key=lambda name: name != "status.json"))

        monkeypatch.setattr(wire._PinnedPrivateDirectory, "names", status_first_names)

        status = server._read_watchdog_status(task_id)

    assert status is not None
    assert status["state"] == "cancelled"
    assert tuple(entry.name for entry in control_root.iterdir()) == ("status.json",)


def test_concurrent_terminal_reconciliation_is_idempotent(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = tmp_path / "transport.sqlite3"
    outcomes: list[Mapping[str, Any]] = []
    errors: list[BaseException] = []
    with AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        state_path,
        secret_provider=secret_provider,
    ) as server:
        client = _client(enrollment_root, server, secret_provider)
        client.execute(manifest, profile)
        task_id, _request_hash = client.execution_identity(manifest, profile)
        durable = server.durable_result_path(task_id)
        durable.unlink()
        control_root = runner_watchdog_control_root(durable, task_id)
        control_root.mkdir()
        _write_watchdog_status(
            control_root,
            task_id,
            state="cancelled",
            error_code="cancelled",
        )
        with sqlite3.connect(state_path) as database:
            database.execute(
                """
                UPDATE transport_tasks
                SET state = 'indeterminate', result_json = NULL,
                    executor_instance = 'crashed-host', effect_dispatched = 1,
                    error_code = 'outcome_indeterminate'
                WHERE task_id = ?
                """,
                (task_id,),
            )

        real_read = server._read_watchdog_status
        readers = threading.Barrier(2)
        calls_lock = threading.Lock()
        calls = 0

        def synchronized_read(current_task_id: str) -> dict[str, Any] | None:
            nonlocal calls
            status = real_read(current_task_id)
            with calls_lock:
                current_call = calls
                calls += 1
            if current_call < 2:
                readers.wait(timeout=5)
            return status

        def reconcile() -> None:
            try:
                outcomes.append(server._reconcile_execute_task(task_id))
            except BaseException as exc:
                errors.append(exc)

        monkeypatch.setattr(server, "_read_watchdog_status", synchronized_read)
        workers = [threading.Thread(target=reconcile, daemon=True) for _index in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=10)
        assert all(not worker.is_alive() for worker in workers)
        monkeypatch.setattr(server, "_read_watchdog_status", real_read)

        repeated = server._reconcile_execute_task(task_id)
        with sqlite3.connect(state_path) as database:
            stored = database.execute(
                "SELECT state, error_code FROM transport_tasks WHERE task_id = ?",
                (task_id,),
            ).fetchone()

    assert errors == []
    assert [outcome["state"] for outcome in outcomes] == ["cancelled", "cancelled"]
    assert repeated["state"] == "cancelled"
    assert stored == ("cancelled", "task_cancelled")
    assert not control_root.exists()


def test_concurrent_indeterminate_reconciliation_is_idempotent(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = tmp_path / "transport.sqlite3"
    outcomes: list[Mapping[str, Any]] = []
    errors: list[BaseException] = []
    with AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        state_path,
        secret_provider=secret_provider,
    ) as server:
        client = _client(enrollment_root, server, secret_provider)
        client.execute(manifest, profile)
        task_id, _request_hash = client.execution_identity(manifest, profile)
        server.durable_result_path(task_id).unlink()
        with sqlite3.connect(state_path) as database:
            database.execute(
                """
                UPDATE transport_tasks
                SET state = 'indeterminate', result_json = NULL,
                    executor_instance = 'crashed-host', effect_dispatched = 1,
                    error_code = 'outcome_indeterminate'
                WHERE task_id = ?
                """,
                (task_id,),
            )

        readers = threading.Barrier(2)
        calls_lock = threading.Lock()
        calls = 0

        def synchronized_discovery(
            _manifest: Mapping[str, Any],
            _profile: Mapping[str, Any],
        ) -> list[str]:
            nonlocal calls
            with calls_lock:
                current_call = calls
                calls += 1
            if current_call < 2:
                readers.wait(timeout=5)
            return []

        def reconcile() -> None:
            try:
                outcomes.append(server._reconcile_execute_task(task_id))
            except BaseException as exc:
                errors.append(exc)

        monkeypatch.setattr(server, "_discover_recovery_receipts", synchronized_discovery)
        workers = [threading.Thread(target=reconcile, daemon=True) for _index in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=10)
        assert all(not worker.is_alive() for worker in workers)

        repeated = server._reconcile_execute_task(task_id)
        with sqlite3.connect(state_path) as database:
            stored = database.execute(
                "SELECT state, error_code FROM transport_tasks WHERE task_id = ?",
                (task_id,),
            ).fetchone()

    assert errors == []
    assert [outcome["state"] for outcome in outcomes] == [
        "indeterminate",
        "indeterminate",
    ]
    assert repeated["state"] == "indeterminate"
    assert stored == ("indeterminate", "outcome_indeterminate")


@pytest.mark.parametrize(
    ("watchdog_state", "watchdog_error"),
    [("cancelled", "cancelled"), ("failed", "timed_out")],
)
def test_terminal_watchdog_cannot_erase_committed_recovery_receipts(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    watchdog_state: str,
    watchdog_error: str,
) -> None:
    state_path = tmp_path / "transport.sqlite3"
    receipt_id = "a" * 64
    encoded_receipts = canonical_json_bytes({"receipt_ids": [receipt_id]})
    with AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        state_path,
        secret_provider=secret_provider,
    ) as server:
        client = _client(enrollment_root, server, secret_provider)
        client.execute(manifest, profile)
        task_id, request_hash = client.execution_identity(manifest, profile)
        durable = server.durable_result_path(task_id)
        durable.unlink()
        control_root = runner_watchdog_control_root(durable, task_id)
        control_root.mkdir()
        _write_watchdog_status(
            control_root,
            task_id,
            state=watchdog_state,
            error_code=watchdog_error,
        )
        with sqlite3.connect(state_path) as database:
            database.execute(
                """
                UPDATE transport_tasks
                SET state = 'recovery_required', result_json = NULL,
                    recovery_receipts_json = ?, cleanup_required = 1,
                    executor_instance = 'crashed-host', effect_dispatched = 1,
                    error_code = 'recovery_required'
                WHERE task_id = ?
                """,
                (encoded_receipts, task_id),
            )
        monkeypatch.setattr(server, "_discover_recovery_receipts", lambda *_args: [])

        reconciled = server._reconcile_execute_task(task_id)
        recovered = client.recover(task_id, request_hash)
        with sqlite3.connect(state_path) as database:
            stored = database.execute(
                """
                SELECT state, recovery_receipts_json, cleanup_required, error_code
                FROM transport_tasks WHERE task_id = ?
                """,
                (task_id,),
            ).fetchone()

    assert reconciled == {
        "state": "recovery_required",
        "result": None,
        "receipt_ids": [receipt_id],
    }
    assert recovered["state"] == "recovery_required"
    assert recovered["receipt_ids"] == [receipt_id]
    assert recovered["cleanup_required"] is True
    assert stored == ("recovery_required", encoded_receipts, 1, "recovery_required")


def test_exact_result_cannot_erase_unreported_recovery_receipts(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = tmp_path / "transport.sqlite3"
    receipt_id = "a" * 64
    encoded_receipts = canonical_json_bytes({"receipt_ids": [receipt_id]})
    with AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        state_path,
        secret_provider=secret_provider,
    ) as server:
        client = _client(enrollment_root, server, secret_provider)
        client.execute(manifest, profile)
        task_id, request_hash = client.execution_identity(manifest, profile)
        with sqlite3.connect(state_path) as database:
            database.execute(
                """
                UPDATE transport_tasks
                SET state = 'recovery_required', result_json = NULL,
                    recovery_receipts_json = ?, cleanup_required = 1,
                    executor_instance = 'crashed-host', effect_dispatched = 1,
                    error_code = 'recovery_required'
                WHERE task_id = ?
                """,
                (encoded_receipts, task_id),
            )
        monkeypatch.setattr(server, "_discover_recovery_receipts", lambda *_args: [])

        recovered = client.recover(task_id, request_hash)

    assert recovered["state"] == "recovery_required"
    assert recovered["result"] is None
    assert recovered["receipt_ids"] == [receipt_id]
    assert recovered["cleanup_required"] is True


def test_unhashable_receipt_values_fail_closed_as_transport_errors(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    malformed = canonical_json_bytes({"receipt_ids": [{}]})
    with AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        with pytest.raises(RunnerTransportError, match="recovery receipt state is invalid"):
            server._stored_recovery_receipt_ids(malformed)
        invalid_result: dict[str, Any] = _result(manifest, profile)
        invalid_result["receipt_ids"] = [{}]
        with pytest.raises(RunnerTransportError, match="receipt identity is invalid"):
            server._validated_execute_result(invalid_result, manifest, profile)


def test_late_recovery_receipt_overrides_a_committed_terminal_state(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = tmp_path / "transport.sqlite3"
    receipt_id = "a" * 64
    discoveries = iter(([], [receipt_id], [receipt_id]))
    with AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        state_path,
        secret_provider=secret_provider,
    ) as server:
        client = _client(enrollment_root, server, secret_provider)
        client.execute(manifest, profile)
        task_id, request_hash = client.execution_identity(manifest, profile)
        durable = server.durable_result_path(task_id)
        durable.unlink()
        control_root = runner_watchdog_control_root(durable, task_id)
        control_root.mkdir()
        _write_watchdog_status(
            control_root,
            task_id,
            state="cancelled",
            error_code="cancelled",
        )
        with sqlite3.connect(state_path) as database:
            database.execute(
                """
                UPDATE transport_tasks
                SET state = 'indeterminate', result_json = NULL,
                    executor_instance = 'crashed-host', effect_dispatched = 1,
                    error_code = 'outcome_indeterminate'
                WHERE task_id = ?
                """,
                (task_id,),
            )
        monkeypatch.setattr(
            server,
            "_discover_recovery_receipts",
            lambda *_args: next(discoveries),
        )

        first = server._reconcile_execute_task(task_id)
        recovered = client.recover(task_id, request_hash)

    assert first["state"] == "cancelled"
    assert recovered["state"] == "recovery_required"
    assert recovered["receipt_ids"] == [receipt_id]
    assert recovered["cleanup_required"] is True


def test_terminal_reconciliation_removes_an_exact_late_cancel_marker(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    state_path = tmp_path / "transport.sqlite3"
    with AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        state_path,
        secret_provider=secret_provider,
    ) as server:
        client = _client(enrollment_root, server, secret_provider)
        client.execute(manifest, profile)
        task_id, _request_hash = client.execution_identity(manifest, profile)
        durable = server.durable_result_path(task_id)
        durable.unlink()
        control_root = runner_watchdog_control_root(durable, task_id)
        control_root.mkdir()
        _write_watchdog_status(
            control_root,
            task_id,
            state="cancelled",
            error_code="cancelled",
        )
        request_runner_task_cancel(durable, task_id)
        with sqlite3.connect(state_path) as database:
            database.execute(
                """
                UPDATE transport_tasks
                SET state = 'cancelled', result_json = NULL,
                    cancellation_requested = 1, effect_dispatched = 1,
                    error_code = 'task_cancelled'
                WHERE task_id = ?
                """,
                (task_id,),
            )

        reconciled = server._reconcile_execute_task(task_id)

    assert reconciled["state"] == "cancelled"
    assert not control_root.exists()


def test_recovery_update_advances_the_cas_token_when_the_clock_does_not(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = tmp_path / "transport.sqlite3"
    first_receipt = "a" * 64
    second_receipt = "b" * 64
    with AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        state_path,
        secret_provider=secret_provider,
    ) as server:
        client = _client(enrollment_root, server, secret_provider)
        result = client.execute(manifest, profile)
        task_id, _request_hash = client.execution_identity(manifest, profile)
        with sqlite3.connect(state_path) as database:
            completed = database.execute(
                "SELECT state, updated_at FROM transport_tasks WHERE task_id = ?",
                (task_id,),
            ).fetchone()
        assert completed is not None
        frozen_clock = int(completed[1])
        monkeypatch.setattr(wire.time, "time_ns", lambda: frozen_clock)

        first = server._set_execute_recovery_state(
            task_id,
            receipt_ids=[first_receipt],
            expected_state=str(completed[0]),
            expected_updated_at=frozen_clock,
        )
        with sqlite3.connect(state_path) as database:
            stale = database.execute(
                "SELECT state, updated_at FROM transport_tasks WHERE task_id = ?",
                (task_id,),
            ).fetchone()
        assert stale is not None
        second = server._set_execute_recovery_state(
            task_id,
            receipt_ids=[second_receipt],
            expected_state=str(stale[0]),
            expected_updated_at=int(stale[1]),
        )
        stale_completion = dict(result)
        stale_completion["receipt_ids"] = [first_receipt, second_receipt]

        completion_applied = server._set_reconciled_completion(
            task_id,
            stale_completion,
            expected_state=str(stale[0]),
            expected_updated_at=int(stale[1]),
        )
        with sqlite3.connect(state_path) as database:
            stored = database.execute(
                """
                SELECT state, recovery_receipts_json, cleanup_required, updated_at
                FROM transport_tasks WHERE task_id = ?
                """,
                (task_id,),
            ).fetchone()

    assert first == ("recovery_required", [first_receipt])
    assert second == ("recovery_required", [first_receipt, second_receipt])
    assert completion_applied is False
    assert stored == (
        "recovery_required",
        canonical_json_bytes({"receipt_ids": [first_receipt, second_receipt]}),
        1,
        int(stale[1]) + 1,
    )


@pytest.mark.parametrize(
    ("write_receipt", "receipt_matches", "expected_code", "expected_state"),
    [
        (False, True, "outcome_indeterminate", "indeterminate"),
        (True, True, "recovery_required", "recovery_required"),
        (True, False, "outcome_indeterminate", "indeterminate"),
    ],
)
def test_effect_then_raise_never_synthesizes_success_and_only_surfaces_bound_receipts(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    write_receipt: bool,
    receipt_matches: bool,
    expected_code: str,
    expected_state: str,
) -> None:
    runner = EffectThenRaiseRunner(write_receipt=write_receipt, receipt_matches=receipt_matches)
    with AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        client = _client(enrollment_root, server, secret_provider)
        task_id, request_hash = client.execution_identity(manifest, profile)
        with pytest.raises(RunnerRemoteError) as error:
            client.execute(manifest, profile)
        recovered = client.recover(task_id, request_hash)

    assert error.value.code == expected_code
    assert recovered["state"] == expected_state
    assert recovered["result"] is None
    if expected_state == "recovery_required":
        assert recovered["receipt_ids"] == [runner.receipt_id]
        assert recovered["cleanup_required"] is True
    else:
        assert recovered["receipt_ids"] == []
        assert recovered["cleanup_required"] is False


@pytest.mark.parametrize("runner_type", [OversizedResultRunner, MismatchedResultRunner])
def test_invalid_post_effect_result_is_indeterminate_not_failed(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    runner_type: type[RecordingRunner],
) -> None:
    runner = runner_type()
    with AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        max_frame_bytes=4096,
        secret_provider=secret_provider,
    ) as server:
        client = _client(enrollment_root, server, secret_provider)
        task_id, request_hash = client.execution_identity(manifest, profile)
        with pytest.raises(RunnerRemoteError) as error:
            client.execute(manifest, profile)
        recovered = client.recover(task_id, request_hash)

    assert error.value.code == "outcome_indeterminate"
    assert recovered["state"] == "indeterminate"
    assert recovered["error_code"] == "outcome_indeterminate"
    assert runner.calls == 1


def test_ledger_completion_write_failure_recovers_durable_result_without_replay(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    runner = RecordingRunner()
    server = FailFirstExecuteCompletionServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    )
    with server:
        client = _client(enrollment_root, server, secret_provider)
        first = client.execute(manifest, profile)
        second = client.execute(manifest, profile)

    assert server.failed_completion is True
    assert first == second
    assert runner.calls == 1


def test_inventory_identity_mismatch_refuses_health_and_execute_before_effect(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    runner = MismatchedInventoryRunner()
    with AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        client = _client(enrollment_root, server, secret_provider)
        with pytest.raises(RunnerRemoteError) as health_error:
            client.health()
        with pytest.raises(RunnerRemoteError) as execute_error:
            client.execute(manifest, profile)

    assert health_error.value.code == "authentication_failed"
    assert execute_error.value.code == "authentication_failed"
    assert runner.calls == 0


def test_transport_identity_binds_authenticated_peer_and_detects_binary_change(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner_binary = tmp_path / "bluefire-runner.exe"
    runner_binary.write_bytes(b"runner-v1")
    runner = RecordingRunner()
    runner.runner_binary = runner_binary  # type: ignore[attr-defined]
    with AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        client = _client(enrollment_root, server, secret_provider)
        identity = client.transport_identity()
        readiness_identity = runner_transport_identity(client, client.inventory())
        assert identity["schema_version"] == "bluefire.runner-transport-identity.v1"
        assert identity["authenticated_peer_fingerprint"] == identity["client_fingerprint"]
        assert identity["runner_binary_digest"] == (
            "sha256:" + hashlib.sha256(b"runner-v1").hexdigest()
        )
        assert readiness_identity == {
            "transport": "bluefire.runner_transport.AuthenticatedRunnerClient",
            "runner_id": "bluefire-rust-runner.v1",
            "runner_version": "0.1.0",
            "platform": "windows",
            "runner_binary_digest": identity["runner_binary_digest"],
        }
        assert "server_instance_id" not in identity
        for mutation in (
            {"runner_id": "different-runner.v1"},
            {"inventory_digest": "sha256:" + "0" * 64},
        ):
            with monkeypatch.context() as scoped:
                scoped.setattr(
                    client,
                    "transport_identity",
                    lambda mutation=mutation: {**identity, **mutation},
                )
                with pytest.raises(RunnerReadinessError, match="could not be verified"):
                    runner_transport_identity(client, client.inventory())

        runner_binary.write_bytes(b"runner-v2")
        with pytest.raises(RunnerRemoteError) as error:
            client.transport_identity()

    assert error.value.code == "runner_failure"


@pytest.mark.parametrize("binary_change", ["mutate", "delete"])
def test_instance_bound_shutdown_survives_binary_quarantine_and_reports_active_tasks(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    binary_change: str,
) -> None:
    runner_binary = tmp_path / "quarantined-runner.exe"
    runner_binary.write_bytes(b"runner-v1")
    runner = RecordingRunner()
    runner.runner_binary = runner_binary  # type: ignore[attr-defined]
    state_path = tmp_path / "transport.sqlite3"
    server = AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        state_path,
        secret_provider=secret_provider,
    ).start()
    client = _client(enrollment_root, server, secret_provider)
    recorded_instance_id = str(client.health()["server_instance_id"])
    client.execute(manifest, profile)
    task_id, _request_hash = client.execution_identity(manifest, profile)
    with sqlite3.connect(state_path) as database:
        database.execute(
            "UPDATE transport_tasks SET state = 'running' WHERE task_id = ?",
            (task_id,),
        )

    if binary_change == "mutate":
        runner_binary.write_bytes(b"runner-v2")
    else:
        runner_binary.unlink()

    with pytest.raises(RunnerRemoteError) as health_error:
        client.shutdown()
    assert health_error.value.code == "runner_failure"
    with pytest.raises(RunnerRemoteError) as active_error:
        client.shutdown(server_instance_id=recorded_instance_id)
    assert active_error.value.code == "active_tasks"

    with sqlite3.connect(state_path) as database:
        database.execute(
            "UPDATE transport_tasks SET state = 'completed' WHERE task_id = ?",
            (task_id,),
        )
    acknowledgement = client.shutdown(server_instance_id=recorded_instance_id)
    if server._serve_thread is not None:
        server._serve_thread.join(timeout=5)
    server.shutdown()

    assert acknowledgement["status"] == "shutdown_acknowledged"
    assert acknowledgement["server_instance_id"] == recorded_instance_id


def test_binary_is_verified_around_inventory_and_after_exception(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    runner_binary = tmp_path / "replace-during-inventory.exe"
    runner_binary.write_bytes(b"runner-v1")
    runner = BinaryReplacingInventoryRunner(runner_binary)
    with AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        with pytest.raises(RunnerRemoteError) as error:
            _client(enrollment_root, server, secret_provider).execute(manifest, profile)

    assert error.value.code == "runner_failure"
    assert runner.inventory_calls == 1
    assert runner.calls == 0


def test_subprocess_runner_construction_digest_cannot_be_rebound_by_server(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
) -> None:
    runner_binary = tmp_path / "constructed-runner.exe"
    runner_binary.write_bytes(b"runner-v1")
    runner = SubprocessRustRunner(runner_binary, tmp_path / "runner-work")
    runner_binary.write_bytes(b"runner-v2")

    with pytest.raises(
        AuthenticatedRunnerTransportError, match="changed after runner construction"
    ):
        AuthenticatedRunnerServer(
            enrollment_root,
            runner,
            tmp_path / "transport.sqlite3",
            secret_provider=secret_provider,
        )


def test_bounded_ledger_reserves_authenticated_control_at_execute_capacity(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    request: pytest.FixtureRequest,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    state_path = tmp_path / "transport.sqlite3"
    runner = BlockingInventoryRunner()
    server = AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        state_path,
        max_terminal_rows=1,
        max_ledger_rows=6,
        control_reserve_rows=3,
        secret_provider=secret_provider,
    ).start()
    control_workers: list[threading.Thread] = []
    control_timeout_seconds = 30.0

    def join_control_workers() -> None:
        deadline = time.monotonic() + control_timeout_seconds + 5
        for worker in control_workers:
            if worker.is_alive():
                worker.join(timeout=max(0.0, deadline - time.monotonic()))

    def cleanup_server() -> None:
        runner.release_inventory.set()
        join_control_workers()
        server.shutdown()

    request.addfinalizer(cleanup_server)
    client = _client(
        enrollment_root,
        server,
        secret_provider,
        timeout_seconds=control_timeout_seconds,
    )
    for _index in range(5):
        client.health()
    with sqlite3.connect(state_path) as database:
        polling_rows = int(
            database.execute(
                "SELECT COUNT(*) FROM transport_tasks WHERE operation != 'execute'"
            ).fetchone()[0]
        )
    assert polling_rows <= 1

    identities: list[tuple[str, str]] = []
    for index in range(3):
        current = {
            **dict(manifest),
            "request_id": f"request-{index}",
            "run_id": f"run-{index}",
            "step_id": f"step-{index}",
            "request_hash": "sha256:" + f"{index + 3:x}" * 64,
        }
        client.execute(current, profile)
        identities.append(client.execution_identity(current, profile))

    status = client.health()
    assert status["ledger"]["execute_rows"] == 3
    assert status["ledger"]["execute_capacity"] == 3
    assert status["ledger"]["accepting_execute"] is False
    saturated = {
        **dict(manifest),
        "request_id": "request-saturated",
        "run_id": "run-saturated",
        "step_id": "step-saturated",
        "request_hash": "sha256:" + "f" * 64,
    }
    with pytest.raises(RunnerRemoteError) as capacity_error:
        client.execute(saturated, profile)
    assert capacity_error.value.code == "ledger_capacity"

    runner.block_inventory = True
    control_results: list[Mapping[str, Any]] = []
    control_errors: list[BaseException] = []

    def health() -> None:
        try:
            control_results.append(client.health())
        except BaseException as exc:
            control_errors.append(exc)

    control_workers = [threading.Thread(target=health, daemon=True) for _index in range(3)]
    for worker in control_workers:
        worker.start()
    assert runner.wait_for_inventory(3)
    runner.release_inventory.set()
    join_control_workers()
    assert all(not worker.is_alive() for worker in control_workers)
    assert control_errors == []
    assert len(control_results) == 3

    recovered = client.recover(*identities[0])
    cancellation = client.cancel(*identities[0])
    acknowledgement = client.shutdown()
    cleanup_server()

    assert recovered["state"] == "completed"
    assert cancellation["state"] == "completed"
    assert cancellation["cancelled"] is False
    assert acknowledgement["status"] == "shutdown_acknowledged"
    assert runner.calls == 3

    stale_instance = str(status["server_instance_id"])
    for cycle in range(2):
        restarted = AuthenticatedRunnerServer(
            enrollment_root,
            runner,
            state_path,
            max_terminal_rows=1,
            max_ledger_rows=6,
            control_reserve_rows=3,
            secret_provider=secret_provider,
        ).start()
        request.addfinalizer(restarted.shutdown)
        restarted_client = _client(enrollment_root, restarted, secret_provider)
        if cycle == 0:
            enrollment = load_local_enrollment(enrollment_root, secret_provider=secret_provider)
            stale_unsigned = _unsigned_request(
                enrollment,
                operation="shutdown",
                task_id="shutdown-stale-instance",
                payload={"server_instance_id": stale_instance},
            )
            stale_request = wire._sign_request(enrollment, stale_unsigned)
            stale_response = _raw_exchange_enrollment(enrollment, restarted, stale_request)
            with pytest.raises(RunnerRemoteError) as stale_error:
                AuthenticatedRunnerClient._validated_response(
                    stale_response, stale_request, enrollment
                )
            assert stale_error.value.code == "task_identity_mismatch"
        restarted_ack = restarted_client.shutdown()
        assert restarted_ack["server_instance_id"] != stale_instance
        if restarted._serve_thread is not None:
            restarted._serve_thread.join(timeout=5)
        restarted.shutdown()

    with sqlite3.connect(state_path) as database:
        total = int(database.execute("SELECT COUNT(*) FROM transport_tasks").fetchone()[0])
        shutdown_rows = int(
            database.execute(
                "SELECT COUNT(*) FROM transport_tasks WHERE operation = 'shutdown'"
            ).fetchone()[0]
        )
    assert total <= 6
    assert shutdown_rows == 1


def test_ledger_byte_quota_refuses_execute_while_preserving_control(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    frame_bytes = 4096
    padded = {**dict(manifest), "quota_padding": "x" * 1800}
    first_payload_size = len(canonical_json_bytes({"manifest": padded, "profile": dict(profile)}))
    byte_capacity = (
        3 * frame_bytes
        + first_payload_size
        + frame_bytes
        + wire._EXECUTE_RECOVERY_RESERVE_BYTES
        + 100
    )
    runner = RecordingRunner()
    with AuthenticatedRunnerServer(
        enrollment_root,
        runner,
        tmp_path / "transport.sqlite3",
        max_frame_bytes=frame_bytes,
        max_ledger_rows=20,
        control_reserve_rows=3,
        max_ledger_bytes=byte_capacity,
        secret_provider=secret_provider,
    ) as server:
        client = _client(enrollment_root, server, secret_provider)
        client.max_frame_bytes = frame_bytes
        first = client.execute(padded, profile)
        health = client.health()
        second = {
            **padded,
            "request_id": "quota-request-2",
            "run_id": "quota-run-2",
            "step_id": "quota-step-2",
            "request_hash": "sha256:" + "e" * 64,
        }
        with pytest.raises(RunnerRemoteError) as capacity_error:
            client.execute(second, profile)
        recovered = client.recover(*client.execution_identity(padded, profile))

    ledger = health["ledger"]
    assert first["status"] == "success"
    assert capacity_error.value.code == "ledger_capacity"
    assert recovered["state"] == "completed"
    assert ledger["byte_capacity"] == byte_capacity
    assert ledger["control_reserve_bytes"] == 3 * frame_bytes
    assert 0 < ledger["blob_bytes"] <= ledger["committed_bytes"] <= byte_capacity
    assert runner.calls == 1


def test_revocation_is_reloaded_without_restarting_server(
    enrollment_root: Path,
    secret_provider: InMemorySecretProvider,
    tmp_path: Path,
) -> None:
    with AuthenticatedRunnerServer(
        enrollment_root,
        RecordingRunner(),
        tmp_path / "transport.sqlite3",
        secret_provider=secret_provider,
    ) as server:
        client = _client(enrollment_root, server, secret_provider)
        assert client.health()["status"] == "ready"
        retained = load_local_enrollment(enrollment_root, secret_provider=secret_provider)
        retained_request = wire._sign_request(
            retained,
            _unsigned_request(retained, task_id="retained-after-revocation"),
        )
        revoke_local_enrollment(enrollment_root, secret_provider=secret_provider)
        with pytest.raises((RunnerConnectionError, OSError, ssl.SSLError)):
            _raw_exchange_enrollment(retained, server, retained_request)
        with pytest.raises(RunnerAuthenticationError, match="inactive"):
            client.health()
