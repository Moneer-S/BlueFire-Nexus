"""Managed correction transport recovery with generated public evidence only."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path

import pytest

import bluefire.runner_transport as runner_transport
from bluefire import product_store_file_access_managed_ready as managed_ready_store
from bluefire import runner_private_files as private_files_module
from bluefire import windows_file_access_managed_evidence as managed_evidence
from bluefire import windows_file_access_managed_result as managed_result
from bluefire import windows_file_access_managed_session as managed_session
from bluefire.runner_client import (
    RunnerTaskCancelled,
    RunnerTransportError,
    SubprocessRustRunner,
    execution_task_identity,
    runner_watchdog_control_root,
)
from bluefire.runner_durable_result import DurableRunnerResult, runner_pending_result_path
from bluefire.runner_private_files import _PinnedPrivateDirectory, _windows_extended_path
from bluefire.runner_transport import (
    AuthenticatedRunnerServer,
    AuthenticatedRunnerTransportError,
    audit_runner_ledger,
)
from bluefire.runner_transport_security import enrollment_binding
from bluefire.runner_trust import create_local_enrollment, load_local_enrollment
from bluefire.secret_store import InMemorySecretProvider
from bluefire.util import canonical_json_bytes, file_hash
from tests_platform.test_authenticated_runner_transport import RecordingRunner
from tests_platform.test_windows_file_access_baseline_publication import saved as saved
from tests_platform.test_windows_file_access_correction_execution import execution as execution
from tests_platform.test_windows_file_access_correction_reservation import reviewed as reviewed
from tests_platform.test_windows_file_access_pair_provenance import paired as paired
from tests_platform.test_windows_file_access_setup_lifecycle import lifecycle as lifecycle


def test_managed_handoff_types_have_one_domain_identity():
    assert (
        managed_session.PersistedManagedCorrectionReady
        is managed_evidence.PersistedManagedCorrectionReady
    )
    assert (
        managed_result.AuthenticatedManagedCorrectionClosure
        is managed_evidence.AuthenticatedManagedCorrectionClosure
    )


def _managed_values(value):
    value.runtime.execute(value.ctx, value.request)
    descriptor = value.state.remote_client.descriptor
    result = value.state.remote_client.result
    records = value.store.file_access_operation_records(value.job)
    task = records["tasks"][0]["task"]
    assert descriptor is not None and result is not None
    return descriptor, result, task["manifest"], task["runner_profile"]


def _local_path(path: Path) -> Path:
    return _windows_extended_path(path) if os.name == "nt" else path


def _observe_windows_rename(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[list[str], list[tuple[object, object, str]]]:
    native_rename = private_files_module._windows_rename_descriptor
    calls: list[str] = []
    failures: list[tuple[object, object, str]] = []

    def checked_rename(descriptor: int, root_descriptor: int, target_name: str) -> None:
        calls.append(target_name)
        try:
            native_rename(descriptor, root_descriptor, target_name)
        except FileExistsError:
            raise
        except OSError as exc:
            failures.append((exc.errno, getattr(exc, "winerror", None), type(exc).__name__))
            raise

    monkeypatch.setattr(private_files_module, "_windows_rename_descriptor", checked_rename)
    return calls, failures


def _fail_with_windows_rename_diagnostic(
    failures: list[tuple[object, object, str]],
    error: RunnerTransportError,
) -> None:
    if not failures:
        raise error
    errno, winerror, error_type = failures[-1]
    pytest.fail(
        "Windows handle-relative managed result promotion failed after production normalization "
        f"(error_type={error_type}, errno={errno!r}, winerror={winerror!r})"
    )


def _windows_path_units(path: Path) -> int:
    return len(os.fspath(path).encode("utf-16-le", errors="surrogatepass")) // 2


def _assert_short_publication_paths(
    destination: Path,
    task_id: str,
    owned_root: Path,
) -> Path:
    pending = runner_pending_result_path(destination, task_id)
    parent = destination.parent
    lengths = {
        "parent": _windows_path_units(parent),
        "staging": _windows_path_units(parent / (".t-" + "0" * 12)),
        "final": _windows_path_units(destination),
        "pending": _windows_path_units(pending),
    }
    namespace = parent.name
    assert len(namespace) == 40 and all(character in "0123456789abcdef" for character in namespace)
    assert parent.parent == owned_root / ".bluefire-runner-results"
    assert destination.name == hashlib.sha256(task_id.encode("utf-8")).hexdigest()[:40] + ".json"
    expected_parent = (
        _windows_path_units(owned_root) + 1 + len(".bluefire-runner-results") + 1 + len(namespace)
    )
    assert lengths == {
        "parent": expected_parent,
        "staging": expected_parent + 16,
        "final": expected_parent + 46,
        "pending": expected_parent + 90,
    }
    if not (
        lengths["parent"] < 160
        and lengths["staging"] < 180
        and lengths["final"] < 220
        and lengths["pending"] < 240
    ):
        pytest.skip(f"short Windows managed result root is unavailable: {lengths}")
    return pending


def _managed_server(
    tmp_path: Path,
    manifest: dict,
    profile: dict,
    *,
    runner=None,
) -> tuple[AuthenticatedRunnerServer, InMemorySecretProvider, Path]:
    provider = InMemorySecretProvider()
    root = tmp_path / "managed-trust"
    create_local_enrollment(
        root,
        runner_id=str(manifest["runner_id"]),
        client_id="bluefire-control-plane.v1",
        allowed_profile_ids=[str(profile["profile_id"])],
        secret_provider=provider,
    )
    server = AuthenticatedRunnerServer(
        root,
        runner or RecordingRunner(),
        tmp_path / "managed-transport.sqlite3",
        secret_provider=provider,
    )
    return server, provider, root


def _insert_running_managed_task(
    server: AuthenticatedRunnerServer,
    enrollment_root: Path,
    provider: InMemorySecretProvider,
    descriptor: managed_session.ManagedCorrectionDescriptor,
    manifest: dict,
    profile: dict,
    *,
    effect_dispatched: int = 1,
) -> None:
    enrollment = load_local_enrollment(enrollment_root, secret_provider=provider)
    binding = enrollment_binding(enrollment, str(enrollment.metadata["client_fingerprint"]))
    now = time.time_ns()
    payload = canonical_json_bytes(
        {
            "manifest": manifest,
            "profile": profile,
            "windows_correction_session": dict(descriptor.value),
        }
    )
    with server._database(write=True) as connection:
        connection.execute(
            """
            INSERT INTO transport_tasks (
                task_id, operation, profile_id, request_hash,
                runner_id, client_id, peer_fingerprint, ca_fingerprint,
                server_fingerprint, client_fingerprint, enrollment_generation,
                nonce, state, execute_payload_json, result_json,
                recovery_receipts_json, cleanup_required, effect_dispatched,
                error_code, executor_instance, cancellation_requested,
                created_at, updated_at, cancellation_proof_json
            ) VALUES (
                ?, 'execute', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', ?,
                NULL, NULL, 0, ?, NULL, ?, 0, ?, ?, NULL
            )
            """,
            (
                descriptor.value["task_id"],
                profile["profile_id"],
                descriptor.value["transport_request_hash"],
                binding["runner_id"],
                binding["client_id"],
                binding["peer_fingerprint"],
                binding["ca_fingerprint"],
                binding["server_fingerprint"],
                binding["client_fingerprint"],
                binding["enrollment_generation"],
                secrets.token_hex(32),
                payload,
                effect_dispatched,
                server.instance_id,
                now,
                now,
            ),
        )


def _write_stale_managed_control(
    server: AuthenticatedRunnerServer,
    descriptor: managed_session.ManagedCorrectionDescriptor,
    manifest: dict,
    profile: dict,
) -> Path:
    task_id = str(descriptor.value["task_id"])
    destination = server.durable_result_path(task_id)
    root = runner_watchdog_control_root(destination, task_id)
    _local_path(root).mkdir()
    config = {
        "schema_version": "bluefire.runner-watchdog-config.v5",
        "task_id": task_id,
        "runner_binary": "C:/synthetic/bluefire-runner.exe",
        "runner_binary_digest": "sha256:" + "1" * 64,
        "parent_death_script_digest": "sha256:" + "2" * 64,
        "watchdog_script_digest": "sha256:" + "3" * 64,
        "watchdog_interpreter": "C:/synthetic/python.exe",
        "watchdog_interpreter_digest": "sha256:" + "4" * 64,
        "work_root": "C:/synthetic/work",
        "timeout_seconds": 5.0,
        "output_limit_bytes": 4096,
        "durable_result_path": str(destination),
        "durable_result_parent_identity": [1, 2],
        "durable_result_parent_mount_identity": None,
        "manifest": manifest,
        "profile": profile,
        "cancellation_lease_token": None,
    }
    ready = {
        "schema_version": "bluefire.runner-watchdog-ready.v1",
        "task_id": task_id,
        "watchdog_pid": 4242,
    }
    status = {
        "schema_version": "bluefire.runner-watchdog-status.v2",
        "task_id": task_id,
        "state": "succeeded",
        "error_code": None,
        "watchdog_pid": 4242,
        "result_digest": file_hash(destination),
    }
    (_local_path(root) / "config.json").write_bytes(canonical_json_bytes(config) + b"\n")
    (_local_path(root) / "session.json").write_bytes(
        canonical_json_bytes(dict(descriptor.value)) + b"\n"
    )
    (_local_path(root) / "start").write_bytes(b"start\n")
    (_local_path(root) / "ready.json").write_bytes(canonical_json_bytes(ready) + b"\n")
    (_local_path(root) / "status.json").write_bytes(canonical_json_bytes(status) + b"\n")
    return root


class _GeneratedPromotion(DurableRunnerResult):
    """Exercise the production writer while replacing the host-native rename."""

    def promote(
        self,
        pending: Path,
        destination: Path,
        *,
        pending_expected: bytes,
        pending_identity: tuple[int, int],
        final_payload: bytes,
    ) -> None:
        assert pending_identity[0] > 0 and pending_identity[1] > 0
        assert _local_path(pending).read_bytes() == pending_expected
        assert final_payload == pending_expected
        _local_path(destination).write_bytes(final_payload)
        _local_path(pending).unlink()


def _promote_managed_result(
    destination: Path,
    descriptor: managed_session.ManagedCorrectionDescriptor,
    result: dict,
    manifest: dict,
    profile: dict,
) -> None:
    publisher = object.__new__(SubprocessRustRunner)
    publisher._durable_results = _GeneratedPromotion()
    assert (
        publisher._commit_managed_correction_result(
            result,
            manifest,
            profile,
            task_id=str(descriptor.value["task_id"]),
            durable_result_path=destination,
        )
        == result
    )
    assert _local_path(destination).read_bytes() == canonical_json_bytes(result) + b"\n"


@pytest.mark.skipif(os.name != "nt", reason="Windows native managed result promotion")
def test_managed_terminal_result_uses_real_short_native_publication(
    execution,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor, result, manifest, profile = _managed_values(execution)
    server, provider, root = _managed_server(tmp_path, manifest, profile)
    task_id = str(descriptor.value["task_id"])
    expected = canonical_json_bytes(result) + b"\n"
    with server:
        _insert_running_managed_task(server, root, provider, descriptor, manifest, profile)
        destination = server.durable_result_path(task_id)
        pending = _assert_short_publication_paths(destination, task_id, tmp_path)
        service_guard = server._result_root_guards[-1]
        assert service_guard.path == destination.parent
        watchdog_guard = _PinnedPrivateDirectory(
            destination.parent,
            expected_identity=service_guard.directory_identity(),
            expected_mount_identity=service_guard.directory_mount_identity(),
        )
        watchdog_guard.__enter__()
        publisher = object.__new__(SubprocessRustRunner)
        publisher._durable_result_guard = watchdog_guard
        publisher._durable_results = DurableRunnerResult(parent_guard=watchdog_guard)
        calls, failures = _observe_windows_rename(monkeypatch)

        try:
            assert (
                publisher._commit_managed_correction_result(
                    result,
                    manifest,
                    profile,
                    task_id=task_id,
                    durable_result_path=destination,
                )
                == result
            )
        except RunnerTransportError as exc:
            _fail_with_windows_rename_diagnostic(failures, exc)
        finally:
            watchdog_guard.close()

        assert calls == [destination.name]
        assert failures == []
        assert _local_path(destination).read_bytes() == expected
        assert not _local_path(pending).exists()
        assert set(os.listdir(_local_path(destination.parent))) == {destination.name}
        service_guard.authorize_cleanup_entry(
            destination.name,
            maximum=server.max_frame_bytes,
        )

        recovered = server._reconcile_execute_task(task_id)
        repeated = server._reconcile_execute_task(task_id)

    assert recovered == {"state": "completed", "result": result, "receipt_ids": []}
    assert repeated == recovered
    _local_path(destination).unlink()
    assert os.listdir(_local_path(destination.parent)) == []


def _insert_running_legacy_task(
    server: AuthenticatedRunnerServer,
    enrollment_root: Path,
    provider: InMemorySecretProvider,
    manifest: dict,
    profile: dict,
) -> None:
    enrollment = load_local_enrollment(enrollment_root, secret_provider=provider)
    binding = enrollment_binding(enrollment, str(enrollment.metadata["client_fingerprint"]))
    task_id, request_hash = execution_task_identity(manifest, profile)
    now = time.time_ns()
    with server._database(write=True) as connection:
        connection.execute(
            """
            INSERT INTO transport_tasks (
                task_id, operation, profile_id, request_hash,
                runner_id, client_id, peer_fingerprint, ca_fingerprint,
                server_fingerprint, client_fingerprint, enrollment_generation,
                nonce, state, execute_payload_json, result_json,
                recovery_receipts_json, cleanup_required, effect_dispatched,
                error_code, executor_instance, cancellation_requested,
                created_at, updated_at, cancellation_proof_json
            ) VALUES (
                ?, 'execute', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', ?,
                NULL, NULL, 0, 0, NULL, ?, 0, ?, ?, NULL
            )
            """,
            (
                task_id,
                profile["profile_id"],
                request_hash,
                binding["runner_id"],
                binding["client_id"],
                binding["peer_fingerprint"],
                binding["ca_fingerprint"],
                binding["server_fingerprint"],
                binding["client_fingerprint"],
                binding["enrollment_generation"],
                secrets.token_hex(32),
                canonical_json_bytes({"manifest": manifest, "profile": profile}),
                server.instance_id,
                now,
                now,
            ),
        )


class _ManagedRunner(RecordingRunner):
    managed_correction_session_protocol = managed_session.DESCRIPTOR_SCHEMA

    def __init__(
        self,
        ready: bytes,
        ack_nonce: str,
        result: dict,
        *,
        hold_cancel: bool = False,
    ) -> None:
        super().__init__()
        self.ready = ready
        self.ack_nonce = ack_nonce
        self.result = result
        self.control = None
        self.begin_attempted = False
        self.cancelled_before_ack = False
        self.ready_published = threading.Event()
        self.cancel_seen = threading.Event()
        self.release_cancel = threading.Event()
        if not hold_cancel:
            self.release_cancel.set()

    def execute_task(
        self,
        manifest,
        profile,
        *,
        task_id,
        cancel_event,
        durable_result_path,
        windows_correction_session,
        windows_correction_control,
    ):
        del durable_result_path
        self.calls += 1
        descriptor = managed_session.validate_descriptor(
            windows_correction_session,
            manifest,
            profile,
            task_id=task_id,
        )
        assert windows_correction_control.descriptor.value == descriptor.value
        self.control = windows_correction_control
        windows_correction_control.publish_ready(self.ready, self.ack_nonce)
        self.ready_published.set()
        try:
            acknowledgement = windows_correction_control.wait_ack(cancel_event)
        except managed_session.ManagedCorrectionSessionError:
            self.cancelled_before_ack = cancel_event.is_set()
            self.cancel_seen.set()
            if not self.release_cancel.wait(timeout=5):
                raise AssertionError("synthetic cancellation release timed out") from None
            raise RunnerTaskCancelled("synthetic cancellation before managed ack") from None
        windows_correction_control.mark_delivered(acknowledgement)
        self.begin_attempted = True
        return self.result


def _persisted_receipt(value, descriptor):
    receipt = value.state.remote_client.consume_receipt
    ready = value.state.remote_client.ready
    assert receipt is not None and ready is not None
    return managed_ready_store.validate_persisted_managed_correction_ready(
        value.store,
        descriptor.value["task_id"],
        descriptor.value["transport_request_hash"],
        descriptor.value["expected_binding"],
        receipt,
        packet=descriptor.packet,
        ready=ready,
        clock=value.runtime._clock(),
    )


def _acknowledgement(descriptor, ready, receipt_document):
    ready_payload = managed_session.watchdog_ready_payload(
        descriptor, ready, receipt_document["ack_nonce"]
    )
    return {
        "schema_version": managed_session.ACK_SCHEMA,
        "original_task_id": descriptor.value["task_id"],
        "original_request_hash": descriptor.value["transport_request_hash"],
        "session_nonce": descriptor.value["session_nonce"],
        "packet_digest": descriptor.packet_digest,
        "ready_digest": ready_payload["ready_digest"],
        "ack_nonce": receipt_document["ack_nonce"],
        "persisted_consume_receipt": receipt_document,
        "persisted_consume_digest": managed_session.persisted_consume_digest(receipt_document),
    }


def _start_execute(
    server,
    root,
    provider,
    descriptor,
    manifest,
    profile,
):
    enrollment = load_local_enrollment(root, secret_provider=provider)
    peer = str(enrollment.metadata["client_fingerprint"])
    binding = enrollment_binding(enrollment, peer)
    request = {
        "profile_id": profile["profile_id"],
        "task_id": descriptor.value["task_id"],
        "request_hash": descriptor.value["transport_request_hash"],
    }
    outcomes = []
    failures = []

    def execute():
        try:
            outcomes.append(
                server._execute_payload(
                    request,
                    enrollment,
                    manifest,
                    profile,
                    peer_fingerprint=peer,
                    windows_correction_descriptor=descriptor.value,
                    enrollment_binding=binding,
                )
            )
        except BaseException as exc:
            failures.append(exc)

    worker = threading.Thread(target=execute, daemon=True)
    worker.start()
    return request, binding, worker, outcomes, failures


@pytest.mark.parametrize(
    "retained_names",
    [
        frozenset({"config.json", "session.json", "start", "ready.json"}),
        frozenset({"status.json"}),
        frozenset({"session.json", "ready.json", "status.json"}),
    ],
)
def test_promoted_managed_result_recovers_exact_terminal_cleanup_states(
    execution, tmp_path: Path, retained_names: frozenset[str]
) -> None:
    descriptor, result, manifest, profile = _managed_values(execution)
    server, provider, root = _managed_server(tmp_path, manifest, profile)
    with server:
        _insert_running_managed_task(server, root, provider, descriptor, manifest, profile)
        assert len(canonical_json_bytes(result)) <= server.max_frame_bytes
        assert server._validated_execute_result(result, manifest, profile) == result
        destination = server.durable_result_path(str(descriptor.value["task_id"]))
        _promote_managed_result(destination, descriptor, result, manifest, profile)
        control_root = _write_stale_managed_control(server, descriptor, manifest, profile)
        for name in (
            "config.json",
            "session.json",
            "start",
            "ready.json",
            "status.json",
        ):
            if name not in retained_names:
                (_local_path(control_root) / name).unlink()

        changed_value = {**descriptor.value, "session_nonce": "d" * 64}
        changed = managed_session.validate_descriptor(
            changed_value,
            manifest,
            profile,
            require_live=False,
        )
        with pytest.raises(RunnerTransportError):
            server._recover_durable_result(
                str(descriptor.value["task_id"]), manifest, profile, changed
            )

        recovered = server._reconcile_execute_task(str(descriptor.value["task_id"]))
        repeated = server._reconcile_execute_task(str(descriptor.value["task_id"]))

    assert recovered == {"state": "completed", "result": result, "receipt_ids": []}
    assert repeated == recovered
    assert not _local_path(control_root).exists()


def test_completed_recovery_retries_cleanup_after_status_publication(
    execution, tmp_path: Path
) -> None:
    descriptor, result, manifest, profile = _managed_values(execution)
    server, provider, root = _managed_server(tmp_path, manifest, profile)
    enrollment = load_local_enrollment(root, secret_provider=provider)
    binding = enrollment_binding(enrollment, str(enrollment.metadata["client_fingerprint"]))
    task_id = str(descriptor.value["task_id"])
    with server:
        _insert_running_managed_task(server, root, provider, descriptor, manifest, profile)
        destination = server.durable_result_path(task_id)
        _promote_managed_result(destination, descriptor, result, manifest, profile)
        control_root = _write_stale_managed_control(server, descriptor, manifest, profile)
        changed_session = {**descriptor.value, "session_nonce": "e" * 64}
        (_local_path(control_root) / "session.json").write_bytes(
            canonical_json_bytes(changed_session) + b"\n"
        )
        retained = set(os.listdir(_local_path(control_root)))

        first = server._reconcile_execute_task(task_id)

        assert first == {"state": "completed", "result": result, "receipt_ids": []}
        assert set(os.listdir(_local_path(control_root))) == retained
        for name in retained:
            (_local_path(control_root) / name).unlink()
        status = {
            "schema_version": "bluefire.runner-watchdog-status.v2",
            "task_id": task_id,
            "state": "succeeded",
            "error_code": None,
            "watchdog_pid": 4242,
            "result_digest": file_hash(destination),
        }
        (_local_path(control_root) / "status.json").write_bytes(
            canonical_json_bytes(status) + b"\n"
        )
        recovered = server._recover_payload(
            {"profile_id": profile["profile_id"]},
            {
                "original_task_id": task_id,
                "original_request_hash": descriptor.value["transport_request_hash"],
            },
            binding,
        )

    assert recovered["state"] == "completed"
    assert recovered["result"] == result
    assert not _local_path(control_root).exists()


def test_promoted_managed_result_never_removes_drifted_stale_controls(
    execution, tmp_path: Path
) -> None:
    descriptor, result, manifest, profile = _managed_values(execution)
    server, provider, root = _managed_server(tmp_path, manifest, profile)
    with server:
        _insert_running_managed_task(server, root, provider, descriptor, manifest, profile)
        destination = server.durable_result_path(str(descriptor.value["task_id"]))
        _promote_managed_result(destination, descriptor, result, manifest, profile)
        control_root = _write_stale_managed_control(server, descriptor, manifest, profile)
        changed_session = {**descriptor.value, "session_nonce": "f" * 64}
        (_local_path(control_root) / "session.json").write_bytes(
            canonical_json_bytes(changed_session) + b"\n"
        )

        recovered = server._reconcile_execute_task(str(descriptor.value["task_id"]))

    assert recovered == {"state": "completed", "result": result, "receipt_ids": []}
    assert _local_path(control_root).exists()


def test_stopped_ledger_audit_accepts_exact_managed_row_and_rejects_drift(
    execution, tmp_path: Path
) -> None:
    descriptor, _result, manifest, profile = _managed_values(execution)
    server, provider, root = _managed_server(tmp_path, manifest, profile)
    state_path = server.state_path
    enrollment = load_local_enrollment(root, secret_provider=provider)
    with server:
        _insert_running_managed_task(server, root, provider, descriptor, manifest, profile)

    assert audit_runner_ledger(state_path, enrollment) == {
        "schema_version": "bluefire.runner-ledger-audit.v1",
        "ledger_generation": server.ledger_generation,
        "total_rows": 1,
        "execute_rows": 1,
        "unresolved_rows": 1,
        "active_rows": 1,
        "cleanup_required_rows": 0,
    }

    with sqlite3.connect(state_path) as connection:
        raw = connection.execute("SELECT execute_payload_json FROM transport_tasks").fetchone()[0]
        decoded = json.loads(bytes(raw).decode("utf-8"))
        decoded["windows_correction_session"]["expected_binding"] = {
            **decoded["windows_correction_session"]["expected_binding"],
            "generation": "changed",
        }
        connection.execute(
            "UPDATE transport_tasks SET execute_payload_json=?",
            (canonical_json_bytes(decoded),),
        )
    with pytest.raises(AuthenticatedRunnerTransportError):
        audit_runner_ledger(state_path, enrollment)


def test_stopped_ledger_audit_still_accepts_legacy_execute_row(tmp_path: Path) -> None:
    sandbox = tmp_path / "legacy-sandbox"
    sandbox.mkdir()
    profile = {
        "schema_version": "bluefire.runner-profile.v1",
        "profile_id": "sandbox-execute.v1",
        "runner_id": "bluefire-rust-runner.v1",
        "platform": "windows",
        "sandbox_root": str(sandbox.resolve(strict=True)),
        "policy_digest": "sha256:" + "2" * 64,
        "limits": {"max_artifact_bytes": 1024, "max_files": 8},
    }
    manifest = {
        "schema_version": "bluefire.runner-manifest.v1",
        "request_id": "legacy-request",
        "request_hash": "sha256:" + "1" * 64,
        "run_id": "legacy-run",
        "step_id": "legacy-step",
        "behavior_id": "sandbox.fixture.create.v1",
        "action_id": "sandbox.fixture.create.v1",
        "runner_id": profile["runner_id"],
        "runner_profile_id": profile["profile_id"],
        "platform": profile["platform"],
        "policy_digest": profile["policy_digest"],
        "limits": profile["limits"],
    }
    server, provider, root = _managed_server(tmp_path, manifest, profile)
    state_path = server.state_path
    enrollment = load_local_enrollment(root, secret_provider=provider)
    with server:
        _insert_running_legacy_task(server, root, provider, manifest, profile)

    assert audit_runner_ledger(state_path, enrollment) == {
        "schema_version": "bluefire.runner-ledger-audit.v1",
        "ledger_generation": server.ledger_generation,
        "total_rows": 1,
        "execute_rows": 1,
        "unresolved_rows": 1,
        "active_rows": 1,
        "cleanup_required_rows": 0,
    }


def test_cancellation_committed_before_ack_releases_no_begin(execution, tmp_path: Path) -> None:
    descriptor, result, manifest, profile = _managed_values(execution)
    ready = execution.state.remote_client.ready
    receipt_document = execution.state.remote_client.consume_receipt
    assert ready is not None and receipt_document is not None
    _persisted_receipt(execution, descriptor)
    runner = _ManagedRunner(
        ready,
        receipt_document["ack_nonce"],
        result,
        hold_cancel=True,
    )
    server, provider, root = _managed_server(tmp_path, manifest, profile, runner=runner)
    with server:
        _insert_running_managed_task(
            server,
            root,
            provider,
            descriptor,
            manifest,
            profile,
            effect_dispatched=0,
        )
        request, binding, worker, _outcomes, failures = _start_execute(
            server, root, provider, descriptor, manifest, profile
        )
        assert runner.ready_published.wait(timeout=5)
        cancellations = []

        def cancel():
            cancellations.append(
                server._cancel_payload(
                    request,
                    {
                        "original_task_id": descriptor.value["task_id"],
                        "original_request_hash": descriptor.value["transport_request_hash"],
                    },
                    binding,
                )
            )

        canceller = threading.Thread(target=cancel, daemon=True)
        canceller.start()
        assert runner.cancel_seen.wait(timeout=5)
        with pytest.raises(runner_transport._RequestRefusal) as refusal:
            server._windows_correction_ack_payload(
                _acknowledgement(descriptor, ready, receipt_document),
                binding,
                profile_id=str(profile["profile_id"]),
            )
        assert getattr(refusal.value, "code", None) == "task_identity_mismatch"
        runner.release_cancel.set()
        worker.join(timeout=5)
        canceller.join(timeout=5)
        assert not worker.is_alive() and not canceller.is_alive()
        with server._database() as connection:
            row = connection.execute(
                "SELECT state,cancellation_requested,result_json FROM transport_tasks "
                "WHERE task_id=?",
                (descriptor.value["task_id"],),
            ).fetchone()

    assert failures and cancellations
    assert cancellations[0]["cancellation_requested"] is True
    assert runner.cancelled_before_ack
    assert not runner.begin_attempted
    assert runner.control is not None and runner.control._ack is None
    assert row["state"] == "cancelled" and row["cancellation_requested"] == 1
    assert row["result_json"] is None


def test_direct_runner_result_requires_the_original_managed_session(
    execution, tmp_path: Path
) -> None:
    descriptor, result, manifest, profile = _managed_values(execution)
    ready = execution.state.remote_client.ready
    receipt_document = execution.state.remote_client.consume_receipt
    assert ready is not None and receipt_document is not None
    _persisted_receipt(execution, descriptor)
    changed_result = copy.deepcopy(result)
    changed_result["output"]["windows_correction"]["session_nonce"] = "e" * 64
    runner = _ManagedRunner(
        ready,
        receipt_document["ack_nonce"],
        changed_result,
    )
    server, provider, root = _managed_server(tmp_path, manifest, profile, runner=runner)
    with server:
        _insert_running_managed_task(
            server,
            root,
            provider,
            descriptor,
            manifest,
            profile,
            effect_dispatched=0,
        )
        _request, binding, worker, outcomes, failures = _start_execute(
            server, root, provider, descriptor, manifest, profile
        )
        assert runner.ready_published.wait(timeout=5)
        server._windows_correction_ack_payload(
            _acknowledgement(descriptor, ready, receipt_document),
            binding,
            profile_id=str(profile["profile_id"]),
        )
        worker.join(timeout=5)
        assert not worker.is_alive()
        with server._database() as connection:
            row = connection.execute(
                "SELECT state,result_json FROM transport_tasks WHERE task_id=?",
                (descriptor.value["task_id"],),
            ).fetchone()

    assert runner.begin_attempted and not outcomes and failures
    assert row["state"] != "completed" and row["result_json"] is None
