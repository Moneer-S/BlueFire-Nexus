from __future__ import annotations

import json
import os
import secrets
import socket
import sqlite3
import stat
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any, BinaryIO, Iterator, Mapping, Sequence

import pytest

import bluefire.runner_host as runner_host_module
import bluefire.runner_lifecycle as runner_lifecycle_module
import bluefire.runner_transport as runner_transport_module
import bluefire.runner_trust as runner_trust_module
from bluefire import __version__
from bluefire.runner_bootstrap import (
    RUNNER_ID,
    BootstrappedRunner,
    RunnerPackageManifest,
    current_architecture,
    current_platform,
    wheel_platform_tag,
)
from bluefire.runner_client import runner_transport_identity
from bluefire.runner_host import (
    LOOPBACK_HOST,
    PROCESS_RECORD_SCHEMA_VERSION,
    RunnerHostError,
    default_host_command,
    process_record_authentication,
)
from bluefire.runner_lifecycle import (
    CLIENT_ID,
    ManagedRunnerLifecycle,
    RunnerHostSpec,
    RunnerLifecycleError,
)
from bluefire.runner_transport import (
    LEDGER_SCHEMA_VERSION,
    RunnerRemoteError,
    runner_result_namespace_path,
)
from bluefire.runner_trust import (
    RunnerTrustError,
    create_local_enrollment,
    load_local_enrollment,
    remove_local_enrollment,
)
from bluefire.util import canonical_json_bytes, file_hash
from tests_platform.runner_lifecycle_host_helper import (
    ProcessFixtureRunner,
    ProcessTestSecretProvider,
)

PROFILE_ID = "sandbox-execute.v1"


def _fake_bootstrap(**values: Any) -> BootstrappedRunner:
    root = Path(values["managed_root"])
    sandbox = root / "sandbox"
    sandbox.mkdir(parents=True, exist_ok=True)
    binary = Path(sys.executable).resolve(strict=True)
    digest = file_hash(binary).removeprefix("sha256:")
    platform_name = current_platform(values.get("platform_name"))
    architecture = current_architecture(values.get("architecture"))
    manifest = RunnerPackageManifest(
        product_version=str(values.get("product_version") or __version__),
        runner_version=__version__,
        platform=platform_name,
        architecture=architecture,
        filename="bluefire-runner.exe" if platform_name == "windows" else "bluefire-runner",
        size=binary.stat().st_size,
        sha256=digest,
        wheel_platform_tag=wheel_platform_tag(platform_name, architecture),
    )
    return BootstrappedRunner(
        binary_path=binary,
        sandbox_path=sandbox.resolve(strict=True),
        source="environment_override",
        managed_binary=False,
        managed_sandbox=True,
        manifest=manifest,
        binary_sha256=digest,
    )


def _host_command(spec: RunnerHostSpec) -> Sequence[str]:
    platform_name = current_platform()
    return (
        str(Path(sys.executable).resolve(strict=True)),
        "-m",
        "tests_platform.runner_lifecycle_host_helper",
        str(spec.enrollment_root),
        str(spec.runner_binary),
        str(spec.work_root),
        str(spec.state_path),
        str(spec.process_record_path),
        str(spec.start_gate_path),
        spec.launch_id,
        platform_name,
        str(spec.runner_timeout_seconds),
    )


@pytest.fixture
def secret_provider() -> ProcessTestSecretProvider:
    return ProcessTestSecretProvider()


@pytest.fixture
def lifecycle(tmp_path: Path, secret_provider: ProcessTestSecretProvider) -> ManagedRunnerLifecycle:
    return ManagedRunnerLifecycle(
        tmp_path / "m",
        secret_provider=secret_provider,
        bootstrap_factory=_fake_bootstrap,
        host_command_factory=_host_command,
        start_timeout_seconds=10,
        stop_timeout_seconds=10,
        runner_timeout_seconds=2,
    )


def _bootstrap(lifecycle: ManagedRunnerLifecycle) -> Mapping[str, Any]:
    return lifecycle.bootstrap(allowed_profile_ids=(PROFILE_ID,))


def test_constructor_and_status_have_no_launch_or_storage_side_effects(
    tmp_path: Path, secret_provider: ProcessTestSecretProvider
) -> None:
    root = tmp_path / "inert"
    manager = ManagedRunnerLifecycle(
        root,
        secret_provider=secret_provider,
        bootstrap_factory=_fake_bootstrap,
    )

    assert not root.exists()
    status = manager.status()

    assert status["state"] == "unbootstrapped"
    assert status["loopback_only"] is True
    assert not root.exists()


def test_execute_client_uses_runner_budget_without_expanding_control_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    timeouts: list[float] = []

    class StubClient:
        def __init__(self, timeout: float) -> None:
            self.socket_timeout_seconds = timeout

    def client_factory(*_args: object, **kwargs: Any) -> StubClient:
        timeout = float(kwargs["socket_timeout_seconds"])
        timeouts.append(timeout)
        return StubClient(timeout)

    class StubEnrollment:
        root = tmp_path / "enrollment"
        allowed_profile_ids = (PROFILE_ID,)

    class StubBootstrap:
        binary_digest = "sha256:" + "0" * 64
        sandbox_path = tmp_path / "sandbox"

    manager = ManagedRunnerLifecycle(
        tmp_path / "managed",
        client_factory=client_factory,  # type: ignore[arg-type]
        start_timeout_seconds=2,
        runner_timeout_seconds=35,
    )
    enrollment = StubEnrollment()
    bootstrap = StubBootstrap()
    monkeypatch.setattr(manager, "_load_active_enrollment", lambda: enrollment)
    monkeypatch.setattr(manager, "_load_bootstrap", lambda _enrollment: bootstrap)
    monkeypatch.setattr(
        runner_lifecycle_module,
        "read_process_record",
        lambda *_args, **_kwargs: {"port": 43123},
    )

    def authenticated_health(
        _enrollment: object,
        _bootstrap: object,
        _record: Mapping[str, Any],
        profile_id: str,
    ) -> tuple[StubClient, Mapping[str, Any]]:
        control = manager._new_client(  # type: ignore[arg-type]
            enrollment,
            profile_id,
            port=43123,
        )
        return control, {"ledger": {"accepting_execute": True}}

    monkeypatch.setattr(manager, "_authenticated_health", authenticated_health)

    client, sandbox = manager.client_for_profile(PROFILE_ID)

    server_execution_envelope = max(manager.runner_timeout_seconds + 5.0, 10.0)
    assert timeouts == [2.0, server_execution_envelope + 5.0]
    assert client.socket_timeout_seconds > server_execution_envelope
    assert sandbox == bootstrap.sandbox_path


def test_bootstrap_creates_exact_enrollment_and_path_free_stopped_status(
    lifecycle: ManagedRunnerLifecycle,
    secret_provider: ProcessTestSecretProvider,
    tmp_path: Path,
) -> None:
    status = _bootstrap(lifecycle)

    enrollment = load_local_enrollment(
        lifecycle.enrollment_root,
        secret_provider=secret_provider,
    )
    assert enrollment.runner_id == RUNNER_ID
    assert enrollment.client_id == CLIENT_ID
    assert enrollment.allowed_profile_ids == (PROFILE_ID,)
    assert status["state"] == "stopped"
    assert status["process"] == "absent"
    assert status["runner"]["binary_digest"].startswith("sha256:")
    assert str(tmp_path) not in json.dumps(status)
    assert "hmac" not in json.dumps(status).casefold()

    repeated = _bootstrap(lifecycle)
    assert repeated["state"] == "stopped"
    with pytest.raises(RunnerLifecycleError, match="does not match"):
        lifecycle.bootstrap(allowed_profile_ids=("different-profile.v1",))


def test_signed_pid_and_port_record_never_substitutes_for_authenticated_health(
    lifecycle: ManagedRunnerLifecycle,
    secret_provider: ProcessTestSecretProvider,
) -> None:
    _bootstrap(lifecycle)
    enrollment = load_local_enrollment(
        lifecycle.enrollment_root,
        secret_provider=secret_provider,
    )
    bootstrap_status = lifecycle.status(profile_id=PROFILE_ID)
    digest = str(bootstrap_status["runner"]["binary_digest"])
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((LOOPBACK_HOST, 0))
        unused_port = int(probe.getsockname()[1])
    unsigned = {
        "schema_version": PROCESS_RECORD_SCHEMA_VERSION,
        "launch_id": secrets.token_hex(32),
        "pid": os.getpid(),
        "host": LOOPBACK_HOST,
        "port": unused_port,
        "runner_id": RUNNER_ID,
        "client_id": CLIENT_ID,
        "server_fingerprint": enrollment.metadata["server_fingerprint"],
        "server_instance_id": secrets.token_hex(16),
        "runner_binary_digest": digest,
        "started_at_ns": time.time_ns(),
    }
    record = {
        **unsigned,
        "authentication": process_record_authentication(enrollment, unsigned),
    }
    lifecycle.process_record_path.write_bytes(canonical_json_bytes(record))
    lifecycle.process_record_path.chmod(0o600)

    assert lifecycle.status(profile_id=PROFILE_ID)["state"] == "stale"
    assert lifecycle.stop(profile_id=PROFILE_ID)["state"] == "stopped"
    # The record deliberately named this test process. Stop removed only the
    # stale fixed record and never signalled the PID.
    assert os.getpid() > 0


def test_real_process_boundary_requires_mtls_health_and_graceful_shutdown(
    lifecycle: ManagedRunnerLifecycle,
) -> None:
    _bootstrap(lifecycle)

    ready = lifecycle.start(profile_id=PROFILE_ID)
    assert ready["state"] == "ready"
    assert ready["process"] == "authenticated"
    assert ready["health"]["transport"] == "mutual-tls-loopback"
    assert ready["health"]["tls"] == "TLSv1.3"
    assert ready["health"]["runner_binary_digest"] == ready["runner"]["binary_digest"]

    client, sandbox = lifecycle.client_for_profile(PROFILE_ID)
    server_execution_envelope = max(lifecycle.runner_timeout_seconds + 5.0, 10.0)
    assert client.socket_timeout_seconds == server_execution_envelope + 5.0
    inventory = client.inventory()
    assert inventory["runner_id"] == RUNNER_ID
    assert (
        runner_transport_identity(client, inventory)["runner_binary_digest"]
        == ready["runner"]["binary_digest"]
    )
    assert sandbox.is_dir()
    with pytest.raises(RunnerLifecycleError, match="stopped before enrollment revocation"):
        lifecycle.revoke()

    stopped = lifecycle.stop(profile_id=PROFILE_ID)
    assert stopped["state"] == "stopped"
    assert stopped["process"] == "absent"
    assert lifecycle._owned_processes == {}
    assert lifecycle.ledger_lock_path.exists()

    revoked = lifecycle.revoke()
    assert revoked["enrollment"] == "revoked"
    removed = lifecycle.remove(confirm_runner_id=RUNNER_ID)
    assert removed["state"] == "unbootstrapped"
    assert not lifecycle.ledger_path.exists()
    assert not lifecycle.ledger_lock_path.exists()
    assert not (lifecycle.control_root / ".bluefire-runner-results").exists()

    # A fresh enrollment cannot inherit stale replay rows or durable results.
    assert _bootstrap(lifecycle)["state"] == "stopped"
    assert not lifecycle.ledger_path.exists()


@pytest.mark.skipif(os.name != "nt", reason="recovery interruption uses a Windows process handle")
def test_recovery_interruption_requires_the_exact_retained_process_handle(
    lifecycle: ManagedRunnerLifecycle,
    secret_provider: ProcessTestSecretProvider,
) -> None:
    _bootstrap(lifecycle)
    ready = lifecycle.start(profile_id=PROFILE_ID)
    enrollment = load_local_enrollment(
        lifecycle.enrollment_root,
        secret_provider=secret_provider,
    )
    before = runner_host_module.read_process_record(
        lifecycle.process_record_path,
        enrollment=enrollment,
        expected_binary_digest=str(ready["runner"]["binary_digest"]),
    )
    assert set(lifecycle._owned_processes) == {before["launch_id"]}

    adopted = ManagedRunnerLifecycle(
        lifecycle.root,
        secret_provider=secret_provider,
        bootstrap_factory=_fake_bootstrap,
        host_command_factory=_host_command,
        start_timeout_seconds=10,
        stop_timeout_seconds=10,
        runner_timeout_seconds=2,
    )
    with pytest.raises(RunnerLifecycleError, match="does not own the exact launch"):
        adopted.interrupt_for_recovery(profile_id=PROFILE_ID)
    assert set(lifecycle._owned_processes) == {before["launch_id"]}
    owned = lifecycle._owned_processes[before["launch_id"]]
    assert owned.process_id == before["pid"]
    assert owned.process_handle is not None
    assert owned.launcher.poll() is None

    interrupted = lifecycle.interrupt_for_recovery(profile_id=PROFILE_ID)
    assert interrupted == {
        "profile_id": PROFILE_ID,
        "launch_id": before["launch_id"],
        "process_id": before["pid"],
        "server_instance_id": before["server_instance_id"],
        "identity_bound": True,
        "process_handle_terminated": True,
        "process_absent": True,
    }
    assert lifecycle.status(profile_id=PROFILE_ID)["state"] == "stopped"
    assert lifecycle._owned_processes == {}

    restarted = lifecycle.start(profile_id=PROFILE_ID)
    after = runner_host_module.read_process_record(
        lifecycle.process_record_path,
        enrollment=enrollment,
        expected_binary_digest=str(restarted["runner"]["binary_digest"]),
    )
    assert after["pid"] != before["pid"]
    assert after["launch_id"] != before["launch_id"]
    assert after["server_instance_id"] != before["server_instance_id"]

    assert lifecycle.stop(profile_id=PROFILE_ID)["state"] == "stopped"
    assert lifecycle._owned_processes == {}
    assert lifecycle.revoke()["enrollment"] == "revoked"
    assert lifecycle.remove(confirm_runner_id=RUNNER_ID)["state"] == "unbootstrapped"


def test_remove_preflight(
    lifecycle: ManagedRunnerLifecycle,
) -> None:
    _bootstrap(lifecycle)
    with pytest.raises(RunnerLifecycleError, match="does not match"):
        lifecycle.remove(confirm_runner_id="different-runner.v1")
    with pytest.raises(RunnerLifecycleError, match="must be revoked"):
        lifecycle.remove(confirm_runner_id=RUNNER_ID)
    lifecycle.revoke()

    ledger_generation = _create_test_ledger(
        lifecycle,
        (("execute", "recovery_required", 1),),
    )

    with pytest.raises(RunnerLifecycleError, match="unresolved execution"):
        lifecycle.remove(confirm_runner_id=RUNNER_ID)

    connection = sqlite3.connect(lifecycle.ledger_path)
    try:
        connection.execute(
            """
            UPDATE transport_tasks
            SET state = 'completed', cleanup_required = 0,
                recovery_receipts_json = NULL, result_json = ?
            """,
            (canonical_json_bytes({}),),
        )
        connection.commit()
    finally:
        connection.close()
    receipt_dir = _fake_sandbox(lifecycle) / ".bluefire" / "receipts"
    receipt_dir.mkdir(parents=True)
    (receipt_dir / ("a" * 64 + ".json")).write_text("{}", encoding="utf-8")
    with pytest.raises(RunnerLifecycleError, match="receipt cleanup obligations"):
        lifecycle.remove(confirm_runner_id=RUNNER_ID)
    (receipt_dir / ("a" * 64 + ".json")).unlink()

    enrollment = load_local_enrollment(
        lifecycle.enrollment_root,
        require_active=False,
        secret_provider=lifecycle.secret_provider,
    )
    result_namespace = runner_result_namespace_path(
        lifecycle.ledger_path,
        enrollment,
        ledger_generation=ledger_generation,
    )
    result_root = result_namespace.parent
    watchdog = result_namespace / (".bluefire-watchdog-" + "b" * 64)
    watchdog.mkdir(parents=True)
    (result_namespace / ("c" * 40 + ".json")).write_text("{}", encoding="utf-8")
    (watchdog / "status.json").write_text("{}", encoding="utf-8")

    with pytest.raises(RunnerLifecycleError, match="live watchdog"):
        lifecycle.remove(confirm_runner_id=RUNNER_ID)
    (watchdog / "status.json").unlink()
    watchdog.rmdir()

    assert lifecycle.remove(confirm_runner_id=RUNNER_ID)["state"] == "unbootstrapped"
    assert not lifecycle.ledger_path.exists()
    assert not lifecycle.ledger_lock_path.exists()
    assert not result_root.exists()


def _fake_sandbox(lifecycle: ManagedRunnerLifecycle) -> Path:
    return lifecycle.runtime_root / "sandbox"


_TEST_LEDGER_GENERATION = "d" * 64


def _create_test_ledger(
    lifecycle: ManagedRunnerLifecycle,
    rows: Sequence[tuple[str, str, int]] = (),
) -> str:
    enrollment = load_local_enrollment(
        lifecycle.enrollment_root,
        require_active=False,
        secret_provider=lifecycle.secret_provider,
    )
    binding = runner_transport_module._enrollment_binding(  # noqa: SLF001
        enrollment,
        str(enrollment.metadata["client_fingerprint"]),
    )
    connection = sqlite3.connect(lifecycle.ledger_path)
    try:
        connection.execute(runner_transport_module._LEDGER_METADATA_SQL)  # noqa: SLF001
        connection.execute(
            "INSERT INTO runner_ledger_metadata VALUES (1, ?, ?)",
            ("bluefire.runner-ledger-metadata.v1", _TEST_LEDGER_GENERATION),
        )
        connection.execute(runner_transport_module._TRANSPORT_TASKS_SQL)  # noqa: SLF001
        connection.execute(runner_transport_module._TRANSPORT_TASKS_NONCE_INDEX_SQL)  # noqa: SLF001
        for index, (operation, state_value, cleanup_required) in enumerate(rows):
            request_hash = "sha256:" + f"{index + 1:064x}"
            recovery_receipts = (
                canonical_json_bytes([]) if state_value == "recovery_required" else None
            )
            result = canonical_json_bytes({}) if state_value == "completed" else None
            connection.execute(
                """
                INSERT INTO transport_tasks (
                    task_id, operation, profile_id, request_hash, runner_id, client_id,
                    peer_fingerprint, ca_fingerprint, server_fingerprint,
                    client_fingerprint, enrollment_generation, nonce, state,
                    execute_payload_json, result_json, recovery_receipts_json,
                    cleanup_required, effect_dispatched, error_code, executor_instance,
                    cancellation_requested, created_at, updated_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    runner_transport_module._execute_task_id(request_hash),  # noqa: SLF001
                    operation,
                    PROFILE_ID,
                    request_hash,
                    binding["runner_id"],
                    binding["client_id"],
                    binding["peer_fingerprint"],
                    binding["ca_fingerprint"],
                    binding["server_fingerprint"],
                    binding["client_fingerprint"],
                    binding["enrollment_generation"],
                    f"{index + 101:064x}",
                    state_value,
                    canonical_json_bytes({"request": index}),
                    result,
                    recovery_receipts,
                    cleanup_required,
                    1,
                    None,
                    f"{index + 201:064x}",
                    0,
                    index + 1,
                    index + 1,
                ),
            )
        connection.execute(f"PRAGMA user_version = {LEDGER_SCHEMA_VERSION}")
        connection.commit()
    finally:
        connection.close()
    return _TEST_LEDGER_GENERATION


def test_default_host_command_uses_isolated_installed_module_semantics(tmp_path: Path) -> None:
    spec = RunnerHostSpec(
        enrollment_root=tmp_path / "enrollment",
        runner_binary=Path(sys.executable).resolve(strict=True),
        work_root=tmp_path / "sandbox",
        state_path=tmp_path / "transport.sqlite3",
        process_record_path=tmp_path / "process.json",
        start_gate_path=tmp_path / "start.gate",
        launch_id="a" * 64,
        runner_timeout_seconds=35,
    )

    command = default_host_command(
        enrollment_root=spec.enrollment_root,
        runner_binary=spec.runner_binary,
        work_root=spec.work_root,
        state_path=spec.state_path,
        process_record_path=spec.process_record_path,
        start_gate_path=spec.start_gate_path,
        launch_id=spec.launch_id,
        runner_timeout_seconds=spec.runner_timeout_seconds,
    )

    assert Path(command[0]).is_absolute()
    assert command[1:4] == ("-I", "-m", "bluefire.runner_host")
    assert "--host" not in command
    assert "--port" not in command


def test_public_status_sanitizes_corrupt_bootstrap_state(
    lifecycle: ManagedRunnerLifecycle, tmp_path: Path
) -> None:
    _bootstrap(lifecycle)
    lifecycle.bootstrap_record_path.write_text(
        '{"binary_path":"C:/private/operator/path"}', encoding="utf-8"
    )

    status = lifecycle.status()

    assert status["state"] == "unavailable"
    assert "private/operator" not in json.dumps(status)
    assert str(tmp_path) not in json.dumps(status)


def test_missing_process_record_with_held_or_unsafe_lock_is_never_stopped(
    lifecycle: ManagedRunnerLifecycle,
) -> None:
    _bootstrap(lifecycle)
    lifecycle.ledger_lock_path.write_bytes(b"\0")
    lifecycle.ledger_lock_path.chmod(0o600)

    with _held_lock(lifecycle.ledger_lock_path):
        assert lifecycle.status()["state"] == "unavailable"
        with pytest.raises(RunnerLifecycleError, match="ownership is unavailable"):
            lifecycle.start(profile_id=PROFILE_ID)
        with pytest.raises(RunnerLifecycleError, match="ownership is unavailable"):
            lifecycle.stop(profile_id=PROFILE_ID)

    lifecycle.ledger_lock_path.unlink()
    lifecycle.ledger_lock_path.mkdir()
    assert lifecycle.status()["state"] == "unavailable"
    with pytest.raises(RunnerLifecycleError, match="ownership is unavailable"):
        lifecycle.start(profile_id=PROFILE_ID)
    lifecycle.ledger_lock_path.rmdir()
    assert lifecycle.status()["state"] == "stopped"


@contextmanager
def _held_lock(path: Path) -> Iterator[None]:
    handle: BinaryIO = path.open("r+b", buffering=0)
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def test_bootstrap_rejects_symlinked_managed_ancestor(
    tmp_path: Path, secret_provider: ProcessTestSecretProvider
) -> None:
    actual = tmp_path / "actual"
    alias = tmp_path / "alias"
    actual.mkdir()
    try:
        alias.symlink_to(actual, target_is_directory=True)
    except OSError:
        pytest.skip("Directory symlinks are unavailable on this host")
    manager = ManagedRunnerLifecycle(
        alias / "managed",
        secret_provider=secret_provider,
        bootstrap_factory=_fake_bootstrap,
    )

    with pytest.raises(RunnerLifecycleError, match="unavailable or unsafe"):
        manager.bootstrap(allowed_profile_ids=(PROFILE_ID,))
    assert not (actual / "managed").exists()


def test_trust_removal_failure_preserves_retryable_bootstrap_state(
    tmp_path: Path, secret_provider: ProcessTestSecretProvider
) -> None:
    attempts = 0

    def flaky_removal(*args: Any, **kwargs: Any) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            enrollment = Path(args[0])
            tombstone = enrollment.with_name(f".{enrollment.name}.removing")
            os.rename(enrollment, tombstone)
            (tombstone / "client-cert.pem").unlink()
            raise RunnerTrustError("synthetic test refusal")
        remove_local_enrollment(*args, **kwargs)

    manager = ManagedRunnerLifecycle(
        tmp_path / "retryable",
        secret_provider=secret_provider,
        bootstrap_factory=_fake_bootstrap,
        trust_removal=flaky_removal,
    )
    _bootstrap(manager)
    manager.revoke()

    with pytest.raises(RunnerLifecycleError, match="could not be removed safely"):
        manager.remove(confirm_runner_id=RUNNER_ID)
    assert not manager.enrollment_root.exists()
    assert manager.enrollment_tombstone_root.exists()
    assert manager.bootstrap_record_path.exists()

    assert manager.remove(confirm_runner_id=RUNNER_ID)["state"] == "unbootstrapped"
    assert not manager.enrollment_root.exists()
    assert not manager.bootstrap_record_path.exists()


def test_removal_intent_without_tombstone_is_recovered_and_lock_is_preserved(
    tmp_path: Path,
    secret_provider: ProcessTestSecretProvider,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = ManagedRunnerLifecycle(
        tmp_path / "intent-retry",
        secret_provider=secret_provider,
        bootstrap_factory=_fake_bootstrap,
    )
    _bootstrap(manager)
    manager.revoke()
    original_unlink = runner_trust_module._unlink_transition_file  # noqa: SLF001
    failed = False

    def fail_after_tombstone_cleanup(path: Path) -> None:
        nonlocal failed
        if path == manager.enrollment_removal_intent_path and not failed:
            failed = True
            raise OSError("simulated crash before intent unlink")
        original_unlink(path)

    monkeypatch.setattr(
        runner_trust_module,
        "_unlink_transition_file",
        fail_after_tombstone_cleanup,
    )
    with pytest.raises(RunnerLifecycleError, match="could not be removed safely"):
        manager.remove(confirm_runner_id=RUNNER_ID)

    assert failed
    assert not manager.enrollment_root.exists()
    assert not manager.enrollment_tombstone_root.exists()
    assert manager.enrollment_removal_intent_path.exists()
    assert manager.enrollment_transition_lock_path.exists()
    assert manager.bootstrap_record_path.exists()

    monkeypatch.setattr(runner_trust_module, "_unlink_transition_file", original_unlink)
    assert manager.remove(confirm_runner_id=RUNNER_ID)["state"] == "unbootstrapped"
    assert not manager.enrollment_removal_intent_path.exists()
    assert manager.enrollment_transition_lock_path.exists()
    assert not manager.bootstrap_record_path.exists()


def test_creation_intent_with_published_enrollment_is_recovered_before_probe(
    tmp_path: Path,
    secret_provider: ProcessTestSecretProvider,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probes: list[str] = []

    def counted_probe(**values: Any) -> BootstrappedRunner:
        probes.append("probe")
        return _fake_bootstrap(**values)

    manager = ManagedRunnerLifecycle(
        tmp_path / "creation-intent-retry",
        secret_provider=secret_provider,
        bootstrap_factory=counted_probe,
    )
    original_unlink = runner_trust_module._unlink_transition_file  # noqa: SLF001
    failed = False

    def fail_after_enrollment_publish(path: Path) -> None:
        nonlocal failed
        if path == manager.enrollment_creation_intent_path and not failed:
            failed = True
            raise OSError("simulated crash before creation intent unlink")
        original_unlink(path)

    monkeypatch.setattr(
        runner_trust_module,
        "_unlink_transition_file",
        fail_after_enrollment_publish,
    )
    with pytest.raises(RunnerLifecycleError, match="could not be completed"):
        _bootstrap(manager)
    assert probes == ["probe"]
    assert manager.enrollment_root.exists()
    assert manager.enrollment_creation_intent_path.exists()
    assert not manager.bootstrap_record_path.exists()
    assert manager.status()["state"] == "unavailable"

    monkeypatch.setattr(runner_trust_module, "_unlink_transition_file", original_unlink)
    probes.clear()
    assert _bootstrap(manager)["state"] == "stopped"
    assert probes == ["probe"]
    assert not manager.enrollment_creation_intent_path.exists()
    assert manager.enrollment_transition_lock_path.exists()


def test_removal_deletes_only_the_enrollment_result_namespace(
    lifecycle: ManagedRunnerLifecycle,
    secret_provider: ProcessTestSecretProvider,
) -> None:
    _bootstrap(lifecycle)
    enrollment = load_local_enrollment(
        lifecycle.enrollment_root,
        secret_provider=secret_provider,
    )
    ledger_generation = _create_test_ledger(lifecycle)
    namespace = runner_result_namespace_path(
        lifecycle.ledger_path,
        enrollment,
        ledger_generation=ledger_generation,
    )
    sibling = namespace.with_name("f" * 40)
    namespace.mkdir(parents=True)
    sibling.mkdir()
    (namespace / ("a" * 40 + ".json")).write_text("{}", encoding="utf-8")
    sibling_result = sibling / ("b" * 40 + ".json")
    sibling_result.write_text("{}", encoding="utf-8")

    lifecycle.revoke()
    assert lifecycle.remove(confirm_runner_id=RUNNER_ID)["state"] == "unbootstrapped"

    assert not namespace.exists()
    assert sibling_result.read_text(encoding="utf-8") == "{}"


def test_result_siblings_without_authenticated_ledger_generation_fail_closed(
    lifecycle: ManagedRunnerLifecycle,
    secret_provider: ProcessTestSecretProvider,
) -> None:
    _bootstrap(lifecycle)
    orphan = lifecycle.control_root / ".bluefire-runner-results" / ("e" * 40)
    orphan.mkdir(parents=True)

    with pytest.raises(RunnerLifecycleError, match="no authenticated ledger generation"):
        lifecycle.revoke()
    assert (
        load_local_enrollment(
            lifecycle.enrollment_root,
            secret_provider=secret_provider,
        ).status
        == "active"
    )


@pytest.mark.parametrize("ledger_kind", ["corrupt", "unresolved"])
def test_revocation_preserves_active_trust_when_ledger_is_not_removal_ready(
    lifecycle: ManagedRunnerLifecycle,
    secret_provider: ProcessTestSecretProvider,
    ledger_kind: str,
) -> None:
    _bootstrap(lifecycle)
    if ledger_kind == "corrupt":
        lifecycle.ledger_path.write_bytes(b"not-a-sqlite-ledger")
    else:
        _create_test_ledger(lifecycle, (("execute", "indeterminate", 0),))

    with pytest.raises(RunnerLifecycleError, match="ledger|unresolved execution"):
        lifecycle.revoke()

    active = load_local_enrollment(
        lifecycle.enrollment_root,
        secret_provider=secret_provider,
    )
    assert active.status == "active"


def test_lifecycle_recovers_authenticated_partial_revocation_before_status_use(
    lifecycle: ManagedRunnerLifecycle,
    secret_provider: ProcessTestSecretProvider,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _bootstrap(lifecycle)
    original_write = runner_trust_module._PinnedRegularUpdate.write  # noqa: SLF001
    failed = False

    def interrupt_write(
        target: runner_trust_module._PinnedRegularUpdate,  # noqa: SLF001
        payload: bytes,
    ) -> None:
        nonlocal failed
        if not failed:
            failed = True
            os.lseek(target.descriptor, 0, os.SEEK_SET)
            os.ftruncate(target.descriptor, 0)
            os.write(target.descriptor, payload[:17])
            os.fsync(target.descriptor)
            raise OSError("injected crash during pinned metadata write")
        original_write(target, payload)

    monkeypatch.setattr(runner_trust_module._PinnedRegularUpdate, "write", interrupt_write)
    with pytest.raises(RunnerLifecycleError, match="could not be revoked"):
        lifecycle.revoke()

    assert failed
    assert lifecycle.enrollment_revocation_intent_path.is_file()
    assert lifecycle.status()["state"] == "unavailable"
    with pytest.raises(RunnerLifecycleError, match="unavailable or inactive"):
        lifecycle.start()
    with pytest.raises(RunnerTrustError, match="revocation must be recovered"):
        load_local_enrollment(
            lifecycle.enrollment_root,
            require_active=False,
            secret_provider=secret_provider,
        )

    monkeypatch.setattr(runner_trust_module._PinnedRegularUpdate, "write", original_write)
    assert lifecycle.revoke()["enrollment"] == "revoked"
    assert not lifecycle.enrollment_revocation_intent_path.exists()


def test_timed_out_execution_is_terminal_when_cleanup_is_complete(
    lifecycle: ManagedRunnerLifecycle,
) -> None:
    _bootstrap(lifecycle)
    _create_test_ledger(lifecycle, (("execute", "timed_out", 0),))

    assert lifecycle.revoke()["enrollment"] == "revoked"
    assert lifecycle.remove(confirm_runner_id=RUNNER_ID)["state"] == "unbootstrapped"


def test_revoke_busy(
    lifecycle: ManagedRunnerLifecycle,
    secret_provider: ProcessTestSecretProvider,
) -> None:
    _bootstrap(lifecycle)
    enrollment = load_local_enrollment(
        lifecycle.enrollment_root,
        secret_provider=secret_provider,
    )
    ledger_generation = _create_test_ledger(lifecycle)
    namespace = runner_result_namespace_path(
        lifecycle.ledger_path,
        enrollment,
        ledger_generation=ledger_generation,
    )
    watchdog = namespace / (".bluefire-watchdog-" + "a" * 64)
    watchdog.mkdir(parents=True)
    (watchdog / "status.json").write_text("{}", encoding="utf-8")

    with pytest.raises(RunnerLifecycleError, match="live watchdog"):
        lifecycle.revoke()
    assert (
        load_local_enrollment(lifecycle.enrollment_root, secret_provider=secret_provider).status
        == "active"
    )

    (watchdog / "status.json").unlink()
    watchdog.rmdir()
    receipt = _fake_sandbox(lifecycle) / ".bluefire" / "receipts" / ("b" * 64 + ".json")
    receipt.parent.mkdir(parents=True)
    receipt.write_text("{}", encoding="utf-8")
    with pytest.raises(RunnerLifecycleError, match="receipt cleanup obligations"):
        lifecycle.revoke()
    assert (
        load_local_enrollment(lifecycle.enrollment_root, secret_provider=secret_provider).status
        == "active"
    )


def test_bootstrap_checks_existing_identity_before_native_probe_or_new_trust(
    tmp_path: Path,
    secret_provider: ProcessTestSecretProvider,
) -> None:
    calls: list[str] = []

    def counted_bootstrap(**values: Any) -> BootstrappedRunner:
        calls.append("probe")
        return _fake_bootstrap(**values)

    manager = ManagedRunnerLifecycle(
        tmp_path / "ordered",
        secret_provider=secret_provider,
        bootstrap_factory=counted_bootstrap,
    )
    _bootstrap(manager)
    assert calls == ["probe"]

    with pytest.raises(RunnerLifecycleError, match="does not match"):
        manager.bootstrap(allowed_profile_ids=("different-profile.v1",))
    assert calls == ["probe"]

    manager.revoke()
    with pytest.raises(RunnerLifecycleError, match="could not be completed"):
        manager.bootstrap(allowed_profile_ids=(PROFILE_ID,))
    assert calls == ["probe"]

    def wrong_runner(**values: Any) -> BootstrappedRunner:
        result = _fake_bootstrap(**values)
        return replace(
            result,
            manifest=replace(result.manifest, runner_id="incompatible-runner.v1"),
        )

    incompatible = ManagedRunnerLifecycle(
        tmp_path / "wrong-runner",
        secret_provider=secret_provider,
        bootstrap_factory=wrong_runner,
    )
    with pytest.raises(RunnerLifecycleError, match="identity is incompatible"):
        _bootstrap(incompatible)
    assert not incompatible.enrollment_root.exists()


def test_bootstrap_refuses_unjournaled_complete_enrollment_stage_before_probe(
    tmp_path: Path,
    secret_provider: ProcessTestSecretProvider,
) -> None:
    calls: list[str] = []
    fail_initial = True

    def staged_probe(**values: Any) -> BootstrappedRunner:
        nonlocal fail_initial
        calls.append("probe")
        result = _fake_bootstrap(**values)
        if fail_initial:
            fail_initial = False
            return replace(
                result,
                manifest=replace(result.manifest, runner_id="incompatible-runner.v1"),
            )
        return result

    manager = ManagedRunnerLifecycle(
        tmp_path / "staged-complete",
        secret_provider=secret_provider,
        bootstrap_factory=staged_probe,
    )
    with pytest.raises(RunnerLifecycleError, match="identity is incompatible"):
        _bootstrap(manager)
    create_local_enrollment(
        manager.enrollment_staging_root,
        runner_id=RUNNER_ID,
        client_id=CLIENT_ID,
        allowed_profile_ids=(PROFILE_ID,),
        secret_provider=secret_provider,
    )
    calls.clear()

    assert manager.status()["state"] == "unavailable"
    with pytest.raises(RunnerLifecycleError, match="could not be completed safely"):
        _bootstrap(manager)
    assert calls == []
    assert not manager.enrollment_root.exists()
    assert manager.enrollment_staging_root.exists()


def test_incomplete_enrollment_stage_refuses_before_native_probe(
    tmp_path: Path,
    secret_provider: ProcessTestSecretProvider,
) -> None:
    calls: list[str] = []

    def initial_failure(**values: Any) -> BootstrappedRunner:
        calls.append("probe")
        result = _fake_bootstrap(**values)
        return replace(
            result,
            manifest=replace(result.manifest, runner_id="incompatible-runner.v1"),
        )

    manager = ManagedRunnerLifecycle(
        tmp_path / "staged-partial",
        secret_provider=secret_provider,
        bootstrap_factory=initial_failure,
    )
    with pytest.raises(RunnerLifecycleError):
        _bootstrap(manager)
    manager.enrollment_staging_root.mkdir()
    (manager.enrollment_staging_root / "partial.material").write_bytes(b"partial")
    calls.clear()

    assert manager.status()["state"] == "unavailable"
    with pytest.raises(RunnerLifecycleError, match="could not be completed"):
        _bootstrap(manager)
    assert calls == []


def test_bootstrap_rejects_broad_or_preexisting_unowned_roots_without_mutation(
    tmp_path: Path,
    secret_provider: ProcessTestSecretProvider,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(RunnerLifecycleError, match="configuration is invalid"):
        ManagedRunnerLifecycle(Path(tmp_path.anchor), secret_provider=secret_provider)

    root = tmp_path / "unowned"
    root.mkdir()
    sentinel = root / "sentinel.txt"
    sentinel.write_bytes(b"operator-owned")
    manager = ManagedRunnerLifecycle(
        root,
        secret_provider=secret_provider,
        bootstrap_factory=_fake_bootstrap,
    )
    with pytest.raises(RunnerLifecycleError, match="unavailable or unsafe"):
        _bootstrap(manager)
    assert sentinel.read_bytes() == b"operator-owned"
    assert not manager.root_marker_path.exists()

    def unavailable_home() -> Path:
        raise RuntimeError("home directory is intentionally unavailable")

    monkeypatch.setattr(runner_lifecycle_module.Path, "home", unavailable_home)
    isolated = ManagedRunnerLifecycle(
        tmp_path / "no-home",
        secret_provider=secret_provider,
    )
    assert isolated.root == tmp_path / "no-home"


def test_operation_lock_path_replacement_cannot_split_serialization(
    lifecycle: ManagedRunnerLifecycle,
) -> None:
    _bootstrap(lifecycle)
    handle, identity = runner_lifecycle_module._open_private_lock_file(  # noqa: SLF001
        lifecycle.operation_lock_path
    )
    replacement = lifecycle.operation_lock_path.with_name("replacement.lock")
    replacement.write_bytes(b"\0")
    replacement.chmod(0o600)
    try:
        try:
            os.replace(replacement, lifecycle.operation_lock_path)
        except OSError:
            runner_lifecycle_module._lock_file(  # noqa: SLF001
                handle,
                path=lifecycle.operation_lock_path,
                expected_identity=identity,
                timeout_seconds=0.5,
            )
            runner_lifecycle_module._unlock_file(handle)  # noqa: SLF001
        else:
            with pytest.raises(RunnerLifecycleError, match="lock changed"):
                runner_lifecycle_module._lock_file(  # noqa: SLF001
                    handle,
                    path=lifecycle.operation_lock_path,
                    expected_identity=identity,
                    timeout_seconds=0.5,
                )
    finally:
        handle.close()


def test_revoke_and_remove_do_not_require_live_binary_or_sandbox(
    tmp_path: Path,
    secret_provider: ProcessTestSecretProvider,
) -> None:
    def disposable_bootstrap(**values: Any) -> BootstrappedRunner:
        result = _fake_bootstrap(**values)
        binary = Path(values["managed_root"]) / "runner-copy.bin"
        binary.write_bytes(Path(sys.executable).read_bytes())
        digest = file_hash(binary).removeprefix("sha256:")
        return replace(
            result,
            binary_path=binary.resolve(strict=True),
            binary_sha256=digest,
            managed_binary=True,
            manifest=replace(
                result.manifest,
                filename=binary.name,
                size=binary.stat().st_size,
                sha256=digest,
            ),
        )

    manager = ManagedRunnerLifecycle(
        tmp_path / "disposable",
        secret_provider=secret_provider,
        bootstrap_factory=disposable_bootstrap,
    )
    _bootstrap(manager)
    (manager.runtime_root / "runner-copy.bin").unlink()
    (manager.runtime_root / "sandbox").rmdir()
    manager.runtime_root.rmdir()

    assert manager.revoke()["enrollment"] == "revoked"
    assert manager.remove(confirm_runner_id=RUNNER_ID)["state"] == "unbootstrapped"


@pytest.mark.parametrize("quarantine", ["missing", "changed"])
def test_stop_uses_exact_instance_when_live_runner_binary_is_quarantined(
    tmp_path: Path,
    secret_provider: ProcessTestSecretProvider,
    quarantine: str,
) -> None:
    def disposable_bootstrap(**values: Any) -> BootstrappedRunner:
        result = _fake_bootstrap(**values)
        binary = Path(values["managed_root"]) / "live-runner-copy.bin"
        binary.write_bytes(Path(sys.executable).read_bytes())
        digest = file_hash(binary).removeprefix("sha256:")
        return replace(
            result,
            binary_path=binary.resolve(strict=True),
            binary_sha256=digest,
            managed_binary=True,
            manifest=replace(
                result.manifest,
                filename=binary.name,
                size=binary.stat().st_size,
                sha256=digest,
            ),
        )

    manager = ManagedRunnerLifecycle(
        tmp_path / f"stop-{quarantine}",
        secret_provider=secret_provider,
        bootstrap_factory=disposable_bootstrap,
        host_command_factory=_host_command,
        start_timeout_seconds=10,
        stop_timeout_seconds=10,
        runner_timeout_seconds=2,
    )
    _bootstrap(manager)
    assert manager.start(profile_id=PROFILE_ID)["state"] == "ready"
    binary = manager.runtime_root / "live-runner-copy.bin"
    if quarantine == "missing":
        binary.unlink()
    else:
        binary.write_bytes(b"quarantined")

    stopped = manager.stop(profile_id=PROFILE_ID)
    assert stopped["process"] in {"absent", "unavailable"}
    assert not manager.process_record_path.exists()
    assert manager.status()["process"] != "authenticated"


def test_post_bootstrap_sandbox_link_swap_is_rejected_before_revocation(
    lifecycle: ManagedRunnerLifecycle,
    secret_provider: ProcessTestSecretProvider,
    tmp_path: Path,
) -> None:
    _bootstrap(lifecycle)
    sandbox = _fake_sandbox(lifecycle)
    original = sandbox.with_name("sandbox-original")
    outside = tmp_path / "outside"
    outside.mkdir()
    sandbox.rename(original)
    try:
        sandbox.symlink_to(outside, target_is_directory=True)
    except OSError:
        original.rename(sandbox)
        pytest.skip("Directory symlinks are unavailable on this host")
    try:
        with pytest.raises(RunnerLifecycleError, match="bootstrap state is unavailable"):
            lifecycle.revoke()
        assert (
            load_local_enrollment(lifecycle.enrollment_root, secret_provider=secret_provider).status
            == "active"
        )
    finally:
        sandbox.unlink()
        original.rename(sandbox)


def test_replacement_bootstrap_requires_explicit_clean_upgrade_and_same_sandbox(
    tmp_path: Path,
    secret_provider: ProcessTestSecretProvider,
) -> None:
    version = "1.0.0"
    alternate = tmp_path / "alternate-sandbox"
    alternate.mkdir()
    use_alternate = False

    def versioned_bootstrap(**values: Any) -> BootstrappedRunner:
        result = _fake_bootstrap(**values)
        return replace(
            result,
            sandbox_path=(alternate.resolve(strict=True) if use_alternate else result.sandbox_path),
            managed_sandbox=not use_alternate,
            manifest=replace(result.manifest, runner_version=version),
        )

    manager = ManagedRunnerLifecycle(
        tmp_path / "upgrade",
        secret_provider=secret_provider,
        bootstrap_factory=versioned_bootstrap,
    )
    _bootstrap(manager)
    version = "2.0.0"
    with pytest.raises(RunnerLifecycleError, match="explicit clean upgrade"):
        _bootstrap(manager)

    _create_test_ledger(manager, (("execute", "completed", 0),))
    with pytest.raises(RunnerLifecycleError, match="prior execution"):
        manager.bootstrap(allowed_profile_ids=(PROFILE_ID,), allow_upgrade=True)
    manager.ledger_path.unlink()

    use_alternate = True
    with pytest.raises(RunnerLifecycleError, match="cannot abandon"):
        manager.bootstrap(allowed_profile_ids=(PROFILE_ID,), allow_upgrade=True)
    use_alternate = False
    assert (
        manager.bootstrap(allowed_profile_ids=(PROFILE_ID,), allow_upgrade=True)["runner"][
            "runner_version"
        ]
        == "2.0.0"
    )


@pytest.mark.parametrize("independent_instance", [False, True])
def test_start_start_is_serialized_to_one_host_launch(
    tmp_path: Path,
    secret_provider: ProcessTestSecretProvider,
    independent_instance: bool,
) -> None:
    launches: list[str] = []

    def counted_host(spec: RunnerHostSpec) -> Sequence[str]:
        launches.append(spec.launch_id)
        return _host_command(spec)

    root = tmp_path / "serialized-start"
    first = ManagedRunnerLifecycle(
        root,
        secret_provider=secret_provider,
        bootstrap_factory=_fake_bootstrap,
        host_command_factory=counted_host,
        start_timeout_seconds=10,
        stop_timeout_seconds=10,
        runner_timeout_seconds=2,
    )
    second = (
        ManagedRunnerLifecycle(
            root,
            secret_provider=secret_provider,
            bootstrap_factory=_fake_bootstrap,
            host_command_factory=counted_host,
            start_timeout_seconds=10,
            stop_timeout_seconds=10,
            runner_timeout_seconds=2,
        )
        if independent_instance
        else first
    )
    _bootstrap(first)
    barrier = threading.Barrier(3)

    def start(manager: ManagedRunnerLifecycle) -> Mapping[str, Any]:
        barrier.wait(timeout=10)
        return manager.start(profile_id=PROFILE_ID)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(start, first), pool.submit(start, second)]
        barrier.wait(timeout=10)
        states = [future.result(timeout=120)["state"] for future in futures]
    try:
        assert states == ["ready", "ready"]
        assert len(launches) == 1
    finally:
        first.stop(profile_id=PROFILE_ID)


@pytest.mark.parametrize("independent_instance", [False, True])
def test_bootstrap_start_barrier_serializes_storage_and_launch(
    tmp_path: Path,
    secret_provider: ProcessTestSecretProvider,
    independent_instance: bool,
) -> None:
    entered = threading.Event()
    release = threading.Event()

    def blocked_bootstrap(**values: Any) -> BootstrappedRunner:
        entered.set()
        if not release.wait(timeout=20):
            raise RuntimeError("test barrier timed out")
        return _fake_bootstrap(**values)

    root = tmp_path / "serialized-bootstrap"
    first = ManagedRunnerLifecycle(
        root,
        secret_provider=secret_provider,
        bootstrap_factory=blocked_bootstrap,
        host_command_factory=_host_command,
        start_timeout_seconds=10,
        stop_timeout_seconds=10,
        runner_timeout_seconds=2,
    )
    second = (
        ManagedRunnerLifecycle(
            root,
            secret_provider=secret_provider,
            bootstrap_factory=_fake_bootstrap,
            host_command_factory=_host_command,
            start_timeout_seconds=10,
            stop_timeout_seconds=10,
            runner_timeout_seconds=2,
        )
        if independent_instance
        else first
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        bootstrapped = pool.submit(_bootstrap, first)
        assert entered.wait(timeout=10)
        started = pool.submit(second.start, profile_id=PROFILE_ID)
        time.sleep(0.1)
        assert not started.done()
        release.set()
        assert bootstrapped.result(timeout=120)["state"] == "stopped"
        assert started.result(timeout=120)["state"] == "ready"
    first.stop(profile_id=PROFILE_ID)


def test_failed_start_terminates_the_exact_host_process_tree(
    tmp_path: Path,
    secret_provider: ProcessTestSecretProvider,
) -> None:
    descendant_pid = tmp_path / "descendant.pid"

    def hanging_host(spec: RunnerHostSpec) -> Sequence[str]:
        return (
            str(Path(sys.executable).resolve(strict=True)),
            "-m",
            "tests_platform.runner_lifecycle_host_helper",
            "descendant-hang",
            str(spec.start_gate_path),
            str(descendant_pid),
        )

    manager = ManagedRunnerLifecycle(
        tmp_path / "failed-tree",
        secret_provider=secret_provider,
        bootstrap_factory=_fake_bootstrap,
        host_command_factory=hanging_host,
        start_timeout_seconds=2,
    )
    _bootstrap(manager)

    with pytest.raises(RunnerLifecycleError, match="authenticated readiness"):
        manager.start(profile_id=PROFILE_ID)

    assert descendant_pid.exists()
    pid = int(descendant_pid.read_text(encoding="ascii"))
    assert not _process_is_alive(pid)
    assert not manager.process_record_path.exists()
    assert not manager.ledger_lock_path.exists()


def _process_is_alive(pid: int) -> bool:
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
    import ctypes

    synchronize = 0x00100000
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)  # type: ignore[attr-defined]
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    handle = kernel32.OpenProcess(synchronize, 0, pid)
    if not handle:
        return False
    try:
        return kernel32.WaitForSingleObject(ctypes.c_void_p(handle), 0) == 0x00000102
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(handle))


def test_stop_sanitizes_active_tasks_and_reports_draining_unavailable(
    lifecycle: ManagedRunnerLifecycle,
    secret_provider: ProcessTestSecretProvider,
) -> None:
    _bootstrap(lifecycle)
    enrollment = load_local_enrollment(
        lifecycle.enrollment_root,
        secret_provider=secret_provider,
    )
    digest = str(lifecycle.status()["runner"]["binary_digest"])
    unsigned = {
        "schema_version": PROCESS_RECORD_SCHEMA_VERSION,
        "launch_id": secrets.token_hex(32),
        "pid": os.getpid(),
        "host": LOOPBACK_HOST,
        "port": 1,
        "runner_id": RUNNER_ID,
        "client_id": CLIENT_ID,
        "server_fingerprint": enrollment.metadata["server_fingerprint"],
        "server_instance_id": secrets.token_hex(16),
        "runner_binary_digest": digest,
        "started_at_ns": time.time_ns(),
    }
    record = {
        **unsigned,
        "authentication": process_record_authentication(enrollment, unsigned),
    }
    lifecycle.process_record_path.write_bytes(canonical_json_bytes(record))
    lifecycle.process_record_path.chmod(0o600)

    class DrainingClient:
        def health(self) -> Mapping[str, Any]:
            return {
                "schema_version": "bluefire.runner-health.v1",
                "status": "ready",
                "runner_id": RUNNER_ID,
                "profile_id": PROFILE_ID,
                "transport": "mutual-tls-loopback",
                "tls": "TLSv1.3",
                "server_fingerprint": enrollment.metadata["server_fingerprint"],
                "client_fingerprint": enrollment.metadata["client_fingerprint"],
                "authenticated_peer_fingerprint": enrollment.metadata["client_fingerprint"],
                "runner_binary_digest": digest,
                "server_instance_id": record["server_instance_id"],
                "ledger": {"accepting_execute": False},
            }

        def shutdown(self, server_instance_id: str | None = None) -> None:
            assert server_instance_id == record["server_instance_id"]
            raise RunnerRemoteError("active_tasks")

    lifecycle.client_factory = lambda *args, **kwargs: DrainingClient()  # type: ignore[assignment]
    assert lifecycle.status(profile_id=PROFILE_ID)["state"] == "unavailable"
    with pytest.raises(RunnerLifecycleError, match="draining active tasks"):
        lifecycle.stop(profile_id=PROFILE_ID)


def test_runner_host_shutdown_finally_cleans_record_and_sanitizes_server_failure(
    lifecycle: ManagedRunnerLifecycle,
    secret_provider: ProcessTestSecretProvider,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _bootstrap(lifecycle)
    shutdowns: list[str] = []

    class FailingServer:
        server_address = (LOOPBACK_HOST, 43123)
        instance_id = "a" * 32

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def serve_forever(self) -> None:
            raise ValueError("private implementation detail")

        def shutdown(self) -> None:
            shutdowns.append("shutdown")

    monkeypatch.setattr(runner_host_module, "AuthenticatedRunnerServer", FailingServer)
    binary = Path(sys.executable).resolve(strict=True)
    with pytest.raises(RunnerHostError, match="could not be initialized or served") as exc:
        runner_host_module.serve_managed_runner(
            enrollment_root=lifecycle.enrollment_root,
            runner_binary=binary,
            work_root=_fake_sandbox(lifecycle),
            state_path=lifecycle.ledger_path,
            process_record_path=lifecycle.process_record_path,
            launch_id="b" * 64,
            secret_provider=secret_provider,
            runner=ProcessFixtureRunner(binary, current_platform()),
        )
    assert "private implementation detail" not in str(exc.value)
    assert shutdowns == ["shutdown"]
    assert not lifecycle.process_record_path.exists()


def test_exact_file_deletion_never_unlinks_a_racing_victim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "owned.json"
    target.write_bytes(b"owned")
    victim = tmp_path / "victim.json"
    victim.write_bytes(b"victim-must-survive")
    replacement = tmp_path / "replacement.json"
    os.link(victim, replacement)
    victim_identity = (victim.stat().st_dev, victim.stat().st_ino)
    race: list[str] = []

    if os.name == "nt":
        original_owner_private = (  # noqa: SLF001
            runner_lifecycle_module._owner_private_native_handle
        )

        def racing_owner_private(handle: int, *, directory: bool) -> None:
            if not directory and not race:
                try:
                    os.replace(replacement, target)
                except OSError:
                    race.append("blocked")
                else:  # pragma: no cover - a broken Windows pin reaches this branch
                    race.append("replaced")
            original_owner_private(handle, directory=directory)

        monkeypatch.setattr(
            runner_lifecycle_module,
            "_owner_private_native_handle",
            racing_owner_private,
        )
        runner_lifecycle_module._unlink_exact_regular(target)  # noqa: SLF001
        assert race == ["blocked"]
        assert not target.exists()
        assert replacement.exists()
    else:
        original_fchmod = os.fchmod

        def racing_fchmod(descriptor: int, mode: int) -> None:
            opened = os.fstat(descriptor)
            if not race and stat.S_ISREG(opened.st_mode):
                os.replace(replacement, target)
                race.append("replaced")
            original_fchmod(descriptor, mode)

        monkeypatch.setattr(runner_lifecycle_module.os, "fchmod", racing_fchmod)
        with pytest.raises(OSError, match="changed"):
            runner_lifecycle_module._unlink_exact_regular(target)  # noqa: SLF001
        assert race == ["replaced"]
        assert target.read_bytes() == b"victim-must-survive"

    assert victim.read_bytes() == b"victim-must-survive"
    assert (victim.stat().st_dev, victim.stat().st_ino) == victim_identity


def test_result_namespace_deletion_never_unlinks_a_racing_victim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "results"
    namespace = parent / ("a" * 40)
    namespace.mkdir(parents=True)
    result = namespace / ("b" * 40 + ".json")
    result.write_bytes(b"owned-result")
    victim = tmp_path / "result-victim.json"
    victim.write_bytes(b"victim-result")
    replacement = tmp_path / "result-replacement.json"
    os.link(victim, replacement)
    victim_identity = (victim.stat().st_dev, victim.stat().st_ino)
    race: list[str] = []

    if os.name == "nt":
        original_owner_private = (  # noqa: SLF001
            runner_lifecycle_module._owner_private_native_handle
        )

        def racing_owner_private(handle: int, *, directory: bool) -> None:
            if not directory and not race:
                try:
                    os.replace(replacement, result)
                except OSError:
                    race.append("blocked")
                else:  # pragma: no cover - a broken Windows pin reaches this branch
                    race.append("replaced")
            original_owner_private(handle, directory=directory)

        monkeypatch.setattr(
            runner_lifecycle_module,
            "_owner_private_native_handle",
            racing_owner_private,
        )
        runner_lifecycle_module._remove_result_namespace(  # noqa: SLF001
            namespace,
            expected_parent=parent,
        )
        assert race == ["blocked"]
        assert not namespace.exists()
        assert replacement.exists()
    else:
        original_fchmod = os.fchmod

        def racing_fchmod(descriptor: int, mode: int) -> None:
            opened = os.fstat(descriptor)
            if not race and stat.S_ISREG(opened.st_mode):
                os.replace(replacement, result)
                race.append("replaced")
            original_fchmod(descriptor, mode)

        monkeypatch.setattr(runner_lifecycle_module.os, "fchmod", racing_fchmod)
        with pytest.raises(OSError, match="changed"):
            runner_lifecycle_module._remove_result_namespace(  # noqa: SLF001
                namespace,
                expected_parent=parent,
            )
        assert race == ["replaced"]
        assert result.read_bytes() == b"victim-result"

    assert victim.read_bytes() == b"victim-result"
    assert (victim.stat().st_dev, victim.stat().st_ino) == victim_identity


def test_host_record_cleanup_never_unlinks_a_racing_foreign_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launch_id = "a" * 64
    record = tmp_path / "process.json"
    record.write_bytes(canonical_json_bytes({"launch_id": launch_id}))
    victim = tmp_path / "foreign-process.json"
    victim_payload = canonical_json_bytes({"launch_id": "b" * 64})
    victim.write_bytes(victim_payload)
    replacement = tmp_path / "foreign-replacement.json"
    os.link(victim, replacement)
    victim_identity = (victim.stat().st_dev, victim.stat().st_ino)
    race: list[str] = []

    if os.name == "nt":
        original_owner_private = runner_host_module._owner_private_native_handle  # noqa: SLF001

        def racing_owner_private(handle: int, *, directory: bool) -> None:
            if not directory and not race:
                try:
                    os.replace(replacement, record)
                except OSError:
                    race.append("blocked")
                else:  # pragma: no cover - a broken Windows pin reaches this branch
                    race.append("replaced")
            original_owner_private(handle, directory=directory)

        monkeypatch.setattr(
            runner_host_module,
            "_owner_private_native_handle",
            racing_owner_private,
        )
        runner_host_module._remove_owned_process_record(record, launch_id)  # noqa: SLF001
        assert race == ["blocked"]
        assert not record.exists()
        assert replacement.exists()
    else:
        original_fchmod = os.fchmod

        def racing_fchmod(descriptor: int, mode: int) -> None:
            opened = os.fstat(descriptor)
            if not race and stat.S_ISREG(opened.st_mode):
                os.replace(replacement, record)
                race.append("replaced")
            original_fchmod(descriptor, mode)

        monkeypatch.setattr(runner_host_module.os, "fchmod", racing_fchmod)
        runner_host_module._remove_owned_process_record(record, launch_id)  # noqa: SLF001
        assert race == ["replaced"]
        assert record.read_bytes() == victim_payload

    assert victim.read_bytes() == victim_payload
    assert (victim.stat().st_dev, victim.stat().st_ino) == victim_identity


def test_process_record_temp_swap_preserves_victim_content_and_acl_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = tmp_path / "process.json"
    owner_payload = {"launch_id": "c" * 64}
    victim = tmp_path / "temp-victim.json"
    victim_payload = canonical_json_bytes({"launch_id": "d" * 64})
    victim.write_bytes(victim_payload)
    replacement = tmp_path / "temp-victim-replacement.json"
    os.link(victim, replacement)
    victim_identity = (victim.stat().st_dev, victim.stat().st_ino)
    victim_mode = stat.S_IMODE(victim.stat().st_mode)
    hardened: list[tuple[int, int]] = []
    swapped: list[Path] = []

    if os.name == "nt":
        original_owner_private = runner_host_module._owner_private_native_handle  # noqa: SLF001

        def recording_owner_private(handle: int, *, directory: bool) -> None:
            details = runner_host_module._windows_handle_details(handle)  # noqa: SLF001
            hardened.append((details[2], (details[3] << 32) | details[4]))
            original_owner_private(handle, directory=directory)

        monkeypatch.setattr(
            runner_host_module,
            "_owner_private_native_handle",
            recording_owner_private,
        )
        original_open = runner_host_module._windows_open_pinned_path  # noqa: SLF001

        def racing_open(
            path: Path,
            *,
            directory: bool,
            delete_access: bool,
            share_delete: bool,
            read_data: bool = False,
            share_write: bool = True,
            write_dac: bool = False,
        ) -> tuple[int, tuple[int, int, int, int, int, int]]:
            if path.name.startswith(".process.json.") and delete_access and not swapped:
                os.replace(replacement, path)
                swapped.append(path)
            return original_open(
                path,
                directory=directory,
                delete_access=delete_access,
                share_delete=share_delete,
                read_data=read_data,
                share_write=share_write,
                write_dac=write_dac,
            )

        monkeypatch.setattr(runner_host_module, "_windows_open_pinned_path", racing_open)
    else:
        original_link = os.link

        def racing_link(
            source: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            destination: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            **kwargs: Any,
        ) -> None:
            temporary = next(tmp_path.glob(".process.json.*.tmp"))
            if not swapped:
                os.replace(replacement, temporary)
                swapped.append(temporary)
            original_link(source, destination, **kwargs)

        monkeypatch.setattr(runner_host_module.os, "link", racing_link)

    with pytest.raises(RunnerHostError, match="could not be published"):
        runner_host_module._write_process_record(record, owner_payload)  # noqa: SLF001

    assert len(swapped) == 1
    assert victim.read_bytes() == victim_payload
    assert (victim.stat().st_dev, victim.stat().st_ino) == victim_identity
    assert stat.S_IMODE(victim.stat().st_mode) == victim_mode
    assert victim_identity not in hardened
    surviving_aliases = [candidate for candidate in (record, swapped[0]) if candidate.exists()]
    assert surviving_aliases
    assert all(candidate.read_bytes() == victim_payload for candidate in surviving_aliases)


@pytest.mark.skipif(os.name == "nt", reason="descriptor-relative POSIX publication")
def test_process_record_publication_never_replaces_a_racing_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = tmp_path / "process.json"
    victim = tmp_path / "victim.json"
    victim_payload = canonical_json_bytes({"victim": True})
    victim.write_bytes(victim_payload)
    replacement = tmp_path / "victim-replacement.json"
    os.link(victim, replacement)
    victim_identity = (victim.stat().st_dev, victim.stat().st_ino)
    original_link = os.link
    raced = False

    def racing_link(
        source: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        destination: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        **kwargs: Any,
    ) -> None:
        nonlocal raced
        if not raced:
            replacement.replace(record)
            raced = True
        original_link(source, destination, **kwargs)

    monkeypatch.setattr(runner_host_module.os, "link", racing_link)

    with pytest.raises(RunnerHostError, match="could not be published"):
        runner_host_module._write_process_record(  # noqa: SLF001
            record,
            {"launch_id": "e" * 64},
        )

    assert raced is True
    assert record.read_bytes() == victim_payload
    assert record.samefile(victim)
    assert victim.read_bytes() == victim_payload
    assert (victim.stat().st_dev, victim.stat().st_ino) == victim_identity


def test_lifecycle_state_temp_swap_preserves_victim_content_and_acl_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = tmp_path / "state.bin"
    victim = tmp_path / "state-victim.bin"
    victim_payload = b"state-victim-must-survive"
    victim.write_bytes(victim_payload)
    replacement = tmp_path / "state-victim-replacement.bin"
    os.link(victim, replacement)
    victim_identity = (victim.stat().st_dev, victim.stat().st_ino)
    victim_mode = stat.S_IMODE(victim.stat().st_mode)
    hardened: list[tuple[int, int]] = []
    swapped: list[Path] = []

    if os.name == "nt":
        original_owner_private = (  # noqa: SLF001
            runner_lifecycle_module._owner_private_native_handle
        )

        def recording_owner_private(handle: int, *, directory: bool) -> None:
            details = runner_lifecycle_module._windows_handle_details(handle)  # noqa: SLF001
            hardened.append((details[2], (details[3] << 32) | details[4]))
            original_owner_private(handle, directory=directory)

        monkeypatch.setattr(
            runner_lifecycle_module,
            "_owner_private_native_handle",
            recording_owner_private,
        )
        original_open = runner_lifecycle_module._windows_open_pinned_path  # noqa: SLF001

        def racing_open(
            path: Path,
            *,
            directory: bool,
            delete_access: bool = True,
            share_delete: bool = False,
            write_dac: bool = False,
        ) -> tuple[int, tuple[int, ...]]:
            if path.name.startswith(".bfstate-") and delete_access and not swapped:
                os.replace(replacement, path)
                swapped.append(path)
            return original_open(
                path,
                directory=directory,
                delete_access=delete_access,
                share_delete=share_delete,
                write_dac=write_dac,
            )

        monkeypatch.setattr(runner_lifecycle_module, "_windows_open_pinned_path", racing_open)
    else:
        original_link = os.link
        original_replace = os.replace

        def racing_link(
            source: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            destination: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            **kwargs: Any,
        ) -> None:
            temporary = next(tmp_path.glob(".bfstate-*.tmp"))
            if not swapped:
                original_replace(replacement, temporary)
                swapped.append(temporary)
            original_link(source, destination, **kwargs)

        monkeypatch.setattr(runner_lifecycle_module.os, "link", racing_link)

    with pytest.raises(RunnerLifecycleError, match="persisted safely"):
        runner_lifecycle_module._write_private_bytes(  # noqa: SLF001
            state_path,
            b"owned-state",
            replace=False,
        )

    assert len(swapped) == 1
    assert victim.read_bytes() == victim_payload
    assert (victim.stat().st_dev, victim.stat().st_ino) == victim_identity
    assert stat.S_IMODE(victim.stat().st_mode) == victim_mode
    assert victim_identity not in hardened
    surviving_aliases = [candidate for candidate in (state_path, swapped[0]) if candidate.exists()]
    assert surviving_aliases
    assert all(candidate.read_bytes() == victim_payload for candidate in surviving_aliases)


def test_lifecycle_private_publication_uses_a_fixed_short_temporary_basename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / ("destination-" + ("x" * 80) + ".json")
    temporary_names: list[str] = []
    publisher_name = (
        "_windows_publish_private_payload" if os.name == "nt" else "_posix_publish_private_payload"
    )
    original_publisher = getattr(runner_lifecycle_module, publisher_name)

    def recording_publisher(path: Path, temporary: Path, *args: Any) -> None:
        temporary_names.append(temporary.name)
        original_publisher(path, temporary, *args)

    monkeypatch.setattr(runner_lifecycle_module, publisher_name, recording_publisher)

    runner_lifecycle_module._write_private_bytes(  # noqa: SLF001
        destination,
        b"owned-state",
        replace=False,
    )

    assert destination.read_bytes() == b"owned-state"
    assert len(temporary_names) == 1
    temporary = temporary_names[0]
    assert temporary.startswith(".bfstate-")
    assert temporary.endswith(".tmp")
    assert len(temporary) == 45
    assert all(character in "0123456789abcdef" for character in temporary[9:-4])
    assert "destination" not in temporary
