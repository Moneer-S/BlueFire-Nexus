from __future__ import annotations

import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest

import bluefire.runner_transport as wire
from bluefire.runner_client import canonical_runner_inventory
from bluefire.runner_inventory import (
    BUILTIN_RUNNER_ACTION_VERSIONS,
    RUNNER_ACTION_SDK_SCHEMA_VERSION,
)
from bluefire.runner_transport import (
    AuthenticatedRunnerClient,
    AuthenticatedRunnerServer,
    AuthenticatedRunnerTransportError,
    RunnerConnectionError,
    RunnerRemoteError,
    audit_runner_ledger,
    read_runner_ledger_generation,
)
from bluefire.runner_transport_client import (
    validated_recovered_cancellation_proof,
    validated_recovery_required_payload,
)
from bluefire.runner_transport_errors import (
    RunnerAuthenticationError,
    validated_cancellation_proof,
)
from bluefire.runner_trust import create_local_enrollment, load_local_enrollment
from bluefire.secret_store import InMemorySecretProvider
from bluefire.util import canonical_json_bytes, content_hash

_PROFILE_ID = "sandbox-execute.v1"
_RUNNER_ID = "bluefire-rust-runner.v1"
_CLIENT_ID = "bluefire-control-plane.v1"
_V4_GENERATION = "ab" * 32

# Frozen v4 schema: these literals verify migration from the exact prior schema,
# rather than generating a legacy fixture from the current schema definition.
_V4_METADATA_SQL = """CREATE TABLE runner_ledger_metadata (
    singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    schema_version TEXT NOT NULL CHECK (
        schema_version = 'bluefire.runner-ledger-metadata.v1'
    ),
    ledger_generation TEXT NOT NULL UNIQUE CHECK (
        length(ledger_generation) = 64
        AND ledger_generation NOT GLOB '*[^0-9a-f]*'
    )
) WITHOUT ROWID"""
_V4_TASKS_SQL = """CREATE TABLE transport_tasks (
    task_id TEXT PRIMARY KEY,
    operation TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    runner_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    peer_fingerprint TEXT NOT NULL,
    ca_fingerprint TEXT NOT NULL,
    server_fingerprint TEXT NOT NULL,
    client_fingerprint TEXT NOT NULL,
    enrollment_generation TEXT NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL,
    execute_payload_json BLOB,
    result_json BLOB,
    recovery_receipts_json BLOB,
    cleanup_required INTEGER NOT NULL DEFAULT 0,
    effect_dispatched INTEGER NOT NULL DEFAULT 0,
    error_code TEXT,
    executor_instance TEXT NOT NULL,
    cancellation_requested INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
)"""


class _InventoryOnlyRunner:
    def inventory(self) -> dict[str, Any]:
        return canonical_runner_inventory(
            {
                "schema_version": "bluefire.runner-inventory.v1",
                "runner_id": _RUNNER_ID,
                "runner_version": "0.1.0",
                "action_sdk_version": RUNNER_ACTION_SDK_SCHEMA_VERSION,
                "receipt_protocol": "bluefire.runner-receipt-wal.v2",
                "platform": "windows",
                "actions": [
                    {
                        "schema_version": RUNNER_ACTION_SDK_SCHEMA_VERSION,
                        "action_id": "sandbox.fixture.create.v1",
                        "action_version": BUILTIN_RUNNER_ACTION_VERSIONS[
                            "sandbox.fixture.create.v1"
                        ],
                        "readiness": "ready",
                    }
                ],
            }
        )


@pytest.fixture
def legacy_ledger(tmp_path: Path) -> tuple[Path, Path, InMemorySecretProvider]:
    root = tmp_path / "trust"
    secret_provider = InMemorySecretProvider()
    create_local_enrollment(
        root,
        runner_id=_RUNNER_ID,
        client_id=_CLIENT_ID,
        allowed_profile_ids=[_PROFILE_ID],
        secret_provider=secret_provider,
    )
    enrollment = load_local_enrollment(root, secret_provider=secret_provider)
    state_path = tmp_path / "transport.sqlite3"
    binding = wire._enrollment_binding(enrollment, str(enrollment.metadata["client_fingerprint"]))
    sandbox = tmp_path / "legacy-sandbox"
    sandbox.mkdir()
    manifest = {
        "schema_version": "bluefire.runner-manifest.v1",
        "request_id": "legacy-request",
        "request_hash": "sha256:" + "5" * 64,
        "run_id": "legacy-run",
        "step_id": "legacy-step",
        "behavior_id": "sandbox.fixture.create.v1",
        "action_id": "sandbox.fixture.create.v1",
        "runner_id": _RUNNER_ID,
        "runner_profile_id": _PROFILE_ID,
        "platform": "windows",
        "policy_digest": "sha256:" + "6" * 64,
        "limits": {"max_artifact_bytes": 1024, "max_files": 8},
    }
    profile = {
        "schema_version": "bluefire.runner-profile.v1",
        "profile_id": _PROFILE_ID,
        "runner_id": _RUNNER_ID,
        "platform": "windows",
        "sandbox_root": str(sandbox.resolve(strict=True)),
        "policy_digest": manifest["policy_digest"],
        "limits": {"max_artifact_bytes": 1024, "max_files": 8},
    }
    execute_payload = {"manifest": manifest, "profile": profile}
    execute_payload_json = canonical_json_bytes(execute_payload)
    execute_request_hash = content_hash(execute_payload)
    execute_task_id = wire._execute_task_id(execute_request_hash)
    execute_nonce = "7" * 64
    execute_instance = "instance-" + "8" * 32
    health_timestamp = time.time_ns()
    with closing(sqlite3.connect(state_path)) as database:
        database.execute(_V4_METADATA_SQL)
        database.execute(_V4_TASKS_SQL)
        database.execute(wire._TRANSPORT_TASKS_NONCE_INDEX_SQL)
        database.execute(
            "INSERT INTO runner_ledger_metadata VALUES (1, ?, ?)",
            ("bluefire.runner-ledger-metadata.v1", _V4_GENERATION),
        )
        database.execute(
            """INSERT INTO transport_tasks (
                task_id, operation, profile_id, request_hash, runner_id, client_id,
                peer_fingerprint, ca_fingerprint, server_fingerprint, client_fingerprint,
                enrollment_generation, nonce, state, execute_payload_json, result_json,
                recovery_receipts_json, cleanup_required, effect_dispatched, error_code,
                executor_instance, cancellation_requested, created_at, updated_at
            ) VALUES (?, 'health', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed', NULL, ?,
                      NULL, 0, 0, NULL, ?, 0, ?, ?)""",
            (
                "health-" + "1" * 48,
                _PROFILE_ID,
                "sha256:" + "2" * 64,
                binding["runner_id"],
                binding["client_id"],
                binding["peer_fingerprint"],
                binding["ca_fingerprint"],
                binding["server_fingerprint"],
                binding["client_fingerprint"],
                binding["enrollment_generation"],
                "3" * 64,
                b'{"status":"healthy"}',
                "instance-" + "4" * 32,
                health_timestamp,
                health_timestamp,
            ),
        )
        database.execute(
            """INSERT INTO transport_tasks (
                task_id, operation, profile_id, request_hash, runner_id, client_id,
                peer_fingerprint, ca_fingerprint, server_fingerprint, client_fingerprint,
                enrollment_generation, nonce, state, execute_payload_json, result_json,
                recovery_receipts_json, cleanup_required, effect_dispatched, error_code,
                executor_instance, cancellation_requested, created_at, updated_at
            ) VALUES (?, 'execute', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'cancelled', ?,
                      NULL, NULL, 0, 1, 'task_cancelled', ?, 1, 3, 4)""",
            (
                execute_task_id,
                _PROFILE_ID,
                execute_request_hash,
                binding["runner_id"],
                binding["client_id"],
                binding["peer_fingerprint"],
                binding["ca_fingerprint"],
                binding["server_fingerprint"],
                binding["client_fingerprint"],
                binding["enrollment_generation"],
                execute_nonce,
                execute_payload_json,
                execute_instance,
            ),
        )
        database.execute("PRAGMA user_version = 4")
        database.commit()
    # Match the private parent/file protections applied by the real server
    # before read-only ledger inspection.
    wire._owner_private(state_path.parent, directory=True)
    wire._owner_private(state_path, directory=False)
    return root, state_path, secret_provider


def test_exact_v4_ledger_audits_read_only_then_migrates_preserving_generation_and_rows(
    legacy_ledger: tuple[Path, Path, InMemorySecretProvider],
) -> None:
    root, state_path, secret_provider = legacy_ledger
    enrollment = load_local_enrollment(root, secret_provider=secret_provider)
    before = state_path.read_bytes()
    with closing(sqlite3.connect(state_path)) as database:
        old_rows_before = database.execute(
            "SELECT * FROM transport_tasks ORDER BY task_id"
        ).fetchall()

    assert read_runner_ledger_generation(state_path) == _V4_GENERATION
    assert audit_runner_ledger(state_path, enrollment) == {
        "schema_version": "bluefire.runner-ledger-audit.v1",
        "ledger_generation": _V4_GENERATION,
        "total_rows": 2,
        "execute_rows": 1,
        "unresolved_rows": 0,
        "active_rows": 0,
        "cleanup_required_rows": 0,
    }
    assert state_path.read_bytes() == before
    with closing(sqlite3.connect(state_path)) as database:
        assert database.execute("PRAGMA user_version").fetchone() == (4,)

    server = AuthenticatedRunnerServer(
        root,
        _InventoryOnlyRunner(),
        state_path,
        secret_provider=secret_provider,
    )
    migrated_generation = server.ledger_generation
    server.shutdown()
    assert migrated_generation == _V4_GENERATION
    assert read_runner_ledger_generation(state_path) == _V4_GENERATION
    assert audit_runner_ledger(state_path, enrollment) == {
        "schema_version": "bluefire.runner-ledger-audit.v1",
        "ledger_generation": _V4_GENERATION,
        "total_rows": 2,
        "execute_rows": 1,
        "unresolved_rows": 0,
        "active_rows": 0,
        "cleanup_required_rows": 0,
    }
    with closing(sqlite3.connect(state_path)) as database:
        assert database.execute("PRAGMA user_version").fetchone() == (wire.LEDGER_SCHEMA_VERSION,)
        assert database.execute(
            "SELECT task_id, state, result_json, cancellation_proof_json "
            "FROM transport_tasks WHERE operation = 'health'"
        ).fetchone() == (
            "health-" + "1" * 48,
            "completed",
            b'{"status":"healthy"}',
            None,
        )
        old_rows_after = database.execute(
            "SELECT task_id, operation, profile_id, request_hash, runner_id, client_id, "
            "peer_fingerprint, ca_fingerprint, server_fingerprint, client_fingerprint, "
            "enrollment_generation, nonce, state, execute_payload_json, result_json, "
            "recovery_receipts_json, cleanup_required, effect_dispatched, error_code, "
            "executor_instance, cancellation_requested, created_at, updated_at "
            "FROM transport_tasks ORDER BY task_id"
        ).fetchall()
        cancelled = database.execute(
            "SELECT task_id, operation, profile_id, request_hash, runner_id, client_id, "
            "peer_fingerprint, ca_fingerprint, server_fingerprint, client_fingerprint, "
            "enrollment_generation, nonce, state, execute_payload_json, result_json, "
            "recovery_receipts_json, cleanup_required, effect_dispatched, error_code, "
            "executor_instance, cancellation_requested, created_at, updated_at, "
            "cancellation_proof_json FROM transport_tasks WHERE operation = 'execute'"
        ).fetchone()
        assert cancelled is not None
        assert cancelled[1:3] == ("execute", _PROFILE_ID)
        assert isinstance(cancelled[3], str) and cancelled[3].startswith("sha256:")
        assert isinstance(cancelled[13], bytes)
        assert cancelled[14:] == (
            None,
            None,
            0,
            1,
            "task_cancelled",
            "instance-" + "8" * 32,
            1,
            3,
            4,
            None,
        )
    assert old_rows_after == old_rows_before

    recovery_server = AuthenticatedRunnerServer(
        root,
        _InventoryOnlyRunner(),
        state_path,
        secret_provider=secret_provider,
    ).start()
    try:
        client = AuthenticatedRunnerClient(
            root,
            profile_id=_PROFILE_ID,
            host=recovery_server.server_address[0],
            port=recovery_server.server_address[1],
            recovery_delay_seconds=0,
            secret_provider=secret_provider,
        )
        recovered = client.recover(cancelled[0], cancelled[3])
        assert recovered["state"] == "cancelled"
        assert "cancellation_proof" not in recovered
    finally:
        recovery_server.shutdown()


def test_tampered_v4_schema_is_not_migrated_or_rewritten(
    legacy_ledger: tuple[Path, Path, InMemorySecretProvider],
) -> None:
    root, state_path, secret_provider = legacy_ledger
    with closing(sqlite3.connect(state_path)) as database:
        database.execute("CREATE TABLE unexpected_objects (value TEXT)")
        database.commit()
    with closing(sqlite3.connect(state_path)) as database:
        before_objects = database.execute(
            "SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' "
            "ORDER BY type, name"
        ).fetchall()
        before_version = database.execute("PRAGMA user_version").fetchone()

    with pytest.raises(AuthenticatedRunnerTransportError):
        AuthenticatedRunnerServer(
            root,
            _InventoryOnlyRunner(),
            state_path,
            secret_provider=secret_provider,
        )

    with closing(sqlite3.connect(state_path)) as database:
        assert database.execute("PRAGMA user_version").fetchone() == before_version == (4,)
        assert (
            database.execute(
                "SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' "
                "ORDER BY type, name"
            ).fetchall()
            == before_objects
        )
        columns = {row[1] for row in database.execute("PRAGMA table_info(transport_tasks)")}
        assert "cancellation_proof_json" not in columns


@pytest.mark.parametrize("mutation", ["wrong_state", "extra_field", "integer_value"])
def test_corrupt_persisted_proof_fails_audit_and_authenticated_recovery(
    legacy_ledger: tuple[Path, Path, InMemorySecretProvider], mutation: str
) -> None:
    root, state_path, secret_provider = legacy_ledger
    enrollment = load_local_enrollment(root, secret_provider=secret_provider)
    server = AuthenticatedRunnerServer(
        root,
        _InventoryOnlyRunner(),
        state_path,
        secret_provider=secret_provider,
    ).start()
    try:
        client = AuthenticatedRunnerClient(
            root,
            profile_id=_PROFILE_ID,
            host=server.server_address[0],
            port=server.server_address[1],
            recovery_delay_seconds=0,
            secret_provider=secret_provider,
        )
        proof: dict[str, Any] = _valid_proof()
        state = "cancelled"
        if mutation == "wrong_state":
            state = "failed"
        elif mutation == "extra_field":
            proof["unrecognized"] = False
        else:
            proof["forced_tree_termination"] = 1

        with closing(sqlite3.connect(state_path)) as database:
            task_id, request_hash, effect_dispatched = database.execute(
                "SELECT task_id, request_hash, effect_dispatched "
                "FROM transport_tasks WHERE operation = 'execute'"
            ).fetchone()
            assert effect_dispatched == 1
            database.execute(
                "UPDATE transport_tasks SET state = ?, cancellation_proof_json = ? "
                "WHERE task_id = ?",
                (state, canonical_json_bytes(proof), task_id),
            )
            database.commit()

        with pytest.raises(AuthenticatedRunnerTransportError):
            audit_runner_ledger(state_path, enrollment)
        with pytest.raises(RunnerRemoteError) as error:
            client.recover(task_id, request_hash)
        assert error.value.code == "runner_failure"
    finally:
        server.shutdown()


def _valid_proof() -> dict[str, bool]:
    return {
        "cooperative_requested": True,
        "cooperative_acknowledged": True,
        "forced_tree_termination": True,
        "control_cleanup_verified": True,
    }


@pytest.mark.parametrize(
    "mutation",
    ["missing", "extra", "integer", "string", "ack_without_request"],
)
def test_cancellation_proof_schema_requires_exact_boolean_facts(mutation: str) -> None:
    proof: dict[str, Any] = _valid_proof()
    if mutation == "missing":
        del proof["forced_tree_termination"]
    elif mutation == "extra":
        proof["detail"] = "not a cancellation fact"
    elif mutation == "integer":
        proof["forced_tree_termination"] = 1
    elif mutation == "string":
        proof["control_cleanup_verified"] = "true"
    else:
        proof["cooperative_requested"] = False

    with pytest.raises(RunnerAuthenticationError):
        validated_cancellation_proof(proof)


def _recovered_task(
    *, task_id: str = "execute-" + "a" * 64, request_hash: str = "sha256:" + "b" * 64
) -> dict[str, Any]:
    return {
        "original_task_id": task_id,
        "original_request_hash": request_hash,
        "state": "cancelled",
        "result": None,
        "error_code": "task_cancelled",
        "cancellation_requested": True,
        "receipt_ids": [],
        "cleanup_required": False,
        "cancellation_proof": _valid_proof(),
    }


@pytest.mark.parametrize("proof_present", [False, True])
def test_recovered_cancellation_binding_is_exact_with_or_without_proof(
    proof_present: bool,
) -> None:
    task_id = "execute-" + "a" * 64
    request_hash = "sha256:" + "b" * 64
    payload = _recovered_task(task_id=task_id, request_hash=request_hash)
    if not proof_present:
        del payload["cancellation_proof"]
    assert validated_recovered_cancellation_proof(payload, task_id, request_hash) == (
        _valid_proof() if proof_present else {}
    )

    for wrong_task, wrong_hash in (
        ("execute-" + "c" * 64, request_hash),
        (task_id, "sha256:" + "d" * 64),
    ):
        with pytest.raises(RunnerAuthenticationError):
            validated_recovered_cancellation_proof(
                payload,
                wrong_task,
                wrong_hash,
            )


@pytest.mark.parametrize("proof_present", [False, True])
@pytest.mark.parametrize(
    "mutation",
    ["not_requested", "receipts", "cleanup", "extra"],
)
def test_recovered_cancelled_shape_is_exact_with_or_without_proof(
    mutation: str, proof_present: bool
) -> None:
    payload = _recovered_task()
    if not proof_present:
        del payload["cancellation_proof"]
    if mutation == "not_requested":
        payload["cancellation_requested"] = False
    elif mutation == "receipts":
        payload["receipt_ids"] = ["a" * 64]
    elif mutation == "cleanup":
        payload["cleanup_required"] = True
    elif mutation == "extra":
        payload["unexpected"] = "not authenticated proof data"
    task_id = payload["original_task_id"]
    request_hash = payload["original_request_hash"]
    with pytest.raises(RunnerAuthenticationError):
        validated_recovered_cancellation_proof(payload, task_id, request_hash)


@pytest.mark.parametrize("mutation", ["completed", "malformed_proof"])
def test_recovered_proof_is_rejected_for_terminal_mismatch_or_malformed_fact(
    mutation: str,
) -> None:
    payload = _recovered_task()
    if mutation == "completed":
        payload.update(state="completed", error_code=None, result={"status": "success"})
    else:
        payload["cancellation_proof"] = {**_valid_proof(), "forced_tree_termination": 1}
    with pytest.raises(RunnerAuthenticationError):
        validated_recovered_cancellation_proof(
            payload, payload["original_task_id"], payload["original_request_hash"]
        )


def test_legacy_recovered_cancelled_state_without_proof_remains_unknown() -> None:
    payload = _recovered_task()
    del payload["cancellation_proof"]
    assert (
        validated_recovered_cancellation_proof(
            payload, payload["original_task_id"], payload["original_request_hash"]
        )
        == {}
    )


def test_legacy_non_cancelled_recovery_without_proof_remains_unknown() -> None:
    payload = _recovered_task()
    del payload["cancellation_proof"]
    payload.update(state="completed", result={"status": "success"}, error_code=None)
    assert (
        validated_recovered_cancellation_proof(
            payload, payload["original_task_id"], payload["original_request_hash"]
        )
        == {}
    )


@pytest.mark.parametrize(
    "cancellation_requested,receipt_ids",
    [
        (False, ["c" * 64]),
        (True, ["c" * 64, "d" * 64]),
    ],
)
def test_recovery_required_payload_accepts_server_contract_variants(
    cancellation_requested: bool, receipt_ids: list[str]
) -> None:
    task_id = "execute-" + "a" * 64
    request_hash = "sha256:" + "b" * 64
    payload = {
        "original_task_id": task_id,
        "original_request_hash": request_hash,
        "state": "recovery_required",
        "result": None,
        "error_code": "recovery_required",
        "cancellation_requested": cancellation_requested,
        "receipt_ids": receipt_ids,
        "cleanup_required": True,
    }
    validated_recovery_required_payload(payload, task_id, request_hash)
    assert validated_recovered_cancellation_proof(payload, task_id, request_hash) == {}


def test_recovery_required_payload_accepts_receipt_limit() -> None:
    task_id = "execute-" + "a" * 64
    request_hash = "sha256:" + "b" * 64
    payload = {
        "original_task_id": task_id,
        "original_request_hash": request_hash,
        "state": "recovery_required",
        "result": None,
        "error_code": "recovery_required",
        "cancellation_requested": False,
        "receipt_ids": [f"{index:064x}" for index in range(512)],
        "cleanup_required": True,
    }
    validated_recovery_required_payload(payload, task_id, request_hash)


@pytest.mark.parametrize(
    "mutation",
    [
        "task_id",
        "request_hash",
        "missing_receipts",
        "non_list_receipts",
        "empty_receipts",
        "malformed_receipt",
        "nonstring_receipt",
        "unhashable_receipt",
        "duplicate_receipt",
        "oversized_receipts",
        "cleanup_false",
        "cancellation_not_boolean",
        "result",
        "error_code",
        "extra_field",
        "proof_field",
    ],
)
def test_recovery_required_payload_rejects_misbinding_or_malformed_details(
    mutation: str,
) -> None:
    task_id = "execute-" + "a" * 64
    request_hash = "sha256:" + "b" * 64
    payload: dict[str, Any] = {
        "original_task_id": task_id,
        "original_request_hash": request_hash,
        "state": "recovery_required",
        "result": None,
        "error_code": "recovery_required",
        "cancellation_requested": True,
        "receipt_ids": ["c" * 64],
        "cleanup_required": True,
    }
    if mutation == "task_id":
        payload["original_task_id"] = "execute-" + "e" * 64
    elif mutation == "request_hash":
        payload["original_request_hash"] = "sha256:" + "f" * 64
    elif mutation == "missing_receipts":
        del payload["receipt_ids"]
    elif mutation == "non_list_receipts":
        payload["receipt_ids"] = "c" * 64
    elif mutation == "empty_receipts":
        payload["receipt_ids"] = []
    elif mutation == "malformed_receipt":
        payload["receipt_ids"] = ["not-a-digest"]
    elif mutation == "nonstring_receipt":
        payload["receipt_ids"] = [7]
    elif mutation == "unhashable_receipt":
        payload["receipt_ids"] = [[]]
    elif mutation == "duplicate_receipt":
        payload["receipt_ids"] = ["c" * 64, "c" * 64]
    elif mutation == "oversized_receipts":
        payload["receipt_ids"] = [f"{index:064x}" for index in range(513)]
    elif mutation == "cleanup_false":
        payload["cleanup_required"] = False
    elif mutation == "cancellation_not_boolean":
        payload["cancellation_requested"] = 1
    elif mutation == "result":
        payload["result"] = {"status": "success"}
    elif mutation == "error_code":
        payload["error_code"] = "task_cancelled"
    elif mutation == "extra_field":
        payload["diagnostic"] = "unrecognized"
    else:
        payload["cancellation_proof"] = _valid_proof()

    with pytest.raises(RunnerAuthenticationError):
        validated_recovered_cancellation_proof(payload, task_id, request_hash)


def test_proof_is_not_accepted_for_unrequested_terminal_cancellation() -> None:
    payload = _recovered_task()
    payload["cancellation_requested"] = False
    with pytest.raises(RunnerAuthenticationError):
        validated_recovered_cancellation_proof(
            payload, payload["original_task_id"], payload["original_request_hash"]
        )


@pytest.mark.parametrize(
    "initial_reply", ["task_cancelled", "duplicate_request", "connection_loss"]
)
@pytest.mark.parametrize("misbound_recovery", [False, True])
def test_direct_execution_preserves_reconciled_cleanup_requirement(
    monkeypatch: pytest.MonkeyPatch, initial_reply: str, misbound_recovery: bool
) -> None:
    client = object.__new__(AuthenticatedRunnerClient)
    client.profile_id = _PROFILE_ID
    client.recovery_attempts = 1
    client.recovery_delay_seconds = 0
    manifest = {"runner_profile_id": _PROFILE_ID}
    profile = {"profile_id": _PROFILE_ID}
    task_id, request_hash = client.execution_identity(manifest, profile)
    calls: list[str] = []

    def call(operation: str, payload: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        calls.append(operation)
        if operation == "execute":
            assert kwargs == {"task_id": task_id, "request_hash": request_hash}
            assert payload == {"manifest": manifest, "profile": profile}
            if initial_reply == "connection_loss":
                raise RunnerConnectionError("fixture response was lost")
            raise RunnerRemoteError(initial_reply)
        assert operation == "recover"
        assert payload == {"original_task_id": task_id, "original_request_hash": request_hash}
        recovery = {
            "original_task_id": task_id,
            "original_request_hash": request_hash,
            "state": "recovery_required",
            "result": None,
            "error_code": "recovery_required",
            "cancellation_requested": True,
            "receipt_ids": ["c" * 64],
            "cleanup_required": True,
        }
        if misbound_recovery:
            recovery["original_request_hash"] = "sha256:" + "d" * 64
        return recovery

    monkeypatch.setattr(client, "_call", call)
    if misbound_recovery:
        with pytest.raises(RunnerAuthenticationError):
            client.execute(manifest, profile)
    else:
        with pytest.raises(RunnerRemoteError) as error:
            client.execute(manifest, profile)
        assert error.value.code == "recovery_required"
    assert calls == ["execute", "recover"]
    assert client.last_execution_identity == (task_id, request_hash)
