"""Capability task payload provenance and migration checks using SQLite only."""

import sqlite3
from datetime import datetime, timezone

import pytest

from bluefire import product_store as product_store_module
from bluefire.execution_contracts import execution_task_identity
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.registry import load_builtin_registry
from bluefire.runner_contracts import (
    _verified_grant_attempt,
    _verified_grant_cleanup,
    build_execution_manifest,
    build_runner_profile,
    current_platform,
    grant_attempt_authorization_digest,
)
from bluefire.runner_reviewed_execution import canonical_reviewed_execution
from bluefire.util import content_hash
from tests_platform.test_product_store_capability_grants import claim, reservation_args
from tests_platform.test_runner_contracts import _execute_profile

pytest_plugins = ("tests_platform.test_product_store_capability_grants",)


def _operation(step):
    behavior_id = step["behavior_id"]
    return {
        "step_id": step["id"],
        "behavior_id": behavior_id,
        "action_id": step.get("action_id", behavior_id),
        "execution_binding_digest": None,
    }


def _reviewed_operation(step, profile):
    operation = _operation(step)
    envelope = canonical_reviewed_execution(profile["reviewed_execution"])
    if operation not in envelope["operations"]:
        raise AssertionError("The task step is outside the exact reviewed profile envelope.")
    return {**operation, "authorization_digest": envelope["authorization_digest"]}


def _manifest(*, step, profile, claim_document, claim_digest, run_id, cleanup, now):
    action_id = step.get("action_id", step["behavior_id"])
    common = {
        "run_id": run_id,
        "step_id": step["id"],
        "behavior_id": step["behavior_id"],
        "action": load_builtin_registry().get_action(action_id),
        "runner_profile": profile,
        "params": (
            {"receipt_ids": [row["receipt_id"] for row in claim_document["receipts"]]}
            if cleanup
            else step["parameters"]
        ),
        "filesystem_scope": (),
        "approval_record": None,
        "reviewed_operation": _reviewed_operation(step, profile),
        "now": datetime.fromtimestamp(now / 1000, timezone.utc),
    }
    if cleanup:
        verified = _verified_grant_cleanup(claim_document, expected_document_digest=claim_digest)
        return build_execution_manifest(**common, grant_cleanup=verified)
    verified = _verified_grant_attempt(claim_document, expected_document_digest=claim_digest)
    return build_execution_manifest(**common, grant_attempt=verified)


@pytest.fixture
def capability_task(saved, tmp_path):
    store, state, compiled, _ = saved
    steps = compiled["scenario"]["steps"]
    cleanup_step = next(row for row in steps if row["behavior_id"] == "sandbox.cleanup.v1")
    business_step = next(row for row in steps if row["behavior_id"] != "sandbox.cleanup.v1")
    plan_digest = content_hash({"transport-test-plan": compiled["compiled_digest"]})
    envelope = canonical_reviewed_execution(
        {
            "schema_version": "bluefire.reviewed-execution.v1",
            "authorization_digest": grant_attempt_authorization_digest(
                compiled["compiled_digest"], plan_digest
            ),
            "operations": [_operation(business_step), _operation(cleanup_step)],
        }
    )
    reservation = reservation_args(saved)
    reservation["plan_digest"] = plan_digest
    reservation["native_envelope_digest"] = content_hash(envelope)
    lease = store.reserve_capability_attempt(state["grant"]["grant_id"], compiled, **reservation)
    claim(saved, lease)
    store.start_capability_preparation(
        lease["attempt_id"], now_ms=4500, current_environment=state["current_environment"]
    )
    store.bind_capability_receiver(
        lease["attempt_id"],
        session_generation="generation-" + lease["attempt_id"],
        review_digest=content_hash("transport-test-session"),
    )
    profile = build_runner_profile(
        _execute_profile(),
        sandbox_root=tmp_path / "sandbox",
        platform=current_platform(),
        reviewed_execution=envelope,
    )
    store.bind_capability_workspace(
        lease["attempt_id"],
        runner_policy_digest=profile["policy_digest"],
        workspace_path_digest=content_hash({"sandbox_root": profile["sandbox_root"]}),
        now_ms=4500,
        current_environment=state["current_environment"],
    )
    claim_record = store.get_capability_attempt(lease["attempt_id"])["claim"]
    claim_document = claim_record["document"]
    manifest = _manifest(
        step=business_step,
        profile=profile,
        claim_document=claim_document,
        claim_digest=claim_record["document_digest"],
        run_id=lease["run_id"],
        cleanup=False,
        now=5000,
    )
    task_id, transport_hash = execution_task_identity(manifest, profile)
    return {
        "store": store,
        "state": state,
        "compiled": compiled,
        "lease": lease,
        "profile": profile,
        "manifest": manifest,
        "task_id": task_id,
        "transport_hash": transport_hash,
        "step_id": business_step["id"],
        "business_step": business_step,
        "cleanup_step": cleanup_step,
    }


def _register_business(context, **overrides):
    payload = {
        "task_id": context["task_id"],
        "step_id": context["step_id"],
        "request_hash": context["manifest"]["request_hash"],
        "now_ms": 5000,
        "current_environment": context["state"]["current_environment"],
        "manifest": context["manifest"],
        "runner_profile": context["profile"],
    }
    payload.update(overrides)
    return context["store"].register_capability_task(context["lease"]["attempt_id"], **payload)


def test_business_payload_is_exact_and_survives_store_reload(capability_task):
    context = capability_task
    assert context["store"].schema_version == 12
    registered = _register_business(context)
    assert registered["transport_request_hash"] == context["transport_hash"]

    reopened = ProductStore(context["store"].path)
    record = reopened.get_capability_task_payload(context["task_id"], context["transport_hash"])
    assert record["payload"]["manifest"] == context["manifest"]
    assert record["payload"]["runner_profile"] == context["profile"]
    assert record["payload"]["attempt_id"] == context["lease"]["attempt_id"]
    assert record["payload"]["dependency_digest"]

    with pytest.raises(ProductStoreError):
        reopened.get_capability_task_payload(context["task_id"], content_hash("wrong transport"))


def test_mismatched_identity_or_half_payload_creates_no_claim(capability_task):
    context = capability_task
    with pytest.raises(ProductStoreError):
        _register_business(context, task_id="execute-" + "0" * 64)
    with pytest.raises(ProductStoreError, match="together"):
        _register_business(context, runner_profile=None)
    with context["store"]._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM capability_task_claims").fetchone()[0] == 0
        assert (
            connection.execute("SELECT COUNT(*) FROM capability_task_payloads").fetchone()[0] == 0
        )


def test_payload_insert_failure_rolls_back_business_claim(capability_task):
    context = capability_task
    with context["store"]._connection(write=True) as connection:
        connection.execute(
            "CREATE TRIGGER fail_task_payload BEFORE INSERT ON capability_task_payloads "
            "BEGIN SELECT RAISE(ABORT,'synthetic payload interruption'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="synthetic payload interruption"):
        _register_business(context)
    with context["store"]._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM capability_task_claims").fetchone()[0] == 0
        assert (
            connection.execute("SELECT COUNT(*) FROM capability_task_payloads").fetchone()[0] == 0
        )


def test_payload_history_is_append_only_and_legacy_claim_has_no_proof(capability_task):
    context = capability_task
    _register_business(context)
    with context["store"]._connection(write=True) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE capability_task_payloads SET payload_json='{}' WHERE task_id=?",
                (context["task_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM capability_task_payloads WHERE task_id=?", (context["task_id"],)
            )

    legacy_id = "legacy-task-without-payload"
    context["store"].register_capability_task(
        context["lease"]["attempt_id"],
        task_id=legacy_id,
        step_id=context["compiled"]["scenario"]["steps"][1]["id"],
        request_hash=content_hash("legacy request"),
        now_ms=5001,
        current_environment=context["state"]["current_environment"],
    )
    with pytest.raises(ProductStoreError):
        context["store"].get_capability_task_payload(legacy_id, content_hash("legacy payload"))


def test_cleanup_payload_binds_cleanup_claim_and_obligation(capability_task):
    context = capability_task
    _register_business(context)
    business_terminal = content_hash("business terminal")
    context["store"].record_capability_task_terminal(
        context["task_id"],
        request_hash=context["manifest"]["request_hash"],
        terminal_digest=business_terminal,
    )
    context["store"].record_capability_cleanup_obligation(
        context["lease"]["attempt_id"],
        workspace_id=content_hash("workspace-id").removeprefix("sha256:"),
        receipts=[
            {
                "receipt_id": content_hash("receipt-id").removeprefix("sha256:"),
                "source_task_id": context["task_id"],
                "source_request_hash": context["manifest"]["request_hash"],
            }
        ],
    )
    cleanup = context["store"].claim_capability_cleanup(
        context["lease"]["attempt_id"], now_ms=6000, timeout_ms=1000
    )
    cleanup_manifest = _manifest(
        step=context["cleanup_step"],
        profile=context["profile"],
        claim_document=cleanup["document"],
        claim_digest=cleanup["document_digest"],
        run_id=context["lease"]["run_id"],
        cleanup=True,
        now=6000,
    )
    cleanup_task_id, cleanup_transport_hash = execution_task_identity(
        cleanup_manifest, context["profile"]
    )
    registered = context["store"].register_capability_cleanup_task(
        context["lease"]["attempt_id"],
        task_id=cleanup_task_id,
        request_hash=cleanup_manifest["request_hash"],
        expected_document_digest=cleanup["document_digest"],
        now_ms=6000,
        step_id=context["cleanup_step"]["id"],
        manifest=cleanup_manifest,
        runner_profile=context["profile"],
    )
    assert registered["transport_request_hash"] == cleanup_transport_hash
    record = context["store"].get_capability_cleanup_task_payload(
        cleanup_task_id, cleanup_transport_hash
    )
    assert record["payload"]["cleanup_claim_digest"] == cleanup["document_digest"]
    assert record["payload"]["cleanup_obligation_digest"]
    assert record["payload"]["step_id"] == context["cleanup_step"]["id"]

    reopened = ProductStore(context["store"].path)
    assert (
        reopened.get_capability_cleanup_task_payload(cleanup_task_id, cleanup_transport_hash)
        == record
    )


def test_v11_upgrade_preserves_rows_without_synthesizing_payloads(capability_task):
    context = capability_task
    store = context["store"]
    path = store.path
    store.set_setting("transport.migration", {"preserve": "exact"})
    _register_business(context)
    job_id = context["state"]["parent_job_id"]
    with store._connection(write=True) as connection:
        original_job = dict(
            connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        )
        original_setting = dict(
            connection.execute("SELECT * FROM settings WHERE key='transport.migration'").fetchone()
        )
        original_claim = dict(
            connection.execute(
                "SELECT * FROM capability_task_claims WHERE task_id=?", (context["task_id"],)
            ).fetchone()
        )
        connection.execute("DROP TABLE capability_task_payloads")
        connection.execute("DROP TABLE capability_cleanup_task_payloads")
        connection.execute("DELETE FROM schema_migrations")
        connection.execute("INSERT INTO schema_migrations(version,applied_at) VALUES(11,'prior')")

    upgraded = ProductStore(path)
    assert upgraded.schema_version == 12
    with upgraded._connection() as connection:
        assert (
            dict(connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone())
            == original_job
        )
        assert (
            dict(
                connection.execute(
                    "SELECT * FROM settings WHERE key='transport.migration'"
                ).fetchone()
            )
            == original_setting
        )
        assert (
            dict(
                connection.execute(
                    "SELECT * FROM capability_task_claims WHERE task_id=?", (context["task_id"],)
                ).fetchone()
            )
            == original_claim
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM capability_task_payloads").fetchone()[0] == 0
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM capability_cleanup_task_payloads").fetchone()[
                0
            ]
            == 0
        )


def test_v11_migration_failure_rolls_back_new_payload_tables_and_marker(tmp_path, monkeypatch):
    path = tmp_path / "failed-upgrade.sqlite3"
    store = ProductStore(path)
    with store._connection(write=True) as connection:
        connection.execute("DROP TABLE capability_task_payloads")
        connection.execute("DROP TABLE capability_cleanup_task_payloads")
        connection.execute("DELETE FROM schema_migrations")
        connection.execute("INSERT INTO schema_migrations(version,applied_at) VALUES(11,'prior')")
    initialize = product_store_module.capability_store_api.initialize_schema

    def fail_after_payload_ddl(connection):
        initialize(connection)
        raise RuntimeError("synthetic migration interruption")

    monkeypatch.setattr(
        product_store_module.capability_store_api, "initialize_schema", fail_after_payload_ddl
    )
    with pytest.raises(RuntimeError, match="synthetic migration interruption"):
        ProductStore(path)
    with store._connection() as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 11
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='capability_task_payloads'"
            ).fetchone()
            is None
        )
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='capability_cleanup_task_payloads'"
            ).fetchone()
            is None
        )


def test_v11_code_refuses_v12_before_payload_table_ddl(tmp_path, monkeypatch):
    path = tmp_path / "future-schema.sqlite3"
    store = ProductStore(path)
    with store._connection(write=True) as connection:
        connection.execute("DROP TABLE capability_task_payloads")
        connection.execute("DROP TABLE capability_cleanup_task_payloads")
    monkeypatch.setattr(product_store_module, "SCHEMA_VERSION", 11)
    with pytest.raises(ProductStoreError, match="newer"):
        ProductStore(path)
    with store._connection() as connection:
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='capability_task_payloads'"
            ).fetchone()
            is None
        )
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='capability_cleanup_task_payloads'"
            ).fetchone()
            is None
        )
