"""Exact historical task lookup tests using synthetic SQLite records only."""

from copy import deepcopy

import pytest

from bluefire.execution_contracts import execution_task_identity
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.product_store_serialization import canonical_json
from bluefire.util import content_hash


@pytest.fixture
def saved_task(tmp_path):
    store = ProductStore(tmp_path / "task-record.db")
    job_id = "job-file-access-record"
    step_id = "step-authored"
    manifest = {
        "run_id": "run-authored-historical",
        "step_id": step_id,
        "request_hash": content_hash({"manifest-seal": "unchanged"}),
        "approval": {
            "approved_at": "2001-01-01T00:00:00Z",
            "expires_at": "2001-01-02T00:00:00Z",
        },
    }
    runner_profile = {"profile_id": "saved-profile", "sandbox_root": "/synthetic/root"}
    task_id, transport_hash = execution_task_identity(manifest, runner_profile)
    task = {
        "job_id": job_id,
        "task_id": task_id,
        "step_id": step_id,
        "request_hash": manifest["request_hash"],
        "transport_request_hash": transport_hash,
        "manifest": manifest,
        "runner_profile": runner_profile,
    }
    with store._connection(write=True) as connection:
        connection.execute(
            "INSERT INTO jobs(job_id,kind,state,request_json,progress_json,created_at,updated_at) "
            "VALUES(?,?,'queued','{}','{}','2001-01-01T00:00:00Z','2001-01-01T00:00:00Z')",
            (job_id, "file_access.operation"),
        )
        operation = {"schema_version": "synthetic.file-access-operation.v1"}
        connection.execute(
            "INSERT INTO file_access_operations VALUES(?,?,?,?,?,?)",
            (
                job_id,
                job_id,
                "synthetic-enrollment",
                "create",
                canonical_json(operation),
                content_hash(operation),
            ),
        )
        connection.execute(
            "INSERT INTO file_access_task_claims VALUES(?,?,?,?,?,?)",
            (
                task_id,
                job_id,
                step_id,
                manifest["request_hash"],
                canonical_json(task),
                content_hash(task),
            ),
        )
    return store, task_id, transport_hash, task


def test_file_access_task_record_returns_claim_and_optional_terminal(saved_task):
    store, task_id, transport_hash, task = saved_task
    terminal = {
        "task_id": task_id,
        "request_hash": task["request_hash"],
        "result": {"status": "success"},
        "receipt_snapshot": {"documents": {}, "committed": []},
    }
    with store._connection(write=True) as connection:
        connection.execute(
            "INSERT INTO file_access_task_terminals VALUES(?,?,?)",
            (task_id, canonical_json(terminal), content_hash(terminal)),
        )

    actual = store.file_access_task_record(task_id, transport_hash)

    assert actual == {
        "task": task,
        "document_digest": content_hash(task),
        "terminal": terminal,
    }


def test_file_access_task_record_refuses_altered_persisted_document(saved_task):
    store, _task_id, _transport_hash, task = saved_task
    altered = deepcopy(task)
    altered["step_id"] = "step-altered"
    altered["manifest"]["step_id"] = "step-altered"
    altered["runner_profile"]["sandbox_root"] = "/changed/root"
    altered_task_id, altered_transport_hash = execution_task_identity(
        altered["manifest"], altered["runner_profile"]
    )
    altered["task_id"] = altered_task_id
    altered["transport_request_hash"] = altered_transport_hash
    with store._connection(write=True) as connection:
        connection.execute(
            "INSERT INTO file_access_task_claims VALUES(?,?,?,?,?,?)",
            (
                altered_task_id,
                altered["job_id"],
                altered["step_id"],
                altered["request_hash"],
                canonical_json(altered),
                content_hash(task),
            ),
        )

    with pytest.raises(ProductStoreError):
        store.file_access_task_record(altered_task_id, altered_transport_hash)


def test_file_access_task_record_requires_the_exact_full_pair_hash(saved_task):
    store, task_id, transport_hash, _task = saved_task

    with pytest.raises(ProductStoreError):
        store.file_access_task_record(task_id, content_hash({"different": "payload"}))


def test_file_access_task_record_rejects_resealed_claim_with_stale_pair_identity(saved_task):
    store, _task_id, _transport_hash, task = saved_task
    manifest = deepcopy(task["manifest"])
    manifest["step_id"] = "step-full-pair-check"
    profile = deepcopy(task["runner_profile"])
    claim_id, claim_hash = execution_task_identity(manifest, profile)
    profile["sandbox_root"] = "/changed/after-identity"
    claim = {
        **task,
        "task_id": claim_id,
        "step_id": manifest["step_id"],
        "manifest": manifest,
        "runner_profile": profile,
        "transport_request_hash": claim_hash,
    }
    with store._connection(write=True) as connection:
        connection.execute(
            "INSERT INTO file_access_task_claims VALUES(?,?,?,?,?,?)",
            (
                claim_id,
                claim["job_id"],
                claim["step_id"],
                claim["request_hash"],
                canonical_json(claim),
                content_hash(claim),
            ),
        )

    with pytest.raises(ProductStoreError):
        store.file_access_task_record(claim_id, claim_hash)


def test_file_access_task_record_rejects_correctly_hashed_misbound_terminal(saved_task):
    store, task_id, transport_hash, task = saved_task
    terminal = {
        "task_id": "execute-mismatched-terminal",
        "request_hash": content_hash({"different": "manifest seal"}),
        "result": {"status": "success"},
        "receipt_snapshot": {"documents": {}, "committed": []},
    }
    with store._connection(write=True) as connection:
        connection.execute(
            "INSERT INTO file_access_task_terminals VALUES(?,?,?)",
            (task_id, canonical_json(terminal), content_hash(terminal)),
        )

    with pytest.raises(ProductStoreError):
        store.file_access_task_record(task_id, transport_hash)


def test_file_access_task_record_does_not_accept_manifest_seal_as_transport_hash(saved_task):
    store, task_id, _transport_hash, task = saved_task

    with pytest.raises(ProductStoreError):
        store.file_access_task_record(task_id, task["request_hash"])


def test_file_access_task_record_accepts_expired_historical_claim_unchanged(saved_task):
    store, task_id, transport_hash, task = saved_task

    actual = store.file_access_task_record(task_id, transport_hash)

    assert actual["task"] == task
    assert actual["task"]["manifest"]["approval"] == {
        "approved_at": "2001-01-01T00:00:00Z",
        "expires_at": "2001-01-02T00:00:00Z",
    }
    assert actual["terminal"] is None


def test_file_access_task_record_missing_claim_raises(saved_task):
    store, _task_id, transport_hash, _task = saved_task

    with pytest.raises(ProductStoreError):
        store.file_access_task_record("execute-" + "0" * 64, transport_hash)
