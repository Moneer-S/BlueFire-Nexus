"""Durable read-proof publication from authored terminals, without native dispatch."""

import sqlite3
from copy import deepcopy
from types import SimpleNamespace

import pytest

from bluefire import file_access_context, file_access_execution, file_access_reconciliation
from bluefire.file_access_control import KIND, FileAccessControl
from bluefire.file_access_observation import baseline_record, control_observation
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.product_store_serialization import canonical_json
from bluefire.util import content_hash
from tests_platform.file_access_fixtures import binding, observation


@pytest.fixture(params=["baseline", "rollback"])
def saved_reads(tmp_path, request, monkeypatch):
    path = tmp_path / "observations.db"
    store = ProductStore(path)
    operation = request.param
    owner_id = store.create_job(KIND, {})["job_id"]
    job_id = store.create_job(KIND, {"control_owner_id": owner_id})["job_id"]
    bound = {**binding(), "control_revision": 2}
    prior_baseline = baseline_record(
        owner_id,
        {
            "source_digest": content_hash("previous read proof"),
            "record_count": bound["resource"]["record_count"],
            "sha256": bound["resource"]["sha256"],
        },
    )
    prior = {
        "control_owner_id": owner_id,
        "enrollment_id": bound["enrollment_id"],
        "revision": 1,
        "status": "created" if operation == "baseline" else "hardened",
        "binding": {**bound, "control_revision": 1},
        "baseline": None if operation == "baseline" else prior_baseline,
    }
    review = {
        "operation": operation,
        "control_owner_id": owner_id,
        "control_digest": content_hash(prior),
    }
    enrolled = {
        "document": {"enrollment_id": bound["enrollment_id"]},
        "document_digest": content_hash("authored enrollment"),
    }
    document = {
        "review": review,
        "submitted_request": {},
        "review_context": {"profile_digest": content_hash({}), "implementations": {}},
    }
    prepared = {
        "recipe": file_access_execution.recipe(operation),
        "prior": prior,
        "source": {"fixture": "authored retained resource"},
        "target_binding": bound,
        "revision": 2,
        "enrollment_digest": enrolled["document_digest"],
    }
    probe, owner = observation(bound), observation(bound, owner=True)
    tasks = []
    for step in prepared["recipe"]:
        identity = step["step_id"]
        observed = {"probe": probe, "owner": owner}.get(identity)
        request_hash = content_hash(identity) if observed is None else observed["request_hash"]
        task = {
            "job_id": job_id,
            "task_id": "task-" + identity,
            "step_id": identity,
            "request_hash": request_hash,
            "transport_request_hash": content_hash("transport-" + identity),
            "manifest": {
                "action_id": step["action_id"],
                "requested_at": "1970-01-01T00:16:39Z",
                "expires_at": "1970-01-01T00:17:00Z",
            },
        }
        result = {"status": "success"}
        if observed is not None:
            result["output"] = {"observation": observed}
        terminal = {
            "task_id": task["task_id"],
            "request_hash": request_hash,
            "result": result,
            "receipt_snapshot": {"documents": {}, "committed": []},
        }
        tasks.append({"task": task, "terminal": terminal})
    proof = control_observation(operation, tasks, binding=bound, now_ms=1_000_002)
    terminal_change = request.node.callspec.params.get("terminal_change")
    if terminal_change is not None:
        row = next(row for row in tasks if row["task"]["step_id"] == "owner")
        row["terminal"] = deepcopy(row["terminal"])
        if terminal_change == "missing_observation":
            row["terminal"]["result"]["output"] = {}
        else:
            row["terminal"]["result"]["output"]["observation"]["request_hash"] = content_hash(
                "foreign read"
            )
    # Admission/native authentication have separate coverage. Seed their durable outputs
    # here so crash tests exercise the real SQLite completion transaction in isolation.
    with store._connection(write=True) as connection:
        for identity, kind, record in ((owner_id, "create", {}), (job_id, operation, document)):
            connection.execute(
                "INSERT INTO file_access_operations VALUES(?,?,?,?,?,?)",
                (
                    identity,
                    owner_id,
                    bound["enrollment_id"],
                    kind,
                    canonical_json(record),
                    content_hash(record),
                ),
            )
        connection.execute(
            "INSERT INTO file_access_revisions VALUES(?,?,?,?,?)",
            (owner_id, 1, owner_id, canonical_json(prior), content_hash(prior)),
        )
        connection.execute(
            "INSERT INTO file_access_preparations VALUES(?,?,?)",
            (job_id, canonical_json(prepared), content_hash(prepared)),
        )
        for row in tasks:
            task, terminal = row["task"], row["terminal"]
            connection.execute(
                "INSERT INTO file_access_task_claims VALUES(?,?,?,?,?,?)",
                (
                    task["task_id"],
                    job_id,
                    task["step_id"],
                    task["request_hash"],
                    canonical_json(task),
                    content_hash(task),
                ),
            )
            connection.execute(
                "INSERT INTO file_access_task_terminals VALUES(?,?,?)",
                (task["task_id"], canonical_json(terminal), content_hash(terminal)),
            )
            if task["step_id"] == "probe":
                closure = {
                    "terminal_digest": content_hash(terminal["result"]),
                    "request_hash": task["request_hash"],
                }
                connection.execute(
                    "INSERT INTO file_access_worker_closures VALUES(?,?,?)",
                    (task["task_id"], canonical_json(closure), content_hash(closure)),
                )
    store.finish_file_access_operation(
        job_id, outcome={"state": "unknown", "evidence_digest": content_hash(tasks)}
    )
    store.transition_job(
        job_id, "failed", error={"code": "authored_exit", "message": "Authored interruption"}
    )
    expected_digest = store.file_access_operation_records(job_id)["outcome_digest"]
    control_document = {
        "schema_version": "bluefire.retained-file-control.v1",
        "control_owner_id": owner_id,
        "enrollment_id": bound["enrollment_id"],
        "revision": 2,
        "status": "baseline_verified" if operation == "baseline" else "rolled_back",
        "binding": bound,
        "binding_digest": content_hash(bound),
        "source": prepared["source"],
        "baseline": baseline_record(job_id, proof) if operation == "baseline" else prior_baseline,
    }
    finish_args = {
        "outcome": {"state": "complete", "evidence_digest": content_hash(tasks)},
        "control": control_document,
        "expected_outcome_digest": expected_digest,
        "verified_observation": proof,
        "now_ms": 1_000_002,
    }
    control = FileAccessControl(SimpleNamespace(product_store=store), clock=lambda: 1_000_002)
    monkeypatch.setattr(control, "_enrollment", lambda: enrolled)
    calls = {"recover": 0, "execute": 0}

    def forbidden_execute(*args, **kwargs):
        calls["execute"] += 1
        raise AssertionError("Recovery must not dispatch a new task")

    current = {
        "enrollment": enrolled,
        "profile": SimpleNamespace(to_dict=lambda: {}),
        "implementation_digests": {},
        "runner": SimpleNamespace(execute=forbidden_execute),
    }
    outputs = {
        "owner": {
            "verification": {
                "probe_observation_digest": content_hash(probe),
                "observation_digest": content_hash(owner),
                "request_hash": owner["request_hash"],
            }
        }
    }

    def recovered(*args):
        calls["recover"] += 1
        return deepcopy(outputs), True

    monkeypatch.setattr(file_access_context, "execution", lambda *args: current)
    monkeypatch.setattr(file_access_context, "binding", lambda *args, **kwargs: deepcopy(bound))
    monkeypatch.setattr(file_access_execution, "_engine", lambda *args: None)
    monkeypatch.setattr(file_access_reconciliation, "recover_tasks", recovered)
    return SimpleNamespace(
        path=path,
        store=store,
        job_id=job_id,
        owner_id=owner_id,
        proof=proof,
        finish_args=finish_args,
        control=control,
        calls=calls,
        request={
            "submission_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "expected_outcome_digest": expected_digest,
            "reviewed_by": "Authored operator",
        },
    )


def reopen(value):
    value.store = ProductStore(value.path)
    value.control.service.product_store = value.store
    value.control.store = value.store
    return value.store.file_access_operation_records(value.job_id)


def test_read_proof_and_control_rollback_together_before_commit(saved_reads):
    value = saved_reads
    with value.store._connection(write=True) as connection:
        connection.execute(
            "CREATE TRIGGER authored_crash BEFORE INSERT ON file_access_outcomes "
            "BEGIN SELECT RAISE(ABORT, 'authored before commit'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="authored before commit"):
        file_access_reconciliation.reconcile(value.control, value.job_id, value.request)
    records = reopen(value)
    assert records["outcome"]["state"] == "unknown"
    assert "verified_observation" not in records["outcome"]
    assert value.store.get_file_access_control(value.owner_id)["document"]["revision"] == 1
    with value.store._connection(write=True) as connection:
        connection.execute("DROP TRIGGER authored_crash")
    response = file_access_reconciliation.reconcile(value.control, value.job_id, value.request)
    assert response["job"]["progress"]["verified_observation"] == value.proof
    assert response["control"]["revision"] == 2
    assert value.calls == {"recover": 2, "execute": 0}


def test_after_commit_crash_resumes_receipt_without_replay(saved_reads, monkeypatch):
    value = saved_reads

    def crash(*args, **kwargs):
        raise RuntimeError("authored after commit")

    monkeypatch.setattr(value.store, "finish_file_access_reconciliation", crash)
    with pytest.raises(RuntimeError, match="authored after commit"):
        file_access_reconciliation.reconcile(value.control, value.job_id, value.request)
    records = reopen(value)
    assert records["outcome"]["verified_observation"] == value.proof
    assert value.store.get_file_access_control(value.owner_id)["document"]["revision"] == 2
    response = file_access_reconciliation.reconcile(value.control, value.job_id, value.request)
    assert response["reconciliation_receipt"]["state"] == "completed"
    assert response["job"]["progress"]["verified_observation"] == value.proof
    assert (
        file_access_reconciliation.reconcile(value.control, value.job_id, value.request) == response
    )
    assert value.calls == {"recover": 1, "execute": 0}


@pytest.mark.parametrize("change", ["missing", "malformed", "digest", "baseline", "future"])
def test_invalid_proof_cannot_commit_control_revision(saved_reads, change):
    value = saved_reads
    arguments = deepcopy(value.finish_args)
    if change == "missing":
        arguments.pop("verified_observation")
    elif change == "malformed":
        arguments["verified_observation"] = {"authored": True}
    elif change == "digest":
        arguments["verified_observation"]["source_digest"] = content_hash("foreign terminal")
    elif change == "baseline":
        arguments["control"]["baseline"]["sha256"] = content_hash("foreign contents")
    else:
        arguments["now_ms"] = 999_999
    with pytest.raises((ProductStoreError, ValueError)):
        value.store.finish_file_access_operation(value.job_id, **arguments)
    assert reopen(value)["outcome"]["state"] == "unknown"
    assert value.store.get_file_access_control(value.owner_id)["document"]["revision"] == 1


def test_duplicate_proof_is_immutable_and_stale_job_progress_cannot_replace_it(saved_reads):
    value = saved_reads
    value.store.finish_file_access_operation(value.job_id, **value.finish_args)
    value.store.finish_file_access_operation(value.job_id, **value.finish_args)
    changed = deepcopy(value.finish_args)
    changed["verified_observation"]["record_count"] += 1
    with pytest.raises(ProductStoreError):
        value.store.finish_file_access_operation(value.job_id, **changed)
    value.store.transition_job(
        value.job_id, "failed", progress={"verified_observation": {"authored": True}}
    )
    reopen(value)
    assert (
        value.control.operation(value.job_id)["job"]["progress"]["verified_observation"]
        == value.proof
    )
    value.store.transition_job(value.job_id, "failed", progress={"phase": "old updater"})
    assert (
        value.control.operation(value.job_id)["job"]["progress"]["verified_observation"]
        == value.proof
    )
    with value.store._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM file_access_revisions").fetchone()[0] == 2


@pytest.mark.parametrize("terminal_change", ["missing_observation", "foreign_request"])
def test_summary_cannot_replace_actual_terminal_read_proof(saved_reads, terminal_change):
    value = saved_reads
    with pytest.raises(ValueError):
        value.store.finish_file_access_operation(value.job_id, **value.finish_args)
    assert reopen(value)["outcome"]["state"] == "unknown"
    assert value.store.get_file_access_control(value.owner_id)["document"]["revision"] == 1


def test_committed_observation_is_hidden_until_job_is_terminal(saved_reads):
    value = saved_reads
    value.store.finish_file_access_operation(value.job_id, **value.finish_args)
    with value.store._connection(write=True) as connection:
        connection.execute("UPDATE jobs SET state='running' WHERE job_id=?", (value.job_id,))
    assert "verified_observation" not in value.control.operation(value.job_id)["job"]["progress"]
    value.store.transition_job(value.job_id, "failed")
    assert (
        value.control.operation(value.job_id)["job"]["progress"]["verified_observation"]
        == value.proof
    )


def test_historical_complete_outcome_does_not_fabricate_proof_from_job_progress(saved_reads):
    value = saved_reads
    record = {
        **value.finish_args["outcome"],
        "control_digest": content_hash(value.finish_args["control"]),
    }
    with value.store._connection(write=True) as connection:
        connection.execute(
            "INSERT INTO file_access_outcomes(job_id,document_json,document_digest) VALUES(?,?,?)",
            (value.job_id, canonical_json(record), content_hash(record)),
        )
    value.store.transition_job(
        value.job_id, "failed", progress={"verified_observation": value.proof}
    )
    reopen(value)
    response = value.control.operation(value.job_id)
    assert response["reconciliation"]["state"] == "complete"
    assert "verified_observation" not in response["job"]["progress"]
