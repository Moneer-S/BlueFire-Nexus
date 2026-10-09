"""Pure worker-closure recovery checks without a probe socket or native process."""

import json
import sqlite3
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from bluefire import composition_file_access, file_access_closure, file_access_recovery
from bluefire.capability_packs import FILE_ACCESS_METHODS
from bluefire.product_store_errors import ProductStoreError
from bluefire.util import content_hash
from tests_platform.file_access_fixtures import binding, observation


@pytest.mark.parametrize("native", ["failed", "cancelled"])
def test_native_terminal_alone_never_closes_worker(monkeypatch, native):
    bound = binding()
    recorded, queried = [], []
    task = {
        "task_id": "execute-authored",
        "request_hash": "sha256:" + "8" * 64,
        "manifest": {
            "action_id": FILE_ACCESS_METHODS[0],
            "requested_at": "1970-01-01T00:16:39Z",
            "expires_at": "1970-01-01T00:30:00Z",
        },
        "runner_profile": {"file_access_binding": bound},
    }
    control = SimpleNamespace(
        clock=lambda: 1_000_000,
        store=SimpleNamespace(
            record_file_access_worker_closure=lambda *args, **kwargs: recorded.append(kwargs)
        ),
    )
    result = (
        {"status": "failed"}
        if native == "failed"
        else {
            "schema_version": "bluefire.authenticated-task-cancelled.v1",
            "control_cleanup_verified": True,
        }
    )

    def unavailable(verified, *, request_hash):
        queried.append((verified.to_dict(), request_hash))
        raise ProductStoreError("Original worker cache entry unavailable")

    monkeypatch.setattr(file_access_recovery, "recover_file_access_closure", unavailable)
    with pytest.raises(ProductStoreError):
        file_access_recovery.close_worker(control, task, result)
    assert queried == [(bound, task["request_hash"])]
    assert recorded == []


def test_authenticated_observation_and_unsent_are_distinct_closures(monkeypatch):
    bound = binding()
    recorded = []
    task = {
        "task_id": "execute-authored",
        "request_hash": "sha256:" + "8" * 64,
        "manifest": {
            "action_id": FILE_ACCESS_METHODS[0],
            "requested_at": "1970-01-01T00:16:39Z",
            "expires_at": "1970-01-01T00:30:00Z",
        },
        "runner_profile": {"file_access_binding": bound},
    }
    control = SimpleNamespace(
        clock=lambda: 1_000_000,
        store=SimpleNamespace(
            record_file_access_worker_closure=lambda *args, **kwargs: recorded.append(kwargs)
        ),
    )
    monkeypatch.setattr(
        file_access_recovery,
        "recover_file_access_closure",
        lambda *args, **kwargs: pytest.fail(
            "successful authenticated observation must not dispatch a second read"
        ),
    )
    file_access_recovery.close_worker(
        control, task, {"status": "success", "output": {"observation": observation(bound)}}
    )
    assert recorded[-1]["proof"]["state"] == "verified_closed"
    file_access_recovery.close_worker(
        control,
        task,
        {
            "schema_version": "bluefire.task-not-sent.v1",
            "task_id": task["task_id"],
            "request_hash": task["request_hash"],
        },
    )
    assert recorded[-1]["proof"]["state"] == "not_sent"


@pytest.fixture
def composition(monkeypatch):
    from bluefire import product_store_capability_dependencies as dependencies
    from bluefire import product_store_capability_grants as grants

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        "CREATE TABLE capability_task_claims(task_id TEXT, attempt_id TEXT, step_id TEXT, request_hash TEXT)"
    )
    connection.execute(
        "CREATE TABLE capability_task_terminals(task_id TEXT, document_json TEXT, document_digest TEXT)"
    )
    connection.execute("CREATE TABLE capability_file_access_terminals(task_id TEXT)")
    bound = binding()
    control = {"binding": bound}
    compiled = {
        "file_access": {
            "control_owner_id": "owner-authored",
            "control_revision": 1,
            "control_digest": content_hash(control),
            "probe_step_id": "probe",
            "owner_step_id": "owner",
        }
    }
    monkeypatch.setattr(grants, "_attempt_at", lambda *args: (None, {}, compiled))
    monkeypatch.setattr(
        dependencies, "dependency_at", lambda *args: {"binding_digest": content_hash(bound)}
    )

    @contextmanager
    def opened():
        yield connection

    recorded, queried = [], []

    def closure(verified, *, request_hash):
        queried.append((verified.to_dict(), request_hash))
        return {"authored_worker_closure": request_hash}

    monkeypatch.setattr(file_access_closure, "recover_file_access_closure", closure)
    store = SimpleNamespace(
        _connection=opened,
        get_file_access_control_revision=lambda *args: {
            "document": control,
            "document_digest": content_hash(control),
        },
        record_capability_file_access_terminal=lambda *args, **kwargs: recorded.append(kwargs),
    )
    jobs = SimpleNamespace(store=store, clock=lambda: 1_000_000)
    yield SimpleNamespace(
        connection=connection, jobs=jobs, recorded=recorded, queried=queried, bound=bound
    )
    connection.close()


def add_task(composition, reader, *, terminal=True):
    task_id = "task-" + reader
    request_hash = content_hash(reader)
    composition.connection.execute(
        "INSERT INTO capability_task_claims VALUES(?,?,?,?)",
        (task_id, "attempt-authored", reader, request_hash),
    )
    if terminal:
        document = {
            "task_id": task_id,
            "request_hash": request_hash,
            "terminal_digest": content_hash("native terminal " + reader),
        }
        composition.connection.execute(
            "INSERT INTO capability_task_terminals VALUES(?,?,?)",
            (task_id, json.dumps(document), content_hash(document)),
        )
    return task_id, request_hash


def test_composition_recovers_only_original_request_after_native_terminals(composition):
    add_task(composition, "owner")
    probe_id, probe_hash = add_task(composition, "probe")
    composition_file_access.recover_requests(composition.jobs, "attempt-authored")
    assert composition.queried == [(composition.bound, probe_hash)]
    assert {row["task_id"] for row in composition.recorded} == {probe_id, "task-owner"}
    assert all(row["proof"]["state"] == "verified_closed" for row in composition.recorded)


def test_composition_unknown_native_terminal_prevents_closure_settlement(composition):
    add_task(composition, "probe", terminal=False)
    with pytest.raises(ProductStoreError):
        composition_file_access.recover_requests(composition.jobs, "attempt-authored")
    assert composition.queried == composition.recorded == []


def test_composition_cannot_recover_foreign_business_step(composition):
    add_task(composition, "foreign")
    with pytest.raises(ProductStoreError, match="unexpected business"):
        composition_file_access.recover_requests(composition.jobs, "attempt-authored")
    assert composition.queried == composition.recorded == []
