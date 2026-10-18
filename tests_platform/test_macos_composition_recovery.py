"""Explicit recovery is limited to the original live zero-dispatch close authority."""

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from types import SimpleNamespace

import pytest

from bluefire import composition_jobs as composition_jobs_module
from bluefire.capability_packs import MACOS_FILE_ACCESS_PACK
from bluefire.composition_jobs import CompositionJobs
from bluefire.product_store_errors import ProductStoreError

OWNER = "job-" + "a" * 32
JOB = "job-" + "b" * 32
ATTEMPT = "attempt-" + "c" * 32
RUN = "run-20261018T120000Z-" + "d" * 16
LEASE_DIGEST = "sha256:" + "e" * 64
COMPILED_DIGEST = "sha256:" + "f" * 64


class _Cursor:
    def __init__(self, rows=()):
        self.rows = rows

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return None


class _Connection:
    def __init__(self, store):
        self.store = store

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, _query, _params=()):
        if "capability_task_terminals" in _query:
            row = self.store.terminals.get(_params[0])
            return _Cursor([row] if row is not None else [])
        return _Cursor(self.store.event_rows)


class _Store:
    def __init__(self):
        marker = {
            "parent_job_id": OWNER,
            "attempt_id": ATTEMPT,
            "run_id": RUN,
            "compiled_digest": COMPILED_DIGEST,
        }
        self.jobs = {
            OWNER: {"job_id": OWNER, "kind": "composition.objective", "progress": {}},
            JOB: {
                "job_id": JOB,
                "kind": "composition.attempt",
                "request": {"composition_attempt": marker},
                "progress": {"settlement": "pending_cleanup"},
            },
        }
        self.event_rows = []
        self._macos_workspace_pid = os.getpid()
        self._macos_attempt_workspaces = {}
        self.released = []
        self.closed = False
        self.tasks = []
        self.terminals = {}
        self.receipts = {}

    def get_job(self, job_id):
        return self.jobs[job_id]

    def list_jobs(self):
        return list(self.jobs.values())

    def _connection(self):
        return _Connection(self)

    def get_capability_attempt(self, _attempt_id):
        return {
            "tasks": self.tasks,
            "compiled": {"macos_file_access": {"attempt_id": ATTEMPT}},
            "lease": {"run_id": RUN, "compiled_digest": COMPILED_DIGEST},
        }

    def record_capability_task_terminal(self, task_id, *, request_hash, terminal_digest):
        self.terminals[task_id] = {
            "attempt_id": ATTEMPT,
            "request_hash": request_hash,
            "terminal_digest": terminal_digest,
        }

    def record_macos_capability_terminal(self, task_id, *, result):
        task = next(row for row in self.tasks if row["task_id"] == task_id)
        self.receipts[task["step_id"]] = {
            "task_id": task_id,
            "state": "not_sent",
            "terminal_digest": self.terminals[task_id]["terminal_digest"],
        }

    def get_macos_capability_closure(self, _attempt_id):
        if not self.closed:
            raise ProductStoreError("closure absent")
        return {"attempt_id": ATTEMPT}

    def release_macos_attempt_workspace(self, attempt_id):
        self.released.append(attempt_id)
        self._macos_attempt_workspaces.pop(attempt_id, None)


class _Guard:
    _pid = os.getpid()
    _attempt_id = ATTEMPT
    _lease_digest = LEASE_DIGEST
    _compiled_digest = COMPILED_DIGEST


def _jobs(monkeypatch):
    from bluefire import macos_attempt_workspace

    monkeypatch.setattr(macos_attempt_workspace, "MacOSAttemptWorkspaceGuard", _Guard)
    store = _Store()
    jobs = CompositionJobs(SimpleNamespace(product_store=store, job_controller=object()))
    jobs._publish = lambda job_id, values: store.jobs[job_id]["progress"].update(values)
    return jobs, store


def _retained(jobs, store, orchestrator):
    store._macos_attempt_workspaces[ATTEMPT] = _Guard()
    jobs._macos_recoveries[ATTEMPT] = {
        "owner_id": OWNER,
        "job_id": JOB,
        "marker": {
            "parent_job_id": OWNER,
            "attempt_id": ATTEMPT,
            "run_id": RUN,
            "compiled_digest": COMPILED_DIGEST,
        },
        "lease": {"attempt_id": ATTEMPT, "lease_digest": LEASE_DIGEST},
        "orchestrator": orchestrator,
        "context": {},
    }


def test_retained_guard_allows_only_explicit_idempotent_close(monkeypatch):
    jobs, store = _jobs(monkeypatch)

    class CloseOnly:
        _macos_close_attempted = True

        def _attempt_emergency_cleanup(self, **context):
            assert context == {}
            self.calls += 1
            store.closed = True

        calls = 0

    close_only = CloseOnly()
    _retained(jobs, store, close_only)

    def settle(_marker, job_id, _lease, _run, _cleanup):
        store.jobs[job_id]["progress"]["settlement"] = "settled"

    jobs._settle_attempt = settle
    first = jobs.recover_macos_attempt(OWNER, ATTEMPT)
    second = jobs.recover_macos_attempt(OWNER, ATTEMPT)

    assert first["attempts"][0]["progress"]["macos_recovery"]["state"] == "closed"
    assert second["attempts"][0]["progress"]["macos_recovery"]["state"] == "closed"
    assert close_only.calls == 1
    assert store.released == [ATTEMPT]


def test_concurrent_recovery_preserves_first_terminal_result(monkeypatch):
    jobs, store = _jobs(monkeypatch)
    close_started = threading.Event()
    allow_close = threading.Event()
    second_waiting = threading.Event()
    child_barrier = threading.Barrier(2)
    child_calls = 0
    child_calls_lock = threading.Lock()

    class TrackingLock:
        def __init__(self):
            self.lock = threading.Lock()
            self.calls = 0

        def __enter__(self):
            self.calls += 1
            if self.calls == 2:
                second_waiting.set()
            self.lock.acquire()
            return self

        def __exit__(self, *_args):
            self.lock.release()

    jobs._macos_recovery_lock = TrackingLock()
    original_children = jobs._children

    def synchronized_children(owner_id):
        nonlocal child_calls
        with child_calls_lock:
            child_calls += 1
            synchronize = child_calls <= 2
        rows = deepcopy(original_children(owner_id))
        if synchronize:
            child_barrier.wait(timeout=3)
        return rows

    jobs._children = synchronized_children

    class CloseOnly:
        _macos_close_attempted = True

        def _attempt_emergency_cleanup(self, **_context):
            close_started.set()
            assert allow_close.wait(3)
            store.closed = True

    _retained(jobs, store, CloseOnly())
    jobs._settle_attempt = lambda _marker, job_id, _lease, _run, _cleanup: store.jobs[job_id][
        "progress"
    ].update(settlement="settled")

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(jobs.recover_macos_attempt, OWNER, ATTEMPT)
        second = pool.submit(jobs.recover_macos_attempt, OWNER, ATTEMPT)
        assert close_started.wait(3)
        assert second_waiting.wait(3)
        allow_close.set()
        results = [first.result(timeout=3), second.result(timeout=3)]

    assert [result["attempts"][0]["progress"]["macos_recovery"]["state"] for result in results] == [
        "closed",
        "closed",
    ]
    assert store.jobs[JOB]["progress"]["macos_recovery"]["state"] == "closed"


def test_retention_publish_is_serialized_with_recovery(monkeypatch):
    jobs, store = _jobs(monkeypatch)
    store._macos_attempt_workspaces[ATTEMPT] = _Guard()
    available_started = threading.Event()
    allow_available_publish = threading.Event()
    recovery_waiting = threading.Event()

    class TrackingLock:
        def __init__(self):
            self.lock = threading.Lock()
            self.calls = 0

        def __enter__(self):
            self.calls += 1
            if self.calls == 2:
                recovery_waiting.set()
            self.lock.acquire()
            return self

        def __exit__(self, *_args):
            self.lock.release()

    jobs._macos_recovery_lock = TrackingLock()
    original_publish = jobs._publish

    def publish(job_id, values):
        recovery = values.get("macos_recovery")
        if recovery is not None and recovery.get("state") == "available":
            available_started.set()
            assert allow_available_publish.wait(3)
        original_publish(job_id, values)

    jobs._publish = publish
    jobs._settle_attempt = lambda _marker, job_id, _lease, _run, _cleanup: store.jobs[job_id][
        "progress"
    ].update(settlement="settled")

    marker = {
        "parent_job_id": OWNER,
        "attempt_id": ATTEMPT,
        "run_id": RUN,
        "compiled_digest": COMPILED_DIGEST,
    }

    class CloseOnly:
        _macos_recovery_context = {"run_id": RUN}

        def _attempt_emergency_cleanup(self, **_context):
            store.closed = True

    orchestrator = CloseOnly()

    with ThreadPoolExecutor(max_workers=2) as pool:
        retaining = pool.submit(
            jobs._retain_macos_close_recovery,
            ATTEMPT,
            marker,
            JOB,
            {"attempt_id": ATTEMPT, "lease_digest": LEASE_DIGEST},
            orchestrator,
        )
        assert available_started.wait(3)
        recovery = pool.submit(jobs.recover_macos_attempt, OWNER, ATTEMPT)
        assert recovery_waiting.wait(3)
        allow_available_publish.set()
        assert retaining.result(timeout=3)
        result = recovery.result(timeout=3)

    assert result["attempts"][0]["progress"]["macos_recovery"]["state"] == "closed"
    assert store.jobs[JOB]["progress"]["macos_recovery"]["state"] == "closed"
    assert store.released == [ATTEMPT]


def test_lost_original_guard_reports_unavailable_without_re_adoption(monkeypatch):
    jobs, store = _jobs(monkeypatch)
    result = jobs.recover_macos_attempt(OWNER, ATTEMPT)
    assert result["attempts"][0]["progress"]["macos_recovery"] == {
        "state": "unavailable",
        "reason": "original_process_authority_unavailable",
    }
    assert not store.released


def test_cleanup_only_window_is_rejected_before_creator_or_attempt_reservations(monkeypatch):
    started_ns = 5_000_000_000
    reservation = {"reserved_attempt_ms": 10_000, "cleanup_reserve_ms": 2_000}
    charges = []
    durable_attempts = []
    store = SimpleNamespace(
        reserve_capability_attempt=lambda *args, **kwargs: durable_attempts.append((args, kwargs))
    )
    jobs = CompositionJobs(
        SimpleNamespace(product_store=store, job_controller=object()), clock=lambda: 1_000
    )
    current = {
        "macos_file_access_binding": SimpleNamespace(
            to_dict=lambda: {"original_deadline_ns": started_ns + 2_000_000_000}
        ),
        "runner": SimpleNamespace(
            reserve_composition_probe_budget=lambda **kwargs: charges.append(kwargs)
        ),
        "current_environment": {},
        "profile": object(),
    }
    grant = {"expires_at_ms": 100_000, "grant_id": "grant", "grant_digest": "digest"}
    jobs._owner = lambda _owner_id: {"job_id": OWNER}
    jobs._current = lambda _owner: (grant, current)
    jobs._orchestrator = lambda _current: SimpleNamespace(
        planner=SimpleNamespace(
            compile=lambda *_args, **_kwargs: SimpleNamespace(to_dict=lambda: {})
        )
    )
    monkeypatch.setattr(
        composition_jobs_module, "grant_pack", lambda _grant: MACOS_FILE_ACCESS_PACK
    )
    monkeypatch.setattr(
        composition_jobs_module.ScenarioDefinition,
        "from_mapping",
        staticmethod(lambda _value: object()),
    )
    monkeypatch.setattr(composition_jobs_module, "native_envelope", lambda _plan, _compiled: {})
    from bluefire import macos_file_access_peer

    monkeypatch.setattr(macos_file_access_peer, "darwin_clock_ns", lambda: started_ns)
    compiled = {
        "scenario": {},
        "action_implementations": {},
        "reservation": reservation,
    }
    request = {
        "composition_attempt": {
            "parent_job_id": OWNER,
            "attempt_id": ATTEMPT,
            "compiled_digest": COMPILED_DIGEST,
        }
    }

    with pytest.raises(ProductStoreError, match="no business window"):
        jobs._execute(SimpleNamespace(job_id=JOB), request, compiled)

    assert charges == []
    assert durable_attempts == []


def test_retention_requires_pending_zero_dispatch_and_original_run_context(monkeypatch):
    jobs, store = _jobs(monkeypatch)
    store._macos_attempt_workspaces[ATTEMPT] = _Guard()
    orchestrator = SimpleNamespace(
        _macos_recovery_context={"run_id": RUN},
    )
    marker = {
        "parent_job_id": OWNER,
        "attempt_id": ATTEMPT,
        "run_id": RUN,
        "compiled_digest": COMPILED_DIGEST,
    }

    assert jobs._retain_macos_close_recovery(
        ATTEMPT, marker, JOB, {"attempt_id": ATTEMPT, "lease_digest": LEASE_DIGEST}, orchestrator
    )
    assert ATTEMPT in jobs._macos_recoveries
    assert not store.released

    store.event_rows = [{"event_type": "dispatch", "event_key": "task"}]
    assert not jobs._retain_macos_close_recovery(
        ATTEMPT, marker, JOB, {"attempt_id": ATTEMPT, "lease_digest": LEASE_DIGEST}, orchestrator
    )


def test_dispatch_marker_refuses_recovery_and_releases_guard(monkeypatch):
    jobs, store = _jobs(monkeypatch)

    class NeverClose:
        def _attempt_emergency_cleanup(self, **_context):
            raise AssertionError("dispatch evidence must prevent close recovery")

    _retained(jobs, store, NeverClose())
    store.event_rows = [{"event_type": "dispatch", "event_key": "business-task"}]

    result = jobs.recover_macos_attempt(OWNER, ATTEMPT)
    assert result["attempts"][0]["progress"]["macos_recovery"]["reason"] == (
        "dispatch_or_original_guard_changed"
    )
    assert store.released == [ATTEMPT]
    assert ATTEMPT not in jobs._macos_recoveries


def test_recovery_records_registered_undispatched_task_before_close(monkeypatch):
    from bluefire import product_store_macos_composition as journal

    jobs, store = _jobs(monkeypatch)
    store.tasks = [
        {"task_id": "task-original", "step_id": "probe", "request_hash": "sha256:" + "e" * 64}
    ]
    monkeypatch.setattr(
        journal,
        "_event",
        lambda _connection, _attempt, event_type, event_key: (
            store.receipts.get(event_key) if event_type == "receipt" else None
        ),
    )

    class CloseOnly:
        _macos_close_attempted = True
        calls = 0

        def _attempt_emergency_cleanup(self, **_context):
            assert store.receipts["probe"]["state"] == "not_sent"
            assert "task-original" in store.terminals
            self.calls += 1
            store.closed = True

    close_only = CloseOnly()
    _retained(jobs, store, close_only)
    jobs._settle_attempt = lambda _marker, job_id, _lease, _run, _cleanup: store.jobs[job_id][
        "progress"
    ].update(settlement="settled")

    jobs.recover_macos_attempt(OWNER, ATTEMPT)

    assert store.receipts["probe"]["task_id"] == "task-original"
    assert close_only.calls == 1
