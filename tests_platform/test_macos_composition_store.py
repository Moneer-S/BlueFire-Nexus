"""Focused SQLite checks for the append-only Darwin attempt journal."""

import sqlite3
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from bluefire import macos_file_access_method as method
from bluefire import product_store_macos_composition as macos_store
from bluefire.contracts import ScenarioStep
from bluefire.product_store_errors import ProductStoreError
from bluefire.product_store_serialization import canonical_json
from bluefire.util import content_hash
from tests_platform import test_macos_file_access_composition_bridge as bridge_cases

creator_fake = bridge_cases.creator_fake
original = bridge_cases.original
attempt = bridge_cases.attempt


@pytest.fixture
def journal():
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("CREATE TABLE capability_attempts(attempt_id TEXT PRIMARY KEY)")
    connection.execute(
        "CREATE TABLE capability_task_claims("
        "task_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL, step_id TEXT NOT NULL, "
        "request_hash TEXT NOT NULL)"
    )
    connection.execute(
        "CREATE TABLE capability_task_terminals("
        "task_id TEXT PRIMARY KEY, document_json TEXT NOT NULL, document_digest TEXT NOT NULL)"
    )
    connection.execute("BEGIN")
    macos_store.initialize_schema(connection)
    connection.commit()
    connection.execute("BEGIN")
    connection.execute("INSERT INTO capability_attempts VALUES(?)", ("attempt-a",))
    reservation = {
        "schema_version": macos_store._ATTEMPT_SCHEMA,
        "attempt_id": "attempt-a",
        "probe_step_id": "probe",
        "owner_step_id": "verify_owner",
        "cleanup_step_id": "close_attempt",
    }
    connection.execute(
        "INSERT INTO capability_macos_file_access_attempts VALUES(?,?,?)",
        ("attempt-a", canonical_json(reservation), content_hash(reservation)),
    )
    yield connection
    connection.close()


def _receipt(connection, *, task_id, step_id, state="complete", budget=5):
    request_hash = content_hash(task_id)
    connection.execute(
        "INSERT INTO capability_task_claims VALUES(?,?,?,?)",
        (task_id, "attempt-a", step_id, request_hash),
    )
    terminal = {
        "task_id": task_id,
        "attempt_id": "attempt-a",
        "request_hash": request_hash,
        "terminal_digest": content_hash("terminal:" + task_id),
    }
    connection.execute(
        "INSERT INTO capability_task_terminals VALUES(?,?,?)",
        (task_id, canonical_json(terminal), content_hash(terminal)),
    )
    macos_store._append(
        connection,
        "capability_macos_file_access_events",
        "attempt-a",
        "receipt",
        step_id,
        {
            "task_id": task_id,
            "transport_request_hash": content_hash("transport:" + task_id),
            "terminal_digest": terminal["terminal_digest"],
            "state": state,
            "native_receipt_digest": (
                content_hash("native:" + task_id) if state == "complete" else None
            ),
            "shared_request_budget_used": budget if state == "complete" else None,
        },
    )


def test_darwin_journal_rows_are_append_only(journal):
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        journal.execute(
            "UPDATE capability_macos_file_access_attempts SET document_json='{}' "
            "WHERE attempt_id='attempt-a'"
        )
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        journal.execute(
            "DELETE FROM capability_macos_file_access_attempts WHERE attempt_id='attempt-a'"
        )


def test_attempt_closure_accepts_probe_only_or_both_exact_business_terminals(journal):
    _receipt(journal, task_id="task-probe", step_id="probe")
    reservation = {
        "probe_step_id": "probe",
        "owner_step_id": "verify_owner",
        "cleanup_step_id": "close_attempt",
    }
    rows = macos_store._task_closures(journal, "attempt-a", reservation)
    assert [row["task_id"] for row in rows] == ["task-probe"]

    _receipt(journal, task_id="task-owner", step_id="verify_owner")
    rows = macos_store._task_closures(journal, "attempt-a", reservation)
    assert [row["task_id"] for row in rows] == ["task-probe", "task-owner"]
    assert all(row["state"] == "complete" for row in rows)


@pytest.mark.parametrize("attempt", [{"prior_used": 3}], indirect=True)
def test_zero_business_tasks_allow_original_no_effect_closure_without_fabricated_probe(
    journal, attempt
):
    reservation = {
        "probe_step_id": "probe",
        "owner_step_id": "verify_owner",
        "cleanup_step_id": "close_attempt",
    }
    assert macos_store._task_closures(journal, "attempt-a", reservation) == []
    journal.execute(
        "INSERT INTO capability_task_claims VALUES(?,?,?,?)",
        ("task-close", "attempt-a", "close_attempt", content_hash("close")),
    )
    assert macos_store._task_closures(journal, "attempt-a", reservation) == []
    closure = attempt.dispatch(attempt.frame("close_attempt"))
    assert closure["task_closures"] == [] and not attempt.state["calls"]
    assert closure["shared_request_budget_used"] == 5
    macos_store._validate_closure_budget(journal, "attempt-a", reservation, closure)


def test_not_sent_probe_cannot_authorize_owner_task(journal):
    _receipt(journal, task_id="task-probe", step_id="probe", state="not_sent")
    _receipt(journal, task_id="task-owner", step_id="verify_owner")
    with pytest.raises(ProductStoreError, match="completed original probe"):
        macos_store._task_closures(
            journal,
            "attempt-a",
            {
                "probe_step_id": "probe",
                "owner_step_id": "verify_owner",
                "cleanup_step_id": "close_attempt",
            },
        )


def test_unknown_dispatch_cannot_become_a_closed_task(journal):
    _receipt(journal, task_id="task-probe", step_id="probe", state="unknown")
    with pytest.raises(ProductStoreError, match="Unknown Darwin dispatch"):
        macos_store._task_closures(
            journal,
            "attempt-a",
            {
                "probe_step_id": "probe",
                "owner_step_id": "verify_owner",
                "cleanup_step_id": "close_attempt",
            },
        )


def test_owner_without_registered_probe_still_cannot_close(journal):
    _receipt(journal, task_id="task-owner", step_id="verify_owner")
    with pytest.raises(ProductStoreError, match="completed original probe"):
        macos_store._task_closures(
            journal,
            "attempt-a",
            {
                "probe_step_id": "probe",
                "owner_step_id": "verify_owner",
                "cleanup_step_id": "close_attempt",
            },
        )


def compiled_graph():
    steps = [
        ScenarioStep(step, action)
        for step, action in zip(("probe", "owner", "close"), method.METHODS, strict=True)
    ]
    return {
        "scenario": {"steps": [step.to_dict() for step in steps]},
        "action_implementations": {step.id: step.behavior_id for step in steps},
    }


def test_real_compiled_scenario_steps_join_exact_separate_action_implementations():
    compiled = compiled_graph()
    assert all("action_id" not in step for step in compiled["scenario"]["steps"])
    assert macos_store._step_actions(compiled) == compiled["action_implementations"]


@pytest.mark.parametrize("change", ["missing", "mismatch", "extra", "duplicate", "native"])
def test_compiled_step_implementation_join_refuses_changed_or_mixed_graph(change):
    compiled = compiled_graph()
    if change == "missing":
        del compiled["action_implementations"]
    elif change == "mismatch":
        compiled["action_implementations"]["probe"] = method.OWNER_ACTION
    elif change == "extra":
        compiled["action_implementations"]["extra"] = method.PROBE_ACTION
    elif change == "duplicate":
        compiled["scenario"]["steps"].append(compiled["scenario"]["steps"][0])
    else:
        compiled["scenario"]["steps"][0]["behavior_id"] = "sandbox.fixture.create.v1"
        compiled["action_implementations"]["probe"] = "sandbox.fixture.create.v1"
    with pytest.raises(ProductStoreError):
        macos_store._step_actions(compiled)


@pytest.mark.parametrize("owner_read", [False, True])
@pytest.mark.parametrize("attempt", [{"prior_used": 3}], indirect=True)
def test_closure_receipts_preserve_the_exact_prepaid_budget(journal, attempt, owner_read):
    probe = attempt.dispatch(attempt.frame())
    _receipt(
        journal, task_id="task-probe", step_id="probe", budget=probe["shared_request_budget_used"]
    )
    if owner_read:
        owner = attempt.dispatch(attempt.frame("verify_owner"))
        _receipt(
            journal,
            task_id="task-owner",
            step_id="verify_owner",
            budget=owner["shared_request_budget_used"],
        )
    closure = attempt.dispatch(attempt.frame("close_attempt"))
    assert closure["shared_request_budget_used"] == attempt.producer._used_budget == 5
    reservation = {"probe_step_id": "probe", "owner_step_id": "verify_owner"}
    macos_store._validate_closure_budget(journal, "attempt-a", reservation, closure)


@pytest.mark.parametrize("changed", [4, 6])
def test_closure_cannot_change_cumulative_authenticated_native_budget(journal, changed):
    _receipt(journal, task_id="task-probe", step_id="probe", budget=5)
    with pytest.raises(ProductStoreError, match="cumulative request budget"):
        macos_store._validate_closure_budget(
            journal,
            "attempt-a",
            {"probe_step_id": "probe", "owner_step_id": "verify_owner"},
            {"shared_request_budget_used": changed},
        )


def test_no_native_receipt_preserves_bounded_parent_counter_without_inventing_zero(journal):
    _receipt(journal, task_id="task-probe", step_id="probe", state="not_sent")
    reservation = {"probe_step_id": "probe", "owner_step_id": "verify_owner"}
    macos_store._validate_closure_budget(
        journal, "attempt-a", reservation, {"shared_request_budget_used": 11}
    )
    with pytest.raises(ProductStoreError, match="cumulative budget"):
        macos_store._validate_closure_budget(
            journal, "attempt-a", reservation, {"shared_request_budget_used": 65}
        )


@pytest.fixture
def terminal_journal(journal, attempt, monkeypatch):
    """Use actual producer receipts and a real transaction around journal writes."""
    clock = {"wall": attempt.state["wall"], "monotonic": attempt.state["clock"]}
    monkeypatch.setattr(
        macos_store, "_acceptance_clock", lambda: (clock["wall"], clock["monotonic"])
    )

    class Store:
        @contextmanager
        def _connection(self, write=False):
            with journal:
                yield journal

    def make(operation="probe", *, unknown=False):
        operations = (
            ("probe",) if operation == "probe" else ("probe", "verify_owner", "close_attempt")
        )
        frames, results = {}, {}
        for current in operations:
            frame = attempt.frame(current)
            if current == "close_attempt":
                by_task = {value["intent"]["task_id"]: key for key, value in frames.items()}
                frame["attempt"]["task_closures"].sort(
                    key=lambda row: frames[by_task[row["task_id"]]]["claim"]["step_id"]
                )
                bridge_cases.rehash(frame)
            native = attempt.dispatch(frame)
            output = (
                {"attempt_closure": native}
                if current == "close_attempt"
                else {
                    "macos_receipt": native,
                    "observation": method.observation(frame, native, observed_at_ms=clock["wall"]),
                }
            )
            if unknown:
                native["state"] = "unknown"
                native["dispatch"] = "attempted"
                output["observation"] = None
            frames[current] = frame
            results[current] = {
                "request_hash": frame["claim"]["request_hash"],
                "status": "error" if unknown else "success",
                "output": output,
            }
        target = frames[operation]
        attempt_id = attempt.base["attempt_id"]
        journal.execute("INSERT INTO capability_attempts VALUES(?)", (attempt_id,))
        journal.execute(
            "INSERT INTO capability_macos_file_access_attempts VALUES(?,?,?)",
            (attempt_id, canonical_json(target["attempt"]), content_hash(target["attempt"])),
        )
        for current, frame in frames.items():
            task_id = frame["intent"]["task_id"]
            request_hash = frame["claim"]["request_hash"]
            journal.execute(
                "INSERT INTO capability_task_claims VALUES(?,?,?,?)",
                (task_id, attempt_id, frame["claim"]["step_id"], request_hash),
            )
            terminal = {
                "attempt_id": attempt_id,
                "request_hash": request_hash,
                "terminal_digest": content_hash(results[current]),
            }
            journal.execute(
                "INSERT INTO capability_task_terminals VALUES(?,?,?)",
                (task_id, canonical_json(terminal), content_hash(terminal)),
            )
            macos_store._append(
                journal,
                "capability_macos_file_access_events",
                attempt_id,
                "dispatch",
                task_id,
                {
                    "intent": frame["intent"],
                    "transport_request_hash": frame["intent"]["transport_request_hash"],
                },
            )
        if operation == "close_attempt":
            macos_store._append(
                journal,
                "capability_macos_file_access_events",
                attempt_id,
                "cleanup_claim",
                "close_attempt",
                {
                    "claim": target["attempt"]["cleanup_claim"],
                    "claim_digest": target["attempt"]["cleanup_claim_digest"],
                    "task_closures": target["attempt"]["task_closures"],
                },
            )
            macos_store._append(
                journal,
                "capability_macos_file_access_events",
                attempt_id,
                "workspace_pre_close",
                target["intent"]["task_id"],
                {"phase": "pre_close"},
            )
        journal.commit()
        store = Store()
        lease = {key: attempt.base[key] for key in ("run_id", "lease_digest", "compiled_digest")}
        by_task = {frame["intent"]["task_id"]: frame for frame in frames.values()}
        monkeypatch.setattr(macos_store.records, "_attempt_at", lambda *args: (None, lease, {}))
        monkeypatch.setattr(
            macos_store,
            "_payload_at",
            lambda store, connection, task, *args, **kwargs: by_task[task["task_id"]]["claim"],
        )
        monkeypatch.setattr(
            macos_store,
            "_mac_dependency",
            lambda compiled: {"control_revision": attempt.producer._revision},
        )
        monkeypatch.setattr(
            macos_store,
            "_original_macos_control",
            lambda *args: (
                None,
                None,
                target["claim"]["runner_profile"]["macos_file_access_binding"],
            ),
        )
        monkeypatch.setattr(
            macos_store.cleanup, "workspace_at", lambda *args: {"attempt_id": attempt_id}
        )
        monkeypatch.setattr(
            macos_store,
            "_verify_workspace_attestation",
            lambda *args: {"phase": args[-2], "state": "verified_empty", "entry_count": 0},
        )
        if operation == "close_attempt":
            for current in ("probe", "verify_owner"):
                macos_store.record_macos_capability_terminal(
                    store, frames[current]["intent"]["task_id"], result=results[current]
                )
        return SimpleNamespace(
            store=store,
            frame=target,
            result=results[operation],
            clock=clock,
            connection=journal,
            attempt_id=attempt_id,
        )

    return make


@pytest.mark.parametrize("attempt", [{"prior_used": 3}], indirect=True)
@pytest.mark.parametrize("operation", ["probe", "close_attempt"])
def test_stalled_wall_clock_during_success_journal_write_rolls_back_acceptance(
    terminal_journal, monkeypatch, operation
):
    current = terminal_journal(operation)
    original_append = macos_store._append
    event_type = "receipt" if operation == "probe" else "producer_closure"

    def delayed_append(connection, table, attempt_id, kind, key, document):
        value = original_append(connection, table, attempt_id, kind, key, document)
        if kind == event_type:
            current.clock["monotonic"] = current.frame["intent"]["deadline_ns"]
        return value

    monkeypatch.setattr(macos_store, "_append", delayed_append)
    task_id = current.frame["intent"]["task_id"]
    with pytest.raises(ProductStoreError, match="durable-success deadline"):
        macos_store.record_macos_capability_terminal(current.store, task_id, result=current.result)
    key = current.frame["claim"]["step_id"] if operation == "probe" else task_id
    assert macos_store._event(current.connection, current.attempt_id, event_type, key) is None
    assert current.connection.execute(
        "SELECT 1 FROM capability_task_terminals WHERE task_id=?", (task_id,)
    ).fetchone()


@pytest.mark.parametrize("attempt", [{"prior_used": 3}], indirect=True)
def test_final_closure_persists_full_post_inventory_in_same_bounded_transaction(terminal_journal):
    current = terminal_journal("close_attempt")
    task_id = current.frame["intent"]["task_id"]
    macos_store.record_macos_capability_terminal(current.store, task_id, result=current.result)
    settled = macos_store.close_macos_capability_attempt(
        current.store, current.attempt_id, cleanup_task_id=task_id, result=current.result
    )
    proof = macos_store._event(
        current.connection, current.attempt_id, "workspace_post_close", task_id
    )
    assert proof == {"phase": "post_close", "state": "verified_empty", "entry_count": 0}
    assert settled["workspace_attestation_digest"] == content_hash(proof)
    assert macos_store.get_macos_capability_closure(current.store, current.attempt_id) == settled


@pytest.mark.parametrize("attempt", [{"prior_used": 3}], indirect=True)
def test_stalled_final_inventory_write_cannot_commit_closure_after_original_cleanup_deadline(
    terminal_journal, monkeypatch
):
    current = terminal_journal("close_attempt")
    task_id = current.frame["intent"]["task_id"]
    macos_store.record_macos_capability_terminal(current.store, task_id, result=current.result)
    original_append = macos_store._append

    def delayed_append(connection, table, attempt_id, kind, key, document):
        value = original_append(connection, table, attempt_id, kind, key, document)
        if kind == "workspace_post_close":
            current.clock["monotonic"] = current.frame["attempt"]["cleanup_claim"]["deadline_ns"]
        return value

    monkeypatch.setattr(macos_store, "_append", delayed_append)
    with pytest.raises(ProductStoreError, match="durable-success deadline"):
        macos_store.close_macos_capability_attempt(
            current.store, current.attempt_id, cleanup_task_id=task_id, result=current.result
        )
    assert (
        macos_store._event(current.connection, current.attempt_id, "workspace_post_close", task_id)
        is None
    )
    assert (
        current.connection.execute(
            "SELECT 1 FROM capability_macos_file_access_closures WHERE attempt_id=?",
            (current.attempt_id,),
        ).fetchone()
        is None
    )


@pytest.mark.parametrize("attempt", [{"prior_used": 3}], indirect=True)
def test_unknown_terminal_can_remain_truthful_after_deadline_without_accepting_success(
    terminal_journal,
):
    current = terminal_journal(unknown=True)
    current.clock["monotonic"] = current.frame["intent"]["deadline_ns"]
    recorded = macos_store.record_macos_capability_terminal(
        current.store, current.frame["intent"]["task_id"], result=current.result
    )
    assert recorded["state"] == "unknown"
    assert recorded["shared_request_budget_used"] is None
