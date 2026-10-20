"""Historical Darwin settlement joins using pure documents and in-memory SQLite."""

import sqlite3
from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace

import pytest

from bluefire import macos_file_access_method as method
from bluefire import product_store_capability_grants as grants
from bluefire import product_store_macos_settlement as settlement
from bluefire.capability_packs import MACOS_FILE_ACCESS_PACK
from bluefire.execution_contracts import execution_task_identity
from bluefire.macos_file_access_contract import REQUEST_SCHEMA
from bluefire.macos_file_access_method import CLOSE_ACTION, CLOSURE_SCHEMA, PROBE_ACTION
from bluefire.product_store_capability_api import CapabilityStoreMixin
from bluefire.product_store_errors import ProductStoreError
from bluefire.product_store_serialization import canonical_json
from bluefire.util import content_hash
from tests_platform.test_macos_composition_store import compiled_graph
from tests_platform.test_macos_file_access_contract import observation
from tests_platform.test_macos_file_access_runner_contracts import build, profile_document


def test_real_macos_settlement_facade_returns_validated_document_and_preserves_forwarded_identity(
    monkeypatch,
):
    store = CapabilityStoreMixin()
    connection = object()
    attempt_id = "attempt-" + "a" * 32
    receipt = {"schema_version": settlement.SCHEMA, "attempt_id": attempt_id}
    validated = {**receipt, "lease_digest": content_hash("validated lease")}
    calls = []

    def validate(actual_store, actual_connection, actual_attempt_id, actual_receipt):
        assert actual_store is store and actual_connection is connection
        assert actual_attempt_id == attempt_id and actual_receipt is receipt
        calls.append((actual_store, actual_connection, actual_attempt_id, actual_receipt))
        return validated

    monkeypatch.setattr(settlement, "validate", validate)
    assert store._validate_macos_capability_settlement(connection, attempt_id, receipt) is validated
    assert len(calls) == 1


@pytest.fixture
def history(monkeypatch):
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    for table in ("capability_macos_file_access_attempts", "capability_macos_file_access_closures"):
        connection.execute(
            f"CREATE TABLE {table}(attempt_id TEXT PRIMARY KEY, document_json TEXT, document_digest TEXT)"
        )
    connection.execute(
        "CREATE TABLE capability_macos_file_access_events(attempt_id TEXT,event_type TEXT,event_key TEXT,document_json TEXT,document_digest TEXT)"
    )
    connection.execute(
        "CREATE TABLE capability_task_claims(task_id TEXT,attempt_id TEXT,step_id TEXT,request_hash TEXT)"
    )
    connection.execute(
        "CREATE TABLE capability_task_terminals(task_id TEXT,document_json TEXT,document_digest TEXT)"
    )
    for table in (
        "capability_cleanup_obligations",
        "capability_cleanup_claims",
        "capability_cleanup_task_claims",
    ):
        connection.execute(f"CREATE TABLE {table}(attempt_id TEXT)")
    profile = profile_document()
    binding = profile["macos_file_access_binding"]
    manifests = {"probe": build(PROBE_ACTION), "close": build(CLOSE_ACTION)}
    lease = {
        "attempt_id": "attempt-" + "1" * 32,
        "grant_id": "grant-" + "2" * 32,
        "grant_digest": content_hash("grant"),
        "lease_digest": content_hash("lease"),
        "compiled_digest": content_hash("compiled"),
        "job_id": "job-" + "3" * 32,
        "run_id": "run-1",
        "control_owner_id": "file-control-" + "4" * 64,
        "created_at_ms": 1000,
        "business_expires_at_ms": 7000,
        "attempt_expires_at_ms": 11500,
    }
    attempt_id = lease["attempt_id"]
    dependency = {
        "schema_version": "bluefire.macos-file-access-composition-dependency.v1",
        "probe_step_id": "probe",
        "owner_step_id": "owner",
        "cleanup_step_id": "close",
        "control_owner_id": lease["control_owner_id"],
        "control_digest": content_hash("control"),
        "resource_id": "file-resource-" + content_hash(binding["resource"])[7:39],
        "resource_generation": binding["generation"],
        "resource_digest": content_hash(binding["resource"]),
        "probe_enrollment_digest": content_hash("enrollment"),
        "baseline_digest": content_hash("baseline"),
        "control_revision": binding["control_revision"],
        "workspace_custody_digest": binding["custody_digest"],
        "binding_digest": content_hash(binding),
    }
    retained = {
        "schema_version": "bluefire.capability-macos-file-access-binding.v1",
        "attempt_id": attempt_id,
        "lease_digest": lease["lease_digest"],
        **{
            key: dependency[key]
            for key in (
                "binding_digest",
                "resource_generation",
                "control_revision",
                "resource_digest",
                "workspace_custody_digest",
            )
        },
    }
    compiled = {
        **compiled_graph(),
        "macos_file_access": dependency,
        "compiled_digest": lease["compiled_digest"],
    }
    workspace = {"workspace_path_digest": content_hash({"sandbox_root": profile["sandbox_root"]})}
    reservation = {
        "schema_version": "bluefire.macos-file-access-attempt-dispatch.v1",
        **{
            key: lease[key]
            for key in (
                "attempt_id",
                "grant_id",
                "grant_digest",
                "lease_digest",
                "compiled_digest",
                "job_id",
                "run_id",
                "control_owner_id",
            )
        },
        "workspace_binding_digest": content_hash(workspace),
        "dependency_digest": content_hash(retained),
        "probe_step_id": "probe",
        "owner_step_id": "owner",
        "cleanup_step_id": "close",
        "issued_at_ms": 1500,
        "business_expires_at_ms": 7000,
        "cleanup_expires_at_ms": 11500,
        "issued_monotonic_ns": 1000,
        "business_deadline_ns": 4_000_001_000,
        "cleanup_deadline_ns": 10_000_001_000,
        "primitive_budget": {"probe": 1, "verify_owner": 1, "total": 2},
    }
    payloads, dispatches, terminals = {}, {}, []

    def event(kind, key, document):
        connection.execute(
            "INSERT INTO capability_macos_file_access_events VALUES(?,?,?,?,?)",
            (attempt_id, kind, key, canonical_json(document), content_hash(document)),
        )

    for step, manifest in manifests.items():
        task_id, transport = execution_task_identity(manifest, profile)
        payloads[task_id] = {
            "manifest": manifest,
            "runner_profile": deepcopy(profile),
            "transport_request_hash": transport,
        }
        connection.execute(
            "INSERT INTO capability_task_claims VALUES(?,?,?,?)",
            (task_id, attempt_id, step, manifest["request_hash"]),
        )
        issued, started, expiry, deadline = (
            (2000, 1_000_001_000, 6000, 4_000_001_000)
            if step == "probe"
            else (7500, 6_000_001_000, 11500, 10_000_001_000)
        )
        operation = "probe" if step == "probe" else "close_attempt"
        intent = {
            "schema_version": "bluefire.macos-file-access-reviewed-task.v1",
            "operation": operation,
            "task_id": task_id,
            "transport_request_hash": transport,
            "context_digest": content_hash(operation),
            "binding_digest": content_hash(binding),
            "control_revision": binding["control_revision"],
            "issued_at_ms": issued,
            "expires_at_ms": expiry,
            "issued_monotonic_ns": started,
            "deadline_ns": deadline,
        }
        dispatches[step] = {
            "schema_version": "bluefire.macos-file-access-dispatch-marker.v1",
            "attempt_id": attempt_id,
            "task_id": task_id,
            "step_id": step,
            "request_hash": manifest["request_hash"],
            "transport_request_hash": transport,
            "operation": operation,
            "intent": intent,
            "creator_context_digest": intent["context_digest"],
            "marked_at_ms": issued,
            "marked_monotonic_ns": started,
        }
        event("dispatch", task_id, dispatches[step])
        terminal = {
            "schema_version": "bluefire.capability-task-terminal.v1",
            "task_id": task_id,
            "attempt_id": attempt_id,
            "request_hash": manifest["request_hash"],
            "terminal_digest": content_hash("terminal:" + task_id),
        }
        connection.execute(
            "INSERT INTO capability_task_terminals VALUES(?,?,?)",
            (task_id, canonical_json(terminal), content_hash(terminal)),
        )
        terminals.append(terminal)
    probe_task, close_task = dispatches["probe"]["task_id"], dispatches["close"]["task_id"]
    request = {
        "schema_version": REQUEST_SCHEMA,
        "binding": binding,
        "binding_digest": content_hash(binding),
        "request_id": "5" * 64,
        "sequence": 4,
        "operation": "read_reader",
        **{
            key: dispatches["probe"]["intent"][key]
            for key in ("issued_at_ms", "expires_at_ms", "issued_monotonic_ns", "deadline_ns")
        },
    }
    denied = observation(request, outcome="denied")
    denied.update(fresh_read=None, request_handle_cleanup="not_opened")
    native = {
        "schema_version": "bluefire.macos-file-access-task-receipt.v1",
        **{
            key: dispatches["probe"]["intent"][key]
            for key in (
                "task_id",
                "transport_request_hash",
                "context_digest",
                "binding_digest",
                "operation",
            )
        },
        "state": "complete",
        "dispatch": "attempted",
        "producer_request_usage": "settled",
        "settlement_scope": "producer_local_only",
        "original_workers": "retained",
        "namespace": "original_creator_held",
        "whole_enrollment_cleanup": False,
        "control_revision_before": 3,
        "control_revision_after": 3,
        "requests": [
            {
                **{key: request[key] for key in ("request_id", "sequence", "operation")},
                "request_digest": content_hash(request),
            }
        ],
        "terminals": [denied],
        "shared_request_budget_used": 5,
    }
    metadata = method.observation(
        {
            "attempt": {
                "attempt_id": attempt_id,
                "probe_task_id": probe_task,
                "probe_receipt_digest": None,
            },
            "claim": {
                "manifest": manifests["probe"],
                "runner_profile": profile,
                "step_id": "probe",
                "request_hash": manifests["probe"]["request_hash"],
            },
            "intent": dispatches["probe"]["intent"],
        },
        native,
        observed_at_ms=2000,
    )

    def runner_result(step, output):
        return {
            "schema_version": "bluefire.runner-result.v1",
            **{
                key: manifests[step][key]
                for key in (
                    "request_id",
                    "run_id",
                    "step_id",
                    "behavior_id",
                    "action_id",
                    "runner_id",
                    "runner_profile_id",
                    "request_hash",
                )
            },
            "platform": profile["platform"],
            "policy_digest": profile["policy_digest"],
            "status": "success",
            "output": output,
            "receipt_ids": [],
            "error": None,
        }

    def bind_terminal(index, result):
        terminals[index]["terminal_digest"] = content_hash(result)
        connection.execute(
            "UPDATE capability_task_terminals SET document_json=?,document_digest=? WHERE task_id=?",
            (
                canonical_json(terminals[index]),
                content_hash(terminals[index]),
                terminals[index]["task_id"],
            ),
        )

    probe_result = runner_result("probe", {"macos_receipt": native, "observation": metadata})
    bind_terminal(0, probe_result)
    row = {
        "task_id": probe_task,
        "transport_request_hash": dispatches["probe"]["transport_request_hash"],
        "request_hash": manifests["probe"]["request_hash"],
        "state": "complete",
        "native_receipt_digest": content_hash(native),
    }
    event(
        "receipt",
        "probe",
        {
            **row,
            "attempt_id": attempt_id,
            "step_id": "probe",
            "terminal_digest": terminals[0]["terminal_digest"],
            "observation_digest": content_hash(metadata),
            "shared_request_budget_used": 5,
            "result": probe_result,
        },
    )
    claim = manifests["close"]["macos_file_access_cleanup"]
    event(
        "cleanup_claim",
        "close_attempt",
        {"claim": claim, "claim_digest": content_hash(claim), "task_closures": [row]},
    )
    raw = {
        "schema_version": CLOSURE_SCHEMA,
        "attempt_id": attempt_id,
        "lease_digest": lease["lease_digest"],
        "compiled_digest": lease["compiled_digest"],
        "run_id": lease["run_id"],
        "binding_digest": content_hash(binding),
        "control_revision": binding["control_revision"],
        "cleanup_task_id": close_task,
        "cleanup_transport_request_hash": dispatches["close"]["transport_request_hash"],
        "cleanup_claim_digest": content_hash(claim),
        "task_closures": [row],
        "state": "closed",
        "producer_request_usage": "settled",
        "attempt_artifacts": "not_created",
        "original_workers": "retained",
        "namespace": "original_creator_held",
        "whole_enrollment_cleanup": False,
        "shared_request_budget_used": 5,
    }
    close_result = runner_result("close", {"attempt_closure": raw})
    bind_terminal(1, close_result)
    producer = {
        "schema_version": "bluefire.macos-file-access-producer-closure.v1",
        "attempt_id": attempt_id,
        "task_id": close_task,
        "terminal_digest": terminals[1]["terminal_digest"],
        "closure": raw,
        "closure_digest": content_hash(raw),
        "result": close_result,
    }
    event("producer_closure", close_task, producer)
    proofs = []
    for phase, kind, key in (
        ("reserve", "workspace_reserved", attempt_id),
        ("pre_close", "workspace_pre_close", close_task),
        ("post_close", "workspace_post_close", close_task),
    ):
        proof = {
            "schema_version": "bluefire.macos-file-access-empty-workspace.v1",
            "attempt_id": attempt_id,
            "lease_digest": lease["lease_digest"],
            "compiled_digest": lease["compiled_digest"],
            "workspace_path_digest": workspace["workspace_path_digest"],
            "workspace_identity_digest": content_hash("original-directory"),
            "phase": phase,
            "entry_count": 0,
            "state": "verified_empty",
        }
        event(kind, key, proof)
        proofs.append(proof)
    closure = {
        "schema_version": "bluefire.macos-file-access-settlement.v1",
        "attempt_id": attempt_id,
        "lease_digest": lease["lease_digest"],
        "compiled_digest": lease["compiled_digest"],
        "cleanup_task_id": close_task,
        "cleanup_claim_digest": content_hash(claim),
        "cleanup_dispatch_digest": content_hash(dispatches["close"]),
        "cleanup_terminal_digest": producer["terminal_digest"],
        "closure_digest": content_hash(raw),
        "workspace_attestation_digest": content_hash(proofs[2]),
        "pre_close_workspace_attestation_digest": content_hash(proofs[1]),
        "workspace_binding_digest": content_hash(workspace),
        "task_closures_digest": content_hash([row]),
        "artifact_state": "not_created",
        "producer_scope": "attempt_artifact_closure_only",
    }
    for table, document in (
        ("capability_macos_file_access_attempts", reservation),
        ("capability_macos_file_access_closures", closure),
    ):
        connection.execute(
            f"INSERT INTO {table} VALUES(?,?,?)",
            (attempt_id, canonical_json(document), content_hash(document)),
        )
    connection.commit()
    grant = {
        "schema_version": "bluefire.capability-grant.v2",
        "pack": MACOS_FILE_ACCESS_PACK,
        "snapshot": {"pack": MACOS_FILE_ACCESS_PACK},
    }
    for module in (settlement, grants):
        monkeypatch.setattr(module, "_attempt_at", lambda *args: (None, lease, compiled))
        monkeypatch.setattr(module, "_grant_at", lambda *args: (None, grant, None))
    monkeypatch.setattr(settlement, "_claim_at", lambda *args: (None, {}))
    monkeypatch.setattr(settlement, "dependency_at", lambda *args: retained)
    monkeypatch.setattr(settlement, "workspace_at", lambda *args: workspace)
    control_reads = []

    def original_control(connection, value):
        control_reads.append(deepcopy(value))
        return None, None, binding

    def payload_at(store, connection, task, *args, purpose):
        assert purpose == ("macos_cleanup" if task["step_id"] == "close" else "business")
        return deepcopy(payloads[task["task_id"]])

    monkeypatch.setattr(settlement.macos, "_original_macos_control", original_control)
    monkeypatch.setattr(settlement.macos, "_payload_at", payload_at)

    class Store:
        @contextmanager
        def _connection(self):
            yield connection

        def _validate_capability_dependency(self, *args):
            raise AssertionError("Mac settlement must not use native/Linux cleanup")

        def _validate_macos_capability_settlement(self, connection, attempt_id, receipt):
            return settlement.validate(self, connection, attempt_id, receipt)

    def rewrite_event(kind, key, mutate):
        document = settlement.macos._event(connection, attempt_id, kind, key)
        mutate(document)
        connection.execute(
            "UPDATE capability_macos_file_access_events SET document_json=?,document_digest=? WHERE event_type=? AND event_key=?",
            (canonical_json(document), content_hash(document), kind, key),
        )

    def rewrite_reservation(mutate):
        document = deepcopy(reservation)
        mutate(document)
        connection.execute(
            "UPDATE capability_macos_file_access_attempts SET document_json=?,document_digest=?",
            (canonical_json(document), content_hash(document)),
        )

    yield SimpleNamespace(
        store=Store(),
        connection=connection,
        attempt_id=attempt_id,
        dependency=dependency,
        close_task=close_task,
        probe_task=probe_task,
        control_reads=control_reads,
        payloads=payloads,
        rewrite_event=rewrite_event,
        rewrite_reservation=rewrite_reservation,
    )
    connection.close()


def test_historical_settlement_joins_original_control_without_live_endpoint_or_new_clocks(
    history, monkeypatch
):
    def forbidden(*args, **kwargs):
        raise AssertionError("Historical readback cannot reacquire live authority")

    monkeypatch.setattr(settlement.macos, "_acceptance_clock", forbidden)
    monkeypatch.setattr(settlement.macos, "_verify_workspace_attestation", forbidden)
    receipt = settlement.receipt(history.store, history.attempt_id)
    assert receipt["schema_version"] == settlement.SCHEMA
    assert history.control_reads == [history.dependency]
    assert (
        grants._settlement(history.store, history.connection, history.attempt_id, receipt)
        == receipt
    )
    with pytest.raises(ProductStoreError, match="settlement changed"):
        settlement.validate(
            history.store,
            history.connection,
            history.attempt_id,
            {**receipt, "macos_closure_digest": content_hash("other")},
        )


@pytest.mark.parametrize(
    "change",
    [
        "budget",
        "workspace",
        "receipt",
        "dispatch",
        "claim_tasks",
        "proof_identity",
        "proof_swap",
        "producer_terminal",
        "payload",
    ],
)
def test_rehashed_history_cannot_replace_original_task_budget_or_workspace_joins(history, change):
    if change == "budget":
        history.rewrite_reservation(lambda value: value["primitive_budget"].update(total=1))
    elif change == "workspace":
        history.rewrite_reservation(
            lambda value: value.update(workspace_binding_digest=content_hash("other"))
        )
    elif change == "receipt":
        history.rewrite_event(
            "receipt",
            "probe",
            lambda value: value.update(transport_request_hash=content_hash("other")),
        )
    elif change == "dispatch":
        history.rewrite_event(
            "dispatch",
            history.close_task,
            lambda value: value["intent"].update(binding_digest=content_hash("other")),
        )
    elif change == "claim_tasks":
        history.rewrite_event(
            "cleanup_claim", "close_attempt", lambda value: value.update(task_closures=[])
        )
    elif change == "proof_identity":
        for kind, key in (
            ("workspace_reserved", history.attempt_id),
            ("workspace_pre_close", history.close_task),
            ("workspace_post_close", history.close_task),
        ):
            history.rewrite_event(
                kind, key, lambda value: value.update(workspace_identity_digest=None)
            )
    elif change == "proof_swap":
        history.rewrite_event(
            "workspace_post_close",
            history.close_task,
            lambda value: value.update(
                workspace_identity_digest=content_hash("different-directory")
            ),
        )
    elif change == "producer_terminal":
        history.rewrite_event(
            "producer_closure",
            history.close_task,
            lambda value: value.update(terminal_digest=content_hash("other")),
        )
    else:
        history.payloads[history.probe_task]["runner_profile"]["macos_file_access_binding"][
            "control_revision"
        ] += 1
    with pytest.raises(ValueError):
        settlement.receipt(history.store, history.attempt_id)


@pytest.mark.parametrize(
    "table",
    [
        "capability_cleanup_obligations",
        "capability_cleanup_claims",
        "capability_cleanup_task_claims",
    ],
)
def test_mac_metadata_settlement_cannot_ignore_native_cleanup_authority(history, table):
    history.connection.execute(f"INSERT INTO {table} VALUES(?)", (history.attempt_id,))
    with pytest.raises(ProductStoreError, match="native cleanup authority"):
        settlement.receipt(history.store, history.attempt_id)


def test_missing_original_immutable_control_revision_blocks_historical_success(
    history, monkeypatch
):
    def missing(*args):
        raise ProductStoreError("Original immutable control revision is unavailable")

    monkeypatch.setattr(settlement.macos, "_original_macos_control", missing)
    with pytest.raises(ProductStoreError, match="immutable control"):
        settlement.receipt(history.store, history.attempt_id)


@pytest.mark.parametrize("target", ["business", "close"])
def test_rehashed_retained_raw_result_must_still_match_original_authenticated_terminal(
    history, target
):
    kind, key = (
        ("receipt", "probe") if target == "business" else ("producer_closure", history.close_task)
    )

    def change(value):
        if target == "business":
            value["result"]["output"]["macos_receipt"]["shared_request_budget_used"] = 6
        else:
            value["result"]["output"]["attempt_closure"]["shared_request_budget_used"] = 6

    history.rewrite_event(kind, key, change)
    with pytest.raises(ProductStoreError, match="authenticated terminal"):
        settlement.receipt(history.store, history.attempt_id)


@pytest.mark.parametrize("payload", ["oversized", "secret"])
def test_result_retention_rejects_unbounded_or_secret_output_before_opening_journal(payload):
    class NoJournal:
        def _connection(self, **kwargs):
            raise AssertionError("Invalid result must not open the journal")

    result = (
        {"output": {"padding": "x" * (settlement.macos._MAX_RESULT_BYTES + 1)}}
        if payload == "oversized"
        # pragma: allowlist nextline secret - fake rejection payload
        else {"output": {"password": "plaintext"}}
    )
    with pytest.raises(ProductStoreError):
        settlement.macos.record_macos_capability_terminal(NoJournal(), "task", result=result)
