from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

import pytest

from bluefire.strix_worker_containment import (
    StrixWorkerActivationReceipt,
    StrixWorkerCleanupRequest,
    StrixWorkerContainmentPlan,
    receipt_document,
)
from bluefire.strix_worker_containment_store import (
    ProductStoreStrixWorkerContainment,
    StrixWorkerContainmentStoreError,
)
from bluefire.util import content_hash
from tests_platform.test_strix_worker_containment import (
    _activation_document as contract_activation_document,
)
from tests_platform.test_strix_worker_containment import (
    _cleanup_document as contract_cleanup_document,
)
from tests_platform.test_strix_worker_containment import _plan as contract_plan
from tests_platform.test_strix_worker_containment import (
    _revalidation_document as contract_revalidation_document,
)

ATTEMPT = "engine-attempt-" + "a" * 32


def _d(label: str) -> str:
    return content_hash({"label": label})


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path

    @contextmanager
    def _connection(self, *, write: bool = False):
        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA synchronous=FULL")
        try:
            if write:
                connection.execute("BEGIN IMMEDIATE")
            yield connection
            if write:
                connection.commit()
        except Exception:
            if write:
                connection.rollback()
            raise
        finally:
            connection.close()


def _journal(path: Path, **changes: object) -> ProductStoreStrixWorkerContainment:
    values = {
        "attempt_id": ATTEMPT,
        "binding_digest": _d("binding"),
        "controller_generation": 7,
        "controller_boot_id_digest": _d("boot"),
    }
    values.update(changes)
    return ProductStoreStrixWorkerContainment(Store(path), **values)


def _plan() -> dict[str, object]:
    return contract_plan().to_dict()


def _receipt(document: dict[str, object], field: str = "receipt_ref") -> dict[str, object]:
    result = dict(document)
    result[field] = content_hash(result)
    return result


def _activation(plan: dict[str, object]) -> dict[str, object]:
    return contract_activation_document(StrixWorkerContainmentPlan.from_mapping(plan))


def _revalidation(
    plan: dict[str, object], activation: dict[str, object], sequence: int = 1
) -> dict[str, object]:
    plan_object = StrixWorkerContainmentPlan.from_mapping(plan)
    activation_object = StrixWorkerActivationReceipt.from_mapping(activation, plan_object)
    document = contract_revalidation_document(activation_object)
    if sequence != 1:
        document.pop("receipt_ref")
        document["observed_at"] = f"2026-11-05T12:{sequence + 1:02d}:00Z"
        document = receipt_document(document)
    return document


def _cleanup_request(
    plan: dict[str, object],
    activation: dict[str, object],
    requested_at: str = "2026-11-05T12:03:00Z",
) -> dict[str, object]:
    plan_object = StrixWorkerContainmentPlan.from_mapping(plan)
    activation_object = StrixWorkerActivationReceipt.from_mapping(activation, plan_object)
    return StrixWorkerCleanupRequest.create(activation_object, requested_at=requested_at).to_dict()


def _cleanup(
    plan: dict[str, object],
    activation: dict[str, object],
    request: dict[str, object],
) -> dict[str, object]:
    plan_object = StrixWorkerContainmentPlan.from_mapping(plan)
    activation_object = StrixWorkerActivationReceipt.from_mapping(activation, plan_object)
    request_object = StrixWorkerCleanupRequest.from_mapping(request, activation_object)
    document = contract_cleanup_document(activation_object, request_object)
    if request_object.requested_at > "2026-11-05T12:04:00Z":
        document.pop("receipt_ref")
        document["observed_at"] = "2026-11-05T12:12:00Z"
        document = receipt_document(document)
    return document


def test_round_trip_retains_exact_lifecycle_without_live_authority(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    journal = _journal(path)
    plan = _plan()
    activation = _activation(plan)
    revalidation = _revalidation(plan, activation)
    request = _cleanup_request(plan, activation)
    cleanup = _cleanup(plan, activation, request)

    journal.prepare_activation(plan)
    assert journal.reopen().unresolved_operations[0].operation == "activation"
    assert journal.retain_activation(activation) == activation["receipt_ref"]
    assert journal.append_revalidation(revalidation) == revalidation["receipt_ref"]
    journal.prepare_cleanup(request)
    assert journal.reopen().unresolved_operations[0].operation == "cleanup"
    assert journal.retain_cleanup(cleanup) == cleanup["receipt_ref"]

    reopened = _journal(path).reopen()
    assert reopened.plan == plan
    assert reopened.activation == activation
    assert reopened.revalidations == (revalidation,)
    assert reopened.cleanup_request == request
    assert reopened.cleanup == cleanup
    assert reopened.unresolved_operations == ()
    assert reopened.reconciliation_required is False
    assert reopened.launch_authorized is False
    assert reopened.reconnect_authorized is False
    assert reopened.journal_digest.startswith("sha256:")


def test_reopen_fences_prepared_and_live_activation_states(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    journal = _journal(path)
    plan = _plan()
    journal.prepare_activation(plan)

    prepared = _journal(path).reopen()
    assert prepared.reconciliation_required is True
    assert [item.operation for item in prepared.unresolved_operations] == ["activation"]

    activation = _activation(plan)
    journal.retain_activation(activation)
    active = _journal(path).reopen()
    assert active.unresolved_operations == ()
    assert active.reconciliation_required is True
    assert active.launch_authorized is False
    assert active.reconnect_authorized is False

    request = _cleanup_request(plan, activation)
    journal.prepare_cleanup(request)
    interrupted_cleanup = _journal(path).reopen()
    assert [item.operation for item in interrupted_cleanup.unresolved_operations] == ["cleanup"]


def test_receipts_require_their_exact_prepared_intent(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "state.sqlite3")
    plan = _plan()
    activation = _activation(plan)
    with pytest.raises(StrixWorkerContainmentStoreError, match="prepared intent"):
        journal.retain_activation(activation)

    journal.prepare_activation(plan)
    journal.retain_activation(activation)
    request = _cleanup_request(plan, activation)
    cleanup = _cleanup(plan, activation, request)
    with pytest.raises(StrixWorkerContainmentStoreError, match="prepared intent"):
        journal.retain_cleanup(cleanup)


def test_exact_replays_are_idempotent_but_substitutions_are_rejected(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "state.sqlite3")
    plan = _plan()
    journal.prepare_activation(plan)
    journal.prepare_activation(plan)
    activation = _activation(plan)
    journal.retain_activation(activation)
    journal.retain_activation(activation)
    request = _cleanup_request(plan, activation)
    journal.prepare_cleanup(request)
    journal.prepare_cleanup(request)

    changed_request = _cleanup_request(plan, activation, "2026-11-05T12:11:00Z")
    journal.prepare_cleanup(changed_request)
    assert journal.reopen().cleanup_requests == (request, changed_request)


def test_partial_cleanup_cannot_close_reconciliation(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "state.sqlite3")
    plan = _plan()
    activation = _activation(plan)
    journal.prepare_activation(plan)
    journal.retain_activation(activation)
    request = _cleanup_request(plan, activation)
    journal.prepare_cleanup(request)
    incomplete = _cleanup(plan, activation, request)
    incomplete["relays_closed"] = False
    incomplete.pop("receipt_ref")
    incomplete = _receipt(incomplete)

    with pytest.raises(StrixWorkerContainmentStoreError, match="complete absence"):
        journal.retain_cleanup(incomplete)
    reopened = journal.reopen()
    assert reopened.cleanup is None
    assert reopened.reconciliation_required is True
    assert [item.request_ref for item in reopened.unresolved_operations] == [request["request_ref"]]


def test_fresh_cleanup_request_can_resolve_an_expired_intent(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "state.sqlite3")
    plan = _plan()
    activation = _activation(plan)
    journal.prepare_activation(plan)
    journal.retain_activation(activation)
    expired = _cleanup_request(plan, activation)
    fresh = _cleanup_request(plan, activation, "2026-11-05T12:11:00Z")
    journal.prepare_cleanup(expired)
    journal.prepare_cleanup(fresh)
    cleanup = _cleanup(plan, activation, fresh)
    journal.retain_cleanup(cleanup)

    reopened = journal.reopen()
    assert reopened.cleanup_request == fresh
    assert reopened.cleanup == cleanup
    assert reopened.reconciliation_required is False
    assert [item.request_ref for item in reopened.unresolved_operations] == [expired["request_ref"]]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("attempt_id", "engine-attempt-" + "b" * 32),
        ("binding_digest", _d("other binding")),
        ("controller_generation", 8),
        ("controller_boot_id_digest", _d("other boot")),
    ],
)
def test_activation_binding_substitutions_are_rejected(
    tmp_path: Path, field: str, value: object
) -> None:
    journal = _journal(tmp_path / "state.sqlite3")
    plan = _plan()
    journal.prepare_activation(plan)
    activation = _activation(plan)
    activation[field] = value
    activation.pop("receipt_ref")
    activation = _receipt(activation)
    with pytest.raises(StrixWorkerContainmentStoreError, match="binding changed"):
        journal.retain_activation(activation)


def test_digest_and_schema_changes_are_rejected(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "state.sqlite3")
    plan = _plan()
    journal.prepare_activation(plan)
    activation = _activation(plan)
    activation["process"] = {"host_pid": 9999, "start_ticks": 8001}
    with pytest.raises(StrixWorkerContainmentStoreError, match="does not match"):
        journal.retain_activation(activation)

    changed_schema = _activation(plan)
    changed_schema["schema_version"] = "bluefire.strix-worker-containment-activation.v2"
    changed_schema.pop("receipt_ref")
    changed_schema = _receipt(changed_schema)
    with pytest.raises(StrixWorkerContainmentStoreError, match="binding changed"):
        journal.retain_activation(changed_schema)


def test_revalidation_cannot_cross_activation_or_follow_cleanup(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "state.sqlite3")
    plan = _plan()
    activation = _activation(plan)
    journal.prepare_activation(plan)
    journal.retain_activation(activation)
    wrong = _revalidation(plan, activation)
    wrong["activation_ref"] = _d("another activation")
    wrong.pop("receipt_ref")
    wrong = _receipt(wrong)
    with pytest.raises(StrixWorkerContainmentStoreError, match="live activation"):
        journal.append_revalidation(wrong)

    request = _cleanup_request(plan, activation)
    journal.prepare_cleanup(request)
    journal.retain_cleanup(_cleanup(plan, activation, request))
    with pytest.raises(StrixWorkerContainmentStoreError, match="live activation"):
        journal.append_revalidation(_revalidation(plan, activation, 2))


def test_database_immutability_and_guard_tampering_are_detected(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    journal = _journal(path)
    journal.prepare_activation(_plan())
    with sqlite3.connect(path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE strix_worker_containment_events SET event_key='changed' "
                "WHERE event_sequence=1"
            )
        connection.rollback()
        connection.execute("DROP TRIGGER strix_worker_containment_no_update")
        connection.commit()
    with pytest.raises(StrixWorkerContainmentStoreError, match="guard changed"):
        journal.reopen()


def test_non_durable_database_mode_is_refused(tmp_path: Path) -> None:
    class UnsafeStore(Store):
        @contextmanager
        def _connection(self, *, write: bool = False):
            connection = sqlite3.connect(self.path)
            connection.execute("PRAGMA synchronous=OFF")
            try:
                if write:
                    connection.execute("BEGIN IMMEDIATE")
                yield connection
                if write:
                    connection.commit()
            finally:
                connection.close()

    with pytest.raises(StrixWorkerContainmentStoreError, match="durable commits"):
        ProductStoreStrixWorkerContainment(
            UnsafeStore(tmp_path / "state.sqlite3"),
            attempt_id=ATTEMPT,
            binding_digest=_d("binding"),
            controller_generation=7,
            controller_boot_id_digest=_d("boot"),
        )


def test_reopen_rejects_canonical_chain_corruption(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    journal = _journal(path)
    journal.prepare_activation(_plan())
    with sqlite3.connect(path) as connection:
        names = (
            "strix_worker_containment_no_update",
            "strix_worker_containment_no_delete",
            "strix_worker_containment_no_replace",
        )
        statements = {
            row[0]: row[1]
            for row in connection.execute(
                "SELECT name,sql FROM sqlite_master WHERE type='trigger'"
            ).fetchall()
            if row[0] in names
        }
        for name in names:
            connection.execute(f"DROP TRIGGER {name}")
        row = connection.execute(
            "SELECT document_json FROM strix_worker_containment_events "
            "WHERE attempt_id=? AND event_sequence=2",
            (ATTEMPT,),
        ).fetchone()
        document = json.loads(row[0])
        document["previous_event_digest"] = _d("rollback")
        connection.execute(
            "UPDATE strix_worker_containment_events SET document_json=? "
            "WHERE attempt_id=? AND event_sequence=2",
            (json.dumps(document, sort_keys=True, separators=(",", ":")), ATTEMPT),
        )
        for name in names:
            connection.execute(statements[name])
        connection.commit()
    with pytest.raises(StrixWorkerContainmentStoreError, match="chain audit"):
        journal.reopen()
