"""Append-only dispatch ownership for one reviewed Windows DACL correction.

Original preparation and current control are independently loaded. A dispatch
lock is never a terminal, and historical rows cannot recreate its allowance.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from . import _windows_file_access_native_contract as wire
from . import product_store_file_access_native_evidence as native
from . import product_store_windows_file_access as windows
from . import windows_file_access_correction_admission as admission
from . import windows_file_access_pair_admission as pair
from .product_store_errors import ProductStoreError
from .product_store_serialization import canonical_json
from .util import content_hash

_ERROR = "The original Windows correction remains unavailable or unresolved."
_EVENT_SCHEMA = "bluefire.windows-file-correction-control-evidence.v1"


def validate_review(
    store: Any,
    connection: Any,
    control: dict,
    context: dict,
    *,
    now_ms: int,
    original_job_id: str | None = None,
) -> dict:
    """Join the actual retained baseline before reserving a correction review."""
    try:
        imported = windows.document(windows.at(connection, owner_id=control["control_owner_id"]))
        wire._require(
            context
            == admission.correction_context(
                imported, control, context["previous_descriptor_sha256"]
            )
        )
        record = imported["enrollment"]
        wire._int(now_ms, record["issued_at_ms"], record["expires_at_ms"] - 1)
        verify_baseline(
            store,
            connection,
            imported,
            control,
            clock=datetime.fromtimestamp(now_ms / 1000, timezone.utc),
        )
        _original_baseline_history(connection, control, original_job_id)
        return imported
    except native._FAILURES:
        raise ProductStoreError(_ERROR) from None


def validate_preparation_at(
    store: Any,
    connection: Any,
    job_id: str,
    document: dict,
    original: dict,
    control: dict,
    *,
    now_ms: int,
) -> None:
    try:
        imported = validate_review(
            store,
            connection,
            control,
            original["review_context"],
            now_ms=now_ms,
            original_job_id=job_id,
        )
        prepared = admission.validate_retained_preparation(document, original, imported, control)
        wire._require(prepared["job_id"] == job_id)
        _live(store, connection, job_id, prepared, now_ms)
        wire._require(not _events(connection, job_id, prepared))
        wire._require(
            not connection.execute(
                "SELECT 1 FROM file_access_task_claims WHERE job_id=? LIMIT 1", (job_id,)
            ).fetchone()
        )
    except native._FAILURES:
        raise ProductStoreError(_ERROR) from None


def original_at(store: Any, connection: Any, job_id: str) -> tuple[dict, dict, dict, dict]:
    operation, _ = windows._bounded(
        connection, "file_access_operations", "job_id", job_id, wire.PUBLIC_MAX
    )
    prepared, _ = windows._bounded(
        connection, "file_access_preparations", "job_id", job_id, wire.PUBLIC_MAX
    )
    imported = windows.document(windows.at(connection, owner_id=prepared["control_owner_id"]))
    wire._require(imported["schema_version"] == pair.IMPORT_SCHEMA)
    prior_row = connection.execute(
        "SELECT document_digest,CASE WHEN length(CAST(document_json AS BLOB)) "
        "BETWEEN 1 AND ? THEN document_json ELSE NULL END AS document_json FROM file_access_revisions "
        "WHERE control_owner_id=? AND revision=?",
        (
            wire.PUBLIC_MAX,
            prepared["control_owner_id"],
            prepared["binding"]["control_revision"] - 1,
        ),
    ).fetchone()
    prior = native._row_document(prior_row, wire.PUBLIC_MAX)
    admission.validate_retained_preparation(prepared, operation, imported, prior)
    _original_baseline_history(connection, prior, job_id)
    verify_baseline(
        store,
        connection,
        imported,
        prior,
        clock=datetime.fromtimestamp(prepared["issued_at_ms"] / 1000, timezone.utc),
    )
    indexed = connection.execute(
        "SELECT operation,control_owner_id,enrollment_id FROM file_access_operations WHERE job_id=?",
        (job_id,),
    ).fetchone()
    wire._require(
        indexed["operation"] == "harden"
        and indexed["control_owner_id"] == imported["control_owner_id"]
        and indexed["enrollment_id"] == imported["enrollment_id"]
    )
    return operation, prepared, imported, prior


def _original_baseline_history(connection: Any, control: dict, original_job_id: str | None) -> None:
    """A missing later revision cannot make a previously used baseline fresh."""
    rows = connection.execute(
        "SELECT job_id FROM file_access_operations WHERE control_owner_id=? AND job_id<>?",
        (control["control_owner_id"], control["operation_job_id"]),
    ).fetchall()
    for row in rows:
        job_id = row["job_id"]
        if job_id == original_job_id:
            continue
        outcome, _ = windows._outcome_at(connection, job_id)
        wire._require(outcome is not None and outcome["state"] == "refused_no_effect")
        wire._require(
            not connection.execute(
                "SELECT 1 FROM file_access_windows_control_evidence WHERE job_id=? LIMIT 1",
                (job_id,),
            ).fetchone()
            and not connection.execute(
                "SELECT 1 FROM file_access_task_claims WHERE job_id=? LIMIT 1", (job_id,)
            ).fetchone()
        )


def verify_baseline(
    store: Any, connection: Any, imported: dict, prior: dict, *, clock: datetime
) -> None:
    """Rejoin the original native reads and physical closure, not just row hashes."""
    job_id = prior["operation_job_id"]
    original = windows._original_pair_at(connection, job_id)
    _, _, prepared, prep_digest, same_import = original
    wire._require(same_import == imported)
    context = native._context(
        store,
        prepared["original"]["task_id"],
        prepared["original"]["transport_request_hash"],
        prepared["expected_binding"],
        _protocol=native._Protocol.PAIR_V2,
    )
    baseline = windows._pair_baseline(connection, context, prepared, prep_digest, imported, clock)
    wire._require(prior == windows._revision(imported, prepared, context, baseline, job_id))
    outcome, _ = windows._outcome_at(connection, job_id)
    wire._require(
        outcome
        == {
            "state": "complete",
            "evidence_digest": baseline["baseline_digest"],
            "control_digest": content_hash(prior),
            "native_baseline": baseline,
        }
    )


def _live(store: Any, connection: Any, job_id: str, prepared: dict, now_ms: int) -> None:
    from .product_store_capability_grants import control_usages_settled

    wire._int(now_ms, prepared["issued_at_ms"], prepared["expires_at_ms"] - 1)
    job = store._job_from_row(
        connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
    )
    current = connection.execute(
        "SELECT document_digest FROM file_access_revisions WHERE control_owner_id=? "
        "ORDER BY revision DESC LIMIT 1",
        (prepared["control_owner_id"],),
    ).fetchone()
    wire._require(
        job["kind"] == "file_access.operation"
        and job["state"] in ("queued", "running")
        and not job["progress"].get("stopped")
        and windows._outcome_at(connection, job_id)[0] is None
        and current is not None
        and current["document_digest"] == prepared["control_digest"]
        and control_usages_settled(store, connection, prepared["control_owner_id"])
    )


def _events(connection: Any, job_id: str, prepared: dict) -> dict[str, dict]:
    rows = connection.execute(
        "SELECT stage,document_digest,CASE WHEN length(CAST(document_json AS BLOB)) "
        "BETWEEN 1 AND ? THEN document_json ELSE NULL END AS document_json "
        "FROM file_access_windows_control_evidence WHERE job_id=? ORDER BY rowid LIMIT 3",
        (wire.PUBLIC_MAX, job_id),
    ).fetchall()
    wire._require(len(rows) <= 2)
    events: dict[str, dict] = {}
    previous = prepared["binding_digest"]
    for expected_stage, row in zip(("dispatch", "closure"), rows, strict=False):
        document = native._row_document(row, wire.PUBLIC_MAX)
        wire._exact(document, "schema_version job_id binding_digest stage previous_digest payload")
        wire._require(
            row["stage"] == document["stage"] == expected_stage
            and document["schema_version"] == _EVENT_SCHEMA
            and document["job_id"] == job_id
            and document["binding_digest"] == prepared["binding_digest"]
            and document["previous_digest"] == previous
        )
        if expected_stage == "dispatch":
            wire._exact(document["payload"], "dispatched_at_ms")
            wire._int(
                document["payload"]["dispatched_at_ms"],
                prepared["issued_at_ms"],
                prepared["expires_at_ms"] - 1,
            )
        else:
            from .windows_file_access_correction_contract import (
                validate_retained_control_receipt,
            )

            validate_retained_control_receipt(document["payload"], prepared["binding"])
        events[expected_stage] = document
        previous = row["document_digest"]
    return events


def _append(
    connection: Any, job_id: str, prepared: dict, stage: str, previous: str, payload: dict
) -> dict:
    wire._require(connection.in_transaction)
    document = {
        "schema_version": _EVENT_SCHEMA,
        "job_id": job_id,
        "binding_digest": prepared["binding_digest"],
        "stage": stage,
        "previous_digest": previous,
        "payload": payload,
    }
    connection.execute(
        "INSERT INTO file_access_windows_control_evidence VALUES(?,?,?,?)",
        (job_id, stage, canonical_json(document), content_hash(document)),
    )
    return document


def begin_dispatch(
    store: Any, job_id: str, *, binding_digest: str, now_ms: int, revalidate: Callable[[], None]
) -> Callable[[int], None]:
    """Commit the only dispatch lock; never reconstruct its callable from rows."""
    try:
        wire._digest(binding_digest)
        with store._connection(write=True) as connection:
            original = original_at(store, connection, job_id)
            prepared = original[1]
            wire._require(prepared["binding_digest"] == binding_digest)
            _live(store, connection, job_id, prepared, now_ms)
            wire._require(not _events(connection, job_id, prepared))
            wire._require(
                not connection.execute(
                    "SELECT 1 FROM file_access_task_claims WHERE job_id=? LIMIT 1", (job_id,)
                ).fetchone()
            )
            revalidate()
            dispatch = _append(
                connection,
                job_id,
                prepared,
                "dispatch",
                binding_digest,
                {"dispatched_at_ms": now_ms},
            )
    except native._FAILURES:
        raise ProductStoreError(_ERROR) from None

    def require_original(current_ms: int) -> None:
        try:
            with store._connection() as connection:
                wire._require(original_at(store, connection, job_id) == original)
                _live(store, connection, job_id, prepared, current_ms)
                wire._require(_events(connection, job_id, prepared) == {"dispatch": dispatch})
        except native._FAILURES:
            raise ProductStoreError(_ERROR) from None

    return require_original


def record_control_closure(store: Any, job_id: str, receipt: Any) -> dict:
    """Accept only supervisor-produced positive closure; never a client boolean."""
    from .windows_file_access_correction_contract import OwnedCorrectionControlReceipt

    try:
        wire._require(type(receipt) is OwnedCorrectionControlReceipt)
        payload = receipt.document()
        with store._connection(write=True) as connection:
            prepared = original_at(store, connection, job_id)[1]
            wire._require(payload["binding_digest"] == prepared["binding_digest"])
            events = _events(connection, job_id, prepared)
            wire._require("dispatch" in events)
            if "closure" in events:
                wire._require(events["closure"]["payload"] == payload)
                return events["closure"]
            _append(
                connection, job_id, prepared, "closure", content_hash(events["dispatch"]), payload
            )
            return _events(connection, job_id, prepared)["closure"]
    except native._FAILURES:
        raise ProductStoreError(_ERROR) from None


def has_dispatch(store: Any, job_id: str) -> bool:
    """Presence is conservative, including corrupt or incomplete effect evidence."""
    with store._connection() as connection:
        return (
            connection.execute(
                "SELECT 1 FROM file_access_windows_control_evidence WHERE job_id=? LIMIT 1",
                (job_id,),
            ).fetchone()
            is not None
        )


def control_evidence(store: Any, job_id: str) -> dict[str, dict]:
    try:
        with store._connection() as connection:
            prepared = original_at(store, connection, job_id)[1]
            return _events(connection, job_id, prepared)
    except native._FAILURES:
        raise ProductStoreError(_ERROR) from None
