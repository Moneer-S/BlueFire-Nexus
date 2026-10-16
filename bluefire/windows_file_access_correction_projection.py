"""Read-only correction views rejoined from retained proof, including after expiry."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from . import product_store_file_access_native_evidence as native
from . import product_store_windows_correction as journal
from . import product_store_windows_correction_publication as publication
from . import product_store_windows_file_access as windows
from . import windows_file_access_correction_admission as admission
from . import windows_file_access_native_wire as wire
from . import windows_file_access_pair_admission as pair
from .product_store_errors import ProductStoreError
from .util import content_hash


def projection(store: Any, owner_id: str, *, clock: datetime) -> dict:
    """Never observe setup, mint a preparation, or execute during historical reads."""
    try:
        wire._clock(clock)
        with store._connection() as connection:
            imported = windows.document(windows.at(connection, owner_id=owner_id))
            row = connection.execute(
                "SELECT job_id,document_digest,CASE WHEN length(CAST(document_json AS BLOB)) "
                "BETWEEN 1 AND ? THEN document_json ELSE NULL END AS document_json "
                "FROM file_access_revisions WHERE control_owner_id=? ORDER BY revision DESC LIMIT 1",
                (wire.PUBLIC_MAX, owner_id),
            ).fetchone()
            control = native._row_document(row, wire.PUBLIC_MAX)
            wire._require(control["control_owner_id"] == owner_id)
            if control["schema_version"] == admission.CONTROL_SCHEMA:
                journal.verify_baseline(store, connection, imported, control, clock=clock)
                change = retest = None
                protection = "reader_readable"
            else:
                wire._require(control["schema_version"] == publication.CONTROL_SCHEMA)
                context = publication._context(store, connection, row["job_id"])
                wire._require(publication._revision(store, connection, context, clock) == control)
                outcome, _ = windows._outcome_at(connection, row["job_id"])
                wire._require(
                    outcome
                    == {
                        "state": "complete",
                        "control_digest": content_hash(control),
                        "evidence_digest": control["retest"]["evidence_digest"],
                        "native_correction": control["retest"],
                    }
                )
                change, retest = control["correction"], control["retest"]
                protection = "metadata_only"
            operations = connection.execute(
                "SELECT job_id FROM file_access_operations WHERE control_owner_id=?",
                (owner_id,),
            ).fetchall()
            settled = True
            for operation in operations:
                outcome, _ = windows._outcome_at(connection, operation["job_id"])
                if outcome is None or outcome["state"] not in ("complete", "refused_no_effect"):
                    settled = False
                elif outcome["state"] == "complete":
                    retained, retained_digest = windows._bounded(
                        connection,
                        "file_access_revisions",
                        "job_id",
                        operation["job_id"],
                        wire.PUBLIC_MAX,
                    )
                    wire._require(
                        retained["control_owner_id"] == owner_id
                        and retained["operation_job_id"] == operation["job_id"]
                        and outcome["control_digest"] == retained_digest
                    )
                else:
                    wire._require(
                        not connection.execute(
                            "SELECT 1 FROM file_access_windows_control_evidence "
                            "WHERE job_id=? LIMIT 1",
                            (operation["job_id"],),
                        ).fetchone()
                        and not connection.execute(
                            "SELECT 1 FROM file_access_task_claims WHERE job_id=? LIMIT 1",
                            (operation["job_id"],),
                        ).fetchone()
                    )
            from .product_store_capability_grants import control_usages_settled

            settled = settled and control_usages_settled(store, connection, owner_id)
            result = pair.projection(imported)
            result.update(
                schema_version="bluefire.windows-file-access-control.v3",
                control_digest=content_hash(control),
                revision=control["revision"],
                status=control["status"] if settled else "uncertain",
                baseline=control["baseline"],
                correction=change,
                retest=retest,
                task_usage_state="settled" if settled else "unresolved",
                allowed_operations=(
                    ["harden"]
                    if settled
                    and control["revision"] == 2
                    and imported["enrollment"]["issued_at_ms"]
                    <= int(clock.timestamp() * 1000)
                    < result["expires_at_ms"]
                    else []
                ),
            )
            result["resource"]["protection"] = protection if settled else "unknown"
        result["operations"] = [
            job
            for job in store.list_jobs()
            if job["kind"] == "file_access.operation"
            and job["request"].get("control_owner_id") == owner_id
        ]
        return result
    except native._FAILURES:
        raise ProductStoreError(journal._ERROR) from None
