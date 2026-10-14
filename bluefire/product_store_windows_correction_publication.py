"""Atomic correction publication from original effect and fresh retained v3 proof."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from . import product_store_file_access_native_evidence as native
from . import product_store_windows_correction as journal
from . import product_store_windows_correction_retest as retest
from . import product_store_windows_file_access as windows
from . import windows_file_access_correction_admission as admission
from . import windows_file_access_native_wire as wire
from ._windows_file_access_native_contract import _digest
from .product_store_errors import ProductStoreError
from .product_store_serialization import canonical_json
from .util import content_hash

CONTROL_SCHEMA = "bluefire.windows-file-access-control-record.v3"


def _context(store: Any, connection: Any, job_id: str) -> native._Context:
    operation, prepared, imported, _ = journal.original_at(store, connection, job_id)
    rows = connection.execute(
        "SELECT task_id,document_digest,CASE WHEN length(CAST(document_json AS BLOB)) "
        "BETWEEN 1 AND ? THEN document_json ELSE NULL END AS document_json "
        "FROM file_access_task_claims WHERE job_id=? LIMIT 2",
        (native._CLAIM_MAX, job_id),
    ).fetchall()
    wire._require(len(rows) == 1)
    claim = native._row_document(rows[0], native._CLAIM_MAX)
    issued = wire._time(claim["manifest"]["requested_at"])
    original, expected = admission._build_retest_original(
        prepared["binding"],
        imported["enrollment"],
        imported["setup_receipt"],
        int(issued.timestamp() * 1000),
        operation["submitted_request"]["reviewed_by"],
    )
    wire._require(rows[0]["task_id"] == original["task_id"])
    context = native._context(
        store,
        original["task_id"],
        original["transport_request_hash"],
        expected,
        _protocol=native._Protocol.CORRECTION_V3,
    )
    retest.retained_context(store, connection, context)
    return context


def _revision(store: Any, connection: Any, context: native._Context, clock: datetime) -> dict:
    prepared, changed = retest.retained_context(store, connection, context)
    job_id = prepared["job_id"]
    _, _, imported, prior = journal.original_at(store, connection, job_id)
    trail, stages = native._load(connection, context, clock)
    closure, cleanup_document = native._cleanup_load(connection, context, clock, trail)
    projected = trail.projection
    wire._require(
        type(trail) is native.CorrectionNativeTaskEvidence
        and type(projected) is wire.PairNativeProjection
        and trail.actual_returncode == 0
        and projected.observation_complete
        and projected.outcome == projected.reader_outcome == "data_access_denied"
        and projected.owner_outcome == "allowed"
        and projected.local_cleanup == "verified"
        and closure.owned_job_cleanup == "verified"
        and set(stages) == {"packet", "ready", "terminal"}
        and cleanup_document is not None
    )
    terminal = wire._document(trail.terminal_bytes, wire.TERMINAL_MAX)
    events = journal._events(connection, job_id, prepared)
    evidence_digest = content_hash(
        {
            "preparation_digest": content_hash(prepared),
            "baseline_digest": prior["baseline"]["baseline_digest"],
            "control_events": {key: content_hash(value) for key, value in events.items()},
            "claim_digest": context.claim_digest,
            "wire_stage_digests": {name: row[0]["document_digest"] for name, row in stages.items()},
            "cleanup_digest": content_hash(cleanup_document),
        }
    )
    return {
        "schema_version": CONTROL_SCHEMA,
        "control_owner_id": imported["control_owner_id"],
        "enrollment_id": imported["enrollment_id"],
        "generation": imported["generation"],
        "revision": prepared["binding"]["control_revision"],
        "status": "hardened",
        "original_import_digest": content_hash(imported),
        "prior_control_digest": content_hash(prior),
        "operation_job_id": job_id,
        "task_id": context.task_id,
        "transport_request_hash": context.transport_hash,
        "resource": prepared["binding"]["target_resource"],
        "baseline": prior["baseline"],
        "correction": {
            "binding_digest": prepared["binding_digest"],
            "before_descriptor_sha256": changed["before_descriptor_sha256"],
            "after_descriptor_sha256": changed["after_descriptor_sha256"],
            "owned_control_cleanup": "verified",
        },
        "retest": {
            "schema_version": "bluefire.windows-file-correction-observation.v3",
            "non_owner": "data_access_denied",
            "owner": "allowed",
            "size_bytes": prior["resource"]["size_bytes"],
            "sha256": prior["resource"]["sha256"],
            "observed_at": terminal["observed_at"],
            "native_cleanup": "verified",
            "owned_job_cleanup": "verified",
            "independent_observation": False,
            "evidence_digest": evidence_digest,
        },
    }


def publish(
    store: Any, job_id: str, *, clock: datetime, expected_outcome_digest: str | None = None
) -> dict:
    """Retain one proven revision; recovery only joins evidence and never re-executes."""
    try:
        wire._clock(clock)
        if expected_outcome_digest is not None:
            _digest(expected_outcome_digest)
        with store._connection() as connection:
            context = _context(store, connection, job_id)
        with store._connection(write=True) as connection:
            wire._require(_context(store, connection, job_id) == context)
            revision = _revision(store, connection, context, clock)
            outcome = {
                "state": "complete",
                "evidence_digest": revision["retest"]["evidence_digest"],
                "control_digest": content_hash(revision),
                "native_correction": revision["retest"],
            }
            prior, prior_digest = windows._outcome_at(connection, job_id)
            committed = connection.execute(
                "SELECT document_digest,CASE WHEN length(CAST(document_json AS BLOB)) "
                "BETWEEN 1 AND ? THEN document_json ELSE NULL END AS document_json "
                "FROM file_access_revisions WHERE job_id=?",
                (wire.PUBLIC_MAX, job_id),
            ).fetchone()
            if prior is not None and prior["state"] == "complete":
                wire._require(
                    prior == outcome
                    and native._row_document(committed, wire.PUBLIC_MAX) == revision
                )
                if expected_outcome_digest is not None:
                    old = connection.execute(
                        "SELECT document_digest,CASE WHEN length(CAST(document_json AS BLOB)) "
                        "BETWEEN 1 AND ? THEN document_json ELSE NULL END AS document_json "
                        "FROM file_access_outcomes WHERE job_id=? AND document_digest=? LIMIT 1",
                        (wire.PUBLIC_MAX, job_id, expected_outcome_digest),
                    ).fetchone()
                    wire._require(native._row_document(old, wire.PUBLIC_MAX)["state"] == "unknown")
                return revision
            wire._require(
                (prior is None and expected_outcome_digest is None)
                or (
                    prior is not None
                    and prior["state"] == "unknown"
                    and prior_digest == expected_outcome_digest
                )
            )
            wire._require(committed is None)
            current = connection.execute(
                "SELECT revision,document_digest FROM file_access_revisions "
                "WHERE control_owner_id=? ORDER BY revision DESC LIMIT 1",
                (revision["control_owner_id"],),
            ).fetchone()
            wire._require(
                current is not None
                and current["revision"] == revision["revision"] - 1
                and current["document_digest"] == revision["prior_control_digest"]
            )
            from .product_store_capability_grants import control_usages_settled

            wire._require(control_usages_settled(store, connection, revision["control_owner_id"]))
            others = connection.execute(
                "SELECT job_id FROM file_access_operations WHERE control_owner_id=? AND job_id<>?",
                (revision["control_owner_id"], job_id),
            ).fetchall()
            for other in others:
                state, _ = windows._outcome_at(connection, other["job_id"])
                wire._require(
                    state is not None and state["state"] in ("complete", "refused_no_effect")
                )
            connection.execute(
                "INSERT INTO file_access_revisions VALUES(?,?,?,?,?)",
                (
                    revision["control_owner_id"],
                    revision["revision"],
                    job_id,
                    canonical_json(revision),
                    content_hash(revision),
                ),
            )
            connection.execute(
                "INSERT INTO file_access_outcomes(job_id,document_json,document_digest) VALUES(?,?,?)",
                (job_id, canonical_json(outcome), content_hash(outcome)),
            )
            return revision
    except native._FAILURES:
        raise ProductStoreError(journal._ERROR) from None
