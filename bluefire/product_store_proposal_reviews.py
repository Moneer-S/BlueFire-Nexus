"""Durable proposal-review decisions in caller-owned product-store transactions."""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
from contextlib import AbstractContextManager
from typing import Any, Mapping, Protocol

from .ai import MUTATING_PROPOSAL_TYPES, AIProviderError, validate_persisted_proposal_record
from .product_store_contracts import safe_document as _safe_document
from .product_store_errors import ProductStoreError
from .product_store_proposal_validation import validate_reviewed_option
from .product_store_serialization import canonical_json as _canonical_json
from .product_store_serialization import utc_now
from .util import content_hash

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
_PROPOSAL_RECORD_ID = re.compile(r"^proposal-review-[0-9a-f]{32}$")
_SOURCE_PROPOSAL_ID = re.compile(r"^proposal-[0-9a-f]{20}$")


class ProposalReviewStore(Protocol):
    def _connection(self, *, write: bool = False) -> AbstractContextManager[sqlite3.Connection]: ...
    def get_ai_proposal_review(self, proposal_record_id: str) -> Mapping[str, Any]: ...
    @staticmethod
    def _ai_proposal_review_from_row(row: sqlite3.Row) -> Mapping[str, Any]: ...


def create_ai_proposal_review(
    self: ProposalReviewStore,
    *,
    job_id: str,
    source_run_id: str,
    record: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Persist one bounded proposal at the operator-review boundary.

    The three digests are copied from the immutable run record and checked
    here before any later operator decision can refer to them.
    """

    if not _RUN_ID.fullmatch(source_run_id):
        raise ProductStoreError("proposal source run ID is invalid")
    document = _safe_document(record, context="AI proposal review")
    if document.get("run_id") != source_run_id:
        raise ProductStoreError("proposal source run identity is mismatched")
    if document.get("application_status") != "awaiting_operator_approval":
        raise ProductStoreError("only pending registered proposals can be reviewed")
    try:
        validated_proposal = validate_persisted_proposal_record(document)
    except AIProviderError as exc:
        raise ProductStoreError("proposal review failed strict contract validation") from exc
    proposal = validated_proposal.to_dict()
    source_proposal_id = validated_proposal.proposal_id
    if not isinstance(source_proposal_id, str) or not _SOURCE_PROPOSAL_ID.fullmatch(
        source_proposal_id
    ):
        raise ProductStoreError("proposal content identity is invalid")
    if validated_proposal.proposal_type not in MUTATING_PROPOSAL_TYPES:
        raise ProductStoreError("only registered runtime proposals can be reviewed")
    try:
        validate_reviewed_option(document, validated_proposal)
    except ValueError as exc:
        raise ProductStoreError(str(exc)) from exc
    state_digest = document.get("state_digest")
    plan_digest = document.get("plan_digest")
    proposal_digest = document.get("proposal_digest")
    if not all(
        isinstance(value, str) and _DIGEST.fullmatch(value)
        for value in (state_digest, plan_digest, proposal_digest)
    ):
        raise ProductStoreError("proposal review digests are invalid")
    if content_hash(proposal) != proposal_digest:
        raise ProductStoreError("proposal content digest is mismatched")
    now = utc_now()
    proposal_record_id = "proposal-review-" + uuid.uuid4().hex
    with self._connection(write=True) as connection:
        if connection.execute("SELECT 1 FROM jobs WHERE job_id = ?", (job_id,)).fetchone() is None:
            raise ProductStoreError("proposal review job was not found")
        existing = connection.execute(
            """
            SELECT proposal_record_id FROM ai_proposal_reviews
            WHERE job_id = ? AND source_run_id = ? AND source_proposal_id = ?
              AND state_digest = ? AND plan_digest = ? AND proposal_digest = ?
            """,
            (
                job_id,
                source_run_id,
                source_proposal_id,
                state_digest,
                plan_digest,
                proposal_digest,
            ),
        ).fetchone()
        if existing is not None:
            proposal_record_id = str(existing["proposal_record_id"])
        else:
            connection.execute(
                """
                INSERT INTO ai_proposal_reviews(
                    proposal_record_id, job_id, source_run_id, source_proposal_id,
                    state_digest, plan_digest, proposal_digest, status,
                    record_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
                """,
                (
                    proposal_record_id,
                    job_id,
                    source_run_id,
                    source_proposal_id,
                    state_digest,
                    plan_digest,
                    proposal_digest,
                    _canonical_json(document),
                    now,
                ),
            )
    return self.get_ai_proposal_review(proposal_record_id)


def get_ai_proposal_review(self: ProposalReviewStore, proposal_record_id: str) -> Mapping[str, Any]:
    if not isinstance(proposal_record_id, str) or not _PROPOSAL_RECORD_ID.fullmatch(
        proposal_record_id
    ):
        raise ProductStoreError("proposal review ID is invalid")
    with self._connection() as connection:
        row = connection.execute(
            "SELECT * FROM ai_proposal_reviews WHERE proposal_record_id = ?",
            (proposal_record_id,),
        ).fetchone()
    if row is None:
        raise ProductStoreError("proposal review was not found")
    return self._ai_proposal_review_from_row(row)


def list_ai_proposal_reviews(self: ProposalReviewStore, job_id: str) -> list[Mapping[str, Any]]:
    with self._connection() as connection:
        if connection.execute("SELECT 1 FROM jobs WHERE job_id = ?", (job_id,)).fetchone() is None:
            raise ProductStoreError("proposal review job was not found")
        rows = connection.execute(
            """
            SELECT * FROM ai_proposal_reviews
            WHERE job_id = ? ORDER BY created_at, proposal_record_id
            """,
            (job_id,),
        ).fetchall()
    return [self._ai_proposal_review_from_row(row) for row in rows]


def resolve_ai_proposal_review(
    self: ProposalReviewStore,
    proposal_record_id: str,
    *,
    job_id: str,
    decision: str,
    decided_by: str,
    expected_state_digest: str,
    expected_plan_digest: str,
    expected_proposal_digest: str,
    resolution: Mapping[str, Any],
) -> Mapping[str, Any]:
    if decision not in {"accepted", "rejected"}:
        raise ProductStoreError("proposal decision is invalid")
    identity = decided_by.strip() if isinstance(decided_by, str) else ""
    if not identity or len(identity) > 128:
        raise ProductStoreError("proposal decision identity is invalid")
    if not _PROPOSAL_RECORD_ID.fullmatch(proposal_record_id):
        raise ProductStoreError("proposal review ID is invalid")
    resolution_document = _safe_document(resolution, context="AI proposal resolution")
    expected = (
        expected_state_digest,
        expected_plan_digest,
        expected_proposal_digest,
    )
    if not all(isinstance(value, str) and _DIGEST.fullmatch(value) for value in expected):
        raise ProductStoreError("proposal decision digests are invalid")
    now = utc_now()
    with self._connection(write=True) as connection:
        row = connection.execute(
            "SELECT * FROM ai_proposal_reviews WHERE proposal_record_id = ?",
            (proposal_record_id,),
        ).fetchone()
        if row is None or row["job_id"] != job_id:
            raise ProductStoreError("proposal review was not found for this job")
        if row["status"] != "pending":
            raise ProductStoreError("proposal review is stale or already resolved")
        if (
            row["state_digest"],
            row["plan_digest"],
            row["proposal_digest"],
        ) != expected:
            raise ProductStoreError("proposal decision does not match the reviewed digests")
        cursor = connection.execute(
            """
            UPDATE ai_proposal_reviews
            SET status = ?, resolution_json = ?, decided_at = ?, decided_by = ?
            WHERE proposal_record_id = ? AND status = 'pending'
            """,
            (
                decision,
                _canonical_json(resolution_document),
                now,
                identity,
                proposal_record_id,
            ),
        )
        if cursor.rowcount != 1:
            raise ProductStoreError("proposal decision lost a concurrent race")
    return self.get_ai_proposal_review(proposal_record_id)


def _ai_proposal_review_from_row(row: sqlite3.Row) -> Mapping[str, Any]:
    return {
        "schema_version": "bluefire.ai-proposal-review.v1",
        "proposal_record_id": str(row["proposal_record_id"]),
        "job_id": str(row["job_id"]),
        "source_run_id": str(row["source_run_id"]),
        "source_proposal_id": str(row["source_proposal_id"]),
        "state_digest": str(row["state_digest"]),
        "plan_digest": str(row["plan_digest"]),
        "proposal_digest": str(row["proposal_digest"]),
        "status": str(row["status"]),
        "record": json.loads(row["record_json"]),
        "resolution": (json.loads(row["resolution_json"]) if row["resolution_json"] else None),
        "created_at": str(row["created_at"]),
        "decided_at": str(row["decided_at"]) if row["decided_at"] else None,
        "decided_by": str(row["decided_by"]) if row["decided_by"] else None,
    }
