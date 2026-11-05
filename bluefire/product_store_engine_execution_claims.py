"""Append-only consumption records for accepted external-engine attempts.

Acceptance reserves a durable job.  This store records the later, distinct
moment when the installed runtime consumes that accepted authority.  The row
contains only canonical identities and digests; it carries no executable,
path, credential, admission document, or target data.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast

from . import product_store_engine_action_submissions as submissions
from . import product_store_engine_jobs as jobs
from .engine_action_contract import EngineWorkspaceAction
from .engine_attempt_contract import AttemptCompleteness, AttemptState, EngineAttemptBinding
from .engine_delegation import EngineCapabilityDelegation, EngineDelegationError
from .engine_experiment import CleanupState, EngineExperimentError
from .product_store_errors import ProductStoreError, ResourceConflictError
from .product_store_serialization import canonical_json
from .util import content_hash, parse_iso8601_datetime

_SCHEMA = "bluefire.engine-attempt-execution-claim.v1"
_CLAIM_REF_SCHEMA = "bluefire.engine-attempt-execution-claim-ref.v1"
_PRE_DISPATCH_SCHEMA = "bluefire.engine-pre-dispatch-settlement.v1"
_PRE_DISPATCH_REF_SCHEMA = "bluefire.engine-pre-dispatch-settlement-ref.v1"
_RECONCILIATION_SCHEMA = "bluefire.engine-attempt-reconciliation-intent.v1"
_RECONCILIATION_REF_SCHEMA = "bluefire.engine-attempt-reconciliation-intent-ref.v1"
_JOB = re.compile(r"^job-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_DOCUMENT_BYTES = 8192
_RECOVERY_JOB_STATES = frozenset({"cancelled", "completed", "failed", "interrupted"})
_EXECUTION_CLAIM_POLICY = {
    "schema_version": "bluefire.engine-execution-claim-policy.v1",
    "claim_protocol": "bluefire.engine-attempt-execution-claim.v1",
    "accepted_jobs_adapter": "bluefire.product-store-accepted-engine-jobs.v1",
}

_FIELDS = frozenset(
    {
        "schema_version",
        "claim_ref",
        "job_id",
        "attempt_id",
        "experiment_id",
        "preparation_ref",
        "preparation_id",
        "preparation_record_digest",
        "acceptance_record_digest",
        "binding_digest",
        "delegation_digest",
        "submission_id",
        "intent_digest",
        "job_request_digest",
        "runtime_resolution_ref",
        "preflight_revision",
        "preflight_experiment_digest",
        "claimed_at",
    }
)

_PRE_DISPATCH_FIELDS = frozenset(
    {
        "schema_version",
        "settlement_ref",
        "job_id",
        "attempt_id",
        "experiment_id",
        "preparation_ref",
        "preparation_id",
        "preparation_record_digest",
        "acceptance_record_digest",
        "binding_digest",
        "delegation_digest",
        "submission_id",
        "intent_digest",
        "job_request_digest",
        "prior_revision",
        "prior_experiment_digest",
        "prior_attempt_state",
        "observed_job_state",
        "exit_reason",
        "adapter_pre_dispatch_ref",
        "terminal_record_digest",
        "settled_at",
    }
)
_PRE_DISPATCH_EXIT_REASONS = frozenset(
    {
        "controller_cancelled_before_dispatch",
        "controller_cancelled_before_execution_claim",
        "authority_expired_before_dispatch",
    }
)
_RECONCILIATION_FIELDS = frozenset(
    {
        "schema_version",
        "reconciliation_ref",
        "claim_ref",
        "job_id",
        "job_state",
        "attempt_id",
        "experiment_id",
        "binding_digest",
        "delegation_digest",
        "job_request_digest",
        "runtime_resolution_ref",
        "created_at",
    }
)


@dataclass(frozen=True, slots=True)
class EngineExecutionClaimRecovery:
    """Pinned terminal-job view used only for non-launching reconciliation."""

    document: Mapping[str, Any] | None
    job_id: str
    job_state: str
    pre_dispatch_document: Mapping[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class EngineExecutionClaimResult:
    """Atomic first-launch decision; only ``created`` conveys authority."""

    document: Mapping[str, Any] | None
    created: bool
    job_state: str
    pre_dispatch_ref: str | None


@dataclass(frozen=True, slots=True)
class EngineExecutionReconciliationResult:
    """Exact installed recovery decision created under the purpose lock."""

    claim_document: Mapping[str, Any] | None
    pre_dispatch_document: Mapping[str, Any] | None
    reconciliation_document: Mapping[str, Any] | None
    job_id: str
    job_state: str
    settled_cleanup_evidence_ref: str | None = None
    settled_reconciliation_ref: str | None = None


class EngineExecutionClaimStore(submissions.SubmissionStore, Protocol):
    def _require_engine_attempt_reconciliation_session(self, capability: object) -> None: ...

    def get_accepted_engine_attempt_execution(
        self,
        *,
        binding: Mapping[str, Any],
        delegation: Mapping[str, Any],
        reviewer: str,
    ) -> EngineExecutionClaimRecovery: ...


def initialize_schema(connection: sqlite3.Connection) -> None:
    if not connection.in_transaction:
        raise ProductStoreError("engine execution claim migration requires one transaction")
    rebuilt_pre_dispatch = False
    pre_dispatch_schema = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' "
        "AND name='engine_attempt_pre_dispatch_settlements'"
    ).fetchone()
    if pre_dispatch_schema is not None:
        normalized = re.sub(r"\s+", "", str(pre_dispatch_schema["sql"]))
        required_check = "observed_job_stateIN('running','cancelling','cancelled')"
        if required_check not in normalized:
            if (
                connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' "
                    "AND name='engine_attempt_pre_dispatch_settlements_v22_draft'"
                ).fetchone()
                is not None
            ):
                raise ProductStoreError("engine pre-dispatch draft migration is inconsistent")
            for trigger in (
                "engine_attempt_pre_dispatch_settlements_no_update",
                "engine_attempt_pre_dispatch_settlements_no_delete",
                "engine_attempt_pre_dispatch_settlements_valid_insert",
            ):
                connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
            connection.execute(
                "ALTER TABLE engine_attempt_pre_dispatch_settlements "
                "RENAME TO engine_attempt_pre_dispatch_settlements_v22_draft"
            )
            rebuilt_pre_dispatch = True
    intent_columns = {
        str(row["name"])
        for row in connection.execute(
            "PRAGMA table_info(engine_attempt_reconciliation_intents)"
        ).fetchall()
    }
    if intent_columns and "job_state" not in intent_columns:
        if (
            connection.execute(
                "SELECT 1 FROM engine_attempt_reconciliation_intents LIMIT 1"
            ).fetchone()
            is not None
        ):
            raise ProductStoreError(
                "saved draft engine reconciliation intents require manual recovery"
            )
        for trigger in (
            "engine_attempt_reconciliation_intents_no_update",
            "engine_attempt_reconciliation_intents_no_delete",
            "engine_attempt_reconciliation_intents_valid_insert",
            "engine_attempt_reconciliation_intents_freeze_job_state",
        ):
            connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        connection.execute("DROP TABLE engine_attempt_reconciliation_intents")
    connection.execute("""CREATE TABLE IF NOT EXISTS engine_attempt_execution_claims (
        claim_ref TEXT PRIMARY KEY,
        job_id TEXT NOT NULL UNIQUE REFERENCES jobs(job_id),
        attempt_id TEXT NOT NULL UNIQUE,
        experiment_id TEXT NOT NULL,
        preparation_ref TEXT NOT NULL UNIQUE
          REFERENCES engine_action_acceptances(request_ref),
        preparation_id TEXT NOT NULL UNIQUE
          REFERENCES engine_action_acceptances(preparation_id),
        preparation_record_digest TEXT NOT NULL
          REFERENCES engine_action_preparations(record_digest),
        acceptance_record_digest TEXT NOT NULL UNIQUE
          REFERENCES engine_action_acceptances(record_digest),
        binding_digest TEXT NOT NULL,
        delegation_digest TEXT NOT NULL,
        submission_id TEXT NOT NULL UNIQUE,
        intent_digest TEXT NOT NULL,
        job_request_digest TEXT NOT NULL,
        runtime_resolution_ref TEXT NOT NULL,
        preflight_revision INTEGER NOT NULL CHECK(preflight_revision > 0),
        preflight_experiment_digest TEXT NOT NULL,
        claimed_at TEXT NOT NULL,
        document_json TEXT NOT NULL CHECK(json_valid(document_json))
          CHECK(length(CAST(document_json AS BLOB)) BETWEEN 1 AND 8192),
        record_digest TEXT NOT NULL UNIQUE
    )""")
    connection.execute("""CREATE TABLE IF NOT EXISTS engine_attempt_pre_dispatch_settlements (
        settlement_ref TEXT PRIMARY KEY,
        job_id TEXT NOT NULL UNIQUE REFERENCES jobs(job_id),
        attempt_id TEXT NOT NULL UNIQUE,
        experiment_id TEXT NOT NULL,
        preparation_ref TEXT NOT NULL UNIQUE
          REFERENCES engine_action_acceptances(request_ref),
        preparation_id TEXT NOT NULL UNIQUE
          REFERENCES engine_action_acceptances(preparation_id),
        preparation_record_digest TEXT NOT NULL
          REFERENCES engine_action_preparations(record_digest),
        acceptance_record_digest TEXT NOT NULL UNIQUE
          REFERENCES engine_action_acceptances(record_digest),
        binding_digest TEXT NOT NULL,
        delegation_digest TEXT NOT NULL,
        submission_id TEXT NOT NULL UNIQUE,
        intent_digest TEXT NOT NULL,
        job_request_digest TEXT NOT NULL,
        prior_revision INTEGER NOT NULL CHECK(prior_revision > 0),
        prior_experiment_digest TEXT NOT NULL,
        prior_attempt_state TEXT NOT NULL CHECK(prior_attempt_state IN ('queued','preflight')),
        observed_job_state TEXT NOT NULL
          CHECK(observed_job_state IN ('running','cancelling','cancelled')),
        exit_reason TEXT NOT NULL CHECK(exit_reason IN (
          'controller_cancelled_before_dispatch',
          'controller_cancelled_before_execution_claim',
          'authority_expired_before_dispatch'
        )),
        adapter_pre_dispatch_ref TEXT,
        terminal_record_digest TEXT NOT NULL,
        settled_at TEXT NOT NULL,
        document_json TEXT NOT NULL CHECK(json_valid(document_json))
          CHECK(length(CAST(document_json AS BLOB)) BETWEEN 1 AND 8192),
        record_digest TEXT NOT NULL UNIQUE
    )""")
    connection.execute("""CREATE TABLE IF NOT EXISTS engine_attempt_reconciliation_intents (
        reconciliation_ref TEXT PRIMARY KEY,
        claim_ref TEXT NOT NULL UNIQUE REFERENCES engine_attempt_execution_claims(claim_ref),
        job_id TEXT NOT NULL UNIQUE REFERENCES engine_attempt_execution_claims(job_id),
        job_state TEXT NOT NULL CHECK(job_state IN ('cancelled','completed','failed','interrupted')),
        attempt_id TEXT NOT NULL UNIQUE,
        experiment_id TEXT NOT NULL,
        binding_digest TEXT NOT NULL,
        delegation_digest TEXT NOT NULL,
        job_request_digest TEXT NOT NULL,
        runtime_resolution_ref TEXT NOT NULL,
        created_at TEXT NOT NULL,
        document_json TEXT NOT NULL CHECK(json_valid(document_json))
          CHECK(length(CAST(document_json AS BLOB)) BETWEEN 1 AND 8192),
        record_digest TEXT NOT NULL UNIQUE
    )""")
    if rebuilt_pre_dispatch:
        connection.execute("""INSERT INTO engine_attempt_pre_dispatch_settlements(
                settlement_ref, job_id, attempt_id, experiment_id, preparation_ref,
                preparation_id, preparation_record_digest, acceptance_record_digest,
                binding_digest, delegation_digest, submission_id, intent_digest,
                job_request_digest, prior_revision, prior_experiment_digest,
                prior_attempt_state, observed_job_state, exit_reason,
                adapter_pre_dispatch_ref, terminal_record_digest, settled_at,
                document_json, record_digest
            ) SELECT
                settlement_ref, job_id, attempt_id, experiment_id, preparation_ref,
                preparation_id, preparation_record_digest, acceptance_record_digest,
                binding_digest, delegation_digest, submission_id, intent_digest,
                job_request_digest, prior_revision, prior_experiment_digest,
                prior_attempt_state, observed_job_state, exit_reason,
                adapter_pre_dispatch_ref, terminal_record_digest, settled_at,
                document_json, record_digest
              FROM engine_attempt_pre_dispatch_settlements_v22_draft""")
        connection.execute("DROP TABLE engine_attempt_pre_dispatch_settlements_v22_draft")
    connection.execute("""CREATE TRIGGER IF NOT EXISTS engine_attempt_execution_claims_no_update
        BEFORE UPDATE ON engine_attempt_execution_claims BEGIN
          SELECT RAISE(ABORT, 'engine attempt execution claims are immutable'); END""")
    connection.execute("""CREATE TRIGGER IF NOT EXISTS engine_attempt_execution_claims_no_delete
        BEFORE DELETE ON engine_attempt_execution_claims BEGIN
          SELECT RAISE(ABORT, 'engine attempt execution claims are append-only'); END""")
    connection.execute(
        """CREATE TRIGGER IF NOT EXISTS engine_attempt_pre_dispatch_settlements_no_update
        BEFORE UPDATE ON engine_attempt_pre_dispatch_settlements BEGIN
          SELECT RAISE(ABORT, 'engine pre-dispatch settlements are immutable'); END"""
    )
    connection.execute(
        """CREATE TRIGGER IF NOT EXISTS engine_attempt_pre_dispatch_settlements_no_delete
        BEFORE DELETE ON engine_attempt_pre_dispatch_settlements BEGIN
          SELECT RAISE(ABORT, 'engine pre-dispatch settlements are append-only'); END"""
    )
    connection.execute(
        """CREATE TRIGGER IF NOT EXISTS engine_attempt_reconciliation_intents_no_update
        BEFORE UPDATE ON engine_attempt_reconciliation_intents BEGIN
          SELECT RAISE(ABORT, 'engine reconciliation intents are immutable'); END"""
    )
    connection.execute(
        """CREATE TRIGGER IF NOT EXISTS engine_attempt_reconciliation_intents_no_delete
        BEFORE DELETE ON engine_attempt_reconciliation_intents BEGIN
          SELECT RAISE(ABORT, 'engine reconciliation intents are append-only'); END"""
    )
    # The valid-insert triggers reference each other, so recreate the claim
    # trigger after both v22 tables exist. This also upgrades databases opened
    # by an earlier development build of the unpublished v22 schema.
    connection.execute("DROP TRIGGER IF EXISTS engine_attempt_execution_claims_valid_insert")
    connection.execute("""CREATE TRIGGER engine_attempt_execution_claims_valid_insert
        BEFORE INSERT ON engine_attempt_execution_claims BEGIN
          SELECT CASE WHEN EXISTS(
            SELECT 1 FROM engine_attempt_execution_claims
            WHERE claim_ref=NEW.claim_ref OR job_id=NEW.job_id
              OR attempt_id=NEW.attempt_id OR preparation_ref=NEW.preparation_ref
              OR preparation_id=NEW.preparation_id
              OR acceptance_record_digest=NEW.acceptance_record_digest
              OR submission_id=NEW.submission_id OR record_digest=NEW.record_digest
          ) THEN RAISE(ABORT, 'engine attempt execution claim conflicts') END;
          SELECT CASE WHEN EXISTS(
            SELECT 1 FROM engine_attempt_pre_dispatch_settlements
            WHERE job_id=NEW.job_id OR attempt_id=NEW.attempt_id
              OR preparation_ref=NEW.preparation_ref
              OR preparation_id=NEW.preparation_id
              OR acceptance_record_digest=NEW.acceptance_record_digest
              OR submission_id=NEW.submission_id
          ) THEN RAISE(ABORT, 'engine attempt execution claim was already settled') END;
          SELECT CASE WHEN NOT EXISTS(
            SELECT 1 FROM jobs WHERE job_id=NEW.job_id
              AND kind='engine-attempt' AND state='running'
          ) THEN RAISE(ABORT, 'engine attempt execution claim job is not running') END;
          SELECT CASE WHEN NOT EXISTS(
            SELECT 1 FROM engine_action_acceptances AS acceptance
            JOIN engine_action_preparations AS preparation
              ON preparation.request_ref=acceptance.request_ref
              AND preparation.record_digest=acceptance.preparation_record_digest
            WHERE acceptance.request_ref=NEW.preparation_ref
              AND acceptance.preparation_id=NEW.preparation_id
              AND acceptance.record_digest=NEW.acceptance_record_digest
              AND preparation.record_digest=NEW.preparation_record_digest
              AND preparation.preparation_kind='engine_attempt'
              AND preparation.action_kind IN ('start_baseline', 'start_adaptive_search')
              AND preparation.submission_id=NEW.submission_id
              AND preparation.intent_digest=NEW.intent_digest
              AND json_extract(acceptance.receipt_json, '$.job.job_id')=NEW.job_id
              AND json_extract(acceptance.receipt_json, '$.job.kind')='engine-attempt'
          ) THEN RAISE(ABORT, 'engine attempt execution claim acceptance changed') END;
          SELECT CASE WHEN
            json_extract(NEW.document_json, '$.schema_version')
                 IS NOT 'bluefire.engine-attempt-execution-claim.v1'
            OR json_extract(NEW.document_json, '$.claim_ref') IS NOT NEW.claim_ref
            OR json_extract(NEW.document_json, '$.job_id') IS NOT NEW.job_id
            OR json_extract(NEW.document_json, '$.attempt_id') IS NOT NEW.attempt_id
            OR json_extract(NEW.document_json, '$.experiment_id') IS NOT NEW.experiment_id
            OR json_extract(NEW.document_json, '$.preparation_ref')
                 IS NOT NEW.preparation_ref
            OR json_extract(NEW.document_json, '$.preparation_id')
                 IS NOT NEW.preparation_id
            OR json_extract(NEW.document_json, '$.preparation_record_digest')
                 IS NOT NEW.preparation_record_digest
            OR json_extract(NEW.document_json, '$.acceptance_record_digest')
                 IS NOT NEW.acceptance_record_digest
            OR json_extract(NEW.document_json, '$.binding_digest')
                 IS NOT NEW.binding_digest
            OR json_extract(NEW.document_json, '$.delegation_digest')
                 IS NOT NEW.delegation_digest
            OR json_extract(NEW.document_json, '$.submission_id')
                 IS NOT NEW.submission_id
            OR json_extract(NEW.document_json, '$.intent_digest') IS NOT NEW.intent_digest
            OR json_extract(NEW.document_json, '$.job_request_digest')
                 IS NOT NEW.job_request_digest
            OR json_extract(NEW.document_json, '$.runtime_resolution_ref')
                 IS NOT NEW.runtime_resolution_ref
            OR json_extract(NEW.document_json, '$.preflight_revision')
                 IS NOT NEW.preflight_revision
            OR json_extract(NEW.document_json, '$.preflight_experiment_digest')
                 IS NOT NEW.preflight_experiment_digest
            OR json_extract(NEW.document_json, '$.claimed_at') IS NOT NEW.claimed_at
          THEN RAISE(ABORT, 'engine attempt execution claim document changed') END;
        END""")
    connection.execute(
        "DROP TRIGGER IF EXISTS engine_attempt_pre_dispatch_settlements_valid_insert"
    )
    connection.execute("""CREATE TRIGGER engine_attempt_pre_dispatch_settlements_valid_insert
        BEFORE INSERT ON engine_attempt_pre_dispatch_settlements BEGIN
          SELECT CASE WHEN EXISTS(
            SELECT 1 FROM engine_attempt_pre_dispatch_settlements
            WHERE settlement_ref=NEW.settlement_ref OR job_id=NEW.job_id
              OR attempt_id=NEW.attempt_id OR preparation_ref=NEW.preparation_ref
              OR preparation_id=NEW.preparation_id
              OR acceptance_record_digest=NEW.acceptance_record_digest
              OR submission_id=NEW.submission_id OR record_digest=NEW.record_digest
          ) THEN RAISE(ABORT, 'engine pre-dispatch settlement conflicts') END;
          SELECT CASE WHEN EXISTS(
            SELECT 1 FROM engine_attempt_execution_claims
            WHERE job_id=NEW.job_id OR attempt_id=NEW.attempt_id
              OR preparation_ref=NEW.preparation_ref
              OR preparation_id=NEW.preparation_id
              OR acceptance_record_digest=NEW.acceptance_record_digest
              OR submission_id=NEW.submission_id
          ) THEN RAISE(ABORT, 'engine pre-dispatch settlement conflicts with execution claim') END;
          SELECT CASE WHEN NOT EXISTS(
            SELECT 1 FROM jobs WHERE job_id=NEW.job_id
              AND kind='engine-attempt' AND state=NEW.observed_job_state
              AND state IN ('running','cancelling','cancelled')
          ) THEN RAISE(ABORT, 'engine pre-dispatch settlement job state changed') END;
          SELECT CASE WHEN NOT EXISTS(
            SELECT 1 FROM engine_action_acceptances AS acceptance
            JOIN engine_action_preparations AS preparation
              ON preparation.request_ref=acceptance.request_ref
              AND preparation.record_digest=acceptance.preparation_record_digest
            WHERE acceptance.request_ref=NEW.preparation_ref
              AND acceptance.preparation_id=NEW.preparation_id
              AND acceptance.record_digest=NEW.acceptance_record_digest
              AND preparation.record_digest=NEW.preparation_record_digest
              AND preparation.preparation_kind='engine_attempt'
              AND preparation.action_kind IN ('start_baseline', 'start_adaptive_search')
              AND preparation.submission_id=NEW.submission_id
              AND preparation.intent_digest=NEW.intent_digest
              AND json_extract(acceptance.receipt_json, '$.job.job_id')=NEW.job_id
              AND json_extract(acceptance.receipt_json, '$.job.kind')='engine-attempt'
          ) THEN RAISE(ABORT, 'engine pre-dispatch settlement acceptance changed') END;
          SELECT CASE WHEN
            json_extract(NEW.document_json, '$.schema_version')
                 IS NOT 'bluefire.engine-pre-dispatch-settlement.v1'
            OR json_extract(NEW.document_json, '$.settlement_ref')
                 IS NOT NEW.settlement_ref
            OR json_extract(NEW.document_json, '$.job_id') IS NOT NEW.job_id
            OR json_extract(NEW.document_json, '$.attempt_id') IS NOT NEW.attempt_id
            OR json_extract(NEW.document_json, '$.experiment_id') IS NOT NEW.experiment_id
            OR json_extract(NEW.document_json, '$.preparation_ref')
                 IS NOT NEW.preparation_ref
            OR json_extract(NEW.document_json, '$.preparation_id')
                 IS NOT NEW.preparation_id
            OR json_extract(NEW.document_json, '$.preparation_record_digest')
                 IS NOT NEW.preparation_record_digest
            OR json_extract(NEW.document_json, '$.acceptance_record_digest')
                 IS NOT NEW.acceptance_record_digest
            OR json_extract(NEW.document_json, '$.binding_digest')
                 IS NOT NEW.binding_digest
            OR json_extract(NEW.document_json, '$.delegation_digest')
                 IS NOT NEW.delegation_digest
            OR json_extract(NEW.document_json, '$.submission_id') IS NOT NEW.submission_id
            OR json_extract(NEW.document_json, '$.intent_digest') IS NOT NEW.intent_digest
            OR json_extract(NEW.document_json, '$.job_request_digest')
                 IS NOT NEW.job_request_digest
            OR json_extract(NEW.document_json, '$.prior_revision') IS NOT NEW.prior_revision
            OR json_extract(NEW.document_json, '$.prior_experiment_digest')
                 IS NOT NEW.prior_experiment_digest
            OR json_extract(NEW.document_json, '$.prior_attempt_state')
                 IS NOT NEW.prior_attempt_state
            OR json_extract(NEW.document_json, '$.observed_job_state')
                 IS NOT NEW.observed_job_state
            OR json_extract(NEW.document_json, '$.exit_reason') IS NOT NEW.exit_reason
            OR json_extract(NEW.document_json, '$.adapter_pre_dispatch_ref')
                 IS NOT NEW.adapter_pre_dispatch_ref
            OR json_extract(NEW.document_json, '$.terminal_record_digest')
                 IS NOT NEW.terminal_record_digest
            OR json_extract(NEW.document_json, '$.settled_at') IS NOT NEW.settled_at
          THEN RAISE(ABORT, 'engine pre-dispatch settlement document changed') END;
        END""")
    connection.execute("DROP TRIGGER IF EXISTS engine_attempt_reconciliation_intents_valid_insert")
    connection.execute("""CREATE TRIGGER engine_attempt_reconciliation_intents_valid_insert
        BEFORE INSERT ON engine_attempt_reconciliation_intents BEGIN
          SELECT CASE WHEN EXISTS(
            SELECT 1 FROM engine_attempt_reconciliation_intents
            WHERE reconciliation_ref=NEW.reconciliation_ref OR claim_ref=NEW.claim_ref
              OR job_id=NEW.job_id OR attempt_id=NEW.attempt_id
              OR record_digest=NEW.record_digest
          ) THEN RAISE(ABORT, 'engine reconciliation intent conflicts') END;
          SELECT CASE WHEN NOT EXISTS(
            SELECT 1 FROM engine_attempt_execution_claims AS claim
            JOIN jobs AS job ON job.job_id=claim.job_id
            WHERE claim.claim_ref=NEW.claim_ref AND claim.job_id=NEW.job_id
              AND claim.attempt_id=NEW.attempt_id
              AND claim.experiment_id=NEW.experiment_id
              AND claim.binding_digest=NEW.binding_digest
              AND claim.delegation_digest=NEW.delegation_digest
              AND claim.job_request_digest=NEW.job_request_digest
              AND claim.runtime_resolution_ref=NEW.runtime_resolution_ref
              AND job.kind='engine-attempt'
              AND job.state=NEW.job_state
              AND job.state IN ('cancelled','completed','failed','interrupted')
              AND NEW.created_at >= claim.claimed_at
              AND NEW.created_at >= job.updated_at
          ) THEN RAISE(ABORT, 'engine reconciliation intent claim changed') END;
          SELECT CASE WHEN
            json_extract(NEW.document_json, '$.schema_version')
                 IS NOT 'bluefire.engine-attempt-reconciliation-intent.v1'
            OR json_extract(NEW.document_json, '$.reconciliation_ref')
                 IS NOT NEW.reconciliation_ref
            OR json_extract(NEW.document_json, '$.claim_ref') IS NOT NEW.claim_ref
            OR json_extract(NEW.document_json, '$.job_id') IS NOT NEW.job_id
            OR json_extract(NEW.document_json, '$.job_state') IS NOT NEW.job_state
            OR json_extract(NEW.document_json, '$.attempt_id') IS NOT NEW.attempt_id
            OR json_extract(NEW.document_json, '$.experiment_id') IS NOT NEW.experiment_id
            OR json_extract(NEW.document_json, '$.binding_digest')
                 IS NOT NEW.binding_digest
            OR json_extract(NEW.document_json, '$.delegation_digest')
                 IS NOT NEW.delegation_digest
            OR json_extract(NEW.document_json, '$.job_request_digest')
                 IS NOT NEW.job_request_digest
            OR json_extract(NEW.document_json, '$.runtime_resolution_ref')
                 IS NOT NEW.runtime_resolution_ref
            OR json_extract(NEW.document_json, '$.created_at') IS NOT NEW.created_at
          THEN RAISE(ABORT, 'engine reconciliation intent document changed') END;
        END""")
    connection.execute(
        "DROP TRIGGER IF EXISTS engine_attempt_reconciliation_intents_freeze_job_state"
    )
    connection.execute("""CREATE TRIGGER engine_attempt_reconciliation_intents_freeze_job_state
        BEFORE UPDATE ON jobs
        WHEN OLD.kind='engine-attempt' AND EXISTS(
            SELECT 1 FROM engine_attempt_reconciliation_intents AS intent
            WHERE intent.job_id=OLD.job_id
          )
        BEGIN
          SELECT RAISE(ABORT, 'engine reconciliation intent freezes its job');
        END""")


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ProductStoreError(f"{label} is invalid")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 40:
        raise ProductStoreError(f"{label} is invalid")
    try:
        parse_iso8601_datetime(value)
    except (TypeError, ValueError) as exc:
        raise ProductStoreError(f"{label} is invalid") from exc
    return value


def _claim_reference(document: Mapping[str, Any]) -> str:
    """Derive the immutable claim identity from every saved authority binding."""

    return content_hash(
        {
            "schema_version": _CLAIM_REF_SCHEMA,
            "job_id": document.get("job_id"),
            "attempt_id": document.get("attempt_id"),
            "experiment_id": document.get("experiment_id"),
            "preparation_ref": document.get("preparation_ref"),
            "preparation_id": document.get("preparation_id"),
            "preparation_record_digest": document.get("preparation_record_digest"),
            "acceptance_record_digest": document.get("acceptance_record_digest"),
            "binding_digest": document.get("binding_digest"),
            "delegation_digest": document.get("delegation_digest"),
            "submission_id": document.get("submission_id"),
            "intent_digest": document.get("intent_digest"),
            "job_request_digest": document.get("job_request_digest"),
            "runtime_resolution_ref": document.get("runtime_resolution_ref"),
            "preflight_revision": document.get("preflight_revision"),
            "preflight_experiment_digest": document.get("preflight_experiment_digest"),
            "claimed_at": document.get("claimed_at"),
        }
    )


def _pre_dispatch_reference(document: Mapping[str, Any]) -> str:
    """Derive the terminal no-custody receipt from its complete saved chain."""

    return content_hash(
        {
            "schema_version": _PRE_DISPATCH_REF_SCHEMA,
            **{
                field: document.get(field)
                for field in _PRE_DISPATCH_FIELDS - {"schema_version", "settlement_ref"}
            },
        }
    )


def _reconciliation_reference(document: Mapping[str, Any]) -> str:
    return content_hash(
        {
            "schema_version": _RECONCILIATION_REF_SCHEMA,
            **{
                field: document.get(field)
                for field in _RECONCILIATION_FIELDS
                - {"schema_version", "reconciliation_ref", "created_at"}
            },
        }
    )


def _decode_row(row: sqlite3.Row) -> Mapping[str, Any]:
    try:
        document = json.loads(str(row["document_json"]))
    except (TypeError, ValueError) as exc:
        raise ProductStoreError("saved engine execution claim is invalid") from exc
    if (
        not isinstance(document, dict)
        or set(document) != _FIELDS
        or document.get("schema_version") != _SCHEMA
        or canonical_json(document) != row["document_json"]
        or content_hash(document) != row["record_digest"]
        or document.get("claim_ref") != _claim_reference(document)
        or any(document.get(field) != row[field] for field in _FIELDS - {"schema_version"})
    ):
        raise ProductStoreError("saved engine execution claim integrity changed")
    if len(str(row["document_json"]).encode("utf-8")) > _MAX_DOCUMENT_BYTES:
        raise ProductStoreError("saved engine execution claim is too large")
    _digest(document["claim_ref"], "engine execution claim reference")
    _digest(document["preparation_ref"], "engine preparation reference")
    _digest(document["preparation_id"], "engine preparation identity")
    for field in (
        "preparation_record_digest",
        "acceptance_record_digest",
        "binding_digest",
        "delegation_digest",
        "intent_digest",
        "job_request_digest",
        "runtime_resolution_ref",
        "preflight_experiment_digest",
    ):
        _digest(document[field], f"engine execution claim {field}")
    if (
        not isinstance(document["preflight_revision"], int)
        or isinstance(document["preflight_revision"], bool)
        or document["preflight_revision"] < 1
    ):
        raise ProductStoreError("engine execution claim preflight revision is invalid")
    _timestamp(document["claimed_at"], "engine execution claim time")
    if not isinstance(document["job_id"], str) or _JOB.fullmatch(document["job_id"]) is None:
        raise ProductStoreError("engine execution claim job is invalid")
    return cast(Mapping[str, Any], document)


def _decode_pre_dispatch_row(row: sqlite3.Row) -> Mapping[str, Any]:
    try:
        document = json.loads(str(row["document_json"]))
    except (TypeError, ValueError) as exc:
        raise ProductStoreError("saved engine pre-dispatch settlement is invalid") from exc
    if (
        not isinstance(document, dict)
        or set(document) != _PRE_DISPATCH_FIELDS
        or document.get("schema_version") != _PRE_DISPATCH_SCHEMA
        or canonical_json(document) != row["document_json"]
        or content_hash(document) != row["record_digest"]
        or document.get("settlement_ref") != _pre_dispatch_reference(document)
        or any(
            document.get(field) != row[field] for field in _PRE_DISPATCH_FIELDS - {"schema_version"}
        )
    ):
        raise ProductStoreError("saved engine pre-dispatch settlement integrity changed")
    if len(str(row["document_json"]).encode("utf-8")) > _MAX_DOCUMENT_BYTES:
        raise ProductStoreError("saved engine pre-dispatch settlement is too large")
    for field in (
        "settlement_ref",
        "preparation_ref",
        "preparation_id",
        "preparation_record_digest",
        "acceptance_record_digest",
        "binding_digest",
        "delegation_digest",
        "intent_digest",
        "job_request_digest",
        "prior_experiment_digest",
        "terminal_record_digest",
    ):
        _digest(document[field], f"engine pre-dispatch settlement {field}")
    adapter_ref = document["adapter_pre_dispatch_ref"]
    if adapter_ref is not None:
        _digest(adapter_ref, "engine adapter pre-dispatch reference")
    if (
        not isinstance(document["prior_revision"], int)
        or isinstance(document["prior_revision"], bool)
        or document["prior_revision"] < 1
        or document["prior_attempt_state"] not in {"queued", "preflight"}
        or document["observed_job_state"] not in {"running", "cancelling", "cancelled"}
        or document["exit_reason"] not in _PRE_DISPATCH_EXIT_REASONS
    ):
        raise ProductStoreError("saved engine pre-dispatch settlement state changed")
    _timestamp(document["settled_at"], "engine pre-dispatch settlement time")
    if not isinstance(document["job_id"], str) or _JOB.fullmatch(document["job_id"]) is None:
        raise ProductStoreError("saved engine pre-dispatch settlement job is invalid")
    return cast(Mapping[str, Any], document)


def _decode_reconciliation_row(row: sqlite3.Row) -> Mapping[str, Any]:
    try:
        document = json.loads(str(row["document_json"]))
    except (TypeError, ValueError) as exc:
        raise ProductStoreError("saved engine reconciliation intent is invalid") from exc
    if (
        not isinstance(document, dict)
        or set(document) != _RECONCILIATION_FIELDS
        or document.get("schema_version") != _RECONCILIATION_SCHEMA
        or canonical_json(document) != row["document_json"]
        or content_hash(document) != row["record_digest"]
        or document.get("reconciliation_ref") != _reconciliation_reference(document)
        or any(
            document.get(field) != row[field]
            for field in _RECONCILIATION_FIELDS - {"schema_version"}
        )
    ):
        raise ProductStoreError("saved engine reconciliation intent integrity changed")
    if len(str(row["document_json"]).encode("utf-8")) > _MAX_DOCUMENT_BYTES:
        raise ProductStoreError("saved engine reconciliation intent is too large")
    for field in (
        "reconciliation_ref",
        "claim_ref",
        "binding_digest",
        "delegation_digest",
        "job_request_digest",
        "runtime_resolution_ref",
    ):
        _digest(document[field], f"engine reconciliation intent {field}")
    _timestamp(document["created_at"], "engine reconciliation intent time")
    if (
        not isinstance(document["job_id"], str)
        or _JOB.fullmatch(document["job_id"]) is None
        or document["job_state"] not in _RECOVERY_JOB_STATES
    ):
        raise ProductStoreError("saved engine reconciliation intent job is invalid")
    return cast(Mapping[str, Any], document)


def _find_existing(
    connection: sqlite3.Connection,
    *,
    job_id: str,
    attempt_id: str,
    preparation_ref: str,
    preparation_id: str,
    acceptance_record_digest: str,
    submission_id: str,
) -> sqlite3.Row | None:
    rows = connection.execute(
        """SELECT * FROM engine_attempt_execution_claims
        WHERE job_id=? OR attempt_id=? OR preparation_ref=? OR preparation_id=?
          OR acceptance_record_digest=? OR submission_id=?""",
        (
            job_id,
            attempt_id,
            preparation_ref,
            preparation_id,
            acceptance_record_digest,
            submission_id,
        ),
    ).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise ProductStoreError("engine execution claim identities diverged")
    return cast(sqlite3.Row, rows[0])


def _find_pre_dispatch_settlement(
    connection: sqlite3.Connection,
    *,
    job_id: str,
    attempt_id: str,
    preparation_ref: str,
    preparation_id: str,
    acceptance_record_digest: str,
    submission_id: str,
) -> sqlite3.Row | None:
    rows = connection.execute(
        """SELECT * FROM engine_attempt_pre_dispatch_settlements
        WHERE job_id=? OR attempt_id=? OR preparation_ref=? OR preparation_id=?
          OR acceptance_record_digest=? OR submission_id=?""",
        (
            job_id,
            attempt_id,
            preparation_ref,
            preparation_id,
            acceptance_record_digest,
            submission_id,
        ),
    ).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise ProductStoreError("engine pre-dispatch settlement identities diverged")
    return cast(sqlite3.Row, rows[0])


def _chain(
    store: EngineExecutionClaimStore,
    connection: sqlite3.Connection,
    *,
    job_id: str,
    binding: EngineAttemptBinding,
    delegation: EngineCapabilityDelegation,
    reviewer: str | None,
) -> tuple[
    sqlite3.Row,
    sqlite3.Row,
    Mapping[str, Any],
    Mapping[str, Any],
    Mapping[str, Any],
    sqlite3.Row,
]:
    raw_job = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
    if raw_job is None:
        raise ProductStoreError("accepted engine execution job was not found")
    request, submission = jobs._saved_job_request(store, raw_job)
    preparation_rows = connection.execute(
        """SELECT preparation.request_ref, acceptance.preparation_id,
          preparation.record_digest AS preparation_record_digest,
          acceptance.record_digest AS acceptance_record_digest
        FROM engine_action_preparations AS preparation
        JOIN engine_action_acceptances AS acceptance
          ON acceptance.request_ref=preparation.request_ref
          AND acceptance.preparation_record_digest=preparation.record_digest
        WHERE preparation.submission_id=? AND preparation.intent_digest=?
          AND preparation.preparation_kind='engine_attempt'
          AND preparation.action_kind IN ('start_baseline', 'start_adaptive_search')
          AND json_extract(acceptance.receipt_json, '$.job.job_id')=?
          AND json_extract(acceptance.receipt_json, '$.job.kind')='engine-attempt'""",
        (submission["submission_id"], submission["intent_digest"], job_id),
    ).fetchall()
    if len(preparation_rows) != 1:
        raise ProductStoreError("accepted engine execution preparation was not found")
    prepared = preparation_rows[0]
    row, record, experiment, approval = submissions._load_at(
        store,
        connection,
        experiment_id=binding.experiment_id,
        preparation_id=str(prepared["preparation_id"]),
        request_ref=str(prepared["request_ref"]),
    )
    if (
        record["action_kind"]
        not in {
            EngineWorkspaceAction.START_BASELINE.value,
            EngineWorkspaceAction.START_ADAPTIVE_SEARCH.value,
        }
        or record["preparation_kind"] != "engine_attempt"
    ):
        raise ProductStoreError("accepted engine execution preparation is not an attempt")
    authority = record["protected_request"]["authority"]["document"]
    try:
        retained_binding = EngineAttemptBinding.from_mapping(authority["binding"])
        retained_delegation = EngineCapabilityDelegation.from_mapping(authority["delegation"])
        retained_delegation.validate_attempt_binding(retained_binding)
    except (EngineDelegationError, KeyError, TypeError, ValueError) as exc:
        raise ProductStoreError("accepted engine execution authority is invalid") from exc
    if retained_binding != binding or retained_delegation != delegation:
        raise ProductStoreError("accepted engine execution authority changed")
    if reviewer is None:
        approval_id = record.get("approval_request_id")
        if not isinstance(approval_id, str):
            raise ProductStoreError("accepted engine execution approval is unavailable")
        approval_row = store._approval_row(connection, approval_id)
        retained_reviewer = approval_row["approved_by"]
        if (
            not isinstance(retained_reviewer, str)
            or not retained_reviewer
            or retained_reviewer != retained_reviewer.strip()
        ):
            raise ProductStoreError("accepted engine execution reviewer changed")
        reviewer = retained_reviewer
    receipt = submissions._receipt_at(
        store,
        connection,
        row=row,
        record=record,
        experiment=experiment,
        preparation_id=str(prepared["preparation_id"]),
        reviewer=reviewer,
    )
    accepted_job = submissions._job_at(store, connection, record, experiment)
    if (
        receipt is None
        or accepted_job is None
        or accepted_job.get("job_id") != job_id
        or request != record["protected_request"]["job_request"]
        or submission["intent_digest"] != record["intent_digest"]
    ):
        raise ProductStoreError("accepted engine execution chain changed")
    acceptance = connection.execute(
        """SELECT * FROM engine_action_acceptances
        WHERE request_ref=? AND preparation_id=?
          AND preparation_record_digest=? AND record_digest=?""",
        (
            record["request_ref"],
            prepared["preparation_id"],
            row["record_digest"],
            prepared["acceptance_record_digest"],
        ),
    ).fetchone()
    if acceptance is None:
        raise ProductStoreError("accepted engine execution receipt disappeared")
    if approval is None:
        raise ProductStoreError("accepted engine execution approval is unavailable")
    return (
        cast(sqlite3.Row, raw_job),
        row,
        record,
        receipt,
        approval,
        cast(sqlite3.Row, acceptance),
    )


def _same_claim(
    document: Mapping[str, Any],
    *,
    raw_job: sqlite3.Row,
    preparation_row: sqlite3.Row,
    record: Mapping[str, Any],
    acceptance: sqlite3.Row,
    binding: EngineAttemptBinding,
    delegation: EngineCapabilityDelegation,
    runtime_resolution_ref: str | None,
) -> None:
    expected = {
        "job_id": raw_job["job_id"],
        "attempt_id": binding.attempt_id,
        "experiment_id": binding.experiment_id,
        "preparation_ref": record["request_ref"],
        "preparation_id": acceptance["preparation_id"],
        "preparation_record_digest": preparation_row["record_digest"],
        "acceptance_record_digest": acceptance["record_digest"],
        "binding_digest": binding.binding_digest,
        "delegation_digest": delegation.delegation_digest,
        "submission_id": record["submission_id"],
        "intent_digest": record["intent_digest"],
        "job_request_digest": content_hash(record["protected_request"]["job_request"]),
    }
    if any(document.get(field) != value for field, value in expected.items()) or (
        runtime_resolution_ref is not None
        and document.get("runtime_resolution_ref") != runtime_resolution_ref
    ):
        raise ResourceConflictError("engine execution claim conflicts with accepted authority")


def _same_pre_dispatch_settlement(
    document: Mapping[str, Any],
    *,
    raw_job: sqlite3.Row,
    preparation_row: sqlite3.Row,
    record: Mapping[str, Any],
    acceptance: sqlite3.Row,
    binding: EngineAttemptBinding,
    delegation: EngineCapabilityDelegation,
) -> None:
    expected = {
        "job_id": raw_job["job_id"],
        "attempt_id": binding.attempt_id,
        "experiment_id": binding.experiment_id,
        "preparation_ref": record["request_ref"],
        "preparation_id": acceptance["preparation_id"],
        "preparation_record_digest": preparation_row["record_digest"],
        "acceptance_record_digest": acceptance["record_digest"],
        "binding_digest": binding.binding_digest,
        "delegation_digest": delegation.delegation_digest,
        "submission_id": record["submission_id"],
        "intent_digest": record["intent_digest"],
        "job_request_digest": content_hash(record["protected_request"]["job_request"]),
    }
    if any(document.get(field) != value for field, value in expected.items()):
        raise ResourceConflictError(
            "engine pre-dispatch settlement conflicts with accepted authority"
        )


def _request_uses_execution_claim_policy(request: Mapping[str, Any]) -> bool:
    return (
        request.get("schema_version") == "bluefire.engine-attempt-job.v2"
        and request.get("execution_claim_policy") == _EXECUTION_CLAIM_POLICY
    )


def _require_execution_claim_policy(record: Mapping[str, Any]) -> None:
    request = record["protected_request"]["job_request"]
    if (
        not isinstance(request, Mapping)
        or request.get("schema_version") != "bluefire.engine-attempt-job.v2"
        or request.get("execution_claim_policy") != _EXECUTION_CLAIM_POLICY
    ):
        raise ResourceConflictError(
            "engine execution claim requires its immutable installed policy"
        )


def _validate_preflight_snapshot(
    connection: sqlite3.Connection,
    document: Mapping[str, Any],
    *,
    raw_job: sqlite3.Row,
    record: Mapping[str, Any],
    binding: EngineAttemptBinding,
    delegation: EngineCapabilityDelegation,
) -> Mapping[str, Any]:
    row = connection.execute(
        """SELECT document_json,digest FROM engine_experiment_versions
        WHERE experiment_id=? AND revision=? AND digest=?""",
        (
            binding.experiment_id,
            document["preflight_revision"],
            document["preflight_experiment_digest"],
        ),
    ).fetchone()
    if row is None:
        raise ProductStoreError("engine execution claim preflight snapshot disappeared")
    try:
        experiment = jobs._engine_document(json.loads(str(row["document_json"])))
        _index, entry = experiment._attempt(binding.attempt_id)
    except (EngineExperimentError, TypeError, ValueError) as exc:
        raise ProductStoreError("engine execution claim preflight snapshot is invalid") from exc
    authority = record["protected_request"]["authority"]["document"]
    if (
        experiment.revision != document["preflight_revision"]
        or experiment.digest != document["preflight_experiment_digest"]
        or entry.job_id != raw_job["job_id"]
        or entry.record.binding != binding
        or entry.record.state is not AttemptState.PREFLIGHT
        or entry.record.upstream_session_id is not None
        or entry.record.started_at is not None
        or entry.delegation_digest != delegation.delegation_digest
        or entry.execution_approval_id != record["approval_request_id"]
        or entry.execution_approval_digest != content_hash(authority["approval_binding"])
    ):
        raise ProductStoreError("engine execution claim preflight snapshot changed")
    return {"updated_at": experiment.updated_at}


def _validate_claim_lifetime(
    document: Mapping[str, Any],
    *,
    raw_job: sqlite3.Row,
    preparation_row: sqlite3.Row,
    approval: Mapping[str, Any],
    binding: EngineAttemptBinding,
    delegation: EngineCapabilityDelegation,
    preflight_updated_at: str,
) -> None:
    claimed = parse_iso8601_datetime(document["claimed_at"])
    chronology = (
        parse_iso8601_datetime(str(preparation_row["prepared_at"])),
        parse_iso8601_datetime(delegation.created_at),
        parse_iso8601_datetime(binding.created_at),
        parse_iso8601_datetime(str(raw_job["created_at"])),
        parse_iso8601_datetime(preflight_updated_at),
    )
    expiries = (
        parse_iso8601_datetime(str(preparation_row["expires_at"])),
        parse_iso8601_datetime(delegation.expires_at),
        parse_iso8601_datetime(str(approval["expires_at"])),
    )
    if (
        approval.get("status") != "claimed"
        or approval.get("claimed_at") != raw_job["created_at"]
        or any(moment > claimed for moment in chronology)
        or any(claimed >= expiry for expiry in expiries)
    ):
        raise ResourceConflictError("engine execution claim is outside its authority")


class EngineExecutionClaimStoreMixin:
    def _require_engine_attempt_execution_claim_at(
        self: EngineExecutionClaimStore,
        connection: sqlite3.Connection,
        *,
        job_id: str,
        experiment_id: str,
        attempt_id: str,
        binding_digest: str,
        delegation_digest: str,
        job_request: Mapping[str, Any],
        reconciliation_ref: str | None = None,
        reconciliation_time: str | None = None,
        reconciliation_capability: object | None = None,
    ) -> Mapping[str, Any] | None:
        """Require a decoded exact claim for every effectful v2 mutation."""

        if not _request_uses_execution_claim_policy(job_request):
            if reconciliation_ref is not None:
                raise ResourceConflictError(
                    "generic engine attempt cannot use installed reconciliation"
                )
            return None
        if reconciliation_ref is None and reconciliation_capability is not None:
            raise ProductStoreError("installed reconciliation capability lacks its durable intent")
        row = connection.execute(
            """SELECT * FROM engine_attempt_execution_claims
            WHERE job_id=? OR attempt_id=?""",
            (job_id, attempt_id),
        ).fetchall()
        if len(row) != 1:
            raise ResourceConflictError(
                "installed engine attempt mutation requires its durable execution claim"
            )
        document = _decode_row(cast(sqlite3.Row, row[0]))
        if (
            document.get("job_id") != job_id
            or document.get("experiment_id") != experiment_id
            or document.get("attempt_id") != attempt_id
            or document.get("binding_digest") != binding_digest
            or document.get("delegation_digest") != delegation_digest
            or document.get("job_request_digest") != content_hash(job_request)
        ):
            raise ResourceConflictError(
                "installed engine attempt mutation differs from its execution claim"
            )
        conflicting = connection.execute(
            """SELECT 1 FROM engine_attempt_pre_dispatch_settlements
            WHERE job_id=? OR attempt_id=? LIMIT 1""",
            (job_id, attempt_id),
        ).fetchone()
        if conflicting is not None:
            raise ProductStoreError(
                "engine execution claim conflicts with a pre-dispatch settlement"
            )
        if reconciliation_ref is not None:
            self._require_engine_attempt_reconciliation_session(reconciliation_capability)
            if reconciliation_time is None:
                raise ProductStoreError("engine recovery mutation lacks its reconciliation time")
            reconciliation_time = _timestamp(
                reconciliation_time, "engine reconciliation mutation time"
            )
            reconciliation_ref = _digest(reconciliation_ref, "engine reconciliation reference")
            intent_row = connection.execute(
                """SELECT * FROM engine_attempt_reconciliation_intents
                WHERE reconciliation_ref=? OR claim_ref=? OR job_id=? OR attempt_id=?""",
                (reconciliation_ref, document["claim_ref"], job_id, attempt_id),
            ).fetchall()
            if len(intent_row) != 1:
                raise ResourceConflictError(
                    "engine recovery mutation requires its reconciliation intent"
                )
            intent = _decode_reconciliation_row(cast(sqlite3.Row, intent_row[0]))
            job_state_row = connection.execute(
                "SELECT state,updated_at FROM jobs WHERE job_id=?", (job_id,)
            ).fetchone()
            if job_state_row is None:
                raise ProductStoreError("engine reconciliation job disappeared")
            expected_intent = {
                "reconciliation_ref": reconciliation_ref,
                "claim_ref": document["claim_ref"],
                "job_id": job_id,
                "job_state": job_state_row["state"],
                "attempt_id": attempt_id,
                "experiment_id": experiment_id,
                "binding_digest": binding_digest,
                "delegation_digest": delegation_digest,
                "job_request_digest": content_hash(job_request),
                "runtime_resolution_ref": document["runtime_resolution_ref"],
            }
            if any(intent.get(field) != value for field, value in expected_intent.items()):
                raise ResourceConflictError(
                    "engine recovery mutation differs from its reconciliation intent"
                )
            if parse_iso8601_datetime(str(intent["created_at"])) < parse_iso8601_datetime(
                str(document["claimed_at"])
            ):
                raise ProductStoreError("engine reconciliation intent predates its claim")
            if parse_iso8601_datetime(str(intent["created_at"])) < parse_iso8601_datetime(
                str(job_state_row["updated_at"])
            ):
                raise ProductStoreError("engine reconciliation intent predates its terminal job")
            if parse_iso8601_datetime(reconciliation_time) < parse_iso8601_datetime(
                str(intent["created_at"])
            ):
                raise ResourceConflictError(
                    "engine recovery mutation predates its reconciliation intent"
                )
        return document

    def settle_engine_attempt_pre_dispatch(
        self: EngineExecutionClaimStore,
        *,
        experiment_id: str,
        attempt_id: str,
        job_id: str,
        binding: Mapping[str, Any],
        delegation: Mapping[str, Any],
        record: Mapping[str, Any],
        exit_reason: str,
        adapter_pre_dispatch_ref: str | None,
        settled_at: str,
        expected_revision: int,
        expected_experiment_digest: str,
    ) -> Mapping[str, Any]:
        """Atomically record and settle one exact installed no-custody outcome.

        A precheck digest supplied by the installed adapter is retained as
        provenance, but never authorizes settlement. Authority comes from the
        fresh ProductStore transaction proving the accepted v2 chain, no
        execution claim, no allocated custody, and the exact job/attempt state.
        """

        if exit_reason not in _PRE_DISPATCH_EXIT_REASONS:
            raise ProductStoreError("engine pre-dispatch settlement reason is invalid")
        settled_at = _timestamp(settled_at, "engine pre-dispatch settlement time")
        if adapter_pre_dispatch_ref is not None:
            adapter_pre_dispatch_ref = _digest(
                adapter_pre_dispatch_ref, "engine adapter pre-dispatch reference"
            )
        try:
            checked_delegation = EngineCapabilityDelegation.from_mapping(delegation)
            checked_binding = checked_delegation.validate_attempt_binding(binding)
            terminal = jobs._attempt_record(record)
        except (EngineDelegationError, TypeError, ValueError) as exc:
            raise ProductStoreError("engine pre-dispatch settlement is invalid") from exc
        if (
            checked_binding.experiment_id != experiment_id
            or checked_binding.attempt_id != attempt_id
            or terminal.binding != checked_binding
            or terminal.state is not AttemptState.CANCELLED
            or terminal.upstream_session_id is not None
            or terminal.started_at is not None
            or terminal.exit_code is not None
            or terminal.exit_reason != exit_reason
            or terminal.ended_at != settled_at
            or terminal.completeness.value != "unknown"
        ):
            raise ProductStoreError(
                "engine pre-dispatch settlement requires its exact no-custody terminal record"
            )
        with self._connection(write=True) as connection:
            experiment = jobs._active_experiment_at(
                connection,
                experiment_id,
                expected_revision=expected_revision,
                expected_digest=expected_experiment_digest,
            )
            try:
                _index, entry = experiment._attempt(attempt_id)
            except EngineExperimentError as exc:
                raise ProductStoreError("engine pre-dispatch attempt was not found") from exc
            raw_job, preparation_row, retained, _receipt, approval, acceptance = _chain(
                self,
                connection,
                job_id=job_id,
                binding=checked_binding,
                delegation=checked_delegation,
                reviewer=None,
            )
            _require_execution_claim_policy(retained)
            request = retained["protected_request"]["job_request"]
            if (
                entry.job_id != job_id
                or entry.record.binding != checked_binding
                or entry.record.state not in {AttemptState.QUEUED, AttemptState.PREFLIGHT}
                or entry.record.upstream_session_id is not None
                or entry.record.started_at is not None
                or entry.settled_at is not None
                or entry.artifact_manifest_ref is not None
                or entry.evidence
                or entry.cleanup_state is not CleanupState.PENDING
                or entry.cleanup_evidence_ref is not None
                or entry.delegation_digest != checked_delegation.delegation_digest
            ):
                raise ResourceConflictError(
                    "engine pre-dispatch settlement requires its exact unallocated attempt"
                )
            claim = _find_existing(
                connection,
                job_id=job_id,
                attempt_id=attempt_id,
                preparation_ref=retained["request_ref"],
                preparation_id=acceptance["preparation_id"],
                acceptance_record_digest=acceptance["record_digest"],
                submission_id=retained["submission_id"],
            )
            if claim is not None:
                _decode_row(claim)
                raise ResourceConflictError(
                    "engine pre-dispatch settlement conflicts with execution custody"
                )
            existing = _find_pre_dispatch_settlement(
                connection,
                job_id=job_id,
                attempt_id=attempt_id,
                preparation_ref=retained["request_ref"],
                preparation_id=acceptance["preparation_id"],
                acceptance_record_digest=acceptance["record_digest"],
                submission_id=retained["submission_id"],
            )
            if existing is not None:
                # A row without its matching terminal experiment version is not
                # proof of absence. Treat it as tamper/crash ambiguity rather
                # than consuming it as authority.
                _decode_pre_dispatch_row(existing)
                raise ResourceConflictError(
                    "engine pre-dispatch settlement already exists without its terminal state"
                )
            observed_job_state = str(raw_job["state"])
            prior_state = entry.record.state.value
            if exit_reason == "controller_cancelled_before_dispatch":
                valid_state = observed_job_state in {"cancelling", "cancelled"} and (
                    prior_state == "queued"
                )
                if adapter_pre_dispatch_ref is not None:
                    valid_state = False
            elif exit_reason == "controller_cancelled_before_execution_claim":
                valid_state = observed_job_state == "cancelling" and prior_state == "preflight"
                if adapter_pre_dispatch_ref is None:
                    valid_state = False
            else:
                valid_state = observed_job_state in {"running", "cancelling"} and (
                    prior_state == "preflight"
                )
                authority = retained["protected_request"]["authority"]["document"]
                approval_binding = authority["approval_binding"]
                current_time = parse_iso8601_datetime(settled_at)
                valid_state = (
                    valid_state
                    and parse_iso8601_datetime(str(raw_job["created_at"])) <= current_time
                    and (
                        current_time >= parse_iso8601_datetime(checked_delegation.expires_at)
                        or current_time >= parse_iso8601_datetime(approval_binding["expires_at"])
                    )
                )
                if adapter_pre_dispatch_ref is not None:
                    valid_state = False
            if not valid_state:
                raise ResourceConflictError(
                    "engine pre-dispatch settlement job or attempt state changed"
                )
            if (
                parse_iso8601_datetime(experiment.updated_at) > parse_iso8601_datetime(settled_at)
                or approval.get("status") != "claimed"
            ):
                raise ResourceConflictError(
                    "engine pre-dispatch settlement is outside its accepted chronology"
                )
            document: dict[str, Any] = {
                "schema_version": _PRE_DISPATCH_SCHEMA,
                "settlement_ref": "",
                "job_id": job_id,
                "attempt_id": attempt_id,
                "experiment_id": experiment_id,
                "preparation_ref": retained["request_ref"],
                "preparation_id": acceptance["preparation_id"],
                "preparation_record_digest": preparation_row["record_digest"],
                "acceptance_record_digest": acceptance["record_digest"],
                "binding_digest": checked_binding.binding_digest,
                "delegation_digest": checked_delegation.delegation_digest,
                "submission_id": retained["submission_id"],
                "intent_digest": retained["intent_digest"],
                "job_request_digest": content_hash(request),
                "prior_revision": experiment.revision,
                "prior_experiment_digest": experiment.digest,
                "prior_attempt_state": prior_state,
                "observed_job_state": observed_job_state,
                "exit_reason": exit_reason,
                "adapter_pre_dispatch_ref": adapter_pre_dispatch_ref,
                "terminal_record_digest": content_hash(terminal.to_dict()),
                "settled_at": settled_at,
            }
            document["settlement_ref"] = _pre_dispatch_reference(document)
            encoded = canonical_json(document)
            if len(encoded.encode("utf-8")) > _MAX_DOCUMENT_BYTES:
                raise ProductStoreError("engine pre-dispatch settlement is too large")
            connection.execute(
                """INSERT INTO engine_attempt_pre_dispatch_settlements(
                settlement_ref,job_id,attempt_id,experiment_id,preparation_ref,preparation_id,
                preparation_record_digest,acceptance_record_digest,binding_digest,
                delegation_digest,submission_id,intent_digest,job_request_digest,
                prior_revision,prior_experiment_digest,prior_attempt_state,
                observed_job_state,exit_reason,adapter_pre_dispatch_ref,
                terminal_record_digest,settled_at,document_json,record_digest
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    document["settlement_ref"],
                    job_id,
                    attempt_id,
                    experiment_id,
                    retained["request_ref"],
                    acceptance["preparation_id"],
                    preparation_row["record_digest"],
                    acceptance["record_digest"],
                    checked_binding.binding_digest,
                    checked_delegation.delegation_digest,
                    retained["submission_id"],
                    retained["intent_digest"],
                    content_hash(request),
                    experiment.revision,
                    experiment.digest,
                    prior_state,
                    observed_job_state,
                    exit_reason,
                    adapter_pre_dispatch_ref,
                    content_hash(terminal.to_dict()),
                    settled_at,
                    encoded,
                    content_hash(document),
                ),
            )
            updated = experiment.settle_attempt(
                terminal,
                engine_evidence=(),
                artifact_manifest_ref=None,
                cleanup_state=CleanupState.VERIFIED_ABSENT,
                cleanup_evidence_ref=str(document["settlement_ref"]),
                settled_at=settled_at,
            )
            return jobs._append_experiment_at(connection, experiment, updated)

    def inspect_accepted_engine_attempt_pre_dispatch_cancellation(
        self: EngineExecutionClaimStore,
        *,
        job_id: str,
        binding: Mapping[str, Any],
        delegation: Mapping[str, Any],
        reviewer: str,
        checked_at: str,
    ) -> EngineExecutionClaimResult | None:
        """Observe cancellation before admission resolution or any claim/effect."""

        if not isinstance(job_id, str) or _JOB.fullmatch(job_id) is None:
            raise ProductStoreError("engine execution claim job is invalid")
        checked_at = _timestamp(checked_at, "engine execution cancellation check time")
        try:
            checked_delegation = EngineCapabilityDelegation.from_mapping(delegation)
            checked_binding = checked_delegation.validate_attempt_binding(binding)
        except (EngineDelegationError, TypeError, ValueError) as exc:
            raise ProductStoreError("engine execution claim authority is invalid") from exc
        with self._connection(write=True) as connection:
            raw_job, preparation_row, record, _receipt, _approval, acceptance = _chain(
                self,
                connection,
                job_id=job_id,
                binding=checked_binding,
                delegation=checked_delegation,
                reviewer=reviewer,
            )
            _require_execution_claim_policy(record)
            existing = _find_existing(
                connection,
                job_id=job_id,
                attempt_id=checked_binding.attempt_id,
                preparation_ref=record["request_ref"],
                preparation_id=acceptance["preparation_id"],
                acceptance_record_digest=acceptance["record_digest"],
                submission_id=record["submission_id"],
            )
            if existing is not None:
                document = _decode_row(existing)
                _same_claim(
                    document,
                    raw_job=raw_job,
                    preparation_row=preparation_row,
                    record=record,
                    acceptance=acceptance,
                    binding=checked_binding,
                    delegation=checked_delegation,
                    runtime_resolution_ref=None,
                )
                return None
            active = jobs._active_experiment_at(connection, checked_binding.experiment_id)
            try:
                _index, entry = active._attempt(checked_binding.attempt_id)
            except EngineExperimentError as exc:
                raise ProductStoreError("engine execution claim attempt was not found") from exc
            authority = record["protected_request"]["authority"]["document"]
            if (
                entry.job_id != job_id
                or entry.record.binding != checked_binding
                or entry.record.state is not AttemptState.PREFLIGHT
                or entry.record.upstream_session_id is not None
                or entry.record.started_at is not None
                or entry.delegation_digest != checked_delegation.delegation_digest
                or entry.execution_approval_id != record["approval_request_id"]
                or entry.execution_approval_digest != content_hash(authority["approval_binding"])
            ):
                raise ResourceConflictError(
                    "engine execution cancellation requires its exact preflight attempt"
                )
            job_state = str(raw_job["state"])
            if job_state != "cancelling":
                return None
            return EngineExecutionClaimResult(
                document=None,
                created=False,
                job_state=job_state,
                pre_dispatch_ref=content_hash(
                    {
                        "schema_version": "bluefire.engine-pre-dispatch-cancellation.v1",
                        "job_id": job_id,
                        "attempt_id": checked_binding.attempt_id,
                        "binding_digest": checked_binding.binding_digest,
                        "delegation_digest": checked_delegation.delegation_digest,
                        "preparation_ref": record["request_ref"],
                        "acceptance_record_digest": acceptance["record_digest"],
                        "preflight_revision": active.revision,
                        "preflight_experiment_digest": active.digest,
                        "job_state": job_state,
                        "recorded_at": checked_at,
                    }
                ),
            )

    def settle_unclaimed_engine_attempt_recovery(
        self: EngineExecutionClaimStore,
        *,
        experiment_id: str,
        attempt_id: str,
        job_id: str,
        job_state: str,
        binding_digest: str,
        delegation_digest: str,
        cleanup_evidence_ref: str,
        timestamp: str,
        expected_revision: int,
        expected_experiment_digest: str,
        reconciliation_capability: object,
    ) -> Mapping[str, Any]:
        """Atomically retain UNKNOWN when terminal history has no claim."""

        self._require_engine_attempt_reconciliation_session(reconciliation_capability)
        timestamp = _timestamp(timestamp, "engine unclaimed recovery time")
        cleanup_evidence_ref = _digest(cleanup_evidence_ref, "engine unclaimed recovery evidence")
        binding_digest = _digest(binding_digest, "engine unclaimed recovery binding")
        delegation_digest = _digest(delegation_digest, "engine unclaimed recovery delegation")
        if job_state not in {"cancelled", "failed", "interrupted"}:
            raise ProductStoreError("unclaimed engine recovery job state is invalid")
        expected_receipt = content_hash(
            {
                "schema_version": "bluefire.engine-unclaimed-recovery.v1",
                "attempt_id": attempt_id,
                "binding_digest": binding_digest,
                "delegation_digest": delegation_digest,
                "job_id": job_id,
                "job_state": job_state,
                "recorded_at": timestamp,
            }
        )
        if cleanup_evidence_ref != expected_receipt:
            raise ProductStoreError("unclaimed engine recovery receipt changed")
        with self._connection(write=True) as connection:
            experiment = jobs._active_experiment_at(
                connection,
                experiment_id,
                expected_revision=expected_revision,
                expected_digest=expected_experiment_digest,
            )
            try:
                _index, entry = experiment._attempt(attempt_id)
            except EngineExperimentError as exc:
                raise ProductStoreError("unclaimed engine recovery attempt was not found") from exc
            job = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            if (
                job is None
                or job["kind"] != "engine-attempt"
                or job["state"] != job_state
                or entry.job_id != job_id
                or entry.record.binding_digest != binding_digest
                or entry.delegation_digest != delegation_digest
            ):
                raise ResourceConflictError("unclaimed engine recovery state changed")
            request, _submission = jobs._saved_job_request(self, job)
            jobs._validate_saved_attempt_request(
                request,
                experiment_id=experiment_id,
                attempt_id=attempt_id,
                binding_digest=binding_digest,
                delegation_digest=delegation_digest,
                execution_approval_digest=entry.execution_approval_digest,
                execution_approval_id=entry.execution_approval_id,
            )
            if not _request_uses_execution_claim_policy(request):
                raise ResourceConflictError(
                    "unclaimed engine recovery requires its installed policy"
                )
            claim = connection.execute(
                """SELECT 1 FROM engine_attempt_execution_claims
                WHERE job_id=? OR attempt_id=? LIMIT 1""",
                (job_id, attempt_id),
            ).fetchone()
            pre_dispatch = connection.execute(
                """SELECT 1 FROM engine_attempt_pre_dispatch_settlements
                WHERE job_id=? OR attempt_id=? LIMIT 1""",
                (job_id, attempt_id),
            ).fetchone()
            if claim is not None or pre_dispatch is not None:
                raise ResourceConflictError(
                    "unclaimed engine recovery gained durable custody history"
                )
            progress = json.loads(str(job["progress_json"]))
            _context, delegation, _approval = jobs._parse_context(
                progress.get("_engine_execution") if isinstance(progress, dict) else None
            )
            binding = delegation.validate_attempt_binding(entry.record.binding)
            if (
                binding.binding_digest != binding_digest
                or delegation.delegation_digest != delegation_digest
            ):
                raise ProductStoreError("unclaimed engine recovery authority changed")
            if entry.settled_at is not None:
                existing_receipt = content_hash(
                    {
                        "schema_version": "bluefire.engine-unclaimed-recovery.v1",
                        "attempt_id": attempt_id,
                        "binding_digest": binding_digest,
                        "delegation_digest": delegation_digest,
                        "job_id": job_id,
                        "job_state": job_state,
                        "recorded_at": entry.settled_at,
                    }
                )
                expected_terminal = (
                    AttemptState.CANCELLED if job_state == "cancelled" else AttemptState.FAILED
                )
                expected_limitations = (
                    "No durable execution claim exists; prior custody remains unknown.",
                )
                if (
                    entry.record.state is not expected_terminal
                    or entry.record.upstream_session_id is not None
                    or entry.record.started_at is not None
                    or entry.record.ended_at != entry.settled_at
                    or entry.record.exit_code is not None
                    or entry.record.completeness is not AttemptCompleteness.UNKNOWN
                    or entry.record.exit_reason != "installed_execution_claim_unknown"
                    or entry.record.limitations != expected_limitations
                    or entry.evidence
                    or entry.artifact_manifest_ref is not None
                    or entry.cleanup_state is not CleanupState.UNKNOWN
                    or entry.cleanup_evidence_ref != existing_receipt
                    or any(
                        observation.attempt_id == attempt_id
                        for observation in experiment.independent_observations
                    )
                ):
                    raise ResourceConflictError("saved unclaimed engine recovery outcome changed")
                prior_row = connection.execute(
                    """SELECT document_json FROM engine_experiment_versions
                    WHERE experiment_id=? AND revision=?""",
                    (experiment_id, experiment.revision - 1),
                ).fetchone()
                if prior_row is None:
                    raise ProductStoreError("unclaimed engine recovery predecessor disappeared")
                try:
                    prior = jobs._engine_document(json.loads(str(prior_row["document_json"])))
                    _prior_index, prior_entry = prior._attempt(attempt_id)
                    if (
                        prior_entry.record.state
                        not in {AttemptState.QUEUED, AttemptState.PREFLIGHT}
                        or prior_entry.record.upstream_session_id is not None
                        or prior_entry.record.started_at is not None
                        or prior_entry.settled_at is not None
                        or prior_entry.evidence
                        or prior_entry.artifact_manifest_ref is not None
                        or prior_entry.cleanup_state is not CleanupState.PENDING
                        or prior_entry.cleanup_evidence_ref is not None
                    ):
                        raise EngineExperimentError(
                            "unclaimed recovery predecessor has possible custody"
                        )
                    rebuilt_record = prior_entry.record.transition(
                        expected_terminal,
                        timestamp=entry.settled_at,
                        completeness=AttemptCompleteness.UNKNOWN,
                        exit_reason="installed_execution_claim_unknown",
                        limitations=expected_limitations,
                    )
                    rebuilt = prior.settle_attempt(
                        rebuilt_record,
                        engine_evidence=(),
                        artifact_manifest_ref=None,
                        cleanup_state=CleanupState.UNKNOWN,
                        cleanup_evidence_ref=existing_receipt,
                        settled_at=entry.settled_at,
                    )
                except (EngineExperimentError, TypeError, ValueError) as exc:
                    raise ProductStoreError(
                        "unclaimed engine recovery predecessor is invalid"
                    ) from exc
                if rebuilt.to_dict() != experiment.to_dict():
                    raise ProductStoreError("saved unclaimed engine recovery history changed")
                return experiment.to_dict()
            if (
                entry.record.state not in {AttemptState.QUEUED, AttemptState.PREFLIGHT}
                or entry.record.upstream_session_id is not None
                or entry.record.started_at is not None
                or entry.record.ended_at is not None
                or entry.record.exit_code is not None
                or entry.record.completeness is not AttemptCompleteness.UNKNOWN
                or entry.record.exit_reason is not None
                or entry.record.limitations
                or entry.evidence
                or entry.artifact_manifest_ref is not None
                or entry.cleanup_state is not CleanupState.PENDING
                or entry.cleanup_evidence_ref is not None
                or any(
                    observation.attempt_id == attempt_id
                    for observation in experiment.independent_observations
                )
            ):
                raise ResourceConflictError("unclaimed engine recovery has possible prior custody")
            terminal_state = (
                AttemptState.CANCELLED if job_state == "cancelled" else AttemptState.FAILED
            )
            terminal = entry.record.transition(
                terminal_state,
                timestamp=timestamp,
                completeness=AttemptCompleteness.UNKNOWN,
                exit_reason="installed_execution_claim_unknown",
                limitations=("No durable execution claim exists; prior custody remains unknown.",),
            )
            updated = experiment.settle_attempt(
                terminal,
                engine_evidence=(),
                artifact_manifest_ref=None,
                cleanup_state=CleanupState.UNKNOWN,
                cleanup_evidence_ref=cleanup_evidence_ref,
                settled_at=timestamp,
            )
            return jobs._append_experiment_at(connection, experiment, updated)

    def claim_accepted_engine_attempt_execution(
        self: EngineExecutionClaimStore,
        *,
        job_id: str,
        binding: Mapping[str, Any],
        delegation: Mapping[str, Any],
        runtime_resolution_ref: str,
        reviewer: str,
        claimed_at: str,
    ) -> EngineExecutionClaimResult:
        if not isinstance(job_id, str) or _JOB.fullmatch(job_id) is None:
            raise ProductStoreError("engine execution claim job is invalid")
        runtime_resolution_ref = _digest(
            runtime_resolution_ref, "engine execution runtime resolution"
        )
        claimed_at = _timestamp(claimed_at, "engine execution claim time")
        try:
            checked_delegation = EngineCapabilityDelegation.from_mapping(delegation)
            checked_binding = checked_delegation.validate_attempt_binding(binding)
        except (EngineDelegationError, TypeError, ValueError) as exc:
            raise ProductStoreError("engine execution claim authority is invalid") from exc
        with self._connection(write=True) as connection:
            raw_job, preparation_row, record, _receipt, approval, acceptance = _chain(
                self,
                connection,
                job_id=job_id,
                binding=checked_binding,
                delegation=checked_delegation,
                reviewer=reviewer,
            )
            _require_execution_claim_policy(record)
            existing = _find_existing(
                connection,
                job_id=job_id,
                attempt_id=checked_binding.attempt_id,
                preparation_ref=record["request_ref"],
                preparation_id=acceptance["preparation_id"],
                acceptance_record_digest=acceptance["record_digest"],
                submission_id=record["submission_id"],
            )
            if existing is not None:
                document = _decode_row(existing)
                _same_claim(
                    document,
                    raw_job=raw_job,
                    preparation_row=preparation_row,
                    record=record,
                    acceptance=acceptance,
                    binding=checked_binding,
                    delegation=checked_delegation,
                    runtime_resolution_ref=runtime_resolution_ref,
                )
                preflight = _validate_preflight_snapshot(
                    connection,
                    document,
                    raw_job=raw_job,
                    record=record,
                    binding=checked_binding,
                    delegation=checked_delegation,
                )
                _validate_claim_lifetime(
                    document,
                    raw_job=raw_job,
                    preparation_row=preparation_row,
                    approval=approval,
                    binding=checked_binding,
                    delegation=checked_delegation,
                    preflight_updated_at=str(preflight["updated_at"]),
                )
                return EngineExecutionClaimResult(
                    document=document,
                    created=False,
                    job_state=str(raw_job["state"]),
                    pre_dispatch_ref=None,
                )
            active = jobs._active_experiment_at(connection, checked_binding.experiment_id)
            try:
                _index, entry = active._attempt(checked_binding.attempt_id)
            except EngineExperimentError as exc:
                raise ProductStoreError("engine execution claim attempt was not found") from exc
            authority = record["protected_request"]["authority"]["document"]
            approval_binding = authority["approval_binding"]
            if (
                entry.job_id != job_id
                or entry.record.binding != checked_binding
                or entry.record.state is not AttemptState.PREFLIGHT
                or entry.record.upstream_session_id is not None
                or entry.record.started_at is not None
                or entry.delegation_digest != checked_delegation.delegation_digest
                or entry.execution_approval_id != record["approval_request_id"]
                or entry.execution_approval_digest != content_hash(approval_binding)
            ):
                raise ResourceConflictError(
                    "engine execution claim requires its exact preflight attempt"
                )
            job_state = str(raw_job["state"])
            if raw_job["kind"] != "engine-attempt":
                raise ResourceConflictError("engine execution claim requires its engine job")
            if job_state == "cancelling":
                return EngineExecutionClaimResult(
                    document=None,
                    created=False,
                    job_state=job_state,
                    pre_dispatch_ref=content_hash(
                        {
                            "schema_version": "bluefire.engine-pre-dispatch-cancellation.v1",
                            "job_id": job_id,
                            "attempt_id": checked_binding.attempt_id,
                            "binding_digest": checked_binding.binding_digest,
                            "delegation_digest": checked_delegation.delegation_digest,
                            "preparation_ref": record["request_ref"],
                            "acceptance_record_digest": acceptance["record_digest"],
                            "preflight_revision": active.revision,
                            "preflight_experiment_digest": active.digest,
                            "job_state": job_state,
                            "recorded_at": claimed_at,
                        }
                    ),
                )
            if job_state != "running":
                raise ResourceConflictError("engine execution claim requires its running job")
            document = {
                "schema_version": _SCHEMA,
                "claim_ref": "",
                "job_id": job_id,
                "attempt_id": checked_binding.attempt_id,
                "experiment_id": checked_binding.experiment_id,
                "preparation_ref": record["request_ref"],
                "preparation_id": acceptance["preparation_id"],
                "preparation_record_digest": preparation_row["record_digest"],
                "acceptance_record_digest": acceptance["record_digest"],
                "binding_digest": checked_binding.binding_digest,
                "delegation_digest": checked_delegation.delegation_digest,
                "submission_id": record["submission_id"],
                "intent_digest": record["intent_digest"],
                "job_request_digest": content_hash(record["protected_request"]["job_request"]),
                "runtime_resolution_ref": runtime_resolution_ref,
                "preflight_revision": active.revision,
                "preflight_experiment_digest": active.digest,
                "claimed_at": claimed_at,
            }
            document["claim_ref"] = _claim_reference(document)
            claim_ref = document["claim_ref"]
            _validate_claim_lifetime(
                document,
                raw_job=raw_job,
                preparation_row=preparation_row,
                approval=approval,
                binding=checked_binding,
                delegation=checked_delegation,
                preflight_updated_at=active.updated_at,
            )
            encoded = canonical_json(document)
            if len(encoded.encode("utf-8")) > _MAX_DOCUMENT_BYTES:
                raise ProductStoreError("engine execution claim is too large")
            connection.execute(
                """INSERT INTO engine_attempt_execution_claims(
                claim_ref,job_id,attempt_id,experiment_id,preparation_ref,preparation_id,
                preparation_record_digest,acceptance_record_digest,binding_digest,
                delegation_digest,submission_id,intent_digest,runtime_resolution_ref,
                job_request_digest,preflight_revision,preflight_experiment_digest,
                claimed_at,document_json,record_digest
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    claim_ref,
                    job_id,
                    checked_binding.attempt_id,
                    checked_binding.experiment_id,
                    record["request_ref"],
                    acceptance["preparation_id"],
                    preparation_row["record_digest"],
                    acceptance["record_digest"],
                    checked_binding.binding_digest,
                    checked_delegation.delegation_digest,
                    record["submission_id"],
                    record["intent_digest"],
                    runtime_resolution_ref,
                    content_hash(record["protected_request"]["job_request"]),
                    active.revision,
                    active.digest,
                    claimed_at,
                    encoded,
                    content_hash(document),
                ),
            )
            return EngineExecutionClaimResult(
                document=cast(Mapping[str, Any], document),
                created=True,
                job_state=job_state,
                pre_dispatch_ref=None,
            )

    def get_accepted_engine_attempt_execution(
        self: EngineExecutionClaimStore,
        *,
        binding: Mapping[str, Any],
        delegation: Mapping[str, Any],
        reviewer: str,
    ) -> EngineExecutionClaimRecovery:
        try:
            checked_delegation = EngineCapabilityDelegation.from_mapping(delegation)
            checked_binding = checked_delegation.validate_attempt_binding(binding)
        except (EngineDelegationError, TypeError, ValueError) as exc:
            raise ProductStoreError("engine execution claim authority is invalid") from exc
        with self._connection() as connection:
            # Pin claim, lineage, terminal job state, and gate provenance to one
            # SQLite snapshot. ProductStore's Python lock does not serialize a
            # separate service process.
            if not connection.in_transaction:
                connection.execute("BEGIN")
            active = jobs._active_experiment_at(connection, checked_binding.experiment_id)
            try:
                _index, entry = active._attempt(checked_binding.attempt_id)
            except EngineExperimentError as exc:
                raise ProductStoreError(
                    "engine execution reconciliation attempt was not found"
                ) from exc
            if not isinstance(entry.job_id, str) or _JOB.fullmatch(entry.job_id) is None:
                raise ProductStoreError("engine execution reconciliation job is invalid")
            raw_job, preparation_row, record, _receipt, approval, acceptance = _chain(
                self,
                connection,
                job_id=entry.job_id,
                binding=checked_binding,
                delegation=checked_delegation,
                reviewer=reviewer,
            )
            job_state = str(raw_job["state"])
            if job_state not in _RECOVERY_JOB_STATES:
                raise ResourceConflictError(
                    "engine execution reconciliation requires its terminal job"
                )
            if job_state == "completed" and (
                entry.record.state
                not in {
                    AttemptState.COMPLETED,
                    AttemptState.PARTIAL,
                    AttemptState.FAILED,
                    AttemptState.CANCELLED,
                    AttemptState.BUDGET_EXHAUSTED,
                    AttemptState.UNKNOWN,
                }
                or entry.settled_at is None
            ):
                raise ResourceConflictError("completed engine job has no settled attempt outcome")
            row = _find_existing(
                connection,
                job_id=entry.job_id,
                attempt_id=checked_binding.attempt_id,
                preparation_ref=record["request_ref"],
                preparation_id=acceptance["preparation_id"],
                acceptance_record_digest=acceptance["record_digest"],
                submission_id=record["submission_id"],
            )
            pre_dispatch_row = _find_pre_dispatch_settlement(
                connection,
                job_id=entry.job_id,
                attempt_id=checked_binding.attempt_id,
                preparation_ref=record["request_ref"],
                preparation_id=acceptance["preparation_id"],
                acceptance_record_digest=acceptance["record_digest"],
                submission_id=record["submission_id"],
            )
            if row is not None and pre_dispatch_row is not None:
                raise ProductStoreError(
                    "engine execution claim conflicts with pre-dispatch settlement history"
                )
            if row is None:
                if pre_dispatch_row is not None:
                    _require_execution_claim_policy(record)
                    pre_dispatch = _decode_pre_dispatch_row(pre_dispatch_row)
                    _same_pre_dispatch_settlement(
                        pre_dispatch,
                        raw_job=raw_job,
                        preparation_row=preparation_row,
                        record=record,
                        acceptance=acceptance,
                        binding=checked_binding,
                        delegation=checked_delegation,
                    )
                    prior_row = connection.execute(
                        """SELECT document_json,digest FROM engine_experiment_versions
                        WHERE experiment_id=? AND revision=? AND digest=?""",
                        (
                            checked_binding.experiment_id,
                            pre_dispatch["prior_revision"],
                            pre_dispatch["prior_experiment_digest"],
                        ),
                    ).fetchone()
                    if prior_row is None:
                        raise ProductStoreError(
                            "engine pre-dispatch settlement prior state disappeared"
                        )
                    try:
                        prior = jobs._engine_document(json.loads(str(prior_row["document_json"])))
                        _prior_index, prior_entry = prior._attempt(checked_binding.attempt_id)
                    except (EngineExperimentError, TypeError, ValueError) as exc:
                        raise ProductStoreError(
                            "engine pre-dispatch settlement prior state is invalid"
                        ) from exc
                    if (
                        prior.digest != pre_dispatch["prior_experiment_digest"]
                        or prior_entry.job_id != entry.job_id
                        or prior_entry.record.binding != checked_binding
                        or prior_entry.record.state.value != pre_dispatch["prior_attempt_state"]
                        or prior_entry.record.upstream_session_id is not None
                        or prior_entry.record.started_at is not None
                        or prior_entry.settled_at is not None
                        or content_hash(entry.record.to_dict())
                        != pre_dispatch["terminal_record_digest"]
                        or entry.record.state is not AttemptState.CANCELLED
                        or entry.record.upstream_session_id is not None
                        or entry.record.started_at is not None
                        or entry.record.exit_reason != pre_dispatch["exit_reason"]
                        or entry.evidence
                        or entry.artifact_manifest_ref is not None
                        or entry.cleanup_state is not CleanupState.VERIFIED_ABSENT
                        or entry.cleanup_evidence_ref != pre_dispatch["settlement_ref"]
                        or entry.settled_at != pre_dispatch["settled_at"]
                        or any(
                            observation.attempt_id == checked_binding.attempt_id
                            for observation in active.independent_observations
                        )
                    ):
                        raise ProductStoreError(
                            "engine pre-dispatch settlement terminal state changed"
                        )
                    return EngineExecutionClaimRecovery(
                        document=None,
                        pre_dispatch_document=pre_dispatch,
                        job_id=entry.job_id,
                        job_state=job_state,
                    )
                if job_state == "completed":
                    raise ResourceConflictError(
                        "completed engine job has no durable execution claim"
                    )
                return EngineExecutionClaimRecovery(
                    document=None,
                    pre_dispatch_document=None,
                    job_id=entry.job_id,
                    job_state=job_state,
                )
            _require_execution_claim_policy(record)
            document = _decode_row(row)
            _same_claim(
                document,
                raw_job=raw_job,
                preparation_row=preparation_row,
                record=record,
                acceptance=acceptance,
                binding=checked_binding,
                delegation=checked_delegation,
                runtime_resolution_ref=None,
            )
            preflight = _validate_preflight_snapshot(
                connection,
                document,
                raw_job=raw_job,
                record=record,
                binding=checked_binding,
                delegation=checked_delegation,
            )
            _validate_claim_lifetime(
                document,
                raw_job=raw_job,
                preparation_row=preparation_row,
                approval=approval,
                binding=checked_binding,
                delegation=checked_delegation,
                preflight_updated_at=str(preflight["updated_at"]),
            )
            return EngineExecutionClaimRecovery(
                document=document,
                pre_dispatch_document=None,
                job_id=entry.job_id,
                job_state=job_state,
            )

    def begin_or_reopen_engine_attempt_reconciliation(
        self: EngineExecutionClaimStore,
        *,
        binding: Mapping[str, Any],
        delegation: Mapping[str, Any],
        reviewer: str,
        created_at: str,
        saved_record: Mapping[str, Any],
        expected_revision: int,
        expected_experiment_digest: str,
        reconciliation_capability: object,
    ) -> EngineExecutionReconciliationResult:
        """Create/reopen one non-authorizing intent under the recovery lock."""

        self._require_engine_attempt_reconciliation_session(reconciliation_capability)
        created_at = _timestamp(created_at, "engine reconciliation intent time")
        retained_record = jobs._attempt_record(saved_record)
        recovery = self.get_accepted_engine_attempt_execution(
            binding=binding,
            delegation=delegation,
            reviewer=reviewer,
        )
        if recovery.document is None:
            with self._connection() as connection:
                if not connection.in_transaction:
                    connection.execute("BEGIN")
                experiment = jobs._active_experiment_at(
                    connection,
                    retained_record.binding.experiment_id,
                    expected_revision=expected_revision,
                    expected_digest=expected_experiment_digest,
                )
                try:
                    _index, entry = experiment._attempt(retained_record.binding.attempt_id)
                except EngineExperimentError as exc:
                    raise ProductStoreError("engine reconciliation attempt was not found") from exc
                raw_job = connection.execute(
                    "SELECT state FROM jobs WHERE job_id=?", (recovery.job_id,)
                ).fetchone()
                if (
                    entry.job_id != recovery.job_id
                    or entry.record.to_dict() != retained_record.to_dict()
                    or raw_job is None
                    or raw_job["state"] != recovery.job_state
                ):
                    raise ResourceConflictError("engine reconciliation snapshot changed")
            return EngineExecutionReconciliationResult(
                claim_document=None,
                pre_dispatch_document=recovery.pre_dispatch_document,
                reconciliation_document=None,
                job_id=recovery.job_id,
                job_state=recovery.job_state,
            )
        claim = recovery.document
        with self._connection(write=True) as connection:
            experiment = jobs._active_experiment_at(
                connection,
                retained_record.binding.experiment_id,
                expected_revision=expected_revision,
                expected_digest=expected_experiment_digest,
            )
            try:
                _index, entry = experiment._attempt(retained_record.binding.attempt_id)
            except EngineExperimentError as exc:
                raise ProductStoreError("engine reconciliation attempt was not found") from exc
            if (
                entry.job_id != recovery.job_id
                or entry.record.to_dict() != retained_record.to_dict()
            ):
                raise ResourceConflictError("engine reconciliation snapshot changed")
            row = connection.execute(
                """SELECT claim.*,job.state AS current_job_state,
                job.updated_at AS current_job_updated_at
                FROM engine_attempt_execution_claims AS claim
                JOIN jobs AS job ON job.job_id=claim.job_id
                WHERE claim.claim_ref=? AND claim.job_id=? AND claim.attempt_id=?""",
                (claim["claim_ref"], claim["job_id"], claim["attempt_id"]),
            ).fetchone()
            if row is None:
                raise ProductStoreError("engine reconciliation claim disappeared")
            decoded = _decode_row(cast(sqlite3.Row, row))
            if decoded != claim or row["current_job_state"] != recovery.job_state:
                raise ResourceConflictError("engine reconciliation claim or job state changed")
            if parse_iso8601_datetime(created_at) < parse_iso8601_datetime(
                str(row["current_job_updated_at"])
            ):
                raise ResourceConflictError(
                    "engine reconciliation intent predates its terminal job"
                )
            existing_rows = connection.execute(
                """SELECT * FROM engine_attempt_reconciliation_intents
                WHERE claim_ref=? OR job_id=? OR attempt_id=?""",
                (claim["claim_ref"], claim["job_id"], claim["attempt_id"]),
            ).fetchall()
            intent: Mapping[str, Any] | None = None
            if existing_rows:
                if len(existing_rows) != 1:
                    raise ProductStoreError("engine reconciliation intent identities diverged")
                intent = _decode_reconciliation_row(cast(sqlite3.Row, existing_rows[0]))
                expected = {
                    "claim_ref": claim["claim_ref"],
                    "job_id": claim["job_id"],
                    "job_state": recovery.job_state,
                    "attempt_id": claim["attempt_id"],
                    "experiment_id": claim["experiment_id"],
                    "binding_digest": claim["binding_digest"],
                    "delegation_digest": claim["delegation_digest"],
                    "job_request_digest": claim["job_request_digest"],
                    "runtime_resolution_ref": claim["runtime_resolution_ref"],
                }
                if any(intent.get(field) != value for field, value in expected.items()):
                    raise ProductStoreError("engine reconciliation intent binding changed")
                if parse_iso8601_datetime(str(intent["created_at"])) < parse_iso8601_datetime(
                    str(claim["claimed_at"])
                ):
                    raise ProductStoreError("engine reconciliation intent predates its claim")
                if parse_iso8601_datetime(str(intent["created_at"])) < parse_iso8601_datetime(
                    str(row["current_job_updated_at"])
                ):
                    raise ProductStoreError(
                        "engine reconciliation intent predates its terminal job"
                    )
                if parse_iso8601_datetime(created_at) < parse_iso8601_datetime(
                    str(intent["created_at"])
                ):
                    raise ResourceConflictError("engine reconciliation reopen predates its intent")
            if entry.settled_at is not None and entry.cleanup_state is CleanupState.VERIFIED_ABSENT:
                if (
                    entry.record.state
                    not in {
                        AttemptState.COMPLETED,
                        AttemptState.PARTIAL,
                        AttemptState.FAILED,
                        AttemptState.CANCELLED,
                        AttemptState.BUDGET_EXHAUSTED,
                        AttemptState.UNKNOWN,
                    }
                    or entry.cleanup_evidence_ref is None
                ):
                    raise ProductStoreError("settled claimed engine cleanup state changed")
                cleanup_evidence_ref = _digest(
                    entry.cleanup_evidence_ref,
                    "settled claimed engine cleanup reference",
                )
                return EngineExecutionReconciliationResult(
                    claim_document=claim,
                    pre_dispatch_document=None,
                    reconciliation_document=intent,
                    job_id=recovery.job_id,
                    job_state=recovery.job_state,
                    settled_cleanup_evidence_ref=cleanup_evidence_ref,
                    settled_reconciliation_ref=(
                        None if intent is None else str(intent["reconciliation_ref"])
                    ),
                )
            if intent is not None:
                return EngineExecutionReconciliationResult(
                    claim_document=claim,
                    pre_dispatch_document=None,
                    reconciliation_document=intent,
                    job_id=recovery.job_id,
                    job_state=recovery.job_state,
                )
            if parse_iso8601_datetime(created_at) < parse_iso8601_datetime(
                str(claim["claimed_at"])
            ):
                raise ResourceConflictError("engine reconciliation intent predates its claim")
            document: dict[str, Any] = {
                "schema_version": _RECONCILIATION_SCHEMA,
                "reconciliation_ref": "",
                "claim_ref": claim["claim_ref"],
                "job_id": claim["job_id"],
                "job_state": recovery.job_state,
                "attempt_id": claim["attempt_id"],
                "experiment_id": claim["experiment_id"],
                "binding_digest": claim["binding_digest"],
                "delegation_digest": claim["delegation_digest"],
                "job_request_digest": claim["job_request_digest"],
                "runtime_resolution_ref": claim["runtime_resolution_ref"],
                "created_at": created_at,
            }
            document["reconciliation_ref"] = _reconciliation_reference(document)
            encoded = canonical_json(document)
            if len(encoded.encode("utf-8")) > _MAX_DOCUMENT_BYTES:
                raise ProductStoreError("engine reconciliation intent is too large")
            connection.execute(
                """INSERT INTO engine_attempt_reconciliation_intents(
                reconciliation_ref,claim_ref,job_id,job_state,attempt_id,experiment_id,
                binding_digest,delegation_digest,job_request_digest,
                runtime_resolution_ref,created_at,document_json,record_digest
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    document["reconciliation_ref"],
                    document["claim_ref"],
                    document["job_id"],
                    document["job_state"],
                    document["attempt_id"],
                    document["experiment_id"],
                    document["binding_digest"],
                    document["delegation_digest"],
                    document["job_request_digest"],
                    document["runtime_resolution_ref"],
                    created_at,
                    encoded,
                    content_hash(document),
                ),
            )
            return EngineExecutionReconciliationResult(
                claim_document=claim,
                pre_dispatch_document=None,
                reconciliation_document=cast(Mapping[str, Any], document),
                job_id=recovery.job_id,
                job_state=recovery.job_state,
            )
