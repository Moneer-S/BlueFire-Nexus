"""Atomic ProductStore repository operations for external-engine jobs.

The immutable experiment history, one-time approval row, and idempotent job
row already provide the required durable boundary.  This mixin joins those
existing records in one SQLite transaction; it does not schedule or execute
engine work and it stores no credentials or raw artifacts.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable
from contextlib import AbstractContextManager
from typing import Any, Mapping, Protocol, cast

from . import product_store_engine_experiments as experiment_store
from .engine_attempt_contract import EngineAttemptBinding, EngineAttemptRecord, EngineEvidenceItem
from .engine_delegation import (
    EngineCapabilityDelegation,
    EngineDelegationError,
    EngineExecutionApprovalBinding,
)
from .engine_experiment import CleanupState, EngineExperiment, EngineExperimentError
from .product_store_contracts import safe_document, stable_identifier
from .product_store_errors import ProductStoreError, ResourceConflictError
from .product_store_serialization import canonical_json, utc_now
from .util import content_hash, parse_iso8601_datetime

_ENGINE_JOB_KIND = "engine-attempt"
_ENGINE_CONTEXT_SCHEMA = "bluefire.engine-execution-context.v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_APPROVAL_ID = re.compile(r"^approval-[0-9a-f]{32}$")
_MAX_CONTEXT_DOCUMENT_BYTES = 128 * 1024


class EngineJobProductStore(Protocol):
    def _connection(self, *, write: bool = False) -> AbstractContextManager[sqlite3.Connection]: ...

    def get_engine_experiment(
        self, experiment_id: str, *, revision: int | None = None
    ) -> Mapping[str, Any]: ...

    def get_engine_experiment_document(self, experiment_id: str) -> Mapping[str, Any]: ...

    def _job_submission_binding(
        self, submission_id: str, intent_digest: str
    ) -> tuple[str, Mapping[str, str]]: ...

    def _matching_job_submission(
        self, row: sqlite3.Row, kind: str, binding: Mapping[str, str]
    ) -> Mapping[str, Any]: ...

    def _job_from_row(self, row: sqlite3.Row) -> Mapping[str, Any]: ...

    def _approval_row(self, connection: sqlite3.Connection, approval_id: str) -> sqlite3.Row: ...

    def _approval_from_row(self, row: sqlite3.Row) -> Any: ...


def _engine_document(value: Any) -> EngineExperiment:
    try:
        experiment = EngineExperiment._from_controller_mapping(value)
    except (EngineExperimentError, TypeError, ValueError) as exc:
        raise ProductStoreError("saved engine experiment failed contract validation") from exc
    if experiment.to_dict() != value:
        raise ProductStoreError("saved engine experiment is not canonical")
    return experiment


def _attempt_record(value: Any) -> EngineAttemptRecord:
    try:
        record = EngineAttemptRecord.from_mapping(value)
    except (TypeError, ValueError) as exc:
        raise ProductStoreError("engine attempt record is invalid") from exc
    if record.to_dict() != value:
        raise ProductStoreError("engine attempt record is not canonical")
    return record


def _engine_evidence(values: Iterable[Mapping[str, Any]]) -> tuple[EngineEvidenceItem, ...]:
    try:
        evidence = tuple(EngineEvidenceItem.from_mapping(value) for value in values)
    except (TypeError, ValueError) as exc:
        raise ProductStoreError("engine attempt evidence is invalid") from exc
    if any(item.to_dict() != value for item, value in zip(evidence, values, strict=True)):
        raise ProductStoreError("engine attempt evidence is not canonical")
    return evidence


def _canonical_context_document(value: Mapping[str, Any], label: str) -> str:
    encoded = canonical_json(value)
    if not encoded or len(encoded.encode("utf-8")) > _MAX_CONTEXT_DOCUMENT_BYTES:
        raise ProductStoreError(f"{label} is too large")
    return encoded


def _decode_context_document(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > _MAX_CONTEXT_DOCUMENT_BYTES:
        raise ProductStoreError(f"saved {label} is invalid")
    try:
        document = json.loads(value)
    except (TypeError, ValueError) as exc:
        raise ProductStoreError(f"saved {label} is invalid") from exc
    if not isinstance(document, dict) or canonical_json(document) != value:
        raise ProductStoreError(f"saved {label} is not canonical")
    return cast(Mapping[str, Any], document)


def _request_for(
    experiment: EngineExperiment,
    binding: EngineAttemptBinding,
    delegation: EngineCapabilityDelegation,
    approval: EngineExecutionApprovalBinding,
    approval_id: str,
) -> dict[str, str]:
    return {
        "schema_version": "bluefire.engine-attempt-job.v1",
        "experiment_id": experiment.experiment_id,
        "attempt_id": binding.attempt_id,
        "binding_digest": binding.binding_digest,
        "delegation_digest": delegation.delegation_digest,
        "execution_approval_digest": content_hash(approval.to_dict()),
        "execution_approval_id": approval_id,
    }


def _context_for(
    *,
    experiment_id: str,
    attempt_id: str,
    job_id: str,
    delegation: EngineCapabilityDelegation,
    approval: EngineExecutionApprovalBinding,
) -> Mapping[str, Any]:
    return {
        "schema_version": _ENGINE_CONTEXT_SCHEMA,
        "experiment_id": experiment_id,
        "attempt_id": attempt_id,
        "job_id": job_id,
        "delegation_digest": delegation.delegation_digest,
        "execution_approval_digest": content_hash(approval.to_dict()),
        # Canonical JSON strings remain safe under generic progress merging.
        # They were parsed and contract-validated before persistence and carry
        # public digest references only, never approval nonce or credentials.
        "delegation_json": _canonical_context_document(delegation.to_dict(), "engine delegation"),
        "approval_binding_json": _canonical_context_document(
            approval.to_dict(), "engine approval binding"
        ),
    }


def _parse_context(
    value: Any,
) -> tuple[Mapping[str, Any], EngineCapabilityDelegation, EngineExecutionApprovalBinding]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "experiment_id",
        "attempt_id",
        "job_id",
        "delegation_digest",
        "execution_approval_digest",
        "delegation_json",
        "approval_binding_json",
    }:
        raise ProductStoreError("saved engine execution context fields changed")
    if value.get("schema_version") != _ENGINE_CONTEXT_SCHEMA:
        raise ProductStoreError("saved engine execution context schema is unsupported")
    try:
        delegation = EngineCapabilityDelegation.from_mapping(
            _decode_context_document(value.get("delegation_json"), "engine delegation")
        )
        approval = EngineExecutionApprovalBinding.from_mapping(
            _decode_context_document(value.get("approval_binding_json"), "engine approval binding")
        )
    except EngineDelegationError as exc:
        raise ProductStoreError("saved engine execution authority is invalid") from exc
    if value.get("delegation_digest") != delegation.delegation_digest or value.get(
        "execution_approval_digest"
    ) != content_hash(approval.to_dict()):
        raise ProductStoreError("saved engine execution authority digest changed")
    return value, delegation, approval


def _approval_chronology(row: sqlite3.Row, *, require_consumed: bool) -> None:
    required = ["requested_at", "approved_at", "consumed_at"]
    if not all(isinstance(row[name], str) and row[name] for name in required):
        raise ProductStoreError("engine approval lifecycle is incomplete")
    try:
        requested = parse_iso8601_datetime(str(row["requested_at"]))
        approved = parse_iso8601_datetime(str(row["approved_at"]))
        consumed = parse_iso8601_datetime(str(row["consumed_at"]))
        expires = parse_iso8601_datetime(str(row["expires_at"]))
        claimed = (
            None
            if row["claimed_at"] is None
            else parse_iso8601_datetime(str(row["claimed_at"]))
        )
    except (TypeError, ValueError) as exc:
        raise ProductStoreError("engine approval lifecycle time is invalid") from exc
    if not requested <= approved <= consumed < expires:
        raise ProductStoreError("engine approval lifecycle chronology is invalid")
    if require_consumed:
        if row["status"] != "consumed" or claimed is not None:
            raise ProductStoreError("engine approval is unavailable or already claimed")
    elif (
        row["status"] != "claimed"
        or claimed is None
        or claimed < consumed
        or claimed >= expires
    ):
        raise ProductStoreError("engine approval is not durably claimed")


def _active_experiment_at(
    connection: sqlite3.Connection,
    experiment_id: str,
    *,
    expected_revision: int | None = None,
    expected_digest: str | None = None,
) -> EngineExperiment:
    identity = experiment_store._experiment_id(experiment_id)
    if expected_revision is not None and (
        isinstance(expected_revision, bool)
        or not isinstance(expected_revision, int)
        or expected_revision <= 0
    ):
        raise ProductStoreError("expected engine experiment revision must be a positive integer")
    row = connection.execute(
        """
        SELECT version.*, head.active_revision, head.active_digest
        FROM engine_experiment_versions AS version
        JOIN engine_experiment_heads AS head USING (experiment_id)
        WHERE version.experiment_id = ?
          AND version.revision = head.active_revision
        """,
        (identity,),
    ).fetchone()
    if row is None:
        raise ProductStoreError("engine experiment was not found")
    record = experiment_store._record_from_row(
        row,
        active_revision=int(row["active_revision"]),
        active_digest=str(row["active_digest"]),
    )
    experiment = _engine_document(record["document"])
    if record["digest"] != experiment.digest:
        raise ProductStoreError("saved engine experiment digest differs from its contract")
    if expected_revision is not None and (
        experiment.revision != expected_revision or record["revision"] != expected_revision
    ):
        raise ResourceConflictError("engine experiment changed since its expected revision")
    if expected_digest is not None and (
        not isinstance(expected_digest, str)
        or _DIGEST.fullmatch(expected_digest) is None
        or experiment.digest != expected_digest
        or record["digest"] != expected_digest
    ):
        raise ResourceConflictError("engine experiment changed since its expected revision")
    return experiment


def _append_experiment_at(
    connection: sqlite3.Connection,
    current: EngineExperiment,
    updated: EngineExperiment,
) -> Mapping[str, Any]:
    if (
        updated.experiment_id != current.experiment_id
        or updated.revision != current.revision + 1
        or updated.previous_revision_digest != current.digest
    ):
        raise ProductStoreError("engine experiment update does not extend its exact head")
    payload = experiment_store._validated_document(
        current.experiment_id,
        updated.to_dict(),
        revision=updated.revision,
        validator=lambda value: _engine_document(value).to_dict(),
    )
    digest = content_hash(payload)
    if digest != updated.digest:
        raise ProductStoreError("engine experiment update digest changed")
    now = utc_now()
    try:
        connection.execute(
            """
            INSERT INTO engine_experiment_versions(
                experiment_id, revision, document_json, digest, prior_digest, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                current.experiment_id,
                updated.revision,
                canonical_json(payload),
                digest,
                current.digest,
                now,
            ),
        )
        cursor = connection.execute(
            """
            UPDATE engine_experiment_heads
            SET active_revision = ?, active_digest = ?, updated_at = ?
            WHERE experiment_id = ? AND active_revision = ? AND active_digest = ?
            """,
            (
                updated.revision,
                digest,
                now,
                current.experiment_id,
                current.revision,
                current.digest,
            ),
        )
    except sqlite3.IntegrityError as exc:
        raise ResourceConflictError("engine experiment update lost a race") from exc
    if cursor.rowcount != 1:
        raise ResourceConflictError("engine experiment update lost a race")
    return payload


class EngineExperimentJobStoreMixin:
    """ProductStore implementation of ``EngineExperimentRepository``."""

    def get_engine_experiment_document(
        self: EngineJobProductStore, experiment_id: str
    ) -> Mapping[str, Any]:
        record = self.get_engine_experiment(experiment_id)
        if (
            not isinstance(record, Mapping)
            or record.get("schema_version") != "bluefire.engine-experiment-record.v1"
            or record.get("active") is not True
            or record.get("revision") != record.get("active_revision")
        ):
            raise ProductStoreError("active engine experiment record is invalid")
        experiment = _engine_document(record.get("document"))
        if record.get("digest") != experiment.digest or record.get("revision") != experiment.revision:
            raise ProductStoreError("active engine experiment record digest is invalid")
        return experiment.to_dict()

    def reserve_engine_attempt_submission(
        self: EngineJobProductStore,
        *,
        experiment_id: str,
        binding: Mapping[str, Any],
        delegation: Mapping[str, Any],
        approval_binding: Mapping[str, Any],
        approval_id: str,
        approval_nonce: str,
        approved_by: str,
        job_kind: str,
        job_request: Mapping[str, Any],
        submission_id: str,
        intent_digest: str,
        expected_revision: int,
        expected_experiment_digest: str,
        reserved_at: str,
    ) -> tuple[Mapping[str, Any], bool]:
        stable_kind = stable_identifier(job_kind, "job kind")
        if stable_kind != _ENGINE_JOB_KIND:
            raise ProductStoreError("engine attempt must use its dedicated job kind")
        if not isinstance(approval_id, str) or _APPROVAL_ID.fullmatch(approval_id) is None:
            raise ProductStoreError("engine approval identity is invalid")
        if not isinstance(approval_nonce, str) or not approval_nonce or len(approval_nonce) > 200:
            raise ProductStoreError("engine approval nonce is invalid")
        if not isinstance(approved_by, str) or not approved_by.strip() or len(approved_by) > 200:
            raise ProductStoreError("engine approval reviewer is invalid")
        try:
            parsed_delegation = EngineCapabilityDelegation.from_mapping(delegation)
            parsed_binding = parsed_delegation.validate_attempt_binding(binding)
            parsed_approval = parsed_delegation.validate_approval_binding(
                approval_binding, parsed_binding
            )
        except (EngineDelegationError, TypeError, ValueError) as exc:
            raise ProductStoreError("engine execution authority is invalid") from exc
        if parsed_binding.experiment_id != experiment_id:
            raise ProductStoreError("engine binding belongs to another experiment")
        expected_request = _request_for(
            _engine_document(
                {
                    **self.get_engine_experiment_document(experiment_id),
                }
            ),
            parsed_binding,
            parsed_delegation,
            parsed_approval,
            approval_id,
        )
        request = safe_document(job_request, context="engine attempt job request")
        if request != expected_request or content_hash(request) != intent_digest:
            raise ProductStoreError("engine job intent differs from its exact authority")
        job_id, submission_binding = self._job_submission_binding(submission_id, intent_digest)
        context = _context_for(
            experiment_id=experiment_id,
            attempt_id=parsed_binding.attempt_id,
            job_id=job_id,
            delegation=parsed_delegation,
            approval=parsed_approval,
        )
        try:
            reserved = parse_iso8601_datetime(reserved_at)
        except (TypeError, ValueError) as exc:
            raise ProductStoreError("engine reservation time is invalid") from exc
        if not (
            parse_iso8601_datetime(parsed_binding.created_at)
            <= reserved
            < parse_iso8601_datetime(parsed_delegation.expires_at)
        ):
            raise ProductStoreError("engine reservation time is outside its delegated authority")

        with self._connection(write=True) as connection:
            existing = connection.execute(
                "SELECT * FROM jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
            if existing is not None:
                snapshot = self._matching_job_submission(existing, stable_kind, submission_binding)
                stored_request = dict(cast(Mapping[str, Any], snapshot["request"]))
                stored_request.pop("_submission", None)
                if stored_request != request:
                    raise ProductStoreError("job submission ID is already bound to different work")
                return snapshot, False

            experiment = _active_experiment_at(
                connection,
                experiment_id,
                expected_revision=expected_revision,
                expected_digest=expected_experiment_digest,
            )
            if _request_for(
                experiment,
                parsed_binding,
                parsed_delegation,
                parsed_approval,
                approval_id,
            ) != request:
                raise ResourceConflictError("engine experiment changed before job reservation")

            approval_row = self._approval_row(connection, approval_id)
            _approval_chronology(approval_row, require_consumed=True)
            parsed_approval.validate_approval_record(
                self._approval_from_row(approval_row).to_dict()
            )
            claimed_at = utc_now()
            claimed_time = parse_iso8601_datetime(claimed_at)
            consumed_time = parse_iso8601_datetime(str(approval_row["consumed_at"]))
            expiry_time = parse_iso8601_datetime(str(approval_row["expires_at"]))
            if (
                approval_row["nonce"] != approval_nonce
                or approval_row["approved_by"] != approved_by.strip()
                or not consumed_time <= claimed_time < expiry_time
            ):
                raise ProductStoreError("engine approval is expired, mismatched, or unavailable")

            updated = experiment.reserve_attempt(
                parsed_binding,
                job_id=job_id,
                delegation_digest=parsed_delegation.delegation_digest,
                execution_approval_digest=content_hash(parsed_approval.to_dict()),
                execution_approval_id=approval_id,
                timestamp=reserved_at,
            )
            cursor = connection.execute(
                """
                UPDATE approval_requests SET status = 'claimed', claimed_at = ?
                WHERE approval_id = ? AND status = 'consumed' AND nonce = ?
                  AND approved_by = ? AND state_digest = ? AND plan_digest = ?
                  AND target_scope_digest = ? AND profile_id = ? AND maximum_tier = ?
                """,
                (
                    claimed_at,
                    approval_id,
                    approval_nonce,
                    approved_by.strip(),
                    parsed_approval.state_digest,
                    parsed_approval.plan_digest,
                    parsed_approval.target_scope_digest,
                    parsed_approval.profile_id,
                    parsed_approval.maximum_tier,
                ),
            )
            if cursor.rowcount != 1:
                raise ResourceConflictError("engine approval claim lost a concurrent race")

            stored_request = dict(cast(Mapping[str, Any], request))
            stored_request["_submission"] = dict(submission_binding)
            progress = safe_document(
                {"_engine_execution": context}, context="engine attempt job progress"
            )
            connection.execute(
                """
                INSERT INTO jobs(
                    job_id, kind, state, request_json, progress_json, created_at, updated_at
                ) VALUES (?, ?, 'queued', ?, ?, ?, ?)
                """,
                (
                    job_id,
                    stable_kind,
                    canonical_json(stored_request),
                    canonical_json(progress),
                    claimed_at,
                    claimed_at,
                ),
            )
            _append_experiment_at(connection, experiment, updated)
            row = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            return self._job_from_row(row), True

    def load_engine_attempt_execution(
        self: EngineJobProductStore, experiment_id: str, attempt_id: str
    ) -> Mapping[str, Any]:
        with self._connection() as connection:
            connection.execute("BEGIN")
            experiment = _active_experiment_at(connection, experiment_id)
            try:
                _index, entry = experiment._attempt(attempt_id)
            except EngineExperimentError as exc:
                raise ProductStoreError("engine attempt was not found") from exc
            job = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (entry.job_id,)).fetchone()
            if job is None or job["kind"] != _ENGINE_JOB_KIND:
                raise ProductStoreError("engine attempt job is unavailable")
            progress = json.loads(str(job["progress_json"]))
            context_value, delegation, approval = _parse_context(
                progress.get("_engine_execution") if isinstance(progress, dict) else None
            )
            approval_row = self._approval_row(connection, entry.execution_approval_id)
            approval_record = self._approval_from_row(approval_row).to_dict()
            connection.commit()

        binding = delegation.validate_attempt_binding(entry.record.binding)
        delegation.validate_approval_binding(approval, binding)
        approval.validate_approval_record(approval_record)
        _approval_chronology(approval_row, require_consumed=False)
        if (
            context_value.get("experiment_id") != experiment_id
            or context_value.get("attempt_id") != attempt_id
            or context_value.get("job_id") != entry.job_id
            or entry.delegation_digest != delegation.delegation_digest
            or entry.execution_approval_digest != content_hash(approval.to_dict())
            or approval_record.get("approval_id") != entry.execution_approval_id
        ):
            raise ProductStoreError("saved engine execution context changed")
        expected_request = _request_for(
            experiment, binding, delegation, approval, entry.execution_approval_id
        )
        saved_request = json.loads(str(job["request_json"]))
        if not isinstance(saved_request, dict):
            raise ProductStoreError("saved engine job request is invalid")
        submission = saved_request.pop("_submission", None)
        if (
            saved_request != expected_request
            or not isinstance(submission, Mapping)
            or set(submission) != {"schema_version", "submission_id", "intent_digest"}
            or submission.get("schema_version") != "bluefire.job-submission.v1"
            or content_hash(saved_request) != submission.get("intent_digest")
        ):
            raise ProductStoreError("saved engine job request changed")
        expected_job_id, _binding = self._job_submission_binding(
            str(submission.get("submission_id")), str(submission.get("intent_digest"))
        )
        if expected_job_id != entry.job_id:
            raise ProductStoreError("saved engine submission identity changed")
        return {
            "experiment": experiment.to_dict(),
            "delegation": delegation.to_dict(),
            "approval_binding": approval.to_dict(),
            "approval_record": approval_record,
        }

    def compare_and_swap_engine_attempt_record(
        self: EngineJobProductStore,
        *,
        experiment_id: str,
        record: Mapping[str, Any],
        expected_revision: int,
        expected_experiment_digest: str,
        timestamp: str,
    ) -> Mapping[str, Any]:
        parsed = _attempt_record(record)
        with self._connection(write=True) as connection:
            experiment = _active_experiment_at(
                connection,
                experiment_id,
                expected_revision=expected_revision,
                expected_digest=expected_experiment_digest,
            )
            updated = experiment.update_attempt_record(parsed, timestamp=timestamp)
            return _append_experiment_at(connection, experiment, updated)

    def compare_and_swap_engine_attempt_settlement(
        self: EngineJobProductStore,
        *,
        experiment_id: str,
        record: Mapping[str, Any],
        engine_evidence: Iterable[Mapping[str, Any]],
        artifact_manifest_ref: str | None,
        cleanup_state: str,
        cleanup_evidence_ref: str,
        settled_at: str,
        expected_revision: int,
        expected_experiment_digest: str,
    ) -> Mapping[str, Any]:
        parsed_record = _attempt_record(record)
        raw_evidence = tuple(engine_evidence)
        evidence = _engine_evidence(raw_evidence)
        try:
            cleanup = CleanupState(cleanup_state)
        except ValueError as exc:
            raise ProductStoreError("engine cleanup state is invalid") from exc
        with self._connection(write=True) as connection:
            experiment = _active_experiment_at(
                connection,
                experiment_id,
                expected_revision=expected_revision,
                expected_digest=expected_experiment_digest,
            )
            updated = experiment.settle_attempt(
                parsed_record,
                engine_evidence=evidence,
                artifact_manifest_ref=artifact_manifest_ref,
                cleanup_state=cleanup,
                cleanup_evidence_ref=cleanup_evidence_ref,
                settled_at=settled_at,
            )
            return _append_experiment_at(connection, experiment, updated)

    def reconcile_engine_attempt_cleanup(
        self: EngineJobProductStore,
        *,
        experiment_id: str,
        attempt_id: str,
        cleanup_state: str,
        cleanup_evidence_ref: str,
        timestamp: str,
        expected_revision: int,
        expected_experiment_digest: str,
    ) -> Mapping[str, Any]:
        try:
            cleanup = CleanupState(cleanup_state)
        except ValueError as exc:
            raise ProductStoreError("engine cleanup state is invalid") from exc
        with self._connection(write=True) as connection:
            experiment = _active_experiment_at(
                connection,
                experiment_id,
                expected_revision=expected_revision,
                expected_digest=expected_experiment_digest,
            )
            updated = experiment.reconcile_attempt_cleanup(
                attempt_id,
                cleanup_state=cleanup,
                cleanup_evidence_ref=cleanup_evidence_ref,
                timestamp=timestamp,
            )
            return _append_experiment_at(connection, experiment, updated)

    def settle_undispatched_engine_attempt_cancellation(
        self: EngineJobProductStore,
        *,
        experiment_id: str,
        attempt_id: str,
        job_id: str,
        record: Mapping[str, Any],
        cleanup_evidence_ref: str,
        settled_at: str,
        expected_revision: int,
        expected_experiment_digest: str,
    ) -> Mapping[str, Any]:
        parsed_record = _attempt_record(record)
        if (
            parsed_record.state.value != "cancelled"
            or parsed_record.upstream_session_id is not None
            or parsed_record.completeness.value != "unknown"
            or parsed_record.exit_code is not None
            or parsed_record.exit_reason != "controller_cancelled_before_dispatch"
        ):
            raise ProductStoreError(
                "undispatched engine cancellation requires the exact no-custody outcome"
            )
        with self._connection(write=True) as connection:
            experiment = _active_experiment_at(
                connection,
                experiment_id,
                expected_revision=expected_revision,
                expected_digest=expected_experiment_digest,
            )
            job = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            if job is None or job["kind"] != _ENGINE_JOB_KIND or job["state"] != "cancelled":
                raise ResourceConflictError("engine job is not durably cancelled")
            try:
                _index, entry = experiment._attempt(attempt_id)
            except EngineExperimentError as exc:
                raise ProductStoreError("engine attempt was not found") from exc
            if (
                entry.job_id != job_id
                or entry.record.state.value != "queued"
                or entry.record.upstream_session_id is not None
                or entry.settled_at is not None
                or entry.artifact_manifest_ref is not None
                or entry.cleanup_state is not CleanupState.PENDING
                or entry.cleanup_evidence_ref is not None
            ):
                raise ResourceConflictError(
                    "engine attempt dispatch or resource custody already began"
                )
            updated = experiment.settle_attempt(
                parsed_record,
                engine_evidence=(),
                artifact_manifest_ref=None,
                cleanup_state=CleanupState.VERIFIED_ABSENT,
                cleanup_evidence_ref=cleanup_evidence_ref,
                settled_at=settled_at,
            )
            return _append_experiment_at(connection, experiment, updated)


__all__ = ["EngineExperimentJobStoreMixin"]
