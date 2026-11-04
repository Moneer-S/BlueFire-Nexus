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
from .engine_experiment import (
    CleanupState,
    ControllerCheckRecord,
    ControllerCheckRole,
    ControllerCheckState,
    DefenseState,
    EngineExperiment,
    EngineExperimentError,
    _controller_observation_record,
)
from .evidence import EvidenceRecord
from .product_store_contracts import safe_document, stable_identifier
from .product_store_errors import ProductStoreError, ResourceConflictError
from .product_store_serialization import canonical_json, utc_now
from .util import content_hash, parse_iso8601_datetime

_ENGINE_JOB_KIND = "engine-attempt"
_DEFENSE_JOB_KIND = "engine-controller-operation"
_CHECK_JOB_KIND = "engine-controller-check"
_ENGINE_CONTEXT_SCHEMA = "bluefire.engine-execution-context.v1"
_CHECK_DISPATCH_SCHEMA = "bluefire.engine-controller-check-dispatch.v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_APPROVAL_ID = re.compile(r"^approval-[0-9a-f]{32}$")
_MAX_CONTEXT_DOCUMENT_BYTES = 128 * 1024
_DEFENSE_OPERATIONS = frozenset(
    {"apply", "reconcile_application", "rollback", "reconcile_rollback"}
)
_RECONCILIATION_OPERATIONS = frozenset({"reconcile_application", "reconcile_rollback"})
_ORIGIN_OPERATIONS = {
    "reconcile_application": "apply",
    "reconcile_rollback": "rollback",
}


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
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > _MAX_CONTEXT_DOCUMENT_BYTES
    ):
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


def _job_request_document(value: Any, *, context: str) -> dict[str, Any]:
    document = safe_document(value, context=context)
    if not isinstance(document, dict):
        raise ProductStoreError(f"{context} must be a JSON object")
    return document


def _saved_job_request(
    store: EngineJobProductStore,
    row: sqlite3.Row,
) -> tuple[dict[str, Any], Mapping[str, str]]:
    try:
        request = json.loads(str(row["request_json"]))
    except (TypeError, ValueError) as exc:
        raise ProductStoreError("saved controller job request is invalid") from exc
    if not isinstance(request, dict):
        raise ProductStoreError("saved controller job request is invalid")
    submission = request.pop("_submission", None)
    if not isinstance(submission, dict) or set(submission) != {
        "schema_version",
        "submission_id",
        "intent_digest",
    }:
        raise ProductStoreError("saved controller job submission is invalid")
    if submission.get("schema_version") != "bluefire.job-submission.v1":
        raise ProductStoreError("saved controller job submission schema is invalid")
    submission_id = submission.get("submission_id")
    intent_digest = submission.get("intent_digest")
    if not isinstance(submission_id, str) or not isinstance(intent_digest, str):
        raise ProductStoreError("saved controller job submission is invalid")
    expected_job_id, expected = store._job_submission_binding(submission_id, intent_digest)
    if (
        expected_job_id != row["job_id"]
        or submission != expected
        or content_hash(request) != intent_digest
    ):
        raise ProductStoreError("saved controller job submission changed")
    return request, cast(Mapping[str, str], submission)


def _insert_idempotent_job_at(
    store: EngineJobProductStore,
    connection: sqlite3.Connection,
    *,
    kind: str,
    request: Mapping[str, Any],
    submission_id: str,
    intent_digest: str,
    now: str,
    initial_progress: Mapping[str, Any] | None = None,
) -> tuple[Mapping[str, Any], bool, str]:
    job_id, submission = store._job_submission_binding(submission_id, intent_digest)
    existing = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    if existing is not None:
        snapshot = store._matching_job_submission(existing, kind, submission)
        saved, _saved_submission = _saved_job_request(store, existing)
        if saved != request:
            raise ProductStoreError("job submission ID is already bound to different work")
        return snapshot, False, job_id
    stored = dict(request)
    stored["_submission"] = dict(submission)
    progress = (
        {}
        if initial_progress is None
        else _job_request_document(initial_progress, context="controller job initial progress")
    )
    connection.execute(
        """
        INSERT INTO jobs(
            job_id, kind, state, request_json, progress_json, created_at, updated_at
        ) VALUES (?, ?, 'queued', ?, ?, ?, ?)
        """,
        (job_id, kind, canonical_json(stored), canonical_json(progress), now, now),
    )
    row = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    return store._job_from_row(row), True, job_id


def _defense_request(
    experiment: EngineExperiment,
    *,
    change_id: str,
    operation: str,
    originating_job_id: str | None,
    originating_operation_receipt_digest: str | None,
) -> dict[str, Any]:
    change = experiment.defense_change
    if change is None or change.change_id != change_id:
        raise ProductStoreError("engine defense change is unavailable")
    if operation not in _DEFENSE_OPERATIONS:
        raise ProductStoreError("engine defense operation is invalid")
    return {
        "schema_version": "bluefire.engine-defense-operation-job.v1",
        "experiment_id": experiment.experiment_id,
        "experiment_revision": experiment.revision,
        "experiment_digest": experiment.digest,
        "change_id": change.change_id,
        "change_digest": content_hash(change.to_dict()),
        "operation": operation,
        "originating_job_id": originating_job_id,
        "originating_operation_receipt_digest": originating_operation_receipt_digest,
    }


def _check_request(
    experiment: EngineExperiment,
    check: ControllerCheckRecord,
) -> dict[str, Any]:
    return {
        "schema_version": "bluefire.engine-controller-check-job.v1",
        "experiment_id": experiment.experiment_id,
        "experiment_revision": experiment.revision,
        "experiment_digest": experiment.digest,
        "check_id": check.check_id,
        "run_id": check.run_id,
        "role": check.role.value,
        "performer": check.performer.value,
        "mechanism_ref": check.mechanism_ref,
        "target_snapshot_ref": check.target_snapshot_ref,
        "input_digest": check.input_digest,
        "reserved_at": check.created_at,
    }


def _historical_experiment_at(
    connection: sqlite3.Connection,
    experiment_id: str,
    revision: Any,
    digest: Any,
) -> EngineExperiment:
    if (
        isinstance(revision, bool)
        or not isinstance(revision, int)
        or revision <= 0
        or not isinstance(digest, str)
        or _DIGEST.fullmatch(digest) is None
    ):
        raise ProductStoreError("saved controller job experiment binding is invalid")
    row = connection.execute(
        """
        SELECT * FROM engine_experiment_versions
        WHERE experiment_id = ? AND revision = ? AND digest = ?
        """,
        (experiment_id, revision, digest),
    ).fetchone()
    if row is None:
        raise ProductStoreError("saved controller job experiment revision is unavailable")
    record = experiment_store._record_from_row(row, active_revision=revision)
    return _engine_document(record["document"])


def _controller_observation(value: Mapping[str, Any]):
    if not isinstance(value, Mapping):
        raise ProductStoreError("controller observation is invalid")
    try:
        observation = _controller_observation_record(
            target_snapshot_ref=value["target_snapshot_ref"],
            mechanism_ref=value["mechanism_ref"],
            attempt_id=value["attempt_id"],
            check_id=value["check_id"],
            check_input_digest=value["check_input_digest"],
            evidence=EvidenceRecord.from_mapping(value["evidence"]),
        )
    except (EngineExperimentError, KeyError, TypeError, ValueError) as exc:
        raise ProductStoreError("controller observation is invalid") from exc
    if observation.to_dict() != value:
        raise ProductStoreError("controller observation is not canonical")
    return observation


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
            None if row["claimed_at"] is None else parse_iso8601_datetime(str(row["claimed_at"]))
        )
    except (TypeError, ValueError) as exc:
        raise ProductStoreError("engine approval lifecycle time is invalid") from exc
    if not requested <= approved <= consumed < expires:
        raise ProductStoreError("engine approval lifecycle chronology is invalid")
    if require_consumed:
        if row["status"] != "consumed" or claimed is not None:
            raise ProductStoreError("engine approval is unavailable or already claimed")
    elif row["status"] != "claimed" or claimed is None or claimed < consumed or claimed >= expires:
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


def reserve_engine_attempt_submission_at(
    store: EngineJobProductStore,
    connection: sqlite3.Connection,
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
    """Reserve exact work inside the caller-owned write transaction."""

    if not connection.in_transaction:
        raise ProductStoreError("engine job reservation requires one transaction")
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
        _active_experiment_at(connection, experiment_id),
        parsed_binding,
        parsed_delegation,
        parsed_approval,
        approval_id,
    )
    request = safe_document(job_request, context="engine attempt job request")
    if request != expected_request or content_hash(request) != intent_digest:
        raise ProductStoreError("engine job intent differs from its exact authority")
    job_id, submission_binding = store._job_submission_binding(submission_id, intent_digest)
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

    existing = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    if existing is not None:
        snapshot = store._matching_job_submission(existing, stable_kind, submission_binding)
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
    if (
        _request_for(
            experiment,
            parsed_binding,
            parsed_delegation,
            parsed_approval,
            approval_id,
        )
        != request
    ):
        raise ResourceConflictError("engine experiment changed before job reservation")

    approval_row = store._approval_row(connection, approval_id)
    _approval_chronology(approval_row, require_consumed=True)
    parsed_approval.validate_approval_record(store._approval_from_row(approval_row).to_dict())
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
    progress = safe_document({"_engine_execution": context}, context="engine attempt job progress")
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
    return store._job_from_row(row), True


def reserve_engine_defense_operation_submission_at(
    store: EngineJobProductStore,
    connection: sqlite3.Connection,
    *,
    experiment_id: str,
    change_id: str,
    operation: str,
    job_kind: str,
    job_request: Mapping[str, Any],
    submission_id: str,
    intent_digest: str,
    expected_revision: int,
    expected_experiment_digest: str,
    originating_job_id: str | None,
    originating_operation_receipt_digest: str | None,
) -> tuple[Mapping[str, Any], bool]:
    """Reserve exact work inside the caller-owned write transaction."""

    if not connection.in_transaction:
        raise ProductStoreError("engine job reservation requires one transaction")
    if stable_identifier(job_kind, "job kind") != _DEFENSE_JOB_KIND:
        raise ProductStoreError("defense operation must use its dedicated job kind")
    request = _job_request_document(job_request, context="engine defense job request")
    if content_hash(request) != intent_digest:
        raise ProductStoreError("engine defense job intent changed")
    job, created, _job_id = _insert_idempotent_job_at(
        store,
        connection,
        kind=_DEFENSE_JOB_KIND,
        request=request,
        submission_id=submission_id,
        intent_digest=intent_digest,
        now=utc_now(),
    )
    if not created:
        return job, False
    experiment = _active_experiment_at(
        connection,
        experiment_id,
        expected_revision=expected_revision,
        expected_digest=expected_experiment_digest,
    )
    expected = _defense_request(
        experiment,
        change_id=change_id,
        operation=operation,
        originating_job_id=originating_job_id,
        originating_operation_receipt_digest=originating_operation_receipt_digest,
    )
    if request != expected:
        raise ProductStoreError("engine defense job differs from its exact experiment")
    change = experiment.defense_change
    assert change is not None
    ready = {
        "apply": change.state is DefenseState.REVIEWED,
        "reconcile_application": (
            change.state is DefenseState.UNKNOWN and change.rollback_operation_digest is None
        ),
        "rollback": change.state in {DefenseState.APPLIED, DefenseState.RETAINED},
        "reconcile_rollback": (
            change.state is DefenseState.UNKNOWN and change.rollback_operation_digest is not None
        ),
    }
    if not ready.get(operation, False):
        raise ProductStoreError("engine defense operation is not ready")
    if operation not in _RECONCILIATION_OPERATIONS:
        if originating_job_id is not None or originating_operation_receipt_digest is not None:
            raise ProductStoreError("new defense operation cannot cite an origin job")
        return job, True
    if not isinstance(originating_job_id, str) or not isinstance(
        originating_operation_receipt_digest, str
    ):
        raise ProductStoreError("defense reconciliation requires its origin job")
    origin = connection.execute(
        "SELECT * FROM jobs WHERE job_id = ?", (originating_job_id,)
    ).fetchone()
    if (
        origin is None
        or origin["kind"] != _DEFENSE_JOB_KIND
        or origin["state"] not in {"failed", "cancelled", "interrupted"}
    ):
        raise ProductStoreError("defense reconciliation requires its immutable terminal origin job")
    origin_request, _submission = _saved_job_request(store, origin)
    origin_operation = _ORIGIN_OPERATIONS[operation]
    historical = _historical_experiment_at(
        connection,
        experiment_id,
        origin_request.get("experiment_revision"),
        origin_request.get("experiment_digest"),
    )
    if origin_request != _defense_request(
        historical,
        change_id=change_id,
        operation=origin_operation,
        originating_job_id=None,
        originating_operation_receipt_digest=None,
    ):
        raise ProductStoreError("originating defense job intent changed")
    expected_receipt = content_hash(
        {
            "schema_version": "bluefire.engine-defense-operation-receipt.v1",
            "job_id": originating_job_id,
            "request_digest": content_hash(origin_request),
            "operation": origin_operation,
        }
    )
    saved_receipt = (
        change.application_receipt_digest
        if operation == "reconcile_application"
        else change.rollback_operation_digest
    )
    if (
        originating_operation_receipt_digest != expected_receipt
        or saved_receipt != expected_receipt
    ):
        raise ProductStoreError("originating defense operation receipt changed")
    return job, True


def reserve_engine_controller_check_submission_at(
    store: EngineJobProductStore,
    connection: sqlite3.Connection,
    *,
    experiment_id: str,
    check_id: str,
    run_id: str,
    role: str,
    mechanism_ref: str,
    target_snapshot_ref: str,
    input_digest: str,
    reserved_at: str,
    job_kind: str,
    job_request: Mapping[str, Any],
    submission_id: str,
    intent_digest: str,
    expected_revision: int,
    expected_experiment_digest: str,
) -> tuple[Mapping[str, Any], bool]:
    """Reserve exact work inside the caller-owned write transaction."""

    if not connection.in_transaction:
        raise ProductStoreError("engine job reservation requires one transaction")
    if stable_identifier(job_kind, "job kind") != _CHECK_JOB_KIND:
        raise ProductStoreError("controller check must use its dedicated job kind")
    request = _job_request_document(job_request, context="engine controller-check request")
    if content_hash(request) != intent_digest:
        raise ProductStoreError("controller-check job intent changed")
    try:
        check_role = ControllerCheckRole(role)
    except ValueError as exc:
        raise ProductStoreError("controller-check role is invalid") from exc
    job, created, job_id = _insert_idempotent_job_at(
        store,
        connection,
        kind=_CHECK_JOB_KIND,
        request=request,
        submission_id=submission_id,
        intent_digest=intent_digest,
        now=utc_now(),
        initial_progress={
            "_engine_controller_dispatch": {
                "schema_version": _CHECK_DISPATCH_SCHEMA,
                "begun": False,
            }
        },
    )
    if not created:
        return job, False
    experiment = _active_experiment_at(
        connection,
        experiment_id,
        expected_revision=expected_revision,
        expected_digest=expected_experiment_digest,
    )
    check = ControllerCheckRecord.reserve(
        check_id=check_id,
        experiment_id=experiment_id,
        job_id=job_id,
        run_id=run_id,
        role=check_role,
        mechanism_ref=mechanism_ref,
        target_snapshot_ref=target_snapshot_ref,
        input_digest=input_digest,
        created_at=reserved_at,
    )
    if request != _check_request(experiment, check):
        raise ProductStoreError("controller-check job differs from its exact experiment")
    updated = experiment.reserve_controller_check(check, timestamp=reserved_at)
    _append_experiment_at(connection, experiment, updated)
    return job, True


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
        if (
            record.get("digest") != experiment.digest
            or record.get("revision") != experiment.revision
        ):
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
        with self._connection(write=True) as connection:
            return reserve_engine_attempt_submission_at(
                self,
                connection,
                experiment_id=experiment_id,
                binding=binding,
                delegation=delegation,
                approval_binding=approval_binding,
                approval_id=approval_id,
                approval_nonce=approval_nonce,
                approved_by=approved_by,
                job_kind=job_kind,
                job_request=job_request,
                submission_id=submission_id,
                intent_digest=intent_digest,
                expected_revision=expected_revision,
                expected_experiment_digest=expected_experiment_digest,
                reserved_at=reserved_at,
            )

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
            job = connection.execute(
                "SELECT * FROM jobs WHERE job_id = ?", (entry.job_id,)
            ).fetchone()
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

    def compare_and_swap_engine_attempt_observation(
        self: EngineJobProductStore,
        *,
        experiment_id: str,
        observation: Mapping[str, Any],
        expected_revision: int,
        expected_experiment_digest: str,
        timestamp: str,
    ) -> Mapping[str, Any]:
        """Atomically append one preverified controller observation.

        The trusted service must first reopen the immutable finalized RunStore
        bundle and verify that it contains this byte-identical EvidenceRecord.
        ProductStore cannot make that cross-filesystem check part of this
        SQLite transaction; it atomically enforces the canonical experiment,
        attempt, job, run, target-snapshot, and evidence identity bindings.
        """

        parsed = _controller_observation(observation)
        if parsed.attempt_id is None or parsed.check_id is not None:
            raise ProductStoreError("engine attempt observation belongs to another workflow owner")
        with self._connection(write=True) as connection:
            experiment = _active_experiment_at(
                connection,
                experiment_id,
                expected_revision=expected_revision,
                expected_digest=expected_experiment_digest,
            )
            try:
                _index, entry = experiment._attempt(parsed.attempt_id)
            except EngineExperimentError as exc:
                raise ProductStoreError("engine observation attempt was not found") from exc
            binding = entry.record.binding
            if (
                binding.experiment_id != experiment.experiment_id
                or binding.run_id != parsed.evidence.run_id
                or binding.target_snapshot_ref != parsed.target_snapshot_ref
                or entry.settled_at is None
                or entry.record.state.value
                not in {
                    "completed",
                    "partial",
                    "failed",
                    "cancelled",
                    "budget_exhausted",
                    "unknown",
                }
            ):
                raise ProductStoreError(
                    "engine observation differs from its settled attempt binding"
                )
            job = connection.execute(
                "SELECT * FROM jobs WHERE job_id = ?", (entry.job_id,)
            ).fetchone()
            if (
                job is None
                or job["kind"] != _ENGINE_JOB_KIND
                or job["state"] not in {"completed", "failed", "cancelled", "interrupted"}
            ):
                raise ProductStoreError("engine observation lacks its terminal bound job")
            request, _submission = _saved_job_request(self, job)
            if (
                request.get("schema_version") != "bluefire.engine-attempt-job.v1"
                or request.get("experiment_id") != experiment.experiment_id
                or request.get("attempt_id") != binding.attempt_id
                or request.get("binding_digest") != binding.binding_digest
                or request.get("delegation_digest") != entry.delegation_digest
                or request.get("execution_approval_digest") != entry.execution_approval_digest
                or request.get("execution_approval_id") != entry.execution_approval_id
                or entry.job_id != job["job_id"]
            ):
                raise ProductStoreError("engine observation job differs from its exact attempt")
            existing = next(
                (
                    item
                    for item in experiment.independent_observations
                    if item.evidence_id == parsed.evidence_id
                ),
                None,
            )
            if existing is not None:
                if existing.to_dict() != parsed.to_dict():
                    raise ProductStoreError(
                        "engine observation identity is already bound to different evidence"
                    )
                return cast(Mapping[str, Any], experiment.to_dict())
            updated = experiment.record_independent_observation(
                parsed,
                timestamp=timestamp,
            )
            return cast(
                Mapping[str, Any],
                _append_experiment_at(connection, experiment, updated),
            )

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

    def reserve_engine_defense_operation_submission(
        self: EngineJobProductStore,
        *,
        experiment_id: str,
        change_id: str,
        operation: str,
        job_kind: str,
        job_request: Mapping[str, Any],
        submission_id: str,
        intent_digest: str,
        expected_revision: int,
        expected_experiment_digest: str,
        originating_job_id: str | None,
        originating_operation_receipt_digest: str | None,
    ) -> tuple[Mapping[str, Any], bool]:
        with self._connection(write=True) as connection:
            return reserve_engine_defense_operation_submission_at(
                self,
                connection,
                experiment_id=experiment_id,
                change_id=change_id,
                operation=operation,
                job_kind=job_kind,
                job_request=job_request,
                submission_id=submission_id,
                intent_digest=intent_digest,
                expected_revision=expected_revision,
                expected_experiment_digest=expected_experiment_digest,
                originating_job_id=originating_job_id,
                originating_operation_receipt_digest=originating_operation_receipt_digest,
            )

    def begin_engine_defense_operation(
        self: EngineJobProductStore,
        *,
        experiment_id: str,
        change_id: str,
        operation: str,
        operation_receipt_digest: str,
        job_id: str,
        request_digest: str,
        started_at: str,
        expected_revision: int,
        expected_experiment_digest: str,
    ) -> Mapping[str, Any]:
        if operation not in {"apply", "rollback"}:
            raise ProductStoreError("only a new defense operation can begin an effect")
        with self._connection(write=True) as connection:
            experiment = _active_experiment_at(
                connection,
                experiment_id,
                expected_revision=expected_revision,
                expected_digest=expected_experiment_digest,
            )
            job = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            if job is None or job["kind"] != _DEFENSE_JOB_KIND or job["state"] != "running":
                raise ProductStoreError("defense effect requires its running bound job")
            request, _submission = _saved_job_request(self, job)
            if request_digest != content_hash(request) or request != _defense_request(
                experiment,
                change_id=change_id,
                operation=operation,
                originating_job_id=None,
                originating_operation_receipt_digest=None,
            ):
                raise ProductStoreError("defense effect job intent changed")
            expected_receipt = content_hash(
                {
                    "schema_version": "bluefire.engine-defense-operation-receipt.v1",
                    "job_id": job_id,
                    "request_digest": request_digest,
                    "operation": operation,
                }
            )
            if operation_receipt_digest != expected_receipt:
                raise ProductStoreError("defense operation receipt changed")
            if operation == "apply":
                updated = experiment.begin_defense_application(
                    change_id,
                    operation_receipt_digest=operation_receipt_digest,
                    started_at=started_at,
                )
            else:
                updated = experiment.begin_defense_rollback(
                    change_id,
                    rollback_operation_digest=operation_receipt_digest,
                    rollback_started_at=started_at,
                )
            return _append_experiment_at(connection, experiment, updated)

    def settle_engine_defense_operation(
        self: EngineJobProductStore,
        *,
        experiment_id: str,
        change_id: str,
        operation: str,
        target_snapshot_ref: str,
        configuration_digest: str | None,
        receipt_digest: str,
        settled_at: str,
        expected_revision: int,
        expected_experiment_digest: str,
    ) -> Mapping[str, Any]:
        if operation not in _DEFENSE_OPERATIONS:
            raise ProductStoreError("engine defense operation is invalid")
        with self._connection(write=True) as connection:
            experiment = _active_experiment_at(
                connection,
                experiment_id,
                expected_revision=expected_revision,
                expected_digest=expected_experiment_digest,
            )
            if operation in {"apply", "reconcile_application"}:
                if configuration_digest is None:
                    raise ProductStoreError("defense application lacks its configuration digest")
                updated = experiment.reconcile_defense_applied(
                    change_id,
                    applied_configuration_digest=configuration_digest,
                    reconciliation_receipt_digest=receipt_digest,
                    observed_target_snapshot_ref=target_snapshot_ref,
                    reconciled_at=settled_at,
                )
            else:
                if configuration_digest is not None:
                    raise ProductStoreError(
                        "defense rollback cannot claim an applied configuration"
                    )
                updated = experiment.reconcile_defense_rolled_back(
                    change_id,
                    rollback_receipt_digest=receipt_digest,
                    observed_target_snapshot_ref=target_snapshot_ref,
                    rolled_back_at=settled_at,
                )
            return _append_experiment_at(connection, experiment, updated)

    def reserve_engine_controller_check_submission(
        self: EngineJobProductStore,
        *,
        experiment_id: str,
        check_id: str,
        run_id: str,
        role: str,
        mechanism_ref: str,
        target_snapshot_ref: str,
        input_digest: str,
        reserved_at: str,
        job_kind: str,
        job_request: Mapping[str, Any],
        submission_id: str,
        intent_digest: str,
        expected_revision: int,
        expected_experiment_digest: str,
    ) -> tuple[Mapping[str, Any], bool]:
        with self._connection(write=True) as connection:
            return reserve_engine_controller_check_submission_at(
                self,
                connection,
                experiment_id=experiment_id,
                check_id=check_id,
                run_id=run_id,
                role=role,
                mechanism_ref=mechanism_ref,
                target_snapshot_ref=target_snapshot_ref,
                input_digest=input_digest,
                reserved_at=reserved_at,
                job_kind=job_kind,
                job_request=job_request,
                submission_id=submission_id,
                intent_digest=intent_digest,
                expected_revision=expected_revision,
                expected_experiment_digest=expected_experiment_digest,
            )

    def compare_and_swap_engine_controller_check_settlement(
        self: EngineJobProductStore,
        *,
        experiment_id: str,
        check: Mapping[str, Any],
        independent_observations: Iterable[Mapping[str, Any]],
        expected_revision: int,
        expected_experiment_digest: str,
    ) -> Mapping[str, Any]:
        try:
            terminal = ControllerCheckRecord.from_mapping(check)
        except (EngineExperimentError, TypeError, ValueError) as exc:
            raise ProductStoreError("controller-check settlement is invalid") from exc
        raw_observations = tuple(independent_observations)
        observations = tuple(_controller_observation(value) for value in raw_observations)
        if tuple(item.evidence_id for item in observations) != terminal.independent_evidence_refs:
            raise ProductStoreError(
                "controller-check observations differ from the terminal evidence references"
            )
        with self._connection(write=True) as connection:
            experiment = _active_experiment_at(
                connection,
                experiment_id,
                expected_revision=expected_revision,
                expected_digest=expected_experiment_digest,
            )
            _index, current = experiment._check(terminal.check_id)
            job = connection.execute(
                "SELECT * FROM jobs WHERE job_id = ?", (current.job_id,)
            ).fetchone()
            if (
                job is None
                or job["kind"] != _CHECK_JOB_KIND
                or job["state"]
                not in {
                    "running",
                    "cancelling",
                    "cancelled",
                    "failed",
                    "interrupted",
                }
            ):
                raise ProductStoreError("controller-check settlement lacks its bound job")
            request, _submission = _saved_job_request(self, job)
            historical = _historical_experiment_at(
                connection,
                experiment_id,
                request.get("experiment_revision"),
                request.get("experiment_digest"),
            )
            if request != _check_request(historical, current):
                raise ProductStoreError("controller-check job intent changed")
            working = experiment
            settled_at = terminal.settled_at or terminal.created_at
            for observation in observations:
                next_value = working.record_independent_observation(
                    observation, timestamp=settled_at
                )
                _append_experiment_at(connection, working, next_value)
                working = next_value
            settled = working.settle_controller_check(terminal, timestamp=settled_at)
            return _append_experiment_at(connection, working, settled)

    def reconcile_engine_controller_check_cleanup(
        self: EngineJobProductStore,
        *,
        experiment_id: str,
        check_id: str,
        cleanup_state: str,
        cleanup_evidence_ref: str,
        timestamp: str,
        expected_revision: int,
        expected_experiment_digest: str,
    ) -> Mapping[str, Any]:
        try:
            cleanup = CleanupState(cleanup_state)
        except ValueError as exc:
            raise ProductStoreError("controller-check cleanup state is invalid") from exc
        with self._connection(write=True) as connection:
            experiment = _active_experiment_at(
                connection,
                experiment_id,
                expected_revision=expected_revision,
                expected_digest=expected_experiment_digest,
            )
            updated = experiment.reconcile_check_cleanup(
                check_id,
                cleanup_state=cleanup,
                cleanup_evidence_ref=cleanup_evidence_ref,
                timestamp=timestamp,
            )
            return _append_experiment_at(connection, experiment, updated)

    def settle_undispatched_engine_controller_check_cancellation(
        self: EngineJobProductStore,
        *,
        experiment_id: str,
        check_id: str,
        job_id: str,
        check: Mapping[str, Any],
        expected_revision: int,
        expected_experiment_digest: str,
    ) -> Mapping[str, Any]:
        try:
            terminal = ControllerCheckRecord.from_mapping(check)
        except (EngineExperimentError, TypeError, ValueError) as exc:
            raise ProductStoreError("controller-check cancellation is invalid") from exc
        if (
            terminal.state is not ControllerCheckState.UNKNOWN
            or terminal.cleanup_state is not CleanupState.VERIFIED_ABSENT
            or terminal.independent_evidence_refs
            or terminal.settled_at is None
        ):
            raise ProductStoreError(
                "undispatched controller cancellation requires the exact absent outcome"
            )
        expected_result = content_hash(
            {
                "schema_version": "bluefire.engine-controller-check-unknown.v1",
                "check_id": check_id,
                "dispatched": False,
                "recorded_at": terminal.settled_at,
            }
        )
        expected_cleanup = content_hash(
            {
                "schema_version": "bluefire.engine-controller-check-uncertain.v1",
                "experiment_id": experiment_id,
                "check_id": check_id,
                "job_id": job_id,
                "run_id": terminal.run_id,
                "dispatched": False,
                "cleanup_state": CleanupState.VERIFIED_ABSENT.value,
                "recorded_at": terminal.settled_at,
            }
        )
        if (
            terminal.result_digest != expected_result
            or terminal.cleanup_evidence_ref != expected_cleanup
        ):
            raise ProductStoreError("controller cancellation receipt changed")
        with self._connection(write=True) as connection:
            experiment = _active_experiment_at(
                connection,
                experiment_id,
                expected_revision=expected_revision,
                expected_digest=expected_experiment_digest,
            )
            _index, current = experiment._check(check_id)
            job = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            if (
                job is None
                or job["kind"] != _CHECK_JOB_KIND
                or job["state"] != "cancelled"
                or current.job_id != job_id
                or current.state is not ControllerCheckState.RESERVED
                or current.cleanup_state is not CleanupState.PENDING
                or current.cleanup_evidence_ref is not None
            ):
                raise ResourceConflictError("controller-check dispatch or custody already began")
            try:
                progress = json.loads(str(job["progress_json"]))
            except (TypeError, ValueError) as exc:
                raise ProductStoreError("controller-check dispatch marker is invalid") from exc
            marker = (
                progress.get("_engine_controller_dispatch") if isinstance(progress, dict) else None
            )
            if marker != {
                "schema_version": _CHECK_DISPATCH_SCHEMA,
                "begun": False,
            }:
                raise ResourceConflictError(
                    "controller-check dispatch may have begun; recovery is required"
                )
            request, _submission = _saved_job_request(self, job)
            historical = _historical_experiment_at(
                connection,
                experiment_id,
                request.get("experiment_revision"),
                request.get("experiment_digest"),
            )
            if request != _check_request(historical, current):
                raise ProductStoreError("controller-check cancellation intent changed")
            updated = experiment.settle_controller_check(terminal, timestamp=terminal.settled_at)
            return _append_experiment_at(connection, experiment, updated)

    def load_engine_controller_check_recovery(
        self: EngineJobProductStore, experiment_id: str, check_id: str
    ) -> Mapping[str, Any]:
        with self._connection() as connection:
            connection.execute("BEGIN")
            experiment = _active_experiment_at(connection, experiment_id)
            try:
                _index, check = experiment._check(check_id)
            except EngineExperimentError as exc:
                raise ProductStoreError("controller check was not found") from exc
            job = connection.execute(
                "SELECT * FROM jobs WHERE job_id = ?", (check.job_id,)
            ).fetchone()
            if (
                job is None
                or job["kind"] != _CHECK_JOB_KIND
                or job["state"]
                not in {
                    "cancelled",
                    "failed",
                    "interrupted",
                    "completed",
                }
            ):
                raise ProductStoreError("controller-check recovery requires its terminal bound job")
            request, _submission = _saved_job_request(self, job)
            historical = _historical_experiment_at(
                connection,
                experiment_id,
                request.get("experiment_revision"),
                request.get("experiment_digest"),
            )
            if request != _check_request(historical, check):
                raise ProductStoreError("controller-check recovery intent changed")
            snapshot = self._job_from_row(job)
            connection.commit()
        return {"experiment": experiment.to_dict(), "job": snapshot}


__all__ = ["EngineExperimentJobStoreMixin"]
