"""Append-only protected preparation records for engine workspace actions.

This is a narrow mixin for the existing :class:`ProductStore`.  It creates no
scheduler and performs no target, engine, model, process, or network work.  A
trusted pure factory supplies one typed protected request while the existing
SQLite transaction binds it to the active experiment head, an optional
pending approval, and an idempotent job submission identity.

The full record is controller-private.  Only :meth:`prepared_engine_action`
returns a browser-safe review envelope.
"""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Any, Mapping, Protocol, cast

from .engine_action_preparation import (
    EngineActionPreparationError,
    EnginePreparedActionKind,
    EnginePreparedApprovalState,
    EngineWorkspaceAction,
    PreparedEngineAction,
    PreparedEngineActionLimits,
    engine_action_contract,
)
from .engine_attempt_contract import AttemptRole, EngineAttemptBinding
from .engine_controller_jobs import (
    DefenseOperation,
    EngineControllerJobError,
    EngineControllerJobs,
)
from .engine_delegation import (
    EngineCapabilityDelegation,
    EngineDelegationError,
    EngineExecutionApprovalBinding,
)
from .engine_experiment import (
    ControllerCheckRecord,
    ControllerCheckRole,
    EngineDefenseChange,
    EngineExperiment,
    EngineExperimentError,
)
from .engine_experiment_jobs import EngineExperimentJobs
from .product_store_contracts import safe_document
from .product_store_errors import ProductStoreError, ResourceConflictError
from .product_store_serialization import canonical_json, utc_now
from .tenant_record_experiment_controller import (
    SCHEMA_MECHANISM,
    SCHEMA_PLAN,
    TenantDefensePlan,
    TenantFailureMechanism,
    TenantRecordControllerError,
    TenantRoute,
    tenant_target_snapshot_ref,
)
from .tenant_record_lab import TenantDefenseConfig, TenantRecordLabError
from .util import content_hash, json_clone, parse_iso8601_datetime

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_EXPERIMENT_ID = re.compile(r"^experiment-[0-9a-f]{32}$")
_APPROVAL_ID = re.compile(r"^approval-[0-9a-f]{32}$")
_MAX_PROTECTED_BYTES = 256 * 1024
_PROTECTED_SCHEMA = "bluefire.protected-engine-action.v1"
_RECORD_SCHEMA = "bluefire.engine-action-preparation-record.v1"
_APPROVAL_BINDING_FIELDS = frozenset(
    {
        "run_id",
        "state_digest",
        "plan_digest",
        "profile_id",
        "target_scope_digest",
        "maximum_tier",
        "expires_at",
    }
)
_PROTECTED_FIELDS = frozenset(
    {
        "schema_version",
        "experiment_id",
        "experiment_revision",
        "experiment_digest",
        "workspace_digest",
        "action_kind",
        "preparation_kind",
        "approval_request_id",
        "submission_id",
        "job_request",
        "authority",
    }
)
_AUTHORITY_FIELDS = frozenset({"schema_version", "kind", "document", "document_digest"})
_ATTEMPT_AUTHORITY_FIELDS = frozenset({"binding", "delegation", "approval_binding"})
_CHECK_AUTHORITY_FIELDS = frozenset(
    {
        "schema_version",
        "mechanism",
        "check_id",
        "run_id",
        "role",
        "input_digest",
        "reserved_at",
    }
)
_DEFENSE_REVIEW_AUTHORITY_FIELDS = frozenset({"schema_version", "plan", "proposed_change"})
_DEFENSE_PLAN_ACTIONS = frozenset(
    {
        EngineWorkspaceAction.RETAIN_DEFENSE,
        EngineWorkspaceAction.APPLY_DEFENSE,
        EngineWorkspaceAction.RECONCILE_DEFENSE,
        EngineWorkspaceAction.ROLLBACK_DEFENSE,
        EngineWorkspaceAction.RECONCILE_ROLLBACK,
    }
)
_ALLOWED_SECRET_DIGEST_FIELDS = frozenset(
    {
        "approval_id",
        "approval_request_id",
        "authorization_digest",
        "model_authorization_ref",
        "source_authorization_digest",
    }
)
_ALLOWED_SECRET_CONTAINERS = frozenset({"approval_binding"})


ProtectedActionFactory = Callable[
    [Mapping[str, Any] | None, str | None],
    tuple[Mapping[str, Any] | None, Mapping[str, Any]],
]


class EngineActionProductStore(Protocol):
    def _connection(self, *, write: bool = False) -> AbstractContextManager[sqlite3.Connection]: ...

    def _create_approval_request_at(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        state_digest: str,
        plan_digest: str,
        profile_id: str,
        target_scope_digest: str,
        maximum_tier: str,
        expires_at: str,
    ) -> Mapping[str, Any]: ...

    def get_approval_request(self, approval_id: str) -> Mapping[str, Any]: ...

    def _approval_row(self, connection: sqlite3.Connection, approval_id: str) -> sqlite3.Row: ...

    def _approval_from_row(self, row: sqlite3.Row) -> Any: ...


def initialize_schema(connection: sqlite3.Connection) -> None:
    """Create the v16 append-only registry in the current migration transaction."""

    if not connection.in_transaction:
        raise ProductStoreError("Engine action migration requires one transaction.")
    statements = (
        """CREATE TABLE IF NOT EXISTS engine_action_preparations (
            request_ref TEXT PRIMARY KEY
                CHECK (length(request_ref) = 71 AND substr(request_ref, 1, 7) = 'sha256:'),
            experiment_id TEXT NOT NULL,
            experiment_revision INTEGER NOT NULL CHECK (experiment_revision > 0),
            experiment_digest TEXT NOT NULL
                CHECK (
                    length(experiment_digest) = 71 AND
                    substr(experiment_digest, 1, 7) = 'sha256:'
                ),
            workspace_digest TEXT NOT NULL
                CHECK (
                    length(workspace_digest) = 71 AND
                    substr(workspace_digest, 1, 7) = 'sha256:'
                ),
            generation INTEGER NOT NULL CHECK (generation > 0),
            action_kind TEXT NOT NULL CHECK (action_kind IN (
                'start_baseline', 'review_defense', 'apply_defense',
                'reconcile_defense', 'repeat_mechanism',
                'start_adaptive_search', 'run_legitimate_use',
                'retain_defense', 'rollback_defense', 'reconcile_rollback'
            )),
            preparation_kind TEXT NOT NULL CHECK (preparation_kind IN (
                'engine_attempt', 'controller_transition', 'controller_job'
            )),
            protected_request_json TEXT NOT NULL
                CHECK (json_valid(protected_request_json))
                CHECK (length(CAST(protected_request_json AS BLOB)) <= 262144),
            protected_request_digest TEXT NOT NULL
                CHECK (
                    length(protected_request_digest) = 71 AND
                    substr(protected_request_digest, 1, 7) = 'sha256:'
                ),
            limits_json TEXT NOT NULL
                CHECK (json_valid(limits_json))
                CHECK (length(CAST(limits_json AS BLOB)) <= 1024),
            limits_digest TEXT NOT NULL
                CHECK (
                    length(limits_digest) = 71 AND
                    substr(limits_digest, 1, 7) = 'sha256:'
                ),
            requires_approval INTEGER NOT NULL CHECK (requires_approval IN (0, 1)),
            approval_request_id TEXT,
            approval_review_binding_digest TEXT,
            submission_id TEXT,
            intent_digest TEXT,
            prepared_at TEXT NOT NULL,
            expires_at TEXT NOT NULL CHECK (prepared_at < expires_at),
            record_digest TEXT NOT NULL UNIQUE
                CHECK (
                    length(record_digest) = 71 AND
                    substr(record_digest, 1, 7) = 'sha256:'
                ),
            UNIQUE (
                experiment_id, experiment_revision, experiment_digest,
                workspace_digest, action_kind, generation
            ),
            FOREIGN KEY (experiment_id, experiment_revision)
                REFERENCES engine_experiment_versions(experiment_id, revision),
            FOREIGN KEY (approval_request_id)
                REFERENCES approval_requests(approval_id),
            CHECK (
                (requires_approval = 1 AND approval_request_id IS NOT NULL AND
                    approval_review_binding_digest IS NOT NULL) OR
                (requires_approval = 0 AND approval_request_id IS NULL AND
                    approval_review_binding_digest IS NULL)
            ),
            CHECK (
                (preparation_kind = 'engine_attempt' AND requires_approval = 1 AND
                    submission_id IS NOT NULL AND intent_digest IS NOT NULL) OR
                (preparation_kind = 'controller_job' AND requires_approval = 0 AND
                    submission_id IS NOT NULL AND intent_digest IS NOT NULL) OR
                (preparation_kind = 'controller_transition' AND requires_approval = 0 AND
                    submission_id IS NULL AND intent_digest IS NULL)
            )
        )""",
        """CREATE UNIQUE INDEX IF NOT EXISTS engine_action_preparations_approval_idx
            ON engine_action_preparations(approval_request_id)
            WHERE approval_request_id IS NOT NULL""",
        """CREATE UNIQUE INDEX IF NOT EXISTS engine_action_preparations_submission_idx
            ON engine_action_preparations(submission_id)
            WHERE submission_id IS NOT NULL""",
        """CREATE INDEX IF NOT EXISTS engine_action_preparations_latest_idx
            ON engine_action_preparations(
                experiment_id, experiment_revision, experiment_digest,
                workspace_digest, action_kind, generation DESC
            )""",
        "DROP TRIGGER IF EXISTS engine_action_preparations_valid_insert",
        """CREATE TRIGGER IF NOT EXISTS engine_action_preparations_valid_insert
        BEFORE INSERT ON engine_action_preparations
        BEGIN
            SELECT CASE WHEN
                EXISTS (
                    SELECT 1 FROM engine_action_preparations
                    WHERE request_ref = NEW.request_ref
                       OR record_digest = NEW.record_digest
                )
                OR (
                    NEW.approval_request_id IS NOT NULL AND EXISTS (
                        SELECT 1 FROM engine_action_preparations
                        WHERE approval_request_id = NEW.approval_request_id
                    )
                )
                OR (
                    NEW.submission_id IS NOT NULL AND EXISTS (
                        SELECT 1 FROM engine_action_preparations
                        WHERE submission_id = NEW.submission_id
                    )
                )
                OR EXISTS (
                    SELECT 1 FROM engine_action_preparations
                    WHERE experiment_id = NEW.experiment_id
                      AND experiment_revision = NEW.experiment_revision
                      AND experiment_digest = NEW.experiment_digest
                      AND workspace_digest = NEW.workspace_digest
                      AND action_kind = NEW.action_kind
                      AND generation = NEW.generation
                )
            THEN RAISE(ABORT, 'prepared action conflicts with append-only history') END;
            SELECT CASE WHEN NOT EXISTS (
                SELECT 1 FROM engine_experiment_heads AS head
                WHERE head.experiment_id = NEW.experiment_id
                  AND head.active_revision = NEW.experiment_revision
                  AND head.active_digest = NEW.experiment_digest
            ) THEN RAISE(ABORT, 'prepared action does not bind the active experiment') END;
            SELECT CASE WHEN NOT EXISTS (
                SELECT 1 FROM engine_experiment_versions AS version
                WHERE version.experiment_id = NEW.experiment_id
                  AND version.revision = NEW.experiment_revision
                  AND version.digest = NEW.experiment_digest
            ) THEN RAISE(ABORT, 'prepared action experiment digest is invalid') END;
        END""",
        """CREATE TRIGGER IF NOT EXISTS engine_action_preparations_no_update
        BEFORE UPDATE ON engine_action_preparations
        BEGIN
            SELECT RAISE(ABORT, 'engine action preparations are immutable');
        END""",
        """CREATE TRIGGER IF NOT EXISTS engine_action_preparations_no_delete
        BEFORE DELETE ON engine_action_preparations
        BEGIN
            SELECT RAISE(ABORT, 'engine action preparations are append-only');
        END""",
    )
    for statement in statements:
        connection.execute(statement)


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ProductStoreError(f"{label} must be an exact sha256 digest")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 40:
        raise ProductStoreError(f"{label} is invalid")
    try:
        parsed = parse_iso8601_datetime(value)
    except ValueError as exc:
        raise ProductStoreError(f"{label} is invalid") from exc
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise ProductStoreError(f"{label} is not canonical")
    return value


def _uuid(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ProductStoreError(f"{label} is invalid")
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise ProductStoreError(f"{label} is invalid") from exc
    if str(parsed) != value:
        raise ProductStoreError(f"{label} is not canonical")
    return value


def _safe_protected(value: Any) -> dict[str, Any]:
    """Validate protected JSON while allowing only known public digest handles."""

    try:
        document = json_clone(value)
    except (TypeError, ValueError) as exc:
        raise ProductStoreError("protected engine action must contain only JSON values") from exc
    if not isinstance(document, dict):
        raise ProductStoreError("protected engine action must be a JSON object")
    scrubbed = json_clone(document)

    def scrub(item: Any) -> None:
        if isinstance(item, list):
            for child in item:
                scrub(child)
            return
        if not isinstance(item, dict):
            return
        for key, child in item.items():
            if key in _ALLOWED_SECRET_CONTAINERS:
                checked_child = json_clone(child)
                scrub(checked_child)
                safe_document(checked_child, context=f"protected engine action.{key}")
                item[key] = None
            elif key in _ALLOWED_SECRET_DIGEST_FIELDS:
                if key in {"approval_id", "approval_request_id"}:
                    if child is not None and (
                        not isinstance(child, str) or _APPROVAL_ID.fullmatch(child) is None
                    ):
                        raise ProductStoreError("protected approval reference is invalid")
                elif child is not None:
                    _digest(child, f"protected {key}")
                item[key] = None
            else:
                scrub(child)

    scrub(scrubbed)
    safe_document(scrubbed, context="protected engine action")
    encoded = canonical_json(document)
    if not encoded or len(encoded.encode("utf-8")) > _MAX_PROTECTED_BYTES:
        raise ProductStoreError("protected engine action exceeds its byte bound")
    if set(document) != _PROTECTED_FIELDS or document.get("schema_version") != _PROTECTED_SCHEMA:
        raise ProductStoreError("protected engine action fields changed")
    return document


def _tenant_config(value: Any) -> TenantDefenseConfig:
    fields = {
        "schema_version",
        "mode",
        "fixture_digest",
        "target_snapshot_id",
        "service_generation",
        "application_nonce",
        "session_key_id",
        "session_key_digest",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ProductStoreError("protected tenant defense configuration fields changed")
    try:
        config = TenantDefenseConfig(
            mode=cast(str, value["mode"]),
            fixture_digest=cast(str, value["fixture_digest"]),
            target_snapshot_id=cast(str, value["target_snapshot_id"]),
            service_generation=cast(str, value["service_generation"]),
            application_nonce=cast(str | None, value["application_nonce"]),
            session_key_id=cast(str | None, value["session_key_id"]),
            session_key_digest=cast(str | None, value["session_key_digest"]),
        )
    except (TenantRecordLabError, TypeError, ValueError) as exc:
        raise ProductStoreError("protected tenant defense configuration is invalid") from exc
    if config.to_dict() != json_clone(value):
        raise ProductStoreError("protected tenant defense configuration is not canonical")
    return config


def _tenant_plan(value: Any) -> TenantDefensePlan:
    fields = {
        "schema_version",
        "operation_id",
        "fixture_digest",
        "before",
        "after",
        "review_id",
        "review_digest",
        "responsible_actor",
        "planned_at",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != fields
        or value.get("schema_version") != SCHEMA_PLAN
    ):
        raise ProductStoreError("protected tenant defense plan fields changed")
    try:
        plan = TenantDefensePlan(
            operation_id=cast(str, value["operation_id"]),
            fixture_digest=cast(str, value["fixture_digest"]),
            before=_tenant_config(value["before"]),
            after=_tenant_config(value["after"]),
            review_id=cast(str, value["review_id"]),
            review_digest=cast(str, value["review_digest"]),
            responsible_actor=cast(str, value["responsible_actor"]),
            planned_at=cast(str, value["planned_at"]),
        )
    except (TenantRecordControllerError, TypeError, ValueError) as exc:
        raise ProductStoreError("protected tenant defense plan is invalid") from exc
    if plan.to_dict() != json_clone(value):
        raise ProductStoreError("protected tenant defense plan is not canonical")
    return plan


def _tenant_mechanism(value: Any) -> TenantFailureMechanism:
    fields = {
        "schema_version",
        "method",
        "host",
        "fixture_digest",
        "original_target_snapshot_id",
        "route",
        "protected_tenant_id",
        "record_id",
        "identity_input",
        "request_digest",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != fields
        or value.get("schema_version") != SCHEMA_MECHANISM
    ):
        raise ProductStoreError("protected failure mechanism fields changed")
    try:
        mechanism = TenantFailureMechanism(
            fixture_digest=cast(str, value["fixture_digest"]),
            original_target_snapshot_id=cast(str, value["original_target_snapshot_id"]),
            route=TenantRoute(value["route"]),
            protected_tenant_id=cast(str, value["protected_tenant_id"]),
            record_id=cast(str | None, value["record_id"]),
            request_digest=cast(str, value["request_digest"]),
        )
    except (TenantRecordControllerError, TypeError, ValueError) as exc:
        raise ProductStoreError("protected failure mechanism is invalid") from exc
    if mechanism.to_dict() != json_clone(value):
        raise ProductStoreError("protected failure mechanism is not canonical")
    return mechanism


def _tenant_check_authority(
    value: Any,
) -> tuple[TenantFailureMechanism, dict[str, Any]]:
    if (
        not isinstance(value, Mapping)
        or set(value) != _CHECK_AUTHORITY_FIELDS
        or value.get("schema_version") != "bluefire.tenant-controller-check-authority.v1"
    ):
        raise ProductStoreError("protected controller check authority fields changed")
    mechanism = _tenant_mechanism(value.get("mechanism"))
    result = dict(json_clone(value))
    result["mechanism"] = mechanism.to_dict()
    return mechanism, result


def _tenant_defense_review_authority(
    value: Any,
) -> tuple[TenantDefensePlan, EngineDefenseChange]:
    if (
        not isinstance(value, Mapping)
        or set(value) != _DEFENSE_REVIEW_AUTHORITY_FIELDS
        or value.get("schema_version") != "bluefire.tenant-defense-review-authority.v1"
    ):
        raise ProductStoreError("protected defense review authority fields changed")
    plan = _tenant_plan(value.get("plan"))
    try:
        change = EngineDefenseChange.from_mapping(value.get("proposed_change"))
    except (EngineExperimentError, TypeError, ValueError) as exc:
        raise ProductStoreError("protected proposed defense change is invalid") from exc
    return plan, change


def _protected_authority(
    value: Any,
    *,
    action: EngineWorkspaceAction,
    experiment: EngineExperiment,
    prepared_at: str,
    reviewed_plan: TenantDefensePlan | None,
    approval_id: str | None,
    approval_record: Mapping[str, Any] | None,
    limits: PreparedEngineActionLimits,
    job_request: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != _AUTHORITY_FIELDS
        or value.get("schema_version") != "bluefire.engine-action-authority.v1"
    ):
        raise ProductStoreError("protected engine authority fields changed")
    if parse_iso8601_datetime(prepared_at) < parse_iso8601_datetime(experiment.updated_at):
        raise ProductStoreError("engine action preparation predates the current experiment")
    kind = value.get("kind")
    document = value.get("document")
    if not isinstance(document, Mapping) or value.get("document_digest") != content_hash(document):
        raise ProductStoreError("protected engine authority digest changed")
    if action in {
        EngineWorkspaceAction.START_BASELINE,
        EngineWorkspaceAction.START_ADAPTIVE_SEARCH,
    }:
        if kind != "engine_attempt" or set(document) != _ATTEMPT_AUTHORITY_FIELDS:
            raise ProductStoreError("protected engine attempt authority fields changed")
        if approval_id is None or approval_record is None or job_request is None:
            raise ProductStoreError("protected engine attempt approval is unavailable")
        try:
            binding = EngineAttemptBinding.from_mapping(document["binding"])
            delegation = EngineCapabilityDelegation.from_mapping(document["delegation"])
            approval = EngineExecutionApprovalBinding.from_mapping(document["approval_binding"])
            delegation.validate_attempt_binding(binding)
            delegation.validate_approval_binding(approval, binding)
            approval.validate_approval_record(approval_record)
        except (EngineDelegationError, TypeError, ValueError) as exc:
            raise ProductStoreError("protected engine attempt authority is invalid") from exc
        expected_role = (
            AttemptRole.BASELINE
            if action is EngineWorkspaceAction.START_BASELINE
            else AttemptRole.ADAPTIVE_SEARCH
        )
        expected_parent = (
            None
            if expected_role is AttemptRole.BASELINE
            else (
                experiment.attempts[0].record.binding.attempt_id
                if len(experiment.attempts) == 1
                else None
            )
        )
        if (
            binding.role is not expected_role
            or binding.parent_attempt_id != expected_parent
            or binding.experiment_id != experiment.experiment_id
            or binding.objective_ref != experiment.objective_ref
            or binding.environment_ref != experiment.environment_ref
            or binding.scope_ref != experiment.scope_ref
            or binding.scope_version != experiment.scope_version
            or binding.target_snapshot_ref != experiment.current_target_snapshot_ref
            or binding.created_at != prepared_at
            or delegation.created_at != prepared_at
            or (expected_role is AttemptRole.BASELINE and experiment.attempts)
            or (expected_role is AttemptRole.ADAPTIVE_SEARCH and len(experiment.attempts) != 1)
            or approval_record.get("approval_id") != approval_id
        ):
            raise ProductStoreError("protected engine attempt differs from the current experiment")
        expected_limits = {
            "wall_clock_seconds": binding.wall_clock_seconds,
            "action_limit": binding.action_limit,
            "artifact_byte_limit": binding.artifact_byte_limit,
            "cost_limit_microunits": binding.cost_limit_microunits,
            "target_scope_digest": approval.target_scope_digest,
            "maximum_tier": approval.maximum_tier,
        }
        if limits.to_dict() != expected_limits:
            raise ProductStoreError("prepared limits differ from engine attempt authority")
        request_policy = (
            job_request.get("execution_claim_policy")
            if job_request.get("schema_version") == "bluefire.engine-attempt-job.v2"
            else None
        )
        expected_request = EngineExperimentJobs._request(
            experiment=experiment,
            binding=binding,
            delegation=delegation,
            approval=approval,
            approval_id=approval_id,
            execution_claim_policy=request_policy,
        )
        if dict(job_request) != expected_request:
            raise ProductStoreError("protected engine attempt job request changed")
        try:
            experiment.reserve_attempt(
                binding,
                job_id="job-" + "0" * 32,
                delegation_digest=delegation.delegation_digest,
                execution_approval_digest=content_hash(approval.to_dict()),
                execution_approval_id=approval_id,
                timestamp=binding.created_at,
            )
        except EngineExperimentError as exc:
            raise ProductStoreError("protected engine attempt is not currently reservable") from exc
    elif action in {
        EngineWorkspaceAction.REVIEW_DEFENSE,
        EngineWorkspaceAction.RETAIN_DEFENSE,
        EngineWorkspaceAction.APPLY_DEFENSE,
        EngineWorkspaceAction.RECONCILE_DEFENSE,
        EngineWorkspaceAction.ROLLBACK_DEFENSE,
        EngineWorkspaceAction.RECONCILE_ROLLBACK,
    }:
        if approval_record is not None or any(
            item is not None for item in limits.to_dict().values()
        ):
            raise ProductStoreError("protected defense action gained engine authority")
        proposed_change: EngineDefenseChange | None = None
        if action is EngineWorkspaceAction.REVIEW_DEFENSE:
            if kind != "tenant_defense_review":
                raise ProductStoreError("protected defense review lacks its exact proposal")
            plan, proposed_change = _tenant_defense_review_authority(document)
        else:
            if kind != "tenant_defense_plan":
                raise ProductStoreError("protected defense action lacks its exact plan")
            plan = _tenant_plan(document)
            if reviewed_plan is None or plan.to_dict() != reviewed_plan.to_dict():
                raise ProductStoreError("protected defense plan is not the retained review plan")
        before_ref = tenant_target_snapshot_ref(
            fixture_digest=plan.before.fixture_digest,
            target_snapshot_id=plan.before.target_snapshot_id,
            service_generation=plan.before.service_generation,
        )
        after_ref = tenant_target_snapshot_ref(
            fixture_digest=plan.after.fixture_digest,
            target_snapshot_id=plan.after.target_snapshot_id,
            service_generation=plan.after.service_generation,
        )
        if action is EngineWorkspaceAction.REVIEW_DEFENSE:
            if (
                job_request is not None
                or experiment.defense_change is not None
                or (experiment.current_target_snapshot_ref != before_ref)
            ):
                raise ProductStoreError("protected defense review differs from current state")
            assert proposed_change is not None
            if (
                proposed_change.preimage_digest != plan.before.digest
                or proposed_change.approved_configuration_digest != plan.after.digest
                or proposed_change.before_target_snapshot_ref != before_ref
                or proposed_change.after_target_snapshot_ref != after_ref
                or proposed_change.rollback_digest != plan.before.digest
                or proposed_change.reviewed_at != plan.planned_at
                or plan.planned_at != prepared_at
                or proposed_change.responsible_actor != "bluefire.controller"
            ):
                raise ProductStoreError("protected defense proposal differs from its plan")
            try:
                experiment.review_defense(
                    proposed_change,
                    timestamp=proposed_change.reviewed_at,
                )
            except EngineExperimentError as exc:
                raise ProductStoreError("protected defense review is not currently valid") from exc
        else:
            change = experiment.defense_change
            if change is None or (
                change.preimage_digest != plan.before.digest
                or change.approved_configuration_digest != plan.after.digest
                or change.before_target_snapshot_ref != before_ref
                or change.after_target_snapshot_ref != after_ref
                or change.reviewed_at != plan.planned_at
            ):
                raise ProductStoreError("protected defense plan differs from the saved change")
            if action is EngineWorkspaceAction.RETAIN_DEFENSE:
                if job_request is not None:
                    raise ProductStoreError("defense retention cannot carry a job request")
                try:
                    experiment.retain_defense(
                        change.change_id,
                        retained_at=experiment.updated_at,
                    )
                except EngineExperimentError as exc:
                    raise ProductStoreError("defense retention is not currently valid") from exc
            else:
                if job_request is None:
                    raise ProductStoreError("protected defense job request is unavailable")
                if action in {
                    EngineWorkspaceAction.RECONCILE_DEFENSE,
                    EngineWorkspaceAction.RECONCILE_ROLLBACK,
                }:
                    raise ProductStoreError(
                        "defense reconciliation preparation requires its terminal origin job"
                    )
                try:
                    parsed, operation = EngineControllerJobs._exact_defense_request(job_request)
                    EngineControllerJobs._require_defense_operation(change, operation)
                except EngineControllerJobError as exc:
                    raise ProductStoreError("protected defense job request is invalid") from exc
                expected_operation = {
                    EngineWorkspaceAction.APPLY_DEFENSE: DefenseOperation.APPLY,
                    EngineWorkspaceAction.RECONCILE_DEFENSE: DefenseOperation.RECONCILE_APPLICATION,
                    EngineWorkspaceAction.ROLLBACK_DEFENSE: DefenseOperation.ROLLBACK,
                    EngineWorkspaceAction.RECONCILE_ROLLBACK: DefenseOperation.RECONCILE_ROLLBACK,
                }[action]
                if (
                    operation is not expected_operation
                    or parsed["experiment_id"] != experiment.experiment_id
                    or parsed["experiment_revision"] != experiment.revision
                    or parsed["experiment_digest"] != experiment.digest
                    or parsed["change_id"] != change.change_id
                    or parsed["change_digest"] != content_hash(change.to_dict())
                ):
                    raise ProductStoreError("protected defense job differs from its builder")
                expected_origin = None
                if operation is DefenseOperation.RECONCILE_APPLICATION:
                    expected_origin = change.application_receipt_digest
                elif operation is DefenseOperation.RECONCILE_ROLLBACK:
                    expected_origin = change.rollback_operation_digest
                if operation in {
                    DefenseOperation.RECONCILE_APPLICATION,
                    DefenseOperation.RECONCILE_ROLLBACK,
                }:
                    if (
                        parsed["originating_job_id"] is None
                        or parsed["originating_operation_receipt_digest"] != expected_origin
                    ):
                        raise ProductStoreError("protected defense reconciliation origin changed")
                elif (
                    parsed["originating_job_id"] is not None
                    or parsed["originating_operation_receipt_digest"] is not None
                ):
                    raise ProductStoreError("protected defense operation gained an origin")
                operation_receipt = content_hash(
                    {
                        "schema_version": "bluefire.engine-defense-preparation-preview.v1",
                        "experiment_id": experiment.experiment_id,
                        "change_id": change.change_id,
                        "operation": operation.value,
                        "request_digest": content_hash(parsed),
                    }
                )
                try:
                    if operation is DefenseOperation.APPLY:
                        experiment.begin_defense_application(
                            change.change_id,
                            operation_receipt_digest=operation_receipt,
                            started_at=experiment.updated_at,
                        )
                    elif operation is DefenseOperation.ROLLBACK:
                        experiment.begin_defense_rollback(
                            change.change_id,
                            rollback_operation_digest=operation_receipt,
                            rollback_started_at=experiment.updated_at,
                        )
                except EngineExperimentError as exc:
                    raise ProductStoreError(
                        "protected defense operation is not currently valid"
                    ) from exc
    else:
        if kind != "tenant_controller_check" or job_request is None:
            raise ProductStoreError("protected controller check lacks its exact mechanism")
        if approval_record is not None or any(
            item is not None for item in limits.to_dict().values()
        ):
            raise ProductStoreError("protected controller check gained engine authority")
        mechanism, check_authority = _tenant_check_authority(document)
        change = experiment.defense_change
        if change is None or change.mechanism_ref != content_hash(mechanism.to_dict()):
            raise ProductStoreError("protected controller mechanism differs from the experiment")
        try:
            parsed = EngineControllerJobs._exact_check_request(job_request)
        except EngineControllerJobError as exc:
            raise ProductStoreError("protected controller check request is invalid") from exc
        expected_check_role = (
            ControllerCheckRole.RETAINED_REPRODUCER
            if action is EngineWorkspaceAction.REPEAT_MECHANISM
            else ControllerCheckRole.LEGITIMATE_USE
        )
        protected_input = {
            "schema_version": "bluefire.tenant-controller-check-authority.v1",
            "mechanism": mechanism.to_dict(),
            "check_id": parsed["check_id"],
            "run_id": parsed["run_id"],
            "role": parsed["role"],
            "input_digest": parsed["input_digest"],
            "reserved_at": parsed["reserved_at"],
        }
        if check_authority != protected_input:
            raise ProductStoreError("protected controller check input changed")
        try:
            role = ControllerCheckRole(parsed["role"])
            preview = ControllerCheckRecord.reserve(
                check_id=parsed["check_id"],
                experiment_id=experiment.experiment_id,
                job_id="job-" + "0" * 32,
                run_id=parsed["run_id"],
                role=role,
                mechanism_ref=parsed["mechanism_ref"],
                target_snapshot_ref=parsed["target_snapshot_ref"],
                input_digest=parsed["input_digest"],
                created_at=parsed["reserved_at"],
            )
            experiment.reserve_controller_check(preview, timestamp=parsed["reserved_at"])
        except (EngineExperimentError, TypeError, ValueError) as exc:
            raise ProductStoreError("protected controller check is invalid") from exc
        if (
            role is not expected_check_role
            or parsed["experiment_id"] != experiment.experiment_id
            or parsed["experiment_revision"] != experiment.revision
            or parsed["experiment_digest"] != experiment.digest
            or parsed["performer"] != preview.performer.value
            or parsed["mechanism_ref"] != change.mechanism_ref
            or parsed["target_snapshot_ref"] != experiment.current_target_snapshot_ref
            or parsed["reserved_at"] != prepared_at
        ):
            raise ProductStoreError("protected controller check differs from its builder")
    return dict(json_clone(value))


def _defense_review_identity(change: EngineDefenseChange) -> dict[str, Any]:
    return {
        "change_id": change.change_id,
        "experiment_id": change.experiment_id,
        "mechanism_ref": change.mechanism_ref,
        "preimage_digest": change.preimage_digest,
        "approved_configuration_digest": change.approved_configuration_digest,
        "before_target_snapshot_ref": change.before_target_snapshot_ref,
        "after_target_snapshot_ref": change.after_target_snapshot_ref,
        "rollback_digest": change.rollback_digest,
        "reviewed_by": change.reviewed_by,
        "reviewed_at": change.reviewed_at,
        "responsible_actor": change.responsible_actor,
    }


def _retained_review_plan(
    connection: sqlite3.Connection,
    *,
    action: EngineWorkspaceAction,
    experiment: EngineExperiment,
) -> TenantDefensePlan | None:
    if action not in _DEFENSE_PLAN_ACTIONS:
        return None
    change = experiment.defense_change
    if change is None:
        raise ProductStoreError("defense action lacks its reviewed change")
    rows = connection.execute(
        """
        SELECT preparation.*, version.document_json AS experiment_document_json,
               version.digest AS stored_experiment_digest
        FROM engine_action_preparations AS preparation
        JOIN engine_experiment_versions AS version
          ON version.experiment_id = preparation.experiment_id
         AND version.revision = preparation.experiment_revision
        WHERE preparation.experiment_id = ?
          AND preparation.action_kind = 'review_defense'
        ORDER BY preparation.prepared_at, preparation.generation
        """,
        (experiment.experiment_id,),
    ).fetchall()
    plans: dict[str, TenantDefensePlan] = {}
    expected_identity = _defense_review_identity(change)
    for row in rows:
        try:
            reviewed_experiment = EngineExperiment._from_controller_mapping(
                json.loads(str(row["experiment_document_json"]))
            )
        except (EngineExperimentError, TypeError, ValueError) as exc:
            raise ProductStoreError("saved defense review experiment is invalid") from exc
        if (
            reviewed_experiment.experiment_id != row["experiment_id"]
            or reviewed_experiment.revision != row["experiment_revision"]
            or reviewed_experiment.digest != row["experiment_digest"]
            or reviewed_experiment.digest != row["stored_experiment_digest"]
        ):
            raise ProductStoreError("saved defense review experiment binding changed")
        record = EngineActionPreparationStoreMixin._protected_engine_action_from_row(
            row,
            reviewed_experiment,
            None,
            reviewed_plan=None,
        )
        authority = record["protected_request"]["authority"]
        plan, proposed = _tenant_defense_review_authority(authority["document"])
        if _defense_review_identity(proposed) == expected_identity:
            plans[content_hash(plan.to_dict())] = plan
    if len(plans) != 1:
        raise ProductStoreError("defense action lacks one exact retained review plan")
    return next(iter(plans.values()))


def _approval_binding(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _APPROVAL_BINDING_FIELDS:
        raise ProductStoreError("engine action approval binding fields changed")
    row = {key: value[key] for key in _APPROVAL_BINDING_FIELDS}
    for field in (
        "run_id",
        "profile_id",
        "maximum_tier",
    ):
        if not isinstance(row[field], str) or not row[field]:
            raise ProductStoreError("engine action approval binding is invalid")
    for field in (
        "state_digest",
        "plan_digest",
        "target_scope_digest",
    ):
        _digest(row[field], f"approval {field}")
    _timestamp(row["expires_at"], "approval expiry")
    return cast(dict[str, str], row)


def _limits(value: PreparedEngineActionLimits | Mapping[str, Any]) -> PreparedEngineActionLimits:
    try:
        return (
            value
            if isinstance(value, PreparedEngineActionLimits)
            else PreparedEngineActionLimits.from_mapping(value)
        )
    except EngineActionPreparationError as exc:
        raise ProductStoreError("engine action limits are invalid") from exc


def _approval_document(
    store: EngineActionProductStore,
    connection: sqlite3.Connection,
    approval_id: Any,
) -> Mapping[str, Any] | None:
    if approval_id is None:
        return None
    if not isinstance(approval_id, str) or _APPROVAL_ID.fullmatch(approval_id) is None:
        raise ProductStoreError("prepared approval reference is invalid")
    return cast(
        Mapping[str, Any],
        store._approval_from_row(store._approval_row(connection, approval_id)).to_dict(),
    )


def _record_document(row: sqlite3.Row, protected: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": _RECORD_SCHEMA,
        "request_ref": row["request_ref"],
        "experiment_id": row["experiment_id"],
        "experiment_revision": row["experiment_revision"],
        "experiment_digest": row["experiment_digest"],
        "workspace_digest": row["workspace_digest"],
        "generation": row["generation"],
        "action_kind": row["action_kind"],
        "preparation_kind": row["preparation_kind"],
        "protected_request": dict(json_clone(protected)),
        "protected_request_digest": row["protected_request_digest"],
        "limits": json.loads(str(row["limits_json"])),
        "limits_digest": row["limits_digest"],
        "requires_approval": bool(row["requires_approval"]),
        "approval_request_id": row["approval_request_id"],
        "approval_review_binding_digest": row["approval_review_binding_digest"],
        "submission_id": row["submission_id"],
        "intent_digest": row["intent_digest"],
        "prepared_at": row["prepared_at"],
        "expires_at": row["expires_at"],
    }


class EngineActionPreparationStoreMixin:
    """Protected action preparation operations mixed into the existing store."""

    def create_engine_action_preparation(
        self: EngineActionProductStore,
        *,
        experiment_id: str,
        experiment_revision: int,
        experiment_digest: str,
        workspace_digest: str,
        action: EngineWorkspaceAction,
        limits: PreparedEngineActionLimits | Mapping[str, Any],
        prepared_at: str,
        expires_at: str,
        protected_factory: ProtectedActionFactory,
        approval_request: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        """Create or reuse one exact unexpired preparation atomically.

        The factory runs only for a new generation and must be pure.  A raised
        error rolls back both the preparation and its pending approval row.
        """

        with self._connection(write=True) as connection:
            return EngineActionPreparationStoreMixin._create_engine_action_preparation_at(
                self,
                connection,
                experiment_id=experiment_id,
                experiment_revision=experiment_revision,
                experiment_digest=experiment_digest,
                workspace_digest=workspace_digest,
                action=action,
                limits=limits,
                prepared_at=prepared_at,
                expires_at=expires_at,
                protected_factory=protected_factory,
                approval_request=approval_request,
            )

    def _create_engine_action_preparation_at(
        self: EngineActionProductStore,
        connection: sqlite3.Connection,
        *,
        experiment_id: str,
        experiment_revision: int,
        experiment_digest: str,
        workspace_digest: str,
        action: EngineWorkspaceAction,
        limits: PreparedEngineActionLimits | Mapping[str, Any],
        prepared_at: str,
        expires_at: str,
        protected_factory: ProtectedActionFactory,
        approval_request: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        """Retain a preparation in the caller's existing write transaction.

        Private slot issuance uses this implementation so the preparation and
        approval remain owned here and commit atomically with their material.
        The caller must use the store's ``BEGIN IMMEDIATE`` connection.
        """

        if not connection.in_transaction:
            raise ProductStoreError("engine action preparation requires one transaction")

        if not isinstance(experiment_id, str) or _EXPERIMENT_ID.fullmatch(experiment_id) is None:
            raise ProductStoreError("engine action experiment identity is invalid")
        if (
            isinstance(experiment_revision, bool)
            or not isinstance(experiment_revision, int)
            or experiment_revision <= 0
        ):
            raise ProductStoreError("engine action experiment revision is invalid")
        experiment_digest = _digest(experiment_digest, "engine action experiment")
        workspace_digest = _digest(workspace_digest, "engine action workspace")
        if not isinstance(action, EngineWorkspaceAction):
            raise ProductStoreError("engine workspace action is invalid")
        preparation_kind, _effect_kind, _summary, _changes, _engine, requires_approval = (
            engine_action_contract(action)
        )
        checked_limits = _limits(limits)
        prepared_at = _timestamp(prepared_at, "engine action preparation time")
        expires_at = _timestamp(expires_at, "engine action expiry")
        prepared_time = parse_iso8601_datetime(prepared_at)
        expiry_time = parse_iso8601_datetime(expires_at)
        if expiry_time <= prepared_time or (expiry_time - prepared_time).total_seconds() > 7_800:
            raise ProductStoreError("engine action expiry is outside its bound")
        checked_approval = None if approval_request is None else _approval_binding(approval_request)
        if requires_approval != (checked_approval is not None):
            raise ProductStoreError("engine action approval requirement changed")
        if checked_approval is not None and checked_approval["expires_at"] != expires_at:
            raise ProductStoreError("engine action and approval expiry differ")
        if preparation_kind is EnginePreparedActionKind.ENGINE_ATTEMPT:
            if checked_limits.wall_clock_seconds is None or checked_limits.maximum_tier is None:
                raise ProductStoreError("engine attempt limits are incomplete")
        elif any(value is not None for value in checked_limits.to_dict().values()):
            raise ProductStoreError("controller action cannot claim engine limits")

        current_time = parse_iso8601_datetime(utc_now())
        if expiry_time <= current_time:
            raise ProductStoreError("engine action preparation is already expired")
        if prepared_time > current_time:
            raise ProductStoreError("engine action preparation time is not current")
        head = connection.execute(
            """
            SELECT head.active_revision, head.active_digest, version.document_json
            FROM engine_experiment_heads AS head
            JOIN engine_experiment_versions AS version
              ON version.experiment_id = head.experiment_id
             AND version.revision = head.active_revision
            WHERE head.experiment_id = ?
            """,
            (experiment_id,),
        ).fetchone()
        if (
            head is None
            or int(head["active_revision"]) != experiment_revision
            or str(head["active_digest"]) != experiment_digest
        ):
            raise ResourceConflictError("engine action experiment head changed")
        try:
            experiment = EngineExperiment._from_controller_mapping(
                json.loads(str(head["document_json"]))
            )
        except (EngineExperimentError, TypeError, ValueError) as exc:
            raise ProductStoreError("engine action experiment is invalid") from exc
        if experiment.digest != experiment_digest:
            raise ProductStoreError("engine action experiment digest changed")
        reviewed_plan = _retained_review_plan(
            connection,
            action=action,
            experiment=experiment,
        )
        latest = connection.execute(
            """
            SELECT * FROM engine_action_preparations
            WHERE experiment_id = ? AND experiment_revision = ?
              AND experiment_digest = ? AND workspace_digest = ?
              AND action_kind = ?
            ORDER BY generation DESC LIMIT 1
            """,
            (
                experiment_id,
                experiment_revision,
                experiment_digest,
                workspace_digest,
                action.value,
            ),
        ).fetchone()
        if latest is not None and parse_iso8601_datetime(str(latest["expires_at"])) > current_time:
            requested_approval_digest = (
                None if checked_approval is None else content_hash(checked_approval)
            )
            if (
                canonical_json(checked_limits.to_dict()) != latest["limits_json"]
                or content_hash(checked_limits.to_dict()) != latest["limits_digest"]
                or prepared_at != latest["prepared_at"]
                or expires_at != latest["expires_at"]
                or requested_approval_digest != latest["approval_review_binding_digest"]
            ):
                raise ResourceConflictError(
                    "unexpired engine action preparation has different review inputs"
                )
            return EngineActionPreparationStoreMixin._protected_engine_action_from_row(
                latest,
                experiment,
                _approval_document(self, connection, latest["approval_request_id"]),
                reviewed_plan=reviewed_plan,
            )
        # Only an exact unexpired durable acknowledgement can outlive this
        # creation window. Its original timestamp and all review inputs were
        # checked above; a new preparation never receives a refreshed time.
        if not 0 <= (current_time - prepared_time).total_seconds() <= 60:
            raise ProductStoreError("engine action preparation time is not current")
        generation = 1 if latest is None else int(latest["generation"]) + 1
        approval: Mapping[str, Any] | None = None
        if checked_approval is not None:
            approval = self._create_approval_request_at(
                connection,
                run_id=checked_approval["run_id"],
                state_digest=checked_approval["state_digest"],
                plan_digest=checked_approval["plan_digest"],
                profile_id=checked_approval["profile_id"],
                target_scope_digest=checked_approval["target_scope_digest"],
                maximum_tier=checked_approval["maximum_tier"],
                expires_at=checked_approval["expires_at"],
            )
        submission_id = (
            str(uuid.uuid4())
            if preparation_kind
            in {
                EnginePreparedActionKind.ENGINE_ATTEMPT,
                EnginePreparedActionKind.CONTROLLER_JOB,
            }
            else None
        )
        job_request, raw_authority = protected_factory(approval, submission_id)
        if not isinstance(raw_authority, Mapping):
            raise ProductStoreError("protected engine authority is invalid")
        if submission_id is None:
            if job_request is not None:
                raise ProductStoreError("controller transition cannot carry a job request")
            intent_digest = None
        else:
            if not isinstance(job_request, Mapping):
                raise ProductStoreError("prepared job request is unavailable")
            intent_digest = content_hash(job_request)
        approval_id = None if approval is None else approval.get("approval_id")
        authority = _protected_authority(
            raw_authority,
            action=action,
            experiment=experiment,
            prepared_at=prepared_at,
            reviewed_plan=reviewed_plan,
            approval_id=cast(str | None, approval_id),
            approval_record=approval,
            limits=checked_limits,
            job_request=job_request,
        )
        protected = _safe_protected(
            {
                "schema_version": _PROTECTED_SCHEMA,
                "experiment_id": experiment_id,
                "experiment_revision": experiment_revision,
                "experiment_digest": experiment_digest,
                "workspace_digest": workspace_digest,
                "action_kind": action.value,
                "preparation_kind": preparation_kind.value,
                "approval_request_id": approval_id,
                "submission_id": submission_id,
                "job_request": None if job_request is None else dict(job_request),
                "authority": authority,
            }
        )
        protected_digest = content_hash(protected)
        approval_review_digest = (
            None if checked_approval is None else content_hash(checked_approval)
        )
        limits_document = checked_limits.to_dict()
        limits_json = canonical_json(limits_document)
        limits_digest = content_hash(limits_document)
        ref_binding = {
            "schema_version": "bluefire.engine-action-preparation-ref.v1",
            "experiment_id": experiment_id,
            "experiment_revision": experiment_revision,
            "experiment_digest": experiment_digest,
            "workspace_digest": workspace_digest,
            "generation": generation,
            "action_kind": action.value,
            "preparation_kind": preparation_kind.value,
            "protected_request_digest": protected_digest,
            "limits_digest": limits_digest,
            "approval_request_id": approval_id,
            "approval_review_binding_digest": approval_review_digest,
            "submission_id": submission_id,
            "intent_digest": intent_digest,
            "prepared_at": prepared_at,
            "expires_at": expires_at,
        }
        request_ref = content_hash(ref_binding)
        row_without_digest = {
            **ref_binding,
            "request_ref": request_ref,
            "protected_request": protected,
            "limits": limits_document,
            "requires_approval": requires_approval,
        }
        record_digest = content_hash(row_without_digest)
        connection.execute(
            """
            INSERT INTO engine_action_preparations(
                request_ref, experiment_id, experiment_revision,
                experiment_digest, workspace_digest, generation,
                action_kind, preparation_kind, protected_request_json,
                protected_request_digest, limits_json, limits_digest,
                requires_approval, approval_request_id,
                approval_review_binding_digest, submission_id, intent_digest,
                prepared_at, expires_at, record_digest
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_ref,
                experiment_id,
                experiment_revision,
                experiment_digest,
                workspace_digest,
                generation,
                action.value,
                preparation_kind.value,
                canonical_json(protected),
                protected_digest,
                limits_json,
                limits_digest,
                int(requires_approval),
                approval_id,
                approval_review_digest,
                submission_id,
                intent_digest,
                prepared_at,
                expires_at,
                record_digest,
            ),
        )
        saved = connection.execute(
            "SELECT * FROM engine_action_preparations WHERE request_ref = ?",
            (request_ref,),
        ).fetchone()
        if saved is None:  # pragma: no cover - SQLite insert invariant
            raise ProductStoreError("engine action preparation was not retained")
        return EngineActionPreparationStoreMixin._protected_engine_action_from_row(
            saved,
            experiment,
            _approval_document(self, connection, saved["approval_request_id"]),
            reviewed_plan=reviewed_plan,
        )

    def get_protected_engine_action_preparation(
        self: EngineActionProductStore, request_ref: str
    ) -> Mapping[str, Any]:
        """Return the controller-private request; never expose this via HTTP."""

        request_ref = _digest(request_ref, "prepared action reference")
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT preparation.*, version.document_json AS experiment_document_json
                FROM engine_action_preparations AS preparation
                JOIN engine_experiment_versions AS version
                  ON version.experiment_id = preparation.experiment_id
                 AND version.revision = preparation.experiment_revision
                WHERE preparation.request_ref = ?
                """,
                (request_ref,),
            ).fetchone()
            if row is None:
                raise ProductStoreError("engine action preparation was not found")
            try:
                experiment = EngineExperiment._from_controller_mapping(
                    json.loads(str(row["experiment_document_json"]))
                )
            except (EngineExperimentError, TypeError, ValueError) as exc:
                raise ProductStoreError("prepared action experiment is invalid") from exc
            approval = _approval_document(self, connection, row["approval_request_id"])
            action = EngineWorkspaceAction(str(row["action_kind"]))
            reviewed_plan = _retained_review_plan(
                connection,
                action=action,
                experiment=experiment,
            )
            return EngineActionPreparationStoreMixin._protected_engine_action_from_row(
                row,
                experiment,
                approval,
                reviewed_plan=reviewed_plan,
            )

    def prepared_engine_action(
        self: EngineActionProductStore, request_ref: str
    ) -> Mapping[str, Any]:
        """Return one strict review envelope without protected request material."""

        record = EngineActionPreparationStoreMixin.get_protected_engine_action_preparation(
            self, request_ref
        )
        action = EngineWorkspaceAction(record["action_kind"])
        preparation_kind, effect_kind, summary, changes, engine, requires = engine_action_contract(
            action
        )
        approval_state = EnginePreparedApprovalState.NOT_REQUIRED
        approval_expiry: str | None = None
        if requires:
            approval_id = record["approval_request_id"]
            if not isinstance(approval_id, str):
                raise ProductStoreError("prepared approval reference is unavailable")
            approval = self.get_approval_request(approval_id)
            checked = {field: approval.get(field) for field in _APPROVAL_BINDING_FIELDS}
            if content_hash(checked) != record["approval_review_binding_digest"]:
                raise ProductStoreError("prepared approval binding changed")
            try:
                approval_state = EnginePreparedApprovalState(str(approval["status"]))
            except (KeyError, ValueError) as exc:
                raise ProductStoreError("prepared approval state is invalid") from exc
            approval_expiry = str(approval["expires_at"])
        try:
            prepared = PreparedEngineAction.create(
                protected_request_ref=record["request_ref"],
                experiment_id=record["experiment_id"],
                revision=record["experiment_revision"],
                experiment_digest=record["experiment_digest"],
                workspace_digest=record["workspace_digest"],
                action_kind=action,
                preparation_kind=preparation_kind,
                effect_kind=effect_kind,
                effect_summary=summary,
                changes_target=changes,
                uses_external_engine=engine,
                requires_approval=requires,
                approval_state=approval_state,
                approval_review_binding_digest=record["approval_review_binding_digest"],
                approval_expires_at=approval_expiry,
                submission_id=record["submission_id"],
                intent_digest=record["intent_digest"],
                limits=PreparedEngineActionLimits.from_mapping(record["limits"]),
                prepared_at=record["prepared_at"],
                expires_at=record["expires_at"],
            )
        except EngineActionPreparationError as exc:
            raise ProductStoreError("prepared action review failed validation") from exc
        return prepared.to_dict()

    @staticmethod
    def _protected_engine_action_from_row(
        row: sqlite3.Row,
        experiment: EngineExperiment,
        approval_record: Mapping[str, Any] | None,
        *,
        reviewed_plan: TenantDefensePlan | None,
    ) -> Mapping[str, Any]:
        try:
            protected_raw = json.loads(str(row["protected_request_json"]))
            protected = _safe_protected(protected_raw)
            limits_raw = json.loads(str(row["limits_json"]))
            checked_limits = PreparedEngineActionLimits.from_mapping(limits_raw).to_dict()
            action = EngineWorkspaceAction(str(row["action_kind"]))
            preparation_kind = EnginePreparedActionKind(str(row["preparation_kind"]))
        except (
            EngineActionPreparationError,
            ProductStoreError,
            TypeError,
            ValueError,
        ) as exc:
            raise ProductStoreError("saved engine action preparation is invalid") from exc
        if (
            canonical_json(protected) != row["protected_request_json"]
            or content_hash(protected) != row["protected_request_digest"]
            or canonical_json(checked_limits) != row["limits_json"]
            or content_hash(checked_limits) != row["limits_digest"]
        ):
            raise ProductStoreError("saved engine action preparation changed")
        record = _record_document(row, protected)
        ref_binding = {
            "schema_version": "bluefire.engine-action-preparation-ref.v1",
            "experiment_id": record["experiment_id"],
            "experiment_revision": record["experiment_revision"],
            "experiment_digest": record["experiment_digest"],
            "workspace_digest": record["workspace_digest"],
            "generation": record["generation"],
            "action_kind": action.value,
            "preparation_kind": preparation_kind.value,
            "protected_request_digest": record["protected_request_digest"],
            "limits_digest": record["limits_digest"],
            "approval_request_id": record["approval_request_id"],
            "approval_review_binding_digest": record["approval_review_binding_digest"],
            "submission_id": record["submission_id"],
            "intent_digest": record["intent_digest"],
            "prepared_at": record["prepared_at"],
            "expires_at": record["expires_at"],
        }
        if content_hash(ref_binding) != record["request_ref"]:
            raise ProductStoreError("saved prepared action reference changed")
        digest_document = {
            **ref_binding,
            "request_ref": record["request_ref"],
            "protected_request": protected,
            "limits": checked_limits,
            "requires_approval": record["requires_approval"],
        }
        if content_hash(digest_document) != row["record_digest"]:
            raise ProductStoreError("saved engine action record changed")
        expected_kind, _effect, _summary, _changes, _engine, approval = engine_action_contract(
            action
        )
        if preparation_kind is not expected_kind or record["requires_approval"] is not approval:
            raise ProductStoreError("saved engine action semantics changed")
        if protected != {
            "schema_version": _PROTECTED_SCHEMA,
            "experiment_id": record["experiment_id"],
            "experiment_revision": record["experiment_revision"],
            "experiment_digest": record["experiment_digest"],
            "workspace_digest": record["workspace_digest"],
            "action_kind": action.value,
            "preparation_kind": preparation_kind.value,
            "approval_request_id": record["approval_request_id"],
            "submission_id": record["submission_id"],
            "job_request": protected["job_request"],
            "authority": protected["authority"],
        }:
            raise ProductStoreError("saved protected action binding changed")
        _protected_authority(
            protected["authority"],
            action=action,
            experiment=experiment,
            prepared_at=record["prepared_at"],
            reviewed_plan=reviewed_plan,
            approval_id=record["approval_request_id"],
            approval_record=approval_record,
            limits=PreparedEngineActionLimits.from_mapping(checked_limits),
            job_request=protected["job_request"],
        )
        if record["submission_id"] is None:
            if protected["job_request"] is not None or record["intent_digest"] is not None:
                raise ProductStoreError("saved transition claimed a job submission")
        else:
            _uuid(record["submission_id"], "prepared submission identity")
            if (
                not isinstance(protected["job_request"], Mapping)
                or content_hash(protected["job_request"]) != record["intent_digest"]
            ):
                raise ProductStoreError("saved prepared job intent changed")
        return cast(Mapping[str, Any], dict(json_clone(record)))


__all__ = [
    "EngineActionPreparationStoreMixin",
    "ProtectedActionFactory",
    "initialize_schema",
]
