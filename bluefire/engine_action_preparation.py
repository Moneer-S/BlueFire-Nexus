"""Strict public contract for one server-prepared engine workspace action.

The browser receives a review envelope, never the protected attempt,
controller request, approval nonce, executable content, or evidence payload.
Preparation is bound to one immutable experiment revision and one exact
rendered workspace.  The protected request is resolved again by trusted
server code before a later submission can have any effect.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Protocol

from .engine_experiment import EngineExperiment, EngineExperimentError
from .product_store_errors import ProductStoreError, ResourceConflictError
from .util import content_hash, json_clone, parse_iso8601_datetime


class EngineActionPreparationError(ValueError):
    """Raised when a prepared-action envelope is not exact and canonical."""


class EngineActionPreparationServiceError(RuntimeError):
    """Privacy-safe product preparation failure with a stable API code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class EngineWorkspaceAction(str, Enum):
    START_BASELINE = "start_baseline"
    REVIEW_DEFENSE = "review_defense"
    APPLY_DEFENSE = "apply_defense"
    RECONCILE_DEFENSE = "reconcile_defense"
    REPEAT_MECHANISM = "repeat_mechanism"
    START_ADAPTIVE_SEARCH = "start_adaptive_search"
    RUN_LEGITIMATE_USE = "run_legitimate_use"
    RETAIN_DEFENSE = "retain_defense"
    ROLLBACK_DEFENSE = "rollback_defense"
    RECONCILE_ROLLBACK = "reconcile_rollback"


class EnginePreparedActionKind(str, Enum):
    ENGINE_ATTEMPT = "engine_attempt"
    CONTROLLER_TRANSITION = "controller_transition"
    CONTROLLER_JOB = "controller_job"


class EnginePreparedEffectKind(str, Enum):
    EXTERNAL_ENGINE_ATTEMPT = "external_engine_attempt"
    DEFENSE_REVIEW = "defense_review"
    DEFENSIVE_CHANGE = "defensive_change"
    CONTROLLER_CHECK = "controller_check"
    DEFENSE_DISPOSITION = "defense_disposition"


class EnginePreparedApprovalState(str, Enum):
    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    CONSUMED = "consumed"
    CLAIMED = "claimed"
    WITHDRAWN = "withdrawn"


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_EXPERIMENT_ID = re.compile(r"^experiment-[0-9a-f]{32}$")
_SCHEMA = "bluefire.engine-prepared-action.v1"
_PREPARE_V1_FIELDS = frozenset(
    {"schema_version", "expected_revision", "expected_digest", "workspace_digest"}
)
_PREPARE_V2_FIELDS = frozenset((*_PREPARE_V1_FIELDS, "action_kind"))
_LIMIT_FIELDS = frozenset(
    {
        "wall_clock_seconds",
        "action_limit",
        "artifact_byte_limit",
        "cost_limit_microunits",
        "target_scope_digest",
        "maximum_tier",
    }
)
_EFFECT_FIELDS = frozenset({"kind", "summary", "changes_target", "uses_external_engine"})
_APPROVAL_FIELDS = frozenset({"required", "state", "review_binding_digest", "expires_at"})
_SUBMISSION_FIELDS = frozenset({"submission_id", "intent_digest"})
_ACTION_CONTRACT = {
    EngineWorkspaceAction.START_BASELINE: (
        EnginePreparedActionKind.ENGINE_ATTEMPT,
        EnginePreparedEffectKind.EXTERNAL_ENGINE_ATTEMPT,
        "Start a bounded external-engine baseline in the authorized disposable environment.",
        False,
        True,
        True,
    ),
    EngineWorkspaceAction.START_ADAPTIVE_SEARCH: (
        EnginePreparedActionKind.ENGINE_ATTEMPT,
        EnginePreparedEffectKind.EXTERNAL_ENGINE_ATTEMPT,
        "Start a fresh bounded adaptive attempt against the current authorized target state.",
        False,
        True,
        True,
    ),
    EngineWorkspaceAction.REVIEW_DEFENSE: (
        EnginePreparedActionKind.CONTROLLER_TRANSITION,
        EnginePreparedEffectKind.DEFENSE_REVIEW,
        "Review one bounded defensive change against the independently observed mechanism.",
        False,
        False,
        False,
    ),
    EngineWorkspaceAction.RETAIN_DEFENSE: (
        EnginePreparedActionKind.CONTROLLER_TRANSITION,
        EnginePreparedEffectKind.DEFENSE_DISPOSITION,
        "Retain the applied defensive change as the experiment disposition.",
        False,
        False,
        False,
    ),
    EngineWorkspaceAction.APPLY_DEFENSE: (
        EnginePreparedActionKind.CONTROLLER_JOB,
        EnginePreparedEffectKind.DEFENSIVE_CHANGE,
        "Apply the exact reviewed defensive change through the trusted controller.",
        True,
        False,
        False,
    ),
    EngineWorkspaceAction.RECONCILE_DEFENSE: (
        EnginePreparedActionKind.CONTROLLER_JOB,
        EnginePreparedEffectKind.DEFENSIVE_CHANGE,
        "Reconcile the interrupted defense operation without repeating the mutation.",
        False,
        False,
        False,
    ),
    EngineWorkspaceAction.ROLLBACK_DEFENSE: (
        EnginePreparedActionKind.CONTROLLER_JOB,
        EnginePreparedEffectKind.DEFENSIVE_CHANGE,
        "Roll back the exact retained defensive change through the trusted controller.",
        True,
        False,
        False,
    ),
    EngineWorkspaceAction.RECONCILE_ROLLBACK: (
        EnginePreparedActionKind.CONTROLLER_JOB,
        EnginePreparedEffectKind.DEFENSIVE_CHANGE,
        "Reconcile the interrupted rollback without repeating the mutation.",
        False,
        False,
        False,
    ),
    EngineWorkspaceAction.REPEAT_MECHANISM: (
        EnginePreparedActionKind.CONTROLLER_JOB,
        EnginePreparedEffectKind.CONTROLLER_CHECK,
        "Retest the original failure mechanism with the trusted controller.",
        False,
        False,
        False,
    ),
    EngineWorkspaceAction.RUN_LEGITIMATE_USE: (
        EnginePreparedActionKind.CONTROLLER_JOB,
        EnginePreparedEffectKind.CONTROLLER_CHECK,
        "Verify the named legitimate use with the trusted controller.",
        False,
        False,
        False,
    ),
}


def engine_action_contract(
    action: EngineWorkspaceAction,
) -> tuple[
    EnginePreparedActionKind,
    EnginePreparedEffectKind,
    str,
    bool,
    bool,
    bool,
]:
    """Return the fixed public meaning of one effectful workspace action."""

    if not isinstance(action, EngineWorkspaceAction):
        raise EngineActionPreparationError("prepared workspace action is invalid")
    return _ACTION_CONTRACT[action]


class EngineActionPreparationHistory(Protocol):
    def get_engine_experiment(
        self, experiment_id: str, *, revision: int | None = None
    ) -> Mapping[str, Any]: ...

    def create_engine_action_preparation(self, **values: Any) -> Mapping[str, Any]: ...

    def prepared_engine_action(self, request_ref: str) -> Mapping[str, Any]: ...


class EngineActionWorkspaceSource(Protocol):
    def workspace(self, experiment_id: str) -> Mapping[str, Any]: ...


ProtectedActionFactory = Callable[
    [Mapping[str, Any] | None, str | None],
    tuple[Mapping[str, Any] | None, Mapping[str, Any]],
]

# Controller-private material sources may retain an immutable slot and its
# preparation in one protected-store transaction. The browser cannot provide
# this callback or any of the trusted preparation values passed into it.
ProtectedPreparationRetainer = Callable[..., Mapping[str, Any]]


@dataclass(frozen=True, slots=True)
class EngineActionPreparationPlan:
    """Pure trusted material passed immediately into the protected store."""

    action: EngineWorkspaceAction
    limits: PreparedEngineActionLimits
    expires_at: str
    protected_factory: ProtectedActionFactory
    approval_request: Mapping[str, Any] | None = None
    retain_preparation: ProtectedPreparationRetainer | None = None


class TrustedEngineActionPreparer(Protocol):
    """Controller-owned pure factory; it cannot launch or mutate anything."""

    def prepare(
        self,
        *,
        experiment: EngineExperiment,
        workspace: Mapping[str, Any],
        action: EngineWorkspaceAction,
        prepared_at: str,
    ) -> EngineActionPreparationPlan: ...


class EngineActionPreparationCoordinator:
    """Derive the sole current action and retain its exact review envelope."""

    def __init__(
        self,
        *,
        history: EngineActionPreparationHistory,
        workspace_source: EngineActionWorkspaceSource,
        preparer: TrustedEngineActionPreparer | None,
        clock: Callable[[], str],
    ) -> None:
        self._history = history
        self._workspace_source = workspace_source
        self._preparer = preparer
        self._clock = clock

    def prepare_request(self, experiment_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        if not isinstance(request, Mapping):
            raise EngineActionPreparationServiceError(
                "engine_request_invalid",
                "The engine action preparation request does not match the supported contract.",
            )
        schema = request.get("schema_version")
        selected_action: EngineWorkspaceAction | None = None
        if schema == "bluefire.engine-action-prepare-request.v1":
            valid_fields = set(request) == _PREPARE_V1_FIELDS
        elif schema == "bluefire.engine-action-prepare-request.v2":
            valid_fields = set(request) == _PREPARE_V2_FIELDS
            try:
                selected_action = EngineWorkspaceAction(request.get("action_kind"))
            except (TypeError, ValueError):
                valid_fields = False
        else:
            valid_fields = False
        if not valid_fields:
            raise EngineActionPreparationServiceError(
                "engine_request_invalid",
                "The engine action preparation request does not match the supported contract.",
            )
        expected_revision = request.get("expected_revision")
        expected_digest = request.get("expected_digest")
        expected_workspace = request.get("workspace_digest")
        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or not 1 <= expected_revision <= 10_000
            or not isinstance(expected_digest, str)
            or _DIGEST.fullmatch(expected_digest) is None
            or not isinstance(expected_workspace, str)
            or _DIGEST.fullmatch(expected_workspace) is None
        ):
            raise EngineActionPreparationServiceError(
                "engine_request_invalid",
                "The engine action preparation request does not match the supported contract.",
            )
        if self._preparer is None:
            raise EngineActionPreparationServiceError(
                "engine_action_unavailable",
                "The trusted engine action preparer is unavailable.",
            )
        try:
            record = self._history.get_engine_experiment(experiment_id)
            experiment = EngineExperiment._from_controller_mapping(record["document"])
            self._expect_head(
                record,
                expected_revision=expected_revision,
                expected_digest=expected_digest,
            )
            workspace = dict(json_clone(self._workspace_source.workspace(experiment_id)))
            action = self._current_action(
                workspace,
                experiment=experiment,
                expected_workspace_digest=expected_workspace,
                requested_action=selected_action,
            )
            prepared_at = _timestamp(self._clock(), "engine action preparation time")
            plan = self._preparer.prepare(
                experiment=experiment,
                workspace=workspace,
                action=action,
                prepared_at=prepared_at,
            )
            if not isinstance(plan, EngineActionPreparationPlan) or plan.action is not action:
                raise EngineActionPreparationError("trusted preparer returned another action")
            # Rebuild the workspace after pure materialization.  Any run,
            # presentation, or experiment drift invalidates this review.
            fresh_record = self._history.get_engine_experiment(experiment_id)
            self._expect_head(
                fresh_record,
                expected_revision=expected_revision,
                expected_digest=expected_digest,
            )
            fresh_workspace = dict(json_clone(self._workspace_source.workspace(experiment_id)))
            if fresh_workspace != workspace:
                raise ResourceConflictError("engine action workspace changed")
            retain_preparation = (
                self._history.create_engine_action_preparation
                if plan.retain_preparation is None
                else plan.retain_preparation
            )
            protected = retain_preparation(
                experiment_id=experiment.experiment_id,
                experiment_revision=experiment.revision,
                experiment_digest=experiment.digest,
                workspace_digest=expected_workspace,
                action=action,
                limits=plan.limits,
                prepared_at=prepared_at,
                expires_at=plan.expires_at,
                protected_factory=plan.protected_factory,
                approval_request=plan.approval_request,
            )
            return self._history.prepared_engine_action(str(protected["request_ref"]))
        except EngineActionPreparationServiceError:
            raise
        except ResourceConflictError as exc:
            raise EngineActionPreparationServiceError(
                "engine_action_stale",
                "The engine workspace changed before the action could be prepared.",
            ) from exc
        except (EngineActionPreparationError, EngineExperimentError, ProductStoreError) as exc:
            raise EngineActionPreparationServiceError(
                "engine_action_preparation_refused",
                "The current engine action could not be prepared safely.",
            ) from exc

    @staticmethod
    def _expect_head(
        record: Mapping[str, Any], *, expected_revision: int, expected_digest: str
    ) -> None:
        if (
            record.get("active") is not True
            or record.get("revision") != expected_revision
            or record.get("digest") != expected_digest
        ):
            raise ResourceConflictError("engine action experiment head changed")

    @staticmethod
    def _current_action(
        workspace: Mapping[str, Any],
        *,
        experiment: EngineExperiment,
        expected_workspace_digest: str,
        requested_action: EngineWorkspaceAction | None = None,
    ) -> EngineWorkspaceAction:
        if (
            workspace.get("schema_version") != "bluefire.engine-experiment-workspace.v1"
            or workspace.get("experiment_id") != experiment.experiment_id
            or workspace.get("revision") != experiment.revision
            or workspace.get("experiment_digest") != experiment.digest
            or workspace.get("workspace_digest") != expected_workspace_digest
        ):
            raise ResourceConflictError("engine action workspace binding changed")
        actions = workspace.get("actions")
        if not isinstance(actions, list) or not actions:
            raise EngineActionPreparationError("engine workspace action is ambiguous")
        if any(not isinstance(item, Mapping) for item in actions):
            raise EngineActionPreparationError("engine workspace action is invalid")
        kinds = [item.get("kind") for item in actions]
        if any(not isinstance(kind, str) for kind in kinds) or len(set(kinds)) != len(kinds):
            raise EngineActionPreparationError("engine workspace action is ambiguous")
        if requested_action is None:
            if len(actions) != 1:
                raise EngineActionPreparationError("engine workspace action is ambiguous")
            row = actions[0]
        else:
            matches = [item for item in actions if item.get("kind") == requested_action.value]
            if len(matches) != 1:
                raise EngineActionPreparationError(
                    "selected engine workspace action is unavailable"
                )
            row = matches[0]
        if not isinstance(row, Mapping) or row.get("enabled") is not True:
            raise EngineActionPreparationServiceError(
                "engine_action_unavailable",
                "The current engine workspace action is unavailable.",
            )
        raw_kind = row.get("kind")
        if raw_kind in {
            "review_evidence",
            "open_comparison",
            "choose_defense_disposition",
        }:
            raise EngineActionPreparationServiceError(
                "engine_action_unavailable",
                "The current workspace action does not use an execution preparation.",
            )
        try:
            action = EngineWorkspaceAction(raw_kind)
        except (TypeError, ValueError) as exc:
            raise EngineActionPreparationError("engine workspace action is unsupported") from exc
        if requested_action is not None and action is not requested_action:
            raise EngineActionPreparationError("selected engine workspace action changed")
        return action


def _exact(value: Any, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise EngineActionPreparationError(f"{label} fields changed")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise EngineActionPreparationError(f"{label} must be an exact sha256 digest")
    return value


def _text(value: Any, label: str, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise EngineActionPreparationError(f"{label} is invalid")
    return value


def _timestamp(value: Any, label: str) -> str:
    result = _text(value, label, maximum=40)
    try:
        parsed = parse_iso8601_datetime(result)
    except ValueError as exc:
        raise EngineActionPreparationError(f"{label} is invalid") from exc
    if parsed.isoformat().replace("+00:00", "Z") != result:
        raise EngineActionPreparationError(f"{label} is not canonical")
    return result


def _bounded_optional_int(value: Any, label: str, minimum: int, maximum: int) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise EngineActionPreparationError(f"{label} is outside its bound")
    return int(value)


@dataclass(frozen=True, slots=True)
class PreparedEngineActionLimits:
    wall_clock_seconds: int | None
    action_limit: int | None
    artifact_byte_limit: int | None
    cost_limit_microunits: int | None
    target_scope_digest: str | None
    maximum_tier: str | None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "PreparedEngineActionLimits":
        row = _exact(value, _LIMIT_FIELDS, "prepared action limits")
        target_scope = row["target_scope_digest"]
        maximum_tier = row["maximum_tier"]
        if target_scope is not None:
            target_scope = _digest(target_scope, "prepared target scope")
        if maximum_tier is not None:
            maximum_tier = _text(maximum_tier, "prepared maximum tier", maximum=32)
            if maximum_tier not in {"safe", "controlled", "restricted"}:
                raise EngineActionPreparationError("prepared maximum tier is unsupported")
        values = (
            row["wall_clock_seconds"],
            row["action_limit"],
            row["artifact_byte_limit"],
            row["cost_limit_microunits"],
        )
        if any(item is None for item in values) and any(item is not None for item in values):
            raise EngineActionPreparationError("prepared numeric limits are incomplete")
        if (target_scope is None) != (maximum_tier is None):
            raise EngineActionPreparationError("prepared authority limits are incomplete")
        return cls(
            wall_clock_seconds=_bounded_optional_int(
                row["wall_clock_seconds"], "prepared wall-clock limit", 1, 7_200
            ),
            action_limit=_bounded_optional_int(
                row["action_limit"], "prepared action limit", 1, 512
            ),
            artifact_byte_limit=_bounded_optional_int(
                row["artifact_byte_limit"],
                "prepared artifact limit",
                1,
                64 * 1024 * 1024,
            ),
            cost_limit_microunits=_bounded_optional_int(
                row["cost_limit_microunits"],
                "prepared cost limit",
                0,
                10_000_000_000,
            ),
            target_scope_digest=target_scope,
            maximum_tier=maximum_tier,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "wall_clock_seconds": self.wall_clock_seconds,
            "action_limit": self.action_limit,
            "artifact_byte_limit": self.artifact_byte_limit,
            "cost_limit_microunits": self.cost_limit_microunits,
            "target_scope_digest": self.target_scope_digest,
            "maximum_tier": self.maximum_tier,
        }


@dataclass(frozen=True, slots=True)
class PreparedEngineAction:
    preparation_id: str
    protected_request_ref: str
    experiment_id: str
    revision: int
    experiment_digest: str
    workspace_digest: str
    action_kind: EngineWorkspaceAction
    preparation_kind: EnginePreparedActionKind
    effect_kind: EnginePreparedEffectKind
    effect_summary: str
    changes_target: bool
    uses_external_engine: bool
    requires_approval: bool
    approval_state: EnginePreparedApprovalState
    approval_review_binding_digest: str | None
    approval_expires_at: str | None
    submission_id: str | None
    intent_digest: str | None
    limits: PreparedEngineActionLimits
    prepared_at: str
    expires_at: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "PreparedEngineAction":
        fields = frozenset(
            {
                "schema_version",
                "preparation_id",
                "protected_request_ref",
                "experiment_id",
                "revision",
                "experiment_digest",
                "workspace_digest",
                "action_kind",
                "preparation_kind",
                "effect",
                "requires_approval",
                "approval",
                "submission",
                "limits",
                "prepared_at",
                "expires_at",
                "effects_started_at_preparation",
            }
        )
        row = _exact(value, fields, "prepared engine action")
        if row["schema_version"] != _SCHEMA or row["effects_started_at_preparation"] is not False:
            raise EngineActionPreparationError("prepared action contract is unsupported")
        experiment_id = row["experiment_id"]
        if not isinstance(experiment_id, str) or _EXPERIMENT_ID.fullmatch(experiment_id) is None:
            raise EngineActionPreparationError("prepared experiment identity is invalid")
        revision = row["revision"]
        if (
            isinstance(revision, bool)
            or not isinstance(revision, int)
            or not 1 <= revision <= 10_000
        ):
            raise EngineActionPreparationError("prepared experiment revision is invalid")
        try:
            action = EngineWorkspaceAction(row["action_kind"])
            kind = EnginePreparedActionKind(row["preparation_kind"])
        except (TypeError, ValueError) as exc:
            raise EngineActionPreparationError("prepared action identity is invalid") from exc
        effect = _exact(row["effect"], _EFFECT_FIELDS, "prepared effect")
        try:
            effect_kind = EnginePreparedEffectKind(effect["kind"])
        except (TypeError, ValueError) as exc:
            raise EngineActionPreparationError("prepared effect kind is invalid") from exc
        if (
            type(effect["changes_target"]) is not bool
            or type(effect["uses_external_engine"]) is not bool
        ):
            raise EngineActionPreparationError("prepared effect flags are invalid")
        requires_approval = row["requires_approval"]
        if type(requires_approval) is not bool:
            raise EngineActionPreparationError("prepared approval requirement is invalid")
        approval = _exact(row["approval"], _APPROVAL_FIELDS, "prepared approval")
        if approval["required"] is not requires_approval:
            raise EngineActionPreparationError("prepared approval requirement changed")
        try:
            approval_state = EnginePreparedApprovalState(approval["state"])
        except (TypeError, ValueError) as exc:
            raise EngineActionPreparationError("prepared approval state is invalid") from exc
        review_digest = approval["review_binding_digest"]
        approval_expiry = approval["expires_at"]
        if requires_approval:
            if approval_state is EnginePreparedApprovalState.NOT_REQUIRED:
                raise EngineActionPreparationError("required approval is unavailable")
            review_digest = _digest(review_digest, "approval review binding")
            approval_expiry = _timestamp(approval_expiry, "approval expiry")
        elif (
            approval_state is not EnginePreparedApprovalState.NOT_REQUIRED
            or review_digest is not None
            or approval_expiry is not None
        ):
            raise EngineActionPreparationError("unrequired approval carried authority")
        submission = row["submission"]
        submission_id: str | None = None
        intent_digest: str | None = None
        if submission is not None:
            parsed_submission = _exact(submission, _SUBMISSION_FIELDS, "prepared submission")
            raw_submission_id = parsed_submission["submission_id"]
            try:
                identifier = uuid.UUID(str(raw_submission_id))
            except ValueError as exc:
                raise EngineActionPreparationError(
                    "prepared submission identity is invalid"
                ) from exc
            if not isinstance(raw_submission_id, str) or str(identifier) != raw_submission_id:
                raise EngineActionPreparationError("prepared submission identity is invalid")
            submission_id = raw_submission_id
            intent_digest = _digest(
                parsed_submission["intent_digest"], "prepared submission intent"
            )
        prepared_at = _timestamp(row["prepared_at"], "preparation time")
        expires_at = _timestamp(row["expires_at"], "preparation expiry")
        duration = (
            parse_iso8601_datetime(expires_at) - parse_iso8601_datetime(prepared_at)
        ).total_seconds()
        if not 0 < duration <= 7_800:
            raise EngineActionPreparationError("prepared action expiry is not in the future")
        candidate = cls(
            preparation_id=_digest(row["preparation_id"], "preparation identity"),
            protected_request_ref=_digest(
                row["protected_request_ref"], "protected request reference"
            ),
            experiment_id=experiment_id,
            revision=revision,
            experiment_digest=_digest(row["experiment_digest"], "experiment digest"),
            workspace_digest=_digest(row["workspace_digest"], "workspace digest"),
            action_kind=action,
            preparation_kind=kind,
            effect_kind=effect_kind,
            effect_summary=_text(effect["summary"], "prepared effect summary", maximum=240),
            changes_target=effect["changes_target"],
            uses_external_engine=effect["uses_external_engine"],
            requires_approval=requires_approval,
            approval_state=approval_state,
            approval_review_binding_digest=review_digest,
            approval_expires_at=approval_expiry,
            submission_id=submission_id,
            intent_digest=intent_digest,
            limits=PreparedEngineActionLimits.from_mapping(row["limits"]),
            prepared_at=prepared_at,
            expires_at=expires_at,
        )
        if candidate.preparation_id != candidate.calculated_preparation_id:
            raise EngineActionPreparationError("prepared action digest changed")
        candidate._validate_semantics()
        return candidate

    def _validate_semantics(self) -> None:
        expected = engine_action_contract(self.action_kind)
        actual = (
            self.preparation_kind,
            self.effect_kind,
            self.effect_summary,
            self.changes_target,
            self.uses_external_engine,
            self.requires_approval,
        )
        if actual != expected:
            raise EngineActionPreparationError("prepared action effect is inconsistent")
        if self.preparation_kind is EnginePreparedActionKind.ENGINE_ATTEMPT:
            if (
                not self.requires_approval
                or self.submission_id is None
                or self.intent_digest is None
                or self.limits.wall_clock_seconds is None
                or self.limits.action_limit is None
                or self.limits.artifact_byte_limit is None
                or self.limits.cost_limit_microunits is None
                or self.limits.target_scope_digest is None
                or self.limits.maximum_tier is None
                or self.effect_kind is not EnginePreparedEffectKind.EXTERNAL_ENGINE_ATTEMPT
                or not self.uses_external_engine
            ):
                raise EngineActionPreparationError("prepared engine attempt is incomplete")
            if self.approval_expires_at != self.expires_at:
                raise EngineActionPreparationError("prepared approval expiry changed")
        elif (
            self.uses_external_engine
            or self.requires_approval
            or any(value is not None for value in self.limits.to_dict().values())
        ):
            raise EngineActionPreparationError("controller action claimed engine authority")
        if self.preparation_kind is EnginePreparedActionKind.CONTROLLER_JOB and (
            self.submission_id is None or self.intent_digest is None
        ):
            raise EngineActionPreparationError("prepared controller job lacks idempotency")
        if self.preparation_kind is EnginePreparedActionKind.CONTROLLER_TRANSITION and (
            self.submission_id is not None or self.intent_digest is not None
        ):
            raise EngineActionPreparationError("prepared transition claimed a job submission")

    def _without_id(self) -> dict[str, Any]:
        return {
            "schema_version": _SCHEMA,
            "protected_request_ref": self.protected_request_ref,
            "experiment_id": self.experiment_id,
            "revision": self.revision,
            "experiment_digest": self.experiment_digest,
            "workspace_digest": self.workspace_digest,
            "action_kind": self.action_kind.value,
            "preparation_kind": self.preparation_kind.value,
            "effect": {
                "kind": self.effect_kind.value,
                "summary": self.effect_summary,
                "changes_target": self.changes_target,
                "uses_external_engine": self.uses_external_engine,
            },
            "requires_approval": self.requires_approval,
            "approval": {
                "required": self.requires_approval,
                "state": self.approval_state.value,
                "review_binding_digest": self.approval_review_binding_digest,
                "expires_at": self.approval_expires_at,
            },
            "submission": (
                None
                if self.submission_id is None
                else {
                    "submission_id": self.submission_id,
                    "intent_digest": self.intent_digest,
                }
            ),
            "limits": self.limits.to_dict(),
            "prepared_at": self.prepared_at,
            "expires_at": self.expires_at,
            "effects_started_at_preparation": False,
        }

    @property
    def calculated_preparation_id(self) -> str:
        document = self._without_id()
        # Approval status is live lifecycle information.  The immutable
        # preparation identity remains stable while that status advances.
        document["approval"] = {
            **document["approval"],
            "state": ("pending" if self.requires_approval else "not_required"),
        }
        return content_hash(document)

    def to_dict(self) -> dict[str, Any]:
        document = {
            **self._without_id(),
            "preparation_id": self.preparation_id,
        }
        # Round-trip before exposing the document so a noncanonical direct
        # constructor cannot bypass the public contract.
        if type(self).from_mapping(document) != self:
            raise EngineActionPreparationError("prepared action is not canonical")
        return dict(json_clone(document))

    @classmethod
    def create(
        cls,
        *,
        protected_request_ref: str,
        experiment_id: str,
        revision: int,
        experiment_digest: str,
        workspace_digest: str,
        action_kind: EngineWorkspaceAction,
        preparation_kind: EnginePreparedActionKind,
        effect_kind: EnginePreparedEffectKind,
        effect_summary: str,
        changes_target: bool,
        uses_external_engine: bool,
        requires_approval: bool,
        approval_state: EnginePreparedApprovalState,
        approval_review_binding_digest: str | None,
        approval_expires_at: str | None,
        submission_id: str | None,
        intent_digest: str | None,
        limits: PreparedEngineActionLimits,
        prepared_at: str,
        expires_at: str,
    ) -> "PreparedEngineAction":
        provisional = cls(
            preparation_id="sha256:" + "0" * 64,
            protected_request_ref=protected_request_ref,
            experiment_id=experiment_id,
            revision=revision,
            experiment_digest=experiment_digest,
            workspace_digest=workspace_digest,
            action_kind=action_kind,
            preparation_kind=preparation_kind,
            effect_kind=effect_kind,
            effect_summary=effect_summary,
            changes_target=changes_target,
            uses_external_engine=uses_external_engine,
            requires_approval=requires_approval,
            approval_state=approval_state,
            approval_review_binding_digest=approval_review_binding_digest,
            approval_expires_at=approval_expires_at,
            submission_id=submission_id,
            intent_digest=intent_digest,
            limits=limits,
            prepared_at=prepared_at,
            expires_at=expires_at,
        )
        document = provisional._without_id()
        identity = dict(json_clone(document))
        identity["approval"] = {
            **identity["approval"],
            "state": "pending" if requires_approval else "not_required",
        }
        document["preparation_id"] = content_hash(identity)
        return cls.from_mapping(document)


__all__ = [
    "EngineActionPreparationCoordinator",
    "EngineActionPreparationError",
    "EngineActionPreparationHistory",
    "EngineActionPreparationPlan",
    "EngineActionPreparationServiceError",
    "EngineActionWorkspaceSource",
    "EnginePreparedActionKind",
    "EnginePreparedApprovalState",
    "EnginePreparedEffectKind",
    "EngineWorkspaceAction",
    "PreparedEngineAction",
    "PreparedEngineActionLimits",
    "ProtectedActionFactory",
    "ProtectedPreparationRetainer",
    "TrustedEngineActionPreparer",
    "engine_action_contract",
]
