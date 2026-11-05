"""Strict, service-owned presenter for external-engine experiment workspaces.

The presenter is intentionally read-only.  It accepts controller-owned display
metadata, projects the canonical experiment through the evidence verifier, and
returns the closed object consumed by the desktop frontend.  It never accepts
engine-authored conclusions or selected-record summaries.
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Protocol, cast

from .engine_attempt_contract import EvidenceCategory
from .engine_experiment import (
    ControllerCheckRole,
    EngineAttemptEntry,
    EngineExperiment,
    EngineExperimentError,
    IndependentObservationRecord,
)
from .engine_experiment_presentation import (
    _DIGEST as _DIGEST,
)
from .engine_experiment_presentation import (
    _LOCAL_PATH as _LOCAL_PATH,
)
from .engine_experiment_presentation import (
    _PRESENTATION_FIELDS as _PRESENTATION_FIELDS,
)
from .engine_experiment_presentation import (
    _REVISION as _REVISION,
)
from .engine_experiment_presentation import (
    _SECRET as _SECRET,
)
from .engine_experiment_presentation import (
    _SOURCE_ID as _SOURCE_ID,
)
from .engine_experiment_presentation import (
    _TIMESTAMP as _TIMESTAMP,
)
from .engine_experiment_presentation import (
    EngineExperimentWorkspaceError as EngineExperimentWorkspaceError,
)
from .engine_experiment_presentation import (
    _checked_defense as _checked_defense,
)
from .engine_experiment_presentation import (
    _checked_presentation as _checked_presentation,
)
from .engine_experiment_presentation import (
    _checked_selection as _checked_selection,
)
from .engine_experiment_presentation import (
    _digest as _digest,
)
from .engine_experiment_presentation import (
    _exact as _exact,
)
from .engine_experiment_presentation import (
    _integer as _integer,
)
from .engine_experiment_presentation import (
    _public_text as _public_text,
)
from .engine_experiment_presentation import (
    _strings as _strings,
)
from .engine_experiment_presentation import (
    _text as _text,
)
from .engine_experiment_presentation import (
    _timestamp as _timestamp,
)
from .engine_experiment_projection import EngineRunSource, project_engine_experiment
from .util import content_hash, json_clone, parse_iso8601_datetime


class EngineExperimentSelectionNotFound(EngineExperimentWorkspaceError):
    """Raised when a well-formed selected work identity is not in the experiment."""


class EngineExperimentPresentationSource(Protocol):
    """Trusted, read-only source for controller-supplied workspace display metadata."""

    def assert_engine_experiment_presentation_create_ready(
        self, experiment: EngineExperiment
    ) -> None:
        """Refuse creation unless exact revision-one presentation is provisioned."""

    def assert_engine_experiment_presentation_transition_ready(
        self,
        current: EngineExperiment,
        successor: EngineExperiment,
    ) -> None:
        """Refuse a transition unless exact successor presentation is provisioned."""

    def get_engine_experiment_presentation(
        self,
        experiment_id: str,
        *,
        revision: int,
        experiment_digest: str,
    ) -> Mapping[str, Any]: ...


_APPROVAL_ID = re.compile(r"^approval-[0-9a-f]{32}$")
_ATTEMPT_ID = re.compile(r"^engine-attempt-[0-9a-f]{32}$")
_CHECK_ID = re.compile(r"^controller-check-[0-9a-f]{32}$")
_WORKSPACE_FIELDS = frozenset(
    {
        "schema_version",
        "workspace_digest",
        "experiment_id",
        "revision",
        "experiment_digest",
        "objective",
        "environment",
        "current_target",
        "engine_setup",
        "authorization",
        "defensive_change",
        "projection",
        "actions",
        "selected_context",
        "limitations",
    }
)
_PROJECTION_FIELDS = frozenset(
    {
        "schema_version",
        "experiment_id",
        "revision",
        "experiment_digest",
        "workflow_state",
        "conclusion",
        "attempts",
        "checks",
        "observations",
        "run_integrity",
        "projection_digest",
    }
)
_PROJECTION_ATTEMPT_FIELDS = frozenset(
    {
        "role",
        "attempt_id",
        "job_id",
        "run_id",
        "state",
        "completeness",
        "engine",
        "model",
        "target_snapshot_ref",
        "delegation_digest",
        "execution_approval_digest",
        "execution_approval_id",
        "cleanup",
        "engine_evidence_count",
        "limitations",
    }
)
_PROJECTION_CHECK_FIELDS = frozenset(
    {
        "role",
        "check_id",
        "job_id",
        "run_id",
        "state",
        "performer",
        "mechanism_ref",
        "target_snapshot_ref",
        "input_digest",
        "result_digest",
        "independent_evidence_refs",
        "cleanup",
    }
)
_PROJECTION_OBSERVATION_FIELDS = frozenset(
    {
        "evidence_id",
        "run_id",
        "attempt_id",
        "check_id",
        "mechanism_ref",
        "target_snapshot_ref",
        "assessment",
        "record_hash",
    }
)
_CONCLUSION_FIELDS = frozenset(
    {
        "headline",
        "original_mechanism",
        "retained_reproducer",
        "adaptive_search",
        "legitimate_use",
        "telemetry_health",
        "cleanup",
        "defense",
        "unknowns",
    }
)


def _projection_attempt(entry: EngineAttemptEntry) -> dict[str, Any]:
    binding = entry.record.binding
    return {
        "role": binding.role.value,
        "attempt_id": binding.attempt_id,
        "job_id": entry.job_id,
        "run_id": binding.run_id,
        "state": entry.record.state.value,
        "completeness": entry.record.completeness.value,
        "engine": {
            "id": binding.engine_id,
            "version": binding.engine_version,
            "revision": binding.engine_revision,
            "package_digest": binding.engine_package_digest,
        },
        "model": {
            "provider": binding.model_provider,
            "id": binding.model_id,
            "data_destination": binding.model_data_destination,
        },
        "target_snapshot_ref": binding.target_snapshot_ref,
        "delegation_digest": entry.delegation_digest,
        "execution_approval_digest": entry.execution_approval_digest,
        "execution_approval_id": entry.execution_approval_id,
        "cleanup": {
            "state": entry.cleanup_state.value,
            "receipt_ref": entry.cleanup_evidence_ref,
        },
        "engine_evidence_count": len(entry.evidence),
        "limitations": list(entry.record.limitations),
    }


def _projection_check(check: Any) -> dict[str, Any]:
    return {
        "role": check.role.value,
        "check_id": check.check_id,
        "job_id": check.job_id,
        "run_id": check.run_id,
        "state": check.state.value,
        "performer": check.performer.value,
        "mechanism_ref": check.mechanism_ref,
        "target_snapshot_ref": check.target_snapshot_ref,
        "input_digest": check.input_digest,
        "result_digest": check.result_digest,
        "independent_evidence_refs": list(check.independent_evidence_refs),
        "cleanup": {
            "state": check.cleanup_state.value,
            "receipt_ref": check.cleanup_evidence_ref,
        },
    }


def _observation_row(observation: IndependentObservationRecord) -> dict[str, Any]:
    return {
        "evidence_id": observation.evidence_id,
        "run_id": observation.evidence.run_id,
        "attempt_id": observation.attempt_id,
        "check_id": observation.check_id,
        "mechanism_ref": observation.mechanism_ref,
        "target_snapshot_ref": observation.target_snapshot_ref,
        "assessment": observation.assessment,
        "record_hash": observation.evidence.record_hash,
    }


def _check_projection_shape(
    projection: Mapping[str, Any], experiment: EngineExperiment
) -> dict[str, Any]:
    row = _exact(projection, _PROJECTION_FIELDS, "engine experiment projection")
    if row["schema_version"] != "bluefire.engine-experiment-projection.v1":
        raise EngineExperimentWorkspaceError("engine experiment projection is unsupported")
    if (
        row["experiment_id"] != experiment.experiment_id
        or row["revision"] != experiment.revision
        or row["experiment_digest"] != experiment.digest
    ):
        raise EngineExperimentWorkspaceError("engine experiment projection identity changed")

    clone = json_clone(row)
    if not isinstance(clone, dict):
        raise EngineExperimentWorkspaceError("engine experiment projection is invalid")
    claimed_digest = clone.pop("projection_digest", None)
    if claimed_digest != content_hash(clone):
        raise EngineExperimentWorkspaceError("engine experiment projection digest changed")

    attempts = row["attempts"]
    if not isinstance(attempts, list) or len(attempts) != len(experiment.attempts):
        raise EngineExperimentWorkspaceError("projected engine attempts changed")
    for item, entry in zip(attempts, experiment.attempts, strict=True):
        attempt = _exact(item, _PROJECTION_ATTEMPT_FIELDS, "projected engine attempt")
        _exact(
            attempt["engine"],
            frozenset({"id", "version", "revision", "package_digest"}),
            "projected engine identity",
        )
        _exact(
            attempt["model"],
            frozenset({"provider", "id", "data_destination"}),
            "projected model identity",
        )
        _exact(attempt["cleanup"], frozenset({"state", "receipt_ref"}), "projected attempt cleanup")
        if dict(json_clone(attempt)) != _projection_attempt(entry):
            raise EngineExperimentWorkspaceError("projected engine attempt changed")
        for limitation in cast(list[Any], attempt["limitations"]):
            _public_text(limitation, "projected attempt limitation", maximum=300)
        if _APPROVAL_ID.fullmatch(cast(str, attempt["execution_approval_id"])) is None:
            raise EngineExperimentWorkspaceError("projected execution approval is invalid")

    checks = row["checks"]
    if not isinstance(checks, list) or len(checks) != len(experiment.checks):
        raise EngineExperimentWorkspaceError("projected controller checks changed")
    for item, check in zip(checks, experiment.checks, strict=True):
        projected = _exact(item, _PROJECTION_CHECK_FIELDS, "projected controller check")
        _exact(projected["cleanup"], frozenset({"state", "receipt_ref"}), "projected check cleanup")
        if dict(json_clone(projected)) != _projection_check(check):
            raise EngineExperimentWorkspaceError("projected controller check changed")

    integrity = row["run_integrity"]
    work = [
        (
            entry.record.binding.run_id,
            entry.record.state.value not in {"queued", "preflight", "running", "stopping"},
        )
        for entry in experiment.attempts
    ] + [(check.run_id, check.state.value != "reserved") for check in experiment.checks]
    if not isinstance(integrity, list) or len(integrity) != len(work):
        raise EngineExperimentWorkspaceError("run integrity changed")
    integrity_by_run: dict[str, str] = {}
    for item, expected in zip(integrity, work, strict=True):
        integrity_row = _exact(
            item,
            frozenset({"run_id", "terminal", "state", "detail"}),
            "run integrity",
        )
        run_id, terminal = expected
        if (
            integrity_row["run_id"] != run_id
            or integrity_row["terminal"] is not terminal
            or integrity_row["state"] not in {"verified", "unavailable"}
        ):
            raise EngineExperimentWorkspaceError("run integrity identity changed")
        _public_text(integrity_row["detail"], "run integrity detail", maximum=500)
        integrity_by_run[run_id] = cast(str, integrity_row["state"])

    expected_observations = [
        _observation_row(observation)
        for run_id, _terminal in work
        if integrity_by_run.get(run_id) == "verified"
        for observation in experiment.independent_observations
        if observation.evidence.run_id == run_id
    ]
    observations = row["observations"]
    if not isinstance(observations, list) or len(observations) != len(expected_observations):
        raise EngineExperimentWorkspaceError("projected independent observations changed")
    for item, expected_observation in zip(observations, expected_observations, strict=True):
        projected = _exact(
            item,
            _PROJECTION_OBSERVATION_FIELDS,
            "projected independent observation",
        )
        if dict(json_clone(projected)) != expected_observation:
            raise EngineExperimentWorkspaceError("projected independent observation changed")

    _check_conclusion_shape(row["conclusion"])
    return dict(cast(dict[str, Any], json_clone(row)))


def _check_conclusion_shape(value: Any) -> None:
    row = _exact(value, _CONCLUSION_FIELDS, "engine experiment conclusion")
    for name in ("original_mechanism", "retained_reproducer", "legitimate_use"):
        _exact(
            row[name],
            frozenset({"status", "run_id", "support_refs"}),
            f"{name} conclusion",
        )
    _exact(
        row["adaptive_search"],
        frozenset({"status", "run_id", "support_refs", "limit_qualified"}),
        "adaptive search conclusion",
    )
    telemetry = _exact(
        row["telemetry_health"],
        frozenset({"status", "expected_sources", "verified_sources", "missing_sources"}),
        "telemetry health",
    )
    for name in ("expected_sources", "verified_sources", "missing_sources"):
        _strings(telemetry[name], f"telemetry {name}", maximum=4, item_maximum=80)
    cleanup = _exact(row["cleanup"], frozenset({"status", "items"}), "conclusion cleanup")
    if not isinstance(cleanup["items"], list):
        raise EngineExperimentWorkspaceError("conclusion cleanup items changed")
    for item in cleanup["items"]:
        _exact(
            item,
            frozenset({"kind", "id", "state", "receipt_ref"}),
            "conclusion cleanup item",
        )
    _exact(
        row["defense"],
        frozenset(
            {
                "state",
                "change_id",
                "mechanism_ref",
                "before_target_snapshot_ref",
                "after_target_snapshot_ref",
                "current_target_snapshot_ref",
                "application_receipt_ref",
                "reconciliation_receipt_ref",
                "rollback_operation_ref",
                "rollback_receipt_ref",
            }
        ),
        "conclusion defense",
    )
    _strings(row["unknowns"], "conclusion unknowns")


def _actions(
    projection: Mapping[str, Any], current_target: Mapping[str, Any] | None
) -> list[dict[str, Any]]:
    state = projection["workflow_state"]
    conclusion = cast(Mapping[str, Any], projection["conclusion"])
    integrity = cast(list[Mapping[str, Any]], projection["run_integrity"])
    all_verified = all(item["state"] == "verified" for item in integrity)
    if state == "choose_defense_disposition":
        defense = cast(Mapping[str, Any], conclusion["defense"])
        cleanup = cast(Mapping[str, Any], conclusion["cleanup"])
        attempts = cast(list[Mapping[str, Any]], projection["attempts"])
        checks = cast(list[Mapping[str, Any]], projection["checks"])
        active = any(
            item["state"] in {"queued", "preflight", "running", "stopping"} for item in attempts
        ) or any(item["state"] == "reserved" for item in checks)
        if (
            not all_verified
            or current_target is None
            or defense["state"] != "applied"
            or cleanup["status"] != "verified_absent"
            or active
        ):
            return []
        return [
            {
                "kind": "retain_defense",
                "label": "Retain applied defensive change",
                "enabled": True,
                "reason": (
                    "Records the applied change as this experiment's disposition without "
                    "claiming cleanup or broad remediation."
                ),
                "primary": False,
            },
            {
                "kind": "rollback_defense",
                "label": "Roll back applied defensive change",
                "enabled": True,
                "reason": (
                    "Runs the exact reviewed rollback through the trusted controller; it does "
                    "not stop workers or reset the lab."
                ),
                "primary": False,
            },
        ]
    primary: dict[str, tuple[str, str, bool]] = {
        "ready_for_baseline": (
            "start_baseline",
            "Start baseline exploration",
            current_target is not None,
        ),
        "baseline_active": (
            "review_evidence",
            "Review active baseline",
            True,
        ),
        "review_defense": (
            "review_defense",
            "Review a defensive change",
            all_verified
            and cast(Mapping[str, Any], conclusion["original_mechanism"])["status"]
            == "established",
        ),
        "apply_defense": (
            "apply_defense",
            "Apply reviewed defense",
            all_verified and current_target is not None,
        ),
        "reconcile_defense": (
            "reconcile_defense",
            "Reconcile defensive state",
            True,
        ),
        "run_retained_reproducer": (
            "repeat_mechanism",
            "Retest the original mechanism",
            all_verified and current_target is not None,
        ),
        "retained_reproducer_active": (
            "review_evidence",
            "Review active retest",
            True,
        ),
        "run_adaptive_search": (
            "start_adaptive_search",
            "Start fresh adaptive search",
            all_verified and current_target is not None,
        ),
        "adaptive_search_active": (
            "review_evidence",
            "Review active adaptive search",
            True,
        ),
        "run_legitimate_use": (
            "run_legitimate_use",
            "Run legitimate-use check",
            all_verified and current_target is not None,
        ),
        "legitimate_use_active": (
            "review_evidence",
            "Review active legitimate-use check",
            True,
        ),
        "complete": (
            "open_comparison",
            "Open outcome comparison",
            True,
        ),
    }
    if state not in primary:
        raise EngineExperimentWorkspaceError("engine workflow state is unsupported")
    kind, label, enabled = primary[state]
    if enabled:
        reason = {
            "start_baseline": "Requires a fresh reviewed execution approval.",
            "review_evidence": "Opens the saved job and available evidence without repeating work.",
            "review_defense": "Uses independently verified baseline evidence for controller review.",
            "apply_defense": "Uses the reviewed controller operation; the engine cannot apply it.",
            "reconcile_defense": "Re-establishes the current target state before more work starts.",
            "repeat_mechanism": "Runs the controller-owned retained mechanism against the changed target.",
            "start_adaptive_search": "Requires a fresh delegation and execution approval.",
            "run_legitimate_use": "Uses the trusted-client check without engine or model authorship.",
            "open_comparison": "Reviews actual attempts, controller checks, unknowns, and cleanup together.",
        }[kind]
    else:
        reason = (
            "The current target is unknown and must be reconciled first."
            if current_target is None
            else "Exact prerequisite run evidence is unavailable. Review the saved run before continuing."
        )
    return [
        {
            "kind": kind,
            "label": label,
            "enabled": enabled,
            "reason": reason,
            "primary": True,
        }
    ]


def _independent_summary(assessment: str) -> str:
    return {
        "unauthorized_disclosure": "Independent observation confirmed protected data exposure.",
        "authorization_denied": "Independent observation confirmed the operation was denied.",
        "legitimate_use_succeeded": "Independent observation confirmed legitimate use succeeded.",
        "no_protected_effect": "Independent observation found no protected effect.",
        "unknown": "Independent observation could not establish the outcome.",
    }[assessment]


def _safe_producer(value: str) -> str:
    try:
        return _public_text(value, "evidence producer", maximum=200)
    except EngineExperimentWorkspaceError:
        return "controller-attested source"


def _safe_session_id(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return _public_text(value, "upstream session identity", maximum=160)
    except EngineExperimentWorkspaceError:
        return None


def _selected_attempt(
    experiment: EngineExperiment,
    projection: Mapping[str, Any],
    attempt_id: str,
) -> dict[str, Any]:
    entry = next(
        item for item in experiment.attempts if item.record.binding.attempt_id == attempt_id
    )
    record = entry.record
    binding = record.binding
    observations: list[dict[str, Any]] = []
    for engine_item in entry.evidence:
        if engine_item.category is EvidenceCategory.ENGINE_ASSERTION:
            summary = (
                "Engine-reported assertion retained for review. "
                "It does not establish an independent outcome."
            )
            provenance = "engine_reported"
        else:
            summary = (
                "Runner-reported tool result retained for review. "
                "It does not establish an independent outcome."
            )
            provenance = "runner_reported"
        observations.append(
            {
                "evidence_id": engine_item.evidence_id,
                "attempt_id": attempt_id,
                "category": engine_item.category.value,
                "provenance": provenance,
                "summary": summary,
                "producer": _safe_producer(engine_item.producer),
                "timestamp": engine_item.observed_at,
                "limitations": ["Raw engine content is omitted from the workspace response."],
            }
        )

    verified_ids = {
        item["evidence_id"]
        for item in cast(list[Mapping[str, Any]], projection["observations"])
        if item["attempt_id"] == attempt_id
    }
    for observation in experiment.independent_observations:
        if observation.attempt_id != attempt_id or observation.evidence_id not in verified_ids:
            continue
        assessment = observation.assessment
        observations.append(
            {
                "evidence_id": observation.evidence_id,
                "attempt_id": attempt_id,
                "category": "independent_security_outcome",
                "provenance": (
                    "control_blocked" if assessment == "authorization_denied" else "observed"
                ),
                "summary": _independent_summary(assessment),
                "producer": _safe_producer(observation.evidence.producer),
                "timestamp": observation.evidence.timestamp,
                "limitations": [],
            }
        )

    duration_ms = 0
    if record.started_at is not None and record.ended_at is not None:
        duration = parse_iso8601_datetime(record.ended_at) - parse_iso8601_datetime(
            record.started_at
        )
        duration_ms = max(0, round(duration.total_seconds() * 1000))
    if duration_ms > binding.wall_clock_seconds * 1000:
        raise EngineExperimentWorkspaceError(
            "selected attempt exceeds its recorded wall clock limit"
        )
    exit_reason = None
    if record.state.value in {"failed", "partial", "cancelled", "budget_exhausted", "unknown"}:
        exit_reason = "The attempt did not complete with full evidence. Inspect its saved run."
    return {
        "attempt_id": attempt_id,
        "role": binding.role.value,
        "job_id": entry.job_id,
        "run_id": binding.run_id,
        "upstream_session_id": _safe_session_id(record.upstream_session_id),
        "state": record.state.value,
        "completeness": record.completeness.value,
        "exit_reason": exit_reason,
        "started_at": record.started_at,
        "finished_at": record.ended_at,
        "usage": {
            "duration_ms": duration_ms,
            "model_requests": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "tool_calls": 0,
            "cost_microusd": None,
        },
        "findings": [],
        "observations": observations,
        "artifacts": [],
        "cleanup": {
            "state": entry.cleanup_state.value,
            "receipt_ref": entry.cleanup_evidence_ref,
            "finished_at": entry.settled_at,
            "limitations": [],
        },
        "resume_supported": False,
    }


def _selected_check(
    experiment: EngineExperiment,
    projection: Mapping[str, Any],
    check_id: str,
) -> dict[str, Any]:
    check = next(item for item in experiment.checks if item.check_id == check_id)
    verified_ids = {
        item["evidence_id"]
        for item in cast(list[Mapping[str, Any]], projection["observations"])
        if item["check_id"] == check_id
    }
    admitted = set(check.independent_evidence_refs)
    observations: list[dict[str, Any]] = []
    for item in experiment.independent_observations:
        if (
            item.check_id != check_id
            or item.evidence_id not in admitted
            or item.evidence_id not in verified_ids
        ):
            continue
        assessment = item.assessment
        observations.append(
            {
                "evidence_id": item.evidence_id,
                "check_id": check_id,
                "category": (
                    "legitimate_use"
                    if check.role is ControllerCheckRole.LEGITIMATE_USE
                    else "independent_security_outcome"
                ),
                "provenance": (
                    "control_blocked" if assessment == "authorization_denied" else "observed"
                ),
                "summary": _independent_summary(assessment),
                "producer": _safe_producer(item.evidence.producer),
                "timestamp": item.evidence.timestamp,
                "limitations": [],
            }
        )
    return {
        "check_id": check.check_id,
        "role": check.role.value,
        "job_id": check.job_id,
        "run_id": check.run_id,
        "performer": check.performer.value,
        "mechanism_ref": check.mechanism_ref,
        "target_snapshot_ref": check.target_snapshot_ref,
        "input_digest": check.input_digest,
        "result_digest": check.result_digest,
        "state": check.state.value,
        "independent_evidence_refs": list(check.independent_evidence_refs),
        "created_at": check.created_at,
        "settled_at": check.settled_at,
        "observations": observations,
        "cleanup": {
            "state": check.cleanup_state.value,
            "receipt_ref": check.cleanup_evidence_ref,
            "finished_at": check.settled_at,
            "limitations": [],
        },
    }


def _selected_context(
    experiment: EngineExperiment,
    projection: Mapping[str, Any],
    selection: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    if selection is None:
        return None
    selected_id = cast(str, selection["id"])
    if selection["kind"] == "engine_attempt":
        return {
            "kind": "engine_attempt",
            "attempt": _selected_attempt(experiment, projection, selected_id),
        }
    return {
        "kind": "controller_check",
        "check": _selected_check(experiment, projection, selected_id),
    }


def _workspace_limitations(
    supplied: list[str],
    presentation: Mapping[str, Any],
    experiment: EngineExperiment,
) -> list[str]:
    rows = list(supplied)
    if cast(Mapping[str, Any], presentation["engine_setup"])["model"]["test_provider"]:
        rows.append("Labeled test-provider responses do not establish live-model decision quality.")
    if experiment.attempts:
        rows.append("Engine-reported evidence is separated from independent observations.")
    if (
        presentation["selection"] is not None
        and presentation["selection"]["kind"] == "engine_attempt"
    ):
        rows.append(
            "Model-token, request, and tool-call counters are not retained in canonical experiment state."
        )
        selected_id = cast(Mapping[str, Any], presentation["selection"])["id"]
        selected_entry = next(
            entry for entry in experiment.attempts if entry.record.binding.attempt_id == selected_id
        )
        if (
            selected_entry.record.upstream_session_id is not None
            and _safe_session_id(selected_entry.record.upstream_session_id) is None
        ):
            rows.append("The private upstream session identity was withheld from this response.")
    if any(entry.artifact_manifest_ref is not None for entry in experiment.attempts):
        rows.append("Raw artifact bodies remain in protected storage and are not included here.")
    unique: list[str] = []
    for row in rows:
        checked = _public_text(row, "workspace limitation", maximum=500)
        if checked not in unique:
            unique.append(checked)
    if len(unique) > 32:
        raise EngineExperimentWorkspaceError("workspace limitations exceed their bound")
    return unique


def project_engine_experiment_workspace(
    value: EngineExperiment,
    run_source: EngineRunSource,
    presentation: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the exact frontend workspace from canonical controller-owned state."""

    if not isinstance(value, EngineExperiment):
        raise EngineExperimentWorkspaceError(
            "engine workspace requires controller-rehydrated experiment state"
        )
    experiment = value
    try:
        experiment.validate()
        projection = _check_projection_shape(
            project_engine_experiment(experiment, run_source), experiment
        )
    except EngineExperimentError as exc:
        raise EngineExperimentWorkspaceError("engine workspace projection failed") from exc
    checked = _checked_presentation(presentation, experiment)
    projection_target = cast(Mapping[str, Any], projection["conclusion"])["defense"]
    projection_target_ref = cast(Mapping[str, Any], projection_target)[
        "current_target_snapshot_ref"
    ]
    checked_target = cast(dict[str, Any] | None, checked["current_target"])
    visible_target_ref = None if checked_target is None else checked_target["snapshot_ref"]
    if projection_target_ref != visible_target_ref:
        raise EngineExperimentWorkspaceError("current target projection changed")

    selection = cast(Mapping[str, Any] | None, checked["selection"])
    payload = {
        "schema_version": "bluefire.engine-experiment-workspace.v1",
        "experiment_id": experiment.experiment_id,
        "revision": experiment.revision,
        "experiment_digest": experiment.digest,
        "objective": checked["objective"],
        "environment": checked["environment"],
        "current_target": checked_target,
        "engine_setup": checked["engine_setup"],
        "authorization": checked["authorization"],
        "defensive_change": checked["defensive_change"],
        "projection": projection,
        "actions": _actions(projection, checked_target),
        "selected_context": _selected_context(experiment, projection, selection),
        "limitations": _workspace_limitations(
            cast(list[str], checked["limitations"]), checked, experiment
        ),
    }
    result = {
        "schema_version": payload["schema_version"],
        "workspace_digest": content_hash(payload),
        **{key: item for key, item in payload.items() if key != "schema_version"},
    }
    return dict(cast(dict[str, Any], json_clone(result)))


def present_engine_experiment_workspace(
    experiment: EngineExperiment,
    run_source: EngineRunSource,
    presentation_source: EngineExperimentPresentationSource,
    *,
    selected_attempt_id: str | None = None,
    selected_check_id: str | None = None,
) -> dict[str, Any]:
    """Return a public workspace with one exact canonical selection, or none.

    Display metadata remains controller-supplied, but it cannot select work.
    The presenter resolves the requested identity to its canonical role, job,
    and run so service and route layers cannot create a partial or mismatched
    selected context.
    """

    if not isinstance(experiment, EngineExperiment):
        raise EngineExperimentWorkspaceError(
            "engine workspace requires controller-rehydrated experiment state"
        )
    try:
        experiment.validate()
    except EngineExperimentError as exc:
        raise EngineExperimentWorkspaceError(
            "engine workspace experiment state is invalid"
        ) from exc
    if selected_attempt_id is not None and selected_check_id is not None:
        raise EngineExperimentWorkspaceError(
            "select either an engine attempt or controller check, not both"
        )
    if selected_attempt_id is not None and (
        not isinstance(selected_attempt_id, str)
        or _ATTEMPT_ID.fullmatch(selected_attempt_id) is None
    ):
        raise EngineExperimentWorkspaceError("selected engine attempt identity is invalid")
    if selected_check_id is not None and (
        not isinstance(selected_check_id, str) or _CHECK_ID.fullmatch(selected_check_id) is None
    ):
        raise EngineExperimentWorkspaceError("selected controller check identity is invalid")

    supplied = presentation_source.get_engine_experiment_presentation(
        experiment.experiment_id,
        revision=experiment.revision,
        experiment_digest=experiment.digest,
    )
    try:
        clone = json_clone(supplied)
    except (TypeError, ValueError) as exc:
        raise EngineExperimentWorkspaceError("engine workspace presentation is invalid") from exc
    if not isinstance(clone, dict):
        raise EngineExperimentWorkspaceError("engine workspace presentation is invalid")
    presentation = cast(dict[str, Any], clone)
    source_row = _exact(presentation, _PRESENTATION_FIELDS, "engine workspace presentation")
    if source_row["selection"] is not None:
        raise EngineExperimentWorkspaceError(
            "trusted presentation source cannot choose a workspace context"
        )

    selection: dict[str, Any] | None = None
    if selected_attempt_id is not None:
        attempt_matches = [
            entry
            for entry in experiment.attempts
            if entry.record.binding.attempt_id == selected_attempt_id
        ]
        if len(attempt_matches) != 1:
            raise EngineExperimentSelectionNotFound("selected engine attempt is unavailable")
        entry = attempt_matches[0]
        binding = entry.record.binding
        selection = {
            "kind": "engine_attempt",
            "id": binding.attempt_id,
            "role": binding.role.value,
            "job_id": entry.job_id,
            "run_id": binding.run_id,
        }
    elif selected_check_id is not None:
        check_matches = [
            check for check in experiment.checks if check.check_id == selected_check_id
        ]
        if len(check_matches) != 1:
            raise EngineExperimentSelectionNotFound("selected controller check is unavailable")
        check = check_matches[0]
        selection = {
            "kind": "controller_check",
            "id": check.check_id,
            "role": check.role.value,
            "job_id": check.job_id,
            "run_id": check.run_id,
        }
    presentation["selection"] = selection
    workspace = project_engine_experiment_workspace(experiment, run_source, presentation)
    return checked_engine_experiment_workspace(
        workspace,
        experiment,
        run_source,
        presentation,
    )


def checked_engine_experiment_workspace(
    value: Mapping[str, Any],
    experiment: EngineExperiment,
    run_source: EngineRunSource,
    presentation: Mapping[str, Any],
) -> dict[str, Any]:
    """Recompute and validate a previously returned workspace byte-for-byte."""

    row = _exact(value, _WORKSPACE_FIELDS, "engine experiment workspace")
    claimed_digest = _digest(row["workspace_digest"], "workspace digest")
    body = dict(cast(dict[str, Any], json_clone(row)))
    body.pop("workspace_digest")
    if claimed_digest != content_hash(body):
        raise EngineExperimentWorkspaceError("engine workspace digest changed")
    expected = project_engine_experiment_workspace(experiment, run_source, presentation)
    if dict(cast(dict[str, Any], json_clone(row))) != expected:
        raise EngineExperimentWorkspaceError("engine workspace changed")
    return expected
