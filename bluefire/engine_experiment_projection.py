"""Evidence-derived projection for external-engine defense experiments.

The projection never accepts an engine summary as a security conclusion.  It
reopens exact RunStore bundles, verifies each independently observed record is
present byte-for-byte in its bound run, and derives the operator view from
those records plus the saved workflow lifecycle.
"""

from __future__ import annotations

from typing import Any, Mapping, Protocol

from .engine_attempt_contract import AttemptCompleteness, AttemptRole, AttemptState
from .engine_experiment import (
    CleanupState,
    ControllerCheckRole,
    ControllerCheckState,
    DefenseState,
    EngineExperiment,
    EngineExperimentError,
    IndependentObservationRecord,
)
from .evidence import EvidenceRecord
from .util import content_hash, json_clone


class EngineRunSource(Protocol):
    """Narrow read-only surface implemented by the existing RunStore."""

    def get_run(self, run_id: str, *, require_finalized: bool = False) -> Mapping[str, Any]: ...


def verify_finalized_independent_observation(
    observation: IndependentObservationRecord,
    run_source: EngineRunSource,
) -> None:
    """Require one exact observation in its immutable finalized run bundle."""

    if not isinstance(observation, IndependentObservationRecord):
        raise EngineExperimentError("independent observation is not controller-attested")
    observation.validate()
    run_id = observation.evidence.run_id
    run = run_source.get_run(run_id, require_finalized=True)
    if run.get("run_id") != run_id:
        raise EngineExperimentError("run identity changed")
    envelope = run.get("evidence")
    if (
        not isinstance(envelope, Mapping)
        or set(envelope) != {"schema_version", "records"}
        or envelope.get("schema_version") != "1.0"
    ):
        raise EngineExperimentError("run evidence envelope schema is unavailable")
    rows = envelope.get("records")
    if not isinstance(rows, list):
        raise EngineExperimentError("run evidence envelope is unavailable")
    matched = False
    identities: set[str] = set()
    for row in rows:
        if not isinstance(row, Mapping):
            raise EngineExperimentError("run evidence row is invalid")
        try:
            record = EvidenceRecord.from_mapping(row)
        except (TypeError, ValueError) as exc:
            raise EngineExperimentError("run evidence row is invalid") from exc
        if record.evidence_id in identities:
            raise EngineExperimentError("run repeats an evidence identity")
        identities.add(record.evidence_id)
        if record.evidence_id == observation.evidence_id:
            if record.to_dict() != observation.evidence.to_dict():
                raise EngineExperimentError("saved observation differs from its exact run record")
            matched = True
    if not matched:
        raise EngineExperimentError("saved observation is absent from its finalized run")


_TERMINAL_ATTEMPT_STATES = frozenset(
    {
        AttemptState.COMPLETED,
        AttemptState.PARTIAL,
        AttemptState.FAILED,
        AttemptState.CANCELLED,
        AttemptState.BUDGET_EXHAUSTED,
        AttemptState.UNKNOWN,
    }
)
_TERMINAL_CHECK_STATES = frozenset(
    {
        ControllerCheckState.COMPLETED,
        ControllerCheckState.FAILED,
        ControllerCheckState.UNKNOWN,
    }
)


def project_engine_experiment(
    value: EngineExperiment, run_source: EngineRunSource
) -> dict[str, Any]:
    """Project canonical state already rehydrated by the trusted repository."""

    if not isinstance(value, EngineExperiment):
        raise EngineExperimentError(
            "engine projection requires controller-rehydrated experiment state"
        )
    experiment = value
    experiment.validate()
    run_integrity, verified_observations = _verified_runs(experiment, run_source)
    by_attempt: dict[str, list[IndependentObservationRecord]] = {}
    by_check: dict[str, list[IndependentObservationRecord]] = {}
    for observation in verified_observations:
        if observation.attempt_id is not None:
            by_attempt.setdefault(observation.attempt_id, []).append(observation)
        elif observation.check_id is not None:
            by_check.setdefault(observation.check_id, []).append(observation)

    baseline = next(
        (
            entry
            for entry in experiment.attempts
            if entry.record.binding.role is AttemptRole.BASELINE
        ),
        None,
    )
    adaptive = next(
        (
            entry
            for entry in experiment.attempts
            if entry.record.binding.role is AttemptRole.ADAPTIVE_SEARCH
        ),
        None,
    )
    reproducer = next(
        (
            check
            for check in experiment.checks
            if check.role is ControllerCheckRole.RETAINED_REPRODUCER
        ),
        None,
    )
    legitimate = next(
        (check for check in experiment.checks if check.role is ControllerCheckRole.LEGITIMATE_USE),
        None,
    )

    baseline_observations = (
        [] if baseline is None else by_attempt.get(baseline.record.binding.attempt_id, [])
    )
    adaptive_observations = (
        [] if adaptive is None else by_attempt.get(adaptive.record.binding.attempt_id, [])
    )
    reproducer_observations = _bound_check_observations(reproducer, by_check)
    legitimate_observations = _bound_check_observations(legitimate, by_check)

    original = _original_mechanism(baseline, baseline_observations)
    reproduced = _reproducer(reproducer, reproducer_observations)
    adaptive_result = _adaptive(adaptive, adaptive_observations)
    legitimate_result = _legitimate(legitimate, legitimate_observations)
    telemetry = _telemetry_health(
        baseline,
        baseline_observations,
        reproducer,
        reproducer_observations,
        adaptive,
        adaptive_observations,
        legitimate,
        legitimate_observations,
    )
    cleanup = _cleanup(experiment)
    unknowns = _unknowns(
        original=original,
        reproduced=reproduced,
        adaptive=adaptive_result,
        legitimate=legitimate_result,
        telemetry=telemetry,
        cleanup=cleanup,
        run_integrity=run_integrity,
        experiment=experiment,
    )
    headline = _headline(
        original=original,
        reproduced=reproduced,
        adaptive=adaptive_result,
        legitimate=legitimate_result,
    )
    body: dict[str, Any] = {
        "schema_version": "bluefire.engine-experiment-projection.v1",
        "experiment_id": experiment.experiment_id,
        "revision": experiment.revision,
        "experiment_digest": experiment.digest,
        "workflow_state": _workflow_state(experiment),
        "conclusion": {
            "headline": headline,
            "original_mechanism": original,
            "retained_reproducer": reproduced,
            "adaptive_search": adaptive_result,
            "legitimate_use": legitimate_result,
            "telemetry_health": telemetry,
            "cleanup": cleanup,
            "defense": _defense(experiment),
            "unknowns": unknowns,
        },
        "attempts": [_attempt_row(entry) for entry in experiment.attempts],
        "checks": [_check_row(check) for check in experiment.checks],
        "observations": [
            {
                "evidence_id": observation.evidence_id,
                "run_id": observation.evidence.run_id,
                "attempt_id": observation.attempt_id,
                "check_id": observation.check_id,
                "mechanism_ref": observation.mechanism_ref,
                "target_snapshot_ref": observation.target_snapshot_ref,
                "assessment": observation.assessment,
                "record_hash": observation.evidence.record_hash,
            }
            for observation in verified_observations
        ],
        "run_integrity": run_integrity,
    }
    body["projection_digest"] = content_hash(body)
    return dict(json_clone(body))


def _verified_runs(
    experiment: EngineExperiment, run_source: EngineRunSource
) -> tuple[list[dict[str, Any]], list[IndependentObservationRecord]]:
    terminal_by_run: dict[str, bool] = {
        entry.record.binding.run_id: entry.record.state in _TERMINAL_ATTEMPT_STATES
        for entry in experiment.attempts
    }
    terminal_by_run.update(
        {check.run_id: check.state in _TERMINAL_CHECK_STATES for check in experiment.checks}
    )
    observations_by_run: dict[str, list[IndependentObservationRecord]] = {}
    for observation in experiment.independent_observations:
        observations_by_run.setdefault(observation.evidence.run_id, []).append(observation)
    integrity: list[dict[str, Any]] = []
    verified: list[IndependentObservationRecord] = []
    for run_id, terminal in terminal_by_run.items():
        state = "verified"
        detail = "Finalized run and exact independent observations verified."
        try:
            run = run_source.get_run(run_id, require_finalized=terminal)
            if run.get("run_id") != run_id:
                raise EngineExperimentError("run identity changed")
            evidence_envelope = run.get("evidence")
            if (
                not isinstance(evidence_envelope, Mapping)
                or set(evidence_envelope) != {"schema_version", "records"}
                or evidence_envelope.get("schema_version") != "1.0"
            ):
                raise EngineExperimentError("run evidence envelope schema is unavailable")
            rows = evidence_envelope.get("records")
            if not isinstance(rows, list):
                raise EngineExperimentError("run evidence envelope is unavailable")
            records: dict[str, EvidenceRecord] = {}
            for row in rows:
                if not isinstance(row, Mapping):
                    raise EngineExperimentError("run evidence row is invalid")
                record = EvidenceRecord.from_mapping(row)
                if record.evidence_id in records:
                    raise EngineExperimentError("run repeats an evidence identity")
                records[record.evidence_id] = record
            run_observations: list[IndependentObservationRecord] = []
            for observation in observations_by_run.get(run_id, []):
                stored = records.get(observation.evidence_id)
                if stored is None or stored.to_dict() != observation.evidence.to_dict():
                    raise EngineExperimentError(
                        "saved observation differs from its exact run record"
                    )
                run_observations.append(observation)
            verified.extend(run_observations)
        except (KeyError, OSError, TypeError, ValueError):
            state = "unavailable"
            detail = "Exact run bundle or observation verification failed."
        integrity.append(
            {
                "run_id": run_id,
                "terminal": terminal,
                "state": state,
                "detail": detail,
            }
        )
    return integrity, verified


def _support(observations: list[IndependentObservationRecord]) -> list[str]:
    return [observation.evidence_id for observation in observations]


def _bound_check_observations(
    check: Any,
    by_check: Mapping[str, list[IndependentObservationRecord]],
) -> list[IndependentObservationRecord]:
    """Return only the observations frozen into the controller settlement."""

    if check is None:
        return []
    admitted = set(check.independent_evidence_refs)
    return [
        observation
        for observation in by_check.get(check.check_id, [])
        if observation.evidence_id in admitted
    ]


def _original_mechanism(
    entry: Any, observations: list[IndependentObservationRecord]
) -> dict[str, Any]:
    if entry is None:
        return {"status": "not_attempted", "run_id": None, "support_refs": []}
    assessments = {observation.assessment for observation in observations}
    status = (
        "established"
        if "unauthorized_disclosure" in assessments
        else "not_established" if observations else "unknown"
    )
    return {
        "status": status,
        "run_id": entry.record.binding.run_id,
        "support_refs": _support(observations),
    }


def _reproducer(check: Any, observations: list[IndependentObservationRecord]) -> dict[str, Any]:
    if check is None:
        return {"status": "not_attempted", "run_id": None, "support_refs": []}
    assessments = {observation.assessment for observation in observations}
    status = (
        "still_succeeds"
        if "unauthorized_disclosure" in assessments
        else (
            "blocked"
            if "authorization_denied" in assessments
            else "not_established" if observations else "unknown"
        )
    )
    return {"status": status, "run_id": check.run_id, "support_refs": _support(observations)}


def _adaptive(entry: Any, observations: list[IndependentObservationRecord]) -> dict[str, Any]:
    if entry is None:
        return {
            "status": "not_attempted",
            "run_id": None,
            "support_refs": [],
            "limit_qualified": False,
        }
    assessments = {observation.assessment for observation in observations}
    if "unauthorized_disclosure" in assessments:
        status = "remaining_path_found"
    elif (
        assessments
        and assessments <= {"authorization_denied", "no_protected_effect"}
        and entry.record.state is AttemptState.COMPLETED
        and entry.record.completeness is AttemptCompleteness.COMPLETE
    ):
        status = "no_path_observed_within_limits"
    elif entry.record.state in _TERMINAL_ATTEMPT_STATES:
        status = "inconclusive"
    else:
        status = "pending"
    return {
        "status": status,
        "run_id": entry.record.binding.run_id,
        "support_refs": _support(observations),
        "limit_qualified": status == "no_path_observed_within_limits",
    }


def _legitimate(check: Any, observations: list[IndependentObservationRecord]) -> dict[str, Any]:
    if check is None:
        return {"status": "not_attempted", "run_id": None, "support_refs": []}
    assessments = {observation.assessment for observation in observations}
    status = (
        "failed"
        if "authorization_denied" in assessments
        else "passed" if assessments == {"legitimate_use_succeeded"} else "unknown"
    )
    return {"status": status, "run_id": check.run_id, "support_refs": _support(observations)}


def _telemetry_health(
    baseline: Any,
    baseline_observations: list[IndependentObservationRecord],
    reproducer: Any,
    reproducer_observations: list[IndependentObservationRecord],
    adaptive: Any,
    adaptive_observations: list[IndependentObservationRecord],
    legitimate: Any,
    legitimate_observations: list[IndependentObservationRecord],
) -> dict[str, Any]:
    admitted = [
        ("baseline", baseline, baseline_observations),
        ("retained_reproducer", reproducer, reproducer_observations),
        ("adaptive_search", adaptive, adaptive_observations),
        ("legitimate_use", legitimate, legitimate_observations),
    ]
    missing = [
        name for name, owner, observations in admitted if owner is not None and not observations
    ]
    verified = [
        name for name, owner, observations in admitted if owner is not None and observations
    ]
    expected = [name for name, owner, _observations in admitted if owner is not None]
    if not expected:
        status = "not_started"
    elif not missing:
        status = "complete"
    elif verified:
        status = "partial"
    else:
        status = "unavailable"
    return {
        "status": status,
        "expected_sources": expected,
        "verified_sources": verified,
        "missing_sources": missing,
    }


def _cleanup(experiment: EngineExperiment) -> dict[str, Any]:
    rows = [
        {
            "kind": "engine_attempt",
            "id": entry.record.binding.attempt_id,
            "state": entry.cleanup_state.value,
            "receipt_ref": entry.cleanup_evidence_ref,
        }
        for entry in experiment.attempts
    ] + [
        {
            "kind": "controller_check",
            "id": check.check_id,
            "state": check.cleanup_state.value,
            "receipt_ref": check.cleanup_evidence_ref,
        }
        for check in experiment.checks
    ]
    states = {row["state"] for row in rows}
    if CleanupState.RESIDUE.value in states:
        status = CleanupState.RESIDUE.value
    elif CleanupState.UNKNOWN.value in states:
        status = CleanupState.UNKNOWN.value
    elif CleanupState.PENDING.value in states:
        status = CleanupState.PENDING.value
    elif rows:
        status = CleanupState.VERIFIED_ABSENT.value
    else:
        status = "not_started"
    return {"status": status, "items": rows}


def _defense(experiment: EngineExperiment) -> dict[str, Any]:
    change = experiment.defense_change
    if change is None:
        return {
            "state": "not_reviewed",
            "change_id": None,
            "mechanism_ref": None,
            "before_target_snapshot_ref": experiment.initial_target_snapshot_ref,
            "after_target_snapshot_ref": None,
            "current_target_snapshot_ref": experiment.current_target_snapshot_ref,
            "application_receipt_ref": None,
            "reconciliation_receipt_ref": None,
            "rollback_operation_ref": None,
            "rollback_receipt_ref": None,
        }
    return {
        "state": change.state.value,
        "change_id": change.change_id,
        "mechanism_ref": change.mechanism_ref,
        "before_target_snapshot_ref": change.before_target_snapshot_ref,
        "after_target_snapshot_ref": change.after_target_snapshot_ref,
        "current_target_snapshot_ref": experiment.current_target_snapshot_ref,
        "application_receipt_ref": change.application_receipt_digest,
        "reconciliation_receipt_ref": change.reconciliation_receipt_digest,
        "rollback_operation_ref": change.rollback_operation_digest,
        "rollback_receipt_ref": change.rollback_receipt_digest,
    }


def _unknowns(
    *,
    original: Mapping[str, Any],
    reproduced: Mapping[str, Any],
    adaptive: Mapping[str, Any],
    legitimate: Mapping[str, Any],
    telemetry: Mapping[str, Any],
    cleanup: Mapping[str, Any],
    run_integrity: list[dict[str, Any]],
    experiment: EngineExperiment,
) -> list[str]:
    rows: list[str] = []
    if original["status"] in {"unknown", "not_attempted"}:
        rows.append("The original failure mechanism is not independently established.")
    if reproduced["status"] in {"unknown", "not_attempted"}:
        rows.append("The exact retained reproducer has no conclusive independent outcome.")
    if adaptive["status"] in {"inconclusive", "pending", "not_attempted"}:
        rows.append("Fresh adaptive search has not produced a conclusive bounded result.")
    if legitimate["status"] in {"unknown", "not_attempted"}:
        rows.append("Legitimate use has not been independently confirmed.")
    if telemetry["status"] not in {"complete", "not_started"}:
        rows.append("Independent telemetry is incomplete for one or more admitted stages.")
    if cleanup["status"] in {
        CleanupState.PENDING.value,
        CleanupState.UNKNOWN.value,
        CleanupState.RESIDUE.value,
    }:
        rows.append("Owned work is not yet verified absent.")
    if (
        experiment.defense_change is not None
        and experiment.defense_change.state is DefenseState.UNKNOWN
    ):
        rows.append("The current defensive configuration requires controller reconciliation.")
    if (
        experiment.defense_change is not None
        and experiment.defense_change.state is DefenseState.ROLLED_BACK
    ):
        rows.append("The defensive change was rolled back; verified retest evidence is historical.")
    if any(row["state"] != "verified" for row in run_integrity):
        rows.append("One or more exact run bundles could not be verified.")
    return rows


def _headline(
    *,
    original: Mapping[str, Any],
    reproduced: Mapping[str, Any],
    adaptive: Mapping[str, Any],
    legitimate: Mapping[str, Any],
) -> str:
    if original["status"] != "established":
        return "inconclusive_original_mechanism"
    if reproduced["status"] != "blocked":
        return (
            "original_mechanism_still_succeeds"
            if reproduced["status"] == "still_succeeds"
            else "inconclusive_retest"
        )
    if legitimate["status"] == "failed":
        return "original_blocked_legitimate_use_failed"
    if legitimate["status"] != "passed":
        return "original_blocked_legitimate_use_unknown"
    if adaptive["status"] == "remaining_path_found":
        return "original_blocked_alternate_path_found"
    if adaptive["status"] == "no_path_observed_within_limits":
        return "original_blocked_no_remaining_path_observed_within_limits"
    return "original_blocked_adaptive_result_unknown"


def _workflow_state(experiment: EngineExperiment) -> str:
    baseline = next(
        (
            entry
            for entry in experiment.attempts
            if entry.record.binding.role is AttemptRole.BASELINE
        ),
        None,
    )
    adaptive = next(
        (
            entry
            for entry in experiment.attempts
            if entry.record.binding.role is AttemptRole.ADAPTIVE_SEARCH
        ),
        None,
    )
    reproducer = next(
        (
            check
            for check in experiment.checks
            if check.role is ControllerCheckRole.RETAINED_REPRODUCER
        ),
        None,
    )
    legitimate = next(
        (check for check in experiment.checks if check.role is ControllerCheckRole.LEGITIMATE_USE),
        None,
    )
    if baseline is None:
        return "ready_for_baseline"
    if baseline.record.state not in _TERMINAL_ATTEMPT_STATES:
        return "baseline_active"
    if experiment.defense_change is None:
        return "review_defense"
    if experiment.defense_change.state is DefenseState.REVIEWED:
        return "apply_defense"
    if experiment.defense_change.state is DefenseState.UNKNOWN:
        return "reconcile_defense"
    if experiment.defense_change.state is DefenseState.ROLLED_BACK:
        return "complete"
    if reproducer is None:
        return "run_retained_reproducer"
    if reproducer.state not in _TERMINAL_CHECK_STATES:
        return "retained_reproducer_active"
    if adaptive is None:
        return "run_adaptive_search"
    if adaptive.record.state not in _TERMINAL_ATTEMPT_STATES:
        return "adaptive_search_active"
    if legitimate is None:
        return "run_legitimate_use"
    if legitimate.state not in _TERMINAL_CHECK_STATES:
        return "legitimate_use_active"
    if experiment.defense_change.state in {DefenseState.RETAINED, DefenseState.ROLLED_BACK}:
        return "complete"
    return "choose_defense_disposition"


def _attempt_row(entry: Any) -> dict[str, Any]:
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


def _check_row(check: Any) -> dict[str, Any]:
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
