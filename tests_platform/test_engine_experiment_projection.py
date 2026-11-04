from __future__ import annotations

from dataclasses import replace
from typing import Any, Mapping

import pytest

from bluefire.engine_experiment import (
    EngineExperiment,
    EngineExperimentError,
    _controller_observation_record,
)
from bluefire.engine_experiment_projection import project_engine_experiment
from tests_platform.test_engine_experiment import (
    AFTER_SNAPSHOT,
    BASELINE_ATTEMPT,
    BASELINE_RUN,
    LEGITIMATE_CHECK,
    LEGITIMATE_RUN,
    MECHANISM_REF,
    _defense,
    _digest,
    _new_experiment,
    _reserve_baseline,
    _settle_latest_attempt,
    _tenant_observation,
    build_completed_experiment,
)


class _RunSource:
    def __init__(self, documents: Mapping[str, Mapping[str, Any]]) -> None:
        self.documents = documents

    def get_run(self, run_id: str, *, require_finalized: bool = False) -> Mapping[str, Any]:
        document = self.documents[run_id]
        if require_finalized and "manifest" not in document:
            raise ValueError("run is not finalized")
        return document


def _run_source(
    experiment: Any | None = None,
    *,
    omit_evidence_run: str | None = None,
    omit_evidence_ids: frozenset[str] = frozenset(),
) -> _RunSource:
    experiment = build_completed_experiment() if experiment is None else experiment
    documents: dict[str, Mapping[str, Any]] = {}
    run_ids = [entry.record.binding.run_id for entry in experiment.attempts] + [
        check.run_id for check in experiment.checks
    ]
    for run_id in run_ids:
        evidence = [
            observation.evidence.to_dict()
            for observation in experiment.independent_observations
            if observation.evidence.run_id == run_id
            and run_id != omit_evidence_run
            and observation.evidence_id not in omit_evidence_ids
        ]
        # Deliberately contradictory engine-style summary fields must never
        # drive the evidence-derived comparison.
        documents[run_id] = {
            "run_id": run_id,
            "status": "completed",
            "engine_summary": {
                "security_outcome": "engine_claimed_success",
                "all_paths_exhausted": False,
            },
            "evidence": {"schema_version": "1.0", "records": evidence},
            "manifest": {"run_id": run_id, "bundle_hash": "ignored-by-protocol-fake"},
        }
    return _RunSource(documents)


def test_projection_recomputes_complete_defensive_outcome_from_exact_runs() -> None:
    experiment = build_completed_experiment()
    projection = project_engine_experiment(experiment, _run_source())

    conclusion = projection["conclusion"]
    assert conclusion["headline"] == ("original_blocked_no_remaining_path_observed_within_limits")
    assert conclusion["original_mechanism"]["status"] == "established"
    assert conclusion["retained_reproducer"]["status"] == "blocked"
    assert conclusion["adaptive_search"]["status"] == ("no_path_observed_within_limits")
    assert conclusion["adaptive_search"]["limit_qualified"] is True
    assert conclusion["legitimate_use"]["status"] == "passed"
    assert conclusion["telemetry_health"]["status"] == "complete"
    assert conclusion["cleanup"]["status"] == "verified_absent"
    assert conclusion["defense"]["state"] == "retained"
    assert conclusion["unknowns"] == []
    assert projection["workflow_state"] == "complete"
    assert len(projection["attempts"]) == 2
    assert len(projection["checks"]) == 2
    assert [row["execution_approval_id"] for row in projection["attempts"]] == [
        "approval-" + "a" * 32,
        "approval-" + "b" * 32,
    ]


def test_projection_never_uses_engine_summary_when_exact_observation_is_missing() -> None:
    experiment = build_completed_experiment()
    adaptive_run = experiment.attempts[1].record.binding.run_id
    projection = project_engine_experiment(
        experiment,
        _run_source(omit_evidence_run=adaptive_run),
    )

    assert projection["conclusion"]["adaptive_search"]["status"] == "inconclusive"
    assert projection["conclusion"]["headline"] == ("original_blocked_adaptive_result_unknown")
    assert projection["conclusion"]["telemetry_health"]["status"] == "partial"
    assert any(
        row["run_id"] == adaptive_run and row["state"] == "unavailable"
        for row in projection["run_integrity"]
    )
    assert (
        "One or more exact run bundles could not be verified."
        in projection["conclusion"]["unknowns"]
    )


@pytest.mark.parametrize(
    "evidence_envelope",
    [
        {"records": []},
        {"schema_version": "2.0", "records": []},
        {"schema_version": "1.0", "records": [], "unexpected": True},
    ],
)
def test_projection_rejects_noncanonical_run_evidence_envelopes(
    evidence_envelope: Mapping[str, Any],
) -> None:
    experiment = build_completed_experiment()
    source = _run_source(experiment)
    documents = dict(source.documents)
    baseline = dict(documents[BASELINE_RUN])
    baseline["evidence"] = evidence_envelope
    documents[BASELINE_RUN] = baseline

    projection = project_engine_experiment(experiment, _RunSource(documents))

    assert projection["conclusion"]["original_mechanism"]["status"] == "unknown"
    assert any(
        row["run_id"] == BASELINE_RUN and row["state"] == "unavailable"
        for row in projection["run_integrity"]
    )


def test_projection_digest_binds_exact_experiment_and_run_projection() -> None:
    experiment = build_completed_experiment()
    source = _run_source()
    first = project_engine_experiment(experiment, source)
    reopened = project_engine_experiment(
        EngineExperiment._from_controller_mapping(experiment.to_dict()), source
    )

    assert reopened == first
    assert first["projection_digest"].startswith("sha256:")
    assert first["experiment_digest"] == experiment.digest

    with pytest.raises(EngineExperimentError, match="controller-rehydrated"):
        project_engine_experiment(experiment.to_dict(), source)  # type: ignore[arg-type]


def test_run_verification_is_atomic_when_a_later_observation_is_missing() -> None:
    experiment = build_completed_experiment()
    later = _controller_observation_record(
        target_snapshot_ref=experiment.initial_target_snapshot_ref,
        mechanism_ref=MECHANISM_REF,
        attempt_id=BASELINE_ATTEMPT,
        evidence=_tenant_observation(
            owner_id=BASELINE_ATTEMPT,
            run_id=BASELINE_RUN,
            timestamp="2026-11-04T12:03:30Z",
            hardened=False,
        ),
    )
    experiment = experiment.record_independent_observation(later, timestamp="2026-11-04T12:20:00Z")

    projection = project_engine_experiment(
        experiment,
        _run_source(experiment, omit_evidence_ids=frozenset({later.evidence_id})),
    )

    assert projection["conclusion"]["original_mechanism"]["status"] == "unknown"
    assert all(row["run_id"] != BASELINE_RUN for row in projection["observations"])


def test_controller_conclusion_uses_only_frozen_settlement_evidence() -> None:
    experiment = build_completed_experiment()
    late_denial = _controller_observation_record(
        target_snapshot_ref=AFTER_SNAPSHOT,
        mechanism_ref=MECHANISM_REF,
        check_id=LEGITIMATE_CHECK,
        check_input_digest=experiment.checks[-1].input_digest,
        evidence=_tenant_observation(
            owner_id=LEGITIMATE_CHECK,
            run_id=LEGITIMATE_RUN,
            timestamp="2026-11-04T12:17:30Z",
            hardened=True,
        ),
    )
    experiment = experiment.record_independent_observation(
        late_denial, timestamp="2026-11-04T12:20:00Z"
    )

    projection = project_engine_experiment(experiment, _run_source(experiment))

    assert projection["conclusion"]["legitimate_use"]["status"] == "passed"
    assert late_denial.evidence_id not in projection["conclusion"]["legitimate_use"]["support_refs"]


def test_conflicting_frozen_legitimate_use_evidence_never_passes() -> None:
    experiment = build_completed_experiment()
    denial = _controller_observation_record(
        target_snapshot_ref=AFTER_SNAPSHOT,
        mechanism_ref=MECHANISM_REF,
        check_id=LEGITIMATE_CHECK,
        check_input_digest=experiment.checks[-1].input_digest,
        evidence=_tenant_observation(
            owner_id=LEGITIMATE_CHECK,
            run_id=LEGITIMATE_RUN,
            timestamp="2026-11-04T12:17:30Z",
            hardened=True,
        ),
    )
    experiment = experiment.record_independent_observation(denial, timestamp="2026-11-04T12:20:00Z")
    legitimate = experiment.checks[-1]
    legitimate = replace(
        legitimate,
        independent_evidence_refs=(*legitimate.independent_evidence_refs, denial.evidence_id),
    )
    experiment = replace(experiment, checks=(*experiment.checks[:-1], legitimate))

    projection = project_engine_experiment(experiment, _run_source(experiment))

    assert projection["conclusion"]["legitimate_use"]["status"] == "failed"
    assert projection["conclusion"]["headline"] == ("original_blocked_legitimate_use_failed")


def test_unreviewed_defense_preserves_the_strict_projection_shape() -> None:
    projection = project_engine_experiment(_new_experiment(), _RunSource({}))

    defense = projection["conclusion"]["defense"]
    assert defense["state"] == "not_reviewed"
    assert defense["application_receipt_ref"] is None
    assert defense["reconciliation_receipt_ref"] is None
    assert defense["rollback_operation_ref"] is None
    assert defense["rollback_receipt_ref"] is None


def test_early_rollback_is_terminal_and_marks_retest_evidence_historical() -> None:
    experiment = _settle_latest_attempt(
        _reserve_baseline(_new_experiment()),
        started_at="2026-11-04T12:02:00Z",
        ended_at="2026-11-04T12:04:00Z",
    )
    observation = _controller_observation_record(
        target_snapshot_ref=experiment.initial_target_snapshot_ref,
        mechanism_ref=MECHANISM_REF,
        attempt_id=BASELINE_ATTEMPT,
        evidence=_tenant_observation(
            owner_id=BASELINE_ATTEMPT,
            run_id=BASELINE_RUN,
            timestamp="2026-11-04T12:03:00Z",
            hardened=False,
        ),
    )
    change = _defense()
    experiment = experiment.record_independent_observation(
        observation, timestamp="2026-11-04T12:05:00Z"
    ).review_defense(change, timestamp="2026-11-04T12:06:00Z")
    experiment = experiment.begin_defense_application(
        change.change_id,
        operation_receipt_digest=_digest("1"),
        started_at="2026-11-04T12:06:30Z",
    ).apply_defense(
        change.change_id,
        applied_configuration_digest=_digest("f"),
        reconciliation_receipt_digest=_digest("2"),
        observed_target_snapshot_ref=AFTER_SNAPSHOT,
        reconciled_at="2026-11-04T12:07:00Z",
    )
    experiment = experiment.begin_defense_rollback(
        change.change_id,
        rollback_operation_digest=_digest("3"),
        rollback_started_at="2026-11-04T12:07:30Z",
    ).rollback_defense(
        change.change_id,
        rollback_receipt_digest=_digest("4"),
        observed_target_snapshot_ref=experiment.initial_target_snapshot_ref,
        rolled_back_at="2026-11-04T12:08:00Z",
    )

    projection = project_engine_experiment(experiment, _run_source(experiment))

    assert projection["workflow_state"] == "complete"
    assert (
        "The defensive change was rolled back; verified retest evidence is historical."
        in projection["conclusion"]["unknowns"]
    )
    defense = projection["conclusion"]["defense"]
    assert defense["reconciliation_receipt_ref"] == _digest("2")
    assert defense["rollback_operation_ref"] == _digest("3")
    assert defense["rollback_receipt_ref"] == _digest("4")


def test_run_store_failure_uses_a_stable_non_sensitive_detail() -> None:
    class _UnavailableRunSource:
        def get_run(self, run_id: str, *, require_finalized: bool = False) -> Mapping[str, Any]:
            del run_id, require_finalized
            raise OSError(r"C:\\private\\operator\\run.json is unavailable")

    projection = project_engine_experiment(build_completed_experiment(), _UnavailableRunSource())

    assert all(
        row["detail"] == "Exact run bundle or observation verification failed."
        for row in projection["run_integrity"]
    )
    assert "private" not in str(projection)
