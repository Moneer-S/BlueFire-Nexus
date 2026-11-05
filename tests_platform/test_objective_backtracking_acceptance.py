"""Contract-level nonlocal replanning acceptance; no model or native execution."""

from dataclasses import replace

import pytest

from bluefire.contracts import StepOutcome
from bluefire.objective_continuation import (
    ConditionBinding,
    FactState,
    ObjectiveContinuationError,
    assess_continuation,
)
from bluefire.util import content_hash
from tests_platform.objective_backtracking_fixture import (
    BacktrackingFixture,
    build_backtracking_fixture,
)


@pytest.fixture(scope="module")
def case() -> BacktrackingFixture:
    return build_backtracking_fixture()


def assess(proposal, history, current, *, now_ms: int):
    return assess_continuation(
        proposal,
        history,
        current,
        expected_history_digest=history.digest,
        expected_current_facts_digest=current.digest,
        now_ms=now_ms,
    )


def test_dead_end_refresh_and_different_actual_continuation(case: BacktrackingFixture):
    direct, diagnosis = case.history.attempts
    choice, generate, bind, blocked = direct.operations
    finding = diagnosis.operations[0].results[0]
    bundle, session = generate.results[0], bind.results[0]
    proposal = case.proposal
    imports = tuple(item.source for item in proposal.operations[0].imports)

    assert len(direct.operations) == 4
    assert blocked.outcome is StepOutcome.BLOCKED
    assert blocked.input_result_refs == (bundle.digest, session.digest)
    assert diagnosis.operations[0].input_result_refs == (blocked.results[0].digest,)
    assert proposal.frontier_attempt_id == diagnosis.attempt_id
    assert proposal.reconsideration.attempt_id == direct.attempt_id
    assert proposal.reconsideration.original_assumption == choice.assumption
    assert "alternate route" in proposal.reconsideration.revised_assumption
    assert proposal.reconsideration.learned_result_refs == (
        blocked.results[0].digest,
        finding.digest,
    )
    assert imports == (bundle, finding, session)
    assert imports[0].attempt_id == direct.attempt_id
    assert imports[1].attempt_id == diagnosis.attempt_id
    assert imports[0].run_id == direct.run_id
    assert imports[1].plan_digest == diagnosis.plan_digest
    assert proposal.operations[0].operation_id not in {
        operation.operation_id
        for attempt in case.history.attempts
        for operation in attempt.operations
    }

    pending = assess(proposal, case.history, case.current, now_ms=1000)
    assert pending.unmet_fact_ids == ("session-current",)
    assert pending.pending_prerequisite_action_ids == ("observe-session",)
    assert not pending.inputs_current
    assert proposal.prerequisites[0].addresses_fact_ids == ("session-current",)
    assert proposal.prerequisites[0].subject_ref == session.digest

    refresh = case.refreshed_history.attempts[-1].operations[0]
    assert case.refreshed_history.attempts[:2] == case.history.attempts
    assert refresh.method_id == proposal.prerequisites[0].method_id
    assert refresh.input_result_refs == (session.digest,)
    assert case.refreshed_current.facts[:2] == case.current.facts[:2]
    assert case.refreshed_current.facts[2].observation_result_ref == refresh.results[0].digest
    assert case.refreshed_current.facts[2].state is FactState.ESTABLISHED
    with pytest.raises(ObjectiveContinuationError, match="frontier"):
        assess(proposal, case.refreshed_history, case.refreshed_current, now_ms=1120)

    ready = assess(
        case.refreshed_proposal, case.refreshed_history, case.refreshed_current, now_ms=1120
    )
    assert ready.inputs_current
    assert ready.unmet_fact_ids == ready.pending_prerequisite_action_ids == ()
    assert case.refreshed_proposal.frontier_attempt_id == "attempt-refresh"
    assert case.refreshed_proposal.prerequisites == ()
    assert tuple(item.source for item in case.refreshed_proposal.operations[0].imports) == imports

    completed = case.completed_history
    executed_attempt = completed.attempts[-1]
    executed = executed_attempt.operations[0]
    assert completed.attempts[:-1] == case.refreshed_history.attempts
    assert completed.attempts[0].operations[-1].outcome is StepOutcome.BLOCKED
    assert executed_attempt.attempt_id == case.refreshed_proposal.new_attempt_id
    assert executed_attempt.plan_digest == case.refreshed_proposal.proposed_plan_digest
    assert executed.method_id == case.refreshed_proposal.operations[0].method_id
    assert executed.input_result_refs == tuple(source.digest for source in imports)
    assert executed.outcome is StepOutcome.SUCCESS
    assert executed.results[0].attempt_id == executed_attempt.attempt_id
    assert executed.results[0].run_id == executed_attempt.run_id
    assert all(
        operation.method_id != generate.method_id
        for attempt in completed.attempts[2:]
        for operation in attempt.operations
    )


def test_defense_change_leaves_prior_observation_historical_not_current(
    case: BacktrackingFixture,
):
    old_session_observation = case.refreshed_history.attempts[-1].operations[0].results[0]
    changed_conditions = (
        case.refreshed_current.conditions[0],
        ConditionBinding("defense_generation", content_hash("defense-generation-v2")),
    )
    changed_current = replace(case.refreshed_current, conditions=changed_conditions)
    operation = replace(case.refreshed_proposal.operations[0], conditions=changed_conditions)
    changed_proposal = replace(case.refreshed_proposal, operations=(operation,))

    assert changed_current.facts[2].state is FactState.ESTABLISHED
    assert changed_current.facts[2].observation_result_ref == old_session_observation.digest
    assert old_session_observation in case.refreshed_history.attempts[-1].operations[0].results
    assessment = assess(changed_proposal, case.refreshed_history, changed_current, now_ms=1120)
    assert assessment.unmet_fact_ids == ("session-current",)
    assert assessment.pending_prerequisite_action_ids == ()
    assert not assessment.inputs_current
    assert {item.fact_id for item in changed_current.facts[:2]} == {
        "bundle-current",
        "alternative-current",
    }
    explicitly_stale = replace(
        changed_current,
        facts=changed_current.facts[:2]
        + (
            replace(
                changed_current.facts[2],
                state=FactState.STALE,
                reason="Defense changed after the old session observation.",
            ),
        ),
    )
    assert assess(
        changed_proposal, case.refreshed_history, explicitly_stale, now_ms=1120
    ).unmet_fact_ids == ("session-current",)
