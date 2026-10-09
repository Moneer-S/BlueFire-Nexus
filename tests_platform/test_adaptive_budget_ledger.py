"""Pure authored pivot-ledger transitions; no execution, cancellation or provider effects."""

from copy import deepcopy

import pytest

from bluefire.adaptive_budget import (
    initial_budget,
    method_identity,
    new_budget,
    record_attempt,
    reserve_method,
    validate_budget,
)
from bluefire.adaptive_execution_contract import AdaptiveExecution
from bluefire.util import content_hash


@pytest.fixture
def policy():
    # Synthetic identities test budget accounting only. No registry action is
    # compiled or dispatched, and a reservation is not an execution claim.
    return AdaptiveExecution.from_mapping(
        {
            "schema_version": "bluefire.adaptive-execution.v2",
            "max_retries": 3,
            "eligible_outcomes": ["failed", "partial"],
            "on_provider_failure": "stop",
            "steps": [
                {
                    "step_id": name,
                    "max_retries": 2,
                    "methods": [
                        {
                            "behavior_id": f"fixture.{name}.v1",
                            "action_id": f"fixture.{name}{index}.v1",
                        }
                        for index in range(count)
                    ],
                }
                for name, count in (("alpha", 4), ("beta", 3))
            ],
        }
    )


def method(policy, step_id, index):
    step = next(step for step in policy.steps if step.step_id == step_id)
    return {"step_id": step_id, **step.methods[index].to_dict()}


def primary_budget(policy):
    budget = new_budget(policy)
    for step in policy.steps:
        budget = record_attempt(budget, policy, method(policy, step.step_id, 0))
    return budget


def legacy_policy(policy):
    raw = policy.to_dict()
    raw.update(schema_version="bluefire.adaptive-execution.v1", max_retries=1)
    for step in raw["steps"]:
        step.pop("max_retries")
    return AdaptiveExecution.from_mapping(raw)


def test_new_budget_binds_exact_policy_with_independent_step_allowances(policy):
    budget = new_budget(policy)
    assert budget == {
        "schema_version": "bluefire.adaptive-retry-budget.v2",
        "policy_digest": content_hash(policy.to_dict()),
        "maximum": 3,
        "used": 0,
        "remaining": 3,
        "per_step": {
            "alpha": {"maximum": 2, "used": 0, "remaining": 2},
            "beta": {"maximum": 2, "used": 0, "remaining": 2},
        },
        "reservations": [],
        "attempted_methods": [],
    }
    assert validate_budget(budget, policy) == budget


def test_primary_records_identity_without_consuming_or_aliasing_retry_allowance(policy):
    original = new_budget(policy)
    primary = {**method(policy, "alpha", 0), "parameters": {"private": "not-ledger-content"}}
    recorded = record_attempt(original, policy, primary)
    assert original["attempted_methods"] == []
    assert recorded["attempted_methods"] == [method(policy, "alpha", 0)]
    assert recorded["reservations"] == []
    assert (recorded["used"], recorded["remaining"]) == (0, 3)
    assert recorded["per_step"]["alpha"] == {"maximum": 2, "used": 0, "remaining": 2}
    assert record_attempt(recorded, policy, primary) == recorded
    # A completed reserved operation may be observed without a second debit.
    reserved = reserve_method(recorded, policy, method(policy, "alpha", 1))
    assert record_attempt(reserved, policy, method(policy, "alpha", 1)) == reserved
    assert reserved["used"] == 1
    assert method_identity(primary) == method(policy, "alpha", 0)


def test_per_step_exhaustion_and_global_exhaustion_independently_refuse_untried_methods(policy):
    budget = primary_budget(policy)
    for index in (1, 2):
        budget = reserve_method(budget, policy, method(policy, "alpha", index))
    assert budget["per_step"]["alpha"]["remaining"] == 0
    assert budget["per_step"]["beta"]["remaining"] == 2
    assert budget["remaining"] == 1
    frozen = deepcopy(budget)
    with pytest.raises(ValueError, match="exhausted"):
        reserve_method(budget, policy, method(policy, "alpha", 3))
    assert budget == frozen
    budget = reserve_method(budget, policy, method(policy, "beta", 1))
    assert budget["used"] == 3 and budget["remaining"] == 0
    assert budget["per_step"]["beta"]["remaining"] == 1
    assert budget["reservations"] == [
        method(policy, "alpha", 1),
        method(policy, "alpha", 2),
        method(policy, "beta", 1),
    ]
    with pytest.raises(ValueError, match="exhausted"):
        reserve_method(budget, policy, method(policy, "beta", 2))


@pytest.mark.parametrize("index", [0, 1])
def test_previously_attempted_primary_or_reserved_method_cannot_be_reserved_again(policy, index):
    budget = primary_budget(policy)
    budget = reserve_method(budget, policy, method(policy, "alpha", 1))
    frozen = deepcopy(budget)
    with pytest.raises(ValueError, match="already attempted"):
        reserve_method(budget, policy, method(policy, "alpha", index))
    assert budget == frozen


def test_reservation_survives_cancelled_or_unobserved_effects_and_continuation(policy):
    before = primary_budget(policy)
    reserved = reserve_method(before, policy, method(policy, "alpha", 1))
    assert before["used"] == 0
    # This is the persisted checkpoint before any caller effects. No completion
    # record is fabricated when the operation is cancelled or outcome is unknown.
    replay = {"adaptive_budget": deepcopy(reserved)}
    continued = initial_budget(policy, replay)
    assert continued == reserved and continued is not replay["adaptive_budget"]
    assert continued["used"] == continued["per_step"]["alpha"]["used"] == 1
    assert continued["remaining"] == 2
    assert method(policy, "alpha", 1) in continued["attempted_methods"]
    with pytest.raises(ValueError, match="already attempted"):
        reserve_method(continued, policy, method(policy, "alpha", 1))
    next_budget = reserve_method(continued, policy, method(policy, "alpha", 2))
    assert next_budget["used"] == 2
    assert replay["adaptive_budget"] == reserved
    continued["attempted_methods"].clear()
    assert replay["adaptive_budget"]["attempted_methods"] == reserved["attempted_methods"]


@pytest.mark.parametrize(
    "path,value",
    [
        (("maximum",), 4),
        (("used",), 0),
        (("remaining",), 3),
        (("maximum",), True),
        (("used",), True),
        (("remaining",), 2.0),
        (("per_step", "alpha", "maximum"), 3),
        (("per_step", "alpha", "used"), 0),
        (("per_step", "alpha", "remaining"), 2),
        (("per_step", "alpha", "used"), True),
        (("per_step", "beta", "used"), False),
        (("per_step", "alpha", "remaining"), 1.0),
        (("policy_digest",), "sha256:" + "0" * 64),
    ],
)
def test_aggregate_counters_and_policy_binding_cannot_be_forged(policy, path, value):
    budget = reserve_method(primary_budget(policy), policy, method(policy, "alpha", 1))
    destination = budget
    for key in path[:-1]:
        destination = destination[key]
    destination[path[-1]] = value
    with pytest.raises(ValueError, match="does not match"):
        validate_budget(budget, policy)


@pytest.mark.parametrize("change", ["missing_field", "extra_field", "unknown_step", "bad_history"])
def test_exact_ledger_shape_is_required(policy, change):
    budget = primary_budget(policy)
    if change == "missing_field":
        budget.pop("reservations")
    elif change == "extra_field":
        budget["refund"] = True
    elif change == "unknown_step":
        budget["per_step"]["not_reviewed"] = {"maximum": 1, "used": 0, "remaining": 1}
    else:
        budget["attempted_methods"] = "not-a-method-list"
    with pytest.raises(ValueError):
        validate_budget(budget, policy)


@pytest.mark.parametrize("field", ["reservations", "attempted_methods"])
@pytest.mark.parametrize("change", ["duplicate", "unknown", "extra", "missing", "bool", "null"])
def test_method_history_has_unique_exact_reviewed_identities(policy, field, change):
    budget = reserve_method(primary_budget(policy), policy, method(policy, "alpha", 1))
    row = budget[field][0]
    if change == "duplicate":
        budget[field].append(deepcopy(row))
    elif change == "unknown":
        row["action_id"] = "fixture.unreviewed.v1"
    elif change == "extra":
        row["parameters"] = {}
    elif change == "missing":
        row.pop("behavior_id")
    elif change == "bool":
        row["step_id"] = True
    else:
        budget[field][0] = None
    with pytest.raises(ValueError):
        validate_budget(budget, policy)


def test_reservation_cannot_disappear_from_attempted_history(policy):
    budget = reserve_method(primary_budget(policy), policy, method(policy, "alpha", 1))
    budget["attempted_methods"].remove(method(policy, "alpha", 1))
    with pytest.raises(ValueError, match="cannot disappear"):
        validate_budget(budget, policy)


@pytest.mark.parametrize("boundary", ["step", "lineage"])
def test_even_consistent_over_limit_history_is_refused(policy, boundary):
    budget = primary_budget(policy)
    reserved = [method(policy, "alpha", index) for index in (1, 2)]
    if boundary == "step":
        reserved.append(method(policy, "alpha", 3))
        alpha_used, beta_used = 3, 0
    else:
        reserved.extend(method(policy, "beta", index) for index in (1, 2))
        alpha_used, beta_used = 2, 2
    budget["reservations"] = reserved
    budget["attempted_methods"].extend(deepcopy(reserved))
    budget.update(used=len(reserved), remaining=3 - len(reserved))
    budget["per_step"]["alpha"].update(used=alpha_used, remaining=2 - alpha_used)
    budget["per_step"]["beta"].update(used=beta_used, remaining=2 - beta_used)
    with pytest.raises(ValueError):
        validate_budget(budget, policy)


def test_retained_multiple_methods_cannot_refund_a_reservation_by_rewriting_counters(policy):
    budget = reserve_method(primary_budget(policy), policy, method(policy, "alpha", 1))
    budget["reservations"].clear()
    budget.update(used=0, remaining=3)
    budget["per_step"]["alpha"].update(used=0, remaining=2)
    # Internally consistent aggregates do not excuse a missing consumed pivot.
    # Fully deleted historical evidence is detected by the caller's immutable
    # source binding, not claimed detectable from this standalone document.
    with pytest.raises(ValueError):
        validate_budget(budget, policy)
    with pytest.raises(ValueError):
        initial_budget(policy, {"adaptive_budget": budget})


def test_recording_another_method_requires_its_prior_reservation(policy):
    budget = primary_budget(policy)
    frozen = deepcopy(budget)
    with pytest.raises(ValueError):
        record_attempt(budget, policy, method(policy, "alpha", 1))
    assert budget == frozen


@pytest.mark.parametrize("operation", [record_attempt, reserve_method])
def test_unknown_adaptive_method_is_refused_without_mutating_input(policy, operation):
    budget = primary_budget(policy)
    frozen = deepcopy(budget)
    with pytest.raises(ValueError):
        operation(budget, policy, {**method(policy, "alpha", 1), "action_id": "fixture.unknown.v1"})
    assert budget == frozen


def test_nonadaptive_primary_does_not_expand_the_ledger(policy):
    budget = primary_budget(policy)
    assert record_attempt(budget, policy, {"step_id": "ordinary_step"}) == budget
    with pytest.raises(ValueError):
        reserve_method(budget, policy, {**method(policy, "alpha", 1), "step_id": "ordinary_step"})


def test_initial_budget_fresh_and_verified_continuation_have_distinct_semantics(policy):
    assert initial_budget(policy, None) == new_budget(policy)
    consumed = reserve_method(primary_budget(policy), policy, method(policy, "beta", 1))
    assert initial_budget(policy, {"adaptive_budget": consumed}) == consumed
    assert initial_budget(policy, {"adaptive_budget": consumed}) != new_budget(policy)


@pytest.mark.parametrize("replay", [{}, {"adaptive_retry_count": 1}, {"adaptive_budget": None}])
def test_v2_continuation_without_valid_retained_ledger_does_not_reset_budget(policy, replay):
    with pytest.raises(ValueError):
        initial_budget(policy, replay)


@pytest.mark.parametrize("has_policy", [False, True])
def test_legacy_execution_never_inherits_v2_budget(policy, has_policy):
    selected = legacy_policy(policy) if has_policy else None
    assert initial_budget(selected, None) is None
    assert initial_budget(selected, {"adaptive_retry_count": 1}) is None
    with pytest.raises(ValueError, match="Legacy execution"):
        initial_budget(selected, {"adaptive_budget": new_budget(policy)})


def test_ledger_cannot_move_to_changed_reviewed_policy(policy):
    changed = policy.to_dict()
    changed["max_retries"] = 2
    changed_policy = AdaptiveExecution.from_mapping(changed)
    with pytest.raises(ValueError, match="does not match"):
        initial_budget(changed_policy, {"adaptive_budget": primary_budget(policy)})
    with pytest.raises(ValueError, match="Explicit v2"):
        new_budget(legacy_policy(policy))
