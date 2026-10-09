"""Offline guard invariants; no provider, runner, or clock wait is started."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

import bluefire.adaptive_dispatch as dispatch
from bluefire.adaptive_budget import new_budget, record_attempt, reserve_method
from bluefire.adaptive_dispatch import ReviewedStepChecks
from bluefire.adaptive_execution import AdaptiveAuthorizationError
from bluefire.adaptive_runtime import reviewed_methods
from tests_platform.test_adaptive_budget_authorization import compiled, rehash


@pytest.fixture
def guard(monkeypatch):
    arguments, authorization = compiled()
    clock = [100.0]
    monkeypatch.setattr(dispatch.time, "monotonic", lambda: clock[0])
    checks = ReviewedStepChecks(
        plan=arguments["plan"],
        authorization=authorization,
        expected_digest=authorization["authorization_digest"],
        registry=arguments["registry"],
        profile=arguments["profile"],
        target_scope=arguments["target_scope"],
        platform=arguments["platform"],
        catalog_authority=None,
        approval={"expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()},
        deadline=111.0,
        cleanup_reserve=1.0,
    )
    policy = arguments["scenario"].adaptive_execution
    assert policy is not None
    methods = reviewed_methods(authorization, "stage_collection")
    budget = record_attempt(new_budget(policy), policy, methods[0].to_dict())
    return checks, authorization, policy, methods, budget, clock


@pytest.mark.parametrize("is_retry", [False, True])
def test_construction_digest_rejects_changed_and_rehashed_authority(guard, is_retry):
    checks, authorization, _, methods, budget, _ = guard
    check = checks.bind(
        remaining_steps=3, retries_used=0, budget=budget, step=methods[1], is_retry=is_retry
    )
    check()
    reviewed_digest = checks.expected_digest
    authorization["objective"] += " Altered after approval."
    rehash(authorization)
    assert authorization["authorization_digest"] != reviewed_digest
    assert checks.expected_digest == reviewed_digest
    with pytest.raises(AdaptiveAuthorizationError, match="digest"):
        check()


def test_bound_counters_remain_frozen_when_the_same_ledger_object_advances(guard):
    checks, _, policy, methods, budget, _ = guard
    budget.update(reserve_method(budget, policy, methods[1].to_dict()))
    check = checks.bind(
        remaining_steps=3,
        retries_used=budget["used"],
        budget=budget,
        is_retry=True,
    )
    check(methods[2])
    budget.update(reserve_method(budget, policy, methods[2].to_dict()))
    assert budget["used"] == budget["per_step"]["stage_collection"]["used"] == 2

    # A callback already bound to the prior admission keeps that exact snapshot.
    check(methods[2])
    fresh_check = checks.bind(
        remaining_steps=3,
        retries_used=budget["used"],
        budget=budget,
        is_retry=True,
    )
    with pytest.raises(AdaptiveAuthorizationError, match="per-step retry budget"):
        fresh_check(methods[2])
    # The reserved effect can still be rechecked without reserving a third pivot.
    checks.bind(remaining_steps=3, retries_used=budget["used"], budget=budget, step=methods[2])()


@pytest.mark.parametrize("is_retry", [False, True])
def test_bound_check_rechecks_live_deadline_including_cleanup_reserve(guard, is_retry):
    checks, _, _, methods, budget, clock = guard
    check = checks.bind(
        remaining_steps=3, retries_used=0, budget=budget, step=methods[1], is_retry=is_retry
    )
    check()
    clock[0] = 110.0
    with pytest.raises(AdaptiveAuthorizationError, match="time budget"):
        check()


def test_nonadaptive_dispatch_still_requires_the_exact_reviewed_plan_step(guard):
    checks, authorization, _, _, budget, _ = guard
    adaptive_ids = {group["step_id"] for group in authorization["steps"]}
    step = next(row for row in checks.plan.steps if row.step_id not in adaptive_ids)
    checks.bind(remaining_steps=3, retries_used=0, budget=budget, step=step)()
    changed = replace(step, parameters={**step.parameters, "unreviewed_guard_value": True})
    with pytest.raises(AdaptiveAuthorizationError, match="non-adaptive step differs"):
        checks.bind(remaining_steps=3, retries_used=0, budget=budget, step=changed)()


def test_retry_without_reviewed_authority_is_refused(guard):
    checks, _, _, methods, _, _ = guard
    legacy = replace(checks, authorization=None, expected_digest=None)
    legacy.bind(remaining_steps=3, retries_used=0, budget=None, step=methods[0])()
    check = legacy.bind(remaining_steps=3, retries_used=0, budget=None, is_retry=True)
    with pytest.raises(AdaptiveAuthorizationError, match="no reviewed authority"):
        check(methods[1])
