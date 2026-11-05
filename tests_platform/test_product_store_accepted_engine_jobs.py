from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from bluefire.engine_attempt_contract import EngineAttemptRecord
from bluefire.engine_reconciliation import (
    ClaimedEngineReconciliation,
    EngineReconciliationError,
)
from bluefire.product_store_accepted_engine_jobs import (
    AbsentPreparedEngineAttempt,
    AcceptedEngineJobError,
    AcceptedPreparedEngineAttempt,
    PreDispatchCancelledEngineAttempt,
    ProductStoreAcceptedEngineJobs,
    ProductStoreEngineReconciliationCoordinator,
    SettledPreDispatchEngineAttempt,
)
from bluefire.product_store_engine_execution_claims import (
    EngineExecutionClaimRecovery,
    EngineExecutionClaimResult,
    EngineExecutionReconciliationResult,
)
from bluefire.strix_runtime_admission_resolver import (
    ControllerQualifiedStrixAdmissionResolver,
    StrixRuntimeAdmissionResolverError,
)
from tests_platform.test_product_store_engine_actions import _attempt_authority, _iso

RESOLUTION_REF = "sha256:" + "d" * 64
CLAIM_REF = "sha256:" + "c" * 64
RECONCILIATION_REF = "sha256:" + "e" * 64
PREPARATION_REF = "sha256:" + "b" * 64
JOB_ID = "job-" + "a" * 32


def _authority():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return _attempt_authority(_iso(now), _iso(now + timedelta(minutes=5)))[:2]


def _document(binding, delegation) -> dict[str, object]:
    return {
        "job_id": JOB_ID,
        "preparation_ref": PREPARATION_REF,
        "binding_digest": binding.binding_digest,
        "delegation_digest": delegation.delegation_digest,
        "claim_ref": CLAIM_REF,
        "runtime_resolution_ref": RESOLUTION_REF,
    }


class _Resolver(ControllerQualifiedStrixAdmissionResolver):
    def __init__(self, *, fail_resolve: bool = False, fail_require: bool = False) -> None:
        self.fail_resolve = fail_resolve
        self.fail_require = fail_require
        self.calls: list[tuple[str, str | None]] = []

    def resolve_for_launch(self, binding, delegation):
        self.calls.append(("resolve", None))
        if self.fail_resolve:
            raise StrixRuntimeAdmissionResolverError("private resolver detail")
        return SimpleNamespace(resolution_ref=RESOLUTION_REF)

    def require_current(self, binding, delegation, *, expected_resolution_ref):
        self.calls.append(("require", expected_resolution_ref))
        if self.fail_require:
            raise StrixRuntimeAdmissionResolverError("private resolver detail")
        return SimpleNamespace(resolution_ref=expected_resolution_ref)


class _Store:
    def __init__(self, *, claim, precheck=None, recovery=None) -> None:
        self.claim = claim
        self.precheck = precheck
        self.recovery = recovery
        self.calls: list[str] = []

    def inspect_accepted_engine_attempt_pre_dispatch_cancellation(self, **values):
        self.calls.append("precheck")
        if isinstance(self.precheck, list):
            return self.precheck.pop(0)
        return self.precheck

    def claim_accepted_engine_attempt_execution(self, **values):
        self.calls.append("claim")
        return self.claim

    def get_accepted_engine_attempt_execution(self, **values):
        self.calls.append("reopen")
        return self.recovery


class _CoordinatorStore:
    def __init__(self, *, binding, delegation) -> None:
        self.capability = object()
        self.binding = binding
        self.delegation = delegation
        self.active = False
        self.begin_values: dict[str, object] | None = None

    @contextmanager
    def engine_attempt_reconciliation_session(self, **values):
        assert not self.active
        assert "deadline" in values
        self.active = True
        try:
            yield self.capability
        finally:
            self.active = False

    def begin_or_reopen_engine_attempt_reconciliation(self, **values):
        assert self.active
        assert values["reconciliation_capability"] is self.capability
        self.begin_values = values
        return EngineExecutionReconciliationResult(
            claim_document=_document(self.binding, self.delegation),
            pre_dispatch_document=None,
            reconciliation_document={"reconciliation_ref": RECONCILIATION_REF},
            job_id=JOB_ID,
            job_state="failed",
        )


def _adapter(store: _Store, resolver: _Resolver) -> ProductStoreAcceptedEngineJobs:
    return ProductStoreAcceptedEngineJobs(
        store=store,
        resolver=resolver,
        reviewer="bluefire.local-operator",
        clock=lambda: _iso(datetime.now(timezone.utc).replace(microsecond=0)),
    )


def test_adapter_resolves_then_claims_and_rechecks_exact_resolution() -> None:
    binding, delegation = _authority()
    result = EngineExecutionClaimResult(
        document=_document(binding, delegation),
        created=True,
        job_state="running",
        pre_dispatch_ref=None,
    )
    store = _Store(claim=result)
    resolver = _Resolver()

    accepted = _adapter(store, resolver).claim_for_execution(
        job_id=JOB_ID, binding=binding, delegation=delegation
    )

    assert isinstance(accepted, AcceptedPreparedEngineAttempt)
    assert accepted.runtime_resolution_ref == RESOLUTION_REF
    assert store.calls == ["precheck", "claim"]
    assert resolver.calls == [("resolve", None), ("require", RESOLUTION_REF)]


def test_atomic_cancellation_precheck_wins_before_failed_resolver() -> None:
    binding, delegation = _authority()
    cancelled = EngineExecutionClaimResult(
        document=None,
        created=False,
        job_state="cancelling",
        pre_dispatch_ref="sha256:" + "e" * 64,
    )
    store = _Store(claim=None, precheck=cancelled)
    resolver = _Resolver(fail_resolve=True)

    result = _adapter(store, resolver).claim_for_execution(
        job_id=JOB_ID, binding=binding, delegation=delegation
    )

    assert isinstance(result, PreDispatchCancelledEngineAttempt)
    assert result.job_state == "cancelling"
    assert store.calls == ["precheck"]
    assert resolver.calls == []


def test_failed_resolver_rechecks_atomic_cancellation_before_reporting_failure() -> None:
    binding, delegation = _authority()
    cancelled = EngineExecutionClaimResult(
        document=None,
        created=False,
        job_state="cancelling",
        pre_dispatch_ref="sha256:" + "f" * 64,
    )
    store = _Store(claim=None, precheck=[None, cancelled])
    resolver = _Resolver(fail_resolve=True)

    result = _adapter(store, resolver).claim_for_execution(
        job_id=JOB_ID, binding=binding, delegation=delegation
    )

    assert isinstance(result, PreDispatchCancelledEngineAttempt)
    assert store.calls == ["precheck", "precheck"]
    assert resolver.calls == [("resolve", None)]


def test_lost_ack_replay_returns_no_second_authority() -> None:
    binding, delegation = _authority()
    result = EngineExecutionClaimResult(
        document=_document(binding, delegation),
        created=False,
        job_state="running",
        pre_dispatch_ref=None,
    )
    store = _Store(claim=result)
    resolver = _Resolver()

    assert (
        _adapter(store, resolver).claim_for_execution(
            job_id=JOB_ID, binding=binding, delegation=delegation
        )
        is None
    )
    assert resolver.calls == [("resolve", None)]


def test_reconciliation_returns_claim_or_conservative_absence() -> None:
    binding, delegation = _authority()
    claimed_store = _Store(
        claim=None,
        recovery=EngineExecutionClaimRecovery(
            document=_document(binding, delegation),
            job_id=JOB_ID,
            job_state="failed",
        ),
    )
    absent_store = _Store(
        claim=None,
        recovery=EngineExecutionClaimRecovery(
            document=None,
            job_id=JOB_ID,
            job_state="interrupted",
        ),
    )

    claimed = _adapter(claimed_store, _Resolver()).reopen_for_reconciliation(
        binding=binding, delegation=delegation
    )
    absent = _adapter(absent_store, _Resolver()).reopen_for_reconciliation(
        binding=binding, delegation=delegation
    )

    assert isinstance(claimed, AcceptedPreparedEngineAttempt)
    assert isinstance(absent, AbsentPreparedEngineAttempt)
    assert absent.job_state == "interrupted"


def test_reconciliation_returns_exact_settled_pre_dispatch_receipt() -> None:
    binding, delegation = _authority()
    settled_at = _iso(datetime.now(timezone.utc).replace(microsecond=0))
    settlement_ref = "sha256:" + "9" * 64
    store = _Store(
        claim=None,
        recovery=EngineExecutionClaimRecovery(
            document=None,
            pre_dispatch_document={
                "settlement_ref": settlement_ref,
                "exit_reason": "controller_cancelled_before_execution_claim",
                "settled_at": settled_at,
            },
            job_id=JOB_ID,
            job_state="interrupted",
        ),
    )

    reopened = _adapter(store, _Resolver()).reopen_for_reconciliation(
        binding=binding,
        delegation=delegation,
    )

    assert isinstance(reopened, SettledPreDispatchEngineAttempt)
    assert reopened.settlement_ref == settlement_ref
    assert reopened.exit_reason == "controller_cancelled_before_execution_claim"
    assert reopened.settled_at == settled_at
    assert store.calls == ["reopen"]


def test_second_current_check_is_claim_ref_bound_and_sanitized() -> None:
    binding, delegation = _authority()
    accepted = AcceptedPreparedEngineAttempt(
        job_id=JOB_ID,
        preparation_ref=PREPARATION_REF,
        binding_digest=binding.binding_digest,
        delegation_digest=delegation.delegation_digest,
        claim_ref=CLAIM_REF,
        runtime_resolution_ref=RESOLUTION_REF,
    )
    resolver = _Resolver(fail_require=True)

    with pytest.raises(AcceptedEngineJobError) as caught:
        _adapter(_Store(claim=None), resolver).require_current(
            accepted=accepted, binding=binding, delegation=delegation
        )

    assert "private resolver detail" not in str(caught.value)
    assert resolver.calls == [("require", RESOLUTION_REF)]


def test_reconciliation_coordinator_propagates_exact_active_capability() -> None:
    binding, delegation = _authority()
    store = _CoordinatorStore(binding=binding, delegation=delegation)
    coordinator = ProductStoreEngineReconciliationCoordinator(
        store=store,
        reviewer="bluefire.local-operator",
        clock=lambda: _iso(datetime.now(timezone.utc).replace(microsecond=0)),
    )
    saved = EngineAttemptRecord.create(binding)

    with coordinator.session(
        experiment_id=binding.experiment_id,
        attempt_id=binding.attempt_id,
    ) as session:
        assert session.reconciliation_capability is store.capability
        plan = session.begin_or_reopen(
            binding=binding,
            delegation=delegation,
            saved_record=saved,
            expected_revision=3,
            expected_experiment_digest="sha256:" + "1" * 64,
        )
        assert isinstance(plan, ClaimedEngineReconciliation)
        assert (
            coordinator.require_active_claimed(
                binding=binding,
                delegation=delegation,
                reconciliation_ref=RECONCILIATION_REF,
            )
            is plan
        )
        with pytest.raises(EngineReconciliationError, match="reference changed"):
            coordinator.require_active_claimed(
                binding=binding,
                delegation=delegation,
                reconciliation_ref="sha256:" + "2" * 64,
            )

    assert not store.active
    assert store.begin_values is not None
    assert store.begin_values["reconciliation_capability"] is store.capability


def test_reconciliation_capability_is_stale_after_session_exit() -> None:
    binding, delegation = _authority()
    store = _CoordinatorStore(binding=binding, delegation=delegation)
    coordinator = ProductStoreEngineReconciliationCoordinator(
        store=store,
        reviewer="bluefire.local-operator",
        clock=lambda: _iso(datetime.now(timezone.utc).replace(microsecond=0)),
    )
    saved = EngineAttemptRecord.create(binding)

    with coordinator.session(
        experiment_id=binding.experiment_id,
        attempt_id=binding.attempt_id,
    ) as session:
        session.begin_or_reopen(
            binding=binding,
            delegation=delegation,
            saved_record=saved,
            expected_revision=3,
            expected_experiment_digest="sha256:" + "1" * 64,
        )

    with pytest.raises(EngineReconciliationError, match="session is not active"):
        coordinator.require_active_claimed(
            binding=binding,
            delegation=delegation,
            reconciliation_ref=RECONCILIATION_REF,
        )
