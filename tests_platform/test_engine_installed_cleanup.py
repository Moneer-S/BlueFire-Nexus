from __future__ import annotations

from types import SimpleNamespace

import pytest

from bluefire.engine_installed_cleanup import (
    InstalledEngineBundleCleanupReceipt,
    InstalledEngineCleanupError,
    InstalledEngineCleanupResourceBinding,
    InstalledEngineResourceCleanupOutcome,
    cleanup_request_ref,
    resource_set_ref,
)
from bluefire.engine_installed_composition import (
    InstalledAttemptComponents,
    InstalledEngineCleanupUnresolved,
    InstalledEngineCompositionError,
)
from bluefire.engine_service_composition import EngineServiceComposition
from bluefire.product_store import ProductStoreError
from tests_platform.test_engine_installed_composition import (
    RESOLUTION,
    _configured,
    _Resource,
)

WORKER = "sha256:" + "8" * 64
MODEL = "sha256:" + "9" * 64
RESOURCE_MANIFEST = (
    InstalledEngineCleanupResourceBinding("worker", WORKER),
    InstalledEngineCleanupResourceBinding("model_lease", MODEL),
)
RESOURCE_SET = resource_set_ref(RESOURCE_MANIFEST)
EVIDENCE = "sha256:" + "a" * 64
ATTEMPT = "sha256:" + "b" * 64
ACTIVATION = "sha256:" + "c" * 64
OWNER = "sha256:" + "d" * 64
NOW = "2026-11-05T14:00:00Z"


def _outcomes(*states: str) -> tuple[InstalledEngineResourceCleanupOutcome, ...]:
    roles = ("model_lease", "worker")
    refs = (MODEL, WORKER)
    return tuple(
        InstalledEngineResourceCleanupOutcome(
            role=role,
            resource_ref=resource_ref,
            state=state,
            evidence_ref=None if state == "unknown" else EVIDENCE,
        )
        for role, resource_ref, state in zip(roles, refs, states, strict=True)
    )


def _receipt(
    cleanup_ref: str,
    *states: str,
    generation: int = 1,
    predecessor_receipt_ref: str | None = None,
) -> InstalledEngineBundleCleanupReceipt:
    outcomes = _outcomes(*states)
    return InstalledEngineBundleCleanupReceipt.create(
        cleanup_ref=cleanup_ref,
        attempt_ref=ATTEMPT,
        activation_ref=ACTIVATION,
        owner_ref=OWNER,
        runtime_resolution_ref=RESOLUTION,
        resource_set_ref=RESOURCE_SET,
        generation=generation,
        predecessor_receipt_ref=predecessor_receipt_ref,
        state=(
            "verified_absent"
            if all(outcome.state != "unknown" for outcome in outcomes)
            else "unknown"
        ),
        outcomes=outcomes,
        settled_at=NOW,
    )


class _CleanupOwner:
    attempt_ref = ATTEMPT
    activation_ref = ACTIVATION
    owner_ref = OWNER
    runtime_resolution_ref = RESOLUTION
    resource_manifest = RESOURCE_MANIFEST
    resource_set_ref = resource_set_ref(resource_manifest)

    def __init__(self, *, settle_states=("verified_revoked", "unknown")) -> None:
        self.settle_states = settle_states
        self.events: list[tuple[str, str]] = []

    def settle(self, *, cleanup_ref):
        self.events.append(("settle", cleanup_ref))
        return _receipt(cleanup_ref, *self.settle_states)

    def reconcile(self, *, receipt):
        self.events.append(("reconcile", receipt.receipt_ref))
        return _receipt(
            receipt.cleanup_ref,
            "verified_revoked",
            "verified_absent",
            generation=receipt.generation + 1,
            predecessor_receipt_ref=receipt.receipt_ref,
        )


def _components(owner, resource):
    return InstalledAttemptComponents(
        runtime=SimpleNamespace(),
        resources=(resource,),
        runtime_resolution_ref=RESOLUTION,
        cleanup_owner=owner,
        resource_set_ref=RESOURCE_SET,
        attempt_ref=ATTEMPT,
        activation_ref=ACTIVATION,
    )


def test_cleanup_receipt_requires_exact_terminal_evidence_and_digest():
    cleanup_ref = cleanup_request_ref(ATTEMPT, ACTIVATION, OWNER, RESOLUTION, RESOURCE_SET)
    receipt = _receipt(cleanup_ref, "verified_revoked", "verified_absent")

    assert receipt.state == "verified_absent"
    assert [outcome.role for outcome in receipt.outcomes] == ["model_lease", "worker"]
    with pytest.raises(InstalledEngineCleanupError, match="requires evidence"):
        InstalledEngineResourceCleanupOutcome(
            role="worker",
            resource_ref=WORKER,
            state="verified_absent",
            evidence_ref=None,
        )
    with pytest.raises(InstalledEngineCleanupError, match="digest"):
        InstalledEngineBundleCleanupReceipt(
            cleanup_ref=receipt.cleanup_ref,
            attempt_ref=receipt.attempt_ref,
            activation_ref=receipt.activation_ref,
            owner_ref=receipt.owner_ref,
            runtime_resolution_ref=receipt.runtime_resolution_ref,
            resource_set_ref=receipt.resource_set_ref,
            generation=receipt.generation,
            predecessor_receipt_ref=receipt.predecessor_receipt_ref,
            state=receipt.state,
            outcomes=receipt.outcomes,
            settled_at=receipt.settled_at,
            receipt_ref="sha256:" + "0" * 64,
        )


def test_cleanup_receipt_must_cover_reverse_exact_resource_manifest():
    cleanup_ref = cleanup_request_ref(ATTEMPT, ACTIVATION, OWNER, RESOLUTION, RESOURCE_SET)
    receipt = InstalledEngineBundleCleanupReceipt.create(
        cleanup_ref=cleanup_ref,
        attempt_ref=ATTEMPT,
        activation_ref=ACTIVATION,
        owner_ref=OWNER,
        runtime_resolution_ref=RESOLUTION,
        resource_set_ref=RESOURCE_SET,
        generation=1,
        predecessor_receipt_ref=None,
        state="verified_absent",
        outcomes=(
            InstalledEngineResourceCleanupOutcome(
                role="worker",
                resource_ref=WORKER,
                state="verified_absent",
                evidence_ref=EVIDENCE,
            ),
        ),
        settled_at=NOW,
    )
    owner = _CleanupOwner()
    owner.settle = lambda **_values: receipt  # type: ignore[method-assign]
    config = _configured()
    config.composition._retain(
        _components(owner, _Resource([], "descriptor")),
        expected_resolution_ref=RESOLUTION,
        expected_attempt_ref=ATTEMPT,
        expected_activation_ref=ACTIVATION,
    )

    with pytest.raises(InstalledEngineCompositionError, match="remains unresolved"):
        config.composition.close()


def test_duplicate_bundle_identity_is_quarantined_without_settling_live_owner():
    first = _CleanupOwner()
    second = _CleanupOwner(settle_states=("verified_revoked", "verified_absent"))
    config = _configured()
    config.composition._retain(
        _components(first, _Resource([], "first")),
        expected_resolution_ref=RESOLUTION,
        expected_attempt_ref=ATTEMPT,
        expected_activation_ref=ACTIVATION,
    )

    with pytest.raises(InstalledEngineCompositionError, match="identity collision"):
        config.composition._retain(
            _components(second, _Resource([], "second")),
            expected_resolution_ref=RESOLUTION,
            expected_attempt_ref=ATTEMPT,
            expected_activation_ref=ACTIVATION,
        )
    assert first.events == second.events == []
    assert config.composition.cleanup_status["collision_count"] == 1
    assert config.composition.cleanup_status["state"] == "unknown"


@pytest.mark.parametrize("changed_ref", ["attempt", "activation"])
def test_attempt_bundle_must_match_accepted_execution_identity(changed_ref):
    owner = _CleanupOwner()
    config = _configured()
    expected_attempt_ref = ATTEMPT if changed_ref != "attempt" else "sha256:" + "e" * 64
    expected_activation_ref = ACTIVATION if changed_ref != "activation" else "sha256:" + "e" * 64

    with pytest.raises(InstalledEngineCompositionError, match="exact attempt components"):
        config.composition._retain(
            _components(owner, _Resource([], "wrong owner")),
            expected_resolution_ref=RESOLUTION,
            expected_attempt_ref=expected_attempt_ref,
            expected_activation_ref=expected_activation_ref,
        )
    assert [event[0] for event in owner.events] == ["settle"]
    assert config.composition.cleanup_status["pending_bundle_count"] == 1
    config.composition.close()
    assert config.composition.cleanup_status["state"] == "verified_absent"


def test_bundle_close_preserves_unknown_then_reconciles_without_generic_close():
    events = []
    resource = _Resource(events, "descriptor")
    owner = _CleanupOwner()
    config = _configured()
    config.composition._retain(
        _components(owner, resource),
        expected_resolution_ref=RESOLUTION,
        expected_attempt_ref=ATTEMPT,
        expected_activation_ref=ACTIVATION,
    )

    with pytest.raises(InstalledEngineCompositionError, match="remains unresolved"):
        config.composition.close()
    assert config.composition._closed is False
    assert config.composition.cleanup_status["state"] == "unknown"
    assert config.composition.cleanup_status["pending_bundle_count"] == 1
    assert events == []

    config.composition.close()
    assert config.composition._closed is True
    assert config.composition.cleanup_status["state"] == "verified_absent"
    assert config.composition.cleanup_status["pending_bundle_count"] == 0
    assert events == []
    assert [event[0] for event in owner.events] == ["settle", "reconcile"]


def test_service_close_retries_only_exact_retained_cleanup_owner():
    config = _configured()
    owner = _CleanupOwner()
    config.composition._retain(
        _components(owner, _Resource([], "owned worker")),
        expected_resolution_ref=RESOLUTION,
        expected_attempt_ref=ATTEMPT,
        expected_activation_ref=ACTIVATION,
    )
    service = EngineServiceComposition(composition=config.composition)

    with pytest.raises(ProductStoreError, match="owned engine resources"):
        service.close(None)
    assert config.composition.cleanup_status["state"] == "unknown"
    service.close(None)
    assert config.composition.cleanup_status["state"] == "verified_absent"
    assert [event[0] for event in owner.events] == ["settle", "reconcile"]


def test_unreceipted_settlement_failure_is_not_replayed():
    class EffectThenFailure(_CleanupOwner):
        def settle(self, *, cleanup_ref):
            self.events.append(("effect_then_failure", cleanup_ref))
            raise OSError("settlement outcome unknown")

    owner = EffectThenFailure()
    config = _configured()
    config.composition._retain(
        _components(owner, _Resource([], "uncertain worker")),
        expected_resolution_ref=RESOLUTION,
        expected_attempt_ref=ATTEMPT,
        expected_activation_ref=ACTIVATION,
    )

    for _ in range(2):
        with pytest.raises(InstalledEngineCompositionError, match="remains unresolved"):
            config.composition.close()
    assert [event[0] for event in owner.events] == ["effect_then_failure"]
    assert config.composition.cleanup_status["state"] == "unknown"


def test_stopping_discard_uses_exact_bundle_owner_and_never_closes_handle_directly():
    events = []
    resource = _Resource(events, "descriptor")
    owner = _CleanupOwner(settle_states=("verified_revoked", "verified_absent"))
    config = _configured()
    config.composition.shutdown_jobs()

    with pytest.raises(InstalledEngineCompositionError, match="stopping"):
        config.composition._retain(
            _components(owner, resource),
            expected_resolution_ref=RESOLUTION,
            expected_attempt_ref=ATTEMPT,
            expected_activation_ref=ACTIVATION,
        )
    assert [event[0] for event in owner.events] == ["settle"]
    assert events == []
    assert config.composition.cleanup_status["state"] == "stopping"
    config.composition.close()
    assert config.composition.cleanup_status["state"] == "verified_absent"


def test_global_legacy_close_failure_is_retained_unknown_and_handle_is_not_retried():
    events = []
    resource = _Resource(events, "uncertain descriptor", fail=True)
    config = _configured(resources=(resource,))

    with pytest.raises(InstalledEngineCompositionError, match="remains unresolved"):
        config.composition.close()
    assert config.composition.cleanup_status == {
        "schema_version": "bluefire.installed-engine-cleanup-status.v1",
        "state": "unknown",
        "pending_bundle_count": 0,
        "legacy_unknown_count": 1,
        "collision_count": 0,
        "receipt_refs": [],
    }
    with pytest.raises(InstalledEngineCompositionError, match="remains unresolved"):
        config.composition.close()
    assert events == [("close", "uncertain descriptor")]


def test_attempt_resources_without_exact_owner_are_quarantined_not_closed():
    events = []
    resource = _Resource(events, "effect owner")
    config = _configured()
    components = InstalledAttemptComponents(
        runtime=SimpleNamespace(),
        resources=(resource,),
        runtime_resolution_ref=RESOLUTION,
    )

    config.composition._discard_components(components)
    assert events == []
    assert config.composition.cleanup_status["state"] == "unknown"
    assert config.composition.cleanup_status["collision_count"] == 1
    with pytest.raises(InstalledEngineCompositionError, match="remains unresolved"):
        config.composition.close()


def test_discard_after_close_reopens_conservative_cleanup_status():
    config = _configured()
    config.composition.close()
    assert config.composition.cleanup_status["state"] == "verified_absent"

    owner = _CleanupOwner()
    config.composition._discard_components(_components(owner, _Resource([], "late owned resource")))
    assert config.composition.cleanup_status["state"] == "unknown"
    config.composition.close()
    assert config.composition.cleanup_status["state"] == "verified_absent"


def test_service_helper_retries_only_the_exact_composition_settlement():
    class Owner:
        def __init__(self):
            self.close_calls = 0
            self.shutdown_calls = 0

        def claim_service(self):
            pass

        def shutdown_jobs(self, jobs):
            self.shutdown_calls += 1

        def close(self):
            self.close_calls += 1
            if self.close_calls == 1:
                raise InstalledEngineCleanupUnresolved("cleanup remains unknown")

    owner = Owner()
    helper = EngineServiceComposition(composition=owner)  # type: ignore[arg-type]
    with pytest.raises(ProductStoreError, match="could not be closed"):
        helper.close(None)
    helper.close(None)
    helper.close(None)

    assert owner.shutdown_calls == 2
    assert owner.close_calls == 2


def test_restart_reopens_retained_receipt_before_advancing_exact_successor():
    journal: dict[str, InstalledEngineBundleCleanupReceipt] = {}

    class DurableOwner(_CleanupOwner):
        def __init__(self, *, recover):
            super().__init__()
            self.recover = recover

        def settle(self, *, cleanup_ref):
            retained = journal.get(cleanup_ref)
            if retained is None:
                retained = _receipt(cleanup_ref, "verified_revoked", "unknown")
                journal[cleanup_ref] = retained
            self.events.append(("settle", retained.receipt_ref))
            return retained

        def reconcile(self, *, receipt):
            self.events.append(("reconcile", receipt.receipt_ref))
            if not self.recover:
                return receipt
            successor = _receipt(
                receipt.cleanup_ref,
                "verified_revoked",
                "verified_absent",
                generation=receipt.generation + 1,
                predecessor_receipt_ref=receipt.receipt_ref,
            )
            journal[receipt.cleanup_ref] = successor
            return successor

    first = _configured()
    first_owner = DurableOwner(recover=False)
    first.composition._retain(
        _components(first_owner, _Resource([], "first worker")),
        expected_resolution_ref=RESOLUTION,
        expected_attempt_ref=ATTEMPT,
        expected_activation_ref=ACTIVATION,
    )
    with pytest.raises(InstalledEngineCompositionError, match="remains unresolved"):
        first.composition.close()

    restarted = _configured()
    restarted_owner = DurableOwner(recover=True)
    restarted.composition._retain(
        _components(restarted_owner, _Resource([], "reopened worker")),
        expected_resolution_ref=RESOLUTION,
        expected_attempt_ref=ATTEMPT,
        expected_activation_ref=ACTIVATION,
    )
    with pytest.raises(InstalledEngineCompositionError, match="remains unresolved"):
        restarted.composition.close()
    restarted.composition.close()

    assert [event[0] for event in restarted_owner.events] == ["settle", "reconcile"]
    assert restarted.composition.cleanup_status["state"] == "verified_absent"
