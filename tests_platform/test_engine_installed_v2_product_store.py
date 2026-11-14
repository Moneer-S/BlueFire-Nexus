"""Journal intent, exact owners, and independent absence for installed V2 resources."""

from __future__ import annotations

from dataclasses import replace

import pytest

from bluefire.engine_installed_v2_authority import InstalledStrixV2CompositionError
from bluefire.engine_installed_v2_product_store import (
    InstalledStrixV2TransactionHead,
    ProductStoreInstalledStrixV2ResourceFactory,
    installed_strix_v2_reconciliation_binding_ref,
)
from bluefire.engine_installed_v2_resources import (
    InstalledStrixV2ReopenedResources,
    InstalledStrixV2ResourceReceipt,
)
from bluefire.util import content_hash
from tests_platform.test_engine_installed_v2_openers import (
    _digest,
    _execute,
    _openers,
    _prepare_reconciliation,
    _reconcile,
    _runtime_identity,
    _TestCleanupOwner,
)


class _Repository:
    def __init__(self, store, events):
        self.store = store
        self.events = events
        self.heads = {}
        self.documents = []
        self.fail_event = None
        self.observer = None

    def require_product_store(self, store):
        if store is not self.store:
            raise InstalledStrixV2CompositionError("wrong store")

    def require_absence_observer(self, observer):
        self.observer = observer

    def prepare_transaction(self, **values):
        ref = values["transaction_ref"]
        if ref not in self.heads:
            self.events.append("journal:prepared")
            self.heads[ref] = InstalledStrixV2TransactionHead(ref, 1, "prepared")
            self.documents.append(values)
        return self.heads[ref]

    def load_transaction(self, transaction_ref):
        return self.heads[transaction_ref]

    def record_absence(self, *, transaction_ref, expected_generation, document):
        assert self.observer.reopen_absence(observation_ref=document["observation_ref"]) == document
        return self.append_event(
            transaction_ref=transaction_ref,
            expected_generation=expected_generation,
            event_type="absence_observed",
            state="stopping",
            document=document,
            receipt_ref=document["observation_ref"],
        )

    def append_event(self, **values):
        event = values["event_type"]
        if self.fail_event == event:
            self.fail_event = None
            raise RuntimeError("journal unavailable")
        ref = values["transaction_ref"]
        old = self.heads[ref]
        if old.generation != values["expected_generation"]:
            raise RuntimeError("transaction CAS lost")
        self.events.append("journal:" + event)
        head = InstalledStrixV2TransactionHead(ref, old.generation + 1, values["state"])
        self.heads[ref] = head
        self.documents.append(values)
        return head


class _Observer:
    observer_identity_ref = _digest("independent-platform-observer")
    observer_generation = 1

    def __init__(self, events, *, mismatch=False):
        self.events = events
        self.mismatch = mismatch
        self.documents = {}

    def observe_absence(self, **values):
        self.events.append("observe:absent")
        document = {
            "schema_version": "bluefire.installed-strix-v2-cleanup-absence.v1",
            **values,
            "role_bindings": [
                {"role": role, "binding_ref": binding, "owner_ref": owner}
                for role, binding, owner in values["role_bindings"]
            ],
            "observer_identity_ref": self.observer_identity_ref,
            "observer_generation": self.observer_generation,
            "observed_at": "2026-11-05T12:00:00Z",
            "state": "absent",
        }
        if self.mismatch:
            document["authority_ref"] = _digest("different-authority")
        retained = {**document, "observation_ref": content_hash(document)}
        self.documents[retained["observation_ref"]] = retained
        return retained

    def reopen_absence(self, *, observation_ref):
        return self.documents[observation_ref]


def _wrapped(*, observer=True, mismatch=False):
    case = _openers()
    case["execution_factory"].observed_identity = _runtime_identity(
        case["accepted"],
        case["binding"],
        case["delegation"],
        case["snapshot"],
        case["plan"],
    )
    repository = _Repository(case["store"], case["events"])
    factory = ProductStoreInstalledStrixV2ResourceFactory(
        product_store=case["store"],
        repository=repository,
        execution_resources=case["execution_factory"],
        reconciliation_resources=case["reconciliation_factory"],
        absence_observer=_Observer(case["events"], mismatch=mismatch) if observer else None,
    )
    case["openers"]._execution_resources = factory
    case["openers"]._reconciliation_resources = factory
    case["journal"] = repository
    case["journal_factory"] = factory
    return case


def _begin(case):
    from bluefire.engine_installed_v2_authority import InstalledStrixV2AuthorityGuard

    guard = InstalledStrixV2AuthorityGuard(
        product_store=case["store"],
        source=case["source"],
        accepted=case["accepted"],
        binding=case["binding"],
        delegation=case["delegation"],
    )
    snapshot = guard.require_prelaunch_current()
    return case["journal_factory"].begin_execution(
        product_store=case["store"],
        snapshot=snapshot,
        launch_plan=case["plan"],
        authority_guard=guard,
    )


def test_begin_is_platform_effect_free_and_prepared_close_uses_journal_proof():
    case = _wrapped(observer=False)
    transaction = _begin(case)
    assert transaction.effects_started is False
    assert "begin" not in case["events"]
    receipt = transaction.close()
    assert receipt.transaction_ref == transaction.transaction_ref
    assert receipt.absence_verified is True
    assert transaction.close() is receipt
    assert case["journal"].load_transaction(transaction.transaction_ref).state == "closed"
    assert "observe:absent" not in case["events"]


def test_authority_is_reopened_before_platform_effects():
    case = _wrapped(observer=False)
    transaction = _begin(case)

    def revoked(**_values):
        raise RuntimeError("authority revoked")

    case["source"].require_prelaunch_current = revoked
    with pytest.raises(InstalledStrixV2CompositionError, match="no longer current"):
        transaction.allocate()
    assert transaction.effects_started is False
    assert "begin" not in case["events"]
    assert "journal:allocation_started" not in case["events"]
    assert transaction.close().absence_verified is True


def test_allocation_intent_precedes_platform_begin_and_roles_are_exact():
    case = _wrapped()
    bundle = _execute(case)
    events = case["events"]
    assert events.index("journal:allocation_started") < events.index("begin")
    assert events.index("journal:commit_started") < events.index("commit")
    assert events.index("commit") < events.index("journal:committed")
    records = [
        row for row in case["journal"].documents if row.get("event_type") == "role_allocated"
    ]
    assert tuple(row["role"] for row in records) == tuple(row.role for row in bundle.resources)
    assert len({row["owner_ref"] for row in records}) == len(bundle.resources)


def test_committed_resources_retain_original_owners_and_refuse_abort():
    case = _wrapped()
    transaction = _begin(case)
    resources = transaction.allocate()
    assert resources is case["execution_factory"].transaction.resources
    transaction.commit()
    with pytest.raises(InstalledStrixV2CompositionError, match="runtime lifecycle"):
        transaction.close()
    assert case["journal"].load_transaction(transaction.transaction_ref).state == "active"


def test_close_without_observer_never_promotes_owner_flags_to_absence():
    case = _wrapped(observer=False)
    transaction = _begin(case)
    transaction.allocate()
    with pytest.raises(InstalledStrixV2CompositionError, match="observer"):
        transaction.close()
    assert case["journal"].load_transaction(transaction.transaction_ref).state == "cleanup_unknown"
    assert "journal:cleaned" not in case["events"]


def test_mismatched_independent_observation_is_unknown():
    case = _wrapped(mismatch=True)
    transaction = _begin(case)
    transaction.allocate()
    with pytest.raises(InstalledStrixV2CompositionError, match="binding changed"):
        transaction.close()
    assert case["journal"].load_transaction(transaction.transaction_ref).state == "cleanup_unknown"
    assert "journal:absence_observed" not in case["events"]


def test_partial_allocation_failure_retains_platform_abort_and_independent_proof():
    case = _wrapped()
    case["execution_factory"].changes["fail_allocate"] = True
    transaction = _begin(case)
    with pytest.raises(RuntimeError, match="partial allocation"):
        transaction.allocate()
    receipt = transaction.close()
    assert receipt.transaction_ref == transaction.transaction_ref
    assert "revoke-reconcile:maintained-model-lease" in case["events"]
    assert case["events"].index("abort") < case["events"].index("observe:absent")


def test_concurrent_prepared_execution_transactions_have_one_allocation_cas():
    case = _wrapped()
    first, second = _begin(case), _begin(case)
    first.allocate()
    with pytest.raises(RuntimeError, match="CAS lost"):
        second.allocate()
    assert case["events"].count("allocate") == 1


def test_historical_reopen_requires_deterministic_exact_cleanup_roles():
    case = _wrapped()
    saved_record, reconciliation_ref, *_ = _prepare_reconciliation(case)
    factory = case["reconciliation_factory"]
    original_begin = factory.begin_reconciliation

    def begin(**arguments):
        transaction = original_begin(**arguments)
        original_reopen = transaction.reopen

        def reopen():
            result = original_reopen()
            assert result.cleanup_owner is not None
            rows = tuple(
                replace(
                    row,
                    binding_ref=installed_strix_v2_reconciliation_binding_ref(
                        authority_ref=arguments["snapshot"].authority_ref,
                        activation_ref=arguments["snapshot"].activation.receipt_ref,
                        reconciliation_ref=reconciliation_ref,
                        role=row.role,
                    ),
                )
                for row in result.resources
            )
            return InstalledStrixV2ReopenedResources(
                rows,
                InstalledStrixV2ResourceReceipt.create(
                    action="reopened",
                    authority_ref=arguments["snapshot"].authority_ref,
                    activation_receipt_ref=arguments["snapshot"].activation.receipt_ref,
                    reconciliation_ref=reconciliation_ref,
                    role_bindings=tuple((row.role, row.binding_ref) for row in rows),
                ),
                _TestCleanupOwner(
                    attempt_ref=result.cleanup_owner.attempt_ref,
                    activation_ref=result.cleanup_owner.activation_ref,
                    runtime_activation_ref=result.cleanup_owner.runtime_activation_ref,
                    runtime_resolution_ref=result.cleanup_owner.runtime_resolution_ref,
                    resources=rows,
                ),
            )

        transaction.reopen = reopen
        return transaction

    factory.begin_reconciliation = begin
    bundle = _reconcile(case, saved_record, reconciliation_ref)
    assert "allocate" not in case["events"]
    assert "begin" not in case["events"]
    for row in bundle.resources:
        assert not callable(getattr(row.owner, "launch", None))
        assert not callable(getattr(row.owner, "connect", None))
    assert next(iter(case["journal"].heads.values())).state == "active"


def test_cleanup_proof_persistence_retry_retains_observation_and_does_not_reclose():
    case = _wrapped()
    transaction = _begin(case)
    transaction.allocate()
    case["journal"].fail_event = "absence_observed"
    with pytest.raises(RuntimeError, match="journal unavailable"):
        transaction.close()
    receipt = transaction.close()
    assert receipt.transaction_ref == transaction.transaction_ref
    assert case["events"].count("abort") == 1
    assert case["events"].count("observe:absent") == 1
    assert case["journal"].load_transaction(transaction.transaction_ref).state == "closed"
