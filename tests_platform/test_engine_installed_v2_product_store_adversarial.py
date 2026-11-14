"""Fault injection at the durable journal/platform owner boundary; no launches."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from types import SimpleNamespace

import pytest

from bluefire.engine_installed_attempt_factory import (
    INSTALLED_STRIX_RECONCILIATION_RESOURCE_ROLES,
    InstalledStrixOwnedResource,
)
from bluefire.engine_installed_v2_authority import (
    InstalledStrixV2AuthorityGuard,
    InstalledStrixV2CompositionError,
    InstalledStrixV2PrelaunchSnapshot,
)
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
    _AuthoritySource,
    _case,
    _ExecutionFactory,
    _openers,
    _Owner,
    _prepare_reconciliation,
    _runtime_identity,
)


class _Crash(BaseException):
    pass


class _Journal:
    """Protocol fake retains acknowledged writes across wrapper reconstruction."""

    def __init__(self, store):
        self.store = store
        self.heads = {}
        self.events = []
        self.crash_after = None
        self.observer = None

    def require_product_store(self, store):
        if store is not self.store:
            raise InstalledStrixV2CompositionError("journal belongs to another ProductStore")

    def require_absence_observer(self, observer):
        self.observer = observer

    def prepare_transaction(self, **values):
        ref = values["transaction_ref"]
        if ref not in self.heads:
            self.heads[ref] = InstalledStrixV2TransactionHead(ref, 1, "prepared")
            self.events.append({"event_type": "prepared", **values})
        return self.heads[ref]

    def append_event(self, **values):
        ref = values["transaction_ref"]
        old = self.heads[ref]
        assert old.generation == values["expected_generation"]
        self.heads[ref] = replace(old, generation=old.generation + 1, state=values["state"])
        self.events.append(values)
        if values["event_type"] == self.crash_after:
            self.crash_after = None
            raise _Crash("lost journal acknowledgement")
        return self.heads[ref]

    def load_transaction(self, ref):
        return self.heads[ref]

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


class _Observer:
    observer_identity_ref = content_hash("independent cleanup observer")
    observer_generation = 1

    def __init__(self):
        self.calls = []
        self.change = None
        self.documents = {}

    def observe_absence(self, **values):
        self.calls.append(values)
        document = {
            "schema_version": "bluefire.installed-strix-v2-cleanup-absence.v1",
            **{key: value for key, value in values.items() if key != "role_bindings"},
            "role_bindings": [
                {"role": role, "binding_ref": binding, "owner_ref": owner}
                for role, binding, owner in values["role_bindings"]
            ],
            "observer_identity_ref": self.observer_identity_ref,
            "observer_generation": self.observer_generation,
            "state": "absent",
            "observed_at": "2026-11-05T12:00:00Z",
        }
        if self.change:
            document.update(self.change)
        retained = {**document, "observation_ref": content_hash(document)}
        self.documents[retained["observation_ref"]] = retained
        return retained

    def reopen_absence(self, *, observation_ref):
        return self.documents[observation_ref]


class _HistoricalFactory:
    def __init__(self, events):
        self.events = events
        self.calls = []
        self.foreign_binding = False

    def begin_reconciliation(self, **values):
        self.calls.append(values)
        snapshot = values["snapshot"]
        ref = values["reconciliation_ref"]
        bindings = tuple(
            (
                role,
                installed_strix_v2_reconciliation_binding_ref(
                    authority_ref=snapshot.authority_ref,
                    activation_ref=snapshot.activation.receipt_ref,
                    reconciliation_ref=content_hash("foreign") if self.foreign_binding else ref,
                    role=role,
                ),
            )
            for role in INSTALLED_STRIX_RECONCILIATION_RESOURCE_ROLES
        )

        def reopen():
            self.events.append("historical-reopen")
            rows = tuple(
                InstalledStrixOwnedResource(role, binding, _Owner(self.events, role))
                for role, binding in bindings
            )
            receipt = InstalledStrixV2ResourceReceipt.create(
                action="reopened",
                authority_ref=snapshot.authority_ref,
                activation_receipt_ref=snapshot.activation.receipt_ref,
                role_bindings=bindings,
                reconciliation_ref=ref,
            )
            return InstalledStrixV2ReopenedResources(rows, receipt)

        return SimpleNamespace(
            effects_started=False,
            transaction_ref=values["resource_transaction_ref"],
            reopen=reopen,
            commit=lambda: self.events.append("historical-commit"),
            close=lambda: self.events.append("historical-close"),
        )


def _fixture():
    binding, delegation, accepted, plan, snapshot = _case()
    store = object()
    events = []
    journal = _Journal(store)
    observer = _Observer()
    execution = _ExecutionFactory(events)
    execution.activation = snapshot.activation
    execution.observed_identity = _runtime_identity(
        accepted,
        binding,
        delegation,
        snapshot,
        plan,
    )
    historical = _HistoricalFactory(events)
    factory = ProductStoreInstalledStrixV2ResourceFactory(
        product_store=store,
        repository=journal,
        execution_resources=execution,
        reconciliation_resources=historical,
        absence_observer=observer,
    )
    guard = InstalledStrixV2AuthorityGuard(
        product_store=store,
        source=_AuthoritySource([snapshot]),
        accepted=accepted,
        binding=binding,
        delegation=delegation,
    )
    prelaunch = InstalledStrixV2PrelaunchSnapshot(snapshot.resolution_ref, snapshot.admission)
    guard.require_prelaunch_current()
    values = dict(product_store=store, snapshot=prelaunch, launch_plan=plan, authority_guard=guard)
    return SimpleNamespace(**locals())


def test_store_and_repository_owner_swaps_are_refused_before_platform_begin():
    f = _fixture()
    with pytest.raises(InstalledStrixV2CompositionError, match="another service"):
        f.factory.begin_execution(**{**f.values, "product_store": object()})
    with pytest.raises(InstalledStrixV2CompositionError, match="another ProductStore"):
        ProductStoreInstalledStrixV2ResourceFactory(
            product_store=object(),
            repository=f.journal,
            execution_resources=f.execution,
            reconciliation_resources=f.historical,
        )
    assert f.events == [] and f.journal.events == []


@pytest.mark.parametrize(
    "event", ["allocation_started", "role_allocated", "allocated", "committed"]
)
def test_crash_after_durable_intent_effect_or_receipt_never_reallocates(event):
    f = _fixture()
    transaction = f.factory.begin_execution(**f.values)
    f.journal.crash_after = event
    with pytest.raises(_Crash):
        transaction.allocate()
        transaction.commit()
    before = list(f.events)
    restarted = ProductStoreInstalledStrixV2ResourceFactory(
        product_store=f.store,
        repository=f.journal,
        execution_resources=f.execution,
        reconciliation_resources=f.historical,
        absence_observer=f.observer,
    )
    with pytest.raises(InstalledStrixV2CompositionError, match="already consumed"):
        restarted.begin_execution(**f.values)
    assert f.events == before
    assert f.events.count("allocate") == (0 if event == "allocation_started" else 1)


@pytest.mark.parametrize(
    "field", ["authority_ref", "activation_ref", "transaction_ref", "role_bindings", "state"]
)
def test_cleanup_requires_exact_independent_absence_observation(field):
    f = _fixture()
    transaction = f.factory.begin_execution(**f.values)
    transaction.allocate()
    f.observer.change = {field: [] if field == "role_bindings" else content_hash("foreign")}
    with pytest.raises(InstalledStrixV2CompositionError, match="binding changed"):
        transaction.close()
    assert f.journal.load_transaction(transaction.transaction_ref).state == "cleanup_unknown"
    assert not any(event["event_type"] == "cleaned" for event in f.journal.events)


@pytest.mark.parametrize("failure", ["missing", "generation", "identity"])
def test_successful_platform_close_cannot_prove_absence(failure):
    f = _fixture()
    transaction = f.factory.begin_execution(**f.values)
    transaction.allocate()
    if failure == "missing":
        f.factory._observer = None
    elif failure == "generation":
        f.observer.observer_generation += 1
    else:
        f.observer.observer_identity_ref = content_hash("replacement observer")
    with pytest.raises(InstalledStrixV2CompositionError):
        transaction.close()
    assert "abort" in f.events
    assert f.journal.load_transaction(transaction.transaction_ref).state == "cleanup_unknown"


def test_concurrent_repeated_abort_closes_once_and_proves_absence_once():
    f = _fixture()
    transaction = f.factory.begin_execution(**f.values)
    transaction.allocate()
    with ThreadPoolExecutor(max_workers=8) as executor:
        receipts = list(executor.map(lambda _: transaction.close(), range(16)))
    assert all(receipt is receipts[0] for receipt in receipts)
    assert f.journal.load_transaction(transaction.transaction_ref).state == "closed"
    assert len(f.observer.calls) == 1
    assert len([event for event in f.journal.events if event["event_type"] == "cleaned"]) == 1
    for role, _binding in f.snapshot.activation.role_bindings:
        assert f.events.count("close:" + role) == 1


@pytest.mark.parametrize("foreign_binding", [False, True])
def test_historical_resource_reopen_has_no_launch_material_and_exact_bindings(foreign_binding):
    f = _fixture()
    case = _openers()
    saved_record, ref = _prepare_reconciliation(case)[:2]
    snapshot = case["source"].reconciliation
    f.historical.foreign_binding = foreign_binding
    transaction = f.factory.begin_reconciliation(
        product_store=f.store,
        snapshot=snapshot,
        saved_record=saved_record,
        reconciliation_ref=ref,
    )
    if foreign_binding:
        with pytest.raises(InstalledStrixV2CompositionError, match="role binding changed"):
            transaction.reopen()
    else:
        transaction.reopen()
        transaction.commit()
        with pytest.raises(InstalledStrixV2CompositionError, match="runtime lifecycle"):
            transaction.close()
    assert len(f.historical.calls) == 1
    assert set(f.historical.calls[0]) == {
        "product_store",
        "snapshot",
        "saved_record",
        "reconciliation_ref",
        "resource_transaction_ref",
        "resource_owner_bindings",
    }
    assert f.historical.calls[0]["resource_transaction_ref"] == transaction.transaction_ref
    assert (
        tuple(role for role, _binding, _owner in f.historical.calls[0]["resource_owner_bindings"])
        == INSTALLED_STRIX_RECONCILIATION_RESOURCE_ROLES
    )
    assert "begin" not in f.events and "allocate" not in f.events and "commit" not in f.events
