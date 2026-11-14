"""ProductStore journal fences around protected installed Strix V2 resources.

The repository persists intent before any platform call. Platform transactions
retain partial effects; the separate absence observer proves their cleanup.
No successful close call or mutable owner flag is promoted into absence proof.
After successful commit the runtime retains the original resource owners; its
settlement and final shutdown are a separate lifecycle lane.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any, Protocol

from .engine_container_custody import ContainerCustodyPlanV2
from .engine_installed_attempt_factory import (
    INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES,
    INSTALLED_STRIX_RECONCILIATION_RESOURCE_ROLES,
    InstalledControlledStrixRuntimeIdentity,
)
from .engine_installed_v2_authority import (
    InstalledStrixV2ActivationReceipt,
    InstalledStrixV2CompositionError,
    InstalledStrixV2HistoricalSnapshot,
    InstalledStrixV2PrelaunchSnapshot,
    _digest,
)
from .engine_installed_v2_resources import (
    InstalledStrixV2CleanupReceipt,
    InstalledStrixV2ExecutionResources,
    InstalledStrixV2ReopenedResources,
)
from .engine_network_policy import EngineNetworkPlanV2
from .strix_controlled_runtime_admission import build_controlled_launch_plan
from .util import content_hash, parse_iso8601_datetime

if TYPE_CHECKING:
    from .product_store import ProductStore


@dataclass(frozen=True, slots=True)
class InstalledStrixV2TransactionHead:
    transaction_ref: str
    generation: int
    state: str


class InstalledStrixV2TransactionRepository(Protocol):
    def require_product_store(self, product_store: ProductStore) -> None: ...

    def require_absence_observer(
        self, observer: InstalledStrixV2CleanupAbsenceObserver | None
    ) -> None: ...

    def prepare_transaction(
        self,
        *,
        attempt_id: str,
        transaction_ref: str,
        authority_ref: str,
        activation_ref: str,
        action: str,
        reconciliation_ref: str | None,
        document: Mapping[str, Any],
    ) -> InstalledStrixV2TransactionHead: ...

    def append_event(
        self,
        *,
        transaction_ref: str,
        expected_generation: int,
        event_type: str,
        state: str,
        document: Mapping[str, Any],
        role: str | None = None,
        owner_ref: str | None = None,
        binding_ref: str | None = None,
        receipt_ref: str | None = None,
    ) -> InstalledStrixV2TransactionHead: ...

    def load_transaction(self, transaction_ref: str) -> InstalledStrixV2TransactionHead: ...

    def record_absence(
        self,
        *,
        transaction_ref: str,
        expected_generation: int,
        document: Mapping[str, Any],
    ) -> InstalledStrixV2TransactionHead: ...


class InstalledStrixV2CleanupAbsenceObserver(Protocol):
    """An independently retained platform observer, never supplied by requests."""

    @property
    def observer_identity_ref(self) -> str: ...

    @property
    def observer_generation(self) -> int: ...

    def observe_absence(
        self,
        *,
        transaction_ref: str,
        authority_ref: str,
        activation_ref: str,
        action: str,
        reconciliation_ref: str | None,
        role_bindings: tuple[tuple[str, str, str], ...],
    ) -> Mapping[str, Any]: ...

    def reopen_absence(self, *, observation_ref: str) -> Mapping[str, Any]:
        """Reopen protected, independently observed platform absence by receipt ref."""
        ...


def installed_strix_v2_reconciliation_binding_ref(
    *,
    authority_ref: str,
    activation_ref: str,
    reconciliation_ref: str,
    role: str,
) -> str:
    if role not in INSTALLED_STRIX_RECONCILIATION_RESOURCE_ROLES:
        raise InstalledStrixV2CompositionError("V2 historical resource role is invalid")
    return content_hash(
        {
            "schema_version": "bluefire.installed-strix-v2-reconciliation-binding.v1",
            "authority_ref": _digest(authority_ref, "V2 historical authority"),
            "activation_ref": _digest(activation_ref, "V2 historical activation"),
            "reconciliation_ref": _digest(reconciliation_ref, "V2 reconciliation"),
            "role": role,
        }
    )


def installed_strix_v2_prelaunch_binding_ref(*, prelaunch_ref: str, role: str) -> str:
    if role not in INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES:
        raise InstalledStrixV2CompositionError("V2 execution resource role is invalid")
    return content_hash(
        {
            "schema_version": "bluefire.installed-strix-v2-prelaunch-resource-binding.v1",
            "prelaunch_ref": _digest(prelaunch_ref, "V2 prelaunch authority"),
            "role": role,
        }
    )


class ProductStoreInstalledStrixV2ResourceFactory:
    """Store-bound wrappers for allocation and cleanup-only historical reopen."""

    def __init__(
        self,
        *,
        product_store: ProductStore,
        repository: InstalledStrixV2TransactionRepository,
        execution_resources: object,
        reconciliation_resources: object,
        absence_observer: InstalledStrixV2CleanupAbsenceObserver | None = None,
    ) -> None:
        if product_store is None:
            raise InstalledStrixV2CompositionError("V2 resource store is required")
        for owner, methods in (
            (
                repository,
                (
                    "require_product_store",
                    "prepare_transaction",
                    "append_event",
                    "load_transaction",
                    "record_absence",
                    "require_absence_observer",
                ),
            ),
            (execution_resources, ("begin_execution",)),
            (reconciliation_resources, ("begin_reconciliation",)),
        ):
            if any(not callable(getattr(owner, name, None)) for name in methods):
                raise InstalledStrixV2CompositionError("V2 resource dependency is incomplete")
        repository.require_product_store(product_store)
        repository.require_absence_observer(absence_observer)
        self._store = product_store
        self._repository = repository
        self._execution = execution_resources
        self._reconciliation = reconciliation_resources
        self._observer = absence_observer
        self._observer_identity = None
        self._observer_generation = None
        if absence_observer is not None:
            self._observer_identity = _digest(
                absence_observer.observer_identity_ref, "V2 cleanup observer identity"
            )
            generation = absence_observer.observer_generation
            if (
                type(generation) is not int
                or generation < 1
                or not callable(getattr(absence_observer, "observe_absence", None))
                or not callable(getattr(absence_observer, "reopen_absence", None))
            ):
                raise InstalledStrixV2CompositionError("V2 cleanup observer is invalid")
            self._observer_generation = generation

    def begin_execution(
        self, *, product_store: ProductStore, snapshot, launch_plan, authority_guard
    ):
        self._require_store(product_store)
        if not isinstance(snapshot, InstalledStrixV2PrelaunchSnapshot):
            raise InstalledStrixV2CompositionError("V2 prelaunch snapshot is invalid")
        # A matching, caller-retained ref is not proof that the accepted claim,
        # runtime authority and admission are still live in this ProductStore.
        if (
            authority_guard.authority_ref != snapshot.prelaunch_ref
            or authority_guard.require_prelaunch_current() != snapshot
        ):
            raise InstalledStrixV2CompositionError("V2 execution authority changed")
        expected_plan = build_controlled_launch_plan(
            snapshot.admission,
            expected_admission_ref=snapshot.admission.admission_ref,
            expected_execution_claim_ref=snapshot.admission.to_dict()[
                "accepted_execution_claim_ref"
            ],
        )
        if launch_plan != expected_plan:
            raise InstalledStrixV2CompositionError("V2 resource launch plan changed")
        return _ExecutionTransaction(
            self,
            snapshot,
            {
                "product_store": self._store,
                "snapshot": snapshot,
                "launch_plan": launch_plan,
                "authority_guard": authority_guard,
            },
        )

    def begin_reconciliation(
        self, *, product_store: ProductStore, snapshot, saved_record, reconciliation_ref
    ):
        self._require_store(product_store)
        if not isinstance(snapshot, InstalledStrixV2HistoricalSnapshot):
            raise InstalledStrixV2CompositionError("V2 historical snapshot is invalid")
        if (
            snapshot.reconciliation_ref != reconciliation_ref
            or snapshot.saved_record_ref != content_hash(saved_record.to_dict())
        ):
            raise InstalledStrixV2CompositionError("V2 historical saved record changed")
        return _ReconciliationTransaction(
            self,
            snapshot,
            {
                "product_store": self._store,
                "snapshot": snapshot,
                "saved_record": saved_record,
                "reconciliation_ref": reconciliation_ref,
            },
        )

    def _require_store(self, product_store):
        if product_store is not self._store:
            raise InstalledStrixV2CompositionError("V2 resources belong to another service")


class _ResourceTransaction:
    def __init__(self, factory, snapshot, arguments, *, action):
        self._factory = factory
        self._snapshot = snapshot
        self._arguments = arguments
        self._action = action
        self._authority_ref = (
            snapshot.prelaunch_ref if action == "execution" else snapshot.authority_ref
        )
        self._activation_ref = None if action == "execution" else snapshot.activation.receipt_ref
        self._reconciliation_ref = arguments.get("reconciliation_ref")
        self._bindings = (
            tuple(
                (
                    role,
                    installed_strix_v2_prelaunch_binding_ref(
                        prelaunch_ref=self._authority_ref,
                        role=role,
                    ),
                )
                for role in INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES
            )
            if action == "execution"
            else tuple(
                (
                    role,
                    installed_strix_v2_reconciliation_binding_ref(
                        authority_ref=self._authority_ref,
                        activation_ref=self._activation_ref,
                        reconciliation_ref=self._reconciliation_ref,
                        role=role,
                    ),
                )
                for role in INSTALLED_STRIX_RECONCILIATION_RESOURCE_ROLES
            )
        )
        document = {
            "schema_version": "bluefire.installed-strix-v2-resource-transaction.v1",
            "action": action,
            "authority_ref": self._authority_ref,
            "activation_ref": self._activation_ref,
            "reconciliation_ref": self._reconciliation_ref,
            "role_bindings": [{"role": role, "binding_ref": ref} for role, ref in self._bindings],
            "constraints": (
                {
                    "mode": "execution",
                    "budgets": snapshot.admission.to_dict()["budgets"],
                    "scope": snapshot.admission.to_dict()["scope"],
                    "network_policy_digest": EngineNetworkPlanV2.from_mapping(
                        snapshot.admission.to_dict()["network_plan"]
                    ).policy_digest,
                    "custody_plan_digest": ContainerCustodyPlanV2.from_mapping(
                        snapshot.admission.to_dict()["custody_plan"]
                    ).plan_digest,
                    "controlled_launch_digest": arguments["launch_plan"].launch_digest,
                    "scope_ref": snapshot.admission.to_dict()["scope"]["scope_digest"],
                }
                if action == "execution"
                else {
                    "mode": "cleanup_only",
                    "saved_record_ref": snapshot.saved_record_ref,
                    "reconciliation_ref": self._reconciliation_ref,
                    "activation_ref": self._activation_ref,
                }
            ),
        }
        self._transaction_ref = content_hash(document)
        document["transaction_ref"] = self._transaction_ref
        self._owner_bindings = tuple(
            (
                role,
                binding,
                content_hash(
                    {
                        "schema_version": "bluefire.installed-strix-v2-resource-owner.v1",
                        "transaction_ref": self._transaction_ref,
                        "role": role,
                        "binding_ref": binding,
                    }
                ),
            )
            for role, binding in self._bindings
        )
        document["owners"] = self._binding_document()
        attempt_id = (
            snapshot.admission.to_dict()["attempt_id"]
            if action == "execution"
            else arguments["saved_record"].binding.attempt_id
        )
        self._head = factory._repository.prepare_transaction(
            attempt_id=attempt_id,
            transaction_ref=self._transaction_ref,
            authority_ref=self._authority_ref,
            activation_ref=self._activation_ref,
            action=action,
            reconciliation_ref=self._reconciliation_ref,
            document=document,
        )
        self._check_head(self._head)
        if self._head.state != "prepared":
            raise InstalledStrixV2CompositionError("V2 resource transaction was already consumed")
        self._lock = threading.RLock()
        self._effects_started = False
        self._inner = None
        self._inner_closed = False
        self._observation = None
        self._resources = None
        self._committed = False
        self._cleanup_receipt = None
        self._close_started = False

    @property
    def transaction_ref(self):
        return self._transaction_ref

    @property
    def effects_started(self):
        return self._effects_started

    def _binding_document(self):
        return [
            {"role": role, "binding_ref": binding, "owner_ref": owner}
            for role, binding, owner in self._owner_bindings
        ]

    def _check_head(self, head):
        if (
            not isinstance(head, InstalledStrixV2TransactionHead)
            or head.transaction_ref != self.transaction_ref
            or type(head.generation) is not int
            or head.generation < 1
        ):
            raise InstalledStrixV2CompositionError("V2 resource journal head changed")

    def _append(
        self,
        event_type,
        state,
        *,
        document=None,
        role=None,
        binding_ref=None,
        owner_ref=None,
        receipt_ref=None,
        refresh=True,
    ):
        head = (
            self._factory._repository.load_transaction(self.transaction_ref)
            if refresh
            else self._head
        )
        self._check_head(head)
        self._head = self._factory._repository.append_event(
            transaction_ref=self.transaction_ref,
            expected_generation=head.generation,
            event_type=event_type,
            state=state,
            document=document or {},
            role=role,
            binding_ref=binding_ref,
            owner_ref=owner_ref,
            receipt_ref=receipt_ref,
        )
        self._check_head(self._head)

    def _open(self):
        with self._lock:
            if self._effects_started or self._close_started:
                raise InstalledStrixV2CompositionError("V2 resource transaction is consumed")
            if self._action == "execution" and (
                self._arguments["authority_guard"].require_prelaunch_current() != self._snapshot
            ):
                raise InstalledStrixV2CompositionError("V2 execution authority changed")
            # From this point, a lost journal acknowledgement is ambiguous.
            # Require independent absence even if the platform call never ran.
            self._effects_started = True
            self._append("allocation_started", "allocating", refresh=False)
            factory = (
                self._factory._execution
                if self._action == "execution"
                else self._factory._reconciliation
            )
            method = (
                factory.begin_execution
                if self._action == "execution"
                else factory.begin_reconciliation
            )
            self._inner = method(
                **self._arguments,
                resource_transaction_ref=self.transaction_ref,
                resource_owner_bindings=self._owner_bindings,
            )
            if getattr(self._inner, "effects_started", None) is not False:
                raise InstalledStrixV2CompositionError("V2 platform begin started effects")
            if getattr(self._inner, "transaction_ref", None) != self.transaction_ref:
                raise InstalledStrixV2CompositionError(
                    "V2 platform transaction differs from durable resource intent"
                )
            for method_name in (
                ("allocate", "commit", "close")
                if self._action == "execution"
                else ("reopen", "commit", "close")
            ):
                if not callable(getattr(self._inner, method_name, None)):
                    raise InstalledStrixV2CompositionError("V2 platform transaction is incomplete")
            allocated = (
                self._inner.allocate() if self._action == "execution" else self._inner.reopen()
            )
            if self._action == "execution":
                if (
                    type(allocated) is not tuple
                    or len(allocated) != 3
                    or not isinstance(allocated[1], InstalledStrixV2ActivationReceipt)
                    or not isinstance(allocated[2], InstalledControlledStrixRuntimeIdentity)
                ):
                    raise InstalledStrixV2CompositionError(
                        "V2 platform allocation lacks observed activation"
                    )
                resources, activation, identity = allocated
            else:
                resources = allocated
                activation = self._snapshot.activation
                identity = None
            self._resources = resources  # retain every returned handle before validation
            self._validate(resources, activation)
            rows = resources.resources
            if tuple(row.role for row in rows) != tuple(role for role, _ref in self._bindings):
                raise InstalledStrixV2CompositionError("V2 resource roles changed")
            if (
                self._action == "reconciliation"
                and tuple((row.role, row.binding_ref) for row in rows) != self._bindings
            ):
                raise InstalledStrixV2CompositionError("V2 historical role binding changed")
            if len({row.binding_ref for row in rows}) != len(rows):
                raise InstalledStrixV2CompositionError("V2 resource roles share a binding")
            if len({id(row.owner) for row in rows}) != len(rows):
                raise InstalledStrixV2CompositionError("V2 resource roles share an owner")
            if self._action == "execution":
                if activation.admission_ref != self._snapshot.admission.admission_ref:
                    raise InstalledStrixV2CompositionError("V2 observed admission changed")
                retained = self._arguments["authority_guard"].retain_activation(
                    admission_ref=activation.admission_ref,
                    activation_ref=activation.receipt_ref,
                    resource_transaction_ref=self.transaction_ref,
                    observed_identity_ref=content_hash(asdict(identity)),
                )
                if retained.activation != activation:
                    raise InstalledStrixV2CompositionError(
                        "V2 retained activation differs from owners"
                    )
                self._activation_ref = activation.receipt_ref
                self._append(
                    "activation_recorded",
                    "allocating",
                    receipt_ref=self._activation_ref,
                    document={
                        "activation_ref": self._activation_ref,
                        "identity_ref": content_hash(asdict(identity)),
                        "resource_receipt_ref": resources.receipt.receipt_ref,
                    },
                )
            for role, binding, owner in self._owner_bindings:
                actual = next(row.binding_ref for row in rows if row.role == role)
                receipt = content_hash(
                    {
                        "schema_version": "bluefire.installed-strix-v2-role-allocation.v1",
                        "transaction_ref": self.transaction_ref,
                        "role": role,
                        "binding_ref": binding,
                        "owner_ref": owner,
                        "resource_receipt_ref": resources.receipt.receipt_ref,
                        "actual_binding_ref": actual,
                    }
                )
                self._append(
                    "role_allocated",
                    "allocating",
                    role=role,
                    binding_ref=binding,
                    owner_ref=owner,
                    receipt_ref=receipt,
                    document={
                        "resource_receipt_ref": resources.receipt.receipt_ref,
                        "actual_binding_ref": actual,
                    },
                )
            self._append(
                "allocated",
                "allocated",
                receipt_ref=resources.receipt.receipt_ref,
                document=resources.receipt.document(),
            )
            return resources

    def _validate(self, resources, activation):
        if self._action == "execution":
            if not isinstance(resources, InstalledStrixV2ExecutionResources):
                raise InstalledStrixV2CompositionError("V2 allocated resources are invalid")
            if resources.authority_guard is not self._arguments["authority_guard"]:
                raise InstalledStrixV2CompositionError("V2 resource authority owner changed")
            resources.validate(activation)
        else:
            if not isinstance(resources, InstalledStrixV2ReopenedResources):
                raise InstalledStrixV2CompositionError("V2 reopened resources are invalid")
            resources.validate(
                activation=self._snapshot.activation,
                authority_ref=self._authority_ref,
                reconciliation_ref=self._reconciliation_ref,
            )

    def commit(self):
        with self._lock:
            if self._committed or self._close_started or self._resources is None:
                raise InstalledStrixV2CompositionError("V2 resource commit is unavailable")
            self._append("commit_started", "committing")
            self._inner.commit()
            self._append("committed", "active")
            self._committed = True

    def _begin_cleanup(self):
        if not self._close_started:
            self._append("cleanup_started", "stopping")
            self._close_started = True

    def _unknown(self):
        self._append("cleanup_unknown", "cleanup_unknown")

    def _observe(self):
        if self._observation is not None:
            self._head = self._factory._repository.record_absence(
                transaction_ref=self.transaction_ref,
                expected_generation=self._factory._repository.load_transaction(
                    self.transaction_ref
                ).generation,
                document=self._observation,
            )
            self._check_head(self._head)
            return
        observer = self._factory._observer
        if observer is None:
            raise InstalledStrixV2CompositionError("V2 independent cleanup observer is unavailable")
        if (
            observer.observer_identity_ref != self._factory._observer_identity
            or type(observer.observer_generation) is not int
            or observer.observer_generation != self._factory._observer_generation
        ):
            raise InstalledStrixV2CompositionError("V2 cleanup observer generation changed")
        action = self._action + "_abort"
        result = dict(
            observer.observe_absence(
                transaction_ref=self.transaction_ref,
                authority_ref=self._authority_ref,
                activation_ref=self._activation_ref,
                action=action,
                reconciliation_ref=self._reconciliation_ref,
                role_bindings=self._owner_bindings,
            )
        )
        expected = {
            "schema_version": "bluefire.installed-strix-v2-cleanup-absence.v1",
            "transaction_ref": self.transaction_ref,
            "authority_ref": self._authority_ref,
            "activation_ref": self._activation_ref,
            "action": action,
            "reconciliation_ref": self._reconciliation_ref,
            "role_bindings": self._binding_document(),
            "observer_identity_ref": self._factory._observer_identity,
            "observer_generation": self._factory._observer_generation,
            "state": "absent",
        }
        if set(result) != set(expected) | {"observed_at", "observation_ref"}:
            raise InstalledStrixV2CompositionError("V2 cleanup observation fields changed")
        if type(result["observer_generation"]) is not int or any(
            result[name] != value for name, value in expected.items()
        ):
            raise InstalledStrixV2CompositionError("V2 cleanup observation binding changed")
        parse_iso8601_datetime(result["observed_at"])
        document = {key: value for key, value in result.items() if key != "observation_ref"}
        if result["observation_ref"] != content_hash(document):
            raise InstalledStrixV2CompositionError("V2 cleanup observation digest changed")
        self._observation = result
        self._head = self._factory._repository.record_absence(
            transaction_ref=self.transaction_ref,
            expected_generation=self._factory._repository.load_transaction(
                self.transaction_ref
            ).generation,
            document=result,
        )
        self._check_head(self._head)

    def _finish_cleanup(self):
        if self._effects_started:
            self._observe()
        receipt = InstalledStrixV2CleanupReceipt.create(
            action=self._action + "_abort",
            transaction_ref=self.transaction_ref,
            authority_ref=self._authority_ref,
            activation_receipt_ref=self._activation_ref,
            reconciliation_ref=self._reconciliation_ref,
        )
        self._append(
            "cleaned", "closed", document=receipt.document(), receipt_ref=receipt.receipt_ref
        )
        self._cleanup_receipt = receipt
        return receipt

    def close(self):
        with self._lock:
            if self._committed:
                raise InstalledStrixV2CompositionError(
                    "V2 committed resources belong to the runtime lifecycle owner"
                )
            if self._cleanup_receipt is not None:
                return self._cleanup_receipt
            self._begin_cleanup()
            try:
                if self._inner is not None and not self._inner_closed:
                    # The platform transaction retains partial allocations even when
                    # allocate/reopen raised before returning any resource bundle.
                    self._inner.close()
                    self._inner_closed = True
                return self._finish_cleanup()
            except BaseException:
                try:
                    self._unknown()
                except Exception:
                    # Preserve the original failure even when storage itself is
                    # unavailable; the prior durable intent remains unresolved.
                    pass
                raise


class _ExecutionTransaction(_ResourceTransaction):
    def __init__(self, factory, snapshot, arguments):
        super().__init__(factory, snapshot, arguments, action="execution")

    def allocate(self):
        return self._open()


class _ReconciliationTransaction(_ResourceTransaction):
    def __init__(self, factory, snapshot, arguments):
        super().__init__(factory, snapshot, arguments, action="reconciliation")

    def reopen(self):
        return self._open()


__all__ = [
    "InstalledStrixV2CleanupAbsenceObserver",
    "InstalledStrixV2TransactionHead",
    "InstalledStrixV2TransactionRepository",
    "ProductStoreInstalledStrixV2ResourceFactory",
    "installed_strix_v2_reconciliation_binding_ref",
]
