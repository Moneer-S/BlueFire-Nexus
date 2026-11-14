"""Controller-only durable ownership of the fixed tenant-record generations.

Construction is an installed-controller boundary. Neither the source protocol
nor its operations accept paths, commands, packet bytes, or bearer material.
The existing protected ProductStore is the only persistence owner. Its private
tenant-generation tables are separate from public experiment/resource history.
An interrupted operation is consumed forever; reconciliation only settles its
exact retained lifecycle and never completes a launch or creates a successor.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, cast

from .controlled_strix_provider import ControlledProviderManifest
from .product_store_tenant_generation_journals import JOURNAL_SCHEMA, JournalValidator
from .runner_private_files import _PinnedPrivateDirectory
from .tenant_record_lab import TenantDefenseConfig
from .tenant_record_lab_launcher import (
    LifecycleCommit,
    LifecycleSink,
    LifecycleState,
    ServiceRole,
    TenantLabLaunchPlan,
    TenantLabLifecycleRecord,
    TenantLabPackets,
    TenantLabStartFailure,
    WorkspaceLayout,
)
from .tenant_record_target_adapter import (
    TenantBoundAuditReceipt,
    TenantControllerAdmission,
    TenantGenerationCleanupIntent,
    TenantGenerationCleanupOutcome,
    TenantGenerationCleanupResult,
    TenantGenerationExpectation,
    TenantGenerationTransitionIntent,
    TenantGenerationTransitionOutcome,
    TenantGenerationTransitionResult,
    TenantRunningGeneration,
    TenantTargetAdapterError,
    TenantTargetPacketBinding,
    _parse_audit,
)
from .tenant_record_target_child import TargetReadyReceipt, TenantTargetPacket
from .util import canonical_json_bytes, content_hash, json_clone, parse_iso8601_datetime

_HEX_ID = re.compile(r"^[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_OPERATIONS = 16


class TenantGenerationStore(Protocol):
    """Existing ProductStore methods; no database connection or second store."""

    def _create_tenant_generation_journal(
        self,
        owner_id: str,
        journal_id: str,
        document: Mapping[str, Any],
        *,
        validator: JournalValidator,
    ) -> Mapping[str, Any]: ...

    def _get_tenant_generation_journal(
        self, owner_id: str, journal_id: str, *, revision: int | None = None
    ) -> Mapping[str, Any]: ...

    def _save_tenant_generation_journal(
        self,
        owner_id: str,
        journal_id: str,
        document: Mapping[str, Any],
        *,
        expected_revision: int,
        expected_digest: str,
        validator: JournalValidator,
    ) -> Mapping[str, Any]: ...


class TenantGenerationLauncher(Protocol):
    """Fixed launcher, including a fresh exact-custody observation."""

    def plan(
        self, *, run_id: str, attempt_id: str, packets: TenantLabPackets, max_runtime_seconds: int
    ) -> TenantLabLaunchPlan: ...

    def prepare(
        self, plan: TenantLabLaunchPlan, packets: TenantLabPackets, sink: LifecycleSink
    ) -> TenantLabLifecycleRecord: ...

    def start(
        self, record: TenantLabLifecycleRecord, sink: LifecycleSink
    ) -> TenantLabLifecycleRecord: ...

    def stop(
        self, record: TenantLabLifecycleRecord, sink: LifecycleSink
    ) -> TenantLabLifecycleRecord: ...

    def reconcile(
        self, record: TenantLabLifecycleRecord, sink: LifecycleSink
    ) -> TenantLabLifecycleRecord: ...

    def cleanup(
        self, record: TenantLabLifecycleRecord, sink: LifecycleSink
    ) -> TenantLabLifecycleRecord: ...

    def check_running(self, record: TenantLabLifecycleRecord) -> str: ...


def _lifecycle_document(record: TenantLabLifecycleRecord) -> dict[str, Any]:
    result = record.to_dict()
    result["plan"] = _plan_document(record.plan)
    return result


def _plan_document(plan: TenantLabLaunchPlan) -> dict[str, Any]:
    result = plan.to_dict()
    # ProductStore forbids bearer-shaped fields even when their value is a
    # digest. This reversible public alias preserves every exact plan field.
    result["provider_material_digest"] = result.pop("provider_token_digest")
    return result


def _plan(value: Mapping[str, Any]) -> TenantLabLaunchPlan:
    result = json_clone(value)
    result["provider_token_digest"] = result.pop("provider_material_digest")
    return TenantLabLaunchPlan.from_mapping(result)


def _lifecycle(value: Mapping[str, Any]) -> TenantLabLifecycleRecord:
    result = json_clone(value)
    plan = result["plan"]
    plan["provider_token_digest"] = plan.pop("provider_material_digest")
    return TenantLabLifecycleRecord.from_mapping(result)


def _validate_journal(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if (
        set(value)
        != {
            "schema_version",
            "experiment_id",
            "revision",
            "inputs_digest",
            "phase",
            "active",
            "operation",
            "consumed",
            "generation_ids",
            "audit_bindings",
            "retained_audit",
        }
        or value["schema_version"] != JOURNAL_SCHEMA
    ):
        raise ValueError("generation journal fields are invalid")
    if not isinstance(value["inputs_digest"], str) or not _DIGEST.fullmatch(value["inputs_digest"]):
        raise ValueError("generation inputs binding is invalid")
    if value["phase"] not in {"idle", "executing", "running", "unknown", "cleaned"}:
        raise ValueError("generation journal phase is invalid")
    consumed = value["consumed"]
    if not isinstance(consumed, list) or len(consumed) > _MAX_OPERATIONS:
        raise ValueError("generation operation bound exceeded")
    if len(set(consumed)) != len(consumed) or any(
        not isinstance(item, str) or not _DIGEST.fullmatch(item) for item in consumed
    ):
        raise ValueError("generation operation history is invalid")
    active = value["active"]
    if active is not None:
        if not isinstance(active, dict) or set(active) != {"plan", "lifecycle", "packet"}:
            raise ValueError("generation active identity is invalid")
        plan = _plan(active["plan"])
        if active["lifecycle"] is not None and _lifecycle(active["lifecycle"]).plan != plan:
            raise ValueError("generation lifecycle changed its planned identity")
        packet = active["packet"]
        if set(packet) != {"run_id", "attempt_id", "created_at", "defense_mode"} or (
            packet["run_id"] != plan.run_id or packet["attempt_id"] != plan.attempt_id
        ):
            raise ValueError("generation packet owner changed")
        if packet["defense_mode"] not in {"client_asserted", "signed_session"}:
            raise ValueError("generation packet mode is invalid")
    if not isinstance(value["audit_bindings"], list) or len(value["audit_bindings"]) > 256:
        raise ValueError("generation audit binding bound exceeded")
    generations = value["generation_ids"]
    if not isinstance(generations, list) or len(generations) > _MAX_OPERATIONS:
        raise ValueError("generation identity bound exceeded")
    if any(
        not isinstance(item, dict) or set(item) != {"run_id", "attempt_id"} for item in generations
    ):
        raise ValueError("generation identity history is invalid")
    if len({item["run_id"] for item in generations}) != len(generations) or len(
        {item["attempt_id"] for item in generations}
    ) != len(generations):
        raise ValueError("generation identity was reused")
    return value


class ProductStoreTenantGenerationJournal:
    """CAS journal in private append-only tables of the protected ProductStore."""

    def __init__(self, store: TenantGenerationStore, *, owner_id: str, inputs_digest: str) -> None:
        if re.fullmatch(r"experiment-[0-9a-f]{32}", owner_id) is None:
            raise TenantTargetAdapterError("generation journal owner is invalid")
        self._store = store
        self.owner_id = owner_id
        self.identity = (
            "experiment-"
            + hashlib.sha256((JOURNAL_SCHEMA + ":" + owner_id).encode("ascii")).hexdigest()[:32]
        )
        initial = {
            "schema_version": JOURNAL_SCHEMA,
            "experiment_id": self.identity,
            "revision": 1,
            "inputs_digest": inputs_digest,
            "phase": "idle",
            "active": None,
            "operation": None,
            "consumed": [],
            "generation_ids": [],
            "audit_bindings": [],
            "retained_audit": None,
        }
        store._create_tenant_generation_journal(
            owner_id, self.identity, initial, validator=_validate_journal
        )
        self._inputs_digest = inputs_digest
        self.read()

    def read(self) -> Mapping[str, Any]:
        result = self._store._get_tenant_generation_journal(self.owner_id, self.identity)
        document = _validate_journal(result["document"])
        if (
            document["inputs_digest"] != self._inputs_digest
            or not result["active"]
            or result["owner_id"] != self.owner_id
            or result["journal_id"] != self.identity
        ):
            raise TenantTargetAdapterError("generation journal custody changed")
        return result

    def save(self, head: Mapping[str, Any], **changes: Any) -> Mapping[str, Any]:
        document = {**head["document"], **changes, "revision": head["revision"] + 1}
        return self._store._save_tenant_generation_journal(
            self.owner_id,
            self.identity,
            document,
            expected_revision=head["revision"],
            expected_digest=head["digest"],
            validator=_validate_journal,
        )


class ProtectedTenantGenerationInputs:
    """Read only fixed filenames beneath an installed controller-private root.

    The target input is a signed-session template admitting exactly one fixture
    and one defense. Its original run/attempt and admission bearers are never
    launched. Each generation derives distinct admissions from that protected
    material and a fresh controller-generated run identity.
    """

    def __init__(self, controller_root: Path) -> None:
        self._root = controller_root.absolute()
        details = self._root.stat()
        self._identity = (details.st_dev, details.st_ino)
        target, provider, bearer = self._read()
        self._target = TenantTargetPacket.from_bytes(target)
        if self._target.defense_mode != "signed_session":
            raise TenantTargetAdapterError("generation input lacks a fixed admitted defense")
        self._provider = json.loads(provider)
        ControlledProviderManifest.from_mapping(self._provider)
        TenantLabPackets(target, provider, bearer)
        self._bearer = bearer
        self.digest = content_hash(
            {"target": _sha256(target), "provider": _sha256(provider), "material": _sha256(bearer)}
        )

    def _read(self) -> tuple[bytes, bytes, bytes]:
        with _PinnedPrivateDirectory(
            self._root, expected_identity=self._identity, verify_permissions_only=True
        ) as pinned:
            return (
                pinned.read("target-input.json", maximum=128 * 1024, apply_permissions=False),
                pinned.read("provider-input.json", maximum=128 * 1024, apply_permissions=False),
                pinned.read("provider-input.txt", maximum=512, apply_permissions=False),
            )

    def packet(self, descriptor: Mapping[str, Any]) -> tuple[TenantTargetPacket, TenantLabPackets]:
        target, provider, bearer = self._read()
        if (
            content_hash(
                {
                    "target": _sha256(target),
                    "provider": _sha256(provider),
                    "material": _sha256(bearer),
                }
            )
            != self.digest
        ):
            raise TenantTargetAdapterError("protected generation inputs changed")
        run_id = descriptor["run_id"]
        template = self._target
        signed = descriptor["defense_mode"] == "signed_session"
        packet = TenantTargetPacket.create(
            run_id=run_id,
            attempt_id=descriptor["attempt_id"],
            fixture_seed=template.fixture_seed,
            held_out=template.held_out,
            defense_mode=descriptor["defense_mode"],
            admissions={
                item.source_identity: hmac.digest(item.token, run_id.encode("ascii"), "sha256")
                for item in template.admissions
            },
            created_at=descriptor["created_at"],
            max_runtime_seconds=template.max_runtime_seconds,
            signing_key=template.signing_key if signed else None,
            key_id=template.key_id if signed else None,
            application_nonce=template.application_nonce if signed else None,
            max_requests=template.max_requests,
            max_audit_events=template.max_audit_events,
            max_audit_bytes=template.max_audit_bytes,
        )
        manifest = {**self._provider, "attempt_id": descriptor["attempt_id"]}
        ControlledProviderManifest.from_mapping(manifest)
        fresh_bearer = hmac.digest(self._bearer, run_id.encode("ascii"), "sha256").hex().encode()
        return packet, TenantLabPackets(
            packet.to_bytes(), canonical_json_bytes(manifest), fresh_bearer
        )

    @property
    def configs(self) -> tuple[TenantDefenseConfig, TenantDefenseConfig]:
        fixture, after = self._target.materialize()
        from .tenant_record_lab import baseline_defense_config

        return baseline_defense_config(fixture), after


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


class ControllerOwnedTenantLauncherGenerationSource:
    """Production controller owner; persist-before-effect and no replay."""

    def __init__(
        self,
        *,
        launcher: TenantGenerationLauncher,
        journal: ProductStoreTenantGenerationJournal,
        inputs: ProtectedTenantGenerationInputs,
        scratch_root: Path,
        clock: Callable[[], str],
        identity_factory: Callable[[], str] = lambda: secrets.token_hex(16),
    ) -> None:
        self._launcher, self._journal, self._inputs = launcher, journal, inputs
        self._clock, self._identity_factory = clock, identity_factory
        self._root = scratch_root.absolute()
        details = self._root.stat()
        self._root_identity = (details.st_dev, details.st_ino)
        with _PinnedPrivateDirectory(
            self._root, expected_identity=self._root_identity, verify_permissions_only=True
        ):
            pass
        self._lock = threading.RLock()
        self._issued_liveness: dict[str, str] = {}
        if journal.read()["document"]["inputs_digest"] != inputs.digest:
            raise TenantTargetAdapterError("source inputs do not bind its journal")

    def start_initial(self) -> TenantRunningGeneration:
        """Explicit controller admission; construction/recovery never launches."""
        with self._lock:
            head = self._journal.read()
            if head["document"]["phase"] != "idle":
                raise TenantTargetAdapterError("initial generation admission was consumed")
            operation = {
                "kind": "initial",
                "digest": content_hash({"initial": self._journal.identity}),
            }
            head = self._reserve(head, operation)
            try:
                self._launch(head, "client_asserted")
                return self.checked_running(None)
            except Exception:
                self._unknown()
                raise TenantTargetAdapterError("initial generation outcome is unknown") from None

    def checked_running(
        self, expected: TenantGenerationExpectation | None
    ) -> TenantRunningGeneration:
        with self._lock:
            head = self._journal.read()
            if head["document"]["phase"] != "running":
                raise TenantTargetAdapterError("generation is not durably running")
            generation, ready = self._running(head)
            if expected is not None and expected != self._expectation(generation, ready):
                raise TenantTargetAdapterError("generation CAS preimage changed")
            return generation

    def transition(
        self, intent: TenantGenerationTransitionIntent
    ) -> TenantGenerationTransitionResult:
        with self._lock:
            head = self._journal.read()
            self._unconsumed(head, content_hash({"operation_id": intent.operation_id}))
            generation = self.checked_running(intent.prior)
            before, after = self._inputs.configs
            prior, desired = (before, after) if intent.direction == "apply" else (after, before)
            if (
                generation.config != prior
                or intent.fixture_digest != generation.fixture.digest
                or intent.prior_config_digest != prior.digest
                or intent.desired_config_digest != desired.digest
            ):
                raise TenantTargetAdapterError("transition is outside protected admission")
            operation = {
                "kind": intent.direction,
                "digest": intent.digest,
                "identity_digest": content_hash({"operation_id": intent.operation_id}),
                "intent": {
                    "operation_id": intent.operation_id,
                    "defense_plan_digest": intent.defense_plan_digest,
                    "fixture_digest": intent.fixture_digest,
                    "prior": _expectation_document(intent.prior),
                    "prior_config_digest": intent.prior_config_digest,
                    "desired_config_digest": intent.desired_config_digest,
                },
            }
            reserved = self._reserve(head, operation)
            write_ahead = reserved["digest"]
            outcome = TenantGenerationTransitionOutcome.UNKNOWN
            result = None
            try:
                self._retire(generation, intent.prior.ready_digest)
                self._launch(self._journal.read(), desired.mode)
                result = self.checked_running(None)
                outcome = TenantGenerationTransitionOutcome.CHANGED
            except Exception:
                self._unknown()
            return TenantGenerationTransitionResult(
                outcome,
                intent.prior.lifecycle_digest,
                write_ahead,
                self._journal.read()["digest"],
                result,
            )

    def cleanup(self, intent: TenantGenerationCleanupIntent) -> TenantGenerationCleanupResult:
        with self._lock:
            head = self._journal.read()
            self._unconsumed(head, content_hash({"operation_id": intent.operation_id}))
            generation = self.checked_running(intent.prior)
            if (
                intent.fixture_digest != generation.fixture.digest
                or intent.expected_config_digest != generation.config.digest
            ):
                raise TenantTargetAdapterError("cleanup preimage changed")
            reserved = self._reserve(
                head,
                {
                    "kind": "cleanup",
                    "digest": intent.digest,
                    "identity_digest": content_hash({"operation_id": intent.operation_id}),
                    "intent": {
                        "operation_id": intent.operation_id,
                        "fixture_digest": intent.fixture_digest,
                        "expected_config_digest": intent.expected_config_digest,
                        "prior": _expectation_document(intent.prior),
                    },
                },
            )
            cleaned = None
            try:
                cleaned = self._retire(generation, intent.prior.ready_digest)
                self._settle_phase("cleaned", LifecycleState.CLEANED)
            except Exception:
                cleaned = None
                self._unknown()
            return TenantGenerationCleanupResult(
                (
                    TenantGenerationCleanupOutcome.UNKNOWN
                    if cleaned is None
                    else TenantGenerationCleanupOutcome.CLEANED
                ),
                intent.prior.lifecycle_digest,
                reserved["digest"],
                self._journal.read()["digest"],
                cleaned_lifecycle=cleaned,
            )

    def reconcile(self) -> TenantLabLifecycleRecord | None:
        """Settle retained custody only. Never launch, resume, or replay intent."""
        with self._lock:
            head = self._journal.read()
            active = head["document"]["active"]
            if active is None:
                return None
            if head["document"]["phase"] == "cleaned":
                return _lifecycle(active["lifecycle"])
            self._journal.save(head, phase="unknown")
            if active["lifecycle"] is None:
                return None  # Planning never implies preparation or process custody.
            record = _lifecycle(active["lifecycle"])
            if record.state is LifecycleState.PREPARED:
                return record  # No exact launch reservation or absence proof.

            def reconcile_sink(
                record: TenantLabLifecycleRecord, phase: str, prior: str | None
            ) -> LifecycleCommit:
                return self._sink(record, phase, prior, reconciling=True)

            record = self._launcher.reconcile(record, reconcile_sink)
            # Retain scratch/audit for controller recovery. No successor can
            # follow an unknown operation even after exact process absence.
            return record

    def retain_audit_binding(self, binding: TenantBoundAuditReceipt) -> str:
        with self._lock:
            head = self._journal.read()
            generation, ready = self._running(head)
            retained = head["document"]["audit_bindings"]
            item = {
                "request_id": binding.request_id,
                "binding_digest": binding.digest,
                "audit_row_digest": binding.audit_row_digest,
                "binding": _binding_document(binding),
            }
            if (
                self._expectation(generation, ready)
                != TenantGenerationExpectation(
                    binding.plan_digest,
                    binding.lifecycle_digest,
                    binding.ready_digest,
                    binding.target_snapshot_id,
                    binding.service_generation,
                )
                or binding.run_id != generation.packet.run_id
                or binding.attempt_id != generation.packet.attempt_id
                or binding.packet_digest != generation.packet.packet_digest
                or binding.fixture_digest != generation.fixture.digest
                or binding.config_digest != generation.config.digest
                or binding.source_admission_digest
                != generation.admission(binding.source_identity).token_digest
                or binding.endpoint.to_dict() != {"host": ready.host, "port": ready.port}
                or (
                    self._issued_liveness.get(binding.liveness_receipt_digest)
                    != generation.lifecycle.digest
                    and item not in retained
                )
            ):
                raise TenantTargetAdapterError("audit binding belongs to another generation")
            rows = self._audit(generation, ready)
            if not any(
                row.request_id == binding.request_id
                and row.digest == binding.audit_row_digest
                and row.source_identity == binding.source_identity
                for row in rows
            ):
                raise TenantTargetAdapterError("audit binding lacks its protected row")
            matches = [item for item in retained if item["request_id"] == binding.request_id]
            if matches:
                if matches != [item]:
                    raise TenantTargetAdapterError("audit request identity was rebound")
                return binding.digest
            self._journal.save(head, audit_bindings=[*retained, item])
            return binding.digest

    def _unconsumed(self, head: Mapping[str, Any], digest: str) -> None:
        if digest in head["document"]["consumed"]:
            raise TenantTargetAdapterError("generation operation cannot be replayed")
        if len(head["document"]["consumed"]) >= _MAX_OPERATIONS:
            raise TenantTargetAdapterError("generation operation limit reached")

    def _reserve(self, head: Mapping[str, Any], operation: Mapping[str, Any]) -> Mapping[str, Any]:
        identity = operation.get("identity_digest", operation["digest"])
        self._unconsumed(head, identity)
        if head["document"]["phase"] not in {"idle", "running"}:
            raise TenantTargetAdapterError("another generation operation is unresolved")
        return self._journal.save(
            head,
            phase="executing",
            operation=operation,
            consumed=[*head["document"]["consumed"], identity],
        )

    def _launch(self, head: Mapping[str, Any], mode: str) -> None:
        if head["document"]["phase"] != "executing":
            raise TenantTargetAdapterError("generation operation lost its durable reservation")
        previous = head["document"]["active"]
        if previous is not None and (
            previous["lifecycle"] is None
            or _lifecycle(previous["lifecycle"]).state is not LifecycleState.CLEANED
        ):
            raise TenantTargetAdapterError("successor requires verified absence and cleanup")
        run, attempt = self._identity_factory(), self._identity_factory()
        if _HEX_ID.fullmatch(run) is None or _HEX_ID.fullmatch(attempt) is None:
            raise TenantTargetAdapterError("controller generation identity is invalid")
        descriptor = {
            "run_id": "engine-lab-" + run,
            "attempt_id": "engine-attempt-" + attempt,
            "created_at": self._clock(),
            "defense_mode": mode,
        }
        if any(
            descriptor["run_id"] == item["run_id"] or descriptor["attempt_id"] == item["attempt_id"]
            for item in head["document"]["generation_ids"]
        ):
            raise TenantTargetAdapterError("successor generation identity was reused")
        packet, packets = self._inputs.packet(descriptor)
        plan = self._launcher.plan(
            run_id=packet.run_id,
            attempt_id=packet.attempt_id,
            packets=packets,
            max_runtime_seconds=packet.max_runtime_seconds,
        )
        # Persist exact plan and packet descriptor before prepare creates files.
        self._journal.save(
            head,
            active={"plan": _plan_document(plan), "lifecycle": None, "packet": descriptor},
            generation_ids=[
                *head["document"]["generation_ids"],
                {"run_id": descriptor["run_id"], "attempt_id": descriptor["attempt_id"]},
            ],
            audit_bindings=[],
            retained_audit=None,
        )

        def prepared_sink(
            record: TenantLabLifecycleRecord, phase: str, prior: str | None
        ) -> LifecycleCommit:
            return self._sink(record, phase, prior, preparing=True)

        prepared = self._launcher.prepare(plan, packets, prepared_sink)
        try:
            self._launcher.start(prepared, self._sink)
        except TenantLabStartFailure as exc:
            # The launcher retains exact uncertain custody through the sink.
            if self._journal.read()["document"]["active"]["lifecycle"] != _lifecycle_document(
                exc.record
            ):
                self._unknown()
                latest = self._journal.read()["document"]["active"]
                retained = _lifecycle(latest["lifecycle"])
                if retained.plan != exc.record.plan or any(
                    child not in exc.record.children for child in retained.children
                ):
                    raise TenantTargetAdapterError(
                        "failed launch custody conflicts with recovery"
                    ) from None
                # An already reserved native launch can finish while another
                # controller is reconciling. Retain its exact returned child
                # identity as UNKNOWN even when normal sink CAS was revoked.
                uncertain = replace(
                    exc.record, revision=retained.revision + 1, state=LifecycleState.UNKNOWN
                )
                self._sink(
                    uncertain, "interrupted_launch_retained", retained.digest, reconciling=True
                )
            raise
        self._settle_phase("running", LifecycleState.RUNNING)

    def _settle_phase(self, phase: str, state: LifecycleState) -> None:
        head = self._journal.read()
        if head["document"]["phase"] != "executing" or (
            _lifecycle(head["document"]["active"]["lifecycle"]).state is not state
        ):
            raise TenantTargetAdapterError("generation settlement lost its durable reservation")
        self._journal.save(head, phase=phase)

    def _sink(
        self,
        record: TenantLabLifecycleRecord,
        phase: str,
        prior: str | None,
        *,
        preparing: bool = False,
        reconciling: bool = False,
    ) -> LifecycleCommit:
        head = self._journal.read()
        if head["document"]["phase"] != ("unknown" if reconciling else "executing"):
            raise TenantTargetAdapterError("lifecycle operation lost its durable reservation")
        active = head["document"]["active"]
        retained = None if active["lifecycle"] is None else _lifecycle(active["lifecycle"])
        if record.plan != _plan(active["plan"]) or (
            (
                preparing
                and (
                    phase != "prepared"
                    or prior is not None
                    or retained is not None
                    or record.revision != 1
                    or record.state is not LifecycleState.PREPARED
                )
            )
            or (
                not preparing
                and (
                    retained is None
                    or prior != retained.digest
                    or record.revision != retained.revision + 1
                )
            )
        ):
            raise TenantTargetAdapterError("lifecycle persistence CAS preimage changed")
        self._journal.save(head, active={**active, "lifecycle": _lifecycle_document(record)})
        fields = {
            "plan_digest": record.plan.digest,
            "prior_record_digest": prior,
            "record_digest": record.digest,
            "phase": phase,
            "committed_at": self._clock(),
        }
        return LifecycleCommit(
            plan_digest=record.plan.digest,
            prior_record_digest=prior,
            record_digest=record.digest,
            phase=phase,
            committed_at=cast(str, fields["committed_at"]),
            receipt_digest=content_hash(fields),
        )

    def _running(
        self, head: Mapping[str, Any]
    ) -> tuple[TenantRunningGeneration, TargetReadyReceipt]:
        if head["document"]["phase"] != "running":
            raise TenantTargetAdapterError("generation custody is unresolved")
        active = head["document"]["active"]
        if active is None or active["lifecycle"] is None:
            raise TenantTargetAdapterError("generation identity is unavailable")
        record = _lifecycle(active["lifecycle"])
        packet, _ = self._inputs.packet(active["packet"])
        if record.plan.target_packet_digest != packet.digest:
            raise TenantTargetAdapterError("retained packet identity changed")
        try:
            liveness = self._launcher.check_running(record)
        except Exception:
            raise TenantTargetAdapterError("exact launcher custody cannot be verified") from None
        ready = TargetReadyReceipt.from_bytes(self._target_file(record, "ready.json", 16 * 1024))
        fixture, config = packet.materialize()
        child = next(item for item in record.children if item.role is ServiceRole.TARGET)
        generic = next(item for item in record.readiness if item.role is ServiceRole.TARGET)
        if (
            ready.packet_digest != packet.digest
            or ready.fixture_digest != fixture.digest
            or ready.config_digest != config.digest
            or ready.admission_digests != packet.admission_digests
            or ready.target_snapshot_id != config.target_snapshot_id
            or ready.service_generation != config.service_generation
            or ready.pid != child.pid
            or ready.host != generic.endpoint.host
            or ready.port != generic.endpoint.port
            or ready.max_requests != packet.max_requests
            or ready.max_audit_events != packet.max_audit_events
            or ready.max_audit_bytes != packet.max_audit_bytes
            or ready.max_runtime_seconds != packet.max_runtime_seconds
        ):
            raise TenantTargetAdapterError("protected readiness binding changed")
        verified_at = self._clock()
        started = parse_iso8601_datetime(ready.started_at)
        if not (
            parse_iso8601_datetime(packet.created_at)
            <= parse_iso8601_datetime(child.started_at)
            <= started
            < parse_iso8601_datetime(packet.expires_at)
        ) or parse_iso8601_datetime(verified_at) < max(
            started,
            parse_iso8601_datetime(generic.observed_at),
            parse_iso8601_datetime(cast(str, record.running_at)),
        ):
            raise TenantTargetAdapterError("protected readiness lifetime changed")
        binding = TenantTargetPacketBinding(
            packet.run_id,
            packet.attempt_id,
            packet.digest,
            fixture.digest,
            config.digest,
            packet.max_requests,
            packet.max_audit_events,
            packet.max_audit_bytes,
            packet.max_runtime_seconds,
            packet.created_at,
            packet.expires_at,
            verified_at,
        )
        generation = TenantRunningGeneration(
            record,
            binding,
            fixture,
            config,
            tuple(
                TenantControllerAdmission.create(item.source_identity, item.token)
                for item in packet.admissions
            ),
            liveness,
        )
        self._issued_liveness[liveness] = record.digest
        if len(self._issued_liveness) > 4096:
            del self._issued_liveness[next(iter(self._issued_liveness))]
        return generation, ready

    @staticmethod
    def _expectation(
        generation: TenantRunningGeneration, ready: TargetReadyReceipt
    ) -> TenantGenerationExpectation:
        return TenantGenerationExpectation(
            generation.lifecycle.plan.digest,
            generation.lifecycle.digest,
            ready.ready_digest,
            generation.config.target_snapshot_id,
            generation.config.service_generation,
        )

    def _target_file(self, record: TenantLabLifecycleRecord, name: str, maximum: int) -> bytes:
        layout = WorkspaceLayout.for_run(self._root, record.plan.run_id)
        with _PinnedPrivateDirectory(
            self._root, expected_identity=self._root_identity, verify_permissions_only=True
        ) as root:
            with _PinnedPrivateDirectory(
                layout.run_root, parent=root, verify_permissions_only=True
            ) as run:
                with _PinnedPrivateDirectory(
                    layout.run_root / "target", parent=run, verify_permissions_only=True
                ) as target:
                    return target.read(name, maximum=maximum, apply_permissions=False)

    def _audit(self, generation: TenantRunningGeneration, ready: TargetReadyReceipt):
        value = self._target_file(
            generation.lifecycle, "audit.jsonl", generation.packet.max_audit_bytes
        )
        return () if not value else _parse_audit(value, ready, generation.packet)

    def _retire(
        self, generation: TenantRunningGeneration, ready_digest: str
    ) -> TenantLabLifecycleRecord:
        stopped = self._launcher.stop(generation.lifecycle, self._sink)
        if stopped.state is not LifecycleState.STOPPED:
            raise TenantTargetAdapterError("old generation process absence is unknown")
        ready = TargetReadyReceipt.from_bytes(self._target_file(stopped, "ready.json", 16 * 1024))
        if ready.ready_digest != ready_digest:
            raise TenantTargetAdapterError("retired readiness identity changed")
        rows = self._audit(generation, ready)
        # Audit is quiescent after verified process absence. Persist the exact
        # bounded semantic rows, not responses, session values or raw logs.
        self._journal.save(
            self._journal.read(),
            retained_audit={
                "plan_digest": generation.lifecycle.plan.digest,
                "ready_digest": ready.ready_digest,
                "rows": [row.to_dict() for row in rows],
            },
        )
        cleaned = self._launcher.cleanup(stopped, self._sink)
        if cleaned.state is not LifecycleState.CLEANED:
            raise TenantTargetAdapterError("old generation scratch absence is unknown")
        return cleaned

    def _unknown(self) -> None:
        head = self._journal.read()
        if head["document"]["phase"] != "unknown":
            self._journal.save(head, phase="unknown")


def _expectation_document(value: TenantGenerationExpectation) -> dict[str, str]:
    return {
        "plan_digest": value.plan_digest,
        "lifecycle_digest": value.lifecycle_digest,
        "ready_digest": value.ready_digest,
        "target_snapshot_id": value.target_snapshot_id,
        "service_generation": value.service_generation,
    }


def _binding_document(value: TenantBoundAuditReceipt) -> dict[str, object]:
    return {
        "request_id": value.request_id,
        "audit_row_digest": value.audit_row_digest,
        "source_identity": value.source_identity,
        "source_admission_digest": value.source_admission_digest,
        "plan_digest": value.plan_digest,
        "lifecycle_digest": value.lifecycle_digest,
        "liveness_receipt_digest": value.liveness_receipt_digest,
        "run_id": value.run_id,
        "attempt_id": value.attempt_id,
        "packet_digest": value.packet_digest,
        "fixture_digest": value.fixture_digest,
        "config_digest": value.config_digest,
        "endpoint": value.endpoint.to_dict(),
        "ready_digest": value.ready_digest,
        "target_snapshot_id": value.target_snapshot_id,
        "service_generation": value.service_generation,
    }
