from __future__ import annotations

import base64
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from bluefire.controlled_strix_provider import DEFAULT_MODEL_ID, MANIFEST_SCHEMA
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ResourceConflictError
from bluefire.tenant_record_generation_source import (
    ControllerOwnedTenantLauncherGenerationSource,
    ProductStoreTenantGenerationJournal,
    ProtectedTenantGenerationInputs,
    _lifecycle,
)
from bluefire.tenant_record_lab_launcher import (
    FixedChildSpec,
    LifecycleState,
    LoopbackEndpoint,
    OwnedChild,
    Presence,
    RuntimeBinding,
    ServiceRole,
    TenantRecordLabLauncher,
    WorkspaceLayout,
)
from bluefire.tenant_record_observer import TenantAuditRow
from bluefire.tenant_record_target_adapter import (
    TenantBoundAuditReceipt,
    TenantGenerationCleanupIntent,
    TenantGenerationCleanupOutcome,
    TenantGenerationExpectation,
    TenantGenerationTransitionIntent,
    TenantGenerationTransitionOutcome,
    TenantTargetAdapterError,
)
from bluefire.tenant_record_target_child import TargetReadyReceipt, TenantTargetPacket
from bluefire.util import canonical_json_bytes, content_hash
from bluefire.windows_owner_acl import apply_owner_private_acl_path
from tests_platform.test_tenant_record_lab_launcher import FakeBackend

NOW = "2026-11-04T15:00:00Z"
OWNER = "experiment-" + "a" * 32


def _protect(path: Path, *, directory: bool) -> None:
    if os.name == "nt":
        apply_owner_private_acl_path(path, directory=directory)
    else:
        path.chmod(0o700 if directory else 0o600)


def _write(path: Path, value: bytes) -> None:
    path.write_bytes(value)
    _protect(path, directory=False)


class Clock:
    def __call__(self) -> str:
        return NOW


class Backend(FakeBackend):
    """Only records effects and writes bounded receipts; launches no processes."""

    def __init__(self, clock: Clock) -> None:
        super().__init__(clock)  # type: ignore[arg-type]
        self.journal: ProductStoreTenantGenerationJournal | None = None
        self.fresh_checks = 0

    def launch(self, spec: FixedChildSpec) -> OwnedChild:
        assert self.journal is not None
        head = self.journal.read()["document"]
        assert head["phase"] == "executing"
        assert head["operation"] is not None
        assert _lifecycle(head["active"]["lifecycle"]).state is LifecycleState.LAUNCH_RESERVED
        return super().launch(spec)

    def verify_ready(self, spec: FixedChildSpec, child: OwnedChild):
        generic = super().verify_ready(spec, child)
        if spec.role is ServiceRole.TARGET:
            path = spec.packet_source.path
            packet = TenantTargetPacket.from_bytes(path.read_bytes())
            fixture, config = packet.materialize()
            ready = TargetReadyReceipt(
                pid=child.pid,
                host=generic.endpoint.host,
                port=generic.endpoint.port,
                packet_digest=packet.digest,
                fixture_digest=fixture.digest,
                config_digest=config.digest,
                target_snapshot_id=config.target_snapshot_id,
                service_generation=config.service_generation,
                admission_digests=packet.admission_digests,
                max_audit_events=packet.max_audit_events,
                max_audit_bytes=packet.max_audit_bytes,
                max_requests=packet.max_requests,
                max_runtime_seconds=packet.max_runtime_seconds,
                started_at=NOW,
            )
            if not path.with_name("ready.json").exists():
                _write(path.with_name("ready.json"), ready.to_bytes())
                _write(path.with_name("audit.jsonl"), b"")
        return generic


def _inputs(root: Path) -> ProtectedTenantGenerationInputs:
    root.mkdir()
    _protect(root, directory=True)
    packet = TenantTargetPacket.create(
        run_id="engine-lab-" + "0" * 32,
        attempt_id="engine-attempt-" + "0" * 32,
        fixture_seed=b"controller-owned-source-fixture-0001",
        held_out=False,
        defense_mode="signed_session",
        admissions={
            "engine_worker": b"a" * 32,
            "ordinary_user": b"b" * 32,
            "controller_probe": b"c" * 32,
        },
        signing_key=b"controller-owned-signing-material-000001",
        key_id="session-key-admitted",
        application_nonce="application-admitted",
        created_at=NOW,
        max_runtime_seconds=600,
    )
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "attempt_id": packet.attempt_id,
        "model_id": DEFAULT_MODEL_ID,
        "max_requests": 4,
        "max_request_bytes": 4096,
        "max_response_bytes": 4096,
        "max_messages": 16,
        "max_tools": 8,
        "max_schema_depth": 8,
        "phases": [
            {
                "phase_id": "finish",
                "tool_name": "finish_scan",
                "tool_schema_digest": content_hash({"schema": "finish"}),
                "arguments": {"summary": "fixed mechanics fixture"},
            }
        ],
    }
    _write(root / "target-input.json", packet.to_bytes())
    _write(root / "provider-input.json", canonical_json_bytes(manifest))
    _write(root / "provider-input.txt", b"controller-owned-provider-material-000001")
    return ProtectedTenantGenerationInputs(root)


def _setup(tmp_path: Path):
    inputs = _inputs(tmp_path / "inputs")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    _protect(scratch, directory=True)
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    for name in ("python.exe", "target.py", "provider.py"):
        (runtime_root / name).write_bytes(name.encode("ascii"))
    runtime = RuntimeBinding.inspect_for_test(
        python_path=runtime_root / "python.exe",
        target_path=runtime_root / "target.py",
        provider_path=runtime_root / "provider.py",
    )
    clock = Clock()
    backend = Backend(clock)
    launcher = TenantRecordLabLauncher(
        scratch_root=scratch,
        runtime=runtime,
        backend=backend,
        root_is_protected=lambda path: path == scratch,
        clock=clock,
    )
    store = ProductStore(tmp_path / "state" / "bluefire.db")
    journal = ProductStoreTenantGenerationJournal(
        store, owner_id=OWNER, inputs_digest=inputs.digest
    )
    backend.journal = journal
    identities = iter(f"{number:032x}" for number in range(1, 100))
    source = ControllerOwnedTenantLauncherGenerationSource(
        launcher=launcher,
        journal=journal,
        inputs=inputs,
        scratch_root=scratch,
        clock=clock,
        identity_factory=lambda: next(identities),
    )
    return source, journal, backend, store, launcher, inputs, scratch


def _expectation(
    source: ControllerOwnedTenantLauncherGenerationSource,
) -> TenantGenerationExpectation:
    generation = source.checked_running(None)
    ready = TargetReadyReceipt.from_bytes(
        source._target_file(generation.lifecycle, "ready.json", 16 * 1024)
    )
    return source._expectation(generation, ready)


def _transition(source, *, direction="apply", marker="a"):
    current = source.checked_running(None)
    before, after = source._inputs.configs
    desired = after if direction == "apply" else before
    return TenantGenerationTransitionIntent(
        direction=direction,
        operation_id=("tenant-defense-" if direction == "apply" else "tenant-rollback-")
        + marker * 32,
        defense_plan_digest=content_hash({"plan": "fixed"}),
        fixture_digest=current.fixture.digest,
        prior=_expectation(source),
        prior_config_digest=current.config.digest,
        desired_config_digest=desired.digest,
    )


def test_initial_generation_is_explicit_persisted_and_freshly_checked(tmp_path: Path) -> None:
    source, journal, backend, store, _, inputs, _ = _setup(tmp_path)
    assert backend.events == []
    generation = source.start_initial()
    assert generation.config.mode == "client_asserted"
    assert journal.read()["document"]["phase"] == "running"
    assert _lifecycle(journal.read()["document"]["active"]["lifecycle"]) == generation.lifecycle
    count = backend.events.count("verify_all_running")
    assert source.checked_running(_expectation(source)).lifecycle == generation.lifecycle
    assert backend.events.count("verify_all_running") > count
    with pytest.raises(TenantTargetAdapterError, match="consumed"):
        source.start_initial()
    versions = store._list_tenant_generation_journal_versions(journal.owner_id, journal.identity)
    documents = [
        store._get_tenant_generation_journal(
            journal.owner_id, journal.identity, revision=item["revision"]
        )["document"]
        for item in versions
    ]
    serialized = json.dumps(documents)
    assert "provider_token_digest" not in serialized
    for filename in ("target-input.json", "provider-input.txt"):
        assert (
            base64.urlsafe_b64encode((inputs._root / filename).read_bytes()).decode()
            not in serialized
        )
    assert "controller-owned-signing-material" not in serialized
    assert "token_b64" not in serialized
    template = TenantTargetPacket.from_bytes((inputs._root / "target-input.json").read_bytes())
    for material in (
        template.fixture_seed,
        template.signing_key,
        *(item.token for item in template.admissions),
    ):
        assert material is not None
        assert base64.urlsafe_b64encode(material).decode().rstrip("=") not in serialized


def test_transition_retains_audit_cleans_then_launches_distinct_generation(tmp_path: Path) -> None:
    source, journal, backend, store, _, _, _ = _setup(tmp_path)
    before = source.start_initial()
    intent = _transition(source)
    backend.events.clear()
    result = source.transition(intent)
    assert result.outcome is TenantGenerationTransitionOutcome.CHANGED
    assert result.generation is not None
    assert result.generation.config.mode == "signed_session"
    assert result.generation.lifecycle.plan.run_id != before.lifecycle.plan.run_id
    assert result.generation.lifecycle.plan.attempt_id != before.lifecycle.plan.attempt_id
    assert result.generation.admission_digests != before.admission_digests
    assert result.generation.packet.packet_digest != before.packet.packet_digest
    assert backend.events.index("cleanup") < backend.events.index("launch:target")
    versions = store._list_tenant_generation_journal_versions(
        journal.owner_id, journal.identity, limit=200
    )
    documents = [
        store._get_tenant_generation_journal(
            journal.owner_id, journal.identity, revision=item["revision"]
        )["document"]
        for item in versions
    ]
    assert any(document["retained_audit"] is not None for document in documents)
    count = len(backend.events)
    with pytest.raises(TenantTargetAdapterError, match="replayed"):
        source.transition(intent)
    assert len(backend.events) == count


@pytest.mark.parametrize("uncertainty", ["process", "cleanup"])
def test_uncertain_absence_prevents_successor_and_recovery_never_launches(
    tmp_path: Path, uncertainty: str
) -> None:
    source, journal, backend, store, launcher, inputs, scratch = _setup(tmp_path)
    source.start_initial()
    intent = _transition(source)
    if uncertainty == "process":
        backend.stop_presence[ServiceRole.TARGET] = Presence.UNKNOWN
        backend.reconcile_presence[ServiceRole.TARGET] = Presence.UNKNOWN
    else:
        backend.cleanup_presence = Presence.UNKNOWN
    count = len(backend.specs)
    result = source.transition(intent)
    assert result.outcome is TenantGenerationTransitionOutcome.UNKNOWN
    assert len(backend.specs) == count
    reopened = ControllerOwnedTenantLauncherGenerationSource(
        launcher=launcher,
        journal=ProductStoreTenantGenerationJournal(
            store, owner_id=OWNER, inputs_digest=inputs.digest
        ),
        inputs=inputs,
        scratch_root=scratch,
        clock=Clock(),
    )
    with pytest.raises(TenantTargetAdapterError, match="running"):
        reopened.checked_running(None)
    reopened.reconcile()
    assert len(backend.specs) == count
    assert journal.read()["document"]["phase"] == "unknown"
    with pytest.raises(TenantTargetAdapterError, match="replayed"):
        reopened.transition(intent)


def test_restart_requires_fresh_exact_custody_and_never_relaunches(tmp_path: Path) -> None:
    source, journal, backend, _, launcher, inputs, scratch = _setup(tmp_path)
    source.start_initial()
    reopened = ControllerOwnedTenantLauncherGenerationSource(
        launcher=launcher,
        journal=journal,
        inputs=inputs,
        scratch_root=scratch,
        clock=Clock(),
    )
    assert reopened.checked_running(None).config.mode == "client_asserted"
    backend.all_running = False
    count = len(backend.specs)
    with pytest.raises(TenantTargetAdapterError, match="custody"):
        reopened.checked_running(None)
    reopened.reconcile()
    assert len(backend.specs) == count
    with pytest.raises(TenantTargetAdapterError, match="running"):
        source.checked_running(None)


def test_cas_preimage_and_unadmitted_defense_are_rejected_before_effect(tmp_path: Path) -> None:
    source, journal, backend, _, _, _, _ = _setup(tmp_path)
    source.start_initial()
    intent = _transition(source)
    count = len(backend.events)
    with pytest.raises(TenantTargetAdapterError, match="CAS"):
        source.transition(
            replace(intent, prior=replace(intent.prior, lifecycle_digest=content_hash("stale")))
        )
    with pytest.raises(TenantTargetAdapterError, match="admission"):
        source.transition(replace(intent, desired_config_digest=content_hash("unadmitted")))
    assert len(backend.specs) == 2
    assert all(not event.startswith("stop:") for event in backend.events[count:])
    head = journal.read()
    journal.save(head, phase="unknown")
    with pytest.raises(ResourceConflictError):
        journal.save(head, phase="cleaned")


def test_protected_input_tampering_blocks_effects(tmp_path: Path) -> None:
    source, journal, backend, _, _, inputs, _ = _setup(tmp_path)
    (inputs._root / "provider-input.txt").write_bytes(b"different-protected-material-value-0001")
    with pytest.raises(TenantTargetAdapterError, match="unknown"):
        source.start_initial()
    assert backend.events == []
    assert journal.read()["document"]["phase"] == "unknown"


def test_cleanup_is_verified_and_consumed(tmp_path: Path) -> None:
    source, journal, backend, _, _, _, scratch = _setup(tmp_path)
    generation = source.start_initial()
    intent = TenantGenerationCleanupIntent(
        "tenant-cleanup-" + "c" * 32,
        generation.fixture.digest,
        generation.config.digest,
        _expectation(source),
    )
    result = source.cleanup(intent)
    assert result.outcome is TenantGenerationCleanupOutcome.CLEANED
    assert result.cleaned_lifecycle is not None
    assert result.cleaned_lifecycle.state is LifecycleState.CLEANED
    assert not WorkspaceLayout.for_run(scratch, generation.lifecycle.plan.run_id).run_root.exists()
    assert journal.read()["document"]["retained_audit"]["rows"] == []
    count = len(backend.events)
    with pytest.raises(TenantTargetAdapterError, match="replayed"):
        source.cleanup(intent)
    assert len(backend.events) == count


def test_generation_id_reuse_is_rejected_before_preparation(tmp_path: Path) -> None:
    source, journal, backend, _, _, _, _ = _setup(tmp_path)
    original = source.start_initial()
    assert (
        source.transition(_transition(source)).outcome is TenantGenerationTransitionOutcome.CHANGED
    )
    source._identity_factory = lambda: original.lifecycle.plan.run_id.removeprefix("engine-lab-")
    count = len(backend.specs)
    result = source.transition(_transition(source, direction="rollback"))
    assert result.outcome is TenantGenerationTransitionOutcome.UNKNOWN
    assert len(backend.specs) == count
    assert journal.read()["document"]["phase"] == "unknown"


def test_audit_binding_requires_exact_row_source_and_issued_custody_proof(tmp_path: Path) -> None:
    source, journal, _, _, _, _, scratch = _setup(tmp_path)
    generation = source.start_initial()
    expected = _expectation(source)
    row = TenantAuditRow(
        1,
        "request-" + "a" * 24,
        NOW,
        "engine_worker",
        "health",
        None,
        None,
        200,
        0,
        content_hash("body"),
        content_hash("headers"),
        (),
        (),
        "public_health",
        generation.config.target_snapshot_id,
        generation.config.service_generation,
    )
    layout = WorkspaceLayout.for_run(scratch, generation.lifecycle.plan.run_id)
    _write(layout.target_audit, canonical_json_bytes(row.to_dict()) + b"\n")
    ready = TargetReadyReceipt.from_bytes(layout.target_ready.read_bytes())
    binding = TenantBoundAuditReceipt(
        row.request_id,
        row.digest,
        row.source_identity,
        generation.admission("engine_worker").token_digest,
        expected.plan_digest,
        expected.lifecycle_digest,
        generation.liveness_receipt_digest,
        generation.packet.run_id,
        generation.packet.attempt_id,
        generation.packet.packet_digest,
        generation.fixture.digest,
        generation.config.digest,
        LoopbackEndpoint(ready.host, ready.port),
        expected.ready_digest,
        expected.target_snapshot_id,
        expected.service_generation,
    )
    with pytest.raises(TenantTargetAdapterError, match="protected row"):
        source.retain_audit_binding(
            replace(
                binding,
                source_identity="ordinary_user",
                source_admission_digest=generation.admission("ordinary_user").token_digest,
            )
        )
    with pytest.raises(TenantTargetAdapterError, match="another generation"):
        source.retain_audit_binding(
            replace(binding, liveness_receipt_digest=content_hash("invented"))
        )
    assert source.retain_audit_binding(binding) == binding.digest
    head = journal.read()
    assert (
        head["document"]["audit_bindings"][0]["binding"]["liveness_receipt_digest"]
        == binding.liveness_receipt_digest
    )
    assert source.retain_audit_binding(binding) == binding.digest
    assert journal.read()["revision"] == head["revision"]
    cleanup = TenantGenerationCleanupIntent(
        "tenant-cleanup-" + "d" * 32, generation.fixture.digest, generation.config.digest, expected
    )
    assert source.cleanup(cleanup).outcome is TenantGenerationCleanupOutcome.CLEANED
    assert journal.read()["document"]["retained_audit"]["rows"] == [row.to_dict()]


def test_reconciliation_revokes_inflight_reservation_without_launching_successor(
    tmp_path: Path,
) -> None:
    source, journal, backend, _, launcher, inputs, scratch = _setup(tmp_path)
    recovered = ControllerOwnedTenantLauncherGenerationSource(
        launcher=launcher,
        journal=journal,
        inputs=inputs,
        scratch_root=scratch,
        clock=Clock(),
    )

    def interrupted(spec: FixedChildSpec) -> OwnedChild:
        # Recovery sees a durable launch reservation before any fake process
        # identity has been produced. Revoke it and do not resume its launch.
        backend.reconcile_presence = {role: Presence.UNKNOWN for role in ServiceRole}
        recovered.reconcile()
        # Model a native effect already admitted by launch_reserved finishing
        # after recovery. Its acknowledgement must become retained UNKNOWN.
        return FakeBackend.launch(backend, spec)

    backend.launch = interrupted  # type: ignore[method-assign]
    with pytest.raises(TenantTargetAdapterError, match="unknown"):
        source.start_initial()
    assert len(backend.specs) == 1
    assert backend.specs[0].role is ServiceRole.TARGET
    assert journal.read()["document"]["phase"] == "unknown"
    retained = _lifecycle(journal.read()["document"]["active"]["lifecycle"])
    assert retained.state is LifecycleState.UNKNOWN
    assert len(retained.children) == 1
    assert retained.children[0].spec_digest == backend.specs[0].digest
    assert "launch:test_provider" not in backend.events
    assert "cleanup" not in backend.events


def test_plan_intent_is_not_a_prepared_lifecycle_and_never_resumes(tmp_path: Path) -> None:
    source, journal, backend, _, launcher, _, scratch = _setup(tmp_path)

    def unavailable(*_args, **_kwargs):
        raise OSError("fixture interruption before prepare")

    launcher.prepare = unavailable  # type: ignore[method-assign]
    with pytest.raises(TenantTargetAdapterError, match="unknown"):
        source.start_initial()
    active = journal.read()["document"]["active"]
    assert active["plan"]["run_id"] == active["packet"]["run_id"]
    assert active["lifecycle"] is None
    assert source.reconcile() is None
    assert list(scratch.iterdir()) == []
    assert backend.events == []


def test_cleanup_phase_persistence_failure_stays_unknown(tmp_path: Path) -> None:
    source, journal, _, _, _, _, _ = _setup(tmp_path)
    generation = source.start_initial()
    intent = TenantGenerationCleanupIntent(
        "tenant-cleanup-" + "e" * 32,
        generation.fixture.digest,
        generation.config.digest,
        _expectation(source),
    )
    original = journal.save

    def fail_finalization(head, **changes):
        if changes.get("phase") == "cleaned":
            raise OSError("fixture settlement commit unavailable")
        return original(head, **changes)

    journal.save = fail_finalization  # type: ignore[method-assign]
    result = source.cleanup(intent)
    assert result.outcome is TenantGenerationCleanupOutcome.UNKNOWN
    assert result.cleaned_lifecycle is None
    assert journal.read()["document"]["phase"] == "unknown"


def test_operation_identity_cannot_be_rebound_after_rollback(tmp_path: Path) -> None:
    source, _, backend, _, _, _, _ = _setup(tmp_path)
    source.start_initial()
    first = _transition(source)
    assert source.transition(first).outcome is TenantGenerationTransitionOutcome.CHANGED
    rollback = _transition(source, direction="rollback")
    assert source.transition(rollback).outcome is TenantGenerationTransitionOutcome.CHANGED
    rebound = _transition(source)
    assert rebound.digest != first.digest
    assert rebound.operation_id == first.operation_id
    count = len(backend.events)
    with pytest.raises(TenantTargetAdapterError, match="replayed"):
        source.transition(rebound)
    assert len(backend.events) == count
