from __future__ import annotations

import base64
import os
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

import bluefire.tenant_record_target_adapter as adapter_module
from bluefire.tenant_record_experiment_controller import (
    TenantDefensePlan,
    TenantFailureMechanism,
    TenantRoute,
    TenantTargetOperationUnknown,
)
from bluefire.tenant_record_lab import (
    TenantDefenseConfig,
    TenantRecordFixture,
    baseline_defense_config,
    generate_tenant_record_fixture,
    hardened_defense_config,
    mint_lab_session,
)
from bluefire.tenant_record_lab_launcher import (
    CleanupReceipt,
    LifecycleState,
    LogSummary,
    LoopbackEndpoint,
    OwnedChild,
    Presence,
    ProcessSettlement,
    ReadinessReceipt,
    ServiceRole,
    TenantLabLaunchPlan,
    TenantLabLifecycleRecord,
    WorkspaceLayout,
)
from bluefire.tenant_record_observer import BoundedTenantAuditLog
from bluefire.tenant_record_service import TenantRecordApplication, TenantResponse
from bluefire.tenant_record_target_adapter import (
    FixedTenantLoopbackTransport,
    TenantControllerAdmission,
    TenantGenerationCleanupOutcome,
    TenantGenerationCleanupResult,
    TenantGenerationExpectation,
    TenantGenerationTransitionOutcome,
    TenantGenerationTransitionResult,
    TenantRecordLauncherTargetAdapter,
    TenantRunningGeneration,
    TenantTargetAdapterError,
    TenantTargetPacketBinding,
)
from bluefire.tenant_record_target_child import SOURCE_HEADER, TargetReadyReceipt
from bluefire.util import canonical_json_bytes, content_hash
from bluefire.windows_owner_acl import apply_owner_private_acl_path

SEED = b"tenant-target-adapter-fixture-seed-0001"
KEY = b"tenant-target-adapter-signing-key-material-000001"
CREATED = "2026-11-04T15:00:00Z"
STARTED = "2026-11-04T15:00:01Z"
VERIFIED = "2026-11-04T15:00:02Z"
EXPIRES = "2026-11-04T15:10:00Z"
NOW = datetime(2026, 11, 4, 15, 0, 3, tzinfo=timezone.utc)
DEFENSE_OPERATION = "tenant-defense-" + "a" * 32
ROLLBACK_OPERATION = "tenant-rollback-" + "b" * 32
CLEANUP_OPERATION = "tenant-cleanup-" + "c" * 32


def _digest(label: str) -> str:
    return content_hash({"test": label})


def _protect(path: Path, *, directory: bool) -> None:
    if os.name == "nt":
        apply_owner_private_acl_path(path, directory=directory)
    else:
        path.chmod(0o700 if directory else 0o600)


def _write_private(path: Path, value: bytes) -> None:
    path.write_bytes(value)
    _protect(path, directory=False)


def _admissions(prefix: bytes = b"a") -> tuple[TenantControllerAdmission, ...]:
    return tuple(
        TenantControllerAdmission.create(identity, prefix + bytes([index]) * 31)
        for index, identity in enumerate(
            ("engine_worker", "ordinary_user", "controller_probe"), start=1
        )
    )


def _owned_child(
    role: ServiceRole,
    *,
    plan_digest: str,
    endpoint: LoopbackEndpoint,
    pid: int,
) -> OwnedChild:
    process = _digest(f"process-{role.value}-{pid}")
    spec = _digest(f"spec-{role.value}-{pid}")
    custody = _digest(f"custody-{role.value}-{pid}")
    fields = {
        "role": role.value,
        "process_identity_digest": process,
        "plan_digest": plan_digest,
        "spec_digest": spec,
        "custody_mode": "windows_job_object",
        "custody_snapshot_digest": custody,
    }
    return OwnedChild(
        role=role,
        pid=pid,
        process_identity_digest=process,
        plan_digest=plan_digest,
        custody_mode="windows_job_object",
        custody_snapshot_digest=custody,
        custody_receipt_digest=content_hash(fields),
        spec_digest=spec,
        endpoint=endpoint,
        started_at=STARTED,
    )


def _generic_ready(
    child: OwnedChild,
    *,
    plan: TenantLabLaunchPlan,
    packet_digest: str,
) -> ReadinessReceipt:
    binding = content_hash(
        {
            "role": child.role.value,
            "process": child.process_identity_digest,
            "endpoint": child.endpoint.to_dict(),
            "packet": packet_digest,
            "plan": plan.digest,
        }
    )
    return ReadinessReceipt(
        role=child.role,
        process_identity_digest=child.process_identity_digest,
        spec_digest=child.spec_digest,
        endpoint=child.endpoint,
        binding_digest=binding,
        observed_at=VERIFIED,
        receipt_digest=content_hash({"binding_digest": binding, "observed_at": VERIFIED}),
    )


def _generation(
    root: Path,
    *,
    fixture: TenantRecordFixture,
    config: TenantDefenseConfig,
    marker: str,
    admissions: tuple[TenantControllerAdmission, ...] | None = None,
) -> TenantRunningGeneration:
    suffix = marker[0] * 32
    run_id = "engine-lab-" + suffix
    attempt_id = "engine-attempt-" + marker[-1] * 32
    packet_digest = _digest(f"packet-{marker}")
    target_endpoint = LoopbackEndpoint("127.0.0.1", 41001 + len(marker))
    provider_endpoint = LoopbackEndpoint("127.0.0.1", 42001 + len(marker))
    plan = TenantLabLaunchPlan(
        run_id=run_id,
        attempt_id=attempt_id,
        runtime_digest=_digest("runtime"),
        target_packet_digest=packet_digest,
        provider_manifest_digest=_digest(f"provider-{marker}"),
        provider_token_digest=_digest(f"provider-token-{marker}"),
        target_endpoint=target_endpoint,
        provider_endpoint=provider_endpoint,
        custody_mode="windows_job_object",
        max_runtime_seconds=600,
        max_log_bytes=64 * 1024,
        created_at=CREATED,
    )
    target = _owned_child(
        ServiceRole.TARGET,
        plan_digest=plan.digest,
        endpoint=target_endpoint,
        pid=5101 + len(marker),
    )
    provider = _owned_child(
        ServiceRole.TEST_PROVIDER,
        plan_digest=plan.digest,
        endpoint=provider_endpoint,
        pid=5201 + len(marker),
    )
    target_ready = _generic_ready(target, plan=plan, packet_digest=packet_digest)
    provider_ready = _generic_ready(
        provider, plan=plan, packet_digest=plan.provider_manifest_digest
    )
    lifecycle = TenantLabLifecycleRecord(
        plan=plan,
        revision=3,
        state=LifecycleState.RUNNING,
        prepared_at=CREATED,
        reserved_at=CREATED,
        running_at=VERIFIED,
        ended_at=None,
        children=(target, provider),
        readiness=(target_ready, provider_ready),
        settlements=(),
        cleanup_receipt=None,
    )
    admitted = admissions or _admissions(marker.encode("ascii"))
    packet = TenantTargetPacketBinding(
        run_id=run_id,
        attempt_id=attempt_id,
        packet_digest=packet_digest,
        fixture_digest=fixture.digest,
        config_digest=config.digest,
        max_requests=32,
        max_audit_events=32,
        max_audit_bytes=64 * 1024,
        max_runtime_seconds=600,
        created_at=CREATED,
        expires_at=EXPIRES,
        verified_at=VERIFIED,
    )
    layout = WorkspaceLayout.for_run(root, run_id)
    (layout.run_root / "target").mkdir(parents=True)
    (layout.run_root / "provider").mkdir()
    ready = TargetReadyReceipt(
        pid=target.pid,
        host=target_endpoint.host,
        port=target_endpoint.port,
        packet_digest=packet_digest,
        fixture_digest=fixture.digest,
        config_digest=config.digest,
        target_snapshot_id=config.target_snapshot_id,
        service_generation=config.service_generation,
        admission_digests={item.source_identity: item.token_digest for item in admitted},
        max_audit_events=packet.max_audit_events,
        max_audit_bytes=packet.max_audit_bytes,
        max_requests=packet.max_requests,
        max_runtime_seconds=packet.max_runtime_seconds,
        started_at=STARTED,
    )
    _write_private(layout.target_ready, ready.to_bytes())
    for directory in (
        layout.run_root / "target",
        layout.run_root / "provider",
        layout.run_root,
        root,
    ):
        _protect(directory, directory=True)
    return TenantRunningGeneration(
        lifecycle=lifecycle,
        packet=packet,
        fixture=fixture,
        config=config,
        admissions=admitted,
        liveness_receipt_digest=_digest(f"live-{marker}"),
    )


def _expectation(generation: TenantRunningGeneration, root: Path) -> TenantGenerationExpectation:
    ready = TargetReadyReceipt.from_bytes(
        WorkspaceLayout.for_run(root, generation.lifecycle.plan.run_id).target_ready.read_bytes()
    )
    return TenantGenerationExpectation(
        plan_digest=generation.lifecycle.plan.digest,
        lifecycle_digest=generation.lifecycle.digest,
        ready_digest=ready.ready_digest,
        target_snapshot_id=ready.target_snapshot_id,
        service_generation=ready.service_generation,
    )


def _cleaned_lifecycle(generation: TenantRunningGeneration) -> TenantLabLifecycleRecord:
    lifecycle = generation.lifecycle
    empty = LogSummary(0, "sha256:" + "0" * 64, False)
    settlements = []
    for child in lifecycle.children:
        fields = {
            "role": child.role.value,
            "process_identity_digest": child.process_identity_digest,
            "plan_digest": lifecycle.plan.digest,
            "custody_mode": child.custody_mode,
            "custody_snapshot_digest": child.custody_snapshot_digest,
            "presence": Presence.ABSENT.value,
            "observed_at": "2026-11-04T15:00:04Z",
            "stdout": {
                "byte_count": 0,
                "sha256": empty.sha256,
                "truncated": False,
            },
            "stderr": {
                "byte_count": 0,
                "sha256": empty.sha256,
                "truncated": False,
            },
        }
        settlements.append(
            ProcessSettlement(
                role=child.role,
                process_identity_digest=child.process_identity_digest,
                plan_digest=lifecycle.plan.digest,
                custody_mode=child.custody_mode,
                custody_snapshot_digest=child.custody_snapshot_digest,
                presence=Presence.ABSENT,
                observed_at="2026-11-04T15:00:04Z",
                custody_receipt_digest=content_hash(fields),
                stdout=empty,
                stderr=empty,
            )
        )
    cleanup_fields = {
        "state": Presence.ABSENT.value,
        "plan_digest": lifecycle.plan.digest,
        "workspace_digest": _digest("cleaned-workspace"),
        "observed_at": "2026-11-04T15:00:05Z",
    }
    cleanup = CleanupReceipt(
        state=Presence.ABSENT,
        plan_digest=lifecycle.plan.digest,
        workspace_digest=cleanup_fields["workspace_digest"],
        observed_at=cleanup_fields["observed_at"],
        receipt_digest=content_hash(cleanup_fields),
    )
    return TenantLabLifecycleRecord(
        plan=lifecycle.plan,
        revision=lifecycle.revision + 2,
        state=LifecycleState.CLEANED,
        prepared_at=lifecycle.prepared_at,
        reserved_at=lifecycle.reserved_at,
        running_at=lifecycle.running_at,
        ended_at="2026-11-04T15:00:04Z",
        children=lifecycle.children,
        readiness=lifecycle.readiness,
        settlements=tuple(settlements),
        cleanup_receipt=cleanup,
    )


class FakeSource:
    def __init__(self, current: TenantRunningGeneration, root: Path) -> None:
        self.current = current
        self.root = root
        self.checked: list[TenantGenerationExpectation | None] = []
        self.transition_result: TenantGenerationTransitionResult | None = None
        self.transition_current: TenantRunningGeneration | None = None
        self.raise_transition_unknown = False
        self.cleanup_result: TenantGenerationCleanupResult | None = None
        self.transition_intents = []
        self.cleanup_intents = []
        self.audit_bindings = []
        self.fail_check = False

    def checked_running(
        self, expected: TenantGenerationExpectation | None
    ) -> TenantRunningGeneration:
        self.checked.append(expected)
        if self.fail_check:
            raise RuntimeError("secret=must-not-escape")
        if expected is not None and expected != _expectation(self.current, self.root):
            raise RuntimeError("stale generation")
        return self.current

    def transition(self, intent):  # type: ignore[no-untyped-def]
        self.transition_intents.append(intent)
        if self.transition_result is None:
            raise RuntimeError("transition not configured token=secret")
        if self.transition_current is not None:
            self.current = self.transition_current
        elif self.transition_result.generation is not None:
            self.current = self.transition_result.generation
        if self.raise_transition_unknown:
            raise TenantTargetOperationUnknown(
                "source transition unknown",
                receipt_digest=_digest("source-raised-unknown"),
            )
        return self.transition_result

    def cleanup(self, intent):  # type: ignore[no-untyped-def]
        self.cleanup_intents.append(intent)
        if self.cleanup_result is None:
            raise RuntimeError("cleanup not configured token=secret")
        return self.cleanup_result

    def retain_audit_binding(self, binding):  # type: ignore[no-untyped-def]
        self.audit_bindings.append(binding)
        return content_hash({"retained_audit_binding": binding.digest})


class FakeTransport:
    def __init__(
        self,
        *,
        generation: TenantRunningGeneration,
        root: Path,
        signing_key: bytes | None = None,
    ) -> None:
        self.generation = generation
        self.root = root
        self.calls = []
        self.counter = 0
        self.audit = BoundedTenantAuditLog(max_events=generation.packet.max_audit_events)
        self.application = TenantRecordApplication(
            fixture=generation.fixture,
            config=generation.config,
            audit_log=self.audit,
            signing_key=signing_key,
            allowed_hosts=("tenant-record.test",),
            clock=lambda: NOW,
            request_id_factory=self._request_id,
        )

    def _request_id(self) -> str:
        self.counter += 1
        return f"request-{self.counter:024x}"

    def request(self, endpoint, request) -> TenantResponse:  # type: ignore[no-untyped-def]
        self.calls.append((endpoint, request.target, request.headers, request.timeout_seconds))
        matching = [
            item for item in self.generation.admissions if item.token == request.source_token
        ]
        assert len(matching) == 1
        headers = {name: value for name, value in request.headers if name != SOURCE_HEADER}
        response = self.application.handle(
            "GET", request.target, headers, source_identity=matching[0].source_identity
        )
        layout = WorkspaceLayout.for_run(self.root, self.generation.lifecycle.plan.run_id)
        _write_private(
            layout.target_audit,
            b"".join(canonical_json_bytes(row.to_dict()) + b"\n" for row in self.audit.snapshot()),
        )
        return response


def _fixture_and_configs() -> tuple[TenantRecordFixture, TenantDefenseConfig, TenantDefenseConfig]:
    fixture = generate_tenant_record_fixture(SEED)
    before = baseline_defense_config(fixture)
    after = hardened_defense_config(
        fixture,
        signing_key=KEY,
        key_id="key-target-adapter-0001",
        application_nonce="nonce-target-adapter-0001",
        prior=before,
    )
    return fixture, before, after


def _plan(
    fixture: TenantRecordFixture,
    before: TenantDefenseConfig,
    after: TenantDefenseConfig,
) -> TenantDefensePlan:
    actor = "bluefire-controller"
    review = {
        "schema_version": "bluefire.tenant-record-defense-review.v1",
        "preimage_digest": before.digest,
        "approved_configuration_digest": after.digest,
        "responsible_actor": actor,
        "reviewed_at": CREATED,
        "claims_application": False,
    }
    review_digest = content_hash(review)
    return TenantDefensePlan(
        operation_id=DEFENSE_OPERATION,
        fixture_digest=fixture.digest,
        before=before,
        after=after,
        review_id="review-" + review_digest.removeprefix("sha256:")[:20],
        review_digest=review_digest,
        responsible_actor=actor,
        planned_at=CREATED,
    )


def _mechanism(fixture: TenantRecordFixture) -> TenantFailureMechanism:
    baseline = baseline_defense_config(fixture)
    record = fixture.records_for(fixture.protected_tenant_id)[0]
    binding = TenantFailureMechanism._request_binding(
        fixture.digest,
        baseline.target_snapshot_id,
        TenantRoute.RECORD_LOOKUP,
        fixture.protected_tenant_id,
        record.record_id,
    )
    return TenantFailureMechanism(
        fixture_digest=fixture.digest,
        original_target_snapshot_id=baseline.target_snapshot_id,
        route=TenantRoute.RECORD_LOOKUP,
        protected_tenant_id=fixture.protected_tenant_id,
        record_id=record.record_id,
        request_digest=content_hash(binding),
    )


def _adapter(
    tmp_path: Path,
    generation: TenantRunningGeneration,
    *,
    signing_key: bytes | None = None,
) -> tuple[TenantRecordLauncherTargetAdapter, FakeSource, FakeTransport]:
    source = FakeSource(generation, tmp_path)
    transport = FakeTransport(generation=generation, root=tmp_path, signing_key=signing_key)
    return (
        TenantRecordLauncherTargetAdapter(
            scratch_root=tmp_path, source=source, transport=transport
        ),
        source,
        transport,
    )


def test_baseline_exact_mechanism_and_audit_are_bound_to_running_generation(
    tmp_path: Path,
) -> None:
    fixture, before, _after = _fixture_and_configs()
    generation = _generation(tmp_path, fixture=fixture, config=before, marker="1a")
    adapter, source, transport = _adapter(tmp_path, generation)

    assert adapter.current_config() == before
    response = adapter.controller_request(
        _mechanism(fixture), source_identity="controller_probe", session_token=None
    )
    row = adapter.audit_row(response.headers["x-bluefire-lab-request"])

    assert response.status == 200
    assert row.source_identity == "controller_probe"
    assert row.target_snapshot_id == before.target_snapshot_id
    bound, retained = adapter.audit_binding(
        row.request_id,
        generation_digest=_expectation(generation, tmp_path).digest,
    )
    assert bound.plan_digest == generation.lifecycle.plan.digest
    assert bound.run_id == generation.lifecycle.plan.run_id
    assert bound.attempt_id == generation.lifecycle.plan.attempt_id
    assert bound.packet_digest == generation.packet.packet_digest
    assert bound.endpoint == generation.lifecycle.plan.target_endpoint
    assert retained == content_hash({"retained_audit_binding": bound.digest})
    endpoint, target, headers, timeout = transport.calls[0]
    assert endpoint == generation.lifecycle.plan.target_endpoint
    assert target.startswith("/records/")
    assert dict(headers)["host"] == "tenant-record.test"
    assert dict(headers)["x-bluefire-lab-tenant"] == fixture.protected_tenant_id
    assert "authorization" not in dict(headers)
    assert 0 < timeout <= 5
    assert len(source.checked) >= 5


def test_hardened_reproducer_replays_original_assertion_and_legitimate_use_uses_session(
    tmp_path: Path,
) -> None:
    fixture, _before, after = _fixture_and_configs()
    generation = _generation(tmp_path, fixture=fixture, config=after, marker="2b")
    adapter, _source, transport = _adapter(tmp_path, generation, signing_key=KEY)
    mechanism = _mechanism(fixture)

    denied = adapter.controller_request(
        mechanism, source_identity="controller_probe", session_token=None
    )
    denied_row = adapter.audit_row(denied.headers["x-bluefire-lab-request"])
    token = mint_lab_session(
        fixture,
        after,
        signing_key=KEY,
        subject_id=fixture.legitimate_subject_id,
        tenant_id=fixture.protected_tenant_id,
        issued_at=NOW,
        lifetime_seconds=60,
    )
    allowed = adapter.controller_request(
        mechanism, source_identity="ordinary_user", session_token=token
    )
    allowed_row = adapter.audit_row(allowed.headers["x-bluefire-lab-request"])

    assert denied.status == 401
    assert denied_row.decision == "denied_missing_session"
    assert dict(transport.calls[0][2])["x-bluefire-lab-tenant"] == fixture.protected_tenant_id
    assert allowed.status == 200
    assert allowed_row.source_identity == "ordinary_user"
    assert "x-bluefire-lab-tenant" not in dict(transport.calls[1][2])
    assert dict(transport.calls[1][2])["authorization"].startswith("BlueFireLab ")


def test_adapter_does_not_expose_engine_admission_or_secrets(tmp_path: Path) -> None:
    fixture, before, _after = _fixture_and_configs()
    generation = _generation(tmp_path, fixture=fixture, config=before, marker="3c")
    adapter, _source, _transport = _adapter(tmp_path, generation)
    secret = generation.admissions[0].token.decode("latin1")

    with pytest.raises(TenantTargetAdapterError, match="source"):
        adapter.controller_request(
            _mechanism(fixture), source_identity="engine_worker", session_token=None
        )
    assert secret not in repr(generation)
    assert secret not in repr(generation.admissions[0])


def test_readiness_drift_makes_current_config_unknown(tmp_path: Path) -> None:
    fixture, before, _after = _fixture_and_configs()
    generation = _generation(tmp_path, fixture=fixture, config=before, marker="4d")
    layout = WorkspaceLayout.for_run(tmp_path, generation.lifecycle.plan.run_id)
    ready = TargetReadyReceipt.from_bytes(layout.target_ready.read_bytes())
    _write_private(layout.target_ready, replace(ready, pid=ready.pid + 1).to_bytes())
    adapter, _source, _transport = _adapter(tmp_path, generation)

    assert adapter.current_config() is None


def test_audit_rejects_noncanonical_or_wrong_generation_rows(tmp_path: Path) -> None:
    fixture, before, _after = _fixture_and_configs()
    generation = _generation(tmp_path, fixture=fixture, config=before, marker="5e")
    adapter, _source, _transport = _adapter(tmp_path, generation)
    layout = WorkspaceLayout.for_run(tmp_path, generation.lifecycle.plan.run_id)
    row = {
        "schema_version": "bluefire.tenant-record-audit.v1",
        "sequence": 1,
        "request_id": "request-" + "1" * 24,
        "timestamp": "2026-11-04T15:00:03Z",
        "source_identity": "controller_probe",
        "route": "record_lookup",
        "requested_tenant": fixture.protected_tenant_id,
        "authenticated_tenant": fixture.protected_tenant_id,
        "response_status": 200,
        "response_bytes": 2,
        "response_sha256": _digest("body"),
        "response_headers_sha256": _digest("headers"),
        "returned_record_ids": [],
        "returned_record_digests": [],
        "decision": "allowed_client_asserted",
        "target_snapshot_id": "target-snapshot-wrong",
        "service_generation": before.service_generation,
    }
    _write_private(layout.target_audit, canonical_json_bytes(row) + b"\n")

    with pytest.raises(TenantTargetAdapterError, match="generation"):
        adapter.audit_row(row["request_id"])


def test_apply_and_rollback_use_fresh_generations_and_canonical_receipts(
    tmp_path: Path,
) -> None:
    fixture, before, after = _fixture_and_configs()
    baseline = _generation(tmp_path, fixture=fixture, config=before, marker="6f")
    hardened = _generation(
        tmp_path,
        fixture=fixture,
        config=after,
        marker="7a",
        admissions=_admissions(b"h"),
    )
    baseline_two = _generation(
        tmp_path,
        fixture=fixture,
        config=before,
        marker="8b",
        admissions=_admissions(b"r"),
    )
    adapter, source, _transport = _adapter(tmp_path, baseline)
    source.transition_result = TenantGenerationTransitionResult(
        outcome=TenantGenerationTransitionOutcome.CHANGED,
        prior_lifecycle_digest=baseline.lifecycle.digest,
        write_ahead_receipt_digest=_digest("apply-wa"),
        source_receipt_digest=_digest("apply-source"),
        generation=hardened,
    )
    plan = _plan(fixture, before, after)

    applied = adapter.apply_defense(plan)
    assert applied.observed_config == after
    assert source.transition_intents[0].prior_config_digest == before.digest
    assert source.transition_intents[0].desired_config_digest == after.digest
    assert baseline.lifecycle.plan.run_id != hardened.lifecycle.plan.run_id

    source.transition_result = TenantGenerationTransitionResult(
        outcome=TenantGenerationTransitionOutcome.CHANGED,
        prior_lifecycle_digest=hardened.lifecycle.digest,
        write_ahead_receipt_digest=_digest("rollback-wa"),
        source_receipt_digest=_digest("rollback-source"),
        generation=baseline_two,
    )
    rolled_back = adapter.rollback_defense(plan, operation_id=ROLLBACK_OPERATION)
    assert rolled_back.observed_config == before
    assert rolled_back.receipt_digest != applied.receipt_digest


def test_transition_source_failure_is_unknown_and_sanitized(tmp_path: Path) -> None:
    fixture, before, after = _fixture_and_configs()
    generation = _generation(tmp_path, fixture=fixture, config=before, marker="9c")
    adapter, _source, _transport = _adapter(tmp_path, generation)

    with pytest.raises(TenantTargetOperationUnknown) as raised:
        adapter.apply_defense(_plan(fixture, before, after))

    assert "secret" not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.receipt_digest.startswith("sha256:")


def test_cleanup_requires_exact_preimage_and_reports_verified_absence(tmp_path: Path) -> None:
    fixture, _before, after = _fixture_and_configs()
    generation = _generation(tmp_path, fixture=fixture, config=after, marker="ad")
    adapter, source, _transport = _adapter(tmp_path, generation, signing_key=KEY)
    source.cleanup_result = TenantGenerationCleanupResult(
        outcome=TenantGenerationCleanupOutcome.CLEANED,
        prior_lifecycle_digest=generation.lifecycle.digest,
        write_ahead_receipt_digest=_digest("cleanup-wa"),
        source_receipt_digest=_digest("cleanup-source"),
        cleaned_lifecycle=_cleaned_lifecycle(generation),
    )

    result = adapter.cleanup_lab(
        fixture,
        expected_config_digest=after.digest,
        operation_id=CLEANUP_OPERATION,
    )

    assert result.verified_absent is True
    assert source.cleanup_intents[0].prior.plan_digest == generation.lifecycle.plan.digest


def test_not_changed_and_unknown_transition_results_remain_distinct(tmp_path: Path) -> None:
    fixture, before, after = _fixture_and_configs()
    generation = _generation(tmp_path, fixture=fixture, config=before, marker="be")
    plan = _plan(fixture, before, after)
    adapter, source, _transport = _adapter(tmp_path, generation)
    source.transition_result = TenantGenerationTransitionResult(
        outcome=TenantGenerationTransitionOutcome.NOT_CHANGED,
        prior_lifecycle_digest=generation.lifecycle.digest,
        write_ahead_receipt_digest=_digest("not-changed-wa"),
        source_receipt_digest=_digest("not-changed-source"),
        generation=generation,
    )

    unchanged = adapter.apply_defense(plan)
    assert unchanged.observed_config == before

    source.transition_result = TenantGenerationTransitionResult(
        outcome=TenantGenerationTransitionOutcome.UNKNOWN,
        prior_lifecycle_digest=generation.lifecycle.digest,
        write_ahead_receipt_digest=_digest("unknown-wa"),
        source_receipt_digest=_digest("unknown-source"),
        generation=None,
    )
    with pytest.raises(TenantTargetOperationUnknown):
        adapter.apply_defense(plan)


def test_unknown_transition_reconciliation_can_adopt_fresh_active_generation(
    tmp_path: Path,
) -> None:
    fixture, before, after = _fixture_and_configs()
    baseline = _generation(tmp_path, fixture=fixture, config=before, marker="ca")
    hardened = _generation(
        tmp_path,
        fixture=fixture,
        config=after,
        marker="db",
        admissions=_admissions(b"n"),
    )
    adapter, source, _transport = _adapter(tmp_path, baseline)
    source.transition_current = hardened
    source.transition_result = TenantGenerationTransitionResult(
        outcome=TenantGenerationTransitionOutcome.UNKNOWN,
        prior_lifecycle_digest=baseline.lifecycle.digest,
        write_ahead_receipt_digest=_digest("unknown-reconcile-wa"),
        source_receipt_digest=_digest("unknown-reconcile-source"),
        generation=None,
    )

    with pytest.raises(TenantTargetOperationUnknown):
        adapter.apply_defense(_plan(fixture, before, after))

    assert adapter.current_config() == after
    assert source.checked[-1] is None


def test_invalid_post_effect_settlement_is_unknown_not_an_adapter_error(
    tmp_path: Path,
) -> None:
    fixture, before, after = _fixture_and_configs()
    baseline = _generation(tmp_path, fixture=fixture, config=before, marker="ec")
    wrong = _generation(
        tmp_path,
        fixture=fixture,
        config=before,
        marker="fd",
        admissions=_admissions(b"w"),
    )
    adapter, source, _transport = _adapter(tmp_path, baseline)
    source.transition_result = TenantGenerationTransitionResult(
        outcome=TenantGenerationTransitionOutcome.CHANGED,
        prior_lifecycle_digest=baseline.lifecycle.digest,
        write_ahead_receipt_digest=_digest("wrong-wa"),
        source_receipt_digest=_digest("wrong-source"),
        generation=wrong,
    )

    with pytest.raises(TenantTargetOperationUnknown) as raised:
        adapter.apply_defense(_plan(fixture, before, after))

    assert raised.value.__cause__ is None
    assert source.current == wrong


def test_source_raised_unknown_also_allows_fresh_reconciliation(tmp_path: Path) -> None:
    fixture, before, after = _fixture_and_configs()
    baseline = _generation(tmp_path, fixture=fixture, config=before, marker="ac")
    hardened = _generation(
        tmp_path,
        fixture=fixture,
        config=after,
        marker="bd",
        admissions=_admissions(b"s"),
    )
    adapter, source, _transport = _adapter(tmp_path, baseline)
    source.transition_current = hardened
    source.transition_result = TenantGenerationTransitionResult(
        outcome=TenantGenerationTransitionOutcome.UNKNOWN,
        prior_lifecycle_digest=baseline.lifecycle.digest,
        write_ahead_receipt_digest=_digest("raised-wa"),
        source_receipt_digest=_digest("raised-source"),
        generation=None,
    )
    source.raise_transition_unknown = True

    with pytest.raises(TenantTargetOperationUnknown):
        adapter.apply_defense(_plan(fixture, before, after))

    assert adapter.current_config() == after
    assert source.checked[-1] is None


def test_result_outcomes_must_be_typed_enums() -> None:
    with pytest.raises(TenantTargetAdapterError, match="outcome"):
        TenantGenerationTransitionResult(
            outcome="changed",  # type: ignore[arg-type]
            prior_lifecycle_digest=_digest("bad-transition-prior"),
            write_ahead_receipt_digest=_digest("bad-transition-wa"),
            source_receipt_digest=_digest("bad-transition-source"),
            generation=None,
        )
    with pytest.raises(TenantTargetAdapterError, match="outcome"):
        TenantGenerationCleanupResult(
            outcome="cleaned",  # type: ignore[arg-type]
            prior_lifecycle_digest=_digest("bad-cleanup-prior"),
            write_ahead_receipt_digest=_digest("bad-cleanup-wa"),
            source_receipt_digest=_digest("bad-cleanup-source"),
        )


def test_stale_liveness_verification_time_is_rejected(tmp_path: Path) -> None:
    fixture, before, _after = _fixture_and_configs()
    generation = _generation(tmp_path, fixture=fixture, config=before, marker="ae")
    stale = replace(
        generation,
        packet=replace(generation.packet, verified_at=CREATED),
    )
    adapter, _source, _transport = _adapter(tmp_path, stale)

    assert adapter.current_config() is None


def test_replaced_scratch_root_cannot_redirect_protected_reads(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    _protect(scratch, directory=True)
    fixture, before, _after = _fixture_and_configs()
    generation = _generation(scratch, fixture=fixture, config=before, marker="ce")
    adapter, source, _transport = _adapter(scratch, generation)
    moved = tmp_path / "moved-scratch"
    scratch.rename(moved)
    source.root = moved
    scratch.mkdir()
    _protect(scratch, directory=True)

    assert adapter.current_config() is None


def test_retained_audit_binding_requires_exact_generation_identity(tmp_path: Path) -> None:
    fixture, before, _after = _fixture_and_configs()
    generation = _generation(tmp_path, fixture=fixture, config=before, marker="df")
    adapter, _source, _transport = _adapter(tmp_path, generation)
    response = adapter.controller_request(
        _mechanism(fixture), source_identity="controller_probe", session_token=None
    )
    request_id = response.headers["x-bluefire-lab-request"]
    adapter.audit_row(request_id)

    with pytest.raises(TenantTargetAdapterError, match="unavailable"):
        adapter.audit_binding(
            request_id,
            generation_digest=_digest("different-generation"),
        )


def test_audit_timestamp_before_child_readiness_is_rejected(tmp_path: Path) -> None:
    fixture, before, _after = _fixture_and_configs()
    generation = _generation(tmp_path, fixture=fixture, config=before, marker="ea")
    adapter, _source, transport = _adapter(tmp_path, generation)
    response = adapter.controller_request(
        _mechanism(fixture), source_identity="controller_probe", session_token=None
    )
    row = replace(transport.audit.snapshot()[0], timestamp=CREATED)
    layout = WorkspaceLayout.for_run(tmp_path, generation.lifecycle.plan.run_id)
    _write_private(layout.target_audit, canonical_json_bytes(row.to_dict()) + b"\n")

    with pytest.raises(TenantTargetAdapterError, match="lifetime"):
        adapter.audit_row(response.headers["x-bluefire-lab-request"])


def test_fixed_loopback_transport_emits_only_fixed_get_grammar(monkeypatch) -> None:
    body = b'{"records":[]}'

    class Response:
        status = 200

        @staticmethod
        def read(maximum: int) -> bytes:
            assert maximum == 64 * 1024 + 1
            return body

        @staticmethod
        def getheaders():
            return [
                ("content-type", "application/json"),
                ("content-length", str(len(body))),
                ("cache-control", "no-store"),
                ("x-content-type-options", "nosniff"),
                ("x-bluefire-lab-request", "request-" + "1" * 24),
            ]

    class Connection:
        instance = None

        def __init__(self, host: str, port: int, timeout: float) -> None:
            self.host = host
            self.port = port
            self.timeout = timeout
            self.method = None
            self.target = None
            self.headers = []
            Connection.instance = self

        def putrequest(
            self,
            method: str,
            target: str,
            *,
            skip_host: bool,
            skip_accept_encoding: bool,
        ) -> None:
            self.method = method
            self.target = target
            assert skip_host and skip_accept_encoding

        def putheader(self, name: str, value: str) -> None:
            self.headers.append((name, value))

        def endheaders(self) -> None:
            return

        def getresponse(self) -> Response:
            return Response()

        def close(self) -> None:
            return

    monkeypatch.setattr(adapter_module.http.client, "HTTPConnection", Connection)
    request = adapter_module._FixedTargetRequest(
        route=TenantRoute.RECORD_LOOKUP,
        protected_tenant_id="tenant-protected",
        record_id="record-protected-0001",
        source_token=b"z" * 32,
        timeout_seconds=2.0,
        tenant_header="tenant-protected",
    )

    response = FixedTenantLoopbackTransport().request(LoopbackEndpoint("127.0.0.1", 43101), request)

    wire = Connection.instance
    assert wire is not None
    assert (wire.method, wire.target) == ("GET", "/records/record-protected-0001")
    assert wire.timeout == 2.0
    assert dict(wire.headers)["host"] == "tenant-record.test"
    encoded = dict(wire.headers)[SOURCE_HEADER]
    assert encoded == base64.urlsafe_b64encode(b"z" * 32).decode("ascii").rstrip("=")
    assert "=" not in encoded
    assert response.body == body


def test_duplicate_response_request_identity_becomes_unknown_before_overwrite(
    tmp_path: Path,
) -> None:
    fixture, before, _after = _fixture_and_configs()
    generation = _generation(tmp_path, fixture=fixture, config=before, marker="bf")
    request_id = "request-" + "9" * 24
    body = b"{}"
    response = TenantResponse(
        status=200,
        headers={
            "content-type": "application/json",
            "content-length": str(len(body)),
            "cache-control": "no-store",
            "x-content-type-options": "nosniff",
            "x-bluefire-lab-request": request_id,
        },
        body=body,
    )

    class RepeatingTransport:
        def request(self, _endpoint, _request):  # type: ignore[no-untyped-def]
            return response

    source = FakeSource(generation, tmp_path)
    adapter = TenantRecordLauncherTargetAdapter(
        scratch_root=tmp_path,
        source=source,
        transport=RepeatingTransport(),
    )
    mechanism = _mechanism(fixture)
    adapter.controller_request(mechanism, source_identity="controller_probe", session_token=None)

    with pytest.raises(TenantTargetOperationUnknown):
        adapter.controller_request(
            mechanism, source_identity="controller_probe", session_token=None
        )
