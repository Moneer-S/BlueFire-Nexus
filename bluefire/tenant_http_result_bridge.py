"""Independent result admission for V2's bounded disposable-app HTTP run.

The caller reopens target and relay audits from protected controller retention.
The engine's finding/completion claims never replace those records. This pure
bridge performs no target operation, persistence, launch or authorization.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from typing import Any

from .engine_attempt_contract import EngineAttemptBinding, EngineEvidenceItem
from .engine_relay import EngineRelayError, RelayAuditRecord, TargetRelayRequest
from .evidence import EvidenceRecord
from .tenant_engine_result_bridge import TenantEngineReportSummary, _engine_report
from .tenant_http_observer import observe_tenant_http_response_v2
from .tenant_http_target_adapter import TenantHttpEngineTargetRequestV2, requested_tenant_v2
from .tenant_http_target_profile import TenantHttpTargetProfileV2, admit_tenant_http_operation
from .tenant_http_target_relay import TenantHttpRelayResultV2
from .tenant_record_controller_contract import tenant_target_snapshot_ref
from .tenant_record_lab import TenantDefenseConfig, TenantRecordFixture
from .tenant_record_target_adapter import TenantBoundAuditReceipt, _check_response
from .util import content_hash, parse_iso8601_datetime

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_STEP = re.compile(r"[a-z][a-z0-9_-]{0,63}")


class TenantHttpResultBridgeError(ValueError):
    """V2 result evidence differs from its independently retained authority."""


def _digest(value: Any) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise TenantHttpResultBridgeError("v2 result proof reference is invalid")
    return value


@dataclass(frozen=True, slots=True)
class TenantHttpBridgedResultV2:
    observation: EvidenceRecord
    engine_report: TenantEngineReportSummary
    operation_ref: str
    generation_ref: str
    audit_binding_ref: str
    audit_retention_ref: str
    relay_audit_ref: str
    relay_retention_ref: str
    target_observation_ref: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.tenant-http-bridged-result.v2",
            "observation": self.observation.to_dict(),
            "engine_report": self.engine_report.to_dict(),
            **{
                name: _digest(getattr(self, name))
                for name in (
                    "operation_ref",
                    "generation_ref",
                    "audit_binding_ref",
                    "audit_retention_ref",
                    "relay_audit_ref",
                    "relay_retention_ref",
                    "target_observation_ref",
                )
            },
        }


def bridge_tenant_http_result_v2(
    *,
    binding: EngineAttemptBinding,
    profile: TenantHttpTargetProfileV2,
    fixture: TenantRecordFixture,
    config: TenantDefenseConfig,
    relay_request: TargetRelayRequest,
    forwarded: TenantHttpRelayResultV2,
    retained_audit_binding: TenantBoundAuditReceipt,
    retained_audit_ref: str,
    retained_relay_audit: RelayAuditRecord,
    retained_relay_audit_ref: str,
    engine_evidence: EngineEvidenceItem | None = None,
    step_id: str = "tenant_http_action_v2",
) -> TenantHttpBridgedResultV2:
    """Admit one target result; refs/copies must be reopened independently.

    Passing the returned result's own audit copy as retained authority defeats
    this caller obligation. Retain finalized observer evidence before supplying
    it to the separate complete-run trace verifier.
    """
    try:
        return _bridge(
            binding=binding,
            profile=profile,
            fixture=fixture,
            config=config,
            relay_request=relay_request,
            forwarded=forwarded,
            retained_audit_binding=retained_audit_binding,
            retained_audit_ref=retained_audit_ref,
            retained_relay_audit=retained_relay_audit,
            retained_relay_audit_ref=retained_relay_audit_ref,
            engine_evidence=engine_evidence,
            step_id=step_id,
        )
    except TenantHttpResultBridgeError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError, EngineRelayError):
        raise TenantHttpResultBridgeError("v2 target result admission failed") from None


def _bridge(
    *,
    binding: EngineAttemptBinding,
    profile: TenantHttpTargetProfileV2,
    fixture: TenantRecordFixture,
    config: TenantDefenseConfig,
    relay_request: TargetRelayRequest,
    forwarded: TenantHttpRelayResultV2,
    retained_audit_binding: TenantBoundAuditReceipt,
    retained_audit_ref: str,
    retained_relay_audit: RelayAuditRecord,
    retained_relay_audit_ref: str,
    engine_evidence: EngineEvidenceItem | None,
    step_id: str,
) -> TenantHttpBridgedResultV2:
    if not all(
        type(value) is expected
        for value, expected in (
            (binding, EngineAttemptBinding),
            (profile, TenantHttpTargetProfileV2),
            (fixture, TenantRecordFixture),
            (config, TenantDefenseConfig),
            (relay_request, TargetRelayRequest),
            (forwarded, TenantHttpRelayResultV2),
            (retained_audit_binding, TenantBoundAuditReceipt),
            (retained_relay_audit, RelayAuditRecord),
        )
    ):
        raise TenantHttpResultBridgeError("v2 result requires typed controller inputs")
    binding.to_dict()
    profile, fixture, config = replace(profile), replace(fixture), replace(config)
    request = replace(forwarded.request)
    if type(request) is not TenantHttpEngineTargetRequestV2:
        raise TenantHttpResultBridgeError("v2 request type changed")
    operation = forwarded.operation
    result = replace(forwarded.result)
    retained, relay, row = (
        replace(retained_audit_binding),
        replace(retained_relay_audit),
        replace(result.audit_row),
    )
    _digest(retained_audit_ref)
    _digest(retained_relay_audit_ref)
    generation = replace(profile.expected_generation)
    snapshot = tenant_target_snapshot_ref(
        fixture_digest=fixture.digest,
        target_snapshot_id=config.target_snapshot_id,
        service_generation=config.service_generation,
    )
    if not isinstance(step_id, str) or _STEP.fullmatch(step_id) is None:
        raise TenantHttpResultBridgeError("v2 observer step is invalid")
    if (
        binding.engine_id != "strix"
        or binding.attempt_id != profile.attempt_id
        or binding.binding_digest != profile.binding_digest
        or binding.objective_ref != profile.objective_ref
        or binding.environment_ref != profile.environment_ref
        or binding.scope_ref != profile.scope_ref
        or binding.target_snapshot_ref != snapshot
        or profile.target_snapshot_ref != snapshot
        or profile.asset_ref != fixture.digest
        or config.fixture_digest != fixture.digest
        or generation.target_snapshot_id != config.target_snapshot_id
        or generation.service_generation != config.service_generation
        or request.profile != profile
        or profile.run_timeout_ms > binding.wall_clock_seconds * 1000
    ):
        raise TenantHttpResultBridgeError("v2 asset or attempt binding changed")
    expected_operation = admit_tenant_http_operation(
        profile, relay_request, deadline_ns=request.deadline_ns
    )
    if (
        operation != expected_operation
        or request.operation != operation
        or result.operation_digest != operation.digest
        or result.relay_request_id != operation.request_id
        or result.generation_digest != generation.digest
        or result.request_target != operation.target
    ):
        raise TenantHttpResultBridgeError("v2 request/operation pairing changed")
    if (
        result.audit_binding != retained
        or result.audit_retention_ref != retained_audit_ref
        or result.target_request_id != row.request_id
        or row.request_id != retained.request_id
        or row.digest != retained.audit_row_digest
        or row.source_identity != "engine_worker"
        or retained.source_identity != "engine_worker"
        or retained.source_admission_digest != profile.engine_source_admission_digest
        or retained.run_id != profile.launcher_run_id
        or retained.attempt_id != profile.launcher_attempt_id
        or retained.fixture_digest != fixture.digest
        or retained.config_digest != config.digest
        or retained.packet_digest != profile.packet_digest
        or retained.plan_digest != generation.plan_digest
        or retained.lifecycle_digest != generation.lifecycle_digest
        or retained.ready_digest != generation.ready_digest
        or retained.target_snapshot_id != generation.target_snapshot_id
        or retained.service_generation != generation.service_generation
        or retained.endpoint != profile.endpoint
        or row.route != operation.route_id
        or row.requested_tenant != requested_tenant_v2(request, fixture)
    ):
        raise TenantHttpResultBridgeError("v2 retained target audit binding changed")
    response = result.response
    _check_response(response)
    response_digest = "sha256:" + hashlib.sha256(response.body).hexdigest()
    if (
        len(response.body) > profile.max_response_bytes
        or response.status != row.response_status
        or len(response.body) != row.response_bytes
        or response_digest != row.response_sha256
        or content_hash(dict(response.headers)) != row.response_headers_sha256
        or response.headers.get("x-bluefire-lab-request") != row.request_id
        or result.protected_secret_absent is not True
    ):
        raise TenantHttpResultBridgeError("v2 response or target audit changed")
    if operation.record_id is not None and row.returned_record_ids not in {
        (),
        (operation.record_id,),
    }:
        raise TenantHttpResultBridgeError("v2 record response identity changed")
    observed_at = parse_iso8601_datetime(row.timestamp)
    if not (
        parse_iso8601_datetime(binding.created_at) <= observed_at
        and parse_iso8601_datetime(profile.created_at)
        <= observed_at
        <= parse_iso8601_datetime(relay.recorded_at)
        < parse_iso8601_datetime(profile.expires_at)
    ):
        raise TenantHttpResultBridgeError("v2 result is outside the bound lifetime")
    expected_observation = content_hash(
        {
            "schema_version": "bluefire.tenant-engine-target-observation.v2",
            "relay_request_id": operation.request_id,
            "operation_digest": operation.digest,
            "target_request_id": row.request_id,
            "generation_digest": generation.digest,
            "target_snapshot_ref": snapshot,
            "request_target": operation.target,
            "audit_row_digest": row.digest,
            "audit_binding_digest": retained.digest,
            "audit_retention_ref": retained_audit_ref,
            "response_status": response.status,
            "response_sha256": response_digest,
            "response_headers_sha256": content_hash(dict(response.headers)),
        }
    )
    if result.target_observation_ref != expected_observation:
        raise TenantHttpResultBridgeError("v2 target observation proof changed")
    if (
        forwarded.relay_audit != relay
        or relay.relay_kind != "target"
        or relay.status != "succeeded"
        or relay.attempt_id != binding.attempt_id
        or relay.objective_ref != binding.objective_ref
        or not 1 <= relay.sequence <= profile.max_http_calls
        or relay.request_id != operation.request_id
        or relay.operation != operation.route_id
        or relay.request_digest != operation.digest
        or relay.request_bytes != 0
        or relay.response_digest != response_digest
        or relay.response_bytes != row.response_bytes
        or relay.result_status != row.response_status
        or relay.policy_digest != profile.policy_digest
        or relay.evidence_ref != expected_observation
        or relay.input_tokens != 0
        or relay.output_tokens != 0
        or relay.cost_microunits != 0
    ):
        raise TenantHttpResultBridgeError("v2 retained relay audit changed")
    observation = observe_tenant_http_response_v2(
        fixture=fixture,
        config=config,
        audit_row=row,
        response_status=response.status,
        response_headers=response.headers,
        response_body=response.body,
        attempt_id=binding.attempt_id,
        run_id=binding.run_id,
        step_id=step_id,
        target_scope_ref=binding.scope_ref,
    )
    return TenantHttpBridgedResultV2(
        observation,
        _engine_report(binding, engine_evidence),
        operation.digest,
        generation.digest,
        retained.digest,
        retained_audit_ref,
        relay.record_digest,
        retained_relay_audit_ref,
        expected_observation,
    )
