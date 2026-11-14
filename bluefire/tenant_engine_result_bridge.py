"""Pure controller admission of one retained Strix target action result.

The caller supplies controller-owned attempt/policy/configuration values and an
target and relay audit receipts reopened from protected retention, separately
from the result. The relay receipt commits the exact action/response pairing.
Nothing here launches an engine, reads a target, writes a store, or upgrades an
engine assertion to independent evidence. A refusal or missing target result is
not an input to this bridge and cannot establish prevention.

Integration seam: retain ``observation.evidence`` in the attempt's finalized
RunStore bundle, then pass ``observation.independent_observation()`` to
``EngineExperiment.record_independent_observation``. Keep upstream evidence in
the existing engine-evidence settlement path. This module performs neither
write; the product store must verify finalized evidence before persistence.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from typing import Any

from .engine_attempt_contract import EngineAttemptBinding, EngineEvidenceItem, EvidenceCategory
from .engine_relay import (
    EngineRelayError,
    RelayAuditRecord,
    TargetOperation,
    TargetRelayPolicy,
    TargetRelayRequest,
    _target_operation,
)
from .tenant_record_experiment_controller import (
    TenantEngineObservation,
    TenantFailureMechanism,
    tenant_target_snapshot_ref,
)
from .tenant_record_lab import TenantDefenseConfig, TenantRecordFixture
from .tenant_record_observer import checked_observation_content, observe_tenant_response
from .tenant_record_target_adapter import (
    TenantBoundAuditReceipt,
    TenantEngineTargetRequest,
    TenantEngineTargetResult,
)
from .util import content_hash, parse_iso8601_datetime

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_STEP = re.compile(r"[a-z][a-z0-9_-]{0,63}")
_LAUNCHER_RUN = re.compile(r"engine-lab-[0-9a-f]{32}")
_ATTEMPT = re.compile(r"engine-attempt-[0-9a-f]{32}")
_SNAPSHOT_FIELDS = frozenset(
    {
        "schema_version",
        "upstream_run_id",
        "engine_status",
        "attempt_state",
        "completeness",
        "exit_reason",
        "process_exit_code",
        "process_classification",
        "engine_reported_findings",
        "security_outcome",
        "caveats",
        "run_record_sha256",
        "coverage_sha256",
    }
)


class TenantEngineResultBridgeError(ValueError):
    """The supplied result does not match its exact controller authority."""


def _digest(value: Any) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise TenantEngineResultBridgeError("result proof reference is invalid")
    return value


@dataclass(frozen=True, slots=True)
class TenantEngineReportSummary:
    """Closed projection; arbitrary engine prose and artifact paths stay private."""

    evidence_ref: str | None
    source_artifact_ref: str | None
    reported_state: str
    reported_completeness: str
    reported_findings: bool | None

    def __post_init__(self) -> None:
        if (self.evidence_ref is None) != (self.source_artifact_ref is None):
            raise TenantEngineResultBridgeError("engine report references are incomplete")
        if self.evidence_ref is not None:
            _digest(self.evidence_ref)
            _digest(self.source_artifact_ref)
        if (
            self.reported_state
            not in {
                "running",
                "completed",
                "partial",
                "failed",
                "cancelled",
                "budget_exhausted",
                "unknown",
            }
            or self.reported_completeness not in {"complete", "partial", "unknown"}
            or type(self.reported_findings) not in {bool, type(None)}
            or (
                self.evidence_ref is None
                and (
                    self.reported_state != "unknown"
                    or self.reported_completeness != "unknown"
                    or self.reported_findings is not None
                )
            )
        ):
            raise TenantEngineResultBridgeError("engine report summary is invalid")

    def to_dict(self) -> dict[str, Any]:
        replace(self)
        return {
            "evidence_ref": self.evidence_ref,
            "source_artifact_ref": self.source_artifact_ref,
            "reported_state": self.reported_state,
            "reported_completeness": self.reported_completeness,
            "reported_findings": self.reported_findings,
            "security_outcome": "not_independently_established",
        }


@dataclass(frozen=True, slots=True)
class TenantEngineBridgedResult:
    observation: TenantEngineObservation
    engine_report: TenantEngineReportSummary
    operation_ref: str
    generation_ref: str
    audit_binding_ref: str
    audit_retention_ref: str
    relay_audit_ref: str
    relay_retention_ref: str
    target_observation_ref: str

    def __post_init__(self) -> None:
        replace(self.observation)
        replace(self.engine_report)
        for reference in (
            self.operation_ref,
            self.generation_ref,
            self.audit_binding_ref,
            self.audit_retention_ref,
            self.relay_audit_ref,
            self.relay_retention_ref,
            self.target_observation_ref,
        ):
            _digest(reference)

    def to_dict(self) -> dict[str, Any]:
        """Return hashes and bounded controller observations, never raw telemetry."""
        replace(self)
        observation = replace(self.observation)
        return {
            "schema_version": "bluefire.tenant-engine-bridged-result.v1",
            "observation": observation.to_dict(),
            "engine_report": self.engine_report.to_dict(),
            "operation_ref": self.operation_ref,
            "generation_ref": self.generation_ref,
            "audit_binding_ref": self.audit_binding_ref,
            "audit_retention_ref": self.audit_retention_ref,
            "relay_audit_ref": self.relay_audit_ref,
            "relay_retention_ref": self.relay_retention_ref,
            "target_observation_ref": self.target_observation_ref,
        }


def _engine_report(
    binding: EngineAttemptBinding, evidence: EngineEvidenceItem | None
) -> TenantEngineReportSummary:
    if evidence is None:
        return TenantEngineReportSummary(None, None, "unknown", "unknown", None)
    if not isinstance(evidence, EngineEvidenceItem):
        raise TenantEngineResultBridgeError("engine report is not admitted evidence")
    document = evidence.to_dict()  # Recheck canonical identity and bounded content.
    if (
        evidence.attempt_id != binding.attempt_id
        or evidence.run_id != binding.run_id
        or evidence.producer != "strix"
        or evidence.category is not EvidenceCategory.ENGINE_ASSERTION
        or evidence.parent_evidence_ids
    ):
        raise TenantEngineResultBridgeError("engine report belongs to another attempt or producer")
    content = document["content"]
    if (
        set(content) != _SNAPSHOT_FIELDS
        or content["schema_version"] != "bluefire.strix-run-snapshot.v1"
        or content["security_outcome"] != "not_independently_established"
        or content["run_record_sha256"] != evidence.source_artifact_digest
        or content["attempt_state"]
        not in {
            "running",
            "completed",
            "partial",
            "failed",
            "cancelled",
            "budget_exhausted",
            "unknown",
        }
        or content["completeness"] not in {"complete", "partial", "unknown"}
        or type(content["engine_reported_findings"]) not in {bool, type(None)}
    ):
        raise TenantEngineResultBridgeError("engine report is not a bounded Strix snapshot")
    _digest(content["run_record_sha256"])
    if content["coverage_sha256"] is not None:
        _digest(content["coverage_sha256"])
    return TenantEngineReportSummary(
        content_hash(document),
        evidence.source_artifact_digest,
        content["attempt_state"],
        content["completeness"],
        content["engine_reported_findings"],
    )


def bridge_tenant_engine_result(
    *,
    binding: EngineAttemptBinding,
    policy: TargetRelayPolicy,
    fixture: TenantRecordFixture,
    config: TenantDefenseConfig,
    operation: TargetOperation,
    relay_request: TargetRelayRequest,
    request: TenantEngineTargetRequest,
    result: TenantEngineTargetResult,
    retained_audit_binding: TenantBoundAuditReceipt,
    retained_audit_ref: str,
    retained_relay_audit: RelayAuditRecord,
    retained_relay_audit_ref: str,
    engine_evidence: EngineEvidenceItem | None = None,
    step_id: str = "tenant_engine_action",
) -> TenantEngineBridgedResult:
    """Bind one admitted action to protected telemetry using pinned authority.

    ``retained_audit_binding`` and its reference must be independently reopened
    from trusted retention by generation and target request ID. Passing the
    result's own copy as retention evidence defeats that caller obligation.
    ``retained_relay_audit`` must likewise be independently reopened from the
    trusted relay's successful audit retention. Its evidence reference binds the
    operation to the response; recomputing a result proof cannot replace it.
    Target audit run/attempt IDs identify the launcher generation, while the
    relay audit correlates the action with the active engine attempt.
    Fresh attempts must supply fresh attempt/run/request identities; old results
    cannot be relabeled because the receipt and operation bind those identities.
    Unknown/refused actions without an exact retained target result must remain
    unknown in the outer job/controller path.
    """
    try:
        return _bridge(
            binding=binding,
            policy=policy,
            fixture=fixture,
            config=config,
            operation=operation,
            relay_request=relay_request,
            request=request,
            result=result,
            retained_audit_binding=retained_audit_binding,
            retained_audit_ref=retained_audit_ref,
            retained_relay_audit=retained_relay_audit,
            retained_relay_audit_ref=retained_relay_audit_ref,
            engine_evidence=engine_evidence,
            step_id=step_id,
        )
    except TenantEngineResultBridgeError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError, EngineRelayError):
        # Exception prose from target/engine values must not cross this boundary.
        raise TenantEngineResultBridgeError("target result admission failed") from None


def _bridge(
    *,
    binding: EngineAttemptBinding,
    policy: TargetRelayPolicy,
    fixture: TenantRecordFixture,
    config: TenantDefenseConfig,
    operation: TargetOperation,
    relay_request: TargetRelayRequest,
    request: TenantEngineTargetRequest,
    result: TenantEngineTargetResult,
    retained_audit_binding: TenantBoundAuditReceipt,
    retained_audit_ref: str,
    retained_relay_audit: RelayAuditRecord,
    retained_relay_audit_ref: str,
    engine_evidence: EngineEvidenceItem | None,
    step_id: str,
) -> TenantEngineBridgedResult:
    if not all(
        isinstance(value, expected)
        for value, expected in (
            (binding, EngineAttemptBinding),
            (policy, TargetRelayPolicy),
            (fixture, TenantRecordFixture),
            (config, TenantDefenseConfig),
            (operation, TargetOperation),
            (relay_request, TargetRelayRequest),
            (request, TenantEngineTargetRequest),
            (result, TenantEngineTargetResult),
            (retained_audit_binding, TenantBoundAuditReceipt),
            (retained_relay_audit, RelayAuditRecord),
        )
    ):
        raise TenantEngineResultBridgeError("target result requires admitted typed inputs")
    binding.to_dict()
    policy, fixture, config, request, result = (
        replace(policy),
        replace(fixture),
        replace(config),
        replace(request),
        replace(result),
    )
    generation = replace(request.expected_generation)
    retained = replace(retained_audit_binding)
    relay_audit = replace(retained_relay_audit)
    row = replace(result.audit_row)
    _digest(retained_audit_ref)
    _digest(retained_relay_audit_ref)
    if not isinstance(step_id, str) or _STEP.fullmatch(step_id) is None:
        raise TenantEngineResultBridgeError("observation step identity is invalid")
    snapshot_ref = tenant_target_snapshot_ref(
        fixture_digest=fixture.digest,
        target_snapshot_id=config.target_snapshot_id,
        service_generation=config.service_generation,
    )
    if (
        binding.engine_id != "strix"
        or binding.target_snapshot_ref != snapshot_ref
        or config.fixture_digest != fixture.digest
        or generation.target_snapshot_id != config.target_snapshot_id
        or generation.service_generation != config.service_generation
        or policy.attempt_id != binding.attempt_id
        or policy.binding_digest != binding.binding_digest
        or policy.objective_ref != binding.objective_ref
        or policy.environment_ref != binding.environment_ref
        or policy.target_snapshot_digest != snapshot_ref
        or request.target_snapshot_ref != snapshot_ref
    ):
        raise TenantEngineResultBridgeError("attempt target authority changed")
    operation_ref = content_hash(operation.to_dict())
    admitted_operation = _target_operation(policy, relay_request, deadline_ns=operation.deadline_ns)
    if admitted_operation != operation:
        raise TenantEngineResultBridgeError("relay request does not match the admitted action")
    if (
        operation.attempt_id != binding.attempt_id
        or operation.binding_digest != binding.binding_digest
        or operation.delegation_digest != policy.delegation_digest
        or operation.network_policy_digest != policy.network_policy_digest
        or operation.relay_identity_ref != policy.relay_identity_ref
        or operation.protected_target_ref != policy.protected_target_ref
        or operation.source_identity != "engine_worker"
        or operation.route_id not in policy.admitted_routes
        or operation.route_id != request.route.value
        or operation.record_id != request.record_id
        or operation.tenant_id != request.tenant_id
        or operation.tenant_assertion != request.tenant_assertion
        or (
            operation.record_id is not None
            and operation.record_id not in policy.admitted_record_ids
        )
        or (
            operation.tenant_id is not None
            and operation.tenant_id not in policy.admitted_tenant_ids
        )
        or (
            operation.tenant_assertion is not None
            and operation.tenant_assertion not in policy.admitted_tenant_ids
        )
        or operation.max_response_bytes != policy.max_response_bytes
        or operation.max_response_bytes != request.max_response_bytes
        or operation.deadline_ns != request.deadline_ns
        or operation.request_id != request.relay_request_id
        or request.operation_digest != operation_ref
        or result.operation_digest != operation_ref
        or result.relay_request_id != request.relay_request_id
        or result.generation_digest != generation.digest
    ):
        raise TenantEngineResultBridgeError("admitted action identity changed")
    if (
        result.audit_binding != retained
        or result.audit_binding.digest != retained.digest
        or result.audit_retention_ref != retained_audit_ref
        or result.target_request_id != retained.request_id
        or row.request_id != retained.request_id
        or row.digest != retained.audit_row_digest
        or row.source_identity != "engine_worker"
        or retained.source_identity != "engine_worker"
        or _ATTEMPT.fullmatch(retained.attempt_id) is None
        or _LAUNCHER_RUN.fullmatch(retained.run_id) is None
        or retained.fixture_digest != fixture.digest
        or retained.config_digest != config.digest
        or retained.plan_digest != generation.plan_digest
        or retained.lifecycle_digest != generation.lifecycle_digest
        or retained.ready_digest != generation.ready_digest
        or retained.target_snapshot_id != generation.target_snapshot_id
        or retained.service_generation != generation.service_generation
        or row.route != request.route.value
    ):
        raise TenantEngineResultBridgeError("retained target audit binding changed")
    observed_at = parse_iso8601_datetime(row.timestamp)
    if not (
        parse_iso8601_datetime(binding.created_at) <= observed_at
        and parse_iso8601_datetime(policy.created_at)
        <= observed_at
        < parse_iso8601_datetime(policy.expires_at)
    ):
        raise TenantEngineResultBridgeError("target observation is outside admitted lifetime")
    requested_tenant = request.tenant_id
    if request.record_id is not None:
        matching = [record for record in fixture.records if record.record_id == request.record_id]
        if len(matching) != 1:
            raise TenantEngineResultBridgeError("target record is outside the retained fixture")
        requested_tenant = matching[0].tenant_id
    if row.requested_tenant != requested_tenant:
        raise TenantEngineResultBridgeError("target request tenant changed")
    if request.record_id is not None and row.returned_record_ids not in {(), (request.record_id,)}:
        raise TenantEngineResultBridgeError("target response returned a different record")
    response = result.response
    if (
        type(response.body) is not bytes
        or len(response.body) > request.max_response_bytes
        or response.headers.get("x-bluefire-lab-request") != row.request_id
        or result.protected_secret_absent is not True
    ):
        raise TenantEngineResultBridgeError("target response binding is incomplete")
    expected_observation_ref = content_hash(
        {
            "schema_version": "bluefire.tenant-engine-target-observation.v1",
            "relay_request_id": request.relay_request_id,
            "operation_digest": operation_ref,
            "target_request_id": row.request_id,
            "generation_digest": generation.digest,
            "target_snapshot_ref": snapshot_ref,
            "audit_row_digest": row.digest,
            "audit_binding_digest": retained.digest,
            "audit_retention_ref": retained_audit_ref,
            "response_status": response.status,
            "response_sha256": "sha256:" + hashlib.sha256(response.body).hexdigest(),
            "response_headers_sha256": content_hash(dict(response.headers)),
        }
    )
    if result.target_observation_ref != expected_observation_ref:
        raise TenantEngineResultBridgeError("target observation proof changed")
    request_digest = content_hash(
        {
            **operation.to_dict(),
            "request_headers_digest": content_hash(list(sorted(relay_request.headers))),
            "request_body_digest": "sha256:" + hashlib.sha256(relay_request.body).hexdigest(),
        }
    )
    if (
        relay_audit.relay_kind != "target"
        or relay_audit.status != "succeeded"
        or relay_audit.attempt_id != binding.attempt_id
        or relay_audit.objective_ref != binding.objective_ref
        or relay_audit.sequence > policy.max_requests
        or relay_audit.request_id != operation.request_id
        or relay_audit.operation != operation.route_id
        or relay_audit.request_digest != request_digest
        or relay_audit.request_bytes != 0
        or relay_audit.response_digest != row.response_sha256
        or relay_audit.response_bytes != row.response_bytes
        or relay_audit.result_status != row.response_status
        or relay_audit.policy_digest != policy.policy_digest
        or relay_audit.evidence_ref != expected_observation_ref
        or relay_audit.input_tokens != 0
        or relay_audit.output_tokens != 0
        or relay_audit.cost_microunits != 0
        or not (
            observed_at
            <= parse_iso8601_datetime(relay_audit.recorded_at)
            < parse_iso8601_datetime(policy.expires_at)
        )
    ):
        raise TenantEngineResultBridgeError("retained successful relay audit changed")
    report = _engine_report(binding, engine_evidence)
    evidence = observe_tenant_response(
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
    content = checked_observation_content(evidence)
    mechanism = (
        TenantFailureMechanism.from_baseline_audit(fixture, config, row)
        if binding.role.value == "baseline" and content["assessment"] == "unauthorized_disclosure"
        else None
    )
    observation = TenantEngineObservation(
        role=binding.role,
        attempt_id=binding.attempt_id,
        run_id=binding.run_id,
        evidence=evidence,
        assessment=content["assessment"],
        target_snapshot_id=config.target_snapshot_id,
        failure_mechanism=mechanism,
    )
    return TenantEngineBridgedResult(
        observation,
        report,
        operation_ref,
        generation.digest,
        retained.digest,
        retained_audit_ref,
        relay_audit.record_digest,
        retained_relay_audit_ref,
        expected_observation_ref,
    )
