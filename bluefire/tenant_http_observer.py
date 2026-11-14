"""Versioned independent observations for the broader tenant HTTP profile.

The v1 response/audit correlation remains the authority for the observed bytes
and record effects. This separate schema additionally represents an unknown
requested tenant when authentication failed before application routing.
"""

from __future__ import annotations

from typing import Any, Mapping

from .evidence import EvidenceRecord
from .tenant_record_lab import TenantDefenseConfig, TenantRecordFixture
from .tenant_record_observer import (
    OBSERVATION_SCHEMA,
    OBSERVER_ID,
    TenantAuditRow,
    TenantRecordObservationError,
    checked_observation_content,
    observe_tenant_response,
)

HTTP_OBSERVATION_SCHEMA_V2 = "bluefire.tenant-http-observation.v2"
HTTP_OBSERVER_ID_V2 = "observer.tenant-http-target.v2"
_UNKNOWN_REQUESTED = "unknown_requested_unauthenticated"


def _rebuild(
    original: EvidenceRecord, *, producer: str, content: Mapping[str, Any]
) -> EvidenceRecord:
    return EvidenceRecord.create(
        run_id=original.run_id,
        step_id=original.step_id,
        behavior_id=original.behavior_id,
        action_id=original.action_id,
        provenance=original.provenance,
        producer=producer,
        runner_profile_id=original.runner_profile_id,
        environment=original.environment,
        timestamp=original.timestamp,
        parent_evidence_ids=original.parent_evidence_ids,
        content=content,
        confidence=original.confidence,
        limitations=original.limitations,
        target_scope_ref=original.target_scope_ref,
    )


def observe_tenant_http_response_v2(
    *,
    fixture: TenantRecordFixture,
    config: TenantDefenseConfig,
    audit_row: TenantAuditRow,
    response_status: int,
    response_headers: Mapping[str, str],
    response_body: bytes,
    attempt_id: str,
    run_id: str,
    step_id: str,
    target_scope_ref: str,
) -> EvidenceRecord:
    """Correlate the exact target audit and response without engine assertions."""

    base = observe_tenant_response(
        fixture=fixture,
        config=config,
        audit_row=audit_row,
        response_status=response_status,
        response_headers=response_headers,
        response_body=response_body,
        attempt_id=attempt_id,
        run_id=run_id,
        step_id=step_id,
        target_scope_ref=target_scope_ref,
    )
    content = {**base.content, "schema_version": HTTP_OBSERVATION_SCHEMA_V2}
    if (
        content["tenant_classification"] == "unresolved"
        and content["requested_tenant"] is not None
        and content["authenticated_tenant"] is None
    ):
        content["tenant_classification"] = _UNKNOWN_REQUESTED
    observed = _rebuild(base, producer=HTTP_OBSERVER_ID_V2, content=content)
    checked_tenant_http_observation_content_v2(observed)
    return observed


def checked_tenant_http_observation_content_v2(record: EvidenceRecord) -> Mapping[str, Any]:
    """Verify v2 evidence hashes and all v1 response/effect shape invariants."""

    checked = EvidenceRecord.from_mapping(record.to_dict())
    content = checked.content
    if (
        checked.producer != HTTP_OBSERVER_ID_V2
        or content.get("schema_version") != HTTP_OBSERVATION_SCHEMA_V2
    ):
        raise TenantRecordObservationError("record is not a v2 tenant HTTP observation")
    classification = content.get("tenant_classification")
    if classification == _UNKNOWN_REQUESTED and (
        content.get("requested_tenant") is None
        or content.get("authenticated_tenant") is not None
        or content.get("response_status") not in {401, 403}
    ):
        raise TenantRecordObservationError("unknown requested tenant classification is invalid")
    # Check the shared closed observation shape through v1's unchanged checker.
    # Its known-tenant unauthenticated category has the same structural rules;
    # only the new v2 category's semantic label differs.
    shared_content = {**content, "schema_version": OBSERVATION_SCHEMA}
    if classification == _UNKNOWN_REQUESTED:
        shared_content["tenant_classification"] = "probe_requested_unauthenticated"
    shared = _rebuild(checked, producer=OBSERVER_ID, content=shared_content)
    checked_observation_content(shared)
    source = content.get("source_identity")
    if source not in {"engine_worker", "ordinary_user", "controller_probe"}:
        raise TenantRecordObservationError("HTTP observation source is invalid")
    protected = content["protected_record_ids"]
    expected = (
        "unauthorized_disclosure"
        if source == "engine_worker" and protected
        else "legitimate_use_succeeded"
        if source == "ordinary_user" and protected
        else "authorization_denied"
        if content["response_status"] in {401, 403} and not protected
        else "no_protected_effect"
        if not protected
        else "unknown"
    )
    if content["assessment"] != expected:
        raise TenantRecordObservationError("HTTP observation contradicts observed effects")
    return content
