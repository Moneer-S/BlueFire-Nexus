from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from bluefire.evidence import EvidenceRecord
from bluefire.tenant_engine_run_trace import (
    NO_DISCLOSURE_OUTCOME,
    TenantEngineRunObservedResult,
    TenantEngineRunTerminal,
    TenantEngineRunTraceBinding,
    TenantEngineRunTraceError,
    TenantEngineRunTraceEvent,
    tenant_engine_trace_digest,
    verify_tenant_engine_run_trace,
)
from bluefire.tenant_http_completion_contract import (
    _CONTROLLER_ADAPTER_AUTHORITY,
    _CONTROLLER_CESSATION_AUTHORITY,
    ADAPTER_REVOCATION_SCHEMA,
    CESSATION_SCHEMA,
    TenantHttpCompletionContractError,
    VerifiedTenantHttpAdapterRevocation,
    VerifiedTenantHttpCessationReceipt,
    _restore_adapter_revocation,
    _restore_controller_cessation_receipt,
)
from bluefire.tenant_http_observer import observe_tenant_http_response_v2
from bluefire.tenant_record_controller_contract import tenant_target_snapshot_ref
from bluefire.tenant_record_lab import baseline_defense_config, generate_tenant_record_fixture
from bluefire.tenant_record_observer import BoundedTenantAuditLog, observe_tenant_response
from bluefire.tenant_record_service import TenantRecordApplication
from bluefire.util import content_hash


def _hash(label: str) -> str:
    return content_hash({"label": label})


def _receipt(binding, *, issued_ns=102, **changes):
    """Pure fixture for the private protected-store restore boundary only."""
    return _restore_controller_cessation_receipt(
        {
            "schema_version": CESSATION_SCHEMA,
            "run_id": binding.run_id,
            "attempt_id": binding.attempt_id,
            "binding_digest": binding.digest,
            "profile_digest": binding.profile_digest,
            "generation_digest": binding.generation_digest,
            "target_snapshot_ref": binding.target_snapshot_ref,
            "controller_trace_ref": binding.controller_trace_ref,
            "adapter_revocation_ref": _hash("adapter-revocation"),
            "artifact_manifest_ref": _hash("artifact-manifest"),
            "artifact_publication_ref": _hash("artifact-publication"),
            "worker_outcome_digest": _hash("worker-outcome"),
            "source_collection_seal_ref": _hash("source-collection-seal"),
            "issued_ns": issued_ns,
            **changes,
        },
        _authority=_CONTROLLER_CESSATION_AUTHORITY,
    )


_TRUSTED_FIXTURE_REOPEN = object()


def _case(*, protected: bool = False, status: int = 200, unknown_tenant=False, http_v2=False):
    fixture = generate_tenant_record_fixture(b"trace-completeness-fixture-seed-000000001")
    config = baseline_defense_config(fixture)
    binding = TenantEngineRunTraceBinding(
        run_id="run-20261105T150000Z-" + "1" * 16,
        attempt_id="engine-attempt-" + "2" * 32,
        profile_digest=_hash("profile-v2"),
        generation_digest=_hash("generation"),
        target_snapshot_ref=tenant_target_snapshot_ref(
            fixture_digest=fixture.digest,
            target_snapshot_id=config.target_snapshot_id,
            service_generation=config.service_generation,
        ),
        scope_ref=_hash("scope"),
        controller_trace_ref=_hash("controller-trace"),
        started_ns=100,
        deadline_ns=10_000,
        max_http_calls=4,
        max_total_response_bytes=65536,
    )
    audit = BoundedTenantAuditLog()
    app = TenantRecordApplication(
        fixture=fixture,
        config=config,
        audit_log=audit,
        clock=lambda: datetime(2026, 11, 5, 15, 0, 1, tzinfo=timezone.utc),
        request_id_factory=lambda: "request-" + "3" * 24,
    )
    tenant = fixture.protected_tenant_id if protected else fixture.probe_tenant_id
    record = fixture.records_for(tenant)[0]
    headers = {"host": "tenant-record.test", "x-bluefire-lab-tenant": tenant}
    if status == 403:
        headers.pop("x-bluefire-lab-tenant")
    target = f"/records/{record.record_id}" if status != 404 else "/records/unknown-record"
    if unknown_tenant:
        target = "/exports?tenant=unknown-tenant"
    response = app.handle("GET", target, headers, source_identity="engine_worker")
    assert response.status == status
    evidence = (observe_tenant_http_response_v2 if http_v2 else observe_tenant_response)(
        fixture=fixture,
        config=config,
        audit_row=audit.snapshot()[0],
        response_status=response.status,
        response_headers=response.headers,
        response_body=response.body,
        attempt_id=binding.attempt_id,
        run_id=binding.run_id,
        step_id="tenant_http_v2",
        target_scope_ref=binding.scope_ref,
    )
    observed = TenantEngineRunObservedResult(
        binding_digest=binding.digest,
        generation_digest=binding.generation_digest,
        relay_request_id="relay-request-" + "4" * 32,
        operation_digest=_hash("operation"),
        target_request_id=audit.snapshot()[0].request_id,
        target_observation_ref=_hash("target-proof"),
        audit_binding_ref=_hash("audit-binding"),
        audit_retention_ref=_hash("target-audit-retention"),
        relay_audit_ref=_hash("relay-audit"),
        observation=evidence,
    )
    events = (
        TenantEngineRunTraceEvent(
            1, binding.digest, "dispatch", observed.relay_request_id, observed.operation_digest, 101
        ),
        TenantEngineRunTraceEvent(
            2,
            binding.digest,
            "target_result",
            observed.relay_request_id,
            observed.operation_digest,
            102,
            observed.digest,
        ),
    )
    terminal = TenantEngineRunTerminal(
        binding_digest=binding.digest,
        state="completed",
        complete=True,
        truncated=False,
        owned_work_settled=True,
        cessation_ref=_receipt(binding).digest,
        exhausted_budgets=(),
        finished_ns=103,
        last_sequence=2,
        trace_digest=tenant_engine_trace_digest(events),
        dispatched_calls=1,
        target_results=1,
        controller_refusals=0,
        unknown_target_calls=0,
        pending_calls=0,
        response_bytes=len(response.body),
    )
    return binding, observed, events, terminal


def _verify(
    binding,
    observed,
    events,
    terminal,
    *,
    retained_results=None,
    terminal_ref=True,
    reopened_cessation=_TRUSTED_FIXTURE_REOPEN,
):
    if reopened_cessation is _TRUSTED_FIXTURE_REOPEN:
        reopened_cessation = _receipt(binding, issued_ns=max(row.recorded_ns for row in events))
        if terminal is not None:
            terminal = replace(terminal, cessation_ref=reopened_cessation.digest)
    return verify_tenant_engine_run_trace(
        binding=binding,
        events=events,
        terminal=terminal,
        retained_results={observed.digest: observed}
        if retained_results is None
        else retained_results,
        retained_terminal_ref=terminal.digest if terminal is not None and terminal_ref else None,
        reopened_cessation=reopened_cessation,
    )


@pytest.mark.parametrize("status", [200, 403, 404])
def test_completed_negative_is_bounded_and_target_denials_remain_results(status):
    case = _case(status=status)
    result = _verify(*case)
    assert result.completeness == "complete"
    assert result.outcome == NO_DISCLOSURE_OUTCOME
    assert result.target_results == 1
    assert result.controller_refusals == 0


def test_completed_disclosure_requires_independent_observation():
    result = _verify(*_case(protected=True))
    assert result.completeness == "complete"
    assert result.outcome == "disclosure observed"


def test_v2_unknown_requested_tenant_denial_is_a_correlated_result():
    result = _verify(*_case(status=403, unknown_tenant=True, http_v2=True))
    assert result.outcome == NO_DISCLOSURE_OUTCOME
    assert result.target_results == 1
    assert result.controller_refusals == 0


@pytest.mark.parametrize(
    "change",
    [
        {"state": "interrupted"},
        {"complete": False},
        {"truncated": True},
        {"owned_work_settled": False},
        {"exhausted_budgets": ("http_calls",)},
        {"exhausted_budgets": ("response_bytes",)},
        {"exhausted_budgets": ("deadline",)},
        {"finished_ns": 10_000},
        {"target_results": 0},
        {"last_sequence": 3},
        {"trace_digest": _hash("wrong-trace")},
    ],
)
def test_incomplete_terminal_never_yields_a_negative(change):
    binding, observed, events, terminal = _case()
    result = _verify(binding, observed, events, replace(terminal, **change))
    assert result.completeness == result.outcome == "unknown"


def test_missing_terminal_and_retention_reference_are_unknown():
    binding, observed, events, terminal = _case()
    assert _verify(binding, observed, events, None).outcome == "unknown"
    assert _verify(binding, observed, events, terminal, terminal_ref=False).outcome == "unknown"


def test_terminal_retention_cannot_be_replaced_by_an_engine_claim():
    binding, observed, events, terminal = _case()
    with pytest.raises(TenantEngineRunTraceError):
        verify_tenant_engine_run_trace(
            binding=binding,
            events=events,
            terminal=terminal,
            retained_results={observed.digest: observed},
            retained_terminal_ref=_hash("engine-claimed-complete"),
        )


def test_missing_response_and_truncated_trace_are_unknown():
    binding, observed, events, terminal = _case()
    result = _verify(binding, observed, events[:1], terminal, retained_results={})
    assert result.outcome == "unknown"
    assert result.pending_calls == 1
    assert "terminal_counts_incomplete" in result.reasons
    result = _verify(binding, observed, events, terminal, retained_results={})
    assert result.outcome == "unknown"
    assert result.unknown_target_calls == 1


def test_controller_refusals_are_counted_separately():
    binding, observed, events, terminal = _case()
    events += (
        TenantEngineRunTraceEvent(
            3,
            binding.digest,
            "controller_refusal",
            "relay-request-" + "5" * 32,
            _hash("refused-operation"),
            103,
            code="scope_refused",
        ),
    )
    terminal = replace(
        terminal,
        last_sequence=3,
        controller_refusals=1,
        finished_ns=104,
        trace_digest=tenant_engine_trace_digest(events),
    )
    result = _verify(binding, observed, events, terminal)
    assert result.outcome == NO_DISCLOSURE_OUTCOME
    assert result.controller_refusals == 1
    assert result.dispatched_calls == result.target_results == 1


def test_budget_refusal_cannot_be_hidden_by_a_completed_terminal():
    binding, observed, events, terminal = _case()
    events += (
        TenantEngineRunTraceEvent(
            3,
            binding.digest,
            "controller_refusal",
            "relay-request-" + "5" * 32,
            _hash("budget-refused"),
            103,
            code="budget_exhausted",
        ),
    )
    terminal = replace(
        terminal,
        last_sequence=3,
        controller_refusals=1,
        finished_ns=104,
        trace_digest=tenant_engine_trace_digest(events),
    )
    result = _verify(binding, observed, events, terminal)
    assert result.outcome == "unknown"
    assert "budget_exhausted" in result.reasons


def test_unknown_after_dispatch_cannot_be_counted_as_a_controller_refusal():
    binding, observed, events, terminal = _case()
    events = (
        events[0],
        replace(events[1], kind="target_unknown", result_ref=None, code="response_unavailable"),
    )
    terminal = replace(
        terminal,
        target_results=0,
        unknown_target_calls=1,
        response_bytes=0,
        trace_digest=tenant_engine_trace_digest(events),
    )
    result = _verify(binding, observed, events, terminal, retained_results={})
    assert result.outcome == "unknown"
    assert result.unknown_target_calls == 1
    assert result.controller_refusals == 0


def test_only_controller_refusals_cannot_establish_a_negative_target_result():
    binding, observed, events, terminal = _case()
    events = (replace(events[0], kind="controller_refusal", code="scope_refused"),)
    terminal = replace(
        terminal,
        last_sequence=1,
        dispatched_calls=0,
        target_results=0,
        controller_refusals=1,
        response_bytes=0,
        trace_digest=tenant_engine_trace_digest(events),
    )
    result = _verify(binding, observed, events, terminal, retained_results={})
    assert result.outcome == "unknown"
    assert result.controller_refusals == 1
    assert result.target_results == 0


def test_sequence_hole_and_out_of_order_time_are_unknown():
    binding, observed, events, terminal = _case()
    for changed in (replace(events[1], sequence=3), replace(events[1], recorded_ns=100)):
        changed_events = (events[0], changed)
        terminal = replace(terminal, trace_digest=tenant_engine_trace_digest(changed_events))
        assert _verify(binding, observed, changed_events, terminal).outcome == "unknown"


def test_observed_effect_does_not_hide_incomplete_run():
    binding, observed, events, terminal = _case(protected=True)
    result = _verify(binding, observed, events, replace(terminal, truncated=True))
    assert result.completeness == result.outcome == "unknown"


@pytest.mark.parametrize(
    "field", ["binding_digest", "generation_digest", "operation_digest", "relay_request_id"]
)
def test_cross_bound_or_relabelled_observations_are_rejected(field):
    binding, observed, events, terminal = _case()
    change = {field: "relay-request-" + "7" * 32 if field == "relay_request_id" else _hash("other")}
    observed = replace(observed, **change)
    events = (events[0], replace(events[1], result_ref=observed.digest))
    terminal = replace(terminal, trace_digest=tenant_engine_trace_digest(events))
    with pytest.raises(TenantEngineRunTraceError):
        _verify(binding, observed, events, terminal)


def test_result_cannot_settle_two_calls_or_omit_dispatch():
    binding, observed, events, terminal = _case()
    with pytest.raises(TenantEngineRunTraceError):
        _verify(binding, observed, (replace(events[1], sequence=1),), terminal)
    with pytest.raises(TenantEngineRunTraceError):
        _verify(binding, observed, (*events, replace(events[1], sequence=3)), terminal)


def test_observation_from_another_snapshot_cannot_be_relabelled():
    binding, observed, events, terminal = _case()
    binding = replace(binding, target_snapshot_ref=_hash("other-snapshot"))
    observed = replace(observed, binding_digest=binding.digest)
    events = tuple(
        replace(
            row,
            binding_digest=binding.digest,
            result_ref=observed.digest if row.kind == "target_result" else None,
        )
        for row in events
    )
    terminal = replace(
        terminal, binding_digest=binding.digest, trace_digest=tenant_engine_trace_digest(events)
    )
    with pytest.raises(TenantEngineRunTraceError):
        _verify(binding, observed, events, terminal)


def test_forged_engine_assessment_is_rejected_even_when_rehashed():
    binding, observed, events, terminal = _case()
    prior = observed.observation
    forged = EvidenceRecord.create(
        run_id=prior.run_id,
        step_id=prior.step_id,
        behavior_id=prior.behavior_id,
        provenance=prior.provenance,
        producer=prior.producer,
        content={**prior.content, "assessment": "authorization_denied"},
        target_scope_ref=prior.target_scope_ref,
        environment=prior.environment,
        timestamp=prior.timestamp,
    )
    observed = replace(observed, observation=forged)
    events = (events[0], replace(events[1], result_ref=observed.digest))
    terminal = replace(terminal, trace_digest=tenant_engine_trace_digest(events))
    with pytest.raises(TenantEngineRunTraceError):
        _verify(binding, observed, events, terminal)


@pytest.mark.parametrize("limit", ["http", "bytes"])
def test_exactly_exhausted_limits_are_unknown(limit):
    binding, observed, events, terminal = _case()
    binding = replace(
        binding,
        **(
            {"max_http_calls": 1}
            if limit == "http"
            else {"max_total_response_bytes": terminal.response_bytes}
        ),
    )
    observed = replace(observed, binding_digest=binding.digest)
    events = tuple(
        replace(
            row,
            binding_digest=binding.digest,
            result_ref=observed.digest if row.kind == "target_result" else None,
        )
        for row in events
    )
    terminal = replace(
        terminal, binding_digest=binding.digest, trace_digest=tenant_engine_trace_digest(events)
    )
    result = _verify(binding, observed, events, terminal)
    assert result.outcome == "unknown"
    assert (
        "http_calls_exhausted" if limit == "http" else "response_bytes_exhausted"
    ) in result.reasons


def test_arbitrary_digest_and_settled_boolean_cannot_prove_cessation():
    binding, observed, events, terminal = _case()
    terminal = replace(terminal, owned_work_settled=True, cessation_ref=_hash("caller-claim"))
    result = _verify(binding, observed, events, terminal, reopened_cessation=None)
    assert result.outcome == "unknown"
    assert "cessation_receipt_missing" in result.reasons


@pytest.mark.parametrize(
    "receipt_type", (VerifiedTenantHttpCessationReceipt, VerifiedTenantHttpAdapterRevocation)
)
def test_public_receipt_constructor_or_mapping_cannot_mint_authority(receipt_type):
    with pytest.raises(TenantHttpCompletionContractError):
        receipt_type()
    with pytest.raises(TenantHttpCompletionContractError):
        receipt_type.from_mapping({})
    uninitialized = object.__new__(receipt_type)
    with pytest.raises(TenantHttpCompletionContractError):
        uninitialized.to_dict()


def test_private_receipt_restore_requires_exact_controller_token():
    binding, *_ = _case()
    document = _receipt(binding).to_dict()
    for authority in (None, object(), _CONTROLLER_ADAPTER_AUTHORITY):
        with pytest.raises(TenantHttpCompletionContractError):
            _restore_controller_cessation_receipt(document, _authority=authority)
    adapter_document = {
        "schema_version": ADAPTER_REVOCATION_SCHEMA,
        "profile_digest": binding.profile_digest,
        "generation_digest": binding.generation_digest,
        "accepted_http_calls": 1,
        "reserved_response_bytes": 65536,
        "request_ids_digest": _hash("request-ids"),
    }
    for authority in (None, object(), _CONTROLLER_CESSATION_AUTHORITY):
        with pytest.raises(TenantHttpCompletionContractError):
            _restore_adapter_revocation(adapter_document, _authority=authority)
    restored = _restore_adapter_revocation(
        adapter_document, _authority=_CONTROLLER_ADAPTER_AUTHORITY
    )
    assert restored.to_dict() == adapter_document
    assert restored.digest == content_hash(adapter_document)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("schema_version", "bluefire.tenant-http-cessation.v1"),
        ("run_id", "another-run"),
        ("attempt_id", "another-attempt"),
        ("issued_ns", True),
        ("issued_ns", -1),
        ("issued_ns", 2**63),
        ("profile_digest", "not-a-digest"),
    ),
)
def test_cessation_receipt_closed_canonical_contract(field, value):
    binding, *_ = _case()
    with pytest.raises(TenantHttpCompletionContractError):
        _receipt(binding, **{field: value})


@pytest.mark.parametrize(
    "field",
    (
        "run_id",
        "attempt_id",
        "binding_digest",
        "profile_digest",
        "generation_digest",
        "target_snapshot_ref",
        "controller_trace_ref",
    ),
)
def test_reopened_cessation_cannot_be_replayed_or_substituted(field):
    binding, observed, events, terminal = _case()
    changed = (
        "run-20261105T150000Z-" + "8" * 16
        if field == "run_id"
        else "engine-attempt-" + "8" * 32
        if field == "attempt_id"
        else _hash("different-identity")
    )
    receipt = _receipt(binding, **{field: changed})
    terminal = replace(terminal, cessation_ref=receipt.digest)
    with pytest.raises(TenantEngineRunTraceError):
        _verify(binding, observed, events, terminal, reopened_cessation=receipt)


def test_reopened_cessation_must_match_terminal_reference():
    binding, observed, events, terminal = _case()
    with pytest.raises(TenantEngineRunTraceError):
        _verify(
            binding,
            observed,
            events,
            replace(terminal, cessation_ref=_hash("substituted")),
            reopened_cessation=_receipt(binding),
        )


@pytest.mark.parametrize("issued_ns", (101, 104))
def test_cessation_must_follow_events_and_precede_terminal(issued_ns):
    binding, observed, events, terminal = _case()
    receipt = _receipt(binding, issued_ns=issued_ns)
    terminal = replace(terminal, cessation_ref=receipt.digest)
    result = _verify(binding, observed, events, terminal, reopened_cessation=receipt)
    assert result.outcome == "unknown"
    assert "cessation_time_incomplete" in result.reasons


def test_receipt_attestation_and_canonical_fields_are_rechecked():
    binding, observed, events, terminal = _case()
    receipt = _receipt(binding)
    object.__setattr__(receipt, "_controller_attestation", object())
    with pytest.raises(TenantEngineRunTraceError):
        _verify(binding, observed, events, terminal, reopened_cessation=receipt)
    receipt = _receipt(binding)
    object.__setattr__(receipt, "issued_ns", True)
    with pytest.raises(TenantEngineRunTraceError):
        _verify(binding, observed, events, terminal, reopened_cessation=receipt)


def test_digest_or_mapping_cannot_replace_reopened_capability():
    binding, observed, events, terminal = _case()
    receipt = _receipt(binding)
    for untrusted in (
        receipt.digest,
        receipt.to_dict(),
        object.__new__(VerifiedTenantHttpCessationReceipt),
    ):
        with pytest.raises(TenantEngineRunTraceError):
            _verify(binding, observed, events, terminal, reopened_cessation=untrusted)
