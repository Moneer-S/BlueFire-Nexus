"""Join protected V2 relay snapshots to the independent terminal contract.

The controller retains the returned event/terminal bundle after settlement and
reopens it before verification. An engine completion message is never an input.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any

from .tenant_engine_run_trace import (
    TenantEngineRunObservedResult,
    TenantEngineRunTerminal,
    TenantEngineRunTraceBinding,
    TenantEngineRunTraceEvent,
    tenant_engine_trace_digest,
)
from .tenant_http_completion import ControllerOwnedTenantHttpCompletion, TenantHttpCompletionError
from .tenant_http_completion_contract import VerifiedTenantHttpCessationReceipt
from .tenant_http_result_bridge import TenantHttpBridgedResultV2
from .tenant_http_target_profile import TenantHttpTargetProfileV2
from .util import content_hash, json_clone


@dataclass(frozen=True, slots=True)
class TenantHttpRunTraceV2:
    binding: TenantEngineRunTraceBinding
    events: tuple[TenantEngineRunTraceEvent, ...]
    terminal: TenantEngineRunTerminal
    results: Mapping[str, TenantEngineRunObservedResult]
    reopened_cessation: VerifiedTenantHttpCessationReceipt | None


def compile_tenant_http_run_trace_v2(
    *,
    profile: TenantHttpTargetProfileV2,
    run_id: str,
    retained_controller_trace: Mapping[str, Any],
    retained_bridged_results: Mapping[str, TenantHttpBridgedResultV2],
    state: str,
    completion_owner: ControllerOwnedTenantHttpCompletion | None = None,
    finished_ns: int,
) -> TenantHttpRunTraceV2:
    """Purely compile a reopened controller trace and independently bridged rows.

    Keys of retained_bridged_results are relay request IDs. Incomplete snapshots,
    missing results, exhaustion, lost trace capacity and unsettled owned work
    survive into the terminal verifier as unknown. Snapshot fields and exact
    event order are hashed by the controller relay before protected retention.
    """
    profile = replace(profile)
    retained_snapshot = json_clone(dict(retained_controller_trace))
    retained_bridged_results = dict(retained_bridged_results)
    document = dict(retained_snapshot)
    trace_ref = document.pop("trace_ref", None)
    expected_fields = {
        "schema_version",
        "profile_digest",
        "started_ns",
        "deadline_ns",
        "events",
        "controller_refusals",
        "accepted_http_calls",
        "target_results",
        "target_unknown",
        "response_bytes",
        "reserved_response_bytes",
        "pending",
        "budget_exhausted",
        "trace_truncated",
        "revoked",
        "relay_instance_id",
        "revocation_state",
    }
    if (
        set(document) != expected_fields
        or trace_ref != content_hash(document)
        or document["schema_version"] != "bluefire.tenant-http-controller-trace.v2"
        or document["profile_digest"] != profile.policy_digest
    ):
        raise ValueError("v2 retained controller trace binding changed")
    binding = TenantEngineRunTraceBinding(
        run_id=run_id,
        attempt_id=profile.attempt_id,
        profile_digest=profile.policy_digest,
        generation_digest=profile.expected_generation.digest,
        target_snapshot_ref=profile.target_snapshot_ref,
        scope_ref=profile.scope_ref,
        started_ns=document["started_ns"],
        deadline_ns=document["deadline_ns"],
        max_http_calls=profile.max_http_calls,
        max_total_response_bytes=profile.max_total_response_bytes,
        max_trace_events=2 * profile.max_http_calls + 256,
        controller_trace_ref=trace_ref,
    )
    if binding.deadline_ns > binding.started_ns + profile.run_timeout_ms * 1_000_000:
        raise ValueError("v2 retained run deadline changed")
    refusals = {content_hash(row): row for row in document["controller_refusals"]}
    used_refusals: set[str] = set()
    results: dict[str, TenantEngineRunObservedResult] = {}
    used_bridged: set[str] = set()
    events: list[TenantEngineRunTraceEvent] = []
    for event in document["events"]:
        kind = event["kind"]
        code: str | None = None
        result_ref: str | None = None
        if kind == "controller_refusal":
            refusal_ref = event["refusal_ref"]
            refusal = refusals[refusal_ref]
            if (
                refusal_ref in used_refusals
                or refusal["profile_digest"] != profile.policy_digest
                or refusal["target_result"] is not False
            ):
                raise ValueError("v2 refusal trace changed")
            used_refusals.add(refusal_ref)
            code = refusal["code"]
            operation_ref = refusal["request_ref"] or refusal_ref
            request_id = "relay-request-" + refusal_ref.removeprefix("sha256:")[:32]
        else:
            request_id, operation_ref = event["request_id"], event["operation_ref"]
            if kind == "target_unknown":
                code = "target_unknown"
            elif kind == "target_result":
                bridged = retained_bridged_results.get(request_id)
                if bridged is None:
                    result_ref = content_hash(
                        {"missing_observation": event["target_observation_ref"]}
                    )
                else:
                    if (
                        bridged.operation_ref != operation_ref
                        or bridged.generation_ref != profile.expected_generation.digest
                        or bridged.target_observation_ref != event["target_observation_ref"]
                        or bridged.relay_audit_ref != event["relay_audit_ref"]
                        or bridged.observation.content["request_id"] != event["target_request_id"]
                    ):
                        raise ValueError("v2 retained independent result changed")
                    observed = TenantEngineRunObservedResult(
                        binding_digest=binding.digest,
                        generation_digest=bridged.generation_ref,
                        relay_request_id=request_id,
                        operation_digest=operation_ref,
                        target_request_id=event["target_request_id"],
                        target_observation_ref=bridged.target_observation_ref,
                        audit_binding_ref=bridged.audit_binding_ref,
                        audit_retention_ref=bridged.audit_retention_ref,
                        relay_audit_ref=bridged.relay_audit_ref,
                        observation=bridged.observation,
                    )
                    result_ref = observed.digest
                    results[result_ref] = observed
                    used_bridged.add(request_id)
        events.append(
            TenantEngineRunTraceEvent(
                sequence=event["sequence"],
                binding_digest=binding.digest,
                kind=kind,
                relay_request_id=request_id,
                operation_digest=operation_ref,
                recorded_ns=event["recorded_ns"],
                result_ref=result_ref,
                code=code,
            )
        )
    if used_refusals != set(refusals):
        raise ValueError("v2 controller refusal trace is incomplete")
    exhausted: set[str] = set()
    if document["accepted_http_calls"] >= profile.max_http_calls:
        exhausted.add("http_calls")
    if document["reserved_response_bytes"] >= profile.max_total_response_bytes:
        exhausted.add("response_bytes")
    if finished_ns >= binding.deadline_ns:
        exhausted.add("deadline")
    if document["budget_exhausted"] and not exhausted:
        exhausted.add("http_calls")
    if len(events) >= binding.max_trace_events or document["trace_truncated"]:
        exhausted.add("trace_events")
    reopened_cessation = None
    if completion_owner is not None:
        if type(completion_owner) is not ControllerOwnedTenantHttpCompletion:
            raise ValueError("completion requires a controller-owned receipt source")
        try:
            reopened_cessation = completion_owner.reopen_for_trace(
                profile=profile, run_id=run_id, controller_trace=retained_snapshot
            )
        except TenantHttpCompletionError:
            # Missing, failed or substituted protected proof cannot close a run.
            reopened_cessation = None
    owned_work_settled = reopened_cessation is not None
    terminal = TenantEngineRunTerminal(
        binding_digest=binding.digest,
        state=state,
        complete=state == "completed"
        and owned_work_settled
        and document["revoked"]
        and not document["pending"],
        truncated=document["trace_truncated"] or used_bridged != set(retained_bridged_results),
        exhausted_budgets=tuple(sorted(exhausted)),
        finished_ns=finished_ns,
        last_sequence=len(events),
        trace_digest=tenant_engine_trace_digest(events),
        dispatched_calls=document["accepted_http_calls"],
        target_results=document["target_results"],
        controller_refusals=len(document["controller_refusals"]),
        unknown_target_calls=document["target_unknown"],
        pending_calls=int(document["pending"]),
        response_bytes=document["response_bytes"],
        owned_work_settled=owned_work_settled,
        cessation_ref=None if reopened_cessation is None else reopened_cessation.digest,
    )
    return TenantHttpRunTraceV2(binding, tuple(events), terminal, results, reopened_cessation)
