"""Pure, controller-retained completeness contract for tenant HTTP profile v2.

The controller records dispatch *before* calling the protected target and retains
one terminal receipt after owned work settles.  An engine's completion assertion
is not a terminal receipt.  Callers must independently reopen the terminal,
events, and observed results from protected retention; hashes establish binding,
not the authority of an untrusted producer.  This module performs no effects.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .evidence import EvidenceRecord
from .tenant_http_completion_contract import (
    TenantHttpCompletionContractError,
    VerifiedTenantHttpCessationReceipt,
)
from .tenant_http_observer import (
    HTTP_OBSERVATION_SCHEMA_V2,
    checked_tenant_http_observation_content_v2,
)
from .tenant_record_controller_contract import tenant_target_snapshot_ref
from .tenant_record_observer import checked_observation_content
from .util import content_hash

TRACE_SCHEMA = "bluefire.tenant-engine-run-trace.v2"
TERMINAL_SCHEMA = "bluefire.tenant-engine-run-terminal.v2"
NO_DISCLOSURE_OUTCOME = "no disclosure observed in this bounded run"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_REQUEST = re.compile(r"relay-request-[0-9a-f]{32}")
_TARGET_REQUEST = re.compile(r"request-[0-9a-f]{24}")
_ATTEMPT = re.compile(r"engine-attempt-[0-9a-f]{32}")
_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_KINDS = frozenset({"dispatch", "target_result", "controller_refusal", "target_unknown"})
_BUDGETS = frozenset({"http_calls", "response_bytes", "deadline", "trace_events"})


class TenantEngineRunTraceError(ValueError):
    """The protected trace has an invalid identity or correlation."""


def _digest(value: object) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise TenantEngineRunTraceError("trace digest is invalid")


def _integer(value: object, minimum: int, maximum: int) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise TenantEngineRunTraceError("trace bound is invalid")


def _observation_content(record: EvidenceRecord) -> Mapping[str, Any]:
    if record.content.get("schema_version") == HTTP_OBSERVATION_SCHEMA_V2:
        return checked_tenant_http_observation_content_v2(record)
    return checked_observation_content(record)


@dataclass(frozen=True, slots=True)
class TenantEngineRunTraceBinding:
    run_id: str
    attempt_id: str
    profile_digest: str
    generation_digest: str
    target_snapshot_ref: str
    scope_ref: str
    controller_trace_ref: str
    started_ns: int
    deadline_ns: int
    max_http_calls: int
    max_total_response_bytes: int
    max_trace_events: int = 1024

    def __post_init__(self) -> None:
        if (
            not isinstance(self.run_id, str)
            or not 1 <= len(self.run_id) <= 80
            or any(ord(item) < 33 or ord(item) > 126 for item in self.run_id)
            or not isinstance(self.attempt_id, str)
            or _ATTEMPT.fullmatch(self.attempt_id) is None
        ):
            raise TenantEngineRunTraceError("trace owner is invalid")
        for value in (
            self.profile_digest,
            self.generation_digest,
            self.target_snapshot_ref,
            self.scope_ref,
            self.controller_trace_ref,
        ):
            _digest(value)
        _integer(self.started_ns, 0, 2**63 - 1)
        _integer(self.deadline_ns, self.started_ns + 1, 2**63 - 1)
        _integer(self.max_http_calls, 1, 256)
        _integer(self.max_total_response_bytes, 1, 256 * 65536)
        _integer(self.max_trace_events, 1, 1024)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": TRACE_SCHEMA,
            "source_identity": "engine_worker",
            **{name: getattr(self, name) for name in self.__dataclass_fields__},
        }

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())


@dataclass(frozen=True, slots=True)
class TenantEngineRunObservedResult:
    """A correlation envelope around independently reopened observer evidence.

    The protected v2 result bridge, after checking target and relay retention,
    supplies the three proof references. The trace verifier also rechecks the
    complete observer record and derives its assessment from observed effects.
    """

    binding_digest: str
    generation_digest: str
    relay_request_id: str
    operation_digest: str
    target_request_id: str
    target_observation_ref: str
    audit_binding_ref: str
    audit_retention_ref: str
    relay_audit_ref: str
    observation: EvidenceRecord

    def __post_init__(self) -> None:
        for value in (
            self.binding_digest,
            self.generation_digest,
            self.operation_digest,
            self.target_observation_ref,
            self.audit_binding_ref,
            self.audit_retention_ref,
            self.relay_audit_ref,
        ):
            _digest(value)
        if (
            not isinstance(self.relay_request_id, str)
            or _REQUEST.fullmatch(self.relay_request_id) is None
            or not isinstance(self.target_request_id, str)
            or _TARGET_REQUEST.fullmatch(self.target_request_id) is None
            or not isinstance(self.observation, EvidenceRecord)
        ):
            raise TenantEngineRunTraceError("trace result identity is invalid")
        content = _observation_content(self.observation)
        if (
            content["request_id"] != self.target_request_id
            or content["source_identity"] != "engine_worker"
        ):
            raise TenantEngineRunTraceError("trace result source or request changed")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.tenant-engine-run-observed-result.v2",
            **{
                name: getattr(self, name)
                for name in self.__dataclass_fields__
                if name != "observation"
            },
            "observation_ref": self.observation.record_hash,
        }

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())


@dataclass(frozen=True, slots=True)
class TenantEngineRunTraceEvent:
    sequence: int
    binding_digest: str
    kind: str
    relay_request_id: str
    operation_digest: str
    recorded_ns: int
    result_ref: str | None = None
    code: str | None = None

    def __post_init__(self) -> None:
        _integer(self.sequence, 1, 1024)
        _integer(self.recorded_ns, 0, 2**63 - 1)
        _digest(self.binding_digest)
        _digest(self.operation_digest)
        if (
            self.kind not in _KINDS
            or not isinstance(self.relay_request_id, str)
            or _REQUEST.fullmatch(self.relay_request_id) is None
        ):
            raise TenantEngineRunTraceError("trace event identity is invalid")
        if self.kind == "target_result":
            _digest(self.result_ref)
            valid = self.code is None
        elif self.kind in {"controller_refusal", "target_unknown"}:
            valid = (
                self.result_ref is None
                and isinstance(self.code, str)
                and _CODE.fullmatch(self.code) is not None
            )
        else:
            valid = self.result_ref is None and self.code is None
        if not valid:
            raise TenantEngineRunTraceError("trace event fields are invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.tenant-engine-run-event.v2",
            **{name: getattr(self, name) for name in self.__dataclass_fields__},
        }


def tenant_engine_trace_digest(events: Sequence[TenantEngineRunTraceEvent]) -> str:
    if len(events) > 1024 or any(not isinstance(row, TenantEngineRunTraceEvent) for row in events):
        raise TenantEngineRunTraceError("trace events are invalid")
    return content_hash(
        {"schema_version": TRACE_SCHEMA, "events": [row.to_dict() for row in events]}
    )


@dataclass(frozen=True, slots=True)
class TenantEngineRunTerminal:
    binding_digest: str
    state: str
    complete: bool
    truncated: bool
    owned_work_settled: bool
    cessation_ref: str | None
    exhausted_budgets: tuple[str, ...]
    finished_ns: int
    last_sequence: int
    trace_digest: str
    dispatched_calls: int
    target_results: int
    controller_refusals: int
    unknown_target_calls: int
    pending_calls: int
    response_bytes: int

    def __post_init__(self) -> None:
        _digest(self.binding_digest)
        _digest(self.trace_digest)
        _integer(self.finished_ns, 0, 2**63 - 1)
        _integer(self.last_sequence, 0, 1024)
        for value in (
            self.dispatched_calls,
            self.target_results,
            self.controller_refusals,
            self.unknown_target_calls,
            self.pending_calls,
        ):
            _integer(value, 0, 1024)
        _integer(self.response_bytes, 0, 256 * 65536)
        if (
            self.state not in {"completed", "stopped", "interrupted", "failed", "unknown"}
            or type(self.complete) is not bool
            or type(self.truncated) is not bool
            or type(self.owned_work_settled) is not bool
            or type(self.exhausted_budgets) is not tuple
            or tuple(sorted(set(self.exhausted_budgets))) != self.exhausted_budgets
            or not set(self.exhausted_budgets) <= _BUDGETS
        ):
            raise TenantEngineRunTraceError("trace terminal state is invalid")
        if self.cessation_ref is not None:
            _digest(self.cessation_ref)
        if self.owned_work_settled and self.cessation_ref is None:
            raise TenantEngineRunTraceError("settled terminal has no cessation proof")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": TERMINAL_SCHEMA,
            **{name: getattr(self, name) for name in self.__dataclass_fields__},
        }

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())


@dataclass(frozen=True, slots=True)
class TenantEngineRunTraceAssessment:
    completeness: str
    outcome: str
    dispatched_calls: int
    target_results: int
    controller_refusals: int
    unknown_target_calls: int
    pending_calls: int
    response_bytes: int
    reasons: tuple[str, ...]
    binding_digest: str
    trace_digest: str
    terminal_ref: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.tenant-engine-run-assessment.v2",
            **{name: getattr(self, name) for name in self.__dataclass_fields__},
        }


def verify_tenant_engine_run_trace(
    *,
    binding: TenantEngineRunTraceBinding,
    events: Sequence[TenantEngineRunTraceEvent],
    terminal: TenantEngineRunTerminal | None,
    retained_results: Mapping[str, TenantEngineRunObservedResult],
    retained_terminal_ref: str | None,
    reopened_cessation: VerifiedTenantHttpCessationReceipt | None = None,
) -> TenantEngineRunTraceAssessment:
    """Verify retained correlations and derive only a bounded run conclusion.

    Missing/truncated sequences and terminal counter mismatches are incomplete,
    not negative evidence. Invalid or cross-attempt observations are rejected.
    Even an observed disclosure has an ``unknown`` run outcome when the run is
    incomplete; the individual disclosure observation remains retained.
    """

    if not isinstance(binding, TenantEngineRunTraceBinding):
        raise TenantEngineRunTraceError("trace requires an admitted binding")
    binding.__post_init__()
    digest = tenant_engine_trace_digest(events)
    reasons: set[str] = set()
    if len(events) >= binding.max_trace_events:
        reasons.add("trace_events_exhausted")
    dispatched: dict[str, str] = {}
    settled: set[str] = set()
    target_ids: set[str] = set()
    used_results: set[str] = set()
    results = refusals = unknown = response_bytes = 0
    disclosure = False
    previous_ns = binding.started_ns
    for index, row in enumerate(events, 1):
        row.__post_init__()
        if row.binding_digest != binding.digest:
            raise TenantEngineRunTraceError("trace event belongs to another binding")
        if row.sequence != index:
            reasons.add("sequence_incomplete")
        if row.recorded_ns < previous_ns or row.recorded_ns < binding.started_ns:
            reasons.add("trace_time_incomplete")
        previous_ns = row.recorded_ns
        if row.recorded_ns >= binding.deadline_ns:
            reasons.add("deadline_exhausted")
        request_id = row.relay_request_id
        if row.kind == "controller_refusal":
            refusals += 1
            if row.code in {"budget_exhausted", "deadline_exceeded", "expired", "trace_exhausted"}:
                reasons.add("budget_exhausted")
            continue
        if row.kind == "dispatch":
            if request_id in dispatched:
                raise TenantEngineRunTraceError("target call was dispatched more than once")
            dispatched[request_id] = row.operation_digest
            continue
        if dispatched.get(request_id) != row.operation_digest or request_id in settled:
            raise TenantEngineRunTraceError("target settlement has no unique dispatch")
        settled.add(request_id)
        if row.kind == "target_unknown":
            unknown += 1
            continue
        observed = retained_results.get(row.result_ref or "")
        if observed is None:
            reasons.add("observation_missing")
            unknown += 1
            continue
        observed.__post_init__()
        content = _observation_content(observed.observation)
        fixture_digest = observed.observation.environment.get("fixture_digest")
        if not isinstance(fixture_digest, str):
            raise TenantEngineRunTraceError("retained observation fixture is invalid")
        try:
            observed_snapshot_ref = tenant_target_snapshot_ref(
                fixture_digest=fixture_digest,
                target_snapshot_id=content["target_snapshot_id"],
                service_generation=content["service_generation"],
            )
        except (TypeError, ValueError):
            raise TenantEngineRunTraceError("retained observation snapshot is invalid") from None
        if (
            observed.digest != row.result_ref
            or observed.binding_digest != binding.digest
            or observed.generation_digest != binding.generation_digest
            or observed.relay_request_id != request_id
            or observed.operation_digest != row.operation_digest
            or observed.observation.run_id != binding.run_id
            or observed.observation.target_scope_ref != binding.scope_ref
            or content["attempt_id"] != binding.attempt_id
            or observed_snapshot_ref != binding.target_snapshot_ref
            or observed.target_request_id in target_ids
        ):
            raise TenantEngineRunTraceError("retained observation correlation changed")
        target_ids.add(observed.target_request_id)
        used_results.add(observed.digest)
        protected = content["protected_record_ids"]
        expected = (
            "unauthorized_disclosure"
            if protected
            else "authorization_denied"
            if content["response_status"] in {401, 403}
            else "no_protected_effect"
        )
        if content["assessment"] != expected:
            raise TenantEngineRunTraceError("observer assessment contradicts observed effects")
        disclosure = disclosure or bool(protected)
        results += 1
        response_bytes += content["response_bytes"]
    if set(retained_results) != used_results:
        reasons.add("observation_set_incomplete")
    pending = len(dispatched) - len(settled)
    if pending or unknown:
        reasons.add("target_calls_incomplete")
    if not dispatched:
        reasons.add("no_target_calls")
    if len(dispatched) >= binding.max_http_calls:
        reasons.add("http_calls_exhausted")
    if response_bytes >= binding.max_total_response_bytes:
        reasons.add("response_bytes_exhausted")
    terminal_ref: str | None = None
    if terminal is None or retained_terminal_ref is None:
        reasons.add("terminal_missing")
    else:
        terminal.__post_init__()
        _digest(retained_terminal_ref)
        if terminal.binding_digest != binding.digest or terminal.digest != retained_terminal_ref:
            raise TenantEngineRunTraceError("retained terminal binding changed")
        terminal_ref = terminal.digest
        if (
            terminal.last_sequence != len(events)
            or terminal.trace_digest != digest
            or terminal.dispatched_calls != len(dispatched)
            or terminal.target_results != results
            or terminal.controller_refusals != refusals
            or terminal.unknown_target_calls != unknown
            or terminal.pending_calls != pending
            or terminal.response_bytes != response_bytes
        ):
            reasons.add("terminal_counts_incomplete")
        if terminal.state != "completed" or not terminal.complete:
            reasons.add("terminal_incomplete")
        if not terminal.owned_work_settled or terminal.cessation_ref is None:
            reasons.add("owned_work_unsettled")
        if reopened_cessation is None:
            reasons.add("cessation_receipt_missing")
        else:
            if type(reopened_cessation) is not VerifiedTenantHttpCessationReceipt:
                raise TenantEngineRunTraceError(
                    "cessation requires a reopened controller capability"
                )
            try:
                reopened_cessation.to_dict()
            except (AttributeError, TypeError, TenantHttpCompletionContractError):
                raise TenantEngineRunTraceError(
                    "cessation capability lacks controller authority"
                ) from None
            if (
                reopened_cessation.run_id != binding.run_id
                or reopened_cessation.attempt_id != binding.attempt_id
                or reopened_cessation.binding_digest != binding.digest
                or reopened_cessation.profile_digest != binding.profile_digest
                or reopened_cessation.generation_digest != binding.generation_digest
                or reopened_cessation.target_snapshot_ref != binding.target_snapshot_ref
                or reopened_cessation.controller_trace_ref != binding.controller_trace_ref
                or terminal.cessation_ref != reopened_cessation.digest
            ):
                raise TenantEngineRunTraceError("cessation receipt belongs to another run or trace")
            if not previous_ns <= reopened_cessation.issued_ns <= terminal.finished_ns:
                reasons.add("cessation_time_incomplete")
        if terminal.truncated:
            reasons.add("trace_truncated")
        if terminal.exhausted_budgets:
            reasons.add("budget_exhausted")
        if terminal.finished_ns < previous_ns or terminal.finished_ns >= binding.deadline_ns:
            reasons.add("terminal_deadline_incomplete")
    complete = not reasons
    return TenantEngineRunTraceAssessment(
        completeness="complete" if complete else "unknown",
        outcome=("disclosure observed" if disclosure else NO_DISCLOSURE_OUTCOME)
        if complete
        else "unknown",
        dispatched_calls=len(dispatched),
        target_results=results,
        controller_refusals=refusals,
        unknown_target_calls=unknown,
        pending_calls=pending,
        response_bytes=response_bytes,
        reasons=tuple(sorted(reasons)),
        binding_digest=binding.digest,
        trace_digest=digest,
        terminal_ref=terminal_ref,
    )
