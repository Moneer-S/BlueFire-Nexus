"""Small, typed observation projection for runtime choices; never raw logs or data."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .evidence import EvidenceProvenance, EvidenceRecord
from .planner import PlanStep
from .util import content_hash

_COUNT_FIELDS = frozenset(
    {
        "record_count",
        "retained_record_count",
        "redacted_record_count",
        "empty_record_count",
        "size_bytes",
        "process_count",
        "file_count",
        "entry_count",
    }
)
_ENUM_FIELDS = {
    "container": {"jsonl", "gzip", "ustar", "tar"},
    "artifact_type": {"file_observation", "collector_observation", "evidence_gap"},
    "observation_kind": {"filesystem", "collection_semantics", "process"},
}
_AUTHORIZATION_ERRORS = frozenset(
    {
        "target_scope_refused",
        "runtime_budget_exhausted",
        "approval_required",
        "approval_expired",
        "action_not_allowed",
        "capability_denied",
        "policy_refused",
    }
)
_KNOWN_ERRORS = _AUTHORIZATION_ERRORS | {
    "platform_blocked",
    "adapter_refused",
    "action_control_blocked",
    "timeout",
    "execution_failed",
    "transport_error",
    "missing_input",
    "input_not_found",
    "atomic_gzip_unavailable",
    "collection_output_limit",
    "artifact_limit_blocked",
}


def _facts(content: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in _COUNT_FIELDS:
        value = content.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**53:
            result[key] = value
    for key, allowed in _ENUM_FIELDS.items():
        value = content.get(key)
        if isinstance(value, str) and value in allowed:
            result[key] = value
    return result


def _failure(row: Mapping[str, Any], records: Sequence[EvidenceRecord]) -> dict[str, Any]:
    error = row.get("error")
    code = error.get("code") if isinstance(error, Mapping) else None
    policy = row.get("policy")
    policy_status = policy.get("status") if isinstance(policy, Mapping) else None
    # A BlueFire control-blocked profile is a product control, not evidence that
    # a target detector prevented an operation. Unknown target effects stay unknown.
    if code == "platform_blocked":
        classification = "platform_mismatch"
    elif code in _AUTHORIZATION_ERRORS or policy_status in {"refused", "approval_required"}:
        classification = "bluefire_authorization_refusal"
    elif code == "action_control_blocked" or policy_status == "control_blocked":
        classification = "bluefire_control_refusal"
    elif code in {"collection_output_limit", "artifact_limit_blocked"}:
        classification = "resource_limit"
    elif code in {"adapter_refused", "missing_input", "input_not_found", "atomic_gzip_unavailable"}:
        classification = "prerequisite_failure"
    elif any(item.provenance is EvidenceProvenance.UNKNOWN for item in records):
        classification = "missing_telemetry"
    elif row.get("status") == "failed":
        classification = "execution_failure"
    elif row.get("status") == "success":
        classification = "none"
    else:
        classification = "unknown"
    return {
        "classification": classification,
        "code": code if isinstance(code, str) and code in _KNOWN_ERRORS else None,
        "unrecognized_code_present": code is not None and code not in _KNOWN_ERRORS,
        "target_prevention": "not_established",
    }


def project_runtime_observations(
    *,
    steps: Sequence[Mapping[str, Any]],
    records: Sequence[EvidenceRecord],
    alternatives: Sequence[PlanStep],
    artifacts: Mapping[str, Any],
    platform: str,
    remaining_steps: int,
    remaining_seconds: float,
    retries_remaining: int,
) -> dict[str, Any]:
    """Project allowlisted metadata and references from verified run objects.

    Evidence stays typed as reported execution versus independent observation.
    Free-form messages, artifact bodies, paths, commands and output streams are
    deliberately absent even when a model's general data policy permits them.
    """
    if remaining_steps < 0 or remaining_seconds < 0 or retries_remaining not in {0, 1}:
        raise ValueError("runtime observation budgets are invalid")
    attempts = []
    selected_rows = list(steps[-16:])
    for index, row in enumerate(selected_rows, start=max(len(steps) - 16, 0)):
        refs = set(row.get("evidence_ids", ()))
        matching = [item for item in records if item.evidence_id in refs]
        evidence = []
        for record in matching[-32:]:
            content = record.content
            facts = _facts(content)
            observed = content.get("observed_fields")
            if record.provenance is EvidenceProvenance.OBSERVED and isinstance(observed, Mapping):
                facts.update(_facts(observed))
            output = content.get("output")
            if record.provenance is EvidenceProvenance.EXECUTED and isinstance(output, Mapping):
                facts.update(_facts(output))
                reported_size = output.get("size")
                if type(reported_size) is int and 0 <= reported_size <= 2**53:
                    facts["reported_size_bytes"] = reported_size
            evidence.append(
                {
                    "evidence_id": record.evidence_id,
                    "record_hash": record.record_hash,
                    "provenance": record.provenance.value,
                    "facts": facts,
                }
            )
        attempts.append(
            {
                "attempt_index": index,
                "step_id": row.get("step_id"),
                "behavior_id": row.get("behavior_id"),
                "action_id": row.get("action_id"),
                "outcome": row.get("status"),
                "failure": _failure(row, matching),
                "evidence": evidence,
                "omitted_evidence_count": max(len(matching) - 32, 0),
                "missing_evidence_count": len(refs - {item.evidence_id for item in matching}),
            }
        )
    methods = []
    for step in alternatives:
        missing_inputs = [
            name
            for name, binding in step.inputs.items()
            if not isinstance(artifacts.get(binding["from_step"]), Mapping)
            or binding["artifact"] not in artifacts[binding["from_step"]]
        ]
        methods.append(
            {
                "step_id": step.step_id,
                "behavior_id": step.behavior_id,
                "action_id": step.action_id,
                "reviewed_step_digest": content_hash(step.to_dict()),
                "required_inputs": list(step.inputs),
                "missing_inputs": missing_inputs,
                "input_compatible": not missing_inputs,
                "required_capabilities": list(step.required_capabilities),
                "expected_outputs": list(step.expected_outputs),
            }
        )
    body = {
        "schema_version": "bluefire.runtime-observations.v1",
        "platform": platform,
        "attempts": attempts,
        "available_methods": methods,
        "omitted_attempt_count": max(len(steps) - 16, 0),
        "remaining_budgets": {
            "steps": remaining_steps,
            "seconds": round(remaining_seconds, 3),
            "retries": retries_remaining,
        },
        "unknowns": [
            "Target prevention is not established by a product refusal.",
            "Reported execution alone does not independently verify the objective.",
            "Method availability does not establish success or external prerequisites.",
        ],
    }
    return {**body, "projection_digest": content_hash(body)}
