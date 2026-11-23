"""Bounded historical findings from exact grant-owned attempts, without execution authority.

Sealed source integrity does not establish semantic truth or current resource availability.
This local projection is not a provider-data-policy bypass or an imported execution input.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from .application_errors import APIError
from .detection_evaluations import _source, _source_binding
from .evidence import EvidenceProvenance, EvidenceRecord
from .product_store_errors import ProductStoreError
from .runner_contracts import _verified_grant_attempt
from .util import canonical_json_bytes, content_hash

QUERY_SCHEMA = "bluefire.composition-knowledge-query.v1"
SCHEMA = "bluefire.composition-knowledge.v1"
MAX_ATTEMPTS = 8
MAX_FINDINGS = 32
MAX_RESPONSE_BYTES = 1_048_576
_SHA256 = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")
_JOB_ID = re.compile(r"job-[0-9a-f]{32}\Z")
_ATTEMPT_ID = re.compile(r"attempt-[0-9a-f]{32}\Z")
_SOURCE_PROBLEM = "The finalized source and its original attempt could not be verified."
_JOB_STATES = {
    "queued",
    "planning",
    "paused",
    "running",
    "awaiting_approval",
    "cancelling",
    "cancelled",
    "completed",
    "failed",
    "interrupted",
}
_RUN_STATES = {
    "created",
    "completed",
    "incomplete",
    "awaiting_approval",
    "failed",
    "cancelled",
    "interrupted",
    "partial",
    "unknown",
}
_COLLECTORS = {
    ("collector.filesystem.sandbox.v1", "filesystem"): "observed_filesystem",
    ("collector.collection-semantics.sandbox.v1", "collection_semantics"): "observed_collection",
    ("collector.process.native.v1", "process"): "observed_process_snapshot",
    ("collector.network.loopback-receiver.v1", "network"): "observed_receiver_binding",
}
_COUNT_FIELDS = {
    "size_bytes",
    "record_count",
    "redacted_record_count",
    "retained_record_count",
    "empty_record_count",
    "process_id",
    "parent_process_id",
    "bytes_received",
    "receiver_process_id",
    "control_revision",
}
_BOOL_FIELDS = {"group_write_bit", "other_write_bit", "non_owner_write_bit"}
_ENUM_FIELDS = {
    "permission_status": {"available", "unavailable_windows", "unsupported_platform"},
    "effective_access": {"not_evaluated"},
    "container": {"jsonl", "ustar", "gzip"},
    "platform": {"linux", "windows", "macos"},
    "runner_status": {"success", "partial", "failed", "refused", "control_blocked", "cancelled"},
    "outcome": {"allowed", "permission_denied"},
    "reader": {"owner", "non_owner"},
}


def _identity(value: Any, pattern: re.Pattern[str]) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _request_ids(request: Any) -> list[str]:
    if (
        not isinstance(request, Mapping)
        or set(request) != {"schema_version", "attempt_ids"}
        or request["schema_version"] != QUERY_SCHEMA
        or not isinstance(request["attempt_ids"], list)
        or not 1 <= len(request["attempt_ids"]) <= MAX_ATTEMPTS
        or any(not _identity(item, _ATTEMPT_ID) for item in request["attempt_ids"])
        or len(set(request["attempt_ids"])) != len(request["attempt_ids"])
    ):
        raise ProductStoreError("Select one to eight distinct saved attempt identities.")
    return list(request["attempt_ids"])


def _members(jobs: Any, owner_id: str, attempt_ids: list[str]) -> list[tuple[dict, dict]]:
    """Validate every requested member before loading any source content."""
    if not _identity(owner_id, _JOB_ID):
        raise ProductStoreError("Select a canonical saved composition objective.")
    owner = jobs.store.get_job(owner_id)
    if (
        owner.get("job_id") != owner_id
        or owner.get("kind") != "composition.objective"
        or owner.get("state") != "completed"
        or owner.get("progress", {}).get("admission") != {"accepted": True, "problem": None}
    ):
        raise ProductStoreError("Select an admitted saved composition objective.")
    result = []
    try:
        grant_id, grant_digest = owner["request"]["grant_id"], owner["request"]["grant_digest"]
        for attempt_id in attempt_ids:
            attempt = jobs.store.get_capability_attempt(attempt_id)
            lease, compiled = attempt["lease"], attempt["compiled"]
            child = jobs.store.get_job(lease["job_id"])
            marker = child["request"]["composition_attempt"]
            if (
                child["kind"] != "composition.attempt"
                or child["job_id"] != lease["job_id"]
                or not _identity(child["job_id"], _JOB_ID)
                or marker["parent_job_id"] != owner_id
                or lease["attempt_id"] != attempt_id
                or lease["grant_id"] != grant_id
                or lease["grant_digest"] != grant_digest
                or compiled["grant_id"] != grant_id
                or compiled["grant_digest"] != grant_digest
                or compiled["compiled_digest"] != lease["compiled_digest"]
                or any(
                    marker[key] != lease[key]
                    for key in (
                        "attempt_id",
                        "grant_id",
                        "grant_digest",
                        "compiled_digest",
                        "run_id",
                    )
                )
                or attempt["state"] not in {"reserved", "claimed", "settled"}
                or child["state"] not in _JOB_STATES
            ):
                raise ProductStoreError(
                    "Selected evidence belongs to another objective or attempt."
                )
            result.append((attempt, child))
    except (KeyError, TypeError, AttributeError) as exc:
        raise ProductStoreError(
            "The saved objective and attempt membership is incomplete."
        ) from exc
    return result


def _project_fields(values: Any, allowed: set[str]) -> dict[str, str | int | bool]:
    """Only scalar fields with specific semantics; never logs, buffers or arbitrary strings."""
    if not isinstance(values, Mapping):
        return {}
    projected: dict[str, str | int | bool] = {}
    for name in sorted(allowed):
        value = values.get(name)
        if name in _COUNT_FIELDS and type(value) is int and 0 <= value <= 2**53 - 1:
            projected[name] = value
        elif name in _BOOL_FIELDS and type(value) is bool:
            projected[name] = value
        elif name in _ENUM_FIELDS and isinstance(value, str) and value in _ENUM_FIELDS[name]:
            projected[name] = value
        elif name == "sha256" and isinstance(value, str) and _identity(value, _SHA256):
            projected[name] = value
        elif name in {"permission_mode_octal", "mode"} and isinstance(value, str):
            if re.fullmatch(r"0[0-7]{3}", value):
                projected[name] = value
    return projected


def _summary(record: EvidenceRecord) -> tuple[str, dict[str, str | int | bool]]:
    content = record.content
    if record.provenance is EvidenceProvenance.OBSERVED:
        observation_kind = content.get("observation_kind")
        kind = (
            _COLLECTORS.get((record.producer, observation_kind))
            if isinstance(observation_kind, str)
            else None
        )
        if kind is not None and content.get("artifact_type") == "collector_observation":
            fields = {
                "observed_filesystem": {
                    "size_bytes",
                    "sha256",
                    "permission_status",
                    "effective_access",
                    "permission_mode_octal",
                    "group_write_bit",
                    "other_write_bit",
                    "non_owner_write_bit",
                },
                "observed_collection": {
                    "size_bytes",
                    "sha256",
                    "container",
                    "record_count",
                    "redacted_record_count",
                    "retained_record_count",
                    "empty_record_count",
                },
                "observed_process_snapshot": {"process_id", "parent_process_id", "platform"},
                "observed_receiver_binding": {"sha256", "bytes_received", "receiver_process_id"},
            }[kind]
            return kind, _project_fields(content.get("observed_fields"), fields)
    if record.provenance in {EvidenceProvenance.EXECUTED, EvidenceProvenance.CONTROL_BLOCKED} and (
        record.producer in {"bluefire-rust-runner", "bluefire-macos-original-workspace"}
    ):
        summary = _project_fields(content, {"runner_status"})
        output = content.get("output")
        observation = output.get("observation") if isinstance(output, Mapping) else None
        # This remains a runner report, not independently authenticated effective-access proof.
        if (
            record.action_id in {"file_access.probe.non_owner.v1", "file_access.verify.owner.v1"}
            and isinstance(observation, Mapping)
            and observation.get("schema_version") == "bluefire.file-access-observation.v1"
        ):
            summary.update(
                {
                    "reported_" + key: value
                    for key, value in _project_fields(
                        observation,
                        {"outcome", "reader", "mode", "sha256", "record_count", "control_revision"},
                    ).items()
                }
            )
        return "runner_result", summary
    if (
        record.provenance is EvidenceProvenance.UNKNOWN
        and content.get("artifact_type") == "evidence_gap"
    ):
        return "evidence_gap", {"observation_available": False}
    return "record_metadata", {}


def _finding(
    owner_id: str, lease: Mapping[str, Any], binding_digest: str, record: EvidenceRecord
) -> dict:
    reference = {
        "owner_id": owner_id,
        "attempt_id": lease["attempt_id"],
        "job_id": lease["job_id"],
        "run_id": lease["run_id"],
        "evidence_id": record.evidence_id,
        "record_hash": record.record_hash,
        "source_binding_digest": binding_digest,
    }
    kind, summary = _summary(record)
    return {
        "finding_id": "finding-" + content_hash(reference).removeprefix("sha256:"),
        "evidence_id": record.evidence_id,
        "step_id": record.step_id,
        "behavior_id": record.behavior_id,
        "action_id": record.action_id,
        "provenance": record.provenance.value,
        "semantic_kind": kind,
        "observed_at": record.timestamp,
        "content_hash": record.content_hash,
        "record_hash": record.record_hash,
        "summary": summary,
        "applicability": {"status": "historical_only", "reason": "current_state_not_verified"},
        "record_ref": reference,
    }


def _attempt_source(jobs: Any, owner_id: str, attempt: dict, child: dict) -> dict:
    lease = attempt["lease"]
    response = {
        "attempt_id": lease["attempt_id"],
        "job_id": lease["job_id"],
        "run_id": lease["run_id"],
        "state": attempt["state"],
        "job_state": child["state"],
        "run_status": None,
        "source_status": "unavailable",
        "source_binding": None,
        "problem": _SOURCE_PROBLEM,
        "findings_total": 0,
        "findings_truncated": False,
        "findings": [],
    }
    try:
        run, records, observed = _source(jobs.service.detection_lab, lease["run_id"])
        claim = _verified_grant_attempt(
            attempt["claim"]["document"],
            expected_document_digest=attempt["claim"]["document_digest"],
        ).to_dict()
        if (
            any(
                claim[key] != lease[key]
                for key in (
                    "grant_id",
                    "grant_digest",
                    "attempt_id",
                    "lease_digest",
                    "compiled_digest",
                    "plan_digest",
                    "native_envelope_digest",
                    "run_id",
                )
            )
            or run["run_id"] != lease["run_id"]
            or run["scenario"] != attempt["compiled"]["scenario"]
            or run["mode"] != "execute"
            or run["plan"]["autonomy"] != "off"
            or content_hash(run["plan"]) != lease["plan_digest"]
            or run["policy"].get("grant_attempt") != claim
            or run.get("status") not in _RUN_STATES
        ):
            return response
        binding = _source_binding(run, records, observed)
        response.update(
            source_status="verified",
            source_binding=binding,
            problem=None,
            run_status=run["status"],
            findings_total=len(records),
            findings_truncated=len(records) > MAX_FINDINGS,
            findings=[
                _finding(owner_id, lease, content_hash(binding), record)
                for record in records[:MAX_FINDINGS]
            ],
        )
    except (APIError, ProductStoreError, ValueError, KeyError, TypeError, AttributeError, OSError):
        # The source's detailed diagnostics stay in its ordinary run view, not this bounded projection.
        return response
    return response


def build_knowledge(jobs: Any, owner_id: str, request: Any) -> dict[str, Any]:
    """Read applicable history identities; never claim, schedule, refresh or mutate an attempt."""
    members = _members(jobs, owner_id, _request_ids(request))
    response = {
        "schema_version": SCHEMA,
        "owner_id": owner_id,
        "attempts": [_attempt_source(jobs, owner_id, attempt, child) for attempt, child in members],
    }
    response["knowledge_digest"] = content_hash(response)
    if len(canonical_json_bytes(response)) > MAX_RESPONSE_BYTES:
        raise ProductStoreError(
            "Selected historical findings exceed the bounded knowledge response."
        )
    return response
