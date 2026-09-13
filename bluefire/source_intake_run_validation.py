"""Independent semantic checks for the Gate 09 native execution record."""

from __future__ import annotations

import re
from typing import Any, Mapping

from .evidence import EvidenceError, EvidenceRecord
from .source_intake_package import ACTION_ID, BEHAVIOR_ID
from .util import content_hash, parse_iso8601_datetime

_TASK_ID = re.compile(r"^execute-[0-9a-f]{64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_INNER_FIELDS = {
    "action_id",
    "behavior_id",
    "details",
    "evidence_id",
    "kind",
    "platform",
    "policy_digest",
    "producer",
    "recorded_at",
    "references",
    "request_hash",
    "runner_id",
    "runner_profile_id",
}
_WINDOWS_VERSION_FIELDS = {
    "build_number",
    "major_version",
    "minor_version",
    "operating_system",
}


def _mapping(value: Any, message: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(message)
    return value


def _bounded_output(value: Any) -> Mapping[str, Any]:
    output = _mapping(value, "runner bounded output is absent")
    total = output.get("total_bytes")
    if (
        set(output) != {"text", "total_bytes", "truncated"}
        or not isinstance(output.get("text"), str)
        or len(str(output["text"]).encode("utf-8")) > 64 * 1024
        or isinstance(total, bool)
        or not isinstance(total, int)
        or not 0 <= total <= 4 * 1024 * 1024
        or not isinstance(output.get("truncated"), bool)
    ):
        raise ValueError("runner bounded output is invalid")
    return output


def _windows_version_output(value: Any) -> Mapping[str, Any]:
    output = _mapping(value, "native Windows version output is absent")
    major = output.get("major_version")
    minor = output.get("minor_version")
    build = output.get("build_number")
    if (
        set(output) != _WINDOWS_VERSION_FIELDS
        or output.get("operating_system") != "windows"
        or isinstance(major, bool)
        or not isinstance(major, int)
        or not 0 <= major <= 2**32 - 1
        or isinstance(minor, bool)
        or not isinstance(minor, int)
        or not 0 <= minor <= 2**32 - 1
        or isinstance(build, bool)
        or not isinstance(build, int)
        or not 0 <= build <= 2**32 - 1
    ):
        raise ValueError("native Windows version output is invalid")
    return output


def _runner_evidence_id(value: Mapping[str, Any]) -> str:
    """Recompute the Rust contract, which seals an empty ID field in place."""

    body = dict(value)
    body["evidence_id"] = ""
    return content_hash(body)


def validate_native_system_step(
    *,
    run_id: str,
    run: Mapping[str, Any],
    step: Mapping[str, Any],
    records: Any,
    runner_row: Mapping[str, Any],
    runner_content: Mapping[str, Any],
    expected_execution_binding: Mapping[str, Any],
    runner_platform: str,
    runner_architecture: str,
) -> None:
    if (
        not isinstance(records, list)
        or not records
        or any(not isinstance(item, Mapping) for item in records)
    ):
        raise ValueError("outer evidence inventory is invalid")
    try:
        verified = [EvidenceRecord.from_mapping(item) for item in records]
    except (EvidenceError, TypeError, ValueError) as exc:
        raise ValueError("outer evidence failed cryptographic validation") from exc
    evidence_ids = [item.evidence_id for item in verified]
    if (
        len(set(evidence_ids)) != len(evidence_ids)
        or step.get("evidence_ids") != evidence_ids
        or runner_row.get("evidence_id") not in evidence_ids
        or runner_row.get("run_id") != run_id
    ):
        raise ValueError("step evidence linkage is invalid")

    task_id = step.get("runner_task_id")
    request_hash = runner_content.get("request_hash")
    policy_digest = runner_content.get("policy_digest")
    if not isinstance(runner_architecture, str) or not runner_architecture:
        raise ValueError("runner architecture is invalid")
    output = _windows_version_output(runner_content.get("output"))
    stdout = _bounded_output(runner_content.get("stdout"))
    stderr = _bounded_output(runner_content.get("stderr"))
    if (
        runner_platform != "windows"
        or not isinstance(task_id, str)
        or _TASK_ID.fullmatch(task_id) is None
        or runner_content.get("runner_task_id") != task_id
        or not isinstance(request_hash, str)
        or _DIGEST.fullmatch(request_hash) is None
        or step.get("request_hash") != request_hash
        or not isinstance(policy_digest, str)
        or _DIGEST.fullmatch(policy_digest) is None
        or step.get("runner_status") != runner_content.get("runner_status")
        or runner_content.get("runner_status") != "success"
        or step.get("receipts") != []
        or runner_content.get("error") is not None
        or step.get("execution_binding") != expected_execution_binding
        or step.get("artifacts")
        != {
            "windows_version": {
                "type": "artifact.endpoint.windows-version.v1",
                "details": dict(output),
            }
        }
    ):
        raise ValueError("native step result is detached or unusable")

    inner_rows = runner_content.get("runner_evidence")
    if not isinstance(inner_rows, list) or len(inner_rows) != 1:
        raise ValueError("runner evidence inventory is invalid")
    inner = _mapping(inner_rows[0], "runner evidence is invalid")
    evidence_id = inner.get("evidence_id")
    details = _mapping(inner.get("details"), "runner evidence details are absent")
    try:
        recorded_at = parse_iso8601_datetime(str(inner.get("recorded_at")))
    except ValueError as exc:
        raise ValueError("runner evidence timestamp is invalid") from exc
    if (
        set(inner) != _INNER_FIELDS
        or evidence_id != _runner_evidence_id(inner)
        or inner.get("kind") != "executed"
        or inner.get("producer") != "bluefire-rust-runner"
        or inner.get("request_hash") != request_hash
        or inner.get("policy_digest") != policy_digest
        or inner.get("action_id") != ACTION_ID
        or inner.get("behavior_id") != BEHAVIOR_ID
        or inner.get("runner_id") != "bluefire-rust-runner.v1"
        or inner.get("runner_profile_id") != run.get("runner_profile_id")
        or inner.get("platform") != runner_platform
        or recorded_at.utcoffset() is None
        or inner.get("references") != []
        or set(details)
        != {"output_hash", "receipt_ids", "status", "stderr_total_bytes", "stdout_total_bytes"}
        or details.get("status") != "success"
        or details.get("output_hash") != content_hash(output)
        or details.get("receipt_ids") != []
        or details.get("stdout_total_bytes") != stdout["total_bytes"]
        or details.get("stderr_total_bytes") != stderr["total_bytes"]
    ):
        raise ValueError("runner evidence is detached from the native system result")


__all__ = ["validate_native_system_step"]
