"""Pure derivation of retained read proof from exact original task terminals."""

from __future__ import annotations

from typing import Any, Mapping

from .domain_errors import ProductStoreError
from .file_access_contract import validate_file_access_observation
from .util import content_hash, parse_iso8601_datetime


def validate_task_observation(task, result, *, binding, reader, now_ms):
    observation = validate_file_access_observation(
        result.get("output", {}).get("observation"),
        binding=binding,
        request_hash=task["request_hash"],
        reader=reader,
    )
    requested_at, expires_at = (
        int(parse_iso8601_datetime(task["manifest"][key]).timestamp() * 1000)
        for key in ("requested_at", "expires_at")
    )
    if not requested_at <= observation["observed_at_ms"] < expires_at or (
        observation["observed_at_ms"] > now_ms
    ):
        raise ProductStoreError("File-access observation is outside its original task lifetime.")
    return observation


def control_observation(operation, tasks, *, binding, now_ms) -> dict[str, Any]:
    by_step = {row["task"]["step_id"]: row for row in tasks}
    if operation not in ("baseline", "rollback") or not {"probe", "owner"} <= by_step.keys():
        raise ProductStoreError("Retained read proof requires both original read tasks.")
    validated = {}
    for step, reader in (("probe", "non_owner"), ("owner", "owner")):
        row = by_step[step]
        if row["terminal"] is None or row["terminal"]["result"].get("status") != "success":
            raise ProductStoreError("Retained read proof requires successful original terminals.")
        validated[reader] = validate_task_observation(
            row["task"], row["terminal"]["result"], binding=binding, reader=reader, now_ms=now_ms
        )
    if (
        any(row["outcome"] != "allowed" for row in validated.values())
        or binding["mode"] != "0640"
        or validated["owner"]["observed_at_ms"] < validated["non_owner"]["observed_at_ms"]
        or validated["owner"]["request_hash"] == validated["non_owner"]["request_hash"]
    ):
        raise ProductStoreError("Both fresh legitimate baseline reads must actually succeed.")
    return {
        "schema_version": "bluefire.file-access-control-observation.v1",
        "operation": operation,
        "non_owner": "allowed",
        "owner": "allowed",
        "resource_generation": binding["resource_generation"],
        "record_count": binding["resource"]["record_count"],
        "sha256": binding["resource"]["sha256"],
        "mode": "0640",
        "source_digest": content_hash({"tasks": tasks, "binding": binding}),
        "observed_at_ms": validated["owner"]["observed_at_ms"],
    }


def baseline_record(job_id: str, observation: Mapping[str, Any]) -> dict[str, Any]:
    digest = observation["source_digest"]
    return {
        "baseline_digest": digest,
        "non_owner": "allowed",
        "owner": "allowed",
        "record_count": observation["record_count"],
        "sha256": observation["sha256"],
        "source_binding": {"operation_job_id": job_id, "evidence_digest": digest},
    }


def validate_committed_observation(
    job_id, operation, prepared, tasks, *, control, outcome, observation, now_ms
) -> None:
    if observation is None or type(now_ms) is not int or now_ms <= 0:
        raise ProductStoreError("Complete reads require their validated durable observation.")
    binding = prepared["target_binding"]
    if (
        binding is None
        or control["binding"] != binding
        or control["binding_digest"] != content_hash(binding)
        or outcome["evidence_digest"] != content_hash(tasks)
    ):
        raise ProductStoreError("Complete read evidence differs from its original preparation.")
    expected = control_observation(operation, tasks, binding=binding, now_ms=now_ms)
    baseline = (
        baseline_record(job_id, expected)
        if operation == "baseline"
        else prepared["prior"]["baseline"]
    )
    if observation != expected or control["baseline"] != baseline:
        raise ProductStoreError("Complete read proof differs from its exact original terminals.")
