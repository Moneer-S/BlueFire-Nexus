"""Secret-free original-task consistency, not renewed execution authority."""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any, Mapping

from .runner_contracts import seal_manifest, seal_profile
from .s3_access_contract import S3AccessError, digest, document, exact
from .s3_access_results import reviewer
from .s3_access_wire import S3WorkerRequest, timestamp
from .util import canonical_json_bytes, content_hash

SCHEMA = "bluefire.s3-original-task.v1"
_PROFILE = {
    "schema_version",
    "profile_id",
    "runner_id",
    "platform",
    "sandbox_root",
    "allowed_actions",
    "control_blocked_actions",
    "capabilities",
    "max_safety_tier",
    "approval_required_at_or_above",
    "target_scope",
    "limits",
    "policy_digest",
    "native_tool_installations",
    "action_bindings",
    "provider_bindings",
    "provider_artifacts",
    "reviewed_execution",
}
_APPROVAL = {
    "schema_version",
    "workflow_job_id",
    "operation_job_id",
    "environment_id",
    "scope_digest",
    "request_digest",
    "phase",
    "reviewed_by",
    "review_digest",
    "expected_workflow_revision",
    "prior_run_ids",
    "policy_change_digest",
}
_TRANSPORT = {
    "schema_version",
    "runner_id",
    "client_id",
    "transport",
    "tls",
    "server_fingerprint",
    "client_fingerprint",
    "authenticated_peer_fingerprint",
    "enrollment_generation",
    "runner_binary_digest",
    "inventory_digest",
}


def _review(request: S3WorkerRequest, approval: Any) -> None:
    exact(approval, _APPROVAL, "S3 original review")
    for key in ("workflow_job_id", "operation_job_id", "environment_id"):
        if (
            not isinstance(approval[key], str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", approval[key]) is None
        ):
            raise S3AccessError("S3 original review identity is invalid")
    runs = approval["prior_run_ids"]
    if (
        not isinstance(runs, list)
        or len(runs) > 32
        or any(
            not isinstance(value, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value) is None
            for value in runs
        )
        or len(set(runs)) != len(runs)
    ):
        raise S3AccessError("S3 original review run references are invalid")
    row = request.to_dict()
    phases = {
        "inspect": {"inspect_policy"},
        "baseline": {"probe_read", "legitimate_read"},
        "retest": {"probe_read", "legitimate_read"},
        "apply": {"apply_policy"},
        "reconcile": {"reconcile_policy"},
        "rollback": {"rollback_policy"},
    }
    change = row["policy_change"]
    if (
        approval["schema_version"] != "bluefire.s3-workflow-approval.v1"
        or not isinstance(approval["phase"], str)
        or row["operation"] not in phases.get(approval["phase"], set())
        or approval["reviewed_by"] != reviewer(approval["reviewed_by"])
        or type(approval["expected_workflow_revision"]) is not int
        or not 0 <= approval["expected_workflow_revision"] <= 1_000_000
        or approval["scope_digest"] != row["scope_digest"]
        or approval["request_digest"] != request.digest
        or approval["policy_change_digest"]
        != (content_hash(change) if change is not None else None)
    ):
        raise S3AccessError("S3 original review differs from its request")
    digest(approval["review_digest"])


def execution_manifest(
    request: S3WorkerRequest, authorization: Mapping[str, Any], profile: Mapping[str, Any]
) -> dict[str, Any]:
    row = request.to_dict()
    deadline = timestamp(row["deadline"])
    seconds = row["scope"]["limits"]["request_seconds"]
    issued = (deadline - timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
    limits = dict(profile["limits"])
    limits["timeout_ms"] = min(limits["timeout_ms"], seconds * 1000)
    return seal_manifest(
        {
            "schema_version": "bluefire.runner-manifest.v1",
            "request_id": "s3-" + row["request_id"],
            "run_id": authorization["operation_job_id"],
            "step_id": row["operation"],
            "behavior_id": "cloud.s3.access_hardening.v1",
            "action_id": "owned.aws.s3_access.v1",
            "mode": "execute",
            "runner_id": profile["runner_id"],
            "runner_profile_id": profile["profile_id"],
            "platform": "linux",
            "requested_at": issued,
            "expires_at": row["deadline"],
            "params": {"worker_request": row, "workflow_approval": dict(authorization)},
            "target_scope": {"filesystem": [], "network": []},
            "required_capabilities": ["cloud_aws_s3_access"],
            "safety_tier": "controlled",
            "limits": limits,
            "cleanup_action_id": None,
            "policy_digest": profile["policy_digest"],
            "approval": {
                "approved_by": authorization["reviewed_by"],
                "approved_at": issued,
                "expires_at": row["deadline"],
                "request_hash": "",
            },
            "evidence_refs": [],
            "request_hash": "",
        }
    )


def validate_recovery_context(request: S3WorkerRequest, value: Any) -> dict[str, Any]:
    """Check a historical checkpoint without consulting a clock or any host."""
    request = S3WorkerRequest.from_mapping(request.to_dict())
    row = document(value, limit=256 * 1024)
    exact(
        row,
        {
            "schema_version",
            "request_digest",
            "task_id",
            "transport_request_hash",
            "manifest",
            "profile",
            "transport_identity",
        },
        "S3 original task",
    )
    try:
        if row["schema_version"] != SCHEMA or row["request_digest"] != request.digest:
            raise S3AccessError("S3 original task belongs to another request")
        profile, manifest, identity = row["profile"], row["manifest"], row["transport_identity"]
        if not isinstance(profile, dict) or set(profile) - _PROFILE:
            raise S3AccessError("S3 original profile has unrecognized fields")
        if canonical_json_bytes(profile) != canonical_json_bytes(seal_profile(profile)):
            raise S3AccessError("S3 original profile seal is invalid")
        params = manifest["params"]
        exact(params, {"worker_request", "workflow_approval"}, "S3 original parameters")
        approval = params["workflow_approval"]
        _review(request, approval)
        expected = execution_manifest(request, approval, profile)
        if canonical_json_bytes(manifest) != canonical_json_bytes(expected):
            raise S3AccessError("S3 original manifest differs from its request")
        transport_hash = content_hash({"manifest": manifest, "profile": profile})
        if row["transport_request_hash"] != transport_hash or row["task_id"] != (
            "execute-" + transport_hash.removeprefix("sha256:")
        ):
            raise S3AccessError("S3 original transport task identity is invalid")
        exact(identity, _TRANSPORT, "S3 original transport identity")
        if (
            identity["schema_version"] != "bluefire.runner-transport-identity.v1"
            or identity["transport"] != "mutual-tls-loopback"
            or identity["tls"] != "TLSv1.3"
            or identity["runner_id"] != profile["runner_id"]
            or identity["client_fingerprint"] != identity["authenticated_peer_fingerprint"]
        ):
            raise S3AccessError("S3 original authenticated host identity is invalid")
        for key in ("runner_id", "client_id"):
            if (
                not isinstance(identity[key], str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", identity[key]) is None
            ):
                raise S3AccessError("S3 original host identity is invalid")
        for key in _TRANSPORT - {"schema_version", "runner_id", "client_id", "transport", "tls"}:
            digest(identity[key])
        return row
    except (KeyError, TypeError, ValueError):
        raise S3AccessError("S3 original task checkpoint is invalid") from None
