"""Exact S3 host-admission data. Authentication remains an inherited host channel."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, cast

from .runner_contracts import seal_manifest, seal_profile
from .s3_access_contract import S3AccessError, digest, document, exact
from .s3_access_host_config import selected_environment
from .s3_access_results import reviewer
from .s3_access_wire import S3WorkerRequest, timestamp
from .util import canonical_json_bytes, content_hash

ACTION = "owned.aws.s3_access.v1"
SCHEMA = "bluefire.s3-access-admission.v1"
PROTOCOL = "bluefire.s3-access-launch.v1"
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
_PHASES = {
    "inspect": {"inspect_policy"},
    "baseline": {"probe_read", "legitimate_read"},
    "retest": {"probe_read", "legitimate_read"},
    "apply": {"apply_policy"},
    "reconcile": {"reconcile_policy"},
    "rollback": {"rollback_policy"},
}


def _require(value: bool) -> None:
    if not value:
        raise S3AccessError("S3 protected admission is unavailable")


def _identifier(value: Any) -> None:
    _require(
        isinstance(value, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value) is not None
    )


def approved_request(
    manifest: Mapping[str, Any], profile: Mapping[str, Any], *, task_id: str, now: datetime
) -> tuple[S3WorkerRequest, dict[str, Any]]:
    """Validate the exact sealed request before any credential or runtime read."""
    _require(now.tzinfo is not None)
    params = document(manifest.get("params"), limit=96 * 1024)
    exact(params, {"worker_request", "workflow_approval"}, "S3 task parameters")
    request = S3WorkerRequest.from_mapping(params["worker_request"])
    request.assert_current(lambda: now)
    workflow = params["workflow_approval"]
    exact(workflow, _APPROVAL, "S3 workflow approval")
    _require(workflow["schema_version"] == "bluefire.s3-workflow-approval.v1")
    for name in ("workflow_job_id", "operation_job_id", "environment_id"):
        _identifier(workflow[name])
    _require(workflow["reviewed_by"] == reviewer(workflow["reviewed_by"]))
    digest(workflow["review_digest"])
    revision = workflow["expected_workflow_revision"]
    _require(type(revision) is int and 0 <= revision <= 1_000_000)
    runs = workflow["prior_run_ids"]
    _require(isinstance(runs, list) and len(runs) <= 32)
    for run in runs:
        _identifier(run)
    _require(len(runs) == len(set(runs)))
    row = request.to_dict()
    _require(
        isinstance(workflow["phase"], str)
        and row["operation"] in _PHASES.get(workflow["phase"], set())
    )
    change = row["policy_change"]
    _require(
        workflow["policy_change_digest"] == (content_hash(change) if change is not None else None)
    )
    _require(
        workflow["scope_digest"] == row["scope_digest"]
        and workflow["request_digest"] == request.digest
    )
    approval = manifest.get("approval")
    if not isinstance(approval, Mapping):
        raise S3AccessError("S3 protected admission is unavailable")
    limits, ceiling = manifest.get("limits"), profile.get("limits")
    if not isinstance(limits, Mapping) or not isinstance(ceiling, Mapping):
        raise S3AccessError("S3 protected admission is unavailable")
    timeout, maximum = limits.get("timeout_ms"), ceiling.get("timeout_ms")
    _require(type(timeout) is int and type(maximum) is int and 0 < timeout <= min(60_000, maximum))
    tiers = {"safe": 1, "controlled": 2, "restricted": 3}
    _require(
        manifest.get("schema_version") == "bluefire.runner-manifest.v1"
        and profile.get("schema_version") == "bluefire.runner-profile.v1"
        and manifest.get("action_id") == ACTION
        and manifest.get("mode") == "execute"
        and manifest.get("platform") == profile.get("platform") == "linux"
        and manifest.get("runner_id") == profile.get("runner_id")
        and manifest.get("runner_profile_id") == profile.get("profile_id")
        and manifest.get("request_hash") == seal_manifest(manifest).get("request_hash")
        and profile.get("policy_digest") == seal_profile(profile).get("policy_digest")
        and manifest.get("policy_digest") == profile.get("policy_digest")
        and approval.get("request_hash") == manifest.get("request_hash")
        and timestamp(approval.get("approved_at")) <= now < timestamp(approval.get("expires_at"))
        and timestamp(manifest.get("requested_at")) <= now < timestamp(manifest.get("expires_at"))
        and manifest.get("required_capabilities") == ["cloud_aws_s3_access"]
        and "cloud_aws_s3_access" in profile.get("capabilities", [])
        and ACTION in profile.get("allowed_actions", [])
        and ACTION not in profile.get("control_blocked_actions", [])
        and manifest.get("safety_tier") in tiers
        and profile.get("max_safety_tier") in tiers
        and tiers[manifest["safety_tier"]] <= tiers[profile["max_safety_tier"]]
        and all(
            manifest.get(name) is None
            for name in (
                "execution_binding",
                "provider_binding",
                "reviewed_operation",
                "grant_attempt",
                "grant_cleanup",
            )
        )
        and task_id
        == "execute-"
        + content_hash({"manifest": dict(manifest), "profile": dict(profile)}).removeprefix(
            "sha256:"
        )
    )
    return request, dict(workflow)


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True, repr=False)
class S3HostAdmission:
    """Immutable data, not a bearer or a substitute for host authentication."""

    _payload: bytes

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], json.loads(self._payload))

    def canonical_bytes(self) -> bytes:
        return self._payload

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())

    @classmethod
    def issue(
        cls,
        *,
        issuer: Mapping[str, Any],
        configuration: Mapping[str, Any],
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        task_id: str,
        runner_digest: str,
        credential_digest: str,
        owner_uid: int,
        now: datetime,
    ) -> S3HostAdmission:
        request, workflow = approved_request(manifest, profile, task_id=task_id, now=now)
        entry = selected_environment(configuration, request, workflow, profile)
        exact(
            issuer,
            {
                "runner_id",
                "client_id",
                "enrollment_generation",
                "peer_fingerprint",
                "server_instance_id",
            },
            "S3 issuer",
        )
        for name in ("runner_id", "client_id", "server_instance_id"):
            _identifier(issuer[name])
        for name in ("enrollment_generation", "peer_fingerprint"):
            digest(issuer[name])
        digest(runner_digest)
        digest(credential_digest)
        _require(
            type(owner_uid) is int
            and 0 < owner_uid < 2**32 - 1
            and issuer["runner_id"] == profile["runner_id"]
        )
        expires = min(
            now + timedelta(seconds=60),
            timestamp(request.to_dict()["deadline"]),
            timestamp(manifest["expires_at"]),
            timestamp(manifest["approval"]["expires_at"]),
        )
        return cls(
            canonical_json_bytes(
                {
                    "schema_version": SCHEMA,
                    "issuer": dict(issuer),
                    "manifest_digest": content_hash(manifest),
                    "profile_digest": content_hash(profile),
                    "request_digest": request.digest,
                    "approval_digest": content_hash(workflow),
                    "host": {
                        "environment_id": entry["environment_id"],
                        "scope_digest": request.to_dict()["scope_digest"],
                        "runtime_digest": entry["runtime_digest"],
                        "worker_generation": entry["worker_generation"],
                        "ledger_root": entry["ledger_root"],
                        "runtime_root": entry["runtime_root"],
                        "owner_uid": owner_uid,
                    },
                    "native_runner_digest": runner_digest,
                    "credential_digest": credential_digest,
                    "issued_at": _utc(now),
                    "expires_at": _utc(expires),
                }
            )
        )

    def recheck(
        self,
        *,
        issuer: Mapping[str, Any],
        configuration: Mapping[str, Any],
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        task_id: str,
        runner_digest: str,
        credential_digest: str,
        owner_uid: int,
        now: datetime,
    ) -> None:
        row = self.to_dict()
        issued, expires = timestamp(row.get("issued_at")), timestamp(row.get("expires_at"))
        _require(issued <= now < expires)
        expected = self.issue(
            issuer=issuer,
            configuration=configuration,
            manifest=manifest,
            profile=profile,
            task_id=task_id,
            runner_digest=runner_digest,
            credential_digest=credential_digest,
            owner_uid=owner_uid,
            now=issued,
        )
        _require(expected.canonical_bytes() == self._payload)
        approved_request(manifest, profile, task_id=task_id, now=now)
