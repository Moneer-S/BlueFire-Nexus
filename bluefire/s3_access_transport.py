"""Authenticated, read-only discovery of explicitly enrolled S3 environments."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .runner_contracts import seal_profile
from .runner_transport_errors import RunnerAuthenticationError
from .s3_access_admission import ACTION, SCHEMA, approved_request
from .s3_access_contract import S3AccessError, digest, document, exact
from .s3_access_host_config import public_environments, read_configuration, selected_environment
from .s3_access_launch import S3LaunchIntent
from .s3_access_results import environment
from .util import canonical_json_bytes

OPERATION = "s3_access_environments"


def server_environments(server, request, enrollment, *, refusal):
    server._require_payload(request, frozenset())
    server._verified_runner_binary_digest()
    if getattr(server.runner, "s3_access_admission_protocol", None) != SCHEMA:
        return {"environments": []}
    inventory, _canonical = server._validated_inventory(enrollment)
    descriptors = [row for row in inventory.get("actions", []) if row.get("action_id") == ACTION]
    if len(descriptors) != 1 or descriptors[0].get("capabilities") != ["cloud_aws_s3_access"]:
        return {"environments": []}
    try:
        configuration = read_configuration(enrollment)
        if configuration is None:
            return {"environments": []}
        from .s3_access_runtime import validate_runtime

        rows = []
        for entry, public in zip(
            configuration["environments"], public_environments(configuration), strict=True
        ):
            if entry["profile"]["profile_id"] != request["profile_id"]:
                continue
            available = False
            try:
                runtime = validate_runtime(Path(entry["runtime_root"]), entry["runtime_digest"])
                available = runtime.worker_generation == entry["worker_generation"]
            except (OSError, ValueError, RuntimeError):
                pass
            rows.append(
                {
                    "environment": public,
                    "profile": entry["profile"],
                    "runtime_digest": entry["runtime_digest"],
                    "worker_generation": entry["worker_generation"],
                    "available": available,
                    "problem": None if available else "runtime_unavailable",
                }
            )
        return {"environments": rows}
    except (OSError, TypeError, ValueError, RuntimeError):
        raise refusal("runner_failure") from None


def authenticated_intent(
    runner, enrollment, manifest, profile, *, task_id, issuer
) -> S3LaunchIntent:
    if getattr(runner, "s3_access_admission_protocol", None) != SCHEMA:
        raise S3AccessError("Enrolled S3 launch authority is unavailable")
    request, approval = approved_request(
        manifest, profile, task_id=task_id, now=datetime.now(timezone.utc)
    )
    configuration = read_configuration(enrollment)
    if configuration is None:
        raise S3AccessError("Enrolled S3 environment is unavailable")
    selected_environment(configuration, request, approval, profile)
    return S3LaunchIntent(dict(issuer))


def client_environments(client: Any) -> list[dict[str, Any]]:
    raw = client._call(OPERATION, {}, task_id=client._random_task("s3-environments"))
    try:
        payload = document(raw, limit=512 * 1024)
        exact(payload, {"environments"}, "S3 environment response")
        rows = payload["environments"]
        if not isinstance(rows, list) or len(rows) > 8:
            raise S3AccessError("S3 environment response is unbounded")
        identifiers = set()
        for row in rows:
            exact(
                row,
                {
                    "environment",
                    "profile",
                    "runtime_digest",
                    "worker_generation",
                    "available",
                    "problem",
                },
                "S3 environment status",
            )
            public = environment(row["environment"])
            if public["environment_id"] in identifiers or canonical_json_bytes(
                public
            ) != canonical_json_bytes(row["environment"]):
                raise S3AccessError("S3 environment response is ambiguous")
            identifiers.add(public["environment_id"])
            digest(row["runtime_digest"])
            digest(row["worker_generation"])
            profile = row["profile"]
            if (
                type(row["available"]) is not bool
                or row["problem"] != (None if row["available"] else "runtime_unavailable")
                or not isinstance(profile, Mapping)
                or profile.get("profile_id") != client.profile_id
                or profile.get("platform") != "linux"
                or profile.get("policy_digest") != seal_profile(profile).get("policy_digest")
                or "cloud_aws_s3_access" not in profile.get("capabilities", [])
                or ACTION not in profile.get("allowed_actions", [])
                or ACTION in profile.get("control_blocked_actions", [])
            ):
                raise S3AccessError("S3 environment response differs from its enrolled profile")
        return rows
    except (TypeError, ValueError, KeyError):
        raise RunnerAuthenticationError("S3 environment response is invalid.") from None
