"""Fixed metadata artifacts for the two enrolled effective-access read methods."""

from __future__ import annotations

import hashlib
from typing import Any, Mapping, Sequence

from .file_access_contract import (
    MAX_REPORT_BYTES,
    OWNER_ACTION,
    PROBE_ACTION,
    READ_ACTIONS,
    canonical_file_access_observation,
    digest,
    exact,
    integer,
)
from .runner_provider_values import RunnerAdapterError
from .util import canonical_json_bytes, content_hash

PROBE_TYPE = "artifact.file_access.probe.v1"
VERIFY_TYPE = "artifact.file_access.verification.v1"


def request(
    action_id: str, parameters: Mapping[str, Any], bound_inputs: Mapping[str, Any]
) -> tuple[dict[str, Any], str]:
    if action_id not in READ_ACTIONS or parameters:
        raise RunnerAdapterError("file-access methods accept only fixed empty parameters")
    if action_id == PROBE_ACTION:
        if bound_inputs:
            raise RunnerAdapterError("non-owner read accepts no caller resource inputs")
        return {}, "fixtures/access-probe.json"
    if set(bound_inputs) != {"probe"}:
        raise RunnerAdapterError("owner verification requires the preceding probe artifact")
    probe = bound_inputs["probe"]
    if not isinstance(probe, Mapping) or probe.get("type") != PROBE_TYPE:
        raise RunnerAdapterError("owner verification requires the typed non-owner probe")
    observed = canonical_file_access_observation(probe.get("observation"))
    if observed["reader"] != "non_owner" or probe.get("observation_digest") != content_hash(
        observed
    ):
        raise RunnerAdapterError("preceding probe identity is invalid")
    return {}, "fixtures/access-owner.json"


def outputs(
    action_id: str,
    parameters: Mapping[str, Any],
    *,
    bound_inputs: Mapping[str, Any],
    runner_output: Any,
    receipt_ids: Sequence[str],
) -> dict[str, Any]:
    _, path = request(action_id, parameters, bound_inputs)
    output = exact(runner_output, {"observation", "report"}, "file-access output")
    observation = canonical_file_access_observation(output["observation"])
    reader = "owner" if action_id == OWNER_ACTION else "non_owner"
    if observation["reader"] != reader:
        raise RunnerAdapterError("file-access result changed its reader")
    report = exact(output["report"], {"path", "sha256", "size"}, "file-access report")
    payload = canonical_json_bytes(observation)
    integer(report["size"], 1, MAX_REPORT_BYTES, "report size")
    if report != {
        "path": path,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
    }:
        raise RunnerAdapterError("file-access report does not encode its exact observation")
    if len(receipt_ids) != 1:
        raise RunnerAdapterError("file-access report requires exactly one attempt-local receipt")
    digest("sha256:" + receipt_ids[0], "report receipt")
    artifact = {
        "type": VERIFY_TYPE if action_id == OWNER_ACTION else PROBE_TYPE,
        **report,
        "observation": observation,
        "observation_digest": content_hash(observation),
        "request_hash": observation["request_hash"],
        "receipt_ids": list(receipt_ids),
    }
    if action_id == OWNER_ACTION:
        probe = bound_inputs["probe"]["observation"]
        if (
            any(
                observation[key] != probe[key]
                for key in (
                    "binding_digest",
                    "resource_id",
                    "resource_generation",
                    "control_revision",
                    "resource",
                    "mode",
                )
            )
            or observation["request_hash"] == probe["request_hash"]
            or observation["observed_at_ms"] < probe["observed_at_ms"]
        ):
            raise RunnerAdapterError("owner read differs from its preceding exact probe")
        artifact["probe_observation_digest"] = content_hash(probe)
        return {"verification": artifact}
    return {
        "probe": artifact,
        "workspace": {
            "type": "artifact.sandbox.workspace.v1",
            "root": "fixtures",
            "receipt_ids": list(receipt_ids),
        },
    }
