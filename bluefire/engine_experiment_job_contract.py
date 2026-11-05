"""Pure engine-attempt job envelopes and installed claim-policy contracts."""

from __future__ import annotations

import re
from typing import Any, Mapping

from .engine_attempt_contract import EngineAttemptBinding
from .engine_delegation import EngineCapabilityDelegation, EngineExecutionApprovalBinding
from .engine_experiment import EngineExperiment
from .util import content_hash

_EXECUTION_CLAIM_POLICY = {
    "schema_version": "bluefire.engine-execution-claim-policy.v1",
    "claim_protocol": "bluefire.engine-attempt-execution-claim.v1",
    "accepted_jobs_adapter": "bluefire.product-store-accepted-engine-jobs.v1",
}

_JOB_REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "experiment_id",
        "attempt_id",
        "binding_digest",
        "delegation_digest",
        "execution_approval_digest",
        "execution_approval_id",
    }
)


class EngineExperimentJobError(RuntimeError):
    """Raised when an engine job cannot retain its exact authority or state."""


def installed_execution_claim_policy() -> dict[str, str]:
    """Return the one exact immutable policy accepted by installed composition."""

    return dict(_EXECUTION_CLAIM_POLICY)


def _claim_policy(value: Any, *, allow_none: bool = True) -> dict[str, str] | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, Mapping) or dict(value) != _EXECUTION_CLAIM_POLICY:
        raise EngineExperimentJobError("engine execution claim policy changed")
    return dict(_EXECUTION_CLAIM_POLICY)


def _job_request(
    value: Mapping[str, Any], *, expected_policy: Mapping[str, Any] | None
) -> dict[str, Any]:
    parsed = dict(value)
    version = parsed.get("schema_version")
    fields = set(parsed)
    if version == "bluefire.engine-attempt-job.v1":
        if fields != _JOB_REQUEST_FIELDS or expected_policy is not None:
            raise EngineExperimentJobError("prepared engine request policy changed")
    elif version == "bluefire.engine-attempt-job.v2":
        if fields != _JOB_REQUEST_FIELDS | {"execution_claim_policy"}:
            raise EngineExperimentJobError("prepared engine request fields changed")
        policy = _claim_policy(parsed.get("execution_claim_policy"), allow_none=False)
        if expected_policy is None or policy != dict(expected_policy):
            raise EngineExperimentJobError("prepared engine request policy changed")
        parsed["execution_claim_policy"] = policy
    else:
        raise EngineExperimentJobError("prepared engine request version changed")
    for field, pattern in (
        ("experiment_id", r"experiment-[0-9a-f]{32}"),
        ("attempt_id", r"engine-attempt-[0-9a-f]{32}"),
        ("execution_approval_id", r"approval-[0-9a-f]{32}"),
        ("binding_digest", r"sha256:[0-9a-f]{64}"),
        ("delegation_digest", r"sha256:[0-9a-f]{64}"),
        ("execution_approval_digest", r"sha256:[0-9a-f]{64}"),
    ):
        if not isinstance(parsed[field], str) or re.fullmatch(pattern, parsed[field]) is None:
            raise EngineExperimentJobError("prepared engine request identity changed")
    return parsed


def engine_attempt_job_request(
    *,
    experiment: EngineExperiment,
    binding: EngineAttemptBinding,
    delegation: EngineCapabilityDelegation,
    approval: EngineExecutionApprovalBinding,
    approval_id: str,
    execution_claim_policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if binding.experiment_id != experiment.experiment_id:
        raise EngineExperimentJobError("engine binding belongs to another experiment")
    policy = _claim_policy(execution_claim_policy)
    request: dict[str, Any] = {
        "schema_version": (
            "bluefire.engine-attempt-job.v2"
            if policy is not None
            else "bluefire.engine-attempt-job.v1"
        ),
        "experiment_id": experiment.experiment_id,
        "attempt_id": binding.attempt_id,
        "binding_digest": binding.binding_digest,
        "delegation_digest": delegation.delegation_digest,
        "execution_approval_digest": content_hash(approval.to_dict()),
        "execution_approval_id": approval_id,
    }
    if policy is not None:
        request["execution_claim_policy"] = policy
    return request
