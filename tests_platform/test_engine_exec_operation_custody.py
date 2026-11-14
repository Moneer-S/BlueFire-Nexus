from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from bluefire.engine_exec_operation_custody import (
    EngineExecOperationCustodyError,
    VerifiedExecLifetimeCustodyV2,
)
from bluefire.util import content_hash


def _digest(label: str) -> str:
    return content_hash(label)


def _proof() -> VerifiedExecLifetimeCustodyV2:
    return VerifiedExecLifetimeCustodyV2(
        admission_digest=_digest("admission"),
        attempt_id="engine-attempt-" + "1" * 32,
        operation_id="operation-" + "2" * 32,
        container_id="3" * 64,
        claim_ref=_digest("claim"),
        controller_fence=_digest("fence"),
        custody_plan_digest=_digest("custody"),
        network_policy_digest=_digest("network"),
        operation_deadline_monotonic_ns=3_000_000_000,
        controller_instance_ref=_digest("controller"),
        supervisor_instance_ref=_digest("supervisor"),
        lease_ref=_digest("lease"),
        lease_generation=1,
    )


def test_verified_lifetime_custody_is_canonical_and_hashes_every_field() -> None:
    proof = _proof()
    assert proof.proof_ref == content_hash(
        {
            "schema_version": "bluefire.verified-exec-lifetime-custody.v2",
            "admission_digest": proof.admission_digest,
            "attempt_id": proof.attempt_id,
            "operation_id": proof.operation_id,
            "container_id": proof.container_id,
            "claim_ref": proof.claim_ref,
            "controller_fence": proof.controller_fence,
            "custody_plan_digest": proof.custody_plan_digest,
            "network_policy_digest": proof.network_policy_digest,
            "operation_deadline_monotonic_ns": proof.operation_deadline_monotonic_ns,
            "controller_instance_ref": proof.controller_instance_ref,
            "supervisor_instance_ref": proof.supervisor_instance_ref,
            "lease_ref": proof.lease_ref,
            "lease_generation": 1,
            "deadline_stop_enforced": True,
            "controller_loss_stop_enforced": True,
        }
    )
    assert replace(proof, lease_generation=2).proof_ref != proof.proof_ref


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("admission_digest", "sha256:not-a-digest"),
        ("attempt_id", "engine-attempt-wrong"),
        ("operation_id", "operation-wrong"),
        ("container_id", "a" * 63),
        ("claim_ref", "sha256:" + "A" * 64),
        ("controller_fence", ""),
        ("custody_plan_digest", "sha256:" + "0" * 63),
        ("network_policy_digest", "sha256:" + "g" * 64),
        ("controller_instance_ref", object()),
        ("supervisor_instance_ref", None),
        ("lease_ref", "sha256:" + "1" * 65),
        ("operation_deadline_monotonic_ns", 0),
        ("operation_deadline_monotonic_ns", True),
        ("lease_generation", 0),
        ("lease_generation", True),
        ("deadline_stop_enforced", False),
        ("controller_loss_stop_enforced", False),
    ),
)
def test_verified_lifetime_custody_rejects_invalid_or_unenforced_values(
    field: str, value: Any
) -> None:
    with pytest.raises(EngineExecOperationCustodyError):
        replace(_proof(), **{field: value})
