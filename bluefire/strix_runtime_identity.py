"""Effect-free identity plumbing shared by the installed Strix runtime.

Keep version fences and V2 settlement hashing outside the runtime coordinator.
No helper resolves authority, acquires credentials, or performs worker effects.
"""

from __future__ import annotations

from typing import Any, Mapping

from .engine_attempt_contract import EngineAttemptBinding
from .engine_container_custody import ContainerCustodyPlanV2
from .engine_delegation import EngineCapabilityDelegation
from .engine_experiment import CleanupState
from .engine_network_policy import EngineNetworkPlanV2
from .engine_worker_runtime import EngineWorkerOutcome
from .util import content_hash


def _require_legacy_runtime_identity(
    admission: Any, admission_type: type[Any], error_type: type[RuntimeError]
) -> None:
    """Fence legacy collaborators from controlled material without qualifying them.

    The legacy runtime supplies its exact admission and error classes to avoid
    an application import cycle. Schema-less protected collaborators retain
    their behavior; declared proof schemas must remain the exact V1 schemas.
    """
    if (
        type(admission) is not admission_type
        or isinstance(admission.network_plan, EngineNetworkPlanV2)
        or isinstance(admission.custody_plan, ContainerCustodyPlanV2)
    ):
        raise error_type("legacy Strix admission contains a different version")
    for name, expected in (
        ("network_plan", "bluefire.engine-network-plan.v1"),
        ("network_snapshot", "bluefire.engine-network-snapshot.v1"),
        ("network_verification", "bluefire.engine-network-verification.v1"),
        ("custody_plan", "bluefire.engine-container-custody.v1"),
        ("protected_roots", "bluefire.engine-protected-runtime-roots.v1"),
        ("containment", "bluefire.engine-process-containment.v1"),
    ):
        proof = getattr(admission, name)
        document = proof.to_dict()
        if (
            not isinstance(document, Mapping)
            or document.get("schema_version", expected) != expected
            or getattr(proof, "schema_version", expected) != expected
        ):
            raise error_type("legacy Strix admission proof version changed")


def _v2_cleanup_receipt(
    binding: EngineAttemptBinding,
    delegation: EngineCapabilityDelegation,
    launch_digest: str,
    resolution_ref: str,
    claim_ref: str,
    outcome: EngineWorkerOutcome,
    revocation_ref: str | None,
    publication_seal_ref: str | None,
    manifest_ref: str | None,
    cleanup_state: CleanupState,
) -> str:
    return content_hash(
        {
            "schema_version": "bluefire.strix-runtime-settlement.v2",
            "binding_digest": binding.binding_digest,
            "delegation_digest": delegation.delegation_digest,
            "launch_digest": launch_digest,
            "runtime_resolution_ref": resolution_ref,
            "execution_claim_ref": claim_ref,
            "worker_outcome_digest": content_hash(outcome.to_dict()),
            "gateway_revocation_ref": revocation_ref,
            "artifact_publication_seal_ref": publication_seal_ref,
            "artifact_manifest_ref": manifest_ref,
            "cleanup_state": cleanup_state.value,
        }
    )
