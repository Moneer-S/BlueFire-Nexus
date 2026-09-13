"""Cross-bind the live recovery witness to the persisted Gate 11 report."""

from __future__ import annotations

import time
from typing import Any, Mapping

from .cross_platform_recovery_witness import (
    RecoveryWitnessError,
    process_identity_running,
    validate_witness_validation,
)

ABSENCE_PROBES = [
    {"delay_ms": delay, "parent_running": False, "descendant_running": False}
    for delay in (0, 100, 250)
]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RecoveryWitnessError(message)


def validate_recovery_witness_binding(
    witness: Any,
    recovery: Mapping[str, Any],
    transport: Mapping[str, Any],
) -> None:
    """Validate the witness, then bind every shared identity and effect fact."""

    validate_witness_validation(witness)
    _require(isinstance(witness, Mapping), "recovery witness is not an object")
    stages = witness["stages"]
    identities = witness["os_process_identities"]
    before = stages["before_interruption"]
    recovered = stages["after_recovery"]
    cleaned = stages["after_cleanup"]
    stopped = stages["after_recovered_host_stop"]
    continued = stages["continuation"]
    host_before = recovery["host_identity_before"]
    host_after = recovery["host_identity_after"]
    _require(
        identities["client"]["process_id"] == transport.get("client_process_id")
        and identities["host_before"]["process_id"] == host_before.get("process_id")
        and identities["host_after"]["process_id"] == host_after.get("process_id")
        and before["ledger_generation"] == recovery.get("ledger_generation_before")
        and recovered["ledger_generation"] == recovery.get("ledger_generation_after")
        and before["result_digest"] == recovery.get("result_digest_before")
        and recovered["result_digest"] == recovery.get("result_digest_after")
        and before["receipt_body_digest"] == recovery.get("receipt_body_digest_before")
        and recovered["receipt_body_digest"] == recovery.get("receipt_body_digest_after")
        and before["receipt_commit_digest"] == recovery.get("receipt_commit_digest_before")
        and recovered["receipt_commit_digest"] == recovery.get("receipt_commit_digest_after")
        and before["effect_digest"] == recovery.get("effect_digest_before")
        and recovered["effect_digest"] == recovery.get("effect_digest_after")
        and before["effect_size"] == recovery.get("effect_size_before")
        and recovered["effect_size"] == recovery.get("effect_size_after")
        and before["effect_count"] == recovery.get("effect_count_before")
        and recovered["effect_count"] == recovery.get("effect_count_after")
        and cleaned["cleanup_result_digest"] == recovery.get("cleanup_result_digest")
        and cleaned["effect_exists"] == recovery.get("effect_exists_after_cleanup")
        and cleaned["effect_directory_exists"]
        == recovery.get("effect_directory_exists_after_cleanup")
        and cleaned["receipt_count"] == len(recovery.get("receipt_ids_after_cleanup", []))
        and cleaned["receipt_commit_count"]
        == len(recovery.get("receipt_commit_ids_after_cleanup", []))
        and stopped["host_before_absent"] is recovery.get("interruption", {}).get("process_absent")
        and continued["result_digest"] == recovery.get("result_digest_after"),
        "recovery live witness is not bound to the persisted recovery proof",
    )


def process_identities_absent(
    parent: Mapping[str, Any],
    descendant: Mapping[str, Any],
) -> bool:
    """Re-probe both exact Windows creation identities at fixed intervals."""

    try:
        for delay_seconds in (0.0, 0.1, 0.25):
            if delay_seconds:
                time.sleep(delay_seconds)
            if process_identity_running(parent) or process_identity_running(descendant):
                return False
    except RecoveryWitnessError:
        return False
    return True


__all__ = ["ABSENCE_PROBES", "process_identities_absent", "validate_recovery_witness_binding"]
