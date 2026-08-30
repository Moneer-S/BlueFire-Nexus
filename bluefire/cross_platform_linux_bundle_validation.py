"""Independent validation for fixed Linux product-run bundles."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable, Mapping, cast

from .cross_platform_process_proof import (
    ProcessProofError,
    validate_posix_watchdog_containment_proof,
)
from .run_store import RunStore

PRIMARY_SCENARIO_VARIANT = "primary"
REGISTERED_ALTERNATE_SCENARIO_VARIANT = "registered-alternate"
LINUX_SCENARIO_VARIANTS = (
    PRIMARY_SCENARIO_VARIANT,
    REGISTERED_ALTERNATE_SCENARIO_VARIANT,
)

_PRIMARY_PLAN_STEPS = (
    ("create_fixture", "sandbox.fixture.create.v1"),
    ("discover_system", "endpoint.discovery.system.v1"),
    ("discover_processes", "endpoint.discovery.processes.v1"),
    ("discover_files", "sandbox.discovery.recursive.v1"),
    ("archive_files", "sandbox.archive.tar.v1"),
    ("transform_fixture", "sandbox.fixture.transform.v1"),
    ("enumerate_fixture", "sandbox.discovery.list.v1"),
    ("stage_records", "sandbox.collection.stage.v1"),
    ("internal_transport", "sandbox.network.loopback.v1"),
    ("approved_fallback", "sandbox.export.local.v1"),
    ("cleanup_workspace", "sandbox.cleanup.v1"),
)
_PLAN_STEPS = {
    PRIMARY_SCENARIO_VARIANT: _PRIMARY_PLAN_STEPS,
    REGISTERED_ALTERNATE_SCENARIO_VARIANT: tuple(
        (
            (step_id, "sandbox.discovery.metadata.v1")
            if step_id == "enumerate_fixture"
            else (step_id, action_id)
        )
        for step_id, action_id in _PRIMARY_PLAN_STEPS
    ),
}
_EXECUTED_STEP_IDS = tuple(
    step_id for step_id, _action_id in _PRIMARY_PLAN_STEPS if step_id != "approved_fallback"
)
_RECEIPT_STEPS = frozenset(
    {"create_fixture", "archive_files", "transform_fixture", "stage_records"}
)
_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")

Require = Callable[[bool, str], None]


def validate_linux_bundle(
    source: Path,
    summary: Mapping[str, Any],
    *,
    scenario_variant: str,
    require: Require,
) -> Mapping[str, Any]:
    """Bind a canonical run to the selected fixed primary or alternate plan."""

    require(scenario_variant in LINUX_SCENARIO_VARIANTS, "invalid Linux scenario variant")
    try:
        validate_posix_watchdog_containment_proof(summary.get("watchdog_containment"))
    except ProcessProofError:
        require(False, "Linux watchdog containment proof is invalid")
        return {}
    run_id = summary.get("run_id")
    require(
        isinstance(run_id, str) and _RUN_ID.fullmatch(run_id) is not None,
        "invalid Linux run id",
    )
    run_id = cast(str, run_id)
    store = RunStore(source.parent)
    require(store.validate_bundle(run_id).get("valid") is True, "Linux run bundle is invalid")
    result = store.read_json(run_id, "result.json")
    plan = store.read_json(run_id, "plan.json")
    profile = store.read_json(run_id, "profile.json")
    policy = store.read_json(run_id, "policy.json")
    evidence = store.read_json(run_id, "evidence.json")
    steps = result.get("steps")
    readiness = policy.get("runner_readiness")
    identity = readiness.get("runner_identity") if isinstance(readiness, Mapping) else None
    plan_steps = plan.get("steps")
    observed_plan = (
        tuple((item.get("step_id"), item.get("action_id")) for item in plan_steps)
        if isinstance(plan_steps, list) and all(isinstance(item, Mapping) for item in plan_steps)
        else ()
    )
    observed_steps = (
        tuple(str(item.get("step_id")) for item in steps)
        if isinstance(steps, list) and all(isinstance(item, Mapping) for item in steps)
        else ()
    )
    receipt_rows = {
        str(item.get("step_id")): item.get("receipts")
        for item in steps or []
        if isinstance(item, Mapping)
    }
    network_step = next(
        (
            item
            for item in steps or []
            if isinstance(item, Mapping) and item.get("step_id") == "internal_transport"
        ),
        None,
    )
    network_artifacts = network_step.get("artifacts") if isinstance(network_step, Mapping) else None
    network_receipt = (
        network_artifacts.get("receipt") if isinstance(network_artifacts, Mapping) else None
    )
    network_details = (
        network_receipt.get("details") if isinstance(network_receipt, Mapping) else None
    )
    step_rows = cast(list[Mapping[str, Any]], steps)
    network_step_row = cast(Mapping[str, Any], network_step)
    receiver = summary.get("receiver")
    transfer = receiver.get("transfer") if isinstance(receiver, Mapping) else None
    runner_summary = summary.get("runner")
    require(
        result.get("mode") == "execute"
        and result.get("status") == "completed"
        and result.get("objective_reached") is True
        and isinstance(result.get("cleanup"), Mapping)
        and result["cleanup"].get("success") is True
        and result["cleanup"].get("outstanding_receipt_count") == 0
        and observed_plan == _PLAN_STEPS[scenario_variant]
        and observed_steps == _EXECUTED_STEP_IDS
        and all(item.get("status") in {"success", "partial"} for item in step_rows)
        and all(item.get("execution_disposition") == "execute" for item in step_rows)
        and all(
            isinstance(item.get("runner_task_id"), str)
            and re.fullmatch(r"execute-[0-9a-f]{64}", str(item["runner_task_id"])) is not None
            for item in step_rows
        )
        and all(
            isinstance(receipt_rows.get(step_id), list)
            and len(cast(list[Any], receipt_rows.get(step_id))) == 1
            for step_id in _RECEIPT_STEPS
        )
        and isinstance(profile.get("platforms"), list)
        and "linux" in profile["platforms"]
        and isinstance(readiness, Mapping)
        and readiness.get("platform") == "linux"
        and isinstance(identity, Mapping)
        and isinstance(runner_summary, Mapping)
        and identity.get("runner_id") == runner_summary.get("runner_id")
        and identity.get("runner_version") == runner_summary.get("runner_version")
        and identity.get("runner_binary_digest") == runner_summary.get("binary_sha256")
        and isinstance(network_details, Mapping)
        and isinstance(receiver, Mapping)
        and isinstance(transfer, Mapping)
        and receiver.get("process_distinct") is True
        and receiver.get("process_exited") is True
        and type(receiver.get("process_id")) is int
        and transfer.get("run_id") == run_id
        and transfer.get("step_id") == "internal_transport"
        and network_step_row.get("runner_task_id") == transfer.get("runner_task_id")
        and transfer.get("authenticated") is True
        and transfer.get("destination_process_id") == receiver.get("process_id")
        and network_details.get("sha256") == transfer.get("sha256")
        and network_details.get("bytes_sent") == transfer.get("bytes")
        and isinstance(evidence.get("records"), list)
        and len(evidence["records"]) >= len(step_rows),
        "Linux service bundle lacks genuine Execute evidence",
    )
    return {
        "run_id": run_id,
        "status": "completed",
        "objective_reached": True,
        "cleanup_success": True,
        "outstanding_receipt_count": 0,
        "step_count": len(step_rows),
    }


__all__ = [
    "LINUX_SCENARIO_VARIANTS",
    "PRIMARY_SCENARIO_VARIANT",
    "REGISTERED_ALTERNATE_SCENARIO_VARIANT",
    "validate_linux_bundle",
]
