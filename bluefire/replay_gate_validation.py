"""Independent persisted-evidence validation for GATE-06."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, cast

from .comparison import compare_runs
from .replay_checkpoint import (
    CheckpointError,
    checkpoint_for_step,
    validate_checkpoint,
    validate_restoration_plan,
)
from .replay_checkpoint_binding import (
    CheckpointBindingError,
    checkpoint_source_binding_hash,
)
from .replay_journey import (
    COMPARISON_REPORT,
    CORRUPTION_REPORT,
    CORRUPTION_SCHEMA,
    DEFENSE_CHANGE,
    DIMENSIONS,
    JOURNEY_REPORT,
    JOURNEY_SCHEMA,
    PARAMETER_STEP_ID,
    RESTART_STEP_ID,
    SWAP_ACTION_ID,
    SWAP_BEHAVIOR_ID,
    SWAP_STEP_ID,
    TARGET_SCOPE,
)
from .run_store import RunStore, RunStoreError
from .util import content_hash

_MAX_REPORT_BYTES = 8 * 1024 * 1024
CHECK_NAMES = frozenset(
    {
        "checkpoint_integrity",
        "materialized_state",
        "scope_cleanup_binding",
        "approval_regeneration",
        "corruption_refusal",
        "exact_replay",
        "node_restart",
        "parameter_override",
        "action_substitution",
        "autonomy_change",
        "profile_change",
        "defense_metadata",
        "comparison_dimensions",
    }
)


class ReplayGateValidationError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReplayGateValidationError(message)


def _read_json(path: Path) -> Mapping[str, Any]:
    _require(path.is_file() and not path.is_symlink(), "GATE-06 report is absent or unsafe")
    _require(path.stat().st_size <= _MAX_REPORT_BYTES, "GATE-06 report exceeds its byte bound")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReplayGateValidationError("GATE-06 report is invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise ReplayGateValidationError("GATE-06 report must be an object")
    return value


def _mapping(value: Any, message: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ReplayGateValidationError(message)
    return value


def _step(run: Mapping[str, Any], step_id: str) -> Mapping[str, Any]:
    rows = run.get("steps")
    matches = (
        [row for row in rows if isinstance(row, Mapping) and row.get("step_id") == step_id]
        if isinstance(rows, list)
        else []
    )
    _require(len(matches) == 1, "GATE-06 run step is absent or duplicated")
    return matches[0]


def _approval_id(run: Mapping[str, Any]) -> str:
    approval = _mapping(run.get("approval"), "GATE-06 approval is absent")
    approval_id = approval.get("approval_id")
    if (
        not isinstance(approval_id, str)
        or not approval_id.startswith("approval-")
        or approval.get("status") != "claimed"
        or not isinstance(approval.get("approved_by"), str)
    ):
        raise ReplayGateValidationError(
            "GATE-06 approval is not a claimed fresh candidate approval"
        )
    return approval_id


def _cleanup_complete(run: Mapping[str, Any]) -> bool:
    return run.get("cleanup") == {
        "attempted": True,
        "success": True,
        "outstanding_receipt_count": 0,
    }


def _checkpoint(source: Mapping[str, Any]) -> Mapping[str, Any]:
    inventory = source.get("replay_checkpoints")
    if not isinstance(inventory, list):
        raise ReplayGateValidationError("GATE-06 source checkpoint inventory is absent")
    scenario = source.get("scenario")
    plan = source.get("plan")
    policy = source.get("policy")
    approval_binding = policy.get("approval_binding") if isinstance(policy, Mapping) else None
    if not all(isinstance(value, Mapping) for value in (scenario, plan, approval_binding)):
        raise ReplayGateValidationError("GATE-06 source binding records are absent")
    try:
        source_binding_hash = checkpoint_source_binding_hash(
            source_run_id=str(source.get("run_id")),
            scenario=cast(Mapping[str, Any], scenario),
            plan=cast(Mapping[str, Any], plan),
            approval_binding=cast(Mapping[str, Any], approval_binding),
        )
        selected = checkpoint_for_step(inventory, RESTART_STEP_ID)
        return cast(
            Mapping[str, Any],
            validate_checkpoint(
                selected,
                expected_source_run_id=str(source.get("run_id")),
                expected_step_id=RESTART_STEP_ID,
                expected_source_binding_hash=source_binding_hash,
            ),
        )
    except (CheckpointBindingError, CheckpointError, KeyError, TypeError, ValueError) as exc:
        raise ReplayGateValidationError("GATE-06 source checkpoint failed validation") from exc


def _restoration(
    run: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
) -> Mapping[str, Any]:
    policy = _mapping(run.get("policy"), "GATE-06 candidate policy is absent")
    context = _mapping(
        policy.get("approval_context"),
        "GATE-06 candidate approval context is absent",
    )
    raw_plan = _mapping(
        context.get("restoration_plan"),
        "GATE-06 restoration plan is absent",
    )
    try:
        plan = validate_restoration_plan(raw_plan, checkpoint)
    except (CheckpointError, TypeError, ValueError) as exc:
        raise ReplayGateValidationError("GATE-06 restoration plan is invalid") from exc
    lineage = _mapping(run.get("replay"), "GATE-06 replay lineage is absent")
    report = _mapping(
        run.get("checkpoint_materialization"),
        "GATE-06 materialization report is absent",
    )
    _require(
        report.get("schema_version") == "bluefire.checkpoint-materialization.v1"
        and report.get("status") == "verified"
        and report.get("checkpoint_id") == checkpoint["checkpoint_id"]
        and report.get("manifest_hash") == checkpoint["manifest_hash"]
        and report.get("restoration_plan_hash") == plan["plan_hash"]
        and report.get("candidate_run_id") == run.get("run_id")
        and report.get("approval_id") == _approval_id(run)
        and report.get("fresh_receipt_count", 0) > 0
        and report.get("source_receipts_reused") is False
        and lineage.get("checkpoint_id") == checkpoint["checkpoint_id"]
        and lineage.get("checkpoint_manifest_hash") == checkpoint["manifest_hash"]
        and lineage.get("restoration_plan_hash") == plan["plan_hash"],
        "GATE-06 materialization is not bound to its checkpoint, plan, and approval",
    )
    rows = run.get("materialization_steps")
    prefix = checkpoint["executed_steps"]
    _require(
        isinstance(rows, list)
        and len(rows) == len(prefix) > 0
        and [row.get("step_id") for row in rows] == [row["step_id"] for row in prefix]
        and all(
            isinstance(row, Mapping)
            and row.get("materialization_phase") == "checkpoint_prefix_recreation"
            and row.get("checkpoint_id") == checkpoint["checkpoint_id"]
            and isinstance(row.get("runner_task_id"), str)
            and row.get("execution_disposition") == "execute"
            for row in rows
        ),
        "GATE-06 prefix was not recreated by real runner dispatches",
    )
    observed = report.get("artifacts")
    expected = checkpoint["material_files"]
    _require(
        isinstance(observed, list)
        and len(observed) == len(expected) > 0
        and all(
            isinstance(row, Mapping)
            and row.get("expected_sha256") == row.get("actual_sha256")
            and isinstance(row.get("evidence_id"), str)
            and any(
                row.get("relative_path") == material["relative_path"]
                and row.get("actual_sha256") == material["sha256"]
                and row.get("actual_size_bytes") == material["size_bytes"]
                for material in expected
            )
            for row in observed
        ),
        "GATE-06 restored material files do not match checkpoint hashes",
    )
    return cast(Mapping[str, Any], plan)


def _run_inventory(
    evidence_dir: Path,
    journey: Mapping[str, Any],
) -> tuple[RunStore, tuple[Mapping[str, str], ...], tuple[Mapping[str, Any], ...]]:
    _require(
        journey.get("schema_version") == JOURNEY_SCHEMA and journey.get("passed") is True,
        "GATE-06 journey report failed or has the wrong schema",
    )
    run_ids = journey.get("run_ids")
    bundles = journey.get("run_bundles")
    if (
        not isinstance(run_ids, list)
        or not all(isinstance(item, str) for item in run_ids)
        or len(run_ids) != len(set(run_ids))
        or len(run_ids) != 4
        or not all(item.startswith("run-") for item in run_ids)
        or not isinstance(bundles, list)
        or len(bundles) != 4
    ):
        raise ReplayGateValidationError("GATE-06 journey must bind exactly four unique runs")
    normalized: list[Mapping[str, str]] = []
    for run_id, raw in zip(run_ids, bundles, strict=True):
        _require(
            isinstance(raw, Mapping)
            and set(raw) == {"run_id", "path"}
            and raw.get("run_id") == run_id
            and raw.get("path") == f"runs/{run_id}",
            "GATE-06 run bundle reference is invalid",
        )
        assert isinstance(raw, Mapping)
        normalized.append({"run_id": run_id, "path": str(raw["path"])})
    roles = journey.get("roles")
    _require(
        roles
        == {
            "source": run_ids[0],
            "exact_restart": run_ids[1],
            "parameter_restart": run_ids[2],
            "combined_restart": run_ids[3],
        },
        "GATE-06 journey roles do not match its run order",
    )
    store = RunStore(evidence_dir / "runs")
    runs: list[Mapping[str, Any]] = []
    for run_id in run_ids:
        try:
            integrity = store.validate_bundle(run_id)
            _require(integrity.get("valid") is True, "GATE-06 run bundle integrity failed")
            run = store.get_run(run_id)
        except (OSError, RunStoreError, TypeError, ValueError) as exc:
            raise ReplayGateValidationError("GATE-06 run bundle is invalid") from exc
        _require(
            run.get("run_id") == run_id
            and run.get("mode") == "execute"
            and run.get("status") == "completed"
            and run.get("objective_reached") is True
            and _cleanup_complete(run),
            "GATE-06 run is not a completed cleanup-safe Execute bundle",
        )
        runs.append(run)
    return store, tuple(normalized), tuple(runs)


def _validate_corruption(report: Mapping[str, Any], source_run_id: str) -> None:
    _require(
        set(report) == {"schema_version", "passed", "source_run_id", "refusals"}
        and report.get("schema_version") == CORRUPTION_SCHEMA
        and report.get("passed") is True
        and report.get("source_run_id") == source_run_id,
        "GATE-06 corruption report is invalid",
    )
    refusals = report.get("refusals")
    _require(
        isinstance(refusals, Mapping)
        and set(refusals) == {"manifest_hash", "material_digest"}
        and all(
            isinstance(row, Mapping)
            and set(row)
            == {
                "refused",
                "error_code",
                "dispatch_count_before",
                "dispatch_count_after",
            }
            and row.get("refused") is True
            and row.get("error_code") == "replay_refused"
            and isinstance(row.get("dispatch_count_before"), int)
            and row.get("dispatch_count_before") == row.get("dispatch_count_after")
            for row in refusals.values()
        ),
        "GATE-06 corruption was not refused before runner dispatch",
    )


def _validate_comparison(
    persisted: Mapping[str, Any],
    store: RunStore,
    run_ids: list[str],
) -> None:
    try:
        expected = compare_runs(store, run_ids)
    except (RunStoreError, TypeError, ValueError) as exc:
        raise ReplayGateValidationError("GATE-06 comparison could not be reconstructed") from exc
    _require(persisted == expected, "GATE-06 comparison does not match canonical run bundles")
    summaries = persisted.get("summaries")
    deltas = persisted.get("deltas")
    _require(
        isinstance(summaries, list)
        and len(summaries) == 4
        and isinstance(deltas, list)
        and len(deltas) == 3
        and all(
            isinstance(row, Mapping) and set(row.get("dimensions", {})) == DIMENSIONS
            for row in summaries
        )
        and all(
            isinstance(row, Mapping) and set(row.get("dimensions", {})) == DIMENSIONS
            for row in deltas
        ),
        "GATE-06 comparison omits a required dimension",
    )


def validate_persisted_replay_gate(
    repository: Path,
    evidence_dir: Path,
) -> tuple[Mapping[str, bool], tuple[Mapping[str, str], ...]]:
    root = repository.resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    _require(
        root.is_dir()
        and (root / "pyproject.toml").is_file()
        and destination.is_dir()
        and not destination.is_symlink(),
        "GATE-06 validation roots are invalid",
    )
    journey = _read_json(destination / JOURNEY_REPORT)
    corruption = _read_json(destination / CORRUPTION_REPORT)
    comparison = _read_json(destination / COMPARISON_REPORT)
    store, bundles, runs = _run_inventory(destination, journey)
    source, exact, parameter, combined = runs
    checkpoint = _checkpoint(source)

    checkpoint_summary = journey.get("checkpoint")
    _require(
        checkpoint_summary
        == {
            "checkpoint_id": checkpoint["checkpoint_id"],
            "manifest_hash": checkpoint["manifest_hash"],
            "artifact_state_hash": checkpoint["artifact_state_hash"],
            "material_state_hash": checkpoint["material_state_hash"],
            "material_file_count": len(checkpoint["material_files"]),
            "prefix_step_ids": [row["step_id"] for row in checkpoint["executed_steps"]],
        }
        and journey.get("restart_step_id") == RESTART_STEP_ID,
        "GATE-06 journey checkpoint summary does not match its bundle",
    )
    source_authority = checkpoint["source_authority"]
    _require(
        source.get("runner_profile_id") == "sandbox-blocked-network.v1"
        and source.get("autonomy") == "off"
        and source.get("authorized_target_scope") == TARGET_SCOPE
        and source_authority["profile"]["profile_id"] == source.get("runner_profile_id")
        and source_authority["target_scope"]["scope_hash"]
        == content_hash({"scope_refs": sorted(TARGET_SCOPE["scope_refs"])})
        and source_authority["runner"]["platform"] == "windows"
        and checkpoint["source_cleanup"]["state"] == "completed"
        and checkpoint["source_cleanup"]["outstanding_receipt_count"] == 0
        and len(checkpoint["material_files"]) > 0
        and _step(source, "try_internal_transport").get("status") == "blocked",
        "GATE-06 source checkpoint lacks profile, scope, material, or cleanup authority",
    )

    plans = [_restoration(run, checkpoint) for run in runs[1:]]
    approval_ids = [_approval_id(run) for run in runs]
    _require(
        len(approval_ids) == len(set(approval_ids)) == 4
        and journey.get("approval_ids") == approval_ids
        and journey.get("materialization_receipt_hashes")
        == [run["checkpoint_materialization"]["receipt_hash"] for run in runs[1:]],
        "GATE-06 candidate approvals or materialization receipts are not fresh",
    )
    _require(
        all(run.get("authorized_target_scope") == TARGET_SCOPE for run in runs)
        and all(_cleanup_complete(run) for run in runs)
        and all(
            plan["target"]["scope_hash"] == source_authority["target_scope"]["scope_hash"]
            for plan in plans
        ),
        "GATE-06 restoration did not preserve scope and cleanup bindings",
    )

    exact_lineage = _mapping(exact.get("replay"), "GATE-06 exact lineage is absent")
    _require(
        exact_lineage.get("source_run_id") == source.get("run_id")
        and exact_lineage.get("exact") is True
        and exact_lineage.get("from_step_id") == RESTART_STEP_ID
        and plans[0]["variant_impact"]
        == {
            "parameter_steps": [],
            "behavior_steps": [],
            "action_steps": [],
            "autonomy_changed": False,
            "profile_changed": False,
            "defense_change_digest": None,
        },
        "GATE-06 exact restart is not exact",
    )
    parameter_lineage = _mapping(
        parameter.get("replay"),
        "GATE-06 parameter lineage is absent",
    )
    parameter_scenario = _mapping(parameter.get("scenario"), "GATE-06 parameter scenario is absent")
    parameter_steps = parameter_scenario.get("steps")
    changed_step = (
        next(
            (
                row
                for row in parameter_steps
                if isinstance(row, Mapping) and row.get("id") == PARAMETER_STEP_ID
            ),
            None,
        )
        if isinstance(parameter_steps, list)
        else None
    )
    _require(
        parameter_lineage.get("parameter_overrides")
        == {PARAMETER_STEP_ID: {"bundle_format": "json"}}
        and isinstance(changed_step, Mapping)
        and changed_step.get("parameters") == {"bundle_format": "json"}
        and plans[1]["variant_impact"]["parameter_steps"] == [PARAMETER_STEP_ID]
        and _step(parameter, PARAMETER_STEP_ID).get("artifacts", {}).get("bundle", {}).get("format")
        == "json",
        "GATE-06 typed downstream parameter override is invalid",
    )

    combined_lineage = _mapping(
        combined.get("replay"),
        "GATE-06 combined lineage is absent",
    )
    combined_impact = plans[2]["variant_impact"]
    _require(
        combined.get("runner_profile_id") == "sandbox-execute.v1"
        and combined.get("autonomy") == "auto"
        and combined_lineage.get("swap_step_id") == SWAP_STEP_ID
        and combined_lineage.get("swap_behavior_id") == SWAP_BEHAVIOR_ID
        and combined_lineage.get("action_implementation_overrides")
        == {SWAP_STEP_ID: SWAP_ACTION_ID}
        and combined_lineage.get("action_implementations_changed") is True
        and combined_lineage.get("ai_changed") is True
        and combined_lineage.get("autonomy_from") == "off"
        and combined_lineage.get("autonomy_to") == "auto"
        and combined_lineage.get("profile_changed") is True
        and combined_lineage.get("profile_from") == "sandbox-blocked-network.v1"
        and combined_lineage.get("profile_to") == "sandbox-execute.v1"
        and combined_lineage.get("defense_change") == DEFENSE_CHANGE
        and combined_lineage.get("defense_change_digest")
        == content_hash({"defense_change": DEFENSE_CHANGE})
        and combined_impact["behavior_steps"] == [SWAP_STEP_ID]
        and combined_impact["action_steps"] == [SWAP_STEP_ID]
        and combined_impact["autonomy_changed"] is True
        and combined_impact["profile_changed"] is True
        and combined_impact["defense_change_digest"]
        == content_hash({"defense_change": DEFENSE_CHANGE})
        and _step(combined, SWAP_STEP_ID).get("behavior_id") == SWAP_BEHAVIOR_ID
        and _step(combined, SWAP_STEP_ID).get("action_id") == SWAP_ACTION_ID,
        "GATE-06 combined action, autonomy, profile, or defense variant is invalid",
    )
    _validate_corruption(corruption, str(source["run_id"]))
    _validate_comparison(comparison, store, [str(run["run_id"]) for run in runs])

    report_checks = journey.get("checks")
    _require(
        isinstance(report_checks, Mapping)
        and set(report_checks) == CHECK_NAMES - {"corruption_refusal"}
        and all(value is True for value in report_checks.values()),
        "GATE-06 journey check inventory is invalid",
    )
    checks = {name: True for name in sorted(CHECK_NAMES)}
    return checks, bundles


__all__ = [
    "CHECK_NAMES",
    "ReplayGateValidationError",
    "validate_persisted_replay_gate",
]
