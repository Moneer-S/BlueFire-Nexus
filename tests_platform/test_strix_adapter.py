from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from bluefire.strix_adapter import (
    StrixAdapterError,
    StrixBudgets,
    StrixBuildIdentity,
    StrixModelGateway,
    StrixRuntimeLimits,
    StrixScope,
    build_launch_plan,
    discover_run_snapshot,
    prepare_attempt_workspace,
)
from bluefire.strix_policy_overlay import (
    OVERLAY_SHA256,
    PATCHED_PROMPT_SHA256,
    REVIEWED_PROMPT_SHA256,
    REVIEWED_SOURCE_REVISION,
)
from bluefire.util import file_hash

ATTEMPT_ID = "attempt-0123456789abcdef0123456789abcdef"
TARGET = "http://bluefire-lab:8080/app"
DIGEST = "sha256:" + "a" * 64


def _build(executable: Path) -> StrixBuildIdentity:
    return StrixBuildIdentity(
        source_revision=REVIEWED_SOURCE_REVISION,
        source_tree_sha256=DIGEST,
        package_sha256="sha256:" + "b" * 64,
        executable_sha256=file_hash(executable),
        image_reference="ghcr.io/usestrix/sandbox@sha256:" + "c" * 64,
        image_inventory_sha256="sha256:" + "d" * 64,
        prompt_upstream_sha256="sha256:" + REVIEWED_PROMPT_SHA256,
        prompt_overlay_sha256="sha256:" + OVERLAY_SHA256,
        prompt_patched_sha256="sha256:" + PATCHED_PROMPT_SHA256,
    )


def _scope() -> StrixScope:
    return StrixScope(
        target=TARGET,
        resolved_addresses=("172.18.0.7",),
        target_snapshot_digest=DIGEST,
        scope_digest="sha256:" + "e" * 64,
        network_policy_digest="sha256:" + "f" * 64,
        network_name="bf-strix-01234567",
    )


def _gateway() -> StrixModelGateway:
    return StrixModelGateway(
        model="controlled-test-provider",
        base_url="http://bluefire-model-gateway:8081/v1",
        authorization_digest="sha256:" + "1" * 64,
    )


def test_launch_plan_is_pinned_secret_free_and_idempotent(tmp_path: Path) -> None:
    executable = tmp_path / "strix"
    executable.write_bytes(b"reviewed executable")
    workspace_root = tmp_path / "attempts"
    workspace_root.mkdir()
    workspace = prepare_attempt_workspace(
        workspace_root,
        attempt_id=ATTEMPT_ID,
        objective="Assess the admitted lab authorization boundary.",
    )

    first = build_launch_plan(
        build=_build(executable),
        scope=_scope(),
        gateway=_gateway(),
        budgets=StrixBudgets(
            wall_seconds=900,
            max_turns_per_agent=20,
            max_model_cost_usd="5",
        ),
        limits=StrixRuntimeLimits(),
        workspace=workspace,
        executable=executable.resolve(),
        path_environment="/reviewed/bin",
    )
    second = build_launch_plan(
        build=_build(executable),
        scope=_scope(),
        gateway=_gateway(),
        budgets=StrixBudgets(900, 20, "5"),
        limits=StrixRuntimeLimits(),
        workspace=workspace,
        executable=executable.resolve(),
        path_environment="/reviewed/bin",
    )

    assert first == second
    assert first.intent_digest == second.intent_digest
    assert first.required_secret_environment == ("LLM_API_KEY",)
    environment = first.environment_dict()
    assert "LLM_API_KEY" not in environment
    assert environment["STRIX_API_TYPE"] == "chat_completions"
    assert environment["STRIX_RUN_ID"] == ATTEMPT_ID
    assert environment["STRIX_DOCKER_SANDBOX_NETWORK"] == "bf-strix-01234567"
    assert first.target == TARGET
    assert first.target_origin == "http://bluefire-lab:8080"
    assert first.resolved_addresses == ("172.18.0.7",)
    assert first.public_dict()["resolved_addresses"] == ["172.18.0.7"]
    assert first.argv == (
        str(executable.resolve()),
        "-n",
        "--target",
        TARGET,
        "--scan-mode",
        "quick",
        "--scope-mode",
        "full",
        "--instruction-file",
        str(workspace.objective_file),
        "--config",
        str(workspace.config_file),
        "--mcp-config",
        str(workspace.mcp_file),
        "--max-turns",
        "20",
        "--max-budget",
        "5",
        "--fail-on",
        "info",
    )
    assert json.loads(workspace.config_file.read_text(encoding="utf-8")) == {"env": {}}
    assert json.loads(workspace.mcp_file.read_text(encoding="utf-8")) == []


def test_workspace_is_exclusive_and_launch_refuses_changed_inputs(tmp_path: Path) -> None:
    root = tmp_path / "attempts"
    root.mkdir()
    workspace = prepare_attempt_workspace(root, attempt_id=ATTEMPT_ID, objective="Objective")
    with pytest.raises(StrixAdapterError, match="exclusively"):
        prepare_attempt_workspace(root, attempt_id=ATTEMPT_ID, objective="Objective")

    executable = tmp_path / "strix"
    executable.write_bytes(b"reviewed executable")
    workspace.objective_file.write_text("changed\n", encoding="utf-8")
    with pytest.raises(StrixAdapterError, match="objective changed"):
        build_launch_plan(
            build=_build(executable),
            scope=_scope(),
            gateway=_gateway(),
            budgets=StrixBudgets(900, 20, "5"),
            limits=StrixRuntimeLimits(),
            workspace=workspace,
            executable=executable.resolve(),
            path_environment="/reviewed/bin",
        )


def test_scope_addresses_are_part_of_launch_intent(tmp_path: Path) -> None:
    executable = tmp_path / "strix"
    executable.write_bytes(b"reviewed executable")
    root = tmp_path / "attempts"
    root.mkdir()
    workspace = prepare_attempt_workspace(root, attempt_id=ATTEMPT_ID, objective="Objective")
    first_scope = _scope()
    second_scope = StrixScope(
        target=TARGET,
        resolved_addresses=("172.18.0.8",),
        target_snapshot_digest=first_scope.target_snapshot_digest,
        scope_digest=first_scope.scope_digest,
        network_policy_digest=first_scope.network_policy_digest,
        network_name=first_scope.network_name,
    )
    common = {
        "build": _build(executable),
        "gateway": _gateway(),
        "budgets": StrixBudgets(900, 20, "5"),
        "limits": StrixRuntimeLimits(),
        "workspace": workspace,
        "executable": executable.resolve(),
        "path_environment": "/reviewed/bin",
    }

    first = build_launch_plan(scope=first_scope, **common)
    second = build_launch_plan(scope=second_scope, **common)

    assert first.resolved_addresses != second.resolved_addresses
    assert first.intent_digest != second.intent_digest


def test_workspace_refuses_fixed_child_symlink(tmp_path: Path) -> None:
    root = tmp_path / "attempts"
    root.mkdir()
    workspace = prepare_attempt_workspace(root, attempt_id=ATTEMPT_ID, objective="Objective")
    original = workspace.config_file.with_suffix(".original")
    try:
        workspace.config_file.replace(original)
        workspace.config_file.symlink_to(original)
    except OSError:
        pytest.skip("symlink fixture creation is unavailable on this host")
    with pytest.raises(StrixAdapterError, match="fixed workspace path"):
        build_launch_plan(
            build=StrixBuildIdentity(
                source_revision=REVIEWED_SOURCE_REVISION,
                source_tree_sha256=DIGEST,
                package_sha256="sha256:" + "b" * 64,
                executable_sha256="sha256:" + "2" * 64,
                image_reference="ghcr.io/usestrix/sandbox@sha256:" + "c" * 64,
                image_inventory_sha256="sha256:" + "d" * 64,
                prompt_upstream_sha256="sha256:" + REVIEWED_PROMPT_SHA256,
                prompt_overlay_sha256="sha256:" + OVERLAY_SHA256,
                prompt_patched_sha256="sha256:" + PATCHED_PROMPT_SHA256,
            ),
            scope=_scope(),
            gateway=_gateway(),
            budgets=StrixBudgets(900, 20, "5"),
            limits=StrixRuntimeLimits(),
            workspace=workspace,
            executable=(tmp_path / "missing").resolve(),
            path_environment="/reviewed/bin",
        )


def test_workspace_refuses_alternate_contained_config_path(tmp_path: Path) -> None:
    root = tmp_path / "attempts"
    root.mkdir()
    workspace = prepare_attempt_workspace(root, attempt_id=ATTEMPT_ID, objective="Objective")
    alternate = workspace.cwd / "alternate-config.json"
    alternate.write_text('{"env":{}}', encoding="utf-8")

    with pytest.raises(StrixAdapterError, match="fixed workspace path"):
        build_launch_plan(
            build=StrixBuildIdentity(
                source_revision=REVIEWED_SOURCE_REVISION,
                source_tree_sha256=DIGEST,
                package_sha256="sha256:" + "b" * 64,
                executable_sha256="sha256:" + "2" * 64,
                image_reference="ghcr.io/usestrix/sandbox@sha256:" + "c" * 64,
                image_inventory_sha256="sha256:" + "d" * 64,
                prompt_upstream_sha256="sha256:" + REVIEWED_PROMPT_SHA256,
                prompt_overlay_sha256="sha256:" + OVERLAY_SHA256,
                prompt_patched_sha256="sha256:" + PATCHED_PROMPT_SHA256,
            ),
            scope=_scope(),
            gateway=_gateway(),
            budgets=StrixBudgets(900, 20, "5"),
            limits=StrixRuntimeLimits(),
            workspace=replace(workspace, config_file=alternate),
            executable=(tmp_path / "missing").resolve(),
            path_environment="/reviewed/bin",
        )


def test_workspace_binds_attempt_identity_to_directory(tmp_path: Path) -> None:
    root = tmp_path / "attempts"
    root.mkdir()
    workspace = prepare_attempt_workspace(root, attempt_id=ATTEMPT_ID, objective="Objective")
    executable = tmp_path / "strix"
    executable.write_bytes(b"reviewed executable")

    with pytest.raises(StrixAdapterError, match="does not match its workspace"):
        build_launch_plan(
            build=_build(executable),
            scope=_scope(),
            gateway=_gateway(),
            budgets=StrixBudgets(900, 20, "5"),
            limits=StrixRuntimeLimits(),
            workspace=replace(
                workspace,
                attempt_id="attempt-ffffffffffffffffffffffffffffffff",
            ),
            executable=executable.resolve(),
            path_environment="/reviewed/bin",
        )


@pytest.mark.parametrize(
    "target,address",
    [
        ("https://example.com", "93.184.216.34"),
        ("http://bluefire-lab:8080?wide=true", "172.18.0.7"),
        ("http://bluefire-lab:8080", "169.254.169.254"),
    ],
)
def test_scope_refuses_global_ambiguous_or_link_local_targets(target: str, address: str) -> None:
    with pytest.raises(StrixAdapterError):
        StrixScope(target, (address,), DIGEST, DIGEST, DIGEST, "bf-strix-test")


def test_scope_requires_canonical_address_order() -> None:
    with pytest.raises(StrixAdapterError, match="canonical sorted order"):
        StrixScope(
            TARGET,
            ("172.18.0.8", "172.18.0.7"),
            DIGEST,
            DIGEST,
            DIGEST,
            "bf-strix-test",
        )

    scope = StrixScope(
        TARGET,
        ("172.18.0.7", "172.18.0.8"),
        DIGEST,
        DIGEST,
        DIGEST,
        "bf-strix-test",
    )
    assert scope.resolved_addresses == ("172.18.0.7", "172.18.0.8")


def _write_run(
    cwd: Path,
    *,
    status: str,
    objective: str,
    complete: bool | None,
    exit_reason: str | None = None,
) -> Path:
    run_dir = cwd / "strix_runs" / "upstream-run-1"
    run_dir.mkdir(parents=True)
    run = {
        "run_id": "upstream-run-1",
        "run_name": "upstream-run-1",
        "status": status,
        "non_interactive": True,
        "scan_mode": "quick",
        "scope_mode": "full",
        "targets_info": [
            {
                "type": "web_application",
                "details": {"target_url": TARGET},
                "original": TARGET,
            }
        ],
        "instruction": objective,
    }
    (run_dir / "run.json").write_text(json.dumps(run), encoding="utf-8")
    if complete is not None:
        coverage = {
            "run_id": "upstream-run-1",
            "run_name": "upstream-run-1",
            "completeness": {
                "complete": complete,
                "scan_status": status,
                "exit_reason": exit_reason,
                "caveats": [] if complete else ["Run ended before all planned work."],
            },
        }
        (run_dir / "coverage.json").write_text(json.dumps(coverage), encoding="utf-8")
    return run_dir


def _objective_digest(objective: str) -> str:
    return "sha256:" + hashlib.sha256(objective.strip().encode("utf-8") + b"\n").hexdigest()


def test_exit_two_is_findings_not_failure_and_completion_needs_coverage(tmp_path: Path) -> None:
    objective = "Assess only the admitted lab."
    _write_run(
        tmp_path, status="completed", objective=objective, complete=True, exit_reason="completed"
    )

    snapshot = discover_run_snapshot(
        tmp_path,
        expected_target=TARGET,
        expected_instruction_sha256=_objective_digest(objective),
        process_exit_code=2,
    )

    assert snapshot.attempt_state == "completed"
    assert snapshot.completeness == "complete"
    assert snapshot.process_classification == "findings_threshold"
    assert snapshot.engine_reported_findings is True
    assert snapshot.security_outcome == "not_independently_established"


def test_zero_exit_stopped_run_is_partial_and_missing_coverage_is_unknown(tmp_path: Path) -> None:
    objective = "Assess only the admitted lab."
    _write_run(tmp_path, status="stopped", objective=objective, complete=None)

    snapshot = discover_run_snapshot(
        tmp_path,
        expected_target=TARGET,
        expected_instruction_sha256=_objective_digest(objective),
        process_exit_code=0,
    )

    assert snapshot.attempt_state == "partial"
    assert snapshot.completeness == "partial"
    assert snapshot.process_classification == "zero_exit"
    assert snapshot.engine_reported_findings is None
    assert snapshot.coverage_sha256 is None
    assert snapshot.caveats == ("Strix coverage artifact is unavailable.",)


def test_budget_and_cancel_are_distinct_terminal_states(tmp_path: Path) -> None:
    objective = "Assess only the admitted lab."
    budget_dir = tmp_path / "budget"
    cancel_dir = tmp_path / "cancel"
    budget_dir.mkdir()
    cancel_dir.mkdir()
    _write_run(
        budget_dir,
        status="stopped",
        objective=objective,
        complete=False,
        exit_reason="budget_exceeded",
    )
    _write_run(cancel_dir, status="interrupted", objective=objective, complete=False)

    budget = discover_run_snapshot(
        budget_dir,
        expected_target=TARGET,
        expected_instruction_sha256=_objective_digest(objective),
        process_exit_code=0,
    )
    cancelled = discover_run_snapshot(
        cancel_dir,
        expected_target=TARGET,
        expected_instruction_sha256=_objective_digest(objective),
        process_exit_code=1,
        cancellation_requested=True,
        cessation_verified=True,
    )

    assert budget.attempt_state == "budget_exhausted"
    assert cancelled.attempt_state == "cancelled"


def test_cancel_requires_verified_cessation_and_exited_running_state_is_inconsistent(
    tmp_path: Path,
) -> None:
    objective = "Assess only the admitted lab."
    cancel_dir = tmp_path / "cancel"
    running_dir = tmp_path / "running"
    cancel_dir.mkdir()
    running_dir.mkdir()
    _write_run(cancel_dir, status="interrupted", objective=objective, complete=False)
    _write_run(running_dir, status="running", objective=objective, complete=None)

    unverified = discover_run_snapshot(
        cancel_dir,
        expected_target=TARGET,
        expected_instruction_sha256=_objective_digest(objective),
        process_exit_code=1,
        cancellation_requested=True,
        cessation_verified=False,
    )
    inconsistent = discover_run_snapshot(
        running_dir,
        expected_target=TARGET,
        expected_instruction_sha256=_objective_digest(objective),
        process_exit_code=0,
    )

    assert unverified.attempt_state == "partial"
    assert any("cessation is unverified" in item for item in unverified.caveats)
    assert inconsistent.attempt_state == "unknown"
    assert any("process exited" in item for item in inconsistent.caveats)


def test_run_discovery_refuses_multiple_runs_target_drift_and_duplicate_json(
    tmp_path: Path,
) -> None:
    objective = "Assess only the admitted lab."
    run_dir = _write_run(tmp_path, status="completed", objective=objective, complete=True)
    second = tmp_path / "strix_runs" / "second"
    second.mkdir()
    with pytest.raises(StrixAdapterError, match="exactly one"):
        discover_run_snapshot(
            tmp_path,
            expected_target=TARGET,
            expected_instruction_sha256=_objective_digest(objective),
            process_exit_code=0,
        )
    second.rmdir()

    record = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    record["targets_info"][0]["original"] = "http://bluefire-lab:8080/other"
    (run_dir / "run.json").write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(StrixAdapterError, match="admitted attempt"):
        discover_run_snapshot(
            tmp_path,
            expected_target=TARGET,
            expected_instruction_sha256=_objective_digest(objective),
            process_exit_code=0,
        )

    (run_dir / "run.json").write_text('{"run_id":"one","run_id":"two"}', encoding="utf-8")
    with pytest.raises(StrixAdapterError, match="repeats a JSON key"):
        discover_run_snapshot(
            tmp_path,
            expected_target=TARGET,
            expected_instruction_sha256=_objective_digest(objective),
            process_exit_code=0,
        )
