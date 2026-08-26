from __future__ import annotations

import copy
import json
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire.approvals import execution_approval_binding
from bluefire.config import AutonomyLevel, RunnerProfile, load_config
from bluefire.contracts import ExecutionMode, load_scenario
from bluefire.orchestrator import OrchestrationError, Orchestrator
from bluefire.product_store import ProductStore
from bluefire.registry import load_builtin_registry
from bluefire.replay import ReplayRequest, prepare_replay
from bluefire.run_store import RunStore
from bluefire.runner_client import RunnerTransportError

ROOT = Path(__file__).resolve().parents[1]
SCENARIO_PATH = ROOT / "scenarios" / "sandbox_research_chain.yaml"
ACTION_IDS = {
    "sandbox.fixture.create.v1",
    "sandbox.fixture.transform.v1",
    "sandbox.discovery.list.v1",
    "sandbox.discovery.metadata.v1",
    "sandbox.collection.stage.v1",
    "sandbox.network.loopback.v1",
    "sandbox.export.local.v1",
    "sandbox.cleanup.v1",
}
RECEIPT_IDS = {
    "sandbox.fixture.create.v1": "a" * 64,
    "sandbox.fixture.transform.v1": "b" * 64,
    "sandbox.collection.stage.v1": "c" * 64,
    "sandbox.export.local.v1": "d" * 64,
}
FULL_TARGET_SCOPE = {"scope_refs": ["sandbox.workspace", "network.loopback", "export.local"]}


def _execute_profile() -> RunnerProfile:
    config = load_config(ROOT / "config" / "bluefire.example.yaml")
    return next(
        profile for profile in config.runner_profiles if profile.mode is ExecutionMode.EXECUTE
    )


class StructuredFakeRunner:
    def __init__(self, *, network_status: str = "success") -> None:
        self.network_status = network_status
        self.inventory_calls = 0
        self.calls: list[tuple[dict[str, Any], dict[str, Any]]] = []

    def inventory(self) -> Mapping[str, Any]:
        self.inventory_calls += 1
        return {
            "schema_version": "bluefire.runner-inventory.v1",
            "actions": [{"action_id": action_id} for action_id in sorted(ACTION_IDS)],
        }

    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        manifest_copy = copy.deepcopy(dict(manifest))
        profile_copy = copy.deepcopy(dict(profile))
        self.calls.append((manifest_copy, profile_copy))
        action_id = str(manifest["action_id"])
        status = self.network_status if action_id == "sandbox.network.loopback.v1" else "success"
        output = {
            "sandbox.fixture.create.v1": {
                "artifact": "fixtures/input.txt",
                "sha256": "sha256:create",
            },
            "sandbox.fixture.transform.v1": {
                "artifact": "fixtures/transformed.txt",
                "sha256": "sha256:transform",
            },
            "sandbox.discovery.list.v1": {"entries": ["fixtures/transformed.txt"]},
            "sandbox.discovery.metadata.v1": {"size_bytes": 16},
            "sandbox.collection.stage.v1": {
                "staged": [
                    {
                        "artifact": "staged/000-transformed.txt",
                        "sha256": "sha256:stage",
                    }
                ]
            },
            "sandbox.network.loopback.v1": {"bytes_sent": 16},
            "sandbox.export.local.v1": {
                "artifact": "exports/bundle.bin",
                "sha256": "sha256:export",
            },
            "sandbox.cleanup.v1": {
                "removed_receipts": list(manifest["params"].get("receipt_ids", []))
            },
        }[action_id]
        receipts = [RECEIPT_IDS[action_id]] if action_id in RECEIPT_IDS else []
        error = None
        if status != "success":
            error = {"code": f"fake_{status}", "message": f"structured {status} result"}
        return {
            "schema_version": "bluefire.runner-result.v1",
            "request_id": manifest["request_id"],
            "run_id": manifest["run_id"],
            "step_id": manifest["step_id"],
            "behavior_id": manifest["behavior_id"],
            "action_id": action_id,
            "runner_id": manifest["runner_id"],
            "runner_profile_id": manifest["runner_profile_id"],
            "request_hash": manifest["request_hash"],
            "policy_digest": profile["policy_digest"],
            "platform": profile["platform"],
            "status": status,
            "output": output,
            "stdout": {"bytes": 0, "truncated": False},
            "stderr": {"bytes": 0, "truncated": False},
            "evidence": [{"kind": "fake-runner", "status": status}],
            "receipt_ids": receipts,
            "cleanup": (
                {
                    "requested_receipts": len(manifest["params"].get("receipt_ids", [])),
                    "removed_paths": list(manifest["params"].get("receipt_ids", [])),
                    "already_absent_receipts": [],
                    "retained_paths": [],
                    "errors": [],
                }
                if action_id == "sandbox.cleanup.v1"
                else None
            ),
            "error": error,
            "limitations": ["Structured local fake; no runner side effect occurred."],
        }


class SlowFirstRunner(StructuredFakeRunner):
    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        if not self.calls:
            time.sleep(0.8)
        return super().execute(manifest, profile)


class RunnerMustNotBeCalled:
    def __init__(self) -> None:
        self.calls = 0

    def inventory(self) -> Mapping[str, Any]:
        self.calls += 1
        raise AssertionError("Simulate must not inspect runner inventory")

    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        self.calls += 1
        raise AssertionError("Simulate must not dispatch a runner action")


@pytest.mark.parametrize(
    ("field", "forged"),
    [
        ("request_id", "request-forged"),
        ("runner_id", "runner-forged.v1"),
        ("runner_profile_id", "profile-forged.v1"),
        ("platform", "linux" if _execute_profile().platforms[0] != "linux" else "windows"),
    ],
)
def test_runner_result_identity_is_bound_to_the_exact_request(
    field: str,
    forged: str,
) -> None:
    manifest = {
        "request_id": "request-exact",
        "run_id": "run-exact",
        "step_id": "step-exact",
        "behavior_id": "behavior.exact.v1",
        "action_id": "action.exact.v1",
        "runner_id": "runner.exact.v1",
        "runner_profile_id": "profile.exact.v1",
        "request_hash": "sha256:" + "a" * 64,
    }
    profile = {
        "platform": "windows",
        "policy_digest": "sha256:" + "b" * 64,
    }
    result = {
        "schema_version": "bluefire.runner-result.v1",
        **manifest,
        "platform": profile["platform"],
        "policy_digest": profile["policy_digest"],
    }
    result[field] = forged

    with pytest.raises(RunnerTransportError, match=field):
        Orchestrator._validate_runner_result(manifest, profile, result)


class FailAfterFirstEffectStore(RunStore):
    def append_event(self, run_id: str, event_type: str, data: Mapping[str, Any]) -> None:
        if event_type == "step.completed" and data.get("action_id") == "sandbox.fixture.create.v1":
            raise RuntimeError("injected event-store failure")
        super().append_event(run_id, event_type, data)


class IncompleteCleanupFakeRunner(StructuredFakeRunner):
    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        result = dict(super().execute(manifest, profile))
        if manifest["action_id"] == "sandbox.cleanup.v1":
            result["cleanup"] = {
                "requested_receipts": 0,
                "removed_paths": [],
                "already_absent_receipts": [],
                "retained_paths": [],
                "errors": [],
            }
        return result


class ReceiptThenTransportFailureRunner(StructuredFakeRunner):
    RECEIPT_ID = "e" * 64

    def __init__(self) -> None:
        super().__init__()
        self.failed_once = False

    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        action_id = str(manifest["action_id"])
        receipt_root = Path(str(profile["sandbox_root"])) / ".bluefire" / "receipts"
        if action_id != "sandbox.cleanup.v1" and not self.failed_once:
            self.failed_once = True
            self.calls.append((copy.deepcopy(dict(manifest)), copy.deepcopy(dict(profile))))
            receipt_root.mkdir(parents=True)
            receipt = {
                "schema_version": "bluefire.receipt/v1",
                "receipt_id": self.RECEIPT_ID,
                "request_hash": manifest["request_hash"],
                "action_id": action_id,
                "runner_profile_id": profile["profile_id"],
                "created_at": "2026-08-24T00:00:00Z",
                "paths": [],
            }
            (receipt_root / f"{self.RECEIPT_ID}.json").write_text(
                json.dumps(receipt),
                encoding="utf-8",
            )
            raise RunnerTransportError("injected result transport failure")
        if action_id == "sandbox.cleanup.v1":
            for receipt_id in manifest["params"]["receipt_ids"]:
                (receipt_root / f"{receipt_id}.json").unlink(missing_ok=True)
        return super().execute(manifest, profile)


def _orchestrator(tmp_path: Path, runner: object) -> Orchestrator:
    return Orchestrator(
        load_builtin_registry(),
        RunStore(tmp_path / "runs"),
        runner=runner,  # type: ignore[arg-type]
        approval_store=ProductStore(tmp_path / "product.sqlite3"),
    )


def _approval_kwargs(
    orchestrator: Orchestrator,
    *,
    scenario: Any,
    profile: RunnerProfile,
    target_scope: Mapping[str, Any],
    approved_by: str = "operator@example.test",
    action_implementations: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    approval_store = orchestrator.approval_store
    assert isinstance(approval_store, ProductStore)
    plan = orchestrator.planner.compile(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        autonomy=AutonomyLevel.OFF,
        action_implementations=action_implementations,
    )
    binding = execution_approval_binding(
        registry=orchestrator.registry,
        scenario=scenario,
        plan=plan.to_dict(),
        profile=profile,
        target_scope=target_scope,
        autonomy=plan.autonomy,
        ai_provider=plan.ai_provider,
    )
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
    pending = approval_store.create_approval_request(
        run_id="test-execution-intent",
        state_digest=binding["state_digest"],
        plan_digest=binding["plan_digest"],
        profile_id=binding["profile_id"],
        target_scope_digest=binding["target_scope_digest"],
        maximum_tier=binding["maximum_tier"],
        expires_at=expires_at,
    )
    approved = approval_store.approve(
        str(pending["approval_id"]),
        approved_by=approved_by,
        expected_state_digest=binding["state_digest"],
        expected_plan_digest=binding["plan_digest"],
        expected_target_scope_digest=binding["target_scope_digest"],
    )
    consumed = approval_store.consume_approval(
        str(approved["approval_id"]),
        nonce=str(approved["nonce"]),
        expected_state_digest=binding["state_digest"],
        expected_plan_digest=binding["plan_digest"],
        expected_target_scope_digest=binding["target_scope_digest"],
    )
    return {"approved_by": approved_by, "approval_record": consumed}


def test_action_implementation_choices_are_execute_only_and_profile_bound(
    tmp_path: Path,
) -> None:
    orchestrator = _orchestrator(tmp_path, StructuredFakeRunner())
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()

    with pytest.raises(OrchestrationError, match="Simulate does not accept"):
        orchestrator.preflight(
            scenario,
            mode=ExecutionMode.SIMULATE,
            action_implementations={"create_fixture": "sandbox.fixture.create.v1"},
        )

    selected = orchestrator.preflight(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        approval_present=True,
        action_implementations={"create_fixture": "sandbox.fixture.create.v1"},
    )
    assert selected.plan["steps"][0]["action_id"] == "sandbox.fixture.create.v1"

    with pytest.raises(OrchestrationError, match="not registered to behavior"):
        orchestrator.preflight(
            scenario,
            mode=ExecutionMode.EXECUTE,
            profile=profile,
            approval_present=True,
            action_implementations={"create_fixture": "sandbox.discovery.list.v1"},
        )

    with pytest.raises(OrchestrationError, match="disabled by"):
        orchestrator.preflight(
            scenario,
            mode=ExecutionMode.EXECUTE,
            profile=replace(
                profile,
                enabled_actions=tuple(
                    action
                    for action in profile.enabled_actions
                    if action != "sandbox.fixture.create.v1"
                ),
            ),
            approval_present=True,
            action_implementations={"create_fixture": "sandbox.fixture.create.v1"},
        )


def test_execute_replay_preserves_action_choices_and_records_explicit_overrides(
    tmp_path: Path,
) -> None:
    runner = StructuredFakeRunner()
    orchestrator = _orchestrator(tmp_path, runner)
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()
    selections = {"create_fixture": "sandbox.fixture.create.v1"}
    approval = _approval_kwargs(
        orchestrator,
        scenario=scenario,
        profile=profile,
        target_scope=FULL_TARGET_SCOPE,
        action_implementations=selections,
    )
    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path,
        target_scope=FULL_TARGET_SCOPE,
        autonomy=AutonomyLevel.OFF,
        action_implementations=selections,
        **approval,
    )

    prepared = prepare_replay(
        orchestrator.store,
        orchestrator.registry,
        ReplayRequest(
            source_run_id=str(result["run_id"]),
            action_implementations={"create_fixture": "sandbox.fixture.create.v1"},
        ),
    )

    assert prepared.action_implementations["create_fixture"] == "sandbox.fixture.create.v1"
    assert prepared.lineage["action_implementations_from"]
    assert prepared.lineage["action_implementation_overrides"] == selections
    assert prepared.lineage["action_implementations_changed"] is True

    swapped = prepare_replay(
        orchestrator.store,
        orchestrator.registry,
        ReplayRequest(
            source_run_id=str(result["run_id"]),
            swap_step_id="discover_records",
            swap_behavior_id="sandbox.discovery.metadata.v1",
        ),
    )
    assert "discover_records" not in swapped.action_implementations
    assert swapped.lineage["action_reselection_steps"] == ["discover_records"]
    assert swapped.lineage["action_implementations_from"]["discover_records"] == (
        "sandbox.discovery.list.v1"
    )
    resolved_swap = orchestrator.planner.compile(
        swapped.scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        action_implementations=swapped.action_implementations,
    )
    resolved_discovery = next(
        step for step in resolved_swap.steps if step.step_id == "discover_records"
    )
    assert resolved_discovery.action_id == "sandbox.discovery.metadata.v1"


def _rows_by_step(result: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {str(row["step_id"]): row for row in result["steps"]}


def _evidence_by_step(result: Mapping[str, Any], step_id: str) -> list[Mapping[str, Any]]:
    return [row for row in result["evidence"]["records"] if row["step_id"] == step_id]


def test_simulate_never_calls_runner_inventory_or_execute(tmp_path: Path) -> None:
    runner = RunnerMustNotBeCalled()
    result = _orchestrator(tmp_path, runner).run(
        load_scenario(SCENARIO_PATH),
        mode=ExecutionMode.SIMULATE,
    )

    assert runner.calls == 0
    assert result["mode"] == "simulate"
    assert result["objective_reached"] is True
    assert result["cleanup"] == {
        "attempted": False,
        "success": None,
        "outstanding_receipt_count": 0,
    }
    assert {record["provenance"] for record in result["evidence"]["records"]} == {"synthetic"}
    assert all(step["action_id"] is None for step in result["steps"])


def test_simulate_persists_canonical_autonomy_and_provider_metadata(tmp_path: Path) -> None:
    provider = {
        "provider_id": "deterministic-offline.v1",
        "kind": "deterministic",
        "model": "deterministic-planner.v1",
    }
    result = _orchestrator(tmp_path, RunnerMustNotBeCalled()).run(
        load_scenario(SCENARIO_PATH),
        mode=ExecutionMode.SIMULATE,
        autonomy=AutonomyLevel.ASSIST,
        ai_provider=provider,
    )

    assert result["autonomy"] == "assist"
    assert result["ai_enabled"] is True
    assert result["ai_provider"] == provider
    assert result["plan"]["autonomy"] == "assist"
    assert result["policy"]["autonomy"] == "assist"
    assert result["policy"]["ai_provider"] == provider


def test_execute_refuses_missing_profile_and_approval_before_runner_use(tmp_path: Path) -> None:
    runner = StructuredFakeRunner()
    orchestrator = _orchestrator(tmp_path, runner)
    scenario = load_scenario(SCENARIO_PATH)

    with pytest.raises(OrchestrationError, match="explicit runner profile"):
        orchestrator.run(
            scenario,
            mode=ExecutionMode.EXECUTE,
            sandbox_root=tmp_path / "sandbox-missing-profile",
            approved_by="operator",
        )

    profile = _execute_profile()
    report = orchestrator.preflight(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        approval_present=False,
    )
    assert report.status == "approval_required"
    assert report.approval_required is True
    assert report.problems == ("Explicit operator approval is required.",)
    with pytest.raises(OrchestrationError, match="operator approval"):
        orchestrator.run(
            scenario,
            mode=ExecutionMode.EXECUTE,
            profile=profile,
            sandbox_root=tmp_path / "sandbox-missing-approval",
        )
    assert runner.inventory_calls == 0
    assert runner.calls == []


def test_execute_requires_explicit_profile_bounded_target_scope_before_runner_use(
    tmp_path: Path,
) -> None:
    runner = StructuredFakeRunner()
    orchestrator = _orchestrator(tmp_path, runner)
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()

    with pytest.raises(OrchestrationError, match="explicit target scope"):
        orchestrator.run(
            scenario,
            mode=ExecutionMode.EXECUTE,
            profile=profile,
            sandbox_root=tmp_path / "sandbox-missing-scope",
            approved_by="operator@example.test",
            approval_record={},
        )
    with pytest.raises(OrchestrationError, match="expands beyond"):
        orchestrator.run(
            scenario,
            mode=ExecutionMode.EXECUTE,
            profile=profile,
            sandbox_root=tmp_path / "sandbox-expanded-scope",
            target_scope={"scope_refs": ["sandbox.workspace", "external.network"]},
            approved_by="operator@example.test",
            approval_record={},
        )

    assert runner.inventory_calls == 0
    assert runner.calls == []


def test_execute_rejects_forged_rebound_and_replayed_approval_capabilities(
    tmp_path: Path,
) -> None:
    runner = StructuredFakeRunner()
    orchestrator = _orchestrator(tmp_path, runner)
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()
    authorization = _approval_kwargs(
        orchestrator,
        scenario=scenario,
        profile=profile,
        target_scope=FULL_TARGET_SCOPE,
    )
    forged = copy.deepcopy(authorization)
    forged["approval_record"]["nonce"] = "forged-capability"
    with pytest.raises(OrchestrationError, match="unavailable|mismatched"):
        orchestrator.run(
            scenario,
            mode=ExecutionMode.EXECUTE,
            profile=profile,
            sandbox_root=tmp_path / "forged",
            target_scope=FULL_TARGET_SCOPE,
            **forged,
        )
    with pytest.raises(OrchestrationError, match="exact plan and target scope"):
        orchestrator.run(
            scenario,
            mode=ExecutionMode.EXECUTE,
            profile=profile,
            sandbox_root=tmp_path / "rebound",
            target_scope={"scope_refs": ["sandbox.workspace", "export.local"]},
            **authorization,
        )
    assert runner.inventory_calls == 0

    orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path / "valid",
        target_scope=FULL_TARGET_SCOPE,
        **authorization,
    )
    inventory_calls = runner.inventory_calls
    with pytest.raises(OrchestrationError, match="already claimed"):
        orchestrator.run(
            scenario,
            mode=ExecutionMode.EXECUTE,
            profile=profile,
            sandbox_root=tmp_path / "replayed",
            target_scope=FULL_TARGET_SCOPE,
            **authorization,
        )
    assert runner.inventory_calls == inventory_calls


def test_operator_scope_refuses_unapproved_action_but_preserves_registered_fallback(
    tmp_path: Path,
) -> None:
    runner = StructuredFakeRunner()
    orchestrator = _orchestrator(tmp_path, runner)
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()
    target_scope = {"scope_refs": ["sandbox.workspace", "export.local"]}
    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path / "sandbox",
        target_scope=target_scope,
        **_approval_kwargs(
            orchestrator,
            scenario=scenario,
            profile=profile,
            target_scope=target_scope,
        ),
    )

    rows = _rows_by_step(result)
    network = rows["try_loopback"]
    assert network["status"] == "blocked"
    assert network["policy"]["status"] == "refused"
    assert network["error"]["code"] == "target_scope_refused"
    assert rows["export_locally"]["status"] == "success"
    assert result["authorized_target_scope"] == {
        "scope_refs": ["sandbox.workspace", "export.local"]
    }
    called_actions = [call[0]["action_id"] for call in runner.calls]
    assert "sandbox.network.loopback.v1" not in called_actions
    assert called_actions[-2:] == ["sandbox.export.local.v1", "sandbox.cleanup.v1"]


def test_execute_checkpoints_each_action_and_seals_remaining_time_in_manifest(
    tmp_path: Path,
) -> None:
    runner = StructuredFakeRunner()
    orchestrator = _orchestrator(tmp_path, runner)
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()
    checkpoints: list[Mapping[str, Any]] = []

    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path / "checkpoint-sandbox",
        target_scope=FULL_TARGET_SCOPE,
        checkpoint=lambda progress: checkpoints.append(dict(progress)),
        **_approval_kwargs(
            orchestrator,
            scenario=scenario,
            profile=profile,
            target_scope=FULL_TARGET_SCOPE,
        ),
    )

    assert checkpoints[0]["phase"] == "planning"
    assert any(str(item.get("run_id", "")).startswith("run-") for item in checkpoints)
    assert len([item for item in checkpoints if item["phase"] == "running"]) >= 2 * len(
        result["steps"]
    )
    configured_ms = profile.budgets.max_seconds * 1000
    assert all(1 <= call[0]["limits"]["timeout_ms"] <= configured_ms for call in runner.calls)
    assert runner.calls[0][0]["limits"]["timeout_ms"] < configured_ms


def test_overall_time_budget_refuses_further_effects_but_uses_cleanup_reserve(
    tmp_path: Path,
) -> None:
    runner = SlowFirstRunner()
    orchestrator = _orchestrator(tmp_path, runner)
    scenario = load_scenario(SCENARIO_PATH)
    base_profile = _execute_profile()
    profile = replace(
        base_profile,
        budgets=replace(base_profile.budgets, max_seconds=1),
    )
    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path / "deadline-sandbox",
        target_scope=FULL_TARGET_SCOPE,
        **_approval_kwargs(
            orchestrator,
            scenario=scenario,
            profile=profile,
            target_scope=FULL_TARGET_SCOPE,
        ),
    )

    rows = _rows_by_step(result)
    assert result["runtime_budget"]["exhausted"] is True
    assert rows["transform_fixture"]["status"] == "blocked"
    assert rows["transform_fixture"]["error"]["code"] == "runtime_budget_exhausted"
    assert result["cleanup"] == {
        "attempted": True,
        "success": True,
        "outstanding_receipt_count": 0,
    }
    assert [call[0]["action_id"] for call in runner.calls] == [
        "sandbox.fixture.create.v1",
        "sandbox.cleanup.v1",
    ]


def test_transport_failure_discovers_fsynced_receipt_and_forces_cleanup(
    tmp_path: Path,
) -> None:
    runner = ReceiptThenTransportFailureRunner()
    orchestrator = _orchestrator(tmp_path, runner)
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()
    sandbox = tmp_path / "receipt-failure-sandbox"

    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=sandbox,
        target_scope=FULL_TARGET_SCOPE,
        **_approval_kwargs(
            orchestrator,
            scenario=scenario,
            profile=profile,
            target_scope=FULL_TARGET_SCOPE,
        ),
    )

    rows = _rows_by_step(result)
    assert rows["create_fixture"]["status"] == "failed"
    assert rows["create_fixture"]["receipts"] == [runner.RECEIPT_ID]
    assert rows["cleanup_workspace"]["status"] == "success"
    assert result["cleanup"] == {
        "attempted": True,
        "success": True,
        "outstanding_receipt_count": 0,
    }
    assert [call[0]["action_id"] for call in runner.calls] == [
        "sandbox.fixture.create.v1",
        "sandbox.cleanup.v1",
    ]
    assert not (sandbox / ".bluefire" / "receipts" / f"{runner.RECEIPT_ID}.json").exists()


def test_missing_independent_observation_is_explicit_unknown_evidence(tmp_path: Path) -> None:
    orchestrator = _orchestrator(tmp_path, StructuredFakeRunner())
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()
    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path / "sandbox",
        target_scope=FULL_TARGET_SCOPE,
        **_approval_kwargs(
            orchestrator,
            scenario=scenario,
            profile=profile,
            target_scope=FULL_TARGET_SCOPE,
        ),
    )

    delivery = _evidence_by_step(result, "create_fixture")
    assert [row["provenance"] for row in delivery] == ["executed", "unknown"]
    assert delivery[0]["producer"] == "bluefire-rust-runner"
    assert delivery[1]["producer"] == "sandbox-observer.v1"
    assert delivery[1]["content"]["artifact_type"] == "evidence_gap"
    assert delivery[1]["parent_evidence_ids"] == [delivery[0]["evidence_id"]]


@pytest.mark.parametrize(
    ("runner_status", "step_status", "provenance"),
    [
        pytest.param("control_blocked", "blocked", "control_blocked", id="control-blocked"),
        pytest.param("failed", "failed", "executed", id="failed-after-dispatch"),
    ],
)
def test_structured_runner_status_preserves_provenance_branch_and_cleanup(
    tmp_path: Path,
    runner_status: str,
    step_status: str,
    provenance: str,
) -> None:
    runner = StructuredFakeRunner(network_status=runner_status)
    orchestrator = _orchestrator(tmp_path, runner)
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()
    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path / "sandbox",
        target_scope=FULL_TARGET_SCOPE,
        **_approval_kwargs(
            orchestrator,
            scenario=scenario,
            profile=profile,
            target_scope=FULL_TARGET_SCOPE,
        ),
    )

    rows = _rows_by_step(result)
    assert rows["try_loopback"]["status"] == step_status
    assert rows["try_loopback"]["runner_status"] == runner_status
    assert rows["export_locally"]["status"] == "success"
    assert rows["cleanup_workspace"]["status"] == "success"
    assert result["objective_reached"] is True
    assert result["cleanup"] == {
        "attempted": True,
        "success": True,
        "outstanding_receipt_count": 0,
    }
    assert [call[0]["action_id"] for call in runner.calls] == [
        "sandbox.fixture.create.v1",
        "sandbox.fixture.transform.v1",
        "sandbox.discovery.list.v1",
        "sandbox.collection.stage.v1",
        "sandbox.network.loopback.v1",
        "sandbox.export.local.v1",
        "sandbox.cleanup.v1",
    ]
    cleanup_manifest = runner.calls[-1][0]
    assert cleanup_manifest["params"]["receipt_ids"] == [
        RECEIPT_IDS["sandbox.export.local.v1"],
        RECEIPT_IDS["sandbox.collection.stage.v1"],
        RECEIPT_IDS["sandbox.fixture.transform.v1"],
        RECEIPT_IDS["sandbox.fixture.create.v1"],
    ]
    assert all(str(call[0]["request_hash"]).startswith("sha256:") for call in runner.calls)
    assert all(str(call[1]["policy_digest"]).startswith("sha256:") for call in runner.calls)

    network_evidence = _evidence_by_step(result, "try_loopback")
    assert len(network_evidence) == 1
    assert network_evidence[0]["provenance"] == provenance
    assert network_evidence[0]["producer"] == "bluefire-rust-runner"
    assert network_evidence[0]["content"]["runner_status"] == runner_status
    assert network_evidence[0]["content"]["runner_evidence"] == [
        {"kind": "fake-runner", "status": runner_status}
    ]
    assert network_evidence[0]["content_hash"].startswith("sha256:")
    assert network_evidence[0]["record_hash"].startswith("sha256:")

    network_decision = next(
        decision
        for decision in result["planner_decisions"]
        if decision["selected_step_id"] == "export_locally"
    )
    assert network_decision["execution_disposition"] == "execute"
    assert network_decision["selected_edge"]["outcome"] == step_status


def test_profile_control_block_prevents_dispatch_but_keeps_real_fallback_and_cleanup(
    tmp_path: Path,
) -> None:
    raw = _execute_profile().to_dict()
    raw["blocked_actions"] = ["sandbox.network.loopback.v1"]
    profile = RunnerProfile.from_mapping(raw)
    runner = StructuredFakeRunner()
    orchestrator = _orchestrator(tmp_path, runner)
    scenario = load_scenario(SCENARIO_PATH)

    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path / "sandbox",
        target_scope=FULL_TARGET_SCOPE,
        **_approval_kwargs(
            orchestrator,
            scenario=scenario,
            profile=profile,
            target_scope=FULL_TARGET_SCOPE,
        ),
    )

    rows = _rows_by_step(result)
    network = rows["try_loopback"]
    assert network["status"] == "blocked"
    assert network["policy"]["status"] == "control_blocked"
    assert network["error"]["code"] == "control_blocked"
    called_actions = [call[0]["action_id"] for call in runner.calls]
    assert "sandbox.network.loopback.v1" not in called_actions
    assert called_actions[-2:] == ["sandbox.export.local.v1", "sandbox.cleanup.v1"]
    assert result["objective_reached"] is True
    assert result["cleanup"]["outstanding_receipt_count"] == 0

    evidence = _evidence_by_step(result, "try_loopback")
    assert len(evidence) == 1
    assert evidence[0]["provenance"] == "control_blocked"
    assert evidence[0]["producer"] == "policy-engine.v1"
    assert evidence[0]["content"]["side_effects_started"] is False


def test_unexpected_post_effect_exception_dispatches_lifo_cleanup(tmp_path: Path) -> None:
    runner = StructuredFakeRunner()
    orchestrator = Orchestrator(
        load_builtin_registry(),
        FailAfterFirstEffectStore(tmp_path / "runs"),
        runner=runner,
        approval_store=ProductStore(tmp_path / "product.sqlite3"),
    )
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()

    with pytest.raises(RuntimeError, match="injected event-store failure"):
        orchestrator.run(
            scenario,
            mode=ExecutionMode.EXECUTE,
            profile=profile,
            sandbox_root=tmp_path / "sandbox",
            target_scope=FULL_TARGET_SCOPE,
            **_approval_kwargs(
                orchestrator,
                scenario=scenario,
                profile=profile,
                target_scope=FULL_TARGET_SCOPE,
            ),
        )

    assert [call[0]["action_id"] for call in runner.calls] == [
        "sandbox.fixture.create.v1",
        "sandbox.cleanup.v1",
    ]
    assert runner.calls[-1][0]["params"]["receipt_ids"] == [
        RECEIPT_IDS["sandbox.fixture.create.v1"]
    ]


def test_execute_preflight_rejects_profile_that_blocks_cleanup(tmp_path: Path) -> None:
    raw = _execute_profile().to_dict()
    raw["blocked_actions"] = ["sandbox.cleanup.v1"]
    profile = RunnerProfile.from_mapping(raw)
    runner = StructuredFakeRunner()
    orchestrator = _orchestrator(tmp_path, runner)

    report = orchestrator.preflight(
        load_scenario(SCENARIO_PATH),
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        approval_present=True,
    )

    assert report.status == "refused"
    assert "control-blocks its required cleanup action" in " ".join(report.problems)
    assert runner.calls == []


def test_cleanup_success_requires_a_complete_runner_report(tmp_path: Path) -> None:
    orchestrator = _orchestrator(tmp_path, IncompleteCleanupFakeRunner())
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()
    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path / "sandbox",
        target_scope=FULL_TARGET_SCOPE,
        **_approval_kwargs(
            orchestrator,
            scenario=scenario,
            profile=profile,
            target_scope=FULL_TARGET_SCOPE,
        ),
    )

    cleanup = _rows_by_step(result)["cleanup_workspace"]
    assert cleanup["status"] == "failed"
    assert cleanup["error"]["code"] == "runner_transport_failed"
    assert result["cleanup"]["success"] is False
    assert result["cleanup"]["outstanding_receipt_count"] == 3
