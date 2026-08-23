from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire.config import RunnerProfile, load_config
from bluefire.contracts import ExecutionMode, load_scenario
from bluefire.orchestrator import OrchestrationError, Orchestrator
from bluefire.registry import load_builtin_registry
from bluefire.run_store import RunStore

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
            "run_id": manifest["run_id"],
            "step_id": manifest["step_id"],
            "behavior_id": manifest["behavior_id"],
            "action_id": action_id,
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


def _orchestrator(tmp_path: Path, runner: object) -> Orchestrator:
    return Orchestrator(
        load_builtin_registry(),
        RunStore(tmp_path / "runs"),
        runner=runner,  # type: ignore[arg-type]
    )


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
    result = _orchestrator(tmp_path, runner).run(
        load_scenario(SCENARIO_PATH),
        mode=ExecutionMode.EXECUTE,
        profile=_execute_profile(),
        sandbox_root=tmp_path / "sandbox",
        approved_by="operator@example.test",
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

    result = _orchestrator(tmp_path, runner).run(
        load_scenario(SCENARIO_PATH),
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path / "sandbox",
        approved_by="operator@example.test",
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
    )

    with pytest.raises(RuntimeError, match="injected event-store failure"):
        orchestrator.run(
            load_scenario(SCENARIO_PATH),
            mode=ExecutionMode.EXECUTE,
            profile=_execute_profile(),
            sandbox_root=tmp_path / "sandbox",
            approved_by="operator@example.test",
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
    result = _orchestrator(tmp_path, IncompleteCleanupFakeRunner()).run(
        load_scenario(SCENARIO_PATH),
        mode=ExecutionMode.EXECUTE,
        profile=_execute_profile(),
        sandbox_root=tmp_path / "sandbox",
        approved_by="operator@example.test",
    )

    cleanup = _rows_by_step(result)["cleanup_workspace"]
    assert cleanup["status"] == "failed"
    assert cleanup["error"]["code"] == "runner_transport_failed"
    assert result["cleanup"]["success"] is False
    assert result["cleanup"]["outstanding_receipt_count"] == 3
