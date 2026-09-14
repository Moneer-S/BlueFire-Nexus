from __future__ import annotations

import copy
import hashlib
import hmac
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import pytest

from bluefire.config import AutonomyLevel, RunnerProfile
from bluefire.contracts import ExecutionMode
from bluefire.evidence import SandboxObserver
from bluefire.orchestrator import OrchestrationError, Orchestrator
from bluefire.planner import ExecutionPlan, PlanStep
from bluefire.run_store import RunStore
from bluefire.runner_adapter import AdaptedAction, RunnerActionAdapter
from bluefire.runner_client import canonical_runner_inventory
from bluefire.runner_contracts import build_runner_profile
from bluefire.util import content_hash
from tests_platform.test_action_provider_packages import (
    ACTION_ID,
    ARTIFACT,
    BEHAVIOR_ID,
    _runner_inventory,
)
from tests_platform.test_provider_action_catalog import _execute_profile, _snapshot


class RecordingProviderAdapter(RunnerActionAdapter):
    def __init__(self) -> None:
        super().__init__()
        self.adapted_step: PlanStep | None = None
        self.output_step: PlanStep | None = None

    def adapt(
        self,
        step: PlanStep,
        *,
        bound_inputs: Mapping[str, Any],
        receipt_ids: Sequence[str],
        loopback_host: str = "127.0.0.1",
    ) -> AdaptedAction:
        self.adapted_step = step
        return super().adapt(
            step,
            bound_inputs=bound_inputs,
            receipt_ids=receipt_ids,
            loopback_host=loopback_host,
        )

    def logical_outputs(
        self,
        step: PlanStep,
        *,
        bound_inputs: Mapping[str, Any],
        runner_output: Any,
        receipt_ids: Sequence[str],
    ) -> dict[str, Any]:
        self.output_step = step
        return super().logical_outputs(
            step,
            bound_inputs=bound_inputs,
            runner_output=runner_output,
            receipt_ids=receipt_ids,
        )


class ProviderRunner:
    def __init__(self, inventory: Mapping[str, Any]) -> None:
        self._inventory = copy.deepcopy(dict(inventory))
        self.calls: list[tuple[dict[str, Any], dict[str, Any]]] = []

    def inventory(self) -> Mapping[str, Any]:
        return copy.deepcopy(self._inventory)

    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        manifest_copy = copy.deepcopy(dict(manifest))
        profile_copy = copy.deepcopy(dict(profile))
        self.calls.append((manifest_copy, profile_copy))
        binding = manifest_copy["provider_binding"]
        output_type = binding["outputs"][0]["type"]
        return {
            "schema_version": "bluefire.runner-result.v1",
            "request_id": manifest["request_id"],
            "run_id": manifest["run_id"],
            "step_id": manifest["step_id"],
            "behavior_id": manifest["behavior_id"],
            "action_id": manifest["action_id"],
            "runner_id": manifest["runner_id"],
            "runner_profile_id": manifest["runner_profile_id"],
            "request_hash": manifest["request_hash"],
            "policy_digest": profile["policy_digest"],
            "platform": profile["platform"],
            "status": "success",
            "output": {
                "schema_version": "bluefire.provider-action-output.v1",
                "outputs": {
                    "result": {
                        "type": output_type,
                        "status": "completed",
                    }
                },
            },
            "stdout": {"bytes": 0, "truncated": False},
            "stderr": {"bytes": 0, "truncated": False},
            "evidence": [{"kind": "provider-test", "status": "success"}],
            "receipt_ids": [],
            "cleanup": None,
            "error": None,
            "limitations": ["Deterministic provider orchestration fixture."],
        }


def _provider_context(
    tmp_path: Path,
    *,
    runner: ProviderRunner | None = None,
) -> tuple[Orchestrator, RunnerProfile, Mapping[str, Any]]:
    snapshot = _snapshot()
    profile = snapshot.profile(_execute_profile())
    binding = snapshot.execution_binding(BEHAVIOR_ID, ACTION_ID)
    assert binding is not None
    orchestrator = Orchestrator(
        snapshot.registry,
        RunStore(tmp_path / "runs"),
        runner=runner,
        action_bindings=snapshot.action_bindings,
        provider_artifacts=snapshot.provider_artifacts,
        catalog_authority=snapshot.authority,
    )
    return orchestrator, profile, binding


def _provider_step(
    orchestrator: Orchestrator,
    binding: Mapping[str, Any],
) -> PlanStep:
    action = orchestrator.registry.get_action(ACTION_ID)
    return PlanStep(
        step_id="provider-step",
        behavior_id=BEHAVIOR_ID,
        action_id=ACTION_ID,
        simulation_id=None,
        parameters={"repeat_count": 1},
        inputs={},
        expected_outputs=tuple(item.name for item in action.outputs),
        required_capabilities=action.capabilities,
        safety_tier=action.safety_tier,
        alternates=(),
        execution_binding=dict(binding),
    )


def _provider_plan(
    orchestrator: Orchestrator,
    profile: RunnerProfile,
    binding: Mapping[str, Any],
) -> ExecutionPlan:
    return ExecutionPlan(
        schema_version="bluefire.plan.v1",
        scenario_id="provider-orchestration-test.v1",
        objective="Exercise an independently distributed provider.",
        mode=ExecutionMode.EXECUTE,
        autonomy=AutonomyLevel.OFF,
        ai_provider={},
        runner_profile_id=profile.id,
        scenario_digest="sha256:" + "a" * 64,
        steps=(_provider_step(orchestrator, binding),),
        edges=(),
    )


def _approval_record() -> dict[str, str]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return {
        "approval_id": "approval-provider-orchestration",
        "nonce": "provider-orchestration-capability",
        "approved_by": "provider-test-operator",
        "approved_at": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
    }


def test_provider_only_inventory_skips_builtin_action_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    orchestrator, profile, binding = _provider_context(tmp_path)
    plan = _provider_plan(orchestrator, profile, binding)

    def fail_builtin_validation(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("provider-only plans must not enter the built-in action gate")

    monkeypatch.setattr(
        "bluefire.orchestrator.validate_builtin_action_inventory",
        fail_builtin_validation,
    )

    raw_inventory = _runner_inventory()
    Orchestrator._validate_inventory(plan, raw_inventory)
    Orchestrator._validate_inventory(plan, canonical_runner_inventory(raw_inventory))


def test_repeated_provider_steps_share_one_exact_inventory_binding(tmp_path: Path) -> None:
    orchestrator, profile, binding = _provider_context(tmp_path)
    first = _provider_step(orchestrator, binding)
    second = replace(first, step_id="provider-step-2", parameters={"repeat_count": 2})
    plan = replace(
        _provider_plan(orchestrator, profile, binding),
        steps=(first, second),
    )

    raw_inventory = _runner_inventory()
    Orchestrator._validate_inventory(plan, raw_inventory)
    Orchestrator._validate_inventory(plan, canonical_runner_inventory(raw_inventory))


def test_provider_artifact_substitution_is_refused_at_construction(tmp_path: Path) -> None:
    snapshot = _snapshot()
    provider_artifacts = {
        digest: dict(artifact) for digest, artifact in snapshot.provider_artifacts.items()
    }
    digest = next(iter(provider_artifacts))
    artifact = provider_artifacts[digest]
    encoded = str(artifact["artifact_hex"])
    artifact["artifact_hex"] = ("0" if encoded[0] != "0" else "1") + encoded[1:]

    with pytest.raises(OrchestrationError):
        Orchestrator(
            snapshot.registry,
            RunStore(tmp_path / "runs"),
            action_bindings=snapshot.action_bindings,
            provider_artifacts=provider_artifacts,
            catalog_authority=snapshot.authority,
        )


def test_provider_profile_contains_the_exact_private_artifact(tmp_path: Path) -> None:
    orchestrator, profile, binding = _provider_context(tmp_path)
    bindings = orchestrator._runner_profile_provider_bindings(profile)
    artifacts = orchestrator._runner_profile_provider_artifacts(profile)

    assert len(bindings) == 1
    assert bindings[0] == binding
    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert set(artifact) == {"artifact_sha256", "artifact_size", "artifact_hex"}
    assert artifact["artifact_sha256"] == binding["artifact_sha256"]
    assert artifact["artifact_size"] == binding["artifact_size"]
    artifact_bytes = bytes.fromhex(str(artifact["artifact_hex"]))
    assert hmac.compare_digest(artifact_bytes, ARTIFACT)
    assert "sha256:" + hashlib.sha256(artifact_bytes).hexdigest() == binding["artifact_sha256"]

    sandbox_root = tmp_path / "sandbox"
    runner_profile = build_runner_profile(
        profile,
        sandbox_root=sandbox_root,
        platform="windows",
        filesystem_scope=(),
        action_bindings=orchestrator._runner_profile_action_bindings(profile),
        provider_bindings=bindings,
        provider_artifacts=artifacts,
    )

    assert runner_profile["provider_bindings"] == [binding]
    assert len(runner_profile["provider_artifacts"]) == 1
    sealed_artifact = runner_profile["provider_artifacts"][0]
    assert sealed_artifact["artifact_sha256"] == binding["artifact_sha256"]
    assert sealed_artifact["artifact_size"] == binding["artifact_size"]
    assert hmac.compare_digest(bytes.fromhex(sealed_artifact["artifact_hex"]), ARTIFACT)


def test_provider_runtime_contract_drift_is_refused_before_dispatch(tmp_path: Path) -> None:
    orchestrator, profile, binding = _provider_context(tmp_path)
    plan = _provider_plan(orchestrator, profile, binding)
    inventory = _runner_inventory()
    runtime = inventory["provider_runtimes"][0]
    runtime["runtime_version"] = "wasmi-drifted-test-runtime"
    runtime_contract = {
        field: value for field, value in runtime.items() if field != "contract_digest"
    }
    runtime["contract_digest"] = content_hash(runtime_contract)

    with pytest.raises(OrchestrationError):
        Orchestrator._validate_inventory(plan, inventory)


def test_provider_execution_preserves_logical_action_and_seals_provider_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("bluefire.orchestrator.current_platform", lambda: "windows")
    runner = ProviderRunner(_runner_inventory())
    orchestrator, profile, binding = _provider_context(tmp_path, runner=runner)
    adapter = RecordingProviderAdapter()
    orchestrator.adapter = adapter
    step = _provider_step(orchestrator, binding)
    bindings = orchestrator._runner_profile_provider_bindings(profile)
    artifacts = orchestrator._runner_profile_provider_artifacts(profile)
    sandbox_root = tmp_path / "sandbox"
    sandbox_root.mkdir()
    runner_profile = build_runner_profile(
        profile,
        sandbox_root=sandbox_root,
        platform="windows",
        filesystem_scope=(),
        action_bindings=orchestrator._runner_profile_action_bindings(profile),
        provider_bindings=bindings,
        provider_artifacts=artifacts,
    )
    approval = _approval_record()

    row, _records, decision, receipts = orchestrator._execute_step(
        run_id="run-provider-orchestration",
        step=step,
        bound_inputs={},
        parent_ids=(),
        profile=profile,
        runner_profile=runner_profile,
        observer=SandboxObserver(sandbox_root),
        approved_by=approval["approved_by"],
        approval_record=approval,
        authorized_target_scope={"scope_refs": ["sandbox.workspace"]},
        receipt_ids=[],
    )

    assert decision.allowed is True
    assert row["status"] == "success"
    assert row["artifacts"]["result"]["status"] == "completed"
    assert receipts == ()
    assert adapter.adapted_step is not None
    assert adapter.adapted_step.action_id == ACTION_ID
    assert adapter.adapted_step.execution_binding == binding
    assert adapter.output_step is not None
    assert adapter.output_step.action_id == ACTION_ID
    assert len(runner.calls) == 1
    manifest, sealed_profile = runner.calls[0]
    assert manifest["action_id"] == ACTION_ID
    assert manifest["provider_binding"] == binding
    assert "execution_binding" not in manifest
    assert len(sealed_profile["provider_artifacts"]) == 1
