"""Offline approval tests; no tool, provider or runner is executed."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from bluefire.adaptive_execution import (
    AdaptiveAuthorizationError,
    compile_adaptive_authorization,
    validate_adaptive_authorization,
)
from bluefire.approvals import execution_approval_binding
from bluefire.config import AutonomyLevel, RunnerProfile, load_config
from bluefire.contracts import ExecutionMode, ScenarioDefinition, load_scenario
from bluefire.native_tool_installations import NativeToolInstallation
from bluefire.planner import DeterministicPlanner
from bluefire.product_store import ProductStore, ProductStoreError
from bluefire.registry import load_builtin_registry
from bluefire.util import content_hash

ROOT = Path(__file__).resolve().parents[1]
SCOPE = {"scope_refs": ["sandbox.workspace", "network.loopback", "export.local"]}


def configured_profile() -> RunnerProfile:
    profile = next(
        item
        for item in load_config(ROOT / "config/bluefire.example.yaml").runner_profiles
        if item.id == "sandbox-execute.v1"
    )
    document = profile.to_dict()
    document["enabled_actions"].append("sandbox.permission.chmod.v1")
    document["native_tool_installations"] = [
        {
            "schema_version": "bluefire.native-tool-installation.v1",
            "adapter_id": "sandbox.permission.chmod.v1",
            "adapter_version": "1.0.0",
            "adapter_contract_digest": "sha256:" + "a" * 64,
            "tool_id": "gnu.coreutils.chmod.v1",
            "tool_version": "9.5",
            "platform": "linux",
            "architecture": "x86_64",
            "content_sha256": "sha256:" + "b" * 64,
            "size_bytes": 1234,
            "installation_location": "/usr/bin/chmod",
        }
    ]
    return RunnerProfile.from_mapping(document)


def changed_profile(profile: RunnerProfile, field: str, value: str) -> RunnerProfile:
    record = profile.native_tool_installations[0].to_dict()
    record[field] = value
    return replace(
        profile, native_tool_installations=(NativeToolInstallation.from_mapping(record),)
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("installation_location", "/opt/reviewed/chmod"),
        ("tool_version", "9.6"),
        ("content_sha256", "sha256:" + "c" * 64),
    ],
)
def test_tool_rebinding_invalidates_durable_operator_approval(
    tmp_path: Path, field: str, value: str
) -> None:
    registry = load_builtin_registry()
    scenario = load_scenario(ROOT / "scenarios/sandbox_research_chain.yaml")
    profile = configured_profile()
    plan = DeterministicPlanner(registry).compile(
        scenario, mode=ExecutionMode.EXECUTE, profile=profile, autonomy=AutonomyLevel.OFF
    )

    def binding(selected: RunnerProfile):
        return execution_approval_binding(
            registry=registry,
            scenario=scenario,
            plan=plan.to_dict(),
            profile=selected,
            target_scope=SCOPE,
            autonomy=plan.autonomy,
            ai_provider=plan.ai_provider,
        )

    original = binding(profile)
    changed = binding(changed_profile(profile, field, value))
    assert original["state_digest"] != changed["state_digest"]
    assert original["plan_digest"] == changed["plan_digest"]
    store = ProductStore(tmp_path / "product.sqlite3")
    saved = store.save_resource("runner_profile", profile.id, profile.to_dict())
    reopened = ProductStore(store.path).get_resource("runner_profile", profile.id)
    assert saved["digest"] == reopened["digest"] == content_hash(profile.to_dict())
    assert RunnerProfile.from_mapping(reopened["document"]).to_dict() == profile.to_dict()
    pending = store.create_approval_request(
        run_id="tool-binding-review",
        state_digest=original["state_digest"],
        plan_digest=original["plan_digest"],
        profile_id=profile.id,
        target_scope_digest=original["target_scope_digest"],
        maximum_tier=original["maximum_tier"],
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
    )
    approved = store.approve(
        pending["approval_id"],
        approved_by="test-operator",
        expected_state_digest=original["state_digest"],
        expected_plan_digest=original["plan_digest"],
        expected_target_scope_digest=original["target_scope_digest"],
    )
    with pytest.raises(ProductStoreError, match="not bound"):
        store.consume_approval(
            approved["approval_id"],
            nonce=approved["nonce"],
            expected_state_digest=changed["state_digest"],
            expected_plan_digest=changed["plan_digest"],
            expected_target_scope_digest=changed["target_scope_digest"],
        )
    assert store.get_approval_request(approved["approval_id"])["status"] == "approved"


def test_tool_rebinding_invalidates_adaptive_authorization() -> None:
    registry = load_builtin_registry()
    # Declarative fixture only: no compiled action or tool dispatch is added.
    registry = registry.extended(
        actions=[
            replace(
                registry.get_action("sandbox.fixture.transform.v1"),
                id="sandbox.permission.chmod.v1",
            )
        ]
    )
    document = load_scenario(ROOT / "scenarios/sandbox_research_chain.yaml").to_dict()
    document["adaptive_execution"] = {
        "schema_version": "bluefire.adaptive-execution.v1",
        "steps": [
            {
                "step_id": "discover_records",
                "methods": [
                    {
                        "behavior_id": "sandbox.discovery.list.v1",
                        "action_id": "sandbox.discovery.list.v1",
                    },
                    {
                        "behavior_id": "sandbox.discovery.metadata.v1",
                        "action_id": "sandbox.discovery.metadata.v1",
                    },
                ],
            }
        ],
        "eligible_outcomes": ["blocked", "failed", "partial"],
        "max_retries": 1,
        "on_provider_failure": "stop",
    }
    scenario = ScenarioDefinition.from_mapping(document)
    profile = configured_profile()
    planner = DeterministicPlanner(registry)
    plan = planner.compile(
        scenario, mode=ExecutionMode.EXECUTE, profile=profile, autonomy=AutonomyLevel.AUTO
    )
    authorization = compile_adaptive_authorization(
        registry=registry,
        scenario=scenario,
        plan=plan,
        profile=profile,
        target_scope=SCOPE,
        platform="linux",
        planner=planner,
    )
    assert authorization is not None
    validate_adaptive_authorization(
        authorization,
        expected_digest=authorization["authorization_digest"],
        registry=registry,
        profile=profile,
        target_scope=SCOPE,
        platform="linux",
    )
    with pytest.raises(AdaptiveAuthorizationError, match="profile changed"):
        validate_adaptive_authorization(
            authorization,
            expected_digest=authorization["authorization_digest"],
            registry=registry,
            profile=changed_profile(profile, "tool_version", "9.6"),
            target_scope=SCOPE,
            platform="linux",
        )
