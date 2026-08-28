from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire.config import load_config
from bluefire.contracts import ExecutionMode, SafetyTier, load_scenario
from bluefire.orchestrator import Orchestrator
from bluefire.planner import PlanStep
from bluefire.registry import load_builtin_registry
from bluefire.run_store import RunStore
from bluefire.runner_adapter import RunnerActionAdapter, RunnerAdapterError

ROOT = Path(__file__).resolve().parents[1]


def _peer_step() -> PlanStep:
    return PlanStep(
        step_id="handoff_to_peer",
        behavior_id="sandbox.peer.handoff.v1",
        action_id="sandbox.peer.handoff.v1",
        simulation_id=None,
        parameters={"port": 4317},
        inputs={},
        expected_outputs=(),
        required_capabilities=(),
        safety_tier=SafetyTier.CONTROLLED,
        alternates=(),
    )


def _bundle() -> dict[str, Any]:
    return {
        "type": "artifact.sandbox.bundle.v1",
        "path": "staged/bundle.jsonl",
        "sha256": "3" * 64,
        "size": 512,
    }


def _peer_output() -> dict[str, Any]:
    return {
        "destination": {"host": "127.0.0.1", "port": 4317},
        "artifact": "staged/bundle.jsonl",
        "bytes_sent": 512,
        "sha256": "3" * 64,
        "http_status": 200,
        "receiver_acknowledged": True,
        "receiver_stored": False,
        "lab_authorization": {
            "scope": "approved_task",
            "credential_kind": "managed_one_task_hmac_capability",
            "credential_handle": "4" * 64,
            "challenge_verified": True,
            "raw_credential_exposed": False,
        },
        "lab_peers": {
            "scope": "authorized_disposable_loopback_lab",
            "source_kind": "rust_runner_process",
            "destination_kind": "managed_loopback_receiver_process",
            "source_process_id": 4100,
            "destination_process_id": 4200,
            "source_handle": "5" * 64,
            "destination_handle": "6" * 64,
            "distinct_processes": True,
            "receiver_mode": "disposable_peer",
            "accepted_artifact_limit": 1,
            "storage_mode": "memory_only",
            "exit_after_accept": True,
            "transfer_acknowledged": True,
        },
    }


def test_peer_output_retains_only_opaque_authorization_and_peer_handles() -> None:
    output = _peer_output()
    receipt = RunnerActionAdapter().logical_outputs(
        _peer_step(),
        bound_inputs={"bundle": _bundle()},
        runner_output=output,
        receipt_ids=(),
    )["receipt"]

    assert receipt == {
        "type": "artifact.sandbox.peer-handoff.receipt.v2",
        "transport": "authenticated_loopback",
        "artifact": "staged/bundle.jsonl",
        "sha256": "3" * 64,
        "size": 512,
        "destination": {"host": "127.0.0.1", "port": 4317},
        "http_status": 200,
        "receiver_acknowledged": True,
        "receiver_stored": False,
        "lab_authorization": output["lab_authorization"],
        "lab_peers": output["lab_peers"],
    }
    assert "value" not in receipt["lab_authorization"]
    assert receipt["lab_peers"]["source_handle"] != receipt["lab_peers"]["destination_handle"]


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("lab_authorization", "scope"), "unbounded"),
        (("lab_authorization", "credential_kind"), "operator_password"),
        (("lab_authorization", "credential_handle"), "short"),
        (("lab_authorization", "challenge_verified"), False),
        (("lab_authorization", "raw_credential_exposed"), True),
        (("lab_peers", "scope"), "external_network"),
        (("lab_peers", "source_kind"), "shell"),
        (("lab_peers", "destination_kind"), "remote_host"),
        (("lab_peers", "destination_process_id"), 4100),
        (("lab_peers", "source_handle"), "6" * 64),
        (("lab_peers", "distinct_processes"), False),
        (("lab_peers", "receiver_mode"), "bounded_receiver"),
        (("lab_peers", "accepted_artifact_limit"), 2),
        (("lab_peers", "storage_mode"), "receiver_owned"),
        (("lab_peers", "exit_after_accept"), False),
        (("lab_peers", "transfer_acknowledged"), False),
    ],
)
def test_peer_output_fails_closed_on_authorization_or_scope_drift(
    path: tuple[str, str], value: object
) -> None:
    output = deepcopy(_peer_output())
    section, field = path
    output[section][field] = value

    with pytest.raises(RunnerAdapterError):
        RunnerActionAdapter().logical_outputs(
            _peer_step(),
            bound_inputs={"bundle": _bundle()},
            runner_output=output,
            receipt_ids=(),
        )


@pytest.mark.parametrize("section", ["lab_authorization", "lab_peers"])
def test_peer_output_rejects_unreviewed_lab_metadata(section: str) -> None:
    output = deepcopy(_peer_output())
    metadata = output[section]
    assert isinstance(metadata, Mapping)
    output[section] = {**metadata, "unreviewed": True}

    with pytest.raises(RunnerAdapterError, match="shape"):
        RunnerActionAdapter().logical_outputs(
            _peer_step(),
            bound_inputs={"bundle": _bundle()},
            runner_output=output,
            receipt_ids=(),
        )


def test_peer_catalog_keeps_remote_compromise_out_of_the_executable_contract() -> None:
    behavior = load_builtin_registry().get_behavior("sandbox.peer.handoff.v1")

    assert behavior.execution_state.value == "action"
    assert behavior.safety_tier is SafetyTier.CONTROLLED
    assert behavior.parameters[0].name == "port"
    assert any("authorized same-host disposable lab roles" in item for item in behavior.limitations)
    assert any("never compromises" in item for item in behavior.limitations)


def test_endpoint_deep_lab_composes_the_exact_reviewed_phases() -> None:
    registry = load_builtin_registry()
    scenario = load_scenario(ROOT / "scenarios" / "endpoint_deep_behavior_lab.yaml")
    config = load_config(ROOT / "config" / "bluefire.example.yaml")
    profile = next(
        item for item in config.runner_profiles if item.id == "sandbox-endpoint-deep-lab.v1"
    )

    assert scenario.id == "scenario.endpoint.deep-behavior-lab.v1"
    assert tuple(step.behavior_id for step in scenario.steps) == (
        "sandbox.execution.native-canary.v1",
        "endpoint.discovery.system.v1",
        "endpoint.discovery.processes.v1",
        "sandbox.fixture.create.v1",
        "sandbox.fixture.transform.v1",
        "sandbox.discovery.metadata.v1",
        "sandbox.collection.stage.v1",
        "sandbox.restricted.persistence-marker.v1",
        "sandbox.observability.variant.v1",
        "sandbox.credential.peer-challenge.v1",
        "sandbox.cleanup.v1",
    )
    assert tuple(tier.value for tier in profile.safety_tiers) == (
        "safe",
        "controlled",
        "restricted",
    )
    assert profile.approval_required is True
    assert profile.environment_type.value == "disposable"
    assert profile.secrets == {}
    assert profile.scope == ("sandbox.workspace", "network.loopback")
    assert profile.network_allowlist == ("127.0.0.1/32",)
    assert profile.budgets.max_steps >= len(scenario.steps)
    assert set(step.behavior_id for step in scenario.steps) - {
        "sandbox.credential.peer-challenge.v1"
    } <= set(profile.enabled_actions)
    credential = registry.get_behavior("sandbox.credential.peer-challenge.v1")
    assert credential.action_ids == ("sandbox.peer.handoff.v1",)
    registry.validate_runner_profile(profile)


def test_endpoint_deep_plan_compiles_exact_runner_roots_and_peer_destination(
    tmp_path: Path,
) -> None:
    registry = load_builtin_registry()
    scenario = load_scenario(ROOT / "scenarios" / "endpoint_deep_behavior_lab.yaml")
    config = load_config(ROOT / "config" / "bluefire.example.yaml")
    profile = next(
        item for item in config.runner_profiles if item.id == "sandbox-endpoint-deep-lab.v1"
    )
    orchestrator = Orchestrator(registry, RunStore(tmp_path / "runs"))
    plan = orchestrator.planner.compile(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
    )

    assert Orchestrator._filesystem_scope(plan) == (
        "fixtures",
        "staged",
        "restricted",
        "observability",
    )
    assert Orchestrator._network_destinations(plan) == ({"host": "127.0.0.1", "port": 4317},)
