from __future__ import annotations

import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from bluefire.config import RunnerProfile, load_config
from bluefire.contracts import ActionDefinition
from bluefire.registry import load_builtin_registry
from bluefire.runner_client import RunnerTransportError, reject_forbidden_execution_keys
from bluefire.runner_contracts import (
    RunnerContractError,
    build_execution_manifest,
    build_runner_profile,
    current_platform,
    seal_manifest,
    seal_profile,
)
from bluefire.runner_inventory import (
    BUILTIN_RUNNER_ACTION_IDS,
    BUILTIN_RUNNER_ACTION_VERSIONS,
)
from bluefire.util import content_hash

ROOT = Path(__file__).resolve().parents[1]

EXPECTED_BUILTIN_RUNNER_ACTION_VERSIONS = {
    "endpoint.discovery.processes.v1": "1.0.0",
    "endpoint.discovery.system.v1": "1.0.0",
    "sandbox.archive.tar.v1": "1.0.0",
    "sandbox.cleanup.v1": "1.1.0",
    "sandbox.collection.stage.v1": "2.0.0",
    "sandbox.discovery.list.v1": "2.0.0",
    "sandbox.discovery.metadata.v1": "2.0.0",
    "sandbox.discovery.recursive.v1": "1.0.0",
    "sandbox.execution.native-canary.v1": "1.0.0",
    "sandbox.export.local.v1": "2.0.0",
    "sandbox.fixture.create.v1": "2.0.0",
    "sandbox.fixture.transform.v1": "2.0.0",
    "sandbox.identity-material.inspect.v1": "1.0.0",
    "sandbox.identity-material.seed.v1": "1.0.0",
    "sandbox.network.loopback.v1": "1.0.0",
    "sandbox.observability.variant.v1": "1.0.0",
    "sandbox.peer.handoff.v1": "1.0.0",
    "sandbox.restricted.persistence-marker.v1": "1.0.0",
}
EXPECTED_EXECUTE_ACTIONS = [
    "sandbox.execution.native-canary.v1",
    "sandbox.identity-material.seed.v1",
    "sandbox.identity-material.inspect.v1",
    "sandbox.fixture.create.v1",
    "sandbox.fixture.transform.v1",
    "sandbox.discovery.list.v1",
    "sandbox.discovery.metadata.v1",
    "endpoint.discovery.system.v1",
    "endpoint.discovery.processes.v1",
    "sandbox.discovery.recursive.v1",
    "sandbox.collection.stage.v1",
    "sandbox.archive.tar.v1",
    "sandbox.network.loopback.v1",
    "sandbox.peer.handoff.v1",
    "sandbox.observability.variant.v1",
    "sandbox.export.local.v1",
    "sandbox.cleanup.v1",
]


def test_python_authority_contains_exactly_eighteen_compiled_actions() -> None:
    assert dict(BUILTIN_RUNNER_ACTION_VERSIONS) == EXPECTED_BUILTIN_RUNNER_ACTION_VERSIONS
    assert BUILTIN_RUNNER_ACTION_IDS == frozenset(EXPECTED_BUILTIN_RUNNER_ACTION_VERSIONS)
    assert len(BUILTIN_RUNNER_ACTION_IDS) == 18


def _execution_binding(
    *,
    behavior_id: str = "acme.endpoint.profile.v1",
    action_id: str = "acme.endpoint.profile-action.v1",
    opcode: str = "endpoint.discovery.system.v1",
    constants: dict[str, object] | None = None,
) -> dict[str, object]:
    reviewed_constants = {} if constants is None else dict(constants)
    program = {
        "schema_version": "bluefire.action-program.v1",
        "steps": [
            {
                "opcode": opcode,
                "adapter": "bluefire.builtin-runner-adapter.v1",
                "constants": reviewed_constants,
            }
        ],
    }
    return {
        "schema_version": "bluefire.runner-execution-binding.v1",
        "catalog_generation": 7,
        "catalog_digest": "sha256:" + "1" * 64,
        "logical_behavior_id": behavior_id,
        "logical_action_id": action_id,
        "package_id": "acme.endpoint-profile-pack",
        "package_version": "1.2.3",
        "package_digest": "sha256:" + "2" * 64,
        "content_digest": "sha256:" + "3" * 64,
        "program_digest": content_hash(program),
        "runner_opcode": opcode,
        "opcode_contract_digest": "sha256:" + "4" * 64,
        "constants": reviewed_constants,
    }


def _alias_action(action_id: str, opcode: str) -> ActionDefinition:
    action = load_builtin_registry().get_action(opcode)
    return replace(action, id=action_id, title="Signed package alias")


def _execute_profile() -> RunnerProfile:
    config = load_config(ROOT / "config" / "bluefire.example.yaml")
    return next(profile for profile in config.runner_profiles if profile.mode.value == "execute")


def _restricted_profile() -> RunnerProfile:
    config = load_config(ROOT / "config" / "bluefire.example.yaml")
    return next(
        profile for profile in config.runner_profiles if profile.id == "sandbox-restricted-owned.v1"
    )


def _blocked_network_profile() -> RunnerProfile:
    config = load_config(ROOT / "config" / "bluefire.example.yaml")
    return next(
        profile for profile in config.runner_profiles if profile.id == "sandbox-blocked-network.v1"
    )


def _unsigned_profile(document: dict[str, object]) -> dict[str, object]:
    unsigned = copy.deepcopy(document)
    unsigned["policy_digest"] = ""
    return unsigned


def _unsigned_manifest(document: dict[str, object]) -> dict[str, object]:
    unsigned = copy.deepcopy(document)
    unsigned["request_hash"] = ""
    approval = unsigned.get("approval")
    if isinstance(approval, dict):
        approval["request_hash"] = ""
    return unsigned


def test_runner_profile_has_exact_shape_and_content_seal(tmp_path: Path) -> None:
    profile = _execute_profile()
    destination = {"host": "127.0.0.1", "port": 4317}
    document = build_runner_profile(
        profile,
        sandbox_root=tmp_path / "sandbox",
        platform=current_platform(),
        filesystem_scope=("fixtures", "staged", "exports"),
        network_destinations=(destination,),
    )

    assert set(document) == {
        "schema_version",
        "profile_id",
        "runner_id",
        "platform",
        "sandbox_root",
        "allowed_actions",
        "control_blocked_actions",
        "capabilities",
        "max_safety_tier",
        "approval_required_at_or_above",
        "target_scope",
        "limits",
        "policy_digest",
    }
    assert document["schema_version"] == "bluefire.runner-profile.v1"
    assert document["profile_id"] == profile.id
    assert document["runner_id"] == "bluefire-rust-runner.v1"
    assert document["sandbox_root"] == str((tmp_path / "sandbox").resolve())
    assert document["allowed_actions"] == list(profile.enabled_actions)
    assert document["control_blocked_actions"] == []
    assert document["capabilities"] == [
        "native_execution",
        "system_discovery",
        "process_discovery",
        "filesystem_read",
        "filesystem_write",
        "process_spawn",
        "network_loopback",
        "export_local",
        "cleanup",
    ]
    assert document["max_safety_tier"] == "controlled"
    assert document["approval_required_at_or_above"] == "safe"
    assert document["target_scope"] == {
        "filesystem": ["fixtures", "staged", "exports"],
        "network": [destination],
    }
    assert document["policy_digest"] == content_hash(_unsigned_profile(document))
    assert str(document["policy_digest"]).startswith("sha256:")

    source = dict(document, policy_digest="sha256:stale")
    resealed = seal_profile(source)
    assert source["policy_digest"] == "sha256:stale"
    assert resealed == document


def test_profile_control_block_is_a_permitted_allowlist_override(tmp_path: Path) -> None:
    raw = _execute_profile().to_dict()
    blocked_action = "sandbox.network.loopback.v1"
    raw["blocked_actions"] = [blocked_action]
    profile = RunnerProfile.from_mapping(raw)

    document = build_runner_profile(
        profile,
        sandbox_root=tmp_path / "sandbox",
        platform=current_platform(),
    )

    assert blocked_action in document["allowed_actions"]
    assert document["control_blocked_actions"] == [blocked_action]


def test_restricted_profile_seals_the_dedicated_runner_capability(tmp_path: Path) -> None:
    profile = _restricted_profile()
    document = build_runner_profile(
        profile,
        sandbox_root=tmp_path / "sandbox",
        platform=current_platform(),
        filesystem_scope=("restricted/persistence-marker.json",),
        network_destinations=(),
    )

    assert document["allowed_actions"] == [
        "sandbox.restricted.persistence-marker.v1",
        "sandbox.cleanup.v1",
    ]
    assert document["capabilities"] == [
        "sandbox_restricted",
        "filesystem_write",
        "cleanup",
    ]
    assert document["max_safety_tier"] == "restricted"
    assert document["policy_digest"] == content_hash(_unsigned_profile(document))


def test_execution_manifest_exactly_binds_profile_approval_and_hash(tmp_path: Path) -> None:
    profile = _execute_profile()
    runner_profile = build_runner_profile(
        profile,
        sandbox_root=tmp_path / "sandbox",
        platform=current_platform(),
    )
    action = load_builtin_registry().get_action("sandbox.fixture.create.v1")
    now = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)

    manifest = build_execution_manifest(
        run_id="run-20260823T120000Z-0123456789abcdef",
        step_id="create_fixture",
        behavior_id=action.id,
        action=action,
        runner_profile=runner_profile,
        params={
            "path": "fixtures/input.jsonl",
            "content_template": "telemetry-seed",
            "record_count": 6,
        },
        filesystem_scope=("fixtures/input.jsonl",),
        evidence_refs=("evidence-parent",),
        approval_record={
            "approved_by": "operator@example.test",
            "approved_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=15)).isoformat(),
        },
        timeout_ms=1_234,
        now=now,
    )

    assert set(manifest) == {
        "schema_version",
        "request_id",
        "run_id",
        "step_id",
        "behavior_id",
        "action_id",
        "mode",
        "runner_id",
        "runner_profile_id",
        "platform",
        "requested_at",
        "expires_at",
        "params",
        "target_scope",
        "required_capabilities",
        "safety_tier",
        "limits",
        "cleanup_action_id",
        "policy_digest",
        "approval",
        "evidence_refs",
        "request_hash",
    }
    assert manifest["schema_version"] == "bluefire.runner-manifest.v1"
    assert manifest["mode"] == "execute"
    assert manifest["action_id"] == action.id
    assert manifest["runner_profile_id"] == runner_profile["profile_id"]
    assert manifest["policy_digest"] == runner_profile["policy_digest"]
    assert manifest["cleanup_action_id"] == "sandbox.cleanup.v1"
    assert manifest["required_capabilities"] == ["filesystem_write"]
    assert manifest["requested_at"] == "2026-08-23T12:00:00Z"
    assert manifest["expires_at"] == "2026-08-23T12:05:00Z"
    assert manifest["evidence_refs"] == ["evidence-parent"]
    assert manifest["limits"]["timeout_ms"] == 1_234
    assert manifest["target_scope"] == {
        "filesystem": ["fixtures/input.jsonl"],
        "network": [],
    }
    approval = manifest["approval"]
    assert isinstance(approval, dict)
    assert approval["approved_by"] == "operator@example.test"
    assert approval["request_hash"] == manifest["request_hash"]
    assert manifest["request_hash"] == content_hash(_unsigned_manifest(manifest))
    assert str(manifest["request_hash"]).startswith("sha256:")

    reordered = dict(reversed(list(manifest.items())))
    assert seal_manifest(reordered)["request_hash"] == manifest["request_hash"]
    mutated = copy.deepcopy(manifest)
    mutated["params"]["content_template"] = "different"
    assert seal_manifest(mutated)["request_hash"] != manifest["request_hash"]


def test_package_alias_binding_is_exactly_sealed_in_profile_and_manifest(
    tmp_path: Path,
) -> None:
    binding = _execution_binding()
    assert binding["program_digest"] == (
        "sha256:e9fa0fe32f0e7bb0b38d5bb946ac3b3fcf91cc4abc14945fc4c1053c0cf57c4a"
    )
    base_profile = _execute_profile()
    alias_id = str(binding["logical_action_id"])
    profile = replace(
        base_profile,
        enabled_actions=base_profile.enabled_actions + (alias_id,),
    )
    runner_profile = build_runner_profile(
        profile,
        sandbox_root=tmp_path / "sandbox",
        platform=current_platform(),
        action_bindings=(binding,),
    )
    action = replace(
        _alias_action(alias_id, str(binding["runner_opcode"])),
        cleanup_action_id="acme.cleanup.v1",
    )
    now = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)
    manifest = build_execution_manifest(
        run_id="run-20260823T120000Z-0123456789abcdef",
        step_id="package_profile",
        behavior_id=str(binding["logical_behavior_id"]),
        action=action,
        runner_profile=runner_profile,
        params={},
        filesystem_scope=(),
        approval_record=None,
        execution_binding=binding,
        resolved_cleanup_action_id="sandbox.cleanup.v1",
        now=now,
    )

    assert runner_profile["action_bindings"] == [binding]
    assert manifest["execution_binding"] == binding
    assert manifest["cleanup_action_id"] == "sandbox.cleanup.v1"
    assert runner_profile["policy_digest"] == content_hash(_unsigned_profile(runner_profile))
    assert manifest["request_hash"] == content_hash(_unsigned_manifest(manifest))

    changed_profile = copy.deepcopy(runner_profile)
    changed_profile["action_bindings"][0]["catalog_generation"] = 8
    assert seal_profile(changed_profile)["policy_digest"] != runner_profile["policy_digest"]
    changed_manifest = copy.deepcopy(manifest)
    changed_manifest["execution_binding"]["package_digest"] = "sha256:" + "5" * 64
    assert seal_manifest(changed_manifest)["request_hash"] != manifest["request_hash"]

    with pytest.raises(RunnerContractError, match="resolved native cleanup"):
        build_execution_manifest(
            run_id="run-20260823T120000Z-0123456789abcdef",
            step_id="package_profile",
            behavior_id=str(binding["logical_behavior_id"]),
            action=action,
            runner_profile=runner_profile,
            params={},
            filesystem_scope=(),
            approval_record=None,
            execution_binding=binding,
            resolved_cleanup_action_id="acme.cleanup.v1",
            now=now,
        )


def test_package_alias_binding_rejects_profile_mismatch_and_constant_conflict(
    tmp_path: Path,
) -> None:
    opcode = "sandbox.fixture.create.v1"
    alias_id = "acme.fixture.create-action.v1"
    behavior_id = "acme.fixture.create.v1"
    binding = _execution_binding(
        behavior_id=behavior_id,
        action_id=alias_id,
        opcode=opcode,
        constants={"content_template": "telemetry-seed"},
    )
    base_profile = _execute_profile()
    profile = replace(
        base_profile,
        enabled_actions=base_profile.enabled_actions + (alias_id,),
    )
    runner_profile = build_runner_profile(
        profile,
        sandbox_root=tmp_path / "sandbox",
        platform=current_platform(),
        action_bindings=(binding,),
    )
    action = _alias_action(alias_id, opcode)

    with pytest.raises(RunnerContractError, match="conflict"):
        build_execution_manifest(
            run_id="run-20260823T120000Z-0123456789abcdef",
            step_id="package_fixture",
            behavior_id=behavior_id,
            action=action,
            runner_profile=runner_profile,
            params={"content_template": "caller-authored"},
            filesystem_scope=(),
            approval_record=None,
            execution_binding=binding,
        )

    mismatched = copy.deepcopy(binding)
    mismatched["package_version"] = "1.2.4"
    with pytest.raises(RunnerContractError, match="sealed runner profile"):
        build_execution_manifest(
            run_id="run-20260823T120000Z-0123456789abcdef",
            step_id="package_fixture",
            behavior_id=behavior_id,
            action=action,
            runner_profile=runner_profile,
            params={"content_template": "telemetry-seed"},
            filesystem_scope=(),
            approval_record=None,
            execution_binding=mismatched,
        )


def test_execution_binding_shape_and_program_are_strict(tmp_path: Path) -> None:
    binding = _execution_binding()
    binding["unknown"] = "not allowed"
    profile = _execute_profile()
    with pytest.raises(RunnerContractError, match="exact execution-binding fields"):
        build_runner_profile(
            profile,
            sandbox_root=tmp_path / "sandbox",
            platform=current_platform(),
            action_bindings=(binding,),
        )

    wrong_program = _execution_binding()
    wrong_program["program_digest"] = "sha256:" + "f" * 64
    with pytest.raises(RunnerContractError, match="program_digest"):
        seal_manifest(
            {
                "schema_version": "bluefire.runner-manifest.v1",
                "requested_at": "2026-08-23T12:00:00Z",
                "expires_at": "2026-08-23T12:05:00Z",
                "approval": None,
                "execution_binding": wrong_program,
            }
        )

    with pytest.raises(RunnerContractError, match="must be an object"):
        seal_manifest(
            {
                "schema_version": "bluefire.runner-manifest.v1",
                "requested_at": "2026-08-23T12:00:00Z",
                "expires_at": "2026-08-23T12:05:00Z",
                "approval": None,
                "execution_binding": None,
            }
        )


def test_manifest_timestamps_match_rust_chrono_hash_normalization(tmp_path: Path) -> None:
    profile = _execute_profile()
    runner_profile = build_runner_profile(
        profile,
        sandbox_root=tmp_path / "sandbox",
        platform=current_platform(),
    )
    action = load_builtin_registry().get_action("sandbox.fixture.transform.v1")
    now = datetime(2026, 8, 23, 12, 0, 0, 123_000, tzinfo=timezone.utc)

    manifest = build_execution_manifest(
        run_id="run-20260823T120000Z-0123456789abcdef",
        step_id="transform_fixture",
        behavior_id=action.id,
        action=action,
        runner_profile=runner_profile,
        params={
            "input": "fixtures/input.jsonl",
            "output": "fixtures/transformed.jsonl",
            "redact_values": True,
        },
        filesystem_scope=("fixtures/input.jsonl", "fixtures/transformed.jsonl"),
        approval_record={
            "approved_by": "operator@example.test",
            "approved_at": "2026-08-23T07:00:00.123000-05:00",
            "expires_at": "2026-08-23T12:15:00.000000Z",
        },
        now=now,
    )

    assert manifest["requested_at"] == "2026-08-23T12:00:00.123Z"
    assert manifest["expires_at"] == "2026-08-23T12:05:00.123Z"
    assert manifest["approval"]["approved_at"] == "2026-08-23T12:00:00.123Z"
    assert manifest["approval"]["expires_at"] == "2026-08-23T12:15:00Z"
    assert manifest["request_hash"] == content_hash(_unsigned_manifest(manifest))

    padded = copy.deepcopy(manifest)
    padded["requested_at"] = "2026-08-23T12:00:00.123000Z"
    padded["expires_at"] = "2026-08-23T12:05:00.123000Z"
    padded["approval"]["approved_at"] = "2026-08-23T12:00:00.123000Z"
    padded["approval"]["expires_at"] = "2026-08-23T12:15:00.000000Z"
    assert seal_manifest(padded) == manifest


@pytest.mark.parametrize(
    "field",
    [
        "binary",
        "cmd",
        "command",
        "executable",
        "interpreter",
        "payload",
        "script",
        "script-body",
        "shell",
        "shellcode",
    ],
)
def test_forbidden_execution_fields_are_rejected_recursively(field: str) -> None:
    value = {"params": {"nested": [{field: "caller-controlled"}]}}
    with pytest.raises(RunnerTransportError, match=r"forbidden execution field at \$\.params"):
        reject_forbidden_execution_keys(value)

    reject_forbidden_execution_keys(
        {"params": {"content_template": "the words command and script are inert values"}}
    )


def test_sealers_reject_unsupported_schema_and_non_object_approval() -> None:
    with pytest.raises(RunnerContractError, match="profile schema"):
        seal_profile({"schema_version": "legacy"})
    with pytest.raises(RunnerContractError, match="manifest schema"):
        seal_manifest({"schema_version": "legacy"})
    with pytest.raises(RunnerContractError, match="approval must be an object"):
        seal_manifest(
            {
                "schema_version": "bluefire.runner-manifest.v1",
                "approval": "operator",
            }
        )


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-08-23T12:00:00",
        "2026-08-23 12:00:00Z",
        "2026-08-23T12:00:00.1234567Z",
        "2026-08-23T12:00:00+00:00:30",
    ],
)
def test_manifest_sealing_rejects_noncanonical_timestamp_grammars(timestamp: str) -> None:
    with pytest.raises(RunnerContractError, match="RFC 3339"):
        seal_manifest(
            {
                "schema_version": "bluefire.runner-manifest.v1",
                "requested_at": timestamp,
                "expires_at": "2026-08-23T12:05:00Z",
                "approval": None,
            }
        )
