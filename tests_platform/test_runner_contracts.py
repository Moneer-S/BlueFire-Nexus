from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from bluefire.config import RunnerProfile, load_config
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
from bluefire.util import content_hash

ROOT = Path(__file__).resolve().parents[1]


def _execute_profile() -> RunnerProfile:
    config = load_config(ROOT / "config" / "bluefire.example.yaml")
    return next(profile for profile in config.runner_profiles if profile.mode.value == "execute")


def _restricted_profile() -> RunnerProfile:
    config = load_config(ROOT / "config" / "bluefire.example.yaml")
    return next(
        profile for profile in config.runner_profiles if profile.id == "sandbox-restricted-owned.v1"
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
        params={"path": "fixtures/input.txt", "content_template": "telemetry-seed"},
        filesystem_scope=("fixtures/input.txt",),
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
        "filesystem": ["fixtures/input.txt"],
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
            "input": "fixtures/input.txt",
            "output": "fixtures/transformed.txt",
            "transform": "uppercase-ascii",
        },
        filesystem_scope=("fixtures/input.txt", "fixtures/transformed.txt"),
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
