from __future__ import annotations

import copy
from typing import Any, Mapping

import pytest

from bluefire.replay_checkpoint import (
    CheckpointError,
    build_checkpoint,
    build_restoration_plan,
    checkpoint_for_step,
    validate_checkpoint,
    validate_restoration_plan,
)
from bluefire.util import content_hash


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _scenario() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.scenario.v1",
        "id": "scenario.checkpoint.test.v1",
        "title": "Checkpoint contract test",
        "purpose": "Recreate a deterministic materialized prefix.",
        "start": "create_fixture",
        "steps": [
            {
                "id": "create_fixture",
                "behavior_id": "sandbox.fixture.create.v1",
                "parameters": {"record_count": 2},
            },
            {
                "id": "transform_fixture",
                "behavior_id": "sandbox.fixture.transform.v1",
                "parameters": {"redact_values": True},
                "inputs": {"workspace": {"from_step": "create_fixture", "artifact": "workspace"}},
            },
            {
                "id": "inspect_fixture",
                "behavior_id": "sandbox.discovery.list.v1",
                "parameters": {"limit": 1},
                "alternates": ["sandbox.discovery.metadata.v1"],
                "inputs": {"fixture": {"from_step": "transform_fixture", "artifact": "fixture"}},
            },
        ],
        "edges": [
            {"from_step": "create_fixture", "outcome": "success", "to_step": "transform_fixture"},
            {"from_step": "transform_fixture", "outcome": "success", "to_step": "inspect_fixture"},
        ],
        "provenance": {"source": "test", "license": "MIT"},
        "limitations": ["Test-only bounded state."],
    }


def _plan(
    scenario: Mapping[str, Any], *, autonomy: str = "off", profile_id: str = "profile.test.v1"
) -> dict[str, Any]:
    action_ids = {
        "create_fixture": "sandbox.fixture.create.v1",
        "transform_fixture": "sandbox.fixture.transform.v1",
        "inspect_fixture": "sandbox.discovery.list.v1",
    }
    steps = []
    for step in scenario["steps"]:
        steps.append(
            {
                "step_id": step["id"],
                "behavior_id": step["behavior_id"],
                "action_id": action_ids[str(step["id"])],
                "simulation_id": None,
                "parameters": dict(step.get("parameters", {})),
                "inputs": copy.deepcopy(step.get("inputs", {})),
                "expected_outputs": ["artifact.test.v1"],
                "required_capabilities": ["filesystem_write"],
                "safety_tier": "safe",
                "alternates": list(step.get("alternates", [])),
            }
        )
    return {
        "schema_version": "bluefire.plan.v1",
        "scenario_id": scenario["id"],
        "objective": scenario["purpose"],
        "mode": "execute",
        "ai_enabled": autonomy != "off",
        "autonomy": autonomy,
        "ai_provider": {"provider_id": "deterministic-offline.v1"},
        "runner_profile_id": profile_id,
        "scenario_digest": content_hash(scenario),
        "steps": steps,
        "edges": copy.deepcopy(scenario["edges"]),
    }


def _profile(profile_id: str = "profile.test.v1") -> dict[str, Any]:
    return {
        "id": profile_id,
        "mode": "execute",
        "environment_type": "sandbox",
        "platforms": ["windows"],
        "runner_binary": {"env": "BLUEFIRE_RUNNER_BIN"},
        "sandbox_root": {"env": "BLUEFIRE_SANDBOX_ROOT"},
        "scope": ["sandbox.workspace"],
        "network_allowlist": ["127.0.0.0/8"],
        "capabilities": ["filesystem_read", "filesystem_write"],
        "safety_tiers": ["safe", "controlled"],
        "approval_required": True,
        "enabled_actions": [
            "sandbox.fixture.create.v1",
            "sandbox.fixture.transform.v1",
            "sandbox.discovery.list.v1",
            "sandbox.discovery.metadata.v1",
            "sandbox.cleanup.v1",
        ],
        "blocked_actions": [],
        "cleanup_policy": "always",
        "budgets": {
            "max_steps": 10,
            "max_seconds": 120,
            "max_artifacts": 10,
            "max_bytes": 1_048_576,
        },
        "secrets": {},
    }


def _catalog() -> dict[str, Any]:
    body = {
        "schema_version": "bluefire.action-catalog-authority.v1",
        "generation": 0,
        "catalog_digest": _digest("1"),
        "built_in_catalog_digest": _digest("2"),
        "packages": [],
        "action_bindings": [],
    }
    return {**body, "authority_digest": content_hash(body)}


def _readiness(profile_id: str = "profile.test.v1") -> dict[str, Any]:
    identity = {
        "schema_version": "bluefire.runner-identity.v1",
        "runner_id": "runner.test.v1",
        "transport": "authenticated-loopback",
    }
    return {
        "schema_version": "bluefire.execute-readiness.v1",
        "profile_id": profile_id,
        "runner_identity": identity,
        "runner_identity_digest": content_hash(identity),
        "inventory_digest": _digest("3"),
        "effective_inventory_digest": _digest("4"),
        "catalog_authority": _catalog(),
        "platform": "windows",
        "enabled_actions": [],
        "sandbox": {"state": "ready", "root_digest": _digest("5")},
        "freshness": {"observed_at": "2026-08-29T00:00:00Z", "max_age_seconds": 30},
        "recovery_identity": {"cleanup_action_digest": _digest("6")},
    }


def _authority(profile_id: str = "profile.test.v1") -> dict[str, Any]:
    return {
        "profile": _profile(profile_id),
        "target_scope": {"scope_refs": ["sandbox.workspace"]},
        "catalog_authority": _catalog(),
        "runner_readiness": _readiness(profile_id),
    }


def _artifacts() -> dict[str, Any]:
    return {
        "create_fixture": {
            "workspace": {
                "type": "artifact.sandbox.workspace.v1",
                "root": "fixtures",
                "record_count": 2,
            }
        },
        "transform_fixture": {
            "fixture": {
                "type": "artifact.sandbox.fixture.v1",
                "path": "fixtures/transformed.jsonl",
                "sha256": "a" * 64,
                "size": 24,
                "record_count": 2,
            }
        },
    }


def _checkpoint_kwargs() -> dict[str, Any]:
    scenario = _scenario()
    return {
        "source_run_id": "run-20260829T000000Z-0123456789abcdef",
        "source_binding_hash": _digest("b"),
        "scenario": scenario,
        "plan": _plan(scenario),
        "checkpoint_before_step_id": "inspect_fixture",
        "executed_steps": [
            {
                "step_id": "create_fixture",
                "behavior_id": "sandbox.fixture.create.v1",
                "action_id": "sandbox.fixture.create.v1",
                "status": "success",
            },
            {
                "step_id": "transform_fixture",
                "behavior_id": "sandbox.fixture.transform.v1",
                "action_id": "sandbox.fixture.transform.v1",
                "status": "success",
            },
        ],
        "artifacts": _artifacts(),
        "material_files": [
            {
                "relative_path": "fixtures/transformed.jsonl",
                "kind": "file",
                "sha256": "a" * 64,
                "size_bytes": 24,
                "source_step_id": "transform_fixture",
                "artifact_name": "fixture",
            }
        ],
        "source_authority": _authority(),
        "source_cleanup": {
            "attempted": True,
            "success": True,
            "outstanding_receipt_count": 0,
        },
        "collector_lineage": {"settings_hash": _digest("7")},
    }


def _build_checkpoint() -> Mapping[str, Any]:
    return build_checkpoint(**_checkpoint_kwargs())


def _rehash_checkpoint(value: dict[str, Any]) -> None:
    body = {
        key: item for key, item in value.items() if key not in {"checkpoint_id", "manifest_hash"}
    }
    value["manifest_hash"] = content_hash(body)
    value["checkpoint_id"] = "checkpoint-" + value["manifest_hash"].removeprefix("sha256:")


def _empty_variant() -> dict[str, Any]:
    return {
        "parameter_steps": [],
        "behavior_steps": [],
        "action_steps": [],
        "autonomy_changed": False,
        "profile_changed": False,
        "defense_change": None,
    }


def _build_plan(checkpoint: Mapping[str, Any]) -> Mapping[str, Any]:
    scenario = _scenario()
    return build_restoration_plan(
        checkpoint,
        target_scenario=scenario,
        target_plan=_plan(scenario),
        target_profile=_profile(),
        target_scope={"scope_refs": ["sandbox.workspace"]},
        target_catalog_authority=_catalog(),
        target_runner_readiness=_readiness(),
        variant_impact=_empty_variant(),
    )


def _rehash_plan(value: dict[str, Any]) -> None:
    body = {key: item for key, item in value.items() if key != "plan_hash"}
    value["plan_hash"] = content_hash(body)


def test_checkpoint_is_canonical_bound_and_selectable() -> None:
    checkpoint = _build_checkpoint()
    validated = validate_checkpoint(
        checkpoint,
        expected_source_run_id="run-20260829T000000Z-0123456789abcdef",
        expected_step_id="inspect_fixture",
    )

    assert validated == checkpoint
    assert checkpoint["checkpoint_id"] == (
        "checkpoint-" + str(checkpoint["manifest_hash"]).removeprefix("sha256:")
    )
    assert checkpoint["material_files"] == [
        {
            "relative_path": "fixtures/transformed.jsonl",
            "kind": "file",
            "sha256": _digest("a"),
            "size_bytes": 24,
            "source_step_id": "transform_fixture",
            "artifact_name": "fixture",
        }
    ]
    assert checkpoint_for_step([checkpoint], "inspect_fixture") == checkpoint
    encoded = str(checkpoint).casefold()
    for forbidden in ("receipt_ids", "credentials", "provider_artifacts"):
        assert forbidden not in encoded


def test_semantic_corruption_is_refused_after_outer_manifest_rehash() -> None:
    checkpoint = copy.deepcopy(_build_checkpoint())
    checkpoint["executed_steps"][0]["behavior_id"] = "sandbox.discovery.list.v1"
    _rehash_checkpoint(checkpoint)

    with pytest.raises(CheckpointError, match="semantically inconsistent"):
        validate_checkpoint(checkpoint)

    checkpoint = copy.deepcopy(_build_checkpoint())
    checkpoint["material_files"][0]["sha256"] = _digest("f")
    checkpoint["material_state_hash"] = content_hash(checkpoint["material_files"])
    _rehash_checkpoint(checkpoint)

    with pytest.raises(CheckpointError, match="logical artifact"):
        validate_checkpoint(checkpoint)


def test_checkpoint_source_binding_is_a_digest_bound_to_the_verified_run() -> None:
    checkpoint = copy.deepcopy(_build_checkpoint())
    checkpoint["source_binding_hash"] = {"api_token": "plaintext-secret"}
    _rehash_checkpoint(checkpoint)

    with pytest.raises(CheckpointError, match="canonical sha256 digest"):
        validate_checkpoint(checkpoint)

    with pytest.raises(CheckpointError, match="verified run bundle"):
        validate_checkpoint(
            _build_checkpoint(),
            expected_source_binding_hash=_digest("c"),
        )


@pytest.mark.parametrize(
    ("authority", "schema"),
    [("catalog", "forged.catalog.v9"), ("runner", "forged.runner.v9")],
)
def test_checkpoint_rejects_rehashed_nested_authority_schema_tampering(
    authority: str, schema: str
) -> None:
    checkpoint = copy.deepcopy(_build_checkpoint())
    checkpoint["source_authority"][authority]["schema_version"] = schema
    _rehash_checkpoint(checkpoint)

    with pytest.raises(CheckpointError, match=f"checkpoint {authority} schema"):
        validate_checkpoint(checkpoint)


@pytest.mark.parametrize("mutation", ["missing", "extra"])
def test_checkpoint_rejects_missing_and_extra_fields(mutation: str) -> None:
    checkpoint = copy.deepcopy(_build_checkpoint())
    if mutation == "missing":
        del checkpoint["source_binding_hash"]
    else:
        checkpoint["unreviewed"] = True

    with pytest.raises(CheckpointError, match="fields"):
        validate_checkpoint(checkpoint)


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("../escape.txt", "file"),
        ("/absolute/file.txt", "file"),
        ("C:/absolute/file.txt", "file"),
        ("fixtures/data.txt:stream", "file"),
        ("fixtures/CON", "file"),
        ("fixtures/trailing. ", "file"),
        ("fixtures/transformed.jsonl", "directory"),
        ("fixtures/transformed.jsonl", "symlink"),
    ],
)
def test_checkpoint_rejects_unsafe_material_paths_and_kinds(path: str, kind: str) -> None:
    kwargs = _checkpoint_kwargs()
    kwargs["material_files"][0]["relative_path"] = path
    kwargs["material_files"][0]["kind"] = kind

    with pytest.raises(CheckpointError):
        build_checkpoint(**kwargs)


@pytest.mark.parametrize(
    "key",
    [
        "secret",
        "credential",
        "receipt_ids",
        "provider_artifacts",
        "credential_handle",
        "accessToken",
        "api-token",
        "receiptHandle",
        "providerArtifactDigest",
        "privateKeyReference",
    ],
)
def test_checkpoint_rejects_sensitive_artifact_authority(key: str) -> None:
    kwargs = _checkpoint_kwargs()
    kwargs["artifacts"]["transform_fixture"]["fixture"][key] = "must-not-persist"

    with pytest.raises(CheckpointError, match="sensitive"):
        build_checkpoint(**kwargs)


def test_checkpoint_rejects_duplicate_material_and_prefix_identities() -> None:
    kwargs = _checkpoint_kwargs()
    kwargs["material_files"].append(copy.deepcopy(kwargs["material_files"][0]))
    with pytest.raises(CheckpointError, match="duplicate"):
        build_checkpoint(**kwargs)

    kwargs = _checkpoint_kwargs()
    kwargs["executed_steps"][1] = copy.deepcopy(kwargs["executed_steps"][0])
    with pytest.raises(CheckpointError, match="prefix"):
        build_checkpoint(**kwargs)


@pytest.mark.parametrize("outstanding", [1, True])
def test_checkpoint_requires_completed_zero_outstanding_cleanup(outstanding: object) -> None:
    kwargs = _checkpoint_kwargs()
    kwargs["source_cleanup"]["outstanding_receipt_count"] = outstanding

    with pytest.raises(CheckpointError, match="zero outstanding"):
        build_checkpoint(**kwargs)


def test_restoration_plan_binds_fresh_recreation_and_validation() -> None:
    checkpoint = _build_checkpoint()
    plan = _build_plan(checkpoint)

    assert validate_restoration_plan(plan, checkpoint) == plan
    assert plan["strategy"] == "recreate_prefix_then_verify"
    assert plan["prefix_step_ids"] == ["create_fixture", "transform_fixture"]
    assert plan["verification"] == {
        "require_prefix_hash_match": True,
        "require_material_hash_match": True,
        "require_fresh_approval": True,
        "reuse_source_receipts": False,
        "require_fresh_cleanup_receipts": True,
        "require_zero_outstanding_cleanup": True,
    }


def test_restoration_plan_accepts_declared_downstream_variants() -> None:
    checkpoint = _build_checkpoint()
    scenario = _scenario()
    target_step = scenario["steps"][2]
    target_step["behavior_id"] = "sandbox.discovery.metadata.v1"
    target_step["parameters"] = {"limit": 2}
    plan = _plan(scenario, autonomy="assist")
    plan["steps"][2]["action_id"] = "sandbox.discovery.metadata.v1"

    restoration = build_restoration_plan(
        checkpoint,
        target_scenario=scenario,
        target_plan=plan,
        target_profile=_profile(),
        target_scope={"scope_refs": ["sandbox.workspace"]},
        target_catalog_authority=_catalog(),
        target_runner_readiness=_readiness(),
        variant_impact={
            "parameter_steps": ["inspect_fixture"],
            "behavior_steps": ["inspect_fixture"],
            "action_steps": ["inspect_fixture"],
            "autonomy_changed": True,
            "profile_changed": False,
            "defense_change": "Enable the reviewed metadata alternate.",
        },
    )

    assert restoration["target"]["autonomy"] == "assist"
    assert restoration["variant_impact"]["defense_change_digest"].startswith("sha256:")
    assert "Enable the reviewed" not in str(restoration)


def test_restoration_refuses_variant_that_changes_materialized_prefix() -> None:
    checkpoint = _build_checkpoint()
    scenario = _scenario()
    scenario["steps"][0]["parameters"] = {"record_count": 3}
    plan = _plan(scenario)

    with pytest.raises(CheckpointError, match="materialized prefix"):
        build_restoration_plan(
            checkpoint,
            target_scenario=scenario,
            target_plan=plan,
            target_profile=_profile(),
            target_scope={"scope_refs": ["sandbox.workspace"]},
            target_catalog_authority=_catalog(),
            target_runner_readiness=_readiness(),
            variant_impact={
                **_empty_variant(),
                "parameter_steps": ["create_fixture"],
            },
        )


def test_restoration_plan_semantic_tamper_is_refused_after_rehash() -> None:
    checkpoint = _build_checkpoint()
    plan = copy.deepcopy(_build_plan(checkpoint))
    plan["target"]["scope_hash"] = _digest("f")
    _rehash_plan(plan)

    with pytest.raises(CheckpointError, match="authority changed"):
        validate_restoration_plan(plan, checkpoint)

    plan = copy.deepcopy(_build_plan(checkpoint))
    plan["verification"]["require_fresh_approval"] = False
    _rehash_plan(plan)
    with pytest.raises(CheckpointError, match="weakened"):
        validate_restoration_plan(plan, checkpoint)


def test_restoration_plan_rejects_unknown_fields() -> None:
    checkpoint = _build_checkpoint()
    plan = copy.deepcopy(_build_plan(checkpoint))
    plan["target"]["approval_nonce"] = "forbidden"
    _rehash_plan(plan)

    with pytest.raises(CheckpointError, match="fields"):
        validate_restoration_plan(plan, checkpoint)
