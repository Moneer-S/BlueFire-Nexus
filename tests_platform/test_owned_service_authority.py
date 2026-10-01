from __future__ import annotations

import hashlib
import tempfile
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from bluefire.config import load_config
from bluefire.contracts import SafetyTier
from bluefire.native_tool_installations import NativeToolInstallation
from bluefire.owned_service_authority import (
    CLEANUP_EFFECTS,
    FIXED_TEMPLATE_DIGEST,
    GRANT_SCHEMA,
    SERVICE_ACTION_ID,
    SETUP_EFFECTS,
    OwnedServiceAdmission,
    OwnedServiceAuthorityError,
    OwnedServiceGrant,
    compile_owned_service_scope,
    mint_owned_service_grant,
    profile_policy_digest,
    render_owned_service_unit_bytes,
    validate_owned_service_grant_for_request,
)
from bluefire.registry import load_builtin_registry
from bluefire.runner_client import execution_task_identity
from bluefire.runner_contracts import build_execution_manifest, build_runner_profile, seal_profile
from bluefire.tool_adapters.service_lifecycle import OwnedUserService
from bluefire.tool_adapters.service_operation_binding import ServiceOperationBinding

CREATED_AT = "2026-01-01T12:00:00Z"
SETUP_EXPIRY = "2026-01-01T12:05:00Z"
CLEANUP_EXPIRY = "2026-01-01T12:30:00Z"
WORKSPACE_ROOT = "/tmp/bluefire-owned-service-workspace"


def _installation(kind: str, path: str) -> NativeToolInstallation:
    return NativeToolInstallation.from_mapping(
        {
            "schema_version": "bluefire.native-tool-installation.v1",
            "adapter_id": f"owned.service.{kind}.v1",
            "adapter_version": "1.0.0",
            "adapter_contract_digest": "sha256:" + "a" * 64,
            "tool_id": f"owned.service.{kind}.binary.v1",
            "tool_version": "1.0.0",
            "platform": "linux",
            "architecture": "x86_64",
            "content_sha256": "sha256:" + ("b" if kind == "manager" else "c") * 64,
            "size_bytes": 4096,
            "installation_location": path,
        }
    )


def _profile() -> dict[str, Any]:
    manager = _installation("manager", "/usr/bin/systemctl")
    payload = _installation("payload", "/opt/bluefire/owned-service-payload")
    return {
        "id": "runner.owned-service.v1",
        "mode": "execute",
        "environment_type": "managed",
        "platforms": ["linux"],
        "runner_binary": {"env": "BLUEFIRE_RUNNER"},
        "sandbox_root": {"env": "BLUEFIRE_SANDBOX"},
        "scope": ["sandbox.workspace"],
        "network_allowlist": [],
        "capabilities": ["service.user"],
        "safety_tiers": ["controlled"],
        "approval_required": True,
        "enabled_actions": [SERVICE_ACTION_ID],
        "blocked_actions": [],
        "cleanup_policy": "required",
        "budgets": {"max_steps": 4, "max_seconds": 120, "max_artifacts": 4, "max_bytes": 4096},
        "secrets": {},
        "native_tool_installations": [manager.to_dict(), payload.to_dict()],
    }


def _scope(profile: dict[str, Any], *, memory_max_bytes: int = 64 * 1024 * 1024) -> dict[str, Any]:
    manager, payload = profile["native_tool_installations"]
    params = {"duration_seconds": 10, "memory_max_bytes": memory_max_bytes}
    limits = {
        "setup_timeout_seconds": 30,
        "cleanup_timeout_seconds": 30,
        "max_unit_bytes": 16 * 1024,
        "max_runtime_seconds": 60,
        "max_memory_bytes": 128 * 1024 * 1024,
        "max_processes": 4,
    }
    unit_bytes = render_owned_service_unit_bytes(
        payload_path=payload["installation_location"],
        duration_seconds=params["duration_seconds"],
        max_runtime_seconds=limits["max_runtime_seconds"],
        memory_max_bytes=params["memory_max_bytes"],
        max_processes=limits["max_processes"],
    )
    return {
        "schema_version": "bluefire.owned-user-service-scope.v1",
        "scenario_id": "owned-service-scenario.v1",
        "step_id": "owned-service-step.v1",
        "action_id": SERVICE_ACTION_ID,
        "profile_id": profile["id"],
        "profile_policy_digest": profile_policy_digest(profile),
        "target_scope_digest": "sha256:" + "d" * 64,
        "workspace": {"workspace_id": "workspace-owned-service.v1", "root": WORKSPACE_ROOT},
        "target": {
            "owner_uid": 1000,
            "boot_id": "12345678-1234-1234-1234-123456789abc",
            "manager_instance_id": "e" * 32,
        },
        "manager": {
            "kind": "systemd.user.v1",
            "bus_identity": "unix:path=/run/user/1000/bus",
        },
        "unit": {
            "nonce": "f" * 32,
            "name": f"bluefire-{'f' * 32}.service",
            "content_digest": "sha256:" + hashlib.sha256(unit_bytes).hexdigest(),
        },
        "template": {
            "template_id": "bluefire.user-service.fixed-wait.v1",
            "content_digest": FIXED_TEMPLATE_DIGEST,
        },
        "installations": {
            "manager": {
                "installation_id": manager["tool_id"],
                "path": manager["installation_location"],
                "digest": NativeToolInstallation.from_mapping(manager).digest,
                "content_sha256": manager["content_sha256"],
            },
            "payload": {
                "installation_id": payload["tool_id"],
                "path": payload["installation_location"],
                "digest": NativeToolInstallation.from_mapping(payload).digest,
                "content_sha256": payload["content_sha256"],
            },
        },
        "effects": {"setup": list(SETUP_EFFECTS), "cleanup": list(CLEANUP_EFFECTS)},
        "parameters": params,
        "limits": limits,
        "created_at": CREATED_AT,
        "setup_expires_at": SETUP_EXPIRY,
        "cleanup_expires_at": CLEANUP_EXPIRY,
    }


def _binding(scope: Any, operation: str) -> ServiceOperationBinding:
    document = scope.to_dict()
    identity = scope.identity_mapping()
    return ServiceOperationBinding.from_mapping(
        {
            "schema_version": "bluefire.service-operation-binding.v1",
            "identity": identity,
            "identity_digest": OwnedUserService.from_mapping(identity).digest,
            "journal_request_id": "request-owned-service.v1",
            "journal_revision": 1 if operation in SETUP_EFFECTS else 3,
            "journal_record_hash": "sha256:" + "1" * 64,
            "operation_id": "op-" + "2" * 32,
            "operation": operation,
            "reviewed_scope_digest": scope.digest,
            "manager_installation_digest": document["installations"]["manager"]["digest"],
            "payload_installation_digest": document["installations"]["payload"]["digest"],
        }
    )


def _grant_fixture(operation: str, *, memory_max_bytes: int = 64 * 1024 * 1024):
    profile = _profile()
    scope = compile_owned_service_scope(
        _scope(profile, memory_max_bytes=memory_max_bytes), profile=profile
    )
    binding = _binding(scope, operation)
    now = datetime(2026, 1, 1, 12, 2, tzinfo=timezone.utc)
    approval_binding = {
        "state_digest": "sha256:" + "3" * 64,
        "plan_digest": "sha256:" + "4" * 64,
        "target_scope_digest": scope.to_dict()["target_scope_digest"],
        "profile_id": scope.to_dict()["profile_id"],
        "maximum_tier": "controlled",
        "owned_service_scope_digest": scope.digest,
    }
    claim = {
        "approval_id": "approval-owned-service.v1",
        **{
            key: approval_binding[key]
            for key in (
                "state_digest",
                "plan_digest",
                "target_scope_digest",
                "profile_id",
                "maximum_tier",
            )
        },
        "status": "claimed",
        "consumed_at": "2026-01-01T12:01:00Z",
        "expires_at": "2026-01-01T12:10:00Z",
    }
    manifest = {
        "run_id": "run-owned-service.v1",
        "step_id": scope.to_dict()["step_id"],
        "action_id": SERVICE_ACTION_ID,
        "runner_profile_id": scope.to_dict()["profile_id"],
        "params": scope.to_dict()["parameters"],
        "request_hash": "sha256:" + "5" * 64,
        "policy_digest": "sha256:" + "6" * 64,
        "limits": {"timeout_ms": 30_000},
    }
    sealed_profile = {
        "profile_id": scope.to_dict()["profile_id"],
        "runner_id": "bluefire-rust-runner.v1",
        "platform": "linux",
        "policy_digest": manifest["policy_digest"],
        "sandbox_root": WORKSPACE_ROOT,
        "native_tool_installations": profile["native_tool_installations"],
    }
    task_id, _ = execution_task_identity(manifest, sealed_profile)
    grant = mint_owned_service_grant(
        scope=scope,
        claimed_approval=claim,
        approval_binding=approval_binding,
        operation_binding=binding,
        run_id=manifest["run_id"],
        manifest=manifest,
        sealed_profile=sealed_profile,
        task_id=task_id,
        now=now,
    )
    return scope, grant, manifest, sealed_profile, task_id


def build_native_golden_fixture() -> dict[str, Any]:
    """Build the shared Rust/Python admission vector from validated Python types."""

    configured = next(
        profile
        for profile in load_config(
            Path(__file__).resolve().parents[1] / "config/bluefire.example.yaml"
        ).runner_profiles
        if profile.id == "sandbox-execute.v1"
    )
    manager = _installation("manager", "/usr/bin/systemctl")
    payload = _installation("payload", "/opt/bluefire/owned-service-payload")
    configured = replace(
        configured,
        enabled_actions=tuple(
            sorted(
                set(configured.enabled_actions)
                | {SERVICE_ACTION_ID, "owned.service.manager.v1", "owned.service.payload.v1"}
            )
        ),
        capabilities=tuple(sorted(set(configured.capabilities) | {"native.execution"})),
        native_tool_installations=(manager, payload),
    )
    with tempfile.TemporaryDirectory(prefix="owned-service-fixture-") as temp_root:
        runner_profile = build_runner_profile(
            configured,
            sandbox_root=Path(temp_root) / "workspace",
            platform="linux",
            filesystem_scope=("fixtures",),
        )
    runner_profile["sandbox_root"] = WORKSPACE_ROOT
    runner_profile = seal_profile(runner_profile)

    profile_policy = configured.to_dict()
    profile_policy["native_tool_installations"] = [manager.to_dict(), payload.to_dict()]
    scope_value = _scope(profile_policy)
    scope_value["profile_policy_digest"] = profile_policy_digest(profile_policy)
    scope = compile_owned_service_scope(scope_value, profile=profile_policy)

    action = replace(
        load_builtin_registry().get_action("sandbox.fixture.create.v1"),
        id=SERVICE_ACTION_ID,
        title="Fixed owned user service",
        purpose="Run the bounded reviewed wait payload.",
        safety_tier=SafetyTier.CONTROLLED,
        capabilities=("native.execution",),
        platforms=("linux",),
        inputs=(),
        outputs=(),
        parameters=(),
        mutates=True,
        cleanup_action_id="sandbox.cleanup.v1",
    )
    now = datetime(2026, 1, 1, 12, 2, tzinfo=timezone.utc)
    manifest = build_execution_manifest(
        run_id="run-owned-service.v1",
        step_id=scope.to_dict()["step_id"],
        behavior_id="owned.service.behavior.v1",
        action=action,
        runner_profile=runner_profile,
        params=scope.to_dict()["parameters"],
        filesystem_scope=("fixtures",),
        approval_record={
            "approved_by": "synthetic-operator",
            "approved_at": "2026-01-01T12:01:00Z",
            "expires_at": "2026-01-01T12:10:00Z",
        },
        timeout_ms=30_000,
        now=now,
    )
    task_id, _ = execution_task_identity(manifest, runner_profile)
    approval_binding = {
        "state_digest": "sha256:" + "3" * 64,
        "plan_digest": "sha256:" + "4" * 64,
        "target_scope_digest": scope.to_dict()["target_scope_digest"],
        "profile_id": scope.to_dict()["profile_id"],
        "maximum_tier": "controlled",
        "owned_service_scope_digest": scope.digest,
    }
    claimed_approval = {
        "approval_id": "approval-owned-service.v1",
        **{
            key: approval_binding[key]
            for key in (
                "state_digest",
                "plan_digest",
                "target_scope_digest",
                "profile_id",
                "maximum_tier",
            )
        },
        "status": "claimed",
        "consumed_at": "2026-01-01T12:01:00Z",
        "expires_at": "2026-01-01T12:10:00Z",
    }
    grant = mint_owned_service_grant(
        scope=scope,
        claimed_approval=claimed_approval,
        approval_binding=approval_binding,
        operation_binding=_binding(scope, "create_unit"),
        run_id=manifest["run_id"],
        manifest=manifest,
        sealed_profile=runner_profile,
        task_id=task_id,
        now=now,
    )
    issuer = {
        "runner_id": "bluefire-rust-runner.v1",
        "client_id": "bluefire-client.v1",
        "enrollment_generation": "sha256:" + "7" * 64,
        "peer_fingerprint": "sha256:" + "8" * 64,
        "server_instance_id": "bluefire-server-instance.v1",
    }
    admission = OwnedServiceAdmission.create(grant, issuer=issuer)
    return {
        "admission": admission.to_dict(),
        "manifest": manifest,
        "profile": runner_profile,
        "now": "2026-01-01T12:03:00Z",
    }


def test_unit_uses_reviewed_lower_resource_parameter_than_ceiling() -> None:
    profile = _profile()
    scope = compile_owned_service_scope(_scope(profile), profile=profile)
    unit = scope.to_dict()
    rendered = render_owned_service_unit_bytes(
        payload_path=unit["installations"]["payload"]["path"],
        duration_seconds=unit["parameters"]["duration_seconds"],
        max_runtime_seconds=unit["limits"]["max_runtime_seconds"],
        memory_max_bytes=unit["parameters"]["memory_max_bytes"],
        max_processes=unit["limits"]["max_processes"],
    )
    assert b"MemoryMax=67108864" in rendered
    assert unit["limits"]["max_memory_bytes"] == 128 * 1024 * 1024
    assert unit["unit"]["content_digest"] == "sha256:" + hashlib.sha256(rendered).hexdigest()


def test_setup_expiry_does_not_extend_but_receipt_cleanup_has_its_own_window() -> None:
    setup_scope, setup_grant, setup_manifest, setup_profile, setup_task_id = _grant_fixture(
        "create_unit"
    )
    with pytest.raises(OwnedServiceAuthorityError, match="grant is expired"):
        validate_owned_service_grant_for_request(
            setup_grant,
            manifest=setup_manifest,
            profile=setup_profile,
            task_id=setup_task_id,
            now=datetime(2026, 1, 1, 12, 6, tzinfo=timezone.utc),
        )

    cleanup_scope, cleanup_grant, cleanup_manifest, cleanup_profile, cleanup_task_id = (
        _grant_fixture("stop")
    )
    assert cleanup_scope.digest == setup_scope.digest
    validate_owned_service_grant_for_request(
        cleanup_grant,
        manifest=cleanup_manifest,
        profile=cleanup_profile,
        task_id=cleanup_task_id,
        now=datetime(2026, 1, 1, 12, 20, tzinfo=timezone.utc),
    )
    with pytest.raises(OwnedServiceAuthorityError, match="grant is expired"):
        validate_owned_service_grant_for_request(
            cleanup_grant,
            manifest=cleanup_manifest,
            profile=cleanup_profile,
            task_id=cleanup_task_id,
            now=datetime(2026, 1, 1, 12, 31, tzinfo=timezone.utc),
        )


def test_cleanup_rejects_claims_consumed_after_setup_or_in_the_future() -> None:
    _scope, grant, manifest, profile, task_id = _grant_fixture("stop")
    for consumed_at, now, parse_rejects in (
        ("2026-01-01T12:06:00Z", datetime(2026, 1, 1, 12, 20, tzinfo=timezone.utc), True),
        ("2026-01-01T12:03:00Z", datetime(2026, 1, 1, 12, 2, tzinfo=timezone.utc), False),
    ):
        document = grant.to_dict()
        document["claim"]["consumed_at"] = consumed_at
        if parse_rejects:
            with pytest.raises(OwnedServiceAuthorityError, match="consumed inside"):
                OwnedServiceGrant.from_mapping(document)
            continue
        malformed = OwnedServiceGrant.from_mapping(document)
        with pytest.raises(OwnedServiceAuthorityError, match="consumed inside"):
            validate_owned_service_grant_for_request(
                malformed,
                manifest=manifest,
                profile=profile,
                task_id=task_id,
                now=now,
            )


def test_service_grant_binds_exact_claim_scope_and_pending_operation() -> None:
    scope, grant, manifest, profile, task_id = _grant_fixture("create_unit")
    document = grant.to_dict()
    assert document["schema_version"] == GRANT_SCHEMA
    assert document["operation_binding"]["identity"] == scope.identity_mapping()
    assert document["operation_binding"]["reviewed_scope_digest"] == scope.digest
    validate_owned_service_grant_for_request(
        grant,
        manifest=manifest,
        profile=profile,
        task_id=task_id,
        now=datetime(2026, 1, 1, 12, 3, tzinfo=timezone.utc),
    )
