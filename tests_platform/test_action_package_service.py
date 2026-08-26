from __future__ import annotations

import json
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bluefire.action_catalog import ActionCatalogError, ActionCatalogSnapshot
from bluefire.action_packages import (
    build_signed_action_package,
    canonical_public_key_b64u,
)
from bluefire.api import APIError
from bluefire.config import RunnerProfile
from bluefire.contracts import ExecutionMode
from bluefire.orchestrator import Orchestrator
from bluefire.runner_client import RunnerReadinessError, RunnerTransportError
from bluefire.runner_contracts import current_platform
from bluefire.service import BlueFireService
from tests_platform.test_action_package_lifecycle import (
    ACTION_ID,
    BEHAVIOR_ID,
    KEY_ID,
    PACKAGE_ID,
    PUBLISHER_ID,
    _manifest,
    _payload,
)
from tests_platform.test_service import (
    EXECUTE_PROFILE_ACTIONS,
    CleanupOnlyRecoveryRunner,
    _ready_inventory,
)

ROOT = Path(__file__).resolve().parents[1]


class PackageRecordingRunner:
    def __init__(self) -> None:
        self.inventory_calls = 0
        self.execute_calls = 0
        self.manifests: list[dict[str, Any]] = []
        self.profiles: list[dict[str, Any]] = []

    def inventory(self) -> Mapping[str, Any]:
        self.inventory_calls += 1
        return _ready_inventory(actions=EXECUTE_PROFILE_ACTIONS)

    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        self.execute_calls += 1
        self.manifests.append(dict(manifest))
        self.profiles.append(dict(profile))
        binding = manifest.get("execution_binding")
        runner_opcode = (
            binding.get("runner_opcode") if isinstance(binding, Mapping) else manifest["action_id"]
        )
        if runner_opcode == "sandbox.fixture.create.v1":
            output: Mapping[str, Any] = {
                "artifact": "fixtures/package-recovery.json",
                "sha256": "sha256:" + "a" * 64,
            }
        elif runner_opcode == "sandbox.cleanup.v1":
            output = {"removed_receipts": []}
        else:
            output = {
                "operating_system": current_platform(),
                "architecture": "test-architecture",
            }
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
            "output": output,
            "stdout": {"bytes": 0, "truncated": False},
            "stderr": {"bytes": 0, "truncated": False},
            "evidence": [{"kind": "test-package-alias", "status": "success"}],
            "receipt_ids": [],
            "cleanup": None,
            "error": None,
            "limitations": ["Deterministic package service test runner."],
        }


@pytest.fixture
def package_service(
    tmp_path: Path,
) -> tuple[BlueFireService, PackageRecordingRunner, Path]:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    runner = PackageRecordingRunner()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
        runner_factory=lambda _profile: (runner, sandbox),
    )
    try:
        yield service, runner, sandbox
    finally:
        service.close()


def _envelope(key: Ed25519PrivateKey, version: str) -> dict[str, Any]:
    return json.loads(
        build_signed_action_package(
            manifest=_manifest(version),
            payload=_payload(),
            key_id=KEY_ID,
            private_key=key,
        )
    )


def _trust(service: BlueFireService, key: Ed25519PrivateKey) -> Mapping[str, Any]:
    return service.trust_action_package_publisher(
        {
            "publisher_id": PUBLISHER_ID,
            "key_id": KEY_ID,
            "public_key": canonical_public_key_b64u(key.public_key()),
            "provenance": {
                "source": "local deterministic service test",
                "purpose": "package lifecycle verification",
            },
            "trusted_by": "package-reviewer",
        }
    )


def _install(
    service: BlueFireService,
    key: Ed25519PrivateKey,
    version: str,
) -> Mapping[str, Any]:
    return service.install_action_package(
        {
            "envelope": _envelope(key, version),
            "installed_by": "package-installer",
        }
    )


def _activate(
    service: BlueFireService,
    version: str,
) -> Mapping[str, Any]:
    return service.activate_action_package(
        PACKAGE_ID,
        version,
        {
            "runner_profile_id": _execute_profile(service).id,
            "activated_by": "package-operator",
            "reason": "reviewed deterministic service acceptance",
        },
    )


def _execute_profile(service: BlueFireService) -> RunnerProfile:
    return next(
        profile
        for profile in service.config.runner_profiles
        if profile.mode is ExecutionMode.EXECUTE
    )


def _package_scenario() -> Mapping[str, Any]:
    return {
        "schema_version": "bluefire.scenario.v1",
        "id": "scenario.package.endpoint-profile.v1",
        "title": "Signed package endpoint profile",
        "purpose": "Execute one signed alias for a reviewed native endpoint operation.",
        "start": "observe_system",
        "steps": [
            {
                "id": "observe_system",
                "behavior_id": BEHAVIOR_ID,
            }
        ],
        "edges": [],
        "provenance": {
            "source": "BlueFire deterministic package service test",
            "reference": "scenario.package.endpoint-profile.v1",
            "license": "MIT",
            "derived": False,
            "notes": "No external content.",
        },
        "limitations": ["Uses a deterministic local runner test double."],
    }


def _package_scenario_with_cleanup() -> Mapping[str, Any]:
    scenario = dict(_package_scenario())
    scenario["id"] = "scenario.package.endpoint-profile-cleanup.v1"
    scenario["start"] = "create_fixture"
    scenario["steps"] = [
        {
            "id": "create_fixture",
            "behavior_id": "sandbox.fixture.create.v1",
            "parameters": {"record_count": 1},
        },
        *list(scenario["steps"]),
        {
            "id": "cleanup_workspace",
            "behavior_id": "sandbox.cleanup.v1",
            "parameters": {"verify_removal": True},
            "inputs": {
                "workspace": {
                    "from_step": "create_fixture",
                    "artifact": "workspace",
                }
            },
        },
    ]
    scenario["edges"] = [
        {
            "from_step": "create_fixture",
            "outcome": "success",
            "to_step": "observe_system",
        },
        {
            "from_step": "observe_system",
            "outcome": "success",
            "to_step": "cleanup_workspace",
        },
    ]
    return scenario


def test_install_is_inert_until_exact_activation_changes_catalog_and_profile(
    package_service: tuple[BlueFireService, PackageRecordingRunner, Path],
) -> None:
    service, _runner, _sandbox = package_service
    key = Ed25519PrivateKey.generate()

    _trust(service, key)
    installed = _install(service, key, "1.2.3")

    assert installed["catalog_changed"] is False
    assert installed["package"]["status"] == "installed"
    assert service.catalog()["action_package_catalog"]["generation"] == 0
    assert ACTION_ID not in service.registry.action_ids

    activated = _activate(service, "1.2.3")
    catalog = service.catalog()
    profile = next(
        item for item in catalog["runner_profiles"] if item["id"] == _execute_profile(service).id
    )

    assert activated["operation"] == "activation"
    assert activated["catalog"]["generation"] == 1
    assert ACTION_ID in service.registry.action_ids
    assert BEHAVIOR_ID in service.registry.behavior_ids
    assert ACTION_ID in profile["enabled_actions"]
    assert activated["runner_identity_digest"].startswith("sha256:")
    assert activated["runner_inventory_digest"].startswith("sha256:")


def test_action_catalog_recomputes_package_set_digest_before_publishing_authority(
    package_service: tuple[BlueFireService, PackageRecordingRunner, Path],
) -> None:
    service, _runner, _sandbox = package_service

    with pytest.raises(ActionCatalogError, match="digest does not match"):
        ActionCatalogSnapshot.compose(
            service.registry,
            generation=0,
            catalog_digest="sha256:" + "0" * 64,
        )


def test_execute_preserves_logical_alias_while_sealing_reviewed_native_binding(
    package_service: tuple[BlueFireService, PackageRecordingRunner, Path],
) -> None:
    service, runner, _sandbox = package_service
    key = Ed25519PrivateKey.generate()
    _trust(service, key)
    _install(service, key, "1.2.3")
    _activate(service, "1.2.3")
    profile = _execute_profile(service)

    result = service.run(
        {
            "scenario": _package_scenario(),
            "mode": "execute",
            "runner_profile_id": profile.id,
            "autonomy": "off",
            "target_scope": {"scope_refs": list(profile.scope)},
            "approval": {
                "confirmed": True,
                "approved_by": "package-execute-reviewer",
            },
        }
    )

    assert result["status"] == "completed"
    assert result["objective_reached"] is True
    assert runner.execute_calls == 1
    manifest = runner.manifests[0]
    runner_profile = runner.profiles[0]
    binding = manifest["execution_binding"]
    assert manifest["behavior_id"] == BEHAVIOR_ID
    assert manifest["action_id"] == ACTION_ID
    assert binding["logical_behavior_id"] == BEHAVIOR_ID
    assert binding["logical_action_id"] == ACTION_ID
    assert binding["runner_opcode"] == "endpoint.discovery.system.v1"
    assert binding in runner_profile["action_bindings"]
    assert result["steps"][0]["behavior_id"] == BEHAVIOR_ID
    assert result["steps"][0]["action_id"] == ACTION_ID
    assert result["policy"]["preflight"]["catalog_authority"]["generation"] == 1


def test_catalog_change_refuses_reviewed_job_before_native_dispatch(
    package_service: tuple[BlueFireService, PackageRecordingRunner, Path],
) -> None:
    service, runner, _sandbox = package_service
    key = Ed25519PrivateKey.generate()
    _trust(service, key)
    _install(service, key, "1.2.3")
    _activate(service, "1.2.3")
    profile = _execute_profile(service)
    submission = service.submit_run(
        {
            "scenario": _package_scenario(),
            "mode": "execute",
            "runner_profile_id": profile.id,
            "autonomy": "off",
            "target_scope": {"scope_refs": list(profile.scope)},
        }
    )
    job_id = str(submission["job"]["job_id"])

    _install(service, key, "1.2.4")
    upgraded = _activate(service, "1.2.4")
    assert upgraded["operation"] == "upgrade"

    with pytest.raises(APIError, match="approval"):
        service.approve_job(job_id, {"approved_by": "stale-reviewer"})

    assert runner.execute_calls == 0
    assert service.job(job_id)["state"] == "awaiting_approval"


def test_exact_execute_replay_refuses_when_source_package_authority_is_inactive(
    package_service: tuple[BlueFireService, PackageRecordingRunner, Path],
) -> None:
    service, runner, _sandbox = package_service
    key = Ed25519PrivateKey.generate()
    _trust(service, key)
    _install(service, key, "1.2.3")
    activated = _activate(service, "1.2.3")
    profile = _execute_profile(service)
    source = service.run(
        {
            "scenario": _package_scenario(),
            "mode": "execute",
            "runner_profile_id": profile.id,
            "autonomy": "off",
            "target_scope": {"scope_refs": list(profile.scope)},
            "approval": {"confirmed": True, "approved_by": "source-reviewer"},
        }
    )
    assert runner.execute_calls == 1
    service.deactivate_action_package(
        PACKAGE_ID,
        "1.2.3",
        {
            "package_digest": activated["package"]["package_digest"],
            "expected_catalog_generation": activated["catalog"]["generation"],
            "expected_catalog_digest": activated["catalog"]["catalog_digest"],
            "deactivated_by": "package-operator",
            "reason": "prove exact replay authority refusal",
        },
    )

    with pytest.raises(APIError) as refused:
        service.replay(
            str(source["run_id"]),
            {
                "exact": True,
                "target_scope": {"scope_refs": list(profile.scope)},
                "approval": {"confirmed": True, "approved_by": "replay-reviewer"},
            },
        )

    assert refused.value.code == "replay_refused"
    assert "source package catalog" in str(refused.value.details)
    assert runner.execute_calls == 1


def test_interrupted_package_replay_recovers_with_its_exact_catalog_authority(
    package_service: tuple[BlueFireService, PackageRecordingRunner, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _runner, sandbox = package_service
    key = Ed25519PrivateKey.generate()
    _trust(service, key)
    _install(service, key, "1.2.3")
    activated = _activate(service, "1.2.3")
    profile = _execute_profile(service)
    source = service.run(
        {
            "scenario": _package_scenario_with_cleanup(),
            "mode": "execute",
            "runner_profile_id": profile.id,
            "autonomy": "off",
            "target_scope": {"scope_refs": list(profile.scope)},
            "approval": {"confirmed": True, "approved_by": "source-reviewer"},
        }
    )

    def interrupt_after_claim_with_receipt(
        _orchestrator: Orchestrator,
        **prepared: Any,
    ) -> Mapping[str, Any]:
        workspace = Path(prepared["observer"].root)
        artifact = workspace / "fixtures" / "interrupted-replay.txt"
        artifact.parent.mkdir()
        artifact.write_text("bounded interrupted replay artifact", encoding="utf-8")
        receipt_id = "e" * 64
        receipt_root = workspace / ".bluefire" / "receipts"
        receipt_root.mkdir(parents=True)
        (receipt_root / f"{receipt_id}.json").write_text(
            json.dumps(
                {
                    "schema_version": "bluefire.receipt/v1",
                    "receipt_id": receipt_id,
                    "request_hash": "sha256:" + "d" * 64,
                    "action_id": ACTION_ID,
                    "runner_profile_id": profile.id,
                    "created_at": "2026-08-26T00:00:00Z",
                    "paths": [
                        {
                            "relative_path": "fixtures/interrupted-replay.txt",
                            "kind": "file",
                            "sha256": None,
                            "size": artifact.stat().st_size,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        raise SystemExit("simulate process loss after replay claim")

    monkeypatch.setattr(Orchestrator, "_run_prepared", interrupt_after_claim_with_receipt)
    with pytest.raises(SystemExit, match="process loss"):
        service.replay(
            str(source["run_id"]),
            {
                "exact": True,
                "target_scope": {"scope_refs": list(profile.scope)},
                "approval": {"confirmed": True, "approved_by": "replay-reviewer"},
            },
        )

    active = service.product_store.list_execution_workspaces(states={"active"})
    assert len(active) == 1
    binding = active[0]
    recovery_authority = binding["recovery_context"]["catalog_authority"]
    assert recovery_authority["generation"] == activated["catalog"]["generation"]
    assert recovery_authority["catalog_digest"] == activated["catalog"]["catalog_digest"]
    assert recovery_authority["authority_digest"].startswith("sha256:")
    replay_workspace = Path(str(binding["workspace_path"]))
    artifact = replay_workspace / "fixtures" / "interrupted-replay.txt"
    assert artifact.is_file()
    runs_dir = service.store.root
    database = service.product_store.path
    service.close()

    recovery_runner = CleanupOnlyRecoveryRunner()
    restarted_sandbox = sandbox.parent / "restarted-sandbox"
    restarted_sandbox.mkdir()
    restarted = BlueFireService(
        project_root=ROOT,
        runs_dir=runs_dir,
        product_db_path=database,
        runner_factory=lambda _profile: (recovery_runner, restarted_sandbox),
    )
    try:
        assert restarted.cleanup_recovery["completed"] == 1
        assert [call["action_id"] for call in recovery_runner.calls] == ["sandbox.cleanup.v1"]
        assert not artifact.exists()
        recovered = restarted.product_store.get_execution_workspace(str(binding["approval_id"]))
        assert recovered["state"] == "recovered"
        assert recovered["outcome"]["status"] == "completed"
    finally:
        restarted.close()


def test_readiness_rejects_tampered_effective_inventory_and_catalog_authority(
    package_service: tuple[BlueFireService, PackageRecordingRunner, Path],
) -> None:
    service, _runner, _sandbox = package_service
    key = Ed25519PrivateKey.generate()
    _trust(service, key)
    _install(service, key, "1.2.3")
    _activate(service, "1.2.3")
    profile = service._profile(_execute_profile(service).id, ExecutionMode.EXECUTE)
    assert profile is not None
    _runner, _root, readiness = service._execute_readiness_boundary(profile)

    bad_effective = dict(readiness)
    bad_effective["effective_inventory_digest"] = "sha256:" + "0" * 64
    with pytest.raises(RunnerReadinessError, match="catalog binding"):
        service._validated_execute_readiness(profile, bad_effective)

    bad_authority = dict(readiness)
    bad_authority["catalog_authority"] = {
        **dict(readiness["catalog_authority"]),
        "generation": 99,
    }
    with pytest.raises(RunnerReadinessError, match="catalog binding"):
        service._validated_execute_readiness(profile, bad_authority)


def test_dispatch_callback_rechecks_product_store_catalog_immediately_before_effect(
    package_service: tuple[BlueFireService, PackageRecordingRunner, Path],
) -> None:
    service, runner, _sandbox = package_service
    profile = service._profile(_execute_profile(service).id, ExecutionMode.EXECUTE)
    assert profile is not None
    bound_runner, _root, readiness = service._execute_readiness_boundary(
        profile,
        for_dispatch=True,
    )
    assert readiness["catalog_authority"]["generation"] == 0

    key = Ed25519PrivateKey.generate()
    _trust(service, key)
    _install(service, key, "1.2.3")
    _activate(service, "1.2.3")

    with pytest.raises(RunnerReadinessError, match="catalog changed"):
        bound_runner.execute({}, {})

    assert runner.execute_calls == 0


def test_deactivate_remove_and_trust_revocation_update_exact_catalog_history(
    package_service: tuple[BlueFireService, PackageRecordingRunner, Path],
) -> None:
    service, _runner, _sandbox = package_service
    key = Ed25519PrivateKey.generate()
    _trust(service, key)
    _install(service, key, "1.2.3")
    activated = _activate(service, "1.2.3")
    active_package = activated["package"]
    active_catalog = activated["catalog"]

    deactivated = service.deactivate_action_package(
        PACKAGE_ID,
        "1.2.3",
        {
            "package_digest": active_package["package_digest"],
            "expected_catalog_generation": active_catalog["generation"],
            "expected_catalog_digest": active_catalog["catalog_digest"],
            "deactivated_by": "package-operator",
            "reason": "deterministic deactivation acceptance",
        },
    )
    assert deactivated["catalog"]["generation"] == 2
    assert ACTION_ID not in service.registry.action_ids

    removed = service.remove_action_package(
        PACKAGE_ID,
        "1.2.3",
        {
            "package_digest": active_package["package_digest"],
            "expected_catalog_generation": deactivated["catalog"]["generation"],
            "expected_catalog_digest": deactivated["catalog"]["catalog_digest"],
            "removed_by": "package-operator",
            "reason": "deterministic removal acceptance",
        },
    )
    historical = service._load_action_catalog_snapshot(1)

    assert removed["package"]["status"] == "removed"
    assert removed["historical_audit_bytes_retained"] is True
    assert historical.generation == 1
    assert ACTION_ID in historical.registry.action_ids
    assert service.action_package(PACKAGE_ID, version="1.2.3")["package"]["status"] == "removed"


def test_suspending_publisher_atomically_deactivates_its_active_package(
    package_service: tuple[BlueFireService, PackageRecordingRunner, Path],
) -> None:
    service, _runner, _sandbox = package_service
    key = Ed25519PrivateKey.generate()
    _trust(service, key)
    _install(service, key, "1.2.3")
    _activate(service, "1.2.3")

    result = service.transition_action_package_publisher(
        PUBLISHER_ID,
        KEY_ID,
        "suspend",
        {
            "actor": "trust-operator",
            "reason": "publisher signing authority review",
        },
    )

    assert result["publisher"]["trust_state"] == "suspended"
    assert result["catalog"]["generation"] == 2
    assert result["catalog"]["packages"] == []
    assert ACTION_ID not in service.registry.action_ids
    with pytest.raises(APIError, match="activation"):
        _activate(service, "1.2.3")


def test_package_runner_transport_errors_are_sanitized_at_activation(
    tmp_path: Path,
) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    class BrokenRunner(PackageRecordingRunner):
        def inventory(self) -> Mapping[str, Any]:
            raise RunnerTransportError("C:/private/runner/socket failed")

    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
        runner_factory=lambda _profile: (BrokenRunner(), sandbox),
    )
    try:
        key = Ed25519PrivateKey.generate()
        _trust(service, key)
        _install(service, key, "1.2.3")

        with pytest.raises(APIError) as captured:
            _activate(service, "1.2.3")

        assert captured.value.code == "action_package_activation_refused"
        assert "C:/private" not in captured.value.message
        assert captured.value.details is None
        assert service.catalog()["action_package_catalog"]["generation"] == 0
    finally:
        service.close()


@pytest.mark.parametrize("policy", ["disabled", "blocked"])
def test_activation_refuses_package_whose_opcode_profile_cannot_dispatch(
    package_service: tuple[BlueFireService, PackageRecordingRunner, Path],
    policy: str,
) -> None:
    service, _runner, _sandbox = package_service
    key = Ed25519PrivateKey.generate()
    _trust(service, key)
    _install(service, key, "1.2.3")
    original = _execute_profile(service)
    opcode = "endpoint.discovery.system.v1"
    restricted = replace(
        original,
        enabled_actions=(
            tuple(action for action in original.enabled_actions if action != opcode)
            if policy == "disabled"
            else original.enabled_actions
        ),
        blocked_actions=(
            original.blocked_actions
            if policy == "disabled"
            else tuple(dict.fromkeys((*original.blocked_actions, opcode)))
        ),
    )
    service._runtime_runner_profiles = tuple(
        restricted if profile.id == original.id else profile
        for profile in service._runtime_runner_profiles
    )

    with pytest.raises(APIError) as captured:
        _activate(service, "1.2.3")

    assert captured.value.code == "action_package_activation_refused"
    assert captured.value.details is None
    assert service.catalog()["action_package_catalog"]["generation"] == 0


def test_readiness_refuses_native_contract_or_version_drift_after_activation(
    package_service: tuple[BlueFireService, PackageRecordingRunner, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, runner, _sandbox = package_service
    key = Ed25519PrivateKey.generate()
    _trust(service, key)
    _install(service, key, "1.2.3")
    _activate(service, "1.2.3")

    def drifted_inventory() -> Mapping[str, Any]:
        inventory = dict(_ready_inventory(actions=EXECUTE_PROFILE_ACTIONS))
        inventory["actions"] = [
            {
                **dict(item),
                **(
                    {"action_version": "1.0.1"}
                    if item.get("action_id") == "endpoint.discovery.system.v1"
                    else {}
                ),
            }
            for item in inventory["actions"]
        ]
        return inventory

    monkeypatch.setattr(runner, "inventory", drifted_inventory)
    profile = service._profile(_execute_profile(service).id, ExecutionMode.EXECUTE)
    assert profile is not None

    with pytest.raises(RunnerReadinessError, match="native action contract changed"):
        service._execute_readiness_boundary(profile)


def test_execute_run_holds_catalog_lease_through_registered_cleanup(
    package_service: tuple[BlueFireService, PackageRecordingRunner, Path],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, runner, _sandbox = package_service
    key = Ed25519PrivateKey.generate()
    _trust(service, key)
    _install(service, key, "1.2.3")
    activated = _activate(service, "1.2.3")
    profile = _execute_profile(service)
    receipt_id = "d" * 64
    original_runner_execute = runner.execute

    def execute_with_receipt(
        manifest: Mapping[str, Any],
        runner_profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        result = dict(original_runner_execute(manifest, runner_profile))
        if manifest.get("action_id") == "sandbox.fixture.create.v1":
            result["receipt_ids"] = [receipt_id]
        elif manifest.get("action_id") == "sandbox.cleanup.v1":
            requested = list(manifest["params"]["receipt_ids"])
            result["output"] = {"removed_receipts": requested}
            result["cleanup"] = {
                "requested_receipts": len(requested),
                "removed_paths": ["fixtures/package-recovery.json"],
                "already_absent_receipts": [],
                "retained_paths": [],
                "errors": [],
            }
        return result

    monkeypatch.setattr(runner, "execute", execute_with_receipt)
    second_sandbox = tmp_path / "second-sandbox"
    second_sandbox.mkdir()
    second = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "second-runs",
        product_db_path=service.product_store.path,
        runner_factory=lambda _profile: (PackageRecordingRunner(), second_sandbox),
    )
    cleanup_gap = threading.Event()
    release_cleanup = threading.Event()
    original_execute_step = Orchestrator._execute_step

    def pause_before_cleanup(
        orchestrator: Orchestrator,
        **prepared: Any,
    ) -> Any:
        step = prepared.get("step")
        if step is not None and orchestrator._runner_opcode(step) == "sandbox.cleanup.v1":
            cleanup_gap.set()
            assert release_cleanup.wait(5)
        return original_execute_step(orchestrator, **prepared)

    monkeypatch.setattr(Orchestrator, "_execute_step", pause_before_cleanup)
    run_result: list[Mapping[str, Any]] = []
    run_error: list[BaseException] = []
    writer_done = threading.Event()
    writer_error: list[BaseException] = []

    def execute_run() -> None:
        try:
            run_result.append(
                service.run(
                    {
                        "scenario": _package_scenario_with_cleanup(),
                        "mode": "execute",
                        "runner_profile_id": profile.id,
                        "autonomy": "off",
                        "target_scope": {"scope_refs": list(profile.scope)},
                        "approval": {
                            "confirmed": True,
                            "approved_by": "lease-cleanup-reviewer",
                        },
                    }
                )
            )
        except BaseException as exc:
            run_error.append(exc)

    def deactivate() -> None:
        try:
            second.deactivate_action_package(
                PACKAGE_ID,
                "1.2.3",
                {
                    "package_digest": activated["package"]["package_digest"],
                    "expected_catalog_generation": activated["catalog"]["generation"],
                    "expected_catalog_digest": activated["catalog"]["catalog_digest"],
                    "deactivated_by": "second-service-operator",
                    "reason": "prove cleanup retains catalog lease",
                },
            )
        except BaseException as exc:
            writer_error.append(exc)
        finally:
            writer_done.set()

    run_thread = threading.Thread(target=execute_run, daemon=True)
    writer_thread = threading.Thread(target=deactivate, daemon=True)
    try:
        run_thread.start()
        assert cleanup_gap.wait(5)
        writer_thread.start()
        assert not writer_done.wait(0.2)
        release_cleanup.set()
        run_thread.join(timeout=10)
        writer_thread.join(timeout=10)
        assert not run_thread.is_alive()
        assert not writer_thread.is_alive()
        assert run_error == []
        assert writer_error == []
        assert run_result[0]["status"] in {"completed", "incomplete"}
        assert run_result[0]["steps"][-1]["action_id"] == "sandbox.cleanup.v1"
        assert run_result[0]["steps"][-1]["status"] == "success"
        assert runner.execute_calls == 3
        assert second.catalog()["action_package_catalog"]["generation"] == 2
    finally:
        release_cleanup.set()
        second.close()
