"""Composition through the original protected workspace, never the Rust inventory."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from . import macos_file_access_control as macos_control
from . import product_store_macos_file_access as macos
from .action_catalog import ActionCatalogSnapshot
from .capability_packs import MACOS_FILE_ACCESS_METHODS
from .config import EnvironmentType, RunnerProfile
from .contracts import ExecutionMode
from .macos_file_access_bridge import CommittedMacOSJournal, MacOSWorkspaceTaskTransport
from .macos_file_access_peer import darwin_clock_ns
from .product_store_errors import ProductStoreError
from .util import content_hash, json_clone

RUNNER_ID = "bluefire-macos-workspace.v1"
INVENTORY_SCHEMA = "bluefire.macos-workspace-inventory.v1"


class MacOSCompositionStore(CommittedMacOSJournal, Protocol):
    def get_file_access_control(self, owner_id: str) -> dict[str, Any]: ...

    def get_file_access_enrollment(self, enrollment_id: str) -> dict[str, Any]: ...


class MacOSCompositionService(Protocol):
    @property
    def product_store(self) -> MacOSCompositionStore: ...

    @property
    def _catalog_snapshot(self) -> ActionCatalogSnapshot: ...

    def _profiles_for_catalog(
        self, catalog: ActionCatalogSnapshot
    ) -> tuple[RunnerProfile, ...]: ...

    def _collector_binding(
        self, collector_ids: Sequence[str], runtime: None = None
    ) -> Mapping[str, Any]: ...


class OriginalMacOSCompositionRunner:
    def __init__(self, service: MacOSCompositionService) -> None:
        self._endpoint = macos_control.endpoint(service)
        self._transport = MacOSWorkspaceTaskTransport(self._endpoint, service.product_store)

    def transport_identity(self):
        self._endpoint.assert_current()
        recipe = self._endpoint._recipe
        required_sources = {
            "bluefire/macos_file_access_context.py",
            "bluefire/macos_file_access_bridge.py",
            "bluefire/macos_file_access_method.py",
            "bluefire/runner_contracts.py",
            "bluefire/macos_file_access_workspace_bootstrap.py",
            "bluefire/product_store_macos_composition.py",
            "bluefire/product_store_macos_completion.py",
            "bluefire/product_store_macos_workspace.py",
            "bluefire/product_store_macos_settlement.py",
            "bluefire/macos_file_access_intent.py",
            "bluefire/macos_attempt_workspace.py",
            "bluefire/composition_macos_file_access.py",
            "bluefire/macos_file_access_clock.py",
            "bluefire/macos_file_access_control.py",
            "bluefire/macos_file_access_workspace_validation.py",
            "bluefire/macos_file_access_endpoint.py",
            "bluefire/composition_result.py",
            "bluefire/product_store_capability_payloads.py",
            "bluefire/product_store_file_access_records.py",
            "bluefire/product_store_macos_setup.py",
        }
        if not required_sources <= set(recipe["source_sha256"]):
            raise ProductStoreError(
                "The original workspace does not pin the composition implementation."
            )
        return {
            "schema_version": "bluefire.macos-workspace-transport.v1",
            "runner_id": RUNNER_ID,
            "transport": "original-inherited-workspace-channel",
            "enrollment_generation": recipe["binding"]["generation"],
            "custody_digest": recipe["binding"]["custody_digest"],
            "source_digest": content_hash(recipe["source_sha256"]),
            "runtime_digest": content_hash(recipe["runtime_sha256"]),
        }

    def inventory(self):
        identity = self.transport_identity()
        return {
            "schema_version": INVENTORY_SCHEMA,
            "runner_id": RUNNER_ID,
            "platform": "macos",
            "source_digest": identity["source_digest"],
            "transport_digest": content_hash(identity),
            "actions": [
                {"action_id": method, "action_version": "1.0.0", "readiness": "ready"}
                for method in MACOS_FILE_ACCESS_METHODS
            ],
            "evidence": "original_producer_metadata",
            "native_filesystem_receipts": False,
        }

    def execute_task(self, manifest, profile, **kwargs):
        return self._transport.execute_task(manifest, profile, **kwargs)

    def validate_plan_inventory(self, plan, inventory):
        if (
            inventory != self.inventory()
            or len(plan.steps) != 3
            or {step.action_id for step in plan.steps} != set(MACOS_FILE_ACCESS_METHODS)
            or any(step.behavior_id != step.action_id or step.parameters for step in plan.steps)
        ):
            raise ProductStoreError(
                "The original workspace cannot execute this exact method graph."
            )


def composition(service: MacOSCompositionService, owner_id: str, now_ms: int) -> dict[str, Any]:
    from .runner_contracts import verify_macos_file_access_binding

    endpoint = macos_control.endpoint(service)
    enrolled = macos_control.enrollment(service, now_ms)
    stored = service.product_store.get_file_access_control(owner_id)
    control = stored["document"]
    if (
        not macos.is_control(control)
        or control["status"] != "hardened"
        or stored["pending_operation"]
        or control["enrollment_id"] != enrolled["document"]["enrollment_id"]
        or not control["baseline"]
    ):
        raise ProductStoreError("Composition requires the original settled hardened macOS control.")
    creator = endpoint.review_context("probe")
    actual = control["binding"]
    if (
        creator["binding"] != actual
        or content_hash(actual) != control["binding_digest"]
        or {**actual, "mode": "0640", "control_revision": 1} != endpoint._recipe["binding"]
        or control["generation"] != actual["generation"]
        or control["revision"] != actual["control_revision"]
    ):
        raise ProductStoreError("The original macOS creator or retained control changed.")
    catalog = service._catalog_snapshot
    profiles = [
        profile
        for profile in service._profiles_for_catalog(catalog)
        if profile.mode is ExecutionMode.EXECUTE
        and "macos" in profile.platforms
        and set(MACOS_FILE_ACCESS_METHODS) <= set(profile.enabled_actions)
        and not set(MACOS_FILE_ACCESS_METHODS).intersection(profile.blocked_actions)
    ]
    if len(profiles) != 1:
        raise ProductStoreError(
            "Select one original workspace profile enabling the three macOS methods."
        )
    profile = profiles[0]
    if (
        profile.environment_type is not EnvironmentType.DISPOSABLE
        or profile.runner_binary.env != "BLUEFIRE_MACOS_RUNNER"
        or profile.sandbox_root.env != "BLUEFIRE_MACOS_SANDBOX"
        or profile.secrets
        or profile.native_tool_installations
        or profile.network_allowlist
    ):
        raise ProductStoreError(
            "The metadata-only macOS profile cannot include extra effect authority."
        )
    runner = OriginalMacOSCompositionRunner(service)
    transport, inventory = runner.transport_identity(), runner.inventory()
    sandbox = Path(endpoint._recipe["workspace_root"]) / "sandbox"
    if (
        not sandbox.is_dir()
        or sandbox.is_symlink()
        or sandbox.absolute() != sandbox.resolve(strict=True)
    ):
        raise ProductStoreError("The original workspace sandbox is unavailable or changed.")
    intent = {
        "runner_profile_id": profile.id,
        "target_scope": {"scope_refs": ["sandbox.workspace"]},
    }
    readiness = {
        "schema_version": "bluefire.macos-workspace-readiness.v1",
        "platform": "macos",
        "transport": transport,
        "inventory": inventory,
        "evidence": "original_producer_metadata",
        "independent_telemetry": False,
    }
    environment = {
        "environment_id": "environment-" + actual["custody_digest"][7:],
        "environment_generation": actual["generation"],
        "runner_id": RUNNER_ID,
        "enrollment_digest": content_hash(transport),
        "profile_digest": content_hash(profile.to_dict()),
        "target_scope_digest": content_hash(intent["target_scope"]),
        "collector_digest": content_hash(service._collector_binding((), None)),
        "control_owner_id": owner_id,
        "control_digest": stored["document_digest"],
        "resource_id": "file-resource-" + content_hash(actual["resource"])[7:39],
        "resource_generation": actual["generation"],
        "resource_digest": content_hash(actual["resource"]),
        "probe_enrollment_digest": enrolled["document_digest"],
        "baseline_digest": control["baseline"]["baseline_digest"],
        "control_revision": control["revision"],
        "mode": actual["mode"],
        "workspace_custody_digest": actual["custody_digest"],
        "binding_digest": control["binding_digest"],
    }
    return {
        "registry": catalog.registry,
        "implementation_digests": {
            method: content_hash(
                {"method": method, "transport": transport, "catalog": catalog.to_dict()}
            )
            for method in MACOS_FILE_ACCESS_METHODS
        },
        "profile": profile,
        "runner": runner,
        "sandbox": sandbox,
        "runner_readiness": readiness,
        "transport": transport,
        "run_intent": intent,
        "collector_ids": (),
        "collector_runtime": None,
        "enrollment": enrolled,
        "expires_at_ms": actual["expires_at_ms"],
        "current_environment": environment,
        "record_count": actual["resource"]["record_count"],
        "resource_sha256": actual["resource"]["sha256"],
        "baseline": json_clone(control["baseline"]),
        "macos_file_access_binding": verify_macos_file_access_binding(
            actual,
            expected_document_digest=control["binding_digest"],
            now_ms=now_ms,
            now_monotonic_ns=darwin_clock_ns(),
        ),
    }
