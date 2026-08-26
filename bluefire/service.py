"""Shared application service for the CLI and loopback web console."""

from __future__ import annotations

import base64
import binascii
import os
import re
import stat
import threading
from contextlib import AbstractContextManager
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import yaml

from .action_catalog import (
    ActionCatalogError,
    ActionCatalogSnapshot,
    ActivatedActionPackage,
)
from .action_packages import (
    ActionPackageError,
    audit_action_package,
    verify_action_package,
)
from .ai import (
    AIProposal,
    AIProvider,
    AIProviderError,
    ProposalType,
    ai_runtime_metadata,
    build_ai_provider,
    validate_persisted_proposal_record,
)
from .ai_drafts import (
    AIDraftError,
    AIDraftProvider,
    AIGraphDraftRequest,
    build_ai_draft_provider,
    normalize_ai_graph_draft,
)
from .api import APIError
from .approvals import (
    execution_approval_binding,
    execution_approval_envelope,
    public_approval_record,
)
from .bootstrap import seed_product_metadata
from .comparison import ComparisonError, compare_runs
from .config import (
    AIConfig,
    AIProviderConfig,
    AIProviderKind,
    AutonomyLevel,
    BlueFireConfig,
    ConfigError,
    RunnerProfile,
    load_config,
)
from .contracts import ContractError, ExecutionMode, ScenarioDefinition, load_scenario
from .detection_lab import DetectionLabService
from .job_runtime import (
    JobCancelled,
    JobContext,
    JobNotManaged,
    JobQueueFull,
    JobResult,
    JobRuntimeError,
    JobStateError,
    RunJobController,
)
from .orchestrator import OrchestrationError, Orchestrator
from .plugins import PluginManifest, PluginManifestError, PluginTrust
from .product_store import (
    ActionPackageConflictError,
    ActionPackageIntegrityError,
    ProductStore,
    ProductStoreError,
    ResearchSourceIntegrityError,
)
from .registry import BehaviorRegistry, RegistryError, load_builtin_registry
from .replay import ReplayError, ReplayRequest, prepare_replay
from .research import ResearchSource, ResearchSourceError
from .run_store import RunStore, RunStoreError
from .runner_bootstrap import RUNNER_ID, managed_product_root
from .runner_client import (
    InventoryBoundRunner,
    RunnerReadinessError,
    RunnerTaskCancelled,
    RunnerTransport,
    RunnerTransportError,
    canonical_runner_inventory,
    runner_transport_identity,
)
from .runner_contracts import RunnerContractError
from .runner_lifecycle import ManagedRunnerLifecycle, RunnerLifecycleError
from .util import canonical_json_bytes, content_hash, file_hash

RunnerFactory = Callable[[RunnerProfile], tuple[RunnerTransport, Path]]
AIProviderFactory = Callable[[AIConfig, str], AIProvider]
AIDraftProviderFactory = Callable[[AIConfig, str], AIDraftProvider]

_MANAGEMENT_IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_MANAGEMENT_STATUS = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_MANAGED_RESOURCE_KINDS = frozenset(
    {
        "action",
        "collector",
        "comparison",
        "detection",
        "detection_backend",
        "model_provider",
        "plugin",
        "research_source",
        "runner",
        "runner_profile",
    }
)
_RUNTIME_RESOURCE_KINDS = frozenset({"model_provider", "runner_profile"})
_RUNNER_PROBE_MAX_ACTIONS = 512
_RUNNER_PROBE_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]*$")
_STEP_IMPLEMENTATION_ID = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_EXECUTE_READINESS_KEY = "_execute_readiness"
_ACTION_CATALOG_AUTHORITY_KEY = "_action_catalog_authority"
_EXECUTE_READINESS_MAX_AGE_SECONDS = 15 * 60


def _default_ai_provider_factory(config: AIConfig, provider_id: str) -> AIProvider:
    return build_ai_provider(config, provider_id=provider_id)


def _default_ai_draft_provider_factory(config: AIConfig, provider_id: str) -> AIDraftProvider:
    return build_ai_draft_provider(config, provider_id=provider_id)


class BlueFireService:
    """Synchronous, JSON-only product boundary used by every frontend."""

    def __init__(
        self,
        *,
        project_root: str | Path | None = None,
        config_path: str | Path | None = None,
        runs_dir: str | Path | None = None,
        product_db_path: str | Path | None = None,
        registry: BehaviorRegistry | None = None,
        config: BlueFireConfig | None = None,
        runner_factory: RunnerFactory | None = None,
        runner_lifecycle: ManagedRunnerLifecycle | None = None,
        ai_provider_factory: AIProviderFactory | None = None,
        ai_draft_provider_factory: AIDraftProviderFactory | None = None,
    ) -> None:
        root = (
            Path(project_root) if project_root is not None else Path(__file__).resolve().parents[1]
        )
        self.project_root = root.resolve()
        self._built_in_registry = registry or load_builtin_registry()
        self.registry = self._built_in_registry
        self.config = config or self._load_default_config(config_path)
        self.store = RunStore(runs_dir or Path.cwd() / ".bluefire-runs")
        self.recovered_runs = self.store.recover_interrupted_runs()
        self.runner_lifecycle = runner_lifecycle or ManagedRunnerLifecycle(managed_product_root())
        self.runner_factory = runner_factory or self._managed_runner
        self.ai_provider_factory = ai_provider_factory or _default_ai_provider_factory
        self.ai_draft_provider_factory = (
            ai_draft_provider_factory or _default_ai_draft_provider_factory
        )
        self._runtime_configuration_lock = threading.RLock()
        self._action_catalog_lock = threading.RLock()
        self._job_retry_lock = threading.RLock()
        self._runtime_runner_profiles = self.config.runner_profiles
        self._runtime_ai_config = self.config.ai
        self.product_store = ProductStore(
            product_db_path or self.store.root / "bluefire-product.sqlite3"
        )
        self._catalog_snapshot = self._load_action_catalog_snapshot()
        self.registry = self._catalog_snapshot.registry
        self._scenarios = self._load_scenarios()
        self.detection_lab = DetectionLabService(
            product_store=self.product_store,
            run_store=self.store,
            registry=self.registry,
        )
        self.recovered_jobs = self.product_store.recover_interrupted_jobs()
        self.job_controller = RunJobController(
            self.product_store,
            self._execute_job,
            max_workers=2,
            max_pending_jobs=8,
            recover_on_start=False,
        )
        self.cleanup_recovery = self._recover_interrupted_cleanup()
        self.seed_counts = seed_product_metadata(
            self.product_store,
            registry=self.registry,
            config=self.config,
            scenarios=self._scenarios,
        )
        self._refresh_runtime_configuration()
        self._synchronize_run_index()

    def _load_action_catalog_snapshot(
        self,
        generation: int | None = None,
    ) -> ActionCatalogSnapshot:
        stored = self.product_store.get_action_package_catalog_snapshot(generation)
        raw_packages = stored.get("packages")
        if not isinstance(raw_packages, list):
            raise ActionCatalogError("persisted action-package catalog has no package list")
        active: list[ActivatedActionPackage] = []
        ordered_packages = sorted(
            raw_packages,
            key=lambda item: (str(item.get("package_id")) if isinstance(item, Mapping) else ""),
        )
        for row in ordered_packages:
            if not isinstance(row, Mapping):
                raise ActionCatalogError("persisted active action-package row is invalid")
            package_id = row.get("package_id")
            if not isinstance(package_id, str):
                raise ActionCatalogError("persisted active action-package ID is invalid")
            activation = row.get("verified_activation")
            activation_generation = row.get("activation_generation")
            if activation is None:
                raise ActionCatalogError(
                    f"active action package {package_id} has no verified activation"
                )
            if (
                isinstance(activation_generation, bool)
                or not isinstance(activation_generation, int)
                or activation_generation < 1
            ):
                raise ActionCatalogError(
                    f"active action package {package_id} has an invalid activation generation"
                )
            active.append(
                ActivatedActionPackage(
                    generation=activation_generation,
                    activation=activation,
                )
            )
        return ActionCatalogSnapshot.compose(
            self._built_in_registry,
            generation=int(stored["generation"]),
            catalog_digest=str(stored["catalog_digest"]),
            active_packages=active,
        )

    def _refresh_action_catalog(self) -> ActionCatalogSnapshot:
        snapshot = self._load_action_catalog_snapshot()
        self._catalog_snapshot = snapshot
        self.registry = snapshot.registry
        detection_lab = getattr(self, "detection_lab", None)
        if detection_lab is not None:
            detection_lab.registry = snapshot.registry
        return snapshot

    def _action_catalog_boundary(
        self,
        expected: Mapping[str, Any] | None = None,
    ) -> ActionCatalogSnapshot:
        snapshot = self._refresh_action_catalog()
        if expected is None:
            return snapshot
        if (
            expected.get("generation") != snapshot.generation
            or expected.get("catalog_digest") != snapshot.catalog_digest
            or expected.get("authority_digest") != snapshot.authority.get("authority_digest")
        ):
            raise ProductStoreError(
                "action-package catalog changed after review; submit a new Execute request"
            )
        return snapshot

    def _historical_action_catalog(
        self,
        authority: Mapping[str, Any] | None,
    ) -> tuple[ActionCatalogSnapshot, Mapping[str, Any] | None]:
        """Reconstruct one immutable authority without making it active again."""

        if authority is None:
            # Pre-package execution workspaces could only reference built-ins.
            return self._load_action_catalog_snapshot(0), None
        generation = authority.get("generation")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
            raise ProductStoreError("historical action-package catalog generation is invalid")
        snapshot = self._load_action_catalog_snapshot(generation)
        if snapshot.to_dict() != dict(authority):
            raise ProductStoreError("historical action-package catalog authority changed")
        return snapshot, dict(authority)

    @staticmethod
    def _run_catalog_authority(
        run: Mapping[str, Any],
    ) -> Mapping[str, Any] | None:
        policy = run.get("policy")
        preflight = policy.get("preflight") if isinstance(policy, Mapping) else None
        authority = preflight.get("catalog_authority") if isinstance(preflight, Mapping) else None
        if authority is not None and not isinstance(authority, Mapping):
            raise ProductStoreError("run action-package catalog authority is invalid")
        return dict(authority) if isinstance(authority, Mapping) else None

    def catalog(self) -> Mapping[str, Any]:
        with self._action_catalog_lock, self.product_store.action_package_catalog_lease():
            snapshot = self._action_catalog_boundary()
            behaviors = [item.to_dict() for item in snapshot.registry.behaviors]
            actions = [item.to_dict() for item in snapshot.registry.actions]
        runtime_ai = self._runtime_ai()
        runtime_profiles = tuple(snapshot.profile(profile) for profile in self._runner_profiles())
        providers = []
        for provider in runtime_ai.providers:
            metadata = ai_runtime_metadata(
                runtime_ai,
                autonomy=self.config.autonomy,
                provider_id=provider.id,
            )
            providers.append(self._provider_metadata(metadata))
        return {
            "schema_version": "bluefire.catalog-response.v1",
            "modes": [mode.value for mode in ExecutionMode],
            "ai": {
                "enabled": self.config.ai_enabled,
                "autonomy": self.config.autonomy.value,
                "autonomy_levels": [level.value for level in AutonomyLevel],
                "independent_of_mode": True,
                "authority": "proposal_only",
                "active_provider": runtime_ai.active_provider,
                "fallback_provider": runtime_ai.fallback_provider,
                "providers": providers,
            },
            "behaviors": behaviors,
            "actions": actions,
            "runner_profiles": [profile.to_dict() for profile in runtime_profiles],
            "action_package_catalog": snapshot.to_dict(),
            "product_state": {
                "storage": "sqlite",
                "schema_version": self.product_store.schema_version,
                "seeded": dict(self.seed_counts),
                "restart_recovery": {
                    "runs": self.recovered_runs,
                    "jobs": self.recovered_jobs,
                    "cleanup": dict(self.cleanup_recovery),
                },
            },
        }

    @staticmethod
    def _sanitized_action_package(record: Mapping[str, Any]) -> dict[str, Any]:
        result = dict(record)
        result.pop("canonical_envelope_bytes", None)
        result.pop("canonical_content_bytes", None)
        return result

    def action_packages(self) -> Mapping[str, Any]:
        """Return the audited package, publisher-trust, and active-catalog inventory."""

        with self._action_catalog_lock, self.product_store.action_package_catalog_lease():
            snapshot = self._action_catalog_boundary()
            packages = [
                self._sanitized_action_package(item)
                for item in self.product_store.list_action_packages()
            ]
            publishers = self.product_store.list_trusted_action_package_publishers()
            activation_events = self.product_store.list_action_package_activation_events()
        return {
            "schema_version": "bluefire.action-package-inventory.v1",
            "packages": packages,
            "publishers": publishers,
            "catalog": snapshot.to_dict(),
            "activation_events": activation_events,
            "execution_boundary": "signed-reviewed-opcodes-only",
        }

    def action_package(
        self,
        package_id: str,
        *,
        version: str | None = None,
    ) -> Mapping[str, Any]:
        try:
            package = self._sanitized_action_package(
                self.product_store.get_action_package(package_id, version)
            )
            versions = [
                self._sanitized_action_package(item)
                for item in self.product_store.list_action_package_versions(package_id)
            ]
            events = self.product_store.list_action_package_lifecycle_events(package_id)
        except ProductStoreError as exc:
            raise APIError(
                HTTPStatus.NOT_FOUND,
                "action_package_not_found",
                "The action package or version was not found.",
                [str(exc)],
            ) from exc
        return {
            "schema_version": "bluefire.action-package-detail.v1",
            "package": package,
            "versions": versions,
            "lifecycle_events": events,
        }

    def trust_action_package_publisher(
        self,
        request: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        required = {
            "publisher_id",
            "key_id",
            "public_key",
            "provenance",
            "trusted_by",
        }
        if set(request) != required or not isinstance(request.get("provenance"), Mapping):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "action_package_trust_invalid",
                "Publisher trust requires exact publisher/key/public-key/provenance/operator fields.",
            )
        try:
            public_key = request["public_key"]
            if isinstance(public_key, str):
                if re.fullmatch(r"[A-Za-z0-9_-]{43}", public_key) is None:
                    raise ActionPackageError(
                        "publisher public key must be canonical unpadded base64url"
                    )
                try:
                    decoded_key = base64.urlsafe_b64decode(public_key + "=")
                except (ValueError, binascii.Error) as exc:
                    raise ActionPackageError("publisher public key is invalid") from exc
                if (
                    len(decoded_key) != 32
                    or base64.urlsafe_b64encode(decoded_key).rstrip(b"=").decode("ascii")
                    != public_key
                ):
                    raise ActionPackageError("publisher public key is not canonical")
                public_key = decoded_key
            trust = self.product_store.trust_action_package_publisher(
                publisher_id=request["publisher_id"],
                key_id=request["key_id"],
                public_key=public_key,
                provenance=request["provenance"],
                trusted_by=request["trusted_by"],
            )
        except (
            ActionPackageError,
            ActionPackageConflictError,
            ActionPackageIntegrityError,
            ProductStoreError,
        ) as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "action_package_trust_refused",
                "The publisher key could not be enrolled in local trust.",
                [str(exc)],
            ) from exc
        return {
            "schema_version": "bluefire.action-package-publisher-trust.v1",
            "publisher": trust,
        }

    def transition_action_package_publisher(
        self,
        publisher_id: str,
        key_id: str,
        action: str,
        request: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        if set(request) != {"actor", "reason"} or action not in {"suspend", "revoke"}:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "action_package_trust_invalid",
                "Trust suspension/revocation requires only actor and reason.",
            )
        with self._action_catalog_lock, self.product_store.action_package_catalog_lease():
            self._action_catalog_boundary()
            try:
                if action == "suspend":
                    trust = self.product_store.suspend_action_package_publisher(
                        publisher_id,
                        key_id,
                        suspended_by=request["actor"],
                        reason=request["reason"],
                    )
                else:
                    trust = self.product_store.revoke_action_package_publisher(
                        publisher_id,
                        key_id,
                        revoked_by=request["actor"],
                        reason=request["reason"],
                    )
                catalog = self._refresh_action_catalog()
            except (
                ActionPackageConflictError,
                ActionPackageIntegrityError,
                ProductStoreError,
            ) as exc:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "action_package_trust_refused",
                    "The publisher trust transition was refused.",
                    [str(exc)],
                ) from exc
        return {
            "schema_version": "bluefire.action-package-publisher-trust.v1",
            "publisher": trust,
            "catalog": catalog.to_dict(),
            "active_packages_deactivated": True,
        }

    def _action_package_occupied_ids(
        self,
        *,
        excluding_package_id: str,
    ) -> tuple[set[str], set[str]]:
        behavior_ids = set(self._built_in_registry.behavior_ids)
        action_ids = set(self._built_in_registry.action_ids)
        for item in self.product_store.list_action_packages():
            if item.get("package_id") == excluding_package_id:
                continue
            manifest = item.get("manifest")
            if not isinstance(manifest, Mapping):
                raise ProductStoreError("installed action-package manifest is invalid")
            raw_behaviors = manifest.get("behavior_ids")
            raw_actions = manifest.get("action_ids")
            if not isinstance(raw_behaviors, list) or not isinstance(raw_actions, list):
                raise ProductStoreError("installed action-package ID inventory is invalid")
            behavior_ids.update(str(value) for value in raw_behaviors)
            action_ids.update(str(value) for value in raw_actions)
        return behavior_ids, action_ids

    def install_action_package(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        if set(request) != {"envelope", "installed_by"} or not isinstance(
            request.get("envelope"), Mapping
        ):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "action_package_install_invalid",
                "Package installation requires only a signed envelope and installed_by.",
            )
        try:
            envelope_bytes = canonical_json_bytes(dict(request["envelope"]))
            signers = self.product_store.trusted_action_package_signers()
            audited = audit_action_package(envelope_bytes, trusted_signers=signers)
            occupied_behaviors, occupied_actions = self._action_package_occupied_ids(
                excluding_package_id=audited.manifest.package_id
            )
            verified = verify_action_package(
                envelope_bytes,
                trusted_signers=signers,
                bluefire_version=None,
                platform=None,
                occupied_behavior_ids=occupied_behaviors,
                occupied_action_ids=occupied_actions,
            )
            package = self.product_store.install_action_package(
                verified,
                installed_by=request["installed_by"],
                occupied_behavior_ids=occupied_behaviors,
                occupied_action_ids=occupied_actions,
            )
        except (
            ActionPackageError,
            ActionPackageConflictError,
            ActionPackageIntegrityError,
            ProductStoreError,
            TypeError,
            ValueError,
        ) as exc:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "action_package_install_refused",
                "The signed action package could not be installed.",
                [str(exc)],
            ) from exc
        return {
            "schema_version": "bluefire.action-package-install.v1",
            "package": self._sanitized_action_package(package),
            "catalog_changed": False,
            "activation_required": True,
        }

    def activate_action_package(
        self,
        package_id: str,
        version: str,
        request: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        if set(request) != {"runner_profile_id", "activated_by", "reason"}:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "action_package_activation_invalid",
                "Activation requires runner_profile_id, activated_by, and reason.",
            )
        with self._action_catalog_lock, self.product_store.action_package_catalog_lease():
            before = self._action_catalog_boundary()
            try:
                profile = self._profile(request.get("runner_profile_id"), ExecutionMode.EXECUTE)
                if profile is None:
                    raise ProductStoreError("activation requires an explicit Execute profile")
                runner, _sandbox = self.runner_factory(profile)
                inventory = runner.inventory()
                identity = runner_transport_identity(runner, inventory)
                activation = self.product_store.prepare_action_package_activation(
                    package_id,
                    version,
                    runner_inventory=inventory,
                    runner_identity_digest=content_hash(identity),
                )
                unavailable_opcodes = sorted(
                    {
                        binding.opcode
                        for binding in activation.opcode_bindings
                        if binding.opcode not in profile.enabled_actions
                        or binding.opcode in profile.blocked_actions
                    }
                )
                if unavailable_opcodes:
                    raise RunnerContractError(
                        "selected Execute profile cannot dispatch every package opcode"
                    )
                package = self.product_store.activate_action_package(
                    activation,
                    activated_by=request["activated_by"],
                    reason=request["reason"],
                )
                after = self._refresh_action_catalog()
            except (RunnerContractError, RunnerTransportError, OSError) as exc:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "action_package_activation_refused",
                    "The package failed exact catalog and authenticated-runner activation.",
                ) from exc
            except (
                ActionPackageConflictError,
                ActionPackageIntegrityError,
                ProductStoreError,
                TypeError,
                ValueError,
            ) as exc:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "action_package_activation_refused",
                    "The package failed exact catalog and authenticated-runner activation.",
                    [str(exc)],
                ) from exc
        previous = next(
            (item for item in before.packages if item.get("package_id") == package_id),
            None,
        )
        return {
            "schema_version": "bluefire.action-package-activation.v1",
            "operation": "upgrade" if previous is not None else "activation",
            "package": self._sanitized_action_package(package),
            "catalog_before": dict(before.authority),
            "catalog": after.to_dict(),
            "runner_identity_digest": activation.runner_identity_digest,
            "runner_inventory_digest": activation.runner_inventory_digest,
        }

    def deactivate_action_package(
        self,
        package_id: str,
        version: str,
        request: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        required = {
            "package_digest",
            "expected_catalog_generation",
            "expected_catalog_digest",
            "deactivated_by",
            "reason",
        }
        if set(request) != required:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "action_package_deactivation_invalid",
                "Deactivation requires the exact package and catalog identity plus operator reason.",
            )
        with self._action_catalog_lock, self.product_store.action_package_catalog_lease():
            self._action_catalog_boundary()
            try:
                package = self.product_store.deactivate_action_package(
                    package_id,
                    version,
                    request["package_digest"],
                    expected_catalog_generation=request["expected_catalog_generation"],
                    expected_catalog_digest=request["expected_catalog_digest"],
                    deactivated_by=request["deactivated_by"],
                    reason=request["reason"],
                )
                catalog = self._refresh_action_catalog()
            except (
                ActionPackageConflictError,
                ActionPackageIntegrityError,
                ProductStoreError,
            ) as exc:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "action_package_deactivation_refused",
                    "The exact active package could not be deactivated.",
                    [str(exc)],
                ) from exc
        return {
            "schema_version": "bluefire.action-package-deactivation.v1",
            "package": self._sanitized_action_package(package),
            "catalog": catalog.to_dict(),
        }

    def remove_action_package(
        self,
        package_id: str,
        version: str,
        request: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        required = {
            "package_digest",
            "expected_catalog_generation",
            "expected_catalog_digest",
            "removed_by",
            "reason",
        }
        if set(request) != required:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "action_package_removal_invalid",
                "Removal requires the exact immutable package/catalog identity and operator reason.",
            )
        with self._action_catalog_lock, self.product_store.action_package_catalog_lease():
            self._action_catalog_boundary()
            try:
                package = self.product_store.remove_action_package(
                    package_id,
                    version,
                    request["package_digest"],
                    expected_catalog_generation=request["expected_catalog_generation"],
                    expected_catalog_digest=request["expected_catalog_digest"],
                    removed_by=request["removed_by"],
                    reason=request["reason"],
                )
                catalog = self._refresh_action_catalog()
            except (
                ActionPackageConflictError,
                ActionPackageIntegrityError,
                ProductStoreError,
            ) as exc:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "action_package_removal_refused",
                    "The exact immutable package version could not be removed.",
                    [str(exc)],
                ) from exc
        return {
            "schema_version": "bluefire.action-package-removal.v1",
            "package": self._sanitized_action_package(package),
            "catalog": catalog.to_dict(),
            "historical_audit_bytes_retained": True,
        }

    def scenarios(self) -> Mapping[str, Any]:
        scenarios = []
        saved_scenarios = sorted(
            self.product_store.list_scenarios(),
            key=lambda item: str(item.get("scenario_id", "")),
        )
        for saved in saved_scenarios:
            document = saved.get("document")
            if not isinstance(document, Mapping):
                raise ProductStoreError("saved scenario document is invalid")
            scenario = ScenarioDefinition.from_mapping(document)
            self.registry.validate_scenario(scenario)
            scenarios.append(scenario.to_dict())
        return {"schema_version": "bluefire.scenario-list.v1", "scenarios": scenarios}

    def draft_ai_graph(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        """Return one validated, normalized, deliberately unsaved scenario draft."""

        allowed_fields = {"objective", "provider_id", "max_nodes", "max_edges"}
        if set(request) - allowed_fields or "objective" not in request:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "ai_draft_request_invalid",
                "AI draft requests require objective and optional provider_id/max_nodes/max_edges only.",
            )
        objective = request.get("objective")
        if not isinstance(objective, str):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "ai_draft_request_invalid",
                "AI draft objective must be text.",
            )
        provider_value = request.get("provider_id")
        if provider_value is not None and (
            not isinstance(provider_value, str)
            or not provider_value.strip()
            or provider_value != provider_value.strip()
        ):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "ai_draft_provider_invalid",
                "provider_id must be a configured provider identifier or null.",
            )
        provider_id = self._resolve_ai_provider_id(provider_value)
        try:
            draft_request = AIGraphDraftRequest.from_registry(
                objective=objective,
                registry=self.registry,
                max_nodes=request.get("max_nodes", 8),
                max_edges=request.get("max_edges", 16),
            )
        except AIDraftError as exc:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "ai_draft_request_invalid",
                "AI graph draft request is invalid.",
                [str(exc)],
            ) from exc
        try:
            provider = self.ai_draft_provider_factory(self._runtime_ai(), provider_id)
            provider_result = provider.draft(draft_request)
            if provider_result.requested_provider_id != provider_id:
                raise AIDraftError("draft provider identity does not match the request")
            result = normalize_ai_graph_draft(
                request=draft_request,
                provider_result=provider_result,
                registry=self.registry,
            )
            return result.to_dict()
        except AIDraftError as exc:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "ai_draft_rejected",
                "AI graph output could not be normalized into a registered typed scenario.",
                [str(exc)],
            ) from exc

    def settings(self) -> Mapping[str, Any]:
        """List secret-safe local product settings."""

        return {
            "schema_version": "bluefire.setting-list.v1",
            "settings": self.product_store.list_settings(),
        }

    def upsert_setting(self, key: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        """Create or replace one setting through the ProductStore safety boundary."""

        stable_key = _management_identifier(key, "setting key")
        if set(request) != {"value"}:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "setting_request_invalid",
                "A setting update requires only value.",
            )
        if stable_key != "ui.preferences":
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "setting_key_unsupported",
                "Only the versioned ui.preferences setting is supported.",
            )
        value = request["value"]
        if not isinstance(value, Mapping) or set(value) != {
            "schema_version",
            "theme",
            "effect_mode",
            "autonomy",
        }:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "setting_value_invalid",
                "UI preferences require only schema_version, theme, effect_mode, and autonomy.",
            )
        if (
            value.get("schema_version") != "bluefire.ui-preferences.v1"
            or value.get("theme") not in {"dark", "light", "system"}
            or value.get("effect_mode") not in {"simulate", "execute"}
            or value.get("autonomy") not in {"off", "assist", "auto"}
        ):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "setting_value_invalid",
                "UI preferences contain an unsupported schema, theme, mode, or autonomy.",
            )
        canonical_value = {
            "schema_version": "bluefire.ui-preferences.v1",
            "theme": value["theme"],
            "effect_mode": value["effect_mode"],
            "autonomy": value["autonomy"],
        }
        try:
            setting = self.product_store.set_setting(stable_key, canonical_value)
        except ProductStoreError as exc:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "setting_invalid",
                "The setting was rejected.",
                [str(exc)],
            ) from exc
        return {"schema_version": "bluefire.setting.v1", "setting": setting}

    def scenario_versions(self) -> Mapping[str, Any]:
        """List the active durable version of every saved scenario."""

        return {
            "schema_version": "bluefire.scenario-version-list.v1",
            "scenarios": self.product_store.list_scenarios(),
        }

    def save_scenario_version(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        """Validate and save one content-addressed scenario version."""

        if set(request) != {"scenario"} or not isinstance(request.get("scenario"), Mapping):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "scenario_version_request_invalid",
                "A scenario-version update requires only a scenario object.",
            )
        try:
            scenario = ScenarioDefinition.from_mapping(request["scenario"])
            self.registry.validate_scenario(scenario)
            saved = self.product_store.save_scenario(scenario.to_dict())
        except (ContractError, ProductStoreError, RegistryError) as exc:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "scenario_version_invalid",
                "The scenario version was rejected.",
                [str(exc)],
            ) from exc
        return {"schema_version": "bluefire.scenario-version.v1", "scenario": saved}

    def scenario_version(
        self,
        scenario_id: str,
        *,
        version: int | None = None,
    ) -> Mapping[str, Any]:
        """Get an active or exact saved scenario version."""

        stable_id = _management_identifier(scenario_id, "scenario ID")
        if version is not None and (
            isinstance(version, bool)
            or not isinstance(version, int)
            or not 1 <= version <= 2**31 - 1
        ):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "scenario_version_invalid",
                "Scenario version must be a positive 32-bit integer.",
            )
        try:
            saved = self.product_store.get_scenario(stable_id, version)
        except ProductStoreError as exc:
            raise APIError(
                HTTPStatus.NOT_FOUND,
                "scenario_version_not_found",
                "Scenario version was not found.",
            ) from exc
        return {"schema_version": "bluefire.scenario-version.v1", "scenario": saved}

    def resources(self, kind: str) -> Mapping[str, Any]:
        """List one explicitly allowlisted resource kind."""

        stable_kind = _managed_resource_kind(kind)
        response: dict[str, Any] = {
            "schema_version": "bluefire.resource-list.v1",
            "kind": stable_kind,
            "resources": self.product_store.list_resources(stable_kind),
        }
        if stable_kind == "plugin":
            response["inventory"] = self._plugin_inventory()
        return response

    def resource(self, kind: str, resource_id: str) -> Mapping[str, Any]:
        """Get one explicitly allowlisted resource."""

        stable_kind = _managed_resource_kind(kind)
        stable_id = _management_identifier(resource_id, f"{stable_kind} ID")
        try:
            resource = self.product_store.get_resource(stable_kind, stable_id)
        except ProductStoreError as exc:
            raise APIError(
                HTTPStatus.NOT_FOUND,
                "resource_not_found",
                "Resource was not found.",
            ) from exc
        return {"schema_version": "bluefire.resource.v1", "resource": resource}

    def detection_health(self) -> Mapping[str, Any]:
        """Report honest parser/compiler and persistence readiness."""

        return self.detection_lab.health()

    def detection_candidates(self) -> Mapping[str, Any]:
        """List strictly rehydrated persisted detection candidates."""

        return self.detection_lab.candidates()

    def detection_candidate(self, candidate_id: str) -> Mapping[str, Any]:
        """Get one strictly rehydrated persisted detection candidate."""

        return self.detection_lab.candidate(candidate_id)

    def upsert_detection_hypothesis(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        """Create one immutable candidate definition or return its exact duplicate."""

        return self.detection_lab.upsert_hypothesis(request)

    def clone_detection_candidate(
        self, candidate_id: str, request: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Clone a candidate definition into a new hypothesis revision."""

        return self.detection_lab.clone(candidate_id, request)

    def tune_detection_candidate(
        self, candidate_id: str, request: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Tune rule semantics into a new hypothesis revision."""

        return self.detection_lab.tune(candidate_id, request)

    def compare_detection_candidates(
        self, candidate_id: str, request: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Compare two immutable definitions and their lifecycle evidence."""

        return self.detection_lab.compare(candidate_id, request)

    def parse_detection_candidate(
        self, candidate_id: str, request: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Apply the candidate language's honest parse or compile semantics."""

        return self.detection_lab.parse(candidate_id, request)

    def exercise_detection_fixtures(
        self, candidate_id: str, request: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Exercise a parsed candidate against bounded malicious fixtures."""

        return self.detection_lab.exercise_fixtures(candidate_id, request)

    def exercise_detection_observed(
        self, candidate_id: str, request: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Exercise against verified observed evidence from an immutable run."""

        return self.detection_lab.exercise_observed(candidate_id, request)

    def evaluate_detection_benign(
        self, candidate_id: str, request: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Evaluate an exercised candidate against bounded benign fixtures."""

        return self.detection_lab.evaluate_benign(candidate_id, request)

    def reject_detection_candidate(
        self, candidate_id: str, request: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Explicitly reject a non-terminal candidate with a bounded reason."""

        return self.detection_lab.reject(candidate_id, request)

    def save_resource(
        self,
        kind: str,
        resource_id: str,
        request: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Create or replace one secret-safe resource document."""

        stable_kind = _managed_resource_kind(kind)
        stable_id = _management_identifier(resource_id, f"{stable_kind} ID")
        if stable_kind == "detection":
            raise APIError(
                HTTPStatus.CONFLICT,
                "detection_lifecycle_required",
                "Detection candidates must use the explicit Detection Lab lifecycle routes.",
            )
        if stable_kind == "plugin":
            return self._save_plugin_resource(stable_id, request)
        if (
            "document" not in request
            or not isinstance(request.get("document"), Mapping)
            or not set(request).issubset({"document", "status"})
        ):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "resource_request_invalid",
                "A resource update requires document and optional status only.",
            )
        default_status = "draft" if stable_kind == "research_source" else "ready"
        status = request.get("status", default_status)
        if (
            not isinstance(status, str)
            or not 1 <= len(status) <= 64
            or not _MANAGEMENT_STATUS.fullmatch(status)
        ):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "resource_status_invalid",
                "Resource status must be a stable lowercase identifier of at most 64 characters.",
            )
        if stable_kind in _RUNTIME_RESOURCE_KINDS and status in {"active", "inactive"}:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "resource_activation_required",
                "Runtime resources must use the explicit activation or deactivation route.",
            )
        document: Mapping[str, Any] = request["document"]
        if stable_kind == "research_source":
            try:
                existing_source = self.product_store.get_resource(stable_kind, stable_id)
            except ProductStoreError:
                existing_source = None
            if existing_source is not None and existing_source.get("document") != document:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "research_source_integrity_conflict",
                    "The research source identity is immutable; promote the exact draft or use a new ID.",
                    ["research source documents are immutable; use a new research source ID"],
                )
            try:
                source = ResearchSource.from_mapping(document, "managed research source")
                if source.id != stable_id:
                    raise ResearchSourceError(
                        "managed research source ID does not match its resource ID"
                    )
                document = source.to_dict()
            except ResearchSourceError as exc:
                raise APIError(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "research_source_invalid",
                    "The pinned research source metadata was rejected.",
                    [str(exc)],
                ) from exc
        try:
            if stable_kind in _RUNTIME_RESOURCE_KINDS:
                with self._runtime_configuration_lock:
                    try:
                        current = self.product_store.get_resource(stable_kind, stable_id)
                    except ProductStoreError:
                        current = None
                    if current is not None and current.get("status") == "active":
                        raise APIError(
                            HTTPStatus.CONFLICT,
                            "resource_deactivation_required",
                            "Deactivate an active runtime resource before editing it.",
                        )
                    persisted_status = (
                        "inactive"
                        if current is not None and current.get("status") == "inactive"
                        else status
                    )
                    resource = self.product_store.save_resource(
                        stable_kind,
                        stable_id,
                        document,
                        status=persisted_status,
                    )
            else:
                resource = self.product_store.save_resource(
                    stable_kind,
                    stable_id,
                    document,
                    status=status,
                )
        except ResearchSourceIntegrityError as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "research_source_integrity_conflict",
                "The research source identity is immutable; promote the exact draft or use a new ID.",
                [str(exc)],
            ) from exc
        except ProductStoreError as exc:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "resource_invalid",
                "The resource was rejected.",
                [str(exc)],
            ) from exc
        return {"schema_version": "bluefire.resource.v1", "resource": resource}

    def activate_resource(
        self,
        kind: str,
        resource_id: str,
        request: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Validate and atomically publish one persisted runtime resource."""

        stable_kind = self._runtime_resource_kind(kind)
        stable_id = _management_identifier(resource_id, f"{stable_kind} ID")
        self._empty_runtime_action(request)
        if stable_kind == "plugin":
            return self._activate_plugin(stable_id)
        with self._runtime_configuration_lock:
            resource = self._runtime_resource(stable_kind, stable_id)
            document = resource.get("document")
            if not isinstance(document, Mapping):
                raise APIError(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "resource_activation_invalid",
                    "The runtime resource document is invalid.",
                )
            try:
                if stable_kind == "runner_profile":
                    self._validated_runner_profile(document, stable_id)
                else:
                    provider = self._validated_ai_provider(document, stable_id)
                    fallback = self.config.ai.fallback
                    if (
                        provider.id == fallback.id
                        and provider.kind is not AIProviderKind.DETERMINISTIC
                    ):
                        raise ConfigError(
                            "the deterministic fallback provider cannot become remote"
                        )
            except (ContractError, RegistryError) as exc:
                raise APIError(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "resource_activation_invalid",
                    "The runtime resource failed activation validation.",
                    [str(exc)],
                ) from exc

            try:
                activated = self.product_store.save_resource(
                    stable_kind,
                    stable_id,
                    document,
                    status="active",
                )
                if stable_kind == "model_provider":
                    for other in self.product_store.list_resources("model_provider"):
                        other_id = other.get("id")
                        if (
                            other_id != stable_id
                            and other.get("status") == "active"
                            and isinstance(other_id, str)
                            and isinstance(other.get("document"), Mapping)
                        ):
                            self.product_store.save_resource(
                                "model_provider",
                                other_id,
                                other["document"],
                                status="inactive",
                            )
            except ProductStoreError as exc:
                raise APIError(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "resource_activation_invalid",
                    "The runtime resource could not be activated.",
                    [str(exc)],
                ) from exc
            self._refresh_runtime_configuration()
        return {
            "schema_version": "bluefire.resource-activation.v1",
            "resource": activated,
        }

    def deactivate_resource(
        self,
        kind: str,
        resource_id: str,
        request: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Persistently withdraw one runtime resource from normal selection."""

        stable_kind = self._runtime_resource_kind(kind)
        stable_id = _management_identifier(resource_id, f"{stable_kind} ID")
        self._empty_runtime_action(request)
        if stable_kind == "plugin":
            return self._deactivate_plugin(stable_id)
        if stable_kind == "model_provider" and stable_id == self.config.ai.fallback_provider:
            raise APIError(
                HTTPStatus.CONFLICT,
                "resource_required",
                "The deterministic fallback provider cannot be deactivated.",
            )
        with self._runtime_configuration_lock:
            resource = self._runtime_resource(stable_kind, stable_id)
            document = resource.get("document")
            if not isinstance(document, Mapping):
                raise APIError(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "resource_deactivation_invalid",
                    "The runtime resource document is invalid.",
                )
            try:
                deactivated = self.product_store.save_resource(
                    stable_kind,
                    stable_id,
                    document,
                    status="inactive",
                )
            except ProductStoreError as exc:
                raise APIError(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "resource_deactivation_invalid",
                    "The runtime resource could not be deactivated.",
                    [str(exc)],
                ) from exc
            self._refresh_runtime_configuration()
        return {
            "schema_version": "bluefire.resource-activation.v1",
            "resource": deactivated,
        }

    def probe_runner_profile(
        self,
        resource_id: str,
        request: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Probe one stored runner profile through its env-reference-only transport."""

        stable_id = _management_identifier(resource_id, "runner_profile ID")
        self._empty_runtime_action(request)
        resource = self._runtime_resource("runner_profile", stable_id)
        document = resource.get("document")
        if not isinstance(document, Mapping):
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "runner_profile_invalid",
                "The runner profile document is invalid.",
            )
        try:
            profile = self._validated_runner_profile(document, stable_id)
        except (ContractError, RegistryError) as exc:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "runner_profile_invalid",
                "The runner profile failed validation.",
                [str(exc)],
            ) from exc

        unavailable: Mapping[str, Any] = {
            "schema_version": "bluefire.runner-probe.v1",
            "profile_id": stable_id,
            "version": None,
            "platform": None,
            "actions": [],
            "health": {
                "state": "unavailable",
                "message": "Runner inventory could not be obtained.",
            },
        }
        try:
            runner = self._runner_probe_transport(profile)
            inventory = runner.inventory()
        except (RunnerContractError, RunnerTransportError, OSError):
            return unavailable
        if not isinstance(inventory, Mapping):
            return unavailable
        return self._sanitized_runner_probe(profile, inventory)

    def runner_status(self, *, profile_id: str | None = None) -> Mapping[str, Any]:
        """Return path-free managed-runner state without starting or bootstrapping it."""

        selected = self._runner_lifecycle_profile(profile_id)
        try:
            return self.runner_lifecycle.status(
                profile_id=selected.id if selected is not None else None
            )
        except RunnerLifecycleError as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "runner_lifecycle_unavailable",
                "Managed runner status could not be verified.",
                [str(exc)],
            ) from exc

    def bootstrap_runner(
        self,
        *,
        profile_id: str | None = None,
        allow_upgrade: bool = False,
    ) -> Mapping[str, Any]:
        """Explicitly install/verify the packaged runner and local enrollment."""

        if type(allow_upgrade) is not bool:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "runner_bootstrap_invalid",
                "Runner upgrade confirmation must be boolean.",
            )
        self._runner_lifecycle_profile(profile_id)
        profiles = tuple(
            profile for profile in self._runner_profiles() if profile.mode is ExecutionMode.EXECUTE
        )
        if not profiles:
            raise APIError(
                HTTPStatus.CONFLICT,
                "runner_profile_unavailable",
                "No Execute runner profile is available for enrollment.",
            )
        try:
            return self.runner_lifecycle.bootstrap(
                allowed_profile_ids=tuple(profile.id for profile in profiles),
                allow_upgrade=allow_upgrade,
            )
        except RunnerLifecycleError as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "runner_bootstrap_refused",
                "Managed runner bootstrap was refused.",
                [str(exc)],
            ) from exc

    def start_runner(self, *, profile_id: str | None = None) -> Mapping[str, Any]:
        selected = self._runner_lifecycle_profile(profile_id)
        try:
            return self.runner_lifecycle.start(
                profile_id=selected.id if selected is not None else None
            )
        except RunnerLifecycleError as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "runner_start_refused",
                "Managed runner start was refused.",
                [str(exc)],
            ) from exc

    def stop_runner(self, *, profile_id: str | None = None) -> Mapping[str, Any]:
        selected = self._runner_lifecycle_profile(profile_id)
        try:
            return self.runner_lifecycle.stop(
                profile_id=selected.id if selected is not None else None
            )
        except RunnerLifecycleError as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "runner_stop_refused",
                "Managed runner stop was refused.",
                [str(exc)],
            ) from exc

    def revoke_runner(self) -> Mapping[str, Any]:
        try:
            return self.runner_lifecycle.revoke()
        except RunnerLifecycleError as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "runner_revoke_refused",
                "Managed runner trust revocation was refused.",
                [str(exc)],
            ) from exc

    def remove_runner(self, *, confirm_runner_id: str) -> Mapping[str, Any]:
        if confirm_runner_id != RUNNER_ID:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "runner_remove_confirmation_invalid",
                "Runner removal requires the exact managed runner ID.",
            )
        try:
            return self.runner_lifecycle.remove(confirm_runner_id=confirm_runner_id)
        except RunnerLifecycleError as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "runner_remove_refused",
                "Managed runner removal was refused.",
                [str(exc)],
            ) from exc

    def validate(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            scenario = self._scenario(request)
            self.registry.validate_scenario(scenario)
        except (ContractError, RegistryError, KeyError, TypeError, ValueError) as exc:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "scenario_invalid",
                "Scenario validation failed.",
                [str(exc)],
            ) from exc
        return {
            "schema_version": "bluefire.validation.v1",
            "valid": True,
            "issues": [],
            "scenario": scenario.to_dict(),
            "graph": {
                "nodes": [
                    {
                        "id": step.id,
                        "behavior_id": step.behavior_id,
                        "alternates": list(step.alternates),
                    }
                    for step in scenario.steps
                ],
                "edges": [edge.to_dict() for edge in scenario.edges],
            },
        }

    def preflight(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        with self._action_catalog_lock:
            expected = request.get(_ACTION_CATALOG_AUTHORITY_KEY)
            if expected is not None and not isinstance(expected, Mapping):
                raise APIError(
                    HTTPStatus.BAD_REQUEST,
                    "action_catalog_binding_invalid",
                    "The action-package catalog binding is invalid.",
                )
            self._action_catalog_boundary(expected)
            return self._preflight_locked(request)

    def _preflight_locked(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        scenario = self._scenario_or_api_error(request)
        mode = self._mode(request)
        profile = self._profile(request.get("runner_profile_id"), mode)
        autonomy, provider = self._ai_context(request)
        action_implementations = self._action_implementations(request, mode=mode)
        approval = self._approval(request, required=False)
        runner: RunnerTransport | None = None
        runner_problem: str | None = None
        runner_readiness: Mapping[str, Any] | None = None
        if mode is ExecutionMode.EXECUTE:
            try:
                if profile is None:
                    raise RunnerContractError("an Execute runner profile must be selected")
                expected_readiness = request.get(_EXECUTE_READINESS_KEY)
                if expected_readiness is not None and not isinstance(expected_readiness, Mapping):
                    raise RunnerReadinessError(
                        "Execute readiness binding is invalid; submit a new Execute request."
                    )
                runner, _sandbox, runner_readiness = self._execute_readiness_boundary(
                    profile,
                    expected=expected_readiness,
                )
            except RunnerReadinessError as exc:
                runner_problem = str(exc)
            except (RunnerContractError, RunnerTransportError, OSError, TypeError, ValueError):
                runner_problem = (
                    "Runner readiness could not be verified; check the selected profile and retry."
                )
        orchestrator = Orchestrator(
            self.registry,
            self.store,
            runner=runner,
            approval_store=self.product_store,
            action_bindings=self._catalog_snapshot.action_bindings,
            catalog_authority=self._catalog_snapshot.to_dict(),
        )
        try:
            report = orchestrator.preflight(
                scenario,
                mode=mode,
                profile=profile,
                autonomy=autonomy,
                ai_provider=provider,
                approval_present=approval is not None,
                action_implementations=action_implementations,
            ).to_dict()
        except OrchestrationError as exc:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "preflight_invalid",
                "The scenario cannot be planned.",
                [str(exc)],
            ) from exc
        problems = list(report["problems"])
        if runner_problem:
            problems = [item for item in problems if "Rust runner transport" not in item]
            problems.append(runner_problem)
        scope_problems = self._scope_problems(request, profile, mode)
        problems.extend(scope_problems)
        report["problems"] = problems
        report["findings"] = problems
        if problems:
            only_approval = problems == ["Explicit operator approval is required."]
            report["status"] = "approval_required" if only_approval else "refused"
            report["ready"] = False
        report["runner_profile"] = profile.id if profile else None
        report["scope"] = request.get("target_scope", {"scope_refs": []})
        report["autonomy"] = autonomy.value
        report["ai_enabled"] = autonomy is not AutonomyLevel.OFF
        report["ai_provider"] = provider
        report["capabilities"] = report["required_capabilities"]
        report["action_implementations"] = {
            str(step["step_id"]): str(step["action_id"])
            for step in report["plan"].get("steps", [])
            if isinstance(step, Mapping) and isinstance(step.get("action_id"), str)
        }
        report["safety_tier"] = self._maximum_tier(scenario)
        report["approval"] = (
            "present"
            if approval
            else ("required" if report["approval_required"] else "not_required")
        )
        report["cleanup"] = {
            "policy": profile.cleanup_policy.value if profile else "simulate_only",
            "action_id": "sandbox.cleanup.v1",
        }
        report["runner_readiness"] = runner_readiness
        if (
            mode is ExecutionMode.EXECUTE
            and profile is not None
            and not scope_problems
            and runner_problem is None
            and runner_readiness is not None
        ):
            target_scope = self._target_scope(request)
            report["approval_binding"] = execution_approval_binding(
                registry=self.registry,
                scenario=scenario,
                plan=report["plan"],
                profile=profile,
                target_scope=target_scope,
                autonomy=autonomy,
                ai_provider=provider,
                runner_readiness=runner_readiness,
                catalog_authority=self._catalog_snapshot.to_dict(),
            )
            report["approval_envelope"] = execution_approval_envelope(
                registry=self.registry,
                scenario=scenario,
                catalog_authority=self._catalog_snapshot.to_dict(),
            )
        else:
            report["approval_binding"] = None
            report["approval_envelope"] = None
        return report

    def run(
        self,
        request: Mapping[str, Any],
        *,
        checkpoint: Callable[[Mapping[str, Any]], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> Mapping[str, Any]:
        with self._action_catalog_lock, self.product_store.action_package_catalog_lease():
            expected = request.get(_ACTION_CATALOG_AUTHORITY_KEY)
            if expected is not None and not isinstance(expected, Mapping):
                raise APIError(
                    HTTPStatus.BAD_REQUEST,
                    "action_catalog_binding_invalid",
                    "The action-package catalog binding is invalid.",
                )
            self._action_catalog_boundary(expected)
            return self._run_locked(
                request,
                checkpoint=checkpoint,
                cancel_event=cancel_event,
            )

    def _run_locked(
        self,
        request: Mapping[str, Any],
        *,
        checkpoint: Callable[[Mapping[str, Any]], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> Mapping[str, Any]:
        scenario = self._scenario_or_api_error(request)
        mode = self._mode(request)
        profile = self._profile(request.get("runner_profile_id"), mode)
        autonomy, provider = self._ai_context(request)
        action_implementations = self._action_implementations(request, mode=mode)
        approval_record = self._stored_approval(request, mode=mode)
        approved_by = (
            str(approval_record["approved_by"])
            if approval_record is not None
            else self._approval(request, required=mode is ExecutionMode.EXECUTE)
        )
        scope_problems = self._scope_problems(request, profile, mode)
        if scope_problems:
            raise APIError(
                HTTPStatus.CONFLICT,
                "scope_refused",
                "Target scope is not authorized.",
                scope_problems,
            )
        runner: RunnerTransport | None = None
        sandbox: Path | None = None
        runner_readiness: Mapping[str, Any] | None = None
        execution_approval_id: str | None = None
        execution_workspace: Path | None = None
        if mode is ExecutionMode.EXECUTE:
            if profile is None:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "profile_required",
                    "Execute requires an explicit runner profile.",
                )
            try:
                expected_readiness = request.get(_EXECUTE_READINESS_KEY)
                if approval_record is not None and not isinstance(expected_readiness, Mapping):
                    raise RunnerReadinessError(
                        "Execute approval lacks runner readiness; submit a new Execute request."
                    )
                if expected_readiness is not None and not isinstance(expected_readiness, Mapping):
                    raise RunnerReadinessError(
                        "Execute readiness binding is invalid; submit a new Execute request."
                    )
                runner, sandbox, runner_readiness = self._execute_readiness_boundary(
                    profile,
                    expected=expected_readiness,
                    for_dispatch=True,
                )
            except (RunnerContractError, RunnerTransportError, OSError) as exc:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "runner_unavailable",
                    "The selected runner is not ready for Execute.",
                    [str(exc)],
                ) from exc
        orchestrator = Orchestrator(
            self.registry,
            self.store,
            runner=runner,
            proposal_provider=self._proposal_provider(autonomy, provider),
            approval_store=self.product_store,
            action_bindings=self._catalog_snapshot.action_bindings,
            catalog_authority=self._catalog_snapshot.to_dict(),
        )
        try:
            resolved_action_implementations = {
                step.step_id: step.action_id
                for step in orchestrator.planner.compile(
                    scenario,
                    mode=mode,
                    profile=profile,
                    autonomy=autonomy,
                    ai_provider=provider,
                    action_implementations=action_implementations,
                ).steps
                if step.action_id is not None
            }
            bound_approval = approval_record or (
                self._bind_and_consume_approval(
                    scenario=scenario,
                    profile=profile,
                    target_scope=self._target_scope(request),
                    autonomy=autonomy,
                    ai_provider=provider,
                    approved_by=approved_by,
                    orchestrator=orchestrator,
                    runner_readiness=runner_readiness,
                    action_implementations=resolved_action_implementations,
                )
                if mode is ExecutionMode.EXECUTE and profile is not None and approved_by is not None
                else None
            )
            if mode is ExecutionMode.EXECUTE:
                if sandbox is None or bound_approval is None:
                    raise OrchestrationError("Execute workspace approval is incomplete")
                sandbox = self._isolated_execution_sandbox(sandbox, bound_approval)
                if runner is None or profile is None:
                    raise OrchestrationError("Execute runner binding is incomplete")
                execution_approval_id = str(bound_approval["approval_id"])
                execution_workspace = sandbox
                self._bind_execution_workspace(
                    approval_record=bound_approval,
                    workspace=sandbox,
                    runner=runner,
                    scenario=scenario,
                    profile=profile,
                    target_scope=self._target_scope(request),
                    autonomy=autonomy,
                    ai_provider=provider,
                    runner_readiness=runner_readiness,
                    action_implementations=resolved_action_implementations,
                    catalog_authority=self._catalog_snapshot.to_dict(),
                )
            tracked_checkpoint = (
                self._execution_checkpoint(execution_approval_id, checkpoint)
                if execution_approval_id is not None
                else checkpoint
            )
            result = orchestrator.run(
                scenario,
                mode=mode,
                profile=profile,
                sandbox_root=sandbox,
                target_scope=(
                    self._target_scope(request) if mode is ExecutionMode.EXECUTE else None
                ),
                approved_by=approved_by,
                approval_record=bound_approval,
                autonomy=autonomy,
                ai_provider=provider,
                action_implementations=resolved_action_implementations,
                runner_readiness=runner_readiness,
                checkpoint=tracked_checkpoint,
                cancel_event=cancel_event,
            )
            if execution_approval_id is not None and execution_workspace is not None:
                self._complete_execution_workspace(
                    execution_approval_id,
                    execution_workspace,
                    result,
                    expected_profile_id=profile.id if profile is not None else None,
                )
            self._index_run(result)
            return result
        except RunnerTaskCancelled as exc:
            if cancel_event is not None and cancel_event.is_set():
                raise JobCancelled("job runner task cancellation was confirmed") from exc
            raise APIError(
                HTTPStatus.CONFLICT,
                "runner_task_cancelled",
                "The runner task was cancelled after its process tree stopped.",
            ) from exc
        except (
            OrchestrationError,
            ProductStoreError,
            RunnerContractError,
            RunnerTransportError,
        ) as exc:
            if execution_approval_id is not None and execution_workspace is not None:
                self._settle_pre_dispatch_refusal(
                    execution_approval_id,
                    execution_workspace,
                    expected_profile_id=profile.id if profile is not None else None,
                )
            raise APIError(
                HTTPStatus.CONFLICT,
                "run_refused",
                "The run was refused before it could complete.",
                [str(exc)],
            ) from exc

    def submit_run(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        """Create a durable background job; Execute waits on a bound review gate."""

        mode = self._mode(request)
        stored_request = dict(request)
        # Browser confirmation is deliberately not accepted as a capability.  The
        # immutable job request is reviewed and approved through ``approve_job``.
        stored_request.pop("approval", None)
        stored_request.pop("approval_request_id", None)
        # This is service-produced, sanitized approval context. A caller cannot
        # nominate its own runner snapshot for a new review.
        stored_request.pop(_EXECUTE_READINESS_KEY, None)
        stored_request.pop(_ACTION_CATALOG_AUTHORITY_KEY, None)
        approval_request: Mapping[str, Any] | None = None
        preflight: Mapping[str, Any] | None = None
        if mode is ExecutionMode.EXECUTE:
            preflight = self.preflight(stored_request)
            problems = [
                str(item)
                for item in preflight.get("problems", [])
                if item != "Explicit operator approval is required."
            ]
            binding = preflight.get("approval_binding")
            runner_readiness = preflight.get("runner_readiness")
            if (
                problems
                or not isinstance(binding, Mapping)
                or not isinstance(runner_readiness, Mapping)
            ):
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "preflight_refused",
                    "The Execute request is not ready for operator review.",
                    problems or ["The exact approval binding could not be created."],
                )
            stored_request[_EXECUTE_READINESS_KEY] = dict(runner_readiness)
            catalog_authority = preflight.get("catalog_authority")
            if not isinstance(catalog_authority, Mapping):
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "preflight_refused",
                    "The Execute request has no exact action-package catalog binding.",
                )
            stored_request[_ACTION_CATALOG_AUTHORITY_KEY] = dict(catalog_authority)
            profile = self._profile(stored_request.get("runner_profile_id"), mode)
            if profile is None:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "profile_required",
                    "Execute requires an explicit runner profile.",
                )
            expires_at = self._approval_review_expires_at()
            intent_digest = content_hash(binding)
            approval_request = self.product_store.create_approval_request(
                run_id="intent-" + intent_digest[7:39],
                state_digest=str(binding["state_digest"]),
                plan_digest=str(binding["plan_digest"]),
                profile_id=str(binding["profile_id"]),
                target_scope_digest=str(binding["target_scope_digest"]),
                maximum_tier=str(binding["maximum_tier"]),
                expires_at=expires_at,
            )
            stored_request["approval_request_id"] = approval_request["approval_id"]
        try:
            queued = self.job_controller.submit(
                "scenario.run",
                stored_request,
                requires_approval=mode is ExecutionMode.EXECUTE,
            )
            job = self.job_controller.snapshot(str(queued["job_id"]))
        except JobQueueFull as exc:
            raise APIError(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "job_capacity_exhausted",
                "The local run queue is at capacity.",
            ) from exc
        return {
            "schema_version": "bluefire.run-job-submission.v1",
            "job": job,
            "approval_request": public_approval_record(approval_request),
            "preflight": preflight,
        }

    def job(self, job_id: str) -> Mapping[str, Any]:
        """Return one durable job plus its nonce-free approval review envelope."""

        try:
            job = self.product_store.get_job(job_id)
        except ProductStoreError as exc:
            raise APIError(HTTPStatus.NOT_FOUND, "job_not_found", "Job was not found.") from exc
        request = job.get("request")
        progress = job.get("progress")
        approval_id = progress.get("approval_request_id") if isinstance(progress, Mapping) else None
        if not isinstance(approval_id, str) and isinstance(request, Mapping):
            approval_id = request.get("approval_request_id")
        approval: Mapping[str, Any] | None = None
        if isinstance(approval_id, str):
            try:
                approval = self.product_store.get_approval_request(approval_id)
            except ProductStoreError as exc:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "job_approval_unavailable",
                    "The job's approval review envelope is unavailable.",
                ) from exc
        return {**job, "approval_request": public_approval_record(approval)}

    def retry_job(self, job_id: str) -> Mapping[str, Any]:
        """Submit a fresh job for one safely settled interrupted scenario run.

        Retry is replacement, never continuation. In particular, an Execute
        retry cannot inherit the original one-time approval capability: it is
        preflighted again by :meth:`submit_run` and waits at a new review gate.
        """

        try:
            source = self.product_store.get_job(job_id)
        except ProductStoreError as exc:
            raise APIError(HTTPStatus.NOT_FOUND, "job_not_found", "Job was not found.") from exc

        try:
            with self._job_retry_lock:
                # Re-read under the retry lock so a concurrent local lifecycle
                # transition cannot be cloned after the eligibility check.
                source = self.product_store.get_job(job_id)
                if source.get("state") != "interrupted":
                    raise ProductStoreError("only an interrupted job can be retried")
                if source.get("kind") != "scenario.run":
                    raise ProductStoreError("only interrupted scenario.run jobs can be retried")
                stored_request = source.get("request")
                if not isinstance(stored_request, Mapping):
                    raise ProductStoreError("interrupted job request is invalid")
                mode = self._mode(stored_request)
                replacement_request = dict(stored_request)
                if mode is ExecutionMode.EXECUTE:
                    self._assert_execute_retry_settled(stored_request)
                    replacement_request.pop("approval", None)
                    replacement_request.pop("approval_request_id", None)

                submission = self.submit_run(replacement_request)
                replacement = submission.get("job")
                if not isinstance(replacement, Mapping) or not isinstance(
                    replacement.get("job_id"), str
                ):
                    raise ProductStoreError("replacement job submission is invalid")

                progress = source.get("progress")
                progress_document = dict(progress) if isinstance(progress, Mapping) else {}
                raw_lineage = progress_document.get("retry_lineage")
                lineage = (
                    [dict(item) for item in raw_lineage if isinstance(item, Mapping)]
                    if isinstance(raw_lineage, list)
                    else []
                )
                lineage.append(
                    {
                        "schema_version": "bluefire.job-retry-lineage.v1",
                        "retry_job_id": replacement["job_id"],
                        "mode": mode.value,
                        "request_digest": content_hash(replacement_request),
                    }
                )
                progress_document["retry_lineage"] = lineage[-32:]
                source = self.product_store.transition_job(
                    job_id,
                    "interrupted",
                    progress=progress_document,
                )
        except (ProductStoreError, RunnerContractError, RunnerTransportError) as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "job_retry_refused",
                "The interrupted job could not be retried safely.",
                [str(exc)],
            ) from exc

        return {
            "schema_version": "bluefire.job-retry.v1",
            "retry_of_job_id": job_id,
            "source_job": source,
            "job": submission["job"],
            "approval_request": submission.get("approval_request"),
            "preflight": submission.get("preflight"),
        }

    def _assert_execute_retry_settled(self, request: Mapping[str, Any]) -> None:
        approval_id = request.get("approval_request_id")
        if not isinstance(approval_id, str):
            raise ProductStoreError("interrupted Execute job has no approval history")
        approval = self.product_store.get_approval_request(approval_id)
        binding = next(
            (
                item
                for item in self.product_store.list_execution_workspaces()
                if item.get("approval_id") == approval_id
            ),
            None,
        )
        if binding is None:
            if approval.get("status") == "claimed":
                raise ProductStoreError(
                    "claimed Execute approval has no durable workspace settlement"
                )
            return

        state = binding.get("state")
        if state not in {"completed", "recovered", "not_required"}:
            raise ProductStoreError("Execute workspace cleanup is active or deferred")
        outcome = binding.get("outcome")
        if not isinstance(outcome, Mapping) or outcome.get("remaining_receipt_count") != 0:
            raise ProductStoreError("Execute workspace settlement has outstanding receipts")
        profile_id = binding.get("profile_id")
        if not isinstance(profile_id, str):
            raise ProductStoreError("Execute workspace profile identity is unavailable")
        workspace = self._bound_execution_workspace(
            binding,
            approval_id=approval_id,
            profile_id=profile_id,
        )
        if self._workspace_receipt_ids(workspace, expected_profile_id=profile_id):
            raise ProductStoreError("Execute workspace still contains runner receipts")

    def proposal_reviews(self, job_id: str) -> Mapping[str, Any]:
        """List durable proposal decisions associated with one run job."""

        try:
            proposals = self.product_store.list_ai_proposal_reviews(job_id)
        except ProductStoreError as exc:
            raise APIError(HTTPStatus.NOT_FOUND, "job_not_found", "Job was not found.") from exc
        return {
            "schema_version": "bluefire.ai-proposal-review-list.v1",
            "job_id": job_id,
            "proposals": proposals,
        }

    def proposal_review(self, job_id: str, proposal_record_id: str) -> Mapping[str, Any]:
        """Return one exact state/plan/proposal review envelope."""

        try:
            proposal = self.product_store.get_ai_proposal_review(proposal_record_id)
            if proposal.get("job_id") != job_id:
                raise ProductStoreError("proposal review was not found for this job")
        except ProductStoreError as exc:
            raise APIError(
                HTTPStatus.NOT_FOUND,
                "proposal_not_found",
                "Proposal review was not found.",
            ) from exc
        return proposal

    def accept_proposal_review(
        self,
        job_id: str,
        proposal_record_id: str,
        request: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Accept a registered proposal after deterministic reconstruction."""

        decision = self._proposal_decision_request(request)
        try:
            job = self.product_store.get_job(job_id)
            if job.get("state") != "awaiting_approval":
                raise ProductStoreError("job is not awaiting a proposal decision")
            review = self.product_store.get_ai_proposal_review(proposal_record_id)
            if review.get("job_id") != job_id or review.get("status") != "pending":
                raise ProductStoreError("proposal review is stale or unavailable")
            if any(
                review.get(field) != decision[field]
                for field in ("state_digest", "plan_digest", "proposal_digest")
            ):
                raise ProductStoreError("proposal decision does not match the reviewed digests")
            prepared = self._prepare_ai_proposal_continuation(job, review)
            fresh_approval: Mapping[str, Any] | None = None
            if prepared["mode"] is ExecutionMode.EXECUTE:
                binding = prepared["approval_binding"]
                if not isinstance(binding, Mapping):
                    raise ProductStoreError("Execute proposal binding is unavailable")
                expires_at = self._approval_review_expires_at()
                intent_digest = content_hash(binding)
                fresh_approval = self.product_store.create_approval_request(
                    run_id="intent-" + intent_digest[7:39],
                    state_digest=str(binding["state_digest"]),
                    plan_digest=str(binding["plan_digest"]),
                    profile_id=str(binding["profile_id"]),
                    target_scope_digest=str(binding["target_scope_digest"]),
                    maximum_tier=str(binding["maximum_tier"]),
                    expires_at=expires_at,
                )
            resolution = {
                "schema_version": "bluefire.ai-proposal-resolution.v1",
                "decision": "accepted",
                "continuation": prepared["audit"],
                "approval_request_id": (
                    fresh_approval["approval_id"] if fresh_approval is not None else None
                ),
            }
            resolved = self.product_store.resolve_ai_proposal_review(
                proposal_record_id,
                job_id=job_id,
                decision="accepted",
                decided_by=decision["decided_by"],
                expected_state_digest=decision["state_digest"],
                expected_plan_digest=decision["plan_digest"],
                expected_proposal_digest=decision["proposal_digest"],
                resolution=resolution,
            )
            progress = dict(job.get("progress", {}))
            progress.update(
                {
                    "phase": "awaiting_approval",
                    "proposal_record_id": proposal_record_id,
                    "proposal_status": "accepted",
                    "approval_kind": (
                        "ai_proposal_execute" if fresh_approval is not None else "ai_proposal"
                    ),
                    "approval_request_id": (
                        fresh_approval["approval_id"] if fresh_approval is not None else None
                    ),
                }
            )
            self.product_store.transition_job(
                job_id,
                "awaiting_approval",
                progress=progress,
            )
            resumed = (
                self.job_controller.approve(job_id, approval_ref=proposal_record_id)
                if fresh_approval is None
                else self.product_store.get_job(job_id)
            )
        except (
            ProductStoreError,
            ReplayError,
            RunStoreError,
            OrchestrationError,
            RunnerContractError,
            RunnerTransportError,
            JobNotManaged,
            JobStateError,
            JobRuntimeError,
            ValueError,
        ) as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "proposal_acceptance_refused",
                "The proposal could not be accepted safely.",
                [str(exc)],
            ) from exc
        return {
            "schema_version": "bluefire.ai-proposal-decision.v1",
            "job": resumed,
            "proposal": resolved,
            "approval_request": public_approval_record(fresh_approval),
        }

    def reject_proposal_review(
        self,
        job_id: str,
        proposal_record_id: str,
        request: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Reject a pending proposal and finish without a mutated continuation."""

        decision = self._proposal_decision_request(request)
        try:
            job = self.product_store.get_job(job_id)
            if job.get("state") != "awaiting_approval":
                raise ProductStoreError("job is not awaiting a proposal decision")
            review = self._validate_ai_proposal_review(job, proposal_record_id)
            resolved = self.product_store.resolve_ai_proposal_review(
                proposal_record_id,
                job_id=job_id,
                decision="rejected",
                decided_by=decision["decided_by"],
                expected_state_digest=decision["state_digest"],
                expected_plan_digest=decision["plan_digest"],
                expected_proposal_digest=decision["proposal_digest"],
                resolution={
                    "schema_version": "bluefire.ai-proposal-resolution.v1",
                    "decision": "rejected",
                    "source_run_id": review["source_run_id"],
                    "mutated_execution": False,
                },
            )
            waiting = self.job_controller.reject_approval(
                job_id,
                decision_ref=proposal_record_id,
            )
        except (
            ProductStoreError,
            RunStoreError,
            JobNotManaged,
            JobStateError,
            JobRuntimeError,
            ValueError,
        ) as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "proposal_rejection_refused",
                "The proposal could not be rejected.",
                [str(exc)],
            ) from exc
        return {
            "schema_version": "bluefire.ai-proposal-decision.v1",
            "job": waiting,
            "proposal": resolved,
            "approval_request": None,
        }

    def approve_job(self, job_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        """Approve the exact immutable Execute request displayed for this job."""

        if set(request) != {"approved_by"}:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "approval_invalid",
                "Approval requires only approved_by.",
            )
        approved_by = request.get("approved_by")
        if (
            not isinstance(approved_by, str)
            or not approved_by.strip()
            or len(approved_by.strip()) > 128
        ):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "approval_invalid",
                "Approval identity must be a non-empty string of at most 128 characters.",
            )
        try:
            job = self.product_store.get_job(job_id)
            if job.get("state") != "awaiting_approval":
                raise JobStateError("job is not awaiting approval")
            stored_request = job.get("request")
            if not isinstance(stored_request, Mapping):
                raise ProductStoreError("job request is invalid")
            progress = job.get("progress")
            if (
                isinstance(progress, Mapping)
                and progress.get("approval_kind") == "ai_proposal_execute"
            ):
                return self._approve_ai_proposal_execute_job(
                    job,
                    approved_by=approved_by.strip(),
                )
            approval_id = stored_request.get("approval_request_id")
            if not isinstance(approval_id, str):
                raise ProductStoreError("job has no bound approval request")
            preflight = self.preflight(stored_request)
            problems = [
                str(item)
                for item in preflight.get("problems", [])
                if item != "Explicit operator approval is required."
            ]
            binding = preflight.get("approval_binding")
            if problems or not isinstance(binding, Mapping):
                detail = "; ".join(problems[:8]) or "approval binding is unavailable"
                raise ProductStoreError(
                    "the reviewed request no longer passes Execute readiness: " + detail
                )
            profile = self._profile(
                stored_request.get("runner_profile_id"),
                ExecutionMode.EXECUTE,
            )
            if profile is None:
                raise ProductStoreError("job has no Execute runner profile")
            pending = self.product_store.get_approval_request(approval_id)
            for field in (
                "state_digest",
                "plan_digest",
                "profile_id",
                "target_scope_digest",
                "maximum_tier",
            ):
                if pending.get(field) != binding.get(field):
                    raise ProductStoreError(
                        "approval request no longer matches the reviewed intent"
                    )
            approved = self.product_store.approve(
                approval_id,
                approved_by=approved_by.strip(),
                expected_state_digest=str(binding["state_digest"]),
                expected_plan_digest=str(binding["plan_digest"]),
                expected_target_scope_digest=str(binding["target_scope_digest"]),
                expires_at=self._approval_execution_expires_at(profile),
            )
            consumed = self.product_store.consume_approval(
                approval_id,
                nonce=str(approved["nonce"]),
                expected_state_digest=str(binding["state_digest"]),
                expected_plan_digest=str(binding["plan_digest"]),
                expected_target_scope_digest=str(binding["target_scope_digest"]),
            )
            resumed = self.job_controller.approve(job_id, approval_ref=approval_id)
        except (
            ProductStoreError,
            JobNotManaged,
            JobStateError,
            JobRuntimeError,
            OrchestrationError,
            RunnerContractError,
            RunnerTransportError,
        ) as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "approval_refused",
                "The job approval could not be applied.",
                [str(exc)],
            ) from exc
        return {
            "schema_version": "bluefire.job-approval.v1",
            "job": resumed,
            "approval_request": public_approval_record(consumed),
        }

    def _approve_ai_proposal_execute_job(
        self,
        job: Mapping[str, Any],
        *,
        approved_by: str,
    ) -> Mapping[str, Any]:
        progress = job.get("progress")
        request = job.get("request")
        if not isinstance(progress, Mapping) or not isinstance(request, Mapping):
            raise ProductStoreError("proposal continuation job is invalid")
        proposal_record_id = progress.get("proposal_record_id")
        approval_id = progress.get("approval_request_id")
        if not isinstance(proposal_record_id, str) or not isinstance(approval_id, str):
            raise ProductStoreError("proposal continuation approval references are unavailable")
        if approval_id == request.get("approval_request_id"):
            raise ProductStoreError("original Execute approval cannot authorize a proposal")
        review = self.product_store.get_ai_proposal_review(proposal_record_id)
        if review.get("job_id") != job.get("job_id") or review.get("status") != "accepted":
            raise ProductStoreError("accepted proposal review is unavailable")
        resolution = review.get("resolution")
        if (
            not isinstance(resolution, Mapping)
            or resolution.get("approval_request_id") != approval_id
        ):
            raise ProductStoreError("proposal resolution does not bind this fresh approval")
        prepared = self._prepare_ai_proposal_continuation(job, review)
        if prepared["mode"] is not ExecutionMode.EXECUTE:
            raise ProductStoreError("proposal continuation does not require Execute approval")
        binding = prepared.get("approval_binding")
        profile = prepared.get("profile")
        if not isinstance(binding, Mapping) or not isinstance(profile, RunnerProfile):
            raise ProductStoreError("proposal continuation binding is incomplete")
        audit = prepared.get("audit")
        if (
            not isinstance(audit, Mapping)
            or resolution.get("continuation") != audit
            or audit.get("execute_approval_binding_digest") != content_hash(binding)
        ):
            raise ProductStoreError("proposal continuation approval binding changed")
        pending = self.product_store.get_approval_request(approval_id)
        for field in (
            "state_digest",
            "plan_digest",
            "profile_id",
            "target_scope_digest",
            "maximum_tier",
        ):
            if pending.get(field) != binding.get(field):
                raise ProductStoreError("fresh approval no longer matches the proposal plan")
        approved = self.product_store.approve(
            approval_id,
            approved_by=approved_by,
            expected_state_digest=str(binding["state_digest"]),
            expected_plan_digest=str(binding["plan_digest"]),
            expected_target_scope_digest=str(binding["target_scope_digest"]),
            expires_at=self._approval_execution_expires_at(profile),
        )
        consumed = self.product_store.consume_approval(
            approval_id,
            nonce=str(approved["nonce"]),
            expected_state_digest=str(binding["state_digest"]),
            expected_plan_digest=str(binding["plan_digest"]),
            expected_target_scope_digest=str(binding["target_scope_digest"]),
        )
        resumed = self.job_controller.approve(str(job["job_id"]), approval_ref=approval_id)
        return {
            "schema_version": "bluefire.job-approval.v1",
            "job": resumed,
            "approval_request": public_approval_record(consumed),
            "proposal_record_id": proposal_record_id,
        }

    def pause_job(self, job_id: str) -> Mapping[str, Any]:
        return self._signal_job(job_id, "pause")

    def resume_job(self, job_id: str) -> Mapping[str, Any]:
        return self._signal_job(job_id, "resume")

    def cancel_job(self, job_id: str) -> Mapping[str, Any]:
        return self._signal_job(job_id, "cancel")

    def _signal_job(self, job_id: str, signal: str) -> Mapping[str, Any]:
        try:
            if signal == "pause":
                return self.job_controller.pause(job_id)
            if signal == "resume":
                return self.job_controller.resume(job_id)
            if signal == "cancel":
                return self.job_controller.cancel(job_id)
            raise AssertionError("unsupported internal job signal")
        except ProductStoreError as exc:
            raise APIError(HTTPStatus.NOT_FOUND, "job_not_found", "Job was not found.") from exc
        except (JobNotManaged, JobStateError, JobRuntimeError) as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "job_signal_refused",
                f"The job could not {signal} from its current state.",
                [str(exc)],
            ) from exc

    def _execute_job(self, context: JobContext, request: Mapping[str, Any]) -> JobResult:
        progress = context.progress_snapshot()
        proposal_record_id = progress.get("proposal_record_id")
        context.checkpoint({"phase": "running", "completed_steps": 0})
        try:
            if isinstance(proposal_record_id, str):
                review = self.product_store.get_ai_proposal_review(proposal_record_id)
                if review.get("job_id") != context.job_id or review.get("status") != "accepted":
                    raise ProductStoreError("accepted proposal continuation is unavailable")
                result = self._run_ai_proposal_continuation(
                    context,
                    request,
                    review,
                )
            else:
                result = self.run(
                    request,
                    checkpoint=context.checkpoint,
                    cancel_event=context.cancellation_event,
                )
        except RunnerTaskCancelled as exc:
            if context.cancellation_event.is_set():
                raise JobCancelled("job runner task cancellation was confirmed") from exc
            raise APIError(
                HTTPStatus.CONFLICT,
                "runner_task_cancelled",
                "The runner task was cancelled after its process tree stopped.",
            ) from exc
        run_id = str(result["run_id"])
        terminal_progress = {
            "run_id": run_id,
            "run_status": result.get("status"),
            "completed_steps": len(result.get("steps", [])),
        }
        if result.get("status") == "awaiting_approval":
            context.checkpoint(terminal_progress)
            proposals = result.get("ai_proposals")
            pending = (
                next(
                    (
                        item
                        for item in reversed(proposals)
                        if isinstance(item, Mapping)
                        and item.get("application_status") == "awaiting_operator_approval"
                    ),
                    None,
                )
                if isinstance(proposals, list)
                else None
            )
            if pending is None:
                raise ProductStoreError("awaiting run has no registered proposal review")
            review = self.product_store.create_ai_proposal_review(
                job_id=context.job_id,
                source_run_id=run_id,
                record=pending,
            )
            return JobResult(
                result_ref=run_id,
                progress={
                    "phase": "awaiting_approval",
                    "approval_kind": "ai_proposal",
                    "proposal_record_id": review["proposal_record_id"],
                    "proposal_status": review["status"],
                    "state_digest": review["state_digest"],
                    "plan_digest": review["plan_digest"],
                    "proposal_digest": review["proposal_digest"],
                },
                awaiting_approval=True,
            )
        return JobResult(
            result_ref=run_id,
            progress={
                **terminal_progress,
                "proposal_status": (
                    "continued" if isinstance(proposal_record_id, str) else "not_requested"
                ),
            },
            completion_confirmed=self._job_completion_is_durably_settled(result),
        )

    def _job_completion_is_durably_settled(self, result: Mapping[str, Any]) -> bool:
        """Prove the callback and every required cleanup obligation are terminal."""

        cleanup = result.get("cleanup")
        if (
            not isinstance(cleanup, Mapping)
            or type(cleanup.get("outstanding_receipt_count")) is not int
            or cleanup.get("outstanding_receipt_count") != 0
        ):
            return False
        mode = result.get("mode")
        if mode == ExecutionMode.SIMULATE.value:
            return True
        if mode != ExecutionMode.EXECUTE.value:
            return False
        approval = result.get("approval")
        approval_id = approval.get("approval_id") if isinstance(approval, Mapping) else None
        run_id = result.get("run_id")
        if not isinstance(approval_id, str) or not isinstance(run_id, str):
            return False
        try:
            workspace = self.product_store.get_execution_workspace(approval_id)
        except ProductStoreError:
            return False
        outcome = workspace.get("outcome")
        return bool(
            workspace.get("state") == "completed"
            and workspace.get("run_id") == run_id
            and isinstance(outcome, Mapping)
            and outcome.get("status") == "completed"
            and type(outcome.get("remaining_receipt_count")) is int
            and outcome.get("remaining_receipt_count") == 0
        )

    @staticmethod
    def _proposal_decision_request(request: Mapping[str, Any]) -> dict[str, str]:
        required = {
            "decided_by",
            "state_digest",
            "plan_digest",
            "proposal_digest",
        }
        if set(request) != required:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "proposal_decision_invalid",
                "Proposal decisions require only decided_by and the three reviewed digests.",
            )
        values = {key: request.get(key) for key in required}
        decided_by = values["decided_by"]
        if (
            not isinstance(decided_by, str)
            or not decided_by.strip()
            or len(decided_by.strip()) > 128
        ):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "proposal_decision_invalid",
                "Proposal decision identity must be non-empty and at most 128 characters.",
            )
        for key in ("state_digest", "plan_digest", "proposal_digest"):
            value = values[key]
            if (
                not isinstance(value, str)
                or not value.startswith("sha256:")
                or len(value) != 71
                or any(character not in "0123456789abcdef" for character in value[7:])
            ):
                raise APIError(
                    HTTPStatus.BAD_REQUEST,
                    "proposal_decision_invalid",
                    "Proposal decision digests must be canonical SHA-256 identifiers.",
                )
        return {
            "decided_by": decided_by.strip(),
            "state_digest": str(values["state_digest"]),
            "plan_digest": str(values["plan_digest"]),
            "proposal_digest": str(values["proposal_digest"]),
        }

    def _validate_ai_proposal_review(
        self,
        job: Mapping[str, Any],
        proposal_record_id: str,
    ) -> Mapping[str, Any]:
        review = self.product_store.get_ai_proposal_review(proposal_record_id)
        if review.get("job_id") != job.get("job_id"):
            raise ProductStoreError("proposal review was not found for this job")
        progress = job.get("progress")
        if (
            not isinstance(progress, Mapping)
            or progress.get("proposal_record_id") != proposal_record_id
        ):
            raise ProductStoreError("job is not waiting on this exact proposal review")
        self._validated_ai_proposal_source(review)
        return review

    def _validated_ai_proposal_source(
        self,
        review: Mapping[str, Any],
    ) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        source_run_id = review.get("source_run_id")
        if not isinstance(source_run_id, str):
            raise ProductStoreError("proposal source run is unavailable")
        integrity = self.store.validate_bundle(source_run_id)
        if not integrity.get("valid"):
            raise RunStoreError("proposal source run bundle failed integrity validation")
        source = self.store.get_run(source_run_id)
        if source.get("status") != "awaiting_approval":
            raise ProductStoreError("proposal source run is not at a review boundary")
        plan = source.get("plan")
        if not isinstance(plan, Mapping) or content_hash(plan) != review.get("plan_digest"):
            raise ProductStoreError("proposal source plan digest is stale or mismatched")
        pause = source.get("approval_pause")
        if not isinstance(pause, Mapping):
            raise ProductStoreError("proposal source has no review pause")
        for field in ("state_digest", "plan_digest", "proposal_digest"):
            if pause.get(field) != review.get(field):
                raise ProductStoreError("proposal review pause digest is stale or mismatched")
        records = source.get("ai_proposals")
        record = (
            next(
                (
                    item
                    for item in records
                    if isinstance(item, Mapping)
                    and isinstance(item.get("proposal"), Mapping)
                    and item["proposal"].get("proposal_id") == review.get("source_proposal_id")
                ),
                None,
            )
            if isinstance(records, list)
            else None
        )
        if record is None or record.get("application_status") != "awaiting_operator_approval":
            raise ProductStoreError("registered proposal record is unavailable")
        for field in ("state_digest", "plan_digest", "proposal_digest"):
            if record.get(field) != review.get(field):
                raise ProductStoreError("registered proposal record digest is mismatched")
        proposal = record.get("proposal")
        if not isinstance(proposal, Mapping) or content_hash(proposal) != review.get(
            "proposal_digest"
        ):
            raise ProductStoreError("registered proposal content was tampered")
        try:
            validated = validate_persisted_proposal_record(record)
        except AIProviderError as exc:
            raise ProductStoreError(
                "proposal is outside the strict registered planning boundary"
            ) from exc
        if (
            pause.get("proposal_id") != validated.proposal_id
            or pause.get("proposed_step_id") != validated.selected_step_id
        ):
            raise ProductStoreError("proposal pause identity is mismatched")
        source_scenario = source.get("scenario")
        if not isinstance(source_scenario, Mapping):
            raise ProductStoreError("proposal source scenario is unavailable")
        scenario = ScenarioDefinition.from_mapping(source_scenario)
        try:
            selected_step = scenario.step(str(validated.selected_step_id))
        except KeyError as exc:
            raise ProductStoreError("proposal selected an unknown scenario node") from exc
        if validated.selected_behavior_id not in (
            selected_step.behavior_id,
            *selected_step.alternates,
        ):
            raise ProductStoreError("proposal behavior is not owned by its selected node")
        if validated.proposal_type is ProposalType.SELECT_NEXT_NODE:
            if (
                validated.selected_edge is None
                or validated.selected_edge.get("from_step") != record.get("current_step_id")
                or validated.selected_edge.get("outcome") != record.get("outcome")
                or dict(validated.selected_edge) not in [edge.to_dict() for edge in scenario.edges]
            ):
                raise ProductStoreError("proposal next edge is not the observed registered edge")
        if validated.proposal_type is ProposalType.CHANGE_PARAMETERS:
            parameters = {
                **dict(selected_step.parameters),
                **dict(validated.parameter_change_map),
            }
            self.registry.get_behavior(str(validated.selected_behavior_id)).validate_parameters(
                parameters,
                f"persisted AI proposal parameters for {selected_step.id}",
            )
        if validated.proposal_type is ProposalType.SELECT_REGISTERED_ACTION:
            action_id = validated.selected_action_id
            behavior = self.registry.get_behavior(str(validated.selected_behavior_id))
            if action_id is None or action_id not in behavior.action_ids:
                raise ProductStoreError("proposal action is not registered to its behavior")
            profile_document = source.get("profile")
            if not isinstance(profile_document, Mapping) or not profile_document:
                raise ProductStoreError("proposal action has no immutable Execute profile")
            source_profile = RunnerProfile.from_mapping(
                profile_document,
                "proposal source runner profile",
            )
            if (
                action_id not in source_profile.enabled_actions
                or action_id in source_profile.blocked_actions
            ):
                raise ProductStoreError(
                    "proposal action was not enabled by the exact source runner profile"
                )
        if validated.proposal_type is ProposalType.RETRY_REGISTERED:
            retry_policy = record.get("proposal_policy")
            source_retry = source.get("adaptive_retry")
            if (
                validated.selected_step_id != record.get("current_step_id")
                or not isinstance(retry_policy, Mapping)
                or retry_policy.get("maximum_adaptive_retries") != 1
                or retry_policy.get("adaptive_retries_used") != 0
                or not isinstance(source_retry, Mapping)
                or source_retry.get("used") != 0
            ):
                raise ProductStoreError("proposal retry exceeds the one-retry lineage bound")
        return source, record

    def _prepare_ai_proposal_continuation(
        self,
        job: Mapping[str, Any],
        review: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        with self._action_catalog_lock:
            self._action_catalog_boundary()
            return self._prepare_ai_proposal_continuation_locked(job, review)

    def _prepare_ai_proposal_continuation_locked(
        self,
        job: Mapping[str, Any],
        review: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        source, record = self._validated_ai_proposal_source(review)
        proposal = record["proposal"]
        assert isinstance(proposal, Mapping)
        validated = AIProposal.from_persisted_mapping(proposal)
        source_scenario = source.get("scenario")
        if not isinstance(source_scenario, Mapping):
            raise ReplayError("proposal source has no scenario snapshot")
        immutable_scenario = ScenarioDefinition.from_mapping(source_scenario)
        assert validated.selected_step_id is not None
        assert validated.selected_behavior_id is not None
        selected_step_id = validated.selected_step_id
        selected_behavior_id = validated.selected_behavior_id
        original_step = immutable_scenario.step(selected_step_id)
        changes_behavior = bool(
            validated.proposal_type is ProposalType.SELECT_REGISTERED
            and selected_behavior_id != original_step.behavior_id
        )
        mode = ExecutionMode(str(source.get("mode")))
        parameter_overrides = (
            {selected_step_id: dict(validated.parameter_change_map)}
            if validated.proposal_type is ProposalType.CHANGE_PARAMETERS
            else None
        )
        action_overrides = (
            {selected_step_id: str(validated.selected_action_id)}
            if validated.proposal_type is ProposalType.SELECT_REGISTERED_ACTION
            and validated.selected_action_id is not None
            else None
        )
        source_retry = source.get("adaptive_retry")
        retries_used = int(source_retry.get("used", 0)) if isinstance(source_retry, Mapping) else 0
        adaptive_retry_count = retries_used + (
            1 if validated.proposal_type is ProposalType.RETRY_REGISTERED else 0
        )
        if not 0 <= adaptive_retry_count <= 1:
            raise ReplayError("adaptive proposal exceeds the one-retry lineage bound")
        prepared = prepare_replay(
            self.store,
            self.registry,
            ReplayRequest(
                source_run_id=str(review["source_run_id"]),
                # A fresh Execute approval always replays prerequisite effects in
                # its fresh workspace. Simulate can safely continue from typed,
                # immutable seed artifacts.
                from_step_id=(None if mode is ExecutionMode.EXECUTE else selected_step_id),
                swap_step_id=selected_step_id if changes_behavior else None,
                swap_behavior_id=selected_behavior_id if changes_behavior else None,
                parameter_overrides=parameter_overrides,
                action_implementations=action_overrides,
            ),
        )
        profile = self._profile(prepared.runner_profile_id, mode)
        provider_id = self._resolve_ai_provider_id(prepared.ai_provider_id)
        provider = self._ai_provider_metadata(prepared.autonomy, provider_id)
        request_document = job.get("request")
        if not isinstance(request_document, Mapping):
            raise ProductStoreError("proposal job request is invalid")
        target_scope = (
            self._target_scope(request_document)
            if mode is ExecutionMode.EXECUTE
            else {"scope_refs": []}
        )
        scope_problems = self._scope_problems(request_document, profile, mode)
        if scope_problems:
            raise OrchestrationError("; ".join(scope_problems))
        runner: RunnerTransport | None = None
        runner_readiness: Mapping[str, Any] | None = None
        if mode is ExecutionMode.EXECUTE:
            if profile is None:
                raise OrchestrationError("Execute proposal continuation requires a profile")
            if validated.selected_action_id is not None and (
                validated.selected_action_id not in profile.enabled_actions
                or validated.selected_action_id in profile.blocked_actions
            ):
                raise OrchestrationError(
                    "selected action is no longer enabled by the exact Execute profile"
                )
            expected_readiness: Mapping[str, Any] | None = None
            stored_resolution = review.get("resolution")
            if isinstance(stored_resolution, Mapping):
                stored_continuation = stored_resolution.get("continuation")
                if isinstance(stored_continuation, Mapping):
                    raw_readiness = stored_continuation.get("runner_readiness")
                    if raw_readiness is not None and not isinstance(raw_readiness, Mapping):
                        raise ProductStoreError("proposal continuation runner readiness is invalid")
                    expected_readiness = raw_readiness
            runner, _sandbox, runner_readiness = self._execute_readiness_boundary(
                profile,
                expected=expected_readiness,
            )
        orchestrator = Orchestrator(
            self.registry,
            self.store,
            runner=runner,
            approval_store=self.product_store,
            action_bindings=self._catalog_snapshot.action_bindings,
            catalog_authority=self._catalog_snapshot.to_dict(),
        )
        preflight = orchestrator.preflight(
            prepared.scenario,
            mode=mode,
            profile=profile,
            autonomy=prepared.autonomy,
            ai_provider=provider,
            approval_present=mode is ExecutionMode.EXECUTE,
            action_implementations=prepared.action_implementations,
        )
        if not preflight.ready:
            raise OrchestrationError("; ".join(preflight.problems))
        resolved_actions = {
            str(step["step_id"]): str(step["action_id"])
            for step in preflight.plan.get("steps", [])
            if isinstance(step, Mapping)
            and isinstance(step.get("step_id"), str)
            and isinstance(step.get("action_id"), str)
        }
        proposal_resolution = {
            "schema_version": "bluefire.ai-proposal-resolution-lineage.v2",
            "proposal_record_id": review["proposal_record_id"],
            "source_proposal_id": review["source_proposal_id"],
            "state_digest": review["state_digest"],
            "plan_digest": review["plan_digest"],
            "proposal_digest": review["proposal_digest"],
            "proposal_policy_digest": record["proposal_policy_digest"],
            "proposal_type": validated.proposal_type.value,
            "apply_after_step_id": record["current_step_id"],
            "selected_step_id": selected_step_id,
            "selected_behavior_id": selected_behavior_id,
            "selected_action_id": validated.selected_action_id,
            "selected_edge": (dict(validated.selected_edge) if validated.selected_edge else None),
            "parameter_changes": dict(validated.parameter_change_map),
        }
        replay_record = {
            **prepared.lineage,
            "ai_provider_to": provider_id,
            "action_implementations_to": resolved_actions,
            "action_implementations_changed": (
                resolved_actions != prepared.lineage.get("action_implementations_from")
            ),
            "adaptive_retry_count": adaptive_retry_count,
            "execute_fresh_workspace_full_replay": mode is ExecutionMode.EXECUTE,
            "proposal_resolution": proposal_resolution,
        }
        continuation_policy = {
            "schema_version": "bluefire.ai-continuation-policy.v1",
            "source_proposal_policy_digest": record["proposal_policy_digest"],
            "preflight_digest": content_hash(preflight.to_dict()),
            "target_scope_digest": content_hash(target_scope),
            "adaptive_retry_count": adaptive_retry_count,
            "execute_fresh_workspace_full_replay": mode is ExecutionMode.EXECUTE,
        }
        replay_record["continuation_policy"] = continuation_policy
        replay_record["continuation_policy_digest"] = content_hash(continuation_policy)
        approval_context = {
            "replay": replay_record,
            "resume_from_step_id": prepared.resume_from_step_id,
        }
        binding = (
            execution_approval_binding(
                registry=self.registry,
                scenario=prepared.scenario,
                plan=preflight.plan,
                profile=profile,
                target_scope=target_scope,
                autonomy=prepared.autonomy,
                ai_provider=provider,
                context=approval_context,
                runner_readiness=runner_readiness,
                catalog_authority=self._catalog_snapshot.to_dict(),
            )
            if mode is ExecutionMode.EXECUTE and profile is not None
            else None
        )
        audit = {
            "schema_version": "bluefire.ai-proposal-continuation.v1",
            "mode": mode.value,
            "scenario_digest": content_hash(prepared.scenario.to_dict()),
            "continuation_plan_digest": content_hash(preflight.plan),
            "resume_from_step_id": prepared.resume_from_step_id,
            "selected_behavior_id": selected_behavior_id,
            "proposal_type": validated.proposal_type.value,
            "selected_action_id": validated.selected_action_id,
            "parameter_changes": dict(validated.parameter_change_map),
            "source_proposal_policy_digest": record["proposal_policy_digest"],
            "continuation_policy_digest": content_hash(continuation_policy),
            "runner_profile_id": profile.id if profile is not None else None,
            "autonomy": prepared.autonomy.value,
            "ai_provider_id": provider_id,
            "replay": replay_record,
            "runner_readiness": runner_readiness,
            "catalog_authority": self._catalog_snapshot.to_dict(),
            "execute_approval_binding_digest": (
                content_hash(binding) if binding is not None else None
            ),
        }
        return {
            "mode": mode,
            "profile": profile,
            "provider": provider,
            "prepared": prepared,
            "target_scope": target_scope,
            "replay": replay_record,
            "approval_context": approval_context,
            "runner_readiness": runner_readiness,
            "approval_binding": binding,
            "action_implementations": resolved_actions,
            "audit": audit,
        }

    def _run_ai_proposal_continuation(
        self,
        context: JobContext,
        request: Mapping[str, Any],
        review: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        with self._action_catalog_lock, self.product_store.action_package_catalog_lease():
            self._action_catalog_boundary()
            return self._run_ai_proposal_continuation_locked(context, request, review)

    def _run_ai_proposal_continuation_locked(
        self,
        context: JobContext,
        request: Mapping[str, Any],
        review: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        job = self.product_store.get_job(context.job_id)
        prepared_context = self._prepare_ai_proposal_continuation(job, review)
        resolution = review.get("resolution")
        if (
            not isinstance(resolution, Mapping)
            or resolution.get("decision") != "accepted"
            or resolution.get("continuation") != prepared_context["audit"]
        ):
            raise ProductStoreError("accepted proposal continuation audit is mismatched")
        mode = prepared_context["mode"]
        prepared = prepared_context["prepared"]
        profile = prepared_context["profile"]
        provider = prepared_context["provider"]
        target_scope = prepared_context["target_scope"]
        replay_record = prepared_context["replay"]
        approval_context = prepared_context["approval_context"]
        runner_readiness = prepared_context["runner_readiness"]
        action_implementations = prepared_context["action_implementations"]
        if not isinstance(action_implementations, Mapping) or not all(
            isinstance(step_id, str) and isinstance(action_id, str)
            for step_id, action_id in action_implementations.items()
        ):
            raise ProductStoreError("proposal continuation action choices are invalid")
        runner: RunnerTransport | None = None
        sandbox: Path | None = None
        approval_record: Mapping[str, Any] | None = None
        approval_id: str | None = None
        if mode is ExecutionMode.EXECUTE:
            if profile is None:
                raise OrchestrationError("Execute proposal continuation requires a profile")
            approval_id_value = resolution.get("approval_request_id")
            if not isinstance(approval_id_value, str):
                raise ProductStoreError("fresh Execute approval is unavailable")
            original_approval_id = request.get("approval_request_id")
            if approval_id_value == original_approval_id:
                raise ProductStoreError("original Execute approval cannot authorize a proposal")
            approval_record = self.product_store.get_approval_request(approval_id_value)
            if approval_record.get("status") != "consumed":
                raise ProductStoreError("fresh Execute approval was not consumed")
            approval_id = approval_id_value
            if not isinstance(runner_readiness, Mapping):
                raise ProductStoreError("fresh Execute runner readiness is unavailable")
            runner, sandbox, runner_readiness = self._execute_readiness_boundary(
                profile,
                expected=runner_readiness,
                for_dispatch=True,
            )
            sandbox = self._isolated_execution_sandbox(sandbox, approval_record)
            self._bind_execution_workspace(
                approval_record=approval_record,
                workspace=sandbox,
                runner=runner,
                scenario=prepared.scenario,
                profile=profile,
                target_scope=target_scope,
                autonomy=prepared.autonomy,
                ai_provider=provider,
                approval_context=approval_context,
                runner_readiness=runner_readiness,
                action_implementations=action_implementations,
                catalog_authority=self._catalog_snapshot.to_dict(),
            )
        orchestrator = Orchestrator(
            self.registry,
            self.store,
            runner=runner,
            proposal_provider=self._proposal_provider(prepared.autonomy, provider),
            approval_store=self.product_store,
            action_bindings=self._catalog_snapshot.action_bindings,
            catalog_authority=self._catalog_snapshot.to_dict(),
        )
        result = orchestrator.run(
            prepared.scenario,
            mode=mode,
            profile=profile,
            sandbox_root=sandbox,
            target_scope=target_scope if mode is ExecutionMode.EXECUTE else None,
            approved_by=(
                str(approval_record["approved_by"]) if approval_record is not None else None
            ),
            approval_record=approval_record,
            autonomy=prepared.autonomy,
            ai_provider=provider,
            replay=replay_record,
            resume_from_step_id=prepared.resume_from_step_id,
            seed_artifacts=prepared.seed_artifacts,
            action_implementations=action_implementations,
            runner_readiness=(runner_readiness if isinstance(runner_readiness, Mapping) else None),
            checkpoint=(
                self._execution_checkpoint(approval_id, context.checkpoint)
                if approval_id is not None
                else context.checkpoint
            ),
            cancel_event=context.cancellation_event,
        )
        if approval_id is not None and sandbox is not None:
            self._complete_execution_workspace(
                approval_id,
                sandbox,
                result,
                expected_profile_id=profile.id if profile is not None else None,
            )
        self._index_run(result)
        return result

    def close(self) -> None:
        """Cooperatively stop locally managed workers."""

        self.job_controller.shutdown()

    def _recover_interrupted_cleanup(self) -> Mapping[str, Any]:
        summary: dict[str, Any] = {
            "examined": 0,
            "completed": 0,
            "no_outstanding_receipts": 0,
            "deferred": 0,
            "legacy_unbound": 0,
            "remaining": 0,
        }
        candidates = self.product_store.list_execution_workspaces(states={"active", "deferred"})
        summary["remaining"] = max(len(candidates) - 16, 0)
        for workspace_binding in candidates[:16]:
            summary["examined"] += 1
            approval_id = str(workspace_binding["approval_id"])
            recovery_run_id = (
                str(workspace_binding["run_id"])
                if isinstance(workspace_binding.get("run_id"), str)
                else None
            )
            try:
                approval = self.product_store.get_approval_request(approval_id)
                context = workspace_binding.get("recovery_context")
                if not isinstance(context, Mapping):
                    raise ProductStoreError("execution recovery context is unavailable")
                scenario = ScenarioDefinition.from_mapping(context.get("scenario"))
                profile = RunnerProfile.from_mapping(
                    context.get("profile"),
                    "execution recovery profile",
                )
                if profile.id != workspace_binding.get("profile_id"):
                    raise ProductStoreError("execution recovery profile identity changed")
                target_scope = context.get("target_scope")
                if not isinstance(target_scope, Mapping):
                    raise ProductStoreError("execution recovery scope is unavailable")
                autonomy = AutonomyLevel(str(context.get("autonomy")))
                provider = context.get("ai_provider")
                if not isinstance(provider, Mapping):
                    raise ProductStoreError("execution recovery provider is unavailable")
                approval_context = context.get("approval_context")
                if approval_context is not None and not isinstance(approval_context, Mapping):
                    raise ProductStoreError("execution approval context is invalid")
                runner_readiness = context.get("runner_readiness")
                if runner_readiness is not None and not isinstance(runner_readiness, Mapping):
                    raise ProductStoreError("execution runner readiness is invalid")
                catalog_authority = context.get("catalog_authority")
                if catalog_authority is not None and not isinstance(catalog_authority, Mapping):
                    raise ProductStoreError("execution catalog authority is invalid")
                recovery_catalog, approval_catalog_authority = self._historical_action_catalog(
                    catalog_authority
                )
                raw_action_implementations = context.get("action_implementations", {})
                if not isinstance(raw_action_implementations, Mapping) or not all(
                    isinstance(step_id, str) and isinstance(action_id, str)
                    for step_id, action_id in raw_action_implementations.items()
                ):
                    raise ProductStoreError("execution action implementations are invalid")
                recovery_action_implementations = {
                    str(step_id): str(action_id)
                    for step_id, action_id in raw_action_implementations.items()
                }
                workspace = self._bound_execution_workspace(
                    workspace_binding,
                    approval_id=approval_id,
                    profile_id=profile.id,
                )
                receipts = self._workspace_receipt_ids(
                    workspace,
                    expected_profile_id=profile.id,
                )
                recovery_run_id = recovery_run_id or self._find_run_for_approval(approval_id)
                if recovery_run_id is not None and workspace_binding.get("run_id") is None:
                    self.product_store.transition_execution_workspace(
                        approval_id,
                        str(workspace_binding["state"]),
                        run_id=recovery_run_id,
                    )

                if approval.get("status") != "claimed":
                    if receipts:
                        raise ProductStoreError(
                            "runner receipts exist without a claimed approval capability"
                        )
                    outcome = {
                        "schema_version": "bluefire.cleanup-recovery-outcome.v1",
                        "status": "not_required",
                        "reason": "execution approval was never claimed and no receipts exist",
                        "remaining_receipt_count": 0,
                    }
                    self.product_store.transition_execution_workspace(
                        approval_id,
                        "not_required",
                        run_id=recovery_run_id,
                        outcome=outcome,
                    )
                    self._update_interrupted_job_cleanup(approval_id, outcome)
                    summary["no_outstanding_receipts"] += 1
                    continue

                if recovery_run_id is None:
                    if receipts:
                        raise ProductStoreError("interrupted effect has no durable run identity")
                    outcome = {
                        "schema_version": "bluefire.cleanup-recovery-outcome.v1",
                        "status": "not_required",
                        "reason": "execution stopped before a run or receipt was created",
                        "remaining_receipt_count": 0,
                    }
                    self.product_store.transition_execution_workspace(
                        approval_id,
                        "not_required",
                        outcome=outcome,
                    )
                    self._update_interrupted_job_cleanup(approval_id, outcome)
                    summary["no_outstanding_receipts"] += 1
                    continue

                runner, _configured_sandbox = self.runner_factory(profile)
                original_runner_identity = workspace_binding.get("runner_identity")
                current_runner_identity = self._runner_recovery_identity(runner)
                if not receipts:
                    if (
                        not isinstance(original_runner_identity, Mapping)
                        or original_runner_identity.get("receipt_protocol")
                        != "bluefire.runner-receipt-wal.v2"
                        or current_runner_identity.get("receipt_protocol")
                        != "bluefire.runner-receipt-wal.v2"
                    ):
                        raise RunnerContractError(
                            "zero-receipt recovery requires the durable pre-effect WAL protocol"
                        )
                    recovery = {
                        "schema_version": "bluefire.cleanup-recovery.v1",
                        "run_id": recovery_run_id,
                        "status": "reconciled_no_outstanding",
                        "approval_id": approval_id,
                        "initial_receipt_count": 0,
                        "remaining_receipt_count": 0,
                        "attempts": [],
                    }
                    self._record_cleanup_recovery(
                        recovery_run_id,
                        recovery,
                        scenario=scenario,
                        profile=profile,
                        autonomy=autonomy,
                    )
                    outcome = self._cleanup_recovery_outcome(recovery)
                    self.product_store.transition_execution_workspace(
                        approval_id,
                        "recovered",
                        run_id=recovery_run_id,
                        outcome=outcome,
                    )
                    self._update_interrupted_job_cleanup(approval_id, outcome)
                    summary["no_outstanding_receipts"] += 1
                    continue

                orchestrator = Orchestrator(
                    recovery_catalog.registry,
                    self.store,
                    runner=runner,
                    approval_store=self.product_store,
                    action_bindings=recovery_catalog.action_bindings,
                    catalog_authority=approval_catalog_authority,
                )
                plan = orchestrator.planner.compile(
                    scenario,
                    mode=ExecutionMode.EXECUTE,
                    profile=profile,
                    autonomy=autonomy,
                    ai_provider=provider,
                    action_implementations=recovery_action_implementations,
                )
                binding = execution_approval_binding(
                    registry=recovery_catalog.registry,
                    scenario=scenario,
                    plan=plan.to_dict(),
                    profile=profile,
                    target_scope=target_scope,
                    autonomy=plan.autonomy,
                    ai_provider=plan.ai_provider,
                    context=approval_context,
                    runner_readiness=runner_readiness,
                    catalog_authority=approval_catalog_authority,
                )
                renewed = self.product_store.renew_claimed_approval_for_cleanup(
                    approval_id,
                    expires_at=self._approval_execution_expires_at(profile),
                    expected_state_digest=binding["state_digest"],
                    expected_plan_digest=binding["plan_digest"],
                    expected_target_scope_digest=binding["target_scope_digest"],
                    expected_profile_id=binding["profile_id"],
                    expected_maximum_tier=binding["maximum_tier"],
                )
                attempts: list[Mapping[str, Any]] = []
                remaining = list(receipts)
                for _attempt in range(2):
                    if not remaining:
                        break
                    with self.product_store.action_package_catalog_lease():
                        attempts.append(
                            orchestrator.recover_cleanup(
                                scenario,
                                run_id=recovery_run_id,
                                profile=profile,
                                sandbox_root=workspace,
                                target_scope=target_scope,
                                approval_record=renewed,
                                receipt_ids=remaining,
                                autonomy=autonomy,
                                ai_provider=provider,
                                approval_context=approval_context,
                                runner_readiness=runner_readiness,
                                action_implementations=recovery_action_implementations,
                            )
                        )
                    remaining = self._workspace_receipt_ids(
                        workspace,
                        expected_profile_id=profile.id,
                    )
                if remaining:
                    raise RunnerContractError("cleanup recovery retained runner receipts")
                recovery = {
                    "schema_version": "bluefire.cleanup-recovery.v1",
                    "run_id": recovery_run_id,
                    "status": "completed",
                    "approval_id": approval_id,
                    "initial_receipt_count": len(receipts),
                    "remaining_receipt_count": 0,
                    "runner_changed": current_runner_identity != original_runner_identity,
                    "attempts": attempts,
                }
                self._record_cleanup_recovery(
                    recovery_run_id,
                    recovery,
                    scenario=scenario,
                    profile=profile,
                    autonomy=autonomy,
                )
                outcome = self._cleanup_recovery_outcome(recovery)
                self.product_store.transition_execution_workspace(
                    approval_id,
                    "recovered",
                    run_id=recovery_run_id,
                    outcome=outcome,
                )
                self._update_interrupted_job_cleanup(approval_id, outcome)
                summary["completed"] += 1
            except (
                APIError,
                ConfigError,
                ContractError,
                OrchestrationError,
                ProductStoreError,
                RegistryError,
                RunnerContractError,
                RunnerTransportError,
                OSError,
                KeyError,
                TypeError,
                ValueError,
            ):
                outcome = {
                    "schema_version": "bluefire.cleanup-recovery-outcome.v1",
                    "status": "deferred",
                    "reason": "exact workspace, runner, approval, or receipt reconciliation was unavailable",
                }
                try:
                    self.product_store.transition_execution_workspace(
                        approval_id,
                        "deferred",
                        run_id=recovery_run_id,
                        outcome=outcome,
                    )
                except ProductStoreError:
                    pass
                self._update_interrupted_job_cleanup(approval_id, outcome)
                summary["deferred"] += 1

        bound_ids = {
            str(item["approval_id"]) for item in self.product_store.list_execution_workspaces()
        }
        for job in self.product_store.list_jobs(state="interrupted"):
            request = job.get("request")
            if not isinstance(request, Mapping) or request.get("mode") != "execute":
                continue
            legacy_approval_id = request.get("approval_request_id")
            if not isinstance(legacy_approval_id, str) or legacy_approval_id in bound_ids:
                continue
            try:
                approval = self.product_store.get_approval_request(legacy_approval_id)
                claimed = approval.get("status") == "claimed"
            except ProductStoreError:
                claimed = True
            outcome = {
                "schema_version": "bluefire.cleanup-recovery-outcome.v1",
                "status": "deferred" if claimed else "not_required",
                "reason": (
                    "legacy execution has no durable workspace binding"
                    if claimed
                    else "execution approval was never claimed"
                ),
            }
            self._update_interrupted_job_cleanup(legacy_approval_id, outcome)
            summary["legacy_unbound"] += 1
            if claimed:
                summary["deferred"] += 1
            else:
                summary["no_outstanding_receipts"] += 1
        return summary

    @staticmethod
    def _workspace_receipt_ids(
        workspace: Path,
        *,
        expected_profile_id: str | None = None,
    ) -> list[str]:
        try:
            return list(
                Orchestrator._discover_runner_receipts(
                    workspace,
                    expected_profile_id=expected_profile_id,
                )
            )
        except RunnerTransportError as exc:
            raise RunnerContractError(str(exc)) from exc

    def _bind_execution_workspace(
        self,
        *,
        approval_record: Mapping[str, Any],
        workspace: Path,
        runner: RunnerTransport,
        scenario: ScenarioDefinition,
        profile: RunnerProfile,
        target_scope: Mapping[str, Any],
        autonomy: AutonomyLevel,
        ai_provider: Mapping[str, Any],
        approval_context: Mapping[str, Any] | None = None,
        runner_readiness: Mapping[str, Any] | None = None,
        action_implementations: Mapping[str, str] | None = None,
        catalog_authority: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        approval_id = approval_record.get("approval_id")
        if not isinstance(approval_id, str):
            raise ProductStoreError("execution approval has no stable identity")
        return self.product_store.bind_execution_workspace(
            approval_id,
            profile_id=profile.id,
            workspace_path=workspace,
            runner_identity=self._runner_recovery_identity(runner),
            recovery_context={
                "scenario": scenario.to_dict(),
                "profile": profile.to_dict(),
                "target_scope": dict(target_scope),
                "autonomy": autonomy.value,
                "ai_provider": dict(ai_provider),
                "approval_context": (
                    dict(approval_context) if approval_context is not None else None
                ),
                "runner_readiness": (
                    dict(runner_readiness) if runner_readiness is not None else None
                ),
                "action_implementations": dict(action_implementations or {}),
                "catalog_authority": (
                    dict(catalog_authority) if catalog_authority is not None else None
                ),
            },
        )

    def _execution_checkpoint(
        self,
        approval_id: str,
        downstream: Callable[[Mapping[str, Any]], None] | None,
    ) -> Callable[[Mapping[str, Any]], None]:
        def checkpoint(progress: Mapping[str, Any]) -> None:
            run_id = progress.get("run_id")
            if isinstance(run_id, str):
                self.product_store.transition_execution_workspace(
                    approval_id,
                    "active",
                    run_id=run_id,
                )
            if downstream is not None:
                downstream(progress)

        return checkpoint

    def _complete_execution_workspace(
        self,
        approval_id: str,
        workspace: Path,
        result: Mapping[str, Any],
        *,
        expected_profile_id: str | None,
    ) -> None:
        remaining = self._workspace_receipt_ids(
            workspace,
            expected_profile_id=expected_profile_id,
        )
        run_id = result.get("run_id")
        if not isinstance(run_id, str):
            raise ProductStoreError("completed execution has no run identity")
        outcome = {
            "schema_version": "bluefire.execution-settlement.v1",
            "status": "completed" if not remaining else "cleanup_pending",
            "run_status": result.get("status"),
            "remaining_receipt_count": len(remaining),
        }
        self.product_store.transition_execution_workspace(
            approval_id,
            "completed" if not remaining else "active",
            run_id=run_id,
            outcome=outcome,
        )

    def _settle_pre_dispatch_refusal(
        self,
        approval_id: str,
        workspace: Path,
        *,
        expected_profile_id: str | None,
    ) -> None:
        """Settle a claimed approval only when no run or receipt was produced."""

        try:
            if self._find_run_for_approval(approval_id) is not None:
                return
            if self._workspace_receipt_ids(
                workspace,
                expected_profile_id=expected_profile_id,
            ):
                return
            self.product_store.transition_execution_workspace(
                approval_id,
                "not_required",
                outcome={
                    "schema_version": "bluefire.execution-settlement.v1",
                    "status": "pre_dispatch_refused",
                    "remaining_receipt_count": 0,
                },
            )
        except (ProductStoreError, RunStoreError, RunnerContractError):
            # Startup recovery remains authoritative if settlement cannot be
            # proven without masking the original fail-closed refusal.
            return

    @staticmethod
    def _runner_recovery_identity(runner: RunnerTransport) -> Mapping[str, Any]:
        if isinstance(runner, InventoryBoundRunner):
            return dict(runner.recovery_identity)
        identity: dict[str, Any] = {
            "schema_version": "bluefire.runner-recovery-identity.v1",
            "transport": f"{type(runner).__module__}.{type(runner).__qualname__}",
            "inventory_status": "unavailable_at_binding",
        }
        try:
            inventory = runner.inventory()
            Orchestrator._validate_cleanup_inventory(inventory)
        except (AttributeError, OSError, OrchestrationError, RunnerTransportError, TypeError):
            pass
        else:
            raw_actions = inventory.get("actions")
            assert isinstance(raw_actions, list)
            cleanup = next(
                row
                for row in raw_actions
                if isinstance(row, Mapping) and row.get("action_id") == "sandbox.cleanup.v1"
            )
            identity["inventory_status"] = "cleanup_available"
            identity["cleanup_action_digest"] = content_hash(cleanup)
            receipt_protocol = inventory.get("receipt_protocol")
            if isinstance(receipt_protocol, str):
                identity["receipt_protocol"] = receipt_protocol
        raw_binary = getattr(runner, "runner_binary", None)
        if isinstance(raw_binary, Path) and raw_binary.is_file():
            binary = raw_binary.resolve(strict=True)
            identity["runner_binary_path"] = str(binary)
            identity["runner_binary_digest"] = file_hash(binary)
        return identity

    @staticmethod
    def _bound_execution_workspace(
        binding: Mapping[str, Any],
        *,
        approval_id: str,
        profile_id: str,
    ) -> Path:
        if binding.get("approval_id") != approval_id or binding.get("profile_id") != profile_id:
            raise ProductStoreError("execution workspace identity is mismatched")
        raw_path = binding.get("workspace_path")
        if not isinstance(raw_path, str):
            raise ProductStoreError("execution workspace path is unavailable")
        candidate = Path(raw_path)
        if (
            not candidate.is_absolute()
            or not candidate.exists()
            or candidate.is_symlink()
            or not candidate.is_dir()
        ):
            raise RunnerContractError("the exact execution workspace is unavailable")
        if candidate.parent.is_symlink() or candidate.parent.name != ".bluefire-executions":
            raise RunnerContractError("the exact execution workspace parent is unsafe")
        resolved = candidate.resolve(strict=True)
        if str(resolved) != raw_path or resolved.name != approval_id:
            raise RunnerContractError("the exact execution workspace identity changed")
        expected_digest = content_hash(
            {
                "approval_id": approval_id,
                "profile_id": profile_id,
                "workspace_path": str(resolved),
            }
        )
        if binding.get("workspace_digest") != expected_digest:
            raise ProductStoreError("execution workspace binding digest changed")
        return resolved

    def _find_run_for_approval(self, approval_id: str) -> str | None:
        matches: list[str] = []
        for summary in self.store.list_runs():
            run_id = summary.get("run_id")
            if not isinstance(run_id, str) or summary.get("status") == "corrupted":
                continue
            try:
                policy = self.store.read_json(run_id, "policy.json")
            except RunStoreError:
                continue
            approval = policy.get("approval")
            if isinstance(approval, Mapping) and approval.get("approval_id") == approval_id:
                matches.append(run_id)
        if len(matches) > 1:
            raise RunStoreError("approval identity is linked to multiple runs")
        return matches[0] if matches else None

    @staticmethod
    def _cleanup_recovery_outcome(recovery: Mapping[str, Any]) -> dict[str, Any]:
        attempts = recovery.get("attempts")
        return {
            "schema_version": "bluefire.cleanup-recovery-outcome.v1",
            "status": recovery.get("status"),
            "run_id": recovery.get("run_id"),
            "initial_receipt_count": recovery.get("initial_receipt_count", 0),
            "remaining_receipt_count": recovery.get("remaining_receipt_count", 0),
            "attempt_count": len(attempts) if isinstance(attempts, list) else 0,
            "runner_changed": bool(recovery.get("runner_changed", False)),
        }

    def _record_cleanup_recovery(
        self,
        run_id: str,
        recovery: Mapping[str, Any],
        *,
        scenario: ScenarioDefinition,
        profile: RunnerProfile,
        autonomy: AutonomyLevel,
    ) -> None:
        manifest_path = self.store.root / run_id / "manifest.json"
        if manifest_path.is_file():
            validation = self.store.validate_bundle(run_id)
            if not validation.get("valid"):
                raise RunStoreError("cannot update a corrupted run bundle during recovery")
            self.store.append_recovery_record(run_id, recovery)
            self._index_run(self.store.get_run(run_id))
            return

        result = dict(self.store.read_json(run_id, "result.json"))
        policy = dict(self.store.read_json(run_id, "policy.json"))
        evidence_document = self.store.read_json(run_id, "evidence.json")
        detection_document = self.store.read_json(run_id, "detections.json")
        raw_evidence = evidence_document.get("records", [])
        raw_detections = detection_document.get("candidates", [])
        if not isinstance(raw_evidence, list) or not isinstance(raw_detections, list):
            raise RunStoreError("run recovery evidence documents are invalid")

        evidence_rows = [item for item in raw_evidence if isinstance(item, Mapping)]
        attempts = recovery.get("attempts")
        if isinstance(attempts, list):
            for attempt in attempts:
                attempt_evidence = attempt.get("evidence") if isinstance(attempt, Mapping) else None
                if isinstance(attempt_evidence, list):
                    evidence_rows.extend(
                        item for item in attempt_evidence if isinstance(item, Mapping)
                    )
        unique_evidence: dict[str, Mapping[str, Any]] = {}
        for index, row in enumerate(evidence_rows):
            evidence_id = row.get("evidence_id")
            key = str(evidence_id) if isinstance(evidence_id, str) else f"anonymous-{index}"
            unique_evidence[key] = row

        policy["cleanup_recovery"] = dict(recovery)
        self.store.write_json(run_id, "policy.json", policy)
        event = self._cleanup_recovery_outcome(recovery)
        self.store.append_event(run_id, "run.cleanup_recovered", event)

        result.setdefault("scenario_id", scenario.id)
        result.setdefault("mode", ExecutionMode.EXECUTE.value)
        result.setdefault("objective_reached", False)
        result.setdefault("autonomy", autonomy.value)
        result.setdefault("runner_profile_id", profile.id)
        if result.get("status") == "created":
            result["status"] = "interrupted"
        result["cleanup_recovery"] = dict(recovery)
        cleanup = result.get("cleanup")
        cleanup_record = dict(cleanup) if isinstance(cleanup, Mapping) else {}
        cleanup_record.update(
            {
                "attempted": bool(attempts),
                "succeeded": True,
                "recovered_after_restart": True,
                "outstanding_receipts": 0,
            }
        )
        result["cleanup"] = cleanup_record
        limitations = result.get("limitations")
        limitation_rows = list(limitations) if isinstance(limitations, list) else []
        recovery_limitation = (
            "The original Execute run was interrupted; cleanup was reconciled during restart."
        )
        if recovery_limitation not in limitation_rows:
            limitation_rows.append(recovery_limitation)
        result["limitations"] = limitation_rows

        self.store.finalize(
            run_id,
            result=result,
            evidence=unique_evidence.values(),
            detections=(item for item in raw_detections if isinstance(item, Mapping)),
        )
        recovered = self.store.get_run(run_id)
        self._index_run(recovered)

    def _update_interrupted_job_cleanup(
        self,
        approval_id: str,
        outcome: Mapping[str, Any],
    ) -> None:
        for job in self.product_store.list_jobs():
            request = job.get("request")
            if (
                not isinstance(request, Mapping)
                or request.get("approval_request_id") != approval_id
            ):
                continue
            progress = job.get("progress")
            progress_document = dict(progress) if isinstance(progress, Mapping) else {}
            progress_document["cleanup_recovery"] = dict(outcome)
            try:
                self.product_store.transition_job(
                    str(job["job_id"]),
                    str(job["state"]),
                    progress=progress_document,
                )
            except ProductStoreError:
                continue

    def list(self) -> Mapping[str, Any]:
        return {"schema_version": "bluefire.run-list.v1", "runs": self.store.list_runs()}

    def detail(self, run_id: str) -> Mapping[str, Any]:
        try:
            return self.store.get_run(run_id)
        except RunStoreError as exc:
            raise APIError(HTTPStatus.NOT_FOUND, "run_not_found", "Run was not found.") from exc

    def events(
        self,
        run_id: str,
        *,
        after_sequence: int = 0,
        limit: int = 250,
    ) -> Mapping[str, Any]:
        try:
            return self.store.read_event_page(
                run_id,
                after_sequence=after_sequence,
                limit=limit,
            )
        except RunStoreError as exc:
            raise APIError(HTTPStatus.NOT_FOUND, "run_not_found", "Run was not found.") from exc

    def replay(self, run_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        with self._action_catalog_lock, self.product_store.action_package_catalog_lease():
            try:
                self._action_catalog_boundary()
                return self._replay_locked(run_id, request)
            except APIError:
                raise
            except (ActionCatalogError, ProductStoreError) as exc:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "replay_refused",
                    "Replay could not be prepared safely.",
                    [str(exc)],
                ) from exc

    def _replay_locked(self, run_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            integrity = self.store.validate_bundle(run_id)
            if not integrity.get("valid"):
                raise ReplayError("source run bundle failed integrity validation")
            source = self.store.get_run(run_id)
            mode = ExecutionMode(str(source.get("mode", "simulate")))
            exact = bool(request.get("exact", False))
            source_catalog_authority = self._run_catalog_authority(source)
            replay_catalog, replay_catalog_authority = (
                self._historical_action_catalog(source_catalog_authority)
                if exact
                else (self._catalog_snapshot, self._catalog_snapshot.to_dict())
            )
            if (
                exact
                and mode is ExecutionMode.EXECUTE
                and source_catalog_authority is not None
                and replay_catalog_authority != self._catalog_snapshot.to_dict()
            ):
                raise ReplayError(
                    "exact Execute replay requires the source package catalog to remain active"
                )
            replay_action_implementations = self._action_implementations(request, mode=mode)
            prepared = prepare_replay(
                self.store,
                replay_catalog.registry,
                ReplayRequest(
                    source_run_id=run_id,
                    exact=exact,
                    from_step_id=self._optional_string(request.get("from_step_id")),
                    swap_step_id=self._optional_string(request.get("swap_step_id")),
                    swap_behavior_id=self._optional_string(request.get("swap_behavior_id")),
                    parameter_overrides=self._parameter_overrides(
                        request.get("parameter_overrides")
                    ),
                    action_implementations=(
                        replay_action_implementations
                        if "action_implementations" in request
                        else None
                    ),
                    autonomy=self._optional_autonomy(request),
                    ai_provider_id=self._optional_ai_provider_id(request),
                    runner_profile_id=self._optional_string(request.get("runner_profile_id")),
                    defense_change=self._optional_string(request.get("defense_change")),
                ),
            )
            profile = self._profile_for_catalog(
                prepared.runner_profile_id,
                mode,
                replay_catalog,
            )
            autonomy = prepared.autonomy
            provider_id = self._resolve_ai_provider_id(prepared.ai_provider_id)
            provider = self._ai_provider_metadata(autonomy, provider_id)
            approved_by = self._approval(request, required=mode is ExecutionMode.EXECUTE)
            scope_problems = self._scope_problems(request, profile, mode)
            if scope_problems:
                raise ReplayError("; ".join(scope_problems))
            runner: RunnerTransport | None = None
            sandbox: Path | None = None
            runner_readiness: Mapping[str, Any] | None = None
            if mode is ExecutionMode.EXECUTE:
                if profile is None:
                    raise ReplayError("Execute replay requires an explicit runner profile")
                runner, sandbox, runner_readiness = self._execute_readiness_boundary(
                    profile,
                    for_dispatch=True,
                )
            orchestrator = Orchestrator(
                replay_catalog.registry,
                self.store,
                runner=runner,
                proposal_provider=self._proposal_provider(autonomy, provider),
                approval_store=self.product_store,
                action_bindings=replay_catalog.action_bindings,
                catalog_authority=replay_catalog_authority,
            )
            resolved_replay_plan = orchestrator.planner.compile(
                prepared.scenario,
                mode=mode,
                profile=profile,
                autonomy=autonomy,
                ai_provider=provider,
                action_implementations=prepared.action_implementations,
            )
            resolved_replay_actions = {
                step.step_id: step.action_id
                for step in resolved_replay_plan.steps
                if step.action_id is not None
            }
            replay_record = {
                **prepared.lineage,
                "catalog_authority_from": source_catalog_authority,
                "catalog_authority_to": replay_catalog_authority,
                "catalog_authority_changed": (source_catalog_authority != replay_catalog_authority),
                "ai_provider_to": provider_id,
                "action_implementations_to": resolved_replay_actions,
                "action_implementations_changed": (
                    resolved_replay_actions != prepared.lineage.get("action_implementations_from")
                ),
            }
            approval_record = (
                self._bind_and_consume_approval(
                    scenario=prepared.scenario,
                    profile=profile,
                    target_scope=self._target_scope(request),
                    autonomy=autonomy,
                    ai_provider=provider,
                    approved_by=approved_by,
                    orchestrator=orchestrator,
                    context={
                        "replay": replay_record,
                        "resume_from_step_id": prepared.resume_from_step_id,
                    },
                    runner_readiness=runner_readiness,
                    action_implementations=resolved_replay_actions,
                )
                if mode is ExecutionMode.EXECUTE and profile is not None and approved_by is not None
                else None
            )
            if mode is ExecutionMode.EXECUTE:
                if sandbox is None or approval_record is None:
                    raise ReplayError("Execute replay workspace approval is incomplete")
                sandbox = self._isolated_execution_sandbox(sandbox, approval_record)
                if runner is None or profile is None:
                    raise ReplayError("Execute replay runner binding is incomplete")
                replay_approval_context = {
                    "replay": replay_record,
                    "resume_from_step_id": prepared.resume_from_step_id,
                }
                replay_approval_id = str(approval_record["approval_id"])
                self._bind_execution_workspace(
                    approval_record=approval_record,
                    workspace=sandbox,
                    runner=runner,
                    scenario=prepared.scenario,
                    profile=profile,
                    target_scope=self._target_scope(request),
                    autonomy=autonomy,
                    ai_provider=provider,
                    approval_context=replay_approval_context,
                    runner_readiness=runner_readiness,
                    action_implementations=resolved_replay_actions,
                    catalog_authority=replay_catalog_authority,
                )
            else:
                replay_approval_context = None
                replay_approval_id = None
            result = orchestrator.run(
                prepared.scenario,
                mode=mode,
                profile=profile,
                sandbox_root=sandbox,
                target_scope=(
                    self._target_scope(request) if mode is ExecutionMode.EXECUTE else None
                ),
                approved_by=approved_by,
                approval_record=approval_record,
                autonomy=autonomy,
                ai_provider=provider,
                replay=replay_record,
                resume_from_step_id=prepared.resume_from_step_id,
                seed_artifacts=prepared.seed_artifacts,
                action_implementations=resolved_replay_actions,
                runner_readiness=runner_readiness,
                checkpoint=(
                    self._execution_checkpoint(replay_approval_id, None)
                    if replay_approval_id is not None
                    else None
                ),
            )
            if replay_approval_id is not None and sandbox is not None:
                self._complete_execution_workspace(
                    replay_approval_id,
                    sandbox,
                    result,
                    expected_profile_id=profile.id if profile is not None else None,
                )
            self._index_run(result)
            return result
        except APIError:
            raise
        except (
            ReplayError,
            ProductStoreError,
            RunStoreError,
            OrchestrationError,
            RunnerContractError,
            RunnerTransportError,
            ValueError,
        ) as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "replay_refused",
                "Replay could not be prepared safely.",
                [str(exc)],
            ) from exc

    def compare(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        run_ids = request.get("run_ids")
        if not isinstance(run_ids, list) or not all(isinstance(item, str) for item in run_ids):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "run_ids_required",
                "Comparison requires a list of run IDs.",
            )
        try:
            return compare_runs(self.store, run_ids)
        except (ComparisonError, RunStoreError) as exc:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "comparison_invalid",
                "Runs could not be compared.",
                [str(exc)],
            ) from exc

    def _bind_and_consume_approval(
        self,
        *,
        scenario: ScenarioDefinition,
        profile: RunnerProfile,
        target_scope: Mapping[str, Any],
        autonomy: AutonomyLevel,
        ai_provider: Mapping[str, Any],
        approved_by: str,
        orchestrator: Orchestrator,
        context: Mapping[str, Any] | None = None,
        runner_readiness: Mapping[str, Any] | None = None,
        action_implementations: Mapping[str, str] | None = None,
    ) -> Mapping[str, Any]:
        """Persist and consume a one-time approval bound to the reviewed envelope."""

        report = orchestrator.preflight(
            scenario,
            mode=ExecutionMode.EXECUTE,
            profile=profile,
            autonomy=autonomy,
            ai_provider=ai_provider,
            approval_present=True,
            action_implementations=action_implementations,
        )
        if not report.ready:
            raise OrchestrationError("; ".join(report.problems))
        binding = execution_approval_binding(
            registry=orchestrator.registry,
            scenario=scenario,
            plan=report.plan,
            profile=profile,
            target_scope=target_scope,
            autonomy=autonomy,
            ai_provider=ai_provider,
            context=context,
            runner_readiness=runner_readiness,
            catalog_authority=orchestrator.catalog_authority,
        )
        intent_digest = content_hash(binding)
        expires_at = self._approval_review_expires_at()
        pending = self.product_store.create_approval_request(
            run_id="intent-" + intent_digest[7:39],
            state_digest=binding["state_digest"],
            plan_digest=binding["plan_digest"],
            profile_id=profile.id,
            target_scope_digest=binding["target_scope_digest"],
            maximum_tier=binding["maximum_tier"],
            expires_at=expires_at,
        )
        approved = self.product_store.approve(
            str(pending["approval_id"]),
            approved_by=approved_by,
            expected_state_digest=binding["state_digest"],
            expected_plan_digest=binding["plan_digest"],
            expected_target_scope_digest=binding["target_scope_digest"],
            expires_at=self._approval_execution_expires_at(profile),
        )
        consumed = self.product_store.consume_approval(
            str(approved["approval_id"]),
            nonce=str(approved["nonce"]),
            expected_state_digest=binding["state_digest"],
            expected_plan_digest=binding["plan_digest"],
            expected_target_scope_digest=binding["target_scope_digest"],
        )
        return consumed

    def _synchronize_run_index(self) -> None:
        """Backfill the query index from immutable bundle summaries after startup."""

        for result in self.store.list_runs():
            required = {"run_id", "scenario_id", "mode", "status", "created_at"}
            if required.issubset(result):
                self._index_run(result)

    @staticmethod
    def _approval_review_expires_at() -> str:
        lifetime = timedelta(minutes=15)
        return (datetime.now(timezone.utc) + lifetime).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _approval_execution_expires_at(profile: RunnerProfile) -> str:
        # Approval refresh is approval-relative, not request-relative, so a
        # deliberate review delay cannot consume the run/cleanup capability.
        lifetime = timedelta(seconds=max(15 * 60, profile.budgets.max_seconds + 60))
        return (datetime.now(timezone.utc) + lifetime).isoformat().replace("+00:00", "Z")

    def _index_run(self, result: Mapping[str, Any]) -> None:
        manifest = result.get("manifest")
        bundle_digest = manifest.get("bundle_hash") if isinstance(manifest, Mapping) else None
        summary = {
            key: result[key]
            for key in (
                "run_id",
                "scenario_id",
                "mode",
                "status",
                "objective_reached",
                "created_at",
                "finalized_at",
                "autonomy",
                "runner_profile_id",
                "cleanup",
                "cleanup_recovery",
                "replay",
            )
            if key in result
        }
        if bundle_digest is not None:
            summary["bundle_digest"] = bundle_digest
        self.product_store.index_run(summary)

    def _managed_runner(self, profile: RunnerProfile) -> tuple[RunnerTransport, Path]:
        """Bind an already-running authenticated host; never mutate lifecycle state."""

        try:
            return self.runner_lifecycle.client_for_profile(profile.id)
        except RunnerLifecycleError:
            raise RunnerReadinessError(
                "Managed runner is not authenticated and ready; use an explicit lifecycle action."
            ) from None

    def _runner_probe_transport(self, profile: RunnerProfile) -> RunnerTransport:
        runner, _sandbox = self.runner_factory(profile)
        return runner

    def _execute_readiness_boundary(
        self,
        profile: RunnerProfile,
        *,
        expected: Mapping[str, Any] | None = None,
        for_dispatch: bool = False,
    ) -> tuple[RunnerTransport, Path, Mapping[str, Any]]:
        """Probe or bind the exact non-mutating Execute readiness envelope."""

        with self._action_catalog_lock:
            validated_expected = (
                self._validated_execute_readiness(profile, expected)
                if expected is not None
                else None
            )
            expected_catalog = (
                validated_expected["catalog_authority"] if validated_expected is not None else None
            )
            self._action_catalog_boundary(expected_catalog)
            return self._execute_readiness_boundary_locked(
                profile,
                expected=validated_expected,
                for_dispatch=for_dispatch,
            )

    def _execute_readiness_boundary_locked(
        self,
        profile: RunnerProfile,
        *,
        expected: Mapping[str, Any] | None = None,
        for_dispatch: bool = False,
    ) -> tuple[RunnerTransport, Path, Mapping[str, Any]]:
        """Implement readiness while the exact catalog generation is locked."""

        try:
            runner, sandbox = self.runner_factory(profile)
        except (
            AttributeError,
            RunnerContractError,
            RunnerTransportError,
            OSError,
            TypeError,
            ValueError,
        ) as exc:
            raise RunnerReadinessError(
                "Runner inventory is unavailable; verify the selected runner and retry."
            ) from exc

        sandbox_readiness = self._sandbox_root_readiness(sandbox)
        expected_snapshot = (
            self._validated_execute_readiness(profile, expected) if expected is not None else None
        )
        if expected_snapshot is not None:
            expected_sandbox = expected_snapshot.get("sandbox")
            if expected_sandbox != sandbox_readiness:
                raise RunnerReadinessError(
                    "Sandbox readiness changed after review; submit a new Execute request."
                )
            if for_dispatch:
                return (
                    InventoryBoundRunner(
                        runner,
                        expected_inventory_digest=str(expected_snapshot["inventory_digest"]),
                        expected_identity_digest=str(expected_snapshot["runner_identity_digest"]),
                        recovery_identity=dict(expected_snapshot["recovery_identity"]),
                        dispatch_lease=self._catalog_dispatch_lease(
                            expected_snapshot["catalog_authority"]
                        ),
                    ),
                    sandbox,
                    expected_snapshot,
                )

        try:
            raw_inventory = runner.inventory()
            canonical_inventory = canonical_runner_inventory(raw_inventory)
            identity = runner_transport_identity(runner, raw_inventory)
        except (
            AttributeError,
            RunnerContractError,
            RunnerTransportError,
            OSError,
            TypeError,
            ValueError,
        ) as exc:
            raise RunnerReadinessError(
                "Runner inventory is unavailable or invalid; verify the selected runner and retry."
            ) from exc

        action_rows = {
            str(item["action_id"]): item
            for item in canonical_inventory["actions"]
            if isinstance(item, Mapping)
        }
        effective_action_rows = dict(action_rows)
        package_bindings_by_action: dict[str, list[Mapping[str, Any]]] = {}
        for binding in self._catalog_snapshot.profile_action_bindings(profile):
            package_bindings_by_action.setdefault(str(binding["logical_action_id"]), []).append(
                binding
            )
        native_requirements_by_action = {
            str(item["logical_action_id"]): item
            for item in self._catalog_snapshot.profile_native_action_requirements(profile)
        }
        for action_id, bindings in package_bindings_by_action.items():
            opcode = str(bindings[0]["runner_opcode"])
            native = action_rows.get(opcode)
            if native is None:
                continue
            requirement = native_requirements_by_action.get(action_id)
            if (
                requirement is None
                or native.get("action_version") != requirement.get("action_version")
                or native.get("contract_digest") != requirement.get("contract_digest")
            ):
                raise RunnerReadinessError(
                    "Runner native action contract changed after package activation; "
                    "review and reactivate the package."
                )
            effective_action_rows[action_id] = {
                **dict(native),
                "action_id": action_id,
                "native_action_id": opcode,
                "package_bindings": [dict(item) for item in bindings],
            }
        missing = sorted(set(profile.enabled_actions) - set(effective_action_rows))
        if missing:
            raise RunnerReadinessError(
                "Runner inventory is missing enabled action(s): " + ", ".join(missing)
            )
        unavailable = sorted(
            action_id
            for action_id in profile.enabled_actions
            if effective_action_rows[action_id].get("readiness") != "ready"
        )
        if unavailable:
            raise RunnerReadinessError(
                "Runner enabled action(s) are not ready: " + ", ".join(unavailable)
            )
        platform = str(canonical_inventory["platform"])
        if platform not in profile.platforms:
            raise RunnerReadinessError("Runner platform is outside the selected profile allowlist.")

        cleanup = action_rows.get("sandbox.cleanup.v1")
        recovery_identity = {
            "schema_version": "bluefire.runner-recovery-identity.v1",
            "transport": identity["transport"],
            "inventory_status": "cleanup_available",
            "cleanup_action_digest": content_hash(cleanup),
            "receipt_protocol": canonical_inventory["receipt_protocol"],
        }
        binary_digest = identity.get("runner_binary_digest")
        if isinstance(binary_digest, str):
            recovery_identity["runner_binary_digest"] = binary_digest
        observed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        snapshot: Mapping[str, Any] = {
            "schema_version": "bluefire.execute-readiness.v1",
            "profile_id": profile.id,
            "runner_identity": identity,
            "runner_identity_digest": content_hash(identity),
            "inventory_digest": content_hash(canonical_inventory),
            "effective_inventory_digest": content_hash(
                {
                    "schema_version": "bluefire.effective-runner-inventory.v1",
                    "native_inventory_digest": content_hash(canonical_inventory),
                    "catalog_authority": self._catalog_snapshot.to_dict(),
                    "actions": [
                        dict(effective_action_rows[action_id])
                        for action_id in sorted(profile.enabled_actions)
                    ],
                }
            ),
            "catalog_authority": self._catalog_snapshot.to_dict(),
            "platform": platform,
            "enabled_actions": [
                dict(effective_action_rows[action_id])
                for action_id in sorted(profile.enabled_actions)
            ],
            "sandbox": sandbox_readiness,
            "freshness": {
                "observed_at": observed_at,
                "max_age_seconds": _EXECUTE_READINESS_MAX_AGE_SECONDS,
            },
            "recovery_identity": recovery_identity,
        }
        if expected_snapshot is not None:
            for field in (
                "profile_id",
                "runner_identity",
                "runner_identity_digest",
                "inventory_digest",
                "effective_inventory_digest",
                "catalog_authority",
                "platform",
                "enabled_actions",
                "sandbox",
                "recovery_identity",
            ):
                if expected_snapshot.get(field) != snapshot.get(field):
                    raise RunnerReadinessError(
                        "Runner readiness changed after review; submit a new Execute request."
                    )
            return runner, sandbox, expected_snapshot
        if for_dispatch:
            runner = InventoryBoundRunner(
                runner,
                expected_inventory_digest=str(snapshot["inventory_digest"]),
                expected_identity_digest=str(snapshot["runner_identity_digest"]),
                recovery_identity=recovery_identity,
                dispatch_lease=self._catalog_dispatch_lease(snapshot["catalog_authority"]),
            )
        return runner, sandbox, snapshot

    def _catalog_dispatch_lease(
        self,
        authority: Mapping[str, Any],
    ) -> Callable[[], AbstractContextManager[Any]]:
        generation = int(authority["generation"])
        catalog_digest = str(authority["catalog_digest"])

        def lease() -> AbstractContextManager[Any]:
            return self.product_store.action_package_catalog_dispatch_lease(
                generation,
                catalog_digest,
            )

        return lease

    @staticmethod
    def _sandbox_root_readiness(configured_root: str | Path) -> Mapping[str, Any]:
        """Verify sandbox containment and writability without creating anything."""

        candidate = Path(configured_root).expanduser()
        try:
            if not candidate.is_absolute() or candidate.is_symlink() or not candidate.exists():
                raise RunnerReadinessError(
                    "Configured sandbox root is missing or unsafe; create a dedicated directory."
                )
            if not candidate.is_dir():
                raise RunnerReadinessError(
                    "Configured sandbox root is unusable; select a writable directory."
                )
            resolved = candidate.resolve(strict=True)
            mode = stat.S_IMODE(resolved.stat().st_mode)
            write_bits = stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
            if not mode & write_bits or not os.access(resolved, os.W_OK):
                raise RunnerReadinessError(
                    "Configured sandbox root is unusable; grant write access and retry."
                )
            execution_parent = resolved / ".bluefire-executions"
            if execution_parent.is_symlink():
                raise RunnerReadinessError(
                    "Configured sandbox execution parent is unsafe; remove the symbolic link."
                )
            if execution_parent.exists():
                if not execution_parent.is_dir():
                    raise RunnerReadinessError("Configured sandbox execution parent is unusable.")
                parent_mode = stat.S_IMODE(execution_parent.stat().st_mode)
                if not parent_mode & write_bits or not os.access(execution_parent, os.W_OK):
                    raise RunnerReadinessError(
                        "Configured sandbox execution parent is not writable."
                    )
        except RunnerReadinessError:
            raise
        except OSError as exc:
            raise RunnerReadinessError(
                "Configured sandbox root could not be verified safely."
            ) from exc
        return {
            "state": "ready",
            "root_digest": content_hash({"resolved_sandbox_root": str(resolved)}),
            "execution_parent": "ready",
            "checked_without_creation": True,
        }

    @staticmethod
    def _validated_execute_readiness(
        profile: RunnerProfile,
        value: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        required = {
            "schema_version",
            "profile_id",
            "runner_identity",
            "runner_identity_digest",
            "inventory_digest",
            "effective_inventory_digest",
            "catalog_authority",
            "platform",
            "enabled_actions",
            "sandbox",
            "freshness",
            "recovery_identity",
        }
        if not isinstance(value, Mapping) or set(value) != required:
            raise RunnerReadinessError(
                "Execute readiness binding is invalid; submit a new Execute request."
            )
        identity = value.get("runner_identity")
        freshness = value.get("freshness")
        enabled_actions = value.get("enabled_actions")
        catalog_authority = value.get("catalog_authority")
        sandbox = value.get("sandbox")
        recovery_identity = value.get("recovery_identity")
        if (
            value.get("schema_version") != "bluefire.execute-readiness.v1"
            or value.get("profile_id") != profile.id
            or not isinstance(identity, Mapping)
            or value.get("runner_identity_digest") != content_hash(identity)
            or not isinstance(value.get("inventory_digest"), str)
            or not str(value["inventory_digest"]).startswith("sha256:")
            or not isinstance(value.get("effective_inventory_digest"), str)
            or not isinstance(catalog_authority, Mapping)
            or value.get("platform") not in profile.platforms
            or not isinstance(enabled_actions, list)
            or not isinstance(sandbox, Mapping)
            or not isinstance(freshness, Mapping)
            or not isinstance(recovery_identity, Mapping)
        ):
            raise RunnerReadinessError(
                "Execute readiness binding is invalid; submit a new Execute request."
            )
        action_ids = [
            item.get("action_id") for item in enabled_actions if isinstance(item, Mapping)
        ]
        if (
            action_ids != sorted(profile.enabled_actions)
            or len(action_ids) != len(enabled_actions)
            or any(
                not isinstance(item, Mapping) or item.get("readiness") != "ready"
                for item in enabled_actions
            )
        ):
            raise RunnerReadinessError(
                "Execute readiness action binding is invalid; submit a new Execute request."
            )
        catalog_body = dict(catalog_authority)
        authority_digest = catalog_body.pop("authority_digest", None)
        if (
            catalog_authority.get("schema_version") != "bluefire.action-catalog-authority.v1"
            or authority_digest != content_hash(catalog_body)
            or value.get("effective_inventory_digest")
            != content_hash(
                {
                    "schema_version": "bluefire.effective-runner-inventory.v1",
                    "native_inventory_digest": value["inventory_digest"],
                    "catalog_authority": dict(catalog_authority),
                    "actions": [dict(item) for item in enabled_actions],
                }
            )
        ):
            raise RunnerReadinessError(
                "Execute readiness catalog binding is invalid; submit a new Execute request."
            )
        observed = freshness.get("observed_at")
        maximum_age = freshness.get("max_age_seconds")
        if not isinstance(observed, str) or maximum_age != _EXECUTE_READINESS_MAX_AGE_SECONDS:
            raise RunnerReadinessError(
                "Execute readiness freshness is invalid; submit a new Execute request."
            )
        try:
            observed_at = datetime.fromisoformat(observed.replace("Z", "+00:00"))
        except ValueError as exc:
            raise RunnerReadinessError(
                "Execute readiness freshness is invalid; submit a new Execute request."
            ) from exc
        if observed_at.tzinfo is None:
            raise RunnerReadinessError(
                "Execute readiness freshness is invalid; submit a new Execute request."
            )
        age = (datetime.now(timezone.utc) - observed_at.astimezone(timezone.utc)).total_seconds()
        if age < -5 or age > _EXECUTE_READINESS_MAX_AGE_SECONDS:
            raise RunnerReadinessError("Execute readiness expired; submit a new Execute request.")
        return dict(value)

    @staticmethod
    def _sanitized_runner_probe(
        profile: RunnerProfile,
        inventory: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        unavailable: Mapping[str, Any] = {
            "schema_version": "bluefire.runner-probe.v1",
            "profile_id": profile.id,
            "version": None,
            "platform": None,
            "actions": [],
            "health": {
                "state": "invalid_response",
                "message": "Runner inventory did not match the supported contract.",
            },
        }
        if inventory.get("schema_version") != "bluefire.runner-inventory.v1":
            return unavailable
        version = _bounded_probe_token(inventory.get("runner_version"), maximum=128)
        platform = inventory.get("platform")
        raw_actions = inventory.get("actions")
        if (
            version is None
            or not isinstance(platform, str)
            or platform not in {"linux", "macos", "windows"}
            or not isinstance(raw_actions, list)
        ):
            return unavailable
        if len(raw_actions) > _RUNNER_PROBE_MAX_ACTIONS:
            return unavailable

        actions: list[Mapping[str, Any]] = []
        action_ids: set[str] = set()
        for raw_action in raw_actions:
            if not isinstance(raw_action, Mapping):
                return unavailable
            action_id = _bounded_probe_token(raw_action.get("action_id"), maximum=200)
            if action_id is None or not _MANAGEMENT_IDENTIFIER.fullmatch(action_id):
                return unavailable
            action: dict[str, Any] = {"action_id": action_id}
            action_version = _bounded_probe_token(raw_action.get("action_version"), maximum=64)
            readiness = _bounded_probe_token(raw_action.get("readiness"), maximum=64)
            if action_version is not None:
                action["version"] = action_version
            if readiness is not None:
                action["readiness"] = readiness
            actions.append(action)
            action_ids.add(action_id)

        problems: list[str] = []
        if platform not in profile.platforms:
            problems.append("Runner platform is outside the stored profile allowlist.")
        missing_actions = sorted(set(profile.enabled_actions) - action_ids)
        if missing_actions:
            problems.append("Runner inventory is missing profile-enabled actions.")
        return {
            "schema_version": "bluefire.runner-probe.v1",
            "profile_id": profile.id,
            "version": version,
            "platform": platform,
            "actions": actions,
            "health": {
                "state": "degraded" if problems else "ready",
                "message": problems[0] if problems else "Runner inventory is available.",
                "missing_actions": missing_actions,
            },
        }

    @staticmethod
    def _isolated_execution_sandbox(
        configured_root: Path,
        approval_record: Mapping[str, Any],
    ) -> Path:
        approval_id = approval_record.get("approval_id")
        if not isinstance(approval_id, str) or not approval_id.startswith("approval-"):
            raise RunnerContractError("Execute approval has no stable workspace identity")
        base = configured_root.resolve(strict=True)
        executions = base / ".bluefire-executions"
        if executions.is_symlink():
            raise RunnerContractError("execution workspace parent cannot be a symbolic link")
        executions.mkdir(parents=False, exist_ok=True)
        execution_parent = executions.resolve(strict=True)
        if execution_parent.parent != base:
            raise RunnerContractError("execution workspace parent escaped the configured sandbox")
        candidate = execution_parent / approval_id
        if candidate.is_symlink():
            raise RunnerContractError("execution workspace cannot be a symbolic link")
        candidate.mkdir(parents=False, exist_ok=True)
        resolved = candidate.resolve(strict=True)
        if resolved.parent != execution_parent:
            raise RunnerContractError("execution workspace escaped the configured sandbox")
        return resolved

    def _scenario(self, request: Mapping[str, Any]) -> ScenarioDefinition:
        value = request.get("scenario")
        if isinstance(value, Mapping):
            return ScenarioDefinition.from_mapping(value)
        scenario_id = request.get("scenario_id")
        if isinstance(scenario_id, str):
            saved = self.product_store.get_scenario(scenario_id)
            document = saved.get("document")
            if not isinstance(document, Mapping):
                raise ContractError("saved scenario document is invalid")
            return ScenarioDefinition.from_mapping(document)
        raise ContractError("request must include a scenario object or known scenario_id")

    def _load_default_config(self, configured: str | Path | None) -> BlueFireConfig:
        if configured is not None:
            return load_config(configured)
        checkout_path = self.project_root / "config" / "bluefire.example.yaml"
        if checkout_path.is_file():
            return load_config(checkout_path)
        resource = files("bluefire.data").joinpath("bluefire.example.yaml")
        with as_file(resource) as resource_path:
            return load_config(resource_path)

    def _load_scenarios(self) -> tuple[ScenarioDefinition, ...]:
        checkout_root = (self.project_root / "scenarios").resolve()
        scenarios: list[ScenarioDefinition] = []
        if checkout_root.is_dir():
            for candidate in sorted(checkout_root.iterdir(), key=lambda item: item.name):
                if candidate.suffix.casefold() not in {".yaml", ".yml"} or not candidate.is_file():
                    continue
                resolved = candidate.resolve(strict=True)
                try:
                    resolved.relative_to(checkout_root)
                except ValueError as exc:
                    raise ContractError("scenario path escapes the checkout scenario root") from exc
                scenarios.append(load_scenario(resolved))
        else:
            data_root = files("bluefire.data")
            for resource in sorted(data_root.iterdir(), key=lambda item: item.name):
                if not resource.name.casefold().endswith((".yaml", ".yml")):
                    continue
                try:
                    raw = yaml.safe_load(resource.read_text(encoding="utf-8"))
                except (OSError, UnicodeError, yaml.YAMLError) as exc:
                    raise ContractError(f"packaged YAML cannot be loaded: {resource.name}") from exc
                if isinstance(raw, Mapping) and raw.get("schema_version") == (
                    "bluefire.scenario.v1"
                ):
                    scenarios.append(
                        ScenarioDefinition.from_mapping(raw, f"packaged scenario {resource.name}")
                    )

        if not scenarios:
            raise ContractError("no scenario definitions were found")
        identifiers: set[str] = set()
        for scenario in scenarios:
            if scenario.id in identifiers:
                raise ContractError(f"duplicate scenario ID: {scenario.id}")
            identifiers.add(scenario.id)
            self.registry.validate_scenario(scenario)
        return tuple(scenarios)

    def _scenario_or_api_error(self, request: Mapping[str, Any]) -> ScenarioDefinition:
        try:
            scenario = self._scenario(request)
            self.registry.validate_scenario(scenario)
            return scenario
        except (ContractError, RegistryError, KeyError, ValueError, TypeError) as exc:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "scenario_invalid",
                "Scenario validation failed.",
                [str(exc)],
            ) from exc

    @staticmethod
    def _mode(request: Mapping[str, Any]) -> ExecutionMode:
        try:
            return ExecutionMode(request.get("mode", "simulate"))
        except ValueError as exc:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "mode_invalid",
                "Mode must be simulate or execute.",
            ) from exc

    def _refresh_runtime_configuration(self) -> None:
        """Rebuild immutable runtime snapshots from validated active resources."""

        with self._runtime_configuration_lock:
            profiles = {profile.id: profile for profile in self.config.runner_profiles}
            for resource in self.product_store.list_resources("runner_profile"):
                resource_id = resource.get("id")
                status = resource.get("status")
                if not isinstance(resource_id, str):
                    continue
                if status == "inactive":
                    profiles.pop(resource_id, None)
                    continue
                if status != "active":
                    continue
                profiles.pop(resource_id, None)
                document = resource.get("document")
                if not isinstance(document, Mapping):
                    continue
                try:
                    profiles[resource_id] = self._validated_runner_profile(
                        document,
                        resource_id,
                    )
                except (ContractError, RegistryError):
                    continue
            self._runtime_runner_profiles = tuple(
                profiles[profile_id] for profile_id in sorted(profiles)
            )

            providers = {provider.id: provider for provider in self.config.ai.providers}
            active_candidates: list[tuple[str, str, AIProviderConfig]] = []
            for resource in self.product_store.list_resources("model_provider"):
                resource_id = resource.get("id")
                status = resource.get("status")
                if not isinstance(resource_id, str):
                    continue
                if status == "inactive":
                    if resource_id != self.config.ai.fallback_provider:
                        providers.pop(resource_id, None)
                    continue
                if status != "active":
                    continue
                providers.pop(resource_id, None)
                document = resource.get("document")
                if not isinstance(document, Mapping):
                    continue
                try:
                    provider = self._validated_ai_provider(document, resource_id)
                except ContractError:
                    continue
                if (
                    resource_id == self.config.ai.fallback_provider
                    and provider.kind is not AIProviderKind.DETERMINISTIC
                ):
                    continue
                providers[resource_id] = provider
                active_candidates.append(
                    (str(resource.get("updated_at", "")), resource_id, provider)
                )

            fallback = providers.get(self.config.ai.fallback_provider, self.config.ai.fallback)
            if fallback.kind is not AIProviderKind.DETERMINISTIC:
                fallback = self.config.ai.fallback
            providers[fallback.id] = fallback
            if active_candidates:
                active_provider = max(active_candidates, key=lambda item: (item[0], item[1]))[1]
            elif self.config.ai.active_provider in providers:
                active_provider = self.config.ai.active_provider
            else:
                active_provider = fallback.id
            self._runtime_ai_config = AIConfig(
                autonomy=self.config.ai.autonomy,
                active_provider=active_provider,
                fallback_provider=fallback.id,
                providers=tuple(providers[provider_id] for provider_id in sorted(providers)),
            )

    def _runner_profiles(self) -> tuple[RunnerProfile, ...]:
        with self._runtime_configuration_lock:
            return self._runtime_runner_profiles

    def _runner_lifecycle_profile(self, profile_id: str | None) -> RunnerProfile | None:
        if profile_id is None:
            return None
        if not isinstance(profile_id, str) or not profile_id:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "profile_invalid",
                "profile_id must be a non-empty string or null.",
            )
        profile = self._profile(profile_id, ExecutionMode.EXECUTE)
        if profile is None:
            raise APIError(
                HTTPStatus.NOT_FOUND,
                "profile_not_found",
                "Runner profile was not found.",
            )
        return profile

    def _runtime_ai(self) -> AIConfig:
        with self._runtime_configuration_lock:
            return self._runtime_ai_config

    def _runtime_resource(
        self,
        kind: str,
        resource_id: str,
    ) -> Mapping[str, Any]:
        try:
            return self.product_store.get_resource(kind, resource_id)
        except ProductStoreError as exc:
            raise APIError(
                HTTPStatus.NOT_FOUND,
                "resource_not_found",
                "Resource was not found.",
            ) from exc

    def _save_plugin_resource(
        self,
        resource_id: str,
        request: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Persist a strict manifest without installing or importing anything."""

        if set(request) != {"document"} or not isinstance(request.get("document"), Mapping):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "plugin_request_invalid",
                "A plugin update requires only a declarative manifest document.",
            )
        try:
            manifest = PluginManifest.from_mapping(
                request["document"],
                "persisted plugin manifest",
            )
            if manifest.id != resource_id:
                raise PluginManifestError(
                    "persisted plugin manifest ID does not match its resource ID"
                )
        except ContractError as exc:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "plugin_manifest_invalid",
                "The declarative plugin manifest was rejected.",
                [str(exc)],
            ) from exc

        with self._runtime_configuration_lock:
            try:
                current = self.product_store.get_resource("plugin", resource_id)
            except ProductStoreError:
                current = None
            if current is not None and current.get("status") == "active":
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "plugin_deactivation_required",
                    "Deactivate an active plugin manifest before editing it.",
                )
            if current is not None and current.get("status") == "inactive":
                status = "inactive"
            elif not manifest.enabled:
                status = "disabled"
            elif manifest.trust is PluginTrust.UNTRUSTED:
                status = "review_required"
            else:
                status = "ready"
            try:
                resource = self.product_store.save_resource(
                    "plugin",
                    resource_id,
                    manifest.to_dict(),
                    status=status,
                )
            except ProductStoreError as exc:
                raise APIError(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "plugin_manifest_invalid",
                    "The declarative plugin manifest could not be persisted.",
                    [str(exc)],
                ) from exc
        return {
            "schema_version": "bluefire.plugin-resource.v1",
            "resource": resource,
            "health": self._plugin_health(resource),
            "executable_loading": False,
            "dynamic_actions": False,
        }

    def _activate_plugin(self, resource_id: str) -> Mapping[str, Any]:
        self._runtime_resource("plugin", resource_id)
        raise APIError(
            HTTPStatus.CONFLICT,
            "plugin_activation_retired",
            "Legacy declarative plugin activation is retired; install and activate a signed action package.",
        )

    def _deactivate_plugin(self, resource_id: str) -> Mapping[str, Any]:
        with self._runtime_configuration_lock:
            resource = self._runtime_resource("plugin", resource_id)
            document = resource.get("document")
            try:
                manifest = PluginManifest.from_mapping(
                    document,
                    "persisted plugin manifest",
                )
                if manifest.id != resource_id:
                    raise PluginManifestError(
                        "persisted plugin manifest ID does not match its resource ID"
                    )
                inactive = self.product_store.save_resource(
                    "plugin",
                    resource_id,
                    manifest.to_dict(),
                    status="inactive",
                )
            except (ContractError, ProductStoreError) as exc:
                raise APIError(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "plugin_deactivation_refused",
                    "The declarative plugin manifest could not be deactivated.",
                    [str(exc)],
                ) from exc
        return {
            "schema_version": "bluefire.plugin-activation.v1",
            "resource": inactive,
            "health": self._plugin_health(inactive),
            "inventory": self._plugin_inventory(),
            "registration": "metadata_only",
            "executable_loading": False,
            "dynamic_actions": False,
        }

    def _plugin_inventory(self) -> Mapping[str, Any]:
        resources = self.product_store.list_resources("plugin")
        active_ids = sorted(
            str(item["id"])
            for item in resources
            if item.get("status") == "active" and isinstance(item.get("id"), str)
        )
        return {
            "schema_version": "bluefire.plugin-inventory.v1",
            "lifecycle": "declarative-manifest-only",
            "manifest_count": len(resources),
            "active_manifest_ids": active_ids,
            "health": {
                "state": "ready",
                "message": "Declarative plugin metadata inventory is available.",
            },
            "executable_loading": False,
            "dynamic_actions": False,
            "python_entry_points": False,
        }

    @staticmethod
    def _plugin_health(resource: Mapping[str, Any]) -> Mapping[str, Any]:
        status = str(resource.get("status", "unavailable"))
        return {
            "state": status,
            "message": (
                "Manifest metadata is registered; executable loading remains disabled."
                if status == "active"
                else "Manifest metadata is not active."
            ),
        }

    @staticmethod
    def _runtime_resource_kind(kind: str) -> str:
        stable_kind = _managed_resource_kind(kind)
        if stable_kind not in _RUNTIME_RESOURCE_KINDS | {"plugin"}:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "resource_not_activatable",
                "Only runner profiles, model providers, and plugin manifests can be activated.",
            )
        return stable_kind

    @staticmethod
    def _empty_runtime_action(request: Mapping[str, Any]) -> None:
        if request:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "resource_action_invalid",
                "Runtime resource actions require an empty JSON object.",
            )

    def _validated_runner_profile(
        self,
        document: Mapping[str, Any],
        expected_id: str,
    ) -> RunnerProfile:
        profile = RunnerProfile.from_mapping(document, "persisted runner profile")
        if profile.id != expected_id:
            raise ConfigError("persisted runner profile ID does not match its resource ID")
        self.registry.validate_runner_profile(profile)
        return profile

    @staticmethod
    def _validated_ai_provider(
        document: Mapping[str, Any],
        expected_id: str,
    ) -> AIProviderConfig:
        candidate: Any = document
        if set(document) == {"config", "runtime"} and isinstance(document.get("config"), Mapping):
            candidate = document["config"]
        provider = AIProviderConfig.from_mapping(candidate, "persisted AI provider")
        if provider.id != expected_id:
            raise ConfigError("persisted AI provider ID does not match its resource ID")
        return provider

    def _profile(self, value: Any, mode: ExecutionMode) -> RunnerProfile | None:
        return self._profile_for_catalog(value, mode, self._catalog_snapshot)

    def _profile_for_catalog(
        self,
        value: Any,
        mode: ExecutionMode,
        catalog: ActionCatalogSnapshot,
    ) -> RunnerProfile | None:
        profiles = tuple(catalog.profile(profile) for profile in self._runner_profiles())
        if value is None or value == "":
            if mode is ExecutionMode.EXECUTE:
                return None
            return next(
                (profile for profile in profiles if profile.mode is mode),
                None,
            )
        if not isinstance(value, str):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "profile_invalid",
                "runner_profile_id must be a string or null.",
            )
        for profile in profiles:
            if profile.id == value:
                if profile.mode is not mode:
                    raise APIError(
                        HTTPStatus.CONFLICT,
                        "profile_mode_mismatch",
                        "Runner profile mode does not match the requested mode.",
                    )
                return profile
        raise APIError(HTTPStatus.NOT_FOUND, "profile_not_found", "Runner profile was not found.")

    @staticmethod
    def _approval(request: Mapping[str, Any], *, required: bool) -> str | None:
        value = request.get("approval")
        if value is None:
            if required:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "approval_required",
                    "Execute requires explicit operator approval.",
                )
            return None
        if not isinstance(value, Mapping) or set(value) - {"confirmed", "approved_by"}:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "approval_invalid",
                "Approval must contain only confirmed and approved_by.",
            )
        confirmed = value.get("confirmed") is True
        identity = value.get("approved_by")
        if (
            not confirmed
            or not isinstance(identity, str)
            or not identity.strip()
            or len(identity.strip()) > 128
        ):
            if required:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "approval_required",
                    "Execute requires an unchecked-by-default explicit approval and identity.",
                )
            return None
        return identity.strip()

    def _stored_approval(
        self,
        request: Mapping[str, Any],
        *,
        mode: ExecutionMode,
    ) -> Mapping[str, Any] | None:
        approval_id = request.get("approval_request_id")
        if approval_id is None:
            return None
        if mode is not ExecutionMode.EXECUTE or not isinstance(approval_id, str):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "approval_invalid",
                "A stored approval capability is valid only for Execute.",
            )
        try:
            approval = self.product_store.get_approval_request(approval_id)
        except ProductStoreError as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "approval_refused",
                "The stored approval capability is unavailable.",
            ) from exc
        if approval.get("status") != "consumed" or not approval.get("nonce"):
            raise APIError(
                HTTPStatus.CONFLICT,
                "approval_refused",
                "The stored approval capability is not ready for execution.",
            )
        return approval

    def _ai_context(self, request: Mapping[str, Any]) -> tuple[AutonomyLevel, Mapping[str, Any]]:
        autonomy = self._autonomy(request)
        provider_id = self._resolve_ai_provider_id(request.get("ai_provider_id"))
        return autonomy, self._ai_provider_metadata(autonomy, provider_id)

    def _autonomy(self, request: Mapping[str, Any]) -> AutonomyLevel:
        has_autonomy = "autonomy" in request
        has_legacy = "ai_enabled" in request
        if has_autonomy and has_legacy:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "autonomy_conflict",
                "Use autonomy or the legacy ai_enabled flag, not both.",
            )
        if has_autonomy:
            try:
                return AutonomyLevel(request["autonomy"])
            except (TypeError, ValueError) as exc:
                raise APIError(
                    HTTPStatus.BAD_REQUEST,
                    "autonomy_invalid",
                    "autonomy must be off, assist, or auto.",
                ) from exc
        if has_legacy:
            value = request["ai_enabled"]
            if not isinstance(value, bool):
                raise APIError(
                    HTTPStatus.BAD_REQUEST,
                    "ai_flag_invalid",
                    "ai_enabled must be a boolean.",
                )
            return AutonomyLevel.ASSIST if value else AutonomyLevel.OFF
        return self.config.autonomy

    @staticmethod
    def _optional_autonomy(request: Mapping[str, Any]) -> AutonomyLevel | None:
        raw_autonomy = request.get("autonomy")
        raw_legacy = request.get("ai_enabled")
        if raw_autonomy is not None and raw_legacy is not None:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "autonomy_conflict",
                "Use autonomy or the legacy ai_enabled flag, not both.",
            )
        if raw_autonomy is not None:
            try:
                return AutonomyLevel(raw_autonomy)
            except (TypeError, ValueError) as exc:
                raise APIError(
                    HTTPStatus.BAD_REQUEST,
                    "autonomy_invalid",
                    "autonomy must be off, assist, or auto.",
                ) from exc
        if raw_legacy is None:
            return None
        if not isinstance(raw_legacy, bool):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "ai_flag_invalid",
                "ai_enabled must be a boolean or null for replay.",
            )
        return AutonomyLevel.ASSIST if raw_legacy else AutonomyLevel.OFF

    def _optional_ai_provider_id(self, request: Mapping[str, Any]) -> str | None:
        if "ai_provider_id" not in request or request["ai_provider_id"] is None:
            return None
        return self._resolve_ai_provider_id(request["ai_provider_id"])

    def _resolve_ai_provider_id(self, value: Any) -> str:
        runtime_ai = self._runtime_ai()
        if value is None or value == "":
            return runtime_ai.active_provider
        if not isinstance(value, str):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "ai_provider_invalid",
                "ai_provider_id must be a string or null.",
            )
        try:
            return runtime_ai.provider(value).id
        except ConfigError as exc:
            raise APIError(
                HTTPStatus.NOT_FOUND,
                "ai_provider_not_found",
                "AI provider was not found.",
            ) from exc

    def _ai_provider_metadata(self, autonomy: AutonomyLevel, provider_id: str) -> Mapping[str, Any]:
        runtime_ai = self._runtime_ai()
        runtime = ai_runtime_metadata(
            runtime_ai,
            autonomy=autonomy,
            provider_id=provider_id,
        )
        return self._provider_metadata(runtime)

    def _proposal_provider(
        self,
        autonomy: AutonomyLevel,
        metadata: Mapping[str, Any],
    ) -> AIProvider | None:
        if autonomy is AutonomyLevel.OFF:
            return None
        provider_id = metadata.get("provider_id")
        if not isinstance(provider_id, str):
            raise AssertionError("validated AI provider metadata has no provider ID")
        return self.ai_provider_factory(self._runtime_ai(), provider_id)

    @staticmethod
    def _provider_metadata(runtime: Mapping[str, Any]) -> Mapping[str, Any]:
        provider = runtime.get("provider")
        health = runtime.get("health")
        if not isinstance(provider, Mapping) or not isinstance(health, Mapping):
            raise AssertionError("AI runtime metadata is incomplete")
        return {
            **provider,
            "health": dict(health),
            "proposal_application": runtime["proposal_application"],
            "trust_boundary": runtime["trust_boundary"],
        }

    @staticmethod
    def _scope_problems(
        request: Mapping[str, Any],
        profile: RunnerProfile | None,
        mode: ExecutionMode,
    ) -> Sequence[str]:
        if mode is ExecutionMode.EXECUTE and "target_scope" not in request:
            return ["Execute requires an explicit target_scope"]
        value = request.get("target_scope", {"scope_refs": ["sandbox.workspace"]})
        if not isinstance(value, Mapping) or set(value) != {"scope_refs"}:
            return ["target_scope must contain only scope_refs"]
        references = value.get("scope_refs")
        if (
            not isinstance(references, list)
            or not references
            or not all(isinstance(item, str) and item for item in references)
        ):
            return ["target_scope.scope_refs must be a non-empty string list"]
        if mode is ExecutionMode.EXECUTE:
            if profile is None:
                return ["an Execute runner profile is required before scope can be resolved"]
            extra = sorted(set(references) - set(profile.scope))
            if extra:
                return ["target scope is outside the selected profile: " + ", ".join(extra)]
        return []

    @staticmethod
    def _target_scope(request: Mapping[str, Any]) -> Mapping[str, Any]:
        value = request["target_scope"]
        if not isinstance(value, Mapping):
            raise AssertionError("target scope must be validated before use")
        references = value.get("scope_refs")
        if not isinstance(references, list):
            raise AssertionError("target scope references must be validated before use")
        return {"scope_refs": list(references)}

    def _maximum_tier(self, scenario: ScenarioDefinition) -> str:
        ranks = {"safe": 1, "controlled": 2, "restricted": 3}
        tiers = [
            self.registry.get_behavior(step.behavior_id).safety_tier.value
            for step in scenario.steps
        ]
        return max(tiers, key=ranks.__getitem__) if tiers else "safe"

    @staticmethod
    def _optional_string(value: Any) -> str | None:
        return value if isinstance(value, str) and value else None

    @staticmethod
    def _parameter_overrides(
        value: Any,
    ) -> Mapping[str, Mapping[str, Any]] | None:
        if value is None:
            return None
        if not isinstance(value, Mapping):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "parameter_overrides_invalid",
                "parameter_overrides must map step IDs to parameter objects.",
            )
        result: dict[str, Mapping[str, Any]] = {}
        for step_id, parameters in value.items():
            if not isinstance(step_id, str) or not step_id or not isinstance(parameters, Mapping):
                raise APIError(
                    HTTPStatus.BAD_REQUEST,
                    "parameter_overrides_invalid",
                    "parameter_overrides must map step IDs to parameter objects.",
                )
            result[step_id] = dict(parameters)
        return result

    @staticmethod
    def _action_implementations(
        request: Mapping[str, Any],
        *,
        mode: ExecutionMode,
    ) -> Mapping[str, str]:
        if "action_implementations" not in request:
            return {}
        if mode is ExecutionMode.SIMULATE:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "action_implementations_invalid",
                "Simulate does not accept action implementation selections.",
            )
        value = request.get("action_implementations")
        if not isinstance(value, Mapping) or len(value) > 100:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "action_implementations_invalid",
                "action_implementations must be a bounded step-to-action mapping.",
            )
        result: dict[str, str] = {}
        for step_id, action_id in value.items():
            if (
                not isinstance(step_id, str)
                or not _STEP_IMPLEMENTATION_ID.fullmatch(step_id)
                or not isinstance(action_id, str)
                or not 1 <= len(action_id) <= 200
                or not _MANAGEMENT_IDENTIFIER.fullmatch(action_id)
            ):
                raise APIError(
                    HTTPStatus.BAD_REQUEST,
                    "action_implementations_invalid",
                    "action_implementations must map bounded step IDs to registered action IDs.",
                )
            result[step_id] = action_id
        return result


def _management_identifier(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 200
        or not _MANAGEMENT_IDENTIFIER.fullmatch(value)
    ):
        raise APIError(
            HTTPStatus.BAD_REQUEST,
            "management_identifier_invalid",
            f"{context} must be a stable lowercase identifier of at most 200 characters.",
        )
    return value


def _managed_resource_kind(value: Any) -> str:
    if not isinstance(value, str) or value not in _MANAGED_RESOURCE_KINDS:
        raise APIError(
            HTTPStatus.BAD_REQUEST,
            "resource_kind_invalid",
            "Resource kind is not managed by this API.",
        )
    return value


def _bounded_probe_token(value: Any, *, maximum: int) -> str | None:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        return None
    if not _RUNNER_PROBE_VERSION.fullmatch(value):
        return None
    return value


__all__ = ["AIDraftProviderFactory", "AIProviderFactory", "BlueFireService", "RunnerFactory"]
