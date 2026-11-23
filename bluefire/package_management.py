"""Action-package trust, installation, activation, and immutable lifecycle operations."""

from __future__ import annotations

import base64
import binascii
import re
from http import HTTPStatus
from typing import Any, Mapping

from .action_packages import (
    ActionPackageError,
    VerifiedActionPackageActivation,
    audit_action_package,
    verify_action_package,
)
from .application_errors import APIError
from .config import RunnerProfile
from .contracts import ExecutionMode, SafetyTier
from .package_management_context import ActionPackageContext
from .product_store import (
    ActionPackageConflictError,
    ActionPackageIntegrityError,
    ProductStoreError,
)
from .runner_client import RunnerTransportError, runner_transport_identity
from .runner_contracts import RunnerContractError
from .util import canonical_json_bytes, content_hash


class ActionPackageOperations:
    """Manage reviewed package authority using the product's existing services."""

    def __init__(self, context: ActionPackageContext) -> None:
        self._context = context

    @staticmethod
    def _sanitized_action_package(record: Mapping[str, Any]) -> dict[str, Any]:
        """Recursively remove immutable package bytes from public responses."""

        private_fields = {
            "artifact_hex",
            "canonical_envelope_bytes",
            "canonical_content_bytes",
        }

        def sanitize(value: Any) -> Any:
            if isinstance(value, Mapping):
                return {
                    str(key): sanitize(child)
                    for key, child in value.items()
                    if key not in private_fields
                }
            if isinstance(value, list):
                return [sanitize(item) for item in value]
            if isinstance(value, tuple):
                return [sanitize(item) for item in value]
            return value

        result = sanitize(record)
        if not isinstance(result, dict):  # pragma: no cover - Mapping input invariant
            raise ProductStoreError("action-package public response is invalid")
        return result

    def action_packages(self) -> Mapping[str, Any]:
        """Return the audited package, publisher-trust, and active-catalog inventory."""

        with (
            self._context._action_catalog_lock,
            self._context.product_store.action_package_catalog_lease(),
        ):
            snapshot = self._context._action_catalog_boundary()
            packages = [
                self._sanitized_action_package(item)
                for item in self._context.product_store.list_action_packages()
            ]
            publishers = self._context.product_store.list_trusted_action_package_publishers()
            activation_events = self._context.product_store.list_action_package_activation_events()
        return {
            "schema_version": "bluefire.action-package-inventory.v1",
            "packages": packages,
            "publishers": publishers,
            "catalog": snapshot.to_dict(),
            "activation_events": activation_events,
            "execution_boundary": "signed-reviewed-opcodes-and-isolated-wasm-providers",
        }

    def action_package(
        self,
        package_id: str,
        *,
        version: str | None = None,
    ) -> Mapping[str, Any]:
        try:
            package = self._sanitized_action_package(
                self._context.product_store.get_action_package(package_id, version)
            )
            versions = [
                self._sanitized_action_package(item)
                for item in self._context.product_store.list_action_package_versions(package_id)
            ]
            events = self._context.product_store.list_action_package_lifecycle_events(package_id)
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
            trust = self._context.product_store.trust_action_package_publisher(
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
        with (
            self._context._action_catalog_lock,
            self._context.product_store.action_package_catalog_lease(),
        ):
            self._context._action_catalog_boundary()
            try:
                if action == "suspend":
                    trust = self._context.product_store.suspend_action_package_publisher(
                        publisher_id,
                        key_id,
                        suspended_by=request["actor"],
                        reason=request["reason"],
                    )
                else:
                    trust = self._context.product_store.revoke_action_package_publisher(
                        publisher_id,
                        key_id,
                        revoked_by=request["actor"],
                        reason=request["reason"],
                    )
                catalog = self._context._refresh_action_catalog()
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
        behavior_ids = set(self._context._built_in_registry.behavior_ids)
        action_ids = set(self._context._built_in_registry.action_ids)
        for item in self._context.product_store.list_action_packages():
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
            signers = self._context.product_store.trusted_action_package_signers()
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
            package = self._context.product_store.install_action_package(
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
        with (
            self._context._action_catalog_lock,
            self._context.product_store.action_package_catalog_lease(),
        ):
            before = self._context._action_catalog_boundary()
            try:
                profile = self._context._profile(
                    request.get("runner_profile_id"), ExecutionMode.EXECUTE
                )
                if profile is None:
                    raise ProductStoreError("activation requires an explicit Execute profile")
                runner, _sandbox = self._context.runner_factory(profile)
                inventory = runner.inventory()
                identity = runner_transport_identity(runner, inventory)
                activation = self._context.product_store.prepare_action_package_activation(
                    package_id,
                    version,
                    runner_inventory=inventory,
                    runner_identity_digest=content_hash(identity),
                )
                if activation.package.provider is None:
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
                else:
                    base_profile = next(
                        (
                            candidate
                            for candidate in self._context._runner_profiles()
                            if candidate.id == profile.id
                        ),
                        None,
                    )
                    if base_profile is None:  # pragma: no cover - _profile invariant
                        raise RunnerContractError("selected Execute profile is unavailable")
                    self._validate_provider_activation_profile(activation, base_profile)
                package = self._context.product_store.activate_action_package(
                    activation,
                    activated_by=request["activated_by"],
                    reason=request["reason"],
                )
                after = self._context._refresh_action_catalog()
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

    @staticmethod
    def _validate_provider_activation_profile(
        activation: VerifiedActionPackageActivation,
        profile: RunnerProfile,
    ) -> None:
        """Require one base Execute profile to authorize the whole provider package."""

        package = activation.package
        manifest = package.manifest
        runner_platform = activation.runner_platform
        actions = tuple(item.definition for item in package.actions)
        if (
            "native.execution" not in profile.capabilities
            or SafetyTier.SAFE not in profile.safety_tiers
            or runner_platform not in profile.platforms
            or runner_platform not in manifest.platforms
            or "native.execution" not in manifest.capabilities
            or "safe" not in manifest.safety_tiers
            or not actions
            or any(
                action.safety_tier is not SafetyTier.SAFE
                or "native.execution" not in action.capabilities
                or runner_platform not in action.platforms
                or action.id in profile.blocked_actions
                for action in actions
            )
        ):
            raise RunnerContractError(
                "selected Execute profile cannot dispatch every provider package action"
            )

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
        with (
            self._context._action_catalog_lock,
            self._context.product_store.action_package_catalog_lease(),
        ):
            self._context._action_catalog_boundary()
            try:
                package = self._context.product_store.deactivate_action_package(
                    package_id,
                    version,
                    request["package_digest"],
                    expected_catalog_generation=request["expected_catalog_generation"],
                    expected_catalog_digest=request["expected_catalog_digest"],
                    deactivated_by=request["deactivated_by"],
                    reason=request["reason"],
                )
                catalog = self._context._refresh_action_catalog()
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
        with (
            self._context._action_catalog_lock,
            self._context.product_store.action_package_catalog_lease(),
        ):
            self._context._action_catalog_boundary()
            try:
                package = self._context.product_store.remove_action_package(
                    package_id,
                    version,
                    request["package_digest"],
                    expected_catalog_generation=request["expected_catalog_generation"],
                    expected_catalog_digest=request["expected_catalog_digest"],
                    removed_by=request["removed_by"],
                    reason=request["reason"],
                )
                catalog = self._context._refresh_action_catalog()
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
