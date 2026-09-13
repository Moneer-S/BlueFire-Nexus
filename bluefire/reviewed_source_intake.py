"""Reviewed source ingestion, package activation, and durable operation receipts."""

from __future__ import annotations

import base64
import binascii
import json
import re
from http import HTTPStatus
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any, Callable, Mapping, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import source_intake_package
from .action_catalog import ActionCatalogError
from .action_packages import ActionPackageError, audit_action_package, canonical_public_key_b64u
from .application_errors import APIError
from .contracts import ExecutionMode
from .product_store import ActionPackageIntegrityError, ProductStoreError
from .source_intake import SourceIntakeError, perform_source_intake
from .source_intake_context import ReviewedSourceIntakeContext
from .source_intake_package import (
    _build_reviewed_t1082_operation_receipt,
    _validate_reviewed_t1082_operation_receipt,
)
from .source_intake_publication import (
    _filesystem_identity,
    _unsafe_regular_file_metadata,
    _verify_reviewed_source_license,
)
from .source_intake_workspace import (
    _REVIEWED_T1082_RECEIPT_FILE,
    _REVIEWED_T1082_STAGE_SCHEMA,
    _allocate_source_intake_destination,
    _publish_reviewed_t1082_operation_receipt,
    _read_interrupted_t1082_destination,
    _read_reviewed_t1082_package_stage,
    _release_failed_source_intake_destination,
    _remove_reviewed_t1082_package_stage,
    _source_intake_release_detail,
    _stage_reviewed_t1082_package,
)
from .util import canonical_json_bytes, content_hash

_WINDOWS_DEVICE_NAMES = frozenset(
    {"aux", "con", "nul", "prn"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)


def _source_intake_operator(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 128
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise APIError(
            HTTPStatus.BAD_REQUEST,
            "source_intake_operator_invalid",
            "operator_id must be a printable non-empty string of at most 128 characters.",
        )
    return value


class ReviewedSourceIntake:
    """Complete the shipped reviewed intake using explicitly borrowed services."""

    def __init__(
        self,
        context: ReviewedSourceIntakeContext,
        identifier: Callable[[Any, str], str],
    ) -> None:
        self._context = context
        self._identifier = identifier

    def intake_reviewed_t1082(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        """Import and activate the one shipped, reviewed ATT&CK T1082 source."""

        if set(request) != {"destination_id", "runner_profile_id", "operator_id"}:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "source_intake_request_invalid",
                (
                    "Reviewed T1082 intake requires exactly destination_id, "
                    "runner_profile_id, and operator_id."
                ),
            )
        destination_id = self._identifier(
            request.get("destination_id"), "source-intake destination ID"
        )
        runner_profile_id = request.get("runner_profile_id")
        profile = self._context._profile(runner_profile_id, ExecutionMode.EXECUTE)
        if profile is None:  # pragma: no cover - explicit value is required above
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "source_intake_request_invalid",
                "Reviewed T1082 intake requires an explicit Execute runner profile.",
            )
        operator_id = _source_intake_operator(request.get("operator_id"))
        if destination_id.split(".", 1)[0] in _WINDOWS_DEVICE_NAMES:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "source_intake_destination_invalid",
                "The source-intake destination ID is reserved by a supported platform.",
            )

        # The database inode lease is the durable operation owner. Holding it
        # from namespace allocation through receipt publication prevents a
        # second service instance from mistaking a live operation for a crash,
        # and keeps every snapshot-derived lifecycle label authoritative.
        try:
            with (
                self._context._action_catalog_lock,
                self._context.product_store.action_package_catalog_lease(),
            ):
                return self._intake_reviewed_t1082_owned(
                    destination_id=destination_id,
                    runner_profile_id=profile.id,
                    operator_id=operator_id,
                )
        except ProductStoreError as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "source_intake_operation_unavailable",
                "The reviewed T1082 intake operation lease is unavailable.",
            ) from exc

    def _intake_reviewed_t1082_owned(
        self,
        *,
        destination_id: str,
        runner_profile_id: str,
        operator_id: str,
    ) -> Mapping[str, Any]:
        """Complete one intake while its durable operation lease is held."""

        destination, destination_identity, intake_root_identity, destination_created = (
            _allocate_source_intake_destination(self._context.store.root, destination_id)
        )
        published_artifact: tuple[Path, tuple[int, int, int], bytes] | None = None
        published_receipt: tuple[Path, tuple[int, int, int], bytes] | None = None
        try:
            license_resource = files("bluefire.data").joinpath(source_intake_package.LICENSE_ASSET)
            with as_file(license_resource) as license_path:
                license_review = _verify_reviewed_source_license(license_path)
            existing_receipt: tuple[Mapping[str, Any], bytes, tuple[int, int, int]] | None = None
            if destination_created:
                source_resource = files("bluefire.data").joinpath(
                    source_intake_package.SOURCE_ASSET
                )
                with as_file(source_resource) as source_path:
                    result = perform_source_intake(
                        source_path.parent,
                        destination,
                        source_intake_package.gate09_intake_request(),
                    )
                published_metadata = result.path.lstat()
                published_payload = canonical_json_bytes(result.envelope)
                if (
                    result.path.parent != destination
                    or result.path.name != f"{source_intake_package.INTAKE_ID}.json"
                    or _unsafe_regular_file_metadata(published_metadata)
                ):
                    raise SourceIntakeError("source intake returned an unsafe published artifact")
                published_artifact = (
                    result.path,
                    _filesystem_identity(published_metadata),
                    published_payload,
                )
                envelope = source_intake_package.validate_gate09_intake_envelope(result.envelope)
            else:
                envelope, existing_receipt = _read_interrupted_t1082_destination(
                    destination,
                    destination_identity=destination_identity,
                )
            artifact_payload = canonical_json_bytes(envelope)
            artifact_ref = f"source-intakes/{destination_id}/{source_intake_package.INTAKE_ID}.json"
            if existing_receipt is None:
                package_activation = self._activate_reviewed_t1082_intake(
                    envelope,
                    runner_profile_id=runner_profile_id,
                    operator_id=operator_id,
                )
                receipt_record = _build_reviewed_t1082_operation_receipt(
                    destination_id=destination_id,
                    operator_id=operator_id,
                    runner_profile_id=runner_profile_id,
                    envelope=envelope,
                    artifact_ref=artifact_ref,
                    artifact_size_bytes=len(artifact_payload),
                    package_activation=package_activation,
                )
                receipt_record = _validate_reviewed_t1082_operation_receipt(
                    receipt_record,
                    destination_id=destination_id,
                    operator_id=operator_id,
                    runner_profile_id=runner_profile_id,
                    envelope=envelope,
                    artifact_ref=artifact_ref,
                    artifact_size_bytes=len(artifact_payload),
                    package_activation=package_activation,
                )
                receipt_path, receipt_identity, receipt_payload = (
                    _publish_reviewed_t1082_operation_receipt(
                        destination,
                        destination_identity=destination_identity,
                        receipt=receipt_record,
                    )
                )
                published_receipt = (receipt_path, receipt_identity, receipt_payload)
            else:
                receipt_record, receipt_payload, _receipt_identity = existing_receipt
                package_activation = self._completed_reviewed_t1082_activation(
                    receipt_record,
                    envelope=envelope,
                )
                receipt_record = _validate_reviewed_t1082_operation_receipt(
                    receipt_record,
                    destination_id=destination_id,
                    operator_id=operator_id,
                    runner_profile_id=runner_profile_id,
                    envelope=envelope,
                    artifact_ref=artifact_ref,
                    artifact_size_bytes=len(artifact_payload),
                    package_activation=package_activation,
                )
            operation_receipt = {
                "media_type": (
                    "application/vnd.bluefire.reviewed-source-intake-operation-receipt+json"
                ),
                "sha256": content_hash(receipt_record),
                "size_bytes": len(receipt_payload),
                "state_ref": (f"source-intakes/{destination_id}/{_REVIEWED_T1082_RECEIPT_FILE}"),
                "record": receipt_record,
            }
        except (OSError, SourceIntakeError, source_intake_package.SourceIntakePackageError) as exc:
            release = _release_failed_source_intake_destination(
                destination,
                destination_identity=destination_identity,
                intake_root_identity=intake_root_identity,
                destination_created=destination_created,
                published_artifact=published_artifact,
                published_receipt=published_receipt,
            )
            details = (
                [str(exc)]
                if isinstance(
                    exc,
                    (SourceIntakeError, source_intake_package.SourceIntakePackageError),
                )
                else []
            )
            release_detail = _source_intake_release_detail(release)
            if release_detail is not None:
                details.append(release_detail)
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "source_intake_rejected",
                "The reviewed T1082 source intake was rejected.",
                details or None,
            ) from exc
        except Exception:
            _release_failed_source_intake_destination(
                destination,
                destination_identity=destination_identity,
                intake_root_identity=intake_root_identity,
                destination_created=destination_created,
                published_artifact=published_artifact,
                published_receipt=published_receipt,
            )
            raise

        return {
            "schema_version": "bluefire.reviewed-source-intake-result.v1",
            "destination_id": destination_id,
            "artifact": {
                "media_type": "application/vnd.bluefire.source-intake+json",
                "sha256": content_hash(envelope),
                "size_bytes": len(artifact_payload),
                "state_ref": artifact_ref,
            },
            "intake": {
                "intake_id": source_intake_package.INTAKE_ID,
                "record_sha256": envelope["record_sha256"],
                "output_sha256": envelope["record"]["transformation_history"][0]["output_sha256"],
                "execution_material_imported": False,
            },
            "license_review": license_review,
            "package_activation": package_activation,
            "operation_receipt": operation_receipt,
            "envelope": envelope,
        }

    def _activate_reviewed_t1082_intake(
        self,
        envelope: Mapping[str, Any],
        *,
        runner_profile_id: str,
        operator_id: str,
    ) -> Mapping[str, Any]:
        """Install or resume the fixed local package and revalidate its activation."""

        expected_manifest, expected_payload = source_intake_package.gate09_package_components(
            envelope
        )
        with (
            self._context._action_catalog_lock,
            self._context.product_store.action_package_catalog_lease(),
        ):
            before = self._context._action_catalog_boundary()
            behavior_was_available = (
                source_intake_package.BEHAVIOR_ID in before.registry.behavior_ids
            )
            action_was_available = source_intake_package.ACTION_ID in before.registry.action_ids
            try:
                package_heads = self._context.product_store.list_action_packages()
                matching_heads = [
                    item
                    for item in package_heads
                    if item.get("package_id") == source_intake_package.PACKAGE_ID
                ]
                if len(matching_heads) > 1:  # pragma: no cover - store uniqueness invariant
                    raise ProductStoreError("reviewed source package has multiple installed heads")
                existing = (
                    None
                    if not matching_heads
                    else self._context.product_store.get_action_package(
                        source_intake_package.PACKAGE_ID,
                        source_intake_package.PACKAGE_VERSION,
                    )
                )
            except (
                ActionPackageIntegrityError,
                ProductStoreError,
                TypeError,
                ValueError,
            ) as exc:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "source_intake_package_conflict",
                    "Existing local action-package state cannot accept the reviewed T1082 package.",
                    [str(exc)],
                ) from exc

            installed_now = existing is None
            active_before = bool(existing is not None and existing.get("active") is True)
            signing_key_lifecycle = "existing_locally_trusted_package"
            if existing is not None:
                self._validate_reviewed_t1082_package(
                    existing,
                    expected_manifest=expected_manifest,
                    expected_payload=expected_payload,
                )
                staged = _read_reviewed_t1082_package_stage(self._context.store.root)
                if staged is not None:
                    staged_document, staged_bytes, _stage_identity = staged
                    staged_envelope, _public_key, staged_trust_actor = (
                        self._validate_reviewed_t1082_stage(
                            staged_document,
                            expected_manifest=expected_manifest,
                            expected_payload=expected_payload,
                            expected_record_sha256=str(envelope["record_sha256"]),
                        )
                    )
                    if staged_trust_actor != operator_id:
                        raise APIError(
                            HTTPStatus.CONFLICT,
                            "source_intake_operator_conflict",
                            (
                                "The recoverable signed package stage belongs to a "
                                "different operator."
                            ),
                        )
                    if canonical_json_bytes(staged_envelope) != existing.get(
                        "canonical_envelope_bytes"
                    ):
                        raise APIError(
                            HTTPStatus.CONFLICT,
                            "source_intake_package_conflict",
                            "The recoverable signed package stage differs from the installed package.",
                        )
                    _remove_reviewed_t1082_package_stage(
                        self._context.store.root,
                        expected_payload=staged_bytes,
                    )
            else:
                private_key = Ed25519PrivateKey.generate()
                public_key = canonical_public_key_b64u(private_key.public_key())
                envelope_bytes = source_intake_package.build_gate09_action_package(
                    envelope,
                    private_key=private_key,
                )
                del private_key
                try:
                    signed_envelope = json.loads(envelope_bytes)
                except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
                    raise APIError(
                        HTTPStatus.UNPROCESSABLE_ENTITY,
                        "source_intake_package_rejected",
                        "The fixed reviewed T1082 package recipe produced invalid bytes.",
                    ) from exc
                proposed_stage = {
                    "schema_version": _REVIEWED_T1082_STAGE_SCHEMA,
                    "source_record_sha256": envelope["record_sha256"],
                    "public_key": public_key,
                    "trust_actor": operator_id,
                    "package_envelope": signed_envelope,
                }
                staged_document, stage_created, staged_bytes = _stage_reviewed_t1082_package(
                    self._context.store.root, proposed_stage
                )
                signed_envelope, public_key, trust_actor = self._validate_reviewed_t1082_stage(
                    staged_document,
                    expected_manifest=expected_manifest,
                    expected_payload=expected_payload,
                    expected_record_sha256=str(envelope["record_sha256"]),
                )
                if trust_actor != operator_id:
                    raise APIError(
                        HTTPStatus.CONFLICT,
                        "source_intake_operator_conflict",
                        ("The recoverable signed package stage belongs to a different operator."),
                    )
                self._context.trust_action_package_publisher(
                    {
                        "publisher_id": source_intake_package.PUBLISHER_ID,
                        "key_id": source_intake_package.KEY_ID,
                        "public_key": public_key,
                        "provenance": {
                            "schema_version": "bluefire.source-intake-signer-provenance.v1",
                            "source_intake_id": source_intake_package.INTAKE_ID,
                            "source_record_sha256": envelope["record_sha256"],
                            "purpose": "Local signing of the fixed reviewed T1082 package recipe.",
                            "private_key_lifecycle": "generated_in_memory_and_not_persisted",  # pragma: allowlist secret -- lifecycle label only
                            "network_used": False,
                        },
                        "trusted_by": trust_actor,
                    }
                )
                self._context.install_action_package(
                    {
                        "envelope": signed_envelope,
                        "installed_by": operator_id,
                    }
                )
                _remove_reviewed_t1082_package_stage(
                    self._context.store.root,
                    expected_payload=staged_bytes,
                )
                signing_key_lifecycle = (
                    "generated_in_memory_and_not_persisted"
                    if stage_created
                    else "resumed_recoverable_signed_envelope"
                )

            activation = self._context.activate_action_package(
                source_intake_package.PACKAGE_ID,
                source_intake_package.PACKAGE_VERSION,
                {
                    "runner_profile_id": runner_profile_id,
                    "activated_by": operator_id,
                    "reason": "Activate the fixed locally signed reviewed T1082 intake package.",
                },
            )
            after = self._context._action_catalog_boundary()
            behavior_is_available = source_intake_package.BEHAVIOR_ID in after.registry.behavior_ids
            action_is_available = source_intake_package.ACTION_ID in after.registry.action_ids
            if not behavior_is_available or not action_is_available:
                raise ActionCatalogError(
                    "reviewed T1082 activation did not publish its behavior and action"
                )

        package = activation.get("package")
        if not isinstance(package, Mapping):  # pragma: no cover - activation response invariant
            raise ActionCatalogError("reviewed T1082 activation returned no package")
        if installed_now:
            operation = "installed_and_activated"
        elif active_before:
            operation = "already_active_revalidated"
        else:
            operation = "resumed_activation"
        return {
            "schema_version": "bluefire.reviewed-source-intake-activation.v1",
            "operation": operation,
            "package": {
                "package_id": source_intake_package.PACKAGE_ID,
                "version": source_intake_package.PACKAGE_VERSION,
                "package_digest": package.get("package_digest"),
                "content_digest": package.get("content_digest"),
                "publisher_id": package.get("publisher_id"),
                "key_id": package.get("key_id"),
                "status": package.get("status"),
            },
            "catalog_delta": {
                "changed": (
                    before.generation != after.generation
                    or before.catalog_digest != after.catalog_digest
                ),
                "generation_before": before.generation,
                "generation_after": after.generation,
                "catalog_digest_before": before.catalog_digest,
                "catalog_digest_after": after.catalog_digest,
                "behavior_ids_added": (
                    [] if behavior_was_available else [source_intake_package.BEHAVIOR_ID]
                ),
                "action_ids_added": (
                    [] if action_was_available else [source_intake_package.ACTION_ID]
                ),
            },
            "availability": {
                "behavior_id": source_intake_package.BEHAVIOR_ID,
                "behavior_available": behavior_is_available,
                "action_id": source_intake_package.ACTION_ID,
                "action_available": action_is_available,
            },
            "runner": {
                "profile_id": runner_profile_id,
                "identity_digest": activation.get("runner_identity_digest"),
                "inventory_digest": activation.get("runner_inventory_digest"),
                "activation_revalidated": True,
            },
            "persistence": {
                "installed_now": installed_now,
                "activated_now": not active_before,
                "durable_product_store": True,
                "signing_key_lifecycle": signing_key_lifecycle,
                "private_signing_key_persisted": False,
            },
        }

    def _completed_reviewed_t1082_activation(
        self,
        receipt: Mapping[str, Any],
        *,
        envelope: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Reconstruct completed authority without dispatching another activation."""

        activation_record = receipt.get("activation")
        receipt_package = receipt.get("package")
        if not isinstance(activation_record, Mapping) or not isinstance(receipt_package, Mapping):
            raise SourceIntakeError("completed source-intake receipt authority is incomplete")
        generation = activation_record.get("catalog_generation")
        catalog_digest = activation_record.get("catalog_digest")
        operation = activation_record.get("operation")
        if (
            isinstance(generation, bool)
            or not isinstance(generation, int)
            or generation < 1
            or not isinstance(catalog_digest, str)
            or operation
            not in {"installed_and_activated", "resumed_activation", "already_active_revalidated"}
        ):
            raise SourceIntakeError("completed source-intake receipt authority is invalid")

        expected_manifest, expected_payload = source_intake_package.gate09_package_components(
            envelope
        )
        with (
            self._context._action_catalog_lock,
            self._context.product_store.action_package_catalog_lease(),
        ):
            try:
                package = self._context.product_store.get_action_package(
                    source_intake_package.PACKAGE_ID,
                    source_intake_package.PACKAGE_VERSION,
                )
                self._validate_reviewed_t1082_package(
                    package,
                    expected_manifest=expected_manifest,
                    expected_payload=expected_payload,
                )
                after = self._context._load_action_catalog_snapshot(generation)
                before_generation = (
                    generation if operation == "already_active_revalidated" else generation - 1
                )
                before = self._context._load_action_catalog_snapshot(before_generation)
                current = self._context._action_catalog_boundary()
            except (
                ActionCatalogError,
                ActionPackageIntegrityError,
                ProductStoreError,
                TypeError,
                ValueError,
            ) as exc:
                raise SourceIntakeError(
                    "completed source-intake package authority could not be reconstructed"
                ) from exc

        package_row = next(
            (
                item
                for item in after.packages
                if item.get("package_id") == source_intake_package.PACKAGE_ID
                and item.get("package_version") == source_intake_package.PACKAGE_VERSION
            ),
            None,
        )
        changed = operation != "already_active_revalidated"
        if (
            after.catalog_digest != catalog_digest
            or not isinstance(package_row, Mapping)
            or package_row.get("package_digest") != receipt_package.get("package_digest")
            or package_row.get("content_digest") != receipt_package.get("content_digest")
            or receipt_package.get("package_id") != source_intake_package.PACKAGE_ID
            or receipt_package.get("version") != source_intake_package.PACKAGE_VERSION
            or package.get("active") is not True
            or (changed and package_row.get("activated_generation") != generation)
            or source_intake_package.BEHAVIOR_ID not in after.registry.behavior_ids
            or source_intake_package.ACTION_ID not in after.registry.action_ids
            or source_intake_package.BEHAVIOR_ID not in current.registry.behavior_ids
            or source_intake_package.ACTION_ID not in current.registry.action_ids
        ):
            raise SourceIntakeError(
                "completed source-intake receipt does not match historical package authority"
            )
        behavior_was_available = source_intake_package.BEHAVIOR_ID in before.registry.behavior_ids
        action_was_available = source_intake_package.ACTION_ID in before.registry.action_ids
        return {
            "schema_version": "bluefire.reviewed-source-intake-activation.v1",
            "operation": operation,
            "package": {
                "package_id": source_intake_package.PACKAGE_ID,
                "version": source_intake_package.PACKAGE_VERSION,
                "package_digest": package_row.get("package_digest"),
                "content_digest": package_row.get("content_digest"),
                "publisher_id": package_row.get("publisher_id"),
                "key_id": package_row.get("key_id"),
                "status": "active",
            },
            "catalog_delta": {
                "changed": changed,
                "generation_before": before.generation,
                "generation_after": after.generation,
                "catalog_digest_before": before.catalog_digest,
                "catalog_digest_after": after.catalog_digest,
                "behavior_ids_added": (
                    [] if behavior_was_available else [source_intake_package.BEHAVIOR_ID]
                ),
                "action_ids_added": (
                    [] if action_was_available else [source_intake_package.ACTION_ID]
                ),
            },
            "availability": {
                "behavior_id": source_intake_package.BEHAVIOR_ID,
                "behavior_available": True,
                "action_id": source_intake_package.ACTION_ID,
                "action_available": True,
            },
            "runner": {
                "profile_id": receipt.get("runner_profile_id"),
                "identity_digest": package_row.get("runner_identity_digest"),
                "inventory_digest": package_row.get("runner_inventory_digest"),
                "activation_revalidated": True,
            },
            "persistence": {
                "installed_now": operation == "installed_and_activated",
                "activated_now": changed,
                "durable_product_store": True,
                "signing_key_lifecycle": (
                    "generated_in_memory_and_not_persisted"
                    if operation == "installed_and_activated"
                    else "existing_locally_trusted_package"
                ),
                "private_signing_key_persisted": False,
            },
        }

    @staticmethod
    def _validate_reviewed_t1082_package(
        package: Mapping[str, Any],
        *,
        expected_manifest: Mapping[str, Any],
        expected_payload: Mapping[str, Any],
    ) -> None:
        """Reject a same-ID package unless its audited immutable recipe is exact."""

        envelope_bytes = package.get("canonical_envelope_bytes")
        try:
            document = json.loads(cast(str | bytes | bytearray, envelope_bytes))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "source_intake_package_conflict",
                "The installed reviewed-source package envelope is invalid.",
            ) from exc
        signature = document.get("signature") if isinstance(document, Mapping) else None
        if (
            not isinstance(envelope_bytes, bytes)
            or not isinstance(document, Mapping)
            or canonical_json_bytes(document) != envelope_bytes
            or package.get("package_id") != source_intake_package.PACKAGE_ID
            or package.get("version") != source_intake_package.PACKAGE_VERSION
            or package.get("publisher_id") != source_intake_package.PUBLISHER_ID
            or package.get("key_id") != source_intake_package.KEY_ID
            or package.get("manifest") != expected_manifest
            or document.get("manifest") != expected_manifest
            or document.get("payload") != expected_payload
            or not isinstance(signature, Mapping)
            or signature.get("key_id") != source_intake_package.KEY_ID
        ):
            raise APIError(
                HTTPStatus.CONFLICT,
                "source_intake_package_conflict",
                "The installed same-ID package is not the fixed reviewed T1082 recipe.",
            )

    @staticmethod
    def _validate_reviewed_t1082_stage(
        stage: Mapping[str, Any],
        *,
        expected_manifest: Mapping[str, Any],
        expected_payload: Mapping[str, Any],
        expected_record_sha256: str,
    ) -> tuple[Mapping[str, Any], str, str]:
        """Cryptographically revalidate a crash-recoverable signed package stage."""

        if (
            set(stage)
            != {
                "schema_version",
                "source_record_sha256",
                "public_key",
                "trust_actor",
                "package_envelope",
            }
            or stage.get("schema_version") != _REVIEWED_T1082_STAGE_SCHEMA
        ):
            raise APIError(
                HTTPStatus.CONFLICT,
                "source_intake_package_conflict",
                "The recoverable signed package stage has an invalid contract.",
            )
        if stage.get("source_record_sha256") != expected_record_sha256:
            raise APIError(
                HTTPStatus.CONFLICT,
                "source_intake_package_conflict",
                "The recoverable signed package stage belongs to another source record.",
            )
        public_key = stage.get("public_key")
        trust_actor = _source_intake_operator(stage.get("trust_actor"))
        signed_envelope = stage.get("package_envelope")
        if not isinstance(public_key, str) or not isinstance(signed_envelope, Mapping):
            raise APIError(
                HTTPStatus.CONFLICT,
                "source_intake_package_conflict",
                "The recoverable signed package stage is incomplete.",
            )
        try:
            if re.fullmatch(r"[A-Za-z0-9_-]{43}", public_key) is None:
                raise ActionPackageError("staged public key is not canonical base64url")
            decoded_public_key = base64.urlsafe_b64decode(public_key + "=")
            if (
                len(decoded_public_key) != 32
                or base64.urlsafe_b64encode(decoded_public_key).rstrip(b"=").decode("ascii")
                != public_key
            ):
                raise ActionPackageError("staged public key is not canonical Ed25519 material")
            audited = audit_action_package(
                canonical_json_bytes(signed_envelope),
                trusted_signers={
                    (
                        source_intake_package.PUBLISHER_ID,
                        source_intake_package.KEY_ID,
                    ): decoded_public_key
                },
            )
        except (ActionPackageError, binascii.Error, TypeError, ValueError) as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "source_intake_package_conflict",
                "The recoverable signed package stage failed cryptographic verification.",
            ) from exc
        document = dict(signed_envelope)
        if (
            audited.manifest.to_dict() != expected_manifest
            or audited.publisher_id != source_intake_package.PUBLISHER_ID
            or audited.key_id != source_intake_package.KEY_ID
            or document.get("manifest") != expected_manifest
            or document.get("payload") != expected_payload
        ):
            raise APIError(
                HTTPStatus.CONFLICT,
                "source_intake_package_conflict",
                "The recoverable signed package stage is not the fixed reviewed T1082 recipe.",
            )
        return signed_envelope, public_key, trust_actor
