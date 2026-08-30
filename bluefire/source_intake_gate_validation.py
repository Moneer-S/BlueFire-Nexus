"""Independent persisted-evidence validation for GATE-09 source intake."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, cast

from .action_packages import SUPPORTED_RUNNER_ACTION_VERSIONS, VerifiedActionPackageActivation
from .product_store import ActionPackageIntegrityError, ProductStore, ProductStoreError
from .registry import load_builtin_registry
from .research import SourceUseClassification, load_builtin_research_registry
from .run_store import RunStore, RunStoreError
from .runner_bootstrap import load_runner_manifest
from .source_intake import perform_source_intake
from .source_intake_browser_validation import (
    SourceIntakeBrowserValidationError,
    validate_source_intake_browser_evidence,
)
from .source_intake_contracts import GATE_CHECK_NAMES as CHECK_NAMES
from .source_intake_journey import (
    BROWSER_INTAKE_ARTIFACT,
    BROWSER_INTAKE_OPERATION_RECEIPT_ARTIFACT,
    BROWSER_REPORT,
    EXECUTION_REPORT,
    EXECUTION_SCHEMA,
    INTAKE_ARTIFACT,
    INTAKE_REPORT,
    INTAKE_SCHEMA,
    PRIMARY_INTAKE_DESTINATION_ID,
    PRIMARY_INTAKE_OPERATION_RECEIPT_ARTIFACT,
    PRODUCT_DB_ARTIFACT,
    SAFETY_REPORT,
    SAFETY_SCHEMA,
)
from .source_intake_package import (
    ACTION_ID,
    BEHAVIOR_ID,
    INTAKE_ID,
    KEY_ID,
    LICENSE_ASSET,
    LICENSE_ID,
    LICENSE_REFERENCE,
    LICENSE_SHA256,
    LICENSE_SIZE_BYTES,
    PACKAGE_ID,
    PACKAGE_VERSION,
    PUBLISHER_ID,
    REQUIRED_NOTICE,
    REVIEWED_OPCODE,
    SOURCE_ASSET,
    SOURCE_BLOB,
    SOURCE_COMMIT,
    SOURCE_ID,
    SOURCE_REFERENCE,
    SOURCE_SHA256,
    SOURCE_SIZE_BYTES,
    SOURCE_TAG_OBJECT,
    SOURCE_VERSION,
    SourceIntakePackageError,
    gate09_intake_request,
    gate09_package_components,
    validate_gate09_intake_envelope,
)
from .source_intake_receipt_validation import (
    MAX_OPERATION_RECEIPT_BYTES,
    SourceIntakeReceiptValidationError,
    validate_source_intake_operation_receipt_binding,
)
from .source_intake_run_validation import validate_native_system_step
from .util import canonical_json_bytes, content_hash, file_hash

_MAX_REPORT_BYTES, _MAX_DATABASE_BYTES = 2 * 1024 * 1024, 64 * 1024 * 1024
_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class SourceIntakeGateValidationError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SourceIntakeGateValidationError(message)


def _mapping(value: Any, message: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SourceIntakeGateValidationError(message)
    return value


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        _require(key not in value, "persisted JSON contains duplicate keys")
        value[key] = item
    return value


def _utc_timestamp(value: Any, message: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise SourceIntakeGateValidationError(message)
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise SourceIntakeGateValidationError(message) from exc
    if parsed.tzinfo != timezone.utc:
        raise SourceIntakeGateValidationError(message)
    return parsed


def _is_link_or_reparse(value: os.stat_result) -> bool:
    return stat.S_ISLNK(value.st_mode) or bool(
        int(getattr(value, "st_file_attributes", 0)) & _REPARSE_POINT
    )


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_nlink,
        int(getattr(value, "st_file_attributes", 0)),
    )


def _read_bytes(path: Path, maximum: int, context: str) -> bytes:
    descriptor: int | None = None
    try:
        before_path = path.lstat()
        _require(
            stat.S_ISREG(before_path.st_mode)
            and not _is_link_or_reparse(before_path)
            and before_path.st_nlink == 1
            and 0 < before_path.st_size <= maximum,
            f"{context} is absent, unsafe, empty, or unbounded",
        )
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        before_handle = os.fstat(descriptor)
        _require(
            stat.S_ISREG(before_handle.st_mode)
            and not _is_link_or_reparse(before_handle)
            and before_handle.st_nlink == 1,
            f"{context} is unsafe",
        )
        payload = bytearray()
        while len(payload) <= maximum:
            block = os.read(descriptor, min(64 * 1024, maximum + 1 - len(payload)))
            if not block:
                break
            payload.extend(block)
        after_handle = os.fstat(descriptor)
        after_path = path.lstat()
        _require(
            len(payload) <= maximum
            and _identity(before_path)
            == _identity(before_handle)
            == _identity(after_handle)
            == _identity(after_path),
            f"{context} changed while it was read",
        )
        return bytes(payload)
    except OSError as exc:
        raise SourceIntakeGateValidationError(f"{context} could not be read") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_json(path: Path, context: str) -> Mapping[str, Any]:
    payload = _read_bytes(path, _MAX_REPORT_BYTES, context)
    try:
        value = json.loads(payload, object_pairs_hook=_object_without_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SourceIntakeGateValidationError(f"{context} is invalid JSON") from exc
    return _mapping(value, f"{context} must contain one object")


def _asset(path: Path, size: int, digest: str, context: str) -> bytes:
    payload = _read_bytes(path, max(size, 1), context)
    _require(
        len(payload) == size and "sha256:" + hashlib.sha256(payload).hexdigest() == digest,
        f"{context} failed its pinned size or SHA-256 identity",
    )
    return payload


def _validate_registry(repository: Path) -> Mapping[str, Any]:
    classifications = {item.value for item in SourceUseClassification}
    _require(
        classifications
        == {
            "reference_only",
            "metadata_import",
            "clean_reimplementation",
            "external_adapter",
            "compatible_code_adaptation",
            "incompatible_or_restricted",
        },
        "the source-intake classification model is incomplete",
    )
    source = load_builtin_research_registry().get(SOURCE_ID)
    document = source.to_dict()
    expected_paths = [
        f"bluefire/data/{SOURCE_ASSET}",
        f"bluefire/data/{LICENSE_ASSET}",
    ]
    _require(
        source.project == "mitre/cti"
        and source.authority == "The MITRE Corporation"
        and source.version == "19.2"
        and source.pin == SOURCE_COMMIT
        and source.exact_ref == SOURCE_COMMIT
        and source.reference_url == SOURCE_REFERENCE
        and source.retrieved_at == "2026-08-29"
        and source.last_verified_at == "2026-08-29"
        and source.license == LICENSE_ID
        and source.license_url == LICENSE_REFERENCE
        and source.license_review.value == "reviewed"
        and source.relationship.value == "imported"
        and source.use_classification.value == "metadata_import"
        and source.cache_policy == "vendored_declarative"
        and source.executable_content is False
        and list(source.imported_paths) == expected_paths
        and REQUIRED_NOTICE in source.attribution
        and SOURCE_SHA256.removeprefix("sha256:") in source.transformation_history
        and LICENSE_SHA256.removeprefix("sha256:") in source.file_level_license_review
        and SOURCE_TAG_OBJECT in source.notes
        and SOURCE_BLOB in source.notes
        and source.update_status == "current"
        and "not executed" in source.security_review.casefold(),
        "the built-in MITRE source record is not the exact reviewed import",
    )
    source_payload = _asset(
        repository / "bluefire" / "data" / SOURCE_ASSET,
        SOURCE_SIZE_BYTES,
        SOURCE_SHA256,
        "the pinned T1082 source asset",
    )
    git_object = hashlib.sha1(usedforsecurity=False)
    git_object.update(f"blob {len(source_payload)}\0".encode("ascii"))
    git_object.update(source_payload)
    _require(
        git_object.hexdigest() == SOURCE_BLOB,
        "the pinned T1082 source asset does not match its Git blob identity",
    )
    license_payload = _asset(
        repository / "bluefire" / "data" / LICENSE_ASSET,
        LICENSE_SIZE_BYTES,
        LICENSE_SHA256,
        "the pinned ATT&CK license asset",
    )
    _require(
        REQUIRED_NOTICE.encode("utf-8") in license_payload,
        "the pinned ATT&CK license omits its required notice",
    )
    return document


def _validate_intake(
    repository: Path,
    evidence_dir: Path,
    report: Mapping[str, Any],
    source_document: Mapping[str, Any],
) -> Mapping[str, Any]:
    _require(
        set(report)
        == {
            "schema_version",
            "passed",
            "source",
            "license",
            "intake_artifact",
            "operation_receipt",
            "output",
            "transformation_history",
            "research_source",
        },
        "the intake report fields are not exact",
    )
    path = evidence_dir / INTAKE_ARTIFACT
    raw = _read_bytes(path, _MAX_REPORT_BYTES, "the persisted source-intake envelope")
    try:
        envelope = json.loads(raw, object_pairs_hook=_object_without_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SourceIntakeGateValidationError("the source-intake envelope is invalid") from exc
    _require(
        isinstance(envelope, Mapping) and raw == canonical_json_bytes(envelope),
        "the source-intake envelope is not canonical JSON",
    )
    envelope = cast(Mapping[str, Any], envelope)
    try:
        validate_gate09_intake_envelope(envelope)
    except SourceIntakePackageError as exc:
        raise SourceIntakeGateValidationError("the source-intake envelope is not reviewed") from exc
    record = _mapping(envelope["record"], "the source-intake record is absent")
    output = _mapping(record.get("output"), "the source-intake output is absent")
    history = record.get("transformation_history")
    _require(
        report.get("schema_version") == INTAKE_SCHEMA
        and report.get("passed") is True
        and report.get("output") == output
        and report.get("transformation_history") == history
        and report.get("research_source") == source_document,
        "the intake report is detached from the canonical record or source registry",
    )
    source = _mapping(report.get("source"), "the intake report source is absent")
    license_row = _mapping(report.get("license"), "the intake report license is absent")
    artifact = _mapping(
        report.get("intake_artifact"), "the intake report artifact binding is absent"
    )
    _require(
        source
        == {
            "path": SOURCE_ASSET,
            "size_bytes": SOURCE_SIZE_BYTES,
            "sha256": SOURCE_SHA256,
            "research_source_id": SOURCE_ID,
            "version": SOURCE_VERSION,
            "commit": SOURCE_COMMIT,
            "tag_object": SOURCE_TAG_OBJECT,
            "blob_sha1": SOURCE_BLOB,
        }
        and license_row
        == {
            "path": LICENSE_ASSET,
            "size_bytes": LICENSE_SIZE_BYTES,
            "sha256": LICENSE_SHA256,
            "identifier": LICENSE_ID,
            "notice": REQUIRED_NOTICE,
        }
        and artifact
        == {
            "path": INTAKE_ARTIFACT,
            "record_sha256": envelope["record_sha256"],
            "output_sha256": content_hash(output),
        },
        "the intake report source, license, or artifact identity is invalid",
    )

    generated_root: Path
    with tempfile.TemporaryDirectory(prefix=".gate09-transform-") as temporary:
        generated_root = Path(temporary)
        regenerated = perform_source_intake(
            repository / "bluefire" / "data",
            generated_root,
            gate09_intake_request(),
        )
        _require(
            regenerated.path.read_bytes() == raw
            and regenerated.envelope == envelope
            and regenerated.record_sha256 == envelope["record_sha256"],
            "a fresh trusted transformation does not reproduce the persisted intake",
        )
    _require(not generated_root.exists(), "the private transform replay was retained")
    return envelope


def _database_snapshot(
    evidence_dir: Path,
    execution: Mapping[str, Any],
) -> bytes:
    row = _mapping(execution.get("product_store"), "the ProductStore binding is absent")
    database = evidence_dir / PRODUCT_DB_ARTIFACT
    payload = _read_bytes(database, _MAX_DATABASE_BYTES, "the persisted ProductStore")
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    _require(
        row
        == {
            "path": PRODUCT_DB_ARTIFACT,
            "size_bytes": len(payload),
            "sha256": digest,
        }
        and all(not Path(str(database) + suffix).exists() for suffix in ("-wal", "-shm")),
        "the ProductStore report binding is invalid or has live sidecars",
    )
    return payload


def _validate_product_store(
    database_payload: bytes,
    execution: Mapping[str, Any],
    intake: Mapping[str, Any],
    source_document: Mapping[str, Any],
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    temporary_root: Path
    try:
        with tempfile.TemporaryDirectory(prefix=".gate09-product-") as temporary:
            temporary_root = Path(temporary)
            database = temporary_root / "product.sqlite3"
            database.write_bytes(database_payload)
            store = ProductStore(database)
            package = store.get_action_package(PACKAGE_ID, PACKAGE_VERSION)
            source = store.get_resource("research_source", SOURCE_ID)
            catalog = store.get_action_package_catalog_snapshot()
    except (
        OSError,
        sqlite3.Error,
        ActionPackageIntegrityError,
        ProductStoreError,
        TypeError,
        ValueError,
    ) as exc:
        raise SourceIntakeGateValidationError(
            "the persisted product state failed independent replay"
        ) from exc
    _require(not temporary_root.exists(), "the private ProductStore replay was retained")
    try:
        expected_manifest, expected_payload = gate09_package_components(intake)
    except SourceIntakePackageError as exc:
        raise SourceIntakeGateValidationError(
            "the independently replayed package recipe is invalid"
        ) from exc
    try:
        stored_envelope = json.loads(
            package["canonical_envelope_bytes"],
            object_pairs_hook=_object_without_duplicate_keys,
        )
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise SourceIntakeGateValidationError("the stored signed package is invalid") from exc
    package_report = _mapping(execution.get("package"), "the execution package is absent")
    _require(
        package.get("status") == "active"
        and package.get("active") is True
        and package.get("publisher_id") == PUBLISHER_ID
        and package.get("key_id") == KEY_ID
        and package.get("active_generation") == 1
        and package.get("trust", {}).get("state") == "trusted"
        and stored_envelope.get("manifest") == expected_manifest
        and stored_envelope.get("payload") == expected_payload
        and package_report
        == {
            "package_id": PACKAGE_ID,
            "version": PACKAGE_VERSION,
            "package_digest": package.get("package_digest"),
            "content_digest": package.get("content_digest"),
            "publisher_id": PUBLISHER_ID,
            "key_id": KEY_ID,
            "trust_state": "trusted",
            "catalog_generation": 1,
        }
        and catalog.get("generation") == 1
        and source.get("status") == "pinned"
        and source.get("document") == source_document,
        "the signed package, catalog, trust, or source projection is invalid",
    )
    return package, catalog


def _expected_execution_binding(
    package: Mapping[str, Any],
    authority: Mapping[str, Any],
) -> Mapping[str, Any]:
    try:
        stored = json.loads(
            package["canonical_envelope_bytes"],
            object_pairs_hook=_object_without_duplicate_keys,
        )
        payload = _mapping(stored["payload"], "the stored package payload is absent")
        actions = payload["actions"]
        packaged_action = actions[0] if isinstance(actions, list) and len(actions) == 1 else None
        packaged_action = _mapping(packaged_action, "the stored package action is absent")
        program = _mapping(packaged_action["program"], "the stored action program is absent")
        program_steps = program["steps"]
        program_step = (
            program_steps[0]
            if isinstance(program_steps, list) and len(program_steps) == 1
            else None
        )
        program_step = _mapping(program_step, "the stored action program step is absent")
        activation = _mapping(package["activation"], "the package activation is absent")
        opcode_bindings = activation["opcode_bindings"]
        opcode_binding = (
            opcode_bindings[0]
            if isinstance(opcode_bindings, list) and len(opcode_bindings) == 1
            else None
        )
        opcode_binding = _mapping(opcode_binding, "the package activation opcode binding is absent")
        activation_runner = _mapping(
            activation["runner"], "the package activation runner is absent"
        )
        activation_inventory = _mapping(
            activation_runner["inventory"], "the package activation inventory is absent"
        )
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise SourceIntakeGateValidationError(
            "the stored package cannot produce an execution binding"
        ) from exc

    expected = {
        "schema_version": "bluefire.runner-execution-binding.v1",
        "catalog_generation": package.get("catalog_generation"),
        "catalog_digest": package.get("catalog_digest"),
        "logical_behavior_id": BEHAVIOR_ID,
        "logical_action_id": ACTION_ID,
        "package_id": PACKAGE_ID,
        "package_version": PACKAGE_VERSION,
        "package_digest": package.get("package_digest"),
        "content_digest": package.get("content_digest"),
        "program_digest": content_hash(program),
        "runner_opcode": REVIEWED_OPCODE,
        "opcode_contract_digest": opcode_binding.get("contract_digest"),
        "constants": program_step.get("constants"),
    }
    built_in = load_builtin_registry()
    built_in_document = {
        "schema_version": "bluefire.built-in-catalog-snapshot.v1",
        "behaviors": [item.to_dict() for item in built_in.behaviors],
        "actions": [item.to_dict() for item in built_in.actions],
    }
    expected_package = {
        "package_id": PACKAGE_ID,
        "package_version": PACKAGE_VERSION,
        "package_digest": package.get("package_digest"),
        "content_digest": package.get("content_digest"),
        "publisher_id": PUBLISHER_ID,
        "key_id": KEY_ID,
        "signer_fingerprint": package.get("signer_fingerprint"),
        "activated_generation": package.get("active_generation"),
        "runner_identity_digest": activation_runner.get("identity_digest"),
        "runner_inventory_digest": activation_runner.get("inventory_digest"),
        "runner_platform": activation_inventory.get("platform"),
        "behavior_ids": [BEHAVIOR_ID],
        "action_ids": [ACTION_ID],
    }
    authority_body = dict(authority)
    authority_digest = authority_body.pop("authority_digest", None)
    _require(
        set(authority)
        == {
            "schema_version",
            "generation",
            "catalog_digest",
            "built_in_catalog_digest",
            "packages",
            "action_bindings",
            "authority_digest",
        }
        and authority.get("schema_version") == "bluefire.action-catalog-authority.v1"
        and authority.get("generation") == package.get("catalog_generation") == 1
        and authority.get("catalog_digest") == package.get("catalog_digest")
        and authority.get("built_in_catalog_digest") == content_hash(built_in_document)
        and authority.get("packages") == [expected_package]
        and authority.get("action_bindings") == [expected]
        and authority_digest == content_hash(authority_body)
        and BEHAVIOR_ID not in built_in.behavior_ids
        and ACTION_ID not in built_in.action_ids
        and opcode_binding
        == {
            "package_action_id": ACTION_ID,
            "opcode": REVIEWED_OPCODE,
            "action_version": SUPPORTED_RUNNER_ACTION_VERSIONS[REVIEWED_OPCODE],
            "readiness": "ready",
            "contract_digest": opcode_binding.get("contract_digest"),
        }
        and program_step
        == {
            "opcode": REVIEWED_OPCODE,
            "adapter": "bluefire.builtin-runner-adapter.v1",
            "constants": {},
        },
        "the run catalog authority is detached from the active reviewed package",
    )
    return expected


def _expected_scenario(record_sha256: str) -> Mapping[str, Any]:
    return {
        "schema_version": "bluefire.scenario.v1",
        "id": "scenario.source-intake.system-information.v1",
        "title": "Reviewed source-intake system information",
        "purpose": (
            "Execute the independently compiled action associated with reviewed T1082 metadata."
        ),
        "start": "observe_system",
        "steps": [
            {
                "id": "observe_system",
                "behavior_id": BEHAVIOR_ID,
                "parameters": {},
                "inputs": {},
                "alternates": [],
            }
        ],
        "edges": [],
        "provenance": {
            "source": "BlueFire Gate 09 reviewed source-intake journey",
            "reference": f"urn:bluefire:source-intake:{INTAKE_ID}:{record_sha256}",
            "license": LICENSE_ID,
            "derived": True,
            "notes": "No upstream executable content is dispatched. " + REQUIRED_NOTICE,
        },
        "limitations": ["Reads bounded platform identity only."],
    }


def _validate_run(
    repository: Path,
    evidence_dir: Path,
    execution: Mapping[str, Any],
    package: Mapping[str, Any],
    catalog: Mapping[str, Any],
    intake: Mapping[str, Any],
) -> tuple[Mapping[str, str], Mapping[str, Any]]:
    run_id, reference = execution.get("run_id"), execution.get("run_bundle")
    _require(
        isinstance(run_id, str)
        and _RUN_ID.fullmatch(run_id) is not None
        and reference == {"run_id": run_id, "path": f"runs/{run_id}"},
        "the Gate 09 run-bundle reference is invalid",
    )
    run_id = cast(str, run_id)
    store = RunStore(evidence_dir / "runs")
    try:
        integrity = store.validate_bundle(run_id)
        run = store.get_run(run_id)
    except (OSError, RunStoreError, TypeError, ValueError) as exc:
        raise SourceIntakeGateValidationError("the Gate 09 run bundle is invalid") from exc
    steps = run.get("steps")
    step = steps[0] if isinstance(steps, list) and len(steps) == 1 else None
    cleanup = run.get("cleanup")
    policy = _mapping(run.get("policy"), "the Gate 09 run policy is absent")
    preflight = _mapping(policy.get("preflight"), "the Gate 09 preflight is absent")
    authority = _mapping(
        preflight.get("catalog_authority"), "the Gate 09 catalog authority is absent"
    )
    expected_execution_binding = _expected_execution_binding(package, authority)
    profile = _mapping(run.get("profile"), "the Gate 09 profile is absent")
    plan = _mapping(run.get("plan"), "the Gate 09 execution plan is absent")
    plan_steps = plan.get("steps")
    plan_step = plan_steps[0] if isinstance(plan_steps, list) and len(plan_steps) == 1 else None
    scenario = _mapping(run.get("scenario"), "the Gate 09 run scenario is absent")
    expected_scenario = _expected_scenario(str(intake.get("record_sha256", "")))
    evidence = _mapping(run.get("evidence"), "the Gate 09 run evidence is absent")
    records = evidence.get("records")
    executed = (
        [
            row
            for row in records
            if isinstance(row, Mapping)
            and row.get("provenance") == "executed"
            and row.get("producer") == "bluefire-rust-runner"
            and row.get("step_id") == "observe_system"
            and row.get("action_id") == ACTION_ID
        ]
        if isinstance(records, list)
        else []
    )
    runner_row = executed[0] if len(executed) == 1 else {}
    runner_environment = runner_row.get("environment") if isinstance(runner_row, Mapping) else None
    runner_content = runner_row.get("content") if isinstance(runner_row, Mapping) else None
    _require(isinstance(runner_content, Mapping), "the Gate 09 runner evidence is absent")
    runner_content = cast(Mapping[str, Any], runner_content)
    catalog_packages = catalog.get("packages")
    catalog_package = (
        catalog_packages[0]
        if isinstance(catalog_packages, list) and len(catalog_packages) == 1
        else None
    )
    catalog_package = _mapping(catalog_package, "the persisted package catalog row is absent")
    activation = _mapping(package.get("activation"), "the active package binding is absent")
    verified_activation = catalog_package.get("verified_activation")
    try:
        verified_activation_document = cast(
            VerifiedActionPackageActivation, verified_activation
        ).to_dict()
    except (AttributeError, TypeError, ValueError):
        verified_activation_document = None
    delta = _mapping(execution.get("catalog_delta"), "the catalog delta is absent")
    expected_delta = {
        "package_id": PACKAGE_ID,
        "package_version": PACKAGE_VERSION,
        "behavior_id": BEHAVIOR_ID,
        "action_id": ACTION_ID,
        "behavior_absent_before": True,
        "action_absent_before": True,
        "behavior_present_after": True,
        "action_present_after": True,
        "generation_before": activation.get("expected_catalog_generation"),
        "generation_after": catalog.get("generation"),
        "catalog_digest_before": activation.get("expected_catalog_digest"),
        "catalog_digest_after": catalog.get("catalog_digest"),
    }
    manifest = load_runner_manifest(resource_root=repository / "bluefire" / "native")
    try:
        validate_native_system_step(
            run_id=run_id,
            run=run,
            step=_mapping(step, "the Gate 09 finalized step is absent"),
            records=records,
            runner_row=runner_row,
            runner_content=runner_content,
            expected_execution_binding=expected_execution_binding,
            runner_platform=manifest.platform,
            runner_architecture=manifest.architecture,
        )
    except (TypeError, ValueError) as exc:
        raise SourceIntakeGateValidationError(
            "the Gate 09 native system step failed persisted linkage validation"
        ) from exc
    _require(
        integrity.get("valid") is True
        and run.get("status") == "completed"
        and run.get("objective_reached") is True
        and run.get("mode") == "execute"
        and isinstance(step, Mapping)
        and step.get("step_id") == "observe_system"
        and step.get("behavior_id") == BEHAVIOR_ID
        and step.get("action_id") == ACTION_ID
        and step.get("execution_binding") == expected_execution_binding
        and step.get("execution_disposition") == "execute"
        and step.get("status") == "success"
        and cleanup == {"attempted": False, "success": False, "outstanding_receipt_count": 0}
        and "recovery_journal" not in run
        and "cleanup_recovery" not in run
        and scenario == expected_scenario
        and profile.get("id") == run.get("runner_profile_id")
        and plan.get("scenario_id") == expected_scenario["id"]
        and plan.get("mode") == "execute"
        and plan.get("runner_profile_id") == run.get("runner_profile_id")
        and isinstance(plan_step, Mapping)
        and plan_step.get("step_id") == "observe_system"
        and plan_step.get("behavior_id") == BEHAVIOR_ID
        and plan_step.get("action_id") == ACTION_ID
        and plan_step.get("execution_binding") == expected_execution_binding
        and catalog.get("generation") == 1
        and catalog.get("catalog_digest") == package.get("catalog_digest")
        and catalog_package.get("package_id") == PACKAGE_ID
        and catalog_package.get("version") == PACKAGE_VERSION
        and catalog_package.get("package_digest") == package.get("package_digest")
        and catalog_package.get("activation") == activation
        and verified_activation_document == activation
        and delta == expected_delta
        and expected_delta["generation_before"] == 0
        and expected_delta["generation_after"] == 1
        and expected_delta["catalog_digest_before"] != expected_delta["catalog_digest_after"]
        and len(executed) == 1
        and runner_row.get("run_id") == run_id
        and runner_row.get("behavior_id") == BEHAVIOR_ID
        and runner_row.get("runner_profile_id") == run.get("runner_profile_id")
        and isinstance(runner_environment, Mapping)
        and runner_environment.get("platform") == "windows"
        and runner_content.get("runner_task_id") == step.get("runner_task_id"),
        "the Gate 09 run is not a native, package-bound, receipt-free Execute run",
    )
    runner = _mapping(execution.get("runner"), "the execution runner binding is absent")
    _require(
        runner
        == {
            "source": "packaged",
            "platform": manifest.platform,
            "binary_sha256": file_hash(repository / "bluefire" / "native" / manifest.filename),
        },
        "the execution report is detached from the packaged native runner",
    )
    binding = _mapping(execution.get("binding"), "the execution binding is absent")
    _require(
        binding
        == {
            "behavior_id": BEHAVIOR_ID,
            "action_id": ACTION_ID,
            "reviewed_opcode": REVIEWED_OPCODE,
            "technique_id": "T1082",
            "implementation": "independent_bluefire_compiled_action",
        }
        and execution.get("profile_id") == run.get("runner_profile_id")
        and execution.get("cleanup") == cleanup,
        "the execution report is detached from its action or run",
    )
    return {"run_id": run_id, "path": f"runs/{run_id}"}, run


def _validate_safety(report: Mapping[str, Any]) -> None:
    refused, transformer = report.get("refused_without_output"), report.get("trusted_transformer")
    _require(
        set(report)
        == {
            "schema_version",
            "passed",
            "refused_without_output",
            "trusted_transformer",
            "external_content_executed",
            "network_intake",
        }
        and report.get("schema_version") == SAFETY_SCHEMA
        and report.get("passed") is True
        and refused
        == {
            "source_digest_mismatch": True,
            "unknown_transformer": True,
            "executable_materialization_field": True,
            "multi_object_bundle": True,
        }
        and transformer
        == {
            "name": "mitre-attack-technique-v1",
            "version": "1.0.0",
            "runtime_discovery": False,
        }
        and report.get("external_content_executed") is False
        and report.get("network_intake") is False,
        "the safe-intake refusal evidence is invalid",
    )


def _validate_browser(
    evidence_dir: Path,
    report: Mapping[str, Any],
    intake: Mapping[str, Any],
    profile_id: str,
    package: Mapping[str, Any],
    catalog: Mapping[str, Any],
    *,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> None:
    browser_raw = _read_bytes(
        evidence_dir / BROWSER_INTAKE_ARTIFACT,
        _MAX_REPORT_BYTES,
        "the browser-created source-intake artifact",
    )
    receipt_raw = _read_bytes(
        evidence_dir / BROWSER_INTAKE_OPERATION_RECEIPT_ARTIFACT,
        MAX_OPERATION_RECEIPT_BYTES,
        "the browser-created source-intake operation receipt",
    )
    try:
        validate_source_intake_browser_evidence(
            report,
            intake=intake,
            browser_artifact_payload=browser_raw,
            browser_receipt_payload=receipt_raw,
            profile_id=profile_id,
            package=package,
            catalog_generation=cast(int, catalog.get("generation")),
            catalog_digest=str(catalog.get("catalog_digest")),
            not_before=not_before,
            not_after=not_after,
        )
    except SourceIntakeBrowserValidationError as exc:
        raise SourceIntakeGateValidationError(str(exc)) from exc


def _validate_primary_operation_receipt(
    evidence_dir: Path,
    report: Mapping[str, Any],
    intake: Mapping[str, Any],
    package: Mapping[str, Any],
    catalog: Mapping[str, Any],
    profile_id: str,
    *,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> None:
    payload = _read_bytes(
        evidence_dir / PRIMARY_INTAKE_OPERATION_RECEIPT_ARTIFACT,
        MAX_OPERATION_RECEIPT_BYTES,
        "the primary source-intake operation receipt",
    )
    try:
        validate_source_intake_operation_receipt_binding(
            payload,
            report.get("operation_receipt"),
            artifact_path=PRIMARY_INTAKE_OPERATION_RECEIPT_ARTIFACT,
            destination_id=PRIMARY_INTAKE_DESTINATION_ID,
            operator_id="gate-09-source-reviewer",
            profile_id=profile_id,
            intake=intake,
            package=package,
            activation_operation="installed_and_activated",
            catalog_generation=cast(int, catalog.get("generation")),
            catalog_digest=str(catalog.get("catalog_digest")),
            not_before=not_before,
            not_after=not_after,
        )
    except SourceIntakeReceiptValidationError as exc:
        raise SourceIntakeGateValidationError(str(exc)) from exc


def _validate_notices(repository: Path) -> None:
    notices = _read_bytes(
        repository / "THIRD_PARTY_NOTICES.md", 1024 * 1024, "THIRD_PARTY_NOTICES.md"
    ).decode("utf-8")
    guide = _read_bytes(
        repository / "docs" / "SOURCE_INTAKE.md", 1024 * 1024, "SOURCE_INTAKE.md"
    ).decode("utf-8")
    readme = _read_bytes(repository / "README.md", 2 * 1024 * 1024, "README.md").decode("utf-8")
    required = (
        REQUIRED_NOTICE,
        LICENSE_ID,
        SOURCE_COMMIT,
        SOURCE_SHA256.removeprefix("sha256:"),
        SOURCE_ASSET,
        LICENSE_ASSET,
    )
    _require(
        all(value in notices for value in required)
        and all(value in guide for value in (LICENSE_ID, SOURCE_ASSET, "T1082"))
        and all(value in readme for value in (SOURCE_COMMIT, SOURCE_ASSET, "T1082")),
        "public intake documentation or third-party notices are incomplete",
    )


def validate_persisted_source_intake_gate(
    repository: Path,
    evidence_dir: Path,
    *,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> tuple[Mapping[str, bool], tuple[Mapping[str, str], ...]]:
    try:
        root_details = repository.lstat()
        destination_details = evidence_dir.lstat()
    except OSError as exc:
        raise SourceIntakeGateValidationError("GATE-09 validation roots are absent") from exc
    _require(
        stat.S_ISDIR(root_details.st_mode)
        and not _is_link_or_reparse(root_details)
        and stat.S_ISDIR(destination_details.st_mode)
        and not _is_link_or_reparse(destination_details),
        "GATE-09 validation roots are invalid",
    )
    root = repository.resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    source_document = _validate_registry(root)
    intake_report = _read_json(destination / INTAKE_REPORT, "the Gate 09 intake report")
    execution = _read_json(destination / EXECUTION_REPORT, "the Gate 09 execution report")
    safety = _read_json(destination / SAFETY_REPORT, "the Gate 09 safety report")
    browser = _read_json(destination / BROWSER_REPORT, "the Gate 09 browser report")
    _require(
        set(execution)
        == {
            "schema_version",
            "passed",
            "package",
            "binding",
            "runner",
            "run_id",
            "run_bundle",
            "profile_id",
            "cleanup",
            "browser_report",
            "product_store",
            "catalog_delta",
        }
        and execution.get("schema_version") == EXECUTION_SCHEMA
        and execution.get("passed") is True
        and execution.get("browser_report") == BROWSER_REPORT,
        "the Gate 09 execution report is invalid",
    )
    intake = _validate_intake(root, destination, intake_report, source_document)
    database_payload = _database_snapshot(destination, execution)
    package, catalog = _validate_product_store(database_payload, execution, intake, source_document)
    bundle, _run = _validate_run(root, destination, execution, package, catalog, intake)
    _validate_safety(safety)
    profile_id = str(execution.get("profile_id"))
    _validate_primary_operation_receipt(
        destination,
        intake_report,
        intake,
        package,
        catalog,
        profile_id,
        not_before=not_before,
        not_after=not_after,
    )
    _validate_browser(
        destination,
        browser,
        intake,
        profile_id,
        package,
        catalog,
        not_before=not_before,
        not_after=not_after,
    )
    _validate_notices(root)
    checks = {name: True for name in sorted(CHECK_NAMES)}
    return checks, (bundle,)


__all__ = [
    "CHECK_NAMES",
    "SourceIntakeGateValidationError",
    "validate_persisted_source_intake_gate",
]
