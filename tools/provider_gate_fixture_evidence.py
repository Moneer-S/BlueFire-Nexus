"""Committed-fixture verification and structural evidence for GATE-02."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from bluefire import __version__
from bluefire.action_packages import VerifiedActionPackage, verify_action_package
from bluefire.action_provider_packages import WasmProviderProgram
from bluefire.runner_inventory import BUILTIN_RUNNER_ACTION_IDS
from bluefire.util import canonical_json_bytes
from tools.provider_gate_common import (
    ACTION_ID,
    ALL_VERSIONS,
    BEHAVIOR_ID,
    DEFINITION_NOTES,
    DEFINITION_SOURCE,
    EXPECTED_COMPATIBILITY,
    EXPECTED_LICENSE,
    EXPECTED_OUTPUTS,
    EXPECTED_PARAMETERS,
    FIXTURE_SCHEMA,
    FIXTURE_SOURCE,
    FORBIDDEN_PACKAGE_EXECUTION_FIELDS,
    LIMIT_VERSION,
    PACKAGE_ID,
    PROVIDER_ID,
    PUBLISHER_ID,
    STRUCTURAL_SCHEMA,
    ProviderGateError,
    _contained_file,
    _decode_public_key,
    _exact_mapping,
    _load_document,
    _sha256_bytes,
    _walk_fields,
    _wasm_sections,
)
from tools.provider_gate_source_audit import _source_audit


def _fixture_set(
    repository: Path,
) -> tuple[Mapping[str, Any], dict[str, Mapping[str, Any]], dict[str, VerifiedActionPackage]]:
    root = repository / "tests_platform" / "fixtures" / "provider_upgrade"
    root = root.resolve(strict=True)
    index = _exact_mapping(
        _load_document(root / "fixture-index.json"),
        {
            "schema_version",
            "package_id",
            "logical_behavior_id",
            "logical_action_id",
            "provider_id",
            "publisher_trust_file",
            "publisher_trust_files",
            "packages",
        },
        "fixture index",
    )
    if (
        index["schema_version"] != FIXTURE_SCHEMA
        or index["package_id"] != PACKAGE_ID
        or index["logical_behavior_id"] != BEHAVIOR_ID
        or index["logical_action_id"] != ACTION_ID
        or index["provider_id"] != PROVIDER_ID
    ):
        raise ProviderGateError("fixture index identity is invalid")
    raw_trust_files = index["publisher_trust_files"]
    if not isinstance(raw_trust_files, list) or len(raw_trust_files) != 2:
        raise ProviderGateError("fixture trust inventory is invalid")
    trusts: dict[str, Mapping[str, Any]] = {}
    signer_keys: dict[tuple[str, str], bytes] = {}
    for name in raw_trust_files:
        trust = _exact_mapping(
            _load_document(_contained_file(root, name)),
            {"publisher_id", "key_id", "public_key", "provenance", "trusted_by"},
            "fixture trust",
        )
        if trust["publisher_id"] != PUBLISHER_ID:
            raise ProviderGateError("fixture publisher identity is invalid")
        key = (str(trust["publisher_id"]), str(trust["key_id"]))
        if key in signer_keys:
            raise ProviderGateError("fixture trust inventory contains a duplicate key")
        signer_keys[key] = _decode_public_key(trust["public_key"])
        trusts[str(name)] = trust

    rows = index["packages"]
    if not isinstance(rows, list) or len(rows) != 3:
        raise ProviderGateError("fixture package inventory is invalid")
    row_by_version: dict[str, Mapping[str, Any]] = {}
    verified: dict[str, VerifiedActionPackage] = {}
    for raw_row in rows:
        if not isinstance(raw_row, Mapping):
            raise ProviderGateError("fixture package row is invalid")
        version = raw_row.get("version")
        if not isinstance(version, str) or version in row_by_version:
            raise ProviderGateError("fixture package version is invalid")
        required_row_fields = {
            "version",
            "file",
            "publisher_trust_file",
            "package_digest",
            "content_digest",
            "artifact_sha256",
            "artifact_size",
        }
        limit_fields = {
            "canonical_output_bytes",
            "expected_run_status",
            "expected_step_error_code",
            "limit_condition",
            "signed_max_output_bytes",
        }
        expected_fields = required_row_fields | (
            limit_fields if version == LIMIT_VERSION else set()
        )
        if set(raw_row) != expected_fields:
            raise ProviderGateError("fixture package row fields are invalid")
        trust_name = raw_row["publisher_trust_file"]
        trust_candidate = trusts.get(str(trust_name))
        if trust_candidate is None:
            raise ProviderGateError("fixture package references unknown trust")
        trust = trust_candidate
        envelope = _load_document(_contained_file(root, raw_row["file"]))
        package = verify_action_package(
            canonical_json_bytes(envelope),
            trusted_signers={
                (str(trust["publisher_id"]), str(trust["key_id"])): signer_keys[
                    (str(trust["publisher_id"]), str(trust["key_id"]))
                ]
            },
            bluefire_version=__version__,
            platform="windows",
        )
        provider = package.provider
        if (
            package.manifest.package_id != PACKAGE_ID
            or package.manifest.version != version
            or package.manifest.action_ids != (ACTION_ID,)
            or package.manifest.behavior_ids != (BEHAVIOR_ID,)
            or provider is None
            or provider.provider_id != PROVIDER_ID
            or package.package_digest != raw_row["package_digest"]
            or package.content_digest != raw_row["content_digest"]
            or provider.artifact_sha256 != raw_row["artifact_sha256"]
            or provider.artifact_size != raw_row["artifact_size"]
            or package.provider_artifact_bytes is None
        ):
            raise ProviderGateError("verified fixture differs from its committed index")
        row_by_version[version] = raw_row
        verified[version] = package
    if tuple(row_by_version) != ALL_VERSIONS:
        raise ProviderGateError("fixture package versions are not in canonical order")
    return index, trusts, verified


def _parameter_rows(definition: Any) -> list[dict[str, Any]]:
    return [
        {
            "name": item.name,
            "type": item.type.value,
            "required": item.required,
            "default": item.default,
            "enum": list(item.enum),
            "minimum": item.minimum,
            "maximum": item.maximum,
        }
        for item in definition.parameters
    ]


def _output_rows(definition: Any) -> list[dict[str, Any]]:
    return [
        {
            "name": item.name,
            "type": item.type,
            "required": item.required,
            "multiple": item.multiple,
        }
        for item in definition.outputs
    ]


def _expected_package_provenance(version: str, artifact_sha256: str) -> dict[str, str]:
    reference_suffix = "3.0.0-output-limit" if version == LIMIT_VERSION else version
    return {
        "publisher_id": PUBLISHER_ID,
        "source": FIXTURE_SOURCE,
        "reference": (
            f"urn:bluefire:fixture:provider-upgrade:{reference_suffix}:{artifact_sha256}"
        ),
        "revision": artifact_sha256,
    }


def _expected_definition_provenance(artifact_sha256: str) -> dict[str, Any]:
    return {
        "source": DEFINITION_SOURCE,
        "reference": f"urn:bluefire:fixture:provider-upgrade:{artifact_sha256}",
        "license": "MIT",
        "derived": False,
        "notes": DEFINITION_NOTES,
    }


def _expected_provider_limits(version: str) -> dict[str, int]:
    return {
        "max_module_bytes": 65_536,
        "max_memory_bytes": 524_288,
        "max_input_bytes": 8_192,
        "max_output_bytes": 176 if version == LIMIT_VERSION else 8_192,
        "fuel": 100_000,
    }


def _safe_contract_row(package: VerifiedActionPackage, version: str) -> dict[str, Any]:
    if len(package.actions) != 1 or len(package.behaviors) != 1:
        return {"version": version, "passed": False}
    packaged_action = package.actions[0]
    action = packaged_action.definition
    behavior = package.behaviors[0]
    provider = package.provider
    program = packaged_action.program
    parameter_rows = _parameter_rows(action)
    output_rows = _output_rows(action)
    behavior_parameters = _parameter_rows(behavior)
    behavior_outputs = _output_rows(behavior)
    artifact_sha256 = provider.artifact_sha256 if provider is not None else ""
    definition_provenance = _expected_definition_provenance(artifact_sha256)
    passed = (
        provider is not None
        and provider.kind == "wasm"
        and provider.provider_id == PROVIDER_ID
        and provider.abi_version == "bluefire.provider-abi.v1"
        and provider.artifact_size == 725
        and provider.limits.to_dict() == _expected_provider_limits(version)
        and package.manifest.compatibility.to_dict() == EXPECTED_COMPATIBILITY
        and package.manifest.license.to_dict() == EXPECTED_LICENSE
        and package.manifest.provenance.to_dict()
        == _expected_package_provenance(version, artifact_sha256)
        and package.manifest.capabilities == ("native.execution",)
        and package.manifest.safety_tiers == ("safe",)
        and package.manifest.platforms == ("windows",)
        and action.schema_version == "bluefire.action.v1"
        and action.id == ACTION_ID
        and action.capabilities == ("native.execution",)
        and action.safety_tier.value == "safe"
        and action.platforms == ("windows",)
        and not action.inputs
        and output_rows == EXPECTED_OUTPUTS
        and parameter_rows == EXPECTED_PARAMETERS
        and not action.mutates
        and action.cleanup_action_id is None
        and action.provenance.to_dict() == definition_provenance
        and behavior.schema_version == "bluefire.behavior.v1"
        and behavior.id == BEHAVIOR_ID
        and behavior.execution_state.value == "action"
        and behavior.action_ids == (ACTION_ID,)
        and behavior.capabilities == ("native.execution",)
        and behavior.safety_tier.value == "safe"
        and behavior.platforms == ("windows",)
        and not behavior.inputs
        and behavior_outputs == EXPECTED_OUTPUTS
        and behavior_parameters == EXPECTED_PARAMETERS
        and behavior.provenance.to_dict() == definition_provenance
        and isinstance(program, WasmProviderProgram)
        and program.schema_version == "bluefire.wasm-provider-program.v1"
        and program.provider_id == PROVIDER_ID
        and program.action_contract_digest.startswith("sha256:")
        and len(program.action_contract_digest) == 71
    )
    return {
        "version": version,
        "passed": passed,
        "typed_parameters": parameter_rows,
        "typed_outputs": output_rows,
        "capabilities": list(action.capabilities),
        "safety_tier": action.safety_tier.value,
        "platforms": list(action.platforms),
        "mutates": action.mutates,
        "cleanup_action_id": action.cleanup_action_id,
        "definition_provenance": action.provenance.to_dict(),
        "package_provenance": package.manifest.provenance.to_dict(),
        "license": package.manifest.license.to_dict(),
        "compatibility": package.manifest.compatibility.to_dict(),
        "provider_limits": provider.limits.to_dict() if provider is not None else None,
        "program_schema": getattr(program, "schema_version", None),
        "action_contract_digest": getattr(program, "action_contract_digest", None),
    }


def _structural_report(
    repository: Path,
    index: Mapping[str, Any],
    trusts: Mapping[str, Mapping[str, Any]],
    packages: Mapping[str, VerifiedActionPackage],
) -> dict[str, Any]:
    signatures = {package.signature_b64u for package in packages.values()}
    artifacts = {
        package.provider_artifact_bytes
        for package in packages.values()
        if package.provider_artifact_bytes
    }
    artifact_sections = {
        version: sorted(_wasm_sections(package.provider_artifact_bytes or b""))
        for version, package in packages.items()
    }
    no_imports = all(2 not in sections for sections in artifact_sections.values())
    programs_are_provider = all(
        isinstance(action.program, WasmProviderProgram)
        for package in packages.values()
        for action in package.actions
    )
    action_contracts = {
        action.program.action_contract_digest
        for package in packages.values()
        for action in package.actions
        if isinstance(action.program, WasmProviderProgram)
    }
    contract_rows = [_safe_contract_row(package, version) for version, package in packages.items()]
    safe_contract = all(row["passed"] is True for row in contract_rows)
    manifest_integrity = (
        len(signatures) == 3
        and len(artifacts) == 2
        and len({package.package_digest for package in packages.values()}) == 3
        and len({package.content_digest for package in packages.values()}) == 3
        and all(
            package.manifest.version == version
            and package.manifest.compatibility.to_dict() == EXPECTED_COMPATIBILITY
            and package.provider is not None
            and package.provider.artifact_sha256
            == _sha256_bytes(package.provider_artifact_bytes or b"")
            for version, package in packages.items()
        )
    )
    fixture_root = repository / "tests_platform" / "fixtures" / "provider_upgrade"
    fixture_documents = [
        index,
        *trusts.values(),
        *(_load_document(_contained_file(fixture_root, row["file"])) for row in index["packages"]),
    ]
    fixture_fields = set().union(*(_walk_fields(item) for item in fixture_documents))
    source_files, shell_findings, process_boundary = _source_audit(repository)
    checks = {
        "core_independence": {
            "passed": ACTION_ID not in BUILTIN_RUNNER_ACTION_IDS and programs_are_provider,
            "logical_action_id": ACTION_ID,
            "absent_from_builtin_inventory": ACTION_ID not in BUILTIN_RUNNER_ACTION_IDS,
            "provider_program_only": programs_are_provider,
        },
        "manifest_integrity": {
            "passed": manifest_integrity,
            "verified_versions": list(packages),
            "distinct_signatures": len(signatures),
            "distinct_artifacts": len(artifacts),
            "distinct_package_digests": len(
                {package.package_digest for package in packages.values()}
            ),
            "distinct_content_digests": len(
                {package.content_digest for package in packages.values()}
            ),
            "compatibility": dict(EXPECTED_COMPATIBILITY),
            "package_digests": {
                version: package.package_digest for version, package in packages.items()
            },
            "content_digests": {
                version: package.content_digest for version, package in packages.items()
            },
            "artifact_digests": {
                version: package.provider.artifact_sha256
                for version, package in packages.items()
                if package.provider is not None
            },
        },
        "safe_contract": {
            "passed": safe_contract and no_imports and len(action_contracts) == 1,
            "provider_id": PROVIDER_ID,
            "abi_version": "bluefire.provider-abi.v1",
            "capabilities": ["native.execution"],
            "safety_tiers": ["safe"],
            "platforms": ["windows"],
            "license": "MIT",
            "no_host_imports": no_imports,
            "wasm_section_ids": artifact_sections,
            "stable_action_contract_digest": next(iter(action_contracts), None),
            "versions": contract_rows,
        },
        "no_model_shell": {
            "passed": not shell_findings
            and process_boundary["passed"] is True
            and not fixture_fields.intersection(FORBIDDEN_PACKAGE_EXECUTION_FIELDS),
            "source_files": source_files,
            "findings": shell_findings,
            "process_boundary": process_boundary,
            "forbidden_fixture_fields": sorted(
                fixture_fields.intersection(FORBIDDEN_PACKAGE_EXECUTION_FIELDS)
            ),
            "execution_boundary": "typed-signed-provider-contract-to-no-import-wasm-only",
        },
    }
    return {
        "schema_version": STRUCTURAL_SCHEMA,
        "passed": all(check["passed"] is True for check in checks.values()),
        "fixture_schema_version": index["schema_version"],
        "checks": checks,
    }
