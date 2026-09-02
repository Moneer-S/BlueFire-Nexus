"""Strict structural-evidence validation for the signed-provider gate."""

from __future__ import annotations

from typing import Any, Mapping

STRUCTURAL_SCHEMA = "bluefire.provider-structural-evidence.v1"

_PROVIDER_ACTION_ID = "fixture.provider-upgrade.action.v1"
_VERSIONS = ("1.0.0", "2.0.0", "3.0.0")
_COMPATIBILITY = {
    "minimum_bluefire_version": "0.1.0",
    "maximum_bluefire_version_exclusive": "1.0.0",
}
_LICENSE = {
    "spdx_id": "MIT",
    "notice": "Copyright 2026 BlueFire fixture authors; MIT licensed.",
}
_TYPED_PARAMETERS = [
    {
        "name": "message",
        "type": "string",
        "required": False,
        "default": "probe",
        "enum": ["probe", "verify"],
        "minimum": None,
        "maximum": None,
    },
    {
        "name": "repeat_count",
        "type": "integer",
        "required": False,
        "default": 1,
        "enum": [1, 2],
        "minimum": 1.0,
        "maximum": 2.0,
    },
]
_TYPED_OUTPUTS = [
    {
        "name": "result",
        "type": "artifact.fixture.provider-upgrade-result.v1",
        "required": True,
        "multiple": False,
    }
]
_SAFE_VERSION_FIELDS = {
    "version",
    "passed",
    "typed_parameters",
    "typed_outputs",
    "capabilities",
    "safety_tier",
    "platforms",
    "mutates",
    "cleanup_action_id",
    "definition_provenance",
    "package_provenance",
    "license",
    "compatibility",
    "provider_limits",
    "program_schema",
    "action_contract_digest",
}
_SOURCE_AUDIT_PATHS = (
    "bluefire/action_packages.py",
    "bluefire/action_provider_packages.py",
    "bluefire/action_catalog.py",
    "bluefire/provider_runner_contracts.py",
    "bluefire/runner_adapter.py",
    "bluefire/orchestrator.py",
    "bluefire/service.py",
    "bluefire/ai.py",
    "bluefire/ai_drafts.py",
    "bluefire/planner.py",
    "bluefire/api.py",
    "bluefire/cli.py",
    "bluefire/job_runtime.py",
    "bluefire/runner_host.py",
    "runner/src/providers.rs",
    "runner/src/provider_action.rs",
    "runner/src/runner.rs",
    "bluefire/runner_client.py",
    "bluefire/runner_bootstrap.py",
    "bluefire/runner_lifecycle.py",
    "bluefire/runner_trust.py",
    "bluefire/runner_watchdog.py",
    "runner/src/process.rs",
)
_PROCESS_CHECKS = {
    "python_process_call_inventory": True,
    "popen_shell_disabled": True,
    "absolute_digest_bound_runner": True,
    "bootstrap_fixed_system_tools": True,
    "trust_fixed_system_tools": True,
    "lifecycle_uses_fixed_installed_host": True,
    "watchdog_has_no_process_launcher": True,
    "native_process_inventory_is_fixed": True,
}
_PYTHON_BOUNDARIES = {
    "runner_client.py": {
        "passed": True,
        "shell_imports": 1,
        "process_calls": ["subprocess.Popen", "subprocess.Popen"],
        "unexpected_findings": [],
    },
    "runner_bootstrap.py": {
        "passed": True,
        "shell_imports": 0,
        "process_calls": [],
        "unexpected_findings": [],
    },
    "runner_lifecycle.py": {
        "passed": True,
        "shell_imports": 1,
        "process_calls": ["subprocess.Popen"],
        "unexpected_findings": [],
    },
    "runner_trust.py": {
        "passed": True,
        "shell_imports": 0,
        "process_calls": [],
        "unexpected_findings": [],
    },
}


def _check_map(value: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ValueError(f"{label} checks do not match the locked workflow")
    for name, check in value.items():
        if not isinstance(check, Mapping) or check.get("passed") is not True:
            raise ValueError(f"{label} check {name} did not pass")
    return value


def _is_sha256_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _validate_structural(report: Mapping[str, Any]) -> Mapping[str, Any]:
    if not isinstance(report, Mapping) or set(report) != {
        "schema_version",
        "passed",
        "fixture_schema_version",
        "checks",
    }:
        raise ValueError("provider structural report fields are invalid")
    if (
        report.get("schema_version") != STRUCTURAL_SCHEMA
        or report.get("fixture_schema_version") != "bluefire.provider-upgrade-fixture-set.v1"
        or report.get("passed") is not True
    ):
        raise ValueError("provider structural report did not pass")
    checks = _check_map(
        report.get("checks"),
        {"core_independence", "manifest_integrity", "safe_contract", "no_model_shell"},
        "provider structural",
    )
    if checks["core_independence"] != {
        "passed": True,
        "logical_action_id": _PROVIDER_ACTION_ID,
        "absent_from_builtin_inventory": True,
        "provider_program_only": True,
    }:
        raise ValueError("provider structural core-independence evidence is invalid")
    manifest = checks["manifest_integrity"]
    manifest_fields = {
        "passed",
        "verified_versions",
        "package_digests",
        "content_digests",
        "artifact_digests",
        "distinct_signatures",
        "distinct_package_digests",
        "distinct_content_digests",
        "distinct_artifacts",
        "compatibility",
    }
    digest_maps = [
        manifest.get("package_digests"),
        manifest.get("content_digests"),
        manifest.get("artifact_digests"),
    ]
    if (
        set(manifest) != manifest_fields
        or manifest.get("verified_versions") != list(_VERSIONS)
        or manifest.get("distinct_signatures") != 3
        or manifest.get("distinct_package_digests") != 3
        or manifest.get("distinct_content_digests") != 3
        or manifest.get("distinct_artifacts") != 2
        or manifest.get("compatibility") != _COMPATIBILITY
        or any(
            not isinstance(items, Mapping)
            or set(items) != set(_VERSIONS)
            or any(not _is_sha256_digest(items[version]) for version in _VERSIONS)
            for items in digest_maps
        )
    ):
        raise ValueError("provider structural manifest-integrity evidence is invalid")
    package_digests, content_digests, artifact_digests = digest_maps
    assert isinstance(package_digests, Mapping)
    assert isinstance(content_digests, Mapping)
    assert isinstance(artifact_digests, Mapping)
    if (
        len(set(package_digests.values())) != 3
        or len(set(content_digests.values())) != 3
        or artifact_digests["1.0.0"] == artifact_digests["2.0.0"]
        or artifact_digests["2.0.0"] != artifact_digests["3.0.0"]
    ):
        raise ValueError("provider structural signed identity evidence is invalid")
    safe = checks["safe_contract"]
    safe_fields = {
        "passed",
        "provider_id",
        "abi_version",
        "capabilities",
        "safety_tiers",
        "platforms",
        "license",
        "no_host_imports",
        "stable_action_contract_digest",
        "wasm_section_ids",
        "versions",
    }
    stable_digest = safe.get("stable_action_contract_digest")
    rows = safe.get("versions")
    if (
        set(safe) != safe_fields
        or safe.get("provider_id") != "fixture.provider-upgrade.runtime.v1"
        or safe.get("abi_version") != "bluefire.provider-abi.v1"
        or safe.get("capabilities") != ["native.execution"]
        or safe.get("safety_tiers") != ["safe"]
        or safe.get("platforms") != ["windows"]
        or safe.get("license") != "MIT"
        or safe.get("no_host_imports") is not True
        or not _is_sha256_digest(stable_digest)
        or safe.get("wasm_section_ids") != {version: [1, 3, 5, 7, 10, 11] for version in _VERSIONS}
        or not isinstance(rows, list)
        or len(rows) != 3
        or any(not isinstance(row, Mapping) for row in rows)
    ):
        raise ValueError("provider structural safe-contract evidence is invalid")
    for version, row in zip(_VERSIONS, rows, strict=True):
        artifact_digest = artifact_digests[version]
        reference_suffix = "3.0.0-output-limit" if version == "3.0.0" else version
        if (
            set(row) != _SAFE_VERSION_FIELDS
            or row.get("passed") is not True
            or row.get("version") != version
            or row.get("action_contract_digest") != stable_digest
            or row.get("program_schema") != "bluefire.wasm-provider-program.v1"
            or row.get("capabilities") != ["native.execution"]
            or row.get("safety_tier") != "safe"
            or row.get("platforms") != ["windows"]
            or row.get("mutates") is not False
            or row.get("cleanup_action_id") is not None
            or row.get("typed_parameters") != _TYPED_PARAMETERS
            or row.get("typed_outputs") != _TYPED_OUTPUTS
            or row.get("license") != _LICENSE
            or row.get("compatibility") != _COMPATIBILITY
            or row.get("definition_provenance")
            != {
                "source": "BlueFire committed deterministic no-import WebAssembly provider fixture",
                "reference": f"urn:bluefire:fixture:provider-upgrade:{artifact_digest}",
                "license": "MIT",
                "derived": False,
                "notes": "Guest output attests the exact canonical message and repeat_count input.",
            }
            or row.get("package_provenance")
            != {
                "publisher_id": "bluefire.fixture.provider-upgrade",
                "source": (
                    "Deterministically assembled no-import WebAssembly fixture committed with "
                    "BlueFire Nexus"
                ),
                "reference": (
                    "urn:bluefire:fixture:provider-upgrade:" f"{reference_suffix}:{artifact_digest}"
                ),
                "revision": artifact_digest,
            }
            or row.get("provider_limits")
            != {
                "max_module_bytes": 65_536,
                "max_memory_bytes": 524_288,
                "max_input_bytes": 8_192,
                "max_output_bytes": 176 if version == "3.0.0" else 8_192,
                "fuel": 100_000,
            }
        ):
            raise ValueError("provider structural version contract evidence is invalid")
    shell = checks["no_model_shell"]
    process = shell.get("process_boundary")
    sources = shell.get("source_files")
    if (
        set(shell)
        != {
            "passed",
            "execution_boundary",
            "forbidden_fixture_fields",
            "findings",
            "source_files",
            "process_boundary",
        }
        or shell.get("execution_boundary")
        != "typed-signed-provider-contract-to-no-import-wasm-only"
        or shell.get("forbidden_fixture_fields") != []
        or shell.get("findings") != []
        or not isinstance(sources, list)
        or len(sources) != len(_SOURCE_AUDIT_PATHS)
        or any(
            not isinstance(item, Mapping)
            or set(item) != {"path", "sha256"}
            or not _is_sha256_digest(item.get("sha256"))
            for item in sources
        )
        or [item.get("path") for item in sources] != list(_SOURCE_AUDIT_PATHS)
        or not isinstance(process, Mapping)
        or set(process) != {"passed", "checks", "python_boundaries", "boundary"}
        or process.get("passed") is not True
        or process.get("boundary")
        != "typed-model-output-to-reviewed-actions-to-fixed-absolute-digest-bound-runner-with-shell-disabled"
        or process.get("checks") != _PROCESS_CHECKS
        or process.get("python_boundaries") != _PYTHON_BOUNDARIES
    ):
        raise ValueError("provider structural no-model-shell evidence is invalid")
    return checks


__all__ = [
    "STRUCTURAL_SCHEMA",
    "_PROVIDER_ACTION_ID",
    "_check_map",
    "_is_sha256_digest",
    "_validate_structural",
]
