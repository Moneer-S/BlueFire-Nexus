"""Strict evidence validation for the signed-provider release gate."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .provider_gate_structural_validation import (
    _PROVIDER_ACTION_ID,
    STRUCTURAL_SCHEMA,
    _check_map,
    _is_sha256_digest,
    _validate_structural,
)
from .util import content_hash

JOURNEY_SCHEMA = "bluefire.provider-journey-evidence.v1"
VERIFICATION_SCHEMA = "bluefire.provider-verification-evidence.v1"

_PROVIDER_CONTRACT_TESTS = (
    "tests_platform/test_provider_gate.py",
    "tests_platform/test_provider_upgrade_fixtures.py",
    "tests_platform/test_action_provider_packages.py",
    "tests_platform/test_provider_action_catalog.py",
    "tests_platform/test_provider_inventory.py",
    "tests_platform/test_provider_runner_contracts.py",
    "tests_platform/test_provider_runner_adapter.py",
    "tests_platform/test_provider_orchestrator.py",
    "tests_platform/test_provider_action_package_service.py",
)
_API_MANAGEMENT_TESTS = (
    "tests_platform/test_api.py::test_action_package_routes_dispatch_exact_lifecycle_authority",
    "tests_platform/test_api.py::test_provider_package_api_forwards_exact_v2_envelope_and_lifecycle_authority",
    "tests_platform/test_provider_upgrade_fixtures.py::test_real_provider_lifecycle_traverses_authenticated_http_management",
)
_CLI_MANAGEMENT_TESTS = (
    "tests_platform/test_cli.py::test_cli_action_package_commands_dispatch_exact_lifecycle_requests",
    "tests_platform/test_cli.py::test_provider_package_cli_forwards_exact_signed_json_and_lifecycle_authority",
    "tests_platform/test_cli.py::test_cli_action_package_file_reads_are_bounded_and_path_safe",
    "tests_platform/test_provider_upgrade_fixtures.py::test_real_provider_lifecycle_traverses_cli_management",
)
_EXPECTED_UI_TESTS = frozenset(
    {
        "action package management shows public isolated-provider metadata and verifies an upgrade against an explicit runner profile",
        "action package management activates a first provider version through an explicit isolated-runtime verification",
        "action package management binds deactivation to the exact immutable package and current catalog snapshot",
        "action package management requires the exact package identity before immutable removal",
        "action package management forwards a file-backed v2 provider envelope to backend verification without a raw editor",
        "action package management fails closed when the server does not report isolated provider support",
        "action package management refuses an oversized signed envelope before reading it into browser memory",
        "action package management uses exact publisher and package lifecycle API routes",
    }
)

_PROVIDER_BEHAVIOR_ID = "fixture.provider-upgrade.behavior.v1"
_PYTEST_SUITE_SCHEMA = "bluefire.architecture-dynamic-check.v1"
_FRONTEND_SUITE_SCHEMA = "bluefire.provider-frontend-check.v1"
_MINIMUM_PROVIDER_CONTRACT_TESTS = 79
_EXPECTED_PROVIDER_CONTRACT_TESTS = 92
_EXPECTED_PROVIDER_CONTRACT_TESTS_SHA256 = (
    "sha256:be2638d8445143728428387a060de41468a76ceffe856722f3dfed4f5d294d42"
)
_REQUIRED_PROVIDER_CONTRACT_TESTS = frozenset(
    {
        "tests_platform.test_provider_gate::test_gate_02_emits_exact_unique_proofs_and_bundle_attachments",
        "tests_platform.test_provider_upgrade_fixtures::test_committed_provider_upgrade_fixtures_are_signed_real_no_import_wasm",
        "tests_platform.test_action_provider_packages::test_v2_package_verifies_provider_descriptor_artifact_and_action_contract",
        "tests_platform.test_provider_action_catalog::test_provider_catalog_seals_runtime_binding_without_core_opcode_alias",
        "tests_platform.test_provider_inventory::test_provider_runtime_inventory_is_canonical_and_core_independent",
        "tests_platform.test_provider_runner_contracts::test_provider_artifact_is_private_to_the_sealed_profile",
        "tests_platform.test_provider_runner_adapter::test_provider_adapter_passes_only_signed_typed_parameters",
        "tests_platform.test_provider_orchestrator::test_repeated_provider_steps_share_one_exact_inventory_binding",
        "tests_platform.test_provider_action_package_service::test_provider_activation_readiness_deactivation_and_private_history",
    }
)


def _pytest_identifier(selector: str) -> str:
    path, separator, test_name = selector.partition("::")
    if not path.endswith(".py"):
        raise ValueError("provider pytest selector is invalid")
    module = path[:-3].replace("/", ".").replace("\\", ".")
    return module if not separator else f"{module}::{test_name}"


def _expected_pytest_command(tests: Sequence[str]) -> list[str]:
    return [
        "{python}",
        "-m",
        "pytest",
        "-p",
        "no:cacheprovider",
        "-q",
        *tests,
        "--junitxml={temporary}",
    ]


def _validate_pytest_suite(
    value: Any,
    *,
    suite_id: str,
    tests: Sequence[str],
    expected_provider_contract_tests: int = _EXPECTED_PROVIDER_CONTRACT_TESTS,
    expected_provider_contract_tests_sha256: str = _EXPECTED_PROVIDER_CONTRACT_TESTS_SHA256,
) -> Mapping[str, Any]:
    expected_fields = {
        "schema_version",
        "suite_id",
        "command",
        "exit_code",
        "passed",
        "tests",
        "passed_tests",
        "failed_tests",
        "skipped_tests",
    }
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        raise ValueError(f"provider verification suite {suite_id} fields are invalid")
    passed_tests = value.get("passed_tests")
    test_count = value.get("tests")
    if (
        value.get("schema_version") != _PYTEST_SUITE_SCHEMA
        or value.get("suite_id") != suite_id
        or value.get("command") != _expected_pytest_command(tests)
        or value.get("exit_code") != 0
        or value.get("passed") is not True
        or isinstance(test_count, bool)
        or not isinstance(test_count, int)
        or not isinstance(passed_tests, list)
        or any(not isinstance(item, str) or not item for item in passed_tests)
        or passed_tests != sorted(passed_tests)
        or len(set(passed_tests)) != len(passed_tests)
        or test_count != len(passed_tests)
        or value.get("failed_tests") != []
        or value.get("skipped_tests") != []
    ):
        raise ValueError(f"provider verification suite {suite_id} did not pass exactly")
    passed_set = set(passed_tests)
    if suite_id == "provider-contracts":
        expected_modules = {_pytest_identifier(item) for item in tests}
        observed_modules = {item.partition("::")[0] for item in passed_tests}
        if (
            test_count < _MINIMUM_PROVIDER_CONTRACT_TESTS
            or test_count != expected_provider_contract_tests
            or content_hash(passed_tests) != expected_provider_contract_tests_sha256
            or not _REQUIRED_PROVIDER_CONTRACT_TESTS.issubset(passed_set)
            or observed_modules != expected_modules
        ):
            raise ValueError("provider contract regression coverage is incomplete")
    else:
        expected_tests = {_pytest_identifier(item) for item in tests}
        if passed_set != expected_tests:
            raise ValueError(f"provider verification suite {suite_id} coverage is invalid")
    return value


def _validate_frontend_suite(value: Any) -> Mapping[str, Any]:
    expected_fields = {
        "schema_version",
        "suite_id",
        "command",
        "exit_code",
        "passed",
        "tests",
        "passed_tests",
        "failed_tests",
    }
    expected_tests = sorted(_EXPECTED_UI_TESTS)
    if (
        not isinstance(value, Mapping)
        or set(value) != expected_fields
        or value.get("schema_version") != _FRONTEND_SUITE_SCHEMA
        or value.get("suite_id") != "provider-management-ui"
        or value.get("command") != ["{node}", "{vitest}", "run", "tests/action-packages.test.tsx"]
        or value.get("exit_code") != 0
        or value.get("passed") is not True
        or value.get("tests") != len(expected_tests)
        or value.get("passed_tests") != expected_tests
        or value.get("failed_tests") != []
    ):
        raise ValueError("provider verification frontend coverage is invalid")
    return value


def _validate_helper_report(value: Any) -> Mapping[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"passed", "exit_code", "command", "protocol_valid"}
        or value.get("passed") is not True
        or value.get("exit_code") != 0
        or value.get("command")
        != ["{python}", "tools/run_provider_gate_journey.py", "{fixed-arguments}"]
        or value.get("protocol_valid") is not True
    ):
        raise ValueError("provider verification helper protocol is invalid")
    return value


def _suite_test_passed(suite: Mapping[str, Any], selector: str) -> bool:
    passed_tests = suite.get("passed_tests")
    return isinstance(passed_tests, list) and _pytest_identifier(selector) in passed_tests


def _validate_packaged_runner(value: Any) -> Mapping[str, Any]:
    expected_fields = {
        "package_manifest_sha256",
        "binary_sha256",
        "binary_size",
        "runner_id",
        "runner_version",
        "platform",
        "architecture",
        "inventory_digest",
        "inventory_contract",
        "provider_runtime",
        "logical_action_absent_from_core_inventory",
    }
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        raise ValueError("provider journey packaged runner fields are invalid")
    runtime = value.get("provider_runtime")
    if not isinstance(runtime, Mapping) or set(runtime) != {
        "kind",
        "abi_version",
        "readiness",
        "runtime_version",
        "no_host_imports",
        "hard_limits",
        "contract_digest",
    }:
        raise ValueError("provider journey packaged runtime fields are invalid")
    inventory_contract = value.get("inventory_contract")
    if not isinstance(inventory_contract, Mapping) or inventory_contract != {
        "schema_version": "bluefire.runner-inventory.v1",
        "runner": "bluefire-rust-runner",
        "runner_id": "bluefire-rust-runner.v1",
        "runner_version": "0.1.0",
        "action_sdk_version": "bluefire.runner-action-sdk.v1",
        "receipt_protocol": "bluefire.runner-receipt-wal.v2",
        "platform": "windows",
        "provider_runtime_count": 1,
        "core_action_count": 18,
    }:
        raise ValueError("provider journey runner inventory contract is invalid")
    hard_limits = runtime.get("hard_limits")
    runtime_contract = {key: item for key, item in runtime.items() if key != "contract_digest"}
    if (
        not _is_sha256_digest(value.get("package_manifest_sha256"))
        or not _is_sha256_digest(value.get("binary_sha256"))
        or not _is_sha256_digest(value.get("inventory_digest"))
        or isinstance(value.get("binary_size"), bool)
        or not isinstance(value.get("binary_size"), int)
        or not 0 < int(value["binary_size"]) <= 134_217_728
        or value.get("runner_id") != "bluefire-rust-runner.v1"
        or value.get("runner_version") != "0.1.0"
        or value.get("platform") != "windows"
        or value.get("architecture") != "x86_64"
        or value.get("logical_action_absent_from_core_inventory") is not True
        or runtime.get("kind") != "wasm"
        or runtime.get("abi_version") != "bluefire.provider-abi.v1"
        or runtime.get("readiness") != "ready"
        or runtime.get("runtime_version") != "wasmi-1.1.0"
        or runtime.get("no_host_imports") is not True
        or hard_limits
        != {
            "max_module_bytes": 2_097_152,
            "max_memory_bytes": 16_777_216,
            "max_input_bytes": 1_048_576,
            "max_output_bytes": 1_048_576,
            "fuel": 100_000_000,
        }
        or runtime.get("contract_digest") != content_hash(runtime_contract)
    ):
        raise ValueError("provider journey packaged runner contract is invalid")
    return value


def _validate_inventory_binding(
    check: Mapping[str, Any], packaged_runner: Mapping[str, Any]
) -> None:
    if set(check) != {
        "passed",
        "activation_snapshots",
        "transition_snapshots",
        "catalog_generations",
        "catalog_digests",
        "native_inventory_digest_stable",
        "effective_inventory_digests",
    }:
        raise ValueError("provider journey inventory check fields are invalid")
    activations = check.get("activation_snapshots")
    transitions = check.get("transition_snapshots")
    if (
        not isinstance(activations, list)
        or len(activations) != 3
        or not isinstance(transitions, list)
        or len(transitions) != 3
        or any(not isinstance(item, Mapping) for item in (*activations, *transitions))
    ):
        raise ValueError("provider journey inventory snapshots are invalid")
    activation_fields = {
        "phase",
        "version",
        "catalog_generation",
        "catalog_digest",
        "native_inventory_digest",
        "effective_inventory_digest",
        "provider_action_count",
        "package_digest",
        "content_digest",
        "artifact_sha256",
        "runtime_contract_digest",
        "execution_model",
        "native_action_id_exposed",
    }
    transition_fields = {
        "phase",
        "catalog_generation",
        "catalog_digest",
        "native_inventory_digest",
        "effective_inventory_digest",
        "provider_action_count",
    }
    if any(set(item) != activation_fields for item in activations) or any(
        set(item) != transition_fields for item in transitions
    ):
        raise ValueError("provider journey inventory snapshot fields are invalid")
    native_digest = packaged_runner["inventory_digest"]
    runtime_digest = packaged_runner["provider_runtime"]["contract_digest"]
    if any(
        item.get("native_inventory_digest") != native_digest
        for item in (*activations, *transitions)
    ):
        raise ValueError("provider journey inventory is detached from the packaged runner")
    if any(item.get("runtime_contract_digest") != runtime_digest for item in activations):
        raise ValueError("provider journey runtime is detached from the packaged runner")
    versions = ["1.0.0", "2.0.0", "3.0.0"]
    if (
        [item.get("version") for item in activations] != versions
        or [item.get("phase") for item in activations]
        != [f"active-{version}" for version in versions]
        or [item.get("phase") for item in transitions]
        != [
            "before-provider-activation",
            "after-provider-deactivation",
            "after-provider-removal",
        ]
        or any(item.get("provider_action_count") != 1 for item in activations)
        or any(item.get("provider_action_count") != 0 for item in transitions)
        or any(item.get("execution_model") != "wasm_provider_v1" for item in activations)
        or any(item.get("native_action_id_exposed") is not False for item in activations)
    ):
        raise ValueError("provider journey inventory transition semantics are invalid")
    for item in (*activations, *transitions):
        if not all(
            _is_sha256_digest(item.get(field))
            for field in (
                "catalog_digest",
                "native_inventory_digest",
                "effective_inventory_digest",
            )
        ):
            raise ValueError("provider journey inventory digest is invalid")
    for item in activations:
        if not all(
            _is_sha256_digest(item.get(field))
            for field in ("package_digest", "content_digest", "artifact_sha256")
        ):
            raise ValueError("provider journey package inventory digest is invalid")
    package_digests = [item["package_digest"] for item in activations]
    content_digests = [item["content_digest"] for item in activations]
    artifact_digests = [item["artifact_sha256"] for item in activations]
    if (
        len(set(package_digests)) != 3
        or len(set(content_digests)) != 3
        or artifact_digests[0] == artifact_digests[1]
        or artifact_digests[1] != artifact_digests[2]
    ):
        raise ValueError("provider journey upgrade identities are invalid")
    timeline = [transitions[0], *activations, transitions[1], transitions[2]]
    generations = [item["catalog_generation"] for item in timeline]
    catalog_digests = [item["catalog_digest"] for item in timeline]
    effective_digests = [item["effective_inventory_digest"] for item in timeline]
    if (
        generations != [0, 1, 2, 3, 4, 4]
        or check.get("catalog_generations") != generations
        or check.get("catalog_digests") != catalog_digests
        or len(set(catalog_digests[:4])) != 4
        or catalog_digests[4] != catalog_digests[0]
        or catalog_digests[5] != catalog_digests[4]
        or check.get("effective_inventory_digests") != effective_digests
        or any(not _is_sha256_digest(item) for item in effective_digests)
        or len(set(effective_digests[:5])) != 5
        or effective_digests[5] != effective_digests[4]
        or check.get("native_inventory_digest_stable") is not True
    ):
        raise ValueError("provider journey inventory timeline is invalid")


def _validate_journey(
    report: Mapping[str, Any],
) -> tuple[Mapping[str, Any], tuple[dict[str, str], ...]]:
    if set(report) != {
        "schema_version",
        "passed",
        "packaged_runner",
        "executions",
        "run_bundles",
        "checks",
    }:
        raise ValueError("provider journey report fields are invalid")
    if report.get("schema_version") != JOURNEY_SCHEMA or report.get("passed") is not True:
        raise ValueError("provider journey report did not pass")
    packaged_runner = _validate_packaged_runner(report.get("packaged_runner"))
    checks = _check_map(
        report.get("checks"),
        {
            "new_provider_artifact",
            "lifecycle",
            "inventory_compatibility",
            "tamper_refusal",
            "limits_cleanup",
        },
        "provider journey",
    )
    _validate_inventory_binding(checks["inventory_compatibility"], packaged_runner)
    raw_bundles = report.get("run_bundles")
    if not isinstance(raw_bundles, list) or len(raw_bundles) != 3:
        raise ValueError("provider journey must bind exactly three run bundles")
    bundles: list[dict[str, str]] = []
    for raw in raw_bundles:
        if not isinstance(raw, Mapping) or set(raw) != {"run_id", "path"}:
            raise ValueError("provider journey run bundle reference is invalid")
        run_id = raw.get("run_id")
        path = raw.get("path")
        if not isinstance(run_id, str) or not isinstance(path, str) or path != f"runs/{run_id}":
            raise ValueError("provider journey run bundle identity is invalid")
        bundles.append({"run_id": run_id, "path": path})
    if len({item["run_id"] for item in bundles}) != 3:
        raise ValueError("provider journey run bundles must be unique")
    executions = report.get("executions")
    if not isinstance(executions, list) or len(executions) != 3:
        raise ValueError("provider journey execution inventory is invalid")
    if any(not isinstance(item, Mapping) for item in executions):
        raise ValueError("provider journey execution row is invalid")
    typed_executions = [item for item in executions if isinstance(item, Mapping)]
    execution_fields = {
        "version",
        "run_id",
        "status",
        "step_status",
        "action_id",
        "behavior_id",
        "typed_output_value",
        "error_code",
        "receipt_count",
        "bundle_valid",
        "acceptance_bound",
        "stored_semantics_bound",
        "private_provider_bytes_exposed",
        "provider_execution",
        "parameter_observations",
        "serialized_parameters",
    }
    if any(set(item) != execution_fields for item in typed_executions):
        raise ValueError("provider journey execution fields are invalid")
    if [item.get("version") for item in typed_executions] != ["1.0.0", "2.0.0", "3.0.0"]:
        raise ValueError("provider journey execution order is invalid")
    execution_run_ids = [item.get("run_id") for item in typed_executions]
    if execution_run_ids != [item["run_id"] for item in bundles]:
        raise ValueError("provider journey executions do not match their run bundles")
    by_version = {str(item.get("version")): item for item in typed_executions}
    expected_parameters = {"message": "verify", "repeat_count": 2}
    success_metrics = [
        by_version[version].get("provider_execution") for version in ("1.0.0", "2.0.0")
    ]
    if (
        set(by_version) != {"1.0.0", "2.0.0", "3.0.0"}
        or by_version["1.0.0"].get("status") != "completed"
        or by_version["2.0.0"].get("status") != "completed"
        or by_version["3.0.0"].get("status") != "incomplete"
        or by_version["1.0.0"].get("step_status") != "success"
        or by_version["2.0.0"].get("step_status") != "success"
        or by_version["3.0.0"].get("step_status") != "failed"
        or any(item.get("action_id") != _PROVIDER_ACTION_ID for item in by_version.values())
        or any(item.get("behavior_id") != _PROVIDER_BEHAVIOR_ID for item in by_version.values())
        or any(item.get("bundle_valid") is not True for item in by_version.values())
        or any(item.get("acceptance_bound") is not True for item in by_version.values())
        or any(item.get("stored_semantics_bound") is not True for item in by_version.values())
        or any(
            item.get("private_provider_bytes_exposed") is not False for item in by_version.values()
        )
        or any(item.get("receipt_count") != 0 for item in by_version.values())
        or any(
            item.get("serialized_parameters") != expected_parameters for item in by_version.values()
        )
        or by_version["1.0.0"].get("typed_output_value") != "1.0.0|message=verify|repeat_count=2"
        or by_version["2.0.0"].get("typed_output_value") != "2.0.0|message=verify|repeat_count=2"
        or by_version["3.0.0"].get("typed_output_value") is not None
        or by_version["1.0.0"].get("error_code") is not None
        or by_version["2.0.0"].get("error_code") is not None
        or by_version["3.0.0"].get("error_code") != "provider_runtime_failed"
        or by_version["3.0.0"].get("provider_execution") is not None
        or any(
            not isinstance(metrics, Mapping)
            or set(metrics)
            != {
                "artifact_sha256",
                "fuel_consumed",
                "memory_bytes",
                "output_bytes",
                "no_host_imports",
            }
            or not isinstance(metrics.get("artifact_sha256"), str)
            or not str(metrics["artifact_sha256"]).startswith("sha256:")
            or isinstance(metrics.get("fuel_consumed"), bool)
            or not isinstance(metrics.get("fuel_consumed"), int)
            or not 0 < int(metrics["fuel_consumed"]) <= 100_000
            or metrics.get("memory_bytes") != 65_536
            or metrics.get("output_bytes") != 177
            or metrics.get("no_host_imports") is not True
            for metrics in success_metrics
        )
    ):
        raise ValueError("provider journey execution outcomes are invalid")
    expected_observation_parameters = [
        {"message": "verify", "repeat_count": 2},
        {"message": "probe", "repeat_count": 1},
    ]
    for version in ("1.0.0", "2.0.0"):
        observations = by_version[version].get("parameter_observations")
        if (
            not isinstance(observations, list)
            or len(observations) != 2
            or any(not isinstance(item, Mapping) for item in observations)
        ):
            raise ValueError("provider journey parameter observations are invalid")
        for index, (observation, parameters) in enumerate(
            zip(observations, expected_observation_parameters, strict=True)
        ):
            metrics = observation.get("provider_execution")
            expected_value = (
                f"{version}|message={parameters['message']}|"
                f"repeat_count={parameters['repeat_count']}"
            )
            if (
                set(observation) != {"parameters", "typed_output_value", "provider_execution"}
                or observation.get("parameters") != parameters
                or observation.get("typed_output_value") != expected_value
                or not isinstance(metrics, Mapping)
                or set(metrics)
                != {
                    "artifact_sha256",
                    "fuel_consumed",
                    "memory_bytes",
                    "output_bytes",
                    "no_host_imports",
                }
                or metrics.get("artifact_sha256")
                != by_version[version]["provider_execution"]["artifact_sha256"]
                or isinstance(metrics.get("fuel_consumed"), bool)
                or not isinstance(metrics.get("fuel_consumed"), int)
                or not 0 < int(metrics["fuel_consumed"]) <= 100_000
                or metrics.get("memory_bytes") != 65_536
                or metrics.get("output_bytes") != 177 - index
                or metrics.get("no_host_imports") is not True
            ):
                raise ValueError("provider journey parameter attestation is invalid")
        if by_version[version].get("provider_execution") != observations[0].get(
            "provider_execution"
        ):
            raise ValueError("provider journey primary execution evidence is invalid")
    limit_observations = by_version["3.0.0"].get("parameter_observations")
    if limit_observations != [
        {
            "parameters": {"message": "verify", "repeat_count": 2},
            "typed_output_value": None,
            "provider_execution": None,
        }
    ]:
        raise ValueError("provider journey limit observation is invalid")
    activation_by_version = {
        str(item["version"]): item
        for item in checks["inventory_compatibility"]["activation_snapshots"]
    }
    if any(
        by_version[version]["provider_execution"]["artifact_sha256"]
        != activation_by_version[version]["artifact_sha256"]
        for version in ("1.0.0", "2.0.0")
    ):
        raise ValueError("provider journey execution artifact binding is invalid")
    new_provider = checks["new_provider_artifact"]
    if (
        set(new_provider)
        != {
            "passed",
            "successful_versions",
            "real_rust_run_ids",
            "guest_parameter_attestation",
        }
        or new_provider.get("successful_versions") != ["1.0.0", "2.0.0"]
        or new_provider.get("real_rust_run_ids") != execution_run_ids[:2]
        or new_provider.get("guest_parameter_attestation") is not True
    ):
        raise ValueError("provider journey new-provider proof is invalid")
    lifecycle = checks["lifecycle"]
    expected_lifecycle = [
        {
            "operation": "trust",
            "publisher_id": "bluefire.fixture.provider-upgrade",
            "key_id": "fixture-release-2026",
        },
        {
            "operation": "trust",
            "publisher_id": "bluefire.fixture.provider-upgrade",
            "key_id": "fixture-limit-release-2026",
        },
        {"operation": "install", "version": "1.0.0"},
        {"operation": "activation", "version": "1.0.0"},
        {"operation": "install", "version": "2.0.0"},
        {"operation": "upgrade", "version": "2.0.0"},
        {"operation": "install", "version": "3.0.0"},
        {"operation": "upgrade", "version": "3.0.0"},
        {"operation": "deactivate", "version": "3.0.0"},
        {"operation": "remove", "version": "3.0.0"},
        {"operation": "remove", "version": "2.0.0"},
        {"operation": "remove", "version": "1.0.0"},
    ]
    if (
        set(lifecycle) != {"passed", "operations"}
        or lifecycle.get("operations") != expected_lifecycle
    ):
        raise ValueError("provider journey lifecycle proof is invalid")
    tamper = checks["tamper_refusal"]
    if set(tamper) != {"passed", "cases"} or tamper.get("cases") != [
        {
            "case_id": case_id,
            "error_code": "action_package_install_refused",
            "status": "refused",
        }
        for case_id in (
            "unknown-publisher-key",
            "altered-signature",
            "substituted-artifact",
        )
    ]:
        raise ValueError("provider journey tamper-refusal proof is invalid")
    limits = checks["limits_cleanup"]
    if (
        set(limits)
        != {
            "passed",
            "canonical_output_bytes",
            "signed_max_output_bytes",
            "fresh_guest_invocations",
            "receipt_counts",
            "sandbox_files_after_runs",
            "teardown",
            "private_product_store_removed",
        }
        or limits.get("canonical_output_bytes") != 177
        or limits.get("signed_max_output_bytes") != 176
        or limits.get("fresh_guest_invocations") != 5
        or limits.get("receipt_counts") != {version: 0 for version in by_version}
        or limits.get("sandbox_files_after_runs") != []
        or limits.get("private_product_store_removed") is not True
        or limits.get("teardown")
        != {
            "catalog_packages": 0,
            "logical_action_registered": False,
            "private_provider_artifacts": 0,
            "version_statuses": {version: "removed" for version in by_version},
        }
    ):
        raise ValueError("provider journey resource-limit cleanup proof is invalid")
    return checks, tuple(bundles)


def _validate_verification(
    report: Mapping[str, Any],
    *,
    expected_provider_contract_tests: int = _EXPECTED_PROVIDER_CONTRACT_TESTS,
    expected_provider_contract_tests_sha256: str = _EXPECTED_PROVIDER_CONTRACT_TESTS_SHA256,
) -> Mapping[str, Any]:
    if set(report) != {"schema_version", "passed", "helper", "suites", "checks"}:
        raise ValueError("provider verification report fields are invalid")
    if report.get("schema_version") != VERIFICATION_SCHEMA or report.get("passed") is not True:
        raise ValueError("provider verification report did not pass")
    _validate_helper_report(report.get("helper"))
    suites = report.get("suites")
    if not isinstance(suites, Mapping) or set(suites) != {
        "provider_contracts",
        "management_api",
        "management_cli",
        "management_ui",
    }:
        raise ValueError("provider verification suite inventory is invalid")
    _validate_pytest_suite(
        suites["provider_contracts"],
        suite_id="provider-contracts",
        tests=_PROVIDER_CONTRACT_TESTS,
        expected_provider_contract_tests=expected_provider_contract_tests,
        expected_provider_contract_tests_sha256=expected_provider_contract_tests_sha256,
    )
    _validate_pytest_suite(
        suites["management_api"],
        suite_id="provider-management-api",
        tests=_API_MANAGEMENT_TESTS,
    )
    _validate_pytest_suite(
        suites["management_cli"],
        suite_id="provider-management-cli",
        tests=_CLI_MANAGEMENT_TESTS,
    )
    _validate_frontend_suite(suites["management_ui"])
    checks = _check_map(
        report.get("checks"),
        {"management_parity", "tamper_refusal", "limits_cleanup"},
        "provider verification",
    )
    management = checks["management_parity"]
    expected_channels = {
        "ui_request_wiring": True,
        "api_route_to_lifecycle_authority": True,
        "cli_request_to_lifecycle_authority": True,
        "api_real_signed_provider_lifecycle": True,
        "cli_real_signed_provider_lifecycle": True,
        "real_signed_provider_lifecycle_service": True,
    }
    if set(management) != {"passed", "channels"} or management.get("channels") != expected_channels:
        raise ValueError("provider verification management channels are invalid")
    tamper = checks["tamper_refusal"]
    if tamper != {
        "passed": True,
        "real_service_refusal": True,
        "contract_regressions": True,
    }:
        raise ValueError("provider verification tamper coverage is invalid")
    limits = checks["limits_cleanup"]
    if limits != {
        "passed": True,
        "real_rust_limit_run": True,
        "contract_regressions": True,
    }:
        raise ValueError("provider verification limit coverage is invalid")
    return checks


__all__ = [
    "JOURNEY_SCHEMA",
    "STRUCTURAL_SCHEMA",
    "VERIFICATION_SCHEMA",
    "_API_MANAGEMENT_TESTS",
    "_CLI_MANAGEMENT_TESTS",
    "_EXPECTED_PROVIDER_CONTRACT_TESTS",
    "_EXPECTED_PROVIDER_CONTRACT_TESTS_SHA256",
    "_EXPECTED_UI_TESTS",
    "_FRONTEND_SUITE_SCHEMA",
    "_MINIMUM_PROVIDER_CONTRACT_TESTS",
    "_PROVIDER_ACTION_ID",
    "_PROVIDER_BEHAVIOR_ID",
    "_PROVIDER_CONTRACT_TESTS",
    "_PYTEST_SUITE_SCHEMA",
    "_REQUIRED_PROVIDER_CONTRACT_TESTS",
    "_check_map",
    "_expected_pytest_command",
    "_is_sha256_digest",
    "_pytest_identifier",
    "_suite_test_passed",
    "_validate_frontend_suite",
    "_validate_helper_report",
    "_validate_inventory_binding",
    "_validate_journey",
    "_validate_packaged_runner",
    "_validate_pytest_suite",
    "_validate_structural",
    "_validate_verification",
]
