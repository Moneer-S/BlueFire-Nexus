"""Real Rust-runner lifecycle and execution evidence for GATE-02."""

from __future__ import annotations

import copy
import os
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from bluefire import __version__
from bluefire.api import APIError
from bluefire.config import RunnerProfile
from bluefire.contracts import ExecutionMode
from bluefire.evidence import EvidenceRecord
from bluefire.runner_bootstrap import (
    current_architecture,
    current_platform,
    load_runner_manifest,
    validate_runner_inventory,
)
from bluefire.runner_client import SubprocessRustRunner, runner_inventory_digest
from bluefire.service import BlueFireService
from bluefire.util import content_hash
from tools.provider_gate_common import (
    ACTION_ID,
    ALL_VERSIONS,
    BEHAVIOR_ID,
    JOURNEY_SCHEMA,
    LIMIT_VERSION,
    PACKAGE_ID,
    SUCCESS_VERSIONS,
    ProviderGateError,
    _assert_public,
    _contained_file,
    _contains_literal,
    _load_document,
    _sha256_file,
)


def _tampered_envelope(envelope: Mapping[str, Any], mode: str, substitute: str) -> dict[str, Any]:
    changed = copy.deepcopy(dict(envelope))
    if mode == "signature":
        signature = str(changed["signature"]["value"])
        changed["signature"]["value"] = signature[:-1] + ("A" if signature[-1] != "A" else "B")
    elif mode == "artifact":
        changed["payload"]["artifact_hex"] = substitute
    else:  # pragma: no cover - repository-owned calls only
        raise ProviderGateError("unknown tamper mode")
    return changed


def _expect_install_refusal(
    service: BlueFireService,
    envelope: Mapping[str, Any],
    case_id: str,
) -> dict[str, str]:
    try:
        service.install_action_package(
            {"envelope": dict(envelope), "installed_by": "provider-gate-refusal-probe"}
        )
    except APIError as exc:
        if exc.code != "action_package_install_refused":
            raise ProviderGateError("tamper refusal returned an unexpected public code") from exc
        return {"case_id": case_id, "status": "refused", "error_code": exc.code}
    raise ProviderGateError("tampered or untrusted provider package was accepted")


def _execute_profile(service: BlueFireService) -> RunnerProfile:
    profiles = [
        profile for profile in service._runner_profiles() if profile.mode is ExecutionMode.EXECUTE
    ]
    if not profiles:
        raise ProviderGateError("no Execute runner profile is available")
    return next(
        (profile for profile in profiles if profile.id == "sandbox-execute.v1"), profiles[0]
    )


def _scenario(*, attest_parameters: bool) -> dict[str, Any]:
    parameter_sets = [{"message": "verify", "repeat_count": 2}]
    if attest_parameters:
        parameter_sets.append({"message": "probe", "repeat_count": 1})
    steps: list[dict[str, Any]] = [
        {
            "id": "provider_probe" if index == 0 else "provider_default_probe",
            "behavior_id": BEHAVIOR_ID,
            "parameters": dict(parameters),
            "inputs": {},
            "alternates": [],
        }
        for index, parameters in enumerate(parameter_sets)
    ]
    edges = [
        {
            "from_step": str(steps[index - 1]["id"]),
            "outcome": "success",
            "to_step": str(steps[index]["id"]),
        }
        for index in range(1, len(steps))
    ]
    return {
        "schema_version": "bluefire.scenario.v1",
        "id": "scenario.provider-upgrade.acceptance.v1",
        "title": "Signed provider upgrade acceptance",
        "purpose": "Execute one independently signed no-import provider through the Rust runner.",
        "start": "provider_probe",
        "steps": steps,
        "edges": edges,
        "provenance": {
            "source": "BlueFire committed provider acceptance fixture",
            "reference": "urn:bluefire:provider-gate:scenario:v1",
            "license": "MIT",
            "derived": False,
            "notes": "No external content or credentials.",
        },
        "limitations": ["The provider is effect-free and receives no host imports."],
    }


def _run_provider(
    service: BlueFireService,
    profile: RunnerProfile,
    *,
    expected_status: str,
    expected_version: str,
    expected_artifact_sha256: str,
    expected_output_bytes: int,
    forbidden_artifact_hex: Sequence[str],
) -> tuple[dict[str, Any], dict[str, str]]:
    attest_parameters = expected_status == "completed"
    scenario = _scenario(attest_parameters=attest_parameters)
    parameter_sets = [
        {"message": "verify", "repeat_count": 2},
        *([{"message": "probe", "repeat_count": 1}] if attest_parameters else []),
    ]
    expected_values: list[str | None] = [
        (
            f"{expected_version}|message={parameters['message']}|"
            f"repeat_count={parameters['repeat_count']}"
            if expected_status == "completed"
            else None
        )
        for parameters in parameter_sets
    ]
    expected_output_sizes = [expected_output_bytes - index for index in range(len(parameter_sets))]
    result = service.run(
        {
            "scenario": scenario,
            "mode": "execute",
            "runner_profile_id": profile.id,
            "autonomy": "off",
            "target_scope": {"scope_refs": list(profile.scope)},
            "approval": {"confirmed": True, "approved_by": "provider-gate-reviewer"},
        }
    )
    _assert_public(result)
    if _contains_literal(result, forbidden_artifact_hex):
        raise ProviderGateError("provider run response exposed private provider bytes")
    run_id = result.get("run_id")
    steps = result.get("steps")
    if (
        not isinstance(run_id, str)
        or not isinstance(steps, list)
        or len(steps) != len(parameter_sets)
        or any(not isinstance(item, Mapping) for item in steps)
        or result.get("status") != expected_status
    ):
        raise ProviderGateError("provider run returned an unexpected result")
    typed_steps = [item for item in steps if isinstance(item, Mapping)]
    if any(
        step.get("action_id") != ACTION_ID or step.get("behavior_id") != BEHAVIOR_ID
        for step in typed_steps
    ):
        raise ProviderGateError("provider run changed its logical identity")
    if expected_status == "completed":
        for step, expected_value in zip(typed_steps, expected_values, strict=True):
            raw_artifacts = step.get("artifacts")
            artifact = raw_artifacts.get("result") if isinstance(raw_artifacts, Mapping) else None
            if (
                step.get("status") != "success"
                or not isinstance(artifact, Mapping)
                or artifact.get("type") != "artifact.fixture.provider-upgrade-result.v1"
                or artifact.get("value") != expected_value
            ):
                raise ProviderGateError(
                    "provider run returned an invalid parameter-attested output"
                )
    else:
        error = typed_steps[0].get("error")
        if (
            typed_steps[0].get("status") != "failed"
            or not isinstance(error, Mapping)
            or error.get("code") != "provider_runtime_failed"
        ):
            raise ProviderGateError("provider limit failure was not enforced by the Rust runtime")
    validation = service.store.validate_bundle(run_id)
    stored = service.store.get_run(run_id)
    expected_binding = {
        "schema_version": "bluefire.product-acceptance-run-binding.v1",
        "acceptance_id": os.environ.get("BLUEFIRE_ACCEPTANCE_ID"),
        "gate_id": os.environ.get("BLUEFIRE_ACCEPTANCE_GATE_ID"),
        "contract_sha256": os.environ.get("BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256"),
        "repository_commit": os.environ.get("BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT"),
        "repository_tree": os.environ.get("BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE"),
        "release": os.environ.get("BLUEFIRE_ACCEPTANCE_RELEASE"),
    }
    stored_steps = stored.get("steps")
    stored_scenario = stored.get("scenario")
    if (
        validation.get("valid") is not True
        or stored.get("acceptance_binding") != expected_binding
        or stored.get("run_id") != run_id
        or stored.get("status") != result.get("status")
        or stored_steps != steps
        or not isinstance(stored_scenario, Mapping)
        or stored_scenario.get("steps") != scenario["steps"]
        or stored_scenario.get("edges") != scenario["edges"]
    ):
        raise ProviderGateError("provider run bundle is invalid or not acceptance-bound")
    _assert_public(stored)
    if _contains_literal(stored, forbidden_artifact_hex):
        raise ProviderGateError("provider run bundle exposed private provider bytes")
    stored_evidence = stored.get("evidence")
    raw_records = stored_evidence.get("records") if isinstance(stored_evidence, Mapping) else None
    if not isinstance(raw_records, list) or not raw_records:
        raise ProviderGateError("provider run bundle has no immutable evidence")
    records = [
        EvidenceRecord.from_mapping(item) for item in raw_records if isinstance(item, Mapping)
    ]
    if len(records) != len(raw_records):
        raise ProviderGateError("provider run bundle evidence is malformed")

    observations: list[dict[str, Any]] = []
    for step, parameters, expected_value, output_bytes in zip(
        typed_steps,
        parameter_sets,
        expected_values,
        expected_output_sizes,
        strict=True,
    ):
        evidence_ids = step.get("evidence_ids")
        matching_records = [
            record
            for record in records
            if isinstance(evidence_ids, list)
            and record.evidence_id in evidence_ids
            and record.run_id == run_id
            and record.behavior_id == BEHAVIOR_ID
            and record.action_id == ACTION_ID
            and record.producer == "bluefire-rust-runner"
        ]
        if len(matching_records) != 1:
            raise ProviderGateError(
                "provider run bundle does not bind one Rust evidence record per invocation"
            )
        runner_evidence = matching_records[0].content.get("runner_evidence")
        provider_metrics: Mapping[str, Any] | None = None
        if expected_status == "completed":
            if (
                not isinstance(runner_evidence, list)
                or len(runner_evidence) != 1
                or not isinstance(runner_evidence[0], Mapping)
            ):
                raise ProviderGateError("provider run bundle has no Rust provider evidence")
            details = runner_evidence[0].get("details")
            metrics = details.get("provider_execution") if isinstance(details, Mapping) else None
            if (
                not isinstance(metrics, Mapping)
                or metrics.get("artifact_sha256") != expected_artifact_sha256
                or isinstance(metrics.get("fuel_consumed"), bool)
                or not isinstance(metrics.get("fuel_consumed"), int)
                or not 0 < int(metrics["fuel_consumed"]) <= 100_000
                or metrics.get("memory_bytes") != 65_536
                or metrics.get("output_bytes") != output_bytes
                or metrics.get("no_host_imports") is not True
            ):
                raise ProviderGateError("provider Rust execution metrics are invalid")
            provider_metrics = metrics
        elif matching_records[0].content.get("error") != step.get("error"):
            raise ProviderGateError("provider limit failure evidence changed in the run bundle")
        observations.append(
            {
                "parameters": dict(parameters),
                "typed_output_value": expected_value,
                "provider_execution": (
                    dict(provider_metrics) if provider_metrics is not None else None
                ),
            }
        )

    receipts: list[str] = []
    for item in typed_steps:
        raw_receipts = item.get("receipts", [])
        if not isinstance(raw_receipts, list):
            raise ProviderGateError("provider run receipts are invalid")
        receipts.extend(str(receipt) for receipt in raw_receipts)
    primary = typed_steps[0]
    summary = {
        "run_id": run_id,
        "status": str(result["status"]),
        "step_status": str(primary["status"]),
        "action_id": str(primary["action_id"]),
        "behavior_id": str(primary["behavior_id"]),
        "typed_output_value": expected_values[0],
        "error_code": (
            str(primary["error"]["code"]) if isinstance(primary.get("error"), Mapping) else None
        ),
        "receipt_count": len(receipts),
        "bundle_valid": True,
        "acceptance_bound": True,
        "stored_semantics_bound": True,
        "private_provider_bytes_exposed": False,
        "provider_execution": observations[0]["provider_execution"],
        "parameter_observations": observations,
        "serialized_parameters": dict(parameter_sets[0]),
    }
    return summary, {"run_id": run_id, "path": f"runs/{run_id}"}


def _inventory_snapshot(
    service: BlueFireService,
    profile: RunnerProfile,
    *,
    phase: str,
    expected_provider_actions: int,
) -> dict[str, Any]:
    effective = service._profile(profile.id, ExecutionMode.EXECUTE)
    if effective is None:
        raise ProviderGateError("effective provider profile is unavailable")
    _runner, _sandbox, readiness = service._execute_readiness_boundary(effective)
    enabled = readiness.get("enabled_actions")
    if not isinstance(enabled, list):
        raise ProviderGateError("provider readiness inventory is invalid")
    rows = [
        item for item in enabled if isinstance(item, Mapping) and item.get("action_id") == ACTION_ID
    ]
    authority = readiness.get("catalog_authority")
    if len(rows) != expected_provider_actions or not isinstance(authority, Mapping):
        raise ProviderGateError("provider readiness inventory transition is invalid")
    snapshot: dict[str, Any] = {
        "phase": phase,
        "provider_action_count": len(rows),
        "catalog_generation": authority.get("generation"),
        "catalog_digest": authority.get("catalog_digest"),
        "native_inventory_digest": readiness.get("inventory_digest"),
        "effective_inventory_digest": readiness.get("effective_inventory_digest"),
    }
    if rows:
        row = rows[0]
        bindings = row.get("provider_bindings")
        if (
            not isinstance(bindings, list)
            or len(bindings) != 1
            or not isinstance(bindings[0], Mapping)
        ):
            raise ProviderGateError("provider readiness binding is invalid")
        binding = bindings[0]
        snapshot.update(
            {
                "package_digest": row.get("package_digest"),
                "content_digest": row.get("content_digest"),
                "artifact_sha256": binding.get("artifact_sha256"),
                "runtime_contract_digest": row.get("provider_runtime_contract_digest"),
                "execution_model": row.get("execution_model"),
                "native_action_id_exposed": "native_action_id" in row,
            }
        )
    return snapshot


def _install(
    service: BlueFireService, envelope: Mapping[str, Any], version: str
) -> Mapping[str, Any]:
    response = service.install_action_package(
        {"envelope": dict(envelope), "installed_by": "provider-gate-installer"}
    )
    _assert_public(response)
    if response.get("catalog_changed") is not False:
        raise ProviderGateError("provider install changed the executable catalog before activation")
    return response


def _activate(
    service: BlueFireService,
    profile: RunnerProfile,
    version: str,
) -> Mapping[str, Any]:
    response = service.activate_action_package(
        PACKAGE_ID,
        version,
        {
            "runner_profile_id": profile.id,
            "activated_by": "provider-gate-operator",
            "reason": f"exercise independently signed provider {version}",
        },
    )
    _assert_public(response)
    expected = "activation" if version == "1.0.0" else "upgrade"
    if response.get("operation") != expected:
        raise ProviderGateError(
            "provider activation did not report the expected lifecycle operation"
        )
    return response


def _remove_version(
    service: BlueFireService,
    version: str,
    package_digest: str,
    catalog: Mapping[str, Any],
) -> Mapping[str, Any]:
    response = service.remove_action_package(
        PACKAGE_ID,
        version,
        {
            "package_digest": package_digest,
            "expected_catalog_generation": catalog["generation"],
            "expected_catalog_digest": catalog["catalog_digest"],
            "removed_by": "provider-gate-operator",
            "reason": f"complete provider teardown for {version}",
        },
    )
    _assert_public(response)
    if response.get("package", {}).get("status") != "removed":
        raise ProviderGateError("provider removal did not reach the removed state")
    return response


def _runner_context(
    repository: Path, evidence_dir: Path
) -> tuple[SubprocessRustRunner, dict[str, Any]]:
    native_root = repository / "bluefire" / "native"
    platform_name = current_platform()
    architecture = current_architecture()
    manifest = load_runner_manifest(
        resource_root=native_root,
        product_version=__version__,
        platform_name=platform_name,
        architecture=architecture,
    )
    binary = (native_root / manifest.filename).resolve(strict=True)
    if (
        binary.stat().st_size != manifest.size
        or _sha256_file(binary) != "sha256:" + manifest.sha256
    ):
        raise ProviderGateError("packaged runner bytes do not match their release manifest")
    runner = SubprocessRustRunner(
        binary,
        evidence_dir / "runner-transport",
        timeout_seconds=30.0,
        output_limit_bytes=4 * 1024 * 1024,
    )
    inventory = dict(runner.inventory())
    validate_runner_inventory(inventory, manifest)
    runtimes = inventory.get("provider_runtimes")
    if not isinstance(runtimes, list) or len(runtimes) != 1:
        raise ProviderGateError("packaged runner does not advertise one provider runtime")
    runtime = runtimes[0]
    if (
        not isinstance(runtime, Mapping)
        or runtime.get("kind") != "wasm"
        or runtime.get("abi_version") != "bluefire.provider-abi.v1"
        or runtime.get("readiness") != "ready"
        or runtime.get("no_host_imports") is not True
        or runtime.get("contract_digest")
        != content_hash({key: value for key, value in runtime.items() if key != "contract_digest"})
    ):
        raise ProviderGateError("packaged provider runtime contract is invalid")
    if ACTION_ID in {
        item.get("action_id") for item in inventory.get("actions", []) if isinstance(item, Mapping)
    }:
        raise ProviderGateError("provider action unexpectedly exists in the core runner inventory")
    return runner, {
        "package_manifest_sha256": _sha256_file(native_root / "runner-manifest.json"),
        "binary_sha256": "sha256:" + manifest.sha256,
        "binary_size": manifest.size,
        "runner_id": manifest.runner_id,
        "runner_version": manifest.runner_version,
        "platform": manifest.platform,
        "architecture": manifest.architecture,
        "inventory_digest": runner_inventory_digest(inventory),
        "inventory_contract": {
            "schema_version": inventory.get("schema_version"),
            "runner": inventory.get("runner"),
            "runner_id": inventory.get("runner_id"),
            "runner_version": inventory.get("runner_version"),
            "action_sdk_version": inventory.get("action_sdk_version"),
            "receipt_protocol": inventory.get("receipt_protocol"),
            "platform": inventory.get("platform"),
            "provider_runtime_count": len(runtimes),
            "core_action_count": len(inventory.get("actions", [])),
        },
        "provider_runtime": dict(runtime),
        "logical_action_absent_from_core_inventory": True,
    }


def _journey_report(
    repository: Path,
    evidence_dir: Path,
    index: Mapping[str, Any],
    trusts: Mapping[str, Mapping[str, Any]],
    *,
    runner_context: Callable[
        [Path, Path], tuple[SubprocessRustRunner, dict[str, Any]]
    ] = _runner_context,
    service_factory: Callable[..., BlueFireService] = BlueFireService,
) -> dict[str, Any]:
    root = repository / "tests_platform" / "fixtures" / "provider_upgrade"
    rows = {str(row["version"]): row for row in index["packages"]}
    envelopes = {
        version: _load_document(_contained_file(root, rows[version]["file"]))
        for version in ALL_VERSIONS
    }
    artifact_hex_values = tuple(
        sorted({str(envelope["payload"]["artifact_hex"]) for envelope in envelopes.values()})
    )
    runner, runner_report = runner_context(repository, evidence_dir)
    sandbox = evidence_dir / "sandbox"
    sandbox.mkdir()
    product_db_path = evidence_dir / "provider-product.sqlite3"
    service: BlueFireService | None = None
    lifecycle: list[dict[str, Any]] = []
    executions: list[dict[str, Any]] = []
    bundles: list[dict[str, str]] = []
    readiness: list[dict[str, Any]] = []
    transition_snapshots: list[dict[str, Any]] = []
    refusal_cases: list[dict[str, str]] = []
    public_responses: list[Any] = []
    try:
        service = service_factory(
            project_root=repository,
            runs_dir=evidence_dir / "runs",
            product_db_path=product_db_path,
            runner_factory=lambda _profile: (runner, sandbox),
        )
        refusal_cases.append(
            _expect_install_refusal(service, envelopes["1.0.0"], "unknown-publisher-key")
        )
        for name in index["publisher_trust_files"]:
            trust = trusts[str(name)]
            response = service.trust_action_package_publisher(dict(trust))
            _assert_public(response)
            public_responses.append(response)
            lifecycle.append(
                {
                    "operation": "trust",
                    "publisher_id": trust["publisher_id"],
                    "key_id": trust["key_id"],
                }
            )
        refusal_cases.append(
            _expect_install_refusal(
                service,
                _tampered_envelope(envelopes["1.0.0"], "signature", ""),
                "altered-signature",
            )
        )
        refusal_cases.append(
            _expect_install_refusal(
                service,
                _tampered_envelope(
                    envelopes["1.0.0"],
                    "artifact",
                    str(envelopes["2.0.0"]["payload"]["artifact_hex"]),
                ),
                "substituted-artifact",
            )
        )
        profile = _execute_profile(service)
        transition_snapshots.append(
            _inventory_snapshot(
                service,
                profile,
                phase="before-provider-activation",
                expected_provider_actions=0,
            )
        )
        for version in SUCCESS_VERSIONS:
            installed = _install(service, envelopes[version], version)
            lifecycle.append({"operation": "install", "version": version})
            activated = _activate(service, profile, version)
            lifecycle.append({"operation": str(activated["operation"]), "version": version})
            readiness.append(
                {
                    "version": version,
                    **_inventory_snapshot(
                        service,
                        profile,
                        phase=f"active-{version}",
                        expected_provider_actions=1,
                    ),
                }
            )
            execution, bundle = _run_provider(
                service,
                profile,
                expected_status="completed",
                expected_version=version,
                expected_artifact_sha256=str(rows[version]["artifact_sha256"]),
                expected_output_bytes=177,
                forbidden_artifact_hex=artifact_hex_values,
            )
            executions.append({"version": version, **execution})
            bundles.append(bundle)
            public_responses.extend((installed, activated))

        installed_limit = _install(service, envelopes[LIMIT_VERSION], LIMIT_VERSION)
        lifecycle.append({"operation": "install", "version": LIMIT_VERSION})
        activated_limit = _activate(service, profile, LIMIT_VERSION)
        lifecycle.append({"operation": "upgrade", "version": LIMIT_VERSION})
        readiness.append(
            {
                "version": LIMIT_VERSION,
                **_inventory_snapshot(
                    service,
                    profile,
                    phase=f"active-{LIMIT_VERSION}",
                    expected_provider_actions=1,
                ),
            }
        )
        limit_execution, limit_bundle = _run_provider(
            service,
            profile,
            expected_status="incomplete",
            expected_version="2.0.0",
            expected_artifact_sha256=str(rows[LIMIT_VERSION]["artifact_sha256"]),
            expected_output_bytes=int(rows[LIMIT_VERSION]["canonical_output_bytes"]),
            forbidden_artifact_hex=artifact_hex_values,
        )
        executions.append({"version": LIMIT_VERSION, **limit_execution})
        bundles.append(limit_bundle)
        public_responses.extend((installed_limit, activated_limit))

        active_catalog = activated_limit["catalog"]
        deactivated = service.deactivate_action_package(
            PACKAGE_ID,
            LIMIT_VERSION,
            {
                "package_digest": rows[LIMIT_VERSION]["package_digest"],
                "expected_catalog_generation": active_catalog["generation"],
                "expected_catalog_digest": active_catalog["catalog_digest"],
                "deactivated_by": "provider-gate-operator",
                "reason": "complete isolated provider lifecycle acceptance",
            },
        )
        _assert_public(deactivated)
        lifecycle.append({"operation": "deactivate", "version": LIMIT_VERSION})
        catalog = deactivated["catalog"]
        public_responses.append(deactivated)
        transition_snapshots.append(
            _inventory_snapshot(
                service,
                profile,
                phase="after-provider-deactivation",
                expected_provider_actions=0,
            )
        )
        for version in reversed(ALL_VERSIONS):
            removed = _remove_version(
                service,
                version,
                str(rows[version]["package_digest"]),
                catalog,
            )
            catalog = removed["catalog"]
            lifecycle.append({"operation": "remove", "version": version})
            public_responses.append(removed)
        transition_snapshots.append(
            _inventory_snapshot(
                service,
                profile,
                phase="after-provider-removal",
                expected_provider_actions=0,
            )
        )

        inventory = service.action_packages()
        detail = service.action_package(PACKAGE_ID)
        catalog_response = service.catalog()
        public_responses.extend((inventory, detail, catalog_response))
        for response in public_responses:
            _assert_public(response)
            if _contains_literal(response, artifact_hex_values):
                raise ProviderGateError(
                    "provider management response exposed private provider bytes"
                )
        remaining_files = sorted(
            path.relative_to(sandbox).as_posix() for path in sandbox.rglob("*") if path.is_file()
        )
        statuses = {
            version: service.action_package(PACKAGE_ID, version=version)["package"]["status"]
            for version in ALL_VERSIONS
        }
        teardown = {
            "catalog_packages": len(service._catalog_snapshot.packages),
            "private_provider_artifacts": len(service._catalog_snapshot.provider_artifacts),
            "logical_action_registered": ACTION_ID in service.registry.action_ids,
            "version_statuses": statuses,
        }
        expected_lifecycle = [
            ("trust", None),
            ("trust", None),
            ("install", "1.0.0"),
            ("activation", "1.0.0"),
            ("install", "2.0.0"),
            ("upgrade", "2.0.0"),
            ("install", "3.0.0"),
            ("upgrade", "3.0.0"),
            ("deactivate", "3.0.0"),
            ("remove", "3.0.0"),
            ("remove", "2.0.0"),
            ("remove", "1.0.0"),
        ]
        actual_lifecycle = [
            (str(item["operation"]), str(item["version"]) if "version" in item else None)
            for item in lifecycle
        ]
        success_runs = [item for item in executions if item["status"] == "completed"]
        limit_runs = [item for item in executions if item["version"] == LIMIT_VERSION]
        inventory_timeline = [
            transition_snapshots[0],
            *readiness,
            transition_snapshots[1],
            transition_snapshots[2],
        ]
        inventory_generations = [item["catalog_generation"] for item in inventory_timeline]
        inventory_digests = [item["catalog_digest"] for item in inventory_timeline]
        native_inventory_digests = {item["native_inventory_digest"] for item in inventory_timeline}
        effective_inventory_digests = [
            item["effective_inventory_digest"] for item in inventory_timeline
        ]
        checks = {
            "new_provider_artifact": {
                "passed": len(success_runs) == 2
                and all(item["step_status"] == "success" for item in success_runs)
                and all(
                    len(item["parameter_observations"]) == 2
                    and item["parameter_observations"][0]["typed_output_value"]
                    != item["parameter_observations"][1]["typed_output_value"]
                    for item in success_runs
                ),
                "successful_versions": [item["version"] for item in success_runs],
                "real_rust_run_ids": [item["run_id"] for item in success_runs],
                "guest_parameter_attestation": True,
            },
            "lifecycle": {
                "passed": actual_lifecycle == expected_lifecycle,
                "operations": lifecycle,
            },
            "inventory_compatibility": {
                "passed": len(readiness) == 3
                and [item["phase"] for item in transition_snapshots]
                == [
                    "before-provider-activation",
                    "after-provider-deactivation",
                    "after-provider-removal",
                ]
                and all(item["provider_action_count"] == 0 for item in transition_snapshots)
                and all(
                    item["execution_model"] == "wasm_provider_v1"
                    and item["native_action_id_exposed"] is False
                    and item["provider_action_count"] == 1
                    for item in readiness
                )
                and readiness[0]["artifact_sha256"] != readiness[1]["artifact_sha256"]
                and readiness[1]["artifact_sha256"] == readiness[2]["artifact_sha256"]
                and readiness[1]["runtime_contract_digest"]
                == readiness[0]["runtime_contract_digest"]
                == readiness[2]["runtime_contract_digest"]
                and all(
                    isinstance(item, int) and not isinstance(item, bool)
                    for item in inventory_generations
                )
                and inventory_generations[:5]
                == list(range(inventory_generations[0], inventory_generations[0] + 5))
                and inventory_generations[5] == inventory_generations[4]
                and len(set(inventory_digests[:4])) == 4
                and inventory_digests[4] == inventory_digests[0]
                and inventory_digests[5] == inventory_digests[4]
                and len(native_inventory_digests) == 1
                and len(set(effective_inventory_digests[:5])) == 5
                and effective_inventory_digests[5] == effective_inventory_digests[4],
                "activation_snapshots": readiness,
                "transition_snapshots": transition_snapshots,
                "catalog_generations": inventory_generations,
                "catalog_digests": inventory_digests,
                "native_inventory_digest_stable": len(native_inventory_digests) == 1,
                "effective_inventory_digests": effective_inventory_digests,
            },
            "tamper_refusal": {
                "passed": len(refusal_cases) == 3
                and all(item["status"] == "refused" for item in refusal_cases),
                "cases": refusal_cases,
            },
            "limits_cleanup": {
                "passed": len(limit_runs) == 1
                and limit_runs[0]["error_code"] == "provider_runtime_failed"
                and rows[LIMIT_VERSION]["limit_condition"]
                == "canonical_output_exceeds_signed_max_output_bytes"
                and rows[LIMIT_VERSION]["expected_run_status"] == "incomplete"
                and rows[LIMIT_VERSION]["expected_step_error_code"] == "provider_runtime_failed"
                and rows[LIMIT_VERSION]["signed_max_output_bytes"] + 1
                == rows[LIMIT_VERSION]["canonical_output_bytes"]
                and not remaining_files
                and all(item["receipt_count"] == 0 for item in executions)
                and sum(len(item["parameter_observations"]) for item in executions) == 5
                and teardown
                == {
                    "catalog_packages": 0,
                    "private_provider_artifacts": 0,
                    "logical_action_registered": False,
                    "version_statuses": {version: "removed" for version in ALL_VERSIONS},
                },
                "signed_max_output_bytes": rows[LIMIT_VERSION]["signed_max_output_bytes"],
                "canonical_output_bytes": rows[LIMIT_VERSION]["canonical_output_bytes"],
                "sandbox_files_after_runs": remaining_files,
                "receipt_counts": {item["version"]: item["receipt_count"] for item in executions},
                "teardown": teardown,
                "fresh_guest_invocations": sum(
                    len(item["parameter_observations"]) for item in executions
                ),
            },
        }
        return {
            "schema_version": JOURNEY_SCHEMA,
            "passed": all(check["passed"] is True for check in checks.values()),
            "packaged_runner": runner_report,
            "executions": executions,
            "run_bundles": bundles,
            "checks": checks,
        }
    finally:
        close_failure: BaseException | None = None
        try:
            if service is not None:
                service.close()
        except BaseException as exc:
            close_failure = exc
        cleanup_failure: OSError | None = None
        for private_path in (
            product_db_path,
            product_db_path.with_name(product_db_path.name + "-wal"),
            product_db_path.with_name(product_db_path.name + "-shm"),
        ):
            try:
                private_path.unlink(missing_ok=True)
            except OSError as exc:
                cleanup_failure = cleanup_failure or exc
        if cleanup_failure is not None:
            raise ProviderGateError(
                "provider private product store cleanup failed"
            ) from cleanup_failure
        if close_failure is not None:
            raise close_failure
