"""Focused fail-closed tests for the executable GATE-02 workflow."""

from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping, Sequence

import pytest

import bluefire.product_gates as product_gates
import bluefire.provider_gate as provider_gate
import tools.run_provider_gate_journey as provider_gate_helper
from bluefire.product_acceptance import load_release_contract
from bluefire.runner_inventory import BUILTIN_RUNNER_ACTION_IDS
from tools import provider_gate_source_audit
from tools.provider_gate_fixture_evidence import (
    _fixture_set,
)
from tools.provider_gate_fixture_evidence import (
    _structural_report as _live_structural_report,
)

REPOSITORY = Path(__file__).resolve().parents[1]
RAW_PROOF_FIELDS = {
    "kind",
    "status",
    "test_id",
    "assertion_ids",
    "evidence_artifacts",
    "run_ids",
    "run_bundles",
    "environment_limitations",
}


def _gate() -> Any:
    contract = load_release_contract()
    return next(item for item in contract.gates if item.gate_id == "GATE-02")


def _passing_suite(suite_id: str, tests: Sequence[str]) -> dict[str, Any]:
    if suite_id == "provider-contracts":
        passed_tests = set(provider_gate._REQUIRED_PROVIDER_CONTRACT_TESTS)
        filler = 0
        while len(passed_tests) < provider_gate._MINIMUM_PROVIDER_CONTRACT_TESTS:
            passed_tests.add(f"tests_platform.test_provider_gate::test_locked_filler_{filler:03d}")
            filler += 1
    else:
        passed_tests = {provider_gate._pytest_identifier(selector) for selector in tests}
    sorted_tests = sorted(passed_tests)
    return {
        "schema_version": "bluefire.architecture-dynamic-check.v1",
        "suite_id": suite_id,
        "command": provider_gate._expected_pytest_command(tests),
        "exit_code": 0,
        "passed": True,
        "tests": len(sorted_tests),
        "passed_tests": sorted_tests,
        "failed_tests": [],
        "skipped_tests": [],
    }


def _structural_report() -> dict[str, Any]:
    versions = ("1.0.0", "2.0.0", "3.0.0")
    artifact_digests = {
        "1.0.0": "sha256:" + "1" * 64,
        "2.0.0": "sha256:" + "2" * 64,
        "3.0.0": "sha256:" + "2" * 64,
    }
    contract_digest = "sha256:" + "3" * 64
    compatibility = {
        "minimum_bluefire_version": "3.0.0",
        "maximum_bluefire_version_exclusive": "4.0.0",
    }
    required_sources = (
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
        "bluefire/runner_darwin_containment.py",
        "bluefire/runner_lifecycle.py",
        "bluefire/runner_parent_death.py",
        "bluefire/runner_trust.py",
        "bluefire/runner_watchdog.py",
        "runner/src/cancellation_witness.rs",
        "runner/src/process.rs",
    )
    return {
        "schema_version": provider_gate.STRUCTURAL_SCHEMA,
        "passed": True,
        "fixture_schema_version": "bluefire.provider-upgrade-fixture-set.v1",
        "checks": {
            "core_independence": {
                "passed": True,
                "logical_action_id": "fixture.provider-upgrade.action.v1",
                "absent_from_builtin_inventory": True,
                "provider_program_only": True,
            },
            "manifest_integrity": {
                "passed": True,
                "verified_versions": list(versions),
                "package_digests": {
                    version: "sha256:" + str(index + 4) * 64
                    for index, version in enumerate(versions)
                },
                "content_digests": {
                    version: "sha256:" + str(index + 7) * 64
                    for index, version in enumerate(versions)
                },
                "artifact_digests": artifact_digests,
                "distinct_signatures": 3,
                "distinct_package_digests": 3,
                "distinct_content_digests": 3,
                "distinct_artifacts": 2,
                "compatibility": compatibility,
            },
            "safe_contract": {
                "passed": True,
                "provider_id": "fixture.provider-upgrade.runtime.v1",
                "abi_version": "bluefire.provider-abi.v1",
                "capabilities": ["native.execution"],
                "safety_tiers": ["safe"],
                "platforms": ["windows"],
                "license": "MIT",
                "no_host_imports": True,
                "stable_action_contract_digest": contract_digest,
                "wasm_section_ids": {version: [1, 3, 5, 7, 10, 11] for version in versions},
                "versions": [
                    {
                        "passed": True,
                        "version": version,
                        "action_contract_digest": contract_digest,
                        "program_schema": "bluefire.wasm-provider-program.v1",
                        "capabilities": ["native.execution"],
                        "safety_tier": "safe",
                        "platforms": ["windows"],
                        "mutates": False,
                        "cleanup_action_id": None,
                        "license": {
                            "spdx_id": "MIT",
                            "notice": "Copyright 2026 BlueFire fixture authors; MIT licensed.",
                        },
                        "definition_provenance": {
                            "source": (
                                "BlueFire committed deterministic no-import WebAssembly "
                                "provider fixture"
                            ),
                            "reference": (
                                "urn:bluefire:fixture:provider-upgrade:" + artifact_digests[version]
                            ),
                            "license": "MIT",
                            "derived": False,
                            "notes": (
                                "Guest output attests the exact canonical message and "
                                "repeat_count input."
                            ),
                        },
                        "package_provenance": {
                            "publisher_id": "bluefire.fixture.provider-upgrade",
                            "source": (
                                "Deterministically assembled no-import WebAssembly fixture "
                                "committed with BlueFire Nexus"
                            ),
                            "revision": artifact_digests[version],
                            "reference": (
                                "urn:bluefire:fixture:provider-upgrade:"
                                + ("3.0.0-output-limit" if version == "3.0.0" else version)
                                + ":"
                                + artifact_digests[version]
                            ),
                        },
                        "compatibility": compatibility,
                        "provider_limits": {
                            "fuel": 100_000,
                            "max_module_bytes": 65_536,
                            "max_memory_bytes": 524_288,
                            "max_input_bytes": 8_192,
                            "max_output_bytes": 176 if version == "3.0.0" else 8_192,
                        },
                        "typed_parameters": [
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
                        ],
                        "typed_outputs": [
                            {
                                "name": "result",
                                "type": "artifact.fixture.provider-upgrade-result.v1",
                                "required": True,
                                "multiple": False,
                            }
                        ],
                    }
                    for version in versions
                ],
            },
            "no_model_shell": {
                "passed": True,
                "execution_boundary": "typed-signed-provider-contract-to-no-import-wasm-only",
                "forbidden_fixture_fields": [],
                "findings": [],
                "source_files": [
                    {"path": path, "sha256": "sha256:" + "a" * 64} for path in required_sources
                ],
                "process_boundary": {
                    "passed": True,
                    "boundary": "typed-model-output-to-reviewed-actions-to-fixed-absolute-digest-bound-runner-with-shell-disabled",
                    "checks": {
                        "python_process_call_inventory": True,
                        "popen_shell_disabled": True,
                        "absolute_digest_bound_runner": True,
                        "bootstrap_fixed_system_tools": True,
                        "trust_fixed_system_tools": True,
                        "lifecycle_uses_fixed_installed_host": True,
                        "watchdog_has_no_process_launcher": True,
                        "native_process_inventory_is_fixed": True,
                    },
                    "python_boundaries": {
                        "runner_client.py": {
                            "passed": True,
                            "unexpected_findings": [],
                            "shell_imports": 1,
                            "process_calls": ["subprocess.Popen", "subprocess.Popen"],
                        },
                        "runner_bootstrap.py": {
                            "passed": True,
                            "unexpected_findings": [],
                            "shell_imports": 0,
                            "process_calls": [],
                        },
                        "runner_darwin_containment.py": {
                            "passed": True,
                            "unexpected_findings": [],
                            "shell_imports": 1,
                            "process_calls": [],
                        },
                        "runner_lifecycle.py": {
                            "passed": True,
                            "unexpected_findings": [],
                            "shell_imports": 1,
                            "process_calls": ["subprocess.Popen"],
                        },
                        "runner_parent_death.py": {
                            "passed": True,
                            "unexpected_findings": [],
                            "shell_imports": 0,
                            "process_calls": [
                                "os.execve",
                                "os.execve",
                                "os.execve",
                                "os.fork",
                            ],
                        },
                        "runner_trust.py": {
                            "passed": True,
                            "unexpected_findings": [],
                            "shell_imports": 0,
                            "process_calls": [],
                        },
                    },
                },
            },
        },
    }


def test_live_source_audit_round_trips_locked_structural_validator() -> None:
    index, trusts, packages = _fixture_set(REPOSITORY)
    report = _live_structural_report(REPOSITORY, index, trusts, packages)

    checks = provider_gate._validate_structural(report)

    assert checks["no_model_shell"]["process_boundary"]["passed"] is True


def _execution(version: str, run_id: str) -> dict[str, Any]:
    success = version != "3.0.0"
    metrics = (
        {
            "artifact_sha256": "sha256:" + ("1" if version == "1.0.0" else "2") * 64,
            "fuel_consumed": 17,
            "memory_bytes": 65_536,
            "output_bytes": 177,
            "no_host_imports": True,
        }
        if success
        else None
    )
    return {
        "version": version,
        "run_id": run_id,
        "status": "completed" if success else "incomplete",
        "step_status": "success" if success else "failed",
        "action_id": "fixture.provider-upgrade.action.v1",
        "behavior_id": "fixture.provider-upgrade.behavior.v1",
        "typed_output_value": (f"{version}|message=verify|repeat_count=2" if success else None),
        "error_code": None if success else "provider_runtime_failed",
        "receipt_count": 0,
        "bundle_valid": True,
        "acceptance_bound": True,
        "stored_semantics_bound": True,
        "private_provider_bytes_exposed": False,
        "provider_execution": metrics,
        "parameter_observations": (
            [
                {
                    "parameters": parameters,
                    "typed_output_value": (
                        f"{version}|message={parameters['message']}|"
                        f"repeat_count={parameters['repeat_count']}"
                    ),
                    "provider_execution": {
                        **metrics,
                        "output_bytes": 177 - index,
                    },
                }
                for index, parameters in enumerate(
                    (
                        {"message": "verify", "repeat_count": 2},
                        {"message": "probe", "repeat_count": 1},
                    )
                )
            ]
            if metrics is not None
            else [
                {
                    "parameters": {"message": "verify", "repeat_count": 2},
                    "typed_output_value": None,
                    "provider_execution": None,
                }
            ]
        ),
        "serialized_parameters": {"message": "verify", "repeat_count": 2},
    }


def _journey_report() -> dict[str, Any]:
    run_ids = ["run-provider-v1", "run-provider-v2", "run-provider-limit"]
    inventory_digest = "sha256:" + "c" * 64
    runtime_contract = {
        "kind": "wasm",
        "abi_version": "bluefire.provider-abi.v1",
        "readiness": "ready",
        "runtime_version": "wasmi-1.1.0",
        "no_host_imports": True,
        "hard_limits": {
            "max_module_bytes": 2_097_152,
            "max_memory_bytes": 16_777_216,
            "max_input_bytes": 1_048_576,
            "max_output_bytes": 1_048_576,
            "fuel": 100_000_000,
        },
    }
    runtime_digest = provider_gate.content_hash(runtime_contract)
    catalog_digests = ["sha256:" + digit * 64 for digit in ("3", "4", "5", "6", "3", "3")]
    effective_digests = ["sha256:" + digit * 64 for digit in ("7", "8", "9", "a", "b", "b")]
    package_digests = ["sha256:" + digit * 64 for digit in ("c", "d", "e")]
    content_digests = ["sha256:" + digit * 64 for digit in ("f", "0", "1")]
    artifact_digests = ["sha256:" + "1" * 64, "sha256:" + "2" * 64, "sha256:" + "2" * 64]
    activations = [
        {
            "phase": f"active-{version}",
            "version": version,
            "catalog_generation": index + 1,
            "catalog_digest": catalog_digests[index + 1],
            "native_inventory_digest": inventory_digest,
            "effective_inventory_digest": effective_digests[index + 1],
            "provider_action_count": 1,
            "package_digest": package_digests[index],
            "content_digest": content_digests[index],
            "artifact_sha256": artifact_digests[index],
            "runtime_contract_digest": runtime_digest,
            "execution_model": "wasm_provider_v1",
            "native_action_id_exposed": False,
        }
        for index, version in enumerate(("1.0.0", "2.0.0", "3.0.0"))
    ]
    transitions = [
        {
            "phase": phase,
            "catalog_generation": generation,
            "catalog_digest": catalog_digest,
            "native_inventory_digest": inventory_digest,
            "effective_inventory_digest": effective_digest,
            "provider_action_count": 0,
        }
        for phase, generation, catalog_digest, effective_digest in (
            (
                "before-provider-activation",
                0,
                catalog_digests[0],
                effective_digests[0],
            ),
            (
                "after-provider-deactivation",
                4,
                catalog_digests[4],
                effective_digests[4],
            ),
            (
                "after-provider-removal",
                4,
                catalog_digests[5],
                effective_digests[5],
            ),
        )
    ]
    return {
        "schema_version": provider_gate.JOURNEY_SCHEMA,
        "passed": True,
        "packaged_runner": {
            "package_manifest_sha256": "sha256:" + "a" * 64,
            "binary_sha256": "sha256:" + "b" * 64,
            "binary_size": 1,
            "runner_id": "bluefire-rust-runner.v1",
            "runner_version": "3.0.0",
            "platform": "windows",
            "architecture": "x86_64",
            "inventory_digest": inventory_digest,
            "inventory_contract": {
                "schema_version": "bluefire.runner-inventory.v1",
                "runner": "bluefire-rust-runner",
                "runner_id": "bluefire-rust-runner.v1",
                "runner_version": "3.0.0",
                "action_sdk_version": "bluefire.runner-action-sdk.v1",
                "receipt_protocol": "bluefire.runner-receipt-wal.v2",
                "platform": "windows",
                "provider_runtime_count": 1,
                "core_action_count": len(BUILTIN_RUNNER_ACTION_IDS),
            },
            "provider_runtime": {
                **runtime_contract,
                "contract_digest": runtime_digest,
            },
            "logical_action_absent_from_core_inventory": True,
        },
        "executions": [
            _execution(version, run_id)
            for version, run_id in zip(("1.0.0", "2.0.0", "3.0.0"), run_ids, strict=True)
        ],
        "run_bundles": [{"run_id": run_id, "path": f"runs/{run_id}"} for run_id in run_ids],
        "checks": {
            "new_provider_artifact": {
                "passed": True,
                "successful_versions": ["1.0.0", "2.0.0"],
                "real_rust_run_ids": run_ids[:2],
                "guest_parameter_attestation": True,
            },
            "lifecycle": {
                "passed": True,
                "operations": [
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
                ],
            },
            "inventory_compatibility": {
                "passed": True,
                "activation_snapshots": activations,
                "transition_snapshots": transitions,
                "catalog_generations": [0, 1, 2, 3, 4, 4],
                "catalog_digests": catalog_digests,
                "native_inventory_digest_stable": True,
                "effective_inventory_digests": effective_digests,
            },
            "tamper_refusal": {
                "passed": True,
                "cases": [
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
                ],
            },
            "limits_cleanup": {
                "passed": True,
                "canonical_output_bytes": 177,
                "signed_max_output_bytes": 176,
                "fresh_guest_invocations": 5,
                "receipt_counts": {version: 0 for version in ("1.0.0", "2.0.0", "3.0.0")},
                "sandbox_files_after_runs": [],
                "teardown": {
                    "catalog_packages": 0,
                    "logical_action_registered": False,
                    "private_provider_artifacts": 0,
                    "version_statuses": {
                        version: "removed" for version in ("1.0.0", "2.0.0", "3.0.0")
                    },
                },
                "private_product_store_removed": True,
            },
        },
    }


def _frontend_report(*, passed: bool = True) -> dict[str, Any]:
    names = sorted(provider_gate._EXPECTED_UI_TESTS)
    return {
        "schema_version": "bluefire.provider-frontend-check.v1",
        "suite_id": "provider-management-ui",
        "command": ["{node}", "{vitest}", "run", "tests/action-packages.test.tsx"],
        "exit_code": 0 if passed else 1,
        "passed": passed,
        "tests": len(names),
        "passed_tests": names if passed else names[:-1],
        "failed_tests": [] if passed else [names[-1]],
    }


def _install_passing_fakes(
    monkeypatch: pytest.MonkeyPatch,
    *,
    structural: Mapping[str, Any] | None = None,
    journey: Mapping[str, Any] | None = None,
    helper: Mapping[str, Any] | None = None,
) -> list[tuple[str, int]]:
    fake_provider_suite = _passing_suite(
        "provider-contracts", provider_gate._PROVIDER_CONTRACT_TESTS
    )
    monkeypatch.setattr(
        provider_gate,
        "_EXPECTED_PROVIDER_CONTRACT_TESTS",
        fake_provider_suite["tests"],
    )
    monkeypatch.setattr(
        provider_gate,
        "_EXPECTED_PROVIDER_CONTRACT_TESTS_SHA256",
        provider_gate.content_hash(fake_provider_suite["passed_tests"]),
    )
    structural_value = dict(structural or _structural_report())
    journey_value = dict(journey or _journey_report())
    helper_value = dict(
        helper
        or {
            "passed": True,
            "exit_code": 0,
            "command": [
                "{python}",
                "tools/run_provider_gate_journey.py",
                "{fixed-arguments}",
            ],
            "protocol_valid": True,
        }
    )
    suite_calls: list[tuple[str, int]] = []

    def fake_helper(_repository: Path, evidence_dir: Path) -> dict[str, Any]:
        (evidence_dir / "provider-structural-report.json").write_text(
            json.dumps(structural_value), encoding="utf-8"
        )
        (evidence_dir / "provider-journey-report.json").write_text(
            json.dumps(journey_value), encoding="utf-8"
        )
        return dict(helper_value)

    def fake_suite(
        _repository: Path,
        _evidence_dir: Path,
        *,
        suite_id: str,
        tests: Sequence[str],
        timeout_seconds: int,
    ) -> Mapping[str, Any]:
        suite_calls.append((suite_id, timeout_seconds))
        return _passing_suite(suite_id, tests)

    monkeypatch.setattr(provider_gate, "_run_helper", fake_helper)
    monkeypatch.setattr(provider_gate, "_run_pytest_suite", fake_suite)
    monkeypatch.setattr(provider_gate, "_run_vitest", lambda _repository: _frontend_report())
    return suite_calls


def test_gate_02_emits_exact_unique_proofs_and_bundle_attachments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    drifted_inventory = _journey_report()
    drifted_inventory["packaged_runner"]["inventory_contract"]["core_action_count"] -= 1
    with pytest.raises(ValueError, match="runner inventory contract is invalid"):
        provider_gate._validate_journey(drifted_inventory)

    evidence_dir = tmp_path / "gate-02"
    evidence_dir.mkdir()
    calls = _install_passing_fakes(monkeypatch)

    outcome = provider_gate.run_gate_02(_gate(), evidence_dir, repository_root=REPOSITORY)

    assert outcome.status == "passed"
    assert outcome.failure_reason is None
    assert calls == [
        ("provider-contracts", 300),
        ("provider-management-api", 90),
        ("provider-management-cli", 90),
    ]
    assert len(outcome.proofs) == 10
    assert len({proof["test_id"] for proof in outcome.proofs}) == 10
    assert all(set(proof) == RAW_PROOF_FIELDS for proof in outcome.proofs)
    proofs = {proof["assertion_ids"][0]: proof for proof in outcome.proofs}
    assert set(proofs) == set(provider_gate._EXPECTED_ASSERTIONS)
    for assertion_id, (
        kind,
        _check,
        artifacts,
        test_id,
    ) in provider_gate._EXPECTED_ASSERTIONS.items():
        proof = proofs[assertion_id]
        assert proof["kind"] == kind
        assert proof["status"] == "passed"
        assert proof["test_id"] == test_id
        assert proof["assertion_ids"] == [assertion_id]
        assert proof["evidence_artifacts"] == list(artifacts)
        assert proof["environment_limitations"] == []
    assert proofs["GATE-02-NEW-PROVIDER-ARTIFACT"]["run_ids"] == [
        "run-provider-v1",
        "run-provider-v2",
    ]
    assert proofs["GATE-02-LIMITS-CLEANUP"]["run_ids"] == ["run-provider-limit"]
    assert all(
        reference["path"] == f"runs/{reference['run_id']}"
        for proof in outcome.proofs
        for reference in proof["run_bundles"]
    )
    assert {path.name for path in evidence_dir.iterdir() if path.name.endswith("-report.json")} == {
        "provider-structural-report.json",
        "provider-journey-report.json",
        "provider-verification-report.json",
    }


def test_gate_02_refuses_locked_assertion_drift_before_running_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = _gate()
    drifted = replace(gate, assertions=gate.assertions[:-1])
    evidence_dir = tmp_path / "gate-02"
    evidence_dir.mkdir()
    monkeypatch.setattr(
        provider_gate,
        "_run_helper",
        lambda *_args, **_kwargs: pytest.fail("helper must not run after contract drift"),
    )

    outcome = provider_gate.run_gate_02(drifted, evidence_dir, repository_root=REPOSITORY)

    assert outcome.status == "failed"
    assert outcome.proofs == ()
    assert outcome.failure_reason == "locked GATE-02 assertion set mismatch"


@pytest.mark.parametrize(
    "drift",
    [
        "extra-structural-field",
        "execution-bundle-mismatch",
        "packaged-runtime-drift",
        "lifecycle-evidence-drift",
        "tamper-evidence-drift",
        "cleanup-evidence-drift",
        "inventory-timeline-drift",
        "execution-fields-drift",
    ],
)
def test_gate_02_fails_closed_on_report_or_bundle_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, drift: str
) -> None:
    structural = _structural_report()
    journey = _journey_report()
    if drift == "extra-structural-field":
        structural["unexpected"] = True
    elif drift == "execution-bundle-mismatch":
        journey["executions"][1]["run_id"] = "run-floating-claim"
    elif drift == "packaged-runtime-drift":
        journey["packaged_runner"]["provider_runtime"]["no_host_imports"] = False
    elif drift == "lifecycle-evidence-drift":
        journey["checks"]["lifecycle"]["operations"].pop()
    elif drift == "tamper-evidence-drift":
        journey["checks"]["tamper_refusal"]["cases"][0]["status"] = "accepted"
    elif drift == "cleanup-evidence-drift":
        journey["checks"]["limits_cleanup"]["private_product_store_removed"] = False
    elif drift == "inventory-timeline-drift":
        journey["checks"]["inventory_compatibility"]["catalog_digests"][4] = "sha256:" + "9" * 64
    elif drift == "execution-fields-drift":
        journey["executions"][0]["unexpected"] = True
    else:
        raise AssertionError(f"unhandled test drift: {drift}")
    evidence_dir = tmp_path / drift
    evidence_dir.mkdir()
    _install_passing_fakes(
        monkeypatch,
        structural=structural,
        journey=journey,
    )

    outcome = provider_gate.run_gate_02(_gate(), evidence_dir, repository_root=REPOSITORY)

    assert outcome.status == "failed"
    assert outcome.proofs == ()
    assert outcome.failure_reason is not None
    assert "GATE-02 failed checks:" in outcome.failure_reason


def test_gate_02_fails_closed_on_exact_structural_contract_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for drift in (
        "core-independence",
        "typed-parameter-schema",
        "safe-version-fields",
        "source-audit-inventory",
        "process-call-inventory",
    ):
        structural = _structural_report()
        if drift == "core-independence":
            structural["checks"]["core_independence"]["provider_program_only"] = False
        elif drift == "typed-parameter-schema":
            structural["checks"]["safe_contract"]["versions"][0]["typed_parameters"][0][
                "name"
            ] = "command"
        elif drift == "safe-version-fields":
            structural["checks"]["safe_contract"]["versions"][0]["unexpected"] = True
        elif drift == "source-audit-inventory":
            sources = structural["checks"]["no_model_shell"]["source_files"]
            structural["checks"]["no_model_shell"]["source_files"] = [
                item for item in sources if item["path"] != "bluefire/service.py"
            ]
        else:
            boundaries = structural["checks"]["no_model_shell"]["process_boundary"]
            boundaries["python_boundaries"]["runner_client.py"]["process_calls"] = [
                "subprocess.run"
            ]
        evidence_dir = tmp_path / drift
        evidence_dir.mkdir()
        _install_passing_fakes(monkeypatch, structural=structural)

        outcome = provider_gate.run_gate_02(_gate(), evidence_dir, repository_root=REPOSITORY)

        assert outcome.status == "failed", drift
        assert outcome.proofs == (), drift
        assert outcome.failure_reason is not None
        assert "GATE-02 failed checks:" in outcome.failure_reason, drift

    mutation_root = tmp_path / "no-model-shell-mutations"
    mutation_root.mkdir()
    shell_mutations = {
        "importlib.py": (
            "import importlib\nimportlib.import_module('subprocess').run(['fixed-program'])\n",
            {"dynamic_shell_import"},
        ),
        "dunder-import.py": (
            "__import__('os').system('fixed-program')\n",
            {"dynamic_shell_import"},
        ),
        "dynamic-getattr.py": (
            "import subprocess\n"
            "operation = 'run'\n"
            "getattr(subprocess, operation)(['fixed-program'])\n",
            {"dynamic_execution_lookup"},
        ),
        "call-alias.py": (
            "import subprocess\nlaunch = subprocess.run\nlaunch(['fixed-program'])\n",
            {"dynamic_execution_alias", "dynamic_execution_call"},
        ),
        "dynamic-builtins.py": (
            "operation = '__import__'\nglobals()[operation]('os').system('fixed-program')\n",
            {"dynamic_namespace_access"},
        ),
    }
    for filename, (source, expected_kinds) in shell_mutations.items():
        path = mutation_root / filename
        path.write_text(source, encoding="utf-8")
        findings = provider_gate_helper._python_shell_findings(path, mutation_root)
        assert expected_kinds.issubset({item["kind"] for item in findings}), filename

    boundary_sources = {
        relative: (REPOSITORY / relative).read_text(encoding="utf-8")
        for relative in provider_gate_source_audit._REVIEWED_PYTHON_PROCESS_BOUNDARY_SOURCES
    }
    assert provider_gate_source_audit._reviewed_python_process_boundary_sources(boundary_sources)
    hidden_watchdog_launcher = dict(boundary_sources)
    hidden_watchdog_launcher[
        "bluefire/runner_watchdog.py"
    ] += "\nos.__dict__[chr(115)+chr(121)+chr(115)+chr(116)+chr(101)+chr(109)](chr(105)+chr(100))\n"
    assert not provider_gate_source_audit._reviewed_python_process_boundary_sources(
        hidden_watchdog_launcher
    )
    hidden_lifecycle_launcher = dict(boundary_sources)
    hidden_lifecycle_launcher["bluefire/runner_lifecycle.py"] = hidden_lifecycle_launcher[
        "bluefire/runner_lifecycle.py"
    ].replace(
        "    process = subprocess.Popen(command, shell=False, **options)  # nosec B603\n",
        "    process = subprocess.Popen(command, shell=False, **options)  # nosec B603\n"
        "    process = subprocess.__dict__["
        "chr(80)+chr(111)+chr(112)+chr(101)+chr(110)](command, shell=False)\n",
        1,
    )
    assert hidden_lifecycle_launcher != boundary_sources
    assert not provider_gate_source_audit._reviewed_python_process_boundary_sources(
        hidden_lifecycle_launcher
    )
    for unreviewed_alias in (
        "bluefire/runner_private_files.py",
        "bluefire/runner_private_files.PY",
        "bluefire/runner_private_files.py.",
        "bluefire\\runner_private_files.py",
    ):
        with monkeypatch.context() as boundary_patch:
            boundary_patch.setattr(
                provider_gate_source_audit,
                "TRUSTED_PROCESS_BOUNDARY_PATHS",
                (
                    *provider_gate_source_audit.TRUSTED_PROCESS_BOUNDARY_PATHS,
                    unreviewed_alias,
                ),
            )
            assert not provider_gate_source_audit._trusted_process_boundary_inventory_is_fixed()
            assert not provider_gate_source_audit._process_boundary_report(REPOSITORY)["passed"]
            with pytest.raises(
                provider_gate_source_audit.ProviderGateError,
                match="trusted process-boundary inventory is not fully reviewed",
            ):
                provider_gate_source_audit._source_audit(REPOSITORY)

    runner_client = REPOSITORY / "bluefire" / "runner_client.py"
    runner_lifecycle = REPOSITORY / "bluefire" / "runner_lifecycle.py"
    assert provider_gate_helper._runner_client_popen_contract(runner_client)
    assert provider_gate_helper._runner_lifecycle_popen_contract(runner_lifecycle)

    client_source = runner_client.read_text(encoding="utf-8")
    no_actual_shell_false = client_source.replace(
        "                shell=False,\n",
        "                # The actual Popen call no longer binds shell.\n",
        1,
    )
    assert no_actual_shell_false != client_source
    no_actual_shell_false += "\nMISLEADING_UNRELATED_OPTIONS = dict(shell=False)\n"
    mutated_client = mutation_root / "runner_client.py"
    mutated_client.write_text(no_actual_shell_false, encoding="utf-8")
    assert not provider_gate_helper._runner_client_popen_contract(mutated_client)

    dynamic_shell_false = client_source.replace("shell=False,", "shell=bool(0),", 1)
    mutated_client.write_text(dynamic_shell_false, encoding="utf-8")
    assert not provider_gate_helper._runner_client_popen_contract(mutated_client)

    dynamic_argv = client_source.replace(
        "                process = subprocess.Popen(  # nosec B603\n                    argv,\n",
        "                process = subprocess.Popen(  # nosec B603\n                    ['fixed-program'],\n",
        1,
    )
    assert dynamic_argv != client_source
    mutated_client.write_text(dynamic_argv, encoding="utf-8")
    assert not provider_gate_helper._runner_client_popen_contract(mutated_client)

    dynamic_parent_death_command = client_source.replace(
        "                    process = subprocess.Popen(  # nosec B603\n"
        "                        [\n"
        "                            interpreter_launch[0],\n"
        '                            "-I",\n',
        "                    process = subprocess.Popen(  # nosec B603\n"
        "                        [\n"
        "                            interpreter_launch[0],\n"
        '                            "-c",\n',
        1,
    )
    assert dynamic_parent_death_command != client_source
    mutated_client.write_text(dynamic_parent_death_command, encoding="utf-8")
    assert not provider_gate_helper._runner_client_popen_contract(mutated_client)

    factory_binding = "                popen_factory=registered_popen,\n"
    factory_bypass = "                popen_factory=subprocess.Popen,\n"
    assert client_source.count(factory_binding) == 2
    parent_factory_bypass = client_source.replace(factory_binding, factory_bypass, 1)
    mutated_client.write_text(parent_factory_bypass, encoding="utf-8")
    assert not provider_gate_helper._runner_client_popen_contract(mutated_client)

    no_fork_factory_index = client_source.rfind(factory_binding)
    assert no_fork_factory_index >= 0
    no_fork_factory_bypass = (
        client_source[:no_fork_factory_index]
        + factory_bypass
        + client_source[no_fork_factory_index + len(factory_binding) :]
    )
    mutated_client.write_text(no_fork_factory_bypass, encoding="utf-8")
    assert not provider_gate_helper._runner_client_popen_contract(mutated_client)

    raw_resource_construction = client_source.replace(
        "            resources = _prepare_darwin_launch_resources(argv, options, resource_sink)\n",
        "            resources = _DarwinLaunchResources("
        "argv=list(argv), options=dict(options), descriptors=[], links=[])\n",
        1,
    )
    assert raw_resource_construction != client_source
    mutated_client.write_text(raw_resource_construction, encoding="utf-8")
    assert not provider_gate_helper._runner_client_popen_contract(mutated_client)

    resource_overwrite = client_source.replace(
        "            resources = _prepare_darwin_launch_resources(argv, options, resource_sink)\n",
        "            resources = _prepare_darwin_launch_resources(argv, options, resource_sink)\n"
        "            resources = _DarwinLaunchResources("
        "argv=list(argv), options=dict(options), descriptors=[], links=[])\n",
        1,
    )
    assert resource_overwrite != client_source
    mutated_client.write_text(resource_overwrite, encoding="utf-8")
    assert not provider_gate_helper._runner_client_popen_contract(mutated_client)

    request_resource_overwrite = client_source.replace(
        "                resources=resources,\n"
        "            )\n"
        "            with _DARWIN_LAUNCH_CONDITION:\n",
        "                resources=resources,\n"
        "            )\n"
        "            request.resources = _DarwinLaunchResources("
        "argv=list(argv), options=dict(options), descriptors=[], links=[])\n"
        "            with _DARWIN_LAUNCH_CONDITION:\n",
        1,
    )
    assert request_resource_overwrite != client_source
    mutated_client.write_text(request_resource_overwrite, encoding="utf-8")
    assert not provider_gate_helper._runner_client_popen_contract(mutated_client)

    direct_executor = client_source.replace(
        "                resources=resources,\n"
        "            )\n"
        "            with _DARWIN_LAUNCH_CONDITION:\n"
        "                _DARWIN_LAUNCH_REQUESTS.append(request)\n",
        "                resources=resources,\n"
        "            )\n"
        "            _execute_darwin_launch_request(request)\n"
        "            with _DARWIN_LAUNCH_CONDITION:\n"
        "                _DARWIN_LAUNCH_REQUESTS.append(request)\n",
        1,
    )
    assert direct_executor != client_source
    mutated_client.write_text(direct_executor, encoding="utf-8")
    assert not provider_gate_helper._runner_client_popen_contract(mutated_client)

    wrapper_bypass = client_source.replace(
        "                arguments,\n                **launch_options,\n",
        "                argv,\n                **launch_options,\n",
        1,
    )
    assert wrapper_bypass != client_source
    mutated_client.write_text(wrapper_bypass, encoding="utf-8")
    assert not provider_gate_helper._runner_client_popen_contract(mutated_client)

    factory_rebind = client_source.replace(
        "        try:\n            process, containment = spawn_darwin_parent_death(\n",
        "        try:\n"
        "            registered_popen = [registered_popen, subprocess.Popen][1]\n"
        "            process, containment = spawn_darwin_parent_death(\n",
        1,
    )
    assert factory_rebind != client_source
    mutated_client.write_text(factory_rebind, encoding="utf-8")
    assert not provider_gate_helper._runner_client_popen_contract(mutated_client)

    wrapper_argument_mutation = client_source.replace(
        "            return self._spawn_registered_darwin_popen(\n",
        "            arguments[:] = argv\n"
        "            return self._spawn_registered_darwin_popen(\n",
        1,
    )
    assert wrapper_argument_mutation != client_source
    mutated_client.write_text(wrapper_argument_mutation, encoding="utf-8")
    assert not provider_gate_helper._runner_client_popen_contract(mutated_client)

    missing_worker_completion = client_source.replace("        request.done.set()\n", "", 1)
    assert missing_worker_completion != client_source
    mutated_client.write_text(missing_worker_completion, encoding="utf-8")
    assert not provider_gate_helper._runner_client_popen_contract(mutated_client)

    borrowed_descriptor = client_source.replace(
        "            duplicate = os.dup(descriptor)\n",
        "            duplicate = descriptor\n",
        1,
    )
    assert borrowed_descriptor != client_source
    mutated_client.write_text(borrowed_descriptor, encoding="utf-8")
    assert not provider_gate_helper._runner_client_popen_contract(mutated_client)

    borrowed_launch_path = client_source.replace(
        '    """Create one worker-owned hard link to an already verified Darwin input."""\n',
        '    """Create one worker-owned hard link to an already verified Darwin input."""\n'
        "    return argument\n",
        1,
    )
    assert borrowed_launch_path != client_source
    mutated_client.write_text(borrowed_launch_path, encoding="utf-8")
    assert not provider_gate_helper._runner_client_popen_contract(mutated_client)

    module_helper_rebind = (
        client_source + "\n_retire_darwin_launch_resources = lambda resources: None\n"
    )
    mutated_client.write_text(module_helper_rebind, encoding="utf-8")
    assert not provider_gate_helper._runner_client_popen_contract(mutated_client)

    method_rebind = (
        client_source + "\nSubprocessRustRunner._spawn_registered_darwin_popen = "
        "lambda self, token, process_sink, argv, **options: "
        "subprocess.__dict__['Popen'](argv, **options)\n"
    )
    mutated_client.write_text(method_rebind, encoding="utf-8")
    assert not provider_gate_helper._runner_client_popen_contract(mutated_client)

    aliased_method_rebind = (
        client_source + "\nRunnerAlias = SubprocessRustRunner\n"
        "RunnerAlias._spawn_registered_darwin_popen = "
        "lambda self, token, process_sink, argv, **options: "
        "self._construct_registered_darwin_popen(token, process_sink, argv, **options)\n"
    )
    mutated_client.write_text(aliased_method_rebind, encoding="utf-8")
    assert not provider_gate_helper._runner_client_popen_contract(mutated_client)

    missing_staticmethod = client_source.replace(
        "    @staticmethod\n    def _cancel_darwin_process_slot",
        "    def _cancel_darwin_process_slot",
        1,
    )
    assert missing_staticmethod != client_source
    mutated_client.write_text(missing_staticmethod, encoding="utf-8")
    assert not provider_gate_helper._runner_client_popen_contract(mutated_client)

    computed_method_rebind = (
        client_source + "\nsetattr(SubprocessRustRunner, "
        "'_spawn_registered_' + 'darwin_popen', lambda *args, **kwargs: None)\n"
    )
    mutated_client.write_text(computed_method_rebind, encoding="utf-8")
    assert not provider_gate_helper._runner_client_popen_contract(mutated_client)

    subclass_override = (
        client_source + "\nclass SubprocessRustRunner(SubprocessRustRunner):\n"
        "    def __getattribute__(self, name):\n"
        "        return super().__getattribute__(name)\n"
    )
    mutated_client.write_text(subclass_override, encoding="utf-8")
    assert not provider_gate_helper._runner_client_popen_contract(mutated_client)

    lifecycle_source = runner_lifecycle.read_text(encoding="utf-8")
    lifecycle_without_shell_false = lifecycle_source.replace(
        "subprocess.Popen(command, shell=False, **options)",
        "subprocess.Popen(command, **options)",
        1,
    )
    assert lifecycle_without_shell_false != lifecycle_source
    lifecycle_without_shell_false += "\nMISLEADING_UNRELATED_OPTIONS = dict(shell=False)\n"
    mutated_lifecycle = mutation_root / "runner_lifecycle.py"
    mutated_lifecycle.write_text(lifecycle_without_shell_false, encoding="utf-8")
    assert not provider_gate_helper._runner_lifecycle_popen_contract(mutated_lifecycle)

    darwin_launcher = REPOSITORY / "bluefire" / "runner_darwin_containment.py"
    assert provider_gate_source_audit._runner_darwin_popen_contract(darwin_launcher)
    mutated_darwin = mutation_root / "runner_darwin_containment.py"
    darwin_source = darwin_launcher.read_text(encoding="utf-8")
    mutated_darwin.write_text(
        darwin_source.replace("shell=False,", "shell=True,", 1),
        encoding="utf-8",
    )
    assert not provider_gate_source_audit._runner_darwin_popen_contract(mutated_darwin)

    unverified_parent = darwin_source.replace(
        "def _validate_macos_launch_parent(path: Path, descriptor: int) -> int:\n",
        "def _validate_macos_launch_parent(path: Path, descriptor: int) -> int:\n"
        "    return int(os.geteuid())\n",
        1,
    )
    assert unverified_parent != darwin_source
    mutated_darwin.write_text(unverified_parent, encoding="utf-8")
    assert not provider_gate_source_audit._runner_darwin_popen_contract(mutated_darwin)

    mutated_timeout = darwin_source.replace(
        'format(execution_timeout_seconds, ".17g"),',
        'format(1.0, ".17g"),',
        1,
    )
    assert mutated_timeout != darwin_source
    mutated_darwin.write_text(mutated_timeout, encoding="utf-8")
    assert not provider_gate_source_audit._runner_darwin_popen_contract(mutated_darwin)

    parent_death = REPOSITORY / "bluefire" / "runner_parent_death.py"
    assert provider_gate_source_audit._runner_parent_death_process_contract(
        parent_death, REPOSITORY
    )
    mutated_parent = mutation_root / "runner_parent_death.py"
    mutated_parent.write_text(
        parent_death.read_text(encoding="utf-8") + "\ndef _run(arguments):\n    return 0\n",
        encoding="utf-8",
    )
    assert not provider_gate_source_audit._runner_parent_death_process_contract(
        mutated_parent,
        mutation_root,
    )

    process_source = (REPOSITORY / "runner" / "src" / "process.rs").read_bytes()
    assert len(process_source) == provider_gate_source_audit._REVIEWED_PROCESS_SOURCE_SIZE
    assert (
        provider_gate_source_audit._sha256_bytes(process_source)
        == provider_gate_source_audit._REVIEWED_PROCESS_SOURCE_SHA256
    )
    assert provider_gate_source_audit._native_process_inventory_is_fixed(process_source)
    cancellation_source = (REPOSITORY / "runner" / "src" / "cancellation_witness.rs").read_bytes()
    assert len(cancellation_source) == provider_gate_source_audit._REVIEWED_CANCELLATION_SOURCE_SIZE
    assert (
        provider_gate_source_audit._sha256_bytes(cancellation_source)
        == provider_gate_source_audit._REVIEWED_CANCELLATION_SOURCE_SHA256
    )
    assert provider_gate_source_audit._native_command_source_inventory_is_fixed(REPOSITORY)

    command_inventory = mutation_root / "command-inventory"
    nested_source = command_inventory / "runner" / "src" / "nested"
    nested_source.mkdir(parents=True)
    (command_inventory / "runner" / "src" / "process.rs").write_bytes(process_source)
    (command_inventory / "runner" / "src" / "cancellation_witness.rs").write_bytes(
        cancellation_source
    )
    assert provider_gate_source_audit._native_command_source_inventory_is_fixed(command_inventory)
    (nested_source / "hidden.rs").write_text(
        "use std :: process :: Command as Hidden;\n"
        'fn hidden() { let _ = Hidden :: new("/bin/sh"); }\n',
        encoding="utf-8",
    )
    assert not provider_gate_source_audit._native_command_source_inventory_is_fixed(
        command_inventory
    )
    process_text = process_source.decode("utf-8")
    process_launcher = "    let mut command = Command::new(&spec.executable);"
    widened_process_source = process_text.replace(
        process_launcher,
        "    let _unexpected = Command::new(&spec.executable);\n" + process_launcher,
        1,
    )
    assert widened_process_source != process_text
    assert not provider_gate_source_audit._native_process_inventory_is_fixed(
        widened_process_source.encode("utf-8")
    )

    spaced_launcher_source = process_text.replace(
        process_launcher,
        "    let _unexpected = Command :: new(&spec.executable);\n" + process_launcher,
        1,
    )
    assert spaced_launcher_source != process_text
    assert "Command :: new(&spec.executable)" in spaced_launcher_source
    assert not provider_gate_source_audit._native_process_inventory_is_fixed(
        spaced_launcher_source.encode("utf-8")
    )

    aliased_launcher_source = process_text.replace(
        "use std::process::{Command, Stdio};",
        "use std::process::{Command, Stdio};\nuse std::process::Command as ProcessCommand;",
        1,
    ).replace(
        process_launcher,
        "    let _unexpected = ProcessCommand::new(&spec.executable);\n" + process_launcher,
        1,
    )
    assert aliased_launcher_source != process_text
    assert "use std::process::Command as ProcessCommand;" in aliased_launcher_source
    assert "ProcessCommand::new(&spec.executable)" in aliased_launcher_source
    assert not provider_gate_source_audit._native_process_inventory_is_fixed(
        aliased_launcher_source.encode("utf-8")
    )

    macro_launcher_source = process_text.replace(
        process_launcher,
        "    macro_rules! hidden_command {\n"
        "        ($ty:ident, $ctor:ident, $arg:expr) => { $ty::$ctor($arg) };\n"
        "    }\n"
        '    let _unexpected = hidden_command!(Command, new, concat!("/bin/", "sh"));\n'
        + process_launcher,
        1,
    )
    assert "hidden_command!(Command, new" in macro_launcher_source
    assert not provider_gate_source_audit._native_process_inventory_is_fixed(
        macro_launcher_source.encode("utf-8")
    )

    status_launcher_source = process_text.replace(
        process_launcher,
        process_launcher + "\n    let _unexpected = command.status();",
        1,
    )
    assert "let _unexpected = command.status();" in status_launcher_source
    assert not provider_gate_source_audit._native_process_inventory_is_fixed(
        status_launcher_source.encode("utf-8")
    )

    shadowed_command_source = process_text.replace(
        process_launcher,
        "    type Command = std::process::Command;\n" + process_launcher,
        1,
    )
    assert "type Command = std::process::Command;" in shadowed_command_source
    assert not provider_gate_source_audit._native_process_inventory_is_fixed(
        shadowed_command_source.encode("utf-8")
    )

    assert not provider_gate_source_audit._native_process_inventory_is_fixed(
        process_source + b"\n}"
    )

    lifecycle_dynamic_shell = lifecycle_source.replace(
        "subprocess.Popen(command, shell=False, **options)",
        "subprocess.Popen(command, shell=bool(0), **options)",
        1,
    )
    assert lifecycle_dynamic_shell != lifecycle_source
    mutated_lifecycle.write_text(lifecycle_dynamic_shell, encoding="utf-8")
    assert not provider_gate_helper._runner_lifecycle_popen_contract(mutated_lifecycle)


def test_gate_02_refuses_passing_suite_with_incomplete_locked_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence_dir = tmp_path / "gate-02"
    evidence_dir.mkdir()
    _install_passing_fakes(monkeypatch)
    passing_suite = provider_gate._run_pytest_suite

    def incomplete_suite(*args: Any, **kwargs: Any) -> Mapping[str, Any]:
        report = dict(passing_suite(*args, **kwargs))
        if kwargs["suite_id"] == "provider-contracts":
            passed_tests = list(report["passed_tests"])
            passed_tests.remove(sorted(provider_gate._REQUIRED_PROVIDER_CONTRACT_TESTS)[0])
            report["passed_tests"] = passed_tests
            report["tests"] = len(passed_tests)
        return report

    monkeypatch.setattr(provider_gate, "_run_pytest_suite", incomplete_suite)

    outcome = provider_gate.run_gate_02(_gate(), evidence_dir, repository_root=REPOSITORY)

    assert outcome.status == "failed"
    assert outcome.proofs == ()
    assert outcome.failure_reason is not None
    assert "provider contract regression coverage is incomplete" in outcome.failure_reason


def test_gate_02_validates_the_persisted_verification_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence_dir = tmp_path / "gate-02"
    evidence_dir.mkdir()
    _install_passing_fakes(monkeypatch)
    write_json = provider_gate._write_json

    def tampering_write(path: Path, value: Mapping[str, Any]) -> None:
        persisted = json.loads(json.dumps(value))
        if path.name == "provider-verification-report.json":
            persisted["checks"]["management_parity"]["channels"][
                "api_real_signed_provider_lifecycle"
            ] = False
        write_json(path, persisted)

    monkeypatch.setattr(provider_gate, "_write_json", tampering_write)

    outcome = provider_gate.run_gate_02(_gate(), evidence_dir, repository_root=REPOSITORY)

    assert outcome.status == "failed"
    assert outcome.proofs == ()
    assert outcome.failure_reason is not None
    assert "provider verification management channels are invalid" in outcome.failure_reason


def test_gate_02_propagates_only_bounded_helper_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence_dir = tmp_path / "gate-02"
    evidence_dir.mkdir()
    _install_passing_fakes(
        monkeypatch,
        helper={
            "passed": False,
            "exit_code": 1,
            "failure_code": "provider_gate_failed",
            "failure_message": "provider structural checks failed",
        },
    )

    outcome = provider_gate.run_gate_02(_gate(), evidence_dir, repository_root=REPOSITORY)

    assert outcome.status == "failed"
    assert outcome.proofs == ()
    assert outcome.failure_reason is not None
    assert (
        "provider real-run helper failed [provider_gate_failed]: provider structural checks failed"
    ) in outcome.failure_reason
    assert str(REPOSITORY) not in outcome.failure_reason


def test_frontend_verifier_rejects_renamed_test_even_when_count_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entrypoint = tmp_path / "frontend" / "node_modules" / "vitest" / "vitest.mjs"
    entrypoint.parent.mkdir(parents=True)
    entrypoint.write_text("// fixed test entrypoint\n", encoding="utf-8")
    names = sorted(provider_gate._EXPECTED_UI_TESTS)
    names[-1] = "action package management renamed coverage"
    output = {
        "success": True,
        "numTotalTests": len(names),
        "testResults": [
            {"assertionResults": [{"fullName": name, "status": "passed"} for name in names]}
        ],
    }
    monkeypatch.setattr(provider_gate.shutil, "which", lambda _name: "node")

    def fake_run(command: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        kwargs["stdout"].write(json.dumps(output).encode("utf-8"))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(provider_gate.subprocess, "run", fake_run)

    report = provider_gate._run_vitest(tmp_path)

    assert report["tests"] == 8
    assert report["passed"] is False


def test_gate_02_is_statically_registered() -> None:
    assert product_gates._WORKFLOWS["GATE-02"] is product_gates._gate_02_workflow
