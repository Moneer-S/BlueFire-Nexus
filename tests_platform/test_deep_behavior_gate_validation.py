from __future__ import annotations

import copy
import json
import secrets
from pathlib import Path
from typing import Any, Mapping

import pytest

import bluefire.deep_behavior_gate_validation as validation
from bluefire.cloud_identity_pack import (
    PACK_ID,
    PROFILE_ID,
    AwsIdentityLabApproval,
    AwsIdentityLabPack,
    AwsIdentityLabProfile,
    DeterministicAwsIdentityBackend,
    ExecuteRequest,
    InMemoryCloudCredentialVault,
    SimulateRequest,
    build_aws_identity_lab_smoke_commands,
    validate_cloud_identity_run_bundle,
)
from bluefire.deep_behavior_gate_validation import DeepBehaviorGateValidationError
from bluefire.product_acceptance import load_release_contract
from bluefire.run_store import RunStore
from bluefire.runner_bootstrap import load_runner_manifest
from bluefire.util import content_hash

REPOSITORY = Path(__file__).resolve().parents[1]
ACCOUNT_ID = "123456789012"
ROLE_NAME = "BlueFireDisposableIdentityLab"
REGION = "us-east-2"


def _binding(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    values = {
        "acceptance_id": "gate03-validator-test",
        "gate_id": "GATE-03",
        "contract_sha256": "sha256:" + "3" * 64,
        "repository_commit": "4" * 40,
        "repository_tree": "5" * 40,
        "release": "true",
    }
    environment = {
        "acceptance_id": "BLUEFIRE_ACCEPTANCE_ID",
        "gate_id": "BLUEFIRE_ACCEPTANCE_GATE_ID",
        "contract_sha256": "BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256",
        "repository_commit": "BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT",
        "repository_tree": "BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE",
        "release": "BLUEFIRE_ACCEPTANCE_RELEASE",
    }
    for key, name in environment.items():
        monkeypatch.setenv(name, values[key])
    return {
        "schema_version": "bluefire.product-acceptance-run-binding.v1",
        **values,
    }


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_bytes(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )


def _bundle(run_id: str) -> dict[str, str]:
    return {"run_id": run_id, "path": f"runs/{run_id}"}


def _run_id(index: int) -> str:
    return f"run-20260830T12000{index}Z-{index:016x}"


def test_contract_exports_match_all_gate03_assertions() -> None:
    contract = load_release_contract(REPOSITORY / "bluefire" / "data" / "product_acceptance.yaml")
    gate = next(item for item in contract.gates if item.gate_id == "GATE-03")

    assert len(validation.CHECK_NAMES) == 15
    assert len(validation.REPORT_PATHS) == 7
    assert validation.JOURNEY_REPORT_PATHS == validation.REPORT_PATHS[:-1]
    assert [(item.assertion_id, item.proof) for item in gate.assertions] == [
        (assertion_id, proof) for assertion_id, proof, _report in validation.ASSERTION_REPORTS
    ]
    assert set(validation.JOURNEY_REPORT_PATHS) == {
        report for _assertion, _proof, report in validation.ASSERTION_REPORTS
    } | {validation.PACK_INVENTORY_REPORT}


def test_report_reader_requires_canonical_duplicate_free_safe_json(tmp_path: Path) -> None:
    _write_json(tmp_path / "report.json", {"passed": True, "schema_version": "test.v1"})
    assert validation._read_report(tmp_path, "report.json")["passed"] is True

    (tmp_path / "report.json").write_text(
        '{"passed":true,"passed":true,"schema_version":"test.v1"}\n',
        encoding="utf-8",
    )
    with pytest.raises(DeepBehaviorGateValidationError, match="duplicate|strict"):
        validation._read_report(tmp_path, "report.json")

    (tmp_path / "report.json").write_text(
        '{"passed":true,"schema_version":"test.v1"}\n', encoding="utf-8"
    )
    with pytest.raises(DeepBehaviorGateValidationError, match="not canonical"):
        validation._read_report(tmp_path, "report.json")


def _endpoint_steps(receiver_pid: int) -> list[dict[str, Any]]:
    names = (
        "run_native_canary",
        "discover_system",
        "discover_processes",
        "create_fixture",
        "transform_fixture",
        "inspect_fixture_metadata",
        "stage_records",
        "create_persistence_canary",
        "create_observability_variant",
        "authorized_peer_handoff",
        "cleanup_workspace",
    )
    values = [
        {"step_id": name, "status": "success", "execution_disposition": "execute"} for name in names
    ]
    by_name = {item["step_id"]: item for item in values}
    by_name["create_observability_variant"]["artifacts"] = {
        "variant": {"equivalence_verified": True}
    }
    by_name["authorized_peer_handoff"].update(
        {
            "behavior_id": "sandbox.credential.peer-challenge.v1",
            "action_id": "sandbox.peer.handoff.v1",
            "runner_task_id": "execute-" + "a" * 64,
            "artifacts": {
                "receipt": {
                    "lab_authorization": {
                        "scope": "approved_task",
                        "challenge_verified": True,
                        "raw_credential_exposed": False,
                    },
                    "lab_peers": {
                        "distinct_processes": True,
                        "source_process_id": receiver_pid - 1,
                        "destination_process_id": receiver_pid,
                        "transfer_acknowledged": True,
                    },
                }
            },
        }
    )
    return values


def _endpoint_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, dict[str, Any]]:
    _binding(monkeypatch)
    evidence = tmp_path / "evidence"
    store = RunStore(evidence / "runs")
    handle = store.create_run(
        scenario={"schema_version": "test.v1"},
        plan={"schema_version": "test.v1"},
        policy={"schema_version": "test.v1"},
        profile={"schema_version": "test.v1"},
    )
    steps = _endpoint_steps(90210)
    store.finalize(
        handle.run_id,
        result={
            "schema_version": "bluefire.run-result.v1",
            "scenario_id": "scenario.endpoint.deep-behavior-lab.v1",
            "runner_profile_id": "sandbox-endpoint-deep-lab.v1",
            "mode": "execute",
            "status": "completed",
            "objective_reached": True,
            "cleanup": {"success": True, "outstanding_receipt_count": 0},
            "steps": steps,
        },
        evidence=(),
        detections=(),
    )
    manifest = load_runner_manifest(resource_root=REPOSITORY / "bluefire" / "native")
    bundle = _bundle(handle.run_id)
    report: dict[str, Any] = {
        "schema_version": "bluefire.deep-behavior-endpoint-execute.v1",
        "passed": True,
        "proof_kind": "dynamic",
        "pack_id": "bluefire.endpoint-identity.v1",
        "platform": "windows",
        "environment_type": "disposable",
        "runner": {
            "runner_id": manifest.runner_id,
            "runner_version": manifest.runner_version,
            "platform": manifest.platform,
            "binary_sha256": "sha256:" + manifest.sha256,
            "binary_size": manifest.size,
        },
        "execution": {
            "run_id": handle.run_id,
            "status": "completed",
            "objective_reached": True,
            "step_count": 11,
        },
        "phases": {
            "execution": True,
            "discovery": True,
            "collection_staging": True,
            "persistence": True,
            "authorized_credentials": True,
            "disposable_lateral": True,
            "telemetry_shaping": True,
            "cleanup": True,
        },
        "receiver": {
            "host": "127.0.0.1",
            "mode": "disposable_peer",
            "process_id": 90210,
            "process_distinct": True,
            "process_exited": True,
            "requests_accepted": 1,
            "terminal_disposition": "exit_after_response",
        },
        "cleanup": {
            "workspace_files_remaining": 0,
            "receiver_process_exited": True,
            "outstanding_receipt_count": 0,
        },
        "credential_scan": validation._bundle_stats(evidence / bundle["path"]),
        "run_bundle": bundle,
    }
    return evidence, report


def test_endpoint_report_is_bound_to_peer_receipt_and_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence, report = _endpoint_fixture(tmp_path, monkeypatch)
    binding = validation._bundle_binding(evidence, report["run_bundle"])

    bundle, checks = validation._validate_endpoint(REPOSITORY, evidence, report)
    assert bundle == report["run_bundle"]
    assert all(checks.values())
    assert validation._normalize_bundles(
        evidence,
        (bundle,),
        expected_binding=binding,
        not_before=None,
        not_after=None,
    ) == (bundle,)

    tampered = copy.deepcopy(report)
    tampered["receiver"]["process_id"] += 1
    with pytest.raises(DeepBehaviorGateValidationError, match="not bound"):
        validation._validate_endpoint(REPOSITORY, evidence, tampered)


def _cloud_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, dict[str, str], dict[str, Any]]:
    binding = _binding(monkeypatch)
    evidence = tmp_path / "cloud"
    credential = secrets.token_bytes(48)
    vault = InMemoryCloudCredentialVault()
    profile = AwsIdentityLabProfile(
        account_id=ACCOUNT_ID,
        region=REGION,
        role_name=ROLE_NAME,
        credential_handle=vault.enroll(credential),
    )
    approval = AwsIdentityLabApproval(
        approval_id="gate03-cloud-approval",
        account_id=ACCOUNT_ID,
        role_name=ROLE_NAME,
    )
    pack = AwsIdentityLabPack(
        credentials=vault,
        backend=DeterministicAwsIdentityBackend(account_id=ACCOUNT_ID, role_name=ROLE_NAME),
    )
    store = RunStore(evidence / "runs")
    simulated = pack.simulate(SimulateRequest("gate03-simulate", profile, approval), store)
    executed = pack.execute(ExecuteRequest("gate03-execute", profile, approval), store)

    def summary(receipt: Any, mode: str) -> dict[str, Any]:
        row = receipt.to_dict()
        row.pop("bundle_path")
        row["validation"] = validate_cloud_identity_run_bundle(
            store,
            receipt.run_id,
            expected_mode=mode,
            expected_acceptance_binding=binding,
        )
        return row

    manual_request = validation.AwsManualSmokeRequest(
        credential_profile="bluefire-gate03-lab",
        account_id=ACCOUNT_ID,
        role_name=ROLE_NAME,
        region=REGION,
        approval_id="gate03-manual",
        approved_account_id=ACCOUNT_ID,
        approved_role_name=ROLE_NAME,
        confirmation=validation.MANUAL_CONFIRMATION,
        timeout_seconds=20,
    )
    report = {
        "schema_version": validation.AWS_REPORT_SCHEMA,
        "passed": True,
        "proof_kind": "dynamic",
        "pack_id": PACK_ID,
        "profile": profile.to_dict(),
        "credential_binding": {
            "handle_prefix": "credential-",
            "opaque": True,
            "raw_material_persisted": False,
            "handle_revoked": True,
        },
        "manual_smoke": {
            "schema_version": validation.AWS_MANUAL_CONTRACT_SCHEMA,
            "credential_reference": manual_request.credential_reference,
            "operations": [
                command.operation
                for command in build_aws_identity_lab_smoke_commands(manual_request)
            ],
            "shell": False,
            "timeout_seconds": 20,
            "external_execution": False,
        },
        "simulate": summary(simulated, "simulate"),
        "execute": summary(executed, "execute"),
        "run_bundles": [_bundle(simulated.run_id), _bundle(executed.run_id)],
    }
    assert report["profile"]["profile_id"] == PROFILE_ID
    return evidence, binding, report


def test_aws_report_revalidates_simulate_execute_revocation_and_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence, binding, report = _cloud_fixture(tmp_path, monkeypatch)

    bundles, checks = validation._validate_aws(evidence, report, expected_binding=binding)
    assert [item["run_id"] for item in bundles] == [
        report["simulate"]["run_id"],
        report["execute"]["run_id"],
    ]
    assert all(checks.values())

    tampered = copy.deepcopy(report)
    tampered["execute"]["credential_revoked"] = False
    with pytest.raises(DeepBehaviorGateValidationError, match="summary is invalid"):
        validation._validate_aws(evidence, tampered, expected_binding=binding)


def test_runtime_secret_scan_must_bind_all_referenced_bundle_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundles: list[Path] = []
    for index in range(5):
        root = tmp_path / f"bundle-{index}"
        root.mkdir()
        (root / "evidence.json").write_text(f'{{"index":{index}}}\n', encoding="utf-8")
        bundles.append(root)
    source = {
        "schema_version": "bluefire.deep-behavior-source-credential-scan.v1",
        "passed": True,
        "files": [{"path": "safe", "size_bytes": 1, "sha256": "sha256:" + "1" * 64}],
        "files_scanned": 1,
        "bytes_scanned": 1,
        "forbidden_matches": [],
        "source_inventory_sha256": "sha256:" + "2" * 64,
    }
    monkeypatch.setattr(validation, "audit_deep_behavior_sources", lambda _root: source)
    inventory = validation._runtime_inventory(bundles)
    report = {
        "schema_version": validation.SECRET_REPORT_SCHEMA,
        "passed": True,
        "source": source,
        "runtime": {
            "schema_version": "bluefire.deep-behavior-runtime-credential-scan.v1",
            "passed": True,
            **inventory,
            "secret_count": 1,
            "matches": 0,
        },
    }

    validation._validate_secret_report(REPOSITORY, report, bundles)
    report["runtime"]["artifact_digest_set_sha256"] = "sha256:" + "0" * 64
    with pytest.raises(DeepBehaviorGateValidationError, match="all five bundles"):
        validation._validate_secret_report(REPOSITORY, report, bundles)


def _linux_report(variant: str) -> dict[str, Any]:
    return {
        "schema_version": "bluefire.cross-platform-linux-execute.v2",
        "passed": True,
        "proof_kind": "dynamic",
        "platform": "linux",
        "environment_type": "disposable-wsl2-distribution",
        "availability": {"state": "ready", "code": None},
        "boundary": {},
        "runner": {},
        "source_intake_publication": {},
        "execution": {},
        "receiver": {},
        "run_bundle": _bundle(_run_id(1)),
        "scenario_variant": variant,
        "watchdog_containment": {},
    }


def test_linux_report_strips_variant_then_revalidates_registered_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding = {"repository_commit": "4" * 40, "repository_tree": "5" * 40}
    report = _linux_report("registered-alternate")
    execution = {
        "run_id": report["run_bundle"]["run_id"],
        "status": "completed",
        "objective_reached": True,
        "cleanup_success": True,
        "outstanding_receipt_count": 0,
        "step_count": 10,
    }
    monkeypatch.setattr(validation, "validate_linux_repository_runner", lambda *_a, **_k: {})
    monkeypatch.setattr(validation.platform_validation, "_reprobe_wsl", lambda: {})

    def fake_linux(core: Mapping[str, Any], *_args: Any, **_kwargs: Any):
        assert "scenario_variant" not in core
        assert core["watchdog_containment"] == {}
        return report["run_bundle"], execution, {}

    def fake_bundle(_path: Path, summary: Mapping[str, Any], **kwargs: Any):
        assert summary["scenario_variant"] == "registered-alternate"
        assert kwargs["scenario_variant"] == "registered-alternate"
        return execution

    monkeypatch.setattr(validation.platform_validation, "_linux", fake_linux)
    monkeypatch.setattr(validation, "validate_linux_bundle", fake_bundle)

    observed, facts = validation._validate_linux(
        REPOSITORY,
        tmp_path,
        report,
        expected_variant="registered-alternate",
        expected_binding=binding,
    )
    assert observed == report["run_bundle"]
    assert facts == execution


def test_typed_linux_unavailability_requires_only_primary_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = _linux_report("primary")
    report.update(
        {
            "passed": False,
            "runner": None,
            "execution": None,
            "receiver": None,
            "run_bundle": None,
            "watchdog_containment": None,
        }
    )
    _write_json(tmp_path / validation.LINUX_PRIMARY_REPORT, report)
    monkeypatch.setattr(validation, "linux_wheelhouse_unavailable", lambda _root: False)
    monkeypatch.setattr(validation.platform_validation, "_reprobe_wsl", lambda: {})

    def unavailable(*_args: Any, **_kwargs: Any) -> None:
        raise validation.platform_validation.LinuxRuntimeUnavailableError("stable blocker")

    monkeypatch.setattr(validation.platform_validation, "_linux", unavailable)
    assert validation.validate_linux_unavailable_report(tmp_path, REPOSITORY) == "stable blocker"

    (tmp_path / "unexpected.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(DeepBehaviorGateValidationError, match="unrelated evidence"):
        validation.validate_linux_unavailable_report(tmp_path, REPOSITORY)


def _verification() -> dict[str, Any]:
    tests = ["tests_platform/test_deep_behavior_gate_validation.py::test_contract"]
    checks = {name: True for name in sorted(validation.CHECK_NAMES)}
    return {
        "schema_version": validation.VERIFICATION_SCHEMA,
        "passed": True,
        "helper": {
            "schema_version": validation.HELPER_SCHEMA,
            "status": "passed",
            "reports": list(validation.JOURNEY_REPORT_PATHS),
            "run_count": 5,
            "blocking_check": None,
            "exit_code": 0,
            "command": ["{python}", "tools/run_deep_behavior_gate_journey.py", "{fixed-arguments}"],
            "protocol_valid": True,
        },
        "suite": {
            "schema_version": "bluefire.architecture-dynamic-check.v1",
            "suite_id": "deep-behavior-contracts",
            "command": ["{python}", "-m", "pytest"],
            "exit_code": 0,
            "passed": True,
            "tests": 1,
            "passed_tests": tests,
            "failed_tests": [],
            "skipped_tests": [],
        },
        "checks": checks,
        "run_ids": [_run_id(index) for index in range(5)],
        "reports": list(validation.JOURNEY_REPORT_PATHS),
        "proof_kinds": ["dynamic", "structural"],
    }


def test_verification_metadata_is_exact_and_tamper_resistant(tmp_path: Path) -> None:
    report = _verification()
    _write_json(tmp_path / validation.VERIFICATION_REPORT, report)
    validation.validate_deep_behavior_verification(
        tmp_path,
        expected_checks=report["checks"],
        expected_run_ids=report["run_ids"],
        expected_suite_tests=report["suite"]["passed_tests"],
    )

    report["helper"]["run_count"] = 4
    _write_json(tmp_path / validation.VERIFICATION_REPORT, report)
    with pytest.raises(DeepBehaviorGateValidationError, match="inconsistent"):
        validation.validate_deep_behavior_verification(
            tmp_path,
            expected_checks=report["checks"],
            expected_run_ids=report["run_ids"],
            expected_suite_tests=report["suite"]["passed_tests"],
        )


def test_aggregate_validator_requires_five_distinct_roles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = tmp_path / "evidence"
    repository = tmp_path / "repository"
    evidence.mkdir()
    repository.mkdir()
    binding = {"gate_id": "GATE-03"}
    bundles = [_bundle(_run_id(index)) for index in range(5)]
    monkeypatch.setattr(validation, "_read_report", lambda _root, name: {"name": name})
    monkeypatch.setattr(validation, "_validate_pack_inventory", lambda *_args: None)
    monkeypatch.setattr(
        validation,
        "_validate_endpoint",
        lambda *_args: (
            bundles[0],
            {name: True for name in validation.CHECK_NAMES if name.startswith("endpoint")}
            | {
                "authorized_credentials": True,
                "disposable_lateral": True,
                "evasion_telemetry": True,
            },
        ),
    )
    monkeypatch.setattr(validation, "_bundle_binding", lambda *_args: binding)

    def linux(*_args: Any, expected_variant: str, **_kwargs: Any):
        index = 1 if expected_variant == "primary" else 2
        return bundles[index], {}

    monkeypatch.setattr(validation, "_validate_linux", linux)
    cloud_checks = {name: True for name in validation.CHECK_NAMES if name.startswith("cloud")}
    monkeypatch.setattr(
        validation,
        "_validate_aws",
        lambda *_args, **_kwargs: ((bundles[3], bundles[4]), cloud_checks),
    )
    monkeypatch.setattr(validation, "_validate_secret_report", lambda *_args: None)
    monkeypatch.setattr(validation, "_forbid_secret_shapes", lambda *_args: None)
    monkeypatch.setattr(validation, "_normalize_bundles", lambda _e, rows, **_k: tuple(rows))

    checks, observed = validation.validate_deep_behavior_reports(
        evidence, repository, expected_binding=binding
    )
    assert set(checks) == validation.CHECK_NAMES
    assert tuple(observed) == tuple(bundles)

    monkeypatch.setattr(
        validation,
        "_validate_aws",
        lambda *_args, **_kwargs: ((bundles[3], bundles[3]), cloud_checks),
    )
    with pytest.raises(DeepBehaviorGateValidationError, match="five distinct"):
        validation.validate_deep_behavior_reports(evidence, repository, expected_binding=binding)


def test_recursive_secret_shape_guard_refuses_raw_credential_fields() -> None:
    validation._forbid_secret_shapes({"credential_handle": "credential-" + "a" * 32})
    with pytest.raises(DeepBehaviorGateValidationError, match="raw credential field"):
        validation._forbid_secret_shapes({"aws_secret_access_key": "not-allowed"})
    with pytest.raises(DeepBehaviorGateValidationError, match="raw credential exposure"):
        validation._forbid_secret_shapes({"raw_credential_exposed": True})
    assert content_hash({"checked": True}).startswith("sha256:")
