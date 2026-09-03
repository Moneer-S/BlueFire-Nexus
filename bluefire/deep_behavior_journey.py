"""Production evidence journey for the three official deep-behavior packs."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any, Mapping, cast

from .cloud_identity_pack import (
    MANUAL_CONFIRMATION,
    PACK_ID,
    AwsIdentityLabApproval,
    AwsIdentityLabPack,
    AwsIdentityLabProfile,
    AwsManualSmokeRequest,
    DeterministicAwsIdentityBackend,
    ExecuteRequest,
    InMemoryCloudCredentialVault,
    SimulateRequest,
    build_aws_identity_lab_smoke_commands,
    validate_cloud_identity_run_bundle,
)
from .cross_platform_artifact_validation import linux_wheelhouse_unavailable
from .cross_platform_linux import (
    LinuxDependenciesUnavailableError,
    linux_dependencies_unavailable_report,
    linux_unavailable_report,
    run_linux_journey,
)
from .cross_platform_linux_bundle_validation import (
    PRIMARY_SCENARIO_VARIANT,
    REGISTERED_ALTERNATE_SCENARIO_VARIANT,
)
from .cross_platform_readiness import probe_wsl2
from .deep_behavior_endpoint import run_endpoint_pack_journey
from .deep_behavior_packs import official_pack_inventory
from .deep_behavior_secret_scan import (
    audit_deep_behavior_sources,
    scan_runtime_secret_material,
)
from .run_store import RunStore
from .runtime_paths import runtime_temp_parent

PACK_REPORT = "pack-inventory.json"
ENDPOINT_REPORT = "endpoint-execute.json"
LINUX_PRIMARY_REPORT = "linux-primary.json"
LINUX_ALTERNATE_REPORT = "linux-alternate.json"
AWS_REPORT = "aws-identity.json"
SECRET_SCAN_REPORT = "secret-scan.json"
JOURNEY_REPORT_PATHS = (
    PACK_REPORT,
    ENDPOINT_REPORT,
    LINUX_PRIMARY_REPORT,
    LINUX_ALTERNATE_REPORT,
    AWS_REPORT,
    SECRET_SCAN_REPORT,
)

HELPER_SCHEMA = "bluefire.deep-behavior-helper.v1"
AWS_REPORT_SCHEMA = "bluefire.deep-behavior-aws-identity.v1"
MANUAL_SMOKE_CONTRACT_SCHEMA = "bluefire.aws-identity-lab-manual-smoke-contract.v1"
SECRET_SCAN_AGGREGATE_SCHEMA = "bluefire.deep-behavior-secret-scan.v1"
_MAX_REPORT_BYTES = 2 * 1024 * 1024
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_ACCEPTANCE_FIELDS = (
    ("acceptance_id", "BLUEFIRE_ACCEPTANCE_ID"),
    ("gate_id", "BLUEFIRE_ACCEPTANCE_GATE_ID"),
    ("contract_sha256", "BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256"),
    ("repository_commit", "BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT"),
    ("repository_tree", "BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE"),
    ("release", "BLUEFIRE_ACCEPTANCE_RELEASE"),
)


class DeepBehaviorJourneyError(ValueError):
    """The official pack journey is unavailable, incomplete, or unsafe."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DeepBehaviorJourneyError(message)


def _safe_root(path: Path, label: str) -> Path:
    details = path.lstat()
    _require(
        stat.S_ISDIR(details.st_mode)
        and not stat.S_ISLNK(details.st_mode)
        and not int(getattr(details, "st_file_attributes", 0)) & _REPARSE_POINT,
        f"the {label} root is unsafe",
    )
    return path.resolve(strict=True)


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    payload = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    _require(
        path.parent.is_dir() and not path.exists() and 0 < len(payload) <= _MAX_REPORT_BYTES,
        "a GATE-03 report destination is stale or unbounded",
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_CREAT
            | os.O_EXCL
            | os.O_WRONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            _require(written > 0, "a GATE-03 report write made no progress")
            offset += written
        os.fsync(descriptor)
    except OSError as exc:
        raise DeepBehaviorJourneyError("a GATE-03 report could not be written") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _acceptance_binding() -> Mapping[str, str]:
    values: dict[str, str] = {}
    for field, name in _ACCEPTANCE_FIELDS:
        value = os.environ.get(name)
        _require(
            isinstance(value, str) and 1 <= len(value) <= 512,
            f"required acceptance binding {name} is unavailable",
        )
        values[field] = cast(str, value)
    _require(values["gate_id"] == "GATE-03", "cloud acceptance gate binding is invalid")
    return {"schema_version": "bluefire.product-acceptance-run-binding.v1", **values}


def _manual_smoke_contract() -> Mapping[str, Any]:
    request = AwsManualSmokeRequest(
        credential_profile="bluefire-disposable-lab",
        account_id="111122223333",
        role_name="BlueFireDisposableIdentityLab",
        region="us-east-2",
        approval_id="gate03-manual-smoke",
        approved_account_id="111122223333",
        approved_role_name="BlueFireDisposableIdentityLab",
        confirmation=MANUAL_CONFIRMATION,
        timeout_seconds=20,
    )
    commands = build_aws_identity_lab_smoke_commands(request)
    _require(len(commands) == 8, "the AWS manual-smoke command inventory changed")
    return {
        "schema_version": MANUAL_SMOKE_CONTRACT_SCHEMA,
        "credential_reference": request.credential_reference,
        "operations": [command.operation for command in commands],
        "shell": False,
        "timeout_seconds": request.timeout_seconds,
        "external_execution": False,
    }


def _cloud_receipt(
    receipt: Any,
    validation: Mapping[str, Any],
) -> Mapping[str, Any]:
    return {
        "schema_version": "bluefire.aws-identity-lab-run-receipt.v1",
        "mode": receipt.mode,
        "run_id": receipt.run_id,
        "bundle_hash": receipt.bundle_hash,
        "cleanup_verified": receipt.cleanup_verified,
        "audit_verified": receipt.audit_verified,
        "credential_revoked": receipt.credential_revoked,
        "acceptance_binding": dict(receipt.acceptance_binding or {}),
        "secret_scan": receipt.secret_scan.to_dict(),
        "validation": dict(validation),
    }


def _run_cloud_pack(evidence: Path, credential: bytes) -> Mapping[str, Any]:
    binding = _acceptance_binding()
    vault = InMemoryCloudCredentialVault()
    handle = vault.enroll(credential)
    profile = AwsIdentityLabProfile(
        account_id="111122223333",
        region="us-east-2",
        role_name="BlueFireDisposableIdentityLab",
        credential_handle=handle,
    )
    approval = AwsIdentityLabApproval(
        approval_id="gate03-cloud-identity",
        account_id=profile.account_id,
        role_name=profile.role_name,
    )
    backend = DeterministicAwsIdentityBackend(
        account_id=profile.account_id,
        role_name=profile.role_name,
    )
    pack = AwsIdentityLabPack(credentials=vault, backend=backend)
    store = RunStore(evidence / "runs")
    simulated = pack.simulate(
        SimulateRequest("gate03-cloud-simulate", profile, approval),
        store,
    )
    executed = pack.execute(
        ExecuteRequest("gate03-cloud-execute", profile, approval),
        store,
    )
    simulate_validation = validate_cloud_identity_run_bundle(
        store,
        simulated.run_id,
        expected_mode="simulate",
        expected_acceptance_binding=binding,
    )
    execute_validation = validate_cloud_identity_run_bundle(
        store,
        executed.run_id,
        expected_mode="execute",
        expected_acceptance_binding=binding,
    )
    _require(not vault.contains(handle) and backend.is_clean(), "AWS cleanup did not reconcile")
    bundles = (
        {"run_id": simulated.run_id, "path": f"runs/{simulated.run_id}"},
        {"run_id": executed.run_id, "path": f"runs/{executed.run_id}"},
    )
    return {
        "schema_version": AWS_REPORT_SCHEMA,
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
        "manual_smoke": _manual_smoke_contract(),
        "simulate": _cloud_receipt(simulated, simulate_validation),
        "execute": _cloud_receipt(executed, execute_validation),
        "run_bundles": list(bundles),
    }


def _blocked_summary(check: str) -> Mapping[str, Any]:
    return {
        "schema_version": HELPER_SCHEMA,
        "status": "failed",
        "blocking_check": check,
        "reports": list(JOURNEY_REPORT_PATHS),
        "run_count": 0,
    }


def produce_deep_behavior_gate_evidence(
    repository: Path,
    evidence_dir: Path,
) -> Mapping[str, Any]:
    """Produce six reports and five canonical bundles for GATE-03."""

    root = _safe_root(repository, "repository")
    destination = _safe_root(evidence_dir, "evidence")
    _require(
        not any((destination / name).exists() for name in (*JOURNEY_REPORT_PATHS, "runs")),
        "the GATE-03 evidence destination contains stale owned artifacts",
    )
    wsl = probe_wsl2()
    state = wsl.get("probe_state")
    if state in {"absent", "incompatible"}:
        report = {**linux_unavailable_report(wsl), "scenario_variant": PRIMARY_SCENARIO_VARIANT}
        _write_json(destination / LINUX_PRIMARY_REPORT, report)
        return _blocked_summary("linux_primary")
    _require(
        state == "ready" and wsl.get("configured") is True and wsl.get("version") == "2",
        "the fixed WSL2 readiness probe was indeterminate",
    )
    if linux_wheelhouse_unavailable(root):
        report = {
            **linux_dependencies_unavailable_report(wsl),
            "scenario_variant": PRIMARY_SCENARIO_VARIANT,
        }
        _write_json(destination / LINUX_PRIMARY_REPORT, report)
        return _blocked_summary("linux_primary")

    runtime = Path(tempfile.mkdtemp(prefix=".gate03-runtime-", dir=runtime_temp_parent()))
    credential = secrets.token_bytes(64)
    reports: dict[str, Mapping[str, Any]] = {}
    cleanup_complete = False
    try:
        reports[PACK_REPORT] = official_pack_inventory(root)
        primary = run_linux_journey(
            root,
            destination,
            runtime,
            wsl,
            scenario_variant=PRIMARY_SCENARIO_VARIANT,
        )
        reports[LINUX_PRIMARY_REPORT] = {
            **primary,
            "scenario_variant": PRIMARY_SCENARIO_VARIANT,
        }
        alternate = run_linux_journey(
            root,
            destination,
            runtime,
            wsl,
            scenario_variant=REGISTERED_ALTERNATE_SCENARIO_VARIANT,
        )
        reports[LINUX_ALTERNATE_REPORT] = {
            **alternate,
            "scenario_variant": REGISTERED_ALTERNATE_SCENARIO_VARIANT,
        }
        endpoint_runtime = runtime / "endpoint"
        endpoint_runtime.mkdir()
        reports[ENDPOINT_REPORT] = run_endpoint_pack_journey(root, destination, endpoint_runtime)
        reports[AWS_REPORT] = _run_cloud_pack(destination, credential)
        source_scan = audit_deep_behavior_sources(root)
        bundle_refs = (
            reports[ENDPOINT_REPORT]["run_bundle"],
            reports[LINUX_PRIMARY_REPORT]["run_bundle"],
            reports[LINUX_ALTERNATE_REPORT]["run_bundle"],
            *reports[AWS_REPORT]["run_bundles"],
        )
        bundle_roots = tuple(destination / str(reference["path"]) for reference in bundle_refs)
        _require(len(bundle_roots) == 5, "the GATE-03 run bundle inventory is incomplete")
        runtime_scan = scan_runtime_secret_material(bundle_roots, (credential,))
        reports[SECRET_SCAN_REPORT] = {
            "schema_version": SECRET_SCAN_AGGREGATE_SCHEMA,
            "passed": True,
            "source": source_scan,
            "runtime": runtime_scan,
        }
        for name in JOURNEY_REPORT_PATHS:
            _write_json(destination / name, reports[name])
    except LinuxDependenciesUnavailableError:
        report = {
            **linux_dependencies_unavailable_report(wsl),
            "scenario_variant": PRIMARY_SCENARIO_VARIANT,
        }
        if not (destination / LINUX_PRIMARY_REPORT).exists():
            _write_json(destination / LINUX_PRIMARY_REPORT, report)
        return _blocked_summary("linux_primary")
    finally:
        credential = b""
        if runtime.exists():
            shutil.rmtree(runtime)
        cleanup_complete = not runtime.exists()
        _require(cleanup_complete, "the GATE-03 runtime survived cleanup")
    return {
        "schema_version": HELPER_SCHEMA,
        "status": "passed",
        "blocking_check": None,
        "reports": list(JOURNEY_REPORT_PATHS),
        "run_count": 5,
    }


__all__ = [
    "AWS_REPORT",
    "AWS_REPORT_SCHEMA",
    "DeepBehaviorJourneyError",
    "ENDPOINT_REPORT",
    "HELPER_SCHEMA",
    "JOURNEY_REPORT_PATHS",
    "LINUX_ALTERNATE_REPORT",
    "LINUX_PRIMARY_REPORT",
    "MANUAL_SMOKE_CONTRACT_SCHEMA",
    "PACK_REPORT",
    "SECRET_SCAN_AGGREGATE_SCHEMA",
    "SECRET_SCAN_REPORT",
    "produce_deep_behavior_gate_evidence",
]
