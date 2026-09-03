"""Independent, fail-closed validation for the GATE-03 evidence set."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence, cast

from . import cross_platform_gate_validation as platform_validation
from .cloud_identity_contracts import (
    CONTROL_ACTION,
    CONTROL_TAG_KEY,
    MANUAL_CONFIRMATION,
    REVOCATION_ACTION,
    AwsIdentityLabProfile,
)
from .cloud_identity_contracts import PACK_ID as AWS_PACK_ID
from .cloud_identity_contracts import PROFILE_ID as AWS_PROFILE_ID
from .cloud_identity_manual_smoke import (
    AwsManualSmokeRequest,
    build_aws_identity_lab_smoke_commands,
)
from .cloud_identity_validation import validate_cloud_identity_run_bundle
from .cross_platform_artifact_validation import (
    linux_wheelhouse_unavailable,
    validate_linux_repository_runner,
)
from .cross_platform_linux_bundle_validation import (
    PRIMARY_SCENARIO_VARIANT,
    REGISTERED_ALTERNATE_SCENARIO_VARIANT,
    validate_linux_bundle,
)
from .deep_behavior_endpoint import (
    ENDPOINT_PACK_ID,
    ENDPOINT_PROFILE_ID,
    ENDPOINT_SCHEMA,
)
from .deep_behavior_packs import PACK_REPORT_SCHEMA, official_pack_inventory
from .deep_behavior_secret_scan import (
    RUNTIME_SCAN_SCHEMA,
    SOURCE_SCAN_SCHEMA,
    audit_deep_behavior_sources,
)
from .deep_behavior_validation_primitives import (
    _RUN_ID,
    DeepBehaviorGateValidationError,
    _bundle_stats,
    _digest,
    _mapping,
    _read_report,
    _require,
    _run_reference,
    _runtime_inventory,
)
from .deep_behavior_validation_primitives import _is_unsafe as _is_unsafe
from .deep_behavior_validation_primitives import _strict_object as _strict_object
from .product_acceptance_run_bundle import validated_run_bundle
from .run_store import RunStore, RunStoreError
from .runner_bootstrap import load_runner_manifest
from .util import file_hash

PACK_INVENTORY_REPORT = "pack-inventory.json"
ENDPOINT_EXECUTE_REPORT = "endpoint-execute.json"
LINUX_PRIMARY_REPORT = "linux-primary.json"
LINUX_ALTERNATE_REPORT = "linux-alternate.json"
AWS_IDENTITY_REPORT = "aws-identity.json"
SECRET_SCAN_REPORT = "secret-scan.json"
VERIFICATION_REPORT = "verification.json"

REPORT_PATHS = (
    PACK_INVENTORY_REPORT,
    ENDPOINT_EXECUTE_REPORT,
    LINUX_PRIMARY_REPORT,
    LINUX_ALTERNATE_REPORT,
    AWS_IDENTITY_REPORT,
    SECRET_SCAN_REPORT,
    VERIFICATION_REPORT,
)
JOURNEY_REPORT_PATHS = REPORT_PATHS[:-1]

CHECK_NAMES = frozenset(
    "endpoint_phases authorized_credentials disposable_lateral evasion_telemetry "
    "endpoint_cleanup linux_effects linux_observation linux_alternate_cleanup "
    "cloud_profile_secrets cloud_enum_control cloud_cleanup_audit cloud_simulate_execute "
    "cloud_deterministic_integration cloud_manual_smoke_contract no_raw_credentials".split()
)

ASSERTION_REPORTS: tuple[tuple[str, str, str], ...] = (
    ("GATE-03-ENDPOINT-PHASES", "dynamic", ENDPOINT_EXECUTE_REPORT),
    ("GATE-03-AUTHORIZED-CREDENTIALS", "dynamic", ENDPOINT_EXECUTE_REPORT),
    ("GATE-03-DISPOSABLE-LATERAL", "dynamic", ENDPOINT_EXECUTE_REPORT),
    ("GATE-03-EVASION-TELEMETRY", "dynamic", ENDPOINT_EXECUTE_REPORT),
    ("GATE-03-ENDPOINT-CLEANUP", "dynamic", ENDPOINT_EXECUTE_REPORT),
    ("GATE-03-LINUX-EFFECTS", "dynamic", LINUX_PRIMARY_REPORT),
    ("GATE-03-LINUX-OBSERVATION", "dynamic", LINUX_PRIMARY_REPORT),
    ("GATE-03-LINUX-ALTERNATE-CLEANUP", "dynamic", LINUX_ALTERNATE_REPORT),
    ("GATE-03-CLOUD-PROFILE-SECRETS", "structural", AWS_IDENTITY_REPORT),
    ("GATE-03-CLOUD-ENUM-CONTROL", "dynamic", AWS_IDENTITY_REPORT),
    ("GATE-03-CLOUD-CLEANUP-AUDIT", "dynamic", AWS_IDENTITY_REPORT),
    ("GATE-03-CLOUD-SIMULATE-EXECUTE", "dynamic", AWS_IDENTITY_REPORT),
    ("GATE-03-CLOUD-DETERMINISTIC-INTEGRATION", "dynamic", AWS_IDENTITY_REPORT),
    ("GATE-03-CLOUD-MANUAL-SMOKE-CONTRACT", "structural", AWS_IDENTITY_REPORT),
    ("GATE-03-NO-RAW-CREDENTIALS", "structural", SECRET_SCAN_REPORT),
)

AWS_REPORT_SCHEMA = "bluefire.deep-behavior-aws-identity.v1"
AWS_MANUAL_CONTRACT_SCHEMA = "bluefire.aws-identity-lab-manual-smoke-contract.v1"
AWS_RECEIPT_SCHEMA = "bluefire.aws-identity-lab-run-receipt.v1"
SECRET_REPORT_SCHEMA = "bluefire.deep-behavior-secret-scan.v1"
VERIFICATION_SCHEMA = "bluefire.deep-behavior-gate-verification.v1"
HELPER_SCHEMA = "bluefire.deep-behavior-helper.v1"

_TASK_ID = re.compile(r"^execute-[0-9a-f]{64}$")
_AWS_PROFILE_REFERENCE = re.compile(r"^aws-profile://[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_AWS_KEY = re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}")
_PRIVATE_KEY = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
_SECRET_ASSIGNMENT = re.compile(
    rb"(?i)(?:aws_secret_access_key|secret_access_key|client_secret|refresh_token)"
    rb"[ \t]{0,16}[:=][ \t]{0,16}['\"][A-Za-z0-9/+_=.-]{16,}['\"]"
)
_FORBIDDEN_SECRET_KEYS = frozenset(
    "aws_access_key_id aws_secret_access_key secret_access_key client_secret refresh_token "
    "session_token private_key password".split()
)


def _validate_pack_inventory(repository: Path, value: Mapping[str, Any]) -> None:
    _mapping(
        value,
        {"schema_version", "passed", "manifest", "manifest_sha256", "packs", "inventory_sha256"},
        "pack inventory",
    )
    _require(value.get("schema_version") == PACK_REPORT_SCHEMA, "pack inventory schema is invalid")
    try:
        expected = official_pack_inventory(repository)
    except (OSError, TypeError, ValueError) as exc:
        raise DeepBehaviorGateValidationError("the official pack inventory is invalid") from exc
    _require(
        dict(value) == dict(expected), "pack inventory is not bound to maintained source assets"
    )


def _endpoint_steps(run: Mapping[str, Any]) -> Mapping[str, Mapping[str, Any]]:
    raw_steps = run.get("steps")
    _require(isinstance(raw_steps, list), "endpoint run has no step evidence")
    raw_steps = cast(list[Any], raw_steps)
    steps: dict[str, Mapping[str, Any]] = {}
    for value in raw_steps:
        _require(isinstance(value, Mapping), "an endpoint step is invalid")
        step_id = value.get("step_id")
        _require(
            isinstance(step_id, str) and step_id not in steps, "endpoint step identity is invalid"
        )
        steps[step_id] = value
    expected = set(
        "run_native_canary discover_system discover_processes create_fixture transform_fixture "
        "inspect_fixture_metadata stage_records create_persistence_canary "
        "create_observability_variant authorized_peer_handoff cleanup_workspace".split()
    )
    _require(set(steps) == expected, "endpoint step inventory is not exact")
    return steps


def _endpoint_bundle_facts(store: RunStore, run_id: str) -> Mapping[str, Any]:
    try:
        _require(store.validate_bundle(run_id).get("valid") is True, "endpoint bundle is invalid")
        run = store.get_run(run_id)
    except (OSError, RunStoreError, ValueError) as exc:
        raise DeepBehaviorGateValidationError(
            "endpoint bundle failed integrity validation"
        ) from exc
    steps = _endpoint_steps(run)
    _require(
        run.get("schema_version") == "bluefire.run-result.v1"
        and run.get("scenario_id") == "scenario.endpoint.deep-behavior-lab.v1"
        and run.get("runner_profile_id") == ENDPOINT_PROFILE_ID
        and run.get("mode") == "execute"
        and run.get("status") == "completed"
        and run.get("objective_reached") is True
        and isinstance(run.get("cleanup"), Mapping)
        and run["cleanup"].get("success") is True
        and run["cleanup"].get("outstanding_receipt_count") == 0
        and all(step.get("execution_disposition") == "execute" for step in steps.values())
        and all(step.get("status") in {"success", "partial"} for step in steps.values()),
        "endpoint Execute run did not complete and reconcile",
    )
    peer = steps["authorized_peer_handoff"]
    artifacts = peer.get("artifacts")
    receipt = artifacts.get("receipt") if isinstance(artifacts, Mapping) else None
    authorization = receipt.get("lab_authorization") if isinstance(receipt, Mapping) else None
    peers = receipt.get("lab_peers") if isinstance(receipt, Mapping) else None
    variant_artifacts = steps["create_observability_variant"].get("artifacts")
    variant = variant_artifacts.get("variant") if isinstance(variant_artifacts, Mapping) else None
    _require(
        peer.get("behavior_id") == "sandbox.credential.peer-challenge.v1"
        and peer.get("action_id") == "sandbox.peer.handoff.v1"
        and peer.get("status") == "success"
        and isinstance(peer.get("runner_task_id"), str)
        and _TASK_ID.fullmatch(str(peer["runner_task_id"])) is not None
        and isinstance(authorization, Mapping)
        and authorization.get("scope") == "approved_task"
        and authorization.get("challenge_verified") is True
        and authorization.get("raw_credential_exposed") is False
        and isinstance(peers, Mapping)
        and peers.get("distinct_processes") is True
        and type(peers.get("source_process_id")) is int
        and type(peers.get("destination_process_id")) is int
        and peers.get("source_process_id") != peers.get("destination_process_id")
        and peers.get("transfer_acknowledged") is True,
        "endpoint credential or disposable-peer proof is invalid",
    )
    _require(
        isinstance(variant, Mapping)
        and variant.get("equivalence_verified") is True
        and steps["cleanup_workspace"].get("status") == "success",
        "endpoint telemetry variant or cleanup is invalid",
    )
    return {"run": run, "steps": steps, "peer": peers}


def _validate_endpoint(
    repository: Path, evidence: Path, value: Mapping[str, Any]
) -> tuple[Mapping[str, str], Mapping[str, bool]]:
    _mapping(
        value,
        set(
            "schema_version passed proof_kind pack_id platform environment_type runner execution "
            "phases receiver cleanup credential_scan run_bundle".split()
        ),
        "endpoint Execute report",
    )
    _require(
        value.get("schema_version") == ENDPOINT_SCHEMA
        and value.get("passed") is True
        and value.get("proof_kind") == "dynamic"
        and value.get("pack_id") == ENDPOINT_PACK_ID
        and value.get("platform") == "windows"
        and value.get("environment_type") == "disposable",
        "endpoint Execute report identity is invalid",
    )
    runner = _mapping(
        value.get("runner"),
        {"runner_id", "runner_version", "platform", "binary_sha256", "binary_size"},
        "endpoint runner",
    )
    try:
        manifest = load_runner_manifest(
            resource_root=repository / "bluefire" / "native",
            platform_name="windows",
            architecture="x86_64",
        )
        binary = repository / "bluefire" / "native" / manifest.filename
    except (OSError, TypeError, ValueError) as exc:
        raise DeepBehaviorGateValidationError("packaged endpoint runner is invalid") from exc
    _require(
        runner
        == {
            "runner_id": manifest.runner_id,
            "runner_version": manifest.runner_version,
            "platform": manifest.platform,
            "binary_sha256": "sha256:" + manifest.sha256,
            "binary_size": manifest.size,
        }
        and file_hash(binary) == "sha256:" + manifest.sha256,
        "endpoint report is not bound to the packaged runner",
    )
    bundle = _run_reference(value.get("run_bundle"), "endpoint run bundle")
    execution = _mapping(
        value.get("execution"),
        {"run_id", "status", "objective_reached", "step_count"},
        "endpoint execution",
    )
    _require(
        execution.get("run_id") == bundle["run_id"]
        and execution.get("status") == "completed"
        and execution.get("objective_reached") is True
        and execution.get("step_count") == 11,
        "endpoint execution summary is invalid",
    )
    phases = _mapping(
        value.get("phases"),
        set(
            "execution discovery collection_staging persistence authorized_credentials "
            "disposable_lateral telemetry_shaping cleanup".split()
        ),
        "endpoint phases",
    )
    _require(all(item is True for item in phases.values()), "an endpoint phase is unproven")
    receiver = _mapping(
        value.get("receiver"),
        set(
            "host mode process_id process_distinct process_exited requests_accepted "
            "terminal_disposition".split()
        ),
        "endpoint receiver",
    )
    cleanup = _mapping(
        value.get("cleanup"),
        {"workspace_files_remaining", "receiver_process_exited", "outstanding_receipt_count"},
        "endpoint cleanup",
    )
    _require(
        receiver.get("host") == "127.0.0.1"
        and receiver.get("mode") == "disposable_peer"
        and type(receiver.get("process_id")) is int
        and int(receiver["process_id"]) > 0
        and receiver.get("process_distinct") is True
        and receiver.get("process_exited") is True
        and receiver.get("requests_accepted") == 1
        and receiver.get("terminal_disposition") == "exit_after_response"
        and cleanup
        == {
            "workspace_files_remaining": 0,
            "receiver_process_exited": True,
            "outstanding_receipt_count": 0,
        },
        "endpoint receiver or cleanup proof is invalid",
    )
    store = RunStore(evidence / "runs")
    facts = _endpoint_bundle_facts(store, bundle["run_id"])
    peer = facts["peer"]
    _require(
        isinstance(peer, Mapping)
        and peer.get("destination_process_id") == receiver.get("process_id")
        and len(facts["steps"]) == execution["step_count"],
        "endpoint report is not bound to its run bundle",
    )
    _require(
        value.get("credential_scan") == _bundle_stats(evidence / bundle["path"]),
        "endpoint credential scan is not bound to its run bundle",
    )
    return bundle, {
        "endpoint_phases": True,
        "authorized_credentials": True,
        "disposable_lateral": True,
        "evasion_telemetry": True,
        "endpoint_cleanup": True,
    }


def _validate_linux(
    repository: Path,
    evidence: Path,
    value: Mapping[str, Any],
    *,
    expected_variant: str,
    expected_binding: Mapping[str, str],
) -> tuple[Mapping[str, str], Mapping[str, Any]]:
    expected_keys = set(
        "schema_version passed proof_kind platform environment_type availability boundary runner "
        "execution receiver run_bundle scenario_variant source_intake_publication "
        "watchdog_containment".split()
    )
    _mapping(value, expected_keys, "Linux deep-behavior report")
    _require(value.get("scenario_variant") == expected_variant, "Linux scenario variant is invalid")
    core = dict(value)
    core.pop("scenario_variant")
    try:
        expected_runner = validate_linux_repository_runner(
            repository, expected_binding=expected_binding
        )
        fresh_wsl = platform_validation._reprobe_wsl()
        bundle, execution, _receiver = platform_validation._linux(
            core,
            expected_runner,
            fresh_wsl,
            repository=repository,
        )
        observed = validate_linux_bundle(
            evidence / str(bundle["path"]),
            value,
            scenario_variant=expected_variant,
            require=_require,
        )
    except DeepBehaviorGateValidationError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise DeepBehaviorGateValidationError("Linux deep-behavior proof is invalid") from exc
    _require(dict(observed) == dict(execution), "Linux report diverges from its bundle plan")
    return bundle, execution


def _secret_scan(value: Any, label: str) -> Mapping[str, Any]:
    row = _mapping(
        value,
        {"schema_version", "passed", "files_scanned", "bytes_scanned", "encodings_checked"},
        label,
    )
    encodings = row.get("encodings_checked")
    allowed = {
        "raw",
        "hex-lower",
        "hex-upper",
        "base64",
        "base64-unpadded",
        "base64url",
        "base64url-unpadded",
    }
    _require(
        row.get("schema_version") == "bluefire.secret-material-scan.v1"
        and row.get("passed") is True
        and row.get("files_scanned") == 9
        and type(row.get("bytes_scanned")) is int
        and int(row["bytes_scanned"]) > 0
        and isinstance(encodings, list)
        and encodings == sorted(set(encodings))
        and {"raw", "hex-lower", "hex-upper", "base64"} <= set(encodings) <= allowed,
        f"{label} is invalid",
    )
    return row


def _cloud_evidence(
    store: RunStore, run_id: str, mode: str, profile: AwsIdentityLabProfile
) -> None:
    evidence = store.read_json(run_id, "evidence.json")
    records = evidence.get("records")
    _require(isinstance(records, list) and len(records) == 4, "cloud evidence is incomplete")
    records = cast(list[Mapping[str, Any]], records)
    expected_interface = "Simulate" if mode == "simulate" else "Execute"
    _require(
        [row.get("phase") for row in records if isinstance(row, Mapping)]
        == ["enumeration", "action", "revocation", "audit"]
        and all(
            isinstance(row, Mapping) and row.get("interface") == expected_interface
            for row in records
        ),
        "cloud evidence phases are invalid",
    )
    enumeration = records[0].get("enumeration")
    _require(
        isinstance(enumeration, Mapping)
        and set(enumeration) == {"account_id", "principal_arn", "role_arns"}
        and enumeration.get("account_id") == profile.account_id
        and isinstance(enumeration.get("principal_arn"), str)
        and str(enumeration["principal_arn"]).startswith(f"arn:aws:sts::{profile.account_id}:")
        and isinstance(enumeration.get("role_arns"), list)
        and profile.role_arn in enumeration["role_arns"]
        and enumeration["role_arns"] == sorted(set(enumeration["role_arns"])),
        "cloud enumeration is not bound to the approved lab target",
    )
    action, revocation, audit = records[1:]
    _require(
        action.get("action") == CONTROL_ACTION
        and action.get("role_arn") == profile.role_arn
        and action.get("tag_key") == CONTROL_TAG_KEY
        and revocation.get("action") == REVOCATION_ACTION,
        "cloud control action or revocation is invalid",
    )
    if mode == "simulate":
        _require(
            records[0].get("fixture") == "deterministic-local-aws.v1"
            and action.get("effect") == "predicted"
            and revocation.get("effect") == "predicted-clean"
            and audit.get("expected_events")
            == ["ListRoles", "TagRole", "ListRoleTags", "UntagRole"]
            and audit.get("verified") is True,
            "cloud Simulate fixture is invalid",
        )
    else:
        events = audit.get("events")
        expected_events = [
            ("enumeration", "ListRoles"),
            ("action", "TagRole"),
            ("audit", "ListRoleTags"),
            ("revocation", "UntagRole"),
            ("audit", "GetRoleCleanupState"),
        ]
        _require(
            records[0].get("backend") == "deterministic-local-aws.v1"
            and action.get("changed") is True
            and revocation.get("removed") is True
            and revocation.get("role_arn") == profile.role_arn
            and revocation.get("tag_key") == CONTROL_TAG_KEY
            and isinstance(events, list)
            and len(events) == len(expected_events)
            and all(
                isinstance(event, Mapping)
                and set(event) == {"sequence", "phase", "event_name", "account_id", "role_arn"}
                and event.get("sequence") == index
                and (event.get("phase"), event.get("event_name")) == expected
                and event.get("account_id") == profile.account_id
                and event.get("role_arn") == profile.role_arn
                for index, (event, expected) in enumerate(
                    zip(events, expected_events, strict=True), start=1
                )
            )
            and audit.get("verified") is True,
            "cloud Execute audit or cleanup evidence is invalid",
        )


def _validate_cloud_summary(
    evidence: Path,
    value: Any,
    *,
    mode: str,
    profile: AwsIdentityLabProfile,
    expected_binding: Mapping[str, str],
) -> Mapping[str, str]:
    row = _mapping(
        value,
        set(
            "schema_version mode run_id bundle_hash cleanup_verified audit_verified "
            "credential_revoked acceptance_binding secret_scan validation".split()
        ),
        f"AWS {mode} summary",
    )
    run_id = row.get("run_id")
    _require(
        row.get("schema_version") == AWS_RECEIPT_SCHEMA
        and row.get("mode") == mode
        and isinstance(run_id, str)
        and _RUN_ID.fullmatch(run_id) is not None
        and row.get("cleanup_verified") is True
        and row.get("audit_verified") is True
        and row.get("credential_revoked") is (mode == "execute")
        and row.get("acceptance_binding") == expected_binding,
        f"AWS {mode} summary is invalid",
    )
    run_id = cast(str, run_id)
    _digest(row.get("bundle_hash"), f"AWS {mode} bundle hash")
    _secret_scan(row.get("secret_scan"), f"AWS {mode} credential scan")
    store = RunStore(evidence / "runs")
    try:
        validation = validate_cloud_identity_run_bundle(
            store,
            run_id,
            expected_mode=mode,
            expected_acceptance_binding=expected_binding,
        )
        _cloud_evidence(store, run_id, mode, profile)
        persisted_profile = store.read_json(run_id, "profile.json")
    except (OSError, RunStoreError, TypeError, ValueError) as exc:
        raise DeepBehaviorGateValidationError(f"AWS {mode} bundle is invalid") from exc
    _require(
        row.get("validation") == validation
        and row.get("bundle_hash") == validation.get("bundle_hash")
        and persisted_profile == profile.to_dict(),
        f"AWS {mode} summary is not bound to its canonical bundle",
    )
    return {"run_id": run_id, "path": f"runs/{run_id}"}


def _validate_manual_contract(value: Any, profile: AwsIdentityLabProfile) -> None:
    row = _mapping(
        value,
        {
            "schema_version",
            "credential_reference",
            "operations",
            "shell",
            "timeout_seconds",
            "external_execution",
        },
        "AWS manual smoke contract",
    )
    reference = row.get("credential_reference")
    timeout = row.get("timeout_seconds")
    _require(
        row.get("schema_version") == AWS_MANUAL_CONTRACT_SCHEMA
        and isinstance(reference, str)
        and _AWS_PROFILE_REFERENCE.fullmatch(reference) is not None
        and row.get("shell") is False
        and type(timeout) is int
        and 1 <= int(timeout) <= 30
        and row.get("external_execution") is False,
        "AWS manual smoke contract identity is invalid",
    )
    timeout = cast(int, timeout)
    credential_profile = str(reference).removeprefix("aws-profile://")
    try:
        request = AwsManualSmokeRequest(
            credential_profile=credential_profile,
            account_id=profile.account_id,
            role_name=profile.role_name,
            region=profile.region,
            approval_id="gate03-manual-contract",
            approved_account_id=profile.account_id,
            approved_role_name=profile.role_name,
            confirmation=MANUAL_CONFIRMATION,
            timeout_seconds=timeout,
        )
        commands = build_aws_identity_lab_smoke_commands(request)
    except (TypeError, ValueError) as exc:
        raise DeepBehaviorGateValidationError("AWS manual smoke contract is invalid") from exc
    _require(
        row.get("operations") == [command.operation for command in commands]
        and len(commands) == 8
        and all(command.argv[0] == "aws" and len(command.argv) <= 20 for command in commands),
        "AWS manual smoke operation inventory is not fixed",
    )


def _validate_aws(
    evidence: Path,
    value: Mapping[str, Any],
    *,
    expected_binding: Mapping[str, str],
) -> tuple[tuple[Mapping[str, str], Mapping[str, str]], Mapping[str, bool]]:
    _mapping(
        value,
        set(
            "schema_version passed proof_kind pack_id profile credential_binding manual_smoke "
            "simulate execute run_bundles".split()
        ),
        "AWS identity report",
    )
    _require(
        value.get("schema_version") == AWS_REPORT_SCHEMA
        and value.get("passed") is True
        and value.get("proof_kind") == "dynamic"
        and value.get("pack_id") == AWS_PACK_ID,
        "AWS identity report is invalid",
    )
    try:
        profile = AwsIdentityLabProfile.from_mapping(value.get("profile"))
    except (TypeError, ValueError) as exc:
        raise DeepBehaviorGateValidationError("AWS lab profile is invalid") from exc
    _require(
        profile.profile_id == AWS_PROFILE_ID,
        "AWS report does not use the explicit lab profile",
    )
    binding = _mapping(
        value.get("credential_binding"),
        {"handle_prefix", "opaque", "raw_material_persisted", "handle_revoked"},
        "AWS credential binding",
    )
    _require(
        binding
        == {
            "handle_prefix": "credential-",
            "opaque": True,
            "raw_material_persisted": False,
            "handle_revoked": True,
        }
        and profile.credential_handle.startswith(str(binding["handle_prefix"])),
        "AWS opaque credential binding or revocation is invalid",
    )
    _validate_manual_contract(value.get("manual_smoke"), profile)
    simulated = _validate_cloud_summary(
        evidence,
        value.get("simulate"),
        mode="simulate",
        profile=profile,
        expected_binding=expected_binding,
    )
    executed = _validate_cloud_summary(
        evidence,
        value.get("execute"),
        mode="execute",
        profile=profile,
        expected_binding=expected_binding,
    )
    raw_bundles = value.get("run_bundles")
    _require(
        isinstance(raw_bundles, list) and len(raw_bundles) == 2, "AWS run bundles are incomplete"
    )
    raw_bundles = cast(list[Any], raw_bundles)
    bundles = tuple(_run_reference(raw, "AWS run bundle") for raw in raw_bundles)
    _require(
        bundles == (simulated, executed) and simulated["run_id"] != executed["run_id"],
        "AWS Simulate and Execute require distinct canonical bundles",
    )
    return (simulated, executed), {
        "cloud_profile_secrets": True,
        "cloud_enum_control": True,
        "cloud_cleanup_audit": True,
        "cloud_simulate_execute": True,
        "cloud_deterministic_integration": True,
        "cloud_manual_smoke_contract": True,
    }


def _forbid_secret_shapes(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            _require(
                str(key).casefold() not in _FORBIDDEN_SECRET_KEYS,
                "persisted evidence contains a raw credential field",
            )
            if str(key) == "raw_credential_exposed":
                _require(item is False, "endpoint evidence claims raw credential exposure")
            _forbid_secret_shapes(item)
    elif isinstance(value, list):
        for item in value:
            _forbid_secret_shapes(item)
    elif isinstance(value, str):
        payload = value.encode("utf-8", errors="strict")
        _require(
            _AWS_KEY.search(payload) is None
            and _PRIVATE_KEY.search(payload) is None
            and _SECRET_ASSIGNMENT.search(payload) is None,
            "persisted evidence contains credential-shaped material",
        )


def _validate_secret_report(
    repository: Path,
    value: Mapping[str, Any],
    bundle_paths: Sequence[Path],
) -> None:
    _mapping(value, {"schema_version", "passed", "source", "runtime"}, "secret scan report")
    _require(
        value.get("schema_version") == SECRET_REPORT_SCHEMA and value.get("passed") is True,
        "secret scan report identity is invalid",
    )
    source = _mapping(
        value.get("source"),
        set(
            "schema_version passed files files_scanned bytes_scanned forbidden_matches "
            "source_inventory_sha256".split()
        ),
        "source credential scan",
    )
    _require(source.get("schema_version") == SOURCE_SCAN_SCHEMA, "source scan schema is invalid")
    try:
        expected_source = audit_deep_behavior_sources(repository)
    except (OSError, TypeError, ValueError) as exc:
        raise DeepBehaviorGateValidationError(
            "deep-behavior sources failed credential audit"
        ) from exc
    _require(dict(source) == dict(expected_source), "source scan is not bound to maintained files")
    runtime = _mapping(
        value.get("runtime"),
        set(
            "schema_version passed files_scanned bytes_scanned secret_count "
            "artifact_digest_set_sha256 matches".split()
        ),
        "runtime credential scan",
    )
    inventory = _runtime_inventory(bundle_paths)
    _require(
        runtime.get("schema_version") == RUNTIME_SCAN_SCHEMA
        and runtime.get("passed") is True
        and type(runtime.get("secret_count")) is int
        and 1 <= int(runtime["secret_count"]) <= 64
        and runtime.get("matches") == 0
        and {key: runtime.get(key) for key in inventory} == inventory,
        "runtime credential scan is not bound to all five bundles",
    )


def _bundle_binding(evidence: Path, bundle: Mapping[str, str]) -> Mapping[str, str]:
    try:
        run = RunStore(evidence / "runs").get_run(bundle["run_id"])
    except (OSError, RunStoreError, ValueError) as exc:
        raise DeepBehaviorGateValidationError("a GATE-03 run bundle is invalid") from exc
    raw = run.get("acceptance_binding")
    _require(isinstance(raw, Mapping), "a GATE-03 run has no acceptance binding")
    raw = cast(Mapping[str, Any], raw)
    expected = set(
        "schema_version acceptance_id gate_id contract_sha256 repository_commit "
        "repository_tree release".split()
    )
    _require(set(raw) == expected and raw.get("gate_id") == "GATE-03", "run binding is invalid")
    return {str(key): str(value) for key, value in raw.items()}


def _normalize_bundles(
    evidence: Path,
    bundles: Sequence[Mapping[str, str]],
    *,
    expected_binding: Mapping[str, str],
    not_before: datetime | None,
    not_after: datetime | None,
) -> tuple[Mapping[str, str], ...]:
    normalized: list[Mapping[str, str]] = []
    for bundle in bundles:
        if not_before is not None and not_after is not None:
            try:
                _item, _artifact = validated_run_bundle(
                    evidence,
                    evidence.parent,
                    bundle,
                    expected_binding=expected_binding,
                    not_before=not_before,
                    not_after=not_after,
                )
            except (OSError, ValueError) as exc:
                raise DeepBehaviorGateValidationError(
                    "a GATE-03 bundle is stale or unbound"
                ) from exc
            normalized.append(dict(bundle))
        else:
            store = RunStore(evidence / "runs")
            try:
                validation = store.validate_bundle(bundle["run_id"])
            except (OSError, RunStoreError, ValueError) as exc:
                raise DeepBehaviorGateValidationError("a GATE-03 bundle failed validation") from exc
            manifest = validation.get("manifest")
            _require(
                validation.get("valid") is True and isinstance(manifest, Mapping),
                "a GATE-03 bundle failed validation",
            )
            normalized.append(dict(bundle))
    return tuple(normalized)


def validate_deep_behavior_reports(
    evidence_dir: Path,
    repository_root: Path,
    *,
    expected_binding: Mapping[str, str] | None = None,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> tuple[Mapping[str, bool], tuple[Mapping[str, str], ...]]:
    """Validate the six journey reports and exactly five canonical run bundles."""
    evidence = evidence_dir.resolve(strict=True)
    repository = repository_root.resolve(strict=True)
    _require(
        evidence.is_dir() and repository.is_dir(), "GATE-03 evidence or repository root is invalid"
    )
    _require(
        (not_before is None) == (not_after is None),
        "GATE-03 freshness bounds must be supplied together",
    )
    reports = {name: _read_report(evidence, name) for name in JOURNEY_REPORT_PATHS}
    _validate_pack_inventory(repository, reports[PACK_INVENTORY_REPORT])
    endpoint_bundle, endpoint_checks = _validate_endpoint(
        repository, evidence, reports[ENDPOINT_EXECUTE_REPORT]
    )
    binding = (
        dict(expected_binding)
        if expected_binding is not None
        else dict(_bundle_binding(evidence, endpoint_bundle))
    )
    _require(binding.get("gate_id") == "GATE-03", "acceptance binding is not for GATE-03")
    primary_bundle, _primary = _validate_linux(
        repository,
        evidence,
        reports[LINUX_PRIMARY_REPORT],
        expected_variant=PRIMARY_SCENARIO_VARIANT,
        expected_binding=binding,
    )
    alternate_bundle, _alternate = _validate_linux(
        repository,
        evidence,
        reports[LINUX_ALTERNATE_REPORT],
        expected_variant=REGISTERED_ALTERNATE_SCENARIO_VARIANT,
        expected_binding=binding,
    )
    aws_bundles, aws_checks = _validate_aws(
        evidence, reports[AWS_IDENTITY_REPORT], expected_binding=binding
    )
    bundles = (endpoint_bundle, primary_bundle, alternate_bundle, *aws_bundles)
    _require(
        len(bundles) == 5 and len({bundle["run_id"] for bundle in bundles}) == 5,
        "GATE-03 requires exactly five distinct run bundles",
    )
    for bundle in bundles:
        _require(
            _bundle_binding(evidence, bundle) == binding,
            "GATE-03 run bundles do not share the acceptance binding",
        )
    bundle_paths = [evidence / bundle["path"] for bundle in bundles]
    _validate_secret_report(repository, reports[SECRET_SCAN_REPORT], bundle_paths)
    for report in reports.values():
        _forbid_secret_shapes(report)
    checks = {
        **endpoint_checks,
        "linux_effects": True,
        "linux_observation": True,
        "linux_alternate_cleanup": True,
        **aws_checks,
        "no_raw_credentials": True,
    }
    _require(set(checks) == CHECK_NAMES and all(checks.values()), "GATE-03 checks are incomplete")
    normalized = _normalize_bundles(
        evidence, bundles, expected_binding=binding, not_before=not_before, not_after=not_after
    )
    return checks, normalized


def validate_linux_unavailable_report(
    evidence_dir: Path,
    repository_root: Path,
) -> str:
    """Validate the only typed helper failure allowed before generic failure handling."""
    evidence = evidence_dir.resolve(strict=True)
    repository = repository_root.resolve(strict=True)
    _require(
        {item.name for item in evidence.iterdir()} == {LINUX_PRIMARY_REPORT},
        "typed Linux unavailability retained unrelated evidence",
    )
    report = _read_report(evidence, LINUX_PRIMARY_REPORT)
    _require(
        report.get("scenario_variant") == PRIMARY_SCENARIO_VARIANT,
        "typed Linux unavailability is not for the primary scenario",
    )
    core = dict(report)
    core.pop("scenario_variant", None)
    try:
        dependency_unavailable = linux_wheelhouse_unavailable(repository)
        platform_validation._linux(
            core,
            {},
            platform_validation._reprobe_wsl(),
            dependency_unavailable=dependency_unavailable,
            repository=repository,
        )
    except platform_validation.LinuxRuntimeUnavailableError as exc:
        return str(exc)
    except (OSError, TypeError, ValueError) as exc:
        raise DeepBehaviorGateValidationError("typed Linux unavailability is invalid") from exc
    raise DeepBehaviorGateValidationError(
        "Linux primary report did not declare typed unavailability"
    )


def validate_deep_behavior_verification(
    evidence_dir: Path,
    *,
    expected_checks: Mapping[str, bool],
    expected_run_ids: Sequence[str],
    expected_suite_tests: Sequence[str],
) -> None:
    """Validate the gate-owned report written after journey and suite validation."""
    value = _read_report(evidence_dir.resolve(strict=True), VERIFICATION_REPORT)
    row = _mapping(
        value,
        set("schema_version passed helper suite checks run_ids reports proof_kinds".split()),
        "GATE-03 verification report",
    )
    helper = _mapping(
        row.get("helper"),
        set(
            "schema_version status reports run_count "
            "blocking_check exit_code command protocol_valid".split()
        ),
        "GATE-03 helper verification",
    )
    suite = _mapping(
        row.get("suite"),
        set(
            "schema_version suite_id command exit_code passed "
            "tests passed_tests failed_tests skipped_tests".split()
        ),
        "GATE-03 contract-suite verification",
    )
    tests = list(expected_suite_tests)
    _require(
        row.get("schema_version") == VERIFICATION_SCHEMA
        and row.get("passed") is True
        and helper.get("schema_version") == HELPER_SCHEMA
        and helper.get("status") == "passed"
        and helper.get("reports") == list(JOURNEY_REPORT_PATHS)
        and helper.get("run_count") == 5
        and helper.get("blocking_check") is None
        and helper.get("exit_code") == 0
        and helper.get("command")
        == ["{python}", "tools/run_deep_behavior_gate_journey.py", "{fixed-arguments}"]
        and helper.get("protocol_valid") is True
        and suite.get("schema_version") == "bluefire.architecture-dynamic-check.v1"
        and suite.get("suite_id") == "deep-behavior-contracts"
        and suite.get("exit_code") == 0
        and suite.get("passed") is True
        and suite.get("tests") == len(tests)
        and suite.get("passed_tests") == tests
        and suite.get("failed_tests") == []
        and suite.get("skipped_tests") == []
        and row.get("checks") == dict(expected_checks)
        and row.get("run_ids") == list(expected_run_ids)
        and row.get("reports") == list(JOURNEY_REPORT_PATHS)
        and row.get("proof_kinds") == ["dynamic", "structural"],
        "GATE-03 verification metadata is inconsistent",
    )


__all__ = """ASSERTION_REPORTS AWS_IDENTITY_REPORT AWS_MANUAL_CONTRACT_SCHEMA AWS_REPORT_SCHEMA
CHECK_NAMES DeepBehaviorGateValidationError ENDPOINT_EXECUTE_REPORT HELPER_SCHEMA
JOURNEY_REPORT_PATHS LINUX_ALTERNATE_REPORT LINUX_PRIMARY_REPORT PACK_INVENTORY_REPORT
REPORT_PATHS SECRET_REPORT_SCHEMA SECRET_SCAN_REPORT VERIFICATION_REPORT VERIFICATION_SCHEMA
validate_deep_behavior_reports validate_deep_behavior_verification
validate_linux_unavailable_report""".split()
