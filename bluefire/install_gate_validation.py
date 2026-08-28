"""Strict persisted-evidence validation for the Gate 01 release workflow."""

from __future__ import annotations

import re
from typing import Any, Mapping

_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
_APPROVAL_ID = re.compile(r"^approval-[0-9a-f]{32}$")
_JOB_ID = re.compile(r"^job-[0-9a-f]{32}$")
_REQUIRED_DISTRIBUTIONS = frozenset({"PyYAML", "cryptography", "PyNaCl", "cffi", "pycparser"})
_EXPECTED_RUNTIME_REQUIREMENTS = [
    {"name": "cryptography", "specifier": "<47,>=45"},
    {"name": "pynacl", "specifier": "<2,>=1.5"},
    {"name": "pyyaml", "specifier": "<7,>=6.0.1"},
]
_RUNTIME_VERSION_RANGES = {
    "PyYAML": ((6, 0, 1), (7,)),
    "cryptography": ((45,), (47,)),
    "PyNaCl": ((1, 5), (2,)),
}


def bounded_failure_message(error: BaseException) -> str:
    message = " ".join(str(error).split())
    if (
        not message
        or len(message) > 240
        or "\\" in message
        or "/" in message
        or re.search(r"(?:^|\s)[A-Za-z]:", message) is not None
    ):
        return "Gate 01 workflow failed without a bounded diagnostic"
    return message


def _mapping(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError(f"{label} fields do not match the Gate 01 contract")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} digest is invalid")
    return value


def validate_inspection(report: Mapping[str, Any]) -> None:
    root = _mapping(
        report,
        {
            "schema_version",
            "wheel",
            "wheel_sha256",
            "tag",
            "platform",
            "architecture",
            "runner",
            "verified",
        },
        "package inspection",
    )
    runner = _mapping(root["runner"], {"filename", "size", "sha256"}, "inspected runner")
    if (
        root["schema_version"] != "bluefire.package-inspection.v1"
        or root["verified"] is not True
        or root["platform"] != "windows"
        or root["architecture"] not in {"x86_64", "aarch64"}
        or root["tag"]
        != ("py3-none-win_amd64" if root["architecture"] == "x86_64" else "py3-none-win_arm64")
        or not isinstance(root["wheel"], str)
        or not root["wheel"].endswith(".whl")
        or not isinstance(root["wheel_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", root["wheel_sha256"]) is None
        or runner["filename"] != "bluefire-runner.exe"
        or type(runner["size"]) is not int
        or runner["size"] <= 0
        or not isinstance(runner["sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", runner["sha256"]) is None
    ):
        raise ValueError("package inspection did not verify the Windows native wheel")


def validate_wheel_dependency_metadata(report: Mapping[str, Any]) -> None:
    root = _mapping(
        report,
        {
            "schema_version",
            "verified",
            "project_name",
            "project_version",
            "requires_python",
            "wheel_sha256",
            "declared_runtime_dependencies",
            "wheel_requires_dist",
        },
        "wheel dependency metadata",
    )
    if (
        root["schema_version"] != "bluefire.gate01-wheel-dependency-metadata.v1"
        or root["verified"] is not True
        or root["project_name"] != "bluefire-nexus"
        or not isinstance(root["project_version"], str)
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", root["project_version"])
        is None
        or root["requires_python"] != ">=3.10"
        or root["declared_runtime_dependencies"] != _EXPECTED_RUNTIME_REQUIREMENTS
        or root["wheel_requires_dist"] != _EXPECTED_RUNTIME_REQUIREMENTS
    ):
        raise ValueError("built wheel dependency metadata proof is invalid")
    _digest(root["wheel_sha256"], "built wheel")
    for index, raw in enumerate(root["wheel_requires_dist"]):
        _mapping(raw, {"name", "specifier"}, f"wheel requirement {index}")


def validate_wheel_metadata_binding(
    inspection: Mapping[str, Any], metadata: Mapping[str, Any]
) -> None:
    validate_inspection(inspection)
    validate_wheel_dependency_metadata(metadata)
    if metadata["wheel_sha256"] != "sha256:" + str(inspection["wheel_sha256"]):
        raise ValueError("wheel dependency metadata is not bound to the inspected wheel")


def validate_dependency_provision(report: Mapping[str, Any]) -> None:
    root = _mapping(
        report,
        {
            "schema_version",
            "verified",
            "method",
            "isolated_environment",
            "wheel_sha256",
            "wheel_requirements_satisfied",
            "distributions",
        },
        "dependency provision",
    )
    distributions = root["distributions"]
    if (
        root["schema_version"] != "bluefire.gate01-dependency-provision.v1"
        or root["verified"] is not True
        or root["method"] != "copied-verified-installed-distributions"
        or root["isolated_environment"] is not True
        or root["wheel_requirements_satisfied"] is not True
        or not isinstance(distributions, Mapping)
        or set(distributions) != _REQUIRED_DISTRIBUTIONS
    ):
        raise ValueError("fresh dependency provision report is invalid")
    _digest(root["wheel_sha256"], "provisioned dependency wheel")
    for name, raw in distributions.items():
        row = _mapping(raw, {"version", "file_count", "content_digest"}, f"{name} provision")
        if (
            not isinstance(row["version"], str)
            or not row["version"]
            or type(row["file_count"]) is not int
            or row["file_count"] <= 0
        ):
            raise ValueError(f"{name} provision is incomplete")
        _digest(row["content_digest"], f"{name} provision")


def _release_version(value: Any) -> tuple[int, ...]:
    if not isinstance(value, str) or re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", value) is None:
        raise ValueError("provisioned runtime dependency version is invalid")
    return tuple(int(part) for part in value.split("."))


def _version_at_least(value: tuple[int, ...], boundary: tuple[int, ...]) -> bool:
    size = max(len(value), len(boundary))
    return value + (0,) * (size - len(value)) >= boundary + (0,) * (size - len(boundary))


def validate_dependency_provision_binding(
    metadata: Mapping[str, Any], provision: Mapping[str, Any]
) -> None:
    validate_wheel_dependency_metadata(metadata)
    validate_dependency_provision(provision)
    if provision["wheel_sha256"] != metadata["wheel_sha256"]:
        raise ValueError("provisioned dependencies are not bound to the built wheel")
    distributions = provision["distributions"]
    for name, (minimum, maximum) in _RUNTIME_VERSION_RANGES.items():
        version = _release_version(distributions[name]["version"])
        if not _version_at_least(version, minimum) or _version_at_least(version, maximum):
            raise ValueError(f"{name} does not satisfy the built wheel runtime requirement")


def validate_dependency_runtime_binding(
    metadata: Mapping[str, Any],
    provision: Mapping[str, Any],
    runtime: Mapping[str, Any],
) -> None:
    validate_wheel_dependency_metadata(metadata)
    validate_dependency_provision(provision)
    validate_package_runtime(runtime)
    if runtime["package_version"] != metadata["project_version"]:
        raise ValueError("installed BlueFire version does not match the built wheel")
    installed = runtime["dependencies"]
    for name in _RUNTIME_VERSION_RANGES:
        if installed[name] != provision["distributions"][name]["version"]:
            raise ValueError(f"{name} runtime version does not match its provisioned files")


def validate_package_runtime(report: Mapping[str, Any]) -> None:
    root = _mapping(
        report,
        {
            "schema_version",
            "verified",
            "package_version",
            "fresh_environment",
            "dependencies",
            "source_overrides_absent",
        },
        "installed package runtime",
    )
    environment = _mapping(
        root["fresh_environment"],
        {
            "isolated_mode",
            "virtual_environment",
            "user_site_enabled",
            "package_under_environment_site",
            "checkout_on_import_path",
            "editable_install",
            "console_entrypoint",
        },
        "fresh environment",
    )
    dependencies = root["dependencies"]
    if (
        root["schema_version"] != "bluefire.gate01-installed-package.v1"
        or root["verified"] is not True
        or not isinstance(root["package_version"], str)
        or not root["package_version"]
        or root["source_overrides_absent"] is not True
        or environment
        != {
            "isolated_mode": True,
            "virtual_environment": True,
            "user_site_enabled": False,
            "package_under_environment_site": True,
            "checkout_on_import_path": False,
            "editable_install": False,
            "console_entrypoint": True,
        }
        or not isinstance(dependencies, Mapping)
        or set(dependencies) != {"PyYAML", "cryptography", "PyNaCl"}
        or any(not isinstance(version, str) or not version for version in dependencies.values())
    ):
        raise ValueError("installed package runtime proof is invalid")


def validate_ui(report: Mapping[str, Any]) -> None:
    root = _mapping(
        report,
        {"schema_version", "verified", "launch", "assets", "api", "runtime_probe"},
        "UI",
    )
    launch = _mapping(
        root["launch"],
        {
            "command",
            "loopback_only",
            "ephemeral_port",
            "capability_fragment_only",
            "capability_single_use",
            "strict_session_cookie",
        },
        "UI launch",
    )
    assets = root["assets"]
    api = _mapping(
        root["api"],
        {"session_healthy", "catalog_behavior_count", "scenario_count", "seeded_scenario_present"},
        "UI API",
    )
    runtime_probe = _mapping(
        root["runtime_probe"],
        {
            "engine",
            "browser_sandbox",
            "network_scope",
            "javascript_executed",
            "authenticated_root_rendered",
            "catalog_data_rendered",
            "runs_navigation_present",
            "runs_route_rendered",
            "guided_execute_rendered",
        },
        "UI runtime probe",
    )
    if (
        root["schema_version"] != "bluefire.gate01-ui-health.v1"
        or root["verified"] is not True
        or launch["command"]
        != [
            "{python}",
            "-I",
            "-m",
            "bluefire.cli",
            "--runs-dir",
            "{runs-dir}",
            "ui",
            "--host",
            "127.0.0.1",
            "--port",
            "0",
        ]
        or any(launch[field] is not True for field in set(launch) - {"command"})
        or not isinstance(assets, Mapping)
        or set(assets) != {"/ui/app.js", "/ui/styles.css"}
        or api["session_healthy"] is not True
        or type(api["catalog_behavior_count"]) is not int
        or api["catalog_behavior_count"] <= 0
        or type(api["scenario_count"]) is not int
        or api["scenario_count"] <= 0
        or api["seeded_scenario_present"] is not True
        or runtime_probe
        != {
            "engine": "edge-headless",
            "browser_sandbox": "disabled-for-ephemeral-probe",
            "network_scope": "loopback-only",
            "javascript_executed": True,
            "authenticated_root_rendered": True,
            "catalog_data_rendered": True,
            "runs_navigation_present": True,
            "runs_route_rendered": True,
            "guided_execute_rendered": True,
        }
    ):
        raise ValueError("production UI health proof is invalid")
    for raw in assets.values():
        asset = _mapping(raw, {"size_bytes", "sha256"}, "UI asset")
        if type(asset["size_bytes"]) is not int or asset["size_bytes"] < 512:
            raise ValueError("production UI asset is too small")
        _digest(asset["sha256"], "UI asset")


def _approval_binding(raw: Any, label: str) -> Mapping[str, Any]:
    binding = _mapping(
        raw,
        {
            "state_digest",
            "plan_digest",
            "target_scope_digest",
            "profile_id",
            "maximum_tier",
        },
        label,
    )
    for field in ("state_digest", "plan_digest", "target_scope_digest"):
        _digest(binding[field], f"{label} {field}")
    if (
        binding["profile_id"] != "sandbox-restricted-owned.v1"
        or binding["maximum_tier"] != "restricted"
    ):
        raise ValueError(f"{label} profile boundary is invalid")
    return binding


def _validate_run(
    raw: Any,
    *,
    replay_of: str | None,
    expected_operator: str,
) -> tuple[str, str, Mapping[str, Any]]:
    run = _mapping(
        raw,
        {
            "run_id",
            "status",
            "objective_reached",
            "step_count",
            "evidence_provenance",
            "cleanup",
            "approval_status",
            "replay_source_run_id",
            "scenario_id",
            "runner_profile_id",
            "scope_refs",
            "approval_id",
            "approval_binding",
            "approval_operator",
            "observation",
            "residual_canary_absent",
        },
        "journey run",
    )
    run_id = run["run_id"]
    approval_id = run["approval_id"]
    binding = _approval_binding(run["approval_binding"], "journey run approval binding")
    cleanup = _mapping(
        run["cleanup"],
        {"attempted", "success", "outstanding_receipt_count"},
        "journey cleanup",
    )
    observation = _mapping(
        run["observation"],
        {
            "producer",
            "collector_id",
            "artifact_path",
            "artifact_digest",
            "parent_linked",
        },
        "journey observation",
    )
    _digest(observation["artifact_digest"], "journey observation artifact")
    if (
        not isinstance(run_id, str)
        or _RUN_ID.fullmatch(run_id) is None
        or run["status"] != "completed"
        or run["objective_reached"] is not True
        or run["step_count"] != 2
        or run["evidence_provenance"] != ["executed", "observed"]
        or cleanup != {"attempted": True, "success": True, "outstanding_receipt_count": 0}
        or run["approval_status"] != "claimed"
        or run["replay_source_run_id"] != replay_of
        or run["scenario_id"] != "scenario.restricted.persistence-canary.v1"
        or run["runner_profile_id"] != "sandbox-restricted-owned.v1"
        or run["scope_refs"] != ["sandbox.workspace"]
        or not isinstance(approval_id, str)
        or _APPROVAL_ID.fullmatch(approval_id) is None
        or run["approval_operator"] != expected_operator
        or observation
        != {
            "producer": "collector.filesystem.sandbox.v1",
            "collector_id": "collector.filesystem.sandbox.v1",
            "artifact_path": "restricted/persistence-marker.json",
            "artifact_digest": observation["artifact_digest"],
            "parent_linked": True,
        }
        or run["residual_canary_absent"] is not True
    ):
        raise ValueError("journey run proof is invalid")
    return run_id, approval_id, binding


def validate_journey(report: Mapping[str, Any]) -> tuple[str, str]:
    root = _mapping(
        report,
        {
            "schema_version",
            "verified",
            "selection",
            "packaged_runner",
            "local_trust",
            "preflight",
            "approval_job",
            "source_run",
            "replay_run",
            "fresh_replay_approval",
            "comparison",
            "teardown",
        },
        "journey",
    )
    selection = _mapping(
        root["selection"],
        {"scenario_id", "runner_profile_id", "collector_id", "scope_refs"},
        "journey selection",
    )
    runner = _mapping(
        root["packaged_runner"],
        {
            "source",
            "managed_binary",
            "managed_sandbox",
            "runner_id",
            "bootstrap_state",
            "recovery_reused_exact_identity",
            "binary_digest",
        },
        "journey runner",
    )
    _digest(runner["binary_digest"], "journey packaged runner")
    trust = _mapping(
        root["local_trust"],
        {
            "enrollment",
            "manual_certificate_input",
            "manual_hmac_input",
            "authenticated_transport",
            "tls",
        },
        "journey trust",
    )
    preflight = _mapping(
        root["preflight"],
        {
            "status",
            "exact_binding_present",
            "exact_envelope_present",
            "collector_bound",
            "approval_binding",
            "envelope_digest",
        },
        "journey preflight",
    )
    preflight_binding = _approval_binding(
        preflight["approval_binding"], "journey preflight approval binding"
    )
    _digest(preflight["envelope_digest"], "journey preflight envelope")
    job = _mapping(
        root["approval_job"],
        {
            "initial_state",
            "approval_status",
            "terminal_state",
            "approval_id",
            "approval_binding",
            "run_approval_status",
            "job_id",
            "request_approval_id",
            "progress_approval_ref",
            "snapshot_count",
            "cross_bound",
        },
        "journey job",
    )
    job_binding = _approval_binding(job["approval_binding"], "journey job approval binding")
    teardown = _mapping(
        root["teardown"],
        {"stopped", "trust_revoked", "state_removed", "final_state"},
        "journey teardown",
    )
    if (
        root["schema_version"] != "bluefire.gate01-journey.v1"
        or root["verified"] is not True
        or selection
        != {
            "scenario_id": "scenario.restricted.persistence-canary.v1",
            "runner_profile_id": "sandbox-restricted-owned.v1",
            "collector_id": "collector.filesystem.sandbox.v1",
            "scope_refs": ["sandbox.workspace"],
        }
        or runner["source"] != "packaged"
        or runner["managed_binary"] is not True
        or runner["managed_sandbox"] is not True
        or runner["runner_id"] != "bluefire-rust-runner.v1"
        or runner["bootstrap_state"] != "stopped"
        or runner["recovery_reused_exact_identity"] is not True
        or trust
        != {
            "enrollment": "active",
            "manual_certificate_input": False,
            "manual_hmac_input": False,
            "authenticated_transport": "mutual-tls-loopback",
            "tls": "TLSv1.3",
        }
        or preflight["status"] != "approval_required"
        or preflight["exact_binding_present"] is not True
        or preflight["exact_envelope_present"] is not True
        or preflight["collector_bound"] is not True
        or job["initial_state"] != "awaiting_approval"
        or job["approval_status"] != "consumed"
        or job["terminal_state"] != "completed"
        or job["run_approval_status"] != "claimed"
        or not isinstance(job["job_id"], str)
        or _JOB_ID.fullmatch(job["job_id"]) is None
        or job["request_approval_id"] != job["approval_id"]
        or job["progress_approval_ref"] != job["approval_id"]
        or job["snapshot_count"] != 4
        or job["cross_bound"] is not True
        or not isinstance(job["approval_id"], str)
        or _APPROVAL_ID.fullmatch(job["approval_id"]) is None
        or job_binding != preflight_binding
        or root["fresh_replay_approval"] is not True
        or teardown
        != {
            "stopped": True,
            "trust_revoked": True,
            "state_removed": True,
            "final_state": "unbootstrapped",
        }
    ):
        raise ValueError("installed-wheel journey proof is invalid")
    source_id, source_approval_id, source_binding = _validate_run(
        root["source_run"],
        replay_of=None,
        expected_operator="gate01-release-operator",
    )
    replay_id, replay_approval_id, replay_binding = _validate_run(
        root["replay_run"],
        replay_of=source_id,
        expected_operator="gate01-replay-operator",
    )
    for field in ("plan_digest", "target_scope_digest", "profile_id", "maximum_tier"):
        if replay_binding[field] != source_binding[field]:
            raise ValueError("replay approval binding drifted from the source run")
    if replay_binding["state_digest"] == source_binding["state_digest"]:
        raise ValueError("replay approval is not bound to a fresh runtime state")
    if (
        source_approval_id != job["approval_id"]
        or source_binding != preflight_binding
        or replay_approval_id == source_approval_id
    ):
        raise ValueError("journey approvals are not cross-bound and single-use")
    comparison = _mapping(
        root["comparison"], {"comparison_id", "run_ids", "delta_count"}, "journey comparison"
    )
    if (
        not isinstance(comparison["comparison_id"], str)
        or not comparison["comparison_id"].startswith("comparison-")
        or comparison["run_ids"] != [source_id, replay_id]
        or comparison["delta_count"] != 1
    ):
        raise ValueError("journey comparison proof is invalid")
    return source_id, replay_id


def validate_runner_digest_binding(
    inspection: Mapping[str, Any], journey: Mapping[str, Any]
) -> None:
    validate_inspection(inspection)
    validate_journey(journey)
    inspected_digest = "sha256:" + str(inspection["runner"]["sha256"])
    journey_digest = journey["packaged_runner"]["binary_digest"]
    if journey_digest != inspected_digest:
        raise ValueError("installed runner digest does not match the inspected wheel binary")


def validate_structural(report: Mapping[str, Any]) -> None:
    root = _mapping(report, {"schema_version", "verified", "checks"}, "structural report")
    checks = root["checks"]
    expected = {
        "console_entrypoint",
        "packaged_ui_and_runner",
        "platform_wheel_verification",
        "explicit_cli_workflow",
        "guided_execute_onboarding",
        "fresh_approval_boundary",
    }
    if (
        root["schema_version"] != "bluefire.gate01-structural.v1"
        or root["verified"] is not True
        or not isinstance(checks, Mapping)
        or set(checks) != expected
        or any(value is not True for value in checks.values())
    ):
        raise ValueError("Gate 01 simple-workflow structural proof is invalid")


def validate_verification(report: Mapping[str, Any]) -> tuple[str, str]:
    root = _mapping(
        report,
        {"schema_version", "passed", "checks", "run_ids"},
        "verification report",
    )
    expected_checks = {
        "fresh_install",
        "ui_launch",
        "packaged_runner",
        "local_trust",
        "execute_journey",
        "observe_cleanup_replay_compare",
        "simple_workflow",
    }
    run_ids = root["run_ids"]
    if (
        root["schema_version"] != "bluefire.gate01-verification.v1"
        or root["passed"] is not True
        or not isinstance(root["checks"], Mapping)
        or set(root["checks"]) != expected_checks
        or any(value is not True for value in root["checks"].values())
        or not isinstance(run_ids, list)
        or len(run_ids) != 2
        or len(set(run_ids)) != 2
        or any(
            not isinstance(run_id, str) or _RUN_ID.fullmatch(run_id) is None for run_id in run_ids
        )
    ):
        raise ValueError("Gate 01 aggregate verification proof is invalid")
    return run_ids[0], run_ids[1]


def validate_summary(report: Mapping[str, Any]) -> None:
    root = _mapping(report, {"schema_version", "status", "checks", "run_count"}, "helper summary")
    if (
        root["schema_version"] != "bluefire.gate01-helper-summary.v1"
        or root["status"] != "passed"
        or root["checks"]
        != [
            "fresh_install",
            "ui_launch",
            "packaged_runner",
            "local_trust",
            "execute_journey",
            "observe_cleanup_replay_compare",
        ]
        or root["run_count"] != 2
    ):
        raise ValueError("Gate 01 helper summary is invalid")


__all__ = [
    "bounded_failure_message",
    "validate_dependency_provision",
    "validate_dependency_provision_binding",
    "validate_dependency_runtime_binding",
    "validate_inspection",
    "validate_journey",
    "validate_package_runtime",
    "validate_runner_digest_binding",
    "validate_structural",
    "validate_summary",
    "validate_ui",
    "validate_verification",
    "validate_wheel_dependency_metadata",
    "validate_wheel_metadata_binding",
]
