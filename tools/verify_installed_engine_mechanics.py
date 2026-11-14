"""Verify deterministic engine workflow mechanics from an isolated installed wheel.

Copy this file, ``installed_engine_mechanics_fixture.py``, and
``verify_installed_engine_experiment.py`` outside the checkout. Run with the
candidate wheel installed in an isolated Linux virtual environment::

    python -I -B verify_installed_engine_mechanics.py \
      --forbid-root /path/to/checkout --wheel /path/to/candidate.whl \
      --source-revision FULL_LOWERCASE_40_HEX_COMMIT \
      --fixture /outside/installed_engine_mechanics_fixture.py \
      --binding-helper /outside/verify_installed_engine_experiment.py \
      --output /outside/fresh-report-directory

This runs an inert queued cancellation and an in-process synthetic workflow.
It never invokes Strix, Docker, a live model, or an external target. The
public summary intentionally excludes runtime paths and raw evidence content.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import importlib.util
import json
import os
import platform
import re
import shutil
import sys
import sysconfig
import threading
from pathlib import Path
from typing import Any, Mapping, cast

_MAX_REPORT_BYTES = 64 * 1024
_MAX_WHEEL_FILES = 4096
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SOURCE_REVISION = re.compile(r"[0-9a-f]{40}\Z")
_ERROR_TYPES = {None, "VerificationError", "RuntimeCleanupError", "ReceiptContractError"}
_PHASE_KEYS = {
    "cancel_restart_reconcile": {
        "status",
        "scope",
        "saved_experiment_digest",
        "saved_cleanup_evidence_ref",
        "saved_run_digest",
        "exact_saved_document_preserved",
        "exact_saved_workspace_preserved",
        "exact_saved_run_preserved",
        "effect_calls_before_and_after_restart",
        "reconciliation_calls_after_restart",
        "recovery_repeated_without_revision",
    },
    "workflow_comparison": {
        "status",
        "scope",
        "workflow_state",
        "headline",
        "baseline_observed_independently",
        "bounded_defense_fixture_applied",
        "exact_retained_reproducer_blocked",
        "fresh_adaptive_attempt_bounded",
        "legitimate_use_passed",
        "comparison_complete",
        "saved_experiment_digest",
        "saved_runs_digest",
        "exact_saved_document_preserved",
        "exact_saved_workspace_preserved",
        "exact_saved_runs_preserved",
        "engine_runtime_execute_calls",
        "restarted_runtime_execute_calls",
        "generic_reconciliation_calls_after_restart",
    },
}
_LIMITATIONS = [
    "The external engine and target are deterministic in-process fixtures.",
    "Queued cancellation uses generic job mechanics; protected v2 preparation was unavailable.",
    "The comparison uses generic synthetic runtime mechanics, not protected prepared-action admission.",
    "No native Strix, Docker, live-model inference, external target, or attack effectiveness was tested.",
]


def _outside(path: Path, forbidden: Path, *, must_exist: bool) -> Path:
    resolved = path.resolve(strict=must_exist)
    if resolved.is_relative_to(forbidden):
        raise RuntimeError("verifier resources must be outside the source checkout")
    return resolved


def _load_file(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("standalone verifier resource is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def _json_tree_valid(value: object, *, _depth: int = 0) -> bool:
    """Accept only bounded JSON primitives, before consulting the field schema."""
    if _depth > 8:
        return False
    if value is None or type(value) in (bool, int):
        return True
    if type(value) is str:
        return len(value) <= 512 and all(32 <= ord(character) <= 126 for character in value)
    if type(value) is list:
        return len(value) <= 32 and all(_json_tree_valid(item, _depth=_depth + 1) for item in value)
    if type(value) is dict:
        return len(value) <= 64 and all(
            type(key) is str
            and _json_tree_valid(key, _depth=_depth + 1)
            and _json_tree_valid(item, _depth=_depth + 1)
            for key, item in value.items()
        )
    return False


def _phase_valid(value: object, name: str) -> bool:
    if (
        name not in _PHASE_KEYS
        or not _json_tree_valid(value)
        or not isinstance(value, Mapping)
        or set(value) != _PHASE_KEYS[name]
    ):
        return False
    row = cast(Mapping[str, Any], value)
    if row.get("status") != "passed":
        return False
    for field in (
        "saved_experiment_digest",
        "saved_cleanup_evidence_ref",
        "saved_run_digest",
        "saved_runs_digest",
    ):
        if field in row and (
            not isinstance(row[field], str) or _DIGEST.fullmatch(row[field]) is None
        ):
            return False
    if name == "cancel_restart_reconcile":
        return (
            row.get("scope") == "generic_installed_wheel_queued_cancel_restart_reconcile_mechanics"
            and row.get("exact_saved_document_preserved") is True
            and row.get("exact_saved_workspace_preserved") is True
            and row.get("exact_saved_run_preserved") is True
            and type(row.get("effect_calls_before_and_after_restart")) is int
            and row.get("effect_calls_before_and_after_restart") == 0
            and type(row.get("reconciliation_calls_after_restart")) is int
            and row.get("reconciliation_calls_after_restart") == 2
            and row.get("recovery_repeated_without_revision") is True
        )
    return (
        row.get("scope") == "synthetic_engine_and_tenant_lab_workflow_mechanics"
        and row.get("workflow_state") == "complete"
        and row.get("headline") == "original_blocked_no_remaining_path_observed_within_limits"
        and all(
            row.get(field) is True
            for field in (
                "baseline_observed_independently",
                "bounded_defense_fixture_applied",
                "exact_retained_reproducer_blocked",
                "fresh_adaptive_attempt_bounded",
                "legitimate_use_passed",
                "comparison_complete",
                "exact_saved_document_preserved",
                "exact_saved_workspace_preserved",
                "exact_saved_runs_preserved",
            )
        )
        and type(row.get("engine_runtime_execute_calls")) is int
        and row.get("engine_runtime_execute_calls") == 2
        and type(row.get("restarted_runtime_execute_calls")) is int
        and row.get("restarted_runtime_execute_calls") == 0
        and type(row.get("generic_reconciliation_calls_after_restart")) is int
        and row.get("generic_reconciliation_calls_after_restart") == 1
    )


def _artifact_identity_valid(value: object) -> bool:
    if (
        not _json_tree_valid(value)
        or not isinstance(value, Mapping)
        or set(value)
        != {
            "distribution",
            "version",
            "os",
            "architecture",
            "wheel_sha256",
            "source_revision",
            "source_provenance",
            "build_metadata_status",
            "ui_digest",
            "ui_files",
            "ui_matches_build",
            "controlled_provider_sha256",
            "wheel_member_count",
            "wheel_payload_digest",
            "installed_payload_digest",
        }
    ):
        return False
    identity = cast(Mapping[str, object], value)
    files = identity.get("ui_files")
    if not isinstance(files, list) or len(files) not in (3, 4):
        return False
    names = ["app.js", "index.html", "styles.css"]
    if len(files) == 4:
        names.append("fonts/InterVariable.woff2")
    for item, name in zip(files, names, strict=True):
        if (
            not isinstance(item, Mapping)
            or set(item) != {"name", "sha256", "size"}
            or item.get("name") != name
            or not isinstance(item.get("sha256"), str)
            or _DIGEST.fullmatch(cast(str, item["sha256"])) is None
            or type(item.get("size")) is not int
            or not 0 < cast(int, item["size"]) <= 8 * 1024 * 1024
        ):
            return False
    revision = identity.get("source_revision")
    provenance = identity.get("source_provenance")
    return (
        identity.get("distribution") == "bluefire-nexus"
        and isinstance(identity.get("version"), str)
        and re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,127}", cast(str, identity["version"]))
        is not None
        and identity.get("os") == "linux"
        and isinstance(identity.get("architecture"), str)
        and identity.get("architecture") in {"x86_64", "aarch64"}
        and isinstance(identity.get("wheel_sha256"), str)
        and _DIGEST.fullmatch(cast(str, identity["wheel_sha256"])) is not None
        and isinstance(revision, str)
        and re.fullmatch(r"[0-9a-f]{40}", revision) is not None
        and provenance == "git_archive"
        and identity.get("build_metadata_status") == "embedded"
        and isinstance(identity.get("ui_digest"), str)
        and _DIGEST.fullmatch(cast(str, identity["ui_digest"])) is not None
        and identity.get("ui_matches_build") is True
        and isinstance(identity.get("controlled_provider_sha256"), str)
        and _DIGEST.fullmatch(cast(str, identity["controlled_provider_sha256"])) is not None
        and type(identity.get("wheel_member_count")) is int
        and 1 <= cast(int, identity["wheel_member_count"]) <= _MAX_WHEEL_FILES
        and isinstance(identity.get("wheel_payload_digest"), str)
        and _DIGEST.fullmatch(cast(str, identity["wheel_payload_digest"])) is not None
        and identity.get("installed_payload_digest") == identity.get("wheel_payload_digest")
    )


def public_summary_valid(value: object) -> bool:
    """Independently validate every public field, including incomplete summaries."""
    if (
        not _json_tree_valid(value)
        or not isinstance(value, Mapping)
        or set(value)
        != {
            "schema_version",
            "status",
            "scope",
            "installed_wheel",
            "source_checkout_import",
            "product_components_used",
            "native_engine_executed",
            "docker_executed",
            "live_model_inference",
            "external_target_execution",
            "protected_prepared_action_admission",
            "protected_v22_admission",
            "comparison_mechanics_verified",
            "limitations",
            "artifact_identity",
            "expected_source_revision",
            "verifier_assets",
            "phases",
            "cleanup",
            "error_type",
        }
    ):
        return False
    report = cast(Mapping[str, Any], value)
    phases = report.get("phases")
    cleanup = report.get("cleanup")
    identity = report.get("artifact_identity")
    assets = report.get("verifier_assets")
    expected_revision = report.get("expected_source_revision")
    return (
        report.get("schema_version") == "bluefire.installed-engine-mechanics-verification.v1"
        and isinstance(report.get("status"), str)
        and report.get("status") in {"passed", "failed_or_incomplete"}
        and report.get("scope") == "installed_wheel_deterministic_mechanics_simulation"
        and type(report.get("installed_wheel")) is bool
        and report.get("source_checkout_import") is False
        and report.get("product_components_used")
        == [
            "ProductStore",
            "RunStore",
            "RunJobController",
            "EngineExperimentJobs",
            "EngineControllerJobs",
            "EngineExperimentService",
        ]
        and report.get("native_engine_executed") is False
        and report.get("docker_executed") is False
        and report.get("live_model_inference") is False
        and report.get("external_target_execution") is False
        and report.get("protected_prepared_action_admission") is False
        and report.get("protected_v22_admission") is False
        and type(report.get("comparison_mechanics_verified")) is bool
        and report.get("limitations") == _LIMITATIONS
        and isinstance(expected_revision, str)
        and _SOURCE_REVISION.fullmatch(expected_revision) is not None
        and (
            identity is None
            or (
                _artifact_identity_valid(identity)
                and cast(Mapping[str, object], identity).get("source_revision") == expected_revision
            )
        )
        and (
            assets is None
            or (
                isinstance(assets, Mapping)
                and set(assets) == {"verifier_sha256", "fixture_sha256", "binding_helper_sha256"}
                and all(
                    isinstance(item, str) and _DIGEST.fullmatch(item) is not None
                    for item in assets.values()
                )
            )
        )
        and isinstance(phases, Mapping)
        and set(phases) <= _PHASE_KEYS.keys()
        and all(_phase_valid(row, name) for name, row in phases.items())
        and isinstance(cleanup, Mapping)
        and set(cleanup) == {"fixture_workers_stopped", "temporary_runtime_removed"}
        and all(type(item) is bool for item in cleanup.values())
        and (report.get("error_type") is None or isinstance(report.get("error_type"), str))
        and report.get("error_type") in _ERROR_TYPES
        and (
            report.get("status") != "passed"
            or (
                report.get("installed_wheel") is True
                and identity is not None
                and assets is not None
                and report.get("comparison_mechanics_verified") is True
                and set(phases) == _PHASE_KEYS.keys()
                and all(item is True for item in cleanup.values())
                and report.get("error_type") is None
            )
        )
    )


def receipt_passed(value: object) -> bool:
    return (
        public_summary_valid(value) and cast(Mapping[str, object], value).get("status") == "passed"
    )


def _validated_phase(value: object, name: str) -> dict[str, Any]:
    if not _phase_valid(value, name):
        raise RuntimeError("fixture result violated the public summary contract")
    return dict(cast(Mapping[str, Any], value))


def _write_new(path: Path, value: Mapping[str, Any], *, source_revision: str) -> None:
    if not public_summary_valid(value) or value.get("expected_source_revision") != source_revision:
        raise RuntimeError("refusing to publish an invalid public summary")
    payload = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True).encode("ascii") + b"\n"
    if len(payload) > _MAX_REPORT_BYTES:
        raise RuntimeError("bounded mechanics receipt exceeded its size limit")
    with path.open("xb") as stream:
        stream.write(payload)


def _source_revision_argument(value: str) -> str:
    if _SOURCE_REVISION.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "source revision must be a full lowercase 40-hex Git commit"
        )
    return value


def _require_source_revision(actual: object, expected: str) -> None:
    if (
        not isinstance(actual, str)
        or _SOURCE_REVISION.fullmatch(actual) is None
        or actual != expected
    ):
        raise RuntimeError("installed source revision does not match the expected commit")


def _parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--forbid-root", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--binding-helper", type=Path, required=True)
    parser.add_argument("--source-revision", type=_source_revision_argument, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def main() -> int:
    args = _parse_arguments()
    if sys.platform != "linux" or not sys.flags.isolated:
        raise RuntimeError("Run with isolated installed Python on Linux")
    forbidden = args.forbid_root.resolve(strict=True)
    script = _outside(Path(__file__), forbidden, must_exist=True)
    fixture_path = _outside(args.fixture, forbidden, must_exist=True)
    helper_path = _outside(args.binding_helper, forbidden, must_exist=True)
    wheel = args.wheel.resolve(strict=True)
    output = _outside(args.output, forbidden, must_exist=False)
    if (
        output.exists()
        or not fixture_path.is_file()
        or not helper_path.is_file()
        or not wheel.is_file()
        or Path.cwd().resolve().is_relative_to(forbidden)
    ):
        raise RuntimeError("Use fresh verifier resources outside the checkout")
    output.mkdir(mode=0o700)
    runtime = output / "runtime"
    report: dict[str, Any] = {
        "schema_version": "bluefire.installed-engine-mechanics-verification.v1",
        "status": "failed_or_incomplete",
        "scope": "installed_wheel_deterministic_mechanics_simulation",
        "installed_wheel": False,
        "source_checkout_import": False,
        "product_components_used": [
            "ProductStore",
            "RunStore",
            "RunJobController",
            "EngineExperimentJobs",
            "EngineControllerJobs",
            "EngineExperimentService",
        ],
        "native_engine_executed": False,
        "docker_executed": False,
        "live_model_inference": False,
        "external_target_execution": False,
        "protected_prepared_action_admission": False,
        "protected_v22_admission": False,
        "comparison_mechanics_verified": False,
        "limitations": list(_LIMITATIONS),
        "artifact_identity": None,
        "expected_source_revision": args.source_revision,
        "verifier_assets": None,
        "phases": {},
        "cleanup": {"fixture_workers_stopped": False, "temporary_runtime_removed": False},
        "error_type": None,
    }
    original_cwd = Path.cwd()
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(runtime / "home"),
        "XDG_STATE_HOME": str(runtime / "state"),
        "XDG_CONFIG_HOME": str(runtime / "state"),
        "XDG_CACHE_HOME": str(runtime / "temp"),
        "TMPDIR": str(runtime / "temp"),
        "LANG": "C.UTF-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        runtime.mkdir(mode=0o700)
        for name in ("home", "state", "temp", "work", "cancel", "comparison"):
            (runtime / name).mkdir(mode=0o700)
        os.environ.clear()
        os.environ.update(environment)
        os.chdir(runtime / "work")
        import bluefire
        from bluefire.build_info import build_info

        package = Path(bluefire.__file__).resolve(strict=True).parent
        purelib = Path(sysconfig.get_path("purelib")).resolve(strict=True)
        if package.is_relative_to(forbidden) or not package.is_relative_to(purelib):
            raise RuntimeError("BlueFire was not imported from the isolated installation")
        helper = _load_file(helper_path, "installed_engine_wheel_binding")
        version = importlib.metadata.version("bluefire-nexus")
        binding = helper.bind_installed_wheel(wheel, purelib=purelib, installed_version=version)
        info = build_info()
        source = cast(Mapping[str, object], info.get("source"))
        _require_source_revision(source.get("revision"), args.source_revision)
        build = cast(Mapping[str, object], info.get("build"))
        ui = cast(Mapping[str, object], info.get("ui"))
        identity = {
            "distribution": "bluefire-nexus",
            "version": version,
            "wheel_sha256": helper.digest(wheel),
            "source_revision": source.get("revision"),
            "source_provenance": source.get("provenance"),
            "build_metadata_status": build.get("metadata_status"),
            "ui_digest": ui.get("digest"),
            "ui_files": ui.get("files"),
            "ui_matches_build": ui.get("matches_build"),
            "controlled_provider_sha256": helper.digest(package / "controlled_strix_provider.py"),
            **binding,
        }
        if not helper.build_identity_valid(identity):
            raise RuntimeError("installed artifact identity is inconsistent")
        identity["os"] = sys.platform
        identity["architecture"] = platform.machine()
        if not _artifact_identity_valid(identity):
            raise RuntimeError("installed platform identity is inconsistent")
        _require_source_revision(identity.get("source_revision"), args.source_revision)
        report["artifact_identity"] = identity
        assets = {
            "verifier_sha256": helper.digest(script),
            "fixture_sha256": helper.digest(fixture_path),
            "binding_helper_sha256": helper.digest(helper_path),
        }
        if not all(isinstance(item, str) and _DIGEST.fullmatch(item) for item in assets.values()):
            raise RuntimeError("verifier asset identity is inconsistent")
        report["verifier_assets"] = assets
        report["installed_wheel"] = True
        fixture = _load_file(fixture_path, "installed_engine_mechanics_fixture")
        report["phases"]["cancel_restart_reconcile"] = _validated_phase(
            fixture.run_cancel_restart_reconcile(runtime / "cancel"), "cancel_restart_reconcile"
        )
        report["phases"]["workflow_comparison"] = _validated_phase(
            fixture.run_joined_product_path(runtime / "comparison"), "workflow_comparison"
        )
        report["comparison_mechanics_verified"] = True
    except Exception:
        # Error details can contain a local path or secret from a fixture.
        report["error_type"] = "VerificationError"
    finally:
        os.chdir(original_cwd)
        prefixes = (
            "installed-mechanics-cancel",
            "installed-mechanics-recover",
            "joined-engine-test",
            "joined-engine-recovery-test",
        )
        report["cleanup"]["fixture_workers_stopped"] = not any(
            thread.is_alive() and thread.name.startswith(prefixes)
            for thread in threading.enumerate()
        )
        if runtime.exists() and report["cleanup"]["fixture_workers_stopped"] is True:
            try:
                shutil.rmtree(runtime)
            except OSError:
                report["error_type"] = "RuntimeCleanupError"
        report["cleanup"]["temporary_runtime_removed"] = not runtime.exists()
        if (
            report["installed_wheel"] is True
            and report["comparison_mechanics_verified"] is True
            and report["cleanup"]["temporary_runtime_removed"] is True
            and report["error_type"] is None
        ):
            report["status"] = "passed"
        if report["status"] == "passed" and not receipt_passed(report):
            report["status"] = "failed_or_incomplete"
            report["error_type"] = "ReceiptContractError"
        _write_new(output / "public-summary.json", report, source_revision=args.source_revision)
    return 0 if receipt_passed(report) else 1


if __name__ == "__main__":
    raise SystemExit(main())
