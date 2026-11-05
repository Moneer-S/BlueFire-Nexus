"""Source-side checks for the standalone installed-wheel mechanics fixture."""

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from tools.installed_engine_mechanics_fixture import (
    run_cancel_restart_reconcile,
    run_joined_product_path,
)
from tools.verify_installed_engine_mechanics import (
    _LIMITATIONS,
    _artifact_identity_valid,
    _phase_valid,
    _validated_phase,
    _write_new,
    public_summary_valid,
    receipt_passed,
)


@pytest.fixture(scope="module")
def summary(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    digest = "sha256:" + "a" * 64
    return {
        "schema_version": "bluefire.installed-engine-mechanics-verification.v1",
        "status": "passed",
        "scope": "installed_wheel_deterministic_mechanics_simulation",
        "installed_wheel": True,
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
        "comparison_mechanics_verified": True,
        "limitations": list(_LIMITATIONS),
        "artifact_identity": {
            "distribution": "bluefire-nexus",
            "version": "1.0.0",
            "os": "linux",
            "architecture": "x86_64",
            "wheel_sha256": digest,
            "source_revision": "a" * 40,
            "source_provenance": "git_archive",
            "build_metadata_status": "embedded",
            "ui_digest": digest,
            "ui_files": [
                {"name": name, "sha256": digest, "size": 100}
                for name in ("app.js", "index.html", "styles.css")
            ],
            "ui_matches_build": True,
            "controlled_provider_sha256": digest,
            "wheel_member_count": 100,
            "wheel_payload_digest": digest,
            "installed_payload_digest": digest,
        },
        "verifier_assets": {
            "verifier_sha256": digest,
            "fixture_sha256": digest,
            "binding_helper_sha256": digest,
        },
        "phases": {
            "cancel_restart_reconcile": run_cancel_restart_reconcile(
                tmp_path_factory.mktemp("cancel")
            ),
            "workflow_comparison": run_joined_product_path(tmp_path_factory.mktemp("comparison")),
        },
        "cleanup": {"fixture_workers_stopped": True, "temporary_runtime_removed": True},
        "error_type": None,
    }


def test_queued_cancel_restart_reconcile_preserves_exact_state(summary: dict[str, Any]) -> None:
    result = summary["phases"]["cancel_restart_reconcile"]
    assert _phase_valid(result, "cancel_restart_reconcile")
    serialized = json.dumps(result, sort_keys=True)
    assert "product.sqlite3" not in serialized
    assert "BlueFireLab " not in serialized


def test_joined_mechanics_comparison_preserves_exact_evidence(summary: dict[str, Any]) -> None:
    result = summary["phases"]["workflow_comparison"]
    assert _phase_valid(result, "workflow_comparison")
    serialized = json.dumps(result, sort_keys=True)
    assert "product.sqlite3" not in serialized
    assert "BlueFireLab " not in serialized


def test_only_bounded_validated_public_summary_is_published(
    summary: dict[str, Any], tmp_path: Path
) -> None:
    assert receipt_passed(summary)
    path = tmp_path / "public-summary.json"
    _write_new(path, summary)
    assert path.stat().st_size <= 64 * 1024
    assert public_summary_valid(json.loads(path.read_text("ascii")))
    assert str(tmp_path).encode() not in path.read_bytes()
    assert list(tmp_path.iterdir()) == [path]
    with pytest.raises(FileExistsError):
        _write_new(path, summary)


@pytest.mark.parametrize(
    "section", [None, "artifact_identity", "verifier_assets", "phases", "cleanup"]
)
def test_unexpected_nested_fields_are_rejected_before_publication(
    summary: dict[str, Any], tmp_path: Path, section: str | None
) -> None:
    changed = deepcopy(summary)
    row = changed if section is None else changed[section]
    row["private_path"] = str(tmp_path / "private-token")
    assert not public_summary_valid(changed)
    with pytest.raises(RuntimeError, match="refusing to publish"):
        _write_new(tmp_path / "public-summary.json", changed)
    assert not (tmp_path / "public-summary.json").exists()


@pytest.mark.parametrize("phase", ["cancel_restart_reconcile", "workflow_comparison"])
def test_malformed_fixture_phase_cannot_be_staged(summary: dict[str, Any], phase: str) -> None:
    changed = deepcopy(summary["phases"][phase])
    changed["raw_payload"] = "BlueFireLab secret-token /private/operator"
    assert not _phase_valid(changed, phase)
    with pytest.raises(RuntimeError, match="public summary contract"):
        _validated_phase(changed, phase)


@pytest.mark.parametrize(
    "field,value",
    [
        ("os", "win32"),
        ("os", None),
        ("architecture", "AMD64"),
        ("architecture", []),
        ("architecture", {}),
        ("source_revision", None),
        ("source_revision", "a" * 39),
        ("source_provenance", "unavailable"),
        ("wheel_sha256", "private/path"),
        ("installed_payload_digest", "sha256:" + "b" * 64),
        ("wheel_member_count", True),
        ("version", "1.0.0\n/private/path"),
    ],
)
def test_artifact_identity_requires_exact_platform_source_and_wheel_binding(
    summary: dict[str, Any], field: str, value: object
) -> None:
    changed = deepcopy(summary["artifact_identity"])
    changed[field] = value
    assert not _artifact_identity_valid(changed)


@pytest.mark.parametrize(
    "section,field,value",
    [
        (None, "protected_v22_admission", 0),
        (None, "protected_v22_admission", True),
        (None, "native_engine_executed", 0),
        (None, "status", []),
        (None, "error_type", "PrivateSecretException"),
        ("cleanup", "fixture_workers_stopped", 1),
        ("cleanup", "temporary_runtime_removed", 1),
        ("cancel_restart_reconcile", "effect_calls_before_and_after_restart", False),
        ("workflow_comparison", "restarted_runtime_execute_calls", False),
    ],
)
def test_public_summary_rejects_type_confusion_and_private_failure_details(
    summary: dict[str, Any], section: str | None, field: str, value: object
) -> None:
    changed = deepcopy(summary)
    row = (
        changed
        if section is None
        else (changed[section] if section == "cleanup" else changed["phases"][section])
    )
    row[field] = value
    assert not public_summary_valid(changed)


def test_ui_rows_have_exact_keys_and_types(summary: dict[str, Any]) -> None:
    for field, value in (("size", True), ("private_path", "/private/operator")):
        changed = deepcopy(summary)
        changed["artifact_identity"]["ui_files"][0][field] = value
        assert not public_summary_valid(changed)


def test_incomplete_summary_stays_sanitized_and_cannot_pass(summary: dict[str, Any]) -> None:
    changed = deepcopy(summary)
    changed.update(status="failed_or_incomplete", error_type="VerificationError", phases={})
    assert public_summary_valid(changed)
    assert not receipt_passed(changed)


def test_recursive_malformed_results_fail_closed(summary: dict[str, Any]) -> None:
    changed = deepcopy(summary)
    changed["phases"]["workflow_comparison"]["raw_payload"] = changed
    assert not public_summary_valid(changed)
