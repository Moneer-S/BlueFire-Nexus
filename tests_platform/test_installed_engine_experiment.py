"""Pure receipt and scope checks for the installed engine-experiment scaffold."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import stat
import zipfile
from copy import deepcopy
from pathlib import Path

import pytest

from tools.verify_installed_engine_experiment import (
    _installed_cli_command,
    bind_installed_wheel,
    browser_report_passed,
    build_identity_valid,
    cleanup_confirmed,
    digest,
    receipt_passed,
)


def _browser_report() -> dict[str, object]:
    return {
        "schema_version": "bluefire.installed-engine-experiment.browser-report.v1",
        "status": "passed",
        "installed_service": True,
        "packaged_ui": True,
        "external_engine_executed": False,
        "controlled_provider_mechanics": False,
        "live_model_inference": False,
        "target_execution": False,
        "defensive_change_applied": False,
        "creation_error_code": "engine_workspace_unavailable",
        "checks": [
            "packaged_ui_rendered_with_real_local_service",
            "empty_engine_history_read_from_installed_service",
            "create_refused_without_controller_presentation_metadata",
            "refused_create_left_no_saved_experiment",
            "engine_route_rendered_recoverable_unavailable_state",
        ],
        "blocked_requests": [],
        "errors": [],
        "browser_context_closed": True,
        "browser_closed": True,
    }


def _identity() -> dict[str, object]:
    names = ["app.js", "index.html", "styles.css", "fonts/InterVariable.woff2"]
    return {
        "distribution": "bluefire-nexus",
        "version": "3.0.0-rc2",
        "wheel_sha256": "sha256:" + "1" * 64,
        "source_revision": "2" * 40,
        "source_provenance": "git_archive",
        "build_metadata_status": "embedded",
        "ui_digest": "sha256:" + "3" * 64,
        "ui_files": [
            {"name": name, "sha256": "sha256:" + str(index + 4) * 64, "size": 1024}
            for index, name in enumerate(names)
        ],
        "ui_matches_build": True,
        "controlled_provider_sha256": "sha256:" + "8" * 64,
        "wheel_member_count": 128,
        "wheel_payload_digest": "sha256:" + "9" * 64,
        "installed_payload_digest": "sha256:" + "9" * 64,
    }


def _receipt() -> dict[str, object]:
    return {
        "schema_version": "bluefire.installed-engine-experiment-verification.v1",
        "status": "passed",
        "scope": "installed_fail_closed_engine_experiment_shell",
        "installed_wheel": True,
        "source_checkout_import": False,
        "real_local_service": True,
        "packaged_ui": True,
        "external_engine_executed": False,
        "controlled_provider_mechanics": False,
        "live_model_inference": False,
        "target_execution": False,
        "defensive_change_applied": False,
        "attack_defense_retest_proven": False,
        "engine_api_fail_closed": True,
        "partial_create_absent": True,
        "limitations": [
            "Controller-owned experiment presentation metadata was not provisioned.",
            "No controlled-provider, external-engine, target, defense, or retest effect ran.",
            "This check does not establish live-model decision quality or attack effectiveness.",
        ],
        "artifact_identity": _identity(),
        "browser_report": _browser_report(),
        "cleanup": {
            "browser_process_group": "stopped",
            "service_process_group": "stopped",
            "temporary_runtime_removed": True,
        },
    }


def _wheel_fixture(tmp_path: Path) -> tuple[Path, Path]:
    purelib = tmp_path / "site"
    purelib.mkdir()
    prefix = "bluefire_nexus-1.2.3.dist-info/"
    payloads = {
        "bluefire/__init__.py": b'__version__ = "1.2.3"\n',
        "bluefire/controlled_strix_provider.py": b'PROVIDER_ID = "fixture"\n',
        prefix + "METADATA": (b"Metadata-Version: 2.1\nName: bluefire-nexus\nVersion: 1.2.3\n\n"),
        prefix + "WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
    }
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for name, payload in payloads.items():
        encoded = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=")
        writer.writerow([name, "sha256=" + encoded.decode("ascii"), str(len(payload))])
        destination = purelib / Path(*name.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    record_name = prefix + "RECORD"
    writer.writerow([record_name, "", ""])
    wheel = tmp_path / "bluefire_nexus-1.2.3-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in {**payloads, record_name: record.getvalue().encode("utf-8")}.items():
            info = zipfile.ZipInfo(name)
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, payload)
    return wheel, purelib


def test_cli_command_uses_isolated_installed_module_and_loopback(tmp_path: Path) -> None:
    command = _installed_cli_command("/isolated/python", tmp_path / "runs")
    assert command[:5] == ["/isolated/python", "-I", "-B", "-m", "bluefire.cli"]
    assert command[-6:] == ["ui", "--host", "127.0.0.1", "--port", "0", "--no-browser"]


def test_digest_streams_sha256(tmp_path: Path) -> None:
    item = tmp_path / "candidate.whl"
    item.write_bytes(b"installed engine experiment")
    assert digest(item) == "sha256:" + hashlib.sha256(item.read_bytes()).hexdigest()


def test_installed_payload_is_bound_to_every_candidate_wheel_member(tmp_path: Path) -> None:
    wheel, purelib = _wheel_fixture(tmp_path)
    binding = bind_installed_wheel(wheel, purelib=purelib, installed_version="1.2.3")
    assert binding["wheel_member_count"] == 4
    assert binding["wheel_payload_digest"] == binding["installed_payload_digest"]


def test_wheel_binding_rejects_tampered_install_or_other_version(tmp_path: Path) -> None:
    wheel, purelib = _wheel_fixture(tmp_path)
    provider = purelib / "bluefire" / "controlled_strix_provider.py"
    provider.write_bytes(provider.read_bytes() + b"tampered\n")
    with pytest.raises(RuntimeError, match="installed wheel member"):
        bind_installed_wheel(wheel, purelib=purelib, installed_version="1.2.3")
    provider.write_bytes(b'PROVIDER_ID = "fixture"\n')
    with pytest.raises(RuntimeError, match="identity"):
        bind_installed_wheel(wheel, purelib=purelib, installed_version="9.9.9")


def test_browser_report_requires_fail_closed_create_and_no_effect_claims() -> None:
    report = _browser_report()
    assert browser_report_passed(report)
    for field, value in (
        ("creation_error_code", "engine_request_invalid"),
        ("external_engine_executed", True),
        ("controlled_provider_mechanics", True),
        ("target_execution", True),
        ("defensive_change_applied", True),
        ("browser_closed", False),
    ):
        changed = deepcopy(report)
        changed[field] = value
        assert not browser_report_passed(changed)


def test_build_identity_requires_embedded_matching_ui_and_provider_hash() -> None:
    identity = _identity()
    assert build_identity_valid(identity)
    for field, value in (
        ("build_metadata_status", "unavailable"),
        ("ui_matches_build", False),
        ("controlled_provider_sha256", None),
    ):
        changed = deepcopy(identity)
        changed[field] = value
        assert not build_identity_valid(changed)


def test_cleanup_requires_both_owned_process_groups_and_runtime_absence() -> None:
    cleanup = _receipt()["cleanup"]
    assert cleanup_confirmed(cleanup)
    assert isinstance(cleanup, dict)
    for field in cleanup:
        changed = deepcopy(cleanup)
        changed[field] = False if field == "temporary_runtime_removed" else "stop_failed"
        assert not cleanup_confirmed(changed)


def test_receipt_is_truthful_about_the_narrow_installed_proof() -> None:
    receipt = _receipt()
    assert receipt_passed(receipt)
    for field, value in (
        ("source_checkout_import", True),
        ("controlled_provider_mechanics", True),
        ("attack_defense_retest_proven", True),
        ("partial_create_absent", False),
    ):
        changed = deepcopy(receipt)
        changed[field] = value
        assert not receipt_passed(changed)


def test_browser_driver_admits_only_one_exact_create_and_no_effect_routes() -> None:
    driver = (
        Path(__file__).resolve().parents[1]
        / "frontend"
        / "tests"
        / "installed"
        / "installed-engine-experiment.mjs"
    ).read_text(encoding="utf-8")
    assert "createPosts === 0 && JSON.stringify(body) === JSON.stringify(createRequest)" in driver
    assert 'assert.equal(rejected.body?.error?.code, "engine_workspace_unavailable")' in driver
    assert "assert.deepEqual(after, initial)" in driver
    assert "/attempts" not in driver
    assert "/defense/" not in driver
    assert "/checks/" not in driver
