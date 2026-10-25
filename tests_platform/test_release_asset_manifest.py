from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import subprocess
import sys
import zipfile
from argparse import Namespace
from pathlib import Path

import pytest

from bluefire.version import native_runner_version
from tools.build_release_asset_manifest import (
    build_release_asset_outputs,
    write_release_asset_outputs,
)
from tools.verify_packaged_runner import inspect_wheel

VERSION = "3.0.0rc2"
SOURCE_REVISION = "a" * 40
TAGS = ("linux_x86_64", "win_amd64")
TARGETS = {
    "linux_x86_64": ("linux", "x86_64", "bluefire-runner"),
    "win_amd64": ("windows", "x86_64", "bluefire-runner.exe"),
}


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def test_manifest_cli_imports_from_outside_checkout_without_pythonpath(tmp_path):
    checkout = Path(__file__).resolve().parents[1]
    outside = tmp_path / "outside"
    outside.mkdir()
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)

    completed = subprocess.run(
        [
            sys.executable,
            "-E",
            "-S",
            str(checkout / "tools" / "build_release_asset_manifest.py"),
            "--help",
        ],
        cwd=outside,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )

    assert completed.returncode == 0
    assert "--asset-dir" in completed.stdout
    assert "--source-revision" in completed.stdout
    assert completed.stderr == ""


def _write_asset(
    root,
    tag: str,
    *,
    version: str = VERSION,
    metadata_version: str | None = None,
    native_version: str | None = None,
    report_change=None,
    unsafe=False,
    metadata_layout: str | None = None,
    record_change=None,
    source_revision: str | None = SOURCE_REVISION,
    source_provenance: str = "git_archive",
    build_info_change=None,
    build_info_missing=False,
    build_info_shadow=False,
    build_info_padding=0,
    build_info_layout="purelib",
    runner_layout="purelib",
    runner_member_path: str | None = None,
    ui_member_change=None,
):
    platform, architecture, executable = TARGETS[tag]
    target = root / tag
    target.mkdir(parents=True)
    wheel_name = f"bluefire_nexus-{version}-py3-none-{tag}.whl"
    runner = b"native-runner-" + tag.encode("ascii")
    native_root = (
        f"bluefire_nexus-{version}.data/{runner_layout}/bluefire/native"
        if runner_layout != "root"
        else "bluefire/native"
    )
    manifest_path = f"{native_root}/runner-manifest.json"
    executable_path = runner_member_path or f"{native_root}/{executable}"
    manifest_version = native_version or native_runner_version(version)
    manifest = {
        "schema_version": "bluefire.native-runner-package.v1",
        "product": {"name": "bluefire-nexus", "version": version},
        "runner": {
            "id": "bluefire-rust-runner.v1",
            "version": manifest_version,
            "inventory_schema": "bluefire.runner-inventory.v1",
            "action_sdk_version": "bluefire.runner-action-sdk.v1",
            "receipt_protocol": "bluefire.runner-receipt-wal.v2",
        },
        "artifact": {
            "filename": executable,
            "platform": platform,
            "architecture": architecture,
            "size": len(runner),
            "sha256": hashlib.sha256(runner).hexdigest(),
            "wheel_platform_tag": tag,
        },
    }
    wheel_metadata = (
        f"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: false\nTag: py3-none-{tag}\n"
    ).encode()
    metadata = (
        f"Metadata-Version: 2.1\nName: bluefire-nexus\nVersion: {metadata_version or version}\n"
        "\nDescription: body text with misleading headers\nName: unrelated-package\n"
        "Version: 99.0\n"
    ).encode()
    ui_payloads = {
        name: f"test asset: {name}\n".encode() for name in ("app.js", "index.html", "styles.css")
    }
    ui_files = [
        {
            "name": name,
            "sha256": "sha256:" + hashlib.sha256(ui_payloads[name]).hexdigest(),
            "size": len(ui_payloads[name]),
        }
        for name in ui_payloads
    ]
    build_info = {
        "schema_version": "bluefire.build-metadata.v1",
        "version": version,
        "source_revision": source_revision,
        "source_provenance": source_provenance,
        "ui_files": ui_files,
        "ui_digest": "sha256:" + hashlib.sha256(_canonical(ui_files)).hexdigest(),
    }
    if build_info_change is not None:
        build_info_change(build_info)
    if ui_member_change is not None:
        ui_member_change(ui_payloads)
    dist_info = metadata_layout or f"bluefire_nexus-{version}.dist-info"
    record_name = f"bluefire_nexus-{version}.dist-info/RECORD"
    build_info_path = (
        "bluefire/_build_info.json"
        if build_info_layout == "root"
        else f"bluefire_nexus-{version}.data/{build_info_layout}/bluefire/_build_info.json"
    )
    package_root = build_info_path.removesuffix("_build_info.json")
    members = {
        f"{dist_info}/METADATA": metadata,
        f"{dist_info}/WHEEL": wheel_metadata,
        manifest_path: json.dumps(manifest).encode(),
        executable_path: runner,
        **{package_root + "ui/" + name: payload for name, payload in ui_payloads.items()},
    }
    if not build_info_missing:
        members[build_info_path] = _canonical(build_info) + b"\n" + b" " * build_info_padding
    if build_info_shadow:
        members[f"{dist_info}/shadow/bluefire/_build_info.json"] = _canonical(build_info) + b"\n"
    if unsafe:
        members["../escape"] = b"x"
    rows = []
    for name, payload in members.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).decode().rstrip("=")
        rows.append((name, f"sha256={digest}", str(len(payload))))
    rows.append((record_name, "", ""))
    if record_change is not None:
        rows = record_change(rows)
    record = io.StringIO(newline="")
    csv.writer(record, lineterminator="\n").writerows(rows)
    members[record_name] = record.getvalue().encode()
    with zipfile.ZipFile(target / wheel_name, "w") as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)

    wheel_sha = hashlib.sha256((target / wheel_name).read_bytes()).hexdigest()
    report = {
        "schema_version": "bluefire.package-inspection.v1",
        "wheel": wheel_name,
        "wheel_sha256": wheel_sha,
        "tag": f"py3-none-{tag}",
        "platform": platform,
        "architecture": architecture,
        "runner": {
            "filename": executable,
            "size": len(runner),
            "sha256": manifest["artifact"]["sha256"],
        },
        "verified": True,
    }
    if report_change is not None:
        report_change(report)
    (target / "package-inspection.json").write_text(json.dumps(report), encoding="utf-8")


def _asset_dir(tmp_path):
    for tag in TAGS:
        _write_asset(tmp_path, tag)
    return tmp_path


def test_build_identity_respects_installed_runtime_size_limit(tmp_path):
    _write_asset(tmp_path, TAGS[0], build_info_padding=16384)
    with pytest.raises(ValueError, match="metadata exceeds its size limit"):
        build_release_asset_outputs(
            tmp_path, version=VERSION, source_revision=SOURCE_REVISION, expected_tags=(TAGS[0],)
        )


def test_outputs_are_deterministic_and_bind_wheels_reports_and_native_runners(tmp_path):
    asset_dir = _asset_dir(tmp_path / "staging-assets")

    checksums, manifest = build_release_asset_outputs(
        asset_dir, version=VERSION, source_revision=SOURCE_REVISION, expected_tags=TAGS
    )
    again = build_release_asset_outputs(
        asset_dir,
        version=VERSION,
        source_revision=SOURCE_REVISION,
        expected_tags=tuple(reversed(TAGS)),
    )

    assert (checksums, manifest) == again
    parsed = json.loads(manifest)
    assert parsed["schema_version"] == "bluefire.release-assets.v1"
    assert parsed["version"] == VERSION
    assert parsed["source_revision"] == SOURCE_REVISION
    assert parsed["native_runner_version"] == "3.0.0-rc2"
    assert len(parsed["assets"]) == 2
    assert all(item["source_revision"] == SOURCE_REVISION for item in parsed["assets"])
    assert all(item["native_runner_version"] == "3.0.0-rc2" for item in parsed["assets"])
    assert all(item["runner"]["size"] > 0 for item in parsed["assets"])
    assert "unsigned content hashes" in parsed["integrity_note"]
    checksum_lines = checksums.decode("ascii").splitlines()
    assert len(checksum_lines) == 2
    assert all("/" not in line.split("  ", 1)[1] for line in checksum_lines)
    assert {item["published_filename"] for item in parsed["assets"]} == {
        line.split("  ", 1)[1] for line in checksum_lines
    }
    assert all(
        item["staging_wheel_path"].startswith(item["tag"] + "/") for item in parsed["assets"]
    )

    downloaded = tmp_path / "flat-download"
    downloaded.mkdir()
    for line in checksum_lines:
        expected_sha, filename = line.split("  ", 1)
        asset = next(item for item in parsed["assets"] if item["published_filename"] == filename)
        payload = (asset_dir / asset["staging_wheel_path"]).read_bytes()
        (downloaded / filename).write_bytes(payload)
        assert hashlib.sha256((downloaded / filename).read_bytes()).hexdigest() == expected_sha

    write_release_asset_outputs(
        asset_dir, version=VERSION, source_revision=SOURCE_REVISION, expected_tags=TAGS
    )
    before = (
        (asset_dir / "SHA256SUMS").read_bytes(),
        (asset_dir / "release-assets.json").read_bytes(),
    )
    write_release_asset_outputs(
        asset_dir, version=VERSION, source_revision=SOURCE_REVISION, expected_tags=TAGS
    )
    assert before == (
        (asset_dir / "SHA256SUMS").read_bytes(),
        (asset_dir / "release-assets.json").read_bytes(),
    )


def test_missing_or_duplicate_expected_platforms_are_refused(tmp_path):
    _write_asset(tmp_path, TAGS[0])

    with pytest.raises(ValueError, match="expected platform assets are missing"):
        build_release_asset_outputs(
            tmp_path, version=VERSION, source_revision=SOURCE_REVISION, expected_tags=TAGS
        )
    with pytest.raises(ValueError, match="distinct"):
        build_release_asset_outputs(
            tmp_path,
            version=VERSION,
            source_revision=SOURCE_REVISION,
            expected_tags=(TAGS[0], TAGS[0]),
        )


def test_unexpected_asset_names_are_refused(tmp_path):
    asset_dir = _asset_dir(tmp_path)
    (asset_dir / "notes.txt").write_text("unexpected", encoding="utf-8")

    with pytest.raises(ValueError, match="unexpected entries"):
        build_release_asset_outputs(
            asset_dir, version=VERSION, source_revision=SOURCE_REVISION, expected_tags=TAGS
        )


def test_inspection_report_must_bind_exact_wheel_digest(tmp_path):
    _write_asset(
        tmp_path, TAGS[0], report_change=lambda report: report.update(wheel_sha256="0" * 64)
    )

    with pytest.raises(ValueError, match="does not bind"):
        build_release_asset_outputs(
            tmp_path, version=VERSION, source_revision=SOURCE_REVISION, expected_tags=(TAGS[0],)
        )


def test_embedded_native_manifest_must_match_expected_version(tmp_path):
    _write_asset(tmp_path, TAGS[0], native_version="3.0.0")

    with pytest.raises(ValueError, match="native runner manifest"):
        build_release_asset_outputs(
            tmp_path, version=VERSION, source_revision=SOURCE_REVISION, expected_tags=(TAGS[0],)
        )


def test_release_manifest_rejects_invalid_expected_source_revision(tmp_path):
    with pytest.raises(ValueError, match="full lowercase 40-hex"):
        build_release_asset_outputs(
            tmp_path, version=VERSION, source_revision="A" * 40, expected_tags=(TAGS[0],)
        )


def test_wheel_build_identity_must_match_requested_source_revision(tmp_path):
    _write_asset(tmp_path, TAGS[0], source_revision="b" * 40)

    with pytest.raises(ValueError, match="expected source revision and version"):
        build_release_asset_outputs(
            tmp_path,
            version=VERSION,
            source_revision=SOURCE_REVISION,
            expected_tags=(TAGS[0],),
        )


def test_all_wheels_must_share_the_expected_source_revision(tmp_path):
    _write_asset(tmp_path, TAGS[0])
    _write_asset(tmp_path, TAGS[1], source_revision="b" * 40)

    with pytest.raises(ValueError, match="expected source revision and version"):
        build_release_asset_outputs(
            tmp_path, version=VERSION, source_revision=SOURCE_REVISION, expected_tags=TAGS
        )


def test_wheel_build_identity_requires_git_archive_provenance(tmp_path):
    _write_asset(tmp_path, TAGS[0], source_provenance="unavailable")

    with pytest.raises(ValueError, match="expected source revision and version"):
        build_release_asset_outputs(
            tmp_path,
            version=VERSION,
            source_revision=SOURCE_REVISION,
            expected_tags=(TAGS[0],),
        )


def test_wheel_build_identity_must_be_present_well_formed_and_unambiguous(tmp_path):
    _write_asset(tmp_path / "missing", TAGS[0], build_info_missing=True)
    _write_asset(
        tmp_path / "malformed",
        TAGS[0],
        build_info_change=lambda value: value.update(extra=True),
    )
    _write_asset(tmp_path / "shadowed", TAGS[0], build_info_shadow=True)

    for directory, message in (
        (tmp_path / "missing", "build identity"),
        (tmp_path / "malformed", "invalid shape"),
        (tmp_path / "shadowed", "build identity"),
    ):
        with pytest.raises(ValueError, match=message):
            build_release_asset_outputs(
                directory,
                version=VERSION,
                source_revision=SOURCE_REVISION,
                expected_tags=(TAGS[0],),
            )


def test_build_identity_must_share_the_native_manifest_package_root(tmp_path):
    _write_asset(
        tmp_path,
        TAGS[0],
        build_info_layout="platlib",
        runner_layout="purelib",
    )

    with pytest.raises(ValueError, match="different package roots"):
        build_release_asset_outputs(
            tmp_path,
            version=VERSION,
            source_revision=SOURCE_REVISION,
            expected_tags=(TAGS[0],),
        )


def test_native_runner_must_share_the_canonical_manifest_directory(tmp_path):
    # RECORD and the inspection report still bind the misplaced runner's exact bytes.
    _write_asset(
        tmp_path,
        TAGS[0],
        runner_member_path=f"bluefire_nexus-{VERSION}.dist-info/shadow/bluefire/native/bluefire-runner",
    )

    with pytest.raises(ValueError, match="must share the canonical native manifest directory"):
        build_release_asset_outputs(
            tmp_path,
            version=VERSION,
            source_revision=SOURCE_REVISION,
            expected_tags=(TAGS[0],),
        )


@pytest.mark.parametrize("package_layout", ("purelib", "platlib"))
def test_build_identity_accepts_matching_canonical_package_roots(tmp_path, package_layout):
    _write_asset(
        tmp_path,
        TAGS[0],
        build_info_layout=package_layout,
        runner_layout=package_layout,
    )

    _checksums, manifest = build_release_asset_outputs(
        tmp_path,
        version=VERSION,
        source_revision=SOURCE_REVISION,
        expected_tags=(TAGS[0],),
    )
    parsed = json.loads(manifest)
    assert parsed["source_revision"] == SOURCE_REVISION
    assert parsed["assets"][0]["source_revision"] == SOURCE_REVISION


@pytest.mark.parametrize(
    ("changes", "message"),
    (
        (
            {"build_info_change": lambda value: value["ui_files"][0].update(sha256="invalid")},
            "invalid UI inventory",
        ),
        (
            {"build_info_change": lambda value: value.update(ui_digest="sha256:" + "0" * 64)},
            "UI digest is invalid",
        ),
        (
            {"ui_member_change": lambda files: files.update({"app.js": b"changed asset\n"})},
            "does not match its UI member",
        ),
    ),
)
def test_build_identity_binds_ui_inventory_digest_and_actual_members(tmp_path, changes, message):
    _write_asset(tmp_path, TAGS[0], **changes)

    with pytest.raises(ValueError, match=message):
        build_release_asset_outputs(
            tmp_path,
            version=VERSION,
            source_revision=SOURCE_REVISION,
            expected_tags=(TAGS[0],),
        )


def test_packaged_verifier_accepts_only_the_projected_native_rc_version(tmp_path, capsys):
    asset_dir = tmp_path / "assets"
    _write_asset(asset_dir, TAGS[0])
    arguments = Namespace(
        wheel_dir=asset_dir / TAGS[0],
        platform="linux",
        architecture="x86_64",
        wheel_platform_tag=TAGS[0],
        report=tmp_path / "inspection.json",
    )
    assert inspect_wheel(arguments) == 0
    assert json.loads(arguments.report.read_text(encoding="utf-8"))["verified"] is True
    capsys.readouterr()

    wrong_dir = tmp_path / "wrong"
    _write_asset(wrong_dir, TAGS[0], native_version=VERSION)
    arguments.wheel_dir = wrong_dir / TAGS[0]
    with pytest.raises(RuntimeError, match="compatibility contract"):
        inspect_wheel(arguments)


def test_wheel_metadata_must_match_expected_normalized_version(tmp_path):
    _write_asset(tmp_path, TAGS[0], metadata_version="3.0.0-rc2")

    with pytest.raises(ValueError, match="metadata has the wrong"):
        build_release_asset_outputs(
            tmp_path, version=VERSION, source_revision=SOURCE_REVISION, expected_tags=(TAGS[0],)
        )


def test_wheel_metadata_must_use_the_canonical_dist_info_directory(tmp_path):
    _write_asset(tmp_path, TAGS[0], metadata_layout="arbitrary.dist-info")

    with pytest.raises(ValueError, match="metadata file"):
        build_release_asset_outputs(
            tmp_path, version=VERSION, source_revision=SOURCE_REVISION, expected_tags=(TAGS[0],)
        )


def test_wheel_record_must_bind_members_and_have_a_blank_self_entry(tmp_path):
    def change(rows):
        return [
            (
                (name, "sha256=" + "A" * 43, size)
                if name.endswith("/METADATA")
                else (name, digest, size)
            )
            for name, digest, size in rows
        ]

    _write_asset(tmp_path, TAGS[0], record_change=change)

    with pytest.raises(ValueError, match="RECORD does not match"):
        build_release_asset_outputs(
            tmp_path, version=VERSION, source_revision=SOURCE_REVISION, expected_tags=(TAGS[0],)
        )


def test_wheel_record_rejects_nonblank_self_entry_and_duplicate_rows(tmp_path):
    def nonblank_self(rows):
        return [
            (row[0], "sha256=" + "A" * 43, "0") if row[0].endswith("/RECORD") else row
            for row in rows
        ]

    _write_asset(tmp_path, TAGS[0], record_change=nonblank_self)
    with pytest.raises(ValueError, match="leave its own"):
        build_release_asset_outputs(
            tmp_path, version=VERSION, source_revision=SOURCE_REVISION, expected_tags=(TAGS[0],)
        )

    duplicate_dir = tmp_path / "duplicate"
    duplicate_dir.mkdir()

    def duplicate_row(rows):
        return [*rows, rows[0]]

    _write_asset(duplicate_dir, TAGS[0], record_change=duplicate_row)
    with pytest.raises(ValueError, match="duplicate or empty"):
        build_release_asset_outputs(
            duplicate_dir,
            version=VERSION,
            source_revision=SOURCE_REVISION,
            expected_tags=(TAGS[0],),
        )


def test_release_manifest_accepts_canonical_zero_serial_rc(tmp_path):
    version = "3.0.0rc0"
    _write_asset(tmp_path, TAGS[0], version=version)
    _checksums, manifest = build_release_asset_outputs(
        tmp_path, version=version, source_revision=SOURCE_REVISION, expected_tags=(TAGS[0],)
    )
    assert json.loads(manifest)["version"] == version


def test_unsafe_archive_names_are_refused(tmp_path):
    _write_asset(tmp_path, TAGS[0], unsafe=True)

    with pytest.raises(ValueError, match="unsafe member"):
        build_release_asset_outputs(
            tmp_path, version=VERSION, source_revision=SOURCE_REVISION, expected_tags=(TAGS[0],)
        )


def test_different_existing_output_is_never_overwritten(tmp_path):
    asset_dir = _asset_dir(tmp_path)
    (asset_dir / "SHA256SUMS").write_text("old", encoding="ascii")

    with pytest.raises(ValueError, match="overwrite"):
        write_release_asset_outputs(
            asset_dir, version=VERSION, source_revision=SOURCE_REVISION, expected_tags=TAGS
        )
    assert (asset_dir / "SHA256SUMS").read_text(encoding="ascii") == "old"
