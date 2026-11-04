from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from bluefire import strix_adapter
from bluefire.strix_adapter import (
    OVERLAY_SHA256,
    PATCHED_PROMPT_SHA256,
    REVIEWED_PROMPT_SHA256,
)
from bluefire.strix_runtime_qualification import (
    RUNTIME_QUALIFICATION_LIMITATIONS,
    StrixRuntimeQualificationError,
    load_strix_runtime_qualification,
)
from bluefire.util import canonical_json_bytes
from tools import build_strix_engine_candidate as candidate
from tools import qualify_strix_runtime_admission as admission
from tools import record_strix_runtime_admission_bundle_ref as bundle_recorder

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github/workflows/strix-runtime-admission.yml"
DOC = ROOT / "docs/strix-runtime-admission.md"
PREPARATION_BOUNDARY = ROOT / "tools/strix_runtime_preparation_boundary.sh"
REVISION = "1" * 40


def digest(character: str) -> str:
    return "sha256:" + character * 64


def valid_probe() -> dict[str, object]:
    return {
        "argv": ["--help"],
        "exit_code": 0,
        "stdout": {"bytes": 100, "sha256": digest("a")},
        "stderr": {"bytes": 0, "sha256": digest("e")},
        "elapsed_milliseconds": 100,
        "network_namespace": "isolated-empty",
        "process_namespace": "isolated",
        "mount_namespace": "isolated",
        "probe_uid": 65534,
        "probe_gid": 65534,
        "credential_environment": False,
        "help_tokens_verified": True,
        "runtime_unchanged": True,
        "owned_work_absent": True,
    }


def valid_manifest() -> dict[str, object]:
    return {
        "schema_version": "bluefire.strix-runtime-admission.v1",
        "status": "qualified-installed-cli-startup-only",
        "bluefire_source_revision": REVISION,
        "inputs": {
            "candidate_manifest_ref": digest("1"),
            "candidate_checksums_ref": digest("2"),
            "preparation_manifest_ref": digest("3"),
            "preparation_checksums_ref": digest("4"),
            "runtime_receipt_ref": digest("5"),
            "oci_inventory_ref": digest("9"),
            "transfer_bundle_ref": digest("d"),
            "threat_review_ref": digest("c"),
        },
        "runner": {
            "system": "Linux",
            "release": "6.11.0",
            "machine": "x86_64",
            "image_os": "ubuntu24",
            "image_version": "20261104.1",
        },
        "build_identity": {
            "engine": "strix",
            "package_version": candidate.DECLARED_PACKAGE_VERSION,
            "source_revision": candidate.UPSTREAM_COMMIT,
            "source_tree_sha256": digest("6"),
            "package_sha256": digest("7"),
            "executable_sha256": digest("8"),
            "image_reference": candidate.SANDBOX_IMAGE,
            "image_inventory_sha256": digest("9"),
            "prompt_upstream_sha256": f"sha256:{REVIEWED_PROMPT_SHA256}",
            "prompt_overlay_sha256": f"sha256:{OVERLAY_SHA256}",
            "prompt_patched_sha256": f"sha256:{PATCHED_PROMPT_SHA256}",
        },
        "probe": valid_probe(),
        "execution": {
            "strix_imported": True,
            "strix_cli": True,
            "argv": ["--help"],
            "sidecar": False,
            "sandbox_container": False,
            "target": False,
            "model": False,
            "network": False,
        },
        "qualification": {
            "runtime_qualified": True,
            "production_runtime_admitted": False,
            "scope": "exact-installed-cli-startup-only",
            "reproducibility_proven": False,
            "containment_proven": False,
            "lifecycle_proven": False,
            "target_execution_proven": False,
            "model_execution_proven": False,
            "effectiveness_proven": False,
            "license_review_complete": False,
            "redistribution_authorized": False,
            "limitations": list(RUNTIME_QUALIFICATION_LIMITATIONS),
        },
    }


def write_manifest(path: Path, value: dict[str, object]) -> bytes:
    payload = canonical_json_bytes(value) + b"\n"
    path.write_bytes(payload)
    return payload


def test_loader_returns_only_the_immutable_runtime_admission(tmp_path: Path) -> None:
    path = tmp_path / admission.MANIFEST_NAME
    payload = write_manifest(path, valid_manifest())

    reference = "sha256:" + hashlib.sha256(payload).hexdigest()
    loaded = load_strix_runtime_qualification(path, expected_ref=reference)

    assert loaded.runtime_qualified is True
    assert loaded.production_runtime_admitted is False
    assert loaded.runtime_qualification_ref == reference
    assert loaded.bluefire_source_revision == REVISION
    assert loaded.threat_review_ref == digest("c")
    assert loaded.build.to_dict() == valid_manifest()["build_identity"]
    assert set(loaded.to_dict()) == {
        "runtime_qualification_ref",
        "runtime_qualified",
        "production_runtime_admitted",
        "bluefire_source_revision",
        "threat_review_ref",
        "build",
    }

    with pytest.raises(StrixRuntimeQualificationError, match="reference changed"):
        load_strix_runtime_qualification(path, expected_ref=digest("f"))


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("probe", "network_namespace", "host"),
        ("probe", "credential_environment", True),
        ("probe", "owned_work_absent", False),
        ("execution", "target", True),
        ("execution", "model", True),
        ("execution", "sandbox_container", True),
        ("qualification", "containment_proven", True),
        ("qualification", "production_runtime_admitted", True),
        ("qualification", "effectiveness_proven", True),
        ("qualification", "redistribution_authorized", True),
    ],
)
def test_loader_rejects_broader_or_unqualified_claims(
    tmp_path: Path, section: str, field: str, value: object
) -> None:
    manifest = valid_manifest()
    manifest[section][field] = value  # type: ignore[index]
    path = tmp_path / admission.MANIFEST_NAME
    payload = write_manifest(path, manifest)

    with pytest.raises(StrixRuntimeQualificationError):
        load_strix_runtime_qualification(
            path, expected_ref="sha256:" + hashlib.sha256(payload).hexdigest()
        )


def test_loader_rejects_noncanonical_extra_and_linked_manifests(tmp_path: Path) -> None:
    path = tmp_path / admission.MANIFEST_NAME
    path.write_text(json.dumps(valid_manifest(), indent=2), encoding="utf-8")
    with pytest.raises(StrixRuntimeQualificationError, match="canonical"):
        load_strix_runtime_qualification(path, expected_ref=digest("1"))

    manifest = valid_manifest()
    manifest["claim"] = "broader"
    payload = write_manifest(path, manifest)
    with pytest.raises(StrixRuntimeQualificationError, match="fields"):
        load_strix_runtime_qualification(
            path, expected_ref="sha256:" + hashlib.sha256(payload).hexdigest()
        )


def test_loader_rejects_oversized_and_special_manifests(tmp_path: Path) -> None:
    path = tmp_path / admission.MANIFEST_NAME
    path.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    with pytest.raises(StrixRuntimeQualificationError, match="bounded regular file"):
        load_strix_runtime_qualification(path, expected_ref=digest("1"))

    if not hasattr(os, "mkfifo"):
        return
    path.unlink()
    os.mkfifo(path)
    with pytest.raises(StrixRuntimeQualificationError, match="bounded regular file"):
        load_strix_runtime_qualification(path, expected_ref=digest("1"))


def test_loader_rejects_a_manifest_changed_during_descriptor_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / admission.MANIFEST_NAME
    write_manifest(path, valid_manifest())
    real_fstat = os.fstat
    calls = 0

    def changing_fstat(descriptor: int) -> os.stat_result | SimpleNamespace:
        nonlocal calls
        value = real_fstat(descriptor)
        calls += 1
        if calls != 2:
            return value
        return SimpleNamespace(
            st_mode=value.st_mode,
            st_dev=value.st_dev,
            st_ino=value.st_ino,
            st_size=value.st_size,
            st_mtime_ns=value.st_mtime_ns + 1,
            st_ctime_ns=value.st_ctime_ns,
        )

    monkeypatch.setattr("bluefire.strix_runtime_qualification.os.fstat", changing_fstat)
    with pytest.raises(StrixRuntimeQualificationError, match="changed while being read"):
        load_strix_runtime_qualification(path, expected_ref=digest("1"))


def test_loader_rejects_contradictory_oci_inventory_identity(tmp_path: Path) -> None:
    manifest = valid_manifest()
    manifest["build_identity"]["image_inventory_sha256"] = digest("a")  # type: ignore[index]
    path = tmp_path / admission.MANIFEST_NAME
    payload = write_manifest(path, manifest)
    with pytest.raises(StrixRuntimeQualificationError, match="contradictory"):
        load_strix_runtime_qualification(
            path, expected_ref="sha256:" + hashlib.sha256(payload).hexdigest()
        )

    target = tmp_path / "target.json"
    payload = write_manifest(target, valid_manifest())
    path.unlink()
    try:
        path.symlink_to(target)
    except OSError:
        pytest.skip("current filesystem does not permit a test symlink")
    with pytest.raises(StrixRuntimeQualificationError, match="regular file"):
        load_strix_runtime_qualification(
            path, expected_ref="sha256:" + hashlib.sha256(payload).hexdigest()
        )


def test_checksum_tree_binds_every_regular_file_and_rejects_links(tmp_path: Path) -> None:
    root = tmp_path / "prepared"
    (root / "wheelhouse").mkdir(parents=True)
    first = root / "manifest.json"
    second = root / "wheelhouse/dependency.whl"
    first.write_bytes(b"{}\n")
    second.write_bytes(b"wheel")
    (root / admission.CHECKSUMS_NAME).write_text(
        f"{hashlib.sha256(first.read_bytes()).hexdigest()}  manifest.json\n"
        f"{hashlib.sha256(second.read_bytes()).hexdigest()}  wheelhouse/dependency.whl\n",
        encoding="ascii",
    )
    reference, expected = admission._validate_checksum_tree(root)
    assert reference.startswith("sha256:")
    assert expected == {
        "manifest.json": hashlib.sha256(first.read_bytes()).hexdigest(),
        "wheelhouse/dependency.whl": hashlib.sha256(second.read_bytes()).hexdigest(),
    }

    second.write_bytes(b"changed")
    with pytest.raises(admission.StrixRuntimeAdmissionQualificationError, match="differs"):
        admission._validate_checksum_tree(root)

    second.write_bytes(b"wheel")
    link = root / "linked"
    try:
        link.symlink_to(first)
    except OSError:
        pytest.skip("current filesystem does not permit a test symlink")
    with pytest.raises(admission.StrixRuntimeAdmissionQualificationError, match="link"):
        admission._validate_checksum_tree(root)


def test_qualifier_emits_an_admissible_manifest_without_running_a_real_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate_root = tmp_path / "candidate"
    source_root = tmp_path / "source"
    preparation_root = tmp_path / "preparation"
    work_root = tmp_path / "preparation-work"
    runtime_root = work_root / "runtime"
    output_root = tmp_path / "admission"
    for path in (candidate_root, source_root, preparation_root, runtime_root / "bin"):
        path.mkdir(parents=True)
    (runtime_root / "bin/strix").write_bytes(b"#!/bin/sh\n")
    candidate_payload = b"candidate\n"
    checksums_payload = b"checksums\n"
    (candidate_root / candidate.MANIFEST_NAME).write_bytes(candidate_payload)
    (candidate_root / candidate.CHECKSUMS_NAME).write_bytes(checksums_payload)

    candidate_manifest = {
        "policy_overlay": {
            "upstream_sha256": REVIEWED_PROMPT_SHA256,
            "overlay_sha256": OVERLAY_SHA256,
            "patched_sha256": PATCHED_PROMPT_SHA256,
        },
        "future_install_identity_inputs": {
            "source_tree_sha256": digest("6"),
            "package_sha256": digest("7"),
        },
        "artifacts": [
            {
                "path": candidate.SOURCE_ARCHIVE_NAME,
                "sha256": "6" * 64,
                "size": 10,
                "media_type": "application/x-tar",
            }
        ],
    }
    candidate_identity = {
        "manifest": candidate_manifest,
        "manifest_sha256": hashlib.sha256(candidate_payload).hexdigest(),
        "checksums_sha256": hashlib.sha256(checksums_payload).hexdigest(),
        "wheel_identity": {"path": "strix.whl", "sha256": "7" * 64, "size": 10},
        "prompt_sha256": PATCHED_PROMPT_SHA256,
        "lock_sha256": "8" * 64,
    }
    prep_manifest = {
        "runner": {
            "os": "Linux",
            "release": "6.11.0",
            "machine": "x86_64",
            "image_os": "ubuntu24",
            "image_version": "20261104.1",
        },
        "oci": {
            "pinned_index_reference": candidate.SANDBOX_IMAGE,
            "platform_child": {
                "digest": digest("c"),
                "platform": {"os": "linux", "architecture": "amd64"},
            },
            "image_executed": False,
        },
    }
    runtime: dict[str, object] = {}
    refs = {
        "preparation_manifest_ref": digest("3"),
        "preparation_checksums_ref": digest("4"),
        "runtime_receipt_ref": digest("5"),
        "oci_inventory_ref": digest("9"),
    }
    inspection = {"cli": {"path": "bin/strix", "sha256": "8" * 64}}
    monkeypatch.setattr(
        admission.preparation, "validate_candidate", lambda *_args, **_kwargs: candidate_identity
    )
    monkeypatch.setattr(
        admission,
        "_validate_preparation",
        lambda *_args, **_kwargs: (prep_manifest, runtime, refs),
    )
    monkeypatch.setattr(admission, "_inspect_runtime", lambda *_args, **_kwargs: inspection)
    monkeypatch.setattr(admission.platform, "system", lambda: "Linux")
    monkeypatch.setattr(admission.platform, "release", lambda: "6.11.0")
    monkeypatch.setattr(admission.platform, "machine", lambda: "x86_64")

    manifest = admission.qualify_runtime_admission(
        candidate_root=candidate_root,
        source_root=source_root,
        preparation_root=preparation_root,
        preparation_work_root=work_root,
        output_root=output_root,
        bluefire_source_revision=REVISION,
        transfer_bundle_ref=digest("d"),
        threat_review_ref=digest("c"),
        inherited_environment={
            "BLUEFIRE_IMAGE_OS": "ubuntu24",
            "BLUEFIRE_IMAGE_VERSION": "20261104.1",
        },
        probe_runner=lambda *_args: valid_probe(),
    )

    assert manifest["qualification"]["runtime_qualified"] is True
    assert manifest["qualification"]["scope"] == "exact-installed-cli-startup-only"
    assert manifest["execution"] == {
        "strix_imported": True,
        "strix_cli": True,
        "argv": ["--help"],
        "sidecar": False,
        "sandbox_container": False,
        "target": False,
        "model": False,
        "network": False,
    }
    payload = (output_root / admission.MANIFEST_NAME).read_bytes()
    loaded = load_strix_runtime_qualification(
        output_root / admission.MANIFEST_NAME,
        expected_ref="sha256:" + hashlib.sha256(payload).hexdigest(),
    )
    assert loaded.build.to_dict() == manifest["build_identity"]
    assert not (tmp_path / ".admission-controller-work").exists()


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("source_tree_sha256", digest("a")),
        ("package_sha256", digest("b")),
    ],
)
def test_candidate_future_build_identity_must_match_validated_artifacts(
    field: str, replacement: str
) -> None:
    manifest = {
        "artifacts": [{"path": candidate.SOURCE_ARCHIVE_NAME, "sha256": "6" * 64}],
        "future_install_identity_inputs": {
            "source_tree_sha256": digest("6"),
            "package_sha256": digest("7"),
        },
    }
    manifest["future_install_identity_inputs"][field] = replacement
    identity = {
        "manifest": manifest,
        "wheel_identity": {"sha256": "7" * 64},
    }
    with pytest.raises(
        admission.StrixRuntimeAdmissionQualificationError,
        match="differs from validated artifacts",
    ):
        admission._validated_build_inputs(identity)


def test_candidate_refs_must_match_the_already_validated_bytes(tmp_path: Path) -> None:
    candidate_root = tmp_path / "candidate"
    candidate_root.mkdir()
    manifest_payload = b"candidate\n"
    checksums_payload = b"checksums\n"
    (candidate_root / candidate.MANIFEST_NAME).write_bytes(manifest_payload)
    (candidate_root / candidate.CHECKSUMS_NAME).write_bytes(checksums_payload)
    identity = {
        "manifest_sha256": hashlib.sha256(manifest_payload).hexdigest(),
        "checksums_sha256": hashlib.sha256(checksums_payload).hexdigest(),
    }
    refs = admission._validated_candidate_refs(candidate_root, identity)
    assert refs == (
        "sha256:" + identity["manifest_sha256"],
        "sha256:" + identity["checksums_sha256"],
    )

    identity["manifest_sha256"] = "f" * 64
    with pytest.raises(
        admission.StrixRuntimeAdmissionQualificationError,
        match="changed after validation",
    ):
        admission._validated_candidate_refs(candidate_root, identity)


def test_full_candidate_preparation_runtime_and_oci_path_is_revalidated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate_root = tmp_path / "candidate"
    source_root = tmp_path / "source"
    preparation_root = tmp_path / "preparation"
    work_root = tmp_path / "preparation-work"
    runtime_root = work_root / "runtime"
    site_packages = runtime_root / "lib/python3.12/site-packages"
    dist_info = site_packages / "strix_agent-1.7.0.dist-info"
    prompt_path = site_packages / candidate.PROMPT_PATH
    cli_relative = "Scripts/strix.exe" if os.name == "nt" else "bin/strix"
    cli = runtime_root / cli_relative
    interpreter = runtime_root / "bin/python"
    for path in (
        candidate_root,
        source_root,
        preparation_root,
        dist_info,
        prompt_path.parent,
        cli.parent,
        interpreter.parent,
    ):
        path.mkdir(parents=True, exist_ok=True)

    prompt = b"reviewed patched fixture prompt\n"
    prompt_hash = hashlib.sha256(prompt).hexdigest()
    upstream_hash = hashlib.sha256(b"fixture upstream").hexdigest()
    overlay_hash = hashlib.sha256(b"fixture overlay").hexdigest()
    monkeypatch.setattr(strix_adapter, "REVIEWED_PROMPT_SHA256", upstream_hash)
    monkeypatch.setattr(strix_adapter, "OVERLAY_SHA256", overlay_hash)
    monkeypatch.setattr(strix_adapter, "PATCHED_PROMPT_SHA256", prompt_hash)

    lock = b"version = 1\n"
    (source_root / "uv.lock").write_bytes(lock)
    source_prompt = source_root / candidate.PROMPT_PATH
    source_prompt.parent.mkdir(parents=True)
    source_prompt.write_bytes(prompt)

    source_archive = b"source archive"
    wheel = b"wheel artifact"
    (candidate_root / candidate.SOURCE_ARCHIVE_NAME).write_bytes(source_archive)
    wheel_name = "strix_agent-1.7.0-py3-none-linux_x86_64.whl"
    (candidate_root / wheel_name).write_bytes(wheel)
    source_digest = hashlib.sha256(source_archive).hexdigest()
    wheel_digest = hashlib.sha256(wheel).hexdigest()
    candidate_manifest: dict[str, object] = {
        "schema": "bluefire.strix-engine-candidate.v1",
        "status": "built-not-executed",
        "bluefire_source_revision": REVISION,
        "upstream": {
            "commit": candidate.UPSTREAM_COMMIT,
            "tree": candidate.UPSTREAM_TREE,
            "declared_package_version": candidate.DECLARED_PACKAGE_VERSION,
            "lock_sha256": hashlib.sha256(lock).hexdigest(),
        },
        "sandbox": {"image": candidate.SANDBOX_IMAGE},
        "execution": {"strix": False},
        "qualification": {"runtime_qualified": False},
        "policy_overlay": {
            "upstream_sha256": upstream_hash,
            "overlay_sha256": overlay_hash,
            "patched_sha256": prompt_hash,
        },
        "artifacts": [
            {
                "path": candidate.SOURCE_ARCHIVE_NAME,
                "size": len(source_archive),
                "sha256": source_digest,
            },
            {"path": wheel_name, "size": len(wheel), "sha256": wheel_digest},
        ],
        "future_install_identity_inputs": {
            "source_tree_sha256": f"sha256:{source_digest}",
            "package_sha256": f"sha256:{wheel_digest}",
        },
    }
    candidate_payload = canonical_json_bytes(candidate_manifest) + b"\n"
    (candidate_root / candidate.MANIFEST_NAME).write_bytes(candidate_payload)
    candidate_checksums = "".join(
        f"{hashlib.sha256((candidate_root / name).read_bytes()).hexdigest()}  {name}\n"
        for name in sorted((candidate.MANIFEST_NAME, candidate.SOURCE_ARCHIVE_NAME, wheel_name))
    ).encode("ascii")
    (candidate_root / candidate.CHECKSUMS_NAME).write_bytes(candidate_checksums)

    def fake_git(arguments: list[str], **_kwargs: object) -> str:
        if arguments[-2:] == ["rev-parse", "HEAD"]:
            return candidate.UPSTREAM_COMMIT
        if arguments[-2:] == ["rev-parse", "HEAD^{tree}"]:
            return candidate.UPSTREAM_TREE
        if arguments[1:3] == ["status", "--porcelain=v1"]:
            return f" M {candidate.PROMPT_PATH}"
        raise AssertionError(arguments)

    monkeypatch.setattr(admission.preparation, "_run", fake_git)
    candidate_controller = tmp_path / "candidate-controller"
    candidate_controller.mkdir()
    environment = admission._safe_environment(candidate_controller)
    identity = admission.preparation.validate_candidate(
        candidate_root, source_root, REVISION, environment
    )

    interpreter.write_bytes(b"fixture interpreter")
    cli_payload = (
        b"MZ fixture launcher"
        if os.name == "nt"
        else f"#!{interpreter}\nfrom strix.interface.main import main\n".encode()
    )
    cli.write_bytes(cli_payload)
    cli.chmod(0o755)
    prompt_path.write_bytes(prompt)
    metadata = b"Name: strix-agent\nVersion: 1.7.0\n\n"
    entry_points = b"[console_scripts]\nstrix = strix.interface.main:main\n"
    (dist_info / "METADATA").write_bytes(metadata)
    (dist_info / "entry_points.txt").write_bytes(entry_points)

    def record_row(relative: str, payload: bytes) -> str:
        encoded = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
        return f"{relative},sha256={encoded},{len(payload)}\n"

    cli_record = ("../../../" + cli_relative).replace("\\", "/")
    prompt_record = candidate.PROMPT_PATH
    record = (
        record_row("strix_agent-1.7.0.dist-info/METADATA", metadata)
        + record_row("strix_agent-1.7.0.dist-info/entry_points.txt", entry_points)
        + record_row(prompt_record, prompt)
        + record_row(cli_record, cli_payload)
        + "strix_agent-1.7.0.dist-info/RECORD,,\n"
    ).encode("utf-8")
    (dist_info / "RECORD").write_bytes(record)
    distribution = {
        "name": "strix-agent",
        "version": candidate.DECLARED_PACKAGE_VERSION,
        "metadata_sha256": hashlib.sha256(metadata).hexdigest(),
        "dist_info": dist_info.name,
    }
    installed = {"strix-agent": distribution}
    inspected = admission.preparation._inspect_installed_candidate(
        runtime_root,
        interpreter,
        site_packages,
        installed,
        prompt_hash,
    )
    runtime_receipt = {
        "python": {"runtime_interpreter": admission.preparation._hash_executable(interpreter)},
        "installed_distributions": [distribution],
        "strix": inspected,
        "engine_imported": False,
        "engine_executed": False,
    }
    oci = {
        "pinned_index_reference": candidate.SANDBOX_IMAGE,
        "platform_child": {
            "digest": digest("a"),
            "platform": {"os": "linux", "architecture": "amd64"},
        },
        "image_executed": False,
    }
    preparation_manifest = {
        "schema": "bluefire.strix-runtime-qualification-preparation.v1",
        "status": "prepared-not-runtime-qualified",
        "bluefire_source_revision": REVISION,
        "execution": {"strix": False},
        "qualification": {"runtime_qualified": False},
        "candidate": {
            "manifest_sha256": identity["manifest_sha256"],
            "checksums_sha256": identity["checksums_sha256"],
            "wheel": identity["wheel_identity"],
            "upstream_commit": candidate.UPSTREAM_COMMIT,
            "upstream_tree": candidate.UPSTREAM_TREE,
            "policy_prompt_sha256": prompt_hash,
            "frozen_lock_sha256": hashlib.sha256(lock).hexdigest(),
        },
        "runner": {
            "os": "Linux",
            "release": "job1",
            "machine": "x86_64",
            "image_os": "ubuntu24",
            "image_version": "job1",
        },
        "python_runtime": runtime_receipt,
        "oci": oci,
    }
    prep_files = {
        admission.preparation.QUALIFICATION_MANIFEST_NAME: canonical_json_bytes(
            preparation_manifest
        )
        + b"\n",
        admission.preparation.RUNTIME_RECEIPT_NAME: canonical_json_bytes(runtime_receipt) + b"\n",
        admission.preparation.OCI_INVENTORY_NAME: canonical_json_bytes(oci) + b"\n",
    }
    for name, payload in prep_files.items():
        (preparation_root / name).write_bytes(payload)
    (preparation_root / admission.CHECKSUMS_NAME).write_text(
        "".join(
            f"{hashlib.sha256(payload).hexdigest()}  {name}\n"
            for name, payload in sorted(prep_files.items())
        ),
        encoding="ascii",
    )

    monkeypatch.setattr(admission.platform, "system", lambda: "Linux")
    monkeypatch.setattr(admission.platform, "release", lambda: "job2-kernel")
    monkeypatch.setattr(admission.platform, "machine", lambda: "x86_64")
    manifest = admission.qualify_runtime_admission(
        candidate_root=candidate_root,
        source_root=source_root,
        preparation_root=preparation_root,
        preparation_work_root=work_root,
        output_root=tmp_path / "admission",
        bluefire_source_revision=REVISION,
        transfer_bundle_ref=digest("d"),
        threat_review_ref=digest("c"),
        inherited_environment={
            "BLUEFIRE_IMAGE_OS": "ubuntu24",
            "BLUEFIRE_IMAGE_VERSION": "job2",
        },
        probe_runner=lambda *_args: valid_probe(),
    )
    assert manifest["runner"]["release"] == "job2-kernel"
    assert (
        manifest["inputs"]["oci_inventory_ref"]
        == manifest["build_identity"]["image_inventory_sha256"]
    )
    assert manifest["build_identity"]["source_tree_sha256"] == f"sha256:{source_digest}"
    assert manifest["build_identity"]["package_sha256"] == f"sha256:{wheel_digest}"


def test_fixed_probe_command_has_no_target_model_or_inherited_shell(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    home = tmp_path / "home"
    wrapper = tmp_path / "wrapper"
    command = admission._probe_command(runtime / "bin/strix", runtime, home, wrapper)
    joined = " ".join(map(str, command))
    assert command[0] == "/usr/bin/unshare"
    assert "--net" in command
    assert "--ipc" in command
    assert "--uts" in command
    assert "--pid" in command
    assert "--mount" in command
    assert "--mount-proc" in command
    assert "--target" not in joined
    assert "model" not in joined.lower()
    assert "/bin/sh" not in command


def test_fresh_runner_stage_metadata_requires_root_owned_search_only() -> None:
    sealed = SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o711)
    assert admission._stage_metadata_is_sealed(sealed)  # type: ignore[arg-type]
    for changed in (
        SimpleNamespace(st_uid=1001, st_gid=0, st_mode=stat.S_IFDIR | 0o711),
        SimpleNamespace(st_uid=0, st_gid=1001, st_mode=stat.S_IFDIR | 0o711),
        SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o700),
        SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o755),
    ):
        assert not admission._stage_metadata_is_sealed(changed)  # type: ignore[arg-type]


def test_fresh_runtime_rejects_transferred_requirements_not_derived_from_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work = tmp_path / "bluefire-strix-qualification-work"
    prepared = tmp_path / "bluefire-strix-qualification-output"
    controller = tmp_path / "controller"
    pip_tool = work / "pip-tool"
    pip_tool.mkdir(parents=True)
    prepared.mkdir()
    controller.mkdir()
    pip_payload = b"pinned-pip-fixture"
    (pip_tool / admission.preparation.PIP_WHEEL_NAME).write_bytes(pip_payload)
    transferred = b"evil-dependency==1 --hash=sha256:" + b"a" * 64 + b"\n"
    controller_derived = b"reviewed-dependency==1 --hash=sha256:" + b"b" * 64 + b"\n"
    (prepared / admission.preparation.REQUIREMENTS_NAME).write_bytes(transferred)
    monkeypatch.setattr(admission.preparation, "PIP_WHEEL_SIZE", len(pip_payload))
    monkeypatch.setattr(
        admission.preparation, "PIP_WHEEL_SHA256", hashlib.sha256(pip_payload).hexdigest()
    )
    monkeypatch.setattr(admission.platform, "python_version", lambda: candidate.PYTHON_VERSION)
    monkeypatch.setattr(admission.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(
        admission.preparation,
        "_run_pip",
        lambda *_args, **_kwargs: f"pip {admission.preparation.PIP_VERSION} fixture",
    )
    runtime_receipt = {
        "pip": {
            "path": admission.preparation.PIP_WHEEL_NAME,
            "size": len(pip_payload),
            "sha256": hashlib.sha256(pip_payload).hexdigest(),
            "version_output": f"pip {admission.preparation.PIP_VERSION} fixture",
        }
    }
    with pytest.raises(
        admission.StrixRuntimeAdmissionQualificationError,
        match="controller-held lock export",
    ):
        admission._reconstruct_runtime_offline(
            work,
            prepared,
            {},
            runtime_receipt,
            controller,
            {},
            controller_derived,
        )
    assert not (work / "runtime").exists()


def _fresh_bundle_paths(root: Path) -> tuple[Path, Path, Path, Path, Path]:
    source_work = root / "bluefire-strix-admission-source-work"
    source = source_work / "source"
    source.mkdir(parents=True)
    controller = root / "bluefire-strix-admission-controller-inputs"
    controller.mkdir()
    requirements = controller / admission.preparation.REQUIREMENTS_NAME
    requirements.write_bytes(b"reviewed==1 --hash=sha256:" + b"a" * 64 + b"\n")
    download = root / "bluefire-strix-admission-download"
    download.mkdir()
    bundle = download / "bluefire-strix-admission-input-1-1.tar"
    bundle.write_bytes(b"fixture")
    return source_work, source, requirements, download, bundle


def test_bundle_wrapper_refuses_extra_download_member_and_runs_owned_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(admission, "_sealed_stage_root", lambda path: path.resolve(strict=True))
    source_work, source, requirements, download, bundle = _fresh_bundle_paths(tmp_path)
    extra = download / "unexpected"
    extra.write_bytes(b"do not delete")
    with pytest.raises(
        admission.StrixRuntimeAdmissionQualificationError,
        match="cleanup or absence failed",
    ):
        admission.qualify_runtime_admission_bundle(
            input_bundle=bundle,
            expected_bundle_ref=digest("a"),
            transfer_root=tmp_path,
            source_work_root=source_work,
            source_root=source,
            controller_requirements_path=requirements,
            output_root=tmp_path / "bluefire-strix-admission-output",
            bluefire_source_revision=REVISION,
            threat_review_ref=digest("b"),
            inherited_environment={},
        )
    assert extra.read_bytes() == b"do not delete"
    assert not bundle.exists()
    assert not source_work.exists()
    assert not requirements.parent.exists()
    assert not (tmp_path / "bluefire-strix-admission-output").exists()
    extra.unlink()
    download.rmdir()


def test_bundle_wrapper_refuses_failed_download_directory_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(admission, "_sealed_stage_root", lambda path: path.resolve(strict=True))
    source_work, source, requirements, download, bundle = _fresh_bundle_paths(tmp_path)
    output = tmp_path / "bluefire-strix-admission-output"
    monkeypatch.setattr(
        admission,
        "extract_transfer_bundle",
        lambda *_args, **_kwargs: (
            tmp_path / admission.CANDIDATE_DIRECTORY,
            tmp_path / admission.PREPARATION_DIRECTORY,
            tmp_path / admission.WORK_DIRECTORY,
        ),
    )

    def fake_qualify(**_kwargs: object) -> dict[str, object]:
        output.mkdir()
        (output / admission.MANIFEST_NAME).write_text("invalidated\n", encoding="utf-8")
        return {"qualification": {"runtime_qualified": True}}

    monkeypatch.setattr(admission, "qualify_runtime_admission", fake_qualify)
    real_rmdir = Path.rmdir

    def failing_rmdir(path: Path) -> None:
        if path == download:
            raise OSError("injected download removal failure")
        real_rmdir(path)

    monkeypatch.setattr(Path, "rmdir", failing_rmdir)
    with pytest.raises(
        admission.StrixRuntimeAdmissionQualificationError,
        match="download directory",
    ):
        admission.qualify_runtime_admission_bundle(
            input_bundle=bundle,
            expected_bundle_ref=digest("a"),
            transfer_root=tmp_path,
            source_work_root=source_work,
            source_root=source,
            controller_requirements_path=requirements,
            output_root=output,
            bluefire_source_revision=REVISION,
            threat_review_ref=digest("b"),
            inherited_environment={},
        )
    assert not bundle.exists()
    assert not source_work.exists()
    assert not requirements.parent.exists()
    assert not output.exists()
    assert download.exists() and not any(download.iterdir())
    os.rmdir(download)


def test_fixed_wrapper_hides_management_sockets_and_drops_privilege(tmp_path: Path) -> None:
    wrapper = tmp_path / "isolate-and-probe"
    admission._write_isolation_wrapper(wrapper)
    text = wrapper.read_text(encoding="utf-8")
    assert "mount --make-rprivate /" in text
    assert "tmpfs /run" in text
    assert "size=8m,nr_inodes=1024 tmpfs /tmp" in text
    assert "size=8m,nr_inodes=1024 tmpfs /var/tmp" in text
    assert "size=8m,nr_inodes=1024 tmpfs /dev/shm" in text
    assert "size=1m,nr_inodes=64 tmpfs /dev/mqueue" in text
    assert 'size=8m,nr_inodes=1024 tmpfs "$home"' in text
    assert 'mount --bind "$runtime" "$runtime"' in text
    assert "remount,bind,ro,nosuid,nodev" in text
    assert "--reuid=65534 --regid=65534 --clear-groups --no-new-privs" in text
    assert "--inh-caps=-all --ambient-caps=-all --bounding-set=-all" in text
    assert ("--cpu=10 --as=2147483648 --nproc=64 --nofile=128 --fsize=1048576 --core=0") in text
    assert "/usr/bin/env -i" in text
    assert '"$cli" --help' in text
    assert "--target" not in text
    assert "API_KEY" not in text
    assert wrapper.stat().st_mode & 0o222 == 0


def test_workflow_is_manual_exact_and_unexecuted_by_repository_events() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    dispatch = workflow[True]["workflow_dispatch"]
    assert dispatch["inputs"]["threat_review_ref"]["required"] is True
    assert set(workflow["jobs"]) == {"prepare", "admit"}
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["jobs"]["prepare"]["runs-on"] == "ubuntu-24.04"
    assert workflow["jobs"]["admit"]["runs-on"] == "ubuntu-24.04"
    assert workflow["jobs"]["admit"]["needs"] == "prepare"
    assert workflow["jobs"]["prepare"]["timeout-minutes"] <= 60
    assert workflow["jobs"]["admit"]["timeout-minutes"] <= 30
    source = WORKFLOW.read_text(encoding="utf-8")
    assert "persist-credentials: false" in source
    assert "sudo -n /usr/bin/unshare --net --fork -- /usr/bin/env -i" in source
    assert "qualify_strix_runtime_admission" in source
    assert "secrets." not in source
    assert "id-token:" not in source
    assert "docker run" not in source
    assert "--target" not in source
    assert source.count("retention-days: 3") == 2
    action_steps = [
        step for job in workflow["jobs"].values() for step in job["steps"] if "uses" in step
    ]
    assert action_steps
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", step["uses"]) for step in action_steps)
    checkouts = [step for step in action_steps if step["uses"].startswith("actions/checkout@")]
    assert len(checkouts) == 2
    assert all(step["with"]["ref"] == "${{ github.sha }}" for step in checkouts)
    assert all(step["with"]["persist-credentials"] is False for step in checkouts)
    pythons = [step for step in action_steps if step["uses"].startswith("actions/setup-python@")]
    assert len(pythons) == 2
    assert all(
        step["with"] == {"python-version": "3.12.14", "check-latest": False} for step in pythons
    )
    go = next(step for step in action_steps if step["uses"].startswith("actions/setup-go@"))
    assert go["with"] == {"go-version": "1.24.10", "cache": False}
    uv_steps = [step for step in action_steps if step["uses"].startswith("astral-sh/setup-uv@")]
    assert len(uv_steps) == 2
    assert all(step["with"] == {"version": "0.13.6", "enable-cache": False} for step in uv_steps)
    download = next(
        step for step in action_steps if step["uses"].startswith("actions/download-artifact@")
    )
    assert download["with"] == {
        "artifact-ids": "${{ needs.prepare.outputs.artifact_id }}",
        "path": (
            "${{ runner.temp }}/bluefire-strix-preparation-stage/bluefire-strix-admission-download"
        ),
        "skip-decompress": True,
        "digest-mismatch": "error",
    }
    prepare = workflow["jobs"]["prepare"]
    assert set(prepare["outputs"]) == {"artifact_id", "artifact_digest", "bundle_ref"}
    transfer_upload = next(step for step in prepare["steps"] if step.get("id") == "upload")
    assert transfer_upload["with"]["archive"] is False
    boundary_step = next(step for step in prepare["steps"] if step.get("id") == "bundle")
    boundary_run = boundary_step["run"]
    assert (
        "/usr/bin/unshare --mount --ipc --uts --pid --fork --kill-child=KILL --mount-proc"
        in boundary_run
    )
    assert "strix_runtime_preparation_boundary.sh" in boundary_run
    admit_steps = workflow["jobs"]["admit"]["steps"]
    source_index = next(
        index
        for index, step in enumerate(admit_steps)
        if "reconstruct_strix_runtime_admission_source" in step.get("run", "")
    )
    download_index = next(
        index
        for index, step in enumerate(admit_steps)
        if str(step.get("uses", "")).startswith("actions/download-artifact@")
    )
    assert source_index < download_index
    requirements_index = next(
        index
        for index, step in enumerate(admit_steps)
        if "derive_strix_runtime_admission_requirements" in step.get("run", "")
    )
    assert source_index < requirements_index < download_index
    qualifier_step = next(
        step for step in admit_steps if "qualify_strix_runtime_admission" in step.get("run", "")
    )
    assert admit_steps.index(qualifier_step) > download_index
    assert qualifier_step["run"].startswith(
        "sudo -n /usr/bin/unshare --net --fork -- /usr/bin/env -i"
    )
    admit_run = "\n".join(str(step.get("run", "")) for step in admit_steps)
    assert "build_strix_engine_candidate" not in admit_run
    assert "BLUEFIRE_IMAGE_OS" in admit_run
    assert "--expected-bundle-ref" in admit_run
    assert "--controller-requirements" in admit_run
    assert admit_run.count("bluefire-strix-preparation-stage") >= 7
    assert "STRIX_RUNTIME_ADMISSION_THREAT_REVIEW_REF" in source
    assert "STRIX_RUNTIME_ADMISSION_PREPARE_BACKENDS_REVIEW_REF" in source
    assert "STRIX_RUNTIME_ADMISSION_SOURCE_REVISION" in source
    assert "requested == approved" in source
    assert "requested == backends" in source
    assert "revision == approved_revision" in source
    cleanup = workflow["jobs"]["admit"]["steps"][-1]
    assert cleanup["if"] == "always()"
    assert 'sudo -n rm -rf -- "$stage"' in cleanup["run"]


def test_preparation_boundary_kills_descendants_and_protects_controller_checkout() -> None:
    text = PREPARATION_BOUNDARY.read_text(encoding="utf-8")
    assert "mount --make-rprivate /" in text
    assert "mount --bind /home /home" in text
    assert "mount --bind /opt /opt" in text
    assert "remount,bind,ro,nosuid,nodev" in text
    assert 'mount --bind "$host_runner_temp" "$host_runner_temp"' in text
    assert 'mount --bind "$stage_root" "$stage_root"' in text
    assert "remount,bind,rw,nosuid,nodev" in text
    assert "tmpfs /run" in text
    assert "resolver_target=$(readlink -f -- /etc/resolv.conf)" in text
    assert 'exec 9<"$resolver_target"' in text
    assert "private_resolver=/run/bluefire-resolv.conf" in text
    assert 'mount --bind "$private_resolver" "$resolver_target"' in text
    assert "tmpfs /dev/mqueue" in text
    assert "--no-new-privs" in text
    assert "boundary_uid=65534" in text
    assert "--bounding-set=-all" in text
    assert "--nproc=512 --nofile=1024 --core=0" in text
    assert "/usr/bin/env -i" in text
    assert "tools.build_strix_engine_candidate" in text
    assert "tools.qualify_strix_runtime_candidate" in text
    assert "tools.package_strix_runtime_admission_input" in text
    assert "upload-artifact" not in text
    assert "GITHUB_OUTPUT" not in text


def test_post_boundary_bundle_ref_is_rehashed_before_github_output(tmp_path: Path) -> None:
    stage = tmp_path / "bluefire-strix-preparation-stage"
    stage.mkdir()
    for name in (
        "bluefire-strix-candidate-work",
        admission.CANDIDATE_DIRECTORY,
        admission.WORK_DIRECTORY,
        admission.PREPARATION_DIRECTORY,
    ):
        (stage / name).mkdir()
    source_bundle = stage / "bundle.tar"
    source_bundle.write_bytes(b"exact transfer fixture")
    expected = "sha256:" + hashlib.sha256(source_bundle.read_bytes()).hexdigest()
    reference = stage / "bundle-ref.txt"
    reference.write_bytes(f"bundle_ref={expected}\n".encode("ascii"))
    trusted_bundle = tmp_path / "trusted.tar"
    github_output = tmp_path / "github-output"
    github_output.touch()
    assert (
        bundle_recorder.record_bundle_ref(
            stage_root=stage,
            reference_file=reference,
            source_bundle=source_bundle,
            trusted_bundle=trusted_bundle,
            github_output=github_output,
        )
        == expected
    )
    assert github_output.read_text(encoding="ascii") == f"bundle_ref={expected}\n"
    assert trusted_bundle.read_bytes() == b"exact transfer fixture"
    assert not stage.exists()


def test_post_boundary_bundle_ref_rejects_tampering(tmp_path: Path) -> None:
    stage = tmp_path / "bluefire-strix-preparation-stage"
    stage.mkdir()
    for name in (
        "bluefire-strix-candidate-work",
        admission.CANDIDATE_DIRECTORY,
        admission.WORK_DIRECTORY,
        admission.PREPARATION_DIRECTORY,
    ):
        (stage / name).mkdir()
    source_bundle = stage / "bundle.tar"
    source_bundle.write_bytes(b"tampered")
    reference = stage / "bundle-ref.txt"
    reference.write_bytes(f"bundle_ref={digest('a')}\n".encode("ascii"))
    trusted_bundle = tmp_path / "trusted.tar"
    github_output = tmp_path / "github-output"
    github_output.touch()
    with pytest.raises(ValueError, match="does not match"):
        bundle_recorder.record_bundle_ref(
            stage_root=stage,
            reference_file=reference,
            source_bundle=source_bundle,
            trusted_bundle=trusted_bundle,
            github_output=github_output,
        )
    assert github_output.read_bytes() == b""
    assert not stage.exists()
    assert not trusted_bundle.exists()


def test_documentation_scopes_the_true_qualification() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "runtime_qualified: true" in text
    assert "production_runtime_admitted: false" in text
    assert "installed CLI startup only" in text
    assert "does not qualify" in text
    for phrase in (
        "target",
        "model",
        "containment",
        "lifecycle",
        "effectiveness",
        "redistribution",
    ):
        assert phrase in text.lower()
