from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

import bluefire.tenant_record_sidecar_image as image_module
import tools.retain_tenant_sidecar_image_inputs as input_module
from bluefire.tenant_record_sidecar_image import (
    PINNED_PYTHON_BASE,
    CommandResult,
    FileTargetSidecarBaseAdmissionSource,
    FileTargetSidecarBuildInputSource,
    FileTenantSidecarImageQualificationSource,
    TenantSidecarImageError,
    _dockerfile,
    _write_once,
    cleanup_target_sidecar_images,
    qualify_target_sidecar_image,
)
from bluefire.util import canonical_json_bytes, content_hash

BASE_ID = "sha256:" + "a" * 64
IMAGE_ID = "sha256:" + "b" * 64
BASE_REF = PINNED_PYTHON_BASE


def test_fixed_sidecar_recipe_uses_exact_local_base_and_no_dynamic_entrypoint() -> None:
    wheel = "bluefire_nexus-3.0.0-py3-none-any.whl"
    source = "sha256:" + "c" * 64
    dockerfile = _dockerfile(BASE_REF, wheel, source, "1" * 32).decode("ascii")
    assert dockerfile.startswith(f"FROM {BASE_REF}\n")
    assert f'LABEL bluefire.target.source-artifact="{source}"' in dockerfile
    assert "pip install --no-index --no-deps --no-cache-dir" in dockerfile
    assert "python3 -I -B -c 'import bluefire.tenant_record_target_sidecar'" in dockerfile
    assert "USER 1000:1000" in dockerfile
    assert 'CMD ["python3","-I","-B","-m","bluefire.tenant_record_target_sidecar"]' in dockerfile


@pytest.mark.skipif(os.name != "posix", reason="bounded subprocess custody is Linux-only")
def test_fixed_command_capture_stops_excess_output_and_timeout(tmp_path: Path) -> None:
    with pytest.raises(TenantSidecarImageError, match="output exceeded"):
        image_module._run(
            (sys.executable, "-c", "import sys;sys.stdout.write('x'*3000000)"),
            {"PATH": "/usr/bin:/bin"}, tmp_path, 5,
        )
    with pytest.raises(TenantSidecarImageError, match="timed out"):
        image_module._run(
            (sys.executable, "-c", "import time;time.sleep(5)"),
            {"PATH": "/usr/bin:/bin"}, tmp_path, 1,
        )


def _wheel(path: Path) -> str:
    with zipfile.ZipFile(path, "w") as archive:
        for name in (
            "bluefire/tenant_record_target_sidecar.py",
            "bluefire/tenant_record_target_child.py",
            "bluefire/tenant_record_service.py",
        ):
            archive.writestr(name, b"# fixed package test\n")
        archive.writestr(
            "bluefire_nexus-3.0.0.dist-info/METADATA",
            b"Metadata-Version: 2.3\nName: bluefire-nexus\nVersion: 3.0.0\n",
        )
        archive.writestr("bluefire_nexus-3.0.0.dist-info/RECORD", b"")
        archive.writestr("bluefire/_build_info.json", canonical_json_bytes({
            "schema_version": "bluefire.build-metadata.v1",
            "version": "3.0.0",
            "source_revision": "f" * 40,
            "source_provenance": "git_archive",
        }))
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _inputs(private: Path, wheel: Path, wheel_digest: str, base_config: dict[str, Any]):
    row = {
        "schema_version": "bluefire.tenant-target-image-build-input.v1",
        "wheel_path": str(wheel),
        "wheel_sha256": wheel_digest,
        "installed_payload_digest": "sha256:" + "e" * 64,
        "source_revision": "f" * 40,
        "base_reference": BASE_REF,
        "base_image_id": BASE_ID,
        "base_config_ref": content_hash(base_config),
    }
    row["input_ref"] = content_hash(row)

    _write_once(private, f"build-input-{row['input_ref'][7:]}.json", row)
    return FileTargetSidecarBuildInputSource(private), row["input_ref"]


@pytest.mark.skipif(os.name != "posix", reason="owner-private qualification is Linux-only")
def test_protected_build_inputs_bind_staged_wheel_to_installed_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private = tmp_path / "qualification"
    private.mkdir(mode=0o700)
    staged = private / "staged"
    staged.mkdir(mode=0o700)
    wheel = staged / "bluefire_nexus-3.0.0-py3-none-any.whl"
    wheel_digest = _wheel(wheel)
    base = {
        "schema_version": input_module.BASE_SCHEMA,
        "base_reference": PINNED_PYTHON_BASE,
        "base_image_id": BASE_ID,
        "base_config_ref": content_hash({"Env": ["PYTHON_VERSION=3.12.14"]}),
    }
    base["base_ref"] = content_hash(base)
    _write_once(private, f"base-{base['base_ref'][7:]}.json", base)
    monkeypatch.setattr(input_module, "bind_installed_wheel", lambda *_args, **_kwargs: {
        "wheel_payload_digest": "sha256:" + "e" * 64,
        "installed_payload_digest": "sha256:" + "e" * 64,
    })
    retained = input_module.retain_target_sidecar_build_inputs(
        root=private,
        staged_wheel=wheel,
        service_purelib=private / "venv" / "site-packages",
        installed_version="3.0.0",
        expected_candidate_revision="f" * 40,
        expected_product_wheel_digest=wheel_digest,
        base_admission=FileTargetSidecarBaseAdmissionSource(private),
        base_ref=base["base_ref"],
    )
    assert retained["wheel_sha256"] == wheel_digest
    assert retained["source_revision"] == "f" * 40
    assert FileTargetSidecarBuildInputSource(private).reopen_inputs(retained["input_ref"]) == retained


@pytest.mark.skipif(os.name != "posix", reason="owner-private qualification is Linux-only")
def test_sidecar_image_qualification_builds_offline_and_reopens_exact_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private = tmp_path / "qualification"
    private.mkdir(mode=0o700)
    staged = private / "staged"
    staged.mkdir(mode=0o700)
    wheel = staged / "bluefire_nexus-3.0.0-py3-none-any.whl"
    wheel_digest = _wheel(wheel)
    base_config = {"Env": ["PATH=/usr/local/bin:/usr/bin", "PYTHON_VERSION=3.12.14"], "Cmd": ["python3"]}
    source, input_ref = _inputs(private, wheel, wheel_digest, base_config)
    image_config = {
        "Labels": {"bluefire.target.source-artifact": wheel_digest},
        "User": "1000:1000",
        "Cmd": ["python3", "-I", "-B", "-m", "bluefire.tenant_record_target_sidecar"],
        "Entrypoint": [],
    }
    calls: list[tuple[str, ...]] = []
    built_image = False

    def runner(argv, environment, cwd, timeout):  # type: ignore[no-untyped-def]
        nonlocal built_image
        command = tuple(argv)
        calls.append(command)
        assert cwd == private
        assert environment["DOCKER_CONFIG"] == str(private / "docker-config")
        assert "DOCKER_AUTH_CONFIG" not in environment
        assert timeout <= 600
        if command[3:5] == ("image", "inspect"):
            identity = command[5]
            if identity == BASE_REF:
                row: dict[str, Any] = {
                    "Id": BASE_ID, "Os": "linux", "Architecture": "amd64", "Config": base_config,
                }
            elif identity == IMAGE_ID or identity.startswith("localhost/bluefire/tenant-target-"):
                row = {
                    "Id": IMAGE_ID, "Os": "linux", "Architecture": "amd64", "Config": image_config,
                }
            else:
                raise AssertionError(identity)
            return CommandResult(0, canonical_json_bytes([row]), b"")
        if command[3:5] == ("image", "ls"):
            return CommandResult(0, (IMAGE_ID + "\n").encode() if built_image else b"", b"")
        if command[3:5] == ("image", "rm"):
            assert built_image
            built_image = False
            return CommandResult(0, b"removed", b"")
        assert command[3] == "build"
        assert {"--pull=false", "--network=none", "--no-cache", "--rm"}.issubset(command)
        image_config["Labels"]["bluefire.target.image-build"] = command[
            command.index("--tag") + 1
        ].split("tenant-target-", 1)[1].split(":", 1)[0]
        iid_path = Path(command[command.index("--iidfile") + 1])
        iid_path.write_text(IMAGE_ID + "\n", encoding="ascii")
        built_image = True
        return CommandResult(0, b"fixed build complete", b"")

    monkeypatch.setattr(image_module, "_run", runner)
    monkeypatch.setattr(image_module, "_fixed_docker_executable", lambda: "/usr/bin/docker")
    receipt = qualify_target_sidecar_image(
        build_inputs=source,
        input_ref=input_ref,
        root=private,
    )
    assert receipt["image_id"] == IMAGE_ID
    assert receipt["image_config_ref"] == content_hash(image_config)
    assert receipt["source_artifact_digest"] == wheel_digest
    assert receipt["offline_no_pull_verified"] is True
    assert len(calls) == 5
    assert FileTenantSidecarImageQualificationSource(private).reopen_qualification(
        receipt["receipt_ref"]
    ) == receipt
    cleanup = cleanup_target_sidecar_images(root=private)
    assert cleanup[0]["state"] == "qualified_tag_absent"
    assert cleanup[0]["tag_absent_at_check"] is True
    assert cleanup_target_sidecar_images(root=private) == cleanup
    assert not any(private.glob("context-*"))
    retained = private / f"qualification-{receipt['receipt_ref'][7:]}.json"
    assert stat.S_IMODE(retained.stat().st_mode) == 0o600
    changed = json.loads(retained.read_text(encoding="utf-8"))
    changed["receipt"]["offline_no_pull_verified"] = False
    retained.write_bytes(canonical_json_bytes(changed))
    with pytest.raises(TenantSidecarImageError, match="source digest"):
        FileTenantSidecarImageQualificationSource(private).reopen_qualification(
            receipt["receipt_ref"]
        )


@pytest.mark.skipif(os.name != "posix", reason="owner-private qualification is Linux-only")
def test_pending_image_intent_reconciles_without_launch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    private = tmp_path / "qualification"
    private.mkdir(mode=0o700)
    staged = private / "staged"
    staged.mkdir(mode=0o700)
    wheel = staged / "bluefire_nexus-3.0.0-py3-none-any.whl"
    _wheel(wheel)
    base_config = {"Env": ["PYTHON_VERSION=3.12.14"], "Cmd": ["python3"]}
    source, input_ref = _inputs(private, wheel, "sha256:" + "f" * 64, base_config)
    calls: list[tuple[str, ...]] = []

    def runner(argv, _environment, _cwd, _timeout):  # type: ignore[no-untyped-def]
        command = tuple(argv)
        calls.append(command)
        if command[3:5] == ("image", "inspect"):
            return CommandResult(0, canonical_json_bytes([
                {"Id": BASE_ID, "Os": "linux", "Architecture": "amd64", "Config": base_config}
            ]), b"")
        if command[3:5] == ("image", "ls"):
            return CommandResult(0, b"", b"")
        raise AssertionError("pending build must not launch Docker build or remove images")

    monkeypatch.setattr(image_module, "_run", runner)
    monkeypatch.setattr(image_module, "_fixed_docker_executable", lambda: "/usr/bin/docker")
    with pytest.raises(TenantSidecarImageError, match="wheel digest"):
        qualify_target_sidecar_image(build_inputs=source, input_ref=input_ref, root=private)
    reconciled = cleanup_target_sidecar_images(root=private)
    assert len(reconciled) == 1
    assert reconciled[0]["state"] == "unqualified_build_unsettled"
    assert reconciled[0]["tag_absent_at_check"] is True
    assert all(command[3:5] != ("image", "rm") for command in calls)


@pytest.mark.skipif(os.name != "posix", reason="owner-private qualification is Linux-only")
def test_crashed_build_removes_only_exact_owned_tag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    private = tmp_path / "qualification"
    private.mkdir(mode=0o700)
    build_id = "1" * 32
    wheel_digest = "sha256:" + "c" * 64
    tag = f"localhost/bluefire/tenant-target-{build_id}:qualified"
    intent = {
        "schema_version": image_module.INTENT_SCHEMA,
        "build_id": build_id,
        "image_tag": tag,
        "base_image_id": BASE_ID,
        "input_ref": "sha256:" + "d" * 64,
        "wheel_digest": wheel_digest,
        "build_recipe_digest": "sha256:" + "e" * 64,
    }
    _write_once(private, f"intent-{build_id}.json", {
        **intent, "intent_ref": content_hash(intent),
    })
    present = False
    calls: list[tuple[str, ...]] = []

    def runner(argv, _environment, _cwd, _timeout):  # type: ignore[no-untyped-def]
        nonlocal present
        command = tuple(argv)
        calls.append(command)
        if command[3:5] == ("image", "ls"):
            return CommandResult(0, (IMAGE_ID + "\n").encode() if present else b"", b"")
        if command[3:5] == ("image", "inspect"):
            assert command[5] == tag
            return CommandResult(0, canonical_json_bytes([{
                "Id": IMAGE_ID,
                "Config": {"Labels": {
                    "bluefire.target.source-artifact": wheel_digest,
                    "bluefire.target.image-build": build_id,
                }},
            }]), b"")
        if command[3:5] == ("image", "rm"):
            assert command[-1] == tag
            present = False
            return CommandResult(0, b"removed", b"")
        raise AssertionError("cleanup attempted a launch")

    monkeypatch.setattr(image_module, "_run", runner)
    monkeypatch.setattr(image_module, "_fixed_docker_executable", lambda: "/usr/bin/docker")
    first = cleanup_target_sidecar_images(root=private)
    assert first[0]["state"] == "unqualified_build_unsettled"
    assert first[0]["image_id"] is None
    assert not (private / f"cleanup-{build_id}.json").exists()
    present = True  # The daemon may finish a build after its CLI client died.
    settled = cleanup_target_sidecar_images(root=private)
    assert settled[0]["state"] == "unqualified_build_unsettled"
    assert settled[0]["image_id"] == IMAGE_ID
    assert any(command[3:5] == ("image", "rm") for command in calls)


@pytest.mark.skipif(os.name != "posix", reason="owner-private qualification is Linux-only")
def test_sidecar_image_qualification_rejects_wrong_wheel_before_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private = tmp_path / "qualification"
    private.mkdir(mode=0o700)
    staged = private / "staged"
    staged.mkdir(mode=0o700)
    wheel = staged / "bluefire_nexus-3.0.0-py3-none-any.whl"
    _wheel(wheel)
    base_config = {"Env": ["PYTHON_VERSION=3.12.14"], "Cmd": ["python3"]}
    source, input_ref = _inputs(private, wheel, "sha256:" + "f" * 64, base_config)

    def runner(argv, _environment, _cwd, _timeout):  # type: ignore[no-untyped-def]
        command = tuple(argv)
        if command[3:5] == ("image", "ls"):
            return CommandResult(0, b"", b"")
        if command[3:5] != ("image", "inspect"):
            raise AssertionError("build started before source identity")
        return CommandResult(
            0,
            canonical_json_bytes([
                {"Id": BASE_ID, "Os": "linux", "Architecture": "amd64", "Config": base_config}
            ]),
            b"",
        )

    monkeypatch.setattr(image_module, "_run", runner)
    monkeypatch.setattr(image_module, "_fixed_docker_executable", lambda: "/usr/bin/docker")
    with pytest.raises(TenantSidecarImageError, match="wheel digest"):
        qualify_target_sidecar_image(
            build_inputs=source,
            input_ref=input_ref,
            root=private,
        )
