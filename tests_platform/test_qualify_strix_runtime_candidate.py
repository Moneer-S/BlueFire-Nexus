from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import pytest
import yaml

from tools import qualify_strix_runtime_candidate as qualification

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/strix-runtime-qualification.yml"
DOC = ROOT / "docs/strix-runtime-qualification.md"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _wheel(path: Path, name: str, version: str) -> None:
    dist = f"{name.replace('-', '_')}-{version}.dist-info"
    with zipfile.ZipFile(path, "x") as archive:
        archive.writestr(
            f"{dist}/METADATA",
            f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n\n",
        )
        archive.writestr(
            f"{dist}/WHEEL",
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        archive.writestr(f"{dist}/RECORD", "")


def _oci_fixture(
    *, architecture: str = "amd64", children: int = 1
) -> tuple[str, dict[str, qualification.RegistryResponse]]:
    config = _canonical(
        {
            "architecture": architecture,
            "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": [f"sha256:{'d' * 64}"]},
        }
    )
    config_digest = _digest(config)
    child = _canonical(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": len(config),
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": f"sha256:{'e' * 64}",
                    "size": 1234,
                }
            ],
        }
    )
    child_digest = _digest(child)
    descriptor = {
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": child_digest,
        "size": len(child),
        "platform": {"os": "linux", "architecture": "amd64"},
    }
    index = _canonical(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [descriptor for _ in range(children)],
        }
    )
    index_digest = _digest(index)
    responses = {
        index_digest: qualification.RegistryResponse(
            index, {"docker-content-digest": index_digest}
        ),
        child_digest: qualification.RegistryResponse(
            child, {"docker-content-digest": child_digest}
        ),
        config_digest: qualification.RegistryResponse(config, {}),
    }
    return index_digest, responses


def test_tool_and_image_pins_are_exact() -> None:
    assert qualification.PIP_VERSION == "25.3"
    assert qualification.PIP_WHEEL_SHA256 == (
        "9655943313a94722b7774661c21049070f6bbb0a1516bf02f7c8d5d9201514cd"
    )
    assert qualification.PIP_WHEEL_SIZE == 1_778_622
    assert qualification.SYFT_VERSION == "1.56.0"
    assert qualification.SYFT_ARCHIVE_SHA256 == (
        "1c2493cfcf52d3367d6cb25780d9190c111c2219c34c820574c43e8bae15c528"
    )
    assert qualification.SYFT_CHECKSUMS_SHA256 == (
        "a2db61bc71f8f7ea8c67fc4a81b8e4e6474386e6a07d104bd2e78e964d5d7ec7"
    )
    assert qualification.candidate.SANDBOX_IMAGE.endswith(
        "@sha256:78df914f3029464c9d00580f531ec51025c251c422ec3b09c3f19c5fa6d80c30"
    )


def test_requirements_accept_exact_multiline_hashes() -> None:
    first = "a" * 64
    second = "b" * 64
    payload = (
        "# generated from the frozen lock\n"
        "demo-package==1.2.3 \\\n"
        f"  --hash=sha256:{first} \\\n"
        f"  --hash=sha256:{second}\n"
        "conditional==4.5; python_version >= '3.12' \\\n"
        f"  --hash=sha256:{first}\n"
    ).encode()
    assert qualification.validate_hashed_requirements(payload) == {
        "requirements": 2,
        "hashes": 3,
    }


@pytest.mark.parametrize(
    "line",
    [
        "unhashed==1.0",
        "--index-url https://example.invalid/simple",
        "demo @ https://example.invalid/demo.whl --hash=sha256:" + "a" * 64,
        "-e ./local --hash=sha256:" + "a" * 64,
        "demo==1.0 --find-links ./wheelhouse --hash=sha256:" + "a" * 64,
    ],
)
def test_requirements_reject_resolution_escape_hatches(line: str) -> None:
    with pytest.raises(
        qualification.StrixRuntimeQualificationError,
        match="exact and hash-bound",
    ):
        qualification.validate_hashed_requirements(f"{line}\n".encode())


def test_strict_json_rejects_duplicate_keys() -> None:
    with pytest.raises(qualification.StrixRuntimeQualificationError, match="duplicate JSON"):
        qualification._strict_json(b'{"a":1,"a":2}', label="fixture")


def test_pip_runner_uses_exact_wheel_without_site_initialization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: list[str] = []

    def fake_run(
        arguments: list[str],
        *,
        cwd: Path,
        environment: dict[str, str],
        timeout: int = qualification.COMMAND_TIMEOUT_SECONDS,
    ) -> str:
        del cwd, environment, timeout
        observed.extend(arguments)
        return "pip 25.3 fixture"

    monkeypatch.setattr(qualification, "_run", fake_run)
    python = tmp_path / "python"
    wheel = tmp_path / qualification.PIP_WHEEL_NAME
    assert (
        qualification._run_pip(
            python,
            wheel,
            ["--version"],
            cwd=tmp_path,
            environment={"PATH": "fixture"},
        )
        == "pip 25.3 fixture"
    )
    assert observed[:4] == [str(python), "-I", "-S", "-c"]
    assert observed[4] == qualification._PIP_RUNNER
    assert observed[5:] == [str(wheel), "--version"]


def test_candidate_validation_binds_checksum_source_and_untracked_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (source / "prompt.jinja").write_text("upstream\n", encoding="utf-8")
    commit = "a" * 40
    tree = "d" * 40
    (source / "prompt.jinja").write_text("patched\n", encoding="utf-8")

    def fake_git_run(
        arguments: list[str],
        *,
        cwd: Path,
        environment: dict[str, str],
        timeout: int = qualification.COMMAND_TIMEOUT_SECONDS,
    ) -> str:
        del cwd, environment, timeout
        if arguments[-1] == "HEAD":
            return commit
        if arguments[-1] == "HEAD^{tree}":
            return tree
        if arguments[1:3] == ["status", "--porcelain=v1"]:
            suffix = "\n?? uv.toml" if (source / "uv.toml").exists() else ""
            return f" M prompt.jinja{suffix}"
        raise AssertionError(arguments)

    monkeypatch.setattr(qualification, "_run", fake_git_run)

    monkeypatch.setattr(qualification.candidate, "UPSTREAM_COMMIT", commit)
    monkeypatch.setattr(qualification.candidate, "UPSTREAM_TREE", tree)
    monkeypatch.setattr(qualification.candidate, "PROMPT_PATH", "prompt.jinja")
    candidate_root = tmp_path / "candidate"
    candidate_root.mkdir()
    wheel_name = "strix_agent-1.7.0-py3-none-linux_x86_64.whl"
    wheel_payload = b"candidate wheel fixture"
    (candidate_root / wheel_name).write_bytes(wheel_payload)
    revision = "b" * 40
    manifest = {
        "schema": "bluefire.strix-engine-candidate.v1",
        "status": "built-not-executed",
        "bluefire_source_revision": revision,
        "upstream": {
            "commit": commit,
            "tree": tree,
            "declared_package_version": qualification.candidate.DECLARED_PACKAGE_VERSION,
            "lock_sha256": hashlib.sha256((source / "uv.lock").read_bytes()).hexdigest(),
        },
        "sandbox": {"image": qualification.candidate.SANDBOX_IMAGE},
        "execution": {
            "strix": False,
            "sidecar": False,
            "sandbox": False,
            "target": False,
            "model": False,
        },
        "qualification": {"runtime_qualified": False},
        "policy_overlay": {
            "patched_sha256": hashlib.sha256((source / "prompt.jinja").read_bytes()).hexdigest()
        },
        "artifacts": [
            {
                "path": wheel_name,
                "size": len(wheel_payload),
                "sha256": hashlib.sha256(wheel_payload).hexdigest(),
                "media_type": "application/zip",
            }
        ],
    }
    manifest_payload = qualification._canonical_json(manifest) + b"\n"
    (candidate_root / qualification.candidate.MANIFEST_NAME).write_bytes(manifest_payload)
    (candidate_root / qualification.candidate.CHECKSUMS_NAME).write_text(
        "".join(
            [
                f"{hashlib.sha256(manifest_payload).hexdigest()}  "
                f"{qualification.candidate.MANIFEST_NAME}\n",
                f"{hashlib.sha256(wheel_payload).hexdigest()}  {wheel_name}\n",
            ]
        ),
        encoding="ascii",
    )
    environment = {"PATH": os.environ["PATH"]}
    receipt = qualification.validate_candidate(candidate_root, source, revision, environment)
    assert receipt["wheel_identity"]["sha256"] == hashlib.sha256(wheel_payload).hexdigest()

    (source / "uv.toml").write_text("offline = false\n", encoding="utf-8")
    with pytest.raises(qualification.StrixRuntimeQualificationError, match="reviewed overlay"):
        qualification.validate_candidate(candidate_root, source, revision, environment)


def test_wheelhouse_is_binary_only_bounded_and_unambiguous(tmp_path: Path) -> None:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    _wheel(wheelhouse / "demo_package-1.2.3-py3-none-any.whl", "demo-package", "1.2.3")
    receipt = qualification.inventory_wheelhouse(wheelhouse)
    assert receipt["count"] == 1
    assert receipt["wheels"][0]["normalized_name"] == "demo-package"

    (wheelhouse / "source-1.0.tar.gz").write_bytes(b"not a wheel")
    with pytest.raises(qualification.StrixRuntimeQualificationError, match="non-wheel"):
        qualification.inventory_wheelhouse(wheelhouse)


def test_wheelhouse_rejects_archive_links(tmp_path: Path) -> None:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    wheel = wheelhouse / "demo-1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "x") as archive:
        metadata = zipfile.ZipInfo("demo-1.0.dist-info/METADATA")
        metadata.external_attr = 0o100644 << 16
        archive.writestr(metadata, "Metadata-Version: 2.4\nName: demo\nVersion: 1.0\n")
        linked = zipfile.ZipInfo("demo/link")
        linked.external_attr = 0o120777 << 16
        archive.writestr(linked, "elsewhere")
    with pytest.raises(qualification.StrixRuntimeQualificationError, match="special"):
        qualification.inventory_wheelhouse(wheelhouse)


def test_wheel_inspection_expands_compressed_filename_tags(tmp_path: Path) -> None:
    wheel = tmp_path / "demo-1.0-py2.py3-none-any.whl"
    with zipfile.ZipFile(wheel, "x") as archive:
        archive.writestr(
            "demo-1.0.dist-info/METADATA",
            "Metadata-Version: 2.4\nName: demo\nVersion: 1.0\n\n",
        )
        archive.writestr(
            "demo-1.0.dist-info/WHEEL",
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\n" "Tag: py2-none-any\nTag: py3-none-any\n",
        )
        archive.writestr("demo-1.0.dist-info/RECORD", "")
    receipt = qualification._inspect_wheel(wheel)
    assert receipt["tags"] == ["py2.py3", "none", "any"]


def test_oci_resolution_binds_index_child_config_and_layers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    index_digest, responses = _oci_fixture()
    monkeypatch.setattr(
        qualification.candidate,
        "SANDBOX_IMAGE",
        f"ghcr.io/usestrix/strix-sandbox@{index_digest}",
    )

    def fetch(digest: str, _accept: str) -> qualification.RegistryResponse:
        return responses[digest]

    result = qualification.resolve_oci_identity(fetch)
    assert result["index"]["digest"] == index_digest
    assert result["platform_child"]["platform"] == {
        "os": "linux",
        "architecture": "amd64",
    }
    assert result["layer_count"] == 1
    assert result["image_executed"] is False


def test_oci_resolution_refuses_ambiguous_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    index_digest, responses = _oci_fixture(children=2)
    monkeypatch.setattr(
        qualification.candidate,
        "SANDBOX_IMAGE",
        f"ghcr.io/usestrix/strix-sandbox@{index_digest}",
    )
    with pytest.raises(qualification.StrixRuntimeQualificationError, match="unambiguous"):
        qualification.resolve_oci_identity(lambda digest, _accept: responses[digest])


def test_oci_resolution_refuses_config_platform_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    index_digest, responses = _oci_fixture(architecture="arm64")
    monkeypatch.setattr(
        qualification.candidate,
        "SANDBOX_IMAGE",
        f"ghcr.io/usestrix/strix-sandbox@{index_digest}",
    )
    with pytest.raises(qualification.StrixRuntimeQualificationError, match="platform/rootfs"):
        qualification.resolve_oci_identity(lambda digest, _accept: responses[digest])


def test_oci_resolution_refuses_registry_header_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    index_digest, responses = _oci_fixture()
    monkeypatch.setattr(
        qualification.candidate,
        "SANDBOX_IMAGE",
        f"ghcr.io/usestrix/strix-sandbox@{index_digest}",
    )
    responses[index_digest] = qualification.RegistryResponse(
        responses[index_digest].payload,
        {"docker-content-digest": f"sha256:{'f' * 64}"},
    )
    with pytest.raises(qualification.StrixRuntimeQualificationError, match="confirm OCI index"):
        qualification.resolve_oci_identity(lambda digest, _accept: responses[digest])


def test_oci_descriptor_refuses_foreign_media_and_external_urls() -> None:
    descriptor = {
        "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
        "digest": f"sha256:{'a' * 64}",
        "size": 100,
        "urls": ["https://example.invalid/layer"],
    }
    with pytest.raises(qualification.StrixRuntimeQualificationError, match="external URLs"):
        qualification._validate_descriptor(
            descriptor,
            allowed_media=qualification.LAYER_MEDIA_TYPES,
            label="image layer",
        )
    descriptor.pop("urls")
    descriptor["mediaType"] = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
    with pytest.raises(qualification.StrixRuntimeQualificationError, match="identity is invalid"):
        qualification._validate_descriptor(
            descriptor,
            allowed_media=qualification.LAYER_MEDIA_TYPES,
            label="image layer",
        )


def _syft_archive(path: Path, *, member_name: str = "syft", link: bool = False) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        info = tarfile.TarInfo(member_name)
        if link:
            info.type = tarfile.SYMTYPE
            info.linkname = "elsewhere"
            archive.addfile(info)
        else:
            executable = bytearray(64)
            executable[:6] = b"\x7fELF\x02\x01"
            executable[18:20] = (62).to_bytes(2, "little")
            info.mode = 0o755
            info.size = len(executable)
            archive.addfile(info, io.BytesIO(executable))
    payload = stream.getvalue()
    path.write_bytes(payload)
    return payload


def test_syft_archive_extracts_only_reviewed_elf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "syft.tar.gz"
    payload = _syft_archive(archive)
    monkeypatch.setattr(qualification, "SYFT_ARCHIVE_SHA256", hashlib.sha256(payload).hexdigest())
    destination = tmp_path / "syft"
    receipt = qualification.extract_verified_syft(archive, destination)
    assert receipt.sha256 == hashlib.sha256(destination.read_bytes()).hexdigest()
    if os.name != "nt":
        assert destination.stat().st_mode & stat.S_IXUSR


def test_syft_archive_refuses_links_and_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    linked_archive = tmp_path / "linked.tar.gz"
    payload = _syft_archive(linked_archive, link=True)
    monkeypatch.setattr(qualification, "SYFT_ARCHIVE_SHA256", hashlib.sha256(payload).hexdigest())
    with pytest.raises(qualification.StrixRuntimeQualificationError, match="links or special"):
        qualification.extract_verified_syft(linked_archive, tmp_path / "syft-link")

    traversal_archive = tmp_path / "traversal.tar.gz"
    payload = _syft_archive(traversal_archive, member_name="../syft")
    monkeypatch.setattr(qualification, "SYFT_ARCHIVE_SHA256", hashlib.sha256(payload).hexdigest())
    with pytest.raises(qualification.StrixRuntimeQualificationError, match="unsafe path"):
        qualification.extract_verified_syft(traversal_archive, tmp_path / "syft-traversal")


def test_syft_reports_bind_exact_platform_child() -> None:
    child_digest = f"sha256:{'a' * 64}"
    syft_payload = _canonical(
        {
            "source": {
                "type": "image",
                "metadata": {"manifestDigest": child_digest},
            },
            "artifacts": [{"name": "demo", "version": "1.0", "type": "deb", "licenses": []}],
        }
    )
    cdx_payload = _canonical({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []})
    _syft, _cdx, receipt = qualification.validate_syft_reports(
        syft_payload, cdx_payload, child_digest
    )
    assert receipt["platform_child_digest"] == child_digest
    assert receipt["package_count"] == 1

    with pytest.raises(qualification.StrixRuntimeQualificationError, match="platform child"):
        qualification.validate_syft_reports(
            syft_payload,
            cdx_payload,
            f"sha256:{'b' * 64}",
        )
    misleading_source = _canonical(
        {
            "source": {
                "type": "image",
                "metadata": {
                    "manifestDigest": f"sha256:{'b' * 64}",
                    "userInput": f"ghcr.io/example@{child_digest}",
                },
            },
            "artifacts": [],
        }
    )
    with pytest.raises(qualification.StrixRuntimeQualificationError, match="platform child"):
        qualification.validate_syft_reports(misleading_source, cdx_payload, child_digest)


def test_syft_checksum_file_must_bind_reviewed_archive() -> None:
    qualification._verify_syft_checksums(
        f"{qualification.SYFT_ARCHIVE_SHA256}  {qualification.SYFT_ARCHIVE_NAME}\n".encode()
    )
    with pytest.raises(qualification.StrixRuntimeQualificationError, match="does not bind"):
        qualification._verify_syft_checksums(
            f"{'0' * 64}  {qualification.SYFT_ARCHIVE_NAME}\n".encode()
        )


def test_notices_report_stays_explicitly_unresolved() -> None:
    report = qualification._notices_from_syft(
        {
            "artifacts": [
                {
                    "name": "demo",
                    "version": "1.0",
                    "type": "deb",
                    "licenses": [{"spdxExpression": "MIT"}],
                }
            ]
        },
        f"sha256:{'a' * 64}",
    )
    assert report["package_count"] == 1
    assert report["notices_complete"] is False
    assert report["license_review_complete"] is False
    assert report["redistribution_review_complete"] is False


def test_preparation_manifest_and_checksums_remain_hard_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate_root = tmp_path / "candidate"
    source_root = tmp_path / "source"
    candidate_root.mkdir()
    source_root.mkdir()
    candidate_wheel = candidate_root / "strix_agent-1.7.0-py3-none-linux_x86_64.whl"
    candidate_wheel.write_bytes(b"candidate")
    candidate_sha = hashlib.sha256(b"candidate").hexdigest()

    def fake_validate(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {
            "manifest_sha256": "1" * 64,
            "checksums_sha256": "2" * 64,
            "wheel_path": candidate_wheel,
            "wheel_identity": {
                "path": candidate_wheel.name,
                "size": 9,
                "sha256": candidate_sha,
                "media_type": "application/zip",
            },
            "prompt_sha256": "3" * 64,
            "lock_sha256": "4" * 64,
        }

    def fake_install(
        _work: Path,
        output: Path,
        _source: Path,
        _candidate_identity: dict[str, Any],
        _environment: dict[str, str],
    ) -> dict[str, Any]:
        (output / qualification.REQUIREMENTS_NAME).write_text(
            f"demo==1 --hash=sha256:{'5' * 64}\n", encoding="ascii"
        )
        wheelhouse = output / qualification.WHEELHOUSE_NAME
        wheelhouse.mkdir()
        (wheelhouse / "demo-1-py3-none-any.whl").write_bytes(b"wheel")
        return {
            "engine_imported": False,
            "engine_executed": False,
            "network_resolution_during_install": False,
        }

    def fake_inventory(
        _work: Path, output: Path, _environment: dict[str, str]
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        for name in (
            qualification.OCI_INVENTORY_NAME,
            qualification.SYFT_SBOM_NAME,
            qualification.CYCLONEDX_SBOM_NAME,
            qualification.NOTICES_REVIEW_NAME,
        ):
            (output / name).write_text("{}\n", encoding="utf-8")
        return (
            {"image_executed": False},
            {"name": "syft", "container_executed": False},
            {"notices": {"license_review_complete": False}},
        )

    monkeypatch.setattr(qualification, "validate_candidate", fake_validate)
    monkeypatch.setattr(qualification, "_install_runtime", fake_install)
    monkeypatch.setattr(qualification, "inventory_image_with_syft", fake_inventory)
    fake_git = tmp_path / "git"
    fake_git.write_bytes(b"git fixture")
    monkeypatch.setattr(qualification.shutil, "which", lambda *_args, **_kwargs: str(fake_git))
    monkeypatch.setattr(qualification, "_run", lambda *_args, **_kwargs: "git version fixture")
    work = tmp_path / "qualification-work"
    output = tmp_path / "qualification-output"
    revision = "c" * 40
    manifest = qualification.prepare_runtime_candidate(
        candidate_root,
        source_root,
        work,
        output,
        bluefire_source_revision=revision,
        inherited_environment={"PATH": os.environ["PATH"]},
    )
    assert manifest["status"] == "prepared-not-runtime-qualified"
    assert manifest["qualification"]["runtime_qualified"] is False
    assert manifest["qualification"]["reproducibility_proven"] is False
    assert not any(manifest["execution"].values())
    checksum_paths = {
        line.split("  ", 1)[1]
        for line in (output / qualification.CHECKSUMS_NAME).read_text(encoding="ascii").splitlines()
    }
    observed = {
        path.relative_to(output).as_posix()
        for path in output.rglob("*")
        if path.is_file() and path.name != qualification.CHECKSUMS_NAME
    }
    assert checksum_paths == observed
    stored = json.loads(
        (output / qualification.QUALIFICATION_MANIFEST_NAME).read_text(encoding="utf-8")
    )
    assert stored["qualification"]["runtime_qualified"] is False


@pytest.mark.skipif(os.name == "nt", reason="qualification launcher is Linux-only")
def test_installed_launcher_must_bind_runtime_interpreter(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    site = runtime / "lib/python3.12/site-packages"
    dist = site / "strix_agent-1.7.0.dist-info"
    prompt = site / qualification.candidate.PROMPT_PATH
    cli = runtime / "bin/strix"
    interpreter = runtime / "bin/python"
    for directory in (dist, prompt.parent, cli.parent):
        directory.mkdir(parents=True, exist_ok=True)
    prompt.write_text("prompt\n", encoding="utf-8")
    (dist / "entry_points.txt").write_text(
        "[console_scripts]\nstrix = strix.interface.main:main\n", encoding="utf-8"
    )
    cli.write_text("#!/wrong/python\nfrom strix.interface.main import main\n", encoding="utf-8")
    cli.chmod(0o700)
    (dist / "RECORD").write_text("", encoding="utf-8")
    installed = {
        "strix-agent": {
            "name": "strix-agent",
            "version": "1.7.0",
            "dist_info": dist.name,
        }
    }
    with pytest.raises(qualification.StrixRuntimeQualificationError, match="launcher"):
        qualification._inspect_installed_candidate(
            runtime,
            interpreter,
            site,
            installed,
            hashlib.sha256(prompt.read_bytes()).hexdigest(),
        )


def test_workflow_is_manual_read_only_pinned_and_non_executing() -> None:
    raw = WORKFLOW.read_text(encoding="utf-8")
    workflow = yaml.safe_load(raw)
    triggers = workflow.get("on", workflow.get(True))
    assert triggers == {"workflow_dispatch": None}
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["jobs"]["prepare"]["runs-on"] == "ubuntu-24.04"
    assert workflow["jobs"]["prepare"]["timeout-minutes"] == 60
    assert "retention-days: 3" in raw
    assert "persist-credentials: false" in raw
    for identity in qualification.ACTION_IDENTITIES.values():
        assert f"@{identity}" in raw
    assert "docker run" not in raw.lower()
    assert "podman" not in raw.lower()
    assert "strix scan" not in raw.lower()
    assert "release" not in workflow["jobs"]["prepare"]
    assert '--source-root "$RUNNER_TEMP/bluefire-strix-candidate-work/source"' in raw
    candidate_workflow = (ROOT / ".github/workflows/strix-engine-candidate.yml").read_text(
        encoding="utf-8"
    )
    for identity in qualification.ACTION_IDENTITIES.values():
        assert (
            f"@{identity}" in candidate_workflow
            or identity == qualification.ACTION_IDENTITIES["upload_artifact"]
        )


def test_documentation_does_not_claim_runtime_qualification() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "does not qualify Strix for use" in text
    assert "runtime_qualified: false" in text
    assert "not been dispatched" in text
    assert "license review" in text
    assert "second clean build" in text
