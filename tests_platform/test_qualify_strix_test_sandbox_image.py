"""The test-image qualifier remains offline, exact, private, and fail closed."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path
from typing import Any

import pytest

from bluefire import strix_test_sandbox_image as contract
from bluefire.util import canonical_json_bytes, content_hash
from tools import qualify_strix_runtime_candidate as runtime_qualifier
from tools import qualify_strix_test_sandbox_image as qualifier_cli
from tools import strix_test_sandbox_image_build as qualifier
from tools import strix_test_sandbox_qualification as qualification


def _digest(label: str) -> str:
    return content_hash({"qualifier-test": label})


def _add(archive: tarfile.TarFile, name: str, payload: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    info.mode = 0o600
    archive.addfile(info, io.BytesIO(payload))


def _oci_archive(
    path: Path,
    *,
    corrupt_layer: bool = False,
    config_architecture: str = "amd64",
    manifest_size_delta: int = 0,
    layer_size_delta: int = 0,
    index_platform: bool = True,
    index_media_type: bool = True,
) -> dict[str, str]:
    config = canonical_json_bytes(
        {"architecture": config_architecture, "os": "linux", "rootfs": {}}
    )
    layer = b"controlled-layer"
    config_digest = qualifier._sha256_bytes(config)
    layer_digest = qualifier._sha256_bytes(layer)
    manifest = canonical_json_bytes(
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
                    "digest": layer_digest,
                    "size": len(layer) + layer_size_delta,
                }
            ],
        }
    )
    manifest_digest = qualifier._sha256_bytes(manifest)
    manifest_descriptor: dict[str, Any] = {
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": manifest_digest,
        "size": len(manifest) + manifest_size_delta,
    }
    if index_platform:
        manifest_descriptor["platform"] = {"os": "linux", "architecture": "amd64"}
    index_document: dict[str, Any] = {
        "schemaVersion": 2,
        "manifests": [manifest_descriptor],
    }
    if index_media_type:
        index_document["mediaType"] = "application/vnd.oci.image.index.v1+json"
    index = canonical_json_bytes(index_document)
    with tarfile.open(path, "w") as archive:
        _add(archive, "oci-layout", b'{"imageLayoutVersion":"1.0.0"}')
        _add(archive, "index.json", index)
        _add(archive, qualifier._blob_name(manifest_digest), manifest)
        _add(archive, qualifier._blob_name(config_digest), config)
        _add(
            archive,
            qualifier._blob_name(layer_digest),
            b"changed" if corrupt_layer else layer,
        )
    return {"config": config_digest, "manifest": manifest_digest, "layer": layer_digest}


def _runtime_closure() -> dict[str, Any]:
    prelaunch_plan_ref = _digest("prelaunch-plan")
    fixed_exec_qualification_ref = _digest("fixed-exec-qualification")
    return {
        "schema_version": "bluefire.strix-linux-qualified-runtime-composite.v1",
        "composite_ref": content_hash(
            {
                "schema_version": "bluefire.strix-linux-qualified-runtime-composite.v1",
                "prelaunch_plan_ref": prelaunch_plan_ref,
                "fixed_exec_qualification_ref": fixed_exec_qualification_ref,
            }
        ),
        "prelaunch_plan_ref": prelaunch_plan_ref,
        "fixed_exec_qualification_ref": fixed_exec_qualification_ref,
        "inventory_digest": _digest("runtime-inventory"),
        "interpreter_digest": _digest("python"),
        "entrypoint_digest": _digest("worker-entrypoint"),
        "worker_invocation_digest": contract.installed_worker_invocation_digest(),
        "worker_distribution": "bluefire-strix-worker",
        "worker_artifact_digest": _digest("bluefire-strix-worker"),
        "worker_record_digest": _digest("bluefire-strix-worker-record"),
        "worker_source_revision": "a" * 40,
        "installed_distributions_digest": _digest("installed-distributions"),
        "full_product_wheel_present": False,
        "strix_candidate_digest": _digest("strix"),
        "source_revision": contract.STRIX_SOURCE_REVISION,
        "python_version": "3.12.14",
    }


def test_dockerfile_is_pinned_offline_and_removes_runtime_installers() -> None:
    text = qualifier.dockerfile_bytes().decode("utf-8")

    assert text.startswith(f"FROM {contract.BASE_IMAGE['index_reference']} AS assemble\n")
    assert "dpkg -i /opt/bluefire/packages/" in text
    assert "/usr/bin/apt-get" in text
    assert "/usr/bin/dpkg" in text
    assert "FROM scratch" in text
    assert "USER 1000:1000" in text
    assert "WORKDIR /workspace" in text
    assert f'ENTRYPOINT ["{contract.CONTROLLED_ENTRYPOINT}"]' in text
    assert "usestrix/strix-sandbox" not in text
    assert "kali" not in text.lower()
    assert "caido" not in text.lower()
    assert "apt-get install" not in text
    assert "curl http" not in text


def test_docker_commands_cannot_pull_publish_or_attach_to_the_host(tmp_path: Path) -> None:
    tag = "localhost/bluefire/strix-test-sandbox-" + "a" * 32 + ":candidate"
    build = qualifier.docker_build_command(context_root=tmp_path / "context", tag=tag)
    save = qualifier.docker_save_command(tag=tag, docker_archive=tmp_path / "image.docker.tar")
    convert = qualifier.skopeo_convert_command(
        docker_archive=tmp_path / "image.docker.tar", oci_archive=tmp_path / "image.oci.tar"
    )
    self_test = qualifier.docker_self_test_command(
        tag=tag,
        container_name="bluefire-strix-test-" + "a" * 32,
        cleanup_label="bluefire.strix-test-sandbox." + "a" * 32,
    )

    assert "--network" in build and build[build.index("--network") + 1] == "none"
    assert "--no-cache" in build
    assert "--pull=false" in build
    assert "--provenance=false" in build
    assert "--sbom=false" in build
    assert build[build.index("--builder") + 1] == "default"
    assert "--load" in build
    assert "type=oci" not in " ".join(build)
    assert not {"push", "login", "--push", "--cache-to"} & set(build)
    assert save[:3] == ["docker", "image", "save"]
    assert convert[0] == "skopeo"
    assert convert[-2].startswith("docker-archive:")
    assert convert[-1].startswith("oci-archive:")
    assert not any("docker://" in item or "--dest-creds" in item for item in convert)
    assert "--read-only" in self_test
    assert self_test[self_test.index("--network") + 1] == "none"
    assert self_test[self_test.index("--user") + 1] == "1000:1000"
    assert self_test[self_test.index("--cap-drop") + 1] == "ALL"
    assert "host-gateway" not in " ".join(self_test)
    assert "/var/run/docker.sock" not in " ".join(self_test)


def test_oci_layout_binds_index_manifest_config_and_every_layer(tmp_path: Path) -> None:
    expected = _oci_archive(tmp_path / "image.tar")
    identity = qualifier.parse_oci_layout(tmp_path / "image.tar")

    assert identity["platform_child"]["digest"] == expected["manifest"]
    assert identity["config"]["digest"] == expected["config"]
    assert identity["image_id"] == expected["config"]
    assert identity["layers"] == [
        {
            "media_type": "application/vnd.oci.image.layer.v1.tar+gzip",
            "digest": expected["layer"],
            "size": len(b"controlled-layer"),
        }
    ]
    assert identity["index_reference"].startswith("localhost/bluefire/strix-test-sandbox@sha256:")


def test_oci_layout_accepts_single_manifest_without_index_platform(tmp_path: Path) -> None:
    _oci_archive(tmp_path / "image.tar", index_platform=False, index_media_type=False)
    identity = qualifier.parse_oci_layout(tmp_path / "image.tar")
    assert identity["platform_child"]["platform"] == contract.PLATFORM


def test_oci_layout_refuses_changed_blob(tmp_path: Path) -> None:
    _oci_archive(tmp_path / "image.tar", corrupt_layer=True)
    with pytest.raises(qualifier.TestSandboxQualificationError, match="layer digest differs"):
        qualifier.parse_oci_layout(tmp_path / "image.tar")


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"config_architecture": "arm64"}, "config platform differs"),
        ({"manifest_size_delta": 1}, "platform manifest descriptor size differs"),
        ({"layer_size_delta": 1}, "layer descriptor size differs"),
    ],
)
def test_oci_layout_refuses_rehashed_platform_or_descriptor_mismatch(
    tmp_path: Path, options: dict[str, Any], message: str
) -> None:
    _oci_archive(tmp_path / "image.tar", **options)
    with pytest.raises(qualifier.TestSandboxQualificationError, match=message):
        qualifier.parse_oci_layout(tmp_path / "image.tar")


def test_composed_manifest_is_accepted_only_as_test_nonproduction(tmp_path: Path) -> None:
    _oci_archive(tmp_path / "image.tar")
    image_identity = qualifier.parse_oci_layout(tmp_path / "image.tar")
    row = qualifier.compose_contract_document(
        bluefire_revision="a" * 40,
        qualifier_revision="b" * 40,
        runtime_closure=_runtime_closure(),
        provider_digest=_digest("provider"),
        dockerfile_digest=_digest("dockerfile"),
        context_digest=_digest("context"),
        entrypoint_digest=_digest("entrypoint"),
        self_test_digest=_digest("self-test"),
        image_identity=image_identity,
        docker_server_digest=_digest("docker"),
        sbom_digest=_digest("sbom"),
        provenance_digest=_digest("provenance"),
        notice_digest=_digest("notices"),
        self_test_evidence_digest=_digest("self-test-evidence"),
        cleanup_label="bluefire.strix-test-sandbox." + "c" * 32,
    )
    parsed = contract.StrixTestSandboxImageContractV1.from_mapping(row)

    assert parsed.runtime_closure_ref == _runtime_closure()["composite_ref"]
    assert parsed.to_dict()["policy"]["test_only"] is True
    assert parsed.to_dict()["policy"]["production_runtime_admitted"] is False
    assert parsed.to_dict()["policy"]["live_engine_proof"] is False
    assert parsed.to_dict()["policy"]["live_caido_proof"] is False


def test_provider_digest_requires_all_three_exact_maintained_sources(tmp_path: Path) -> None:
    assert qualifier_cli.provider_source_digest is qualifier.provider_source_digest

    entry = tmp_path / "test_caido_protocol_entry.py"
    provider = tmp_path / "test_caido_protocol_provider.py"
    server = tmp_path / "test_caido_protocol_server.py"
    entry.write_text("entry")
    provider.write_text("provider")
    server.write_text("server")

    first = qualifier.provider_source_digest([entry, provider, server])
    assert first.startswith("sha256:")
    server.write_text("changed")
    assert qualifier.provider_source_digest([entry, provider, server]) != first
    with pytest.raises(qualifier.TestSandboxQualificationError, match="exactly three"):
        qualifier.provider_source_digest([provider])
    with pytest.raises(qualifier.TestSandboxQualificationError, match="duplicated"):
        qualifier.provider_source_digest([entry, provider, provider])


def test_missing_docker_is_an_explicit_proof_failure() -> None:
    with pytest.raises(qualifier.TestSandboxQualificationError, match="executable is unavailable"):
        qualifier._run(["bluefire-command-that-does-not-exist-75d3"])


def test_imported_image_identity_must_match_oci_config() -> None:
    expected = _digest("expected-image")
    observed = _digest("foreign-image")
    calls: list[list[str]] = []

    def foreign_image(argv: Any, environment: Any = None) -> qualifier.CommandResult:
        del environment
        calls.append(list(argv))
        return qualifier.CommandResult(0, (f'"{observed}"\n').encode(), b"")

    with pytest.raises(qualifier.TestSandboxQualificationError, match="differs from OCI config"):
        qualification._confirm_imported_image_id(
            runner=foreign_image,
            environment={},
            tag="localhost/bluefire/strix-test-sandbox-" + "f" * 32 + ":candidate",
            expected_id=expected,
        )
    assert len(calls) == 2
    assert all(call[:3] == ["docker", "image", "inspect"] for call in calls)


def test_local_converter_requires_reviewed_package_and_executable(tmp_path: Path) -> None:
    executable = tmp_path / "skopeo"
    executable.write_bytes(b"reviewed executable fixture")

    def reviewed(argv: Any, environment: Any = None) -> qualifier.CommandResult:
        del environment
        if argv == ["skopeo", "--version"]:
            return qualifier.CommandResult(0, b"skopeo version 1.13.3\n", b"")
        if argv == ["dpkg-query", "-W", "-f=${Version}", "skopeo"]:
            return qualifier.CommandResult(0, b"1.13.3+ds1-2ubuntu0.24.04.3", b"")
        raise AssertionError(argv)

    identity = qualification._verify_local_converter(
        runner=reviewed, environment={}, executable=executable
    )
    assert identity["executable_digest"] == qualifier._sha256_file(executable)

    def changed_package(argv: Any, environment: Any = None) -> qualifier.CommandResult:
        result = reviewed(argv, environment)
        if argv[0] == "dpkg-query":
            return qualifier.CommandResult(0, b"1.13.3+ds1-2ubuntu0.24.04.4", b"")
        return result

    with pytest.raises(qualifier.TestSandboxQualificationError, match="package differs"):
        qualification._verify_local_converter(
            runner=changed_package, environment={}, executable=executable
        )


def test_cli_has_only_preparation_qualification_and_bounded_cleanup_subcommands() -> None:
    parser = qualifier_cli._parser()
    subcommands = parser._subparsers._group_actions[0].choices

    assert set(subcommands) == {"prepare-inputs", "qualify", "cleanup", "cleanup-partial"}
    assert "verify" not in subcommands


def test_prepare_inputs_uses_verified_syft_file_identity(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(contract, "OFFLINE_CURL_CLOSURE", ())
    monkeypatch.setattr(qualification, "validate_package_root", lambda root: None)

    def downloaded(url: str, path: Path, digest: str, maximum: int) -> dict[str, Any]:
        del url, digest, maximum
        path.write_bytes(b"reviewed fixture")
        return {"name": path.name, "size": path.stat().st_size, "digest": _digest(path.name)}

    monkeypatch.setattr(qualification, "_download", downloaded)
    monkeypatch.setattr(runtime_qualifier, "_verify_syft_checksums", lambda payload: None)
    monkeypatch.setattr(
        runtime_qualifier,
        "extract_verified_syft",
        lambda archive, destination: runtime_qualifier.FileIdentity(
            destination.name, 4, "a" * 64, "application/x-elf"
        ),
    )

    tool_root = tmp_path / "tools"
    qualification.prepare_inputs(package_root=tmp_path / "packages", tool_root=tool_root)
    receipt = qualification._read_json(tool_root / "input-preparation.json")
    assert receipt["syft_executable"] == {
        "name": "syft",
        "size": 4,
        "digest": "sha256:" + "a" * 64,
    }


def test_self_test_checks_real_tools_readonly_root_and_controller_provider_separation() -> None:
    text = qualifier.self_test_bytes().decode("utf-8")
    entrypoint = qualifier.entrypoint_bytes().decode("utf-8")

    for tool in ("bash", "sh", "curl", "mkdir", "tar", "rm"):
        assert tool in text
    for provider in (
        "test_caido_protocol_entry.py",
        "test_caido_protocol_provider.py",
        "test_caido_protocol_server.py",
    ):
        assert provider in text
    assert "controller_provider_outside_image" in text
    assert "/tmp/bluefire-write-probe" in text
    assert "/var/run/docker.sock" in text
    assert "apt apt-get dpkg apk dnf yum docker podman" in text
    assert "bluefire-strix-worker" in text
    assert "bluefire-nexus" in text
    assert "worker_distribution_present" in text
    assert "full_product_wheel_absent" in text
    assert "exec /runtime/bin/python -I -S -B -X utf8 /bootstrap/worker.py\n" in entrypoint
    assert '"$@"' not in entrypoint


def test_runtime_requires_minimal_worker_record_and_rejects_full_product(tmp_path: Path) -> None:
    runtime_root = tmp_path / "runtime-root"
    site = runtime_root / "runtime/lib/python3.12/site-packages"
    worker = site / "bluefire_strix_worker-0.1.dist-info"
    worker.mkdir(parents=True)
    (worker / "METADATA").write_text("Metadata-Version: 2.3\nName: bluefire-strix-worker\n")
    (worker / "RECORD").write_text("bluefire/worker.py,,\n")
    runtime = _runtime_closure()
    runtime["worker_record_digest"] = qualifier._sha256_file(worker / "RECORD")

    qualifier.validate_worker_distribution(runtime_root, runtime)

    product = site / "bluefire_nexus-3.0.dist-info"
    product.mkdir()
    (product / "METADATA").write_text("Metadata-Version: 2.3\nName: BlueFire_Nexus\n")
    (product / "RECORD").write_text("bluefire/api.py,,\n")
    with pytest.raises(qualifier.TestSandboxQualificationError, match="full BlueFire"):
        qualifier.validate_worker_distribution(runtime_root, runtime)


def test_private_ledger_and_evidence_filenames_are_exact_and_nonartifact_globs() -> None:
    assert qualifier.PRIVATE_LEDGER_FILENAME == "strix-test-sandbox-private-ledger.json"
    assert contract.MANIFEST_FILENAME == "strix-test-sandbox-image-manifest.json"
    assert contract.CLEANUP_FILENAME == "strix-test-sandbox-image-cleanup.json"
    assert qualifier.PARTIAL_CLEANUP_FILENAME == "strix-test-sandbox-image-partial-cleanup.json"
    for name in (
        qualifier.PROVENANCE_FILENAME,
        qualifier.NOTICE_FILENAME,
        qualifier.SBOM_FILENAME,
        qualifier.SELF_TEST_FILENAME,
    ):
        assert "*" not in name and "/" not in name and "\\" not in name


def test_provisional_ledger_prebinds_exact_resources_and_timeout(tmp_path: Path) -> None:
    work_root = (tmp_path / "private" / "work").resolve()
    work_root.mkdir(parents=True)
    row = qualification._private_ledger_document(
        state="reserved",
        runtime_composite_ref=_digest("runtime"),
        provider_source_digest=_digest("provider"),
        cleanup_label="bluefire.strix-test-sandbox." + "d" * 32,
        container_name="bluefire-strix-test-" + "d" * 32,
        image_tag="localhost/bluefire/strix-test-sandbox-" + "d" * 32 + ":candidate",
        image_id=None,
        work_root=work_root,
        context_root=work_root / "context",
        oci_archive=work_root / "image.oci.tar",
    )
    validated = qualification._validate_private_ledger(row)

    assert validated["state"] == "reserved"
    assert validated["command_timeout_seconds"] == qualifier.COMMAND_TIMEOUT_SECONDS == 900
    assert validated["resource_entry"]["image_id"] is None
    changed = dict(row)
    changed["resource_entry"] = dict(row["resource_entry"], image_tag="changed")
    with pytest.raises(qualifier.TestSandboxQualificationError, match="resource entry differs"):
        qualification._validate_private_ledger(changed)


def test_partial_cleanup_removes_reserved_resources_without_minting_contract_receipt(
    tmp_path: Path,
) -> None:
    output_root = (tmp_path / "private" / "output").resolve()
    work_root = (tmp_path / "private" / "work").resolve()
    output_root.mkdir(parents=True)
    (work_root / "context" / "runtime-root").mkdir(parents=True)
    (work_root / "image.oci.tar").write_bytes(b"partial")
    ledger_path = output_root / qualifier.PRIVATE_LEDGER_FILENAME
    ledger = qualification._private_ledger_document(
        state="reserved",
        runtime_composite_ref=_digest("runtime"),
        provider_source_digest=_digest("provider"),
        cleanup_label="bluefire.strix-test-sandbox." + "e" * 32,
        container_name="bluefire-strix-test-" + "e" * 32,
        image_tag="localhost/bluefire/strix-test-sandbox-" + "e" * 32 + ":candidate",
        image_id=None,
        work_root=work_root,
        context_root=work_root / "context",
        oci_archive=work_root / "image.oci.tar",
    )
    qualification._validate_private_ledger(ledger)
    ledger_path.write_bytes(canonical_json_bytes(ledger))

    def absent_runner(argv: Any, environment: Any = None) -> qualifier.CommandResult:
        del environment
        return qualifier.CommandResult(1 if "inspect" in argv else 0, b"", b"")

    receipt_digest = qualification.cleanup_partial(
        ledger_path=ledger_path,
        output_root=output_root,
        docker_socket="unix:///var/run/docker.sock",
        runner=absent_runner,
    )
    receipt = qualifier._read_json(output_root / qualifier.PARTIAL_CLEANUP_FILENAME)

    assert receipt_digest == qualifier._sha256_file(
        output_root / qualifier.PARTIAL_CLEANUP_FILENAME
    )
    assert receipt["qualification_completed"] is False
    assert receipt["contract_cleanup_receipt_emitted"] is False
    assert receipt["container_absent"] is True
    assert receipt["image_absent"] is True
    assert not ledger_path.exists()
    assert not work_root.exists()
    assert not (output_root / contract.CLEANUP_FILENAME).exists()


def test_cleanup_rejects_ledger_pointing_to_other_work_root(tmp_path: Path) -> None:
    output_root = (tmp_path / "private" / "output").resolve()
    outside = (tmp_path / "unrelated" / "work").resolve()
    output_root.mkdir(parents=True)
    outside.mkdir(parents=True)
    sentinel = outside / "keep"
    sentinel.write_text("owned by another task")
    ledger_path = output_root / qualifier.PRIVATE_LEDGER_FILENAME
    ledger = qualification._private_ledger_document(
        state="reserved",
        runtime_composite_ref=_digest("runtime"),
        provider_source_digest=_digest("provider"),
        cleanup_label="bluefire.strix-test-sandbox." + "a" * 32,
        container_name="bluefire-strix-test-" + "a" * 32,
        image_tag="localhost/bluefire/strix-test-sandbox-" + "a" * 32 + ":candidate",
        image_id=None,
        work_root=outside,
        context_root=outside / "context",
        oci_archive=outside / "image.oci.tar",
    )
    ledger_path.write_bytes(canonical_json_bytes(ledger))

    def no_docker(argv: Any, environment: Any = None) -> qualifier.CommandResult:
        raise AssertionError(f"Docker must not run for a foreign ledger: {argv}")

    with pytest.raises(qualifier.TestSandboxQualificationError, match="work root differs"):
        qualification.cleanup_partial(
            ledger_path=ledger_path,
            output_root=output_root,
            docker_socket="unix:///var/run/docker.sock",
            runner=no_docker,
        )
    assert sentinel.read_text() == "owned by another task"


def test_interrupted_conversion_cleans_bound_image_and_both_archives(tmp_path: Path) -> None:
    output_root = (tmp_path / "private" / "output").resolve()
    work_root = (tmp_path / "private" / "work").resolve()
    output_root.mkdir(parents=True)
    work_root.mkdir()
    (work_root / "image.docker.tar").write_bytes(b"partial Docker archive")
    (work_root / "image.oci.tar").write_bytes(b"partial OCI archive")
    image_id = _digest("built-image")
    ledger = qualification._private_ledger_document(
        state="image-bound",
        runtime_composite_ref=_digest("runtime"),
        provider_source_digest=_digest("provider"),
        cleanup_label="bluefire.strix-test-sandbox." + "b" * 32,
        container_name="bluefire-strix-test-" + "b" * 32,
        image_tag="localhost/bluefire/strix-test-sandbox-" + "b" * 32 + ":candidate",
        image_id=image_id,
        work_root=work_root,
        context_root=work_root / "context",
        oci_archive=work_root / "image.oci.tar",
    )
    ledger_path = output_root / qualifier.PRIVATE_LEDGER_FILENAME
    ledger_path.write_bytes(canonical_json_bytes(ledger))
    calls: list[list[str]] = []

    def absent_runner(argv: Any, environment: Any = None) -> qualifier.CommandResult:
        del environment
        calls.append(list(argv))
        return qualifier.CommandResult(1 if "inspect" in argv else 0, b"", b"")

    qualification.cleanup_partial(
        ledger_path=ledger_path,
        output_root=output_root,
        docker_socket="unix:///var/run/docker.sock",
        runner=absent_runner,
    )
    assert ["docker", "image", "rm", "--force", image_id] in calls
    assert not work_root.exists()
    assert not ledger_path.exists()
