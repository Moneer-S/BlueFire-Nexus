"""Qualify and clean one exact runner-private Strix test sandbox image."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence

from bluefire import strix_test_sandbox_image as contract
from bluefire.strix_image_contract import StrixImageContractError
from bluefire.util import canonical_json_bytes, content_hash
from tools.strix_test_sandbox_image_build import (
    _CLEANUP_LABEL,
    _CONTAINER_NAME,
    _IMAGE_TAG,
    _LEDGER_SCHEMA,
    _PARTIAL_CLEANUP_SCHEMA,
    COMMAND_TIMEOUT_SECONDS,
    MAX_RUNTIME_BYTES,
    NOTICE_FILENAME,
    PARTIAL_CLEANUP_FILENAME,
    PRIVATE_LEDGER_FILENAME,
    PROVENANCE_FILENAME,
    SBOM_FILENAME,
    SELF_TEST_FILENAME,
    CommandRunner,
    TestSandboxQualificationError,
    _checked,
    _docker_environment,
    _notice_document,
    _read_json,
    _run,
    _runtime_inventory,
    _safe_empty_directory,
    _sha256_bytes,
    _sha256_file,
    _strict_object,
    _validate_digest,
    _validate_revision,
    _write_canonical,
    compose_contract_document,
    docker_build_command,
    docker_save_command,
    docker_self_test_command,
    parse_oci_layout,
    prepare_context,
    provider_source_digest,
    self_test_bytes,
    skopeo_convert_command,
    validate_package_root,
    validate_runtime_composite_document,
    validate_worker_distribution,
)


def _resource_entry(*, image_tag: str, image_id: str | None, cleanup_label: str) -> dict[str, Any]:
    row: dict[str, Any] = {
        "kind": "runner-private-docker-image",
        "image_tag": image_tag,
        "image_id": image_id,
        "cleanup_label": cleanup_label,
    }
    row["resource_digest"] = content_hash(
        {"schema_version": "bluefire.strix-test-sandbox-resource.v1", **row}
    )
    return row


def _private_ledger_document(
    *,
    state: str,
    runtime_composite_ref: str,
    provider_source_digest: str,
    cleanup_label: str,
    container_name: str,
    image_tag: str,
    image_id: str | None,
    work_root: Path,
    context_root: Path,
    oci_archive: Path,
    contract_digest: str | None = None,
    qualification_ref: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": _LEDGER_SCHEMA,
        "state": state,
        "contract_digest": contract_digest,
        "qualification_ref": qualification_ref,
        "runtime_composite_ref": runtime_composite_ref,
        "provider_source_digest": provider_source_digest,
        "cleanup_label": cleanup_label,
        "container_name": container_name,
        "image_tag": image_tag,
        "image_id": image_id,
        "resource_entry": _resource_entry(
            image_tag=image_tag, image_id=image_id, cleanup_label=cleanup_label
        ),
        "command_timeout_seconds": COMMAND_TIMEOUT_SECONDS,
        "work_root": str(work_root),
        "context_root": str(context_root),
        "oci_archive": str(oci_archive),
        "docker_archive": str(work_root / "image.docker.tar"),
        "staged_runtime_root": str(context_root / "runtime-root"),
    }


def _validate_private_ledger(value: Mapping[str, Any]) -> dict[str, Any]:
    expected_fields = {
        "schema_version",
        "state",
        "contract_digest",
        "qualification_ref",
        "runtime_composite_ref",
        "provider_source_digest",
        "cleanup_label",
        "container_name",
        "image_tag",
        "image_id",
        "resource_entry",
        "command_timeout_seconds",
        "work_root",
        "context_root",
        "oci_archive",
        "docker_archive",
        "staged_runtime_root",
    }
    if set(value) != expected_fields or value.get("schema_version") != _LEDGER_SCHEMA:
        raise TestSandboxQualificationError("private cleanup ledger shape is invalid")
    state = value.get("state")
    if state not in {"reserved", "image-bound", "qualified"}:
        raise TestSandboxQualificationError("private cleanup ledger state is invalid")
    runtime_ref = _validate_digest(
        value.get("runtime_composite_ref"), "runtime composite reference"
    )
    provider_ref = _validate_digest(value.get("provider_source_digest"), "provider digest")
    tag = value.get("image_tag")
    container_name = value.get("container_name")
    cleanup_label = value.get("cleanup_label")
    if not isinstance(tag, str) or _IMAGE_TAG.fullmatch(tag) is None:
        raise TestSandboxQualificationError("private cleanup image tag is invalid")
    if not isinstance(container_name, str) or _CONTAINER_NAME.fullmatch(container_name) is None:
        raise TestSandboxQualificationError("private cleanup container name is invalid")
    if not isinstance(cleanup_label, str) or _CLEANUP_LABEL.fullmatch(cleanup_label) is None:
        raise TestSandboxQualificationError("private cleanup label is invalid")
    run_id = tag.removeprefix("localhost/bluefire/strix-test-sandbox-").removesuffix(":candidate")
    if container_name != f"bluefire-strix-test-{run_id}" or cleanup_label != (
        f"bluefire.strix-test-sandbox.{run_id}"
    ):
        raise TestSandboxQualificationError("private cleanup resource identities differ")
    image_id = value.get("image_id")
    if image_id is not None:
        image_id = _validate_digest(image_id, "private cleanup image ID")
    contract_digest = value.get("contract_digest")
    qualification_ref = value.get("qualification_ref")
    if state == "reserved":
        if image_id is not None or contract_digest is not None or qualification_ref is not None:
            raise TestSandboxQualificationError("reserved cleanup ledger contains later identity")
    elif state == "image-bound":
        if image_id is None or contract_digest is not None or qualification_ref is not None:
            raise TestSandboxQualificationError("image-bound cleanup ledger identity is invalid")
    else:
        _validate_digest(contract_digest, "qualified contract digest")
        _validate_digest(qualification_ref, "qualification reference")
        if image_id is None:
            raise TestSandboxQualificationError("qualified cleanup ledger has no image ID")
    if value.get("command_timeout_seconds") != COMMAND_TIMEOUT_SECONDS:
        raise TestSandboxQualificationError("private cleanup command timeout differs")
    expected_resource = _resource_entry(
        image_tag=tag, image_id=image_id, cleanup_label=cleanup_label
    )
    if value.get("resource_entry") != expected_resource:
        raise TestSandboxQualificationError("private cleanup resource entry differs")
    raw_paths = [
        value.get("work_root"),
        value.get("context_root"),
        value.get("oci_archive"),
        value.get("docker_archive"),
        value.get("staged_runtime_root"),
    ]
    if not all(isinstance(item, str) and item and Path(item).is_absolute() for item in raw_paths):
        raise TestSandboxQualificationError("private cleanup paths are invalid")
    work_root, context_root, oci_archive, docker_archive, runtime_stage_root = (
        Path(item).resolve() for item in raw_paths if isinstance(item, str)
    )
    if (
        len(work_root.parts) < 4
        or context_root != work_root / "context"
        or oci_archive != work_root / "image.oci.tar"
        or docker_archive != work_root / "image.docker.tar"
        or runtime_stage_root != context_root / "runtime-root"
    ):
        raise TestSandboxQualificationError("private cleanup paths are not scoped")
    return {
        **dict(value),
        "runtime_composite_ref": runtime_ref,
        "provider_source_digest": provider_ref,
        "work_root": str(work_root),
        "context_root": str(context_root),
        "oci_archive": str(oci_archive),
        "docker_archive": str(docker_archive),
        "staged_runtime_root": str(runtime_stage_root),
    }


def _write_private_ledger(path: Path, value: Mapping[str, Any]) -> str:
    ledger = _validate_private_ledger(value)
    payload = canonical_json_bytes(ledger)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise TestSandboxQualificationError("private cleanup ledger temporary file already exists")
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise TestSandboxQualificationError(
            "private cleanup ledger could not be committed"
        ) from exc
    return _sha256_bytes(payload)


def _existing_scoped_directory(path: Path, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise TestSandboxQualificationError(f"{label} is unavailable") from exc
    if resolved == Path(resolved.anchor) or len(resolved.parts) < 4:
        raise TestSandboxQualificationError(f"{label} is too broad")
    if not resolved.is_dir() or resolved.is_symlink():
        raise TestSandboxQualificationError(f"{label} is invalid")
    return resolved


def _confirm_imported_image_id(
    *, runner: CommandRunner, environment: Mapping[str, str], tag: str, expected_id: str
) -> None:
    inspect_command = ["docker", "image", "inspect", tag, "--format", "{{json .Id}}"]
    inspect = runner(inspect_command, environment)
    if inspect.returncode != 0:
        _checked(runner, ["docker", "tag", expected_id, tag], environment)
    imported_id = _read_docker_image_id(runner, environment, tag)
    if imported_id != expected_id:
        raise TestSandboxQualificationError("imported Docker image ID differs from OCI config")


def _read_docker_image_id(
    runner: CommandRunner, environment: Mapping[str, str], reference: str
) -> str:
    try:
        image_id = json.loads(
            _checked(
                runner,
                ["docker", "image", "inspect", reference, "--format", "{{json .Id}}"],
                environment,
            )
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TestSandboxQualificationError("Docker image ID is invalid") from exc
    return _validate_digest(image_id, "Docker image ID")


def _confirm_runtime_inventory(root: Path, expected_digest: str) -> None:
    try:
        from tools.strix_runtime_closure_prepare_core import runtime_inventory_digest
    except ImportError as exc:
        raise TestSandboxQualificationError(
            "qualified runtime inventory helper is unavailable"
        ) from exc
    if runtime_inventory_digest(root) != expected_digest:
        raise TestSandboxQualificationError("qualified runtime inventory differs")


def _verify_local_converter(
    *, runner: CommandRunner, environment: Mapping[str, str], executable: Path
) -> dict[str, str]:
    version = _checked(runner, ["skopeo", "--version"], environment).strip()
    if version != b"skopeo version 1.13.3":
        raise TestSandboxQualificationError("reviewed Skopeo version differs")
    package = _checked(runner, ["dpkg-query", "-W", "-f=${Version}", "skopeo"], environment).strip()
    if package != b"1.13.3+ds1-2ubuntu0.24.04.3":
        raise TestSandboxQualificationError("reviewed Skopeo package differs")
    return {
        "version": version.decode("ascii"),
        "package_version": package.decode("ascii"),
        "executable_digest": _sha256_file(executable),
    }


def qualify(
    *,
    bluefire_revision: str,
    qualifier_revision: str,
    runtime_root: Path,
    runtime_composite_manifest: Path,
    runtime_composite_ref: str,
    provider_sources: Sequence[Path],
    expected_provider_digest: str,
    package_root: Path,
    output_root: Path,
    work_root: Path,
    docker_socket: str,
    syft_path: Path,
    runner: CommandRunner = _run,
) -> contract.StrixTestSandboxImageContractV1:
    bluefire_revision = _validate_revision(bluefire_revision, "BlueFire revision")
    qualifier_revision = _validate_revision(qualifier_revision, "qualifier revision")
    runtime_composite_ref = _validate_digest(runtime_composite_ref, "runtime composite reference")
    expected_provider_digest = _validate_digest(expected_provider_digest, "provider digest")
    output_root = _safe_empty_directory(output_root)
    work_root = _safe_empty_directory(work_root)
    _validate_cleanup_work_root({"work_root": str(work_root)}, output_root)
    if not syft_path.is_file() or syft_path.is_symlink():
        raise TestSandboxQualificationError("verified Syft executable is unavailable")
    runtime_document = validate_runtime_composite_document(
        _read_json(runtime_composite_manifest),
        bluefire_revision=bluefire_revision,
        expected_ref=runtime_composite_ref,
    )
    _confirm_runtime_inventory(runtime_root, runtime_document["inventory_digest"])
    _runtime_inventory(runtime_root)
    validate_worker_distribution(runtime_root, runtime_document)
    if _sha256_file(runtime_root / "runtime/bin/python") != runtime_document.get(
        "interpreter_digest"
    ):
        raise TestSandboxQualificationError("runtime interpreter digest differs")
    if _sha256_file(runtime_root / "bootstrap/worker.py") != runtime_document.get(
        "entrypoint_digest"
    ):
        raise TestSandboxQualificationError("runtime worker entrypoint digest differs")
    observed_provider_digest = provider_source_digest(provider_sources)
    if observed_provider_digest != expected_provider_digest:
        raise TestSandboxQualificationError("provider source digest differs")
    validate_package_root(package_root)

    environment = _docker_environment(docker_socket)
    docker_version = _checked(
        runner, ["docker", "version", "--format", "{{json .Server}}"], environment
    )
    if not docker_version.strip():
        raise TestSandboxQualificationError("Docker server identity is empty")
    docker_server_digest = _sha256_bytes(docker_version.strip())
    builder = _checked(runner, ["docker", "buildx", "inspect", "default"], environment)
    if re.search(rb"(?m)^Driver:[ \t]*docker[ \t]*$", builder) is None:
        raise TestSandboxQualificationError("reviewed local Docker builder differs")
    skopeo_executable = shutil.which("skopeo")
    if skopeo_executable is None:
        raise TestSandboxQualificationError("reviewed Skopeo executable is unavailable")
    if Path(skopeo_executable).resolve() != Path("/usr/bin/skopeo"):
        raise TestSandboxQualificationError("reviewed Skopeo executable path differs")
    converter = _verify_local_converter(
        runner=runner, environment=environment, executable=Path(skopeo_executable)
    )
    base_id = _read_docker_image_id(runner, environment, contract.BASE_IMAGE["index_reference"])
    if base_id != contract.BASE_IMAGE["config"]["digest"]:
        raise TestSandboxQualificationError("preloaded base image ID differs")

    run_id = uuid.uuid4().hex
    tag = f"localhost/bluefire/strix-test-sandbox-{run_id}:candidate"
    cleanup_label = f"bluefire.strix-test-sandbox.{run_id}"
    container_name = f"bluefire-strix-test-{run_id}"
    context_root = work_root / "context"
    oci_archive = work_root / "image.oci.tar"
    docker_archive = work_root / "image.docker.tar"
    ledger_path = output_root / PRIVATE_LEDGER_FILENAME
    _write_private_ledger(
        ledger_path,
        _private_ledger_document(
            state="reserved",
            runtime_composite_ref=runtime_composite_ref,
            provider_source_digest=observed_provider_digest,
            cleanup_label=cleanup_label,
            container_name=container_name,
            image_tag=tag,
            image_id=None,
            work_root=work_root,
            context_root=context_root,
            oci_archive=oci_archive,
        ),
    )
    dockerfile_digest, entrypoint_digest, context_digest = prepare_context(
        context_root,
        runtime_root=runtime_root,
        package_root=package_root,
    )
    _confirm_runtime_inventory(context_root / "runtime-root", runtime_document["inventory_digest"])
    self_test_digest = _sha256_bytes(self_test_bytes())
    _checked(
        runner,
        docker_build_command(context_root=context_root, tag=tag),
        environment,
    )
    built_id = _read_docker_image_id(runner, environment, tag)
    _write_private_ledger(
        ledger_path,
        _private_ledger_document(
            state="image-bound",
            runtime_composite_ref=runtime_composite_ref,
            provider_source_digest=observed_provider_digest,
            cleanup_label=cleanup_label,
            container_name=container_name,
            image_tag=tag,
            image_id=built_id,
            work_root=work_root,
            context_root=context_root,
            oci_archive=oci_archive,
        ),
    )
    _checked(runner, docker_save_command(tag=tag, docker_archive=docker_archive), environment)
    _checked(
        runner,
        skopeo_convert_command(docker_archive=docker_archive, oci_archive=oci_archive),
        environment,
    )
    image_identity = parse_oci_layout(oci_archive)
    if image_identity["image_id"] != built_id:
        raise TestSandboxQualificationError("OCI config differs from built Docker image")
    _checked(runner, ["docker", "image", "rm", "--force", tag], environment)
    if runner(["docker", "image", "inspect", built_id], environment).returncode == 0:
        _checked(runner, ["docker", "image", "rm", "--force", built_id], environment)
    if runner(["docker", "image", "inspect", built_id], environment).returncode == 0:
        raise TestSandboxQualificationError("built image could not be removed before import")
    _checked(runner, ["docker", "load", "--input", str(docker_archive)], environment)
    _confirm_imported_image_id(
        runner=runner,
        environment=environment,
        tag=tag,
        expected_id=image_identity["image_id"],
    )

    self_test_output = _checked(
        runner,
        docker_self_test_command(
            tag=tag, container_name=container_name, cleanup_label=cleanup_label
        ),
        environment,
    )
    self_test_document = _strict_object(self_test_output, "sandbox self-test")
    expected_self_test = {
        "schema_version": "bluefire.strix-test-sandbox-self-test.v1",
        "uid": 1000,
        "gid": 1000,
        "working_directory": "/workspace",
        "controller_provider_outside_image": True,
        "package_manager_absent": True,
        "docker_socket_absent": True,
        "read_only_root_observed": True,
        "worker_distribution_present": True,
        "full_product_wheel_absent": True,
    }
    if self_test_document != expected_self_test:
        raise TestSandboxQualificationError("sandbox self-test result differs")
    self_test_evidence_digest = _write_canonical(
        output_root / SELF_TEST_FILENAME, self_test_document
    )
    _checked(
        runner,
        [str(syft_path), f"docker:{tag}", "-o", f"cyclonedx-json={output_root / SBOM_FILENAME}"],
        environment,
    )
    sbom_digest = _sha256_file(output_root / SBOM_FILENAME, maximum=64 * 1024 * 1024)
    notice_digest = _write_canonical(output_root / NOTICE_FILENAME, _notice_document())
    provenance_document = {
        "schema_version": "bluefire.strix-test-sandbox-provenance.v1",
        "bluefire_source_revision": bluefire_revision,
        "qualifier_revision": qualifier_revision,
        "base_index_digest": contract.BASE_IMAGE["index"]["digest"],
        "package_lock_digest": contract.package_lock_digest(),
        "runtime_composite_ref": runtime_composite_ref,
        "provider_source_digest": observed_provider_digest,
        "dockerfile_digest": dockerfile_digest,
        "context_digest": context_digest,
        "image_index_digest": image_identity["index"]["digest"],
        "image_manifest_digest": image_identity["platform_child"]["digest"],
        "image_config_digest": image_identity["config"]["digest"],
        "docker_archive_digest": _sha256_file(docker_archive, maximum=MAX_RUNTIME_BYTES),
        "skopeo_version": converter["version"],
        "skopeo_package_version": converter["package_version"],
        "skopeo_executable_digest": converter["executable_digest"],
        "sbom_digest": sbom_digest,
        "build_network": "none",
        "image_conversion": "local-docker-archive-to-oci-archive",
        "pull": False,
        "runner_private": True,
        "image_uploaded": False,
        "image_published": False,
    }
    provenance_digest = _write_canonical(output_root / PROVENANCE_FILENAME, provenance_document)
    document = compose_contract_document(
        bluefire_revision=bluefire_revision,
        qualifier_revision=qualifier_revision,
        runtime_closure=runtime_document,
        provider_digest=observed_provider_digest,
        dockerfile_digest=dockerfile_digest,
        context_digest=context_digest,
        entrypoint_digest=entrypoint_digest,
        self_test_digest=self_test_digest,
        image_identity=image_identity,
        docker_server_digest=docker_server_digest,
        sbom_digest=sbom_digest,
        provenance_digest=provenance_digest,
        notice_digest=notice_digest,
        self_test_evidence_digest=self_test_evidence_digest,
        cleanup_label=cleanup_label,
    )
    try:
        qualified = contract.StrixTestSandboxImageContractV1.from_mapping(document)
    except StrixImageContractError as exc:
        raise TestSandboxQualificationError("qualified image manifest is invalid") from exc
    manifest_path = output_root / contract.MANIFEST_FILENAME
    manifest_path.write_bytes(qualified.canonical_bytes)
    reopened = contract.StrixTestSandboxImageContractV1(manifest_path.read_bytes())
    if reopened.contract_digest != qualified.contract_digest:
        raise TestSandboxQualificationError("written image manifest differs")
    _write_private_ledger(
        ledger_path,
        _private_ledger_document(
            state="qualified",
            runtime_composite_ref=runtime_composite_ref,
            provider_source_digest=observed_provider_digest,
            cleanup_label=cleanup_label,
            container_name=container_name,
            image_tag=tag,
            image_id=image_identity["image_id"],
            work_root=work_root,
            context_root=context_root,
            oci_archive=oci_archive,
            contract_digest=qualified.contract_digest,
            qualification_ref=qualified.qualification_ref,
        ),
    )
    return qualified


def _remove_tree(path: Path) -> bool:
    try:
        if path.exists():
            shutil.rmtree(path)
        return not path.exists()
    except OSError:
        return False


def _cleanup_private_resources(
    ledger: Mapping[str, Any],
    *,
    docker_socket: str,
    runner: CommandRunner,
) -> dict[str, bool]:
    environment = _docker_environment(docker_socket)
    container_name = str(ledger["container_name"])
    image_tag = str(ledger["image_tag"])
    image_id = ledger["image_id"]
    runner(["docker", "rm", "--force", container_name], environment)
    runner(["docker", "image", "rm", "--force", image_tag], environment)
    if isinstance(image_id, str):
        runner(["docker", "image", "rm", "--force", image_id], environment)
    container_absent = (
        runner(["docker", "container", "inspect", container_name], environment).returncode != 0
    )
    image_absent = runner(["docker", "image", "inspect", image_tag], environment).returncode != 0
    if isinstance(image_id, str):
        image_absent = image_absent and (
            runner(["docker", "image", "inspect", image_id], environment).returncode != 0
        )
    work_root = Path(str(ledger["work_root"]))
    context_root = Path(str(ledger["context_root"]))
    oci_archive = Path(str(ledger["oci_archive"]))
    docker_archive = Path(str(ledger["docker_archive"]))
    runtime_stage_root = Path(str(ledger["staged_runtime_root"]))
    removed = container_absent and image_absent and _remove_tree(work_root)
    return {
        "container_absent": container_absent,
        "network_absent": True,
        "image_absent": image_absent,
        "build_context_absent": removed and not context_root.exists(),
        "oci_layout_absent": removed and not oci_archive.exists(),
        "docker_archive_absent": removed and not docker_archive.exists(),
        "runtime_stage_absent": removed and not runtime_stage_root.exists(),
    }


def _validate_cleanup_location(*, ledger_path: Path, output_root: Path) -> tuple[Path, Path]:
    output_root = _existing_scoped_directory(output_root, "cleanup output directory")
    try:
        ledger_path = ledger_path.resolve(strict=True)
    except OSError as exc:
        raise TestSandboxQualificationError("private cleanup ledger is unavailable") from exc
    if ledger_path.parent != output_root or ledger_path.name != PRIVATE_LEDGER_FILENAME:
        raise TestSandboxQualificationError("private cleanup ledger location differs")
    return ledger_path, output_root


def _validate_cleanup_work_root(ledger: Mapping[str, Any], output_root: Path) -> None:
    if not output_root.name.endswith("output"):
        raise TestSandboxQualificationError("private cleanup output name is invalid")
    expected_name = output_root.name.removesuffix("output") + "work"
    expected = output_root.with_name(expected_name)
    if Path(str(ledger["work_root"])) != expected or expected.is_symlink():
        raise TestSandboxQualificationError("private cleanup work root differs")


def cleanup(
    *,
    manifest_path: Path,
    ledger_path: Path,
    output_root: Path,
    docker_socket: str,
    runner: CommandRunner = _run,
) -> contract.StrixTestSandboxImageCleanupReceiptV1:
    ledger_path, output_root = _validate_cleanup_location(
        ledger_path=ledger_path, output_root=output_root
    )
    try:
        qualified = contract.StrixTestSandboxImageContractV1(manifest_path.read_bytes())
    except (OSError, StrixImageContractError) as exc:
        raise TestSandboxQualificationError("qualified image manifest cannot be reopened") from exc
    ledger = _validate_private_ledger(_read_json(ledger_path, maximum=64 * 1024))
    _validate_cleanup_work_root(ledger, output_root)
    if ledger["state"] != "qualified":
        raise TestSandboxQualificationError("private cleanup ledger is not qualified")
    qualified_document = qualified.to_dict()
    expected = {
        "contract_digest": qualified.contract_digest,
        "qualification_ref": qualified.qualification_ref,
        "runtime_composite_ref": qualified_document["runtime_closure"]["composite_ref"],
        "provider_source_digest": qualified_document["test_provider"]["provider_source_digest"],
        "cleanup_label": qualified_document["qualification"]["cleanup_label"],
    }
    if any(ledger.get(name) != value for name, value in expected.items()):
        raise TestSandboxQualificationError("private cleanup ledger binding differs")
    status = _cleanup_private_resources(ledger, docker_socket=docker_socket, runner=runner)
    cleanup_body = {
        "contract_digest": qualified.contract_digest,
        "qualification_ref": qualified.qualification_ref,
        "cleanup_label": expected["cleanup_label"],
        **status,
    }
    required = (
        "container_absent",
        "network_absent",
        "image_absent",
        "build_context_absent",
        "oci_layout_absent",
        "docker_archive_absent",
        "runtime_stage_absent",
    )
    if not all(cleanup_body[name] for name in required):
        raise TestSandboxQualificationError("private image cleanup is incomplete")
    cleanup_document = {
        "schema_version": contract.CLEANUP_SCHEMA_VERSION,
        **cleanup_body,
        "cleanup_evidence_digest": content_hash(
            {"schema_version": "bluefire.strix-test-sandbox-cleanup-evidence.v1", **cleanup_body}
        ),
    }
    receipt = contract.StrixTestSandboxImageCleanupReceiptV1.from_mapping(cleanup_document)
    (output_root / contract.CLEANUP_FILENAME).write_bytes(receipt.canonical_bytes)
    try:
        ledger_path.unlink()
    except OSError as exc:
        raise TestSandboxQualificationError("private cleanup ledger could not be removed") from exc
    return receipt


def cleanup_partial(
    *,
    ledger_path: Path,
    output_root: Path,
    docker_socket: str,
    runner: CommandRunner = _run,
) -> str:
    """Clean an interrupted qualification without minting a contract cleanup receipt."""

    ledger_path, output_root = _validate_cleanup_location(
        ledger_path=ledger_path, output_root=output_root
    )
    ledger = _validate_private_ledger(_read_json(ledger_path, maximum=64 * 1024))
    _validate_cleanup_work_root(ledger, output_root)
    status = _cleanup_private_resources(ledger, docker_socket=docker_socket, runner=runner)
    if not all(status.values()):
        raise TestSandboxQualificationError("partial image cleanup is incomplete")
    cleanup_body = {
        "ledger_state": ledger["state"],
        "qualification_completed": ledger["state"] == "qualified",
        "contract_cleanup_receipt_emitted": False,
        "contract_digest": ledger["contract_digest"],
        "qualification_ref": ledger["qualification_ref"],
        "runtime_composite_ref": ledger["runtime_composite_ref"],
        "provider_source_digest": ledger["provider_source_digest"],
        "cleanup_label": ledger["cleanup_label"],
        **status,
    }
    document = {
        "schema_version": _PARTIAL_CLEANUP_SCHEMA,
        **cleanup_body,
        "cleanup_evidence_digest": content_hash(
            {
                "schema_version": "bluefire.strix-test-sandbox-partial-cleanup-evidence.v1",
                **cleanup_body,
            }
        ),
    }
    receipt_digest = _write_canonical(output_root / PARTIAL_CLEANUP_FILENAME, document)
    try:
        ledger_path.unlink()
    except OSError as exc:
        raise TestSandboxQualificationError("private cleanup ledger could not be removed") from exc
    return receipt_digest


def _download(url: str, path: Path, expected_sha256: str, maximum: int) -> dict[str, Any]:
    if urllib.parse.urlsplit(url).scheme != "https":
        raise TestSandboxQualificationError("preparation URL is not HTTPS")
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/octet-stream", "User-Agent": "BlueFire-Test-Image/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:  # nosec B310 - fixed HTTPS
            if urllib.parse.urlsplit(response.geturl()).scheme != "https":
                raise TestSandboxQualificationError("preparation redirect left HTTPS")
            payload = response.read(maximum + 1)
    except OSError as exc:
        raise TestSandboxQualificationError("preparation download failed") from exc
    if len(payload) > maximum or hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise TestSandboxQualificationError("preparation download digest differs")
    path.write_bytes(payload)
    return {"name": path.name, "size": len(payload), "digest": _sha256_bytes(payload)}


def prepare_inputs(*, package_root: Path, tool_root: Path) -> str:
    """Prefetch reviewed inputs; this does not build or qualify an image."""

    package_root = _safe_empty_directory(package_root)
    tool_root = _safe_empty_directory(tool_root)
    packages = []
    for item in contract.OFFLINE_CURL_CLOSURE:
        packages.append(
            _download(
                item["url"], package_root / item["filename"], item["sha256"], 64 * 1024 * 1024
            )
        )
    validate_package_root(package_root)
    from tools import qualify_strix_runtime_candidate as runtime_qualifier

    archive = tool_root / runtime_qualifier.SYFT_ARCHIVE_NAME
    checksums = tool_root / runtime_qualifier.SYFT_CHECKSUMS_NAME
    archive_receipt = _download(
        runtime_qualifier.SYFT_ARCHIVE_URL,
        archive,
        runtime_qualifier.SYFT_ARCHIVE_SHA256,
        256 * 1024 * 1024,
    )
    checksum_receipt = _download(
        runtime_qualifier.SYFT_CHECKSUMS_URL,
        checksums,
        runtime_qualifier.SYFT_CHECKSUMS_SHA256,
        2 * 1024 * 1024,
    )
    try:
        runtime_qualifier._verify_syft_checksums(checksums.read_bytes())
        syft_identity = runtime_qualifier.extract_verified_syft(archive, tool_root / "syft")
    except Exception as exc:
        raise TestSandboxQualificationError("reviewed Syft preparation failed") from exc
    receipt = {
        "schema_version": "bluefire.strix-test-sandbox-input-preparation.v1",
        "qualifying": False,
        "package_lock_digest": contract.package_lock_digest(),
        "packages": packages,
        "syft_archive": archive_receipt,
        "syft_checksums": checksum_receipt,
        "syft_executable": {
            "name": syft_identity.path,
            "size": syft_identity.size,
            "digest": "sha256:" + syft_identity.sha256,
        },
    }
    return _write_canonical(tool_root / "input-preparation.json", receipt)
