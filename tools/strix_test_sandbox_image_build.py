"""Construct and inspect one runner-private BlueFire Strix test sandbox image.

The image is built only from preloaded and hash-bound inputs. Docker build
network access and pulls are disabled. The OCI layout, build context, package
archives, and loaded image stay on one owned runner until paired cleanup.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess  # nosec B404 - fixed Docker/Syft command vectors
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from bluefire import strix_test_sandbox_image as contract
from bluefire.strix_image_contract import StrixImageContractError
from bluefire.util import canonical_json_bytes, content_hash

PRIVATE_LEDGER_FILENAME = "strix-test-sandbox-private-ledger.json"
PARTIAL_CLEANUP_FILENAME = "strix-test-sandbox-image-partial-cleanup.json"
PROVENANCE_FILENAME = "strix-test-sandbox-provenance.json"
NOTICE_FILENAME = "strix-test-sandbox-notices.json"
SBOM_FILENAME = "strix-test-sandbox.cdx.json"
SELF_TEST_FILENAME = "strix-test-sandbox-self-test.json"
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_RUNTIME_BYTES = 2 * 1024**3
MAX_RUNTIME_FILES = 200_000
MAX_COMMAND_OUTPUT = 4 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 900
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REVISION = re.compile(r"[0-9a-f]{40,64}\Z")
_IMAGE_TAG = re.compile(r"localhost/bluefire/strix-test-sandbox-[0-9a-f]{32}:candidate\Z")
_CONTAINER_NAME = re.compile(r"bluefire-strix-test-[0-9a-f]{32}\Z")
_CLEANUP_LABEL = re.compile(r"bluefire\.strix-test-sandbox\.[0-9a-f]{32}\Z")
_LEDGER_SCHEMA = "bluefire.strix-test-sandbox-private-ledger.v2"
_PARTIAL_CLEANUP_SCHEMA = "bluefire.strix-test-sandbox-partial-cleanup.v1"


class TestSandboxQualificationError(RuntimeError):
    """The exact ephemeral image could not be positively qualified."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


CommandRunner = Callable[[Sequence[str], Mapping[str, str] | None], CommandResult]


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path, *, maximum: int | None = None) -> str:
    if not path.is_file() or path.is_symlink():
        raise TestSandboxQualificationError("qualification input is not a regular file")
    if maximum is not None and path.stat().st_size > maximum:
        raise TestSandboxQualificationError("qualification input exceeds its size bound")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def _read_json(path: Path, *, maximum: int = MAX_JSON_BYTES) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > maximum:
        raise TestSandboxQualificationError("qualification JSON is unavailable or excessive")
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TestSandboxQualificationError("qualification JSON is invalid") from exc
    if not isinstance(value, dict):
        raise TestSandboxQualificationError("qualification JSON root is invalid")
    return value


def _write_canonical(path: Path, value: Mapping[str, Any]) -> str:
    payload = canonical_json_bytes(dict(value))
    path.write_bytes(payload)
    return _sha256_bytes(payload)


def _run(argv: Sequence[str], environment: Mapping[str, str] | None = None) -> CommandResult:
    if not argv or any(not isinstance(item, str) or not item for item in argv):
        raise TestSandboxQualificationError("qualification command vector is invalid")
    try:
        process = subprocess.run(  # nosec B603 - no shell and caller selects no executable
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
            env=dict(environment) if environment is not None else None,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise TestSandboxQualificationError("qualification executable is unavailable") from exc
    if len(process.stdout) > MAX_COMMAND_OUTPUT or len(process.stderr) > MAX_COMMAND_OUTPUT:
        raise TestSandboxQualificationError("qualification command output is excessive")
    return CommandResult(process.returncode, bytes(process.stdout), bytes(process.stderr))


def _checked(
    runner: CommandRunner,
    argv: Sequence[str],
    environment: Mapping[str, str] | None = None,
) -> bytes:
    result = runner(argv, environment)
    if result.returncode != 0:
        raise TestSandboxQualificationError("qualification command failed")
    return result.stdout


def _docker_environment(docker_socket: str) -> dict[str, str]:
    if not isinstance(docker_socket, str) or not docker_socket.startswith("unix:///"):
        raise TestSandboxQualificationError("Docker socket must be an absolute Unix endpoint")
    path = docker_socket.removeprefix("unix://")
    if "//" in path or any(part in {"", ".", "..", "~"} for part in path.split("/")[1:]):
        raise TestSandboxQualificationError("Docker socket endpoint is not canonical")
    return {"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8", "DOCKER_HOST": docker_socket}


def _validate_revision(value: str, label: str) -> str:
    if not isinstance(value, str) or _REVISION.fullmatch(value) is None:
        raise TestSandboxQualificationError(f"{label} is invalid")
    return value


def _validate_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise TestSandboxQualificationError(f"{label} is invalid")
    return value


def _safe_empty_directory(path: Path) -> Path:
    resolved = path.resolve()
    if resolved == Path(resolved.anchor) or len(resolved.parts) < 4:
        raise TestSandboxQualificationError("qualification directory is too broad")
    if resolved.exists():
        if not resolved.is_dir() or resolved.is_symlink() or any(resolved.iterdir()):
            raise TestSandboxQualificationError("qualification directory must be empty")
    else:
        resolved.mkdir(parents=True, mode=0o700)
    return resolved


def _runtime_inventory(root: Path) -> tuple[list[dict[str, Any]], str]:
    root = root.resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        raise TestSandboxQualificationError("runtime root is invalid")
    entries: list[dict[str, Any]] = []
    total = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise TestSandboxQualificationError("runtime root contains a symbolic link")
        if path.is_dir():
            entries.append({"path": relative + "/", "mode": stat.S_IMODE(path.stat().st_mode)})
            continue
        if not path.is_file():
            raise TestSandboxQualificationError("runtime root contains a special object")
        size = path.stat().st_size
        total += size
        if total > MAX_RUNTIME_BYTES or len(entries) >= MAX_RUNTIME_FILES:
            raise TestSandboxQualificationError("runtime root exceeds its bound")
        entries.append(
            {
                "path": relative,
                "mode": stat.S_IMODE(path.stat().st_mode),
                "size": size,
                "digest": _sha256_file(path),
            }
        )
    if not entries:
        raise TestSandboxQualificationError("runtime root is empty")
    return entries, content_hash(
        {"schema_version": "bluefire.strix-test-image-runtime-inventory.v1", "entries": entries}
    )


def _normalized_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _distribution_name(metadata: Path) -> str:
    try:
        if not metadata.is_file() or metadata.is_symlink() or metadata.stat().st_size > 1024 * 1024:
            raise TestSandboxQualificationError("runtime distribution metadata is invalid")
        lines = metadata.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise TestSandboxQualificationError("runtime distribution metadata is unreadable") from exc
    names = [line[6:].strip() for line in lines if line.startswith("Name: ")]
    if len(names) != 1 or not names[0]:
        raise TestSandboxQualificationError("runtime distribution name is invalid")
    return _normalized_distribution_name(names[0])


def validate_worker_distribution(runtime_root: Path, runtime_document: Mapping[str, Any]) -> None:
    if runtime_document.get("worker_distribution") != "bluefire-strix-worker":
        raise TestSandboxQualificationError("runtime worker distribution differs")
    if runtime_document.get("full_product_wheel_present") is not False:
        raise TestSandboxQualificationError("full BlueFire product wheel is not excluded")
    worker_record_digest = _validate_digest(
        runtime_document.get("worker_record_digest"), "runtime worker RECORD digest"
    )
    site_packages = runtime_root / "runtime/lib/python3.12/site-packages"
    if not site_packages.is_dir() or site_packages.is_symlink():
        raise TestSandboxQualificationError("runtime site-packages directory is unavailable")
    workers: list[tuple[Path, Path]] = []
    full_product = []
    for metadata in sorted(site_packages.glob("*.dist-info/METADATA")):
        name = _distribution_name(metadata)
        record = metadata.parent / "RECORD"
        if name == "bluefire-strix-worker":
            if not record.is_file() or record.is_symlink():
                raise TestSandboxQualificationError("runtime worker RECORD is unavailable")
            workers.append((metadata, record))
        elif name == "bluefire-nexus":
            full_product.append(metadata)
    if len(workers) != 1:
        raise TestSandboxQualificationError("runtime must contain exactly one minimal worker")
    if full_product:
        raise TestSandboxQualificationError("runtime contains the full BlueFire product wheel")
    if _sha256_file(workers[0][1], maximum=8 * 1024 * 1024) != worker_record_digest:
        raise TestSandboxQualificationError("runtime worker RECORD digest differs")


def validate_runtime_composite_document(
    value: Mapping[str, Any], *, bluefire_revision: str, expected_ref: str
) -> dict[str, Any]:
    fields = {
        "schema_version",
        "composite_ref",
        "prelaunch_plan_ref",
        "fixed_exec_qualification_ref",
        "inventory_digest",
        "interpreter_digest",
        "entrypoint_digest",
        "worker_invocation_digest",
        "worker_distribution",
        "worker_artifact_digest",
        "worker_record_digest",
        "worker_source_revision",
        "installed_distributions_digest",
        "full_product_wheel_present",
        "strix_candidate_digest",
        "source_revision",
        "python_version",
    }
    if set(value) != fields:
        raise TestSandboxQualificationError("runtime composite shape is invalid")
    if value.get("schema_version") != "bluefire.strix-linux-qualified-runtime-composite.v1":
        raise TestSandboxQualificationError("runtime composite schema differs")
    for field in (
        "composite_ref",
        "prelaunch_plan_ref",
        "fixed_exec_qualification_ref",
        "inventory_digest",
        "interpreter_digest",
        "entrypoint_digest",
        "worker_invocation_digest",
        "worker_artifact_digest",
        "worker_record_digest",
        "installed_distributions_digest",
        "strix_candidate_digest",
    ):
        _validate_digest(value.get(field), f"runtime {field}")
    expected_composite = content_hash(
        {
            "schema_version": "bluefire.strix-linux-qualified-runtime-composite.v1",
            "prelaunch_plan_ref": value["prelaunch_plan_ref"],
            "fixed_exec_qualification_ref": value["fixed_exec_qualification_ref"],
        }
    )
    if value.get("composite_ref") != expected_ref or expected_ref != expected_composite:
        raise TestSandboxQualificationError("runtime composite reference differs")
    if value.get("worker_invocation_digest") != contract.installed_worker_invocation_digest():
        raise TestSandboxQualificationError("runtime worker invocation differs")
    if value.get("worker_source_revision") != bluefire_revision:
        raise TestSandboxQualificationError("runtime worker source revision differs")
    if value.get("source_revision") != contract.STRIX_SOURCE_REVISION:
        raise TestSandboxQualificationError("runtime Strix source revision differs")
    if value.get("python_version") != "3.12.14":
        raise TestSandboxQualificationError("runtime Python version differs")
    if value.get("worker_distribution") != "bluefire-strix-worker":
        raise TestSandboxQualificationError("runtime worker distribution differs")
    if value.get("full_product_wheel_present") is not False:
        raise TestSandboxQualificationError("full BlueFire product wheel is not excluded")
    return dict(value)


def provider_source_digest(paths: Sequence[Path]) -> str:
    if len(paths) != 3:
        raise TestSandboxQualificationError("exactly three provider source files are required")
    rows = []
    expected_names = {
        "test_caido_protocol_entry.py",
        "test_caido_protocol_provider.py",
        "test_caido_protocol_server.py",
    }
    for path in paths:
        if path.name not in expected_names:
            raise TestSandboxQualificationError("provider source filename is not reviewed")
        rows.append(
            {
                "name": f"bluefire/{path.name}",
                "digest": _sha256_file(path, maximum=512 * 1024),
            }
        )
    if {Path(row["name"]).name for row in rows} != expected_names:
        raise TestSandboxQualificationError("provider source set is incomplete or duplicated")
    rows.sort(key=lambda row: row["name"])
    return content_hash(
        {"schema_version": "bluefire.test-caido-protocol-provider-source.v1", "files": rows}
    )


def validate_package_root(package_root: Path) -> list[dict[str, str]]:
    if not package_root.is_dir() or package_root.is_symlink():
        raise TestSandboxQualificationError("offline package root is invalid")
    rows: list[dict[str, str]] = []
    expected_names = {item["filename"] for item in contract.OFFLINE_CURL_CLOSURE}
    actual_names = {path.name for path in package_root.iterdir() if path.is_file()}
    if actual_names != expected_names:
        raise TestSandboxQualificationError("offline package root does not match the lock")
    for item in contract.OFFLINE_CURL_CLOSURE:
        path = package_root / item["filename"]
        digest = _sha256_file(path, maximum=64 * 1024 * 1024).removeprefix("sha256:")
        rows.append({"filename": path.name, "sha256": digest})
    try:
        contract.validate_package_archive_digests(rows)
    except StrixImageContractError as exc:
        raise TestSandboxQualificationError("offline package digest does not match") from exc
    return rows


def entrypoint_bytes() -> bytes:
    return (
        "#!/bin/sh\nset -eu\n"
        '[ "$(id -u)" = 1000 ]\n[ "$(id -g)" = 1000 ]\n'
        '[ "$(pwd -P)" = /workspace ]\n'
        "exec /runtime/bin/python -I -S -B -X utf8 /bootstrap/worker.py\n"
    ).encode("utf-8")


def self_test_bytes() -> bytes:
    return (
        "#!/bin/sh\nset -eu\n"
        '[ "$(id -u)" = 1000 ]\n[ "$(id -g)" = 1000 ]\n'
        '[ "$(pwd -P)" = /workspace ]\n'
        'for tool in bash sh curl mkdir tar rm; do command -v "$tool" >/dev/null; done\n'
        "for forbidden in apt apt-get dpkg apk dnf yum docker podman; do "
        'if command -v "$forbidden" >/dev/null 2>&1; then exit 31; fi; done\n'
        "[ ! -e /var/run/docker.sock ]\n"
        "mkdir -p /workspace/tmp /workspace/home /workspace/cache\n"
        "printf probe > /workspace/tmp/write-probe\n"
        "if printf forbidden > /tmp/bluefire-write-probe 2>/dev/null; then exit 32; fi\n"
        "/runtime/bin/python -I -S -B -X utf8 -c 'from email.parser import BytesParser; "
        "from pathlib import Path; import re; "
        'root=Path("/runtime/lib/python3.12/site-packages"); '
        'paths=list(root.glob("*.dist-info/METADATA")); '
        'assert all(p.is_file() and not p.is_symlink() and (p.parent/"RECORD").is_file() '
        'and not (p.parent/"RECORD").is_symlink() for p in paths); '
        'names=[re.sub(r"[-_.]+","-",BytesParser().parsebytes(p.read_bytes())["Name"]).lower() '
        'for p in paths]; assert names.count("bluefire-strix-worker")==1; '
        'assert "bluefire-nexus" not in names\'\n'
        "for provider in test_caido_protocol_entry.py "
        "test_caido_protocol_provider.py test_caido_protocol_server.py; do "
        "[ ! -e /runtime/lib/python3.12/site-packages/bluefire/$provider ]; done\n"
        "printf '%s\\n' "
        '\'{"schema_version":"bluefire.strix-test-sandbox-self-test.v1",'
        '"uid":1000,"gid":1000,"working_directory":"/workspace",'
        '"controller_provider_outside_image":true,"package_manager_absent":true,'
        '"docker_socket_absent":true,"read_only_root_observed":true,'
        '"worker_distribution_present":true,"full_product_wheel_absent":true}\'\n'
    ).encode("utf-8")


def dockerfile_bytes() -> bytes:
    checks = "\\n".join(
        f"{item['sha256']}  /opt/bluefire/packages/{item['filename']}"
        for item in contract.OFFLINE_CURL_CLOSURE
    )
    packages = " ".join(
        f"/opt/bluefire/packages/{item['filename']}" for item in contract.OFFLINE_CURL_CLOSURE
    )
    return (
        f"FROM {contract.BASE_IMAGE['index_reference']} AS assemble\n"
        "COPY packages/ /opt/bluefire/packages/\n"
        "COPY package-sha256s /opt/bluefire/package-sha256s\n"
        f"RUN sha256sum -c /opt/bluefire/package-sha256s && dpkg -i {packages}\n"
        "COPY runtime-root/ /\n"
        f"COPY strix-test-sandbox-entrypoint {contract.CONTROLLED_ENTRYPOINT}\n"
        f"COPY strix-test-sandbox-self-test {contract.CONTROLLED_SELF_TEST}\n"
        "RUN chmod 0555 /opt/bluefire/bin/strix-test-sandbox-entrypoint "
        "/opt/bluefire/bin/strix-test-sandbox-self-test && mkdir -p /workspace "
        "&& chown 1000:1000 /workspace && rm -rf /opt/bluefire/packages "
        "/opt/bluefire/package-sha256s /var/lib/apt /var/cache/apt /usr/lib/apt "
        "/usr/lib/dpkg /usr/bin/apt /usr/bin/apt-cache /usr/bin/apt-cdrom "
        "/usr/bin/apt-config /usr/bin/apt-get /usr/bin/apt-mark /usr/bin/dpkg "
        "/usr/bin/dpkg-deb /usr/bin/dpkg-divert /usr/bin/dpkg-maintscript-helper "
        "/usr/bin/dpkg-query /usr/bin/dpkg-realpath /usr/bin/dpkg-split "
        "/usr/bin/dpkg-statoverride /usr/bin/dpkg-trigger /usr/sbin/update-alternatives\n"
        "FROM scratch\nCOPY --from=assemble / /\n"
        "ENV HOME=/workspace/home TMPDIR=/workspace/tmp XDG_CACHE_HOME=/workspace/cache "
        "PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1\n"
        "USER 1000:1000\nWORKDIR /workspace\n"
        f'ENTRYPOINT ["{contract.CONTROLLED_ENTRYPOINT}"]\nCMD []\n'
        f"# package-lock-sha256: {contract.package_lock_digest()}\n"
        f"# package-sha256s\n# {checks.replace(chr(10), chr(10) + '# ')}\n"
    ).encode("utf-8")


def prepare_context(
    context_root: Path,
    *,
    runtime_root: Path,
    package_root: Path,
) -> tuple[str, str, str]:
    context_root = _safe_empty_directory(context_root)
    validate_package_root(package_root)
    shutil.copytree(runtime_root, context_root / "runtime-root", symlinks=False)
    if _runtime_inventory(context_root / "runtime-root")[1] != _runtime_inventory(runtime_root)[1]:
        raise TestSandboxQualificationError("staged runtime differs from qualified root")
    packages = context_root / "packages"
    packages.mkdir(mode=0o700)
    for item in contract.OFFLINE_CURL_CLOSURE:
        shutil.copyfile(package_root / item["filename"], packages / item["filename"])
    lines = [
        f"{item['sha256']}  /opt/bluefire/packages/{item['filename']}"
        for item in contract.OFFLINE_CURL_CLOSURE
    ]
    (context_root / "package-sha256s").write_text("\n".join(lines) + "\n")
    dockerfile = dockerfile_bytes()
    entrypoint = entrypoint_bytes()
    self_test = self_test_bytes()
    (context_root / "Dockerfile").write_bytes(dockerfile)
    (context_root / "strix-test-sandbox-entrypoint").write_bytes(entrypoint)
    (context_root / "strix-test-sandbox-self-test").write_bytes(self_test)
    _, inventory_digest = _runtime_inventory(context_root)
    return (
        _sha256_bytes(dockerfile),
        _sha256_bytes(entrypoint),
        content_hash(
            {
                "context_inventory_digest": inventory_digest,
                "self_test_digest": _sha256_bytes(self_test),
            }
        ),
    )


def docker_build_command(*, context_root: Path, tag: str) -> list[str]:
    if _IMAGE_TAG.fullmatch(tag) is None:
        raise TestSandboxQualificationError("private image tag is invalid")
    return [
        "docker",
        "buildx",
        "build",
        "--builder",
        "default",
        "--platform",
        "linux/amd64",
        "--network",
        "none",
        "--no-cache",
        "--pull=false",
        "--provenance=false",
        "--sbom=false",
        "--load",
        "--tag",
        tag,
        str(context_root),
    ]


def docker_save_command(*, tag: str, docker_archive: Path) -> list[str]:
    if _IMAGE_TAG.fullmatch(tag) is None or not docker_archive.is_absolute():
        raise TestSandboxQualificationError("private Docker archive identity is invalid")
    return ["docker", "image", "save", "--output", str(docker_archive), tag]


def skopeo_convert_command(*, docker_archive: Path, oci_archive: Path) -> list[str]:
    if not docker_archive.is_absolute() or not oci_archive.is_absolute():
        raise TestSandboxQualificationError("private conversion archive path is invalid")
    return [
        "skopeo",
        "--insecure-policy",
        "--override-os",
        "linux",
        "--override-arch",
        "amd64",
        "copy",
        f"docker-archive:{docker_archive}",
        f"oci-archive:{oci_archive}:candidate",
    ]


def docker_self_test_command(*, tag: str, container_name: str, cleanup_label: str) -> list[str]:
    if _IMAGE_TAG.fullmatch(tag) is None or not container_name.startswith("bluefire-strix-test-"):
        raise TestSandboxQualificationError("private self-test identity is invalid")
    return [
        "docker",
        "run",
        "--name",
        container_name,
        "--label",
        f"bluefire.test-sandbox-owner={cleanup_label}",
        "--user",
        "1000:1000",
        "--read-only",
        "--tmpfs",
        "/workspace:rw,nosuid,nodev,noexec,size=536870912,uid=1000,gid=1000,mode=0700",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        "256",
        "--memory",
        "2147483648",
        "--memory-swap",
        "2147483648",
        "--cpus",
        "2",
        "--network",
        "none",
        "--entrypoint",
        contract.CONTROLLED_SELF_TEST,
        tag,
    ]


def _tar_member(archive: tarfile.TarFile, name: str, maximum: int = MAX_JSON_BYTES) -> bytes:
    try:
        member = archive.getmember(name)
    except KeyError as exc:
        raise TestSandboxQualificationError("OCI layout object is missing") from exc
    if not member.isfile() or member.size <= 0 or member.size > maximum:
        raise TestSandboxQualificationError("OCI layout object is invalid")
    stream = archive.extractfile(member)
    if stream is None:
        raise TestSandboxQualificationError("OCI layout object cannot be read")
    payload = stream.read(maximum + 1)
    if len(payload) != member.size:
        raise TestSandboxQualificationError("OCI layout object length differs")
    return payload


def _strict_object(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TestSandboxQualificationError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise TestSandboxQualificationError(f"{label} root is invalid")
    return value


def _blob_name(digest: str) -> str:
    _validate_digest(digest, "OCI descriptor digest")
    return "blobs/sha256/" + digest.removeprefix("sha256:")


def _require_descriptor(
    descriptor: Mapping[str, Any], payload: bytes, media_type: str, label: str
) -> None:
    if descriptor.get("mediaType") != media_type or type(descriptor.get("size")) is not int:
        raise TestSandboxQualificationError(f"{label} descriptor fields are invalid")
    if descriptor["size"] != len(payload):
        raise TestSandboxQualificationError(f"{label} descriptor size differs")


def parse_oci_layout(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_RUNTIME_BYTES:
        raise TestSandboxQualificationError("OCI layout archive is unavailable or excessive")
    try:
        with tarfile.open(path, "r:*") as archive:
            layout = _strict_object(_tar_member(archive, "oci-layout"), "OCI layout marker")
            if layout != {"imageLayoutVersion": "1.0.0"}:
                raise TestSandboxQualificationError("OCI layout version differs")
            index_payload = _tar_member(archive, "index.json")
            index = _strict_object(index_payload, "OCI layout index")
            if index.get("schemaVersion") != 2 or index.get("mediaType") not in (
                None,
                "application/vnd.oci.image.index.v1+json",
            ):
                raise TestSandboxQualificationError("OCI index media type differs")
            manifests = index.get("manifests")
            if not isinstance(manifests, list) or len(manifests) != 1:
                raise TestSandboxQualificationError("OCI layout must contain one image manifest")
            descriptor = manifests[0]
            if not isinstance(descriptor, dict):
                raise TestSandboxQualificationError("OCI manifest descriptor is invalid")
            manifest_digest = _validate_digest(descriptor.get("digest"), "OCI platform manifest")
            manifest_payload = _tar_member(archive, _blob_name(manifest_digest))
            if _sha256_bytes(manifest_payload) != manifest_digest:
                raise TestSandboxQualificationError("OCI platform manifest digest differs")
            _require_descriptor(
                descriptor,
                manifest_payload,
                "application/vnd.oci.image.manifest.v1+json",
                "OCI platform manifest",
            )
            platform = descriptor.get("platform")
            if platform is not None and (
                not isinstance(platform, dict)
                or platform.get("os") != "linux"
                or platform.get("architecture") != "amd64"
            ):
                raise TestSandboxQualificationError("OCI platform descriptor differs")
            manifest = _strict_object(manifest_payload, "OCI platform manifest")
            if manifest.get("schemaVersion") != 2 or manifest.get("mediaType") not in (
                None,
                "application/vnd.oci.image.manifest.v1+json",
            ):
                raise TestSandboxQualificationError("OCI manifest media type differs")
            config_descriptor = manifest.get("config")
            layers = manifest.get("layers")
            if not isinstance(config_descriptor, dict) or not isinstance(layers, list):
                raise TestSandboxQualificationError("OCI manifest contents are incomplete")
            config_digest = _validate_digest(config_descriptor.get("digest"), "OCI config")
            config_payload = _tar_member(archive, _blob_name(config_digest))
            if _sha256_bytes(config_payload) != config_digest:
                raise TestSandboxQualificationError("OCI config digest differs")
            _require_descriptor(
                config_descriptor,
                config_payload,
                "application/vnd.oci.image.config.v1+json",
                "OCI config",
            )
            config = _strict_object(config_payload, "OCI config")
            if config.get("os") != "linux" or config.get("architecture") != "amd64":
                raise TestSandboxQualificationError("OCI config platform differs")
            if not 1 <= len(layers) <= 64:
                raise TestSandboxQualificationError("OCI layer count is invalid")
            parsed_layers = []
            for layer in layers:
                if not isinstance(layer, dict):
                    raise TestSandboxQualificationError("OCI layer descriptor is invalid")
                digest = _validate_digest(layer.get("digest"), "OCI layer")
                payload = _tar_member(archive, _blob_name(digest), maximum=MAX_RUNTIME_BYTES)
                if _sha256_bytes(payload) != digest:
                    raise TestSandboxQualificationError("OCI layer digest differs")
                if layer.get("mediaType") not in {
                    "application/vnd.oci.image.layer.v1.tar",
                    "application/vnd.oci.image.layer.v1.tar+gzip",
                }:
                    raise TestSandboxQualificationError("OCI layer media type differs")
                if type(layer.get("size")) is not int or layer["size"] != len(payload):
                    raise TestSandboxQualificationError("OCI layer descriptor size differs")
                parsed_layers.append(
                    {"media_type": layer["mediaType"], "digest": digest, "size": layer["size"]}
                )
    except (OSError, tarfile.TarError) as exc:
        raise TestSandboxQualificationError("OCI layout archive is invalid") from exc
    index_digest = _sha256_bytes(index_payload)
    return {
        "index_reference": f"localhost/bluefire/strix-test-sandbox@{index_digest}",
        "index": {
            "media_type": "application/vnd.oci.image.index.v1+json",
            "digest": index_digest,
            "size": len(index_payload),
        },
        "platform_child": {
            "media_type": descriptor.get("mediaType"),
            "digest": manifest_digest,
            "size": len(manifest_payload),
            "platform": dict(contract.PLATFORM),
        },
        "config": {
            "media_type": config_descriptor.get("mediaType"),
            "digest": config_digest,
            "size": len(config_payload),
        },
        "layers": parsed_layers,
        "image_id": config_digest,
        "imported_reference": f"localhost/bluefire/strix-test-sandbox-amd64@{manifest_digest}",
    }


def _qualification_ref(document: Mapping[str, Any]) -> str:
    return content_hash(
        {"schema_version": "bluefire.strix-test-image-qualification-ref.v1", **dict(document)}
    )


def _policy() -> dict[str, bool]:
    return {
        "test_only": True,
        "runner_private": True,
        "image_upload_allowed": False,
        "image_publish_allowed": False,
        "production_runtime_admitted": False,
        "live_engine_proof": False,
        "live_caido_proof": False,
        "redistribution_authorized": False,
    }


def compose_contract_document(
    *,
    bluefire_revision: str,
    qualifier_revision: str,
    runtime_closure: Mapping[str, Any],
    provider_digest: str,
    dockerfile_digest: str,
    context_digest: str,
    entrypoint_digest: str,
    self_test_digest: str,
    image_identity: Mapping[str, Any],
    docker_server_digest: str,
    sbom_digest: str,
    provenance_digest: str,
    notice_digest: str,
    self_test_evidence_digest: str,
    cleanup_label: str,
) -> dict[str, Any]:
    qualification_body = {
        "qualifier_revision": qualifier_revision,
        "docker_server_digest": docker_server_digest,
        "sbom_digest": sbom_digest,
        "provenance_digest": provenance_digest,
        "notice_report_digest": notice_digest,
        "self_test_evidence_digest": self_test_evidence_digest,
        "cleanup_label": cleanup_label,
        "image_config_digest": image_identity["config"]["digest"],
    }
    return {
        "schema_version": contract.SCHEMA_VERSION,
        "bluefire_source_revision": bluefire_revision,
        "strix_source_revision": contract.STRIX_SOURCE_REVISION,
        "platform": dict(contract.PLATFORM),
        "base_image": json.loads(json.dumps(contract.BASE_IMAGE)),
        "package_lock": {
            "digest": contract.package_lock_digest(),
            "document": contract.package_lock_document(),
        },
        "runtime_closure": dict(runtime_closure),
        "test_provider": {
            "schema_version": "bluefire.test-caido-protocol-provider.v1",
            "module": contract.TEST_PROVIDER_MODULE,
            "execution_location": "controller",
            "provider_source_digest": provider_digest,
            "artifact_digest": provider_digest,
            "invocation_digest": contract.test_provider_invocation_digest(),
            "sdk_client_wheel_digest": contract.CAIDO_SDK_CLIENT_WHEEL_DIGEST,
            "sdk_wire_fixture_digest": contract.CAIDO_SDK_WIRE_FIXTURE_DIGEST,
            "sdk_project_document_digest": contract.CAIDO_SDK_PROJECT_DOCUMENT_DIGEST,
            "strix_bootstrap_digest": contract.STRIX_CAIDO_BOOTSTRAP_DIGEST,
            "host": contract.TEST_PROVIDER_HOST,
            "port": contract.TEST_PROVIDER_PORT,
            "test_provider": True,
            "live_caido_proof": False,
            "production_eligible": False,
            "caido_cli_or_server_present": False,
            "official_caido_image_present": False,
            "derived_caido_image_present": False,
        },
        "build": {
            "dockerfile_digest": dockerfile_digest,
            "context_digest": context_digest,
            "runtime_closure_digest": runtime_closure["composite_ref"],
            "container_entrypoint_digest": entrypoint_digest,
            "self_test_digest": self_test_digest,
            "network_mode": "none",
            "pull": False,
            "runtime_installs": False,
        },
        "image": dict(image_identity),
        "runtime_profile": contract.proposed_test_runtime_profile(),
        "qualification": {
            "qualification_ref": _qualification_ref(qualification_body),
            "qualifier_revision": qualifier_revision,
            "runner_os": "Linux",
            "runner_image": "ubuntu-24.04",
            "runner_architecture": "x86_64",
            "docker_server_digest": docker_server_digest,
            "sbom_digest": sbom_digest,
            "provenance_digest": provenance_digest,
            "notice_report_digest": notice_digest,
            "self_test_evidence_digest": self_test_evidence_digest,
            "image_built": True,
            "image_imported": True,
            "image_started": True,
            "self_test_passed": True,
            "cleanup_label": cleanup_label,
        },
        "policy": _policy(),
    }


def _notice_document() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.strix-test-sandbox-notices.v1",
        "base_license_evidence": contract.BASE_IMAGE["source"]["license_evidence"],
        "package_license_evidence": [
            item["license_evidence"] for item in contract.OFFLINE_CURL_CLOSURE
        ],
        "provider_is_bluefire_source": True,
        "notices_complete": False,
        "license_review_complete": False,
        "redistribution_authorized": False,
        "image_publication_allowed": False,
    }
