"""Qualify one exact installed Strix CLI for compatibility-only admission.

The future hosted invocation starts only ``strix --help``. It does so in new
network, PID, and mount namespaces, as uid/gid 65534, with no inherited
environment, credentials, model, target, container, or tool-server config.
This module is not dispatched or executed merely because it is checked in.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import stat

# Only one fixed, reviewed argv is launched.
import subprocess  # nosec B404
import sys
import time
import venv
from collections.abc import Callable, Mapping
from pathlib import Path, PurePosixPath
from typing import Any, cast

from bluefire.strix_runtime_qualification import (
    RUNTIME_QUALIFICATION_LIMITATIONS,
    load_strix_runtime_qualification,
)
from bluefire.strix_runtime_transfer import (
    CANDIDATE_DIRECTORY,
    PREPARATION_DIRECTORY,
    WORK_DIRECTORY,
    extract_transfer_bundle,
    remove_transfer_tree,
)
from bluefire.util import canonical_json_bytes
from tools import build_strix_engine_candidate as candidate
from tools import qualify_strix_runtime_candidate as preparation


class StrixRuntimeAdmissionQualificationError(RuntimeError):
    """Raised when the exact installed candidate cannot be admitted."""


MANIFEST_NAME = "strix-runtime-admission.json"
CHECKSUMS_NAME = "SHA256SUMS"
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_STREAM_BYTES = 1024 * 1024
MAX_TREE_FILES = 100_000
MAX_TREE_BYTES = 4 * 1024 * 1024 * 1024
PROBE_TIMEOUT_SECONDS = 30
PROBE_UID = 65534
PROBE_GID = 65534
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_DIGEST_REF = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_RUNNER = re.compile(r"^[ -~]{1,200}$")
ProbeRunner = Callable[[Path, Path, Path], Mapping[str, Any]]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical(value: Mapping[str, Any]) -> bytes:
    return cast(bytes, canonical_json_bytes(value))


def _strict_json(payload: bytes, *, label: str) -> dict[str, Any]:
    if not payload or len(payload) > MAX_JSON_BYTES:
        raise StrixRuntimeAdmissionQualificationError(f"{label} is empty or oversized")

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise StrixRuntimeAdmissionQualificationError(f"{label} contains duplicate keys")
            result[key] = value
        return result

    try:
        value = json.loads(payload, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StrixRuntimeAdmissionQualificationError(f"{label} is not JSON") from exc
    if not isinstance(value, dict):
        raise StrixRuntimeAdmissionQualificationError(f"{label} is not an object")
    return cast(dict[str, Any], value)


def _read_regular(path: Path, maximum: int) -> bytes:
    try:
        path_metadata = path.lstat()
    except OSError as exc:
        raise StrixRuntimeAdmissionQualificationError("qualification input is unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(path_metadata.st_mode)
        or path_metadata.st_size < 0
        or path_metadata.st_size > maximum
    ):
        raise StrixRuntimeAdmissionQualificationError(
            "qualification input is not a bounded regular file"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise StrixRuntimeAdmissionQualificationError(
            "qualification input is not a bounded regular file"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 0
            or before.st_size > maximum
            or (path_metadata.st_dev, path_metadata.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise StrixRuntimeAdmissionQualificationError(
                "qualification input is not a bounded regular file"
            )
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, min(1024 * 1024, maximum + 1 - total)):
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise StrixRuntimeAdmissionQualificationError(
                    "qualification input exceeds its byte bound"
                )
        after = os.fstat(descriptor)
        if total != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise StrixRuntimeAdmissionQualificationError("qualification input changed while read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _hash_regular(path: Path, maximum: int) -> tuple[str, int]:
    try:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise StrixRuntimeAdmissionQualificationError(
            "qualification artifact cannot be opened"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > maximum:
            raise StrixRuntimeAdmissionQualificationError(
                "qualification artifact is not a bounded regular file"
            )
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > maximum:
                raise StrixRuntimeAdmissionQualificationError(
                    "qualification artifact exceeds its byte bound"
                )
            digest.update(chunk)
        after = os.fstat(descriptor)
        if total != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise StrixRuntimeAdmissionQualificationError(
                "qualification artifact changed while read"
            )
        return digest.hexdigest(), total
    finally:
        os.close(descriptor)


def _relative(value: str) -> PurePosixPath:
    relative = PurePosixPath(value)
    if (
        not value
        or len(value) > 500
        or relative.is_absolute()
        or "\\" in value
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise StrixRuntimeAdmissionQualificationError("qualification checksum path is unsafe")
    return relative


def _validate_checksum_tree(root: Path) -> tuple[str, dict[str, str]]:
    root = root.resolve(strict=True)
    checksums_payload = _read_regular(root / CHECKSUMS_NAME, MAX_JSON_BYTES)
    try:
        text = checksums_payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise StrixRuntimeAdmissionQualificationError(
            "qualification checksums are not ASCII"
        ) from exc
    expected: dict[str, str] = {}
    casefolded: set[str] = set()
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None:
            raise StrixRuntimeAdmissionQualificationError(
                "qualification checksum syntax is invalid"
            )
        relative = _relative(match.group(2)).as_posix()
        if relative in expected or relative.casefold() in casefolded or relative == CHECKSUMS_NAME:
            raise StrixRuntimeAdmissionQualificationError("qualification checksum set is ambiguous")
        expected[relative] = match.group(1)
        casefolded.add(relative.casefold())
    if not expected or len(expected) > MAX_TREE_FILES:
        raise StrixRuntimeAdmissionQualificationError("qualification checksum set is invalid")

    observed: dict[str, Path] = {}
    observed_casefolded: set[str] = set()
    total = 0
    for path in root.rglob("*"):
        metadata = path.lstat()
        if path.is_symlink() or not (
            stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)
        ):
            raise StrixRuntimeAdmissionQualificationError(
                "qualification tree contains a link or special file"
            )
        if path.is_dir():
            continue
        relative = path.relative_to(root).as_posix()
        if relative == CHECKSUMS_NAME:
            continue
        if relative in observed or relative.casefold() in observed_casefolded:
            raise StrixRuntimeAdmissionQualificationError("qualification tree is ambiguous")
        observed[relative] = path
        observed_casefolded.add(relative.casefold())
    if set(observed) != set(expected):
        raise StrixRuntimeAdmissionQualificationError(
            "qualification output differs from its checksum inventory"
        )
    for name, path in observed.items():
        digest, size = _hash_regular(path, MAX_TREE_BYTES)
        total += size
        if total > MAX_TREE_BYTES or digest != expected[name]:
            raise StrixRuntimeAdmissionQualificationError(
                "qualification artifact differs from its checksum"
            )
    return f"sha256:{_sha256(checksums_payload)}", expected


def _safe_environment(work: Path) -> dict[str, str]:
    home = work / "controller-home"
    cache = work / "controller-cache"
    for path in (home, cache):
        path.mkdir(mode=0o700)
    return {
        "HOME": str(home),
        "XDG_CACHE_HOME": str(cache),
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
    }


def _canonical_manifest(path: Path, *, label: str) -> tuple[dict[str, Any], bytes]:
    payload = _read_regular(path, MAX_JSON_BYTES)
    value = _strict_json(payload, label=label)
    if payload != _canonical(value) + b"\n":
        raise StrixRuntimeAdmissionQualificationError(f"{label} is not canonical")
    return value, payload


def _validate_preparation(
    preparation_root: Path,
    *,
    revision: str,
    candidate_identity: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
    checksums_ref, expected = _validate_checksum_tree(preparation_root)
    manifest, manifest_payload = _canonical_manifest(
        preparation_root / preparation.QUALIFICATION_MANIFEST_NAME,
        label="runtime preparation manifest",
    )
    if _sha256(manifest_payload) != expected.get(preparation.QUALIFICATION_MANIFEST_NAME):
        raise StrixRuntimeAdmissionQualificationError(
            "runtime preparation manifest changed after checksum validation"
        )
    if (
        manifest.get("schema") != "bluefire.strix-runtime-qualification-preparation.v1"
        or manifest.get("status") != "prepared-not-runtime-qualified"
        or manifest.get("bluefire_source_revision") != revision
    ):
        raise StrixRuntimeAdmissionQualificationError("runtime preparation identity drifted")
    execution = manifest.get("execution")
    qualification = manifest.get("qualification")
    if (
        not isinstance(execution, dict)
        or not execution
        or any(value is not False for value in execution.values())
        or not isinstance(qualification, dict)
        or qualification.get("runtime_qualified") is not False
    ):
        raise StrixRuntimeAdmissionQualificationError(
            "runtime preparation unexpectedly records execution or qualification"
        )
    prepared_candidate = manifest.get("candidate")
    if not isinstance(prepared_candidate, dict) or (
        prepared_candidate.get("manifest_sha256") != candidate_identity["manifest_sha256"]
        or prepared_candidate.get("checksums_sha256") != candidate_identity["checksums_sha256"]
        or prepared_candidate.get("wheel") != candidate_identity["wheel_identity"]
        or prepared_candidate.get("upstream_commit") != candidate.UPSTREAM_COMMIT
        or prepared_candidate.get("upstream_tree") != candidate.UPSTREAM_TREE
        or prepared_candidate.get("policy_prompt_sha256") != candidate_identity["prompt_sha256"]
        or prepared_candidate.get("frozen_lock_sha256") != candidate_identity["lock_sha256"]
    ):
        raise StrixRuntimeAdmissionQualificationError("runtime preparation candidate drifted")
    runtime, runtime_payload = _canonical_manifest(
        preparation_root / preparation.RUNTIME_RECEIPT_NAME,
        label="runtime installation receipt",
    )
    if _sha256(runtime_payload) != expected.get(preparation.RUNTIME_RECEIPT_NAME):
        raise StrixRuntimeAdmissionQualificationError(
            "runtime installation receipt changed after checksum validation"
        )
    if manifest.get("python_runtime") != runtime:
        raise StrixRuntimeAdmissionQualificationError(
            "runtime installation receipt differs from preparation manifest"
        )
    if runtime.get("engine_imported") is not False or runtime.get("engine_executed") is not False:
        raise StrixRuntimeAdmissionQualificationError(
            "runtime preparation already records engine execution"
        )
    oci = manifest.get("oci")
    if (
        not isinstance(oci, dict)
        or oci.get("pinned_index_reference") != candidate.SANDBOX_IMAGE
        or oci.get("image_executed") is not False
        or not isinstance(oci.get("platform_child"), dict)
        or oci["platform_child"].get("platform")
        != {
            "os": "linux",
            "architecture": "amd64",
        }
    ):
        raise StrixRuntimeAdmissionQualificationError("runtime preparation OCI identity drifted")
    oci_inventory, oci_inventory_payload = _canonical_manifest(
        preparation_root / preparation.OCI_INVENTORY_NAME,
        label="OCI inventory",
    )
    if _sha256(oci_inventory_payload) != expected.get(preparation.OCI_INVENTORY_NAME):
        raise StrixRuntimeAdmissionQualificationError(
            "OCI inventory changed after checksum validation"
        )
    if oci_inventory != oci:
        raise StrixRuntimeAdmissionQualificationError(
            "OCI inventory differs from preparation manifest"
        )
    return (
        manifest,
        runtime,
        {
            "preparation_manifest_ref": f"sha256:{_sha256(manifest_payload)}",
            "preparation_checksums_ref": checksums_ref,
            "runtime_receipt_ref": f"sha256:{_sha256(runtime_payload)}",
            "oci_inventory_ref": f"sha256:{_sha256(oci_inventory_payload)}",
        },
    )


def _installed_map(runtime: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    rows = runtime.get("installed_distributions")
    if not isinstance(rows, list) or not rows:
        raise StrixRuntimeAdmissionQualificationError("installed distribution receipt is invalid")
    result: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str):
            raise StrixRuntimeAdmissionQualificationError(
                "installed distribution receipt is invalid"
            )
        name = preparation._canonical_name(row["name"])
        if name in result:
            raise StrixRuntimeAdmissionQualificationError(
                "installed distribution receipt is ambiguous"
            )
        result[name] = row
    return result


def _inspect_runtime(
    runtime_root: Path,
    runtime: Mapping[str, Any],
    *,
    prompt_sha256: str,
) -> dict[str, Any]:
    root = runtime_root.resolve(strict=True)
    if root.name != "runtime":
        raise StrixRuntimeAdmissionQualificationError("runtime root identity is invalid")
    interpreter = root / "bin/python"
    interpreter.resolve(strict=True)
    site_packages = (root / "lib/python3.12/site-packages").resolve(strict=True)
    if root not in site_packages.parents:
        raise StrixRuntimeAdmissionQualificationError("runtime site-packages escaped its root")
    actual_interpreter = preparation._hash_executable(root / "bin/python")
    python = runtime.get("python")
    if not isinstance(python, dict) or python.get("runtime_interpreter") != actual_interpreter:
        raise StrixRuntimeAdmissionQualificationError("runtime interpreter identity drifted")
    inspected = cast(
        dict[str, Any],
        preparation._inspect_installed_candidate(
            root,
            interpreter,
            site_packages,
            _installed_map(runtime),
            prompt_sha256,
        ),
    )
    if runtime.get("strix") != inspected:
        raise StrixRuntimeAdmissionQualificationError("installed Strix identity drifted")
    return inspected


def _reconstruct_runtime_offline(
    work_root: Path,
    preparation_root: Path,
    candidate_identity: Mapping[str, Any],
    runtime_receipt: Mapping[str, Any],
    controller_work: Path,
    environment: Mapping[str, str],
    controller_requirements_payload: bytes,
) -> Path:
    """Build a fresh runtime only from the revalidated, transferred wheel bytes."""

    if platform.python_version() != candidate.PYTHON_VERSION or platform.machine().lower() not in {
        "x86_64",
        "amd64",
    }:
        raise StrixRuntimeAdmissionQualificationError(
            "fresh runtime reconstruction requires CPython 3.12.14 on x86-64"
        )
    work = work_root.resolve(strict=True)
    prepared = preparation_root.resolve(strict=True)
    controller = controller_work.resolve(strict=True)
    runtime_root = work / "runtime"
    if runtime_root.exists() or runtime_root.is_symlink():
        raise StrixRuntimeAdmissionQualificationError(
            "fresh runtime reconstruction requires an absent runtime tree"
        )

    pip_wheel = work / "pip-tool" / preparation.PIP_WHEEL_NAME
    pip_payload = _read_regular(pip_wheel, preparation.MAX_DOWNLOAD_BYTES)
    if (
        len(pip_payload) != preparation.PIP_WHEEL_SIZE
        or _sha256(pip_payload) != preparation.PIP_WHEEL_SHA256
    ):
        raise StrixRuntimeAdmissionQualificationError("pinned pip wheel identity drifted")
    pip_receipt = runtime_receipt.get("pip")
    if (
        not isinstance(pip_receipt, Mapping)
        or pip_receipt.get("path") != preparation.PIP_WHEEL_NAME
        or pip_receipt.get("size") != preparation.PIP_WHEEL_SIZE
        or pip_receipt.get("sha256") != preparation.PIP_WHEEL_SHA256
    ):
        raise StrixRuntimeAdmissionQualificationError("runtime receipt pip identity drifted")
    pip_version = preparation._run_pip(
        Path(sys.executable),
        pip_wheel,
        ["--version"],
        cwd=controller,
        environment=environment,
    )
    if (
        not pip_version.startswith(f"pip {preparation.PIP_VERSION} ")
        or pip_receipt.get("version_output") != pip_version
    ):
        raise StrixRuntimeAdmissionQualificationError("pinned pip version output drifted")

    requirements_path = prepared / preparation.REQUIREMENTS_NAME
    requirements_payload = _read_regular(requirements_path, preparation.MAX_REQUIREMENTS_BYTES)
    preparation.validate_hashed_requirements(requirements_payload)
    preparation.validate_hashed_requirements(controller_requirements_payload)
    if requirements_payload != controller_requirements_payload:
        raise StrixRuntimeAdmissionQualificationError(
            "transferred requirements differ from the controller-held lock export"
        )
    requirements_receipt = runtime_receipt.get("requirements")
    wheel_identity = candidate_identity.get("wheel_identity")
    if not isinstance(requirements_receipt, Mapping) or not isinstance(wheel_identity, Mapping):
        raise StrixRuntimeAdmissionQualificationError(
            "runtime reconstruction receipt is incomplete"
        )
    if (
        requirements_receipt.get("path") != preparation.REQUIREMENTS_NAME
        or requirements_receipt.get("sha256") != _sha256(requirements_payload)
        or requirements_receipt.get("frozen_lock_sha256") != candidate_identity.get("lock_sha256")
        or requirements_receipt.get("candidate_wheel_sha256") != wheel_identity.get("sha256")
    ):
        raise StrixRuntimeAdmissionQualificationError("runtime requirements identity drifted")

    wheelhouse = prepared / preparation.WHEELHOUSE_NAME
    wheelhouse_receipt = preparation.inventory_wheelhouse(wheelhouse)
    if runtime_receipt.get("wheelhouse") != wheelhouse_receipt:
        raise StrixRuntimeAdmissionQualificationError("runtime wheelhouse identity drifted")

    candidate_wheel = Path(str(candidate_identity.get("wheel_path", ""))).resolve(strict=True)
    combined_payload = requirements_payload
    if not combined_payload.endswith(b"\n"):
        combined_payload += b"\n"
    combined_payload += (
        f"strix-agent @ {candidate_wheel.as_uri()} --hash=sha256:{wheel_identity.get('sha256')}\n"
    ).encode("ascii")
    if requirements_receipt.get("one_shot_install_manifest_sha256") != _sha256(combined_payload):
        raise StrixRuntimeAdmissionQualificationError("runtime install manifest identity drifted")
    combined_requirements = controller / "runtime-install-requirements.txt"
    preparation._write_exclusive(combined_requirements, combined_payload)

    os.chmod(work, 0o700)
    venv.EnvBuilder(with_pip=False, symlinks=True).create(runtime_root)
    try:
        preparation._run_pip(
            Path(sys.executable),
            pip_wheel,
            [
                "--isolated",
                "--python",
                str(runtime_root),
                "install",
                "--no-index",
                "--no-cache-dir",
                "--no-compile",
                "--no-deps",
                "--require-hashes",
                "--find-links",
                str(wheelhouse),
                "--requirement",
                str(combined_requirements),
            ],
            cwd=controller,
            environment=environment,
        )
        site_packages = (runtime_root / "lib/python3.12/site-packages").resolve(strict=True)
        if runtime_root.resolve(strict=True) not in site_packages.parents:
            raise StrixRuntimeAdmissionQualificationError(
                "fresh runtime site-packages escaped its root"
            )
        installed = preparation._installed_distributions(site_packages)
        expected_installed = _installed_map(runtime_receipt)
        if installed != expected_installed:
            raise StrixRuntimeAdmissionQualificationError(
                "fresh installed distribution identities differ from the receipt"
            )
        expected_versions = {
            str(row["normalized_name"]): str(row["version"])
            for row in cast(list[dict[str, Any]], wheelhouse_receipt["wheels"])
        }
        expected_versions["strix-agent"] = candidate.DECLARED_PACKAGE_VERSION
        if {name: str(row["version"]) for name, row in installed.items()} != expected_versions:
            raise StrixRuntimeAdmissionQualificationError(
                "fresh installed distributions differ from the offline closure"
            )
        inspected = _inspect_runtime(
            runtime_root,
            runtime_receipt,
            prompt_sha256=str(candidate_identity["prompt_sha256"]),
        )
        if runtime_receipt.get("strix") != inspected:
            raise StrixRuntimeAdmissionQualificationError(
                "fresh installed Strix identity differs from the receipt"
            )
    except BaseException:
        shutil.rmtree(runtime_root, ignore_errors=False)
        raise
    return runtime_root.resolve(strict=True)


def _validated_build_inputs(candidate_identity: Mapping[str, Any]) -> tuple[str, str]:
    manifest = candidate_identity.get("manifest")
    wheel = candidate_identity.get("wheel_identity")
    if not isinstance(manifest, Mapping) or not isinstance(wheel, Mapping):
        raise StrixRuntimeAdmissionQualificationError("candidate build identity is missing")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise StrixRuntimeAdmissionQualificationError("candidate artifact identity is missing")
    source_rows = [
        row
        for row in artifacts
        if isinstance(row, Mapping) and row.get("path") == candidate.SOURCE_ARCHIVE_NAME
    ]
    if len(source_rows) != 1:
        raise StrixRuntimeAdmissionQualificationError("candidate source identity is ambiguous")
    source_digest = source_rows[0].get("sha256")
    package_digest = wheel.get("sha256")
    if (
        not isinstance(source_digest, str)
        or _DIGEST.fullmatch(source_digest) is None
        or not isinstance(package_digest, str)
        or _DIGEST.fullmatch(package_digest) is None
    ):
        raise StrixRuntimeAdmissionQualificationError("candidate build digest is invalid")
    source_ref = f"sha256:{source_digest}"
    package_ref = f"sha256:{package_digest}"
    future = manifest.get("future_install_identity_inputs")
    if not isinstance(future, Mapping) or (
        future.get("source_tree_sha256") != source_ref
        or future.get("package_sha256") != package_ref
    ):
        raise StrixRuntimeAdmissionQualificationError(
            "candidate future build identity differs from validated artifacts"
        )
    return source_ref, package_ref


def _validated_candidate_refs(
    candidate_path: Path, candidate_identity: Mapping[str, Any]
) -> tuple[str, str]:
    manifest_payload = _read_regular(
        candidate_path / candidate.MANIFEST_NAME, candidate.MAX_OUTPUT_BYTES
    )
    checksums_payload = _read_regular(
        candidate_path / candidate.CHECKSUMS_NAME, candidate.MAX_OUTPUT_BYTES
    )
    manifest_hash = _sha256(manifest_payload)
    checksums_hash = _sha256(checksums_payload)
    if manifest_hash != candidate_identity.get(
        "manifest_sha256"
    ) or checksums_hash != candidate_identity.get("checksums_sha256"):
        raise StrixRuntimeAdmissionQualificationError("candidate receipts changed after validation")
    return f"sha256:{manifest_hash}", f"sha256:{checksums_hash}"


def _make_runtime_read_only(runtime_root: Path, work_root: Path) -> None:
    root = runtime_root.resolve(strict=True)
    work = work_root.resolve(strict=True)
    if root != work / "runtime":
        raise StrixRuntimeAdmissionQualificationError("runtime root differs from preparation work")
    # The unprivileged namespace identity needs traversal to the exact runtime.
    # Other preparation children retain their private modes; the runtime itself
    # is open-source code and is made read-only before it becomes traversable.
    os.chmod(work, 0o711)  # nosec B103
    for path in sorted(root.rglob("*"), key=lambda value: len(value.parts), reverse=True):
        if path.is_symlink():
            continue
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            os.chmod(path, 0o555)  # nosec B103
        elif stat.S_ISREG(metadata.st_mode):
            os.chmod(path, 0o555 if metadata.st_mode & 0o111 else 0o444)
        else:
            raise StrixRuntimeAdmissionQualificationError("runtime tree contains a special file")
    os.chmod(root, 0o555)  # nosec B103


def _write_probe_directory(path: Path) -> None:
    path.mkdir(mode=0o700)
    chown = getattr(os, "chown", None)
    if chown is None:
        raise StrixRuntimeAdmissionQualificationError("probe ownership control is unavailable")
    chown(path, PROBE_UID, PROBE_GID)


def _stream_receipt(path: Path) -> dict[str, Any]:
    payload = _read_regular(path, MAX_STREAM_BYTES)
    return {"bytes": len(payload), "sha256": f"sha256:{_sha256(payload)}"}


def _check_probe_tree(path: Path) -> None:
    count = 0
    total = 0
    for child in path.rglob("*"):
        metadata = child.lstat()
        if child.is_symlink() or not (
            stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)
        ):
            raise StrixRuntimeAdmissionQualificationError(
                "probe writable state contains a link or special file"
            )
        if child.is_dir():
            continue
        count += 1
        total += metadata.st_size
        if count > 128 or total > MAX_STREAM_BYTES:
            raise StrixRuntimeAdmissionQualificationError("probe writable state exceeds its bound")


def _write_isolation_wrapper(path: Path) -> None:
    payload = b"""#!/bin/sh
set -eu
runtime=$1
cli=$2
home=$3
mount --make-rprivate /
mount -t tmpfs -o nosuid,nodev,noexec,mode=755,size=1m,nr_inodes=256 tmpfs /run
mount -t tmpfs -o nosuid,nodev,noexec,mode=1777,size=8m,nr_inodes=1024 tmpfs /tmp
mount -t tmpfs -o nosuid,nodev,noexec,mode=1777,size=8m,nr_inodes=1024 tmpfs /var/tmp
mount -t tmpfs -o nosuid,nodev,noexec,mode=1777,size=8m,nr_inodes=1024 tmpfs /dev/shm
mount -t tmpfs -o nosuid,nodev,noexec,mode=000,size=1m,nr_inodes=64 tmpfs /dev/mqueue
mount -t tmpfs -o nosuid,nodev,noexec,mode=700,uid=65534,gid=65534,size=8m,nr_inodes=1024 tmpfs "$home"
mount --bind "$runtime" "$runtime"
mount -o remount,bind,ro,nosuid,nodev "$runtime"
exec /usr/bin/setpriv \
  --reuid=65534 --regid=65534 --clear-groups --no-new-privs \
  --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
  /usr/bin/prlimit \
  --cpu=10 --as=2147483648 --nproc=64 --nofile=128 --fsize=1048576 --core=0 \
  /usr/bin/env -i \
  "HOME=$home" \
  "XDG_CONFIG_HOME=$home/config" \
  "XDG_CACHE_HOME=$home/cache" \
  "XDG_DATA_HOME=$home/data" \
  "TMPDIR=/tmp" \
  "DOCKER_CONFIG=$home/docker" \
  "PATH=$runtime/bin:/usr/bin:/bin" \
  PYTHONNOUSERSITE=1 PYTHONSAFEPATH=1 PYTHONDONTWRITEBYTECODE=1 \
  PIP_CONFIG_FILE=/dev/null LC_ALL=C.UTF-8 LANG=C.UTF-8 TERM=dumb \
  "$cli" --help
"""
    path.write_bytes(payload)
    os.chmod(path, 0o555)  # nosec B103


def _probe_command(cli: Path, runtime: Path, home: Path, wrapper: Path) -> list[str]:
    return [
        "/usr/bin/unshare",
        "--net",
        "--ipc",
        "--uts",
        "--pid",
        "--mount",
        "--fork",
        "--kill-child",
        "--mount-proc",
        os.fspath(wrapper),
        os.fspath(runtime),
        os.fspath(cli),
        os.fspath(home),
    ]


def _production_probe(cli: Path, runtime_root: Path, work_root: Path) -> Mapping[str, Any]:
    geteuid = getattr(os, "geteuid", None)
    killpg = getattr(os, "killpg", None)
    kill_signal = getattr(signal, "SIGKILL", signal.SIGTERM)
    if (
        os.name != "posix"
        or platform.system() != "Linux"
        or geteuid is None
        or geteuid() != 0
        or killpg is None
    ):
        raise StrixRuntimeAdmissionQualificationError(
            "runtime admission probe requires a root controller on Linux"
        )
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        raise StrixRuntimeAdmissionQualificationError(
            "runtime admission probe requires Linux x86-64"
        )
    for executable in (
        Path("/usr/bin/unshare"),
        Path("/usr/bin/mount"),
        Path("/usr/bin/setpriv"),
        Path("/usr/bin/prlimit"),
        Path("/usr/bin/env"),
    ):
        metadata = executable.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise StrixRuntimeAdmissionQualificationError(
                "runtime admission isolation tool is not trusted"
            )
    _make_runtime_read_only(runtime_root, work_root)
    state = work_root / "admission-probe-state"
    if state.exists():
        raise StrixRuntimeAdmissionQualificationError("probe state already exists")
    state.mkdir(mode=0o711)
    process: subprocess.Popen[bytes] | None = None
    try:
        home = state / "home"
        _write_probe_directory(home)
        wrapper = state / "isolate-and-probe"
        _write_isolation_wrapper(wrapper)
        stdout_path = state / "stdout"
        stderr_path = state / "stderr"
        started = time.monotonic()
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            # The command is constructed solely from fixed tools and validated paths.
            process = subprocess.Popen(  # nosec B603
                _probe_command(cli, runtime_root, home, wrapper),
                cwd=state,
                env={
                    "PATH": "/usr/bin:/bin",
                    "LC_ALL": "C.UTF-8",
                    "LANG": "C.UTF-8",
                },
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
            try:
                exit_code = process.wait(timeout=PROBE_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired as exc:
                killpg(process.pid, kill_signal)
                process.wait(timeout=5)
                raise StrixRuntimeAdmissionQualificationError(
                    "runtime admission probe exceeded its wall-clock bound"
                ) from exc
        elapsed = int((time.monotonic() - started) * 1000)
        stdout_payload = _read_regular(stdout_path, MAX_STREAM_BYTES)
        stderr_payload = _read_regular(stderr_path, MAX_STREAM_BYTES)
        try:
            help_text = (stdout_payload + b"\n" + stderr_payload).decode("utf-8").lower()
        except UnicodeDecodeError as exc:
            raise StrixRuntimeAdmissionQualificationError(
                "runtime admission probe output is not UTF-8"
            ) from exc
        if exit_code != 0 or "usage" not in help_text or "--target" not in help_text:
            raise StrixRuntimeAdmissionQualificationError(
                "installed Strix CLI help probe did not complete"
            )
        _check_probe_tree(home)
        return {
            "argv": ["--help"],
            "exit_code": 0,
            "stdout": _stream_receipt(stdout_path),
            "stderr": _stream_receipt(stderr_path),
            "elapsed_milliseconds": elapsed,
            "network_namespace": "isolated-empty",
            "process_namespace": "isolated",
            "mount_namespace": "isolated",
            "probe_uid": PROBE_UID,
            "probe_gid": PROBE_GID,
            "credential_environment": False,
            "help_tokens_verified": True,
            "runtime_unchanged": True,
            "owned_work_absent": True,
        }
    finally:
        if process is not None and process.poll() is None:
            killpg(process.pid, kill_signal)
            process.wait(timeout=5)
        shutil.rmtree(state, ignore_errors=False)
        if state.exists():
            raise StrixRuntimeAdmissionQualificationError("probe writable state remains")


def qualify_runtime_admission(
    *,
    candidate_root: Path,
    source_root: Path,
    preparation_root: Path,
    preparation_work_root: Path,
    output_root: Path,
    bluefire_source_revision: str,
    transfer_bundle_ref: str,
    threat_review_ref: str,
    inherited_environment: Mapping[str, str] | None = None,
    probe_runner: ProbeRunner | None = None,
    require_fresh_runtime: bool = False,
    controller_requirements_payload: bytes | None = None,
) -> dict[str, Any]:
    """Validate the exact preparation, run the fixed probe, and emit one manifest."""

    if _REVISION.fullmatch(bluefire_source_revision) is None:
        raise StrixRuntimeAdmissionQualificationError("BlueFire revision must be an exact commit")
    if _DIGEST_REF.fullmatch(transfer_bundle_ref) is None:
        raise StrixRuntimeAdmissionQualificationError("transfer bundle ref is invalid")
    if _DIGEST_REF.fullmatch(threat_review_ref) is None:
        raise StrixRuntimeAdmissionQualificationError("threat-review ref is invalid")
    candidate_path = candidate_root.resolve(strict=True)
    source = source_root.resolve(strict=True)
    prepared = preparation_root.resolve(strict=True)
    work = preparation_work_root.resolve(strict=True)
    runtime_path = work / "runtime"
    output = output_root.resolve(strict=False)
    roots = (candidate_path, source, prepared, work, output)
    if len(set(roots)) != len(roots) or any(
        first in second.parents or second in first.parents
        for index, first in enumerate(roots)
        for second in roots[index + 1 :]
    ):
        raise StrixRuntimeAdmissionQualificationError("runtime admission roots must be separate")
    if output.exists():
        raise StrixRuntimeAdmissionQualificationError("runtime admission output root must be new")
    controller_work = output.parent / f".{output.name}-controller-work"
    if controller_work.exists():
        raise StrixRuntimeAdmissionQualificationError(
            "runtime admission controller work root already exists"
        )
    output.mkdir(mode=0o755)
    controller_work.mkdir(mode=0o700)
    succeeded = False
    try:
        environment = _safe_environment(controller_work)
        environment.update(
            {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "safe.directory",
                "GIT_CONFIG_VALUE_0": os.fspath(source),
            }
        )
        for name in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"):
            value = (inherited_environment or {}).get(name)
            if value:
                environment[name] = value
        candidate_identity = preparation.validate_candidate(
            candidate_path,
            source,
            bluefire_source_revision,
            environment,
        )
        candidate_manifest = cast(Mapping[str, Any], candidate_identity["manifest"])
        prep_manifest, runtime, input_refs = _validate_preparation(
            prepared,
            revision=bluefire_source_revision,
            candidate_identity=candidate_identity,
        )
        if require_fresh_runtime:
            if controller_requirements_payload is None:
                raise StrixRuntimeAdmissionQualificationError(
                    "fresh runtime reconstruction requires controller-held requirements"
                )
            if runtime_path.exists() or runtime_path.is_symlink():
                raise StrixRuntimeAdmissionQualificationError(
                    "transferred runtime tree is forbidden on the fresh runner"
                )
            runtime_root = _reconstruct_runtime_offline(
                work,
                prepared,
                candidate_identity,
                runtime,
                controller_work,
                environment,
                controller_requirements_payload,
            )
        else:
            runtime_root = runtime_path.resolve(strict=True)
        before = _inspect_runtime(
            runtime_root,
            runtime,
            prompt_sha256=str(candidate_identity["prompt_sha256"]),
        )
        cli = runtime_root / str(cast(Mapping[str, Any], before["cli"])["path"])
        probe = dict((probe_runner or _production_probe)(cli, runtime_root, work))
        after = _inspect_runtime(
            runtime_root,
            runtime,
            prompt_sha256=str(candidate_identity["prompt_sha256"]),
        )
        if after != before:
            raise StrixRuntimeAdmissionQualificationError(
                "installed runtime changed during the startup probe"
            )
        if set(probe) != {
            "argv",
            "exit_code",
            "stdout",
            "stderr",
            "elapsed_milliseconds",
            "network_namespace",
            "process_namespace",
            "mount_namespace",
            "probe_uid",
            "probe_gid",
            "credential_environment",
            "help_tokens_verified",
            "runtime_unchanged",
            "owned_work_absent",
        }:
            raise StrixRuntimeAdmissionQualificationError(
                "runtime admission probe receipt is invalid"
            )

        candidate_manifest_ref, candidate_checksums_ref = _validated_candidate_refs(
            candidate_path, candidate_identity
        )
        policy = cast(Mapping[str, Any], candidate_manifest["policy_overlay"])
        source_ref, package_ref = _validated_build_inputs(candidate_identity)
        runner_values = {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "image_os": str((inherited_environment or {}).get("BLUEFIRE_IMAGE_OS", "")),
            "image_version": str((inherited_environment or {}).get("BLUEFIRE_IMAGE_VERSION", "")),
        }
        if any(_SAFE_RUNNER.fullmatch(value) is None for value in runner_values.values()):
            raise StrixRuntimeAdmissionQualificationError("runner identity is invalid")
        manifest: dict[str, Any] = {
            "schema_version": "bluefire.strix-runtime-admission.v1",
            "status": "qualified-installed-cli-startup-only",
            "bluefire_source_revision": bluefire_source_revision,
            "inputs": {
                "candidate_manifest_ref": candidate_manifest_ref,
                "candidate_checksums_ref": candidate_checksums_ref,
                **input_refs,
                "transfer_bundle_ref": transfer_bundle_ref,
                "threat_review_ref": threat_review_ref,
            },
            "runner": {
                "system": runner_values["system"],
                "release": runner_values["release"],
                "machine": runner_values["machine"],
                "image_os": runner_values["image_os"],
                "image_version": runner_values["image_version"],
            },
            "build_identity": {
                "engine": "strix",
                "package_version": candidate.DECLARED_PACKAGE_VERSION,
                "source_revision": candidate.UPSTREAM_COMMIT,
                "source_tree_sha256": source_ref,
                "package_sha256": package_ref,
                "executable_sha256": f"sha256:{before['cli']['sha256']}",
                "image_reference": candidate.SANDBOX_IMAGE,
                "image_inventory_sha256": input_refs["oci_inventory_ref"],
                "prompt_upstream_sha256": f"sha256:{policy['upstream_sha256']}",
                "prompt_overlay_sha256": f"sha256:{policy['overlay_sha256']}",
                "prompt_patched_sha256": f"sha256:{policy['patched_sha256']}",
            },
            "probe": probe,
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
        payload = _canonical(manifest) + b"\n"
        manifest_path = output / MANIFEST_NAME
        manifest_path.write_bytes(payload)
        checksum_payload = f"{_sha256(payload)}  {MANIFEST_NAME}\n".encode("ascii")
        (output / CHECKSUMS_NAME).write_bytes(checksum_payload)
        manifest_ref = f"sha256:{_sha256(payload)}"
        loaded = load_strix_runtime_qualification(manifest_path, expected_ref=manifest_ref)
        if (
            loaded.runtime_qualified is not True
            or loaded.production_runtime_admitted is not False
            or loaded.runtime_qualification_ref != manifest_ref
            or loaded.bluefire_source_revision != bluefire_source_revision
            or loaded.threat_review_ref != threat_review_ref
        ):
            raise StrixRuntimeAdmissionQualificationError(
                "emitted runtime qualification cannot be admitted"
            )
        succeeded = True
        return manifest
    finally:
        shutil.rmtree(controller_work, ignore_errors=False)
        if not succeeded:
            shutil.rmtree(output, ignore_errors=False)


def _stage_metadata_is_sealed(metadata: os.stat_result) -> bool:
    return metadata.st_uid == 0 and metadata.st_gid == 0 and stat.S_IMODE(metadata.st_mode) == 0o711


def _sealed_stage_root(path: Path) -> Path:
    root_input = Path(os.path.abspath(path))
    root_metadata = root_input.lstat()
    if root_input.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
        raise StrixRuntimeAdmissionQualificationError(
            "fresh-runner stage parent is not a real directory"
        )
    root = root_input.resolve(strict=True)
    if root != root_input:
        raise StrixRuntimeAdmissionQualificationError("fresh-runner stage parent traverses a link")
    if os.name == "posix" and not _stage_metadata_is_sealed(root_metadata):
        raise StrixRuntimeAdmissionQualificationError(
            "fresh-runner stage parent is not root-owned search-only"
        )
    return root


def qualify_runtime_admission_bundle(
    *,
    input_bundle: Path,
    expected_bundle_ref: str,
    transfer_root: Path,
    source_work_root: Path,
    source_root: Path,
    controller_requirements_path: Path,
    output_root: Path,
    bluefire_source_revision: str,
    threat_review_ref: str,
    inherited_environment: Mapping[str, str],
) -> dict[str, Any]:
    """Extract on a fresh runner, revalidate, probe, and remove transfer state."""

    root = _sealed_stage_root(transfer_root)
    bundle = Path(os.path.abspath(input_bundle))
    download = root / "bluefire-strix-admission-download"
    controller_inputs = root / "bluefire-strix-admission-controller-inputs"
    controller_requirements = Path(os.path.abspath(controller_requirements_path))
    source_work = source_work_root.resolve(strict=True)
    source = source_root.resolve(strict=True)
    output = output_root.resolve(strict=False)
    if (
        source.parent != source_work
        or source_work.name != "bluefire-strix-admission-source-work"
        or root not in source_work.parents
        or re.fullmatch(r"bluefire-strix-admission-input-[0-9]+-[0-9]+\.tar", bundle.name) is None
        or bundle.parent != download
        or controller_requirements != controller_inputs / preparation.REQUIREMENTS_NAME
        or root not in output.parents
    ):
        raise StrixRuntimeAdmissionQualificationError(
            "fresh-runner admission paths do not match the fixed layout"
        )
    fixed_roots = [
        root / name for name in (CANDIDATE_DIRECTORY, PREPARATION_DIRECTORY, WORK_DIRECTORY)
    ]
    if any(path.exists() or path.is_symlink() for path in fixed_roots):
        raise StrixRuntimeAdmissionQualificationError(
            "fresh-runner transfer roots must be absent before extraction"
        )

    result: dict[str, Any] | None = None
    primary_error: BaseException | None = None
    try:
        controller_metadata = controller_inputs.lstat()
        if controller_inputs.is_symlink() or not stat.S_ISDIR(controller_metadata.st_mode):
            raise StrixRuntimeAdmissionQualificationError(
                "controller requirements path is not a real directory"
            )
        controller_entries = list(os.scandir(controller_inputs))
        if (
            len(controller_entries) != 1
            or controller_entries[0].name != preparation.REQUIREMENTS_NAME
        ):
            raise StrixRuntimeAdmissionQualificationError(
                "controller requirements directory inventory is not exact"
            )
        controller_file_metadata = controller_entries[0].stat(follow_symlinks=False)
        if (
            controller_entries[0].is_symlink()
            or not stat.S_ISREG(controller_file_metadata.st_mode)
            or controller_file_metadata.st_nlink != 1
        ):
            raise StrixRuntimeAdmissionQualificationError(
                "controller requirements are not a standalone regular file"
            )
        controller_requirements_payload = _read_regular(
            controller_requirements, preparation.MAX_REQUIREMENTS_BYTES
        )
        download_metadata = download.lstat()
        if download.is_symlink() or not stat.S_ISDIR(download_metadata.st_mode):
            raise StrixRuntimeAdmissionQualificationError(
                "fresh-runner download path is not a real directory"
            )
        entries = list(os.scandir(download))
        if len(entries) != 1 or entries[0].name != bundle.name:
            raise StrixRuntimeAdmissionQualificationError(
                "fresh-runner download directory inventory is not exact"
            )
        bundle_metadata = entries[0].stat(follow_symlinks=False)
        if (
            entries[0].is_symlink()
            or not stat.S_ISREG(bundle_metadata.st_mode)
            or bundle_metadata.st_nlink != 1
        ):
            raise StrixRuntimeAdmissionQualificationError(
                "fresh-runner transfer is not a standalone regular file"
            )
        candidate_root, preparation_root, preparation_work_root = extract_transfer_bundle(
            bundle,
            transfer_root=root,
            expected_ref=expected_bundle_ref,
            bluefire_source_revision=bluefire_source_revision,
            threat_review_ref=threat_review_ref,
        )
        result = qualify_runtime_admission(
            candidate_root=candidate_root,
            source_root=source,
            preparation_root=preparation_root,
            preparation_work_root=preparation_work_root,
            output_root=output,
            bluefire_source_revision=bluefire_source_revision,
            transfer_bundle_ref=expected_bundle_ref,
            threat_review_ref=threat_review_ref,
            inherited_environment=inherited_environment,
            require_fresh_runtime=True,
            controller_requirements_payload=controller_requirements_payload,
        )
    except BaseException as exc:
        primary_error = exc

    cleanup_errors: list[str] = []
    try:
        remove_transfer_tree(root)
    except BaseException as exc:
        cleanup_errors.append(f"transfer roots: {exc}")
    try:
        if source_work.is_symlink():
            source_work.unlink()
        elif source_work.exists():
            shutil.rmtree(source_work, ignore_errors=False)
    except BaseException as exc:
        cleanup_errors.append(f"source work: {exc}")
    try:
        if controller_inputs.is_symlink():
            controller_inputs.unlink()
        elif controller_inputs.exists():
            shutil.rmtree(controller_inputs, ignore_errors=False)
    except BaseException as exc:
        cleanup_errors.append(f"controller requirements: {exc}")
    try:
        metadata = bundle.lstat()
        if stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            bundle.unlink()
        else:
            raise StrixRuntimeAdmissionQualificationError(
                "fresh-runner transfer path became a non-file"
            )
    except FileNotFoundError:
        pass
    except BaseException as exc:
        cleanup_errors.append(f"transfer bundle: {exc}")
    try:
        download.rmdir()
    except FileNotFoundError:
        pass
    except BaseException as exc:
        cleanup_errors.append(f"download directory: {exc}")

    for label, path in [
        *[("transfer root", item) for item in fixed_roots],
        ("source work", source_work),
        ("controller requirements", controller_inputs),
        ("transfer bundle", bundle),
        ("download directory", download),
    ]:
        try:
            remains = path.exists() or path.is_symlink()
        except OSError as exc:
            cleanup_errors.append(f"{label} absence: {exc}")
        else:
            if remains:
                cleanup_errors.append(f"{label} remains")

    if cleanup_errors:
        try:
            if output.is_symlink():
                output.unlink()
            elif output.exists():
                shutil.rmtree(output, ignore_errors=False)
        except BaseException as exc:
            cleanup_errors.append(f"invalid admission output: {exc}")
        message = "fresh-runner admission cleanup or absence failed: " + "; ".join(cleanup_errors)
        raise StrixRuntimeAdmissionQualificationError(message) from primary_error
    if primary_error is not None:
        raise primary_error
    if result is None:
        raise StrixRuntimeAdmissionQualificationError("fresh-runner admission produced no result")
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-bundle", type=Path, required=True)
    parser.add_argument("--expected-bundle-ref", required=True)
    parser.add_argument("--transfer-root", type=Path, required=True)
    parser.add_argument("--source-work-root", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--controller-requirements", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--bluefire-source-revision", required=True)
    parser.add_argument("--threat-review-ref", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        manifest = qualify_runtime_admission_bundle(
            input_bundle=args.input_bundle,
            expected_bundle_ref=args.expected_bundle_ref,
            transfer_root=args.transfer_root,
            source_work_root=args.source_work_root,
            source_root=args.source_root,
            controller_requirements_path=args.controller_requirements,
            output_root=args.output_root,
            bluefire_source_revision=args.bluefire_source_revision,
            threat_review_ref=args.threat_review_ref,
            inherited_environment=os.environ,
        )
    except (OSError, ValueError, StrixRuntimeAdmissionQualificationError) as exc:
        print(f"Strix runtime admission qualification refused: {exc}", file=sys.stderr)
        return 2
    print(
        "Qualified exact installed Strix CLI startup only; target, model, containment, "
        "lifecycle, and effectiveness remain unproven."
    )
    if manifest["qualification"]["runtime_qualified"] is not True:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
