"""Prepare an offline, hash-bound Strix runtime candidate without running Strix.

This qualification-preparation step consumes the exact candidate produced by
``build_strix_engine_candidate``. It binds a Linux x86-64 Python installation
closure and inventories the pinned sandbox image, but it never imports or runs
Strix, starts a container, contacts a target or model, or publishes a package.
Runtime qualification deliberately remains false in every emitted receipt.
"""

from __future__ import annotations

import argparse
import base64
import configparser
import csv
import hashlib
import io
import json
import os
import platform
import re
import shutil
import stat
import subprocess  # nosec B404
import sys
import tarfile
import urllib.parse
import urllib.request
import venv
import zipfile
from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import default as email_policy
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence

from bluefire.strix_policy_overlay import (
    OVERLAY_SHA256,
    PATCHED_PROMPT_SHA256,
    REVIEWED_PROMPT_SHA256,
)
from bluefire.strix_redistribution_review import (
    is_blocked_strix_redistribution_review,
    strix_redistribution_review,
)
from bluefire.strix_startup_overlay import (
    PATCHED_STARTUP_SHA256,
    REVIEWED_STARTUP_SHA256,
    STARTUP_OVERLAY_SHA256,
)
from tools import build_strix_engine_candidate as candidate

PIP_VERSION = "25.3"
PIP_WHEEL_NAME = "pip-25.3-py3-none-any.whl"
PIP_WHEEL_URL = (
    "https://files.pythonhosted.org/packages/44/3c/"
    "d717024885424591d5376220b5e836c2d5293ce2011523c9de23ff7bf068/"
    "pip-25.3-py3-none-any.whl"
)
PIP_WHEEL_SHA256 = "9655943313a94722b7774661c21049070f6bbb0a1516bf02f7c8d5d9201514cd"  # pragma: allowlist secret -- public wheel digest
PIP_WHEEL_SIZE = 1_778_622

SYFT_VERSION = "1.56.0"
SYFT_ARCHIVE_NAME = "syft_1.56.0_linux_amd64.tar.gz"
SYFT_ARCHIVE_URL = (
    "https://github.com/anchore/syft/releases/download/v1.56.0/syft_1.56.0_linux_amd64.tar.gz"
)
SYFT_ARCHIVE_SHA256 = "1c2493cfcf52d3367d6cb25780d9190c111c2219c34c820574c43e8bae15c528"  # pragma: allowlist secret -- public release archive digest
SYFT_CHECKSUMS_NAME = "syft_1.56.0_checksums.txt"
SYFT_CHECKSUMS_URL = (
    "https://github.com/anchore/syft/releases/download/v1.56.0/syft_1.56.0_checksums.txt"
)
SYFT_CHECKSUMS_SHA256 = "a2db61bc71f8f7ea8c67fc4a81b8e4e6474386e6a07d104bd2e78e964d5d7ec7"  # pragma: allowlist secret -- public release checksums digest

QUALIFICATION_MANIFEST_NAME = "strix-runtime-qualification-manifest.json"
REQUIREMENTS_NAME = "strix-runtime-requirements.txt"
RUNTIME_RECEIPT_NAME = "python-runtime-install-receipt.json"
OCI_INVENTORY_NAME = "strix-sandbox-oci-inventory.json"
SYFT_SBOM_NAME = "strix-sandbox.syft.json"
CYCLONEDX_SBOM_NAME = "strix-sandbox.cdx.json"
NOTICES_REVIEW_NAME = "strix-sandbox-third-party-notices-review.json"
CHECKSUMS_NAME = "SHA256SUMS"
WHEELHOUSE_NAME = "wheelhouse"

MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024
MAX_WHEEL_COUNT = 512
MAX_WHEELHOUSE_BYTES = 2 * 1024 * 1024 * 1024
MAX_OUTPUT_BYTES = 2 * 1024 * 1024 * 1024
MAX_REQUIREMENTS_BYTES = 8 * 1024 * 1024
MAX_JSON_BYTES = 128 * 1024 * 1024
MAX_JSON_ITEMS = 100_000
MAX_LAYER_BYTES = 8 * 1024 * 1024 * 1024
MAX_IMAGE_BYTES = 32 * 1024 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 30 * 60

INDEX_MEDIA_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
CONFIG_MEDIA_TYPES = {
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
}
LAYER_MEDIA_TYPES = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
}
MAX_NOTICE_PACKAGES = 50_000
MAX_NOTICE_LICENSES_PER_PACKAGE = 32
MAX_NOTICE_TEXT_BYTES = 16 * 1024 * 1024

ACTION_IDENTITIES: Mapping[str, str] = {
    "checkout": "d23441a48e516b6c34aea4fa41551a30e30af803",  # pragma: allowlist secret -- public GitHub Action commit
    "setup_python": "ece7cb06caefa5fff74198d8649806c4678c61a1",  # pragma: allowlist secret -- public GitHub Action commit
    "setup_go": "b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",  # pragma: allowlist secret -- public GitHub Action commit
    "setup_uv": "68559e99cc807c1eb7e9238fd43a15bba460eec2",  # pragma: allowlist secret -- public GitHub Action commit
}

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$")
_REQUIREMENT = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9_,.-]+\])?==[^\s;\\]+"
    r"(?:\s*;\s*[^\\]+)?(?:\s+--hash=sha256:[0-9a-f]{64})+$"
)
_PIP_RUNNER = (
    "import runpy,sys;"
    "sys.path.insert(0,sys.argv[1]);"
    "sys.argv=sys.argv[1:];"
    "runpy.run_module('pip',run_name='__main__')"
)


class StrixRuntimeQualificationError(RuntimeError):
    """The preparation could not establish an exact, bounded identity."""


@dataclass(frozen=True, slots=True)
class FileIdentity:
    path: str
    size: int
    sha256: str
    media_type: str

    def to_dict(self) -> dict[str, str | int]:
        return {
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "media_type": self.media_type,
        }


@dataclass(frozen=True, slots=True)
class RegistryResponse:
    payload: bytes
    headers: Mapping[str, str]


RegistryFetch = Callable[[str, str], RegistryResponse]


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _is_reparse(details: os.stat_result) -> bool:
    return bool(
        int(getattr(details, "st_file_attributes", 0))
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _read_regular(path: Path, maximum: int, *, allow_empty: bool = False) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise StrixRuntimeQualificationError(f"required file is unavailable: {path.name}") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or _is_reparse(before)
        or before.st_nlink != 1
        or before.st_size > maximum
        or (before.st_size == 0 and not allow_empty)
    ):
        raise StrixRuntimeQualificationError(
            f"file is not a bounded standalone regular file: {path.name}"
        )
    try:
        payload = path.read_bytes()
        after = path.lstat()
    except OSError as exc:
        raise StrixRuntimeQualificationError(f"file changed while read: {path.name}") from exc
    before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if (
        len(payload) != before.st_size
        or before_identity != after_identity
        or not stat.S_ISREG(after.st_mode)
        or _is_reparse(after)
        or after.st_nlink != 1
    ):
        raise StrixRuntimeQualificationError(f"file identity changed while read: {path.name}")
    return payload


def _strict_json(payload: bytes, *, label: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise StrixRuntimeQualificationError(f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    try:
        return json.loads(payload, object_pairs_hook=reject_duplicates)
    except StrixRuntimeQualificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StrixRuntimeQualificationError(f"{label} is not strict JSON") from exc


def _write_exclusive(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        with path.open("xb") as handle:
            handle.write(payload)
    except OSError as exc:
        raise StrixRuntimeQualificationError(f"refused to replace output: {path.name}") from exc


def _require_new_directory(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise StrixRuntimeQualificationError(f"directory already exists: {path.name}")
    path.mkdir(parents=True, mode=0o700, exist_ok=False)


def _run(
    arguments: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout: int = COMMAND_TIMEOUT_SECONDS,
) -> str:
    if not arguments or not all(isinstance(item, str) and item for item in arguments):
        raise StrixRuntimeQualificationError("refusing malformed command")
    try:
        # Every caller supplies fixed or strictly validated argv; no shell is involved.
        completed = subprocess.run(  # noqa: S603  # nosec B603
            list(arguments),
            cwd=cwd,
            env=dict(environment),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StrixRuntimeQualificationError(f"command failed to run: {arguments[0]}") from exc
    if completed.returncode != 0:
        raise StrixRuntimeQualificationError(
            f"command returned {completed.returncode}: {Path(arguments[0]).name}"
        )
    if len(completed.stdout) > 1024 * 1024:
        raise StrixRuntimeQualificationError("command output exceeded its bound")
    return completed.stdout.rstrip("\r\n")


def _run_pip(
    python: Path,
    pip_wheel: Path,
    arguments: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
) -> str:
    """Run pip only from the exact wheel, without installing or resolving pip."""

    return _run(
        [str(python), "-I", "-S", "-c", _PIP_RUNNER, str(pip_wheel), *arguments],
        cwd=cwd,
        environment=environment,
    )


def _urlopen_no_proxy(request: urllib.request.Request, *, timeout: int) -> Any:
    """Open a fixed HTTPS request without ambient proxy or credential helpers."""

    class RestrictedRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(  # type: ignore[no-untyped-def]
            self, request, file_pointer, code, message, headers, new_url
        ):
            redirected = super().redirect_request(
                request, file_pointer, code, message, headers, new_url
            )
            if redirected is None or urllib.parse.urlsplit(new_url).scheme != "https":
                raise StrixRuntimeQualificationError("refused unsafe HTTPS redirect")
            old_host = urllib.parse.urlsplit(request.full_url).hostname
            new_host = urllib.parse.urlsplit(new_url).hostname
            if old_host != new_host:
                redirected.remove_header("Authorization")
            return redirected

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), RestrictedRedirect())
    return opener.open(request, timeout=timeout)


def _sanitized_environment(work: Path, inherited: Mapping[str, str]) -> dict[str, str]:
    path_value = inherited.get("PATH")
    if not path_value:
        raise StrixRuntimeQualificationError("PATH is required")
    home = work / "home"
    temporary = work / "tmp"
    cache = work / "cache"
    docker = work / "docker-config"
    for directory in (home, temporary, cache, docker):
        directory.mkdir(parents=True, mode=0o700, exist_ok=False)
    result = {
        "PATH": path_value,
        "HOME": str(home),
        "TMPDIR": str(temporary),
        "TMP": str(temporary),
        "TEMP": str(temporary),
        "XDG_CACHE_HOME": str(cache),
        "UV_CACHE_DIR": str(cache / "uv"),
        "PIP_CACHE_DIR": str(cache / "pip"),
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INPUT": "1",
        "PIP_ROOT_USER_ACTION": "ignore",
        "PIP_CONFIG_FILE": os.devnull,
        "DOCKER_CONFIG": str(docker),
        "SYFT_CHECK_FOR_APP_UPDATE": "false",
        "SYFT_LOG_QUIET": "true",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
    }
    for name in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"):
        value = inherited.get(name)
        if value:
            result[name] = value
    return result


def _canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _parse_checksums(payload: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise StrixRuntimeQualificationError("checksum file is not ASCII") from exc
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]{0,199})", line)
        if match is None or match.group(2) in result:
            raise StrixRuntimeQualificationError("candidate checksum syntax is invalid")
        result[match.group(2)] = match.group(1)
    if not result:
        raise StrixRuntimeQualificationError("candidate checksum set is empty")
    return result


def validate_candidate(
    candidate_root: Path,
    source_root: Path,
    bluefire_source_revision: str,
    environment: Mapping[str, str],
) -> dict[str, Any]:
    """Validate the exact candidate and its still-present reviewed source checkout."""

    if not _REVISION.fullmatch(bluefire_source_revision):
        raise StrixRuntimeQualificationError("BlueFire revision must be an exact commit")
    root = candidate_root.resolve(strict=True)
    source = source_root.resolve(strict=True)
    manifest_payload = _read_regular(root / candidate.MANIFEST_NAME, candidate.MAX_OUTPUT_BYTES)
    manifest = _strict_json(manifest_payload, label="candidate manifest")
    if not isinstance(manifest, dict):
        raise StrixRuntimeQualificationError("candidate manifest must be an object")
    required_identity = {
        "schema": "bluefire.strix-engine-candidate.v1",
        "status": "built-not-executed",
        "bluefire_source_revision": bluefire_source_revision,
    }
    if any(manifest.get(key) != value for key, value in required_identity.items()):
        raise StrixRuntimeQualificationError("candidate identity does not match this revision")
    upstream = manifest.get("upstream")
    sandbox = manifest.get("sandbox")
    execution = manifest.get("execution")
    qualification = manifest.get("qualification")
    if not isinstance(upstream, dict) or (
        upstream.get("commit") != candidate.UPSTREAM_COMMIT
        or upstream.get("tree") != candidate.UPSTREAM_TREE
        or upstream.get("declared_package_version") != candidate.DECLARED_PACKAGE_VERSION
        or upstream.get("lock_sha256")
        != _sha256(_read_regular(source / "uv.lock", candidate.MAX_SOURCE_FILE_BYTES))
    ):
        raise StrixRuntimeQualificationError("candidate upstream identity drifted")
    if not isinstance(sandbox, dict) or sandbox.get("image") != candidate.SANDBOX_IMAGE:
        raise StrixRuntimeQualificationError("candidate sandbox pin drifted")
    if not isinstance(execution, dict) or not execution or any(execution.values()):
        raise StrixRuntimeQualificationError("candidate unexpectedly records execution")
    if not isinstance(qualification, dict) or qualification.get("runtime_qualified") is not False:
        raise StrixRuntimeQualificationError("candidate qualification state is invalid")
    if not is_blocked_strix_redistribution_review(qualification.get("redistribution_review")):
        raise StrixRuntimeQualificationError("candidate redistribution review must remain blocked")

    checksums = _parse_checksums(
        _read_regular(root / candidate.CHECKSUMS_NAME, candidate.MAX_OUTPUT_BYTES)
    )
    observed = {path.name for path in root.iterdir()}
    if observed != set(checksums) | {candidate.CHECKSUMS_NAME}:
        raise StrixRuntimeQualificationError("candidate output set does not match its checksums")
    for name, digest in checksums.items():
        if _sha256(_read_regular(root / name, candidate.MAX_OUTPUT_BYTES)) != digest:
            raise StrixRuntimeQualificationError("candidate artifact hash mismatch")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise StrixRuntimeQualificationError("candidate artifact inventory is missing")
    artifact_rows: dict[str, dict[str, Any]] = {}
    for row in artifacts:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            raise StrixRuntimeQualificationError("candidate artifact row is invalid")
        if row["path"] in artifact_rows:
            raise StrixRuntimeQualificationError("candidate artifact inventory is ambiguous")
        artifact_rows[row["path"]] = row
    if set(artifact_rows) | {candidate.MANIFEST_NAME} != set(checksums):
        raise StrixRuntimeQualificationError("candidate manifest/checksum inventories disagree")
    for name, row in artifact_rows.items():
        payload = _read_regular(root / name, candidate.MAX_OUTPUT_BYTES)
        if row.get("sha256") != _sha256(payload) or row.get("size") != len(payload):
            raise StrixRuntimeQualificationError("candidate artifact receipt drifted")
    wheels = [name for name in artifact_rows if name.endswith(".whl")]
    if len(wheels) != 1:
        raise StrixRuntimeQualificationError("candidate must contain exactly one wheel")

    head = _run(["git", "rev-parse", "HEAD"], cwd=source, environment=environment)
    tree = _run(["git", "rev-parse", "HEAD^{tree}"], cwd=source, environment=environment)
    changed = _run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=source,
        environment=environment,
    )
    if head != candidate.UPSTREAM_COMMIT or tree != candidate.UPSTREAM_TREE:
        raise StrixRuntimeQualificationError("candidate source checkout identity drifted")
    modified_paths = sorted((candidate.PROMPT_PATH, candidate.STARTUP_PATH))
    if changed.splitlines() != [f" M {path}" for path in modified_paths]:
        raise StrixRuntimeQualificationError(
            "candidate source changes are not the two reviewed overlays"
        )
    prompt = _read_regular(source / candidate.PROMPT_PATH, candidate.MAX_SOURCE_FILE_BYTES)
    overlay = manifest.get("policy_overlay")
    if (
        not isinstance(overlay, dict)
        or any(
            overlay.get(key) != value
            for key, value in {
                "schema_version": "bluefire.strix-prompt-overlay.v1",
                "source_revision": candidate.UPSTREAM_COMMIT,
                "path": candidate.PROMPT_PATH,
                "upstream_sha256": REVIEWED_PROMPT_SHA256,
                "overlay_sha256": OVERLAY_SHA256,
                "patched_sha256": PATCHED_PROMPT_SHA256,
                "modified_upstream_build": True,
            }.items()
        )
        or _sha256(prompt) != PATCHED_PROMPT_SHA256
    ):
        raise StrixRuntimeQualificationError("candidate source prompt is not manifest-bound")
    startup = _read_regular(source / candidate.STARTUP_PATH, candidate.MAX_SOURCE_FILE_BYTES)
    startup_digest = _sha256(startup)
    startup_overlay = manifest.get("startup_overlay")
    if (
        not isinstance(startup_overlay, dict)
        or any(
            startup_overlay.get(key) != value
            for key, value in {
                "schema_version": "bluefire.strix-startup-overlay.v1",
                "source_revision": candidate.UPSTREAM_COMMIT,
                "path": candidate.STARTUP_PATH,
                "upstream_sha256": REVIEWED_STARTUP_SHA256,
                "overlay_sha256": STARTUP_OVERLAY_SHA256,
                "patched_sha256": PATCHED_STARTUP_SHA256,
                "modified_upstream_build": True,
            }.items()
        )
        or startup_digest != PATCHED_STARTUP_SHA256
    ):
        raise StrixRuntimeQualificationError("candidate startup overlay receipt drifted")
    source_archive = manifest.get("source_archive")
    wheel_inspection = manifest.get("wheel_inspection")
    if (
        not isinstance(source_archive, dict)
        or source_archive.get("modified_paths") != modified_paths
        or not isinstance(wheel_inspection, dict)
        or wheel_inspection.get("prompt_sha256") != _sha256(prompt)
        or wheel_inspection.get("startup_sha256") != startup_digest
    ):
        raise StrixRuntimeQualificationError("candidate startup inventory drifted")

    return {
        "manifest": manifest,
        "manifest_sha256": _sha256(manifest_payload),
        "checksums_sha256": _sha256(
            _read_regular(root / candidate.CHECKSUMS_NAME, candidate.MAX_OUTPUT_BYTES)
        ),
        "wheel_path": root / wheels[0],
        "wheel_identity": artifact_rows[wheels[0]],
        "prompt_sha256": _sha256(prompt),
        "startup_sha256": startup_digest,
        "modified_paths": modified_paths,
        "lock_sha256": upstream["lock_sha256"],
    }


def validate_hashed_requirements(payload: bytes) -> dict[str, int]:
    """Reject requirements that could resolve outside the frozen, hashed lock export."""

    if not payload or len(payload) > MAX_REQUIREMENTS_BYTES:
        raise StrixRuntimeQualificationError("requirements export is empty or oversized")
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise StrixRuntimeQualificationError("requirements export is not UTF-8") from exc
    logical: list[str] = []
    current = ""
    for raw in lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        continued = stripped.endswith("\\")
        fragment = stripped[:-1].strip() if continued else stripped
        current = f"{current} {fragment}".strip()
        if not continued:
            logical.append(re.sub(r"\s+", " ", current))
            current = ""
    if current:
        raise StrixRuntimeQualificationError("requirements export has an incomplete continuation")
    if not logical:
        raise StrixRuntimeQualificationError("requirements export has no packages")
    hashes = 0
    for line in logical:
        lowered = line.lower()
        if (
            line.startswith("-")
            or " @ " in line
            or "://" in line
            or "file:" in lowered
            or "git+" in lowered
            or "--index" in lowered
            or "--find-links" in lowered
            or "--trusted-host" in lowered
            or _REQUIREMENT.fullmatch(line) is None
        ):
            raise StrixRuntimeQualificationError("requirements export is not exact and hash-bound")
        hashes += line.count("--hash=sha256:")
    return {"requirements": len(logical), "hashes": hashes}


def _download_exact(url: str, destination: Path, sha256: str, size: int) -> FileIdentity:
    if not _SHA256.fullmatch(sha256) or size <= 0 or size > MAX_DOWNLOAD_BYTES:
        raise StrixRuntimeQualificationError("download identity is invalid")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/octet-stream",
            "Accept-Encoding": "identity",
            "User-Agent": "BlueFire-Strix-Qualification/1",
        },
    )
    try:
        with _urlopen_no_proxy(request, timeout=60) as response:
            final_url = response.geturl()
            if urllib.parse.urlsplit(final_url).scheme != "https":
                raise StrixRuntimeQualificationError("download redirected away from HTTPS")
            chunks: list[bytes] = []
            observed = 0
            while True:
                chunk = response.read(min(1024 * 1024, size + 1 - observed))
                if not chunk:
                    break
                chunks.append(chunk)
                observed += len(chunk)
                if observed > size:
                    raise StrixRuntimeQualificationError("download exceeded exact size")
    except StrixRuntimeQualificationError:
        raise
    except OSError as exc:
        raise StrixRuntimeQualificationError("exact download failed") from exc
    payload = b"".join(chunks)
    if len(payload) != size or _sha256(payload) != sha256:
        raise StrixRuntimeQualificationError("download did not match exact hash and size")
    _write_exclusive(destination, payload)
    return FileIdentity(destination.name, len(payload), sha256, "application/zip")


def _export_requirements(
    source: Path, destination: Path, environment: Mapping[str, str]
) -> dict[str, Any]:
    version = _run(["uv", "-V"], cwd=source, environment=environment)
    if version != f"uv {candidate.UV_VERSION}":
        raise StrixRuntimeQualificationError("uv version does not match candidate build")
    _run(
        [
            "uv",
            "export",
            "--frozen",
            "--no-dev",
            "--no-emit-project",
            "--format",
            "requirements-txt",
            "--output-file",
            str(destination),
        ],
        cwd=source,
        environment=environment,
    )
    payload = _read_regular(destination, MAX_REQUIREMENTS_BYTES)
    counts = validate_hashed_requirements(payload)
    uv_path = shutil.which("uv", path=environment["PATH"])
    if uv_path is None:
        raise StrixRuntimeQualificationError("uv executable cannot be identified")
    return {
        "version": version,
        "executable_sha256": _sha256(_read_regular(Path(uv_path), 128 * 1024 * 1024)),
        "requirements_sha256": _sha256(payload),
        **counts,
    }


def _safe_zip_member(name: str) -> PurePosixPath:
    value = PurePosixPath(name)
    if not name or value.is_absolute() or "\\" in name or ".." in value.parts:
        raise StrixRuntimeQualificationError("wheel contains an unsafe member path")
    return value


def _inspect_wheel(path: Path) -> dict[str, Any]:
    payload = _read_regular(path, MAX_DOWNLOAD_BYTES)
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            members = archive.infolist()
            if len(members) > 100_000:
                raise StrixRuntimeQualificationError("wheel has too many members")
            total = 0
            metadata_names: list[str] = []
            wheel_names: list[str] = []
            observed_members: set[str] = set()
            observed_casefold: set[str] = set()
            for member in members:
                _safe_zip_member(member.filename)
                if (
                    member.filename in observed_members
                    or member.filename.casefold() in observed_casefold
                ):
                    raise StrixRuntimeQualificationError("wheel member identity is ambiguous")
                observed_members.add(member.filename)
                observed_casefold.add(member.filename.casefold())
                mode = (member.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(mode)
                if member.flag_bits & 0x1 or file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise StrixRuntimeQualificationError(
                        "wheel contains encrypted or special content"
                    )
                total += member.file_size
                if total > MAX_DOWNLOAD_BYTES * 4:
                    raise StrixRuntimeQualificationError("wheel expanded content is oversized")
                if member.filename.endswith(".dist-info/METADATA"):
                    if member.file_size > 4 * 1024 * 1024:
                        raise StrixRuntimeQualificationError("wheel metadata is oversized")
                    metadata_names.append(member.filename)
                if member.filename.endswith(".dist-info/WHEEL"):
                    if member.file_size > 1024 * 1024:
                        raise StrixRuntimeQualificationError("wheel tag metadata is oversized")
                    wheel_names.append(member.filename)
            if len(metadata_names) != 1 or len(wheel_names) != 1:
                raise StrixRuntimeQualificationError("wheel metadata is ambiguous")
            metadata_payload = archive.read(metadata_names[0])
            wheel_payload = archive.read(wheel_names[0])
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        raise StrixRuntimeQualificationError("wheel is not a valid bounded archive") from exc
    metadata = BytesParser(policy=email_policy).parsebytes(metadata_payload)
    name = metadata.get("Name")
    version = metadata.get("Version")
    if not isinstance(name, str) or not isinstance(version, str):
        raise StrixRuntimeQualificationError("wheel metadata lacks name or version")
    if not _SAFE_NAME.fullmatch(name) or not _SAFE_NAME.fullmatch(version):
        raise StrixRuntimeQualificationError("wheel name or version is unsafe")
    stem = path.name[:-4]
    pieces = stem.split("-")
    if (
        len(pieces) < 5
        or _canonical_name(pieces[0]) != _canonical_name(name)
        or pieces[1].replace("_", "-").lower() != version.replace("_", "-").lower()
    ):
        raise StrixRuntimeQualificationError("wheel filename and metadata disagree")
    expected_tags = {
        f"{python_tag}-{abi_tag}-{platform_tag}"
        for python_tag in pieces[-3].split(".")
        for abi_tag in pieces[-2].split(".")
        for platform_tag in pieces[-1].split(".")
    }
    wheel_metadata = BytesParser(policy=email_policy).parsebytes(wheel_payload)
    if set(wheel_metadata.get_all("Tag", [])) != expected_tags:
        raise StrixRuntimeQualificationError("wheel filename and declared tags disagree")
    return {
        "filename": path.name,
        "size": len(payload),
        "sha256": _sha256(payload),
        "name": name,
        "normalized_name": _canonical_name(name),
        "version": version,
        "tags": pieces[-3:],
    }


def inventory_wheelhouse(wheelhouse: Path) -> dict[str, Any]:
    entries = list(wheelhouse.iterdir())
    if not entries or len(entries) > MAX_WHEEL_COUNT:
        raise StrixRuntimeQualificationError("wheelhouse count is empty or excessive")
    wheels: list[dict[str, Any]] = []
    names: set[str] = set()
    total = 0
    for path in sorted(entries, key=lambda value: value.name.casefold()):
        if path.suffix != ".whl" or path.name != path.name.casefold():
            raise StrixRuntimeQualificationError("wheelhouse contains a non-wheel or unstable name")
        receipt = _inspect_wheel(path)
        total += int(receipt["size"])
        normalized = str(receipt["normalized_name"])
        if normalized in names:
            raise StrixRuntimeQualificationError("wheelhouse contains duplicate distributions")
        names.add(normalized)
        wheels.append(receipt)
    if total > MAX_WHEELHOUSE_BYTES:
        raise StrixRuntimeQualificationError("wheelhouse exceeds its byte bound")
    return {"count": len(wheels), "bytes": total, "wheels": wheels}


def _python_executable(venv_root: Path) -> Path:
    if os.name == "nt":
        return venv_root / "Scripts" / "python.exe"
    return venv_root / "bin" / "python"


def _hash_executable(path: Path) -> dict[str, Any]:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise StrixRuntimeQualificationError("runtime interpreter cannot be resolved") from exc
    payload = _read_regular(resolved, 256 * 1024 * 1024)
    return {
        "logical_path": path.as_posix(),
        "resolved_path": resolved.as_posix(),
        "size": len(payload),
        "sha256": _sha256(payload),
    }


def _installed_distributions(site_packages: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for metadata_path in sorted(site_packages.glob("*.dist-info/METADATA")):
        payload = _read_regular(metadata_path, 4 * 1024 * 1024)
        metadata = BytesParser(policy=email_policy).parsebytes(payload)
        name = metadata.get("Name")
        version = metadata.get("Version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise StrixRuntimeQualificationError("installed distribution metadata is incomplete")
        normalized = _canonical_name(name)
        if normalized in result:
            raise StrixRuntimeQualificationError("installed distribution identity is ambiguous")
        result[normalized] = {
            "name": name,
            "version": version,
            "metadata_sha256": _sha256(payload),
            "dist_info": metadata_path.parent.name,
        }
    return result


def _inspect_installed_candidate(
    runtime_root: Path,
    runtime_python: Path,
    site_packages: Path,
    installed: Mapping[str, Mapping[str, Any]],
    prompt_sha256: str,
    startup_sha256: str,
) -> dict[str, Any]:
    row = installed.get("strix-agent")
    if row is None or row.get("version") != candidate.DECLARED_PACKAGE_VERSION:
        raise StrixRuntimeQualificationError("installed Strix distribution identity drifted")
    dist_info = site_packages / str(row["dist_info"])
    entry_payload = _read_regular(dist_info / "entry_points.txt", 1024 * 1024)
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(entry_payload.decode("utf-8"))
        entrypoint = parser.get("console_scripts", "strix")
    except (UnicodeDecodeError, configparser.Error) as exc:
        raise StrixRuntimeQualificationError("installed Strix entry point is invalid") from exc
    if entrypoint.strip() != "strix.interface.main:main":
        raise StrixRuntimeQualificationError("installed Strix entry point drifted")

    cli = runtime_root / ("Scripts/strix.exe" if os.name == "nt" else "bin/strix")
    cli_payload = _read_regular(cli, 8 * 1024 * 1024)
    if os.name != "nt" and (
        cli_payload.splitlines()[0] != f"#!{runtime_python}".encode("utf-8")
        or b"from strix.interface.main import main" not in cli_payload
    ):
        raise StrixRuntimeQualificationError("installed Strix launcher is not the expected script")
    if os.name != "nt" and not (cli.stat().st_mode & stat.S_IXUSR):
        raise StrixRuntimeQualificationError("installed Strix launcher is not executable")
    prompt = site_packages / candidate.PROMPT_PATH
    prompt_payload = _read_regular(prompt, candidate.MAX_SOURCE_FILE_BYTES)
    if _sha256(prompt_payload) != prompt_sha256:
        raise StrixRuntimeQualificationError("installed Strix prompt drifted")
    startup = site_packages / candidate.STARTUP_PATH
    startup_payload = _read_regular(startup, candidate.MAX_SOURCE_FILE_BYTES)
    if _sha256(startup_payload) != startup_sha256:
        raise StrixRuntimeQualificationError("installed Strix startup module drifted")

    record_payload = _read_regular(dist_info / "RECORD", 32 * 1024 * 1024)
    aggregate_rows: list[str] = []
    recorded_paths: set[str] = set()
    count = 0
    try:
        rows = csv.reader(io.StringIO(record_payload.decode("utf-8"), newline=""))
        for record in rows:
            if len(record) != 3:
                raise StrixRuntimeQualificationError("installed RECORD row is malformed")
            relative, encoded_hash, encoded_size = record
            if relative in recorded_paths:
                raise StrixRuntimeQualificationError("installed RECORD contains duplicate paths")
            recorded_paths.add(relative)
            target = (site_packages / relative).resolve(strict=True)
            if target != runtime_root and runtime_root not in target.parents:
                raise StrixRuntimeQualificationError("installed RECORD escapes runtime root")
            payload = _read_regular(target, MAX_DOWNLOAD_BYTES)
            digest = _sha256(payload)
            if encoded_hash:
                expected = base64.urlsafe_b64encode(bytes.fromhex(digest)).rstrip(b"=").decode()
                if encoded_hash != f"sha256={expected}":
                    raise StrixRuntimeQualificationError("installed RECORD hash mismatch")
            elif target != (dist_info / "RECORD").resolve(strict=True):
                raise StrixRuntimeQualificationError("installed RECORD omits a file hash")
            if encoded_size and encoded_size != str(len(payload)):
                raise StrixRuntimeQualificationError("installed RECORD size mismatch")
            if not encoded_size and target != (dist_info / "RECORD").resolve(strict=True):
                raise StrixRuntimeQualificationError("installed RECORD omits a file size")
            aggregate_rows.append(f"{relative}\0{len(payload)}\0{digest}\n")
            count += 1
    except (UnicodeDecodeError, csv.Error, OSError) as exc:
        raise StrixRuntimeQualificationError("installed Strix RECORD cannot be verified") from exc
    if not {candidate.PROMPT_PATH, candidate.STARTUP_PATH} <= recorded_paths:
        raise StrixRuntimeQualificationError("installed RECORD omits a reviewed source path")
    aggregate = "".join(sorted(aggregate_rows)).encode("utf-8")
    return {
        "distribution": dict(row),
        "entry_point": "strix = strix.interface.main:main",
        "cli": {
            "path": "Scripts/strix.exe" if os.name == "nt" else "bin/strix",
            "size": len(cli_payload),
            "sha256": _sha256(cli_payload),
        },
        "prompt": {
            "path": candidate.PROMPT_PATH,
            "size": len(prompt_payload),
            "sha256": _sha256(prompt_payload),
        },
        "startup": {
            "path": candidate.STARTUP_PATH,
            "size": len(startup_payload),
            "sha256": _sha256(startup_payload),
        },
        "package_record": {
            "record_sha256": _sha256(record_payload),
            "verified_files": count,
            "aggregate_sha256": _sha256(aggregate),
        },
        "imported": False,
        "executed": False,
    }


def _install_runtime(
    work: Path,
    output: Path,
    source: Path,
    candidate_identity: Mapping[str, Any],
    environment: Mapping[str, str],
) -> dict[str, Any]:
    if platform.python_version() != candidate.PYTHON_VERSION or platform.machine().lower() not in {
        "x86_64",
        "amd64",
    }:
        raise StrixRuntimeQualificationError("runtime closure requires CPython 3.12.14 on x86-64")
    requirements = output / REQUIREMENTS_NAME
    uv_receipt = _export_requirements(source, requirements, environment)

    pip_directory = work / "pip-tool"
    pip_directory.mkdir(mode=0o700)
    pip_wheel = pip_directory / PIP_WHEEL_NAME
    pip_artifact = _download_exact(PIP_WHEEL_URL, pip_wheel, PIP_WHEEL_SHA256, PIP_WHEEL_SIZE)
    pip_version = _run_pip(
        Path(sys.executable), pip_wheel, ["--version"], cwd=work, environment=environment
    )
    if not pip_version.startswith(f"pip {PIP_VERSION} "):
        raise StrixRuntimeQualificationError("hash-pinned pip wheel reports another version")

    wheelhouse = output / WHEELHOUSE_NAME
    wheelhouse.mkdir(mode=0o700)
    _run_pip(
        Path(sys.executable),
        pip_wheel,
        [
            "--isolated",
            "download",
            "--no-cache-dir",
            "--only-binary=:all:",
            "--require-hashes",
            "--no-deps",
            "--dest",
            str(wheelhouse),
            "--requirement",
            str(requirements),
        ],
        cwd=work,
        environment=environment,
    )
    wheelhouse_receipt = inventory_wheelhouse(wheelhouse)

    runtime_root = work / "runtime"
    venv.EnvBuilder(with_pip=False, symlinks=(os.name != "nt")).create(runtime_root)
    runtime_python = _python_executable(runtime_root)
    candidate_wheel = Path(str(candidate_identity["wheel_path"]))
    combined_requirements = work / "runtime-install-requirements.txt"
    requirement_payload = _read_regular(requirements, MAX_REQUIREMENTS_BYTES)
    wheel_identity = candidate_identity["wheel_identity"]
    combined_payload = requirement_payload
    if not combined_payload.endswith(b"\n"):
        combined_payload += b"\n"
    combined_payload += (
        f"strix-agent @ {candidate_wheel.as_uri()} --hash=sha256:{wheel_identity['sha256']}\n"
    ).encode("ascii")
    _write_exclusive(combined_requirements, combined_payload)
    _run_pip(
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
        cwd=work,
        environment=environment,
    )
    site_packages = (runtime_root / "lib/python3.12/site-packages").resolve(strict=True)
    if runtime_root.resolve() not in site_packages.parents:
        raise StrixRuntimeQualificationError("runtime site-packages escaped isolated root")
    installed = _installed_distributions(site_packages)
    expected = {
        str(row["normalized_name"]): str(row["version"]) for row in wheelhouse_receipt["wheels"]
    }
    expected["strix-agent"] = candidate.DECLARED_PACKAGE_VERSION
    observed = {name: str(row["version"]) for name, row in installed.items()}
    if observed != expected:
        raise StrixRuntimeQualificationError(
            "offline installed distributions differ from wheel closure"
        )
    strix = _inspect_installed_candidate(
        runtime_root,
        runtime_python,
        site_packages,
        installed,
        str(candidate_identity["prompt_sha256"]),
        str(candidate_identity["startup_sha256"]),
    )
    return {
        "platform": {"system": platform.system(), "machine": platform.machine()},
        "python": {
            "version": platform.python_version(),
            "build_executable_sha256": _sha256(
                _read_regular(Path(sys.executable).resolve(strict=True), 256 * 1024 * 1024)
            ),
            "runtime_interpreter": _hash_executable(runtime_python),
        },
        "uv": uv_receipt,
        "pip": {**pip_artifact.to_dict(), "version_output": pip_version},
        "requirements": {
            "path": REQUIREMENTS_NAME,
            "sha256": uv_receipt["requirements_sha256"],
            "frozen_lock_sha256": candidate_identity["lock_sha256"],
            "one_shot_install_manifest_sha256": _sha256(combined_payload),
            "candidate_wheel_sha256": wheel_identity["sha256"],
        },
        "wheelhouse": wheelhouse_receipt,
        "installed_distributions": [installed[name] for name in sorted(installed)],
        "strix": strix,
        "network_resolution_during_install": False,
        "all_dependency_payloads_are_wheels": True,
        "engine_imported": False,
        "engine_executed": False,
    }


def _validate_descriptor(value: Any, *, allowed_media: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StrixRuntimeQualificationError(f"{label} descriptor is not an object")
    digest = value.get("digest")
    size = value.get("size")
    media_type = value.get("mediaType")
    urls = value.get("urls")
    if urls not in (None, []):
        raise StrixRuntimeQualificationError(f"{label} descriptor has external URLs")
    if (
        not isinstance(digest, str)
        or _DIGEST.fullmatch(digest) is None
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or size > MAX_LAYER_BYTES
        or media_type not in allowed_media
    ):
        raise StrixRuntimeQualificationError(f"{label} descriptor identity is invalid")
    return {"digest": digest, "size": size, "media_type": media_type}


def resolve_oci_identity(fetch: RegistryFetch) -> dict[str, Any]:
    """Resolve the pinned OCI index to one exact linux/amd64 image without running it."""

    repository = "usestrix/strix-sandbox"
    index_digest = candidate.SANDBOX_IMAGE.rsplit("@", 1)[1]
    index_response = fetch(index_digest, ", ".join(sorted(INDEX_MEDIA_TYPES)))
    if _sha256(index_response.payload) != index_digest.removeprefix("sha256:"):
        raise StrixRuntimeQualificationError("OCI index payload does not match pinned digest")
    if index_response.headers.get("docker-content-digest") != index_digest:
        raise StrixRuntimeQualificationError("registry did not confirm OCI index digest")
    index = _strict_json(index_response.payload, label="OCI index")
    if (
        not isinstance(index, dict)
        or index.get("schemaVersion") != 2
        or index.get("mediaType") not in INDEX_MEDIA_TYPES
    ):
        raise StrixRuntimeQualificationError("pinned sandbox object is not an OCI index")
    manifests = index.get("manifests")
    if not isinstance(manifests, list) or len(manifests) > MAX_JSON_ITEMS:
        raise StrixRuntimeQualificationError("OCI index manifest set is invalid")
    matches: list[dict[str, Any]] = []
    for raw in manifests:
        if not isinstance(raw, dict):
            raise StrixRuntimeQualificationError("OCI index descriptor is invalid")
        platform_row = raw.get("platform")
        if not isinstance(platform_row, dict):
            continue
        if (
            platform_row.get("os") == "linux"
            and platform_row.get("architecture") == "amd64"
            and platform_row.get("variant") in (None, "")
        ):
            descriptor = _validate_descriptor(
                raw, allowed_media=MANIFEST_MEDIA_TYPES, label="platform child"
            )
            descriptor["platform"] = {"os": "linux", "architecture": "amd64"}
            matches.append(descriptor)
    if len(matches) != 1:
        raise StrixRuntimeQualificationError("OCI index lacks one unambiguous linux/amd64 child")
    child = matches[0]
    child_response = fetch(str(child["digest"]), ", ".join(sorted(MANIFEST_MEDIA_TYPES)))
    if len(child_response.payload) != child["size"] or _sha256(child_response.payload) != str(
        child["digest"]
    ).removeprefix("sha256:"):
        raise StrixRuntimeQualificationError("OCI child bytes differ from index descriptor")
    if child_response.headers.get("docker-content-digest") != child["digest"]:
        raise StrixRuntimeQualificationError("registry did not confirm OCI child digest")
    child_doc = _strict_json(child_response.payload, label="OCI child manifest")
    if (
        not isinstance(child_doc, dict)
        or child_doc.get("schemaVersion") != 2
        or child_doc.get("mediaType") not in MANIFEST_MEDIA_TYPES
    ):
        raise StrixRuntimeQualificationError("OCI child manifest media type is invalid")
    config = _validate_descriptor(
        child_doc.get("config"), allowed_media=CONFIG_MEDIA_TYPES, label="image config"
    )
    layers_value = child_doc.get("layers")
    if not isinstance(layers_value, list) or not layers_value or len(layers_value) > 1024:
        raise StrixRuntimeQualificationError("OCI layer inventory is empty or excessive")
    layers = [
        _validate_descriptor(value, allowed_media=LAYER_MEDIA_TYPES, label="image layer")
        for value in layers_value
    ]
    if sum(int(layer["size"]) for layer in layers) > MAX_IMAGE_BYTES:
        raise StrixRuntimeQualificationError("OCI layer inventory exceeds the image bound")
    config_response = fetch(str(config["digest"]), str(config["media_type"]))
    if len(config_response.payload) != config["size"] or _sha256(config_response.payload) != str(
        config["digest"]
    ).removeprefix("sha256:"):
        raise StrixRuntimeQualificationError("OCI config bytes differ from manifest descriptor")
    config_doc = _strict_json(config_response.payload, label="OCI image config")
    if not isinstance(config_doc, dict):
        raise StrixRuntimeQualificationError("OCI image config is not an object")
    rootfs = config_doc.get("rootfs")
    if (
        config_doc.get("os") != "linux"
        or config_doc.get("architecture") != "amd64"
        or not isinstance(rootfs, dict)
        or rootfs.get("type") != "layers"
        or not isinstance(rootfs.get("diff_ids"), list)
        or len(rootfs["diff_ids"]) != len(layers)
        or any(
            not isinstance(item, str) or _DIGEST.fullmatch(item) is None
            for item in rootfs["diff_ids"]
        )
    ):
        raise StrixRuntimeQualificationError("OCI config platform/rootfs identity is invalid")
    return {
        "repository": f"ghcr.io/{repository}",
        "pinned_index_reference": candidate.SANDBOX_IMAGE,
        "index": {
            "digest": index_digest,
            "size": len(index_response.payload),
            "media_type": index["mediaType"],
        },
        "platform_child": child,
        "config": {
            **config,
            "os": "linux",
            "architecture": "amd64",
            "rootfs_diff_ids": rootfs["diff_ids"],
        },
        "layers": layers,
        "layer_count": len(layers),
        "compressed_layer_bytes": sum(int(layer["size"]) for layer in layers),
        "resolver_downloaded_layer_blobs": False,
        "image_executed": False,
    }


def _registry_fetcher() -> RegistryFetch:
    # This is a public anonymous-token endpoint, not a credential or embedded secret.
    token_url = (  # nosec B105
        "https://ghcr.io/token?service=ghcr.io&scope=repository%3Ausestrix%2Fstrix-sandbox%3Apull"
    )
    request = urllib.request.Request(
        token_url,
        headers={"Accept": "application/json", "User-Agent": "BlueFire-Strix-Qualification/1"},
    )
    try:
        with _urlopen_no_proxy(request, timeout=60) as response:
            token_payload = response.read(128 * 1024 + 1)
    except OSError as exc:
        raise StrixRuntimeQualificationError("anonymous GHCR token request failed") from exc
    if len(token_payload) > 128 * 1024:
        raise StrixRuntimeQualificationError("anonymous GHCR token response is oversized")
    token_doc = _strict_json(token_payload, label="anonymous GHCR token response")
    token = token_doc.get("token") if isinstance(token_doc, dict) else None
    if not isinstance(token, str) or not token or len(token) > 16_384:
        raise StrixRuntimeQualificationError("anonymous GHCR token is missing")

    def fetch(digest: str, accept: str) -> RegistryResponse:
        if _DIGEST.fullmatch(digest) is None:
            raise StrixRuntimeQualificationError("refusing non-digest OCI lookup")
        kind = "blobs" if accept in CONFIG_MEDIA_TYPES else "manifests"
        url = f"https://ghcr.io/v2/usestrix/strix-sandbox/{kind}/{digest}"
        registry_request = urllib.request.Request(
            url,
            headers={
                "Accept": accept,
                "Accept-Encoding": "identity",
                "Authorization": f"Bearer {token}",
                "User-Agent": "BlueFire-Strix-Qualification/1",
            },
        )
        try:
            with _urlopen_no_proxy(registry_request, timeout=120) as response:
                payload = response.read(MAX_JSON_BYTES + 1)
                headers = {key.lower(): value for key, value in response.headers.items()}
        except OSError as exc:
            raise StrixRuntimeQualificationError("exact OCI object retrieval failed") from exc
        if len(payload) > MAX_JSON_BYTES:
            raise StrixRuntimeQualificationError("OCI metadata object is oversized")
        return RegistryResponse(payload, headers)

    return fetch


def extract_verified_syft(archive_path: Path, destination: Path) -> FileIdentity:
    payload = _read_regular(archive_path, MAX_DOWNLOAD_BYTES)
    if _sha256(payload) != SYFT_ARCHIVE_SHA256:
        raise StrixRuntimeQualificationError("Syft archive hash drifted")
    executable: bytes | None = None
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            members = archive.getmembers()
            if not members or len(members) > 128:
                raise StrixRuntimeQualificationError("Syft archive member count is invalid")
            for member in members:
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts or "\\" in member.name:
                    raise StrixRuntimeQualificationError("Syft archive contains an unsafe path")
                if not (member.isdir() or member.isreg()):
                    raise StrixRuntimeQualificationError(
                        "Syft archive contains links or special files"
                    )
                if member.size > MAX_DOWNLOAD_BYTES:
                    raise StrixRuntimeQualificationError("Syft archive member is oversized")
                if member.isreg() and path.name == "syft":
                    if executable is not None:
                        raise StrixRuntimeQualificationError("Syft archive executable is ambiguous")
                    handle = archive.extractfile(member)
                    if handle is None:
                        raise StrixRuntimeQualificationError("Syft executable cannot be read")
                    executable = handle.read(MAX_DOWNLOAD_BYTES + 1)
    except (OSError, tarfile.TarError) as exc:
        raise StrixRuntimeQualificationError("Syft archive is invalid") from exc
    if (
        executable is None
        or len(executable) > MAX_DOWNLOAD_BYTES
        or executable[:6] != b"\x7fELF\x02\x01"
        or int.from_bytes(executable[18:20], "little") != 62
    ):
        raise StrixRuntimeQualificationError("Syft executable is not Linux x86-64 ELF")
    _write_exclusive(destination, executable)
    destination.chmod(0o700)
    return FileIdentity(destination.name, len(executable), _sha256(executable), "application/x-elf")


def _download_bounded_hash(
    url: str,
    destination: Path,
    expected_sha256: str,
    maximum: int,
    media_type: str,
) -> FileIdentity:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/octet-stream",
            "Accept-Encoding": "identity",
            "User-Agent": "BlueFire-Strix-Qualification/1",
        },
    )
    try:
        with _urlopen_no_proxy(request, timeout=120) as response:
            if urllib.parse.urlsplit(response.geturl()).scheme != "https":
                raise StrixRuntimeQualificationError("tool download redirected away from HTTPS")
            payload = response.read(maximum + 1)
    except OSError as exc:
        raise StrixRuntimeQualificationError("Syft archive download failed") from exc
    if len(payload) > maximum or _sha256(payload) != expected_sha256:
        raise StrixRuntimeQualificationError("tool download did not match its reviewed checksum")
    _write_exclusive(destination, payload)
    return FileIdentity(destination.name, len(payload), _sha256(payload), media_type)


def _verify_syft_checksums(payload: bytes) -> None:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise StrixRuntimeQualificationError("Syft checksum file is not ASCII") from exc
    expected = f"{SYFT_ARCHIVE_SHA256}  {SYFT_ARCHIVE_NAME}"
    if lines.count(expected) != 1:
        raise StrixRuntimeQualificationError(
            "Syft checksum file does not bind the reviewed archive"
        )


def _notices_from_syft(syft_document: Mapping[str, Any], child_digest: str) -> dict[str, Any]:
    artifacts = syft_document.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) > MAX_NOTICE_PACKAGES:
        raise StrixRuntimeQualificationError("Syft package inventory is invalid")
    packages: list[dict[str, Any]] = []
    text_bytes = 0
    for item in artifacts:
        if not isinstance(item, dict):
            raise StrixRuntimeQualificationError("Syft package row is invalid")
        name = item.get("name")
        version = item.get("version")
        package_type = item.get("type")
        if (
            not isinstance(name, str)
            or not isinstance(version, str)
            or not isinstance(package_type, str)
        ):
            raise StrixRuntimeQualificationError("Syft package identity is incomplete")
        licenses_value = item.get("licenses", [])
        if (
            not isinstance(licenses_value, list)
            or len(licenses_value) > MAX_NOTICE_LICENSES_PER_PACKAGE
        ):
            raise StrixRuntimeQualificationError("Syft package licenses are invalid")
        licenses: list[str] = []
        for license_row in licenses_value:
            if isinstance(license_row, str):
                value = license_row
            elif isinstance(license_row, dict):
                candidate_value = license_row.get("spdxExpression") or license_row.get("value")
                value = candidate_value if isinstance(candidate_value, str) else "unreported"
            else:
                value = "unreported"
            licenses.append(value[:500])
        package = {
            "name": name[:500],
            "version": version[:500],
            "type": package_type[:100],
            "reported_licenses": sorted(set(licenses)),
        }
        text_bytes += len(_canonical_json(package))
        if text_bytes > MAX_NOTICE_TEXT_BYTES:
            raise StrixRuntimeQualificationError("Syft notices inventory is oversized")
        packages.append(package)
    report = {
        "schema": "bluefire.strix-sandbox-notices-review.v1",
        "platform_child_digest": child_digest,
        "packages": sorted(
            packages, key=lambda row: (row["name"].casefold(), row["version"], row["type"])
        ),
        "package_count": len(packages),
        "notices_complete": False,
        "license_review_complete": False,
        "redistribution_review_complete": False,
        "unresolved": [
            "Package metadata is not a legal or redistribution review.",
            "Image-layer NOTICE and license-file completeness has not been independently reviewed.",
            "The sandbox image is not represented as wholly Apache-2.0.",
        ],
    }
    if len(_canonical_json(report)) > MAX_NOTICE_TEXT_BYTES + 1024 * 1024:
        raise StrixRuntimeQualificationError("Syft notices report is oversized")
    return report


def validate_syft_reports(
    syft_payload: bytes, cdx_payload: bytes, child_digest: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Bind bounded Syft outputs to the already resolved platform child."""

    if _DIGEST.fullmatch(child_digest) is None:
        raise StrixRuntimeQualificationError("Syft platform child digest is invalid")
    syft_doc = _strict_json(syft_payload, label="Syft image SBOM")
    cdx_doc = _strict_json(cdx_payload, label="CycloneDX image SBOM")
    if not isinstance(syft_doc, dict) or not isinstance(cdx_doc, dict):
        raise StrixRuntimeQualificationError("image SBOM root is invalid")
    source = syft_doc.get("source")
    artifacts = syft_doc.get("artifacts")
    source_metadata = source.get("metadata") if isinstance(source, dict) else None
    if (
        not isinstance(source, dict)
        or source.get("type") != "image"
        or not isinstance(source_metadata, dict)
        or source_metadata.get("manifestDigest") != child_digest
        or not isinstance(artifacts, list)
        or len(artifacts) > MAX_NOTICE_PACKAGES
        or cdx_doc.get("bomFormat") != "CycloneDX"
    ):
        raise StrixRuntimeQualificationError("image SBOM is not bound to the platform child")
    components = cdx_doc.get("components", [])
    if not isinstance(components, list) or len(components) > MAX_JSON_ITEMS:
        raise StrixRuntimeQualificationError("CycloneDX component inventory is invalid")
    return (
        syft_doc,
        cdx_doc,
        {
            "syft_json_sha256": _sha256(syft_payload),
            "cyclonedx_json_sha256": _sha256(cdx_payload),
            "package_count": len(artifacts),
            "component_count": len(components),
            "platform_child_digest": child_digest,
        },
    )


def inventory_image_with_syft(
    work: Path,
    output: Path,
    environment: Mapping[str, str],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    inventory = resolve_oci_identity(_registry_fetcher())
    _write_exclusive(output / OCI_INVENTORY_NAME, _canonical_json(inventory) + b"\n")
    checksums_path = work / SYFT_CHECKSUMS_NAME
    checksums_identity = _download_bounded_hash(
        SYFT_CHECKSUMS_URL,
        checksums_path,
        SYFT_CHECKSUMS_SHA256,
        1024 * 1024,
        "text/plain",
    )
    _verify_syft_checksums(_read_regular(checksums_path, 1024 * 1024))
    archive_path = work / SYFT_ARCHIVE_NAME
    archive_identity = _download_bounded_hash(
        SYFT_ARCHIVE_URL,
        archive_path,
        SYFT_ARCHIVE_SHA256,
        128 * 1024 * 1024,
        "application/gzip",
    )
    syft_path = work / "syft"
    executable_identity = extract_verified_syft(archive_path, syft_path)
    version_output = _run([str(syft_path), "version"], cwd=work, environment=environment)
    if re.search(r"\b1\.56\.0\b", version_output) is None:
        raise StrixRuntimeQualificationError("reviewed Syft binary reports another version")
    child_digest = str(inventory["platform_child"]["digest"])
    exact_image = f"ghcr.io/usestrix/strix-sandbox@{child_digest}"
    syft_path_output = output / SYFT_SBOM_NAME
    cdx_path_output = output / CYCLONEDX_SBOM_NAME
    _run(
        [
            str(syft_path),
            "scan",
            exact_image,
            "--from",
            "registry",
            "--platform",
            "linux/amd64",
            "-o",
            f"syft-json={syft_path_output}",
            "-o",
            f"cyclonedx-json={cdx_path_output}",
        ],
        cwd=work,
        environment=environment,
    )
    syft_payload = _read_regular(syft_path_output, MAX_JSON_BYTES)
    cdx_payload = _read_regular(cdx_path_output, MAX_JSON_BYTES)
    syft_doc, _cdx_doc, sbom = validate_syft_reports(syft_payload, cdx_payload, child_digest)
    notices = _notices_from_syft(syft_doc, child_digest)
    _write_exclusive(output / NOTICES_REVIEW_NAME, _canonical_json(notices) + b"\n")
    tool = {
        "name": "syft",
        "version": SYFT_VERSION,
        "archive": archive_identity.to_dict(),
        "archive_url": SYFT_ARCHIVE_URL,
        "official_checksums": checksums_identity.to_dict(),
        "official_checksums_url": SYFT_CHECKSUMS_URL,
        "executable": executable_identity.to_dict(),
        "version_output": version_output,
        "source": exact_image,
        "source_mode": "registry",
        "platform": "linux/amd64",
        "registry_layers_read_for_inventory": True,
        "container_executed": False,
    }
    return inventory, tool, {"sbom": sbom, "notices": notices}


def _media_type(path: Path) -> str:
    if path.suffix == ".whl":
        return "application/zip"
    if path.suffix == ".json":
        return "application/json"
    if path.suffix == ".txt" or path.name == CHECKSUMS_NAME:
        return "text/plain"
    return "application/octet-stream"


def _output_artifacts(output: Path, *, include_manifest: bool) -> list[FileIdentity]:
    result: list[FileIdentity] = []
    total = 0
    for path in sorted(output.rglob("*"), key=lambda value: value.as_posix()):
        if path.is_symlink():
            raise StrixRuntimeQualificationError("qualification output contains a link")
        if path.is_dir():
            continue
        relative = path.relative_to(output).as_posix()
        if relative == CHECKSUMS_NAME or (
            relative == QUALIFICATION_MANIFEST_NAME and not include_manifest
        ):
            continue
        payload = _read_regular(path, MAX_DOWNLOAD_BYTES)
        total += len(payload)
        result.append(FileIdentity(relative, len(payload), _sha256(payload), _media_type(path)))
    if total > MAX_OUTPUT_BYTES:
        raise StrixRuntimeQualificationError("qualification output exceeds its byte bound")
    return result


def prepare_runtime_candidate(
    candidate_root: Path,
    source_root: Path,
    work_root: Path,
    output_root: Path,
    *,
    bluefire_source_revision: str,
    inherited_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Prepare exact offline artifacts while leaving runtime qualification false."""

    work = work_root.resolve(strict=False)
    output = output_root.resolve(strict=False)
    source = source_root.resolve(strict=True)
    candidate_path = candidate_root.resolve(strict=True)
    roots = (work, output, source, candidate_path)
    if len(set(roots)) != len(roots) or any(
        first in second.parents or second in first.parents
        for index, first in enumerate(roots)
        for second in roots[index + 1 :]
    ):
        raise StrixRuntimeQualificationError("qualification roots must be separate")
    _require_new_directory(work)
    _require_new_directory(output)
    environment = _sanitized_environment(work, inherited_environment or os.environ)
    git_path_value = shutil.which("git", path=environment["PATH"])
    if git_path_value is None:
        raise StrixRuntimeQualificationError("Git executable cannot be identified")
    git_path = Path(git_path_value).resolve(strict=True)
    git_tool = {
        "version": _run(["git", "--version"], cwd=source, environment=environment),
        "executable_sha256": _sha256(_read_regular(git_path, 256 * 1024 * 1024)),
    }
    candidate_identity = validate_candidate(
        candidate_path, source, bluefire_source_revision, environment
    )
    runtime = _install_runtime(work, output, source, candidate_identity, environment)
    _write_exclusive(output / RUNTIME_RECEIPT_NAME, _canonical_json(runtime) + b"\n")
    oci, syft_tool, image_reports = inventory_image_with_syft(work, output, environment)

    artifacts = _output_artifacts(output, include_manifest=False)
    manifest: dict[str, Any] = {
        "schema": "bluefire.strix-runtime-qualification-preparation.v1",
        "status": "prepared-not-runtime-qualified",
        "bluefire_source_revision": bluefire_source_revision,
        "candidate": {
            "manifest_sha256": candidate_identity["manifest_sha256"],
            "checksums_sha256": candidate_identity["checksums_sha256"],
            "wheel": candidate_identity["wheel_identity"],
            "upstream_commit": candidate.UPSTREAM_COMMIT,
            "upstream_tree": candidate.UPSTREAM_TREE,
            "policy_prompt_sha256": candidate_identity["prompt_sha256"],
            "startup_main_sha256": candidate_identity["startup_sha256"],
            "modified_paths": candidate_identity["modified_paths"],
            "frozen_lock_sha256": candidate_identity["lock_sha256"],
        },
        "runner": {
            "os": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "image_os": os.environ.get("ImageOS", "unreported")[:100],
            "image_version": os.environ.get("ImageVersion", "unreported")[:100],
        },
        "actions": dict(ACTION_IDENTITIES),
        "source_validation_tool": {"name": "git", **git_tool},
        "python_runtime": runtime,
        "oci": oci,
        "inventory_tool": syft_tool,
        "image_reports": image_reports,
        "artifacts": [item.to_dict() for item in artifacts],
        "limits": {
            "wheel_count": MAX_WHEEL_COUNT,
            "wheelhouse_bytes": MAX_WHEELHOUSE_BYTES,
            "output_bytes": MAX_OUTPUT_BYTES,
            "image_compressed_bytes": MAX_IMAGE_BYTES,
            "command_timeout_seconds": COMMAND_TIMEOUT_SECONDS,
        },
        "execution": {
            "strix_imported": False,
            "strix_cli": False,
            "strix_sidecar": False,
            "container": False,
            "target": False,
            "model": False,
        },
        "qualification": {
            "runtime_qualified": False,
            "reproducibility_proven": False,
            "containment_proven": False,
            "lifecycle_proven": False,
            "license_review_complete": False,
            "redistribution_review": strix_redistribution_review(),
            "blocking_reasons": [
                "Independent review of this preparation has not completed.",
                "A second clean build has not established artifact reproducibility.",
                "Containment, lifecycle, cancellation, and cleanup have not been exercised.",
                "Go TUI, bundled viewer assets, complete runtime wheels, and OCI rights remain unreviewed.",
                "No Strix, target, sandbox container, or model execution was performed.",
            ],
        },
    }
    manifest_payload = _canonical_json(manifest) + b"\n"
    _write_exclusive(output / QUALIFICATION_MANIFEST_NAME, manifest_payload)
    checksum_items = _output_artifacts(output, include_manifest=True)
    checksum_payload = "".join(
        f"{item.sha256}  {item.path}\n" for item in sorted(checksum_items, key=lambda row: row.path)
    ).encode("ascii")
    _write_exclusive(output / CHECKSUMS_NAME, checksum_payload)
    expected = {item.path for item in checksum_items} | {CHECKSUMS_NAME}
    observed = {path.relative_to(output).as_posix() for path in output.rglob("*") if path.is_file()}
    if observed != expected:
        raise StrixRuntimeQualificationError("final qualification output set drifted")
    return manifest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--bluefire-source-revision", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        manifest = prepare_runtime_candidate(
            arguments.candidate_root,
            arguments.source_root,
            arguments.work_root,
            arguments.output_root,
            bluefire_source_revision=arguments.bluefire_source_revision,
        )
    except StrixRuntimeQualificationError as exc:
        print(f"Strix runtime qualification preparation refused: {exc}", file=sys.stderr)
        return 1
    print(
        "Prepared exact offline Strix runtime artifacts for "
        f"{manifest['candidate']['upstream_commit']}; runtime qualification remains false."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
