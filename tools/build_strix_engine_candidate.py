"""Build a provenance-bound, non-executed Strix engine candidate.

This tool fetches one reviewed upstream Git object, validates its identity and
declared license, applies BlueFire's reviewed prompt and startup corrections, and
builds immutable candidate artifacts from the frozen upstream lock. It never
launches Strix, its sidecar, a sandbox image, a target, or a model.
"""

from __future__ import annotations

import argparse
import base64
import csv
import email.policy
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
import zipfile
from dataclasses import dataclass
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from bluefire.strix_policy_overlay import (
    PATCHED_PROMPT_SHA256,
    REVIEWED_PROMPT_SHA256,
    REVIEWED_SOURCE_REVISION,
    apply_policy_overlay,
)
from bluefire.strix_redistribution_review import strix_redistribution_review
from bluefire.strix_startup_overlay import (
    PATCHED_STARTUP_SHA256,
    REVIEWED_STARTUP_SHA256,
    apply_startup_overlay,
)
from bluefire.strix_startup_overlay import (
    REVIEWED_SOURCE_REVISION as REVIEWED_STARTUP_SOURCE_REVISION,
)

UPSTREAM_REPOSITORY = "https://github.com/usestrix/strix.git"
UPSTREAM_COMMIT = "6b7ae2ebe4d47037a927aade23265ff4e4f27e84"  # pragma: allowlist secret
UPSTREAM_TREE = "23c06e4a0e58bdf3b4979863d7623230e4091332"  # pragma: allowlist secret
DECLARED_PACKAGE_VERSION = "1.7.0"
PUBLISHED_RELEASE_COMMIT = "55bc07991aacb1c26a81b43e7ca53148730d2019"  # pragma: allowlist secret
UPSTREAM_LICENSE = "Apache-2.0"
UPSTREAM_PYTHON_REQUIREMENT = ">=3.12"
PROMPT_PATH = "strix/agents/prompts/system_prompt.jinja"
STARTUP_PATH = "strix/interface/main.py"

# The reviewed source selects sandbox 1.3.1. A tag is not an immutable
# identity, so the later runtime may use only this OCI index digest and must
# additionally bind the platform child manifest before execution.
SANDBOX_IMAGE = (
    "ghcr.io/usestrix/strix-sandbox@"
    "sha256:78df914f3029464c9d00580f531ec51025c251c422ec3b09c3f19c5fa6d80c30"
)
UV_VERSION = "0.13.6"
UV_RELEASE_COMMIT = "329bf9448afd9f9088d14a4d57fbc61eb454f117"  # pragma: allowlist secret -- public uv release commit
UV_RELEASE_DATE = "2026-10-26"
UV_TARGET_TRIPLE = "x86_64-unknown-linux-gnu"
UV_VERSION_OUTPUT = f"uv {UV_VERSION} (329bf9448 {UV_RELEASE_DATE} {UV_TARGET_TRIPLE})"
GO_VERSION = "1.24.10"
PYTHON_VERSION = "3.12.14"

MAX_OUTPUT_BYTES = 256 * 1024 * 1024
MAX_SOURCE_BYTES = 192 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 32 * 1024 * 1024
MAX_WHEEL_BYTES = 160 * 1024 * 1024
MAX_WHEEL_MEMBER_BYTES = 64 * 1024 * 1024
MAX_SBOM_BYTES = 24 * 1024 * 1024
MAX_METADATA_BYTES = 2 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 15 * 60
SOURCE_DATE_EPOCH = "315532800"  # 1980-01-01, valid for ZIP timestamps.

SOURCE_ARCHIVE_NAME = "strix-agent-1.7.0-bluefire-src.tar"
LICENSE_NAME = "LICENSE.strix-apache-2.0.txt"
SBOM_NAME = "strix-agent-1.7.0-dependencies.cdx.json"
MANIFEST_NAME = "strix-engine-candidate-manifest.json"
CHECKSUMS_NAME = "SHA256SUMS"

EXPECTED_BLOBS: Mapping[str, str] = {
    "pyproject.toml": "512d0e5cb7f8af68a6fbd9eed9ca36d15439ef68",  # pragma: allowlist secret
    "uv.lock": "aa7a27ef224c85aad82e9bb9a2e29a96a5a6a763",  # pragma: allowlist secret
    "LICENSE": "65c4e8f58a00552cc29f6bd1dcaf1c4ef10012b8",  # pragma: allowlist secret
    PROMPT_PATH: "fd09d0774f48c85b056104e1eb5e265e8b3c756b",  # pragma: allowlist secret
    STARTUP_PATH: "846a35da9878a299905a774247e6b537d07d81ce",  # pragma: allowlist secret
    "scripts/tui_sidecar_hook.py": "01de6fdc1a63a1ee4787e8a27a1d6d17ef147802",  # pragma: allowlist secret
    "strix/interface/tui/go.mod": "1ff6ec350e8a6dc3a03cb08015ba9eed56bee2db",  # pragma: allowlist secret
    "strix/interface/tui/go.sum": "f255aec1de72d711f90f22d150648a45ee33bd7b",  # pragma: allowlist secret
}

_REVISION = re.compile(r"^[0-9a-f]{40}$")
_SAFE_RUNNER_VALUE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
_REQUIRED_LOCKED_COMPONENTS: Mapping[str, str] = {
    "caido-sdk-client": "0.2.0",
    "docker": "7.1.0",
    "litellm": "1.101.0",
    "openai": "2.53.0",
    "openai-agents": "0.19.0",
    "pydantic": "2.13.4",
}
_BUILD_BACKEND_WHEELS: Mapping[str, Mapping[str, str | bool]] = {
    "hatchling": {
        "version": "1.32.4",
        "url": "https://files.pythonhosted.org/packages/5f/80/91f51f439c05d4ec4623c22928ce16a938d6d793bf709477830823497859/hatchling-1.32.4-py3-none-any.whl",
        "sha256": "08ecf7548fb48205e7f213d70c71e67b8271b7242093dc3f1da578b42c734a2c",  # pragma: allowlist secret
        "version_cross_checked_in_upstream_lock": False,
    },
    "packaging": {
        "version": "26.2",
        "url": "https://files.pythonhosted.org/packages/df/b2/87e62e8c3e2f4b32e5fe99e0b86d576da1312593b39f47d8ceef365e95ed/packaging-26.2-py3-none-any.whl",
        "sha256": "5fc45236b9446107ff2415ce77c807cee2862cb6fac22b8a73826d0693b0980e",  # pragma: allowlist secret
        "version_cross_checked_in_upstream_lock": True,
    },
    "pathspec": {
        "version": "1.1.1",
        "url": "https://files.pythonhosted.org/packages/f1/d9/7fb5aa316bc299258e68c73ba3bddbc499654a07f151cba08f6153988714/pathspec-1.1.1-py3-none-any.whl",
        "sha256": "a00ce642f577bf7f473932318056212bc4f8bfdf53128c78bbd5af0b9b20b189",  # pragma: allowlist secret
        "version_cross_checked_in_upstream_lock": True,
    },
    "pluggy": {
        "version": "1.6.0",
        "url": "https://files.pythonhosted.org/packages/54/20/4d324d65cc6d9205fabedc306948156824eb9f0ee1633355a8f7ec5c66bf/pluggy-1.6.0-py3-none-any.whl",
        "sha256": "e920276dd6813095e9377c0bc5566d94c932c33b27a3e3945d8389c374dd4746",  # pragma: allowlist secret
        "version_cross_checked_in_upstream_lock": True,
    },
    "tomlkit": {
        "version": "0.15.2",
        "url": "https://files.pythonhosted.org/packages/da/46/7d84138a60a8bd796825b2d38ebe92d0d16501ca57d501b7c5d677401bbc/tomlkit-0.15.2-py3-none-any.whl",
        "sha256": "05562412163a3037b94497385fb7f9204c637bc605af7a48199e41cf2272f437",  # pragma: allowlist secret
        "version_cross_checked_in_upstream_lock": False,
    },
    "trove-classifiers": {
        "version": "2026.9.21.13",
        "url": "https://files.pythonhosted.org/packages/30/81/0da8afb52a71d0a4f2bd3152357b1a441e393b286374802b9d3addab4ab5/trove_classifiers-2026.9.21.13-py3-none-any.whl",
        "sha256": "8b1ff4f9c191b1040b71c37f1e445ab99732911e3cd91de52838453a854d7a17",  # pragma: allowlist secret
        "version_cross_checked_in_upstream_lock": False,
    },
}


class StrixCandidateBuildError(RuntimeError):
    """A candidate identity, input, build, or artifact failed closed."""


@dataclass(frozen=True, slots=True)
class ArtifactIdentity:
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


def _is_reparse(details: os.stat_result) -> bool:
    return bool(
        int(getattr(details, "st_file_attributes", 0))
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_regular(path: Path, maximum: int, *, allow_empty: bool = False) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise StrixCandidateBuildError(
            f"required regular file is unavailable: {path.name}"
        ) from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or _is_reparse(before)
        or before.st_nlink != 1
        or before.st_size > maximum
        or (before.st_size == 0 and not allow_empty)
    ):
        raise StrixCandidateBuildError(
            f"file is not a bounded standalone regular file: {path.name}"
        )
    try:
        payload = path.read_bytes()
        after = path.lstat()
    except OSError as exc:
        raise StrixCandidateBuildError(f"file changed or became unavailable: {path.name}") from exc
    before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if (
        len(payload) != before.st_size
        or before_identity != after_identity
        or not stat.S_ISREG(after.st_mode)
        or _is_reparse(after)
        or after.st_nlink != 1
    ):
        raise StrixCandidateBuildError(f"file changed while being read: {path.name}")
    return payload


def _artifact(path: Path, media_type: str, maximum: int) -> ArtifactIdentity:
    payload = _read_regular(path, maximum)
    return ArtifactIdentity(
        path=path.name,
        size=len(payload),
        sha256=_sha256(payload),
        media_type=media_type,
    )


def _run(
    arguments: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout: int = COMMAND_TIMEOUT_SECONDS,
) -> str:
    if not arguments or not all(isinstance(item, str) and item for item in arguments):
        raise StrixCandidateBuildError("refusing an empty or malformed build command")
    try:
        completed = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv; no shell.
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
        raise StrixCandidateBuildError(f"candidate command failed to run: {arguments[0]}") from exc
    if completed.returncode != 0:
        # Command output can contain untrusted upstream text. Keep the public
        # failure concise instead of copying it into logs or the manifest.
        raise StrixCandidateBuildError(
            f"candidate command returned {completed.returncode}: {arguments[0]}"
        )
    return completed.stdout.rstrip("\r\n")


def build_sanitized_environment(work_root: Path, inherited: Mapping[str, str]) -> dict[str, str]:
    """Return the complete, credential-free environment for upstream processes."""

    path_value = inherited.get("PATH", "")
    if not path_value:
        raise StrixCandidateBuildError("PATH is required to locate reviewed build tools")
    environment: dict[str, str] = {"PATH": path_value}
    for name in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"):
        value = inherited.get(name)
        if value:
            environment[name] = value

    isolated_home = work_root / "home"
    temporary = work_root / "tmp"
    go_cache = work_root / "cache" / "go-build"
    go_modules = work_root / "cache" / "go-modules"
    uv_cache = work_root / "cache" / "uv"
    for directory in (isolated_home, temporary, go_cache, go_modules, uv_cache):
        directory.mkdir(parents=True, mode=0o700, exist_ok=False)

    null_device = "NUL" if os.name == "nt" else "/dev/null"
    bluefire_repository = Path(__file__).resolve().parents[1]
    environment.update(
        {
            "HOME": str(isolated_home),
            "TMPDIR": str(temporary),
            "TMP": str(temporary),
            "TEMP": str(temporary),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PIP_CONFIG_FILE": null_device,
            "UV_NO_CONFIG": "1",
            "UV_NO_PROGRESS": "1",
            "UV_LINK_MODE": "copy",
            "UV_CACHE_DIR": str(uv_cache),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": null_device,
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "safe.directory",
            "GIT_CONFIG_VALUE_0": str(bluefire_repository),
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": null_device,
            "GCM_INTERACTIVE": "never",
            "GIT_LFS_SKIP_SMUDGE": "1",
            "CGO_ENABLED": "0",
            "GOTOOLCHAIN": "local",
            "GOPROXY": "https://proxy.golang.org",
            "GOSUMDB": "sum.golang.org",
            "GONOSUMDB": "",
            "GOVCS": "*:off",
            "GOFLAGS": "-mod=readonly -buildvcs=false",
            "GOCACHE": str(go_cache),
            "GOMODCACHE": str(go_modules),
            "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH,
        }
    )
    return environment


def clone_reviewed_source(source: Path, environment: Mapping[str, str]) -> None:
    source.mkdir(mode=0o700, parents=False, exist_ok=False)
    _run(["git", "init", "--quiet"], cwd=source, environment=environment)
    _run(
        ["git", "config", "remote.origin.url", UPSTREAM_REPOSITORY],
        cwd=source,
        environment=environment,
    )
    _run(["git", "config", "core.autocrlf", "false"], cwd=source, environment=environment)
    _run(["git", "config", "core.hooksPath", os.devnull], cwd=source, environment=environment)
    _run(["git", "config", "submodule.recurse", "false"], cwd=source, environment=environment)
    _run(
        [
            "git",
            "-c",
            "credential.helper=",
            "-c",
            "filter.lfs.smudge=",
            "-c",
            "filter.lfs.required=false",
            "fetch",
            "--quiet",
            "--no-tags",
            "--depth=1",
            "origin",
            UPSTREAM_COMMIT,
        ],
        cwd=source,
        environment=environment,
    )
    _run(
        ["git", "-c", "core.autocrlf=false", "checkout", "--quiet", "--detach", "FETCH_HEAD"],
        cwd=source,
        environment=environment,
    )


def _tracked_source_inventory(
    source: Path, environment: Mapping[str, str]
) -> list[tuple[str, str, str]]:
    listing = _run(
        ["git", "-c", "core.quotepath=false", "ls-tree", "-r", "--full-tree", "HEAD"],
        cwd=source,
        environment=environment,
    )
    inventory: list[tuple[str, str, str]] = []
    for line in listing.splitlines():
        try:
            metadata, path = line.split("\t", 1)
            mode, object_type, object_id = metadata.split(" ", 2)
        except ValueError as exc:
            raise StrixCandidateBuildError("reviewed Git tree inventory is malformed") from exc
        if object_type != "blob" or mode not in {"100644", "100755"}:
            raise StrixCandidateBuildError(
                "reviewed Git tree contains a link, submodule, or special mode"
            )
        pure = PurePosixPath(path)
        if (
            not path
            or "\\" in path
            or pure.is_absolute()
            or any(part in {"", ".", ".."} for part in pure.parts)
        ):
            raise StrixCandidateBuildError("reviewed Git tree contains an unsafe path")
        inventory.append((path, mode, object_id))
    if not inventory or len({item[0] for item in inventory}) != len(inventory):
        raise StrixCandidateBuildError("reviewed Git tree inventory is empty or ambiguous")
    inventory.sort(key=lambda item: item[0])
    return inventory


def _validate_bluefire_checkout(
    repository: Path,
    expected_revision: str,
    environment: Mapping[str, str],
) -> dict[str, Any]:
    commit = _run(
        ["git", "rev-parse", "--verify", "HEAD^{commit}"],
        cwd=repository,
        environment=environment,
    )
    tree = _run(
        ["git", "rev-parse", "--verify", "HEAD^{tree}"],
        cwd=repository,
        environment=environment,
    )
    dirty = _run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=repository,
        environment=environment,
    )
    if commit != expected_revision:
        raise StrixCandidateBuildError("supplied BlueFire revision does not match checkout HEAD")
    if dirty:
        raise StrixCandidateBuildError("BlueFire checkout is not clean at candidate build time")
    reviewed_paths = (
        "tools/build_strix_engine_candidate.py",
        ".github/workflows/strix-engine-candidate.yml",
        "bluefire/strix_policy_overlay.py",
        "bluefire/data/strix_prompt_policy_overlay.txt",
        "bluefire/strix_startup_overlay.py",
    )
    files: dict[str, dict[str, str]] = {}
    for relative in reviewed_paths:
        blob = _run(
            ["git", "rev-parse", "--verify", f"HEAD:{relative}"],
            cwd=repository,
            environment=environment,
        )
        payload = _read_regular(repository / relative, MAX_SOURCE_FILE_BYTES)
        working_blob = _run(
            ["git", "hash-object", "--no-filters", relative],
            cwd=repository,
            environment=environment,
        )
        if working_blob != blob:
            raise StrixCandidateBuildError(
                f"BlueFire candidate input differs from HEAD: {relative}"
            )
        files[relative] = {"git_blob": blob, "sha256": _sha256(payload)}
    return {"commit": commit, "tree": tree, "files": files}


def validate_source_checkout(source: Path, environment: Mapping[str, str]) -> dict[str, Any]:
    remote = _run(["git", "remote", "get-url", "origin"], cwd=source, environment=environment)
    commit = _run(
        ["git", "rev-parse", "--verify", "HEAD^{commit}"], cwd=source, environment=environment
    )
    tree = _run(
        ["git", "rev-parse", "--verify", "HEAD^{tree}"], cwd=source, environment=environment
    )
    dirty = _run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=source,
        environment=environment,
    )
    if remote != UPSTREAM_REPOSITORY:
        raise StrixCandidateBuildError("upstream repository identity does not match the review")
    if (
        commit != UPSTREAM_COMMIT
        or commit != REVIEWED_SOURCE_REVISION
        or commit != REVIEWED_STARTUP_SOURCE_REVISION
    ):
        raise StrixCandidateBuildError("upstream source commit does not match the review")
    if tree != UPSTREAM_TREE:
        raise StrixCandidateBuildError("upstream source tree does not match the review")
    if dirty:
        raise StrixCandidateBuildError("reviewed source checkout is not clean")

    inventory = _tracked_source_inventory(source, environment)
    inventory_blobs = {path: object_id for path, _mode, object_id in inventory}

    observed_blobs: dict[str, str] = {}
    for relative_path, expected_blob in EXPECTED_BLOBS.items():
        observed = _run(
            ["git", "rev-parse", "--verify", f"HEAD:{relative_path}"],
            cwd=source,
            environment=environment,
        )
        if observed != expected_blob or inventory_blobs.get(relative_path) != expected_blob:
            raise StrixCandidateBuildError(f"reviewed Git blob drifted: {relative_path}")
        _read_regular(source / relative_path, MAX_SOURCE_FILE_BYTES)
        observed_blobs[relative_path] = observed

    try:
        project = tomllib.loads(
            _read_regular(source / "pyproject.toml", MAX_SOURCE_FILE_BYTES).decode("utf-8")
        )["project"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise StrixCandidateBuildError("upstream project metadata is malformed") from exc
    if project.get("name") != "strix-agent" or project.get("version") != DECLARED_PACKAGE_VERSION:
        raise StrixCandidateBuildError("upstream package name or declared version drifted")
    if project.get("license") != UPSTREAM_LICENSE:
        raise StrixCandidateBuildError("upstream declared license is not Apache-2.0")
    if project.get("requires-python") != UPSTREAM_PYTHON_REQUIREMENT:
        raise StrixCandidateBuildError("upstream Python requirement drifted")

    license_payload = _read_regular(source / "LICENSE", MAX_SOURCE_FILE_BYTES)
    if b"Apache License" not in license_payload or b"Version 2.0" not in license_payload:
        raise StrixCandidateBuildError("upstream Apache-2.0 license text is not recognizable")
    tracked = _run(
        ["git", "ls-tree", "-r", "--name-only", "HEAD"],
        cwd=source,
        environment=environment,
    ).splitlines()
    notice_names = {
        "notice",
        "notice.md",
        "notice.txt",
    }
    notices = [path for path in tracked if PurePosixPath(path).name.casefold() in notice_names]
    if notices:
        raise StrixCandidateBuildError(
            "reviewed source unexpectedly contains NOTICE files requiring explicit distribution"
        )
    return {
        "repository": remote,
        "commit": commit,
        "tree": tree,
        "blobs": observed_blobs,
        "notice_paths": notices,
        "tracked_file_count": len(inventory),
    }


def apply_reviewed_overlay(source: Path, environment: Mapping[str, str]) -> dict[str, str]:
    prompt = source / PROMPT_PATH
    upstream = _read_regular(prompt, MAX_SOURCE_FILE_BYTES)
    if _sha256(upstream) != REVIEWED_PROMPT_SHA256:
        raise StrixCandidateBuildError("reviewed prompt preimage drifted before overlay")
    try:
        patched, receipt = apply_policy_overlay(upstream)
    except (OSError, ValueError) as exc:
        raise StrixCandidateBuildError("reviewed Strix prompt overlay was refused") from exc
    if _sha256(patched) != PATCHED_PROMPT_SHA256:
        raise StrixCandidateBuildError("reviewed Strix prompt overlay result drifted")
    prompt.write_bytes(patched)
    changed = _run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=source,
        environment=environment,
    )
    expected_status = f" M {PROMPT_PATH}"
    if changed != expected_status:
        raise StrixCandidateBuildError("the policy overlay changed more than the reviewed prompt")
    raw_receipt = receipt.to_dict()
    return {
        "schema_version": str(raw_receipt["schema_version"]),
        "source_revision": str(raw_receipt["source_revision"]),
        "upstream_sha256": str(raw_receipt["upstream_sha256"]),
        "overlay_sha256": str(raw_receipt["overlay_sha256"]),
        "patched_sha256": str(raw_receipt["patched_sha256"]),
    }


def apply_reviewed_startup_overlay(source: Path, environment: Mapping[str, str]) -> dict[str, str]:
    startup = source / STARTUP_PATH
    upstream = _read_regular(startup, MAX_SOURCE_FILE_BYTES)
    if _sha256(upstream) != REVIEWED_STARTUP_SHA256:
        raise StrixCandidateBuildError("reviewed startup preimage drifted before overlay")
    try:
        patched, receipt = apply_startup_overlay(upstream)
    except (OSError, ValueError) as exc:
        raise StrixCandidateBuildError("reviewed Strix startup overlay was refused") from exc
    if _sha256(patched) != PATCHED_STARTUP_SHA256:
        raise StrixCandidateBuildError("reviewed Strix startup overlay result drifted")
    startup.write_bytes(patched)
    changed = _run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=source,
        environment=environment,
    )
    expected_status = "\n".join(f" M {path}" for path in sorted((PROMPT_PATH, STARTUP_PATH)))
    if changed != expected_status:
        raise StrixCandidateBuildError("the reviewed overlays changed another source path")
    raw_receipt = receipt.to_dict()
    return {
        "schema_version": str(raw_receipt["schema_version"]),
        "source_revision": str(raw_receipt["source_revision"]),
        "upstream_sha256": str(raw_receipt["upstream_sha256"]),
        "overlay_sha256": str(raw_receipt["overlay_sha256"]),
        "patched_sha256": str(raw_receipt["patched_sha256"]),
    }


def create_source_archive(
    source: Path,
    destination: Path,
    environment: Mapping[str, str],
) -> ArtifactIdentity:
    inventory = _tracked_source_inventory(source, environment)
    total = 0
    root_name = "strix-agent-1.7.0-bluefire"
    try:
        with tarfile.open(destination, "x", format=tarfile.PAX_FORMAT) as archive:
            for relative_name, git_mode, _object_id in inventory:
                path = source / PurePosixPath(relative_name)
                payload = _read_regular(path, MAX_SOURCE_FILE_BYTES, allow_empty=True)
                total += len(payload)
                if total > MAX_SOURCE_BYTES:
                    raise StrixCandidateBuildError("reviewed source exceeds the archive size limit")
                member = tarfile.TarInfo(f"{root_name}/{relative_name}")
                member.size = len(payload)
                member.mode = 0o755 if git_mode == "100755" else 0o644
                member.uid = 0
                member.gid = 0
                member.uname = ""
                member.gname = ""
                member.mtime = 0
                archive.addfile(member, io.BytesIO(payload))
    except (OSError, tarfile.TarError) as exc:
        raise StrixCandidateBuildError("could not create the reviewed source archive") from exc
    return _artifact(destination, "application/x-tar", MAX_SOURCE_BYTES + 8 * 1024 * 1024)


def _safe_archive_name(name: str) -> bool:
    if (
        not name
        or "\\" in name
        or "\x00" in name
        or name.startswith("/")
        or re.match(r"^[A-Za-z]:", name)
    ):
        return False
    parts = PurePosixPath(name.rstrip("/")).parts
    return bool(parts) and all(part not in {"", ".", ".."} for part in parts)


def _wheel_member(archive: zipfile.ZipFile, name: str, maximum: int) -> bytes:
    try:
        info = archive.getinfo(name)
    except KeyError as exc:
        raise StrixCandidateBuildError(f"wheel is missing required member: {name}") from exc
    if info.file_size > maximum:
        raise StrixCandidateBuildError(f"wheel member exceeds its size limit: {name}")
    with archive.open(info) as member:
        payload = member.read(maximum + 1)
    if len(payload) != info.file_size or len(payload) > maximum:
        raise StrixCandidateBuildError(f"wheel member has inconsistent size: {name}")
    return payload


def _validate_wheel_record(archive: zipfile.ZipFile, record_name: str) -> None:
    payload = _wheel_member(archive, record_name, MAX_METADATA_BYTES)
    try:
        rows = list(csv.reader(io.StringIO(payload.decode("utf-8"), newline=""), strict=True))
    except (UnicodeError, csv.Error) as exc:
        raise StrixCandidateBuildError("wheel RECORD is malformed") from exc
    expected = {info.filename for info in archive.infolist() if not info.is_dir()}
    seen: set[str] = set()
    for row in rows:
        if len(row) != 3 or row[0] in seen or row[0] not in expected:
            raise StrixCandidateBuildError("wheel RECORD is incomplete or ambiguous")
        seen.add(row[0])
        if row[0] == record_name:
            if row[1] or row[2]:
                raise StrixCandidateBuildError("wheel RECORD must leave its own digest empty")
            continue
        member = _wheel_member(archive, row[0], MAX_WHEEL_MEMBER_BYTES)
        expected_digest = (
            base64.urlsafe_b64encode(hashlib.sha256(member).digest()).rstrip(b"=").decode()
        )
        if row[1] != f"sha256={expected_digest}" or row[2] != str(len(member)):
            raise StrixCandidateBuildError("wheel RECORD digest or size does not match content")
    if seen != expected:
        raise StrixCandidateBuildError("wheel RECORD does not cover every regular member")


def inspect_wheel(
    wheel: Path,
    expected_prompt: bytes,
    expected_startup: bytes,
    expected_license: bytes,
) -> dict[str, Any]:
    identity = _artifact(wheel, "application/vnd.python.wheel", MAX_WHEEL_BYTES)
    if not wheel.name.endswith("-py3-none-linux_x86_64.whl"):
        raise StrixCandidateBuildError("wheel filename does not bind the hosted Linux x86-64 tag")
    try:
        with zipfile.ZipFile(wheel) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)) or not all(_safe_archive_name(name) for name in names):
                raise StrixCandidateBuildError("wheel contains duplicate or unsafe member names")
            aggregate = 0
            for info in infos:
                member_type = stat.S_IFMT(info.external_attr >> 16)
                allowed = {0, stat.S_IFDIR} if info.is_dir() else {0, stat.S_IFREG}
                if member_type not in allowed or info.file_size > MAX_WHEEL_MEMBER_BYTES:
                    raise StrixCandidateBuildError("wheel contains a special or oversized member")
                aggregate += info.file_size
            if aggregate > MAX_WHEEL_BYTES:
                raise StrixCandidateBuildError("wheel expands beyond its aggregate size limit")

            metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
            record_names = [name for name in names if name.endswith(".dist-info/RECORD")]
            entry_names = [name for name in names if name.endswith(".dist-info/entry_points.txt")]
            wheel_names = [name for name in names if name.endswith(".dist-info/WHEEL")]
            if (
                len(metadata_names) != 1
                or len(record_names) != 1
                or len(entry_names) != 1
                or len(wheel_names) != 1
            ):
                raise StrixCandidateBuildError("wheel metadata layout is incomplete or ambiguous")
            metadata = BytesParser(policy=email.policy.default).parsebytes(
                _wheel_member(archive, metadata_names[0], MAX_METADATA_BYTES)
            )
            if metadata.defects:
                raise StrixCandidateBuildError("wheel package metadata is malformed")
            if (
                metadata.get("Name") != "strix-agent"
                or metadata.get("Version") != DECLARED_PACKAGE_VERSION
            ):
                raise StrixCandidateBuildError(
                    "wheel package identity does not match reviewed source"
                )
            if metadata.get("Requires-Python") != UPSTREAM_PYTHON_REQUIREMENT:
                raise StrixCandidateBuildError(
                    "wheel Python requirement does not match reviewed source"
                )
            license_expression = metadata.get("License-Expression") or metadata.get("License")
            if license_expression != UPSTREAM_LICENSE:
                raise StrixCandidateBuildError("wheel license metadata is not Apache-2.0")
            entry_points = _wheel_member(archive, entry_names[0], MAX_METADATA_BYTES).decode(
                "utf-8"
            )
            if "strix = strix.interface.main:main" not in entry_points:
                raise StrixCandidateBuildError("wheel Strix entry point drifted")
            wheel_metadata = _wheel_member(archive, wheel_names[0], MAX_METADATA_BYTES).decode(
                "utf-8"
            )
            if (
                "Root-Is-Purelib: false" not in wheel_metadata
                or "Tag: py3-none-linux_x86_64" not in wheel_metadata
            ):
                raise StrixCandidateBuildError("wheel metadata does not bind Linux x86-64")
            if _wheel_member(archive, PROMPT_PATH, MAX_SOURCE_FILE_BYTES) != expected_prompt:
                raise StrixCandidateBuildError("wheel does not contain the reviewed policy overlay")
            if _wheel_member(archive, STARTUP_PATH, MAX_SOURCE_FILE_BYTES) != expected_startup:
                raise StrixCandidateBuildError(
                    "wheel does not contain the reviewed startup overlay"
                )
            license_names = [name for name in names if name.endswith(".dist-info/licenses/LICENSE")]
            if (
                len(license_names) != 1
                or _wheel_member(archive, license_names[0], MAX_SOURCE_FILE_BYTES)
                != expected_license
            ):
                raise StrixCandidateBuildError("wheel does not contain the exact upstream license")
            sidecars = [name for name in names if name == "strix/bin/strix-tui"]
            sidecar = (
                _wheel_member(archive, sidecars[0], MAX_WHEEL_MEMBER_BYTES)
                if len(sidecars) == 1
                else b""
            )
            if not sidecar:
                raise StrixCandidateBuildError("wheel does not contain the built Linux TUI sidecar")
            sidecar_mode = archive.getinfo(sidecars[0]).external_attr >> 16
            if stat.S_IFMT(sidecar_mode) not in {0, stat.S_IFREG} or sidecar_mode & 0o111 == 0:
                raise StrixCandidateBuildError("wheel TUI sidecar is not marked executable")
            if (
                len(sidecar) < 20
                or sidecar[:6] != b"\x7fELF\x02\x01"
                or int.from_bytes(sidecar[18:20], "little") != 62
            ):
                raise StrixCandidateBuildError("wheel TUI sidecar is not Linux x86-64 ELF")
            _validate_wheel_record(archive, record_names[0])
    except (OSError, UnicodeError, zipfile.BadZipFile) as exc:
        raise StrixCandidateBuildError("candidate wheel is unreadable") from exc
    return {
        "artifact": identity.to_dict(),
        "declared_name": "strix-agent",
        "declared_version": DECLARED_PACKAGE_VERSION,
        "prompt_sha256": _sha256(expected_prompt),
        "startup_sha256": _sha256(expected_startup),
        "contained_sidecar": {
            "path": "strix/bin/strix-tui",
            "size": len(sidecar),
            "sha256": _sha256(sidecar),
            "format": "elf64-little-endian",
            "architecture": "x86_64",
            "executed": False,
        },
        "executed": False,
    }


def _normalized_package_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _lock_packages(lock_payload: bytes) -> dict[str, dict[str, Any]]:
    try:
        document = tomllib.loads(lock_payload.decode("utf-8"))
        packages = document["package"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise StrixCandidateBuildError("upstream uv.lock is malformed") from exc
    if not isinstance(packages, list):
        raise StrixCandidateBuildError("upstream uv.lock package roster is malformed")
    result: dict[str, dict[str, Any]] = {}
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("name"), str):
            raise StrixCandidateBuildError("upstream uv.lock contains a malformed package")
        name = _normalized_package_name(package["name"])
        if name in result:
            previous = result[name]
            if previous.get("version") == package.get("version"):
                continue
            result[name] = {
                "name": name,
                "_ambiguous_versions": sorted(
                    {str(previous.get("version")), str(package.get("version"))}
                ),
            }
            continue
        result[name] = package
    for name, version in _REQUIRED_LOCKED_COMPONENTS.items():
        package = result.get(name)
        if package is None or package.get("version") != version:
            raise StrixCandidateBuildError(f"required locked dependency drifted: {name}")
    return result


def _write_build_constraints(lock_payload: bytes, destination: Path) -> dict[str, Any]:
    packages = _lock_packages(lock_payload)
    selected: dict[str, dict[str, str | bool]] = {}
    lines: list[str] = []
    for name, requirement in sorted(_BUILD_BACKEND_WHEELS.items()):
        version = requirement["version"]
        url = requirement["url"]
        digest = requirement["sha256"]
        version_cross_checked = requirement["version_cross_checked_in_upstream_lock"]
        if (
            not isinstance(version, str)
            or not isinstance(url, str)
            or not isinstance(digest, str)
            or not isinstance(version_cross_checked, bool)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or not url.startswith("https://files.pythonhosted.org/")
        ):
            raise StrixCandidateBuildError(f"reviewed build backend pin is malformed: {name}")
        if version_cross_checked:
            locked = packages.get(name)
            if locked is None or locked.get("version") != version:
                raise StrixCandidateBuildError(
                    f"build backend dependency does not match uv.lock: {name}"
                )
        selected[name] = {
            "version": version,
            "url": url,
            "sha256": digest,
            "version_cross_checked_in_upstream_lock": version_cross_checked,
        }
        lines.append(f"{name} @ {url}#sha256={digest}\n")
    payload = "".join(lines).encode("ascii")
    with destination.open("xb") as handle:
        handle.write(payload)
    return {
        "sha256": _sha256(payload),
        "constraints": selected,
        "complete_for_python_3_12": True,
    }


def _reject_json_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrixCandidateBuildError("dependency SBOM contains duplicate JSON keys")
        result[key] = value
    return result


def _walk_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for nested in value for item in _walk_strings(nested)]
    if isinstance(value, dict):
        return [item for nested in value.values() for item in _walk_strings(nested)]
    return []


def _validate_sbom(
    path: Path,
    lock_payload: bytes,
    *,
    forbidden_roots: Sequence[Path],
) -> ArtifactIdentity:
    payload = _read_regular(path, MAX_SBOM_BYTES)
    try:
        document = json.loads(payload.decode("utf-8"), object_pairs_hook=_reject_json_duplicates)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise StrixCandidateBuildError("dependency SBOM is not valid JSON") from exc
    if not isinstance(document, dict):
        raise StrixCandidateBuildError("dependency SBOM root is not an object")
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.5":
        raise StrixCandidateBuildError("dependency SBOM is not CycloneDX 1.5")
    components = document.get("components")
    if not isinstance(components, list) or not components:
        raise StrixCandidateBuildError("dependency SBOM does not contain locked components")
    lock_packages = _lock_packages(lock_payload)
    observed: dict[str, str] = {}
    for component in components:
        if not isinstance(component, dict):
            raise StrixCandidateBuildError("dependency SBOM component is malformed")
        name = component.get("name")
        version = component.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise StrixCandidateBuildError("dependency SBOM component lacks name or version")
        normalized_name = _normalized_package_name(name)
        if normalized_name in observed:
            raise StrixCandidateBuildError("dependency SBOM contains duplicate component names")
        locked = lock_packages.get(normalized_name)
        if locked is None or locked.get("version") != version:
            raise StrixCandidateBuildError(
                f"dependency SBOM component does not match uv.lock: {normalized_name}"
            )
        observed[normalized_name] = version
    for name, version in _REQUIRED_LOCKED_COMPONENTS.items():
        if lock_packages[name].get("version") != version or observed.get(name) != version:
            raise StrixCandidateBuildError(f"dependency SBOM does not match uv.lock: {name}")
    forbidden = [str(root.resolve(strict=False)) for root in forbidden_roots]
    for value in _walk_strings(document):
        normalized = value.replace("\\", "/")
        if (
            normalized.startswith("file://")
            or "/".join(("", "home", "runner", "")) in normalized
            or re.match(r"^[A-Za-z]:/", normalized)
            or any(root in value or root.replace("\\", "/") in normalized for root in forbidden)
        ):
            raise StrixCandidateBuildError("dependency SBOM leaks a build-host path")
    return ArtifactIdentity(
        path=path.name,
        size=len(payload),
        sha256=_sha256(payload),
        media_type="application/vnd.cyclonedx+json",
    )


def _executable_sha256(name: str, environment: Mapping[str, str]) -> str:
    executable = shutil.which(name, path=environment.get("PATH"))
    if executable is None:
        raise StrixCandidateBuildError(f"reviewed build tool is unavailable: {name}")
    try:
        resolved = Path(executable).resolve(strict=True)
        details = resolved.stat()
        if not stat.S_ISREG(details.st_mode) or details.st_size > MAX_OUTPUT_BYTES:
            raise StrixCandidateBuildError(f"reviewed build tool is not a bounded file: {name}")
        digest = hashlib.sha256()
        size = 0
        with resolved.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                size += len(chunk)
                if size > MAX_OUTPUT_BYTES:
                    raise StrixCandidateBuildError(f"reviewed build tool is oversized: {name}")
                digest.update(chunk)
    except OSError as exc:
        raise StrixCandidateBuildError(f"reviewed build tool could not be hashed: {name}") from exc
    return digest.hexdigest()


def _reject_uv_json_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrixCandidateBuildError("uv release identity contains duplicate JSON keys")
        result[key] = value
    return result


def validate_uv_release_identity(payload: str) -> dict[str, Any]:
    if len(payload.encode("utf-8")) > 4096:
        raise StrixCandidateBuildError("uv release identity is oversized")
    try:
        document = json.loads(payload, object_pairs_hook=_reject_uv_json_duplicates)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise StrixCandidateBuildError("uv release identity is invalid JSON") from exc
    if not isinstance(document, dict) or set(document) != {
        "package_name",
        "version",
        "commit_info",
        "target_triple",
    }:
        raise StrixCandidateBuildError("uv release identity has an invalid shape")
    if any(
        not isinstance(document[name], str) for name in ("package_name", "version", "target_triple")
    ):
        raise StrixCandidateBuildError("uv release identity has an invalid shape")
    commit = document["commit_info"]
    if not isinstance(commit, dict) or set(commit) != {
        "short_commit_hash",
        "commit_hash",
        "commit_date",
        "last_tag",
        "commits_since_last_tag",
    }:
        raise StrixCandidateBuildError("uv release identity has an invalid shape")
    commit_distance = commit["commits_since_last_tag"]
    last_tag = commit["last_tag"]
    if (
        any(
            not isinstance(commit[name], str)
            for name in ("short_commit_hash", "commit_hash", "commit_date")
        )
        or (last_tag is not None and not isinstance(last_tag, str))
        or not isinstance(commit_distance, int)
        or isinstance(commit_distance, bool)
    ):
        raise StrixCandidateBuildError("uv release identity has an invalid shape")
    if (
        document["package_name"] != "uv"
        or document["version"] != UV_VERSION
        or document["target_triple"] != UV_TARGET_TRIPLE
        or commit["short_commit_hash"] != UV_RELEASE_COMMIT[:9]
        or commit["commit_hash"] != UV_RELEASE_COMMIT
        or commit["commit_date"] != UV_RELEASE_DATE
        or last_tag not in (None, UV_VERSION)
        or commit_distance != 0
    ):
        raise StrixCandidateBuildError("uv release identity is not the reviewed build")
    return document


def _validate_toolchains(source: Path, environment: Mapping[str, str]) -> dict[str, Any]:
    uv = _run(["uv", "-V"], cwd=source, environment=environment)
    uv_full = _run(["uv", "--version"], cwd=source, environment=environment)
    uv_identity = validate_uv_release_identity(
        _run(
            ["uv", "self", "version", "--output-format", "json"],
            cwd=source,
            environment=environment,
        )
    )
    go = _run(["go", "version"], cwd=source, environment=environment)
    git = _run(["git", "--version"], cwd=source, environment=environment)
    if uv != UV_VERSION_OUTPUT or uv_full != UV_VERSION_OUTPUT:
        raise StrixCandidateBuildError("uv version is not the reviewed build version")
    if f"go{GO_VERSION} " not in f"{go} ":
        raise StrixCandidateBuildError("Go version is not the reviewed build version")
    if platform.python_version() != PYTHON_VERSION:
        raise StrixCandidateBuildError("candidate build requires the reviewed Python patch release")
    return {
        "python": {
            "version": platform.python_version(),
            "executable_sha256": _executable_sha256("python", environment),
        },
        "uv": {
            "version": uv,
            "full_version": uv_full,
            "release_identity": uv_identity,
            "executable_sha256": _executable_sha256("uv", environment),
        },
        "go": {"version": go, "executable_sha256": _executable_sha256("go", environment)},
        "git": {"version": git, "executable_sha256": _executable_sha256("git", environment)},
    }


def _require_new_directory(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise StrixCandidateBuildError(f"candidate directory already exists: {path.name}")
    path.mkdir(parents=True, mode=0o700, exist_ok=False)


def _validate_output_set(output: Path, allowed: set[str]) -> None:
    total = 0
    observed: set[str] = set()
    for path in output.iterdir():
        if path.name not in allowed:
            raise StrixCandidateBuildError(f"unexpected candidate output: {path.name}")
        payload = _read_regular(path, MAX_OUTPUT_BYTES)
        total += len(payload)
        observed.add(path.name)
    if observed != allowed:
        raise StrixCandidateBuildError("candidate output set is incomplete")
    if total > MAX_OUTPUT_BYTES:
        raise StrixCandidateBuildError("candidate artifacts exceed the 256 MiB output limit")


def _safe_runner_value(value: str | None) -> str:
    if value is None or not _SAFE_RUNNER_VALUE.fullmatch(value):
        return "unreported"
    return value


def build_candidate(
    work_root: Path,
    output_root: Path,
    *,
    bluefire_source_revision: str,
    inherited_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    if not _REVISION.fullmatch(bluefire_source_revision):
        raise StrixCandidateBuildError("BlueFire source revision must be an exact commit identity")
    work = work_root.resolve(strict=False)
    output = output_root.resolve(strict=False)
    if work == output or work in output.parents or output in work.parents:
        raise StrixCandidateBuildError("work and output directories must be separate")
    _require_new_directory(work)
    _require_new_directory(output)
    environment = build_sanitized_environment(work, inherited_environment or os.environ)
    bluefire_repository = Path(__file__).resolve().parents[1]
    bluefire_identity = _validate_bluefire_checkout(
        bluefire_repository, bluefire_source_revision, environment
    )
    source = work / "source"
    clone_reviewed_source(source, environment)
    source_identity = validate_source_checkout(source, environment)
    toolchains = _validate_toolchains(source, environment)
    overlay_receipt = apply_reviewed_overlay(source, environment)
    startup_overlay_receipt = apply_reviewed_startup_overlay(source, environment)
    patched_prompt = _read_regular(source / PROMPT_PATH, MAX_SOURCE_FILE_BYTES)
    patched_startup = _read_regular(source / STARTUP_PATH, MAX_SOURCE_FILE_BYTES)

    source_artifact = create_source_archive(source, output / SOURCE_ARCHIVE_NAME, environment)
    license_payload = _read_regular(source / "LICENSE", MAX_SOURCE_FILE_BYTES)
    lock_payload = _read_regular(source / "uv.lock", MAX_SOURCE_FILE_BYTES)
    build_constraints = _write_build_constraints(lock_payload, work / "build-constraints.txt")
    license_path = output / LICENSE_NAME
    with license_path.open("xb") as handle:
        handle.write(license_payload)
    license_artifact = _artifact(license_path, "text/plain", MAX_SOURCE_FILE_BYTES)

    sbom_path = output / SBOM_NAME
    _run(
        [
            "uv",
            "export",
            "--frozen",
            "--no-dev",
            "--format",
            "cyclonedx1.5",
            "--output-file",
            str(sbom_path),
        ],
        cwd=source,
        environment=environment,
    )
    sbom_artifact = _validate_sbom(
        sbom_path,
        lock_payload,
        forbidden_roots=(work, output, source, bluefire_repository),
    )

    _run(
        [
            "uv",
            "build",
            "--wheel",
            "--frozen",
            "--build-constraint",
            str(work / "build-constraints.txt"),
            "--require-build-hashes",
            "--out-dir",
            str(output),
        ],
        cwd=source,
        environment=environment,
    )
    wheels = sorted(output.glob("*.whl"))
    if len(wheels) != 1 or not wheels[0].name.startswith("strix_agent-1.7.0-"):
        raise StrixCandidateBuildError("candidate build did not produce exactly one expected wheel")
    wheel_receipt = inspect_wheel(wheels[0], patched_prompt, patched_startup, license_payload)

    for initial, media_type, maximum in (
        (source_artifact, "application/x-tar", MAX_SOURCE_BYTES + 8 * 1024 * 1024),
        (license_artifact, "text/plain", MAX_SOURCE_FILE_BYTES),
        (sbom_artifact, "application/vnd.cyclonedx+json", MAX_SBOM_BYTES),
    ):
        if _artifact(output / initial.path, media_type, maximum) != initial:
            raise StrixCandidateBuildError("candidate payload changed during the upstream build")
    changed_tracked = _run(
        ["git", "diff", "--name-only", "--no-renames"],
        cwd=source,
        environment=environment,
    )
    if changed_tracked != "\n".join(sorted((PROMPT_PATH, STARTUP_PATH))):
        raise StrixCandidateBuildError("upstream build changed tracked source beyond the overlay")

    wheel_artifact = ArtifactIdentity(**wheel_receipt["artifact"])
    artifacts = [source_artifact, license_artifact, sbom_artifact, wheel_artifact]
    manifest: dict[str, Any] = {
        "schema": "bluefire.strix-engine-candidate.v1",
        "status": "built-not-executed",
        "candidate_label": f"strix-agent-1.7.0-bluefire.{bluefire_source_revision[:12]}",
        "bluefire_source_revision": bluefire_source_revision,
        "bluefire": bluefire_identity,
        "upstream": {
            **source_identity,
            "declared_package_version": DECLARED_PACKAGE_VERSION,
            "published_release_commit": PUBLISHED_RELEASE_COMMIT,
            "release_equivalence": False,
            "release_equivalence_claimed": False,
            "license": UPSTREAM_LICENSE,
            "requires_python": UPSTREAM_PYTHON_REQUIREMENT,
            "lock_sha256": _sha256(lock_payload),
            "go_mod_sha256": _sha256(
                _read_regular(source / "strix/interface/tui/go.mod", MAX_SOURCE_FILE_BYTES)
            ),
            "go_sum_sha256": _sha256(
                _read_regular(source / "strix/interface/tui/go.sum", MAX_SOURCE_FILE_BYTES)
            ),
        },
        "policy_overlay": {
            **overlay_receipt,
            "path": PROMPT_PATH,
            "modified_upstream_build": True,
            "notice": (
                "BlueFire replaces only the reviewed upstream prompt policy block; "
                "this candidate is not the unmodified upstream release."
            ),
        },
        "startup_overlay": {
            **startup_overlay_receipt,
            "path": STARTUP_PATH,
            "modified_upstream_build": True,
            "notice": (
                "BlueFire validates the registered effective backend before scan preflight "
                "and limits Docker setup to the Docker backend."
            ),
        },
        "sandbox": {
            "image": SANDBOX_IMAGE,
            "oci_index_digest": SANDBOX_IMAGE.rsplit("@", 1)[1],
            "unverified_external_pointer": True,
            "platform_child_manifest_digest": None,
            "config_digest": None,
            "layer_digests": [],
            "inventory_and_notices_complete": False,
            "pulled": False,
            "executed": False,
            "platform_child_digest_validation_required_before_runtime": True,
        },
        "build_actions": {
            "checkout": "d23441a48e516b6c34aea4fa41551a30e30af803",  # pragma: allowlist secret
            "setup_python": "ece7cb06caefa5fff74198d8649806c4678c61a1",  # pragma: allowlist secret
            "setup_go": "b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",  # pragma: allowlist secret
            "setup_uv": "68559e99cc807c1eb7e9238fd43a15bba460eec2",  # pragma: allowlist secret
        },
        "build_backend": {
            **build_constraints,
            "source": (
                "separately reviewed hash-pinned PyPI wheel closure; shared dependency versions "
                "must also match upstream uv.lock"
            ),
            "constraint_applied": True,
        },
        "toolchains": toolchains,
        "runner": {
            "os": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "image_os": _safe_runner_value(os.environ.get("ImageOS")),
            "image_version": _safe_runner_value(os.environ.get("ImageVersion")),
        },
        "artifacts": [
            artifact.to_dict() for artifact in sorted(artifacts, key=lambda item: item.path)
        ],
        "source_archive": {
            "sha256": source_artifact.sha256,
            "modified_paths": sorted((PROMPT_PATH, STARTUP_PATH)),
            "upstream_prompt_sha256": overlay_receipt["upstream_sha256"],
            "patched_prompt_sha256": overlay_receipt["patched_sha256"],
            "upstream_startup_sha256": startup_overlay_receipt["upstream_sha256"],
            "patched_startup_sha256": startup_overlay_receipt["patched_sha256"],
            "upstream_notice_paths": source_identity["notice_paths"],
        },
        "limits": {
            "maximum_output_bytes": MAX_OUTPUT_BYTES,
            "command_timeout_seconds": COMMAND_TIMEOUT_SECONDS,
        },
        "execution": {
            "strix": False,
            "sidecar": False,
            "sandbox": False,
            "target": False,
            "model": False,
        },
        "wheel_inspection": {
            "declared_name": wheel_receipt["declared_name"],
            "declared_version": wheel_receipt["declared_version"],
            "prompt_sha256": wheel_receipt["prompt_sha256"],
            "startup_sha256": wheel_receipt["startup_sha256"],
            "contained_sidecar": wheel_receipt["contained_sidecar"],
            "installable": False,
            "installation_requirement": (
                "Create and verify an offline wheelhouse from the exact uv.lock for this "
                "platform, then bind its receipt before installing the candidate wheel."
            ),
        },
        "sbom": {
            "scope": (
                "Python components exported by uv; excludes Go and OCI contents. Every emitted "
                "name/version is reconciled to uv.lock."
            ),
            "every_emitted_component_reconciled": True,
            "independent_production_closure_completeness_proven": False,
        },
        "future_install_identity_inputs": {
            "source_revision": UPSTREAM_COMMIT,
            "source_tree_sha256": f"sha256:{source_artifact.sha256}",
            "package_sha256": f"sha256:{wheel_artifact.sha256}",
            "executable_sha256": None,
            "image_inventory_sha256": None,
            "embedded_tui_sha256": (f"sha256:{wheel_receipt['contained_sidecar']['sha256']}"),
            "ready_for_strix_build_identity": False,
            "note": (
                "The protected installed Strix CLI executable and qualified image inventory "
                "must be hashed before creating StrixBuildIdentity. The embedded TUI is not "
                "the CLI launch executable."
            ),
        },
        "qualification": {
            "runtime_qualified": False,
            "redistribution_review": strix_redistribution_review(),
            "blocking_reasons": [
                "OCI platform child manifest/config/layers have not been bound.",
                "Sandbox image inventory and third-party notices are not complete.",
                "No engine, lifecycle, containment, target, or model execution was performed.",
                "An exact offline runtime dependency wheelhouse is not attached.",
                "SBOM production-closure completeness is not independently proven.",
                "A second clean build has not established artifact reproducibility.",
                "Go TUI, bundled viewer assets, complete runtime wheels, and OCI rights remain unreviewed.",
            ],
        },
        "limitations": [
            "This candidate is a package/provenance artifact, not runtime qualification.",
            "The Strix engine, TUI sidecar, sandbox image, target, and model were not executed.",
            "The OCI index digest still requires platform-child binding before runtime use.",
            "Dependency presence in the SBOM is not a complete license or vulnerability clearance.",
        ],
    }
    manifest_path = output / MANIFEST_NAME
    manifest_payload = _canonical_json(manifest) + b"\n"
    with manifest_path.open("xb") as handle:
        handle.write(manifest_payload)

    checksum_targets = [artifact.path for artifact in artifacts] + [MANIFEST_NAME]
    checksum_lines = []
    for name in sorted(checksum_targets):
        payload = _read_regular(output / name, MAX_OUTPUT_BYTES)
        if name != MANIFEST_NAME:
            expected = next(artifact for artifact in artifacts if artifact.path == name)
            if len(payload) != expected.size or _sha256(payload) != expected.sha256:
                raise StrixCandidateBuildError("candidate payload changed before checksumming")
        checksum_lines.append(f"{_sha256(payload)}  {name}\n")
    checksums_path = output / CHECKSUMS_NAME
    with checksums_path.open("x", encoding="ascii", newline="\n") as handle:
        handle.writelines(checksum_lines)

    allowed = set(checksum_targets) | {CHECKSUMS_NAME}
    _validate_output_set(output, allowed)
    return manifest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--bluefire-source-revision", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        manifest = build_candidate(
            arguments.work_root,
            arguments.output_root,
            bluefire_source_revision=arguments.bluefire_source_revision,
        )
    except StrixCandidateBuildError as exc:
        print(f"Strix candidate build refused: {exc}", file=sys.stderr)
        return 1
    print(
        "Built non-executed Strix candidate for "
        f"{manifest['upstream']['commit']} with {len(manifest['artifacts'])} immutable artifacts."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
