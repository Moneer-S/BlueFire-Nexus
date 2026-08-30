"""Load the Gate 11 Linux runner from an exact immutable Git commit."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess  # nosec B404 - only a fixed local Git object-reading grammar is used
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Mapping, Sequence

from .runner_bootstrap import RunnerBootstrapError, parse_runner_manifest

LINUX_ARTIFACT_SOURCE = "commit-bound-repository-release-artifact"
LINUX_BINARY_PATH = "bluefire/native/linux-x86_64/bluefire-runner"
LINUX_MANIFEST_PATH = "bluefire/native/linux-x86_64/runner-manifest.json"

_GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_MAX_BINARY_BYTES = 128 * 1024 * 1024
_MAX_MANIFEST_BYTES = 64 * 1024


class CommittedLinuxArtifactError(ValueError):
    """Raised when exact commit objects do not prove the Linux release artifact."""


@dataclass(frozen=True)
class CommittedLinuxArtifact:
    record: Mapping[str, Any]
    binary: bytes
    manifest: bytes


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CommittedLinuxArtifactError(message)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        _require(key not in value, "the committed Linux manifest contains duplicate keys")
        value[key] = item
    return value


def _git_environment() -> Mapping[str, str]:
    names = ("SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")
    environment = {name: os.environ[name] for name in names if os.environ.get(name)}
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C",
            "LC_ALL": "C",
        }
    )
    return environment


def _trusted_git_executable() -> Path:
    candidates: list[Path] = []
    discovered = shutil.which("git")
    if discovered:
        candidates.append(Path(discovered))
    if os.name == "nt":
        windows = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
        if windows:
            candidates.append(
                Path(windows).resolve(strict=True).parent / "Program Files/Git/cmd/git.exe"
            )
    else:
        candidates.extend((Path("/usr/bin/git"), Path("/usr/local/bin/git")))
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    for candidate in candidates:
        try:
            details = candidate.lstat()
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if (
            candidate == resolved
            and candidate.name.casefold() in {"git", "git.exe"}
            and stat.S_ISREG(details.st_mode)
            and not candidate.is_symlink()
            and not bool(int(getattr(details, "st_file_attributes", 0)) & reparse)
        ):
            return resolved
    raise CommittedLinuxArtifactError("the fixed Git object reader is unavailable")


def _git_output(
    repository: Path,
    arguments: Sequence[str],
    *,
    maximum: int,
    label: str,
) -> bytes:
    executable = _trusted_git_executable()
    command = [
        os.fspath(executable),
        "-c",
        f"safe.directory={repository}",
        *arguments,
    ]
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            completed = subprocess.run(  # nosec B603 - fixed executable and argument grammar
                command,
                cwd=repository,
                env=_git_environment(),
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                timeout=30,
                check=False,
            )
            stdout.seek(0, os.SEEK_END)
            output_size = stdout.tell()
            stderr.seek(0, os.SEEK_END)
            error_size = stderr.tell()
            _require(
                completed.returncode == 0
                and 0 < output_size <= maximum
                and error_size <= 64 * 1024,
                f"the committed Linux {label} Git object is unavailable",
            )
            stdout.seek(0)
            return stdout.read(output_size)
    except CommittedLinuxArtifactError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise CommittedLinuxArtifactError(
            f"the committed Linux {label} Git object could not be read"
        ) from exc


def _object_id(repository: Path, revision: str, label: str) -> str:
    try:
        value = (
            _git_output(
                repository,
                ["rev-parse", "--verify", revision],
                maximum=128,
                label=label,
            )
            .decode("ascii")
            .strip()
        )
    except UnicodeError as exc:
        raise CommittedLinuxArtifactError(
            f"the committed Linux {label} Git identity is invalid"
        ) from exc
    _require(
        _GIT_OBJECT.fullmatch(value) is not None,
        f"the committed Linux {label} Git identity is invalid",
    )
    return value


def _blob(repository: Path, object_id: str, maximum: int, label: str) -> bytes:
    try:
        size = int(
            _git_output(
                repository,
                ["cat-file", "-s", object_id],
                maximum=64,
                label=f"{label} size",
            )
            .decode("ascii")
            .strip()
        )
    except (UnicodeError, ValueError) as exc:
        raise CommittedLinuxArtifactError(f"the committed Linux {label} size is invalid") from exc
    _require(1 <= size <= maximum, f"the committed Linux {label} exceeds its bound")
    payload = _git_output(
        repository,
        ["cat-file", "blob", object_id],
        maximum=maximum,
        label=label,
    )
    _require(len(payload) == size, f"the committed Linux {label} size changed")
    return payload


def _linux_architecture(payload: bytes) -> str:
    _require(
        len(payload) >= 20 and payload[:4] == b"\x7fELF" and payload[4] == 2,
        "the committed Linux runner is not ELF64",
    )
    order: Literal["little", "big"]
    if payload[5] == 1:
        order = "little"
    elif payload[5] == 2:
        order = "big"
    else:
        raise CommittedLinuxArtifactError("the committed Linux runner has an invalid ELF header")
    machine = int.from_bytes(payload[18:20], order)
    return {62: "x86_64", 183: "aarch64"}.get(machine, "unknown")


def load_committed_linux_artifact(
    repository: Path,
    *,
    repository_commit: str,
    repository_tree: str,
) -> CommittedLinuxArtifact:
    """Return exact Linux runner bytes and public provenance from one Git commit."""

    root = repository.resolve(strict=True)
    _require(root.is_dir(), "the Gate 11 repository root is not a directory")
    _require(
        _GIT_OBJECT.fullmatch(repository_commit) is not None
        and _GIT_OBJECT.fullmatch(repository_tree) is not None,
        "the Linux artifact acceptance Git binding is invalid",
    )
    commit = _object_id(root, f"{repository_commit}^{{commit}}", "commit")
    tree = _object_id(root, f"{commit}^{{tree}}", "tree")
    _require(
        commit == repository_commit and tree == repository_tree,
        "the Linux artifact does not match the acceptance commit and tree",
    )
    binary_blob = _object_id(root, f"{commit}:{LINUX_BINARY_PATH}", "runner blob")
    manifest_blob = _object_id(root, f"{commit}:{LINUX_MANIFEST_PATH}", "manifest blob")
    binary = _blob(root, binary_blob, _MAX_BINARY_BYTES, "runner")
    manifest_payload = _blob(root, manifest_blob, _MAX_MANIFEST_BYTES, "manifest")
    try:
        manifest_value = json.loads(
            manifest_payload.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
        manifest = parse_runner_manifest(
            manifest_value,
            platform_name="linux",
            architecture="x86_64",
        )
    except (UnicodeError, json.JSONDecodeError, RunnerBootstrapError, ValueError) as exc:
        raise CommittedLinuxArtifactError(
            "the committed Linux runner manifest is incompatible"
        ) from exc
    binary_digest = "sha256:" + hashlib.sha256(binary).hexdigest()
    _require(
        _linux_architecture(binary) == "x86_64"
        and manifest.filename == "bluefire-runner"
        and manifest.size == len(binary)
        and "sha256:" + manifest.sha256 == binary_digest,
        "the committed Linux runner bytes do not match their manifest",
    )
    record = {
        "source": LINUX_ARTIFACT_SOURCE,
        "runner_id": manifest.runner_id,
        "runner_version": manifest.runner_version,
        "platform": "linux",
        "architecture": "x86_64",
        "repository_commit": commit,
        "repository_tree": tree,
        "binary_git_blob": binary_blob,
        "manifest_git_blob": manifest_blob,
        "binary_sha256": binary_digest,
        "binary_size": len(binary),
        "manifest_sha256": "sha256:" + hashlib.sha256(manifest_payload).hexdigest(),
        "manifest_size": len(manifest_payload),
    }
    return CommittedLinuxArtifact(record=record, binary=binary, manifest=manifest_payload)


__all__ = [
    "CommittedLinuxArtifact",
    "CommittedLinuxArtifactError",
    "LINUX_ARTIFACT_SOURCE",
    "LINUX_BINARY_PATH",
    "LINUX_MANIFEST_PATH",
    "load_committed_linux_artifact",
]
