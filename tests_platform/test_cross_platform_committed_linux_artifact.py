from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from bluefire.cross_platform_committed_linux_artifact import (
    LINUX_BINARY_PATH,
    LINUX_MANIFEST_PATH,
    CommittedLinuxArtifactError,
    load_committed_linux_artifact,
)
from bluefire.cross_platform_linux import _stage_product


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _committed_repository(tmp_path: Path) -> tuple[Path, str, str]:
    source = Path(__file__).resolve().parents[1]
    repository = tmp_path / "repository"
    repository.mkdir()
    binary = repository / Path(*LINUX_BINARY_PATH.split("/"))
    manifest = repository / Path(*LINUX_MANIFEST_PATH.split("/"))
    binary.parent.mkdir(parents=True)
    shutil.copyfile(source / Path(*LINUX_BINARY_PATH.split("/")), binary)
    shutil.copyfile(source / Path(*LINUX_MANIFEST_PATH.split("/")), manifest)
    _git(repository, "init", "--quiet")
    _git(repository, "config", "user.email", "gate11@example.invalid")
    _git(repository, "config", "user.name", "Gate 11 Test")
    _git(repository, "add", "--", LINUX_BINARY_PATH, LINUX_MANIFEST_PATH)
    _git(repository, "commit", "--quiet", "-m", "fixture")
    return (
        repository,
        _git(repository, "rev-parse", "HEAD"),
        _git(repository, "rev-parse", "HEAD^{tree}"),
    )


@pytest.mark.skipif(shutil.which("git") is None, reason="Git is unavailable")
def test_linux_artifact_uses_exact_commit_blobs_not_live_worktree(tmp_path: Path) -> None:
    repository, commit, tree = _committed_repository(tmp_path)
    expected = load_committed_linux_artifact(
        repository, repository_commit=commit, repository_tree=tree
    )

    (repository / Path(*LINUX_BINARY_PATH.split("/"))).write_bytes(b"untrusted-live-runner")
    (repository / Path(*LINUX_MANIFEST_PATH.split("/"))).write_bytes(b"{}\n")
    observed = load_committed_linux_artifact(
        repository, repository_commit=commit, repository_tree=tree
    )

    assert observed == expected
    assert observed.record["repository_commit"] == commit
    assert observed.record["repository_tree"] == tree
    assert observed.record["binary_git_blob"] == _git(
        repository, "rev-parse", f"{commit}:{LINUX_BINARY_PATH}"
    )
    assert observed.record["manifest_git_blob"] == _git(
        repository, "rev-parse", f"{commit}:{LINUX_MANIFEST_PATH}"
    )


@pytest.mark.skipif(shutil.which("git") is None, reason="Git is unavailable")
def test_linux_artifact_rejects_wrong_acceptance_tree(tmp_path: Path) -> None:
    repository, commit, _tree = _committed_repository(tmp_path)

    with pytest.raises(CommittedLinuxArtifactError, match="commit and tree"):
        load_committed_linux_artifact(
            repository,
            repository_commit=commit,
            repository_tree="0" * len(commit),
        )


@pytest.mark.skipif(shutil.which("git") is None, reason="Git is unavailable")
def test_linux_product_stage_replaces_live_runner_with_commit_blobs(tmp_path: Path) -> None:
    repository, commit, tree = _committed_repository(tmp_path)
    artifact = load_committed_linux_artifact(
        repository, repository_commit=commit, repository_tree=tree
    )
    (repository / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
    (repository / Path(*LINUX_BINARY_PATH.split("/"))).write_bytes(b"untrusted-live-runner")
    (repository / Path(*LINUX_MANIFEST_PATH.split("/"))).write_bytes(b"{}\n")
    staging = tmp_path / "staging"
    staging.mkdir()

    _stage_product(repository, staging, artifact)

    native = staging / "product" / Path(*LINUX_MANIFEST_PATH.split("/")).parent
    assert (native / "bluefire-runner").read_bytes() == artifact.binary
    assert (native / "runner-manifest.json").read_bytes() == artifact.manifest
