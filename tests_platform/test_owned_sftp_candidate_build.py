from __future__ import annotations

import subprocess
import tarfile
from pathlib import Path

import pytest
import yaml

from tools import build_owned_sftp_candidate as candidate

ROOT = Path(__file__).parents[1]
ELF = """Class: ELF64
Machine: Advanced Micro Devices X86-64
[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
0x0000000000000001 (NEEDED) Shared library: [libcrypto.so.3]
0x0000000000000001 (NEEDED) Shared library: [libc.so.6]
"""


def test_subprocess_environment_cannot_inherit_credentials_or_loader_overrides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "must-never-reach-build")
    monkeypatch.setenv("ACTIONS_RUNTIME_TOKEN", "must-never-reach-build")
    monkeypatch.setenv("LD_PRELOAD", "unexpected.so")
    monkeypatch.setenv("OPENSSL_CONF", "/unexpected/config")
    monkeypatch.setenv("BASH_ENV", "/unexpected/shell-hook")
    (tmp_path / "home").mkdir()
    builder = candidate.Builder(tmp_path)
    observed = []

    def fake_run(argv, **kwargs):
        observed.append(kwargs["env"])
        kwargs["stdout"].write(b"candidate evidence\n")
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(candidate.subprocess, "run", fake_run)
    assert (
        builder.run(("/usr/bin/readelf", "--version"), tmp_path, "fake") == "candidate evidence\n"
    )
    assert observed == [candidate.clean_environment(tmp_path / "home", tmp_path)]
    assert not set(observed[0]) & {
        "GITHUB_TOKEN",
        "ACTIONS_RUNTIME_TOKEN",
        "LD_PRELOAD",
        "OPENSSL_CONF",
        "BASH_ENV",
    }
    assert observed[0]["GIT_CONFIG_GLOBAL"] == "/dev/null"


def test_elf_evidence_refuses_search_overrides_architecture_and_path_dependencies() -> None:
    assert candidate.parse_elf(ELF) == {
        "interpreter": "/lib64/ld-linux-x86-64.so.2",
        "needed": ["libc.so.6", "libcrypto.so.3"],
    }
    for changed in (
        ELF + "(RUNPATH) Library runpath: [/tmp/replacement]\n",
        ELF + "(RPATH) Library rpath: [$ORIGIN]\n",
        ELF.replace("Advanced Micro Devices X86-64", "AArch64"),
        ELF.replace("[libc.so.6]", "[/tmp/libc.so.6]"),
        ELF + "[Requesting program interpreter: /tmp/second-loader]\n",
    ):
        with pytest.raises(candidate.CandidateBuildError):
            candidate.parse_elf(changed)


def test_cache_evidence_retains_alternatives_instead_of_claiming_loader_selection() -> None:
    text = """3 libs found in cache `/etc/ld.so.cache'
    libc.so.6 (libc6,x86-64) => /lib/x86_64-linux-gnu/libc.so.6
    libc.so.6 (libc6,x86-64, hwcap: "x86-64-v3") => /lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3/libc.so.6
    libc.so.6 (libc6) => /lib/i386-linux-gnu/libc.so.6
"""
    assert candidate.parse_cache(text) == {
        "libc.so.6": [
            "/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3/libc.so.6",
            "/lib/x86_64-linux-gnu/libc.so.6",
        ]
    }


def test_corresponding_source_retains_originals_and_generated_inputs_without_git_auth(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "LICENCE").write_text("complete notice")
    (source / "implementation.c").write_text("source implementation")
    (source / "generated.h").write_text("generated definitions")
    (source / "object.o").write_bytes(b"\x7fELFobject")
    (source / "libstrace.a").write_bytes(b"!<arch>\nobject")
    (source / ".git").mkdir()
    (source / ".git" / "config").write_text("credentials must not be archived")
    pinned = tmp_path / "pinned.tar.gz"
    candidate.archive_sources(source, pinned, tracked=["LICENCE", "implementation.c"])
    with tarfile.open(pinned) as archive:
        assert set(archive.getnames()) == {"LICENCE", "implementation.c"}
    generated = tmp_path / "generated.tar.gz"
    candidate.archive_sources(source, generated)
    with tarfile.open(generated) as archive:
        assert set(archive.getnames()) == {"LICENCE", "implementation.c", "generated.h"}


def test_workflow_is_manual_fixed_single_job_and_starts_builder_with_empty_environment() -> None:
    workflow = yaml.load(
        (ROOT / ".github/workflows/owned-sftp-build.yml").read_text(), Loader=yaml.BaseLoader
    )
    assert workflow["on"] == {"workflow_dispatch": "", "workflow_call": ""}
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"] == {
        "group": "owned-sftp-candidate-build",
        "cancel-in-progress": "false",
    }
    assert set(workflow["jobs"]) == {"candidate"}
    job = workflow["jobs"]["candidate"]
    assert job["runs-on"] == "ubuntu-24.04"
    assert job["timeout-minutes"] == "30"
    checkout, dependencies, build, upload = job["steps"]
    assert checkout["with"]["persist-credentials"] == "false"
    assert checkout["with"]["ref"] == "${{ github.sha }}"
    assert "env -i" in dependencies["run"]
    assert '/usr/bin/env -i PATH=/usr/bin:/bin HOME="$build_root/home"' in build["run"]
    assert "/usr/bin/python3 -I tools/build_owned_sftp_candidate.py" in build["run"]
    assert "github.event.inputs" not in build["run"]
    assert "token" not in build["run"].lower()
    assert upload["with"]["retention-days"] == "7"
    assert upload["with"]["if-no-files-found"] == "error"
    assert "release" not in upload.get("uses", "")
