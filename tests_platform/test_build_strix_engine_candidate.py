from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import subprocess
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import pytest
import yaml

from bluefire.strix_policy_overlay import PATCHED_PROMPT_SHA256
from bluefire.strix_redistribution_review import strix_redistribution_review
from tools import build_strix_engine_candidate as candidate

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/strix-engine-candidate.yml"
DOC = ROOT / "docs/engine-provenance.md"


def _record_row(name: str, payload: bytes) -> list[str]:
    digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
    return [name, f"sha256={digest}", str(len(payload))]


def _synthetic_wheel(path: Path, prompt: bytes, license_payload: bytes) -> None:
    dist = "strix_agent-1.7.0.dist-info"
    sidecar = bytearray(64)
    sidecar[:6] = b"\x7fELF\x02\x01"
    sidecar[18:20] = (62).to_bytes(2, "little")
    members = {
        candidate.PROMPT_PATH: prompt,
        "strix/bin/strix-tui": bytes(sidecar),
        f"{dist}/METADATA": (
            b"Metadata-Version: 2.4\n"
            b"Name: strix-agent\n"
            b"Version: 1.7.0\n"
            b"License-Expression: Apache-2.0\n"
            b"Requires-Python: >=3.12\n\n"
        ),
        f"{dist}/entry_points.txt": b"[console_scripts]\nstrix = strix.interface.main:main\n",
        f"{dist}/licenses/LICENSE": license_payload,
        f"{dist}/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: fixture\nRoot-Is-Purelib: false\n"
            b"Tag: py3-none-linux_x86_64\n"
        ),
    }
    rows = [_record_row(name, payload) for name, payload in sorted(members.items())]
    rows.append([f"{dist}/RECORD", "", ""])
    record = io.StringIO(newline="")
    csv.writer(record, lineterminator="\n").writerows(rows)
    members[f"{dist}/RECORD"] = record.getvalue().encode()
    with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in members.items():
            if name == "strix/bin/strix-tui":
                info = zipfile.ZipInfo(name)
                info.external_attr = (0o100755 << 16) | 0o20
                archive.writestr(info, payload)
            else:
                archive.writestr(name, payload)


def _git(arguments: list[str], cwd: Path) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def _fixture_repository(path: Path) -> dict[str, str]:
    path.mkdir()
    _git(["init", "--quiet"], path)
    _git(["config", "user.email", "candidate@example.invalid"], path)
    _git(["config", "user.name", "Candidate Test"], path)
    (path / "a.txt").write_text("alpha\n", encoding="utf-8")
    (path / "empty.txt").write_bytes(b"")
    nested = path / "nested"
    nested.mkdir()
    (nested / "b.txt").write_text("beta\n", encoding="utf-8")
    _git(["add", "a.txt", "empty.txt", "nested/b.txt"], path)
    _git(["commit", "--quiet", "-m", "fixture"], path)
    return dict(os.environ)


def test_reviewed_source_and_runtime_pins_are_immutable_and_distinct() -> None:
    assert candidate.UPSTREAM_REPOSITORY == "https://github.com/usestrix/strix.git"
    assert candidate.UPSTREAM_COMMIT == "6b7ae2ebe4d47037a927aade23265ff4e4f27e84"
    assert candidate.UPSTREAM_TREE == "23c06e4a0e58bdf3b4979863d7623230e4091332"
    assert candidate.PUBLISHED_RELEASE_COMMIT == "55bc07991aacb1c26a81b43e7ca53148730d2019"
    assert candidate.UPSTREAM_COMMIT != candidate.PUBLISHED_RELEASE_COMMIT
    assert candidate.DECLARED_PACKAGE_VERSION == "1.7.0"
    assert candidate.PYTHON_VERSION == "3.12.14"
    assert candidate.UV_VERSION == "0.13.6"
    assert candidate.GO_VERSION == "1.24.10"
    assert candidate.SANDBOX_IMAGE.endswith(
        "@sha256:78df914f3029464c9d00580f531ec51025c251c422ec3b09c3f19c5fa6d80c30"
    )
    assert ":latest" not in candidate.SANDBOX_IMAGE
    assert candidate.MAX_OUTPUT_BYTES == 256 * 1024 * 1024


def test_sanitized_environment_drops_ambient_credentials(tmp_path: Path) -> None:
    sensitive_names = (
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
        "OPENAI_API_KEY",
        "DOCKER_HOST",
        "HTTPS_PROXY",
    )
    inherited = {
        "PATH": os.environ.get("PATH", "fixture-path"),
        "HOME": "/ambient/home",
    }
    inherited.update(dict.fromkeys(sensitive_names, "fixture-value"))
    environment = candidate.build_sanitized_environment(tmp_path, inherited)
    assert set(environment).isdisjoint(sensitive_names)
    assert environment["HOME"] == str(tmp_path / "home")
    assert environment["GOPROXY"] == "https://proxy.golang.org"
    assert "," not in environment["GOPROXY"]
    assert environment["GOTOOLCHAIN"] == "local"
    assert environment["GONOSUMDB"] == ""
    assert environment["GOFLAGS"] == "-mod=readonly -buildvcs=false"
    assert environment["GIT_CONFIG_COUNT"] == "1"
    assert environment["GIT_CONFIG_KEY_0"] == "safe.directory"
    assert environment["GIT_CONFIG_VALUE_0"] == str(Path(candidate.__file__).resolve().parents[1])
    assert environment["GIT_CONFIG_VALUE_0"] != "*"


def test_source_archive_is_deterministic_and_uses_git_inventory(tmp_path: Path) -> None:
    source = tmp_path / "source"
    environment = _fixture_repository(source)
    first = candidate.create_source_archive(source, tmp_path / "first.tar", environment)
    second = candidate.create_source_archive(source, tmp_path / "second.tar", environment)
    assert first.sha256 == second.sha256
    with tarfile.open(tmp_path / "first.tar") as archive:
        members = archive.getmembers()
    assert [member.name for member in members] == [
        "strix-agent-1.7.0-bluefire/a.txt",
        "strix-agent-1.7.0-bluefire/empty.txt",
        "strix-agent-1.7.0-bluefire/nested/b.txt",
    ]
    assert all(member.uid == 0 and member.gid == 0 and member.mtime == 0 for member in members)


def test_source_archive_refuses_tracked_symlink(tmp_path: Path) -> None:
    source = tmp_path / "source"
    environment = _fixture_repository(source)
    link = source / "linked.txt"
    try:
        link.symlink_to(source / "a.txt")
    except OSError:
        pytest.skip("host does not permit symlink fixture creation")
    _git(["add", "linked.txt"], source)
    _git(["commit", "--quiet", "-m", "link"], source)
    with pytest.raises(candidate.StrixCandidateBuildError, match="link, submodule, or special"):
        candidate.create_source_archive(source, tmp_path / "source.tar", environment)


def test_wheel_inspection_binds_prompt_license_sidecar_and_record(tmp_path: Path) -> None:
    prompt = b"reviewed patched prompt\n"
    license_payload = b"Apache License\nVersion 2.0\n"
    wheel = tmp_path / "strix_agent-1.7.0-py3-none-linux_x86_64.whl"
    _synthetic_wheel(wheel, prompt, license_payload)
    receipt = candidate.inspect_wheel(wheel, prompt, license_payload)
    assert receipt["declared_version"] == "1.7.0"
    assert receipt["executed"] is False
    assert receipt["contained_sidecar"]["architecture"] == "x86_64"
    assert receipt["contained_sidecar"]["executed"] is False


def test_wheel_inspection_refuses_prompt_or_license_drift(tmp_path: Path) -> None:
    wheel = tmp_path / "strix_agent-1.7.0-py3-none-linux_x86_64.whl"
    _synthetic_wheel(wheel, b"different\n", b"Apache License\nVersion 2.0\n")
    with pytest.raises(candidate.StrixCandidateBuildError, match="policy overlay"):
        candidate.inspect_wheel(
            wheel,
            b"reviewed\n",
            b"Apache License\nVersion 2.0\n",
        )


def _lock_fixture() -> bytes:
    versions = {
        **candidate._REQUIRED_LOCKED_COMPONENTS,
        "packaging": "26.2",
        "pathspec": "1.1.1",
        "pluggy": "1.6.0",
    }
    sections = ["version = 1\n", "revision = 3\n"]
    for name, version in versions.items():
        sections.extend(
            [
                "\n[[package]]\n",
                f'name = "{name}"\n',
                f'version = "{version}"\n',
            ]
        )
    return "".join(sections).encode()


def _sbom_fixture() -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"type": "library", "name": name, "version": version}
            for name, version in candidate._REQUIRED_LOCKED_COMPONENTS.items()
        ],
    }


def test_build_backend_constraints_are_hash_pinned_and_cross_checked(tmp_path: Path) -> None:
    destination = tmp_path / "constraints.txt"
    receipt = candidate._write_build_constraints(_lock_fixture(), destination)
    assert set(receipt["constraints"]) == {
        "hatchling",
        "packaging",
        "pathspec",
        "pluggy",
        "tomlkit",
        "trove-classifiers",
    }
    assert receipt["constraints"]["hatchling"]["version"] == "1.32.4"
    assert receipt["constraints"]["hatchling"]["version_cross_checked_in_upstream_lock"] is False
    assert receipt["constraints"]["packaging"]["version_cross_checked_in_upstream_lock"] is True
    assert "#sha256=" in destination.read_text(encoding="ascii")
    source = (ROOT / "tools/build_strix_engine_candidate.py").read_text(encoding="utf-8")
    assert '"--require-build-hashes"' in source
    assert '_run(["uv", "-V"]' in source
    assert receipt["sha256"] == hashlib.sha256(destination.read_bytes()).hexdigest()


def test_sbom_must_match_reviewed_lock_and_not_leak_host_paths(tmp_path: Path) -> None:
    import json

    sbom = tmp_path / "dependencies.cdx.json"
    sbom.write_text(json.dumps(_sbom_fixture()), encoding="utf-8")
    identity = candidate._validate_sbom(
        sbom,
        _lock_fixture(),
        forbidden_roots=(tmp_path / "build",),
    )
    assert identity.media_type == "application/vnd.cyclonedx+json"

    leaking = _sbom_fixture()
    leaking["metadata"] = {"property": str(tmp_path / "build" / "secret")}
    sbom.write_text(json.dumps(leaking), encoding="utf-8")
    with pytest.raises(candidate.StrixCandidateBuildError, match="build-host path"):
        candidate._validate_sbom(
            sbom,
            _lock_fixture(),
            forbidden_roots=(tmp_path / "build",),
        )

    duplicate = _sbom_fixture()
    duplicate["components"].append(dict(duplicate["components"][0]))
    sbom.write_text(json.dumps(duplicate), encoding="utf-8")
    with pytest.raises(candidate.StrixCandidateBuildError, match="duplicate component"):
        candidate._validate_sbom(sbom, _lock_fixture(), forbidden_roots=(tmp_path / "build",))

    unlocked = _sbom_fixture()
    unlocked["components"].append({"type": "library", "name": "unlocked-package", "version": "1.0"})
    sbom.write_text(json.dumps(unlocked), encoding="utf-8")
    with pytest.raises(candidate.StrixCandidateBuildError, match="does not match uv.lock"):
        candidate._validate_sbom(sbom, _lock_fixture(), forbidden_roots=(tmp_path / "build",))


def test_overlay_result_is_the_reviewed_modified_build() -> None:
    assert (
        PATCHED_PROMPT_SHA256 == "1908703508eff7287d492e63d1722d7f1a4a968ab3d2c237e92898abdd65d6fe"
    )


def test_root_license_attribution_does_not_clear_bundled_components() -> None:
    review = strix_redistribution_review()
    assert review["project_license_attribution"] == {
        "bluefire": "MIT",
        "strix_source": "Apache-2.0",
    }
    assert review["redistribution_ready"] is False
    assert review["redistribution_authorized"] is False
    assert review["root_license_is_component_clearance"] is False
    assert set(review["component_reviews"]) == {
        "third_party_go_tui",
        "bundled_frontend_viewer_assets",
        "complete_python_runtime_wheels",
        "oci_image",
    }
    for component in review["component_reviews"].values():
        assert component["review_complete"] is False
        assert component["license_expression"] is None
        assert component["notices_complete"] is None
        assert component["redistribution_rights_confirmed"] is None


def test_workflow_is_manual_read_only_bounded_and_commit_pinned() -> None:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert set(workflow["on"]) == {"workflow_dispatch", "workflow_call"}
    assert workflow["permissions"] == {"contents": "read"}
    assert set(workflow["jobs"]) == {"build"}
    job = workflow["jobs"]["build"]
    assert job["runs-on"] == "ubuntu-24.04"
    assert job["timeout-minutes"] == "30"
    steps = job["steps"]
    uses = {step["uses"]: step for step in steps if "uses" in step}
    checkout = uses["actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803"]["with"]
    assert checkout == {
        "ref": "${{ github.sha }}",
        "fetch-depth": "1",
        "persist-credentials": "false",
    }
    python = uses["actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1"]["with"]
    assert python["python-version"] == "3.12.14"
    go = uses["actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e"]["with"]
    assert go == {"go-version": "1.24.10", "cache": "false"}
    uv = uses["astral-sh/setup-uv@68559e99cc807c1eb7e9238fd43a15bba460eec2"]["with"]
    assert uv == {"version": "0.13.6", "enable-cache": "false"}
    assert not any("upload-artifact" in action for action in uses)


def test_workflow_builds_only_the_candidate_and_never_publishes_or_executes_strix() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    lowered = text.lower()
    assert "${{ secrets." not in lowered
    assert "packages: write" not in lowered
    assert "contents: write" not in lowered
    assert "docker pull" not in lowered
    assert "python -m strix" not in lowered
    assert "strix --" not in lowered
    assert "uv run" not in lowered
    assert "gh release" not in lowered
    assert "python -m tools.build_strix_engine_candidate" in text


def test_provenance_document_states_modified_non_runtime_non_installable_scope() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert candidate.UPSTREAM_COMMIT in text
    assert candidate.PUBLISHED_RELEASE_COMMIT in text
    assert candidate.SANDBOX_IMAGE in text
    assert "modified upstream build" in text
    assert "not a standalone installation artifact" in text
    assert "does not pull, execute, bundle, or redistribute" in text
    assert "single build does not" in text
