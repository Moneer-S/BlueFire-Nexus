"""Keep hosted deterministic mechanics evidence source-bound and summary-only."""

from __future__ import annotations

import re
import shlex
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
VERIFY_NAME = "Verify installed Linux deterministic engine mechanics simulation"
UPLOAD_NAME = "Upload installed Linux deterministic engine mechanics public summary"
OUTPUT_ROOT = "${{ runner.temp }}/bluefire-installed-engine-mechanics-evidence"
PUBLIC_SUMMARY = OUTPUT_ROOT + "/public-summary.json"
# Public action commit pin, not a credential.
UPLOAD_ACTION = (
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"  # pragma: allowlist secret
)


def _workflow() -> dict:
    return yaml.load(
        (ROOT / ".github/workflows/tests.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )


def _step(workflow: dict, name: str) -> dict:
    return next(step for step in workflow["jobs"]["package"]["steps"] if step["name"] == name)


def _could_cover_mechanics_output(path: str) -> bool:
    # An exact child, directory ancestor, or glob prefix can expose runtime
    # evidence. Inspect every artifact path, including uploads with other names.
    prefix = re.split(r"[*?\[]", path.strip(), maxsplit=1)[0].rstrip("/")
    return (
        prefix == OUTPUT_ROOT
        or prefix.startswith(OUTPUT_ROOT + "/")
        or OUTPUT_ROOT.startswith(prefix + "/")
    )


def _assert_publication_contract(workflow: dict) -> None:
    steps = workflow["jobs"]["package"]["steps"]
    upload = _step(workflow, UPLOAD_NAME)
    assert upload["uses"] == UPLOAD_ACTION
    assert upload["if"] == (
        "always() && matrix.platform == 'linux' "
        "&& steps.installed-engine-mechanics.outcome != 'skipped'"
    )
    assert upload["with"] == {
        "name": "bluefire-installed-deterministic-engine-mechanics-linux-x86_64-${{ github.sha }}",
        "path": PUBLIC_SUMMARY,
        "retention-days": "7",
        "if-no-files-found": "error",
    }
    assert not upload.get("env")
    for other in steps:
        if other is upload or "upload-artifact@" not in other.get("uses", ""):
            continue
        assert not any(
            _could_cover_mechanics_output(path)
            for path in other.get("with", {}).get("path", "").splitlines()
        ), "Mechanics output has a separate unreviewed publication channel"


def test_mechanics_uses_the_existing_exact_candidate_linux_wheel_lane() -> None:
    workflow = _workflow()
    assert workflow["permissions"] == {"contents": "read"}
    package = workflow["jobs"]["package"]
    linux = [row for row in package["strategy"]["matrix"]["include"] if row["platform"] == "linux"]
    assert len(linux) == 1
    assert linux[0]["os"] == "ubuntu-24.04"
    assert linux[0]["architecture"] == "x86_64"
    assert linux[0]["venv-python"] == "bin/python"
    checkout = _step(workflow, "Checkout")
    assert checkout["with"] == {
        "ref": "${{ github.sha }}",
        "fetch-depth": "1",
        "persist-credentials": "false",
    }
    archive = _step(workflow, "Archive exact committed wheel source")["run"]
    assert 'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"' in archive
    assert (
        'archive --format=tar --output="$RUNNER_TEMP/bluefire-wheel-source.tar" "$GITHUB_SHA"'
        in archive
    )
    assert package["defaults"]["run"]["working-directory"] == "./wheel-source"


def test_mechanics_runs_isolated_after_smoke_with_only_standalone_assets() -> None:
    workflow = _workflow()
    steps = workflow["jobs"]["package"]["steps"]
    verify = _step(workflow, VERIFY_NAME)
    assert verify["id"] == "installed-engine-mechanics"
    assert verify["if"] == "matrix.platform == 'linux'"
    assert verify["shell"] == "bash"
    assert verify["timeout-minutes"] == "5"
    assert not verify.get("env") and "working-directory" not in verify
    assert steps.index(_step(workflow, "Smoke installed wheel outside checkout")) < steps.index(
        verify
    )
    commands = verify["run"].splitlines()
    assets = (
        "verify_installed_engine_mechanics.py",
        "installed_engine_mechanics_fixture.py",
        "verify_installed_engine_experiment.py",
    )
    assert commands[:3] == [f'cp tools/{name} "$RUNNER_TEMP/{name}"' for name in assets]
    assert commands[3:7] == [
        'wheels=("$GITHUB_WORKSPACE"/wheel-source/dist/*.whl)',
        'test "${#wheels[@]}" = 1',
        'test -f "${wheels[0]}"',
        'cd "$RUNNER_TEMP"',
    ]
    assert shlex.split("\n".join(commands[7:]).replace("\\\n", "")) == [
        "$RUNNER_TEMP/bluefire-wheel-smoke/bin/python",
        "-I",
        "-B",
        "verify_installed_engine_mechanics.py",
        "--source-revision",
        "$GITHUB_SHA",
        "--forbid-root",
        "$GITHUB_WORKSPACE",
        "--wheel",
        "${wheels[0]}",
        "--fixture",
        "$RUNNER_TEMP/installed_engine_mechanics_fixture.py",
        "--binding-helper",
        "$RUNNER_TEMP/verify_installed_engine_experiment.py",
        "--output",
        "$RUNNER_TEMP/bluefire-installed-engine-mechanics-evidence",
    ]
    assert steps.index(verify) < steps.index(_step(workflow, UPLOAD_NAME))


def test_mechanics_publication_is_summary_only_and_truthfully_labeled() -> None:
    _assert_publication_contract(_workflow())


@pytest.mark.parametrize(
    "path",
    [
        OUTPUT_ROOT,
        OUTPUT_ROOT + "/",
        OUTPUT_ROOT + "/*.json",
        OUTPUT_ROOT + "/**",
        OUTPUT_ROOT + "/runtime",
        OUTPUT_ROOT + "/runtime/receipt.json",
        "${{ runner.temp }}/**",
        "wheel-source/dist/*.whl",
        PUBLIC_SUMMARY + "\n" + OUTPUT_ROOT + "/runtime",
    ],
)
def test_mechanics_publication_rejects_payloads_outside_exact_summary(path: str) -> None:
    workflow = _workflow()
    _step(workflow, UPLOAD_NAME)["with"]["path"] = path
    with pytest.raises(AssertionError):
        _assert_publication_contract(workflow)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("name", "bluefire-native-strix-proof-linux-x86_64-${{ github.sha }}"),
        ("name", "bluefire-installed-deterministic-engine-mechanics-linux-x86_64"),
        ("retention-days", "90"),
        ("if-no-files-found", "warn"),
    ],
)
def test_mechanics_publication_rejects_weakened_scope_or_retention(key: str, value: str) -> None:
    workflow = _workflow()
    _step(workflow, UPLOAD_NAME)["with"][key] = value
    with pytest.raises(AssertionError):
        _assert_publication_contract(workflow)


@pytest.mark.parametrize(
    "condition",
    [
        "success() && matrix.platform == 'linux' && steps.installed-engine-mechanics.outcome == 'success'",
        "always()",
        "matrix.platform == 'linux'",
        "success()",
    ],
)
def test_mechanics_publication_runs_after_verifier_failure_but_only_on_linux(
    condition: str,
) -> None:
    workflow = _workflow()
    _step(workflow, UPLOAD_NAME)["if"] = condition
    with pytest.raises(AssertionError):
        _assert_publication_contract(workflow)


@pytest.mark.parametrize("path", [OUTPUT_ROOT + "/**", "${{ runner.temp }}/", PUBLIC_SUMMARY])
def test_another_artifact_cannot_publish_mechanics_runtime_or_duplicate_summary(path: str) -> None:
    workflow = _workflow()
    other = deepcopy(_step(workflow, UPLOAD_NAME))
    other["name"] = "Other evidence"
    other["with"]["path"] = path
    workflow["jobs"]["package"]["steps"].append(other)
    with pytest.raises(AssertionError, match="separate unreviewed publication channel"):
        _assert_publication_contract(workflow)
