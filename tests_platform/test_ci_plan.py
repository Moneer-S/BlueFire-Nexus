from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from tools import ci_plan

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/tests.yml"


def test_draft_pull_requests_run_linux_only() -> None:
    scope = ci_plan.plan("pull_request", "true")
    assert scope["full"] is False
    assert scope["python_os"] == ["ubuntu-latest"]
    assert scope["python_windows"] == []
    assert [package["platform"] for package in scope["packages"]] == ["linux"]


@pytest.mark.parametrize(
    ("event", "draft"),
    [("pull_request", "false"), ("pull_request", ""), ("push", ""), ("workflow_dispatch", "")],
)
def test_ready_pull_requests_main_and_manual_runs_use_every_platform(
    event: str, draft: str
) -> None:
    scope = ci_plan.plan(event, draft)
    assert scope["full"] is True
    assert scope["python_os"] == ["ubuntu-latest", "macos-latest"]
    assert len(scope["python_windows"]) == 10
    assert [(package["platform"], package["architecture"]) for package in scope["packages"]] == [
        ("linux", "x86_64"),
        ("windows", "x86_64"),
        ("macos", "x86_64"),
        ("macos", "aarch64"),
    ]


def test_outputs_are_single_line_json_for_github(tmp_path: Path) -> None:
    output = tmp_path / "output"
    assert (
        ci_plan.main(
            {
                "GITHUB_EVENT_NAME": "pull_request",
                "BLUEFIRE_CI_DRAFT": "true",
                "GITHUB_OUTPUT": str(output),
            }
        )
        == 0
    )
    lines = output.read_text(encoding="utf-8").splitlines()
    values = dict(line.split("=", 1) for line in lines)
    assert set(values) == {"full", "python_os", "python_windows", "packages"}
    assert json.loads(values["python_os"]) == ["ubuntu-latest"]


def test_workflow_reads_every_plan_output_and_gates_tests_on_checks() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    outputs = jobs["plan"]["outputs"]
    assert set(outputs) == set(ci_plan.plan("push", ""))
    assert all(value == f"${{{{ steps.scope.outputs.{key} }}}}" for key, value in outputs.items())
    for job in ("python", "package"):
        assert jobs[job]["needs"] == ["plan", "checks"]
    # A draft marked ready must start the all-platform run.
    assert "ready_for_review" in workflow[True]["pull_request"]["types"]
    # Static checks run once, not once per platform and partition.
    python_steps = {step["name"] for step in jobs["python"]["steps"]}
    assert not {"Lint", "Format", "Type-check"} & python_steps
    assert jobs["python"]["env"]["BLUEFIRE_TEST_WAIT_SCALE"] == "4"
