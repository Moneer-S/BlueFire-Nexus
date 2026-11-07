from __future__ import annotations

import json
from pathlib import Path

import yaml

from tools import ci_digest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/tests.yml"

STAMP = "2026-11-05T09:27:53.5990846Z "


def test_extracts_why_a_job_failed_from_real_log_shapes() -> None:
    verifier = {
        "status": "failed_or_incomplete",
        "failure_stage": "explicit_replacement",
        "error_type": "RuntimeError",
        "browser_progress": {
            "browser_stage": "explicit-replacement-completion",
            "browser_error_type": "AssertionError",
        },
        "wheel_sha256": "not reported",
    }
    log = "\n".join(
        STAMP + line
        for line in (
            "tests_platform/test_x.py::test_ok PASSED [ 99%]",
            "FAILED tests_platform/test_service.py::test_execute_job - bluefire.job_runtime."
            "JobWaitTimeout: job did not reach cancelled, completed before timeout",
            "would reformat D:\\a\\repo\\tests_platform\\test_ai_retained_composition.py",
            "bluefire/service.py:12: error: Incompatible return value type  [return-value]",
            "tools/ci_plan.py:3:1: F401 `os` imported but unused",
            " FAIL  tests/builder-routes.test.tsx > keeps every route",
            json.dumps(verifier),
            "##[error]Process completed with exit code 1.",
        )
    )
    assert ci_digest.extract_signals(log) == [
        "FAILED tests_platform/test_service.py::test_execute_job - bluefire.job_runtime."
        "JobWaitTimeout: job did not reach cancelled, completed before timeout",
        "would reformat D:\\a\\repo\\tests_platform\\test_ai_retained_composition.py",
        "bluefire/service.py:12: error: Incompatible return value type [return-value]",
        "tools/ci_plan.py:3:1: F401 `os` imported but unused",
        "FAIL tests/builder-routes.test.tsx > keeps every route",
        "verifier: status=failed_or_incomplete, failure_stage=explicit_replacement, "
        "error_type=RuntimeError, browser_stage=explicit-replacement-completion, "
        "browser_error_type=AssertionError",
    ]


def test_falls_back_to_error_annotations_and_bounds_output() -> None:
    log = STAMP + "##[error]Unable to download artifact\n" + STAMP + "##[error]Process completed"
    assert ci_digest.extract_signals(log + " with exit code 1.") == ["Unable to download artifact"]
    many = "\n".join(f"FAILED tests_platform/test_{index}.py::t" for index in range(30))
    signals = ci_digest.extract_signals(many)
    assert len(signals) == ci_digest.MAX_SIGNALS_PER_JOB + 1
    assert signals[-1] == "… and 18 more"
    assert len(ci_digest.extract_signals("FAILED " + "x" * 1000)[0]) == ci_digest.MAX_LINE


def test_passing_verifier_lines_are_not_reported() -> None:
    assert ci_digest.extract_signals('{"status": "passed", "failure_stage": null}') == []


def test_render_lists_failed_jobs_steps_and_a_tally() -> None:
    jobs = [
        {"id": 1, "name": "Lint, format and types", "conclusion": "success", "steps": []},
        {
            "id": 2,
            "name": "Python 3.12 · windows-latest · a-b",
            "conclusion": "failure",
            "steps": [
                {"name": "Compile", "conclusion": "success"},
                {"name": "Test Windows partition", "conclusion": "failure"},
            ],
        },
        {"id": 3, "name": "Native wheel - macos aarch64", "conclusion": "cancelled", "steps": []},
        {"id": 4, "name": ci_digest.DIGEST_JOB_NAME, "conclusion": None, "status": "in_progress"},
    ]
    lines = ci_digest.render(jobs, {2: ["FAILED tests_platform/test_a.py::t - AssertionError"]})
    assert lines == [
        "FAILURE  Python 3.12 · windows-latest · a-b  (step: Test Windows partition)",
        "    FAILED tests_platform/test_a.py::t - AssertionError",
        "CANCELLED  Native wheel - macos aarch64",
        "Jobs: 1 cancelled, 1 failure, 1 success",
    ]
    assert ci_digest.render(jobs[:1], {}) == ["All jobs passed.", "Jobs: 1 success"]


def test_missing_environment_is_reported_without_failing() -> None:
    assert ci_digest.main({}) == 0


def test_workflow_runs_the_digest_after_every_other_job() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    digest = jobs["digest"]
    assert digest["name"] == ci_digest.DIGEST_JOB_NAME
    assert set(digest["needs"]) == set(jobs) - {"digest"}
    assert digest["if"] == "${{ !cancelled() }}"
    # It reads job results and logs; it never writes.
    assert digest["permissions"] == {"contents": "read", "actions": "read"}
