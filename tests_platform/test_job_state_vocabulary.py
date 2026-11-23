from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from bluefire.job_runtime import JobState

ROOT = Path(__file__).resolve().parents[1]
JOB_STATES = {state.value for state in JobState}

# Every hand-written copy of the complete job-state list. A job can be in any
# JobState while another surface reads it, so a copy that omits one state turns
# a valid job into a rejected record (a paused file-access job once was).
PYTHON_COPIES = (
    ("bluefire/product_store.py", "_JOB_STATES"),
    ("bluefire/composition_knowledge.py", "_JOB_STATES"),
    ("bluefire/assistance_file_access_context.py", "_JOB_STATES"),
)
FRONTEND_COPIES = (
    ("frontend/src/types.ts", "export type JobState ="),
    ("frontend/src/lib/s3-access.ts", "const jobStates ="),
    ("frontend/src/lib/file-access-assistance.ts", "const operationStates ="),
)


def _python_literal(path: str, name: str) -> set[str]:
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in node.targets
        ):
            return set(ast.literal_eval(node.value))
    raise AssertionError(f"{path} no longer defines {name}")


def _frontend_literal(path: str, prefix: str) -> set[str]:
    lines = [
        line
        for line in (ROOT / path).read_text(encoding="utf-8").splitlines()
        if line.strip().startswith(prefix)
    ]
    assert len(lines) == 1, f"{path} no longer has exactly one line starting with {prefix!r}"
    return set(re.findall(r'"([a-z_]+)"', lines[0].split("=", 1)[1]))


@pytest.mark.parametrize(("path", "name"), PYTHON_COPIES)
def test_python_job_state_copies_match_the_job_runtime(path: str, name: str) -> None:
    assert _python_literal(path, name) == JOB_STATES


@pytest.mark.parametrize(("path", "prefix"), FRONTEND_COPIES)
def test_frontend_job_state_copies_match_the_job_runtime(path: str, prefix: str) -> None:
    assert _frontend_literal(path, prefix) == JOB_STATES
