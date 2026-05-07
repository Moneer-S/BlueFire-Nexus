"""Test-suite fixtures shared across BlueFire-Nexus tests.

Two session-scope autouse fixtures live here so they observe the
ENTIRE test session regardless of which tests are collected first:

1. ``_isolate_runtime_output_root`` redirects the default runtime
   output root to a session-scoped tmp directory so unrelated tests
   cannot observe each other's run artifacts via the project-root
   ``output/`` directory.

2. ``_canary_no_writes_to_project_output`` snapshots the project-root
   canary directories (``output/`` and ``logs/``) at session start
   and end and fails the session if any new file appears. This
   fixture used to live inside ``tests/test_module_artifact_paths.py``
   but pytest only triggers per-test-file autouse fixtures when that
   file is collected — moving the fixture here closes Codex P2 on
   PR #36 and ensures the canary observes the full session.

In addition, this module sets ``BLUEFIRE_LOG_DIR`` at module-import
time (before any test file is collected) so the import-time
``setup_logger()`` call in ``src/core/logger.py`` writes its
``bluefire_YYYYMMDD.log`` file to a session tempdir rather than the
project-root ``logs/`` directory. Without this, the canary fixture
would (correctly) fail the session over a pre-existing leak that
predated the canary's session-wide scope.
"""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path
from typing import Iterable, Set

import pytest

# Module-scope: redirect the import-time logger before pytest collects
# any test files. Test modules transitively import ``src.core.logger``
# which calls ``setup_logger()`` at module-import time and would
# otherwise write to project-root ``logs/``. Using ``setdefault`` so an
# operator-supplied value (e.g. CI) wins.
os.environ.setdefault(
    "BLUEFIRE_LOG_DIR",
    tempfile.mkdtemp(prefix="bluefire-test-logs-"),
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Canary directories — modules that hardcode write paths (rather than
# honouring ``context["output_dir"]``) tend to land here. Snapshotted
# once per session, not per test.
_CANARY_DIRS = (
    PROJECT_ROOT / "output",
    PROJECT_ROOT / "logs",
)


def _snapshot_files(paths: Iterable[Path], *, mtime_after: float | None = None) -> Set[Path]:
    """Snapshot files under ``paths``, optionally restricted to recent mtimes.

    ``mtime_after`` filters out files older than the test session window
    so pre-existing local-dev artifacts are not attributed to the
    current run.
    """
    seen: Set[Path] = set()
    for p in paths:
        if not p.exists():
            continue
        for child in p.rglob("*"):
            if not child.is_file():
                continue
            if mtime_after is not None:
                try:
                    if child.stat().st_mtime <= mtime_after:
                        continue
                except OSError:
                    # File disappeared between rglob and stat; ignore.
                    continue
            seen.add(child.resolve())
    return seen


@pytest.fixture(scope="session", autouse=True)
def _isolate_runtime_output_root(tmp_path_factory: pytest.TempPathFactory):
    """Redirect the default runtime output root to a session-scoped tmp dir.

    Without this, every test that instantiates `BlueFireNexus` and
    runs a scenario or operation writes a fresh `output/<run_id>/`
    directory under the project root. That accumulates stale state
    across runs and — more importantly — interferes with the canary
    fixture below, which snapshots the project-root `output/` to
    detect modules that write outside their declared
    `context["output_dir"]`.

    The session-level scope keeps this fast (one tmp dir for the
    entire test session) and is automatically cleaned up by pytest
    when the session ends.
    """
    output_root = tmp_path_factory.mktemp("bluefire-output-root")
    previous = os.environ.get("BLUEFIRE_OUTPUT_ROOT")
    os.environ["BLUEFIRE_OUTPUT_ROOT"] = str(output_root)
    try:
        yield output_root
    finally:
        if previous is None:
            os.environ.pop("BLUEFIRE_OUTPUT_ROOT", None)
        else:
            os.environ["BLUEFIRE_OUTPUT_ROOT"] = previous


@pytest.fixture(scope="session", autouse=True)
def _canary_no_writes_to_project_output() -> Iterable[None]:
    """Fail the session if any test writes a new file under the canary dirs.

    With ``_isolate_runtime_output_root`` redirecting
    ``BlueFireNexus._output_root()`` to a session tmp dir, ambient
    nexus runs do NOT land under project-root ``output/`` during the
    test session. Any new file appearing there comes from a module
    that hardcodes a write path — the exact discipline this fixture
    guards against.

    Captured ``before`` / ``after`` snapshots are mtime-filtered to
    the session window so prior local-dev artifacts under
    ``output/`` do not get attributed here.

    Lives in conftest (rather than inside
    ``tests/test_module_artifact_paths.py``) so the snapshot starts
    at the very beginning of the session, not after that file is
    first collected. Closes Codex P2 on PR #36.
    """
    session_start = time.time() - 1.0
    before = _snapshot_files(_CANARY_DIRS, mtime_after=session_start)
    yield
    after = _snapshot_files(_CANARY_DIRS, mtime_after=session_start)
    leaked = sorted(after - before)
    assert not leaked, (
        "module writes leaked into project-root canary directories during "
        "the test session — these violate the artifact-path discipline:\n  "
        + "\n  ".join(str(p) for p in leaked)
    )
