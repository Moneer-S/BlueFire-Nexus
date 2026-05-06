"""Test-suite fixtures shared across BlueFire-Nexus tests.

Right now this file exists for one purpose: scope the runtime output
root (`BlueFireNexus._output_root`) to a per-session temp directory so
unrelated tests cannot observe each other's run artifacts via the
project-root `output/` directory.

Tests that explicitly set `general.output_root` in their config still
take precedence — see `BlueFireNexus._output_root` for the resolution
order. This fixture only sets a fallback via the
`BLUEFIRE_OUTPUT_ROOT` env var, so tests that do not configure their
own output root automatically land in the session tmp dir instead of
the project-root `output/`.
"""

from __future__ import annotations

import os

import pytest


@pytest.fixture(scope="session", autouse=True)
def _isolate_runtime_output_root(tmp_path_factory: pytest.TempPathFactory):
    """Redirect the default runtime output root to a session-scoped tmp dir.

    Without this, every test that instantiates `BlueFireNexus` and
    runs a scenario or operation writes a fresh `output/<run_id>/`
    directory under the project root. That accumulates stale state
    across runs and — more importantly — interferes with
    `tests/test_module_artifact_paths.py`, which snapshots the
    project-root `output/` to detect modules that write outside their
    declared `context["output_dir"]`.

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
