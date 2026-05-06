"""Artifact path discipline.

Every module must write its files under ``context["output_dir"]`` and
register the resulting paths under a clear key in ``ModuleResult.artifacts``.

The invariant is enforced at two levels:

1. **Per-test (fast path)** — every existing on-disk path string named in
   ``ModuleResult.artifacts`` must resolve under ``context["output_dir"]``.
   This is the strong artifact-path discipline check: if a module writes a
   file outside its declared output dir AND records that path in artifacts,
   we fail immediately with an attributable error message naming the module.

2. **Per-session (canary)** — a session-scope fixture snapshots the
   project-root canary directories (``output/`` and ``logs/``) once at
   start and once at end and diffs them. Any new file appearing in those
   directories during the test session — regardless of which test was
   running — fails the session. This catches the rarer case of a module
   writing to disk WITHOUT recording the path in artifacts (a silent
   side-effect).

The two-level split keeps the per-test fast path fast: previously the test
walked the project-root ``output/`` directory (14000+ stale run artifacts
locally) twice per parametrised case (62 cases × 2 walks × ~6s each ≈
12 minutes wall clock). With the per-test rglob removed and the canary
amortised over the whole session, the same checks complete in seconds.

The session canary preserves the invariant — it just defers the
"where did the leak go" question to one session-end report rather than
a per-test attribution. With the legacy `_make_run_context` now scoped
through ``BlueFireNexus._output_root()`` (config / env / default), the
project-root canary should be empty across the entire session under
healthy module behaviour.

Companion tests:
- ``tests/test_module_contract.py`` — module result shape + status.
- ``tests/test_module_safety.py`` — side-effect freedom under dry-run.
- ``tests/test_runtime_output_root.py`` — output_root resolution.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set

import pytest

from src.core.modules.registry import build_runtime_modules
from tests.test_module_contract import (
    _lab_off_config,
    _lab_simulate_config,
    _make_context,
    _params_for,
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

    Used by the session-scope canary fixture. ``mtime_after`` filters out
    files older than the test session window, so pre-existing local-dev
    artifacts are not attributed to the current run.
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
def _canary_no_writes_to_project_output() -> Iterable[None]:
    """Fail the session if any test writes a new file under the canary dirs.

    ``BlueFireNexus._output_root()`` is normally scoped to the session
    tmp directory (see ``tests/conftest.py``), so ambient nexus runs do
    NOT land under project-root ``output/`` during the test session. Any
    new file appearing there comes from a module that hardcodes a write
    path — the exact discipline this test guards against.

    Captured ``before``/``after`` snapshots are mtime-filtered to the
    session window so prior local-dev artifacts under ``output/`` do
    not get attributed here.
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


def _resolve_under(value: str) -> Path | None:
    """Return the resolved Path for a string that names an existing file, else None."""
    try:
        candidate = Path(value)
    except (TypeError, ValueError):
        return None
    if not candidate.exists() or not candidate.is_file():
        return None
    return candidate.resolve()


def _path_strings(obj: Any) -> List[str]:
    """Recursively pull every string out of an artifacts dict/list/tuple."""
    out: List[str] = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            out.extend(_path_strings(v))
    elif isinstance(obj, (list, tuple, set)):
        for v in obj:
            out.extend(_path_strings(v))
    return out


def _all_module_names() -> list[str]:
    return sorted(build_runtime_modules().keys())


@pytest.fixture(scope="module")
def runtime_modules() -> Dict[str, Any]:
    return build_runtime_modules()


def _run_and_assert_paths(
    module_name: str,
    runtime_modules: Dict[str, Any],
    tmp_path: Path,
    cfg: Dict[str, Any],
    *,
    legacy_enabled: bool,
) -> None:
    output_dir = (tmp_path / "run-output").resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    module = runtime_modules[module_name]
    module_cfg = dict(cfg["modules"].get(module_name, {}))
    module_cfg["config_root"] = cfg
    if module_name.startswith("legacy_"):
        module_cfg["enabled"] = legacy_enabled
        module_cfg["mode"] = "simulate"
        module_cfg["lab_confirmation"] = legacy_enabled
    module.update_config(module_cfg)
    context = _make_context(tmp_path, cfg)
    context["output_dir"] = output_dir

    try:
        result = module.execute(_params_for(module_name), context)
    except RuntimeError:
        # Legacy adapter rejected because pack disabled; nothing else to
        # assert at the per-test level. The session canary still catches
        # any side-effect file that appeared during the raise path.
        return

    # Strong artifact-path discipline: every existing on-disk path
    # referenced from ModuleResult.artifacts must live under output_dir.
    for value in _path_strings(result.artifacts):
        resolved = _resolve_under(value)
        if resolved is None:
            continue
        assert output_dir in resolved.parents or resolved == output_dir, (
            f"{module_name}.artifacts references on-disk path outside output_dir: "
            f"{resolved}"
        )


@pytest.mark.parametrize("module_name", _all_module_names())
def test_module_artifact_paths_lab_off(
    module_name: str, runtime_modules: Dict[str, Any], tmp_path: Path
) -> None:
    _run_and_assert_paths(
        module_name, runtime_modules, tmp_path, _lab_off_config(), legacy_enabled=False
    )


@pytest.mark.parametrize("module_name", _all_module_names())
def test_module_artifact_paths_lab_simulate(
    module_name: str, runtime_modules: Dict[str, Any], tmp_path: Path
) -> None:
    _run_and_assert_paths(
        module_name, runtime_modules, tmp_path, _lab_simulate_config(), legacy_enabled=True
    )
