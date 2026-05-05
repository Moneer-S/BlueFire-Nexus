"""Artifact path discipline.

Every module must write its files under ``context["output_dir"]`` and
register the resulting paths under a clear key in ``ModuleResult.artifacts``.

This test enforces both halves:

1. Snapshot the on-disk state of every well-known write target (project
   ``output/``, project ``logs/``) before each module ``execute()``. Any
   *new* file (created or modified after the test window starts) appearing
   outside ``context["output_dir"]`` after execute returns is a violation.
   Pre-existing files from prior local runs are explicitly ignored via an
   mtime filter so the test stays deterministic when developers iterate
   without cleaning ``output/``.

2. Walk every string value in ``ModuleResult.artifacts`` (recursively).
   Any value that names an existing file on disk must resolve under
   ``context["output_dir"]``.

The contract test (``tests/test_module_contract.py``) and the safety test
(``tests/test_module_safety.py``) cover shape and side-effect freedom; this
test covers where artifacts physically live.
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

# Directories where modules might leak writes if they ignore output_dir.
# Snapshotted before each run; new entries after execute() are violations
# unless they live under context["output_dir"].
_WATCHED_DIRS = (
    PROJECT_ROOT / "output",
    PROJECT_ROOT / "logs",
)


def _snapshot(paths: Iterable[Path], *, mtime_after: float | None = None) -> Set[Path]:
    """Snapshot files under ``paths``, optionally restricted to recent mtimes.

    ``mtime_after`` filters out files that have not been touched since that
    timestamp. This keeps the test deterministic when the project ``output/``
    directory contains stale artifacts from prior local runs: only files
    written *during the test window* count. The invariant we are enforcing
    (no module writes outside ``context["output_dir"]``) is preserved
    because *new* writes always update mtime.
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

    # Use mtime filtering so files left over from prior local runs don't get
    # attributed to this test. Subtract a small fudge factor (1s) to absorb
    # filesystem mtime granularity on platforms that round to whole seconds.
    test_window_start = time.time() - 1.0
    before = _snapshot(_WATCHED_DIRS, mtime_after=test_window_start)
    try:
        result = module.execute(_params_for(module_name), context)
    except RuntimeError:
        # Legacy adapter rejected because pack disabled; nothing to assert.
        after = _snapshot(_WATCHED_DIRS, mtime_after=test_window_start)
        leaked = sorted(after - before)
        assert not leaked, f"{module_name} created files outside output_dir while raising: {leaked}"
        return

    after = _snapshot(_WATCHED_DIRS, mtime_after=test_window_start)
    leaked = sorted(p for p in (after - before) if output_dir not in p.parents)
    assert not leaked, (
        f"{module_name} wrote files outside context['output_dir']:\n  "
        + "\n  ".join(str(p) for p in leaked)
    )

    # Every existing on-disk path referenced from artifacts must live under output_dir.
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
