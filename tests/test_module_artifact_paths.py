"""Artifact path discipline.

Every module must write its files under ``context["output_dir"]`` and
register the resulting paths under a clear key in ``ModuleResult.artifacts``.

The invariant is enforced at two levels:

1. **Per-test (fast path)** — every existing on-disk path string named in
   ``ModuleResult.artifacts`` must resolve under ``context["output_dir"]``.
   This is the strong artifact-path discipline check: if a module writes a
   file outside its declared output dir AND records that path in artifacts,
   we fail immediately with an attributable error message naming the module.

2. **Per-session (canary)** — see
   ``_canary_no_writes_to_project_output`` in ``tests/conftest.py``. The
   session-scope autouse fixture lives in conftest so it observes the
   ENTIRE test session regardless of which tests are collected first
   (closes Codex P2 on PR #36 — fixture used to live in this file and
   only triggered once this module was collected).

The two-level split keeps the per-test fast path fast: previously the test
walked the project-root ``output/`` directory (14000+ stale run artifacts
locally) twice per parametrised case (62 cases × 2 walks × ~6s each ≈
12 minutes wall clock). With the per-test rglob removed and the canary
amortised over the whole session, the same checks complete in seconds.

Companion tests:
- ``tests/test_module_contract.py`` — module result shape + status.
- ``tests/test_module_safety.py`` — side-effect freedom under dry-run.
- ``tests/test_runtime_output_root.py`` — output_root resolution.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from src.core.modules.registry import build_runtime_modules
from tests.test_module_contract import (
    _lab_off_config,
    _lab_simulate_config,
    _make_context,
    _params_for,
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
