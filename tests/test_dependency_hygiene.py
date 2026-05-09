"""Pin the default dependency manifest against silent re-additions.

The Security and Quality Analysis CI workflow runs ``pip-audit`` against the
declared default dependency set. When a package is declared but not actually
imported, every CVE filed against it shows up as inherited noise that blocks
unrelated PRs. This test exists to prevent that drift.

Each entry in ``_BANNED_DEFAULT_DEPS`` was checked for runtime imports under
``src/``, ``tests/``, and ``scripts/`` at the time of removal and is being
held out of the default install on purpose. If a future feature actually
needs one of these, the right move is to import it AND re-declare it (so
both ends of the contract land in the same PR), not to silently re-add the
declaration.
"""

from __future__ import annotations

from pathlib import Path

import pytest

try:  # py3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - py3.10 fallback
    import tomli as tomllib  # type: ignore[no-redef]


REPO_ROOT = Path(__file__).resolve().parent.parent

# Packages that have been deliberately removed from the default install set.
# Each entry must include a one-line rationale so future readers understand
# why re-adding it without an import would be a regression.
_BANNED_DEFAULT_DEPS: dict[str, str] = {
    "paramiko": (
        "Removed because no module under src/, tests/, or scripts/ imports "
        "it; declaring it pulled in CVE-2026-44405 noise on every CI run."
    ),
}


def _normalise(name: str) -> str:
    """PEP 503 normalisation - lowercase, dashes/underscores/dots collapse."""

    out: list[str] = []
    last_dash = False
    for ch in name.strip().lower():
        if ch in "-_.":
            if not last_dash:
                out.append("-")
                last_dash = True
        else:
            out.append(ch)
            last_dash = False
    return "".join(out).strip("-")


def _split_requirement(line: str) -> str:
    """Strip version specifiers / markers / comments from a requirement line."""

    candidate = line.split("#", 1)[0].strip()
    if not candidate:
        return ""
    if candidate.startswith("-"):  # -r, -e, etc.
        return ""
    for sep in ("==", ">=", "<=", "~=", "!=", ">", "<", ";", "[", " "):
        idx = candidate.find(sep)
        if idx != -1:
            candidate = candidate[:idx]
    return _normalise(candidate)


def _read_requirements_txt() -> set[str]:
    raw = (REPO_ROOT / "requirements.txt").read_text(encoding="utf-8")
    names: set[str] = set()
    for line in raw.splitlines():
        token = _split_requirement(line)
        if token:
            names.add(token)
    return names


def _read_pyproject_default_deps() -> set[str]:
    data = tomllib.loads(
        (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    deps = data.get("project", {}).get("dependencies", []) or []
    return {_split_requirement(dep) for dep in deps if _split_requirement(dep)}


@pytest.mark.parametrize("banned, rationale", sorted(_BANNED_DEFAULT_DEPS.items()))
def test_banned_default_deps_absent_from_requirements_txt(
    banned: str, rationale: str
) -> None:
    """``requirements.txt`` must not declare a banned default dependency."""

    declared = _read_requirements_txt()
    assert banned not in declared, (
        f"requirements.txt re-declares banned default dependency {banned!r}. "
        f"Rationale for keeping it out: {rationale}"
    )


@pytest.mark.parametrize("banned, rationale", sorted(_BANNED_DEFAULT_DEPS.items()))
def test_banned_default_deps_absent_from_pyproject(
    banned: str, rationale: str
) -> None:
    """``pyproject.toml`` ``project.dependencies`` must not list a banned dep."""

    declared = _read_pyproject_default_deps()
    assert banned not in declared, (
        f"pyproject.toml re-declares banned default dependency {banned!r}. "
        f"Rationale for keeping it out: {rationale}"
    )


def test_requirements_txt_and_pyproject_default_deps_are_aligned() -> None:
    """Default install set should agree between requirements.txt and pyproject.

    The two manifests serve distinct entry points (``pip install -r`` vs
    ``pip install -e .``), so divergence is silently shippable. Pin them.
    Platform-conditional pins (e.g. ``pywin32; sys_platform == 'win32'``) are
    explicitly tolerated because pyproject does not currently express them.
    """

    req = _read_requirements_txt()
    proj = _read_pyproject_default_deps()

    # Tolerate documented platform-only deps that only appear in requirements.txt.
    tolerated_platform_only = {"pywin32"}

    only_in_req = (req - proj) - tolerated_platform_only
    only_in_proj = proj - req

    assert not only_in_req, (
        "Packages declared in requirements.txt but missing from "
        "pyproject.toml [project].dependencies: "
        f"{sorted(only_in_req)}"
    )
    assert not only_in_proj, (
        "Packages declared in pyproject.toml [project].dependencies "
        f"but missing from requirements.txt: {sorted(only_in_proj)}"
    )
