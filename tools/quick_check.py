"""Fast pre-push checks: lint, format and type-check in a couple of minutes.

Run this before pushing instead of using CI to find these errors:

    python tools/quick_check.py                # Python and frontend
    python tools/quick_check.py --python-only  # what the CI "checks" job runs

Type-checking covers Linux, Windows and macOS from any host, so platform-only
code is checked without a Windows or macOS machine. Every check runs even when
an earlier one fails, and the summary lists each result.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON_PATHS = (
    "bluefire",
    "tests_platform",
    "tools/prepare_ci_python.py",
    "tools/ci_digest.py",
    "tools/ci_plan.py",
    "tools/quick_check.py",
)
MYPY_PLATFORMS = ("linux", "win32", "darwin")


def python_checks() -> list[tuple[str, list[str], Path]]:
    python = sys.executable
    checks = [
        ("ruff", [python, "-m", "ruff", "check", *PYTHON_PATHS], ROOT),
        ("black", [python, "-m", "black", "--check", "--quiet", *PYTHON_PATHS], ROOT),
    ]
    checks += [
        (f"mypy ({platform})", [python, "-m", "mypy", "--platform", platform, "bluefire"], ROOT)
        for platform in MYPY_PLATFORMS
    ]
    return checks


def frontend_checks() -> list[tuple[str, list[str], Path]]:
    corepack = shutil.which("corepack")
    if corepack is None:
        print("frontend: skipped (corepack is not installed)")
        return []
    frontend = ROOT / "frontend"
    return [
        ("frontend types", [corepack, "pnpm", "typecheck"], frontend),
        ("frontend lint", [corepack, "pnpm", "lint"], frontend),
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--python-only", action="store_true", help="skip frontend checks")
    args = parser.parse_args(argv)

    checks = python_checks() + ([] if args.python_only else frontend_checks())
    results: list[tuple[str, bool, float]] = []
    for name, command, cwd in checks:
        print(f"\n== {name}", flush=True)
        started = time.monotonic()
        passed = subprocess.run(command, cwd=cwd, check=False).returncode == 0
        results.append((name, passed, time.monotonic() - started))

    print("\nSummary")
    for name, passed, seconds in results:
        print(f"  {'pass' if passed else 'FAIL'}  {name} ({seconds:.0f}s)")
    return 0 if all(passed for _, passed, _ in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
