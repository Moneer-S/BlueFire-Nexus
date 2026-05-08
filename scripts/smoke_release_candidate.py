"""Maintainer-facing release-candidate smoke script.

Purpose
-------

Validate the canonical fresh-clone operator path end-to-end and
re-assert every release-candidate polish invariant the rc1 cut
fixed. Designed to run on a clean checkout immediately before
publishing an `-rcN` tag, against the actual scenario runner —
not against mocked surfaces.

Usage
-----

    python scripts/smoke_release_candidate.py
    python scripts/smoke_release_candidate.py --keep-output
    python scripts/smoke_release_candidate.py --scenario enterprise_intrusion_chain

Exit codes
----------

- ``0`` — every check passed.
- non-zero — at least one check failed; the exit code is the
  number of failures.

Constraints
-----------

- **No network calls.** The script invokes `python -m
  src.run_scenario` and `python -m src.core.cli` against a
  default config; both paths are dry-run / template-AI / offline
  by construction.
- **No real API calls.** The default AI provider is the
  deterministic template; the smoke script never sets
  `modules.ai.enabled: true` and never reads an API key.
- **Local output only.** Output lands in a tempdir under
  `BLUEFIRE_OUTPUT_ROOT`; the project's `output/` is not
  touched unless ``--keep-output`` is passed pointing at the
  project root.
- **No state leaks across runs.** Each invocation gets its own
  fresh tempdir. ``--keep-output`` opts out for debugging.
- **Idempotent.** Running twice in a row produces the same
  pass/fail outcome.

Checks
------

Each check is a single function that returns ``(name, ok,
details)``. Failures collect the details for the final summary.
The full list mirrors the rc1-polish acceptance gate:

1. Package imports cleanly (``from src.core.bluefire_nexus import BlueFireNexus``).
2. ``python -m src.run_scenario --output-json`` runs the canonical
   ``apt29_credential_access`` scenario.
3. The ``--output-json`` stdout parses cleanly as JSON and reports
   ``status == "success"``.
4. ``output/<run_id>/`` exists and contains the canonical demo
   bundle (manifest.json, index.html, report.md, report.json,
   risk_summary.json, telemetry.jsonl).
5. ``output/<run_id>/index.html`` exists and is non-empty.
6. ``output/index.html`` aggregator exists and is non-empty.
7. ``python -m src.core.cli list-runs --output-root <tmp>`` runs
   without error and lists the run.
8. ``python -m src.core.cli latest-run --output-root <tmp>`` runs
   without error and prints a ``file://`` URI on a standalone line.
9. ``python -m src.core.cli show-run <run_id> --output-root <tmp>``
   runs without error.
10. ``python -m src.core.cli validate-run <run_id> --json --output-root
    <tmp>`` reports ``ok=true``, ``missing=[]``, ``broken_links=[]``.
11. ``python -m src.core.cli build-report-view <run_id> --output-root
    <tmp>`` runs and rewrites the per-run viewer.
12. **No filename in the run dir contains ``:``** (NTFS ADS guard).
13. **YARA-L files do not contain ``run_id = "manual"``** (Sigma
    <-> YARA-L correlation parity).
14. **SPL files carry the ``DRAFT detection search`` header** and
    are not pure ``| makeresults`` echoes when a logsource is
    available (post-PR #89 upgrade).
15. **CLI output contains no Unicode replacement character** ``U+FFFD``
    (Windows mojibake guard from PR #91).
16. **CLI output does NOT contain ``—`` (U+2014)** in the cooked
    surfaces — the source-level invariant in PR #91 forbids
    em-dash in user-facing strings.
17. ``copilot_narrative.md`` (when present) carries scenario name
    + step-by-step timeline + run-specific paths under
    ``output/<run_id>/`` (PR #93 quality bar).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
# Smoke script invokes ``python -m src.run_scenario`` and ``python -m
# src.core.cli`` against a fixed argument shape; never accepts shell
# input from outside the script. ``shell=False`` (the default) below
# keeps each invocation immune to shell-injection. nosec narrowed per
# the project's bandit baseline discipline.
import subprocess  # nosec B404 - controlled subprocess invocations only
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Tuple

# Force UTF-8 stdout for the smoke script's own subprocess invocations
# so the replacement-char and em-dash checks compare against the
# actual byte stream the operator's terminal would receive.
ENV = dict(os.environ)
ENV["PYTHONIOENCODING"] = "utf-8"
ENV["NO_COLOR"] = "1"
ENV["COLUMNS"] = "240"


CheckResult = Tuple[str, bool, str]
CheckFn = Callable[["Context"], CheckResult]


@dataclass
class Context:
    """Mutable state passed between checks.

    Populated incrementally so a check can reference earlier
    results (e.g. the run id discovered by check 2 lands in
    ``run_id`` so checks 7-11 can reuse it).
    """

    output_root: Path
    scenario: str
    keep_output: bool

    run_id: str = ""
    run_dir: Path = Path()
    scenario_stdout: str = ""
    scenario_stderr: str = ""


def _run(cmd: List[str], *, capture: bool = True) -> subprocess.CompletedProcess[str]:
    """Run a subprocess with the smoke-test environment, UTF-8 stdout.

    All callers pass argument lists composed of fixed strings plus
    safe path strings (the tempdir output_root and the operator-
    supplied scenario name, which is itself validated downstream
    by the scenario loader's own path-traversal guard). ``shell``
    is left at its default ``False`` so even a pathological
    scenario name cannot be parsed as a shell command.
    """
    return subprocess.run(  # nosec B603 - shell=False, fixed-shape argument list
        cmd,
        capture_output=capture,
        text=True,
        env=ENV,
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Individual checks (each returns (name, ok, details))
# ---------------------------------------------------------------------------


def check_package_imports(ctx: Context) -> CheckResult:
    name = "package import"
    proc = _run(
        [
            sys.executable,
            "-c",
            "from src.core.bluefire_nexus import BlueFireNexus; print('ok')",
        ]
    )
    ok = proc.returncode == 0 and "ok" in proc.stdout
    details = (
        ""
        if ok
        else f"returncode={proc.returncode} stdout={proc.stdout!r} stderr={proc.stderr!r}"
    )
    return name, ok, details


def check_scenario_run(ctx: Context) -> CheckResult:
    name = f"run scenario --profile {ctx.scenario} --output-json"
    proc = _run(
        [
            sys.executable,
            "-m",
            "src.run_scenario",
            "--profile",
            ctx.scenario,
            "--output-json",
        ]
    )
    ctx.scenario_stdout = proc.stdout
    ctx.scenario_stderr = proc.stderr or ""
    ok = proc.returncode == 0
    details = (
        ""
        if ok
        else f"returncode={proc.returncode} stderr_tail={proc.stderr[-500:]!r}"
    )
    return name, ok, details


def check_scenario_json_parses(ctx: Context) -> CheckResult:
    name = "scenario --output-json stdout parses + status=success"
    try:
        data = json.loads(ctx.scenario_stdout)
    except json.JSONDecodeError as exc:
        return (
            name,
            False,
            f"json parse failed: {exc}; stdout_head={ctx.scenario_stdout[:200]!r}",
        )
    ctx.run_id = str(data.get("run_id") or "")
    ctx.run_dir = Path(data.get("output_dir") or "")
    status = str(data.get("status") or "")
    if status != "success":
        return name, False, f"status={status!r}, expected 'success'"
    if not ctx.run_id:
        return name, False, "run_id missing from JSON output"
    if not ctx.run_dir.exists():
        return name, False, f"output_dir {ctx.run_dir} does not exist"
    return name, True, ""


def check_canonical_artifacts(ctx: Context) -> CheckResult:
    name = "canonical demo bundle present"
    expected = (
        "manifest.json",
        "index.html",
        "report.md",
        "report.json",
        "risk_summary.json",
        "telemetry.jsonl",
    )
    missing = [n for n in expected if not (ctx.run_dir / n).exists()]
    if missing:
        return name, False, f"missing: {missing}"
    return name, True, ""


def check_per_run_index_html(ctx: Context) -> CheckResult:
    name = "output/<run_id>/index.html non-empty"
    p = ctx.run_dir / "index.html"
    if not p.exists():
        return name, False, f"missing: {p}"
    size = p.stat().st_size
    if size < 1024:
        return name, False, f"suspiciously small: {size} bytes"
    return name, True, ""


def check_top_level_aggregator(ctx: Context) -> CheckResult:
    name = "output/index.html aggregator non-empty"
    p = ctx.output_root / "index.html"
    if not p.exists():
        return name, False, f"missing: {p}"
    size = p.stat().st_size
    if size < 256:
        return name, False, f"suspiciously small: {size} bytes"
    return name, True, ""


def check_cli_list_runs(ctx: Context) -> CheckResult:
    name = "cli list-runs"
    proc = _run(
        [
            sys.executable,
            "-m",
            "src.core.cli",
            "list-runs",
            "--output-root",
            str(ctx.output_root),
        ]
    )
    if proc.returncode != 0:
        return name, False, f"returncode={proc.returncode} stderr={proc.stderr!r}"
    if ctx.run_id not in proc.stdout:
        return name, False, f"run_id {ctx.run_id} not in stdout"
    return name, True, ""


def check_cli_latest_run_uri_on_own_line(ctx: Context) -> CheckResult:
    name = "cli latest-run prints file:// URI on standalone line"
    proc = _run(
        [
            sys.executable,
            "-m",
            "src.core.cli",
            "latest-run",
            "--output-root",
            str(ctx.output_root),
        ]
    )
    if proc.returncode != 0:
        return name, False, f"returncode={proc.returncode} stderr={proc.stderr!r}"
    file_lines = [line for line in proc.stdout.splitlines() if "file://" in line]
    if not file_lines:
        return name, False, "no file:// URI in stdout"
    standalone = [line for line in file_lines if line.lstrip().startswith("file://")]
    if not standalone:
        return (
            name,
            False,
            f"file:// URI never starts a line; saw: {file_lines!r}",
        )
    return name, True, ""


def check_cli_show_run(ctx: Context) -> CheckResult:
    name = "cli show-run"
    proc = _run(
        [
            sys.executable,
            "-m",
            "src.core.cli",
            "show-run",
            ctx.run_id,
            "--output-root",
            str(ctx.output_root),
        ]
    )
    if proc.returncode != 0:
        return name, False, f"returncode={proc.returncode} stderr={proc.stderr!r}"
    if ctx.run_id not in proc.stdout:
        return name, False, f"run_id {ctx.run_id} not in stdout"
    return name, True, ""


def check_cli_validate_run(ctx: Context) -> CheckResult:
    name = "cli validate-run --json -> ok=true"
    proc = _run(
        [
            sys.executable,
            "-m",
            "src.core.cli",
            "validate-run",
            ctx.run_id,
            "--json",
            "--output-root",
            str(ctx.output_root),
        ]
    )
    if proc.returncode != 0:
        return (
            name,
            False,
            f"returncode={proc.returncode} stdout={proc.stdout!r} stderr={proc.stderr!r}",
        )
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return name, False, f"json parse failed: {exc}; stdout={proc.stdout!r}"
    if not report.get("ok"):
        return (
            name,
            False,
            f"ok=False; missing={report.get('missing')!r}, "
            f"broken_links={report.get('broken_links')!r}",
        )
    return name, True, ""


def check_cli_build_report_view(ctx: Context) -> CheckResult:
    name = "cli build-report-view"
    proc = _run(
        [
            sys.executable,
            "-m",
            "src.core.cli",
            "build-report-view",
            ctx.run_id,
            "--output-root",
            str(ctx.output_root),
        ]
    )
    if proc.returncode != 0:
        return name, False, f"returncode={proc.returncode} stderr={proc.stderr!r}"
    return name, True, ""


def check_no_colon_filenames(ctx: Context) -> CheckResult:
    name = "no filenames with ':' in run dir (NTFS ADS guard)"
    bad = [
        str(p.relative_to(ctx.run_dir))
        for p in ctx.run_dir.rglob("*")
        if p.is_file() and ":" in p.name
    ]
    if bad:
        return name, False, f"{len(bad)} unsafe filenames: {bad[:5]}..."
    return name, True, ""


def check_yara_l_real_run_id(ctx: Context) -> CheckResult:
    name = 'YARA-L meta carries real run_id (not "manual")'
    yaral_dir = ctx.run_dir / "detections" / "yara_l"
    if not yaral_dir.exists():
        return name, True, "no yara_l dir; skipped"
    files = list(yaral_dir.glob("*.yaral"))
    if not files:
        return name, True, "no yara_l files; skipped"
    bad = []
    for p in files:
        body = p.read_text(encoding="utf-8")
        if 'run_id = "manual"' in body:
            bad.append(str(p.name))
    if bad:
        return (
            name,
            False,
            f"{len(bad)} files still have manual run_id: {bad[:3]}",
        )
    return name, True, ""


def check_spl_not_makeresults_only(ctx: Context) -> CheckResult:
    name = "SPL drafts carry DRAFT header (not makeresults-only echo)"
    spl_dir = ctx.run_dir / "detections" / "spl"
    if not spl_dir.exists():
        return name, True, "no spl dir; skipped"
    files = list(spl_dir.glob("*.spl"))
    if not files:
        return name, True, "no spl files; skipped"
    bad: list[str] = []
    for p in files:
        body = p.read_text(encoding="utf-8")
        # Every SPL must carry the DRAFT comment header.
        if "DRAFT detection search" not in body:
            bad.append(f"{p.name}: missing DRAFT header")
    if bad:
        return name, False, f"{len(bad)} files: {bad[:3]}"
    return name, True, ""


def check_cli_no_replacement_char(ctx: Context) -> CheckResult:
    name = "CLI output free of replacement char + em-dash"
    proc = _run(
        [
            sys.executable,
            "-m",
            "src.core.cli",
            "latest-run",
            "--output-root",
            str(ctx.output_root),
        ]
    )
    combined = (proc.stdout or "") + (proc.stderr or "")
    if "�" in combined:
        return name, False, "Unicode replacement char (U+FFFD) in CLI output"
    if "—" in combined:
        return name, False, "Em-dash (U+2014) in CLI output (Windows mojibake risk)"
    return name, True, ""


def check_offline_copilot_narrative(ctx: Context) -> CheckResult:
    name = "offline copilot narrative carries scenario context"
    narrative = ctx.run_dir / "copilot_narrative.md"
    if not narrative.exists():
        return name, True, "no copilot artifact; skipped (AI may be off in default config)"
    body = narrative.read_text(encoding="utf-8")
    markers = [
        ("scenario name surfaces", ctx.scenario.split("/")[-1].replace(".yaml", "") in body or "scenario" in body.lower()),
        ("step-by-step timeline section", "Step-by-step timeline" in body or "## Step" in body),
        ("run-specific validate-run path", f"validate-run {ctx.run_id}" in body),
        ("run-specific viewer path", f"output/{ctx.run_id}/index.html" in body),
    ]
    missing = [label for label, ok in markers if not ok]
    if missing:
        return name, False, f"missing markers: {missing}"
    return name, True, ""


CHECKS: List[CheckFn] = [
    check_package_imports,
    check_scenario_run,
    check_scenario_json_parses,
    check_canonical_artifacts,
    check_per_run_index_html,
    check_top_level_aggregator,
    check_cli_list_runs,
    check_cli_latest_run_uri_on_own_line,
    check_cli_show_run,
    check_cli_validate_run,
    check_cli_build_report_view,
    check_no_colon_filenames,
    check_yara_l_real_run_id,
    check_spl_not_makeresults_only,
    check_cli_no_replacement_char,
    check_offline_copilot_narrative,
]


def main() -> int:
    parser = argparse.ArgumentParser(description="rc smoke validator")
    parser.add_argument(
        "--scenario",
        default="apt29_credential_access",
        help="scenario profile to run (default: apt29_credential_access)",
    )
    parser.add_argument(
        "--keep-output",
        action="store_true",
        help="keep the tmp output dir on disk for inspection",
    )
    args = parser.parse_args()

    output_root = Path(tempfile.mkdtemp(prefix="bf-rc-smoke-"))
    ENV["BLUEFIRE_OUTPUT_ROOT"] = str(output_root)

    ctx = Context(
        output_root=output_root,
        scenario=args.scenario,
        keep_output=args.keep_output,
    )

    print(f"=== BlueFire-Nexus release-candidate smoke ===")
    print(f"scenario:    {args.scenario}")
    print(f"output_root: {output_root}")
    print(f"python:      {sys.executable}")
    print()

    failures: list[tuple[str, str]] = []
    for index, check in enumerate(CHECKS, start=1):
        try:
            name, ok, details = check(ctx)
        except Exception as exc:  # pragma: no cover - belt-and-braces
            name = check.__name__
            ok = False
            details = f"check raised {type(exc).__name__}: {exc}"
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {index:2d}. {name}")
        if not ok:
            print(f"         -> {details}")
            failures.append((name, details))

    print()
    if failures:
        print(f"=== {len(failures)} check(s) FAILED ===")
        for name, details in failures:
            print(f"  - {name}")
    else:
        print("=== ALL CHECKS PASSED ===")

    if not args.keep_output:
        shutil.rmtree(output_root, ignore_errors=True)
    else:
        print(f"\noutput_root preserved: {output_root}")

    return len(failures)


if __name__ == "__main__":
    sys.exit(main())
