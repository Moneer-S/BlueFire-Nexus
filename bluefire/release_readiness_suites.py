"""Source-preserving full-suite execution for GATE-12."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Mapping, Sequence

from .product_acceptance_process import _playwright_browsers_path
from .release_readiness_validation import SBOM_REPORT, SUITE_SCHEMA

_MAX_OUTPUT_BYTES = 16 * 1024 * 1024


def _base_environment(temporary: Path) -> dict[str, str]:
    environment = dict(os.environ)
    browser_root = _playwright_browsers_path(environment)
    home = temporary / "home"
    local = home / "AppData" / "Local"
    roaming = home / "AppData" / "Roaming"
    local.mkdir(parents=True)
    roaming.mkdir(parents=True)
    environment.update(
        {
            "APPDATA": os.fspath(roaming),
            "BLACK_CACHE_DIR": os.fspath(temporary / "black-cache"),
            "CI": "1",
            "HOME": os.fspath(home),
            "LOCALAPPDATA": os.fspath(local),
            "NO_COLOR": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPYCACHEPREFIX": os.fspath(temporary / "pycache"),
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "MYPY_CACHE_DIR": os.fspath(temporary / "mypy-cache"),
            "RUFF_CACHE_DIR": os.fspath(temporary / "ruff-cache"),
            "TEMP": os.fspath(temporary),
            "TMP": os.fspath(temporary),
            "TMPDIR": os.fspath(temporary),
            "USERPROFILE": os.fspath(home),
        }
    )
    if browser_root is not None:
        environment["PLAYWRIGHT_BROWSERS_PATH"] = os.fspath(browser_root)
    return environment


def _run(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
) -> tuple[int | None, bytes, bytes]:
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            completed = subprocess.run(
                list(command),
                cwd=cwd,
                env=dict(environment),
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                check=False,
                timeout=timeout_seconds,
            )
            outputs: list[bytes] = []
            for stream in (stdout, stderr):
                stream.flush()
                stream.seek(0, os.SEEK_END)
                if stream.tell() > _MAX_OUTPUT_BYTES:
                    return completed.returncode, b"", b"output-limit-exceeded"
                stream.seek(0)
                outputs.append(stream.read(_MAX_OUTPUT_BYTES + 1))
        return completed.returncode, outputs[0], outputs[1]
    except (OSError, subprocess.TimeoutExpired):
        return None, b"", b"process-unavailable-or-timed-out"


def _row(
    suite_id: str,
    command: Sequence[str],
    exit_code: int | None,
    *,
    passed_ids: Sequence[str] = (),
    skipped_ids: Sequence[str] = (),
    details: Mapping[str, Any] | None = None,
    passed: bool | None = None,
) -> dict[str, Any]:
    passed_tests = sorted(set(passed_ids))
    skipped_tests = sorted(set(skipped_ids))
    return {
        "suite_id": suite_id,
        "command": list(command),
        "exit_code": exit_code,
        "passed": exit_code == 0 if passed is None else passed,
        "test_count": len(passed_tests) + len(skipped_tests),
        "passed_test_ids": passed_tests,
        "skipped_test_ids": skipped_tests,
        "details": dict(details or {}),
    }


def _tracked_snapshot(repository: Path) -> dict[str, str]:
    completed = subprocess.run(
        ["git", "-C", os.fspath(repository), "ls-files", "-z"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        return {}
    result: dict[str, str] = {}
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            relative = raw.decode("utf-8", "strict")
            payload = (repository / relative).read_bytes()
        except (OSError, UnicodeError):
            return {}
        result[relative] = hashlib.sha256(payload).hexdigest()
    return result


def _archive_source(repository: Path, destination: Path, environment: Mapping[str, str]) -> bool:
    destination.mkdir(parents=True, exist_ok=False)
    archive = destination / "source.tar"
    code, _stdout, _stderr = _run(
        ["git", "archive", "--format=tar", f"--output={archive}", "HEAD"],
        cwd=repository,
        environment=environment,
        timeout_seconds=120,
    )
    if code != 0 or not archive.is_file():
        return False
    source = destination / "source"
    source.mkdir()
    try:
        with tarfile.open(archive, "r:") as handle:
            for member in handle.getmembers():
                path = Path(member.name)
                if (
                    not path.parts
                    or path.is_absolute()
                    or ".." in path.parts
                    or not (member.isdir() or member.isfile())
                ):
                    return False
            for member in handle.getmembers():
                path = Path(member.name)
                target = source.joinpath(*path.parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                extracted = handle.extractfile(member)
                if extracted is None:
                    return False
                with extracted, target.open("xb") as output:
                    shutil.copyfileobj(extracted, output, length=1024 * 1024)
    except (OSError, tarfile.TarError, TypeError, ValueError):
        return False
    return True


def _junit(path: Path) -> tuple[list[str], list[str], list[str]]:
    try:
        root = ET.parse(path).getroot()  # nosec B314 - locally generated by pytest
    except (OSError, ET.ParseError):
        return [], [], ["junit-unavailable"]
    passed: list[str] = []
    skipped: list[str] = []
    failed: list[str] = []
    for case in root.iter("testcase"):
        identity = f"{case.get('classname', '')}::{case.get('name', '')}".strip(":")
        if case.find("failure") is not None or case.find("error") is not None:
            failed.append(identity)
        elif case.find("skipped") is not None:
            skipped.append(identity)
        else:
            passed.append(identity)
    return sorted(passed), sorted(skipped), sorted(failed)


def _python_suites(
    repository: Path,
    temporary: Path,
    environment: Mapping[str, str],
) -> list[dict[str, Any]]:
    temporary.mkdir(parents=True, exist_ok=False)
    rows: list[dict[str, Any]] = []
    archived = _archive_source(repository, temporary / "archive", environment)
    archive_root = temporary / "archive" / "source"
    compile_command = [
        "{python}",
        "-m",
        "compileall",
        "-q",
        "-f",
        "bluefire",
        "tests_platform",
        "tools",
    ]
    if archived:
        code, _stdout, _stderr = _run(
            [
                sys.executable,
                "-m",
                "compileall",
                "-q",
                "-f",
                "bluefire",
                "tests_platform",
                "tools",
            ],
            cwd=archive_root,
            environment=environment,
            timeout_seconds=300,
        )
    else:
        code = None
    rows.append(
        _row("python.compile", compile_command, code, details={"committed_archive": archived})
    )

    pytest_environment = dict(environment)
    packaged_runner = (
        repository
        / "bluefire"
        / "native"
        / ("bluefire-runner.exe" if os.name == "nt" else "linux-x86_64/bluefire-runner")
    )
    if packaged_runner.is_file():
        pytest_environment["BLUEFIRE_E2E_RUNNER"] = os.fspath(packaged_runner.resolve())
    junit = temporary / "python-full.xml"
    code, _stdout, _stderr = _run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-q",
            f"--basetemp={temporary / 'pytest-temp'}",
            f"--junitxml={junit}",
        ],
        cwd=repository,
        environment=pytest_environment,
        timeout_seconds=1800,
    )
    passed, skipped, failed = _junit(junit)
    rows.append(
        _row(
            "python.pytest",
            ["{python}", "-m", "pytest", "-p", "no:cacheprovider", "-q"],
            code,
            passed_ids=passed,
            skipped_ids=skipped,
            details={"failed_test_ids": failed, "packaged_runner_bound": packaged_runner.is_file()},
            passed=code == 0 and bool(passed) and not failed,
        )
    )
    for suite_id, arguments, timeout in (
        ("python.ruff", ("ruff", "check", "bluefire", "tests_platform"), 300),
        ("python.black", ("black", "--check", "bluefire", "tests_platform"), 300),
        ("python.mypy", ("mypy", "bluefire"), 600),
    ):
        code, _stdout, _stderr = _run(
            [sys.executable, "-m", *arguments],
            cwd=repository,
            environment=environment,
            timeout_seconds=timeout,
        )
        rows.append(
            _row(
                suite_id,
                ["{python}", "-m", *arguments],
                code,
                details={"output_bounded": True},
            )
        )
    return rows


def _rust_test_ids(output: bytes) -> list[str]:
    result: list[str] = []
    for line in output.decode("utf-8", "replace").splitlines():
        normalized = line.strip()
        if normalized.endswith(": test") and len(normalized) <= 512:
            result.append(normalized.removesuffix(": test"))
    return sorted(set(result))


def _rust_suites(
    repository: Path,
    temporary: Path,
    environment: Mapping[str, str],
) -> tuple[list[dict[str, Any]], Mapping[str, Any]]:
    temporary.mkdir(parents=True, exist_ok=False)
    cargo_raw = shutil.which("cargo", path=environment.get("PATH"))
    toolchain: dict[str, Any] = {"cargo_available": cargo_raw is not None}
    commands = {
        "rust.fmt": ["fmt", "--manifest-path", "runner/Cargo.toml", "--", "--check"],
        "rust.clippy": [
            "clippy",
            "--locked",
            "--manifest-path",
            "runner/Cargo.toml",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
        "rust.test": ["test", "--locked", "--manifest-path", "runner/Cargo.toml", "--all"],
        "rust.release": [
            "build",
            "--locked",
            "--release",
            "--manifest-path",
            "runner/Cargo.toml",
            "--bin",
            "bluefire-runner",
        ],
    }
    if cargo_raw is None:
        return (
            [
                _row(
                    suite_id,
                    ["{cargo}", *arguments],
                    None,
                    details={"reason": "pinned-cargo-unavailable"},
                    passed=False,
                )
                for suite_id, arguments in commands.items()
            ],
            toolchain,
        )
    cargo = Path(cargo_raw).resolve(strict=True)
    rust_environment = dict(environment)
    rust_environment.update(
        {
            "CARGO_TARGET_DIR": os.fspath(temporary / "cargo-target"),
            "CARGO_INCREMENTAL": "0",
        }
    )
    version_code, version_out, _version_err = _run(
        [os.fspath(cargo), "--version", "--verbose"],
        cwd=repository,
        environment=rust_environment,
        timeout_seconds=30,
    )
    toolchain["cargo_version_verified"] = version_code == 0 and b"cargo" in version_out
    rows: list[dict[str, Any]] = []
    test_ids: list[str] = []
    list_code, list_out, _list_err = _run(
        [os.fspath(cargo), *commands["rust.test"], "--", "--list"],
        cwd=repository,
        environment=rust_environment,
        timeout_seconds=600,
    )
    if list_code == 0:
        test_ids = _rust_test_ids(list_out)
    for suite_id, arguments in commands.items():
        code, _stdout, _stderr = _run(
            [os.fspath(cargo), *arguments],
            cwd=repository,
            environment=rust_environment,
            timeout_seconds=1200 if suite_id in {"rust.test", "rust.release"} else 600,
        )
        rows.append(
            _row(
                suite_id,
                ["{cargo}", *arguments],
                code,
                passed_ids=test_ids if suite_id == "rust.test" else (),
                details={
                    "locked": suite_id != "rust.fmt",
                    "external_target": True,
                    "listed_tests": len(test_ids) if suite_id == "rust.test" else 0,
                },
                passed=(code == 0 and bool(test_ids)) if suite_id == "rust.test" else code == 0,
            )
        )
    return rows, toolchain


def _vitest_ids(value: Any, frontend: Path) -> list[str]:
    if not isinstance(value, Mapping) or not isinstance(value.get("testResults"), list):
        return []
    result: list[str] = []
    for file_result in value["testResults"]:
        if not isinstance(file_result, Mapping) or not isinstance(
            file_result.get("assertionResults"), list
        ):
            return []
        try:
            relative = (
                Path(str(file_result["name"]))
                .resolve(strict=True)
                .relative_to(frontend.resolve(strict=True))
            )
        except (KeyError, OSError, ValueError):
            return []
        for assertion in file_result["assertionResults"]:
            if (
                not isinstance(assertion, Mapping)
                or assertion.get("status") != "passed"
                or not isinstance(assertion.get("title"), str)
                or not isinstance(assertion.get("ancestorTitles"), list)
            ):
                return []
            parts = [
                relative.as_posix(),
                *[str(item) for item in assertion["ancestorTitles"]],
                str(assertion["title"]),
            ]
            result.append("::".join(parts))
    return sorted(set(result))


def _playwright_ids(value: Any) -> tuple[list[str], list[str], list[str]]:
    passed: list[str] = []
    skipped: list[str] = []
    failed: list[str] = []

    def visit(item: Any, titles: tuple[str, ...] = ()) -> None:
        if not isinstance(item, Mapping):
            return
        title = item.get("title")
        current = titles + ((str(title),) if isinstance(title, str) and title else ())
        specs = item.get("specs")
        if isinstance(specs, list):
            for spec in specs:
                if not isinstance(spec, Mapping):
                    continue
                spec_title = spec.get("title")
                tests = spec.get("tests")
                if not isinstance(spec_title, str) or not isinstance(tests, list):
                    continue
                for test in tests:
                    if not isinstance(test, Mapping):
                        continue
                    project = test.get("projectName")
                    results = test.get("results")
                    identity = "::".join((*current, spec_title, str(project or "default")))
                    statuses = (
                        [row.get("status") for row in results if isinstance(row, Mapping)]
                        if isinstance(results, list)
                        else []
                    )
                    if statuses and statuses[-1] == "passed":
                        passed.append(identity)
                    elif statuses and statuses[-1] == "skipped":
                        skipped.append(identity)
                    else:
                        failed.append(identity)
        suites = item.get("suites")
        if isinstance(suites, list):
            for child in suites:
                visit(child, current)

    visit(value)
    return sorted(set(passed)), sorted(set(skipped)), sorted(set(failed))


def _ui_digest(root: Path) -> Mapping[str, str]:
    expected = {"index.html", "app.js", "styles.css"}
    try:
        entries = {item.name: item for item in root.iterdir() if item.is_file()}
    except OSError:
        return {}
    if set(entries) != expected:
        return {}
    return {
        name: "sha256:" + hashlib.sha256(entries[name].read_bytes()).hexdigest()
        for name in sorted(entries)
    }


def _playwright_config(frontend: Path, temporary: Path, report: Path) -> Path:
    config = temporary / "playwright.release.cjs"
    module = frontend / "node_modules/@playwright/test/index.js"
    test_dir = frontend / "tests/e2e"
    setup = frontend / "tests/global-setup.ts"
    output = temporary / "playwright-output"
    text = f"""
const {{ defineConfig, devices }} = require({json.dumps(os.fspath(module))});
module.exports = defineConfig({{
  testDir: {json.dumps(os.fspath(test_dir))},
  testMatch: ["app.spec.ts", "builder-runs.spec.ts", "management.spec.ts"],
  globalSetup: {json.dumps(os.fspath(setup))},
  timeout: 30000,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: true,
  reporter: [["json", {{ outputFile: {json.dumps(os.fspath(report))} }}]],
  outputDir: {json.dumps(os.fspath(output))},
  use: {{
    baseURL: "http://127.0.0.1:5173/ui/",
    trace: "off",
    screenshot: "off",
    video: "off"
  }},
  projects: [{{ name: "chromium", use: {{ ...devices["Desktop Chrome"] }} }}]
}});
""".strip()
    config.write_text(text + "\n", encoding="utf-8")
    return config


def _frontend_suites(
    repository: Path,
    temporary: Path,
    environment: Mapping[str, str],
) -> list[dict[str, Any]]:
    temporary.mkdir(parents=True, exist_ok=False)
    frontend = repository / "frontend"
    node_raw = shutil.which("node", path=environment.get("PATH"))
    binaries = {
        "tsc": frontend / "node_modules/typescript/bin/tsc",
        "eslint": frontend / "node_modules/eslint/bin/eslint.js",
        "vitest": frontend / "node_modules/vitest/vitest.mjs",
        "vite": frontend / "node_modules/vite/bin/vite.js",
        "playwright": frontend / "node_modules/@playwright/test/cli.js",
    }
    if node_raw is None or any(not path.is_file() for path in binaries.values()):
        return [
            _row(
                suite_id,
                ["{node}", "{frontend-tool}"],
                None,
                details={"reason": "frontend-toolchain-unavailable"},
                passed=False,
            )
            for suite_id in (
                "frontend.typecheck",
                "frontend.lint",
                "frontend.unit",
                "frontend.build-parity",
                "frontend.e2e-demo",
            )
        ]
    node = Path(node_raw).resolve(strict=True)
    rows: list[dict[str, Any]] = []
    app_code, _stdout, _stderr = _run(
        [
            os.fspath(node),
            os.fspath(binaries["tsc"]),
            "--noEmit",
            "-p",
            "tsconfig.app.json",
            "--pretty",
            "false",
        ],
        cwd=frontend,
        environment=environment,
        timeout_seconds=300,
    )
    node_code, _stdout, _stderr = _run(
        [
            os.fspath(node),
            os.fspath(binaries["tsc"]),
            "--noEmit",
            "-p",
            "tsconfig.node.json",
            "--pretty",
            "false",
            "--tsBuildInfoFile",
            os.fspath(temporary / "tsconfig.node.tsbuildinfo"),
        ],
        cwd=frontend,
        environment=environment,
        timeout_seconds=300,
    )
    rows.append(
        _row(
            "frontend.typecheck",
            ["{node}", "typescript/bin/tsc", "--noEmit", "{app-and-node-projects}"],
            0 if app_code == node_code == 0 else (app_code if app_code else node_code),
            details={
                "app_exit_code": app_code,
                "node_exit_code": node_code,
                "external_build_info": True,
            },
            passed=app_code == node_code == 0,
        )
    )
    lint_code, _stdout, _stderr = _run(
        [os.fspath(node), os.fspath(binaries["eslint"]), ".", "--max-warnings", "0"],
        cwd=frontend,
        environment=environment,
        timeout_seconds=300,
    )
    rows.append(
        _row(
            "frontend.lint",
            ["{node}", "eslint/bin/eslint.js", ".", "--max-warnings", "0"],
            lint_code,
            details={"output_bounded": True},
        )
    )
    unit_code, unit_stdout, _unit_stderr = _run(
        [
            os.fspath(node),
            os.fspath(binaries["vitest"]),
            "run",
            "--configLoader",
            "runner",
            "--no-cache",
            "--reporter=json",
        ],
        cwd=frontend,
        environment=environment,
        timeout_seconds=600,
    )
    try:
        unit_value = json.loads(unit_stdout.decode("utf-8")) if unit_code == 0 else None
    except (UnicodeError, json.JSONDecodeError):
        unit_value = None
    unit_ids = _vitest_ids(unit_value, frontend)
    rows.append(
        _row(
            "frontend.unit",
            ["{node}", "vitest/vitest.mjs", "run", "--no-cache", "--reporter=json"],
            unit_code,
            passed_ids=unit_ids,
            details={"exact_report_parsed": bool(unit_ids)},
            passed=unit_code == 0 and bool(unit_ids),
        )
    )
    production_output = temporary / "production-ui"
    production_environment = dict(environment)
    production_environment["VITE_DEMO_MODE"] = "false"
    build_code, _stdout, _stderr = _run(
        [
            os.fspath(node),
            os.fspath(binaries["vite"]),
            "build",
            "--configLoader",
            "runner",
            "--mode",
            "production",
            "--outDir",
            os.fspath(production_output),
            "--emptyOutDir",
        ],
        cwd=frontend,
        environment=production_environment,
        timeout_seconds=600,
    )
    generated = _ui_digest(production_output) if build_code == 0 else {}
    committed = _ui_digest(repository / "bluefire/ui")
    parity = bool(generated) and generated == committed
    rows.append(
        _row(
            "frontend.build-parity",
            ["{node}", "vite/bin/vite.js", "build", "--outDir", "{temporary}"],
            build_code,
            details={"asset_digests": generated, "committed_assets_match": parity},
            passed=build_code == 0 and parity,
        )
    )
    demo_output = temporary / "dist"
    demo_environment = dict(environment)
    demo_environment["VITE_DEMO_MODE"] = "true"
    demo_build, _stdout, _stderr = _run(
        [
            os.fspath(node),
            os.fspath(binaries["vite"]),
            "build",
            "--configLoader",
            "runner",
            "--mode",
            "demo",
            "--outDir",
            os.fspath(demo_output),
            "--emptyOutDir",
        ],
        cwd=frontend,
        environment=demo_environment,
        timeout_seconds=600,
    )
    browser_report = temporary / "playwright.json"
    config = _playwright_config(frontend, temporary, browser_report)
    if demo_build == 0:
        e2e_code, _stdout, _stderr = _run(
            [
                os.fspath(node),
                os.fspath(binaries["playwright"]),
                "test",
                "--config",
                os.fspath(config),
                "--project=chromium",
            ],
            cwd=temporary,
            environment=demo_environment,
            timeout_seconds=900,
        )
    else:
        e2e_code = None
    try:
        browser_value = json.loads(browser_report.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        browser_value = None
    e2e_passed, e2e_skipped, e2e_failed = _playwright_ids(browser_value)
    rows.append(
        _row(
            "frontend.e2e-demo",
            [
                "{node}",
                "playwright/test/cli.js",
                "test",
                "{non-production-specs}",
                "--project=chromium",
            ],
            e2e_code,
            passed_ids=e2e_passed,
            skipped_ids=e2e_skipped,
            details={"failed_test_ids": e2e_failed, "external_build_output": True},
            passed=e2e_code == 0 and bool(e2e_passed) and not e2e_failed,
        )
    )
    return rows


def _security_suites(
    repository: Path,
    evidence_dir: Path,
    temporary: Path,
    environment: Mapping[str, str],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    gitleaks = shutil.which("gitleaks", path=environment.get("PATH"))
    if gitleaks:
        code, _stdout, _stderr = _run(
            [gitleaks, "git", "--redact", "--no-banner", "."],
            cwd=repository,
            environment=environment,
            timeout_seconds=600,
        )
    else:
        code = None
    rows.append(
        _row(
            "security.gitleaks",
            ["{gitleaks}", "git", "--redact", "--no-banner", "."],
            code,
            details={"history_and_worktree": True, "tool_available": gitleaks is not None},
        )
    )
    tracked_process = subprocess.run(
        ["git", "-C", os.fspath(repository), "ls-files", "-z"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=30,
    )
    tracked = (
        [item.decode("utf-8", "strict") for item in tracked_process.stdout.split(b"\0") if item]
        if tracked_process.returncode == 0
        else []
    )
    if tracked:
        code, _stdout, _stderr = _run(
            [
                sys.executable,
                "-m",
                "detect_secrets.pre_commit_hook",
                "--baseline",
                ".secrets.baseline",
                *tracked,
            ],
            cwd=repository,
            environment=environment,
            timeout_seconds=600,
        )
    else:
        code = None
    rows.append(
        _row(
            "security.detect-secrets",
            [
                "{python}",
                "-m",
                "detect_secrets.pre_commit_hook",
                "--baseline",
                ".secrets.baseline",
                "{tracked-files}",
            ],
            code,
            details={"tracked_files": len(tracked)},
        )
    )
    for suite_id, arguments, timeout in (
        ("security.bandit", ("bandit", "-r", "bluefire", "-ll"), 600),
        (
            "security.pip-audit",
            ("pip_audit", "--ignore-vuln", "PYSEC-2026-2447"),
            900,
        ),
    ):
        code, _stdout, _stderr = _run(
            [sys.executable, "-m", *arguments],
            cwd=repository,
            environment=environment,
            timeout_seconds=timeout,
        )
        rows.append(
            _row(
                suite_id,
                ["{python}", "-m", *arguments],
                code,
                details={
                    "reviewed_exceptions": (
                        ["PYSEC-2026-2447"] if suite_id.endswith("pip-audit") else []
                    )
                },
            )
        )
    sbom_path = evidence_dir / SBOM_REPORT
    code, _stdout, _stderr = _run(
        [
            sys.executable,
            "-m",
            "cyclonedx_py",
            "environment",
            "--output-file",
            os.fspath(sbom_path),
        ],
        cwd=repository,
        environment=environment,
        timeout_seconds=600,
    )
    sbom_valid = False
    try:
        sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
        sbom_valid = isinstance(sbom, Mapping) and isinstance(sbom.get("components"), list)
    except (OSError, UnicodeError, json.JSONDecodeError):
        pass
    rows.append(
        _row(
            "security.sbom",
            ["{python}", "-m", "cyclonedx_py", "environment", "--output-file", SBOM_REPORT],
            code,
            details={"artifact": SBOM_REPORT, "valid_cyclonedx": sbom_valid},
            passed=code == 0 and sbom_valid,
        )
    )
    return rows


def _production_rows(
    upstream: Mapping[str, Any],
    journey: Mapping[str, Any],
) -> list[dict[str, Any]]:
    raw = upstream.get("production_playwright")
    indexed = (
        {
            str(item.get("gate_id")): item
            for item in raw
            if isinstance(item, Mapping) and isinstance(item.get("gate_id"), str)
        }
        if isinstance(raw, list)
        else {}
    )
    expected_upstream = {
        "GATE-07": ("gate-07/gate07-browser-report.json", 1),
        "GATE-08": ("gate-08/gate08-browser-report.json", 4),
        "GATE-09": ("gate-09/gate09-browser-report.json", 1),
    }
    upstream_inventory_valid = bool(
        isinstance(raw, list)
        and len(raw) == len(expected_upstream)
        and set(indexed) == set(expected_upstream)
        and all(
            isinstance(indexed[gate_id], Mapping)
            and set(indexed[gate_id])
            == {
                "gate_id",
                "report",
                "sha256",
                "semantic_check_count",
                "semantic_checks_sha256",
                "run_count",
            }
            and indexed[gate_id].get("report") == report
            and isinstance(indexed[gate_id].get("sha256"), str)
            and len(str(indexed[gate_id]["sha256"])) == 71
            and str(indexed[gate_id]["sha256"]).startswith("sha256:")
            and all(
                character in "0123456789abcdef" for character in str(indexed[gate_id]["sha256"])[7:]
            )
            and type(indexed[gate_id].get("semantic_check_count")) is int
            and int(indexed[gate_id]["semantic_check_count"]) > 0
            and isinstance(indexed[gate_id].get("semantic_checks_sha256"), str)
            and len(str(indexed[gate_id]["semantic_checks_sha256"])) == 71
            and str(indexed[gate_id]["semantic_checks_sha256"]).startswith("sha256:")
            and all(
                character in "0123456789abcdef"
                for character in str(indexed[gate_id]["semantic_checks_sha256"])[7:]
            )
            and indexed[gate_id].get("run_count") == run_count
            for gate_id, (report, run_count) in expected_upstream.items()
        )
    )
    fresh = journey.get("production_playwright_specs")
    specs = {
        "frontend.production-detection": (
            "GATE-07",
            "frontend/tests/e2e/detection-production.spec.ts",
        ),
        "frontend.production-operator": (
            "GATE-12",
            "frontend/tests/e2e/operator-production.spec.ts",
        ),
        "frontend.production-source-intake": (
            "GATE-09",
            "frontend/tests/e2e/source-intake-production.spec.ts",
        ),
    }
    rows: list[dict[str, Any]] = []
    for suite_id, (gate_id, spec) in specs.items():
        upstream_valid = (
            upstream_inventory_valid and gate_id in indexed
            if gate_id != "GATE-12"
            else fresh == [spec]
        )
        rows.append(
            _row(
                suite_id,
                ["{node}", "playwright/test/cli.js", "test", spec, "--project=chromium"],
                0 if upstream_valid else None,
                passed_ids=[spec] if upstream_valid else [],
                details={
                    "evidence_source": (
                        "fresh-gate12-journey"
                        if gate_id == "GATE-12"
                        else "same-acceptance-upstream-gate"
                    ),
                    "gate_id": gate_id,
                },
                passed=upstream_valid,
            )
        )
    return rows


def run_full_release_suites(
    repository: Path,
    evidence_dir: Path,
    *,
    upstream: Mapping[str, Any],
    journey: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Run every local release suite without writing generated output to source."""

    before = _tracked_snapshot(repository)
    with tempfile.TemporaryDirectory(prefix=".gate12-suites-", dir=evidence_dir) as raw:
        temporary = Path(raw)
        environment = _base_environment(temporary)
        rows = _python_suites(repository, temporary / "python", environment)
        rust_rows, rust_toolchain = _rust_suites(repository, temporary / "rust", environment)
        rows.extend(rust_rows)
        rows.extend(_frontend_suites(repository, temporary / "frontend", environment))
        rows.extend(_production_rows(upstream, journey))
        rows.extend(_security_suites(repository, evidence_dir, temporary / "security", environment))
    after = _tracked_snapshot(repository)
    changed = sorted(
        path for path in set(before) | set(after) if before.get(path) != after.get(path)
    )
    return {
        "schema_version": SUITE_SCHEMA,
        "passed": bool(before) and before == after and all(row["passed"] for row in rows),
        "suites": sorted(rows, key=lambda row: str(row["suite_id"])),
        "toolchain": {
            "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "node_available": shutil.which("node", path=os.environ.get("PATH")) is not None,
            **rust_toolchain,
        },
        "source_writes": changed,
    }


__all__ = ["run_full_release_suites"]
