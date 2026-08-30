"""Executable clean-install and bootstrap acceptance workflow for GATE-01."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence, cast

from . import install_gate_validation as validation
from . import install_gate_workspace as workspace
from .install_gate_package_metadata import _canonical_name as _canonical_name
from .install_gate_package_metadata import _project_dependencies as _project_dependencies
from .install_gate_package_metadata import _project_section as _project_section
from .install_gate_package_metadata import _project_string as _project_string
from .install_gate_package_metadata import _project_version as _project_version
from .install_gate_package_metadata import _requirement_row as _requirement_row
from .install_gate_package_metadata import _static_version_value as _static_version_value
from .install_gate_package_metadata import (
    _wheel_dependency_metadata_report as _wheel_dependency_metadata_report,
)
from .runner_trust import _is_link_or_reparse, _owner_private
from .runtime_paths import runtime_temp_parent as _runtime_temp_parent

_REQUIRED_DISTRIBUTIONS = ("PyYAML", "cryptography", "PyNaCl", "cffi", "pycparser")
_WINDOWS = os.name == "nt"
_WORKSPACE_DIRECTORY = re.compile(r"^a[0-9a-f]{8}$")
_RUNTIME_DIRECTORY = re.compile(r"^b[0-9a-f]{8}$")
_WINDOWS_RUNTIME_ROOT_MAX_CHARS = 48
_HARNESS_EVIDENCE_ENTRIES = frozenset(
    {
        "runtime-cargo-target",
        "runtime-home",
        "runtime-temp",
        "workflow.stderr.log",
        "workflow.stdout.log",
    }
)
_EXPECTED_ASSERTIONS: Mapping[str, tuple[str, tuple[str, ...], str, str]] = {
    "GATE-01-FRESH-INSTALL": (
        "dynamic",
        (
            "gate01-package-inspection-report.json",
            "gate01-wheel-dependency-metadata-report.json",
            "gate01-dependency-provision-report.json",
            "gate01-package-runtime-report.json",
        ),
        "GATE-01.fresh-wheel-install.isolated-runtime.v1",
        "fresh_install",
    ),
    "GATE-01-UI-LAUNCH": (
        "dynamic",
        ("gate01-ui-health-report.json",),
        "GATE-01.production-ui.loopback-health.v1",
        "ui_launch",
    ),
    "GATE-01-PACKAGED-RUNNER": (
        "dynamic",
        ("gate01-package-inspection-report.json", "gate01-journey-report.json"),
        "GATE-01.packaged-runner.managed-bootstrap.v1",
        "packaged_runner",
    ),
    "GATE-01-LOCAL-TRUST": (
        "dynamic",
        ("gate01-journey-report.json",),
        "GATE-01.local-trust.recovery-mtls.v1",
        "local_trust",
    ),
    "GATE-01-EXECUTE-JOURNEY": (
        "dynamic",
        ("gate01-journey-report.json",),
        "GATE-01.seeded-execute.approval-job.v1",
        "execute_journey",
    ),
    "GATE-01-OBSERVE-CLEANUP-REPLAY-COMPARE": (
        "dynamic",
        ("gate01-journey-report.json", "gate01-verification-report.json"),
        "GATE-01.observe-cleanup-replay-compare.real-runner.v1",
        "observe_cleanup_replay_compare",
    ),
    "GATE-01-SIMPLE-WORKFLOW": (
        "structural",
        ("gate01-structural-report.json",),
        "GATE-01.guided-execute.workflow-audit.v1",
        "simple_workflow",
    ),
}
_EVIDENCE_REPORTS = tuple(
    sorted(
        {
            artifact
            for _kind, artifacts, _test_id, _check_name in _EXPECTED_ASSERTIONS.values()
            for artifact in artifacts
        }
    )
)


@dataclass(frozen=True)
class Gate01Outcome:
    status: str
    proofs: tuple[Mapping[str, Any], ...]
    failure_reason: str | None


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _load_json(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path.name} is unavailable or invalid") from exc
    if not isinstance(value, Mapping):
        raise ValueError(f"{path.name} must contain an object")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def _content_digest(rows: Sequence[tuple[str, str]]) -> str:
    payload = json.dumps(list(rows), ensure_ascii=False, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _environment() -> dict[str, str]:
    environment = dict(os.environ)
    for name in ("PYTHONPATH", "PYTHONHOME", "BLUEFIRE_RUNNER_BINARY", "BLUEFIRE_SANDBOX_ROOT"):
        environment.pop(name, None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    return environment


def _spawn_process(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    stdout: Any,
    stderr: Any,
) -> subprocess.Popen[bytes]:
    isolation: dict[str, Any]
    if _WINDOWS:
        isolation = {
            "creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        }
    else:
        isolation = {"start_new_session": True}
    return subprocess.Popen(
        command,
        cwd=cwd,
        env=environment,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=stdout,
        stderr=stderr,
        **isolation,
    )


def _wait_for_exit(process: subprocess.Popen[bytes], timeout_seconds: int) -> bool:
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        return False
    return True


def _kill_direct_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        process.kill()
    except OSError:
        pass
    if not _wait_for_exit(process, 10):
        raise RuntimeError("release subprocess did not exit after direct kill")


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if _WINDOWS:
        try:
            terminated = subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                shell=False,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=20,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            _kill_direct_process(process)
            raise RuntimeError("release subprocess tree termination failed") from exc
        if terminated.returncode != 0:
            _kill_direct_process(process)
            raise RuntimeError("release subprocess tree termination failed")
        if not _wait_for_exit(process, 10):
            _kill_direct_process(process)
        return

    try:
        process_group = os.getpgid(process.pid)  # type: ignore[attr-defined]
        os.killpg(process_group, signal.SIGTERM)  # type: ignore[attr-defined]
    except OSError as exc:
        _kill_direct_process(process)
        raise RuntimeError("release subprocess tree termination failed") from exc
    if _wait_for_exit(process, 10):
        return
    try:
        os.killpg(  # type: ignore[attr-defined]
            process_group,
            signal.SIGKILL,  # type: ignore[attr-defined]
        )
    except OSError as exc:
        _kill_direct_process(process)
        raise RuntimeError("release subprocess tree kill failed") from exc
    if not _wait_for_exit(process, 10):
        raise RuntimeError("release subprocess did not exit after tree kill")


def _wait_process(
    process: subprocess.Popen[bytes],
    command: Sequence[str],
    timeout_seconds: int,
) -> int:
    try:
        return process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        _terminate_process_tree(process)
        raise subprocess.TimeoutExpired(command, timeout_seconds) from None


def _bounded_remove(destination: Path, path: Path) -> bool:
    destination_resolved = destination.resolve(strict=True)
    target_resolved = path.resolve(strict=False)
    if target_resolved == destination_resolved or not target_resolved.is_relative_to(
        destination_resolved
    ):
        return False
    if (path.exists() or path.is_symlink()) and _is_link_or_reparse(path):
        return False
    for attempt in range(10):
        try:
            if path.is_dir():
                shutil.rmtree(path)
            elif path.exists() or path.is_symlink():
                path.unlink()
        except OSError:
            if attempt < 9:
                time.sleep(0.25)
                continue
        if not path.exists() and not path.is_symlink():
            return True
    return not path.exists() and not path.is_symlink()


def _validated_directory(path: Path, *, label: str) -> Path:
    return workspace.validated_directory(
        path,
        label=label,
        is_link_or_reparse=_is_link_or_reparse,
    )


def _validated_evidence_destination(path: Path) -> Path:
    return workspace.validated_evidence_destination(
        path,
        allowed_entries=_HARNESS_EVIDENCE_ENTRIES,
        is_link_or_reparse=_is_link_or_reparse,
    )


def _workspace_dependencies() -> workspace.WorkspaceDependencies:
    return workspace.WorkspaceDependencies(
        windows=_WINDOWS,
        runtime_root_max_chars=_WINDOWS_RUNTIME_ROOT_MAX_CHARS,
        workspace_directory=_WORKSPACE_DIRECTORY,
        runtime_directory=_RUNTIME_DIRECTORY,
        runtime_temp_parent=_runtime_temp_parent,
        token_hex=secrets.token_hex,
        is_link_or_reparse=_is_link_or_reparse,
        owner_private=_owner_private,
        bounded_remove=_bounded_remove,
    )


def _allocate_external_workspace(repository: Path) -> tuple[Path, Path, Path]:
    return workspace.allocate_external_workspace(repository, _workspace_dependencies())


def _allocate_short_runtime_root(
    destination: Path,
    *,
    repository_root: Path | None = None,
) -> Path:
    return workspace.allocate_short_runtime_root(
        destination,
        _workspace_dependencies(),
        repository_root=repository_root,
    )


def _run(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
    failure_label: str,
) -> None:
    with tempfile.TemporaryFile() as output:
        try:
            process = _spawn_process(
                command,
                cwd=cwd,
                environment=environment,
                stdout=output,
                stderr=output,
            )
        except OSError:
            raise ValueError(f"{failure_label} could not start") from None
        try:
            returncode = _wait_process(process, command, timeout_seconds)
        except subprocess.TimeoutExpired:
            raise ValueError(f"{failure_label} timed out") from None
        except (OSError, RuntimeError):
            raise ValueError(f"{failure_label} process control failed") from None
        output.flush()
        output.seek(0, os.SEEK_END)
        if output.tell() > 16 * 1024 * 1024:
            raise ValueError(f"{failure_label} output exceeded its bound")
    if returncode != 0:
        raise ValueError(f"{failure_label} exited nonzero")


def _run_json(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
    failure_label: str,
) -> tuple[int, Mapping[str, Any]]:
    with tempfile.TemporaryFile() as output:
        try:
            process = _spawn_process(
                command,
                cwd=cwd,
                environment=environment,
                stdout=output,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            raise ValueError(f"{failure_label} could not start") from None
        try:
            returncode = _wait_process(process, command, timeout_seconds)
        except subprocess.TimeoutExpired:
            raise ValueError(f"{failure_label} timed out") from None
        except (OSError, RuntimeError):
            raise ValueError(f"{failure_label} process control failed") from None
        output.flush()
        output.seek(0, os.SEEK_END)
        size = output.tell()
        if size > 64 * 1024:
            raise ValueError(f"{failure_label} output exceeded its bound")
        output.seek(0)
        payload = output.read(size)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{failure_label} returned invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise ValueError(f"{failure_label} returned an invalid object")
    return returncode, value


def _archive_committed_source(repository: Path, source: Path, archive_path: Path) -> None:
    _run(
        [
            "git",
            "-c",
            f"safe.directory={repository}",
            "archive",
            "--format=tar",
            "--output",
            os.fspath(archive_path),
            "HEAD",
        ],
        cwd=repository,
        environment=_environment(),
        timeout_seconds=120,
        failure_label="committed source archive",
    )
    source.mkdir()
    with tarfile.open(archive_path, "r:") as archive:
        for member in archive.getmembers():
            target = (source / member.name).resolve()
            if (
                not target.is_relative_to(source.resolve())
                or member.issym()
                or member.islnk()
                or not (member.isfile() or member.isdir())
            ):
                raise ValueError("committed source archive contains an unsafe member")
        archive.extractall(source, filter="data")
    if not (source / "pyproject.toml").is_file() or not (source / "setup.py").is_file():
        raise ValueError("committed packaging source is incomplete")


def _native_target(source: Path) -> tuple[str, str, str]:
    manifest = _load_json(source / "bluefire" / "native" / "runner-manifest.json")
    artifact = manifest.get("artifact")
    if not isinstance(artifact, Mapping):
        raise ValueError("native package artifact is invalid")
    platform_name = artifact.get("platform")
    architecture = artifact.get("architecture")
    wheel_tag = artifact.get("wheel_platform_tag")
    if (
        platform_name != "windows"
        or architecture not in {"x86_64", "aarch64"}
        or wheel_tag != ("win_amd64" if architecture == "x86_64" else "win_arm64")
    ):
        raise ValueError("Gate 01 requires the compatible Windows native package")
    return str(platform_name), str(architecture), str(wheel_tag)


def _build_and_inspect(
    source: Path,
    wheel_dir: Path,
    evidence_dir: Path,
) -> Path:
    wheel_dir.mkdir()
    environment = _environment()
    _run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            os.fspath(wheel_dir),
            os.fspath(source),
        ],
        cwd=evidence_dir,
        environment=environment,
        timeout_seconds=300,
        failure_label="wheel build",
    )
    wheels = list(wheel_dir.glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("release build did not produce exactly one wheel")
    platform_name, architecture, wheel_tag = _native_target(source)
    _run(
        [
            sys.executable,
            os.fspath(source / "tools" / "verify_packaged_runner.py"),
            "inspect",
            "--wheel-dir",
            os.fspath(wheel_dir),
            "--platform",
            platform_name,
            "--architecture",
            architecture,
            "--wheel-platform-tag",
            wheel_tag,
            "--report",
            os.fspath(evidence_dir / "gate01-package-inspection-report.json"),
        ],
        cwd=source,
        environment=environment,
        timeout_seconds=120,
        failure_label="packaged runner inspection",
    )
    dependency_metadata = _wheel_dependency_metadata_report(source, wheels[0])
    _write_json(
        evidence_dir / "gate01-wheel-dependency-metadata-report.json",
        dependency_metadata,
    )
    validation.validate_wheel_dependency_metadata(dependency_metadata)
    return wheels[0]


def _fresh_python(environment_root: Path) -> Path:
    return environment_root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _provision_distribution(
    name: str,
    destination: Path,
) -> Mapping[str, Any]:
    distribution = importlib.metadata.distribution(name)
    files = distribution.files
    if not files:
        raise ValueError(f"required distribution {name} has no installed file record")
    source_root = Path(cast(os.PathLike[str], distribution.locate_file(""))).resolve(strict=True)
    copied: list[tuple[str, str]] = []
    for package_path in files:
        source = Path(cast(os.PathLike[str], distribution.locate_file(package_path)))
        try:
            resolved = source.resolve(strict=True)
            relative = resolved.relative_to(source_root)
        except (OSError, ValueError):
            continue
        if source.is_symlink() or not resolved.is_file():
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(resolved, target)
        copied.append((relative.as_posix(), _sha256(target)))
    if not copied:
        raise ValueError(f"required distribution {name} could not be provisioned")
    copied.sort()
    return {
        "version": distribution.version,
        "file_count": len(copied),
        "content_digest": _content_digest(copied),
    }


def _create_fresh_environment(
    environment_root: Path,
    wheel: Path,
    evidence_dir: Path,
) -> Path:
    _run(
        [sys.executable, "-m", "venv", "--copies", os.fspath(environment_root)],
        cwd=evidence_dir,
        environment=_environment(),
        timeout_seconds=180,
        failure_label="fresh virtual environment creation",
    )
    python = _fresh_python(environment_root)
    site_packages = (
        environment_root / "Lib" / "site-packages"
        if os.name == "nt"
        else environment_root
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    if not python.is_file() or not site_packages.is_dir():
        raise ValueError("fresh virtual environment is incomplete")
    distributions = {
        name: _provision_distribution(name, site_packages) for name in _REQUIRED_DISTRIBUTIONS
    }
    dependency_metadata = _load_json(evidence_dir / "gate01-wheel-dependency-metadata-report.json")
    provision_report = {
        "schema_version": "bluefire.gate01-dependency-provision.v1",
        "verified": True,
        "method": "copied-verified-installed-distributions",
        "isolated_environment": True,
        "wheel_sha256": dependency_metadata.get("wheel_sha256"),
        "wheel_requirements_satisfied": True,
        "distributions": distributions,
    }
    validation.validate_dependency_provision_binding(dependency_metadata, provision_report)
    _write_json(evidence_dir / "gate01-dependency-provision-report.json", provision_report)
    _run(
        [
            os.fspath(python),
            "-I",
            "-m",
            "pip",
            "install",
            "--isolated",
            "--no-index",
            "--no-deps",
            "--force-reinstall",
            os.fspath(wheel),
        ],
        cwd=evidence_dir,
        environment=_environment(),
        timeout_seconds=180,
        failure_label="fresh wheel installation",
    )
    return python


def _run_installed_helper(
    source: Path,
    forbidden_checkout: Path,
    evidence_dir: Path,
    runtime_root: Path,
    python: Path,
    helper_copy: Path,
    support_copy: Path,
) -> Mapping[str, Any]:
    shutil.copyfile(source / "tools" / "run_install_gate_journey.py", helper_copy)
    shutil.copyfile(source / "tools" / "install_gate_journey_support.py", support_copy)
    exit_code, summary = _run_json(
        [
            os.fspath(python),
            "-I",
            os.fspath(helper_copy),
            "--evidence-dir",
            os.fspath(evidence_dir),
            "--runtime-root",
            os.fspath(runtime_root),
            "--forbid-root",
            os.fspath(forbidden_checkout),
            "--support-module",
            os.fspath(support_copy),
        ],
        cwd=evidence_dir,
        environment=_environment(),
        timeout_seconds=600,
        failure_label="installed-wheel journey",
    )
    if exit_code != 0:
        code = summary.get("error_code")
        message = summary.get("message")
        if (
            isinstance(code, str)
            and code.replace("_", "").isalnum()
            and isinstance(message, str)
            and 1 <= len(message) <= 200
            and "\\" not in message
        ):
            raise ValueError(f"installed helper failed [{code}]: {message}")
        raise ValueError("installed helper failed with an invalid summary")
    validation.validate_summary(summary)
    return summary


def _structural_report(repository: Path) -> Mapping[str, Any]:
    pyproject = (repository / "pyproject.toml").read_text(encoding="utf-8")
    setup = (repository / "setup.py").read_text(encoding="utf-8")
    cli = (repository / "bluefire" / "cli.py").read_text(encoding="utf-8")
    onboarding = (
        repository / "frontend" / "src" / "components" / "ExecuteOnboarding.tsx"
    ).read_text(encoding="utf-8")
    runs = (repository / "frontend" / "src" / "pages" / "Runs.tsx").read_text(encoding="utf-8")
    packaged_app = (repository / "bluefire" / "ui" / "app.js").read_text(encoding="utf-8")
    guided_copy = (
        "Runner ready to approved run",
        "Verify & enroll local runner",
        "Use seeded restricted canary",
        "Run guided preflight",
        "Review one-time approval",
        "collector.filesystem.sandbox.v1",
    )
    approval_copy = (
        "Create approval-gated job",
        "I approve this exact immutable",
        "Approve and release job",
    )
    onboarding_imported = (
        re.search(
            r"import\s*\{[^}]*\bExecuteOnboarding\b[^}]*\}\s*from\s*"
            r'["\']\.\./components/ExecuteOnboarding["\']\s*;?',
            runs,
        )
        is not None
    )
    onboarding_rendered = re.search(r"<ExecuteOnboarding(?:\s|/|>)", runs) is not None
    checks = {
        "console_entrypoint": 'bluefire = "bluefire.cli:main"' in pyproject,
        "packaged_ui_and_runner": all(
            token in pyproject
            for token in ('"ui/*.html"', '"ui/*.js"', '"ui/*.css"', '"native/bluefire-runner.exe"')
        ),
        "platform_wheel_verification": all(
            token in setup
            for token in (
                "class PlatformNativeWheel",
                "_native_architecture",
                "native runner artifact failed build-time integrity verification",
            )
        ),
        "explicit_cli_workflow": all(
            token in cli
            for token in (
                'commands.add_parser("ui"',
                "runner_commands.add_parser(",
                '"bootstrap"',
                '"start"',
                'scenario_commands.add_parser("preview"',
                'scenario_commands.add_parser("run"',
                'commands.add_parser("replay"',
                'commands.add_parser("compare"',
            )
        ),
        "guided_execute_onboarding": (
            "export function ExecuteOnboarding" in onboarding
            and onboarding_imported
            and onboarding_rendered
            and all(token in onboarding for token in guided_copy)
            and all(token in packaged_app for token in guided_copy)
        ),
        "fresh_approval_boundary": (
            all(token in onboarding + runs for token in approval_copy)
            and all(token in packaged_app for token in approval_copy)
        ),
    }
    return {
        "schema_version": "bluefire.gate01-structural.v1",
        "verified": all(checks.values()),
        "checks": checks,
    }


def _proof(
    assertion_id: str,
    kind: str,
    artifacts: Sequence[str],
    test_id: str,
    bundles: Sequence[Mapping[str, str]] = (),
) -> Mapping[str, Any]:
    return {
        "kind": kind,
        "status": "passed",
        "test_id": test_id,
        "assertion_ids": [assertion_id],
        "evidence_artifacts": list(artifacts),
        "run_ids": [bundle["run_id"] for bundle in bundles],
        "run_bundles": [dict(bundle) for bundle in bundles],
        "environment_limitations": [],
    }


def _validate_reports(evidence_dir: Path) -> tuple[str, str]:
    inspection = _load_json(evidence_dir / "gate01-package-inspection-report.json")
    dependency_metadata = _load_json(evidence_dir / "gate01-wheel-dependency-metadata-report.json")
    provision = _load_json(evidence_dir / "gate01-dependency-provision-report.json")
    package_runtime = _load_json(evidence_dir / "gate01-package-runtime-report.json")
    ui = _load_json(evidence_dir / "gate01-ui-health-report.json")
    journey = _load_json(evidence_dir / "gate01-journey-report.json")
    structural = _load_json(evidence_dir / "gate01-structural-report.json")
    validation.validate_inspection(inspection)
    validation.validate_wheel_dependency_metadata(dependency_metadata)
    validation.validate_wheel_metadata_binding(inspection, dependency_metadata)
    validation.validate_dependency_provision(provision)
    validation.validate_dependency_provision_binding(dependency_metadata, provision)
    validation.validate_package_runtime(package_runtime)
    validation.validate_dependency_runtime_binding(dependency_metadata, provision, package_runtime)
    validation.validate_ui(ui)
    run_ids = validation.validate_journey(journey)
    validation.validate_runner_digest_binding(inspection, journey)
    validation.validate_structural(structural)
    return run_ids


def _verification_report(run_ids: Sequence[str]) -> Mapping[str, Any]:
    return {
        "schema_version": "bluefire.gate01-verification.v1",
        "passed": True,
        "checks": {
            "fresh_install": True,
            "ui_launch": True,
            "packaged_runner": True,
            "local_trust": True,
            "execute_journey": True,
            "observe_cleanup_replay_compare": True,
            "simple_workflow": True,
        },
        "run_ids": list(run_ids),
    }


def _copy_regular_file_exclusive(source: Path, destination: Path) -> None:
    try:
        before = source.lstat()
    except OSError as exc:
        raise ValueError("Gate 01 staged evidence is unavailable") from exc
    if not stat.S_ISREG(before.st_mode) or _is_link_or_reparse(source):
        raise ValueError("Gate 01 staged evidence contains an unsafe file")
    descriptor: int | None = None
    try:
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with source.open("rb") as input_file, os.fdopen(descriptor, "wb") as output_file:
            descriptor = None
            shutil.copyfileobj(input_file, output_file, length=1024 * 1024)
            output_file.flush()
            os.fsync(output_file.fileno())
        after = source.lstat()
        if not os.path.samestat(before, after) or _is_link_or_reparse(source):
            raise ValueError("Gate 01 staged evidence changed during publication")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _copy_evidence_tree(source: Path, destination: Path) -> None:
    source_root = _validated_directory(source, label="Gate 01 staged run evidence")
    destination.mkdir(mode=0o700)
    for entry in os.scandir(source_root):
        source_entry = Path(entry.path)
        destination_entry = destination / entry.name
        try:
            details = source_entry.lstat()
        except OSError as exc:
            raise ValueError("Gate 01 staged run evidence is unavailable") from exc
        if _is_link_or_reparse(source_entry):
            raise ValueError("Gate 01 staged run evidence contains a link or reparse point")
        if stat.S_ISDIR(details.st_mode):
            _copy_evidence_tree(source_entry, destination_entry)
        elif stat.S_ISREG(details.st_mode):
            _copy_regular_file_exclusive(source_entry, destination_entry)
        else:
            raise ValueError("Gate 01 staged run evidence contains an unsafe entry")


def _publish_gate_evidence(source: Path, destination: Path) -> tuple[str, str]:
    staged_run_ids = _validate_reports(source)
    staged_verification = _load_json(source / "gate01-verification-report.json")
    if validation.validate_verification(staged_verification) != staged_run_ids:
        raise ValueError("Gate 01 staged verification run binding is invalid")
    names = (*_EVIDENCE_REPORTS, "runs")
    if any((destination / name).exists() or (destination / name).is_symlink() for name in names):
        raise ValueError("Gate 01 evidence directory contains stale owned artifacts")

    published: list[Path] = []
    try:
        for name in _EVIDENCE_REPORTS:
            target = destination / name
            published.append(target)
            _copy_regular_file_exclusive(source / name, target)
        runs = destination / "runs"
        published.append(runs)
        _copy_evidence_tree(source / "runs", runs)
        persisted_run_ids = _validate_reports(destination)
        persisted_verification = _load_json(destination / "gate01-verification-report.json")
        if (
            persisted_run_ids != staged_run_ids
            or validation.validate_verification(persisted_verification) != staged_run_ids
        ):
            raise ValueError("Gate 01 published evidence binding is invalid")
        return staged_run_ids
    except (OSError, RuntimeError, ValueError):
        cleanup_failures = [
            path.name for path in reversed(published) if not _bounded_remove(destination, path)
        ]
        if cleanup_failures:
            raise ValueError("Gate 01 partial evidence cleanup failed") from None
        raise


def run_gate_01(
    gate: Any,
    evidence_dir: Path,
    *,
    repository_root: Path | None = None,
) -> Gate01Outcome:
    repository = _validated_directory(
        repository_root or Path.cwd(),
        label="Gate 01 repository root",
    )
    try:
        destination = _validated_evidence_destination(evidence_dir)
    except (OSError, ValueError) as exc:
        return Gate01Outcome(
            "failed",
            (),
            "GATE-01 failed: " + validation.bounded_failure_message(exc),
        )
    contract_assertions = {
        assertion.assertion_id: assertion.proof for assertion in getattr(gate, "assertions", ())
    }
    expected_kinds = {assertion_id: row[0] for assertion_id, row in _EXPECTED_ASSERTIONS.items()}
    if contract_assertions != expected_kinds:
        return Gate01Outcome("failed", (), "locked GATE-01 assertion set mismatch")

    completed = False
    issue: str | None = None
    run_ids: tuple[str, ...] = ()
    external_parent: Path | None = None
    external_workspace: Path | None = None
    runtime_root: Path | None = None
    try:
        external_parent, external_workspace, staged_evidence = _allocate_external_workspace(
            repository
        )
        archive_path = staged_evidence / "s.tar"
        source = staged_evidence / "s"
        wheel_dir = staged_evidence / "wheel"
        environment_root = staged_evidence / "e"
        helper_copy = staged_evidence / "h.py"
        support_copy = staged_evidence / "i.py"
        runtime_root = _allocate_short_runtime_root(
            staged_evidence,
            repository_root=repository,
        )
        _archive_committed_source(repository, source, archive_path)
        wheel = _build_and_inspect(source, wheel_dir, staged_evidence)
        fresh_python = _create_fresh_environment(environment_root, wheel, staged_evidence)
        _run_installed_helper(
            source,
            repository,
            staged_evidence,
            runtime_root,
            fresh_python,
            helper_copy,
            support_copy,
        )
        structural = _structural_report(source)
        _write_json(staged_evidence / "gate01-structural-report.json", structural)
        validation.validate_structural(structural)
        run_ids = _validate_reports(staged_evidence)
        verification = _verification_report(run_ids)
        _write_json(staged_evidence / "gate01-verification-report.json", verification)
        persisted_verification = _load_json(staged_evidence / "gate01-verification-report.json")
        if validation.validate_verification(persisted_verification) != run_ids:
            raise ValueError("Gate 01 verification run binding is invalid")
        run_ids = _publish_gate_evidence(staged_evidence, destination)
        completed = True
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired, tarfile.TarError) as exc:
        issue = validation.bounded_failure_message(exc)
    finally:
        cleanup_failures: list[str] = []
        if (
            runtime_root is not None
            and external_parent is not None
            and not _bounded_remove(external_parent, runtime_root)
        ):
            cleanup_failures.append("external-runtime")
        if (
            external_workspace is not None
            and external_parent is not None
            and not _bounded_remove(external_parent, external_workspace)
        ):
            cleanup_failures.append("external-workspace")
        if cleanup_failures:
            if completed and not _bounded_remove(destination, destination / "runs"):
                cleanup_failures.append("runs")
            completed = False
            issue = "ephemeral Gate 01 cleanup failed: " + ", ".join(cleanup_failures)
    if not completed:
        return Gate01Outcome(
            "failed",
            (),
            "GATE-01 failed: " + (issue or "installed-wheel workflow did not complete"),
        )

    bundles = tuple({"run_id": run_id, "path": f"runs/{run_id}"} for run_id in run_ids)
    proofs: list[Mapping[str, Any]] = []
    for assertion_id, (kind, artifacts, test_id, check_name) in _EXPECTED_ASSERTIONS.items():
        attached: Sequence[Mapping[str, str]] = ()
        if check_name == "execute_journey":
            attached = bundles[:1]
        elif check_name == "observe_cleanup_replay_compare":
            attached = bundles
        proofs.append(_proof(assertion_id, kind, artifacts, test_id, attached))
    return Gate01Outcome("passed", tuple(proofs), None)


__all__ = ["Gate01Outcome", "run_gate_01"]
