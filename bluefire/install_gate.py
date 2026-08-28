"""Executable clean-install and bootstrap acceptance workflow for GATE-01."""

from __future__ import annotations

import ast
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import default as email_policy
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import install_gate_validation as validation

_REQUIRED_DISTRIBUTIONS = ("PyYAML", "cryptography", "PyNaCl", "cffi", "pycparser")
_RUNTIME_DISTRIBUTIONS = frozenset({"pyyaml", "cryptography", "pynacl"})
_REQUIREMENT_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(.*)$")
_REQUIREMENT_SPECIFIER = re.compile(r"^(?:~=|==|!=|<=|>=|<|>)[A-Za-z0-9][A-Za-z0-9.*+!_-]*$")
_WINDOWS = os.name == "nt"
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
        process_group = os.getpgid(process.pid)
        os.killpg(process_group, signal.SIGTERM)
    except OSError as exc:
        _kill_direct_process(process)
        raise RuntimeError("release subprocess tree termination failed") from exc
    if _wait_for_exit(process, 10):
        return
    try:
        os.killpg(process_group, signal.SIGKILL)
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
    for attempt in range(10):
        try:
            if path.is_dir() and not path.is_symlink():
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


def _canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _requirement_row(value: str) -> Mapping[str, str]:
    if ";" in value or "[" in value or "]" in value or "@" in value:
        raise ValueError("runtime dependency must be an unconditional distribution requirement")
    match = _REQUIREMENT_NAME.fullmatch(value.strip())
    if match is None:
        raise ValueError("runtime dependency requirement is invalid")
    name = _canonical_name(match.group(1))
    specifiers = [part.strip() for part in match.group(2).split(",") if part.strip()]
    if not specifiers or any(_REQUIREMENT_SPECIFIER.fullmatch(part) is None for part in specifiers):
        raise ValueError("runtime dependency specifier is invalid")
    return {"name": name, "specifier": ",".join(sorted(specifiers))}


def _project_section(document: str) -> str:
    match = re.search(r"(?ms)^\[project\]\s*$\n(.*?)(?=^\[|\Z)", document)
    if match is None:
        raise ValueError("packaging source has no project metadata")
    return match.group(1)


def _project_string(project: str, field: str) -> str:
    match = re.search(rf'(?m)^{re.escape(field)}\s*=\s*("(?:\\.|[^"\\])*")\s*$', project)
    if match is None:
        raise ValueError(f"packaging source has no {field} value")
    try:
        value = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        raise ValueError(f"packaging source {field} value is invalid") from exc
    if not isinstance(value, str) or not value:
        raise ValueError(f"packaging source {field} value is invalid")
    return value


def _project_version(source: Path, document: str, project: str) -> str:
    if re.search(r"(?m)^version\s*=", project) is not None:
        return _project_string(project, "version")
    dynamic_match = re.search(r"(?ms)^dynamic\s*=\s*\[(.*?)\]\s*$", project)
    if dynamic_match is None:
        raise ValueError("packaging source has no version declaration")
    dynamic_body = dynamic_match.group(1)
    literals = re.findall(r'"(?:\\.|[^"\\])*"', dynamic_body)
    remainder = re.sub(r'"(?:\\.|[^"\\])*"', "", dynamic_body)
    if remainder.strip(" \t\r\n,"):
        raise ValueError("packaging source dynamic metadata is invalid")
    try:
        dynamic_fields = [json.loads(literal) for literal in literals]
    except json.JSONDecodeError as exc:
        raise ValueError("packaging source dynamic metadata is invalid") from exc
    dynamic_section = re.search(
        r"(?ms)^\[tool\.setuptools\.dynamic\]\s*$\n(.*?)(?=^\[|\Z)", document
    )
    version_binding = (
        re.findall(
            r'(?m)^version\s*=\s*\{\s*attr\s*=\s*"bluefire\.__version__"\s*\}\s*$',
            dynamic_section.group(1),
        )
        if dynamic_section is not None
        else []
    )
    if dynamic_fields.count("version") != 1 or len(version_binding) != 1:
        raise ValueError("packaging source dynamic version binding is invalid")
    version_source = source / "bluefire" / "__init__.py"
    try:
        source_text = version_source.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError("packaging source version module is unavailable") from exc
    if len(source_text.encode("utf-8")) > 1024 * 1024:
        raise ValueError("packaging source version module exceeds its size bound")
    try:
        module = ast.parse(source_text, filename="bluefire/__init__.py")
    except SyntaxError as exc:
        raise ValueError("packaging source version module is invalid") from exc
    assignments = [
        node
        for node in module.body
        if (
            isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "__version__"
                for target in node.targets
            )
        )
        or (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "__version__"
        )
    ]
    if (
        len(assignments) != 1
        or not isinstance(assignments[0], ast.Assign)
        or len(assignments[0].targets) != 1
        or not isinstance(assignments[0].targets[0], ast.Name)
        or not isinstance(assignments[0].value, ast.Constant)
        or not isinstance(assignments[0].value.value, str)
        or not assignments[0].value.value
    ):
        raise ValueError("packaging source dynamic version value is invalid")
    return assignments[0].value.value


def _project_dependencies(project: str) -> list[str]:
    match = re.search(r"(?ms)^dependencies\s*=\s*\[(.*?)\]\s*$", project)
    if match is None:
        raise ValueError("packaging source has no runtime dependencies")
    body = match.group(1)
    literals = re.findall(r'"(?:\\.|[^"\\])*"', body)
    remainder = re.sub(r'"(?:\\.|[^"\\])*"', "", body)
    remainder = re.sub(r"(?m)#.*$", "", remainder)
    if remainder.strip(" \t\r\n,") or not literals:
        raise ValueError("packaging source runtime dependencies are invalid")
    try:
        values = [json.loads(literal) for literal in literals]
    except json.JSONDecodeError as exc:
        raise ValueError("packaging source runtime dependencies are invalid") from exc
    if any(not isinstance(value, str) or not value for value in values):
        raise ValueError("packaging source runtime dependencies are invalid")
    return values


def _wheel_dependency_metadata_report(source: Path, wheel: Path) -> Mapping[str, Any]:
    document = (source / "pyproject.toml").read_text(encoding="utf-8")
    project = _project_section(document)
    project_name = _canonical_name(_project_string(project, "name"))
    project_version = _project_version(source, document, project)
    requires_python = _project_string(project, "requires-python")
    declared = sorted(
        (_requirement_row(requirement) for requirement in _project_dependencies(project)),
        key=lambda row: row["name"],
    )
    if {row["name"] for row in declared} != _RUNTIME_DISTRIBUTIONS:
        raise ValueError("declared BlueFire runtime dependency set is invalid")

    try:
        with zipfile.ZipFile(wheel, "r") as archive:
            metadata_members = [
                name
                for name in archive.namelist()
                if re.fullmatch(r"[^/]+\.dist-info/METADATA", name) is not None
            ]
            if len(metadata_members) != 1:
                raise ValueError("built wheel does not contain exactly one metadata record")
            metadata_bytes = archive.read(metadata_members[0])
    except (OSError, KeyError, zipfile.BadZipFile) as exc:
        raise ValueError("built wheel metadata is unavailable") from exc
    if len(metadata_bytes) > 1024 * 1024:
        raise ValueError("built wheel metadata exceeds its size bound")
    metadata = BytesParser(policy=email_policy).parsebytes(metadata_bytes)
    metadata_name = metadata.get("Name")
    metadata_version = metadata.get("Version")
    metadata_requires_python = metadata.get("Requires-Python")
    if (
        not isinstance(metadata_name, str)
        or not isinstance(metadata_version, str)
        or not isinstance(metadata_requires_python, str)
    ):
        raise ValueError("built wheel project metadata is incomplete")
    wheel_requirements: list[Mapping[str, str]] = []
    for requirement in metadata.get_all("Requires-Dist", []):
        if not isinstance(requirement, str):
            raise ValueError("built wheel dependency metadata is invalid")
        marker = requirement.partition(";")[2]
        if marker and re.search(r"\bextra\s*==", marker):
            continue
        wheel_requirements.append(_requirement_row(requirement))
    wheel_requirements.sort(key=lambda row: row["name"])
    if (
        project_name != "bluefire-nexus"
        or _canonical_name(metadata_name) != project_name
        or metadata_version != project_version
        or metadata_requires_python != requires_python
    ):
        raise ValueError("built wheel project metadata does not match the project declaration")
    if wheel_requirements != declared:
        raise ValueError(
            "built wheel Requires-Dist metadata does not match the project declaration"
        )
    return {
        "schema_version": "bluefire.gate01-wheel-dependency-metadata.v1",
        "verified": True,
        "project_name": project_name,
        "project_version": project_version,
        "requires_python": requires_python,
        "wheel_sha256": _sha256(wheel),
        "declared_runtime_dependencies": declared,
        "wheel_requires_dist": wheel_requirements,
    }


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
    source_root = Path(distribution.locate_file("")).resolve(strict=True)
    copied: list[tuple[str, str]] = []
    for package_path in files:
        source = Path(distribution.locate_file(package_path))
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


def run_gate_01(
    gate: Any,
    evidence_dir: Path,
    *,
    repository_root: Path | None = None,
) -> Gate01Outcome:
    repository = (repository_root or Path.cwd()).resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    contract_assertions = {
        assertion.assertion_id: assertion.proof for assertion in getattr(gate, "assertions", ())
    }
    expected_kinds = {assertion_id: row[0] for assertion_id, row in _EXPECTED_ASSERTIONS.items()}
    if contract_assertions != expected_kinds:
        return Gate01Outcome("failed", (), "locked GATE-01 assertion set mismatch")

    archive_path = destination / "s.tar"
    source = destination / "s"
    wheel_dir = destination / "wheel"
    environment_root = destination / "e"
    helper_copy = destination / "h.py"
    support_copy = destination / "i.py"
    completed = False
    issue: str | None = None
    run_ids: tuple[str, str] = ()
    try:
        if destination.is_relative_to(repository):
            raise ValueError("Gate 01 evidence must remain outside the checkout")
        _archive_committed_source(repository, source, archive_path)
        wheel = _build_and_inspect(source, wheel_dir, destination)
        fresh_python = _create_fresh_environment(environment_root, wheel, destination)
        _run_installed_helper(
            source,
            repository,
            destination,
            fresh_python,
            helper_copy,
            support_copy,
        )
        structural = _structural_report(source)
        _write_json(destination / "gate01-structural-report.json", structural)
        validation.validate_structural(structural)
        run_ids = _validate_reports(destination)
        verification = _verification_report(run_ids)
        _write_json(destination / "gate01-verification-report.json", verification)
        persisted_verification = _load_json(destination / "gate01-verification-report.json")
        if validation.validate_verification(persisted_verification) != run_ids:
            raise ValueError("Gate 01 verification run binding is invalid")
        completed = True
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired, tarfile.TarError) as exc:
        issue = validation.bounded_failure_message(exc)
    finally:
        cleanup_targets = [
            source,
            environment_root,
            destination / "runtime",
            archive_path,
            helper_copy,
            support_copy,
        ]
        if not completed:
            cleanup_targets.append(destination / "runs")
        cleanup_failures = [
            path.name for path in cleanup_targets if not _bounded_remove(destination, path)
        ]
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
