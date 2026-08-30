"""Disposable WSL2 distribution lifecycle for the Gate 11 Linux proof."""

from __future__ import annotations

import os
import re
import secrets
import stat
import subprocess  # nosec B404 - only fixed WSL management commands are used
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .cross_platform_readiness import (
    WSL_DISTRIBUTION_ID,
    probe_wsl_distribution,
)

EXECUTION_DISTRIBUTION_PREFIX = "BlueFire-Gate11-Run-"
ABSENCE_DELAYS_MS = (0, 100, 250)

_EXECUTION_DISTRIBUTION = re.compile(r"^BlueFire-Gate11-Run-[0-9a-f]{16}$")
_MAX_MANAGEMENT_OUTPUT = 64 * 1024
_CLONE_TIMEOUT_SECONDS = 300


class DisposableWslDistributionError(ValueError):
    """Raised unless creation and removal of the disposable distro are exact."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DisposableWslDistributionError(message)


def _environment() -> Mapping[str, str]:
    names = ("SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")
    return {name: os.environ[name] for name in names if os.environ.get(name)}


def _process_options(cwd: Path) -> dict[str, Any]:
    options: dict[str, Any] = {
        "cwd": cwd,
        "env": _environment(),
        "shell": False,
        "stdin": subprocess.DEVNULL,
    }
    if os.name == "nt":
        options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return options


def _bounded_result(
    executable: Path,
    arguments: list[str],
    *,
    cwd: Path,
    timeout: int,
) -> subprocess.CompletedProcess[bytes]:
    command = [os.fspath(executable), *arguments]
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            completed = subprocess.run(  # nosec B603 - fixed executable and grammar
                command,
                stdout=stdout,
                stderr=stderr,
                timeout=timeout,
                check=False,
                **_process_options(cwd),
            )
            stdout.seek(0, os.SEEK_END)
            output_size = stdout.tell()
            stderr.seek(0, os.SEEK_END)
            error_size = stderr.tell()
            _require(
                output_size <= _MAX_MANAGEMENT_OUTPUT and error_size <= _MAX_MANAGEMENT_OUTPUT,
                "a WSL distribution-management stream exceeded its bound",
            )
            stdout.seek(0)
            output = stdout.read(output_size)
            stderr.seek(0)
            error = stderr.read(error_size)
    except DisposableWslDistributionError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise DisposableWslDistributionError(
            "a fixed WSL distribution-management command failed"
        ) from exc
    return subprocess.CompletedProcess(command, completed.returncode, output, error)


def _stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def _stream_clone(
    executable: Path,
    *,
    source_name: str,
    execution_name: str,
    install_root: Path,
    cwd: Path,
) -> None:
    export_command = [os.fspath(executable), "--export", source_name, "-"]
    import_command = [
        os.fspath(executable),
        "--import",
        execution_name,
        os.fspath(install_root),
        "-",
        "--version",
        "2",
    ]
    export: subprocess.Popen[bytes] | None = None
    imported: subprocess.Popen[bytes] | None = None
    try:
        with (
            tempfile.TemporaryFile() as export_error,
            tempfile.TemporaryFile() as import_output,
            tempfile.TemporaryFile() as import_error,
        ):
            export_options = _process_options(cwd)
            export_options["stdin"] = subprocess.DEVNULL
            export = subprocess.Popen(  # nosec B603 - fixed WSL export grammar
                export_command,
                stdout=subprocess.PIPE,
                stderr=export_error,
                **export_options,
            )
            if export.stdout is None:
                raise DisposableWslDistributionError("the WSL export stream is unavailable")
            export_stdout = export.stdout
            import_options = _process_options(cwd)
            import_options["stdin"] = export_stdout
            imported = subprocess.Popen(  # nosec B603 - fixed WSL import grammar
                import_command,
                stdout=import_output,
                stderr=import_error,
                **import_options,
            )
            export_stdout.close()
            deadline = time.monotonic() + _CLONE_TIMEOUT_SECONDS
            imported.wait(timeout=max(1.0, deadline - time.monotonic()))
            export.wait(timeout=max(1.0, deadline - time.monotonic()))
            export_error.seek(0, os.SEEK_END)
            export_error_size = export_error.tell()
            import_output.seek(0, os.SEEK_END)
            import_output_size = import_output.tell()
            import_error.seek(0, os.SEEK_END)
            import_error_size = import_error.tell()
            _require(
                export.returncode == 0
                and imported.returncode == 0
                and export_error_size <= _MAX_MANAGEMENT_OUTPUT
                and import_output_size <= _MAX_MANAGEMENT_OUTPUT
                and import_error_size <= _MAX_MANAGEMENT_OUTPUT,
                "the disposable WSL2 distribution could not be cloned",
            )
    except DisposableWslDistributionError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise DisposableWslDistributionError(
            "the disposable WSL2 distribution clone failed"
        ) from exc
    finally:
        if imported is not None:
            _stop(imported)
        if export is not None:
            _stop(export)


def _root_identity(path: Path) -> tuple[int, int]:
    details = path.lstat()
    reparse = bool(
        int(getattr(details, "st_file_attributes", 0))
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )
    _require(
        stat.S_ISDIR(details.st_mode) and not stat.S_ISLNK(details.st_mode) and not reparse,
        "the disposable WSL2 storage root is unsafe",
    )
    return int(details.st_dev), int(details.st_ino)


def _remove_empty_storage(path: Path, identity: tuple[int, int]) -> bool:
    try:
        if not path.exists():
            return True
        details = path.lstat()
        if (
            (int(details.st_dev), int(details.st_ino)) != identity
            or not stat.S_ISDIR(details.st_mode)
            or path.is_symlink()
            or any(path.iterdir())
        ):
            return False
        path.rmdir()
        return not path.exists()
    except OSError:
        return False


def probe_distribution_absence(distribution_name: str) -> list[Mapping[str, Any]]:
    """Return three fresh registry/CLI absence probes for one exact run name."""

    _require(
        _EXECUTION_DISTRIBUTION.fullmatch(distribution_name) is not None,
        "the disposable WSL2 distribution name is invalid",
    )
    probes: list[Mapping[str, Any]] = []
    for delay_ms in ABSENCE_DELAYS_MS:
        if delay_ms:
            time.sleep(delay_ms / 1000)
        facts = probe_wsl_distribution(distribution_name)
        absent = (
            facts.get("probe_state") == "absent"
            and facts.get("configured") is False
            and facts.get("version") is None
            and facts.get("distribution_id") == distribution_name
        )
        probes.append({"delay_ms": delay_ms, "registered": not absent})
    return probes


@dataclass
class DisposableWslDistribution:
    executable: Path
    runtime: Path
    distribution_name: str
    install_root: Path
    install_identity: tuple[int, int]
    may_be_registered: bool = False
    cleaned: bool = False

    def command(self, *arguments: str) -> list[str]:
        _require(not self.cleaned, "the disposable WSL2 distribution was already removed")
        return [
            os.fspath(self.executable),
            "--distribution",
            self.distribution_name,
            *arguments,
        ]

    def isolated_python_command(self, script: str, *, new_session: bool = False) -> list[str]:
        arguments = ["--exec"]
        if new_session:
            arguments.extend(("/usr/bin/setsid", "--wait"))
        arguments.extend(("/usr/bin/python3", "-I", "-B", "-X", "utf8", script))
        return self.command(*arguments)

    def cleanup(self) -> Mapping[str, Any]:
        _require(not self.cleaned, "the disposable WSL2 distribution cleanup was repeated")
        facts = probe_wsl_distribution(self.distribution_name)
        if facts.get("probe_state") != "absent":
            terminated = _bounded_result(
                self.executable,
                ["--terminate", self.distribution_name],
                cwd=self.runtime,
                timeout=30,
            )
            # An already-stopped distribution can return a nonzero status. The
            # destructive unregister result and fresh absence probes are final.
            _require(
                terminated.returncode in {0, 1},
                "the disposable WSL2 distribution could not be terminated",
            )
            unregistered = _bounded_result(
                self.executable,
                ["--unregister", self.distribution_name],
                cwd=self.runtime,
                timeout=60,
            )
            _require(
                unregistered.returncode == 0,
                "the disposable WSL2 distribution could not be unregistered",
            )
        probes = probe_distribution_absence(self.distribution_name)
        _require(
            probes
            == [{"delay_ms": delay_ms, "registered": False} for delay_ms in ABSENCE_DELAYS_MS],
            "the disposable WSL2 distribution registration survived cleanup",
        )
        storage_removed = _remove_empty_storage(self.install_root, self.install_identity)
        _require(storage_removed, "the disposable WSL2 distribution storage survived cleanup")
        self.cleaned = True
        return {
            "execution_distribution_id": self.distribution_name,
            "execution_distribution_disposable": True,
            "execution_distribution_removed": True,
            "distribution_storage_removed": True,
            "distribution_absence_probes": probes,
        }


def create_disposable_wsl_distribution(
    executable: Path,
    runtime: Path,
) -> DisposableWslDistribution:
    """Stream-clone the dedicated base into one randomly named WSL2 distro."""

    _require(
        executable.is_file(),
        "the trusted WSL distribution-management executable is unavailable",
    )
    source = probe_wsl_distribution(WSL_DISTRIBUTION_ID)
    _require(
        source.get("probe_state") == "ready"
        and source.get("configured") is True
        and source.get("version") == "2",
        "the dedicated Gate 11 WSL2 source distribution is unavailable",
    )
    token = secrets.token_hex(8)
    distribution_name = EXECUTION_DISTRIBUTION_PREFIX + token
    _require(
        probe_wsl_distribution(distribution_name).get("probe_state") == "absent",
        "the disposable WSL2 distribution name is already registered",
    )
    install_root = runtime / f"wsl-distribution-{token}"
    install_root.mkdir(mode=0o700)
    lease = DisposableWslDistribution(
        executable=executable,
        runtime=runtime,
        distribution_name=distribution_name,
        install_root=install_root,
        install_identity=_root_identity(install_root),
    )
    try:
        _stream_clone(
            executable,
            source_name=WSL_DISTRIBUTION_ID,
            execution_name=distribution_name,
            install_root=install_root,
            cwd=runtime,
        )
        lease.may_be_registered = True
        facts = probe_wsl_distribution(distribution_name)
        _require(
            facts.get("probe_state") == "ready"
            and facts.get("configured") is True
            and facts.get("version") == "2",
            "the cloned Gate 11 execution distribution is not WSL2",
        )
        return lease
    except BaseException as primary:
        try:
            lease.cleanup()
        except BaseException as cleanup_error:
            raise DisposableWslDistributionError(
                "the failed disposable WSL2 clone could not be cleaned"
            ) from cleanup_error
        raise primary


__all__ = [
    "ABSENCE_DELAYS_MS",
    "EXECUTION_DISTRIBUTION_PREFIX",
    "DisposableWslDistribution",
    "DisposableWslDistributionError",
    "create_disposable_wsl_distribution",
    "probe_distribution_absence",
]
