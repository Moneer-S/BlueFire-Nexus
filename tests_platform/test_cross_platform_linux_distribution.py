from __future__ import annotations

import io
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping

import pytest

import bluefire.cross_platform_linux_distribution as distribution_module
from bluefire.cross_platform_linux_distribution import (
    ABSENCE_DELAYS_MS,
    DisposableWslDistribution,
    DisposableWslDistributionError,
    create_disposable_wsl_distribution,
)
from bluefire.cross_platform_readiness import WSL_DISTRIBUTION_ID


def _facts(name: str, *, ready: bool) -> Mapping[str, Any]:
    return {
        "provider": "wsl2",
        "probe_state": "ready" if ready else "absent",
        "configured": True if ready else False,
        "distribution_id": name,
        "version": "2" if ready else None,
        "facts_digest": "sha256:" + "1" * 64,
    }


def test_disposable_cleanup_unregisters_and_removes_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    name = "BlueFire-Gate11-Run-0123456789abcdef"
    install = tmp_path / "install"
    install.mkdir()
    state = {"registered": True}
    commands: list[list[str]] = []

    def probe(distribution_name: str) -> Mapping[str, Any]:
        assert distribution_name == name
        return _facts(name, ready=state["registered"])

    def run(
        _executable: Path,
        arguments: list[str],
        **_options: Any,
    ) -> subprocess.CompletedProcess[bytes]:
        commands.append(arguments)
        if arguments[0] == "--unregister":
            state["registered"] = False
        return subprocess.CompletedProcess(arguments, 0, b"", b"")

    monkeypatch.setattr(distribution_module, "probe_wsl_distribution", probe)
    monkeypatch.setattr(distribution_module, "_bounded_result", run)
    monkeypatch.setattr(distribution_module.time, "sleep", lambda _seconds: None)
    lease = DisposableWslDistribution(
        executable=Path(sys.executable).resolve(strict=True),
        runtime=tmp_path,
        distribution_name=name,
        install_root=install,
        install_identity=distribution_module._root_identity(install),
        may_be_registered=True,
    )

    proof = lease.cleanup()

    assert commands == [["--terminate", name], ["--unregister", name]]
    assert proof == {
        "execution_distribution_id": name,
        "execution_distribution_disposable": True,
        "execution_distribution_removed": True,
        "distribution_storage_removed": True,
        "distribution_absence_probes": [
            {"delay_ms": delay, "registered": False} for delay in ABSENCE_DELAYS_MS
        ],
    }
    assert not install.exists()


def test_failed_clone_cleans_private_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "0123456789abcdef"
    execution_name = "BlueFire-Gate11-Run-" + token

    def probe(name: str) -> Mapping[str, Any]:
        return _facts(name, ready=name == WSL_DISTRIBUTION_ID)

    def fail_clone(*_args: Any, **_kwargs: Any) -> None:
        raise DisposableWslDistributionError("simulated clone failure")

    monkeypatch.setattr(distribution_module, "probe_wsl_distribution", probe)
    monkeypatch.setattr(distribution_module, "_stream_clone", fail_clone)
    monkeypatch.setattr(distribution_module.secrets, "token_hex", lambda _size: token)
    monkeypatch.setattr(distribution_module.time, "sleep", lambda _seconds: None)

    with pytest.raises(DisposableWslDistributionError, match="simulated clone failure"):
        create_disposable_wsl_distribution(Path(sys.executable), tmp_path)

    assert probe(execution_name)["probe_state"] == "absent"
    assert not (tmp_path / f"wsl-distribution-{token}").exists()


def test_stream_clone_pipes_export_directly_into_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], dict[str, Any], Any]] = []

    class FakeProcess:
        def __init__(self, command: list[str], **options: Any) -> None:
            self.command = command
            self.returncode = 0
            self.stdout = io.BytesIO(b"rootfs") if "--export" in command else None
            calls.append((command, options, self))

        def wait(self, timeout: float | None = None) -> int:
            assert timeout is None or timeout > 0
            return self.returncode

        def poll(self) -> int:
            return self.returncode

        def terminate(self) -> None:
            raise AssertionError("a completed clone process must not be terminated")

        def kill(self) -> None:
            raise AssertionError("a completed clone process must not be killed")

    monkeypatch.setattr(distribution_module.subprocess, "Popen", FakeProcess)
    executable = Path(sys.executable).resolve(strict=True)
    install = tmp_path / "install"
    install.mkdir()

    distribution_module._stream_clone(
        executable,
        source_name=WSL_DISTRIBUTION_ID,
        execution_name="BlueFire-Gate11-Run-0123456789abcdef",
        install_root=install,
        cwd=tmp_path,
    )

    assert len(calls) == 2
    assert calls[0][0] == [str(executable), "--export", WSL_DISTRIBUTION_ID, "-"]
    assert calls[1][0] == [
        str(executable),
        "--import",
        "BlueFire-Gate11-Run-0123456789abcdef",
        str(install),
        "-",
        "--version",
        "2",
    ]
    assert calls[1][1]["stdin"] is calls[0][2].stdout
