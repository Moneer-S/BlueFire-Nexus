"""Management commands are simulated; every storage path belongs to the test."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import cross_platform_linux_distribution as distribution
from bluefire import cross_platform_readiness as readiness
from tests_platform.test_cross_platform_linux_distribution import _facts


def _lease(tmp_path, monkeypatch):
    name = "BlueFire-Gate11-Run-0123456789abcdef"
    install = tmp_path / "storage"
    install.mkdir()
    lease = distribution.DisposableWslDistribution(
        Path(sys.executable),
        tmp_path,
        name,
        install,
        distribution._root_identity(install),
        may_be_registered=True,
        registration_id="original-guid",
    )
    state = {"registered": True, "guid": "original-guid"}
    commands = []

    def probe(selected, *, require_cli=False):
        assert selected == name and require_cli
        return _facts(name, ready=state["registered"])

    def command(_executable, arguments, **_kwargs):
        commands.append(arguments[0])
        if arguments[0] == "--unregister":
            state["registered"] = False
        return subprocess.CompletedProcess(arguments, 0, b"", b"")

    monkeypatch.setattr(distribution, "probe_wsl_distribution", probe)
    monkeypatch.setattr(distribution, "registration", lambda _: (state["guid"], install))
    monkeypatch.setattr(distribution, "_bounded_result", command)
    monkeypatch.setattr(distribution.time, "sleep", lambda _: None)
    return lease, state, commands, command


@pytest.mark.parametrize("fault", ["guid", "unbound", "volume", "indeterminate"])
def test_unproven_ownership_never_reaches_destructive_management(tmp_path, monkeypatch, fault):
    lease, state, commands, _ = _lease(tmp_path, monkeypatch)
    if fault == "guid":
        state["guid"] = "replacement"
    elif fault == "unbound":
        lease.registration_id = None
    elif fault == "volume":
        lease.install_identity = (lease.install_identity[0] ^ (1 << 32), lease.install_identity[1])
    else:
        monkeypatch.setattr(distribution, "probe_wsl_distribution", lambda *_a, **_k: {})
    with pytest.raises(distribution.DisposableWslDistributionError):
        lease.cleanup()
    assert not commands and not lease.cleaned and lease.install_root.is_dir()


def test_registration_replacement_after_termination_blocks_unregister(tmp_path, monkeypatch):
    lease, state, commands, command = _lease(tmp_path, monkeypatch)

    def replace(*args, **kwargs):
        result = command(*args, **kwargs)
        state["guid"] = "replacement"
        return result

    monkeypatch.setattr(distribution, "_bounded_result", replace)
    with pytest.raises(distribution.DisposableWslDistributionError, match="identity changed"):
        lease.cleanup()
    assert commands == ["--terminate"] and not lease.cleaned


@pytest.mark.parametrize("fault", ["registration_returns", "disk_retained", "unregister_failure"])
def test_cleanup_never_reports_completion_before_both_registration_and_storage_absence(
    tmp_path, monkeypatch, fault
):
    lease, state, commands, command = _lease(tmp_path, monkeypatch)
    if fault == "disk_retained":
        (lease.install_root / "retained.vhdx").write_bytes(b"test-owned")

    def fail(*args, **kwargs):
        result = command(*args, **kwargs)
        if result.args[0] == "--unregister":
            if fault == "registration_returns":
                state["registered"] = True
            elif fault == "unregister_failure":
                result.returncode = 1
        return result

    monkeypatch.setattr(distribution, "_bounded_result", fail)
    with pytest.raises(distribution.DisposableWslDistributionError):
        lease.cleanup()
    assert commands == ["--terminate", "--unregister"]
    assert not lease.cleaned and lease.install_root.is_dir()


@pytest.mark.parametrize("fault", ["nonzero", "stderr", "missing_executable"])
def test_strict_absence_requires_successful_cli_while_readiness_keeps_legacy_fallback(
    tmp_path, monkeypatch, fault
):
    executable = tmp_path / "management.exe"
    if fault != "missing_executable":
        executable.touch()
    name = "BlueFire-Gate11-Run-0123456789abcdef"
    facts = _facts(name, ready=False)
    monkeypatch.setattr(readiness, "os", SimpleNamespace(name="nt", fspath=str))
    monkeypatch.setattr(readiness, "_probe_wsl_registry", lambda _: facts)
    monkeypatch.setattr(readiness, "_trusted_wsl_executable", lambda: executable)

    def run(command, **kwargs):
        if fault == "stderr":
            kwargs["stderr"].write(b"management failure")
        return subprocess.CompletedProcess(command, 1 if fault == "nonzero" else 0)

    monkeypatch.setattr(readiness.subprocess, "run", run)
    assert readiness.probe_wsl_distribution(name)["probe_state"] == "absent"
    assert (
        readiness.probe_wsl_distribution(name, require_cli=True)["probe_state"] == "indeterminate"
    )


def test_failed_clone_retains_ownership_storage_when_cleanup_probe_is_indeterminate(
    tmp_path, monkeypatch
):
    token = "0123456789abcdef"
    started = []

    def clone(*_args, **_kwargs):
        started.append(True)
        raise distribution.DisposableWslDistributionError("original clone failure")

    def probe(name, **_kwargs):
        if name == readiness.WSL_DISTRIBUTION_ID:
            return _facts(name, ready=True)
        return {} if started else _facts(name, ready=False)

    monkeypatch.setattr(distribution, "probe_wsl_distribution", probe)
    monkeypatch.setattr(distribution, "registration", lambda _: None)
    monkeypatch.setattr(distribution, "_distribution_storage_parent", lambda: tmp_path)
    monkeypatch.setattr(distribution.secrets, "token_hex", lambda _: token)
    monkeypatch.setattr(distribution, "_stream_clone", clone)
    with pytest.raises(distribution.DisposableWslDistributionError, match="could not be cleaned"):
        distribution.create_disposable_wsl_distribution(Path(sys.executable), tmp_path)
    assert (tmp_path / ("wsl-distribution-" + token)).is_dir()


def test_strict_absence_reconciles_successful_cli_and_registry(tmp_path, monkeypatch):
    executable = tmp_path / "management.exe"
    executable.touch()
    name = "BlueFire-Gate11-Run-0123456789abcdef"
    monkeypatch.setattr(readiness, "os", SimpleNamespace(name="nt", fspath=str))
    monkeypatch.setattr(readiness, "_probe_wsl_registry", lambda _: _facts(name, ready=False))
    monkeypatch.setattr(readiness, "_trusted_wsl_executable", lambda: executable)
    listing = ["  NAME STATE VERSION\n  DedicatedBase Stopped 2\n"]

    def run(command, **kwargs):
        kwargs["stdout"].write(listing[0].encode("utf-16-le"))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(readiness.subprocess, "run", run)
    assert readiness.probe_wsl_distribution(name, require_cli=True)["probe_state"] == "absent"
    listing[0] += "  " + name + " Stopped 2\n"
    assert (
        readiness.probe_wsl_distribution(name, require_cli=True)["probe_state"] == "indeterminate"
    )
