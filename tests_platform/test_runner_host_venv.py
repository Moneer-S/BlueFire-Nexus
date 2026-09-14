"""The production host command must load its installed environment in -I mode."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import venv
from pathlib import Path

import pytest

from bluefire.runner_host import default_host_command


def _command(root: Path) -> tuple[str, ...]:
    return default_host_command(
        enrollment_root=root / "enrollment",
        runner_binary=root / "runner",
        work_root=root / "sandbox",
        state_path=root / "state.sqlite3",
        process_record_path=root / "process.json",
        start_gate_path=root / "start.gate",
        launch_id="a" * 64,
        runner_timeout_seconds=35,
    )


def test_host_command_keeps_current_interpreter_path(tmp_path: Path) -> None:
    command = _command(tmp_path)
    assert command[0] == str(Path(sys.executable).absolute())
    assert command[1:4] == ("-I", "-m", "bluefire.runner_host")


@pytest.mark.skipif(os.name != "posix", reason="POSIX venv uses interpreter symlinks")
def test_host_command_loads_installed_module_from_symlink_venv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment = tmp_path / "installed environment"
    venv.EnvBuilder(with_pip=False, symlinks=True).create(environment)
    python = environment / "bin" / "python"
    assert python.is_symlink()
    probe = subprocess.run(
        [str(python), "-I", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    package = Path(probe.stdout.strip()) / "bluefire"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    # A module-loading witness only: no server, native runner, or effects.
    (package / "runner_host.py").write_text(
        "import json, sys\n"
        "print(json.dumps({'prefix': sys.prefix, 'isolated': sys.flags.isolated}))\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "executable", str(python))
    completed = subprocess.run(
        _command(tmp_path),
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert json.loads(completed.stdout) == {"prefix": str(environment), "isolated": 1}
