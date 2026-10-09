"""A descriptor-pinned Linux watchdog retains the active installed environment."""

from __future__ import annotations

import json
import os
import stat
import sys
import venv
from pathlib import Path

import pytest

from bluefire.runner_client import SubprocessRustRunner
from bluefire.runner_python_environment import ActivePythonEnvironment
from bluefire.runner_transport_errors import RunnerTransportError
from bluefire.util import file_hash

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux FD exec")


@pytest.fixture(params=[True, False], ids=["symlink", "copy"])
def installed_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request):
    symlinks = request.param
    environment = tmp_path / "installed environment"
    venv.EnvBuilder(with_pip=False, symlinks=symlinks).create(environment)
    launcher = environment / "bin/python"
    assert launcher.is_symlink() is symlinks
    site = (
        environment / f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages"
    )
    marker = site / "bluefire_test_venv_dependency.py"
    marker.write_text("VALUE = 'installed-only'\n", encoding="utf-8")
    monkeypatch.setattr(sys, "executable", str(launcher))
    monkeypatch.setattr(sys, "prefix", str(environment))
    return environment, launcher, marker


@pytest.fixture
def copied_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    environment = tmp_path / "copied installed environment"
    venv.EnvBuilder(with_pip=False, symlinks=False).create(environment)
    launcher = environment / "bin/python"
    assert launcher.is_file() and not launcher.is_symlink()
    monkeypatch.setattr(sys, "executable", str(launcher))
    monkeypatch.setattr(sys, "prefix", str(environment))
    return environment, launcher


def test_watchdog_preserves_venv_with_pinned_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, installed_environment
) -> None:
    environment, launcher, marker = installed_environment
    # Ambient module/launcher overrides must never enter the launch environment.
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "untrusted"))
    monkeypatch.setenv("__PYVENV_LAUNCHER__", str(tmp_path / "untrusted/python"))
    runtime = Path(sys._base_executable).resolve(strict=True)
    runner = SubprocessRustRunner(runtime, tmp_path / "work")
    script = tmp_path / "runner_watchdog.py"
    script.write_text(
        "import json, os, pathlib, sys, time\n"
        "import bluefire_test_venv_dependency as dependency\n"
        "root = pathlib.Path(sys.argv[1]).parent\n"
        "(root / 'probe.json').write_text(json.dumps({'prefix': sys.prefix, "
        "'executable': sys.executable, 'actual_executable': os.readlink('/proc/self/exe'), "
        "'isolated': sys.flags.isolated, 'dependency': dependency.__file__, "
        "'value': dependency.VALUE, 'pythonpath': os.environ.get('PYTHONPATH'), "
        "'launcher_override': os.environ.get('__PYVENV_LAUNCHER__')}))\n"
        "ready = root / 'ready.json'\n"
        "ready.write_text(json.dumps({'schema_version': 'bluefire.runner-watchdog-ready.v1', "
        "'task_id': 'test-venv', 'watchdog_pid': os.getpid()}))\n"
        "ready.chmod(0o600)\n"
        "deadline = time.monotonic() + 10\n"
        "while not (root / 'finish').exists() and time.monotonic() < deadline: time.sleep(.01)\n",
        encoding="utf-8",
    )
    runner.watchdog_script = script
    runner.watchdog_script_digest = file_hash(script)
    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    config = control / "config.json"
    config.write_text("{}", encoding="utf-8")
    processes = []
    try:
        process = runner._spawn_watchdog(
            config, receiver_environment={}, task_id="test-venv", process_sink=processes
        )
        result = json.loads((control / "probe.json").read_text())
        assert result == {
            "prefix": str(environment),
            "executable": str(launcher),
            "actual_executable": str(runtime),
            "isolated": 1,
            "dependency": str(marker),
            "value": "installed-only",
            "pythonpath": None,
            "launcher_override": None,
        }
        (control / "finish").touch(mode=0o600)
        assert runner._finish_posix_process_group(process)
        assert process.returncode == 0
    finally:
        for process in processes:
            assert runner._terminate_process_tree(process)


def test_protected_copied_venv_launcher_matches_base_runtime(
    tmp_path: Path, copied_environment
) -> None:
    _, launcher = copied_environment
    runtime = Path(sys._base_executable).resolve(strict=True)
    assert file_hash(launcher) == file_hash(runtime)

    environment = ActivePythonEnvironment.capture(runtime)

    assert environment is not None
    assert environment.recheck(runtime) == str(launcher)


def test_copied_venv_launcher_with_different_contents_refuses_before_capture(
    copied_environment,
) -> None:
    _, launcher = copied_environment
    launcher.write_bytes(b"not the protected base interpreter")
    launcher.chmod(0o755)

    with pytest.raises(RunnerTransportError, match="application environment"):
        ActivePythonEnvironment.capture(Path(sys._base_executable).resolve(strict=True))


def test_changed_copied_launcher_refuses_on_recheck(copied_environment) -> None:
    _, launcher = copied_environment
    runtime = Path(sys._base_executable).resolve(strict=True)
    environment = ActivePythonEnvironment.capture(runtime)
    assert environment is not None
    launcher.write_bytes(launcher.read_bytes() + b"changed")

    with pytest.raises(RunnerTransportError, match="application environment changed"):
        environment.recheck(runtime)


@pytest.mark.parametrize("change", ["contents", "replacement", "symlink"])
def test_changed_venv_configuration_refuses_before_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, installed_environment, change: str
) -> None:
    environment, _, _ = installed_environment
    runner = SubprocessRustRunner(Path(sys._base_executable), tmp_path / "work")
    config = environment / "pyvenv.cfg"
    if change == "contents":
        config.write_text(config.read_text() + "\nchanged = true\n")
    else:
        replacement = environment / "replacement.cfg"
        replacement.write_bytes(config.read_bytes())
        config.unlink()
        if change == "replacement":
            replacement.rename(config)
        else:
            config.symlink_to(replacement)

    def forbidden_spawn(*_args, **_kwargs):
        pytest.fail("changed application environment reached process creation")

    monkeypatch.setattr(runner, "_spawn", forbidden_spawn)
    with pytest.raises(RunnerTransportError, match="application environment"):
        runner._spawn_watchdog(
            tmp_path / "config.json", receiver_environment={}, task_id="test-venv", process_sink=[]
        )


def test_writable_launcher_ancestor_refuses_before_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, installed_environment
) -> None:
    _, _, _ = installed_environment
    runner = SubprocessRustRunner(Path(sys._base_executable), tmp_path / "work")
    original_mode = tmp_path.stat().st_mode
    tmp_path.chmod(0o777)

    def forbidden_spawn(*_args, **_kwargs):
        pytest.fail("writable launcher ancestor reached process creation")

    monkeypatch.setattr(runner, "_spawn", forbidden_spawn)
    try:
        with pytest.raises(RunnerTransportError, match="application environment"):
            runner._spawn_watchdog(
                tmp_path / "config.json",
                receiver_environment={},
                task_id="test-venv",
                process_sink=[],
            )
    finally:
        tmp_path.chmod(stat.S_IMODE(original_mode))


def test_replaced_launcher_ancestor_refuses_before_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ancestor = tmp_path / "launcher-parent"
    ancestor.mkdir(mode=0o700)
    environment = ancestor / "installed environment"
    venv.EnvBuilder(with_pip=False, symlinks=True).create(environment)
    monkeypatch.setattr(sys, "executable", str(environment / "bin/python"))
    monkeypatch.setattr(sys, "prefix", str(environment))
    runner = SubprocessRustRunner(Path(sys._base_executable), tmp_path / "work")

    displaced = tmp_path / "displaced-parent"
    ancestor.rename(displaced)
    ancestor.mkdir(mode=0o700)
    os.rename(displaced / environment.name, ancestor / environment.name)

    def forbidden_spawn(*_args, **_kwargs):
        pytest.fail("replaced launcher ancestor reached process creation")

    monkeypatch.setattr(runner, "_spawn", forbidden_spawn)
    with pytest.raises(RunnerTransportError, match="application environment"):
        runner._spawn_watchdog(
            tmp_path / "config.json",
            receiver_environment={},
            task_id="test-venv",
            process_sink=[],
        )


def test_replaced_interpreter_symlink_refuses_before_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, installed_environment
) -> None:
    _, launcher, _ = installed_environment
    runtime = Path(sys._base_executable).resolve(strict=True)
    intermediate = tmp_path / "interpreter-target"
    intermediate.symlink_to(runtime)
    launcher.unlink()
    launcher.symlink_to(intermediate)
    runner = SubprocessRustRunner(Path(sys._base_executable), tmp_path / "work")
    replacement = tmp_path / "interpreter-target-replacement"
    replacement.symlink_to(runtime)
    os.replace(replacement, intermediate)

    def forbidden_spawn(*_args, **_kwargs):
        pytest.fail("replaced interpreter symlink reached process creation")

    monkeypatch.setattr(runner, "_spawn", forbidden_spawn)
    with pytest.raises(RunnerTransportError, match="application environment"):
        runner._spawn_watchdog(
            tmp_path / "config.json",
            receiver_environment={},
            task_id="test-venv",
            process_sink=[],
        )


def test_symlinked_launcher_ancestor_refuses_before_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, installed_environment
) -> None:
    environment, _, _ = installed_environment
    alias = tmp_path / "launcher-alias"
    alias.symlink_to(environment, target_is_directory=True)
    monkeypatch.setattr(sys, "executable", str(alias / "bin/python"))
    monkeypatch.setattr(sys, "prefix", str(environment))

    with pytest.raises(RunnerTransportError, match="application environment"):
        SubprocessRustRunner(Path(sys._base_executable), tmp_path / "work")


def test_interpreter_symlink_target_ancestor_must_be_protected(
    tmp_path: Path, installed_environment
) -> None:
    _, launcher, _ = installed_environment
    runtime = Path(sys._base_executable).resolve(strict=True)
    unsafe_parent = tmp_path / "unsafe-runtime-parent"
    unsafe_parent.mkdir(mode=0o777)
    unsafe_parent.chmod(0o777)
    target = unsafe_parent / "python-target"
    target.symlink_to(runtime)
    launcher.unlink()
    launcher.symlink_to(target)

    with pytest.raises(RunnerTransportError, match="application environment"):
        SubprocessRustRunner(runtime, tmp_path / "work")


def test_interpreter_symlink_with_parent_component_refuses_before_capture(
    tmp_path: Path, installed_environment
) -> None:
    _, launcher, _ = installed_environment
    runtime = Path(sys._base_executable).resolve(strict=True)
    intermediate = launcher.parent / "runtime-parent"
    intermediate.symlink_to(runtime.parent, target_is_directory=True)
    launcher.unlink()
    launcher.symlink_to(f"runtime-parent/../{runtime.parent.name}/{runtime.name}")

    with pytest.raises(RunnerTransportError, match="application environment"):
        SubprocessRustRunner(runtime, tmp_path / "work")


def test_unrelated_sibling_change_keeps_environment_identity(
    tmp_path: Path, installed_environment
) -> None:
    _, _, _ = installed_environment
    runtime = Path(sys._base_executable).resolve(strict=True)
    environment = ActivePythonEnvironment.capture(runtime)
    assert environment is not None
    (tmp_path / "unrelated-sibling").write_text("unrelated\n", encoding="utf-8")
    assert environment.recheck(runtime) == str(environment.launcher)


@pytest.mark.parametrize("change", ["launcher", "path", "descriptor", "grammar", "script"])
def test_executable_override_is_limited_to_captured_watchdog(
    tmp_path: Path, installed_environment, change: str
) -> None:
    _, launcher, _ = installed_environment
    runtime = Path(sys._base_executable).resolve(strict=True)
    environment = ActivePythonEnvironment.capture(runtime)
    assert environment is not None
    descriptor = os.open(runtime, os.O_RDONLY)
    script = os.open(__file__, os.O_RDONLY)
    try:
        executable = f"/proc/self/fd/{descriptor}"
        descriptors = (descriptor, script)
        argv = [
            str(launcher),
            "-I",
            "-B",
            "-X",
            "utf8",
            f"/proc/self/fd/{script}",
            str(tmp_path / "config.json"),
        ]
        if change == "launcher":
            argv[0] = str(runtime)
        elif change == "path":
            executable = str(runtime)
        elif change == "descriptor":
            descriptors = (script,)
        elif change == "grammar":
            argv[1] = "-c"
        else:
            argv[5] = __file__
        with pytest.raises(RunnerTransportError, match="executable context"):
            environment.validate_exec(argv, executable, descriptors, runtime)
    finally:
        os.close(script)
        os.close(descriptor)


def test_non_venv_runtime_has_no_launcher_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "prefix", sys.base_prefix)
    assert ActivePythonEnvironment.capture(Path(sys._base_executable)) is None
