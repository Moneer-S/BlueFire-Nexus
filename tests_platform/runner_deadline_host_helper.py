"""Managed-host deadline fixture: Python sleep/result only, no native action."""

import shutil
import sys
from dataclasses import replace
from pathlib import Path

from bluefire import runner_host
from bluefire.runner_client import SubprocessRustRunner
from bluefire.runner_host import serve_managed_runner
from bluefire.runner_transport import AuthenticatedRunnerServer
from bluefire.util import file_hash
from tests_platform.runner_lifecycle_host_helper import (
    ProcessFixtureRunner,
    ProcessTestSecretProvider,
)
from tests_platform.test_runner_cancellation import _HELPER


def deadline_bootstrap(**values):
    from tests_platform.test_runner_lifecycle import _fake_bootstrap

    bootstrap = _fake_bootstrap(**values)
    if bootstrap.manifest.platform != "macos":
        return bootstrap
    # The shared CI Python is an inventory fixture, not an owner-private launch
    # input. Match the existing cancellation fixture before exercising Darwin pins.
    runtime = bootstrap.sandbox_path / "fixture-runtime"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    binary = runtime / "python-runner"
    for target in (binary, runtime / "python-watchdog"):
        shutil.copyfile(bootstrap.binary_path, target)
        target.chmod(0o700)
    digest = file_hash(binary).removeprefix("sha256:")
    return replace(
        bootstrap,
        binary_path=binary,
        binary_sha256=digest,
        manifest=replace(bootstrap.manifest, size=binary.stat().st_size, sha256=digest),
    )


class TimedFixtureRunner(SubprocessRustRunner):
    def inventory(self):
        return ProcessFixtureRunner(self.runner_binary, self.platform_name).inventory()


class ShortIngressServer(AuthenticatedRunnerServer):
    def __init__(self, *args, **kwargs):
        assert kwargs["socket_timeout_seconds"] == 10.0
        kwargs["socket_timeout_seconds"] = 0.5
        super().__init__(*args, **kwargs)


def main():
    enrollment, binary, work, state, record, gate, launch_id, platform_name, timeout = sys.argv[1:]
    root = Path(work)
    # Existing fixed Python executable fixture; only the selected sleep behavior
    # changes to a short duration and publishes a test synchronization marker.
    code = _HELPER.replace(
        'if behavior == "sleep":\n    time.sleep(60)',
        'if behavior == "sleep":\n    open("fixture-started", "w").close()\n    time.sleep(1.25)',
    )
    (root / "execute").write_text(code, encoding="utf-8")
    watchdog = Path(binary).parent / "python-watchdog" if platform_name == "macos" else None
    runner = TimedFixtureRunner(
        binary, root, timeout_seconds=float(timeout), _watchdog_interpreter=watchdog
    )
    runner.platform_name = platform_name
    runner_host.AuthenticatedRunnerServer = ShortIngressServer
    serve_managed_runner(
        enrollment_root=enrollment,
        runner_binary=binary,
        work_root=work,
        state_path=state,
        process_record_path=record,
        start_gate_path=gate,
        launch_id=launch_id,
        runner_timeout_seconds=float(timeout),
        secret_provider=ProcessTestSecretProvider(),
        runner=runner,
    )


if __name__ == "__main__":
    main()
