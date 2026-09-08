"""Managed-host deadline fixture: Python sleep/result only, no native action."""

import sys
from pathlib import Path

from bluefire import runner_host
from bluefire.runner_client import SubprocessRustRunner
from bluefire.runner_host import serve_managed_runner
from bluefire.runner_transport import AuthenticatedRunnerServer
from tests_platform.runner_lifecycle_host_helper import (
    ProcessFixtureRunner,
    ProcessTestSecretProvider,
)
from tests_platform.test_runner_cancellation import _HELPER


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
    runner = TimedFixtureRunner(binary, root, timeout_seconds=float(timeout))
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
