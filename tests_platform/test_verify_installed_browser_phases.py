"""Lifecycle gates for serial independent phases in the installed browser verifier."""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

import pytest

from tools import verify_installed_browser as browser
from tools.verify_installed_browser import (
    _PRIMARY_PHASE_CLEANUP_KEYS,
    _phase_timeout,
    _receiver_phase_block_reason,
    _receiver_retained_redaction_accepted,
    _required_phases_passed,
    _run_receiver_phase,
    _runtime_process_cleanup_confirmed,
)


def clean_primary_report() -> dict[str, object]:
    return {key: True for key in _PRIMARY_PHASE_CLEANUP_KEYS}


def test_receiver_can_follow_an_assistant_failure_only_after_primary_cleanup() -> None:
    report = clean_primary_report()
    report.update(
        {
            "browser_phase_status": "passed",
            "assistant_fixture_phase_status": "failed",
            "receiver_phase_status": "passed",
        }
    )

    assert _receiver_phase_block_reason(report, runtime_admitted=True, work_remaining=30) is None
    assert not _required_phases_passed(report)


@pytest.mark.parametrize(
    ("browser_status", "runtime_admitted", "work_remaining", "changed_key", "expected"),
    [
        ("passed", False, 30, None, "installed_runtime_not_admitted"),
        ("failed", True, 30, None, "primary_browser_phase_not_passed"),
        ("not_attempted", True, 30, None, "primary_browser_phase_not_passed"),
        ("passed", True, 30, "service_closed", "primary_phase_cleanup_unconfirmed"),
        ("passed", True, 0, None, "outer_work_deadline_reached"),
        ("passed", True, None, None, "outer_work_deadline_reached"),
    ],
)
def test_receiver_is_not_attempted_without_admission_cleanup_or_budget(
    browser_status: str,
    runtime_admitted: bool,
    work_remaining: float | None,
    changed_key: str | None,
    expected: str,
) -> None:
    report = clean_primary_report()
    report["browser_phase_status"] = browser_status
    if changed_key is not None:
        report[changed_key] = False

    assert (
        _receiver_phase_block_reason(
            report, runtime_admitted=runtime_admitted, work_remaining=work_remaining
        )
        == expected
    )


def test_phase_timeout_never_exceeds_child_cap_or_outer_deadline() -> None:
    assert _phase_timeout(350.0, 240.0, now=100.0) == 240.0
    assert _phase_timeout(120.0, 360.0, now=100.0) == 20.0
    assert _phase_timeout(100.0, 360.0, now=100.0) is None


def test_unstarted_receiver_is_not_treated_as_unclean_or_as_receiver_proof() -> None:
    report = clean_primary_report()
    report.update(
        {
            "receiver_phase_status": "not_attempted",
            "receiver_driver_started": False,
            "receiver_driver_cleanup_confirmed": False,
            "receiver_process_group_stopped": True,
            "receiver_service_thread_stopped": True,
            "receiver_http_server_closed": True,
            "receiver_service_closed": True,
            "temporary_state_removed": True,
            "cleanup_errors": [],
            "receiver_retained_redaction_driver_passed": False,
        }
    )

    assert _runtime_process_cleanup_confirmed(report)
    assert not _receiver_retained_redaction_accepted(report)


def test_started_receiver_requires_its_driver_cleanup_confirmation() -> None:
    report = clean_primary_report()
    report.update(
        {
            "receiver_phase_status": "failed",
            "receiver_driver_started": True,
            "receiver_driver_cleanup_confirmed": False,
            "receiver_process_group_stopped": True,
            "receiver_service_thread_stopped": True,
            "receiver_http_server_closed": True,
            "receiver_service_closed": True,
        }
    )

    assert not _runtime_process_cleanup_confirmed(report)
    report["receiver_driver_cleanup_confirmed"] = True
    assert _runtime_process_cleanup_confirmed(report)

    report["receiver_phase_status"] = "passed"
    report["receiver_driver_started"] = False
    assert not _runtime_process_cleanup_confirmed(report)


def test_receiver_service_uses_owned_parent_environment_and_restores_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "output"
    runtime = output / "runtime"
    output.mkdir()
    runtime.mkdir()
    driver = tmp_path / "driver.mjs"
    guard = tmp_path / "receiver-guards.mjs"
    deadline_file = tmp_path / "receiver-deadline.mjs"
    for path in (driver, guard, deadline_file):
        path.write_text("// fixture\n", encoding="utf-8")
    primary_cwd = Path.cwd()
    primary_environment = dict(os.environ)
    events: list[tuple[str, str, Path, Path | None, Path | None]] = []
    report: dict[str, object] = {
        "status": "failed_or_incomplete",
        "receiver_driver_cleanup_confirmed": False,
        "receiver_driver_started": False,
    }
    cleanup_errors: list[str] = []

    class FakeLifecycle:
        def __init__(self, root: Path) -> None:
            self.root = root

    class FakeService:
        def __init__(self, *, runs_dir: Path, runner_lifecycle: FakeLifecycle) -> None:
            events.append(
                (
                    "service_init",
                    os.environ["HOME"],
                    Path.cwd(),
                    runs_dir,
                    runner_lifecycle.root,
                )
            )
            self.runs_dir = runs_dir
            self.runner_lifecycle = runner_lifecycle

        def close(self) -> None:
            events.append(("service_close", os.environ["HOME"], Path.cwd(), None, None))

    class FakeServer:
        server_address = ("127.0.0.1", 41999)

        def __init__(self) -> None:
            self.stopped = threading.Event()

        def serve_forever(self) -> None:
            self.stopped.wait()

        def shutdown(self) -> None:
            self.stopped.set()

        def server_close(self) -> None:
            pass

    class FakeChild:
        returncode = 0

        def communicate(self, _input: bytes, *, timeout: float) -> None:
            assert timeout <= 360
            (output / "installed-receiver-report.json").write_text(
                json.dumps({"cleanup": {}}), encoding="utf-8"
            )

    server = FakeServer()
    monkeypatch.setattr(browser.subprocess, "Popen", lambda *args, **kwargs: FakeChild())
    monkeypatch.setattr(browser, "stop_group", lambda _process: True)

    _run_receiver_phase(
        report=report,
        driver=driver,
        guards=guard,
        deadline_file=deadline_file,
        node=Path("node"),
        playwright=Path("playwright"),
        output=output,
        runtime=runtime,
        environment={
            "PATH": "receiver-path",
            "HOME": str(runtime / "primary-home"),
            "XDG_STATE_HOME": str(runtime / "primary-state"),
            "XDG_CONFIG_HOME": str(runtime / "primary-state"),
            "XDG_CACHE_HOME": str(runtime / "primary-temp"),
            "TMPDIR": str(runtime / "primary-temp"),
            "LANG": "C.UTF-8",
            "PLAYWRIGHT_BROWSERS_PATH": str(runtime / "browser-cache"),
            "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD": "1",
        },
        work_deadline=time.monotonic() + 30,
        service_type=FakeService,
        runner_lifecycle_type=FakeLifecycle,
        create_server=lambda *_args, **_kwargs: server,
        generate_capability=lambda: "test-capability",
        cleanup_errors=cleanup_errors,
    )

    receiver_home = str(runtime / "receiver" / "home")
    assert events == [
        (
            "service_init",
            receiver_home,
            runtime / "receiver" / "work",
            runtime / "receiver" / "runs",
            runtime / "receiver" / "managed-runner",
        ),
        ("service_close", receiver_home, runtime / "receiver" / "work", None, None),
    ]
    assert os.environ == primary_environment
    assert Path.cwd() == primary_cwd
    assert cleanup_errors == []
    assert report["receiver_phase_status"] == "failed"


@pytest.mark.parametrize(
    ("browser", "assistant", "receiver", "expected"),
    [
        ("passed", "passed", "passed", True),
        ("passed", "failed", "passed", False),
        ("passed", "not_attempted", "passed", False),
        ("passed", "not_requested", "passed", True),
        ("passed", "not_requested", "not_attempted", False),
        ("failed", "not_attempted", "passed", False),
    ],
)
def test_overall_phase_result_is_a_conjunction(
    browser: str, assistant: str, receiver: str, expected: bool
) -> None:
    report = {
        "browser_phase_status": browser,
        "assistant_fixture_phase_status": assistant,
        "receiver_phase_status": receiver,
    }

    assert _required_phases_passed(report) is expected
