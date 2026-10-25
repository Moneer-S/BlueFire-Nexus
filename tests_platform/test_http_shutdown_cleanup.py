from __future__ import annotations

import unittest

from tools import verify_installed_browser as browser
from tools import verify_installed_windows_cancellation as windows


class FakeThread:
    def __init__(self, events: list[str], *, exits_on_join: bool = False) -> None:
        self.ident = 123
        self.alive = True
        self.exits_on_join = exits_on_join
        self.events = events

    def is_alive(self) -> bool:
        return self.alive

    def join(self, timeout: float) -> None:
        assert timeout == 10
        self.events.append("join")
        if self.exits_on_join:
            self.alive = False


class FakeServer:
    def __init__(self, events: list[str], *, shutdown_raises: bool = False) -> None:
        self.events = events
        self.shutdown_raises = shutdown_raises

    def shutdown(self) -> None:
        self.events.append("shutdown")
        if self.shutdown_raises:
            raise RuntimeError("injected shutdown error")

    def server_close(self) -> None:
        self.events.append("server_close")


class FakeEvent:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def set(self) -> None:
        self.events.append("release")


class HttpShutdownCleanupTests(unittest.TestCase):
    def test_fixture_receipt_separates_stopped_thread_from_shutdown_failure(self) -> None:
        events: list[str] = []
        fixture = browser.LocalGraphFixture.__new__(browser.LocalGraphFixture)
        fixture.release = FakeEvent(events)
        fixture.server = FakeServer(events, shutdown_raises=True)
        fixture.thread = FakeThread(events, exits_on_join=True)
        fixture.failed = False
        report: dict[str, object] = {
            "status": "passed",
            "fixture_thread_stopped": False,
            "fixture_http_server_closed": False,
        }
        cleanup_errors: list[str] = []

        browser._close_fixture_for_report(fixture, report, cleanup_errors)

        self.assertTrue(report["fixture_thread_stopped"])
        self.assertTrue(report["fixture_http_server_closed"])
        self.assertEqual(report["status"], "failed_or_incomplete")
        self.assertEqual(cleanup_errors, ["fixture_http_shutdown"])
        self.assertEqual(events, ["release", "shutdown", "join", "server_close"])

    def test_browser_helper_never_closes_socket_while_thread_is_live(self) -> None:
        events: list[str] = []
        errors: list[str] = []
        thread = FakeThread(events)
        server = FakeServer(events, shutdown_raises=True)

        stopped, closed = browser._stop_http_server(server, thread, "http", errors)

        self.assertFalse(stopped)
        self.assertFalse(closed)
        self.assertEqual(events, ["shutdown", "join"])
        self.assertIn("http_close_deferred_thread_alive", errors)

    def test_browser_helper_closes_only_after_thread_stops_and_records_shutdown_error(self) -> None:
        events: list[str] = []
        errors: list[str] = []
        thread = FakeThread(events, exits_on_join=True)
        server = FakeServer(events, shutdown_raises=True)

        stopped, closed = browser._stop_http_server(server, thread, "http", errors)

        self.assertTrue(stopped and closed)
        self.assertEqual(events, ["shutdown", "join", "server_close"])
        self.assertIn("http_shutdown", errors)

    def test_browser_helper_skips_shutdown_after_thread_already_exited(self) -> None:
        events: list[str] = []
        errors: list[str] = []
        thread = FakeThread(events)
        thread.alive = False
        server = FakeServer(events)

        stopped, closed = browser._stop_http_server(server, thread, "http", errors)

        self.assertTrue(stopped and closed)
        self.assertEqual(events, ["join", "server_close"])
        self.assertIn("http_thread_already_stopped", errors)

    def test_windows_absent_server_and_thread_are_reported_cleanly(self) -> None:
        report: dict[str, object] = {}

        (
            report["service_thread_stopped"],
            report["service_shutdown_succeeded"],
            report["service_http_server_closed"],
        ) = windows._stop_http_server(None, None, False)

        self.assertTrue(report["service_thread_stopped"])
        self.assertTrue(report["service_shutdown_succeeded"])
        self.assertTrue(report["service_http_server_closed"])

    def test_windows_helper_never_closes_socket_while_thread_is_live(self) -> None:
        events: list[str] = []
        thread = FakeThread(events)
        server = FakeServer(events, shutdown_raises=True)

        stopped, shutdown_succeeded, closed = windows._stop_http_server(server, thread, True)

        self.assertFalse(stopped)
        self.assertFalse(shutdown_succeeded)
        self.assertFalse(closed)
        self.assertEqual(events, ["shutdown", "join"])

    def test_windows_helper_closes_after_stopped_thread_but_keeps_failure_flag(self) -> None:
        events: list[str] = []
        thread = FakeThread(events, exits_on_join=True)
        server = FakeServer(events, shutdown_raises=True)

        stopped, shutdown_succeeded, closed = windows._stop_http_server(server, thread, True)

        self.assertTrue(stopped and closed)
        self.assertFalse(shutdown_succeeded)
        self.assertEqual(events, ["shutdown", "join", "server_close"])

    def test_windows_safe_removal_does_not_claim_shutdown_qualification(self) -> None:
        report = {
            "driver_job_created": False,
            "driver_job_empty": True,
            "driver_process_exited": True,
            "driver_input_writer_stopped": True,
            "managed_runner_stopped": True,
            "service_thread_stopped": True,
            "service_shutdown_succeeded": False,
            "service_http_server_closed": True,
            "service_closed": True,
            "witness_could_have_started": False,
            "witness_observer_stopped": True,
            "witness_process_handles_stopped": True,
            "witness_control_tree_removed": True,
        }

        self.assertTrue(windows._runtime_removal_allowed(report))
        self.assertFalse(windows._cleanup_qualified(report))
