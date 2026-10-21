"""Pure contracts for the installed CLI restart and saved-reopen verifier."""

from __future__ import annotations

import hashlib
import io
import signal
from copy import deepcopy
from pathlib import Path
from unittest.mock import Mock

import pytest

from tools import verify_installed_reopen as verifier
from tools.verify_installed_reopen import (
    _URL_RE,
    _browser_report_passed,
    _capability_digest,
    _cleanup_accepted,
    _cli_output_diagnostic,
    _digest,
    _first_stop_precedes_restart,
    _fresh_capability,
    _installed_cli_command,
    _read_cli_stream,
    _read_state,
    _restart_order_confirmed,
    _run_driver,
    _started_groups_stopped,
    _valid_state,
)


def fixture_state() -> dict[str, object]:
    return {
        "schema_version": "bluefire.installed-reopen.fixture-state.v1",
        "scenario_id": "scenario.installed-reopen.fixture.v1",
        "source_example_id": "scenario.endpoint.lab-collection-methods.v1",
        "versions": [
            {
                "version": 1,
                "digest": "sha256:" + "a" * 64,
                "document": {
                    "id": "scenario.installed-reopen.fixture.v1",
                    "title": "Fixture v1",
                    "steps": [],
                },
            },
            {
                "version": 2,
                "digest": "sha256:" + "b" * 64,
                "document": {
                    "id": "scenario.installed-reopen.fixture.v1",
                    "title": "Fixture v2",
                    "steps": [],
                },
            },
        ],
    }


def clean_report() -> dict[str, object]:
    return {
        "status": "passed",
        "first_cli_process_stopped": True,
        "second_cli_process_stopped": True,
        "pass_1_cli_process_group_started": True,
        "pass_2_cli_process_group_started": True,
        "pass_1_cli_process_group_stopped": True,
        "pass_2_cli_process_group_stopped": True,
        "first_browser_group_started": True,
        "second_browser_group_started": True,
        "first_browser_group_stopped": True,
        "second_browser_group_stopped": True,
        "restart_order_confirmed": True,
        "fresh_capability_confirmed": True,
        "pass_1_cli_returncode": 130,
        "pass_2_cli_returncode": 130,
        "checks": [
            "fresh_cli_process_saved_two_fixture_versions",
            "old_cli_process_stopped_before_restart",
            "distinct_capability_and_fresh_browser_after_restart",
            "fresh_authenticated_server_reads_matched_both_saved_versions",
        ],
        "temporary_runtime_removed": True,
    }


def browser_report(mode: str) -> dict[str, object]:
    report = {
        "schema_version": "bluefire.installed-reopen.browser-report.v1",
        "mode": mode,
        "status": "passed",
        "fixture_identity": "packaged collection example copied to owned fixture scenario",
        "native_execution": False,
        "live_model_inference": False,
        "checks": [
            (
                "packaged_example_seeded_as_owned_fixture_then_second_version_saved_through_ui"
                if mode == "create"
                else "both_versions_opened_and_reread_with_current_head_from_fresh_server"
            )
        ],
        "blocked_requests": [],
        "errors": [],
    }
    if mode == "reopen":
        report["verified_state"] = fixture_state()
    return report


def test_capability_announcement_parser_accepts_only_exact_loopback_fragment() -> None:
    match = _URL_RE.fullmatch("http://127.0.0.1:49152/#bluefire-session=" + "A" * 64)
    assert match is not None
    assert match.groups() == ("49152", "A" * 64)
    for value in (
        "http://localhost:49152/#bluefire-session=" + "A" * 64,
        "http://127.0.0.1:49152/#bluefire-session=" + "A" * 63,
        "http://127.0.0.1:49152/?token=" + "A" * 64,
        "http://127.0.0.1:49152/#bluefire-session=" + "A" * 64 + "extra",
    ):
        assert _URL_RE.fullmatch(value) is None


def test_installed_command_uses_the_declared_cli_module_entrypoint(tmp_path) -> None:
    root = Path(__file__).resolve().parents[1]
    command = _installed_cli_command("/owned/venv/bin/python", tmp_path / "runs")

    assert command == [
        "/owned/venv/bin/python",
        "-I",
        "-B",
        "-m",
        "bluefire.cli",
        "--runs-dir",
        str(tmp_path / "runs"),
        "ui",
        "--host",
        "127.0.0.1",
        "--port",
        "0",
        "--no-browser",
    ]
    assert not (root / "bluefire" / "__main__.py").exists()
    assert '[project.scripts]\nbluefire = "bluefire.cli:main"' in (
        root / "pyproject.toml"
    ).read_text(encoding="utf-8")
    assert 'if __name__ == "__main__":' in (root / "bluefire" / "cli.py").read_text(
        encoding="utf-8"
    )


def test_signal_number_accepts_the_standard_signal_enum_and_refuses_missing(monkeypatch) -> None:
    assert verifier._signal_number("SIGINT") == signal.SIGINT
    monkeypatch.setattr(verifier.signal, "SIGINT", True)
    with pytest.raises(RuntimeError, match="signals are unavailable"):
        verifier._signal_number("SIGINT")
    with pytest.raises(RuntimeError, match="signals are unavailable"):
        verifier._signal_number("BLUEFIRE_MISSING_SIGNAL")


def test_cli_output_diagnostics_match_real_announcement_without_retaining_credentials() -> None:
    capability = "A" * 64
    state: dict[str, object] = {"overflow": False}
    lock = verifier.threading.Lock()
    stderr = io.BytesIO(
        (
            f"BlueFire local console: http://127.0.0.1:49152/#bluefire-session={capability}\n"
            f"One-time connection code: {capability}\n"
        ).encode("ascii")
    )

    _read_cli_stream(stderr, stderr=True, state=state, lock=lock)
    diagnostic = _cli_output_diagnostic(state, returncode=None)

    assert state["port"] == 49152
    assert diagnostic == {
        "stdout_bytes": 0,
        "stderr_bytes": len(stderr.getvalue()),
        "stderr_lines": 2,
        "console_announcement_lines": 1,
        "valid_console_announcements": 1,
        "connection_code_lines": 1,
        "valid_connection_codes": 1,
        "oversized_stderr_lines": 0,
        "stream_overflow": False,
        "announced_fields_match": True,
        "returncode": None,
    }
    assert capability not in repr(diagnostic)
    assert "url_capability" not in diagnostic
    assert "code" not in diagnostic


def test_cli_output_diagnostics_distinguish_missing_or_malformed_announcement() -> None:
    capability = "B" * 64
    state: dict[str, object] = {"overflow": False}
    lock = verifier.threading.Lock()
    stderr = io.BytesIO(
        (
            "BlueFire local console: http://localhost:49152/#bluefire-session="
            f"{capability}\n"
            f"One-time connection code: {capability}\n"
        ).encode("ascii")
    )

    _read_cli_stream(stderr, stderr=True, state=state, lock=lock)
    diagnostic = _cli_output_diagnostic(state, returncode=1)

    assert diagnostic["console_announcement_lines"] == 1
    assert diagnostic["valid_console_announcements"] == 0
    assert diagnostic["valid_connection_codes"] == 1
    assert diagnostic["announced_fields_match"] is False
    assert diagnostic["returncode"] == 1
    assert capability not in repr(diagnostic)


def test_cli_output_diagnostics_count_an_oversized_unterminated_line() -> None:
    state: dict[str, object] = {"overflow": False}
    verifier._read_cli_stream(
        io.BytesIO(b"x" * 2049), stderr=True, state=state, lock=verifier.threading.Lock()
    )
    diagnostic = verifier._cli_output_diagnostic(state, returncode=1)
    assert diagnostic["stderr_bytes"] == 2049
    assert diagnostic["stderr_lines"] == 1
    assert diagnostic["oversized_stderr_lines"] == 1
    assert diagnostic["announced_fields_match"] is False


def test_saved_fixture_contract_requires_two_owned_sequential_digested_versions() -> None:
    state = fixture_state()
    assert _valid_state(state)
    mutations = (
        lambda value: value.update(scenario_id="scenario.foreign.v1"),
        lambda value: value["versions"][0].update(version=True),
        lambda value: value["versions"][1].update(version=3),
        lambda value: value["versions"][0].update(digest="not-a-digest"),
        lambda value: value["versions"][0]["document"].update(id="scenario.foreign.v1"),
        lambda value: value["versions"][1].update(document=value["versions"][0]["document"]),
        lambda value: value.update(unexpected="credential or path field"),
    )
    for mutate in mutations:
        changed = deepcopy(state)
        mutate(changed)
        assert not _valid_state(changed)


def test_state_reader_rejects_oversized_metadata(tmp_path) -> None:
    path = tmp_path / "fixture-state.json"
    path.write_bytes(b" " * (512 * 1024 + 1))
    try:
        _read_state(path)
    except RuntimeError as error:
        assert "size limit" in str(error)
    else:
        raise AssertionError("oversized fixture state was accepted")


def test_digest_streams_files_without_python311_file_digest(tmp_path) -> None:
    path = tmp_path / "wheel.whl"
    payload = b"bounded installed wheel digest\x00" * 4096
    path.write_bytes(payload)

    assert _digest(path) == hashlib.sha256(payload).hexdigest()


def test_browser_driver_uses_mutable_and_truthful_restart_contracts() -> None:
    driver = (
        Path(__file__).resolve().parents[1]
        / "frontend"
        / "tests"
        / "installed"
        / "installed-reopen.mjs"
    )
    source = driver.read_text(encoding="utf-8")

    assert "let { capability } = JSON.parse(input);" in source
    assert "const { capability } = JSON.parse(input);" not in source
    assert source.count('capability = "";') == 3
    assert "packaged_example_seeded_as_owned_fixture_then_second_version_saved_through_ui" in source


def test_browser_report_requires_expected_mode_and_clean_contract() -> None:
    assert _browser_report_passed(browser_report("create"), "create")
    assert _browser_report_passed(browser_report("reopen"), "reopen")
    for field, value in (
        ("status", "failed_or_incomplete"),
        ("native_execution", True),
        ("blocked_requests", [{"path": "/api/v1/runs"}]),
        ("errors", [{"stage": "journey", "kind": "failed"}]),
        ("unexpected", "extra field"),
    ):
        changed = browser_report("create")
        changed[field] = value
        assert not _browser_report_passed(changed, "create"), field
    changed = browser_report("reopen")
    changed["verified_state"]["scenario_id"] = "scenario.foreign.v1"
    assert not _browser_report_passed(changed, "reopen")


def test_restart_contract_requires_old_process_stopped_before_new_process() -> None:
    assert _first_stop_precedes_restart(["first_started", "first_stopped"])
    assert not _first_stop_precedes_restart(["first_started", "second_started", "first_stopped"])
    assert _restart_order_confirmed(
        ["first_started", "first_stopped", "second_started", "second_stopped"]
    )
    assert not _restart_order_confirmed(
        ["first_started", "second_started", "first_stopped", "second_stopped"]
    )


def test_restart_requires_distinct_one_time_capability_without_reporting_digest() -> None:
    first = "A" * 64
    second = "B" * 64
    first_digest = _capability_digest(first)

    assert not _fresh_capability(None, second)
    assert not _fresh_capability(first_digest, first)
    assert _fresh_capability(first_digest, second)


def test_browser_driver_group_is_stopped_when_communication_raises(monkeypatch, tmp_path) -> None:
    child = Mock(returncode=None)
    child.communicate.side_effect = OSError("pipe failed")
    stopped = []
    monkeypatch.setattr(verifier.subprocess, "Popen", lambda *_args, **_kwargs: child)
    monkeypatch.setattr(verifier, "_stop_group", lambda process: stopped.append(process) or True)

    try:
        _run_driver(
            node=tmp_path / "node",
            driver=tmp_path / "driver.mjs",
            playwright=tmp_path / "playwright.mjs",
            environment={},
            output=tmp_path,
            port=49152,
            capability="A" * 64,
            mode="create",
            state_path=None,
        )
    except OSError as error:
        assert str(error) == "pipe failed"
    else:
        raise AssertionError("driver communication failure was swallowed")

    assert stopped == [child]


def test_cleanup_evidence_is_required_for_acceptance() -> None:
    report = clean_report()
    assert _cleanup_accepted(report)
    for key in report:
        changed = clean_report()
        changed[key] = False
        assert not _cleanup_accepted(changed), key


def test_incomplete_preflight_can_remove_runtime_but_cannot_pass() -> None:
    report = clean_report()
    for key in (
        "pass_1_cli_process_group_started",
        "pass_2_cli_process_group_started",
        "first_browser_group_started",
        "second_browser_group_started",
        "first_cli_process_stopped",
        "second_cli_process_stopped",
        "pass_1_cli_process_group_stopped",
        "pass_2_cli_process_group_stopped",
        "first_browser_group_stopped",
        "second_browser_group_stopped",
    ):
        report[key] = False
    report["status"] = "failed_or_incomplete"

    assert _started_groups_stopped(report)
    assert not _cleanup_accepted(report)


def test_runtime_is_retained_when_any_started_group_lacks_stop_confirmation() -> None:
    report = clean_report()
    report["second_browser_group_started"] = False
    report["second_browser_group_stopped"] = False
    assert _started_groups_stopped(report)

    report["second_browser_group_started"] = True
    report["second_browser_group_stopped"] = False
    assert not _started_groups_stopped(report)

    report["second_browser_group_started"] = False
    report["second_browser_group_stopped"] = True
    assert not _started_groups_stopped(report)


def test_browser_driver_allowlists_initial_overview_reads_and_declares_globals() -> None:
    driver = (
        Path(__file__).resolve().parents[1]
        / "frontend"
        / "tests"
        / "installed"
        / "installed-reopen.mjs"
    )
    source = driver.read_text(encoding="utf-8")

    assert '|| path === "/api/v1/runs"' in source
    assert '|| path === "/api/v1/receiver-defense/jobs"' in source
    assert "/* global process, Buffer, fetch, sessionStorage, URL, URLSearchParams */" in source
