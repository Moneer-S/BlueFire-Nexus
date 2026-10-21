"""Verify installed CLI restart and saved scenario reopen on Linux.

Copy this verifier and its browser driver outside the source checkout. Run it
with the isolated Python that has the built wheel installed.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import sysconfig
import threading
import time
from pathlib import Path

_SCENARIO_ID = "scenario.installed-reopen.fixture.v1"
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CAP_RE = re.compile(r"[A-Za-z0-9_-]{64}\Z")
_URL_RE = re.compile(
    r"http://127\.0\.0\.1:([1-9][0-9]{0,4})/#bluefire-session=([A-Za-z0-9_-]{64})\Z"
)
_MAX_STREAM_BYTES = 64 * 1024
_MAX_STATE_BYTES = 512 * 1024
_MAX_REPORT_BYTES = 1024 * 1024
_MAX_DRIVER_SECONDS = 180


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_new(path: Path, value: object) -> None:
    encoded = json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    if len(encoded) > _MAX_STATE_BYTES:
        raise RuntimeError("bounded report exceeded its size limit")
    with path.open("xb") as stream:
        stream.write(encoded)


def _read_state(path: Path) -> dict[str, object]:
    with path.open("rb") as stream:
        raw = stream.read(_MAX_STATE_BYTES + 1)
    if len(raw) > _MAX_STATE_BYTES:
        raise RuntimeError("saved fixture metadata exceeded its size limit")
    value = json.loads(raw)
    if not _valid_state(value):
        raise RuntimeError("saved fixture metadata did not satisfy its contract")
    return value


def _read_browser_report(path: Path, mode: str) -> dict[str, object]:
    with path.open("rb") as stream:
        raw = stream.read(_MAX_REPORT_BYTES + 1)
    if len(raw) > _MAX_REPORT_BYTES:
        raise RuntimeError("browser report exceeded its size limit")
    value = json.loads(raw)
    if not _browser_report_passed(value, mode):
        raise RuntimeError("browser report did not satisfy its contract")
    return value


def _browser_report_passed(value: object, mode: str) -> bool:
    if mode not in ("create", "reopen") or not isinstance(value, dict):
        return False
    required = {
        "schema_version",
        "mode",
        "status",
        "fixture_identity",
        "native_execution",
        "live_model_inference",
        "checks",
        "blocked_requests",
        "errors",
    }
    if mode == "reopen":
        required.add("verified_state")
    expected_check = (
        "packaged_example_seeded_as_owned_fixture_then_second_version_saved_through_ui"
        if mode == "create"
        else "both_versions_opened_and_reread_with_current_head_from_fresh_server"
    )
    return (
        set(value) == required
        and value.get("schema_version") == "bluefire.installed-reopen.browser-report.v1"
        and value.get("mode") == mode
        and value.get("status") == "passed"
        and value.get("fixture_identity")
        == "packaged collection example copied to owned fixture scenario"
        and value.get("native_execution") is False
        and value.get("live_model_inference") is False
        and value.get("checks") == [expected_check]
        and value.get("blocked_requests") == []
        and value.get("errors") == []
        and (mode != "reopen" or _valid_state(value.get("verified_state")))
    )


def _valid_state(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "scenario_id",
        "versions",
        "source_example_id",
    }:
        return False
    rows = value.get("versions")
    if (
        value.get("schema_version") != "bluefire.installed-reopen.fixture-state.v1"
        or value.get("scenario_id") != _SCENARIO_ID
        or value.get("source_example_id") != "scenario.endpoint.lab-collection-methods.v1"
        or not isinstance(rows, list)
        or len(rows) != 2
    ):
        return False
    for expected_version, row in enumerate(rows, 1):
        if (
            not isinstance(row, dict)
            or set(row) != {"version", "digest", "document"}
            or type(row.get("version")) is not int
            or row["version"] != expected_version
            or not isinstance(row.get("digest"), str)
            or _DIGEST_RE.fullmatch(row["digest"]) is None
            or not isinstance(row.get("document"), dict)
            or row["document"].get("id") != _SCENARIO_ID
            or not isinstance(row["document"].get("title"), str)
        ):
            return False
    return rows[0]["document"] != rows[1]["document"]


def _restart_order_confirmed(events: object) -> bool:
    return events == ["first_started", "first_stopped", "second_started", "second_stopped"]


def _first_stop_precedes_restart(events: object) -> bool:
    return events == ["first_started", "first_stopped"]


def _capability_digest(capability: str) -> bytes:
    return hashlib.sha256(capability.encode("ascii")).digest()


def _fresh_capability(previous_digest: bytes | None, capability: str) -> bool:
    return previous_digest is not None and _capability_digest(capability) != previous_digest


def _cleanup_accepted(report: dict[str, object]) -> bool:
    expected_checks = [
        "fresh_cli_process_saved_two_fixture_versions",
        "old_cli_process_stopped_before_restart",
        "distinct_capability_and_fresh_browser_after_restart",
        "fresh_authenticated_server_reads_matched_both_saved_versions",
    ]
    return (
        report.get("status") == "passed"
        and report.get("pass_1_cli_process_group_started") is True
        and report.get("pass_2_cli_process_group_started") is True
        and report.get("first_browser_group_started") is True
        and report.get("second_browser_group_started") is True
        and report.get("first_cli_process_stopped") is True
        and report.get("second_cli_process_stopped") is True
        and report.get("first_browser_group_stopped") is True
        and report.get("second_browser_group_stopped") is True
        and report.get("pass_1_cli_process_group_stopped") is True
        and report.get("pass_2_cli_process_group_stopped") is True
        and report.get("restart_order_confirmed") is True
        and report.get("fresh_capability_confirmed") is True
        and report.get("pass_1_cli_returncode") == 130
        and report.get("pass_2_cli_returncode") == 130
        and report.get("checks") == expected_checks
        and report.get("temporary_runtime_removed") is True
    )


def _started_groups_stopped(report: dict[str, object]) -> bool:
    for index in (1, 2):
        cli_started = report.get(f"pass_{index}_cli_process_group_started")
        cli_stopped = report.get(f"pass_{index}_cli_process_group_stopped")
        browser_started = report.get(
            "first_browser_group_started" if index == 1 else "second_browser_group_started"
        )
        browser_stopped = report.get(
            "first_browser_group_stopped" if index == 1 else "second_browser_group_stopped"
        )
        if any(
            type(value) is not bool
            for value in (cli_started, cli_stopped, browser_started, browser_stopped)
        ):
            return False
        if (cli_started and not cli_stopped) or (browser_started and not browser_stopped):
            return False
        if (not cli_started and cli_stopped) or (not browser_started and browser_stopped):
            return False
    return True


def _stop_group(process: subprocess.Popen[bytes]) -> bool:
    try:
        os.killpg(process.pid, signal.SIGINT)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        pass
    for sig, grace in ((signal.SIGTERM, 3), (signal.SIGKILL, 5)):
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            break
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            break
        try:
            process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            pass
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        if process.poll() is None:
            process.wait(timeout=5)
        return process.poll() is not None
    return False


def _read_cli_stream(
    stream, *, stderr: bool, state: dict[str, object], lock: threading.Lock
) -> None:
    total = 0
    pending = bytearray()
    for chunk in iter(lambda: stream.read1(1024), b""):
        total += len(chunk)
        if total > _MAX_STREAM_BYTES:
            state["overflow"] = True
            pending.clear()
            continue
        if state.get("overflow"):
            continue
        if not stderr:
            continue
        pending.extend(chunk)
        while b"\n" in pending:
            line, _, rest = pending.partition(b"\n")
            pending = bytearray(rest)
            if len(line) > 2048:
                continue
            text = line.decode("utf-8", errors="ignore").strip()
            if text.startswith("BlueFire local console: "):
                match = _URL_RE.fullmatch(text.removeprefix("BlueFire local console: "))
                if match:
                    with lock:
                        state["port"] = int(match.group(1))
                        state["url_capability"] = match.group(2)
            elif text.startswith("One-time connection code: "):
                candidate = text.removeprefix("One-time connection code: ")
                if _CAP_RE.fullmatch(candidate):
                    with lock:
                        state["code"] = candidate
    if stderr and pending and len(pending) <= 2048:
        text = pending.decode("utf-8", errors="ignore").strip()
        if text.startswith("One-time connection code: "):
            candidate = text.removeprefix("One-time connection code: ")
            if _CAP_RE.fullmatch(candidate):
                with lock:
                    state["code"] = candidate


def _wait_ready(
    process: subprocess.Popen[bytes], state: dict[str, object], lock: threading.Lock
) -> tuple[int, str]:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        with lock:
            port, capability, code = (
                state.get("port"),
                state.get("url_capability"),
                state.get("code"),
            )
        if (
            type(port) is int
            and 1 <= port <= 65535
            and isinstance(capability, str)
            and capability == code
        ):
            return port, capability
        if process.poll() is not None or state.get("overflow"):
            break
        time.sleep(0.05)
    raise RuntimeError("CLI did not announce a bounded loopback session")


def _run_driver(
    *,
    node: Path,
    driver: Path,
    playwright: Path,
    environment: dict[str, str],
    output: Path,
    port: int,
    capability: str,
    mode: str,
    state_path: Path | None,
    on_started=None,
) -> tuple[int, bool]:
    command = [
        str(node),
        str(driver),
        str(playwright),
        mode,
        str(output),
        str(port),
        str(state_path) if state_path else "-",
    ]
    child = subprocess.Popen(
        command,
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    if on_started is not None:
        on_started()
    returncode = 124
    try:
        child.communicate(
            json.dumps({"capability": capability}).encode("ascii"), timeout=_MAX_DRIVER_SECONDS
        )
        returncode = child.returncode or 0
    except subprocess.TimeoutExpired:
        pass
    finally:
        stopped = _stop_group(child)
    return returncode, stopped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--forbid-root", required=True, type=Path)
    parser.add_argument("--node", required=True, type=Path)
    parser.add_argument("--playwright", required=True, type=Path)
    parser.add_argument("--browser-driver", required=True, type=Path)
    parser.add_argument("--browser-cache", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != "linux" or not sys.flags.isolated:
        raise RuntimeError("This verifier supports isolated installed Python on Linux only")
    forbidden = args.forbid_root.resolve(strict=True)
    driver = args.browser_driver.resolve(strict=True)
    node = args.node.resolve(strict=True)
    playwright = args.playwright.resolve(strict=True)
    browser_cache = args.browser_cache.resolve(strict=True)
    wheel = args.wheel.resolve(strict=True)
    output = args.output.resolve()
    if (
        output.exists()
        or output.is_relative_to(forbidden)
        or driver.is_relative_to(forbidden)
        or Path.cwd().is_relative_to(forbidden)
        or not driver.is_file()
    ):
        raise RuntimeError("Use a fresh output and copied browser driver outside checkout")
    output.mkdir(mode=0o700)
    for name in ("identity.json", "receipt.json"):
        if (output / name).exists():
            raise RuntimeError("Refusing to overwrite verifier output")
    runtime = output / "runtime"
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(runtime / "home"),
        "XDG_STATE_HOME": str(runtime / "state"),
        "XDG_CONFIG_HOME": str(runtime / "state"),
        "XDG_CACHE_HOME": str(runtime / "temp"),
        "TMPDIR": str(runtime / "temp"),
        "LANG": "C.UTF-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PLAYWRIGHT_BROWSERS_PATH": str(browser_cache),
        "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD": "1",
    }
    report: dict[str, object] = {
        "schema_version": "bluefire.installed-reopen-verification.v1",
        "status": "failed_or_incomplete",
        "scope": "installed_cli_restart_and_saved_fixture_reopen",
        "fixture_identity": "installed packaged collection example; owned fixture versions",
        "installed_outside_checkout": False,
        "live_model_inference": False,
        "active_runs_or_jobs": False,
        "native_actions": False,
        "assistant_inflight_recovery": False,
        "stale_tab_session_recovery": False,
        "upgrade_verification": False,
        "external_proof": False,
        "other_operating_systems": False,
        "first_cli_process_stopped": False,
        "second_cli_process_stopped": False,
        "pass_1_cli_process_group_started": False,
        "pass_2_cli_process_group_started": False,
        "pass_1_cli_process_group_stopped": False,
        "pass_2_cli_process_group_stopped": False,
        "first_browser_group_started": False,
        "second_browser_group_started": False,
        "first_browser_group_stopped": False,
        "second_browser_group_stopped": False,
        "fresh_capability_confirmed": False,
    }
    state_file = output / "fixture-state.json"
    cap_to_clear = ""
    processes: list[subprocess.Popen[bytes]] = []
    lifecycle = []
    original_cwd = Path.cwd()
    runtime_created = False
    try:
        runtime.mkdir(mode=0o700)
        runtime_created = True
        for name in ("home", "state", "temp", "work"):
            (runtime / name).mkdir(mode=0o700)
        os.environ.clear()
        os.environ.update(env)
        os.chdir(runtime / "work")
        import bluefire

        package = Path(bluefire.__file__).resolve(strict=True).parent
        site = Path(sysconfig.get_path("purelib")).resolve(strict=True)
        distribution = importlib.metadata.distribution("bluefire-nexus")
        if (
            not package.is_relative_to(site)
            or package.is_relative_to(forbidden)
            or Path(sys.prefix).resolve() == Path(sys.base_prefix).resolve()
            or any(Path(entry or ".").resolve().is_relative_to(forbidden) for entry in sys.path)
            or '"editable": true' in (distribution.read_text("direct_url.json") or "").lower()
        ):
            raise RuntimeError("BlueFire must come from a non-editable installed wheel")
        report["installed_outside_checkout"] = True
        report["product_version"] = distribution.version
        report["wheel_sha256"] = _digest(wheel)
        report["harness_sha256"] = _digest(Path(__file__).resolve())
        report["browser_driver_sha256"] = _digest(driver)
        report["environment_names"] = sorted(env)
        report["platform"] = platform.system().lower()
        report["architecture"] = platform.machine()
        report["os_release"] = platform.release()
        report["python_version"] = platform.python_version()
        checks = []
        prior_capability_digest: bytes | None = None
        for pass_index, mode in enumerate(("create", "reopen"), 1):
            if pass_index == 2 and (
                not _first_stop_precedes_restart(lifecycle)
                or processes[0].poll() is None
                or report.get("first_cli_process_stopped") is not True
            ):
                raise RuntimeError("first CLI process must stop before restart")
            runs = runtime / "runs"
            command = [
                sys.executable,
                "-I",
                "-B",
                "-m",
                "bluefire",
                "--runs-dir",
                str(runs),
                "ui",
                "--host",
                "127.0.0.1",
                "--port",
                "0",
                "--no-browser",
            ]
            service = subprocess.Popen(
                command,
                env=env,
                cwd=runtime / "work",
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            processes.append(service)
            report[f"pass_{pass_index}_cli_process_group_started"] = True
            lifecycle.append("first_started" if pass_index == 1 else "second_started")
            stream_state: dict[str, object] = {"overflow": False}
            lock = threading.Lock()
            readers = [
                threading.Thread(
                    target=_read_cli_stream,
                    args=(service.stdout,),
                    kwargs={"stderr": False, "state": stream_state, "lock": lock},
                    daemon=True,
                ),
                threading.Thread(
                    target=_read_cli_stream,
                    args=(service.stderr,),
                    kwargs={"stderr": True, "state": stream_state, "lock": lock},
                    daemon=True,
                ),
            ]
            for reader in readers:
                reader.start()
            port, cap_to_clear = _wait_ready(service, stream_state, lock)
            current_capability_digest = _capability_digest(cap_to_clear)
            if pass_index == 1:
                prior_capability_digest = current_capability_digest
            else:
                fresh_capability = _fresh_capability(prior_capability_digest, cap_to_clear)
                report["fresh_capability_confirmed"] = fresh_capability
                if not fresh_capability:
                    raise RuntimeError("restarted CLI reused the previous one-time capability")
            driver_code, browser_stopped = _run_driver(
                node=node,
                driver=driver,
                playwright=playwright,
                environment=env,
                output=output,
                port=port,
                capability=cap_to_clear,
                mode=mode,
                state_path=state_file if mode == "reopen" else None,
                on_started=lambda index=pass_index: report.__setitem__(
                    "first_browser_group_started" if index == 1 else "second_browser_group_started",
                    True,
                ),
            )
            cap_to_clear = ""
            report[
                "first_browser_group_stopped" if pass_index == 1 else "second_browser_group_stopped"
            ] = browser_stopped
            stopped = _stop_group(service)
            for reader in readers:
                reader.join(timeout=3)
            report[f"pass_{pass_index}_cli_returncode"] = service.returncode
            if not stopped:
                report[f"pass_{pass_index}_cli_process_group_stopped"] = False
                raise RuntimeError("CLI process tree did not stop")
            report[f"pass_{pass_index}_cli_process_group_stopped"] = True
            lifecycle.append("first_stopped" if pass_index == 1 else "second_stopped")
            if (
                service.returncode != 130
                or driver_code != 0
                or stream_state.get("overflow")
                or not browser_stopped
            ):
                raise RuntimeError("bounded installed UI journey failed")
            if pass_index == 1:
                _read_browser_report(output / "create-report.json", "create")
                state = _read_state(state_file)
                report["fixture"] = {
                    "scenario_id": state["scenario_id"],
                    "versions": [
                        {"version": row["version"], "digest": row["digest"]}
                        for row in state["versions"]
                    ],
                }
                checks.append("fresh_cli_process_saved_two_fixture_versions")
            else:
                driver_report = _read_browser_report(output / "reopen-report.json", "reopen")
                if driver_report["verified_state"] != _read_state(state_file):
                    raise RuntimeError("reopened server data differed from saved fixture metadata")
                checks.extend(
                    (
                        "old_cli_process_stopped_before_restart",
                        "distinct_capability_and_fresh_browser_after_restart",
                        "fresh_authenticated_server_reads_matched_both_saved_versions",
                    )
                )
            if pass_index == 1:
                # The old process is fully reaped before the next loop starts.
                report["first_cli_process_stopped"] = stopped
        report["checks"] = checks
        report["status"] = (
            "passed" if _restart_order_confirmed(lifecycle) else "failed_or_incomplete"
        )
    except (
        OSError,
        ImportError,
        subprocess.SubprocessError,
        ValueError,
        KeyError,
        RuntimeError,
        json.JSONDecodeError,
    ) as error:
        report["error_type"] = type(error).__name__
        report["status"] = "failed_or_incomplete"
    finally:
        cap_to_clear = ""
        for process_index, process in enumerate(processes, 1):
            key = f"pass_{process_index}_cli_process_group_stopped"
            try:
                stopped = report.get(key) is True or _stop_group(process)
            except OSError:
                stopped = False
            report[key] = stopped
        report["first_cli_process_stopped"] = (
            report.get("pass_1_cli_process_group_started") is True
            and report.get("pass_1_cli_process_group_stopped") is True
            and bool(processes)
            and processes[0].poll() is not None
        )
        report["second_cli_process_stopped"] = (
            report.get("pass_2_cli_process_group_started") is True
            and report.get("pass_2_cli_process_group_stopped") is True
            and len(processes) > 1
            and processes[1].poll() is not None
        )
        report["restart_order_confirmed"] = _restart_order_confirmed(lifecycle)
        if report["pass_1_cli_process_group_started"] and not report["first_cli_process_stopped"]:
            report["status"] = "failed_or_incomplete"
        if report["pass_2_cli_process_group_started"] and not report["second_cli_process_stopped"]:
            report["status"] = "failed_or_incomplete"
        _write_new(output / "receipt.json", report)
        runtime_safe_to_remove = _started_groups_stopped(report) and (
            runtime_created or not runtime.exists()
        )
        try:
            os.chdir(original_cwd)
        except OSError:
            runtime_safe_to_remove = False
        if runtime_safe_to_remove:
            try:
                if runtime.exists():
                    shutil.rmtree(runtime)
                report["temporary_runtime_removed"] = True
            except OSError:
                report["temporary_runtime_removed"] = False
                report["status"] = "failed_or_incomplete"
        else:
            report["temporary_runtime_removed"] = False
            report["status"] = "failed_or_incomplete"
        # Rewrite only our owned receipt after cleanup; no credentials or host paths are included.
        (output / "receipt.json").unlink(missing_ok=True)
        _write_new(output / "receipt.json", report)
    print(json.dumps(report, sort_keys=True))
    return 0 if _cleanup_accepted(report) else 1


if __name__ == "__main__":
    raise SystemExit(main())
