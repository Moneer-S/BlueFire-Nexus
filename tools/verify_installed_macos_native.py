"""Verify one generated native desktop journey in an installed Intel macOS wheel.

This does not establish effective access, identity separation, live inference, or
customer endpoint compatibility. Run outside checkout with isolated Python.
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
import stat
import subprocess
import sys
import sysconfig
import threading
import time
import zipfile
from email.parser import BytesParser
from pathlib import Path
from typing import Any

PROFILE = "sandbox-execute.v1"
SCENARIO = re.compile(
    r"scenario\.installed-macos-native\.[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.v1"
)
MAX_REPORT_BYTES = 128 * 1024
MAX_PACKAGE_BYTES = 256 * 1024 * 1024
TERMINAL_STATES = {"completed", "failed", "cancelled", "interrupted"}
WORKER_CLEANUP_CHECKS = {
    "browser_process_group_stopped",
    "owned_jobs_settled",
    "runner_stopped",
    "generated_workspace_empty",
    "http_shutdown",
    "http_close",
    "service_closed",
    "service_thread_stopped",
}
REQUIRED_CHECKS = {
    "normal_ephemeral_browser_session",
    "shipped_execute_profile_verified",
    "managed_runner_started",
    "saved_generated_two_step_plan",
    "exact_preflight_and_approval",
    "two_native_steps_completed",
    "independent_fixture_observed_before_cleanup",
    "receipt_cleanup_complete",
    "saved_run_reopened_in_packaged_ui",
    "evidence_and_cleanup_views_inspected",
    "same_tab_reload_preserved_run",
    "managed_runner_stopped",
    "scope_guard_no_unexpected_requests",
    "report_credentials_absent",
}


def digest(path: Path) -> str:
    details = path.lstat()
    if not stat.S_ISREG(details.st_mode) or details.st_size > MAX_PACKAGE_BYTES:
        raise ValueError("Verifier input is not a bounded regular file")
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def write_new(path: Path, value: object) -> None:
    raw = json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"
    if len(raw.encode("utf-8")) > MAX_REPORT_BYTES:
        raise ValueError("Verifier evidence exceeds its bound")
    with path.open("x", encoding="utf-8") as stream:
        stream.write(raw)


def read_report(path: Path) -> dict[str, Any]:
    if not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError("Browser report is not a bounded regular file")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate report key")
            result[key] = value
        return result

    def reject_constant(_value):
        raise ValueError("Non-finite report value")

    value = json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=unique, parse_constant=reject_constant
    )
    if type(value) is not dict:
        raise ValueError("Browser report must be an object")
    return value


def installed_package_matches_wheel(wheel: Path, package: Path, version: str) -> bool:
    """Match installed package bytes, including native and browser resources."""
    try:
        with zipfile.ZipFile(wheel) as archive:
            infos = [item for item in archive.infolist() if not item.is_dir()]
            metadata = [
                item for item in infos if re.fullmatch(r"[^/]+\.dist-info/METADATA", item.filename)
            ]
            if len(infos) > 4196 or len(metadata) != 1 or metadata[0].file_size > 256 * 1024:
                return False
            headers = BytesParser().parsebytes(archive.read(metadata[0]))
            if (
                re.sub(r"[-_.]+", "-", headers.get("Name", "")).lower() != "bluefire-nexus"
                or headers.get("Version") != version
            ):
                return False
            data_root = metadata[0].filename.removesuffix(".dist-info/METADATA") + ".data"
            expected = {}
            total = 0
            for item in infos:
                parts = item.filename.split("/")
                if parts[0] == "bluefire":
                    relative_parts = parts[1:]
                elif len(parts) > 3 and parts[:3] in (
                    [data_root, "purelib", "bluefire"],
                    [data_root, "platlib", "bluefire"],
                ):
                    relative_parts = parts[3:]
                else:
                    continue
                total += item.file_size
                if (
                    not relative_parts
                    or any(part in {"", ".", ".."} for part in parts)
                    or "\\" in item.filename
                    or item.external_attr >> 16 & 0o170000 == 0o120000
                    or total > MAX_PACKAGE_BYTES
                ):
                    return False
                relative = "/".join(relative_parts)
                if relative in expected:
                    return False
                expected[relative] = (
                    item.file_size,
                    hashlib.sha256(archive.read(item)).hexdigest(),
                )
            if "__init__.py" not in expected:
                return False
            actual = {}
            for path in package.rglob("*"):
                if path.is_symlink():
                    return False
                if path.is_dir() or "__pycache__" in path.parts or path.suffix == ".pyc":
                    continue
                actual[path.relative_to(package).as_posix()] = (path.stat().st_size, digest(path))
                if len(actual) > 4096:
                    return False
            return actual == expected
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
        return False


def isolated_environment(runtime: Path, node: Path, cache: Path) -> dict[str, str]:
    return {
        "PATH": os.pathsep.join((str(node.parent), "/usr/bin", "/bin", "/usr/sbin", "/sbin")),
        "HOME": str(runtime / "home"),
        "XDG_STATE_HOME": str(runtime / "state"),
        "XDG_CONFIG_HOME": str(runtime / "state"),
        "XDG_CACHE_HOME": str(runtime / "temp"),
        "TMPDIR": str(runtime / "temp"),
        "LANG": "en_US.UTF-8",
        "PLAYWRIGHT_BROWSERS_PATH": str(cache),
        "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD": "1",
    }


def driver_passed(value: object) -> bool:
    if type(value) is not dict:
        return False
    cleanup = value.get("cleanup")
    observed = value.get("observed")
    checks = value.get("checks")
    screenshots = value.get("screenshots")
    return (
        value.get("schema_version") == "bluefire.installed-macos-native-desktop.v1"
        and value.get("status") == "passed"
        and value.get("real_service") is True
        and value.get("mocked_responses") is False
        and value.get("native_execution") is True
        and value.get("live_model_inference") is False
        and value.get("effective_access") is False
        and value.get("blocked_requests") == []
        and value.get("errors") == []
        and type(cleanup) is dict
        and cleanup.get("runner_stopped") is True
        and cleanup.get("job_settled") is True
        and type(observed) is dict
        and type(observed.get("filesystem_records")) is int
        and observed["filesystem_records"] >= 1
        and type(observed.get("executed_steps")) is int
        and observed["executed_steps"] == 2
        and type(observed.get("generated_records")) is int
        and observed["generated_records"] == 1
        and type(checks) is list
        and all(type(item) is str for item in checks)
        and len(checks) == len(REQUIRED_CHECKS)
        and set(checks) == REQUIRED_CHECKS
        and type(screenshots) is list
        and len(screenshots) == 4
        and all(
            type(item) is dict
            and type(item.get("name")) is str
            and re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", "")))
            for item in screenshots
        )
        and {item.get("name") for item in screenshots}
        == {
            "macos-native-result",
            "macos-native-evidence",
            "macos-native-cleanup",
            "macos-native-reopened",
        }
    )


def screenshots_verified(output: Path, browser: dict[str, Any]) -> bool:
    if not driver_passed(browser):
        return False
    for item in browser["screenshots"]:
        path = output / (item["name"] + ".png")
        if digest(path) != item["sha256"]:
            return False
        with path.open("rb") as stream:
            if stream.read(8) != b"\x89PNG\r\n\x1a\n":
                return False
    return True


def workspace_clean(service, runtime: Path, run_id: str) -> bool:
    """Independently inspect only the exact persisted owned execution workspace."""
    workspaces = service.product_store.list_execution_workspaces()
    if len(workspaces) != 1:
        return False
    binding = workspaces[0]
    if (
        binding.get("state") != "completed"
        or binding.get("profile_id") != PROFILE
        or binding.get("run_id") != run_id
    ):
        return False
    workspace = Path(binding["workspace_path"])
    if (
        not workspace.is_absolute()
        or workspace.resolve(strict=True) != workspace
        or not workspace.is_relative_to(runtime.resolve(strict=True))
    ):
        return False
    for path in (workspace, *workspace.parents):
        if path == runtime:
            break
        if path.is_symlink() or not path.is_dir():
            return False

    def fail_walk(error: OSError) -> None:
        raise error

    count = 0
    for directory, children, files in os.walk(workspace, followlinks=False, onerror=fail_walk):
        count += len(children) + len(files)
        if count > 256:
            return False
        for name in children + files:
            if (Path(directory) / name).is_symlink():
                return False
        if Path(directory) == workspace:
            children[:] = [name for name in children if name != ".bluefire"]
        if files:
            return False
    return True


def settle_owned_jobs(service, *, timeout: float = 20) -> bool:
    """Cancel only the generated scenario in this newly created private service."""
    jobs = service.product_store.list_jobs()
    if len(jobs) > 1:
        return False
    for job in jobs:
        request = job.get("request", {})
        scenario = request.get("scenario", {})
        if (
            job.get("kind") != "scenario.run"
            or not SCENARIO.fullmatch(str(scenario.get("id", "")))
            or request.get("runner_profile_id") != PROFILE
            or request.get("mode") != "execute"
        ):
            return False
    for job in jobs:
        if job["state"] not in TERMINAL_STATES:
            service.cancel_job(job["job_id"])
    deadline = time.monotonic() + timeout
    while True:
        if all(service.job(job["job_id"])["state"] in TERMINAL_STATES for job in jobs):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.1)


def stop_group(process: subprocess.Popen[bytes]) -> bool:
    from bluefire.runner_lifecycle import (
        _LaunchProcess,
        _terminate_darwin_contained_launch,
    )

    # Both callers own an unreaped child launched with start_new_session=True.
    # Reuse the bounded Darwin drain: EPERM alone never establishes absence.
    return _terminate_darwin_contained_launch(
        _LaunchProcess(process=process, containment=process.pid)
    )


def stop_runner(service) -> bool:
    result = service.stop_runner(profile_id=PROFILE)
    return result.get("state") == "stopped" and result.get("profile_id") == PROFILE


def wait_driver_exit(process, exited_without_reap, *, timeout: float = 160) -> None:
    deadline = time.monotonic() + timeout
    while not exited_without_reap(process.pid):
        if time.monotonic() >= deadline:
            raise subprocess.TimeoutExpired("owned installed browser driver", timeout)
        time.sleep(0.1)


def supervise_owned_child(
    child,
    exited_without_reap,
    output: Path,
    *,
    timeout: float = 230,
    close_timeout: float = 20,
    stop=stop_group,
    clock=time.monotonic,
    sleep=time.sleep,
) -> dict[str, Any]:
    """Reserve bounded group termination outside the service worker's deadline."""
    deadline = clock() + timeout
    close_deadline = None
    result: dict[str, Any] = {
        "worker_exit_observed": False,
        "worker_process_group_stopped": False,
        "worker_timeout_stage": None,
        "worker_returncode": None,
    }
    try:
        while True:
            now = clock()
            if close_deadline is None and (output / "service-close-started.json").exists():
                close_deadline = now + close_timeout
            if now >= deadline or (close_deadline is not None and now >= close_deadline):
                result["worker_timeout_stage"] = (
                    "service_close"
                    if close_deadline is not None and now >= close_deadline
                    else "journey"
                )
                break
            if exited_without_reap(child.pid):
                result["worker_exit_observed"] = True
                break
            sleep(min(0.1, deadline - now))
    except Exception as exc:
        result["worker_error_type"] = type(exc).__name__
    finally:
        try:
            result["worker_process_group_stopped"] = stop(child) is True
        except Exception as exc:
            result["worker_stop_error_type"] = type(exc).__name__
        result["worker_returncode"] = child.returncode
    return result


def worker_ready(value: object) -> bool:
    return (
        type(value) is dict
        and value.get("schema_version") == "bluefire.installed-macos-native-receipt.v1"
        and value.get("status") == "ready_for_finalization"
        and value.get("scope") == "owned_generated_fixture_native_desktop"
        and value.get("native_desktop_verified") is True
        and value.get("effective_access") is False
        and value.get("temporary_state_removed") is False
        and type(value.get("browser_returncode")) is int
        and value["browser_returncode"] == 0
        and value.get("cleanup_errors") == []
        and all(value.get(name) is True for name in WORKER_CLEANUP_CHECKS)
    )


def finalize_supervised_receipt(output: Path, supervision: dict[str, Any]) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": "bluefire.installed-macos-native-receipt.v1",
        "status": "failed_or_incomplete",
        "scope": "owned_generated_fixture_native_desktop",
        "native_desktop_verified": False,
        "effective_access": False,
        "temporary_state_removed": False,
        "cleanup_errors": [],
        **dict.fromkeys(WORKER_CLEANUP_CHECKS, False),
    }
    worker = None
    cleanup_evidence = None
    try:
        worker = read_report(output / "worker-result.json")
        cleanup_evidence = worker
        report["worker_result_sha256"] = digest(output / "worker-result.json")
    except (OSError, ValueError) as exc:
        report["worker_result_error_type"] = type(exc).__name__
        try:
            cleanup_evidence = read_report(output / "service-close-started.json")
        except (OSError, ValueError):
            pass
    if cleanup_evidence is not None:
        for name in WORKER_CLEANUP_CHECKS:
            report[name] = cleanup_evidence.get(name) is True
        if type(cleanup_evidence.get("browser_returncode")) is int:
            report["browser_returncode"] = cleanup_evidence["browser_returncode"]
        report["cleanup_errors"] = cleanup_evidence.get("cleanup_errors")
    report.update(supervision)
    report["status"] = "failed_or_incomplete"
    report["native_desktop_verified"] = False
    report["temporary_state_removed"] = False
    errors = report.get("cleanup_errors")
    errors = (
        list(errors) if type(errors) is list and all(type(item) is str for item in errors) else []
    )
    ready = (
        worker_ready(worker)
        and supervision.get("worker_exit_observed") is True
        and supervision.get("worker_process_group_stopped") is True
        and type(supervision.get("worker_returncode")) is int
        and supervision["worker_returncode"] == 0
        and supervision.get("worker_timeout_stage") is None
        and "worker_error_type" not in supervision
        and "worker_stop_error_type" not in supervision
    )
    if ready:
        try:
            shutil.rmtree(output / "runtime")
            report["temporary_state_removed"] = not (output / "runtime").exists()
        except OSError:
            errors.append("temporary_state")
        if report["temporary_state_removed"] and not errors:
            report["native_desktop_verified"] = True
            report["status"] = "passed"
    else:
        errors.append("worker_shutdown_unverified")
    report["cleanup_errors"] = errors
    report["supervision_scope"] = (
        "Verifier process group only; its termination does not establish browser or runner-session cleanup"
    )
    write_new(output / "receipt.json", report)
    return report


def parse_arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "forbid-root",
        "node",
        "playwright",
        "browser-driver",
        "browser-cache",
        "wheel",
        "output",
    ):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def checked_inputs(args) -> tuple[Path, Path, dict[str, Path]]:
    if sys.platform != "darwin" or platform.machine() != "x86_64" or not sys.flags.isolated:
        raise RuntimeError("Use isolated installed Intel macOS Python for this verifier")
    forbidden = args.forbid_root.resolve(strict=True)
    output = args.output.resolve()
    inputs = {
        name: getattr(args, name).resolve(strict=True)
        for name in ("node", "playwright", "browser_driver", "browser_cache", "wheel")
    }
    if (
        output.exists()
        or output.is_relative_to(forbidden)
        or Path.cwd().resolve().is_relative_to(forbidden)
        or Path(__file__).resolve().is_relative_to(forbidden)
        or inputs["browser_driver"].is_relative_to(forbidden)
    ):
        raise RuntimeError("Fresh evidence and copied harness must be outside checkout")
    return forbidden, output, inputs


def run_supervised(args) -> int:
    forbidden, output, inputs = checked_inputs(args)
    from bluefire.runner_client import (
        _darwin_child_exited_without_reap,
        _darwin_child_status_ownership_available,
    )

    if not _darwin_child_status_ownership_available():
        raise RuntimeError("Original verifier child-status custody is unavailable")
    environment = isolated_environment(output / "runtime", inputs["node"], inputs["browser_cache"])
    for name in ("ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH"):
        if name in os.environ:
            environment[name] = os.environ[name]
    command = [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--worker"]
    for name, value in {"forbid_root": forbidden, **inputs, "output": output}.items():
        command.extend(("--" + name.replace("_", "-"), str(value)))
    child = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=environment,
        start_new_session=True,
    )
    supervision = supervise_owned_child(child, _darwin_child_exited_without_reap, output)
    output.mkdir(mode=0o700, exist_ok=True)
    if output.is_symlink():
        raise RuntimeError("Verifier output must remain an owned directory")
    report = finalize_supervised_receipt(output, supervision)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


def run_journey(args) -> int:
    forbidden, output, inputs = checked_inputs(args)
    output.mkdir(mode=0o700)
    runtime = output / "runtime"
    runtime.mkdir(mode=0o700)
    for name in ("home", "state", "temp", "work"):
        (runtime / name).mkdir(mode=0o700)
    hosted_image = {
        name: os.environ.get(name)
        for name in ("ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH")
    }
    environment = isolated_environment(runtime, inputs["node"], inputs["browser_cache"])
    os.environ.clear()
    os.environ.update(environment)
    os.chdir(runtime / "work")

    import bluefire
    from bluefire.api import create_server, generate_browser_bootstrap_capability
    from bluefire.runner_client import (
        _darwin_child_exited_without_reap,
        _darwin_child_status_ownership_available,
    )
    from bluefire.service import BlueFireService

    package = Path(bluefire.__file__).resolve(strict=True).parent
    distribution = importlib.metadata.distribution("bluefire-nexus")
    if (
        not package.is_relative_to(Path(sysconfig.get_path("purelib")).resolve(strict=True))
        or package.is_relative_to(forbidden)
        or Path(sys.prefix).resolve() == Path(sys.base_prefix).resolve()
        or any(Path(entry or ".").resolve().is_relative_to(forbidden) for entry in sys.path)
        or not installed_package_matches_wheel(inputs["wheel"], package, distribution.version)
    ):
        raise RuntimeError("Installed package does not match the exact wheel outside checkout")
    build = json.loads((package / "_build_info.json").read_text(encoding="utf-8"))
    write_new(
        output / "identity.json",
        {
            "schema_version": "bluefire.installed-macos-native-identity.v1",
            "system": platform.system(),
            "os_version": platform.mac_ver()[0],
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "hosted_image": hosted_image,
            "python_version": platform.python_version(),
            "product_version": distribution.version,
            "source_revision": build["source_revision"],
            "source_provenance": build["source_provenance"],
            "wheel_filename": inputs["wheel"].name,
            "wheel_sha256": digest(inputs["wheel"]),
            "installed_package_matches_wheel": True,
            "installed_outside_checkout": True,
            "harness_sha256": digest(Path(__file__)),
            "driver_sha256": digest(inputs["browser_driver"]),
            "ui_sha256": {
                name: digest(package / "ui" / name)
                for name in ("index.html", "app.js", "styles.css")
            },
            "environment_names": sorted(environment),
            "not_proven": [
                "effective file access",
                "identity separation",
                "Apple Silicon execution",
                "live model inference",
                "AD or AWS",
                "customer endpoint compatibility",
                "process restart recovery",
            ],
        },
    )
    service = BlueFireService(runs_dir=runtime / "runs")
    capability = generate_browser_bootstrap_capability()
    server = create_server(
        service, host="127.0.0.1", port=0, browser_bootstrap_capability=capability
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    child = None
    browser = None
    report = {
        "schema_version": "bluefire.installed-macos-native-receipt.v1",
        "status": "failed_or_incomplete",
        "scope": "owned_generated_fixture_native_desktop",
        "native_desktop_verified": False,
        "effective_access": False,
    }
    thread.start()
    try:
        if not _darwin_child_status_ownership_available():
            raise RuntimeError("Original browser child-status custody is unavailable")
        child = subprocess.Popen(
            [
                str(inputs["node"]),
                str(inputs["browser_driver"]),
                str(inputs["playwright"]),
                str(output),
                str(server.server_address[1]),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
            start_new_session=True,
        )
        child.stdin.write(json.dumps({"capability": capability}).encode())
        child.stdin.close()
        wait_driver_exit(child, _darwin_child_exited_without_reap)
        browser = read_report(output / "macos-native-browser-report.json")
        report["native_desktop_verified"] = driver_passed(browser) and screenshots_verified(
            output, browser
        )
    except Exception as exc:
        report["error_type"] = type(exc).__name__
    finally:
        capability = ""
        errors = []
        for name, operation in (
            ("browser_process_group_stopped", lambda: child is None or stop_group(child)),
            ("owned_jobs_settled", lambda: settle_owned_jobs(service)),
            ("runner_stopped", lambda: stop_runner(service)),
            (
                "generated_workspace_empty",
                lambda: browser is not None
                and workspace_clean(service, runtime, browser.get("run_id", "")),
            ),
            ("http_shutdown", server.shutdown),
            ("http_close", server.server_close),
            ("service_closed", service.close),
        ):
            try:
                if name == "service_closed":
                    write_new(
                        output / "service-close-started.json",
                        {**report, "cleanup_errors": list(errors)},
                    )
                result = operation()
                report[name] = result is not False
                if result is False:
                    errors.append(name)
            except Exception:
                report[name] = False
                errors.append(name)
        thread.join(timeout=10)
        report["browser_returncode"] = child.returncode if child is not None else None
        if report["browser_returncode"] != 0:
            report["native_desktop_verified"] = False
        report["service_thread_stopped"] = not thread.is_alive()
        os.chdir(output)
        report["temporary_state_removed"] = False
        report["cleanup_errors"] = errors
        if report["native_desktop_verified"] and not errors and not thread.is_alive():
            report["status"] = "ready_for_finalization"
        write_new(output / "worker-result.json", report)
    return 0 if report["status"] == "ready_for_finalization" else 1


def main(argv: list[str] | None = None) -> int:
    args = parse_arguments(argv)
    return run_journey(args) if args.worker else run_supervised(args)


if __name__ == "__main__":
    raise SystemExit(main())
