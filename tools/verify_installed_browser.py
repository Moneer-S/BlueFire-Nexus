"""Exercise the installed wheel's real HTTP service and packaged desktop UI.

Run this copied verifier with the wheel-only interpreter, outside the checkout.
This Linux browser journey permits saved generated work and AI-Off simulation;
it does not establish native execution, live inference, or external access.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import sysconfig
import threading
import time
from pathlib import Path


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_new(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def stop_group(process: subprocess.Popen[bytes]) -> bool:
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            process.wait(timeout=10)
            return True
        time.sleep(0.2)
    process.wait(timeout=10)
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return True
    return False


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
        raise RuntimeError("Use isolated installed Linux Python for this verifier")
    forbidden = args.forbid_root.resolve(strict=True)
    output = args.output.resolve()
    driver = args.browser_driver.resolve(strict=True)
    wheel = args.wheel.resolve(strict=True)
    node = args.node.resolve(strict=True)
    playwright = args.playwright.resolve(strict=True)
    cache = args.browser_cache.resolve(strict=True)
    if output.is_relative_to(forbidden) or output.exists():
        raise RuntimeError("A fresh output folder outside checkout is required")
    if driver.is_relative_to(forbidden) or Path.cwd().is_relative_to(forbidden):
        raise RuntimeError("Copy the browser driver outside checkout before verification")
    output.mkdir(mode=0o700)
    runtime = output / "runtime"
    runtime.mkdir(mode=0o700)
    for name in ("home", "state", "temp", "work"):
        (runtime / name).mkdir(mode=0o700)
    hosted_image = {
        name: os.environ.get(name)
        for name in ("ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH")
    }
    environment = {
        "PATH": os.pathsep.join((str(node.parent), "/usr/bin", "/bin")),
        "HOME": str(runtime / "home"),
        "XDG_STATE_HOME": str(runtime / "state"),
        "XDG_CONFIG_HOME": str(runtime / "state"),
        "XDG_CACHE_HOME": str(runtime / "temp"),
        "TMPDIR": str(runtime / "temp"),
        "LANG": "C.UTF-8",
        "PLAYWRIGHT_BROWSERS_PATH": str(cache),
        "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD": "1",
    }
    os.environ.clear()
    os.environ.update(environment)
    os.chdir(runtime / "work")

    import bluefire
    from bluefire.api import create_server, generate_browser_bootstrap_capability
    from bluefire.service import BlueFireService

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
        raise RuntimeError("The package must be wheel-installed outside checkout")
    build_info = json.loads((package / "_build_info.json").read_text(encoding="utf-8"))
    write_new(
        output / "identity.json",
        {
            "schema_version": "bluefire.installed-browser-identity.v1",
            "os_release": platform.freedesktop_os_release(),
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "hosted_image": hosted_image,
            "python_version": platform.python_version(),
            "product_version": distribution.version,
            "source_revision": build_info["source_revision"],
            "source_provenance": build_info["source_provenance"],
            "wheel_filename": wheel.name,
            "wheel_sha256": digest(wheel),
            "ui_sha256": {
                name: digest(package / "ui" / name)
                for name in ("index.html", "app.js", "styles.css")
            },
            "installed_outside_checkout": True,
            "harness_sha256": digest(Path(__file__)),
            "browser_driver_sha256": digest(driver),
            "environment_names": sorted(environment),
            "not_proven": [
                "CLI launch",
                "native execution or effective-access validation",
                "live model inference",
                "AD, AWS, or external endpoint access",
                "other operating systems or Linux security configurations",
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
    report: dict[str, object] = {
        "schema_version": "bluefire.installed-browser-verification.v1",
        "status": "failed_or_incomplete",
        "real_installed_service": True,
        "native_execution": False,
        "live_model_inference": False,
    }
    thread.start()
    try:
        child = subprocess.Popen(
            [str(node), str(driver), str(playwright), str(output), str(server.server_address[1])],
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        child.communicate(json.dumps({"capability": capability}).encode(), timeout=240)
        capability = ""
        report["browser_returncode"] = child.returncode
        if child.returncode == 0:
            report["status"] = "passed"
    except (OSError, subprocess.TimeoutExpired) as error:
        report["error_type"] = type(error).__name__
    finally:
        capability = ""
        cleanup_errors = []
        report["browser_process_group_stopped"] = child is None
        try:
            if child is not None:
                report["browser_process_group_stopped"] = stop_group(child)
        except (OSError, subprocess.TimeoutExpired):
            cleanup_errors.append("browser_process_group")
        for name, operation in (
            ("http_shutdown", server.shutdown),
            ("http_close", server.server_close),
            ("service_close", service.close),
        ):
            try:
                operation()
            except Exception:
                cleanup_errors.append(name)
        thread.join(timeout=10)
        report["service_thread_stopped"] = not thread.is_alive() and not cleanup_errors
        os.chdir(output)
        if report["browser_process_group_stopped"] and report["service_thread_stopped"]:
            try:
                shutil.rmtree(runtime)
            except OSError:
                cleanup_errors.append("temporary_state")
        report["temporary_state_removed"] = not runtime.exists()
        report["cleanup_errors"] = cleanup_errors
        if not all(
            report.get(key)
            for key in (
                "browser_process_group_stopped",
                "service_thread_stopped",
                "temporary_state_removed",
            )
        ):
            report["status"] = "failed_or_incomplete"
        write_new(output / "receipt.json", report)
        print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
