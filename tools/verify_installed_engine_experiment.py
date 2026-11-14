"""Verify the installed engine-experiment shell fails closed without controller setup.

Copy this verifier and its browser driver outside the checkout, then run it with
an isolated Python environment containing the exact candidate wheel.  This
check deliberately performs no engine, model, target, container, or defensive
effect.  It proves the packaged UI and real local service expose the saved
engine-experiment surface while refusing a partial experiment when trusted
controller-owned presentation metadata is unavailable.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import hmac
import importlib.metadata
import io
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import sysconfig
import threading
import time
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, cast

_CAPABILITY = re.compile(r"[A-Za-z0-9_-]{64}\Z")
_CONSOLE_URL = re.compile(
    r"http://127\.0\.0\.1:([1-9][0-9]{0,4})/#bluefire-session=([A-Za-z0-9_-]{64})\Z"
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_STREAM_BYTES = 64 * 1024
_MAX_REPORT_BYTES = 512 * 1024
_MAX_DRIVER_SECONDS = 120
_MAX_WHEEL_FILES = 4096
_MAX_WHEEL_BYTES = 128 * 1024 * 1024
_CHECKS = [
    "packaged_ui_rendered_with_real_local_service",
    "empty_engine_history_read_from_installed_service",
    "create_refused_without_controller_presentation_metadata",
    "refused_create_left_no_saved_experiment",
    "engine_route_rendered_recoverable_unavailable_state",
]


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return "sha256:" + value.hexdigest()


def _member_digest(payload: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(
        b"="
    ).decode("ascii")


def _payload_digest(rows: list[dict[str, object]]) -> str:
    payload = json.dumps(rows, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _read_installed_member(path: Path, expected_size: int) -> bytes:
    before = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_size != expected_size:
        raise RuntimeError("installed wheel member is unavailable or unsafe")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns):
            raise RuntimeError("installed wheel member changed during verification")
        payload = bytearray()
        while len(payload) <= expected_size:
            chunk = os.read(descriptor, min(65536, expected_size + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        current = path.lstat()
        if (
            len(payload) != expected_size
            or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
        ):
            raise RuntimeError("installed wheel member changed during verification")
        return bytes(payload)
    finally:
        os.close(descriptor)


def bind_installed_wheel(
    wheel: Path, *, purelib: Path, installed_version: str
) -> dict[str, object]:
    """Bind every wheel-owned payload member to the loaded installation.

    Pip may rewrite ``RECORD`` and add installer metadata, so that one member is
    excluded.  Every other candidate member must have an exact safe installed
    counterpart whose bytes match the candidate wheel and its own RECORD row.
    """

    wheel_rows: list[dict[str, object]] = []
    installed_rows: list[dict[str, object]] = []
    with zipfile.ZipFile(wheel) as archive:
        infos = archive.infolist()
        if not 1 <= len(infos) <= _MAX_WHEEL_FILES:
            raise RuntimeError("candidate wheel member count is invalid")
        names: set[str] = set()
        total = 0
        for info in infos:
            path = PurePosixPath(info.filename)
            mode = info.external_attr >> 16
            if (
                info.filename in names
                or info.is_dir()
                or path.is_absolute()
                or not path.parts
                or any(part in ("", ".", "..") for part in info.filename.split("/"))
                or "\\" in info.filename
                or (mode and stat.S_IFMT(mode) not in (0, stat.S_IFREG))
                or info.file_size < 0
            ):
                raise RuntimeError("candidate wheel contains an unsafe member")
            names.add(info.filename)
            total += info.file_size
            if total > _MAX_WHEEL_BYTES:
                raise RuntimeError("candidate wheel exceeds its verification bound")
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        record_names = [name for name in names if name.endswith(".dist-info/RECORD")]
        wheel_names = [name for name in names if name.endswith(".dist-info/WHEEL")]
        if len(metadata_names) != 1 or len(record_names) != 1 or len(wheel_names) != 1:
            raise RuntimeError("candidate wheel metadata is ambiguous")
        dist_prefix = metadata_names[0].removesuffix("METADATA")
        if record_names[0] != dist_prefix + "RECORD" or wheel_names[0] != dist_prefix + "WHEEL":
            raise RuntimeError("candidate wheel metadata belongs to another distribution")
        data_purelib_prefix = dist_prefix.removesuffix(".dist-info/") + ".data/purelib/"
        metadata = BytesParser().parsebytes(archive.read(metadata_names[0]))
        if metadata.get("Name") != "bluefire-nexus" or metadata.get("Version") != installed_version:
            raise RuntimeError("candidate wheel identity does not match the installation")
        try:
            record_text = archive.read(record_names[0]).decode("utf-8")
        except UnicodeError as exc:
            raise RuntimeError("candidate wheel RECORD is invalid") from exc
        records: dict[str, tuple[str, int | None]] = {}
        for row in csv.reader(io.StringIO(record_text, newline="")):
            if len(row) != 3 or row[0] in records:
                raise RuntimeError("candidate wheel RECORD is invalid")
            record_path, record_hash, record_size = row
            if record_path not in names:
                raise RuntimeError("candidate wheel RECORD references an absent member")
            if record_path == record_names[0]:
                if record_hash or record_size:
                    raise RuntimeError("candidate wheel RECORD self-entry is invalid")
                records[record_path] = ("", None)
                continue
            if (
                not record_hash.startswith("sha256=")
                or not record_size.isascii()
                or not record_size.isdigit()
            ):
                raise RuntimeError("candidate wheel RECORD member is unbound")
            records[record_path] = (record_hash, int(record_size))
        if set(records) != names:
            raise RuntimeError("candidate wheel RECORD inventory is incomplete")
        installed_names: set[str] = set()
        for name in sorted(names - {record_names[0]}):
            info = archive.getinfo(name)
            payload = archive.read(info)
            expected_hash, expected_size = records[name]
            if (
                len(payload) != info.file_size
                or len(payload) != expected_size
                or _member_digest(payload) != expected_hash
            ):
                raise RuntimeError("candidate wheel payload failed RECORD verification")
            installed_name = name
            if ".data/" in name:
                if not name.startswith(data_purelib_prefix):
                    raise RuntimeError("candidate wheel uses an unsupported .data scheme")
                installed_name = name.removeprefix(data_purelib_prefix)
                if not installed_name:
                    raise RuntimeError("candidate wheel contains an unsafe .data member")
            if installed_name in installed_names:
                raise RuntimeError("candidate wheel has ambiguous installed member paths")
            installed_names.add(installed_name)
            candidate = purelib / Path(*PurePosixPath(installed_name).parts)
            destination = candidate.resolve(strict=True)
            if (
                not destination.is_relative_to(purelib)
                or destination != candidate
                or destination.is_symlink()
                or not destination.is_file()
                or destination.stat().st_size != len(payload)
            ):
                raise RuntimeError("installed wheel member is unavailable or unsafe")
            installed_payload = _read_installed_member(destination, len(payload))
            if len(installed_payload) != len(payload) or not hmac_compare(
                hashlib.sha256(installed_payload).digest(), hashlib.sha256(payload).digest()
            ):
                raise RuntimeError("installed distribution does not match the candidate wheel")
            wheel_rows.append(
                {
                    "name": name,
                    "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                }
            )
            installed_rows.append(
                {
                    "name": name,
                    "sha256": "sha256:" + hashlib.sha256(installed_payload).hexdigest(),
                    "size": len(installed_payload),
                }
            )
    wheel_digest = _payload_digest(wheel_rows)
    installed_digest = _payload_digest(installed_rows)
    if wheel_digest != installed_digest:
        raise RuntimeError("installed payload identity does not match the candidate wheel")
    return {
        "wheel_member_count": len(wheel_rows),
        "wheel_payload_digest": wheel_digest,
        "installed_payload_digest": installed_digest,
    }


def hmac_compare(left: bytes, right: bytes) -> bool:
    return hmac.compare_digest(left, right)


def _write_new(path: Path, value: object, *, maximum: int = _MAX_REPORT_BYTES) -> None:
    payload = json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    if len(payload) > maximum:
        raise RuntimeError("bounded verification report exceeded its size limit")
    with path.open("xb") as stream:
        stream.write(payload)


def _installed_cli_command(executable: str, runs: Path) -> list[str]:
    return [
        executable,
        "-I",
        "-B",
        "-m",
        "bluefire.cli",
        "--runs-dir",
        str(runs),
        "ui",
        "--host",
        "127.0.0.1",
        "--port",
        "0",
        "--no-browser",
    ]


def browser_report_passed(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    report = cast(Mapping[str, object], value)
    return (
        set(report)
        == {
            "schema_version",
            "status",
            "installed_service",
            "packaged_ui",
            "external_engine_executed",
            "controlled_provider_mechanics",
            "live_model_inference",
            "target_execution",
            "defensive_change_applied",
            "creation_error_code",
            "checks",
            "blocked_requests",
            "errors",
            "browser_context_closed",
            "browser_closed",
        }
        and report.get("schema_version") == "bluefire.installed-engine-experiment.browser-report.v1"
        and report.get("status") == "passed"
        and report.get("installed_service") is True
        and report.get("packaged_ui") is True
        and report.get("external_engine_executed") is False
        and report.get("controlled_provider_mechanics") is False
        and report.get("live_model_inference") is False
        and report.get("target_execution") is False
        and report.get("defensive_change_applied") is False
        and report.get("creation_error_code") == "engine_workspace_unavailable"
        and report.get("checks") == _CHECKS
        and report.get("blocked_requests") == []
        and report.get("errors") == []
        and report.get("browser_context_closed") is True
        and report.get("browser_closed") is True
    )


def _read_browser_report(path: Path) -> dict[str, object]:
    with path.open("rb") as stream:
        payload = stream.read(_MAX_REPORT_BYTES + 1)
    if len(payload) > _MAX_REPORT_BYTES:
        raise RuntimeError("browser report exceeded its size limit")
    value: object = json.loads(payload)
    if not browser_report_passed(value):
        raise RuntimeError("browser report did not satisfy its contract")
    return cast(dict[str, object], value)


def build_identity_valid(value: object) -> bool:
    if not isinstance(value, Mapping) or set(value) != {
        "distribution",
        "version",
        "wheel_sha256",
        "source_revision",
        "source_provenance",
        "build_metadata_status",
        "ui_digest",
        "ui_files",
        "ui_matches_build",
        "controlled_provider_sha256",
        "wheel_member_count",
        "wheel_payload_digest",
        "installed_payload_digest",
    }:
        return False
    identity = cast(Mapping[str, object], value)
    files = identity.get("ui_files")
    if not isinstance(files, list) or len(files) not in (3, 4):
        return False
    names = ["app.js", "index.html", "styles.css"]
    if len(files) == 4:
        names.append("fonts/InterVariable.woff2")
    for item, name in zip(files, names, strict=True):
        if (
            not isinstance(item, Mapping)
            or set(item) != {"name", "sha256", "size"}
            or item.get("name") != name
            or not isinstance(item.get("sha256"), str)
            or _DIGEST.fullmatch(cast(str, item["sha256"])) is None
            or isinstance(item.get("size"), bool)
            or not isinstance(item.get("size"), int)
            or not 0 < cast(int, item["size"]) <= 8 * 1024 * 1024
        ):
            return False
    revision = identity.get("source_revision")
    provenance = identity.get("source_provenance")
    return (
        identity.get("distribution") == "bluefire-nexus"
        and isinstance(identity.get("version"), str)
        and bool(identity.get("version"))
        and isinstance(identity.get("wheel_sha256"), str)
        and _DIGEST.fullmatch(cast(str, identity["wheel_sha256"])) is not None
        and (
            (revision is None and provenance == "unavailable")
            or (
                isinstance(revision, str)
                and re.fullmatch(r"[0-9a-f]{40}", revision) is not None
                and provenance == "git_archive"
            )
        )
        and identity.get("build_metadata_status") == "embedded"
        and isinstance(identity.get("ui_digest"), str)
        and _DIGEST.fullmatch(cast(str, identity["ui_digest"])) is not None
        and identity.get("ui_matches_build") is True
        and isinstance(identity.get("controlled_provider_sha256"), str)
        and _DIGEST.fullmatch(cast(str, identity["controlled_provider_sha256"])) is not None
        and isinstance(identity.get("wheel_member_count"), int)
        and not isinstance(identity.get("wheel_member_count"), bool)
        and 1 <= cast(int, identity["wheel_member_count"]) <= _MAX_WHEEL_FILES
        and isinstance(identity.get("wheel_payload_digest"), str)
        and _DIGEST.fullmatch(cast(str, identity["wheel_payload_digest"])) is not None
        and identity.get("installed_payload_digest") == identity.get("wheel_payload_digest")
    )


def cleanup_confirmed(value: object) -> bool:
    return isinstance(value, Mapping) and value == {
        "browser_process_group": "stopped",
        "service_process_group": "stopped",
        "temporary_runtime_removed": True,
    }


def receipt_passed(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    receipt = cast(Mapping[str, object], value)
    return (
        set(receipt)
        == {
            "schema_version",
            "status",
            "scope",
            "installed_wheel",
            "source_checkout_import",
            "real_local_service",
            "packaged_ui",
            "external_engine_executed",
            "controlled_provider_mechanics",
            "live_model_inference",
            "target_execution",
            "defensive_change_applied",
            "attack_defense_retest_proven",
            "engine_api_fail_closed",
            "partial_create_absent",
            "limitations",
            "artifact_identity",
            "browser_report",
            "cleanup",
        }
        and receipt.get("schema_version") == "bluefire.installed-engine-experiment-verification.v1"
        and receipt.get("status") == "passed"
        and receipt.get("scope") == "installed_fail_closed_engine_experiment_shell"
        and receipt.get("installed_wheel") is True
        and receipt.get("source_checkout_import") is False
        and receipt.get("real_local_service") is True
        and receipt.get("packaged_ui") is True
        and receipt.get("external_engine_executed") is False
        and receipt.get("controlled_provider_mechanics") is False
        and receipt.get("live_model_inference") is False
        and receipt.get("target_execution") is False
        and receipt.get("defensive_change_applied") is False
        and receipt.get("attack_defense_retest_proven") is False
        and receipt.get("engine_api_fail_closed") is True
        and receipt.get("partial_create_absent") is True
        and receipt.get("limitations")
        == [
            "Controller-owned experiment presentation metadata was not provisioned.",
            "No controlled-provider, external-engine, target, defense, or retest effect ran.",
            "This check does not establish live-model decision quality or attack effectiveness.",
        ]
        and build_identity_valid(receipt.get("artifact_identity"))
        and browser_report_passed(receipt.get("browser_report"))
        and cleanup_confirmed(receipt.get("cleanup"))
    )


def _signal_number(name: str) -> int:
    value = getattr(signal, name, None)
    if not isinstance(value, int) or isinstance(value, bool):
        raise RuntimeError("POSIX process signals are unavailable")
    return value


def _kill_group(process_id: int, signum: int) -> None:
    killpg = getattr(os, "killpg", None)
    if not callable(killpg):
        raise RuntimeError("POSIX process-group cleanup is unavailable")
    killpg(process_id, signum)


def stop_group(process: subprocess.Popen[bytes]) -> bool:
    for signum, grace in (
        (_signal_number("SIGINT"), 8),
        (_signal_number("SIGTERM"), 3),
        (_signal_number("SIGKILL"), 5),
    ):
        try:
            _kill_group(process.pid, 0)
        except ProcessLookupError:
            if process.poll() is None:
                process.wait(timeout=5)
            return process.poll() is not None
        try:
            _kill_group(process.pid, signum)
        except ProcessLookupError:
            continue
        try:
            process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            continue
    try:
        _kill_group(process.pid, 0)
    except ProcessLookupError:
        return True
    return False


def _drain(stream: Any, state: dict[str, object], lock: threading.Lock) -> None:
    total = 0
    pending = bytearray()
    for chunk in iter(lambda: stream.read1(1024), b""):
        total += len(chunk)
        with lock:
            state["stderr_bytes"] = total
            if total > _MAX_STREAM_BYTES:
                state["overflow"] = True
        if total > _MAX_STREAM_BYTES:
            pending.clear()
            continue
        pending.extend(chunk)
        while b"\n" in pending:
            line, _, rest = pending.partition(b"\n")
            pending = bytearray(rest)
            _consume_line(line, state, lock)
    if pending:
        _consume_line(pending, state, lock)


def _consume_line(line: bytes, state: dict[str, object], lock: threading.Lock) -> None:
    if len(line) > 2048:
        return
    text = line.decode("utf-8", errors="ignore").strip()
    if text.startswith("BlueFire local console: "):
        match = _CONSOLE_URL.fullmatch(text.removeprefix("BlueFire local console: "))
        if match:
            with lock:
                state["port"] = int(match.group(1))
                state["url_capability"] = match.group(2)
    elif text.startswith("One-time connection code: "):
        capability = text.removeprefix("One-time connection code: ")
        if _CAPABILITY.fullmatch(capability):
            with lock:
                state["code"] = capability


def _wait_ready(
    process: subprocess.Popen[bytes], state: dict[str, object], lock: threading.Lock
) -> tuple[int, str]:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        with lock:
            port = state.get("port")
            capability = state.get("url_capability")
            code = state.get("code")
            overflow = state.get("overflow") is True
        if (
            type(port) is int
            and 1 <= cast(int, port) <= 65535
            and isinstance(capability, str)
            and capability == code
        ):
            return cast(int, port), capability
        if process.poll() is not None or overflow:
            break
        time.sleep(0.05)
    raise RuntimeError("installed CLI did not announce one bounded loopback session")


def _run_driver(
    *,
    node: Path,
    driver: Path,
    playwright: Path,
    environment: dict[str, str],
    output: Path,
    port: int,
    capability: str,
) -> tuple[int, bool]:
    child = subprocess.Popen(
        [str(node), str(driver), str(playwright), str(output), str(port)],
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    returncode = 124
    try:
        child.communicate(
            json.dumps({"capability": capability}).encode("ascii"),
            timeout=_MAX_DRIVER_SECONDS,
        )
        returncode = child.returncode or 0
    except subprocess.TimeoutExpired:
        pass
    finally:
        stopped = stop_group(child)
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
        or Path(__file__).resolve().is_relative_to(forbidden)
        or driver.is_relative_to(forbidden)
        or Path.cwd().resolve().is_relative_to(forbidden)
        or not driver.is_file()
        or not node.is_file()
        or not playwright.is_file()
        or not browser_cache.is_dir()
        or not wheel.is_file()
    ):
        raise RuntimeError("Use fresh verifier resources outside the checkout")
    output.mkdir(mode=0o700)
    runtime = output / "runtime"
    browser_report_path = output / "browser-report.json"
    cleanup: dict[str, object] = {
        "browser_process_group": "not_started",
        "service_process_group": "not_started",
        "temporary_runtime_removed": False,
    }
    receipt: dict[str, object] = {
        "schema_version": "bluefire.installed-engine-experiment-verification.v1",
        "status": "failed_or_incomplete",
        "scope": "installed_fail_closed_engine_experiment_shell",
        "installed_wheel": False,
        "source_checkout_import": False,
        "real_local_service": False,
        "packaged_ui": False,
        "external_engine_executed": False,
        "controlled_provider_mechanics": False,
        "live_model_inference": False,
        "target_execution": False,
        "defensive_change_applied": False,
        "attack_defense_retest_proven": False,
        "engine_api_fail_closed": False,
        "partial_create_absent": False,
        "limitations": [
            "Controller-owned experiment presentation metadata was not provisioned.",
            "No controlled-provider, external-engine, target, defense, or retest effect ran.",
            "This check does not establish live-model decision quality or attack effectiveness.",
        ],
        "artifact_identity": None,
        "browser_report": None,
        "cleanup": cleanup,
    }
    process: subprocess.Popen[bytes] | None = None
    stream_thread: threading.Thread | None = None
    original_cwd = Path.cwd()
    environment = {
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
    try:
        runtime.mkdir(mode=0o700)
        for name in ("home", "state", "temp", "work", "runs"):
            (runtime / name).mkdir(mode=0o700)
        os.environ.clear()
        os.environ.update(environment)
        os.chdir(runtime / "work")
        import bluefire
        from bluefire.build_info import build_info

        package = Path(bluefire.__file__).resolve(strict=True).parent
        purelib = Path(sysconfig.get_path("purelib")).resolve(strict=True)
        if package.is_relative_to(forbidden) or not package.is_relative_to(purelib):
            raise RuntimeError("candidate package was not imported from isolated installation")
        info = build_info()
        source = cast(Mapping[str, object], info.get("source"))
        build = cast(Mapping[str, object], info.get("build"))
        ui = cast(Mapping[str, object], info.get("ui"))
        provider = package / "controlled_strix_provider.py"
        version = importlib.metadata.version("bluefire-nexus")
        wheel_binding = bind_installed_wheel(wheel, purelib=purelib, installed_version=version)
        identity = {
            "distribution": "bluefire-nexus",
            "version": version,
            "wheel_sha256": digest(wheel),
            "source_revision": source.get("revision"),
            "source_provenance": source.get("provenance"),
            "build_metadata_status": build.get("metadata_status"),
            "ui_digest": ui.get("digest"),
            "ui_files": ui.get("files"),
            "ui_matches_build": ui.get("matches_build"),
            "controlled_provider_sha256": digest(provider),
            **wheel_binding,
        }
        if not build_identity_valid(identity):
            raise RuntimeError("installed artifact identity is unavailable or inconsistent")
        receipt["artifact_identity"] = identity
        receipt["installed_wheel"] = True

        state: dict[str, object] = {}
        lock = threading.Lock()
        process = subprocess.Popen(
            _installed_cli_command(sys.executable, runtime / "runs"),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        cleanup["service_process_group"] = "started"
        assert process.stderr is not None
        stream_thread = threading.Thread(
            target=_drain,
            args=(process.stderr, state, lock),
            daemon=True,
        )
        stream_thread.start()
        port, capability = _wait_ready(process, state, lock)
        receipt["real_local_service"] = True
        cleanup["browser_process_group"] = "started"
        driver_code, browser_stopped = _run_driver(
            node=node,
            driver=driver,
            playwright=playwright,
            environment=environment,
            output=output,
            port=port,
            capability=capability,
        )
        capability = ""
        cleanup["browser_process_group"] = "stopped" if browser_stopped else "stop_failed"
        if driver_code != 0 or not browser_stopped:
            raise RuntimeError("installed browser verification failed")
        browser_report = _read_browser_report(browser_report_path)
        receipt["browser_report"] = browser_report
        receipt["packaged_ui"] = True
        receipt["engine_api_fail_closed"] = True
        receipt["partial_create_absent"] = True
    finally:
        if process is not None:
            cleanup["service_process_group"] = "stopped" if stop_group(process) else "stop_failed"
        if stream_thread is not None:
            stream_thread.join(timeout=5)
        os.chdir(original_cwd)
        if runtime.exists() and cleanup["service_process_group"] == "stopped":
            shutil.rmtree(runtime)
        cleanup["temporary_runtime_removed"] = not runtime.exists()
        if (
            receipt.get("browser_report") is not None
            and cleanup_confirmed(cleanup)
            and receipt.get("installed_wheel") is True
        ):
            receipt["status"] = "passed"
        _write_new(output / "receipt.json", receipt)
    return 0 if receipt_passed(receipt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
