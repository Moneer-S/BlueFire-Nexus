"""Fixed product-surface, WSL2, and macOS readiness proofs for Gate 11."""

from __future__ import annotations

import ctypes
import http.client
import json
import os
import re
import subprocess  # nosec B404 - commands are fixed product/WSL grammars
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable, Mapping, cast

from .api import BROWSER_BOOTSTRAP_HEADER, create_server, generate_browser_bootstrap_capability
from .runner_bootstrap import current_platform, wheel_platform_tag
from .runner_contracts import RunnerContractError, build_runner_profile
from .service import BlueFireService
from .util import canonical_json_bytes, content_hash

READINESS_SCHEMA = "bluefire.cross-platform-readiness.v1"
MACOS_SCHEMA = "bluefire.cross-platform-macos-contract.v1"
PROFILE_ID = "sandbox-endpoint-deep-lab.v1"
WINDOWS_ONLY_PROFILE_ID = "sandbox-windows-source-intake.v1"
WSL_DISTRIBUTION_ID = "BlueFire-Gate11-Base-v1"
_WSL_DISTRIBUTION_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_PRIVATE_PATH = re.compile(r"(?:^|[\s(\[{'\"=])(?:[A-Za-z]:[\\/]|\\\\[^\\/\s]+[\\/]|/[^\s])")
_FILE_URL = re.compile(r"file:(?://+|\\\\)", re.IGNORECASE)
_MAX_STATUS_BYTES = 64 * 1024
_MAX_WSL_PROBE_BYTES = 64 * 1024
_WSL_REGISTRY_KEY = r"Software\Microsoft\Windows\CurrentVersion\Lxss"

Require = Callable[[bool, str], None]
ChildEnvironment = Callable[[Path, Path], dict[str, str]]


def _macos_process_adapter_is_in_process(process_text: str) -> bool:
    start = process_text.find('#[cfg(target_os = "macos")]\nmod macos_process_api')
    end = process_text.find('#[cfg(target_os = "windows")]\nmod windows_process_api', start)
    if start < 0 or end <= start:
        return False
    adapter = process_text[start:end]
    return all(
        token in adapter
        for token in (
            "proc_listallpids",
            "proc_pidinfo",
            "MAX_PROCESS_COUNT",
            "limits.max_stdout_bytes",
            "max_entries",
        )
    ) and all(
        token not in adapter for token in ("Command::new(", ".spawn(", "/bin/ps", "/usr/bin/ps")
    )


def _http_runner_status(service: BlueFireService, require: Require) -> Mapping[str, Any]:
    capability = generate_browser_bootstrap_capability()
    server = create_server(
        service,
        browser_bootstrap_capability=capability,
        host="127.0.0.1",
        port=0,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = int(server.server_address[1])
    try:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request(
            "POST",
            "/api/v1/session",
            headers={
                BROWSER_BOOTSTRAP_HEADER: capability,
                "Origin": f"http://127.0.0.1:{port}",
            },
        )
        response = connection.getresponse()
        bootstrap_payload = response.read(_MAX_STATUS_BYTES + 1)
        cookie = response.getheader("Set-Cookie")
        connection.close()
        require(
            response.status == 204 and bootstrap_payload == b"" and isinstance(cookie, str),
            "HTTP session bootstrap failed",
        )
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request(
            "GET",
            "/api/v1/runner",
            headers={"Cookie": cast(str, cookie).split(";", 1)[0]},
        )
        response = connection.getresponse()
        payload = response.read(_MAX_STATUS_BYTES + 1)
        connection.close()
        require(0 < len(payload) <= _MAX_STATUS_BYTES, "HTTP runner status exceeded its bound")
        value = json.loads(payload)
        require(response.status == 200 and isinstance(value, Mapping), "HTTP runner status failed")
        return dict(value)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        require(not thread.is_alive(), "HTTP runner status server thread survived cleanup")


def _cli_runner_status(
    repository: Path,
    runtime: Path,
    state_parent: Path,
    child_environment: ChildEnvironment,
    require: Require,
) -> Mapping[str, Any]:
    command = [
        os.fspath(Path(sys.executable).resolve(strict=True)),
        "-m",
        "bluefire.cli",
        "--runs-dir",
        os.fspath(runtime / "cli-runs"),
        "runner",
        "status",
        "--profile",
        PROFILE_ID,
    ]
    stdout_path = runtime / "cli-status.stdout"
    stderr_path = runtime / "cli-status.stderr"
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        completed = subprocess.run(  # nosec B603 - fixed product CLI command
            command,
            cwd=repository,
            env=child_environment(repository, state_parent),
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            timeout=30,
            check=False,
            shell=False,
        )
    stdout_payload = stdout_path.read_bytes()
    stderr_payload = stderr_path.read_bytes()
    require(
        len(stdout_payload) <= _MAX_STATUS_BYTES and len(stderr_payload) <= _MAX_STATUS_BYTES,
        "CLI runner status exceeded its bound",
    )
    require(completed.returncode == 0 and stderr_payload == b"", "CLI runner status failed")
    try:
        value = json.loads(stdout_payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("CLI runner status is not strict JSON") from exc
    require(isinstance(value, Mapping), "CLI runner status is not an object")
    return dict(value)


def _path_free(value: Any) -> bool:
    if isinstance(value, Mapping):
        return all(_path_free(key) and _path_free(item) for key, item in value.items())
    if isinstance(value, list):
        return all(_path_free(item) for item in value)
    if not isinstance(value, str):
        return True
    return _PRIVATE_PATH.search(value) is None and _FILE_URL.search(value) is None


def _platform_mismatches(
    service: BlueFireService,
    runtime: Path,
    require: Require,
) -> list[Mapping[str, Any]]:
    profile = next(
        item for item in service.config.runner_profiles if item.id == WINDOWS_ONLY_PROFILE_ID
    )
    rows: list[Mapping[str, Any]] = []
    for requested in ("linux", "macos"):
        blocked = False
        try:
            build_runner_profile(
                profile,
                sandbox_root=runtime / f"mismatch-{requested}",
                platform=requested,
                filesystem_scope=(),
            )
        except RunnerContractError as exc:
            blocked = str(exc) == "selected runner profile does not support this platform"
        require(blocked, "a fixed cross-platform mismatch was not blocked")
        rows.append(
            {
                "requested_platform": requested,
                "actual_platform": "windows",
                "code": "platform_blocked",
                "dispatch_prevented": True,
            }
        )
    return rows


def _wsl_facts(
    probe_state: str,
    configured: bool | None,
    version: str | None,
    *,
    distribution_id: str = WSL_DISTRIBUTION_ID,
) -> Mapping[str, Any]:
    facts = {
        "provider": "wsl2",
        "probe_state": probe_state,
        "configured": configured,
        "distribution_id": distribution_id,
        "version": version,
    }
    return {**facts, "facts_digest": content_hash(facts)}


def _trusted_wsl_executable() -> Path | None:
    """Resolve System32 through the kernel API, never PATH or environment state."""

    if sys.platform != "win32":
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_system_directory = kernel32.GetSystemDirectoryW
    get_system_directory.argtypes = (ctypes.c_wchar_p, ctypes.c_uint32)
    get_system_directory.restype = ctypes.c_uint32
    buffer = ctypes.create_unicode_buffer(32768)
    length = int(get_system_directory(buffer, len(buffer)))
    if not 0 < length < len(buffer):
        raise OSError("trusted Windows system-directory resolution failed")
    return Path(buffer.value) / "wsl.exe"


def _parse_wsl_list_output(
    payload: bytes,
    *,
    distribution_id: str = WSL_DISTRIBUTION_ID,
) -> Mapping[str, Any]:
    """Classify one bounded ``wsl --list --verbose`` response fail closed."""

    try:
        if payload.startswith((b"\xff\xfe", b"\xfe\xff")) or b"\x00" in payload:
            text = (
                payload.decode("utf-16")
                if payload.startswith((b"\xff\xfe", b"\xfe\xff"))
                else payload.decode("utf-16-le")
            )
        else:
            text = payload.decode("utf-8-sig")
    except UnicodeError:
        return _wsl_facts("indeterminate", None, None, distribution_id=distribution_id)
    candidates: list[list[str]] = []
    for raw_line in text.splitlines():
        line = raw_line.replace("\x00", "").strip()
        if line.startswith("*"):
            line = line[1:].strip()
        fields = line.split()
        if fields and fields[0] == distribution_id:
            candidates.append(fields)
    if not candidates:
        return _wsl_facts("absent", False, None, distribution_id=distribution_id)
    if len(candidates) != 1:
        return _wsl_facts("indeterminate", None, None, distribution_id=distribution_id)
    fields = candidates[0]
    if len(fields) != 3 or fields[2] not in {"1", "2"}:
        return _wsl_facts("indeterminate", None, None, distribution_id=distribution_id)
    if fields[2] == "1":
        return _wsl_facts("incompatible", True, "1", distribution_id=distribution_id)
    return _wsl_facts("ready", True, "2", distribution_id=distribution_id)


def _probe_wsl_registry(
    distribution_id: str = WSL_DISTRIBUTION_ID,
) -> Mapping[str, Any]:
    """Read the fixed WSL registration hive without interpreting localized text."""

    if sys.platform != "win32":
        return _wsl_facts("absent", False, None, distribution_id=distribution_id)
    try:
        import winreg

        try:
            root = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                _WSL_REGISTRY_KEY,
                0,
                winreg.KEY_READ,
            )
        except FileNotFoundError:
            return _wsl_facts("absent", False, None, distribution_id=distribution_id)
        matches: list[int] = []
        with root:
            subkey_count = int(winreg.QueryInfoKey(root)[0])
            if not 0 <= subkey_count <= 256:
                return _wsl_facts("indeterminate", None, None, distribution_id=distribution_id)
            for index in range(subkey_count):
                name = winreg.EnumKey(root, index)
                with winreg.OpenKey(root, name, 0, winreg.KEY_READ) as distribution:
                    distribution_name, distribution_type = winreg.QueryValueEx(
                        distribution, "DistributionName"
                    )
                    version, version_type = winreg.QueryValueEx(distribution, "Version")
                if (
                    distribution_type != winreg.REG_SZ
                    or not isinstance(distribution_name, str)
                    or not 1 <= len(distribution_name) <= 256
                    or version_type != winreg.REG_DWORD
                    or type(version) is not int
                ):
                    return _wsl_facts("indeterminate", None, None, distribution_id=distribution_id)
                if distribution_name == distribution_id:
                    matches.append(version)
    except (OSError, ValueError):
        return _wsl_facts("indeterminate", None, None, distribution_id=distribution_id)
    if not matches:
        return _wsl_facts("absent", False, None, distribution_id=distribution_id)
    if len(matches) != 1 or matches[0] not in {1, 2}:
        return _wsl_facts("indeterminate", None, None, distribution_id=distribution_id)
    if matches[0] == 1:
        return _wsl_facts("incompatible", True, "1", distribution_id=distribution_id)
    return _wsl_facts("ready", True, "2", distribution_id=distribution_id)


def probe_wsl2() -> Mapping[str, Any]:
    """Inspect only the literal approved distribution; never install or mutate it."""

    return probe_wsl_distribution(WSL_DISTRIBUTION_ID)


def probe_wsl_distribution(distribution_id: str) -> Mapping[str, Any]:
    """Reconcile registry and CLI facts for one exact bounded distribution name."""

    if _WSL_DISTRIBUTION_NAME.fullmatch(distribution_id) is None:
        return _wsl_facts("indeterminate", None, None, distribution_id=distribution_id)
    if os.name != "nt":
        return _wsl_facts("absent", False, None, distribution_id=distribution_id)
    registry = _probe_wsl_registry(distribution_id)
    if registry.get("probe_state") == "indeterminate":
        return registry
    try:
        executable = _trusted_wsl_executable()
    except OSError:
        return _wsl_facts("indeterminate", None, None, distribution_id=distribution_id)
    if executable is None:
        return _wsl_facts("indeterminate", None, None, distribution_id=distribution_id)
    if not executable.is_file():
        return (
            registry
            if registry.get("probe_state") == "absent"
            else _wsl_facts("indeterminate", None, None, distribution_id=distribution_id)
        )
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            completed = subprocess.run(  # nosec B603 - list-only fixed WSL boundary
                [os.fspath(executable), "--list", "--verbose"],
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                timeout=15,
                check=False,
                shell=False,
            )
            stdout.seek(0)
            raw = stdout.read(_MAX_WSL_PROBE_BYTES + 1)
            stderr.seek(0)
            error = stderr.read(_MAX_WSL_PROBE_BYTES + 1)
    except (OSError, subprocess.TimeoutExpired):
        return _wsl_facts("indeterminate", None, None, distribution_id=distribution_id)
    if len(raw) > _MAX_WSL_PROBE_BYTES or len(error) > _MAX_WSL_PROBE_BYTES:
        return _wsl_facts("indeterminate", None, None, distribution_id=distribution_id)
    if completed.returncode != 0 or error != b"":
        return (
            registry
            if registry.get("probe_state") in {"absent", "incompatible"}
            else _wsl_facts("indeterminate", None, None, distribution_id=distribution_id)
        )
    listed = _parse_wsl_list_output(raw, distribution_id=distribution_id)
    if listed.get("probe_state") == "indeterminate":
        return listed
    if (
        listed.get("probe_state") != registry.get("probe_state")
        or listed.get("configured") != registry.get("configured")
        or listed.get("version") != registry.get("version")
    ):
        return _wsl_facts("indeterminate", None, None, distribution_id=distribution_id)
    return registry


def macos_report(repository: Path, service: BlueFireService, require: Require) -> Mapping[str, Any]:
    contract_text = (repository / "runner" / "src" / "contract.rs").read_text(encoding="utf-8")
    process_text = (repository / "runner" / "src" / "process.rs").read_text(encoding="utf-8")
    contract = {
        "platform_enum": current_platform("darwin") == "macos",
        "profile_metadata": any(
            "macos" in profile.platforms for profile in service.config.runner_profiles
        ),
        "package_metadata": "macos"
        in service.registry.get_action("sandbox.execution.native-canary.v1").platforms,
        "rust_target_cfg": "Macos" in contract_text and 'target_os = "macos"' in contract_text,
        "fixed_process_adapter": _macos_process_adapter_is_in_process(process_text),
        "x86_64_wheel_tag": wheel_platform_tag("macos", "x86_64"),
        "aarch64_wheel_tag": wheel_platform_tag("macos", "aarch64"),
    }
    expected = {
        "platform_enum": True,
        "profile_metadata": True,
        "package_metadata": True,
        "rust_target_cfg": True,
        "fixed_process_adapter": True,
        "x86_64_wheel_tag": "macosx_11_0_x86_64",
        "aarch64_wheel_tag": "macosx_11_0_arm64",
    }
    require(contract == expected, "the macOS structural contract is incomplete")
    return {
        "schema_version": MACOS_SCHEMA,
        "passed": True,
        "proof_kind": "structural",
        "platform": "macos",
        "dynamic_proof": False,
        "availability": {"state": "structural", "code": "macos_host_unavailable"},
        "contract": contract,
    }


def platform_readiness_report(
    repository: Path,
    runtime: Path,
    state_parent: Path,
    service: BlueFireService,
    linux: Mapping[str, Any],
    macos: Mapping[str, Any],
    wsl: Mapping[str, Any],
    *,
    child_environment: ChildEnvironment,
    require: Require,
) -> Mapping[str, Any]:
    service_status = service.runner_status(profile_id=PROFILE_ID)
    http_status = _http_runner_status(service, require)
    cli_status = _cli_runner_status(repository, runtime, state_parent, child_environment, require)
    identical = service_status == http_status == cli_status
    path_free = all(_path_free(item) for item in (service_status, http_status, cli_status))
    status_documents = {
        "service": dict(service_status),
        "http": dict(http_status),
        "cli": dict(cli_status),
    }
    require(
        all(
            0 < len(canonical_json_bytes(item)) <= _MAX_STATUS_BYTES
            for item in status_documents.values()
        ),
        "a canonical runner status exceeded its evidence bound",
    )
    runner = service_status.get("runner")
    windows_ready = bool(
        identical
        and path_free
        and service_status.get("state") == "ready"
        and isinstance(runner, Mapping)
        and runner.get("platform") == "windows"
    )
    linux_ready = linux.get("passed") is True
    linux_availability = linux.get("availability")
    linux_code = (
        linux_availability.get("code")
        if isinstance(linux_availability, Mapping)
        and linux_availability.get("code")
        in {
            "wsl_distribution_absent",
            "wsl_distribution_not_v2",
            "linux_dependencies_unavailable",
        }
        else "linux_runtime_unavailable"
    )
    platforms = [
        {
            "platform": "windows",
            "proof_kind": "dynamic",
            "state": "ready" if windows_ready else "unavailable",
            "code": None if windows_ready else "runner_status_unavailable",
        },
        {
            "platform": "linux",
            "proof_kind": "dynamic",
            "state": "ready" if linux_ready else "unavailable",
            "code": None if linux_ready else linux_code,
        },
        {
            "platform": "macos",
            "proof_kind": "structural",
            "state": "structural",
            "code": "macos_host_unavailable",
        },
    ]
    passed = windows_ready and linux_ready and macos.get("passed") is True
    return {
        "schema_version": READINESS_SCHEMA,
        "passed": passed,
        "proof_kind": "dynamic",
        "status_documents": status_documents,
        "platforms": platforms,
        "wsl": {**dict(wsl), "dynamic_execution": linux_ready},
        "authorities": {
            "service": service_status.get("state") == "ready",
            "http": http_status.get("state") == "ready",
            "cli": cli_status.get("state") == "ready",
            "identical": identical,
            "path_free": path_free,
            "status_digest": content_hash(dict(service_status)),
        },
        "platform_mismatches": _platform_mismatches(service, runtime, require),
    }


__all__ = [
    "MACOS_SCHEMA",
    "PROFILE_ID",
    "READINESS_SCHEMA",
    "WSL_DISTRIBUTION_ID",
    "macos_report",
    "platform_readiness_report",
    "probe_wsl_distribution",
    "probe_wsl2",
]
