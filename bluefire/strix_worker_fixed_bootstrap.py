"""Exact ``/bootstrap/worker.py`` for the pinned Linux runtime closure.

The runtime assembler copies this file byte-for-byte.  It is invoked only as::

    /runtime/bin/python -I -S -B -X utf8 /bootstrap/worker.py

It verifies and loads the sealed lockdown source by absolute path, establishes
the final seccomp filter, and only afterward exposes pinned site-packages.
"""

from __future__ import annotations

import sys

_PERMITTED_STDLIB_PATHS = {
    "/runtime/lib/python312.zip",
    "/runtime/lib/python3.12",
    "/runtime/lib/python3.12/lib-dynload",
}


def _validate_interpreter(state: object = sys) -> None:
    """Use only built-in ``sys`` facts before any path-loaded import."""

    flags = getattr(state, "flags", None)
    required_flags = (
        "isolated",
        "ignore_environment",
        "no_site",
        "no_user_site",
        "dont_write_bytecode",
        "utf8_mode",
        "safe_path",
    )
    if (
        getattr(state, "executable", None) != "/runtime/bin/python"
        or getattr(state, "prefix", None) != "/runtime"
        or getattr(state, "base_prefix", None) != "/runtime"
        or getattr(state, "exec_prefix", None) != "/runtime"
        or getattr(state, "base_exec_prefix", None) != "/runtime"
        or getattr(state, "dont_write_bytecode", None) is not True
        or flags is None
        or any(getattr(flags, name, None) != 1 for name in required_flags)
        or "site" in getattr(state, "modules", {})
    ):
        raise RuntimeError("worker interpreter isolation flags do not match")


def _validate_stdlib_paths(state: object = sys) -> None:
    search_path = getattr(state, "path", None)
    if not search_path or any(path not in _PERMITTED_STDLIB_PATHS for path in search_path):
        raise RuntimeError("worker interpreter search path is not closure-private")
    if (
        "/runtime/lib/python3.12" not in search_path
        or "/runtime/lib/python3.12/lib-dynload" not in search_path
    ):
        raise RuntimeError("worker interpreter standard library is incomplete")


# In the exact installed path these checks run before importing even a trusted
# path-loaded stdlib module.  Importing this source as a package is supported
# only for build-time identity tests and never launches a worker.
if __name__ == "__main__":
    _validate_interpreter()
    _validate_stdlib_paths()

import importlib.util  # noqa: E402 - path validation must precede stdlib imports
import os  # noqa: E402 - path validation must precede stdlib imports
import stat  # noqa: E402 - path validation must precede stdlib imports

try:  # The exact Python 3.12 closure must provide its closure-local _sha2 module.
    import _sha2 as _sha  # noqa: E402
except ImportError:  # pragma: no cover - build-time import on Python 3.10/3.11
    if sys.version_info[:2] >= (3, 12):
        raise
    import _sha256 as _sha  # noqa: E402

LOCKDOWN_PATH = "/bootstrap/worker_lockdown.py"
LOCKDOWN_SOURCE_DIGEST = "sha256:81c54fc91e5be48e8b0b7d04258adb9ebb65862eec2be210c40b1f84015595aa"
POLICY_DIGEST = "sha256:40524c5404267c5237a70ff0e9c6c916a825e447aa0b6bb4eb39a67d9cb36fc6"
RUNTIME_SITE_PACKAGES = "/runtime/lib/python3.12/site-packages"
CONTROLLED_WORKER_MODULE = "bluefire.strix_controlled_installed_worker"
LOCKDOWN_MODULE = "bluefire.strix_worker_seccomp_bootstrap"
_MAX_LOCKDOWN_BYTES = 128 * 1024
OBSERVATION_FD = 30
OBSERVATION_BASIS_FD = 31
OBSERVATION_ENVELOPE_SCHEMA = "bluefire.strix-fixed-exec-observation-envelope.v1"
OBSERVATION_BASIS_SCHEMA = "bluefire.strix-fixed-exec-observation-basis.v1"
ARMED_SCHEMA = "bluefire.strix-fixed-exec-armed.v1"
QUALIFIED_SCHEMA = "bluefire.strix-linux-fixed-exec-receipt.v1"
_MAX_OBSERVATION_BYTES = 64 * 1024
_OBSERVATION_TIMEOUT_SECONDS = 2.0
_MEMFD_SEALS = 0x0001 | 0x0002 | 0x0004 | 0x0008
_DIGEST_PREFIX = "sha256:"
_BASIS_FIELDS = {
    "schema_version",
    "armed_payload",
    "qualified_receipt_base",
    "basis_ref",
}
_ARMED_FIELDS = {
    "schema_version",
    "attempt_id",
    "plan_ref",
    "worker_custody_identity_digest",
    "seccomp_profile_digest",
    "no_new_privileges",
    "seccomp_mode",
    "tsync",
}
_POST_ARM_RECEIPT_FIELDS = {
    "startup_imports_verified",
    "required_threads_verified",
    "exec_process_probes_refused",
    "seccomp_tsync_armed",
    "no_new_privileges",
    "production_activation_eligible",
}
_QUALIFIED_RECEIPT_BASE_FIELDS = {
    "schema_version",
    "observed_at",
    "attempt_id",
    "resource_claim_ref",
    "worker_activation_ref",
    "worker_containment_ref",
    "boundary_helper_digest",
    "worker_custody_identity_digest",
    "cgroup_ref",
    "seccomp_profile_digest",
    "input_bindings_ref",
    "installed_projection_ref",
    "startup_overlay_ref",
    "sealed_inputs_ref",
    "controller_socket_identity_ref",
    "model_listener_ref",
    "caido_listener_ref",
    "endpoint_cleanup_authority_ref",
    "endpoint_directory_identity_ref",
    "native_observation_ref",
    "controller_boot_id",
    "worker_host_pid",
    "worker_uid",
    "worker_gid",
    "worker_start_ticks",
    "worker_nspid",
    "plan_ref",
    "source_root_identity_digest",
    "closure_inventory_digest",
    "interpreter_digest",
    "strix_entrypoint_digest",
    "bootstrap_digest",
    "lockdown_source_digest",
    "private_root_mount_id",
    "private_root_st_dev",
    "private_root_st_ino",
    "mount_namespace_inode",
    "network_namespace_inode",
    "ipc_namespace_inode",
    "uts_namespace_inode",
    "argv_digest",
    "environment_digest",
    "input_paths_digest",
    "guest_projection_digest",
    "private_device_policy_digest",
    "control_socket_path",
    "private_overmounts",
    "execveat_empty_path",
    "fresh_address_space",
    "ambient_credentials_absent",
    "closure_copy_verified",
    "closure_mount_read_only",
    "closure_mount_nosuid",
    "closure_mount_nodev",
    "private_devices_exact",
    "private_etc_exact",
    "proc_absent",
    "sys_absent",
    "host_root_detached",
    "sealed_inputs_bound",
    "controller_socket_bound",
    "model_listener_bound",
    "caido_listener_bound",
    "supplementary_groups_empty",
    "capabilities_empty",
    "endpoint_cleanup_capability_held",
}
_REQUIRED_CONCURRENT_THREAD_PROBES = 8
_REQUIRED_RUNTIME_IMPORTS = (
    CONTROLLED_WORKER_MODULE,
    "strix",
    "strix.runtime.backends",
    "strix.interface.main",
    "agents",
    "agents.sandbox.session",
    "agents.sandbox.snapshot",
    "agents.sandbox.types",
    "openai",
)


def _read_lockdown_source() -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(LOCKDOWN_PATH, flags)
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_mode & 0o222
            or not 0 < details.st_size <= _MAX_LOCKDOWN_BYTES
        ):
            raise RuntimeError("worker lockdown source identity is invalid")
        chunks = []
        remaining = details.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise RuntimeError("worker lockdown source is incomplete")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise RuntimeError("worker lockdown source changed while reading")
        source = b"".join(chunks)
    finally:
        os.close(descriptor)
    observed = "sha256:" + _sha.sha256(source).hexdigest()
    if observed != LOCKDOWN_SOURCE_DIGEST:
        raise RuntimeError("worker lockdown source digest does not match")
    return source


def _load_and_arm(source: bytes) -> object:
    specification = importlib.util.spec_from_loader(LOCKDOWN_MODULE, loader=None)
    if specification is None:
        raise RuntimeError("worker lockdown module specification is unavailable")
    module = importlib.util.module_from_spec(specification)
    sys.modules[LOCKDOWN_MODULE] = module
    try:
        code = compile(source, LOCKDOWN_PATH, "exec", dont_inherit=True, optimize=2)
        exec(code, module.__dict__)
        arm = getattr(module, "arm", None)
        if not callable(arm):
            raise RuntimeError("worker lockdown entrypoint is unavailable")
        installation = arm(expected_policy_digest=POLICY_DIGEST)
        if (
            getattr(installation, "policy_digest", None) != POLICY_DIGEST
            or getattr(installation, "no_new_privileges", None) is not True
            or getattr(installation, "seccomp_mode", None) != 2
            or getattr(installation, "tsync", None) is not True
        ):
            raise RuntimeError("worker lockdown kernel evidence does not match")
        return installation
    except BaseException:
        sys.modules.pop(LOCKDOWN_MODULE, None)
        raise


def _canonical_json_bytes(value: object) -> bytes:
    import json

    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _document_ref(value: object) -> str:
    return _DIGEST_PREFIX + str(_sha.sha256(_canonical_json_bytes(value)).hexdigest())


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith(_DIGEST_PREFIX)
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _effective_uid() -> int:
    getter = getattr(os, "geteuid", None)
    return int(getter()) if callable(getter) else 1_000


def _effective_gid() -> int:
    getter = getattr(os, "getegid", None)
    return int(getter()) if callable(getter) else 1_000


def _read_observation_basis(descriptor: int = OBSERVATION_BASIS_FD) -> dict[str, object]:
    import fcntl
    import json

    details = os.fstat(descriptor)
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_nlink != 0
        or stat.S_IMODE(details.st_mode) != 0o400
        or not 0 < details.st_size <= _MAX_OBSERVATION_BYTES
        or fcntl.__dict__["fcntl"](descriptor, fcntl.__dict__.get("F_GET_SEALS", 1034))
        != _MEMFD_SEALS
    ):
        raise RuntimeError("worker observation basis identity is invalid")
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks = []
    remaining = details.st_size
    while remaining:
        chunk = os.read(descriptor, min(remaining, 16 * 1024))
        if not chunk:
            raise RuntimeError("worker observation basis is incomplete")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise RuntimeError("worker observation basis changed while reading")
    os.close(descriptor)
    encoded = b"".join(chunks)
    try:
        value = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("worker observation basis is not JSON") from error
    if not isinstance(value, dict) or _canonical_json_bytes(value) != encoded:
        raise RuntimeError("worker observation basis is not canonical")
    return _validate_observation_basis(value)


def _validate_observation_basis(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _BASIS_FIELDS:
        raise RuntimeError("worker observation basis fields do not match")
    if value["schema_version"] != OBSERVATION_BASIS_SCHEMA:
        raise RuntimeError("worker observation basis schema is unsupported")
    expected_ref = _document_ref(
        {name: item for name, item in value.items() if name != "basis_ref"}
    )
    if value["basis_ref"] != expected_ref:
        raise RuntimeError("worker observation basis digest does not match")
    armed = value["armed_payload"]
    receipt = value["qualified_receipt_base"]
    if not isinstance(armed, dict) or set(armed) != _ARMED_FIELDS:
        raise RuntimeError("worker armed payload fields do not match")
    if (
        armed["schema_version"] != ARMED_SCHEMA
        or not isinstance(armed["attempt_id"], str)
        or not armed["attempt_id"]
        or not _is_digest(armed["plan_ref"])
        or not _is_digest(armed["worker_custody_identity_digest"])
        or armed["seccomp_profile_digest"] != POLICY_DIGEST
        or armed["no_new_privileges"] is not True
        or armed["seccomp_mode"] != 2
        or armed["tsync"] is not True
    ):
        raise RuntimeError("worker armed payload identity is invalid")
    if (
        not isinstance(receipt, dict)
        or set(receipt) != _QUALIFIED_RECEIPT_BASE_FIELDS
        or receipt.get("schema_version") != QUALIFIED_SCHEMA
        or receipt.get("attempt_id") != armed["attempt_id"]
        or receipt.get("plan_ref") != armed["plan_ref"]
        or receipt.get("worker_custody_identity_digest")
        != armed["worker_custody_identity_digest"]
        or receipt.get("seccomp_profile_digest") != POLICY_DIGEST
        or not _is_digest(receipt.get("native_observation_ref"))
        or receipt.get("worker_host_pid") != os.getpid()
        or receipt.get("worker_uid") != _effective_uid()
        or receipt.get("worker_gid") != _effective_gid()
    ):
        raise RuntimeError("worker qualified receipt basis is invalid")
    return value


def _observation_envelope(phase: str, payload: dict[str, object]) -> bytes:
    if phase not in {"armed", "qualified"}:
        raise RuntimeError("worker observation phase is invalid")
    envelope = {
        "schema_version": OBSERVATION_ENVELOPE_SCHEMA,
        "phase": phase,
        "payload": payload,
        "payload_ref": _document_ref(payload),
    }
    encoded = _canonical_json_bytes(envelope)
    if len(encoded) > _MAX_OBSERVATION_BYTES:
        raise RuntimeError("worker observation packet exceeds its bound")
    return encoded


def _open_observation_socket(descriptor: int = OBSERVATION_FD) -> object:
    import socket

    channel = socket.socket(fileno=descriptor)
    if (
        channel.family != socket.__dict__["AF_UNIX"]
        or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET
    ):
        channel.close()
        raise RuntimeError("worker observation channel identity is invalid")
    channel.settimeout(_OBSERVATION_TIMEOUT_SECONDS)
    return channel


def _send_observation(channel: object, phase: str, payload: dict[str, object]) -> None:
    encoded = _observation_envelope(phase, payload)
    try:
        sent = channel.send(encoded)  # type: ignore[attr-defined]
    except (BrokenPipeError, TimeoutError, OSError) as error:
        raise RuntimeError("worker observation delivery failed") from error
    if sent != len(encoded):
        raise RuntimeError("worker observation delivery was incomplete")


def _probe_process_refusals() -> None:
    import errno

    try:
        os.execve("/__bluefire_exec_probe_absent__", ["bluefire-probe"], {})
    except PermissionError as error:
        if error.errno != errno.EPERM:
            raise RuntimeError("worker exec refusal errno is invalid") from error
    except OSError as error:
        raise RuntimeError("worker exec was not refused by policy") from error
    else:  # pragma: no cover - successful exec cannot return
        raise RuntimeError("worker exec unexpectedly returned")

    try:
        child = os.__dict__["fork"]()
    except PermissionError as error:
        if error.errno != errno.EPERM:
            raise RuntimeError("worker fork refusal errno is invalid") from error
        return
    except OSError as error:
        raise RuntimeError("worker fork was not refused by policy") from error
    if child == 0:  # pragma: no cover - reachable only with a broken policy
        os._exit(127)
    os.waitpid(child, 0)
    raise RuntimeError("worker fork policy did not hold")


def _probe_required_thread() -> None:
    import threading

    observed: list[tuple[int, int]] = []
    barrier = threading.Barrier(_REQUIRED_CONCURRENT_THREAD_PROBES + 1)
    release = threading.Event()

    def record() -> None:
        observed.append((os.getpid(), threading.get_native_id()))
        barrier.wait(_OBSERVATION_TIMEOUT_SECONDS)
        release.wait(_OBSERVATION_TIMEOUT_SECONDS)

    threads = [
        threading.Thread(target=record, name=f"bluefire-strix-lockdown-probe-{index}")
        for index in range(_REQUIRED_CONCURRENT_THREAD_PROBES)
    ]
    try:
        for thread in threads:
            thread.start()
        barrier.wait(_OBSERVATION_TIMEOUT_SECONDS)
        if any(not thread.is_alive() for thread in threads):
            raise RuntimeError("worker concurrent thread probe ended early")
    except (RuntimeError, threading.BrokenBarrierError) as error:
        raise RuntimeError("worker concurrent thread probe failed") from error
    finally:
        release.set()
        for thread in threads:
            if thread.ident is not None:
                thread.join(_OBSERVATION_TIMEOUT_SECONDS)
    native_ids = {native_id for pid, native_id in observed if pid == os.getpid()}
    if (
        any(thread.is_alive() for thread in threads)
        or len(observed) != _REQUIRED_CONCURRENT_THREAD_PROBES
        or len(native_ids) != _REQUIRED_CONCURRENT_THREAD_PROBES
        or threading.get_native_id() in native_ids
    ):
        raise RuntimeError("worker same-process thread probe failed")


def _validate_module_origin(name: str, module: object) -> None:
    specification = getattr(module, "__spec__", None)
    origin = getattr(specification, "origin", None) or getattr(module, "__file__", None)
    if origin in {"built-in", "frozen"}:
        return
    if isinstance(origin, str) and os.path.realpath(origin).startswith("/runtime/"):
        return
    search_locations = getattr(specification, "submodule_search_locations", None)
    if search_locations and all(
        isinstance(path, str) and os.path.realpath(path).startswith("/runtime/")
        for path in search_locations
    ):
        return
    raise RuntimeError("worker import escaped the private runtime: " + name)


def _probe_runtime_imports() -> None:
    import importlib

    if RUNTIME_SITE_PACKAGES in sys.path:
        raise RuntimeError("worker site-packages was exposed before qualification")
    sys.path.append(RUNTIME_SITE_PACKAGES)
    before = set(sys.modules)
    imported = []
    for name in _REQUIRED_RUNTIME_IMPORTS:
        module = importlib.import_module(name)
        _validate_module_origin(name, module)
        imported.append(module)
    for name in set(sys.modules) - before:
        module = sys.modules.get(name)
        if module is not None:
            _validate_module_origin(name, module)
    if any(module is None for module in imported):
        raise RuntimeError("worker required import is unavailable")
    # The installed worker is executed with runpy after the final receipt.  Do
    # not retain its probe import and trigger runpy's already-imported path.
    sys.modules.pop(CONTROLLED_WORKER_MODULE, None)


def _complete_observation(installation: object) -> None:
    basis = _read_observation_basis()
    armed = basis["armed_payload"]
    receipt_base = basis["qualified_receipt_base"]
    if not isinstance(armed, dict) or not isinstance(receipt_base, dict):
        raise RuntimeError("worker observation basis is invalid")
    if (
        armed["seccomp_profile_digest"] != getattr(installation, "policy_digest", None)
        or armed["no_new_privileges"]
        is not getattr(installation, "no_new_privileges", None)
        or armed["seccomp_mode"] != getattr(installation, "seccomp_mode", None)
        or armed["tsync"] is not getattr(installation, "tsync", None)
    ):
        raise RuntimeError("worker armed observation does not match the kernel")
    channel = _open_observation_socket()
    try:
        _send_observation(channel, "armed", armed)
        _probe_process_refusals()
        _probe_required_thread()
        _probe_runtime_imports()
        qualified = dict(receipt_base)
        qualified.update(
            {
                "startup_imports_verified": True,
                "required_threads_verified": True,
                "exec_process_probes_refused": True,
                "seccomp_tsync_armed": True,
                "no_new_privileges": True,
                "production_activation_eligible": True,
            }
        )
        qualified["receipt_ref"] = _document_ref(qualified)
        _send_observation(channel, "qualified", qualified)
    finally:
        channel.close()  # type: ignore[attr-defined]


def main() -> int:
    _validate_interpreter()
    _validate_stdlib_paths()
    source = _read_lockdown_source()
    installation = _load_and_arm(source)
    _complete_observation(installation)

    # Site processing remains disabled; qualification added only the exact
    # closure site-packages path after the final seccomp policy was armed.
    import runpy

    runpy.run_module(CONTROLLED_WORKER_MODULE, run_name="__main__", alter_sys=False)
    return 0


if __name__ == "__main__":  # pragma: no cover - exact installed entrypoint
    raise SystemExit(main())
