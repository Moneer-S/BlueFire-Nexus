from __future__ import annotations

import builtins
import ctypes
import errno
import multiprocessing
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

import bluefire.secret_store as secret_store
from bluefire.runner_bootstrap import managed_product_root
from bluefire.secret_store import (
    InMemorySecretProvider,
    PosixOwnerPrivateSecretProvider,
    SecretProvider,
    SecretStoreError,
    WindowsDPAPISecretProvider,
    default_secret_provider,
)

_POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="POSIX secret provider test")
_DARWIN_ONLY = pytest.mark.skipif(sys.platform != "darwin", reason="Darwin security test")
_PROCESS_TIMEOUT_SECONDS = 15.0


class _DarwinSecurityApiStub:
    def __init__(
        self,
        *,
        mount_flags: int = 0,
        acl_pointer: int | None = 1,
        acl_errno: int = 0,
        entry_result: int = -1,
        entry_errno: int = errno.EINVAL,
        free_result: int = 0,
    ) -> None:
        self.mount_flags = mount_flags
        self.acl_pointer = acl_pointer
        self.acl_errno = acl_errno
        self.entry_result = entry_result
        self.entry_errno = entry_errno
        self.free_result = free_result
        self.free_calls = 0

    def fstatfs(self, _descriptor: int, output) -> int:
        details = ctypes.cast(
            output,
            ctypes.POINTER(secret_store._DarwinStatFs),
        ).contents
        details.f_flags = self.mount_flags
        return 0

    def acl_get_fd_np(self, _descriptor: int, _acl_type: int) -> int | None:
        ctypes.set_errno(self.acl_errno)
        return self.acl_pointer

    def acl_get_entry(self, _acl, _entry_id: int, output) -> int:
        ctypes.set_errno(self.entry_errno)
        if self.entry_result == 0:
            entry = ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))
            entry.contents.value = 2
        return self.entry_result

    def acl_free(self, _acl) -> int:
        self.free_calls += 1
        return self.free_result


def _posix_key_path(tmp_path: Path, name: str = "master-key.v1") -> Path:
    root = tmp_path / name.removesuffix(".v1")
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    return root / name


def _posix_process_protect(
    key_path: str,
    index: int,
    ready_queue,
    start_event,
    result_queue,
) -> None:
    try:
        ready_queue.put(index)
        if not start_event.wait(timeout=_PROCESS_TIMEOUT_SECONDS):
            raise TimeoutError("test start barrier timed out")
        purpose = f"runner.concurrent-{index}"
        opaque = PosixOwnerPrivateSecretProvider(key_path).protect(
            purpose,
            f"material-{index}".encode(),
        )
        result_queue.put((index, purpose, opaque, ""))
    except Exception as error:
        result_queue.put((index, "", b"", f"{type(error).__name__}: {error}"))


def _posix_process_attempt_protect(key_path: str, result_queue) -> None:
    try:
        PosixOwnerPrivateSecretProvider(key_path).protect("runner.hmac-key", b"material")
    except Exception as error:
        result_queue.put((type(error).__name__, str(error)))
    else:
        result_queue.put(("ok", ""))


def _posix_process_hold_lock(lock_path: str, release_event, status_queue) -> None:
    import fcntl

    descriptor: int | None = None
    locked = False
    try:
        descriptor = os.open(lock_path, os.O_RDWR | getattr(os, "O_NONBLOCK", 0))
        fcntl.flock(descriptor, int(fcntl.LOCK_EX))
        locked = True
        status_queue.put(("ready", ""))
        if not release_event.wait(timeout=_PROCESS_TIMEOUT_SECONDS):
            raise TimeoutError("test lock release timed out")
        status_queue.put(("done", ""))
    except Exception as error:
        status_queue.put(("error", f"{type(error).__name__}: {error}"))
    finally:
        if descriptor is not None:
            if locked:
                fcntl.flock(descriptor, int(fcntl.LOCK_UN))
            os.close(descriptor)


@pytest.mark.parametrize(
    ("platform_name", "bootstrap_platform", "environ"),
    [
        ("linux", "linux", {"XDG_STATE_HOME": "/var/tmp/bluefire-state"}),
        ("linux", "linux", {"XDG_STATE_HOME": "  "}),
        ("darwin", "macos", {"XDG_STATE_HOME": "/ignored"}),
    ],
)
def test_posix_managed_root_policy_matches_runner_bootstrap(
    platform_name: str,
    bootstrap_platform: str,
    environ: dict[str, str],
) -> None:
    assert secret_store._posix_managed_product_root(
        environ=environ,
        platform_name=platform_name,
    ) == managed_product_root(environ=environ, platform_name=bootstrap_platform)


def test_runner_watchdog_import_does_not_require_posix_crypto_binding() -> None:
    repository_root = Path(__file__).resolve().parents[1]
    base_executable = getattr(sys, "_base_executable", None)
    assert isinstance(base_executable, str) and base_executable
    script = """
import builtins
import sys

original_import = builtins.__import__
blocked = []

def guarded_import(name, *args, **kwargs):
    if name == "nacl" or name.startswith("nacl."):
        blocked.append(name)
        raise ModuleNotFoundError("optional crypto binding is unavailable")
    return original_import(name, *args, **kwargs)

builtins.__import__ = guarded_import
sys.path.insert(0, sys.argv[1])
import bluefire.runner_watchdog
assert blocked == []
assert not any(name == "nacl" or name.startswith("nacl.") for name in sys.modules)
print("watchdog-import-ok")
"""

    completed = subprocess.run(
        [base_executable, "-I", "-c", script, os.fspath(repository_root)],
        cwd=repository_root,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "watchdog-import-ok"


def test_posix_provider_missing_crypto_binding_fails_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_import = builtins.__import__

    def blocked_import(name, *args, **kwargs):
        if name == "nacl" or name.startswith("nacl."):
            raise ModuleNotFoundError("injected missing crypto binding")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked_import)
    monkeypatch.setattr(secret_store, "_POSIX_CRYPTO_API", None)
    provider = object.__new__(PosixOwnerPrivateSecretProvider)

    with pytest.raises(SecretStoreError) as protect_error:
        provider.protect("runner.hmac-key", b"material")
    assert str(protect_error.value) == "Secret protection failed."
    assert "nacl" not in str(protect_error.value).casefold()

    payload = b"\0" * (
        secret_store._POSIX_PAYLOAD_HEADER.size + secret_store._POSIX_XCHACHA_TAG_BYTES
    )
    opaque = secret_store._encode_envelope(secret_store._PROVIDER_POSIX_OWNER_PRIVATE, payload)
    with pytest.raises(SecretStoreError) as unprotect_error:
        provider.unprotect("runner.hmac-key", opaque)
    assert str(unprotect_error.value) == "Protected secret is invalid or cannot be opened."
    assert "nacl" not in str(unprotect_error.value).casefold()


def test_darwin_mount_policy_rejects_ownership_disabled_flag() -> None:
    secret_store._validate_darwin_mount_flags(0)
    with pytest.raises(OSError, match="ignores ownership"):
        secret_store._validate_darwin_mount_flags(0x00200000)
    with pytest.raises(OSError, match="ignores ownership"):
        secret_store._validate_darwin_mount_flags(0x80200001)


@pytest.mark.parametrize(
    ("api", "expected_message", "expected_free_calls"),
    [
        (
            _DarwinSecurityApiStub(acl_pointer=None, acl_errno=errno.ENOENT),
            None,
            0,
        ),
        (_DarwinSecurityApiStub(), None, 1),
        (
            _DarwinSecurityApiStub(acl_pointer=None, acl_errno=errno.EIO),
            "cannot be verified",
            0,
        ),
        (
            _DarwinSecurityApiStub(entry_result=0, entry_errno=0),
            "not owner-private",
            1,
        ),
        (
            _DarwinSecurityApiStub(entry_result=-1, entry_errno=errno.EIO),
            "cannot be parsed",
            1,
        ),
        (
            _DarwinSecurityApiStub(free_result=-1),
            "release failed",
            1,
        ),
    ],
)
def test_darwin_acl_policy_fails_closed_and_frees_returned_acls(
    monkeypatch: pytest.MonkeyPatch,
    api: _DarwinSecurityApiStub,
    expected_message: str | None,
    expected_free_calls: int,
) -> None:
    monkeypatch.setattr(secret_store.sys, "platform", "darwin")
    monkeypatch.setattr(secret_store, "_darwin_security_api", lambda: api)

    if expected_message is None:
        secret_store._validate_darwin_descriptor_security(17)
    else:
        with pytest.raises(OSError, match=expected_message):
            secret_store._validate_darwin_descriptor_security(17)

    assert api.free_calls == expected_free_calls


def test_in_memory_provider_persists_only_random_process_local_handles() -> None:
    provider = InMemorySecretProvider()
    plaintext = b"violet-river-sensitive-material"

    first = provider.protect("runner.client-key", plaintext)
    second = provider.protect("runner.client-key", plaintext)

    assert provider.provider_id == "in-memory-test.v1"
    assert isinstance(provider, SecretProvider)
    assert first != second
    assert plaintext not in first
    assert plaintext not in second
    assert provider.unprotect("runner.client-key", first) == plaintext
    assert provider.unprotect("runner.client-key", second) == plaintext
    assert plaintext.decode() not in repr(provider)

    with pytest.raises(SecretStoreError, match="invalid or cannot be opened"):
        provider.unprotect("runner.server-key", first)

    # A handle is a reference into one provider instance, not reversible data.
    with pytest.raises(SecretStoreError, match="invalid or cannot be opened"):
        InMemorySecretProvider().unprotect("runner.client-key", first)


def test_in_memory_provider_rejects_tampered_or_unsupported_envelopes() -> None:
    provider = InMemorySecretProvider()
    opaque = provider.protect("runner.hmac-key", b"bounded-sensitive-material")

    tampered = bytearray(opaque)
    tampered[-1] ^= 0x01
    with pytest.raises(SecretStoreError, match="invalid or cannot be opened"):
        provider.unprotect("runner.hmac-key", bytes(tampered))

    wrong_version = bytearray(opaque)
    wrong_version[4] += 1
    with pytest.raises(SecretStoreError, match="invalid or cannot be opened"):
        provider.unprotect("runner.hmac-key", bytes(wrong_version))

    wrong_provider = bytearray(opaque)
    wrong_provider[5] = 1
    with pytest.raises(SecretStoreError, match="invalid or cannot be opened"):
        provider.unprotect("runner.hmac-key", bytes(wrong_provider))

    truncated = opaque[:-1]
    with pytest.raises(SecretStoreError, match="invalid or cannot be opened"):
        provider.unprotect("runner.hmac-key", truncated)


def test_secret_provider_validates_purpose_and_size_limits() -> None:
    provider = InMemorySecretProvider()

    with pytest.raises(SecretStoreError, match="purpose is invalid"):
        provider.protect("", b"material")
    with pytest.raises(SecretStoreError, match="purpose is invalid"):
        provider.protect("bad\npurpose", b"material")
    with pytest.raises(SecretStoreError, match="protection limit"):
        provider.protect("bounded-purpose", b"x" * (1024 * 1024 + 1))
    with pytest.raises(SecretStoreError, match="invalid or cannot be opened"):
        provider.unprotect("bounded-purpose", b"x" * (2 * 1024 * 1024 + 32))


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI is Windows-only")
def test_windows_dpapi_is_current_user_purpose_bound_and_randomized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Loading known DLLs is system32-constrained and must not derive a path from
    # an attacker-controlled SYSTEMROOT environment variable.
    monkeypatch.setenv("SYSTEMROOT", r"C:\attacker-controlled")
    provider = WindowsDPAPISecretProvider()
    plaintext = b"ember-lake-sensitive-material"

    first = provider.protect("runner.client-key", plaintext)
    second = provider.protect("runner.client-key", plaintext)

    assert provider.provider_id == "windows-dpapi-current-user.v1"
    assert isinstance(provider, SecretProvider)
    assert first != second
    assert plaintext not in first
    assert plaintext not in second
    assert provider.unprotect("runner.client-key", first) == plaintext
    assert isinstance(default_secret_provider(), WindowsDPAPISecretProvider)

    with pytest.raises(SecretStoreError) as wrong_purpose:
        provider.unprotect("runner.server-key", first)
    assert str(wrong_purpose.value) == "Protected secret is invalid or cannot be opened."
    assert plaintext.decode() not in str(wrong_purpose.value)

    tampered = bytearray(first)
    tampered[-1] ^= 0x01
    with pytest.raises(SecretStoreError) as corrupt:
        provider.unprotect("runner.client-key", bytes(tampered))
    assert str(corrupt.value) == "Protected secret is invalid or cannot be opened."
    assert plaintext.decode() not in str(corrupt.value)


@_POSIX_ONLY
def test_posix_provider_is_persistent_purpose_bound_and_randomized(tmp_path: Path) -> None:
    key_path = _posix_key_path(tmp_path)
    first_provider = PosixOwnerPrivateSecretProvider(key_path)
    plaintext = b"cedar-ridge-sensitive-material"

    first = first_provider.protect("runner.client-key", plaintext)
    second = first_provider.protect("runner.client-key", plaintext)

    assert first_provider.provider_id == "posix-owner-private-xchacha20poly1305.v1"
    assert isinstance(first_provider, SecretProvider)
    assert first != second
    assert plaintext not in first
    assert plaintext not in second
    assert plaintext not in key_path.read_bytes()
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    assert key_path.stat().st_nlink == 1

    restarted = PosixOwnerPrivateSecretProvider(key_path)
    assert restarted.unprotect("runner.client-key", first) == plaintext
    assert restarted.unprotect("runner.client-key", second) == plaintext

    with pytest.raises(SecretStoreError) as wrong_purpose:
        restarted.unprotect("runner.server-key", first)
    assert str(wrong_purpose.value) == "Protected secret is invalid or cannot be opened."

    tampered = bytearray(first)
    tampered[-1] ^= 0x01
    with pytest.raises(SecretStoreError) as corrupt:
        restarted.unprotect("runner.client-key", bytes(tampered))
    assert str(corrupt.value) == "Protected secret is invalid or cannot be opened."
    assert plaintext.decode() not in str(corrupt.value)


@_DARWIN_ONLY
def test_darwin_descriptor_security_abi_and_live_happy_path(tmp_path: Path) -> None:
    assert ctypes.sizeof(secret_store._DarwinStatFs) == 2168
    assert ctypes.alignment(secret_store._DarwinStatFs) == 8
    assert secret_store._DarwinStatFs.f_flags.offset == 64
    assert dict(secret_store._DarwinStatFs._fields_)["f_flags"] is ctypes.c_uint32

    key_path = _posix_key_path(tmp_path, "darwin-live-key.v1")
    provider = PosixOwnerPrivateSecretProvider(key_path)
    opaque = provider.protect("runner.hmac-key", b"material")
    assert provider.unprotect("runner.hmac-key", opaque) == b"material"

    lock_path = key_path.with_name(f".{key_path.name}.lock")
    for path, directory in (
        (key_path.parent, True),
        (key_path, False),
        (lock_path, False),
    ):
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if directory:
            flags |= getattr(os, "O_DIRECTORY", 0)
        descriptor = os.open(path, flags)
        try:
            secret_store._validate_darwin_descriptor_security(descriptor)
        finally:
            os.close(descriptor)


@_DARWIN_ONLY
@pytest.mark.parametrize("secured_path", ["root", "key", "lock"])
def test_darwin_provider_rejects_real_extended_acl_without_mode_change(
    tmp_path: Path,
    secured_path: str,
) -> None:
    key_path = _posix_key_path(tmp_path, f"darwin-acl-{secured_path}.v1")
    provider = PosixOwnerPrivateSecretProvider(key_path)
    opaque = provider.protect("runner.hmac-key", b"material")
    lock_path = key_path.with_name(f".{key_path.name}.lock")
    target, expected_mode, acl_entry = {
        "root": (key_path.parent, 0o700, "everyone allow list"),
        "key": (key_path, 0o600, "everyone allow read"),
        "lock": (lock_path, 0o600, "everyone allow read"),
    }[secured_path]

    added = subprocess.run(
        ["/bin/chmod", "+a", acl_entry, os.fspath(target)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert added.returncode == 0, added.stderr
    try:
        assert stat.S_IMODE(target.stat().st_mode) == expected_mode
        with pytest.raises(SecretStoreError) as refused:
            PosixOwnerPrivateSecretProvider(key_path).unprotect("runner.hmac-key", opaque)
        assert str(refused.value) == "Protected secret is invalid or cannot be opened."
    finally:
        subprocess.run(
            ["/bin/chmod", "-N", os.fspath(target)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )


@_POSIX_ONLY
def test_posix_unprotect_never_creates_a_missing_key(tmp_path: Path) -> None:
    source_key = _posix_key_path(tmp_path, "source-key.v1")
    opaque = PosixOwnerPrivateSecretProvider(source_key).protect("runner.hmac-key", b"material")
    missing_key = _posix_key_path(tmp_path, "missing-key.v1")

    with pytest.raises(SecretStoreError, match="invalid or cannot be opened"):
        PosixOwnerPrivateSecretProvider(missing_key).unprotect("runner.hmac-key", opaque)

    assert not missing_key.exists()
    assert list(missing_key.parent.iterdir()) == []


@_POSIX_ONLY
def test_posix_provider_rejects_unsafe_key_storage(tmp_path: Path) -> None:
    key_path = _posix_key_path(tmp_path, "unsafe-key.v1")
    provider = PosixOwnerPrivateSecretProvider(key_path)
    opaque = provider.protect("runner.hmac-key", b"material")

    key_path.chmod(0o640)
    with pytest.raises(SecretStoreError, match="invalid or cannot be opened"):
        provider.unprotect("runner.hmac-key", opaque)
    key_path.chmod(0o600)

    hardlink = key_path.with_name("hardlinked-key.v1")
    os.link(key_path, hardlink)
    with pytest.raises(SecretStoreError, match="invalid or cannot be opened"):
        provider.unprotect("runner.hmac-key", opaque)
    hardlink.unlink()

    symlink = key_path.with_name("symlinked-key.v1")
    try:
        symlink.symlink_to(key_path)
    except OSError:
        pytest.skip("File symlinks are unavailable on this host")
    with pytest.raises(SecretStoreError, match="invalid or cannot be opened"):
        PosixOwnerPrivateSecretProvider(symlink).unprotect("runner.hmac-key", opaque)

    permissive_root = tmp_path / "permissive"
    permissive_root.mkdir(mode=0o755)
    permissive_root.chmod(0o755)
    refused_key = permissive_root / "master-key.v1"
    with pytest.raises(SecretStoreError, match="protection failed"):
        PosixOwnerPrivateSecretProvider(refused_key).protect("runner.hmac-key", b"material")
    assert not refused_key.exists()


@_POSIX_ONLY
def test_posix_provider_rejects_parent_traversal_and_symlinked_ancestor(
    tmp_path: Path,
) -> None:
    with pytest.raises(SecretStoreError, match="unavailable"):
        PosixOwnerPrivateSecretProvider(tmp_path / "safe" / ".." / "escaped" / "master-key.v1")

    actual_parent = tmp_path / "actual-parent"
    key_root = actual_parent / "key-root"
    key_root.mkdir(parents=True, mode=0o700)
    key_root.chmod(0o700)
    linked_parent = tmp_path / "linked-parent"
    try:
        linked_parent.symlink_to(actual_parent, target_is_directory=True)
    except OSError:
        pytest.skip("Directory symlinks are unavailable on this host")
    key_path = linked_parent / "key-root" / "master-key.v1"

    with pytest.raises(SecretStoreError, match="protection failed"):
        PosixOwnerPrivateSecretProvider(key_path).protect("runner.hmac-key", b"material")

    assert not (key_root / "master-key.v1").exists()


@_POSIX_ONLY
def test_posix_provider_closes_new_lock_descriptor_when_permission_fix_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_path = _posix_key_path(tmp_path, "lock-fchmod-key.v1")
    failed_descriptors: list[int] = []

    def fail_permission_fix(descriptor: int, _mode: int) -> None:
        failed_descriptors.append(descriptor)
        raise OSError("injected lock permission failure")

    monkeypatch.setattr(secret_store.os, "fchmod", fail_permission_fix)
    with pytest.raises(SecretStoreError, match="protection failed"):
        PosixOwnerPrivateSecretProvider(key_path).protect("runner.hmac-key", b"material")

    assert len(failed_descriptors) == 1
    with pytest.raises(OSError) as closed:
        os.fstat(failed_descriptors[0])
    assert closed.value.errno == errno.EBADF


@_POSIX_ONLY
def test_posix_first_use_is_serialized_across_processes(tmp_path: Path) -> None:
    key_path = _posix_key_path(tmp_path, "concurrent-key.v1")
    context = multiprocessing.get_context("spawn")
    ready_queue = context.Queue()
    result_queue = context.Queue()
    start_event = context.Event()
    processes = [
        context.Process(
            target=_posix_process_protect,
            args=(str(key_path), index, ready_queue, start_event, result_queue),
        )
        for index in range(6)
    ]

    try:
        for process in processes:
            process.start()
        assert sorted(ready_queue.get(timeout=_PROCESS_TIMEOUT_SECONDS) for _ in processes) == list(
            range(len(processes))
        )
        start_event.set()
        protected = [result_queue.get(timeout=_PROCESS_TIMEOUT_SECONDS) for _ in processes]
        for process in processes:
            process.join(timeout=_PROCESS_TIMEOUT_SECONDS)
            assert process.exitcode == 0
    finally:
        start_event.set()
        for process in processes:
            if process.is_alive():
                process.terminate()
            process.join(timeout=5)
        ready_queue.close()
        result_queue.close()

    restarted = PosixOwnerPrivateSecretProvider(key_path)
    for index, purpose, opaque, error in sorted(protected):
        assert not error
        assert restarted.unprotect(purpose, opaque) == f"material-{index}".encode()
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    assert not list(key_path.parent.glob("*.tmp"))


@_POSIX_ONLY
def test_posix_provider_recovers_exact_interrupted_publication(tmp_path: Path) -> None:
    key_path = _posix_key_path(tmp_path, "recover-key.v1")
    opaque = PosixOwnerPrivateSecretProvider(key_path).protect("runner.hmac-key", b"material")
    interrupted = key_path.with_name(f".{key_path.name}.{'a' * 32}.tmp")
    os.link(key_path, interrupted)

    assert key_path.stat().st_nlink == 2
    assert (
        PosixOwnerPrivateSecretProvider(key_path).unprotect("runner.hmac-key", opaque)
        == b"material"
    )
    assert key_path.stat().st_nlink == 1
    assert not interrupted.exists()


@_POSIX_ONLY
@pytest.mark.parametrize("final_exists", [False, True])
def test_posix_provider_removes_stale_reserved_temporary_key(
    tmp_path: Path,
    final_exists: bool,
) -> None:
    source_key = _posix_key_path(tmp_path, "stale-source-key.v1")
    PosixOwnerPrivateSecretProvider(source_key).protect("runner.hmac-key", b"source")
    key_path = _posix_key_path(tmp_path, "stale-target-key.v1")
    provider = PosixOwnerPrivateSecretProvider(key_path)
    opaque = provider.protect("runner.hmac-key", b"target") if final_exists else None
    stale = key_path.with_name(f".{key_path.name}.{'b' * 32}.tmp")
    stale.write_bytes(source_key.read_bytes())
    stale.chmod(0o600)

    if opaque is None:
        opaque = provider.protect("runner.hmac-key", b"target")
    else:
        assert provider.unprotect("runner.hmac-key", opaque) == b"target"

    assert not stale.exists()
    assert provider.unprotect("runner.hmac-key", opaque) == b"target"


@_POSIX_ONLY
@pytest.mark.parametrize("stale_size", [0, 7])
def test_posix_provider_recovers_stale_partial_key_write(
    tmp_path: Path,
    stale_size: int,
) -> None:
    source_key = _posix_key_path(tmp_path, f"partial-source-{stale_size}.v1")
    PosixOwnerPrivateSecretProvider(source_key).protect("runner.hmac-key", b"source")
    key_path = _posix_key_path(tmp_path, f"partial-target-{stale_size}.v1")
    stale = key_path.with_name(f".{key_path.name}.{'c' * 32}.tmp")
    stale.write_bytes(source_key.read_bytes()[:stale_size])
    stale.chmod(0o600)

    provider = PosixOwnerPrivateSecretProvider(key_path)
    opaque = provider.protect("runner.hmac-key", b"target")

    assert not stale.exists()
    assert provider.unprotect("runner.hmac-key", opaque) == b"target"


@_POSIX_ONLY
@pytest.mark.parametrize("poisoned_path", ["key", "lock"])
def test_posix_provider_rejects_special_files_without_blocking(
    tmp_path: Path,
    poisoned_path: str,
) -> None:
    key_path = _posix_key_path(tmp_path, f"{poisoned_path}-fifo-key.v1")
    path = key_path if poisoned_path == "key" else key_path.with_name(f".{key_path.name}.lock")
    os.mkfifo(path, mode=0o600)
    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue()
    process = context.Process(
        target=_posix_process_attempt_protect,
        args=(str(key_path), result_queue),
    )

    try:
        process.start()
        process.join(timeout=5)
        assert not process.is_alive(), f"provider blocked while opening {poisoned_path} FIFO"
        assert process.exitcode == 0
        assert result_queue.get(timeout=2) == ("SecretStoreError", "Secret protection failed.")
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
        result_queue.close()


@_POSIX_ONLY
def test_posix_provider_bounds_initialization_lock_contention(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_path = _posix_key_path(tmp_path, "contended-key.v1")
    provider = PosixOwnerPrivateSecretProvider(key_path)
    provider.protect("runner.hmac-key", b"initial")
    lock_path = key_path.with_name(f".{key_path.name}.lock")
    context = multiprocessing.get_context("spawn")
    release_event = context.Event()
    status_queue = context.Queue()
    process = context.Process(
        target=_posix_process_hold_lock,
        args=(str(lock_path), release_event, status_queue),
    )
    monkeypatch.setattr(secret_store, "_POSIX_LOCK_TIMEOUT_SECONDS", 0.15)
    try:
        process.start()
        assert status_queue.get(timeout=5) == ("ready", "")
        started = time.monotonic()
        with pytest.raises(SecretStoreError) as refused:
            provider.protect("runner.hmac-key", b"blocked")
        elapsed = time.monotonic() - started
    finally:
        release_event.set()
        process.join(timeout=5)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)

    assert str(refused.value) == "Secret protection failed."
    assert elapsed < 1.0
    assert process.exitcode == 0
    assert status_queue.get(timeout=2) == ("done", "")
    status_queue.close()
    assert provider.protect("runner.hmac-key", b"retry")


@_POSIX_ONLY
def test_default_provider_selects_persistent_posix_protection() -> None:
    assert isinstance(default_secret_provider(), PosixOwnerPrivateSecretProvider)
