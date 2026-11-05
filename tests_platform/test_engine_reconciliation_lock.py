from __future__ import annotations

import os
import select
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import bluefire.engine_reconciliation_lock as lock_module
from bluefire.engine_reconciliation_lock import (
    EngineReconciliationLock,
    EngineReconciliationLockError,
)
from bluefire.local_lock import (
    owner_private_database_lock,
    prepare_owner_private_database_file,
)


def _database(tmp_path: Path, name: str = "product.sqlite3") -> tuple[Path, tuple[int, int]]:
    return prepare_owner_private_database_file(tmp_path / name)


def _child_code(body: str) -> str:
    return f"""
import sys
import time
from bluefire.engine_reconciliation_lock import EngineReconciliationLock

path = sys.argv[1]
identity = (int(sys.argv[2]), int(sys.argv[3]))
lock = EngineReconciliationLock(path, expected=identity)
{body}
"""


def _child_command(
    path: Path,
    identity: tuple[int, int],
    body: str,
) -> list[str]:
    return [
        sys.executable,
        "-c",
        _child_code(body),
        os.fspath(path),
        str(identity[0]),
        str(identity[1]),
    ]


def test_session_is_reentrant_and_releases_after_owner_exception(tmp_path: Path) -> None:
    path, identity = _database(tmp_path)
    lock = EngineReconciliationLock(path, expected=identity)

    with lock.session():
        with lock.session():
            assert lock.database_identity == identity

    with pytest.raises(RuntimeError, match="effect failed"):
        with lock.session():
            raise RuntimeError("effect failed")

    with lock.session():
        pass


@pytest.mark.parametrize(
    "deadline",
    [float("nan"), float("inf"), 10**10000, True, "later"],
    ids=["nan", "infinity", "huge-integer", "boolean", "text"],
)
def test_session_rejects_invalid_deadlines(tmp_path: Path, deadline: object) -> None:
    path, identity = _database(tmp_path)
    lock = EngineReconciliationLock(path, expected=identity)

    with pytest.raises(EngineReconciliationLockError, match="deadline is invalid"):
        with lock.session(deadline=deadline):  # type: ignore[arg-type]
            pass


def test_cancelled_wait_never_enters_the_session(tmp_path: Path) -> None:
    path, identity = _database(tmp_path)
    first = EngineReconciliationLock(path, expected=identity)
    second = EngineReconciliationLock(path, expected=identity)
    attempted = threading.Event()
    cancel = threading.Event()
    entered = threading.Event()
    errors: list[BaseException] = []

    def contender() -> None:
        attempted.set()
        try:
            with second.session(cancel_event=cancel):
                entered.set()
        except BaseException as exc:
            errors.append(exc)

    with first.session():
        thread = threading.Thread(target=contender, daemon=True)
        thread.start()
        assert attempted.wait(5)
        assert not entered.wait(0.15)
        cancel.set()
        thread.join(timeout=5)

    assert not thread.is_alive()
    assert not entered.is_set()
    assert len(errors) == 1
    assert isinstance(errors[0], EngineReconciliationLockError)
    assert "cancelled" in str(errors[0])


def test_expired_wait_never_enters_the_session(tmp_path: Path) -> None:
    path, identity = _database(tmp_path)
    lock = EngineReconciliationLock(path, expected=identity)

    with pytest.raises(EngineReconciliationLockError, match="admission expired"):
        with lock.session(deadline=time.monotonic()):
            pass


def test_two_processes_serialize_on_the_pinned_identity(tmp_path: Path) -> None:
    path, identity = _database(tmp_path)
    lock = EngineReconciliationLock(path, expected=identity)
    process: subprocess.Popen[str] | None = None
    try:
        with lock.session():
            process = subprocess.Popen(  # nosec B603 - fixed interpreter and test script
                _child_command(
                    path,
                    identity,
                    'print("attempt", flush=True)\nwith lock.session():\n    print("entered", flush=True)',
                ),
                cwd=Path(__file__).resolve().parents[1],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            assert process.stdout is not None
            assert process.stdout.readline().strip() == "attempt"
            time.sleep(0.2)
            assert process.poll() is None

        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, stderr
        assert stdout.strip() == "entered"
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def test_process_crash_releases_exact_reconciliation_lock(tmp_path: Path) -> None:
    path, identity = _database(tmp_path)
    process = subprocess.Popen(  # nosec B603 - fixed interpreter and test script
        _child_command(
            path,
            identity,
            'with lock.session():\n    print("entered", flush=True)\n    time.sleep(60)',
        ),
        cwd=Path(__file__).resolve().parents[1],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        assert process.stdout.readline().strip() == "entered"
        process.kill()
        process.wait(timeout=5)
        assert process.returncode is not None

        with EngineReconciliationLock(path, expected=identity).session(
            deadline=time.monotonic() + 5
        ):
            pass
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def test_cross_process_os_contention_honors_absolute_deadline(tmp_path: Path) -> None:
    path, identity = _database(tmp_path)
    process = subprocess.Popen(  # nosec B603 - fixed interpreter and test script
        _child_command(
            path,
            identity,
            'with lock.session():\n    print("entered", flush=True)\n    time.sleep(60)',
        ),
        cwd=Path(__file__).resolve().parents[1],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        assert process.stdout.readline().strip() == "entered"
        with pytest.raises(EngineReconciliationLockError, match="admission expired"):
            with EngineReconciliationLock(path, expected=identity).session(
                deadline=time.monotonic() + 0.2
            ):
                pass
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)

    with EngineReconciliationLock(path, expected=identity).session(deadline=time.monotonic() + 5):
        pass


def test_reconciliation_lock_does_not_compete_with_catalog_lock(tmp_path: Path) -> None:
    path, identity = _database(tmp_path)
    result: subprocess.CompletedProcess[str]

    with owner_private_database_lock(path, expected=identity):
        result = subprocess.run(  # nosec B603 - fixed interpreter and test script
            _child_command(
                path,
                identity,
                'with lock.session(deadline=time.monotonic() + 3):\n    print("entered")',
            ),
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "entered"


def test_replaced_database_path_is_refused(tmp_path: Path) -> None:
    path, identity = _database(tmp_path)
    lock = EngineReconciliationLock(path, expected=identity)
    replacement_path, replacement_identity = _database(tmp_path, "replacement.sqlite3")
    assert replacement_identity != identity
    path.unlink()
    replacement_path.replace(path)

    with pytest.raises(EngineReconciliationLockError, match="unavailable or unsafe"):
        with lock.session():
            pass


def test_symlink_database_path_is_refused(tmp_path: Path) -> None:
    path, identity = _database(tmp_path)
    lock = EngineReconciliationLock(path, expected=identity)
    target, _target_identity = _database(tmp_path, "target.sqlite3")
    path.unlink()
    try:
        path.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable on this platform")

    with pytest.raises(EngineReconciliationLockError, match="unavailable or unsafe"):
        with lock.session():
            pass


@pytest.mark.skipif(os.name == "nt", reason="POSIX uses an identity-lock registry")
def test_posix_identity_lock_symlink_is_refused(tmp_path: Path) -> None:
    path, identity = _database(tmp_path)
    purpose_path = lock_module._purpose_lock_path(identity)
    target = tmp_path / "attacker-lock"
    target.write_bytes(b"")
    try:
        purpose_path.symlink_to(target)
    except FileExistsError:
        purpose_path.unlink()
        purpose_path.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable on this platform")

    with pytest.raises(EngineReconciliationLockError, match="unavailable or unsafe"):
        with EngineReconciliationLock(path, expected=identity).session():
            pass


@pytest.mark.skipif(os.name == "nt", reason="POSIX identity locks expose link counts")
def test_posix_identity_lock_hard_link_is_refused(tmp_path: Path) -> None:
    path, identity = _database(tmp_path)
    lock = EngineReconciliationLock(path, expected=identity)
    with lock.session():
        pass
    purpose_path = lock_module._purpose_lock_path(identity)
    alias = tmp_path / "purpose-lock-alias"
    try:
        os.link(purpose_path, alias)
    except OSError:
        pytest.skip("hard links are unavailable across the test filesystem")
    if purpose_path.stat().st_nlink == 1:
        alias.unlink()
        pytest.skip("filesystem does not expose hard-link counts")

    try:
        with pytest.raises(EngineReconciliationLockError, match="unavailable or unsafe"):
            with lock.session():
                pass
    finally:
        alias.unlink()

    with lock.session():
        pass


@pytest.mark.skipif(
    not callable(getattr(os, "register_at_fork", None)) or not callable(getattr(os, "fork", None)),
    reason="requires direct POSIX fork callbacks",
)
def test_forked_child_cannot_inherit_reentrant_session(tmp_path: Path) -> None:
    path, identity = _database(tmp_path)
    lock = EngineReconciliationLock(path, expected=identity)
    receiver, sender = os.pipe()
    outer = lock.session()
    outer.__enter__()
    fork = os.__dict__["fork"]
    child_pid = fork()
    if child_pid == 0:
        os.close(receiver)
        try:
            os.write(sender, b"A")
            with lock.session():
                os.write(sender, b"E")
        except BaseException:
            os.write(sender, b"X")
            os._exit(1)
        os._exit(0)

    os.close(sender)
    released = False
    try:
        assert os.read(receiver, 1) == b"A"
        readable, _writable, _exceptional = select.select([receiver], [], [], 0.25)
        assert readable == []
        outer.__exit__(None, None, None)
        released = True
        _, status = os.waitpid(child_pid, 0)
        assert os.read(receiver, 1) == b"E"
        assert os.waitstatus_to_exitcode(status) == 0
    finally:
        if not released:
            outer.__exit__(None, None, None)
        try:
            waited_pid, _status = os.waitpid(child_pid, os.__dict__["WNOHANG"])
        except ChildProcessError:
            waited_pid = child_pid
        if waited_pid == 0:
            os.kill(child_pid, 9)
            os.waitpid(child_pid, 0)
        os.close(receiver)


@pytest.mark.skipif(
    not callable(getattr(os, "register_at_fork", None)) or not callable(getattr(os, "fork", None)),
    reason="requires direct POSIX fork callbacks",
)
def test_forked_stale_context_cannot_unlock_reused_child_descriptor(
    tmp_path: Path,
) -> None:
    parent_path, parent_identity = _database(tmp_path, "parent.sqlite3")
    child_path, child_identity = _database(tmp_path, "child.sqlite3")
    parent_lock = EngineReconciliationLock(parent_path, expected=parent_identity)
    child_lock = EngineReconciliationLock(child_path, expected=child_identity)
    child_purpose_path = lock_module._purpose_lock_path(child_identity)
    outer = parent_lock.session()
    outer.__enter__()
    parent_descriptor = lock_module._STATES[parent_identity].descriptor
    assert parent_descriptor is not None
    receiver, sender = os.pipe()
    fork = os.__dict__["fork"]
    child_pid = fork()
    if child_pid == 0:
        os.close(receiver)
        inner = child_lock.session()
        try:
            inner.__enter__()
            child_descriptor = lock_module._STATES[child_identity].descriptor
            assert child_descriptor == parent_descriptor
            outer.__exit__(None, None, None)
            os.fstat(child_descriptor)
            probe_code = """
import fcntl
import os
import sys

descriptor = os.open(sys.argv[1], os.O_RDWR)
blocked = False
try:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        blocked = True
    else:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
finally:
    os.close(descriptor)
raise SystemExit(0 if blocked else 3)
"""
            probe = subprocess.run(  # nosec B603 - fixed interpreter and test script
                [sys.executable, "-c", probe_code, os.fspath(child_purpose_path)],
                cwd=Path(__file__).resolve().parents[1],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            assert probe.returncode == 0, probe.stdout + probe.stderr
        except BaseException:
            os.write(sender, b"X")
            os._exit(1)
        else:
            inner.__exit__(None, None, None)
            os.write(sender, b"R")
            os._exit(0)

    os.close(sender)
    try:
        outer.__exit__(None, None, None)
        _, status = os.waitpid(child_pid, 0)
        assert os.read(receiver, 1) == b"R"
        assert os.waitstatus_to_exitcode(status) == 0
    finally:
        try:
            outer.__exit__(None, None, None)
        except BaseException:
            pass
        try:
            waited_pid, _status = os.waitpid(child_pid, os.__dict__["WNOHANG"])
        except ChildProcessError:
            waited_pid = child_pid
        if waited_pid == 0:
            os.kill(child_pid, 9)
            os.waitpid(child_pid, 0)
        os.close(receiver)


def test_wrong_database_identity_is_refused_at_construction(tmp_path: Path) -> None:
    path, identity = _database(tmp_path)

    with pytest.raises(EngineReconciliationLockError, match="unavailable or unsafe"):
        EngineReconciliationLock(path, expected=(identity[0], identity[1] + 1))


@pytest.mark.parametrize("identity", [(0, 1), (1, 0), (True, 2), (1,), [1, 2]])
def test_invalid_database_identity_is_refused(
    tmp_path: Path,
    identity: object,
) -> None:
    path, _actual = _database(tmp_path)

    with pytest.raises(EngineReconciliationLockError, match="identity is invalid"):
        EngineReconciliationLock(path, expected=identity)  # type: ignore[arg-type]
