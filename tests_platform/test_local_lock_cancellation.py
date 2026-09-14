"""Portable lock-wait/ownership tests; no OS lock, file, or process effects."""

from __future__ import annotations

import errno
import os
import sys
import threading
from types import SimpleNamespace

import pytest

import bluefire.local_lock as locks


class LockHarness:
    def __init__(self, monkeypatch, tmp_path, platform="linux"):
        self.path = tmp_path / "product.sqlite"
        self.identity = (17, 23)
        self.state = locks._DatabaseLockState()
        self.closed = []
        self.calls = []
        self.opened = []
        self.verified = []
        self.opened_event = threading.Event()
        self.on_lock = lambda: None
        self.on_validate = lambda: None
        monkeypatch.setattr(locks, "sys", SimpleNamespace(platform=platform))
        monkeypatch.setattr(
            locks,
            "os",
            SimpleNamespace(
                getpid=os.getpid,
                close=self.closed.append,
                lseek=lambda *args: 0,
                SEEK_SET=os.SEEK_SET,
            ),
        )
        monkeypatch.setattr(locks, "_DATABASE_DESCRIPTORS", {})
        monkeypatch.setattr(locks, "_canonical_database_path", lambda path: self.path)
        monkeypatch.setattr(locks, "_state_for", lambda identity: self.state)
        monkeypatch.setattr(locks, "_open_database_descriptor", self.open_database)
        monkeypatch.setattr(
            locks, "_open_registered_posix_identity_lock_descriptor", self.open_lock
        )
        monkeypatch.setattr(locks, "_validate_locked_database", self.validate)
        monkeypatch.setitem(
            sys.modules,
            "fcntl",
            SimpleNamespace(
                LOCK_EX=2,
                LOCK_NB=4,
                LOCK_UN=8,
                flock=self.flock,
            ),
        )
        monkeypatch.setitem(
            sys.modules,
            "msvcrt",
            SimpleNamespace(
                LK_NBLCK=2,
                LK_UNLCK=8,
                locking=self.locking,
            ),
        )

    def register(self):
        descriptor = 100 + len(self.opened)
        registration = locks._DatabaseDescriptorRegistration(os.getpid())
        locks._DATABASE_DESCRIPTORS[descriptor] = registration
        self.opened.append(descriptor)
        return descriptor, registration

    def open_database(self, path, *, expected):
        assert path == self.path and expected == self.identity
        descriptor, registration = self.register()
        self.opened_event.set()
        return descriptor, self.identity, registration

    def open_lock(self, identity):
        assert identity == self.identity
        return self.register()

    def validate(self, path, descriptor, expected):
        assert path == self.path and expected == self.identity
        assert descriptor in locks._DATABASE_DESCRIPTORS
        self.verified.append(descriptor)
        self.on_validate()

    def flock(self, descriptor, operation):
        self.calls.append((descriptor, operation))
        if operation != 8:
            self.on_lock()

    def locking(self, descriptor, operation, length):
        assert length == 1
        self.flock(descriptor, operation)

    def lease(self, cancel_event=None, *, deadline=None):
        return locks.owner_private_database_lock(
            self.path,
            expected=self.identity,
            cancel_event=cancel_event,
            deadline=deadline,
        )

    def assert_released(self):
        assert sorted(self.closed) == self.opened
        assert len(set(self.closed)) == len(self.closed)
        assert locks._DATABASE_DESCRIPTORS == {}
        assert self.state.depth == 0
        assert self.state.owner_pid is None and self.state.owner_thread is None
        assert self.state.descriptor is None
        assert self.state.guard.acquire(blocking=False)
        self.state.guard.release()


def test_cancellation_interrupts_contended_thread_guard_and_closes_registered_descriptor(
    monkeypatch,
    tmp_path,
):
    harness = LockHarness(monkeypatch, tmp_path)
    cancelled = threading.Event()
    results = []

    def wait_for_lock():
        try:
            with harness.lease(cancelled):
                results.append("entered")
        except Exception as exc:
            results.append(exc)

    harness.state.guard.acquire()
    thread = threading.Thread(target=wait_for_lock)
    try:
        thread.start()
        assert harness.opened_event.wait(2)
        cancelled.set()
        thread.join(2)
        assert not thread.is_alive()
        assert len(results) == 1 and isinstance(results[0], locks.LocalLockError)
        assert "cancelled" in str(results[0])
        assert harness.calls == [] and harness.verified == []
        assert harness.closed == harness.opened == [100]
    finally:
        cancelled.set()
        harness.state.guard.release()
        thread.join(2)
    harness.assert_released()


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_os_contention_uses_nonblocking_poll_and_cancellation_closes_exact_ownership(
    monkeypatch,
    tmp_path,
    platform,
):
    harness = LockHarness(monkeypatch, tmp_path, platform)
    cancelled = threading.Event()

    def blocked():
        cancelled.set()
        raise OSError(errno.EAGAIN, "contended")

    harness.on_lock = blocked
    with pytest.raises(locks.LocalLockError, match="cancelled"):
        with harness.lease(cancelled):
            pytest.fail("cancelled waiter entered protected operation")
    assert harness.calls == [(harness.opened[-1], 2 if platform == "win32" else 6)]
    assert harness.verified == []
    harness.assert_released()


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_cancellation_racing_os_acquisition_unlocks_before_any_protected_operation(
    monkeypatch,
    tmp_path,
    platform,
):
    harness = LockHarness(monkeypatch, tmp_path, platform)
    cancelled = threading.Event()
    harness.on_lock = cancelled.set
    with pytest.raises(locks.LocalLockError, match="cancelled"):
        with harness.lease(cancelled):
            pytest.fail("late lock acquisition became permission to continue")
    assert harness.calls[-1] == (harness.opened[-1], 8)
    assert harness.verified == []
    harness.assert_released()


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_noncontention_os_error_refuses_once_and_closes_without_false_unlock(
    monkeypatch,
    tmp_path,
    platform,
):
    harness = LockHarness(monkeypatch, tmp_path, platform)

    def refused():
        raise OSError(errno.EPERM, "not contention")

    harness.on_lock = refused
    with pytest.raises(locks.LocalLockError, match="unavailable or unsafe"):
        with harness.lease(threading.Event()):
            pytest.fail("OS refusal entered protected operation")
    assert len(harness.calls) == 1
    harness.assert_released()


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_default_lease_keeps_lock_mode_reentrancy_and_identity_validation(
    monkeypatch,
    tmp_path,
    platform,
):
    harness = LockHarness(monkeypatch, tmp_path, platform)
    with harness.lease():
        assert harness.state.depth == 1
        outer_descriptor = harness.state.descriptor
        with harness.lease():
            assert harness.state.depth == 2
            assert harness.state.descriptor == outer_descriptor
        assert harness.state.depth == 1
        assert harness.state.descriptor == outer_descriptor
    assert harness.calls == [(outer_descriptor, 2), (outer_descriptor, 8)]
    assert harness.verified == [outer_descriptor, outer_descriptor]
    harness.assert_released()


def test_reentrant_cancellation_preserves_outer_lease_and_restores_depth(monkeypatch, tmp_path):
    harness = LockHarness(monkeypatch, tmp_path)
    cancelled = threading.Event()
    with harness.lease():
        outer_descriptor = harness.state.descriptor
        harness.on_validate = cancelled.set
        with pytest.raises(locks.LocalLockError, match="cancelled"):
            with harness.lease(cancelled):
                pytest.fail("cancelled nested lease entered protected operation")
        assert harness.state.depth == 1 and harness.state.descriptor == outer_descriptor
        assert harness.calls == [(outer_descriptor, 2)]
    harness.assert_released()


def test_cancel_after_entering_lease_does_not_release_protected_ownership(monkeypatch, tmp_path):
    harness = LockHarness(monkeypatch, tmp_path)
    cancelled = threading.Event()
    with harness.lease(cancelled):
        cancelled.set()
        assert harness.state.depth == 1 and harness.state.descriptor in locks._DATABASE_DESCRIPTORS
        assert harness.calls[-1][1] == 6
    harness.assert_released()


def test_already_cancelled_wait_does_not_open_any_descriptor(monkeypatch, tmp_path):
    harness = LockHarness(monkeypatch, tmp_path)
    cancelled = threading.Event()
    cancelled.set()
    with pytest.raises(locks.LocalLockError, match="cancelled"):
        with harness.lease(cancelled):
            pytest.fail("cancelled waiter entered protected operation")
    assert harness.opened == []
    harness.assert_released()


def test_identity_refusal_after_acquisition_still_unlocks_and_closes(monkeypatch, tmp_path):
    harness = LockHarness(monkeypatch, tmp_path)

    def changed_identity():
        raise locks.LocalLockError("Pinned local database identity changed.")

    harness.on_validate = changed_identity
    with pytest.raises(locks.LocalLockError, match="identity changed"):
        with harness.lease(threading.Event()):
            pytest.fail("changed identity entered protected operation")
    assert harness.calls[-1][1] == 8
    harness.assert_released()


@pytest.mark.parametrize("platform", ["linux", "win32"])
@pytest.mark.parametrize("acquired", [False, True])
def test_deadline_bounds_os_contention_and_rejects_late_acquisition(
    monkeypatch, tmp_path, platform, acquired
):
    harness = LockHarness(monkeypatch, tmp_path, platform)
    now = [0.0]
    monkeypatch.setattr(locks.time, "monotonic", lambda: now[0])

    def expired():
        now[0] = 2.0
        if not acquired:
            raise OSError(errno.EAGAIN, "other process owns lock")

    harness.on_lock = expired
    with pytest.raises(locks.LocalLockError, match="admission expired"):
        with harness.lease(deadline=1.0):
            pytest.fail("expired admission entered the protected operation")
    assert harness.calls[0][1] == (2 if platform == "win32" else 6)
    assert [call[1] for call in harness.calls[1:]] == ([8] if acquired else [])
    assert harness.verified == []
    harness.assert_released()


def test_expired_nested_admission_preserves_the_current_outer_owner(monkeypatch, tmp_path):
    harness = LockHarness(monkeypatch, tmp_path)
    now = [0.0]
    monkeypatch.setattr(locks.time, "monotonic", lambda: now[0])
    with harness.lease():
        descriptor = harness.state.descriptor
        harness.on_validate = lambda: now.__setitem__(0, 2.0)
        with pytest.raises(locks.LocalLockError, match="admission expired"):
            with harness.lease(deadline=1.0):
                pytest.fail("expired nested admission entered")
        assert harness.state.depth == 1 and harness.state.descriptor == descriptor
        assert harness.calls == [(descriptor, 2)]
    harness.assert_released()
