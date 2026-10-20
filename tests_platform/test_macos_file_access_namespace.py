"""Synthetic namespace ownership tests; no privileged setup or filesystem calls."""

import hashlib
import json
import stat
import threading
from types import SimpleNamespace

import pytest

from bluefire import macos_file_access_namespace as namespace
from bluefire.macos_file_access_contract import MacOSFileAccessContractError
from tests_platform.test_macos_file_access_contract import binding


@pytest.fixture
def owned(monkeypatch):
    # Patch only the product's module view, not pytest's shared OS/time modules.
    monkeypatch.setattr(namespace, "os", SimpleNamespace(**vars(namespace.os)))
    monkeypatch.setattr(namespace, "time", SimpleNamespace(**vars(namespace.time)))
    document = binding()
    value = object.__new__(namespace.SealedMacOSNamespace)
    value._creator = 42
    value._state = "sealed"
    value._lock = threading.RLock()
    value._active = False
    value._handle_cleanup_unknown = False
    value._issued_ms = document["issued_at_ms"]
    value._expires_ms = document["expires_at_ms"]
    value._deadline_ns = document["original_deadline_ns"]
    value._owner, value._reader = document["owner"], document["reader"]
    value._group = 501
    value._generation, value._enrollment = document["generation"], document["enrollment_id"]
    value._anchor_fd, value._directory_fd, value._leaf_fd = 3, 4, 5
    value._descriptors = [3, 4, 5]
    value._directory_identity, value._leaf_identity = (1, 10), (1, 11)
    value._payload = namespace._records()
    value._resource = {
        **document["resource"],
        "size_bytes": len(value._payload),
        "sha256": "sha256:" + hashlib.sha256(value._payload).hexdigest(),
    }
    anchor = SimpleNamespace(st_dev=1, st_ino=9, st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o700)
    directory = SimpleNamespace(
        st_dev=1, st_ino=10, st_uid=0, st_gid=501, st_mode=stat.S_IFDIR | 0o550
    )
    leaf = SimpleNamespace(
        st_dev=1,
        st_ino=11,
        st_uid=501,
        st_gid=501,
        st_mode=stat.S_IFREG | 0o640,
        st_nlink=1,
        st_size=len(value._payload),
    )
    facts = {3: anchor, 4: directory, 5: leaf}
    value._chain = [(3, value._generation, 4, (1, 10))]
    monkeypatch.setattr(namespace, "_root", lambda: None)
    monkeypatch.setattr(namespace, "_security", lambda _fd: None)
    monkeypatch.setattr(namespace, "darwin_clock_ns", lambda: 2000)
    monkeypatch.setattr(namespace.time, "time_ns", lambda: 1000_000_000)
    monkeypatch.setattr(namespace.os, "getpid", lambda: 42)
    monkeypatch.setattr(namespace.os, "fstat", lambda fd: facts[fd])

    def visible(name, *, dir_fd, follow_symlinks):
        assert follow_symlinks is False
        assert (dir_fd, name) in {(3, value._generation), (4, namespace.LEAF)}
        return directory if dir_fd == 3 else leaf

    monkeypatch.setattr(namespace.os, "stat", visible)
    return value, facts


def test_generated_payload_has_only_eight_fixed_records():
    rows = [json.loads(line) for line in namespace._records().splitlines()]
    assert len(rows) == 8
    assert [row["record_id"] for row in rows] == list(range(1, 9))
    assert all(row["category"] == "generated-validation" for row in rows)
    with pytest.raises(TypeError):
        namespace.SealedMacOSNamespace()


def test_reader_and_fresh_owner_never_receive_held_leaf(owned):
    value, _facts = owned
    assert value.descriptor("reader") == value.descriptor("owner") == 4
    assert value.descriptor("control") == 5
    with pytest.raises(MacOSFileAccessContractError):
        value.descriptor("arbitrary")


def test_binding_is_inactive_original_document(owned):
    value, _facts = owned
    result = value.binding(custody_digest="sha256:" + "3" * 64, revision=1)
    assert result["mode"] == "0640"
    assert result["resource"]["size_bytes"] == len(value._payload)
    assert result["original_deadline_ns"] == value._deadline_ns
    assert "authority" not in result


@pytest.mark.parametrize(
    "field,new",
    [
        ("st_ino", 99),
        ("st_uid", 502),
        ("st_gid", 999),
        ("st_nlink", 2),
        ("st_size", 999),
        ("st_mode", stat.S_IFREG | 0o666),
    ],
)
def test_leaf_drift_refused(owned, field, new):
    value, facts = owned
    setattr(facts[5], field, new)
    with pytest.raises(MacOSFileAccessContractError):
        value.assert_current()


@pytest.mark.parametrize("descriptor", [3, 4])
def test_unsealed_parent_refused(owned, descriptor):
    value, facts = owned
    facts[descriptor].st_mode |= 0o020
    with pytest.raises(MacOSFileAccessContractError):
        value.assert_current()


def test_generation_replacement_is_not_adopted(owned, monkeypatch):
    value, _facts = owned
    monkeypatch.setattr(
        namespace.os, "stat", lambda *_args, **_kwargs: SimpleNamespace(st_dev=1, st_ino=99)
    )
    with pytest.raises(MacOSFileAccessContractError):
        value.assert_current()


@pytest.mark.parametrize("kind", ["creator", "wall", "monotonic", "unknown"])
def test_lost_or_expired_custody_cannot_be_reloaded(owned, monkeypatch, kind):
    value, _facts = owned
    if kind == "creator":
        monkeypatch.setattr(namespace.os, "getpid", lambda: 43)
    elif kind == "wall":
        monkeypatch.setattr(namespace.time, "time_ns", lambda: value._expires_ms * 1_000_000)
    elif kind == "monotonic":
        monkeypatch.setattr(namespace, "darwin_clock_ns", lambda: value._deadline_ns)
    else:
        value._state = "unknown"
    with pytest.raises(MacOSFileAccessContractError):
        value.assert_current()


def test_operation_holds_namespace_and_rejects_nested_use(owned):
    value, _facts = owned
    with value.operation():
        assert value._active
        with pytest.raises(MacOSFileAccessContractError):
            with value.operation():
                raise AssertionError("nested operation admitted")
        with pytest.raises(MacOSFileAccessContractError):
            value.close_handles()
    assert not value._active and value._state == "sealed"


def test_unknown_operation_stays_readonly(owned):
    value, _facts = owned
    with pytest.raises(OSError):
        with value.operation():
            raise OSError("fake interrupted operation")
    assert value._state == "unknown" and not value._active
    with pytest.raises(MacOSFileAccessContractError):
        value.descriptor("control")


def test_close_failure_is_sticky_not_retried(owned, monkeypatch):
    value, _facts = owned
    closed = []

    def close(fd):
        closed.append(fd)
        if fd == 5:
            raise OSError("ambiguous close")

    monkeypatch.setattr(namespace.os, "close", close)
    assert value.close_handles() is False
    assert value.close_handles() is False
    assert closed == [5, 4, 3] and value._state == "unknown"


@pytest.mark.parametrize("failure", [KeyboardInterrupt, RuntimeError])
def test_interrupted_close_stays_unknown_after_remaining_handles_retire(
    owned, monkeypatch, failure
):
    value, _facts = owned
    closed = []

    def close(fd):
        closed.append(fd)
        if fd == 5:
            raise failure("fake close invalidated its handle then failed")

    monkeypatch.setattr(namespace.os, "close", close)
    with pytest.raises(failure):
        value.close_handles()
    assert closed == [5] and value._state == "unknown"
    assert value._handle_cleanup_unknown and value._descriptors == [3, 4]
    assert value.close_handles() is False
    assert value.close_handles() is False
    assert closed == [5, 4, 3] and value._state == "unknown"


def test_partial_creation_retained_before_any_effect(owned, monkeypatch):
    _value, _facts = owned
    retained = []

    def fail(value):
        assert retained == [value]
        assert value._state == "creating"
        with pytest.raises(MacOSFileAccessContractError):
            value.close_handles()
        assert value._state == "creating" and not value._descriptors
        raise OSError("fake setup failure")

    monkeypatch.setattr(namespace.SealedMacOSNamespace, "_create", fail)
    with pytest.raises(OSError):
        namespace.SealedMacOSNamespace.create(
            owner=binding()["owner"], reader=binding()["reader"], retained=retained
        )
    assert len(retained) == 1 and retained[0]._state == "unknown"
    assert retained[0].close_handles() is True
    assert retained[0]._state == "unknown"
