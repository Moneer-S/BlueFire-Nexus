"""Fake fixed-path operations only; no Windows APIs, ACL reads or setup effects."""

from __future__ import annotations

import copy
import hashlib
from dataclasses import FrozenInstanceError, replace
from typing import Any

import pytest

from bluefire import windows_file_access_enrollment as enrollment
from bluefire import windows_file_access_enrollment_reader as module
from bluefire.util import canonical_json_bytes
from bluefire.windows_file_access_handles import WindowsFileFacts
from bluefire.windows_session_facts import WindowsPrincipalFacts
from tests_platform.test_windows_file_access_enrollment import NOW_MS, declared_candidate
from tests_platform.test_windows_file_access_enrollment_native import descriptor
from tests_platform.test_windows_file_access_enrollment_setup import declared_anchor


class FakeReader:
    """Synthetic native boundary; does not authenticate production enrollment."""

    def __init__(self, gate: Any) -> None:
        self.gate = gate
        self.raw = canonical_json_bytes(declared_candidate())
        self.owner = WindowsPrincipalFacts(
            4001, 555, "S-1-5-21-101-202-303-1001", 11, 22, 33, 2, False
        )
        self.objects: dict[int, tuple[int, bool, int]] = {}
        self.opens = [0] * 5
        self.visits: dict[int, int] = {}
        self.calls: list[tuple[Any, ...]] = []
        self.position = 0
        self.closed: list[int] = []
        self.fault = ""
        self.clock = [100.0]
        self.wall = [NOW_MS]
        self.principals = 0

    def open(self, index: int, *, data: bool = False) -> int:
        self.calls.append(("open", index, data))
        if self.fault == "open" and index == 3:
            raise OSError("synthetic private location")
        self.opens[index] += 1
        handle = 100 + len(self.objects)
        self.objects[handle] = (index, data, self.opens[index])
        if self.fault == "deadline_open" and index == 2:
            self.clock[0] = 104.0
        return handle

    def facts(self, handle: int, *, directory: bool) -> WindowsFileFacts:
        index, data, opening = self.objects[handle]
        assert directory is (index < 4)
        self.visits[handle] = self.visits.get(handle, 0) + 1
        facts = WindowsFileFacts(
            (0xFEDCBA9876543210, 1 << 127 | index + 1),
            "\\\\?\\" + module._PATHS[index],
            directory,
            0 if directory else len(self.raw),
            1,
            0x10 if directory else 0x80,
            123,
            456,
            789,
        )
        if self.fault == "data_identity" and data:
            facts = replace(facts, identity=(facts.identity[0], facts.identity[1] ^ 1 << 127))
        elif self.fault == "ancestor_identity" and index == 1 and opening > 1:
            facts = replace(facts, identity=(facts.identity[0], facts.identity[1] ^ 1 << 127))
        elif self.fault == "held_drift" and index == 3 and self.visits[handle] > 1:
            facts = replace(facts, changed=790)
        elif self.fault == "volume" and index == 1:
            facts = replace(facts, identity=(facts.identity[0] ^ 1 << 63, facts.identity[1]))
        elif self.fault == "final_path" and index == 4:
            facts = replace(facts, final_path=r"\\?\C:\ProgramData\OTHER\enrollment.json")
        elif self.fault == "reparse":
            facts = replace(facts, attributes=facts.attributes | 0x400)
        elif self.fault == "offline":
            facts = replace(facts, attributes=facts.attributes | 0x1000)
        elif self.fault == "hardlink" and index == 4:
            facts = replace(facts, links=2)
        elif self.fault == "oversize" and index == 4:
            facts = replace(facts, size=16385)
        elif self.fault == "bool_identity":
            facts = replace(facts, identity=(True, facts.identity[1]))
        return facts

    def protected(self, handle: int, owner_sid: str, *, directory: bool) -> str:
        index, data, opening = self.objects[handle]
        assert index in (2, 3, 4) and owner_sid == self.owner.user_sid
        self.calls.append(("protected", index, data, opening))
        raw = descriptor(directory=directory)
        if self.fault == "unprotected":
            raw = raw[:2] + b"\x04\x80" + raw[4:]
        if self.fault == "user_owned":
            raw = descriptor(owner=owner_sid, directory=directory)
        result = module.native.verify_protected_metadata_descriptor(
            raw, owner_sid, directory=directory
        )
        if (
            self.fault == "data_descriptor"
            and data
            or self.fault == "fresh_descriptor"
            and opening > 1
            and not data
        ):
            result = "sha256:" + "f" * 64
        return result

    def principal(self) -> WindowsPrincipalFacts:
        self.principals += 1
        if self.fault == "elevated":
            return replace(self.owner, elevated=True)
        if self.fault == "principal_drift" and self.principals > 1:
            return replace(self.owner, modified_id=34)
        if self.fault == "principal_error":
            raise OSError("synthetic sensitive identity")
        return self.owner

    def read(self, handle: int, count: int) -> bytes:
        assert self.objects[handle][1]
        self.calls.append(("read", count))
        if self.fault == "read_error":
            raise OSError("synthetic private read detail")
        if self.fault == "deadline_read":
            self.clock[0] = 104.0
        elif self.fault == "wall_expiry":
            self.wall[0] = NOW_MS + 1000
        elif self.fault == "wall_rollback":
            self.wall[0] = NOW_MS - 2
        payload = self.raw + (b"x" if self.fault == "growth" else b"")
        if self.fault == "short":
            payload = payload[:-1]
        chunk = payload[self.position : self.position + count]
        self.position += len(chunk)
        return chunk

    def close(self) -> None:
        self.closed = list(self.objects)
        if self.fault == "cleanup":
            raise OSError("synthetic ambiguous cleanup")


def install(monkeypatch: pytest.MonkeyPatch, *, fault: str = "", row: Any = None) -> FakeReader:
    fake = FakeReader(None)
    fake.fault = fault
    if row is not None:
        fake.raw = canonical_json_bytes(row)
    monkeypatch.setattr(module.time, "monotonic", lambda: fake.clock[0])
    monkeypatch.setattr(module.time, "time_ns", lambda: fake.wall[0] * 1_000_000)

    def factory(gate: Any) -> FakeReader:
        fake.gate = gate
        return fake

    monkeypatch.setattr(module, "_ProtectedRecordReader", factory)
    return fake


def observe() -> module.ProtectedEnrollmentRecordObservation:
    return module.observe_protected_enrollment_record(deadline=104.0, cancelled=lambda: False)


def test_fake_fixed_record_is_immutable_non_authoritative_and_all_handles_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = install(monkeypatch)
    result = observe()
    assert result.raw_bytes == fake.raw
    assert result.record_sha256 == "sha256:" + hashlib.sha256(fake.raw).hexdigest()
    assert result.record_identity_wire == ("fedcba9876543210", "05000000000000000000000000000080")
    assert len(result.object_facts) == 5
    assert fake.closed == list(fake.objects) and len(fake.closed) == 11
    assert fake.principals == 2
    assert [call for call in fake.calls if call[0] == "read"][-1] == ("read", 1)
    assert not hasattr(result, "verified") and not hasattr(result, "available")
    assert fake.raw.decode() not in repr(result) and fake.owner.user_sid not in repr(result)
    with pytest.raises(FrozenInstanceError):
        result.raw_bytes = b"changed"


@pytest.mark.parametrize(
    "fault",
    [
        "open",
        "data_identity",
        "ancestor_identity",
        "held_drift",
        "volume",
        "final_path",
        "reparse",
        "offline",
        "hardlink",
        "oversize",
        "bool_identity",
        "unprotected",
        "user_owned",
        "data_descriptor",
        "fresh_descriptor",
        "elevated",
        "principal_drift",
        "principal_error",
        "read_error",
        "growth",
        "short",
        "deadline_open",
        "deadline_read",
        "wall_expiry",
        "wall_rollback",
        "cleanup",
    ],
)
def test_fake_races_geometry_protection_identity_deadline_and_cleanup_refuse(
    monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    fake = install(monkeypatch, fault=fault)
    with pytest.raises(module.WindowsEnrollmentRecordError) as caught:
        observe()
    assert fake.closed == list(fake.objects)
    assert caught.value.__cause__ is None and caught.value.__suppress_context__
    assert "sensitive" not in str(caught.value) and "private" not in str(caught.value)


@pytest.mark.parametrize(
    "fault", ["owner", "stale", "future", "unknown", "password", "generation", "image", "sid_alias"]
)
def test_fake_record_contract_drift_never_becomes_enrollment(
    monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    row = copy.deepcopy(declared_candidate())
    if fault == "owner":
        row["resource"]["owner_sid"] = "S-1-5-21-101-202-303-1003"
        row["credential_reference"]["purpose_digest"] = module.enrollment._purpose(row)
    elif fault == "stale":
        row["expires_at_ms"] = NOW_MS
    elif fault == "future":
        row["issued_at_ms"] = NOW_MS + 1
    elif fault == "unknown":
        row["verified"] = True
    elif fault == "password":
        row["credential_reference"]["password"] = "synthetic secret must not be diagnosed"
    elif fault == "generation":
        row["generation"] = "f" * 32
    elif fault == "image":
        row["native_image"]["image_name"] = "caller.exe"
    else:
        row["resource"]["owner_sid"] = "S-1-5-21-0101-202-303-1001"
    fake = install(monkeypatch, row=row)
    with pytest.raises(module.WindowsEnrollmentRecordError) as caught:
        observe()
    assert fake.closed == list(fake.objects)
    assert "secret" not in str(caught.value)


def test_stop_after_open_closes_just_acquired_handle_before_any_more_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = install(monkeypatch, fault="deadline_open")
    with pytest.raises(module.WindowsEnrollmentRecordError):
        observe()
    assert fake.closed == [100, 101, 102]
    assert fake.calls == [("open", 0, False), ("open", 1, False), ("open", 2, False)]


def test_primitive_accepts_no_caller_path_anchor_owner_or_verified_flag() -> None:
    for keyword, value in (
        ("path", r"C:\caller.json"),
        ("anchor_bytes", b"{}"),
        ("owner_sid", "synthetic"),
        ("verified", True),
    ):
        with pytest.raises(TypeError):
            module.observe_protected_enrollment_record(
                deadline=104.0, cancelled=lambda: False, **{keyword: value}
            )


def test_existing_runtime_reader_remains_unavailable_even_after_fake_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install(monkeypatch)
    observe()
    with pytest.raises(module.enrollment.WindowsEnrollmentUnavailable):
        enrollment.read_windows_file_access_enrollment(now_ms=NOW_MS)


def test_noncanonical_public_record_bytes_are_retained_exactly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = install(monkeypatch)
    fake.raw = b" \n" + fake.raw + b"\n"
    result = observe()
    assert result.raw_bytes == fake.raw
    assert result.record_sha256 == "sha256:" + hashlib.sha256(fake.raw).hexdigest()


@pytest.mark.parametrize(
    "raw", [b"\xff", b"\xef\xbb\xbf{}", b'{"generation":1,"generation":2}', "{}".encode("utf-16")]
)
def test_malformed_wire_bytes_refused_after_bounded_read_and_cleanup(
    monkeypatch: pytest.MonkeyPatch, raw: bytes
) -> None:
    fake = install(monkeypatch)
    fake.raw = raw
    with pytest.raises(module.WindowsEnrollmentRecordError):
        observe()
    assert fake.closed == list(fake.objects)


@pytest.mark.parametrize(
    "deadline,cancelled",
    [(100.0, False), (106.0, False), (float("nan"), False), (True, False), (104.0, True)],
)
def test_initial_deadline_or_cancellation_refuses_before_reader_and_io(
    monkeypatch: pytest.MonkeyPatch, deadline: float, cancelled: bool
) -> None:
    monkeypatch.setattr(module.time, "monotonic", lambda: 100.0)

    def forbidden(gate: Any) -> None:
        pytest.fail("stopped observation created a reader")

    monkeypatch.setattr(module, "_ProtectedRecordReader", forbidden)
    with pytest.raises(module.WindowsEnrollmentRecordError):
        module.observe_protected_enrollment_record(deadline=deadline, cancelled=lambda: cancelled)


def test_cancellation_after_protected_callback_prevents_data_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = install(monkeypatch)
    stopped = [False]
    original = fake.protected

    def stop(handle: int, owner_sid: str, *, directory: bool) -> str:
        result = original(handle, owner_sid, directory=directory)
        stopped[0] = True
        return result

    monkeypatch.setattr(fake, "protected", stop)
    with pytest.raises(module.WindowsEnrollmentRecordError):
        module.observe_protected_enrollment_record(deadline=104.0, cancelled=lambda: stopped[0])
    assert not any(call[0] == "open" and call[2] for call in fake.calls)
    assert fake.closed == list(fake.objects)


@pytest.mark.parametrize("failure_positions", [(), (0,), (2,), (0, 1, 2)])
def test_concrete_wrapper_tracks_and_attempts_every_owned_close(
    monkeypatch: pytest.MonkeyPatch, failure_positions: tuple[int, ...]
) -> None:
    monkeypatch.setattr(module.time, "monotonic", lambda: 100.0)
    gate = module.native._Gate(104.0, lambda: False)
    reader = module._ProtectedRecordReader(gate)
    opened: list[tuple[str, bool, bool]] = []
    closed: list[int] = []
    original_close = module.os.close

    def fake_open(path: Any, *, directory: bool, data: bool = False) -> int:
        opened.append((str(path), directory, data))
        return 9000 + len(opened)

    def fake_close(descriptor: int) -> None:
        if descriptor not in (9001, 9002, 9003):
            original_close(descriptor)
            return
        closed.append(descriptor)
        if len(closed) - 1 in failure_positions:
            raise OSError("synthetic close uncertainty")

    monkeypatch.setattr(module.handles, "open_observation", fake_open)
    monkeypatch.setattr(module.os, "close", fake_close)
    assert [reader.open(0), reader.open(4), reader.open(4, data=True)] == [9001, 9002, 9003]
    assert reader.descriptors == [9001, 9002, 9003]
    assert opened == [
        (module._PATHS[0], True, False),
        (module._PATHS[4], False, False),
        (module._PATHS[4], False, True),
    ]
    if failure_positions:
        with pytest.raises(module.WindowsEnrollmentRecordError, match="cleanup is unknown"):
            reader.close()
    else:
        reader.close()
    assert closed == [9003, 9002, 9001]
    assert reader.descriptors == []


def test_concrete_wrapper_post_open_cancellation_tracks_then_closes_new_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(module.time, "monotonic", lambda: 100.0)
    owner = FakeReader(None).owner
    stopped = [False]
    opened: list[tuple[str, bool, bool]] = []
    closed: list[int] = []
    original_close = module.os.close
    monkeypatch.setattr(module, "current_process_principal", lambda: owner)

    def fake_open(path: Any, *, directory: bool, data: bool = False) -> int:
        opened.append((str(path), directory, data))
        stopped[0] = True
        return 9101

    def fake_close(descriptor: int) -> None:
        if descriptor != 9101:
            original_close(descriptor)
            return
        closed.append(descriptor)

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("post-open cancellation reached metadata or data I/O")

    monkeypatch.setattr(module.handles, "open_observation", fake_open)
    monkeypatch.setattr(module.handles, "inspect_observation", forbidden)
    monkeypatch.setattr(module.os, "close", fake_close)
    monkeypatch.setattr(module.os, "read", forbidden)
    with pytest.raises(module.WindowsEnrollmentRecordError, match="stopped"):
        module.observe_protected_enrollment_record(deadline=104.0, cancelled=lambda: stopped[0])
    assert opened == [(module._PATHS[0], True, False)]
    assert closed == [9101]


def test_concrete_wrapper_failed_open_retains_only_previously_owned_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(module.time, "monotonic", lambda: 100.0)
    reader = module._ProtectedRecordReader(module.native._Gate(104.0, lambda: False))
    opened: list[str] = []
    closed: list[int] = []
    original_close = module.os.close

    def fake_open(path: Any, *, directory: bool, data: bool = False) -> int:
        opened.append(str(path))
        if len(opened) > 1:
            raise OSError("synthetic unopened object")
        return 9201

    def fake_close(descriptor: int) -> None:
        if descriptor != 9201:
            original_close(descriptor)
            return
        closed.append(descriptor)

    monkeypatch.setattr(module.handles, "open_observation", fake_open)
    monkeypatch.setattr(module.os, "close", fake_close)
    reader.open(0)
    with pytest.raises(OSError, match="unopened"):
        reader.open(1)
    assert reader.descriptors == [9201]
    reader.close()
    assert closed == [9201]


def test_concrete_wrapper_delegates_only_borrowed_handle_and_original_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(module.time, "monotonic", lambda: 100.0)

    def cancelled() -> bool:
        return False

    reader = module._ProtectedRecordReader(module.native._Gate(104.0, cancelled))
    owner = FakeReader(None).owner
    facts = WindowsFileFacts((7, 8), "synthetic", False, 12, 1, 0x80, 1, 2, 3)
    calls: list[tuple[Any, ...]] = []
    monkeypatch.setattr(module, "current_process_principal", lambda: owner)
    monkeypatch.setattr(module, "_handle_from_descriptor", lambda descriptor: descriptor + 100)

    def inspect(descriptor: int, *, directory: bool) -> WindowsFileFacts:
        calls.append(("facts", descriptor, directory))
        return facts

    def protected(
        handle: int, sid: str, *, directory: bool, deadline: float, cancelled: Any
    ) -> str:
        calls.append(("protected", handle, sid, directory, deadline, cancelled))
        return "sha256:" + "a" * 64

    original_read = module.os.read

    def read(descriptor: int, count: int) -> bytes:
        if descriptor != 9301:
            return original_read(descriptor, count)
        calls.append(("read", descriptor, count))
        return b"synthetic"

    monkeypatch.setattr(module.handles, "inspect_observation", inspect)
    monkeypatch.setattr(module.native, "observe_protected_metadata_descriptor", protected)
    monkeypatch.setattr(module.os, "read", read)
    assert reader.principal() is owner
    assert reader.facts(9301, directory=False) is facts
    assert reader.protected(9301, owner.user_sid, directory=False) == "sha256:" + "a" * 64
    assert reader.read(9301, 12) == b"synthetic"
    assert calls == [
        ("facts", 9301, False),
        ("protected", 9401, owner.user_sid, False, 104.0, cancelled),
        ("read", 9301, 12),
    ]


class PairFakeReader(FakeReader):
    """Synthetic pair facts with concurrent ownership, never setup authority."""

    def __init__(self, gate: Any) -> None:
        super().__init__(gate)
        self.anchor_raw = canonical_json_bytes(declared_anchor(self.raw))
        self.anchor_objects: dict[int, tuple[int, bool, int]] = {}
        self.anchor_opens = [0] * 6
        self.anchor_positions: dict[int, int] = {}
        self.late_record_drift = False

    def open_anchor(self, index: int, generation: str, *, data: bool = False) -> int:
        assert generation == declared_candidate()["generation"]
        assert 104 in self.objects and 105 in self.objects and not self.closed
        self.calls.append(("anchor_open", index, data))
        if self.fault == "anchor_missing":
            raise OSError("synthetic missing protected anchor")
        self.anchor_opens[index] += 1
        handle = 100 + len(self.objects)
        entry = (index, data, self.anchor_opens[index])
        self.objects[handle] = self.anchor_objects[handle] = entry
        if self.fault == "anchor_deadline" and index == 4:
            self.clock[0] = 104.0
        if self.fault == "late_record_drift" and index == 0 and self.anchor_opens[index] > 1:
            self.late_record_drift = True
        return handle

    def facts(self, handle: int, *, directory: bool) -> WindowsFileFacts:
        if handle not in self.anchor_objects:
            facts = super().facts(handle, directory=directory)
            if self.late_record_drift and self.objects[handle][0] == 4:
                facts = replace(facts, changed=790)
            return facts
        index, data, opening = self.anchor_objects[handle]
        assert directory is (index < 5)
        paths = module.setup._anchor_paths(declared_candidate()["generation"])
        identity = (0xFEDCBA9876543210, (1 << 127) | (index + 1 if index < 3 else 100 + index))
        facts = WindowsFileFacts(
            identity,
            "\\\\?\\" + paths[index],
            directory,
            0 if directory else len(self.anchor_raw),
            1,
            0x10 if directory else 0x80,
            123,
            456,
            789,
        )
        if self.fault == "anchor_parent" and index == 2:
            facts = replace(facts, changed=790)
        elif self.fault == "anchor_volume" and index == 4:
            facts = replace(facts, identity=(identity[0] ^ (1 << 63), identity[1]))
        elif self.fault == "anchor_data_identity" and data:
            facts = replace(facts, identity=(identity[0], identity[1] ^ (1 << 127)))
        elif self.fault == "anchor_fresh_identity" and index == 4 and opening > 1:
            facts = replace(facts, identity=(identity[0], identity[1] ^ (1 << 127)))
        elif self.fault == "anchor_alias" and index == 3:
            facts = replace(facts, identity=(identity[0], (1 << 127) | 4))
        elif self.fault == "anchor_duplicate" and index == 5:
            facts = replace(facts, identity=(identity[0], (1 << 127) | 104))
        elif self.fault == "anchor_path" and index == 5:
            facts = replace(facts, final_path=paths[index])
        elif self.fault == "anchor_oversize" and index == 5:
            facts = replace(facts, size=4097)
        elif self.fault == "anchor_hardlink" and index == 5:
            facts = replace(facts, links=2)
        return facts

    def protected(self, handle: int, owner_sid: str, *, directory: bool) -> str:
        if handle not in self.anchor_objects:
            return super().protected(handle, owner_sid, directory=directory)
        index, data, opening = self.anchor_objects[handle]
        assert index >= 2 and owner_sid == self.owner.user_sid
        self.calls.append(("anchor_protected", index, data, opening))
        raw = descriptor(
            directory=directory,
            owner=owner_sid if self.fault == "anchor_user_owned" else "S-1-5-18",
        )
        result = module.native.verify_protected_metadata_descriptor(
            raw, owner_sid, directory=directory
        )
        if self.fault == "anchor_shared_descriptor" and index == 2:
            return "sha256:" + "e" * 64
        if (
            self.fault == "anchor_data_descriptor"
            and data
            or self.fault == "anchor_fresh_descriptor"
            and opening > 1
            and not data
        ):
            return "sha256:" + "f" * 64
        return result

    def read(self, handle: int, count: int) -> bytes:
        if handle not in self.anchor_objects:
            return super().read(handle, count)
        assert self.anchor_objects[handle][1]
        self.calls.append(("anchor_read", count))
        if self.fault == "anchor_read_deadline":
            self.clock[0] = 104.0
        elif self.fault == "anchor_wall_expiry":
            self.wall[0] = NOW_MS + 1000
        elif self.fault == "anchor_wall_rollback":
            self.wall[0] = NOW_MS - 2
        payload = self.anchor_raw + (b"x" if self.fault == "anchor_growth" else b"")
        if self.fault == "anchor_short":
            payload = payload[:-1]
        position = self.anchor_positions.get(handle, 0)
        chunk = payload[position : position + count]
        self.anchor_positions[handle] = position + len(chunk)
        return chunk


def install_pair(monkeypatch: pytest.MonkeyPatch, *, fault: str = "") -> PairFakeReader:
    fake = PairFakeReader(None)
    fake.fault = fault
    monkeypatch.setattr(module.time, "monotonic", lambda: fake.clock[0])
    monkeypatch.setattr(module.time, "time_ns", lambda: fake.wall[0] * 1_000_000)

    def factory(gate: Any) -> PairFakeReader:
        fake.gate = gate
        return fake

    monkeypatch.setattr(module, "_ProtectedRecordReader", factory)
    return fake


def test_fake_pair_holds_both_ancestries_concurrently_and_returns_no_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = install_pair(monkeypatch)
    fake.anchor_raw = b" \n" + fake.anchor_raw + b"\n"
    result = module.observe_protected_enrollment_pair(deadline=104.0, cancelled=lambda: False)
    assert result.record.raw_bytes == fake.raw and result.anchor_bytes == fake.anchor_raw
    assert len(result.record.object_facts) == 5 and len(result.anchor_object_facts) == 6
    assert result.anchor_sha256 == "sha256:" + hashlib.sha256(fake.anchor_raw).hexdigest()
    assert len(fake.objects) == 24 and fake.closed == list(fake.objects)
    assert result.record.record_identity_wire[1] == "05000000000000000000000000000080"
    assert not hasattr(result, "verified") and not hasattr(result, "available")
    with pytest.raises(FrozenInstanceError):
        result.anchor_bytes = b"changed"
    with pytest.raises(module.enrollment.WindowsEnrollmentUnavailable):
        enrollment.read_windows_file_access_enrollment(now_ms=NOW_MS)


@pytest.mark.parametrize(
    "fault",
    [
        "anchor_missing",
        "anchor_parent",
        "anchor_shared_descriptor",
        "anchor_volume",
        "anchor_data_identity",
        "anchor_fresh_identity",
        "anchor_alias",
        "anchor_duplicate",
        "anchor_path",
        "anchor_oversize",
        "anchor_hardlink",
        "anchor_user_owned",
        "anchor_data_descriptor",
        "anchor_fresh_descriptor",
        "anchor_growth",
        "anchor_short",
        "anchor_deadline",
        "anchor_read_deadline",
        "anchor_wall_expiry",
        "anchor_wall_rollback",
        "late_record_drift",
        "cleanup",
    ],
)
def test_fake_pair_refuses_partial_drift_and_stopped_observations(
    monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    fake = install_pair(monkeypatch, fault=fault)
    with pytest.raises(module.WindowsEnrollmentRecordError) as caught:
        module.observe_protected_enrollment_pair(deadline=104.0, cancelled=lambda: False)
    assert fake.closed == list(fake.objects)
    assert caught.value.__cause__ is None and caught.value.__suppress_context__


@pytest.mark.parametrize(
    "field",
    [
        "host_id",
        "setup_receipt_digest",
        "image_sha256",
        "credential_binding_digest",
        "enrollment_digest",
        "generation",
        "record_identity",
    ],
)
def test_fake_pair_anchor_linkage_is_exact_without_declared_trust(
    monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    fake = install_pair(monkeypatch)
    row = declared_anchor(fake.raw)
    if field == "generation":
        row[field] = "f" * 32
        row["enrollment_id"] = "win-file-enrollment-" + "f" * 32
    elif field == "record_identity":
        row[field]["file_id"] = "05000000000000000000000000000000"
    else:
        row[field] = "sha256:" + "f" * 64
    fake.anchor_raw = canonical_json_bytes(row)
    with pytest.raises(module.WindowsEnrollmentRecordError):
        module.observe_protected_enrollment_pair(deadline=104.0, cancelled=lambda: False)
    assert fake.closed == list(fake.objects)


def test_concrete_anchor_open_tracks_post_open_cancel_without_arbitrary_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stopped = [False]
    monkeypatch.setattr(module.time, "monotonic", lambda: 100.0)
    reader = module._ProtectedRecordReader(module.native._Gate(104.0, lambda: stopped[0]))
    paths: list[str] = []
    closed: list[int] = []
    original_close = module.os.close

    def fake_open(path: Any, *, directory: bool, data: bool = False) -> int:
        assert not directory and data
        paths.append(str(path))
        stopped[0] = True
        return 9601

    def fake_close(descriptor: int) -> None:
        if descriptor != 9601:
            original_close(descriptor)
        else:
            closed.append(descriptor)

    monkeypatch.setattr(module.handles, "open_observation", fake_open)
    monkeypatch.setattr(module.os, "close", fake_close)
    with pytest.raises(module.native.WindowsEnrollmentNativeError, match="stopped"):
        reader.open_anchor(5, declared_candidate()["generation"], data=True)
    assert reader.descriptors == [9601]
    reader.close()
    assert closed == [9601]
    assert paths == [module.setup._anchor_paths(declared_candidate()["generation"])[-1]]
