from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

import bluefire.cross_platform_linux as linux_host
import tools.run_cross_platform_linux_cleanup as linux_cleanup
import tools.run_cross_platform_linux_worker as linux_worker
from tools.run_cross_platform_linux_worker import (
    APPROVAL_REVIEWER,
    WorkerError,
    _publish_control_file,
    _retained_receiver_key_factory,
    _scan_secrets,
    _scenario_document,
    _secret_encodings,
)


def test_linux_cleanup_ignores_unready_supervisor_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace_name = "bluefire-gate11-0123456789abcdef"
    (tmp_path / "request.json").write_text(
        json.dumps({"workspace_name": workspace_name}) + "\n", encoding="utf-8"
    )
    (tmp_path / "supervisor.json").write_bytes(b'{"schema_version":')
    observed: list[object] = []

    def terminate(
        record: object, _staging: Path, _workspace: Path
    ) -> tuple[list[object], tuple[object, ...]]:
        observed.append(record)
        return [], ()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(linux_cleanup, "_terminate_scope", terminate)
    monkeypatch.setattr(linux_cleanup, "_remove_workspace", lambda _workspace: None)

    result = linux_cleanup.run()

    assert observed == [None]
    assert result["workspace_name"] == workspace_name


@pytest.mark.parametrize("corruption", ["invalid-ready", "malformed-supervisor"])
def test_linux_cleanup_falls_back_for_invalid_supervisor_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, corruption: str
) -> None:
    workspace_name = "bluefire-gate11-0123456789abcdef"
    (tmp_path / "request.json").write_text(
        json.dumps({"workspace_name": workspace_name}) + "\n", encoding="utf-8"
    )
    (tmp_path / "supervisor.ready").write_bytes(b"x" if corruption == "invalid-ready" else b"")
    (tmp_path / "supervisor.json").write_bytes(b'{"schema_version":')
    observed: list[object] = []

    def terminate(
        record: object, _staging: Path, _workspace: Path
    ) -> tuple[list[object], tuple[object, ...]]:
        observed.append(record)
        return [], ()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(linux_cleanup, "_terminate_scope", terminate)
    monkeypatch.setattr(linux_cleanup, "_remove_workspace", lambda _workspace: None)

    linux_cleanup.run()

    assert observed == [None]


def test_linux_control_json_parses_descriptor_verified_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "control.json"
    path.write_text('{"unverified":true}\n', encoding="utf-8")
    verified = b'{"verified":true}\n'
    monkeypatch.setattr(
        linux_host,
        "_safe_regular_payload",
        lambda _path, _maximum: (verified, (len(verified), "sha256:" + "0" * 64)),
    )

    assert linux_host._control_json(path, 4096) == {"verified": True}


def test_receiver_task_key_factory_retains_every_derived_key() -> None:
    master = b"m" * 32

    def derive(enrollment_key: bytes, task_id: object) -> bytes:
        assert enrollment_key == master
        return str(task_id).encode("ascii").ljust(32, b"-")

    factory, retained = _retained_receiver_key_factory(master, derive)

    first = factory("first")
    second = factory("second")

    assert retained == [first, second]
    assert all(len(key) == 32 for key in retained)


def test_linux_worker_executes_only_the_registered_alternate() -> None:
    root = Path(__file__).resolve().parents[1]

    primary = _scenario_document(root, "primary", 43171)
    alternate = _scenario_document(root, "registered-alternate", 43172)
    primary_step = next(item for item in primary["steps"] if item["id"] == "enumerate_fixture")
    alternate_step = next(item for item in alternate["steps"] if item["id"] == "enumerate_fixture")

    assert primary_step["behavior_id"] == "sandbox.discovery.list.v1"
    assert primary_step["alternates"] == ["sandbox.discovery.metadata.v1"]
    assert alternate_step["behavior_id"] == "sandbox.discovery.metadata.v1"
    assert alternate_step["alternates"] == ["sandbox.discovery.list.v1"]


def test_linux_worker_uses_gate_bound_review_identity() -> None:
    assert APPROVAL_REVIEWER == "gate-11-linux-runtime-reviewer"


def test_linux_supervisor_publication_is_atomic_across_short_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = b'{"schema_version":"bluefire.cross-platform-linux-supervisor.v1"}\n'
    pending = tmp_path / ".supervisor.json.pending"
    final = tmp_path / "supervisor.json"
    ready = tmp_path / "supervisor.ready"
    writes: list[int] = []
    real_open = os.open
    real_write = os.write
    real_link = os.link
    real_unlink = os.unlink

    def tracked_open(path: Any, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        if Path(path) == ready:
            details = final.lstat()
            assert details.st_nlink == 1
            assert details.st_size == len(payload)
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    def short_write(descriptor: int, chunk: bytes) -> int:
        assert not os.path.lexists(final)
        assert not os.path.lexists(ready)
        writes.append(len(chunk))
        return real_write(descriptor, chunk[:3])

    def tracked_link(source: Any, destination: Any, **kwargs: Any) -> None:
        real_link(source, destination, **kwargs)
        assert pending.lstat().st_nlink == final.lstat().st_nlink == 2
        assert not os.path.lexists(ready)

    def tracked_unlink(path: Any, *args: Any, **kwargs: Any) -> None:
        real_unlink(path, *args, **kwargs)
        if Path(path) == pending:
            assert final.lstat().st_nlink == 1
            assert not os.path.lexists(ready)

    monkeypatch.setattr(linux_worker.os, "open", tracked_open)
    monkeypatch.setattr(linux_worker.os, "write", short_write)
    monkeypatch.setattr(linux_worker.os, "link", tracked_link)
    monkeypatch.setattr(linux_worker.os, "unlink", tracked_unlink)

    _publish_control_file(tmp_path, payload)

    assert len(writes) > 1
    assert final.read_bytes() == payload
    assert ready.read_bytes() == b""
    assert not os.path.lexists(pending)


def test_linux_supervisor_publication_refuses_destination_collision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = b'{"valid":true}\n'
    final = tmp_path / "supervisor.json"
    real_link = os.link

    def collide(source: Any, destination: Any, **kwargs: Any) -> None:
        final.write_bytes(b"foreign\n")
        real_link(source, destination, **kwargs)

    monkeypatch.setattr(linux_worker.os, "link", collide)

    with pytest.raises(FileExistsError):
        _publish_control_file(tmp_path, payload)

    assert final.read_bytes() == b"foreign\n"
    assert not os.path.lexists(tmp_path / ".supervisor.json.pending")
    assert not os.path.lexists(tmp_path / "supervisor.ready")


def test_linux_supervisor_publication_rejects_zero_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(linux_worker.os, "write", lambda _descriptor, _payload: 0)

    with pytest.raises(WorkerError, match="made no progress"):
        _publish_control_file(tmp_path, b'{"valid":true}\n')

    assert not os.path.lexists(tmp_path / ".supervisor.json.pending")
    assert not os.path.lexists(tmp_path / "supervisor.json")
    assert not os.path.lexists(tmp_path / "supervisor.ready")


@pytest.mark.parametrize("failure_point", ["after-link", "after-unlink", "ready-open"])
def test_linux_supervisor_publication_fails_closed_before_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_point: str
) -> None:
    payload = b'{"valid":true}\n'
    pending = tmp_path / ".supervisor.json.pending"
    final = tmp_path / "supervisor.json"
    ready = tmp_path / "supervisor.ready"
    real_link = os.link
    real_open = os.open
    real_unlink = os.unlink

    def fail_after_link(source: Any, destination: Any, **kwargs: Any) -> None:
        real_link(source, destination, **kwargs)
        raise OSError("injected failure after link")

    def fail_after_unlink(path: Any, *args: Any, **kwargs: Any) -> None:
        real_unlink(path, *args, **kwargs)
        if Path(path) == pending:
            raise OSError("injected failure after unlink")

    def fail_ready_open(
        path: Any, flags: int, mode: int = 0o777, *, dir_fd: int | None = None
    ) -> int:
        if Path(path) == ready:
            raise OSError("injected failure before readiness commit")
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    if failure_point == "after-link":
        monkeypatch.setattr(linux_worker.os, "link", fail_after_link)
    elif failure_point == "after-unlink":
        monkeypatch.setattr(linux_worker.os, "unlink", fail_after_unlink)
    else:
        monkeypatch.setattr(linux_worker.os, "open", fail_ready_open)

    with pytest.raises(OSError, match="injected failure"):
        _publish_control_file(tmp_path, payload)

    assert not os.path.lexists(ready)
    assert not os.path.lexists(pending)
    assert final.read_bytes() == payload
    assert final.lstat().st_nlink == 1
    with pytest.raises(WorkerError, match="boundary is stale"):
        _publish_control_file(tmp_path, payload)


def test_linux_supervisor_ready_creation_is_publication_commit_point(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = b'{"valid":true}\n'
    ready = tmp_path / "supervisor.ready"
    marker_descriptor: list[int] = []
    real_close = os.close
    real_open = os.open

    def tracked_open(path: Any, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        if dir_fd is None:
            descriptor = real_open(path, flags, mode)
        else:
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if Path(path) == ready:
            marker_descriptor.append(descriptor)
        return descriptor

    def fail_marker_close(descriptor: int) -> None:
        real_close(descriptor)
        if marker_descriptor == [descriptor]:
            raise OSError("injected post-commit close failure")

    monkeypatch.setattr(linux_worker.os, "open", tracked_open)
    monkeypatch.setattr(linux_worker.os, "close", fail_marker_close)

    _publish_control_file(tmp_path, payload)

    assert ready.read_bytes() == b""
    assert (tmp_path / "supervisor.json").read_bytes() == payload


@pytest.mark.parametrize("encoding_index", range(7))
def test_linux_run_scan_rejects_every_derived_key_encoding(
    tmp_path: Path, encoding_index: int
) -> None:
    master = b"m" * 32
    derived = b"\xfb\xff" * 16
    encodings = _secret_encodings(derived)
    assert len(encodings) == 7
    (tmp_path / "evidence.bin").write_bytes(b"prefix:" + encodings[encoding_index])

    with pytest.raises(WorkerError, match="secret leaked"):
        _scan_secrets(tmp_path, (master, derived))
