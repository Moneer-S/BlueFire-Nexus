"""Guest endpoint cleanup remains pending until native and local absence agree."""

from __future__ import annotations

import os
import socket
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from bluefire.strix_linux_native_endpoint_cleanup import (
    NativeGuestEndpointCleanupError,
    NativeGuestEndpointCleanupOwner,
)
from bluefire.util import content_hash

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux descriptor custody")
_CLAIM = "sha256:" + "a" * 64
_RESOURCE_CLAIM = "sha256:" + "d" * 64
_CONTAINMENT = "sha256:" + "b" * 64
_QUALIFIED = "sha256:" + "c" * 64
_ATTEMPT = "engine-attempt-" + "1" * 32


class _Worker:
    def __init__(self, observed: dict[str, Any], directory_fd: int, listener_fd: int) -> None:
        self._observed = observed
        self.endpoint_directory_fd = directory_fd
        self.control_listener_fd = listener_fd
        self.qualified_receipt_ref = _QUALIFIED
        self.cleanup_uncertain = True
        self.terminal: dict[str, Any] | None = None

    def observed_document(self) -> dict[str, Any]:
        return dict(self._observed)

    def terminal_receipt(self) -> dict[str, Any] | None:
        return None if self.terminal is None else dict(self.terminal)


def _fact(details: os.stat_result) -> dict[str, int]:
    return {
        "device": details.st_dev,
        "inode": details.st_ino,
        "mode": stat.S_IMODE(details.st_mode),
        "uid": details.st_uid,
        "gid": details.st_gid,
    }


@pytest.fixture
def endpoint(tmp_path: Path):
    guest = tmp_path / "guest"
    guest.mkdir(mode=0o700)
    socket_path = guest / "controller.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    listener.bind(str(socket_path))
    listener.listen(1)
    directory_fd = os.open(guest, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    host = tmp_path / "host-launch"
    host.mkdir(mode=0o700)
    launch = host / "launch.json"
    launch.write_bytes(b"generated")
    observed = {
        "schema_version": "bluefire.strix-worker-runtime-observation.v1",
        "attempt_id": _ATTEMPT,
        "plan_ref": "sha256:" + "d" * 64,
        "worker": {
            "pid": 2_000_000_000,
            "uid": os.geteuid(),
            "gid": os.getegid(),
            "start_ticks": 123_456,
        },
        "cgroup_ref": "sha256:" + "f" * 64,
        "listeners": {
            "endpoint_directory_device": os.fstat(directory_fd).st_dev,
            "endpoint_directory_inode": os.fstat(directory_fd).st_ino,
            "endpoint_directory_mode": 0o700,
            "endpoint_directory_uid": os.geteuid(),
            "endpoint_directory_gid": os.getegid(),
            "endpoint_path": _fact(socket_path.lstat()),
            "control": _fact(os.fstat(listener.fileno())),
        },
    }
    observed["observation_ref"] = content_hash(observed)
    worker = _Worker(observed, directory_fd, listener.fileno())
    owner = NativeGuestEndpointCleanupOwner(
        worker=worker,
        attempt_id=_ATTEMPT,
        claim_digest=_CLAIM,
        resource_claim_ref=_RESOURCE_CLAIM,
        worker_containment_ref=_CONTAINMENT,
        host_launch_directory=host,
        host_directory_identity=(host.stat().st_dev, host.stat().st_ino),
    )
    launch_identity = (launch.stat().st_dev, launch.stat().st_ino)
    try:
        yield owner, worker, guest, socket_path, host, launch, launch_identity
    finally:
        owner.close()
        os.close(directory_fd)
        listener.close()


def _terminal(worker: _Worker) -> dict[str, Any]:
    document = {
        "schema_version": "bluefire.strix-worker-runtime-terminal.v1",
        "attempt_id": _ATTEMPT,
        "resource_claim_ref": _RESOURCE_CLAIM,
        "plan_ref": worker._observed["plan_ref"],
        "cgroup_ref": worker._observed["cgroup_ref"],
        "observation_ref": worker._observed["observation_ref"],
        "qualified_receipt_ref": _QUALIFIED,
        "worker_pid": worker._observed["worker"]["pid"],
        "worker_start_ticks": worker._observed["worker"]["start_ticks"],
        "worker_reaped": True,
        "cgroup_empty_and_removed": True,
        "endpoint_absent": True,
        "staging_root_absent": True,
        "identity_released": True,
        "verified_absent": True,
    }
    document["receipt_ref"] = content_hash(document)
    return document


def _remove_paths(socket_path: Path, host: Path, launch: Path) -> None:
    socket_path.unlink()
    launch.unlink()
    host.rmdir()


def test_endpoint_owner_requires_terminal_and_fd_relative_absence(endpoint) -> None:
    owner, worker, guest, socket_path, host, launch, launch_identity = endpoint
    with pytest.raises(NativeGuestEndpointCleanupError):
        owner.cleanup(launch_identity=launch_identity)
    _remove_paths(socket_path, host, launch)
    worker.terminal = _terminal(worker)
    worker.cleanup_uncertain = False
    receipt = owner.cleanup(launch_identity=launch_identity)
    assert receipt.schema_version == "bluefire.strix-native-guest-endpoint-cleanup-receipt.v1"
    assert receipt.endpoint_absent and receipt.launch_absent and receipt.directory_absent
    assert receipt.native_worker_absent and receipt.socket_entry_unlinked
    assert receipt.host_staging_absent and receipt.retained_directory_fd_open
    assert receipt.native_terminal_ref == worker.terminal["receipt_ref"]
    assert receipt.cleanup_owner_ref == owner.cleanup_owner_ref
    assert receipt.receipt_ref == content_hash(
        {key: value for key, value in receipt.to_dict().items() if key != "receipt_ref"}
    )
    # The guest tmpfs directory FD remains deliberately pinned; the receipt
    # asserts that no worker/host pathname reaches it, not inode deletion.
    assert stat.S_ISDIR(os.fstat(owner._guest_directory_fd).st_mode)
    assert guest.exists()
    assert owner.cleanup(launch_identity=launch_identity) is receipt
    assert owner.reopen_live_terminal() is receipt
    with pytest.raises(NativeGuestEndpointCleanupError):
        owner.cleanup(launch_identity=(1, 2))


def test_endpoint_live_reopen_refuses_changed_native_source(endpoint) -> None:
    owner, worker, _guest, socket_path, host, launch, launch_identity = endpoint
    _remove_paths(socket_path, host, launch)
    worker.terminal = _terminal(worker)
    worker.cleanup_uncertain = False
    owner.cleanup(launch_identity=launch_identity)
    worker.terminal = {**worker.terminal, "identity_released": False}
    worker.terminal["receipt_ref"] = content_hash(
        {key: value for key, value in worker.terminal.items() if key != "receipt_ref"}
    )
    with pytest.raises(NativeGuestEndpointCleanupError):
        owner.reopen_live_terminal()


def test_endpoint_owner_refuses_terminal_without_removed_socket(endpoint) -> None:
    owner, worker, _guest, _socket_path, _host, _launch, launch_identity = endpoint
    worker.terminal = _terminal(worker)
    worker.cleanup_uncertain = False
    with pytest.raises(NativeGuestEndpointCleanupError):
        owner.cleanup(launch_identity=launch_identity)


def test_endpoint_owner_refuses_mismatched_native_source(endpoint) -> None:
    owner, worker, _guest, socket_path, host, launch, launch_identity = endpoint
    _remove_paths(socket_path, host, launch)
    terminal = _terminal(worker)
    terminal["resource_claim_ref"] = "sha256:" + "e" * 64
    terminal["receipt_ref"] = content_hash(
        {key: value for key, value in terminal.items() if key != "receipt_ref"}
    )
    worker.terminal = terminal
    worker.cleanup_uncertain = False
    with pytest.raises(NativeGuestEndpointCleanupError):
        owner.cleanup(launch_identity=launch_identity)


def test_endpoint_owner_refuses_uncertain_terminal_then_retries(endpoint) -> None:
    owner, worker, _guest, socket_path, host, launch, launch_identity = endpoint
    _remove_paths(socket_path, host, launch)
    worker.terminal = _terminal(worker)
    with pytest.raises(NativeGuestEndpointCleanupError):
        owner.cleanup(launch_identity=launch_identity)
    worker.cleanup_uncertain = False
    assert owner.cleanup(launch_identity=launch_identity).endpoint_absent


def test_qualification_only_owner_has_no_published_launch(endpoint, tmp_path: Path) -> None:
    _owner, worker, _guest, socket_path, _host, _launch, _launch_identity = endpoint
    empty_host = tmp_path / "qualifier-host"
    empty_host.mkdir(mode=0o700)
    owner = NativeGuestEndpointCleanupOwner(
        worker=worker,
        attempt_id=_ATTEMPT,
        claim_digest=_CLAIM,
        resource_claim_ref=_RESOURCE_CLAIM,
        worker_containment_ref=_CONTAINMENT,
        host_launch_directory=empty_host,
        host_directory_identity=(empty_host.stat().st_dev, empty_host.stat().st_ino),
        require_launch_file=False,
    )
    try:
        with pytest.raises(NativeGuestEndpointCleanupError):
            owner.cleanup(launch_identity=None)
        socket_path.unlink()
        empty_host.rmdir()
        worker.terminal = _terminal(worker)
        worker.cleanup_uncertain = False
        receipt = owner.cleanup(launch_identity=None)
        assert receipt.launch_identity is None
        assert receipt.launch_absent
    finally:
        owner.close()
