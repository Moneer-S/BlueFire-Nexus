"""Explicit setup-only enrollment of one fixed reader in the existing lab namespace."""

from __future__ import annotations

import hashlib
import os
import secrets
import socket
import subprocess  # nosec B404
import sys
import time
from pathlib import Path
from typing import Any

from .file_access_contract import (
    ANCHOR,
    ENROLLMENT_PATH,
    MAX_BYTES,
    MAX_ENROLLMENT_MS,
    MAX_REQUEST_MS,
    MAX_REQUESTS,
    OWNER_UID,
    PROBE_UID,
    FileAccessContractError,
    linux_attr,
)
from .file_access_enrollment import SCHEMA, canonical_enrollment
from .prepared_lab_runtime import ENV, PYTHON, namespaces, stop_child
from .util import canonical_json_bytes


def assert_probe_identity_unused() -> None:
    """Check in the outer PID namespace before hiding any existing processes."""
    if sys.platform != "linux" or os.getuid() != 0:
        raise FileAccessContractError("probe enrollment requires explicit clone-local setup")
    import grp
    import pwd

    if any(row.pw_uid == PROBE_UID or row.pw_gid == PROBE_UID for row in pwd.getpwall()) or any(
        row.gr_gid == PROBE_UID for row in grp.getgrall()
    ):
        raise FileAccessContractError("the reserved probe identity is already assigned")
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            status = dict(
                line.split(":", 1)
                for line in (entry / "status").read_text().splitlines()
                if ":" in line
            )
        except FileNotFoundError:
            continue
        if any(str(PROBE_UID) in status.get(key, "").split() for key in ("Uid", "Gid", "Groups")):
            raise FileAccessContractError("the reserved probe identity has a live process")


def _directory(path: Path, mode: int, uid: int, gid: int) -> None:
    path.mkdir(mode=mode)
    linux_attr(os, "chown")(path, uid, gid, follow_symlinks=False)
    os.chmod(path, mode, follow_symlinks=False)


def enroll_fixed_reader() -> dict[str, Any]:
    """Only called by the explicit file-access lab start mode, never by a task."""
    from .ai_broker_bootstrap import (
        bootstrap_pair,
        protected_identity,
        receive_bootstrap,
        send_bootstrap,
    )
    from .linux_session_facts import isolation_surface_facts

    if sys.platform != "linux" or os.getuid() != 0 or os.getpid() != 1:
        raise FileAccessContractError("probe setup requires the fresh isolated namespace init")
    isolation_surface_facts()
    assert_probe_identity_unused()
    anchor = Path(ANCHOR)
    if anchor.exists() or anchor.is_symlink():
        raise FileAccessContractError("an earlier enrollment is retained; setup cannot replace it")
    generation = secrets.token_hex(16)
    launch = secrets.token_hex(32)
    root = anchor / "data" / generation
    control = anchor / "control" / generation
    _directory(anchor, 0o755, 0, 0)
    _directory(anchor / "data", 0o755, 0, 0)
    _directory(anchor / "control", 0o711, 0, 0)
    _directory(root, 0o2710, OWNER_UID, PROBE_UID)
    _directory(root / "fixtures", 0o2710, OWNER_UID, PROBE_UID)
    _directory(control, 0o700, OWNER_UID, OWNER_UID)
    issued = time.time_ns() // 1_000_000
    socket_path = str(control / "probe.sock")
    definition = {
        "enrollment_id": "file-enrollment-" + secrets.token_hex(16),
        "resource_id": "file-resource-" + secrets.token_hex(16),
        "resource_generation": "file-generation-" + generation,
        "expires_at_ms": issued + MAX_ENROLLMENT_MS,
        "root": str(root),
        "socket_path": socket_path,
        "launch_nonce": launch,
    }
    parent, child = bootstrap_pair()
    process = None
    admitted = False
    try:
        with socket.socket(linux_attr(socket, "AF_UNIX"), socket.SOCK_SEQPACKET) as listener:
            listener.bind(socket_path)
            linux_attr(os, "chown")(socket_path, OWNER_UID, OWNER_UID, follow_symlinks=False)
            os.chmod(socket_path, 0o600, follow_symlinks=False)
            process = subprocess.Popen(  # nosec B603
                [
                    "/usr/bin/setpriv",
                    "--reuid=1002",
                    "--regid=1002",
                    "--clear-groups",
                    "--no-new-privs",
                    "--bounding-set=-all",
                    "--inh-caps=-all",
                    "--ambient-caps=-all",
                    str(PYTHON),
                    "-I",
                    "-B",
                    "-m",
                    "bluefire.file_access_probe",
                    str(child.fileno()),
                    str(listener.fileno()),
                    "1",
                    launch,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                close_fds=True,
                pass_fds=(child.fileno(), listener.fileno()),
                env=ENV,
                cwd="/",
            )
            child.close()
            send_bootstrap(parent, definition)
            ready, inherited = receive_bootstrap(
                parent, expected_uid=PROBE_UID, expected_pid=process.pid
            )
            identity = protected_identity(process.pid, PROBE_UID)
            principal = {
                "uid": PROBE_UID,
                "gid": PROBE_UID,
                "pid": process.pid,
                "start_ticks": identity[1],
                "namespaces": namespaces(),
            }
            if inherited is not None or ready != {
                "kind": "ready",
                "launch_nonce": launch,
                "principal": principal,
            }:
                raise FileAccessContractError("post-drop probe launch did not match setup")
            details, fixture = root.stat(), (root / "fixtures").stat()
            source = Path(__file__).with_name("file_access_probe.py").read_bytes()
            document = canonical_enrollment(
                {
                    "schema_version": SCHEMA,
                    **{
                        key: definition[key]
                        for key in (
                            "enrollment_id",
                            "resource_id",
                            "resource_generation",
                            "expires_at_ms",
                        )
                    },
                    "issued_at_ms": issued,
                    "runner_profile_id": "sandbox-execute.v1",
                    "root": {
                        "path": str(root),
                        "device": details.st_dev,
                        "inode": details.st_ino,
                        "parent_device": fixture.st_dev,
                        "parent_inode": fixture.st_ino,
                    },
                    "worker": {
                        **principal,
                        "socket_path": definition["socket_path"],
                        "launch_nonce": launch,
                    },
                    "worker_source_digest": "sha256:" + hashlib.sha256(source).hexdigest(),
                    "limits": {
                        "max_requests": MAX_REQUESTS,
                        "max_read_bytes": MAX_BYTES,
                        "per_request_ms": MAX_REQUEST_MS,
                    },
                }
            )
            fd = os.open(
                ENROLLMENT_PATH,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | linux_attr(os, "O_NOFOLLOW")
                | linux_attr(os, "O_CLOEXEC"),
                0o444,
            )
            with os.fdopen(fd, "wb") as output:
                output.write(canonical_json_bytes(document))
                output.flush()
                os.fchmod(output.fileno(), 0o444)
                os.fsync(output.fileno())
            if protected_identity(process.pid, PROBE_UID) != identity:
                raise FileAccessContractError("probe process changed before admission")
            send_bootstrap(parent, {"kind": "admit", "launch_nonce": launch})
            admitted = True
            return document
    finally:
        parent.close()
        child.close()
        if not admitted:
            stop_child(process)
        # Failed setup is retained until the owned namespace is torn down.
