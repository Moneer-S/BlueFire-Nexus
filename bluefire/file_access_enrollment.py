"""Read-only verification of setup-root enrollment and the retained generated file."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
import sys
import time
from pathlib import Path
from typing import Any

from .file_access_contract import (
    ACL_ABSENT_DIGEST,
    ANCHOR,
    ENROLLMENT_PATH,
    MAX_BYTES,
    MAX_ENROLLMENT_MS,
    MAX_REQUEST_MS,
    MAX_REQUESTS,
    OWNER_UID,
    PROBE_UID,
    FileAccessContractError,
    digest,
    exact,
    identifier,
    integer,
    linux_attr,
    namespaces,
)
from .util import content_hash, json_clone

SCHEMA = "bluefire.file-access-enrollment.v1"
_FIELDS = {
    "schema_version",
    "enrollment_id",
    "resource_id",
    "resource_generation",
    "issued_at_ms",
    "expires_at_ms",
    "runner_profile_id",
    "root",
    "worker",
    "worker_source_digest",
    "limits",
}


def canonical_enrollment(value: Any) -> dict[str, Any]:
    row = exact(value, _FIELDS, "file-access enrollment")
    if row["schema_version"] != SCHEMA or row["runner_profile_id"] != "sandbox-execute.v1":
        raise FileAccessContractError("file-access enrollment version or profile is unsupported")
    identifier(row["enrollment_id"], "file-enrollment")
    identifier(row["resource_id"], "file-resource")
    generation = identifier(row["resource_generation"], "file-generation").rsplit("-", 1)[1]
    issued = integer(row["issued_at_ms"], 1, 2**63 - 1, "setup time")
    integer(row["expires_at_ms"], issued + 1, issued + MAX_ENROLLMENT_MS, "setup expiry")
    root = exact(
        row["root"], {"path", "device", "inode", "parent_device", "parent_inode"}, "enrolled root"
    )
    if root["path"] != f"{ANCHOR}/data/{generation}" or root["device"] != root["parent_device"]:
        raise FileAccessContractError("enrolled root is outside its fixed generation")
    integer(root["device"], 0, 2**64 - 1, "root device")
    integer(root["inode"], 1, 2**64 - 1, "root inode")
    integer(root["parent_inode"], 1, 2**64 - 1, "fixtures inode")
    worker = exact(
        row["worker"],
        {"socket_path", "uid", "gid", "pid", "start_ticks", "launch_nonce", "namespaces"},
        "enrolled worker",
    )
    if worker["socket_path"] != f"{ANCHOR}/control/{generation}/probe.sock":
        raise FileAccessContractError("enrolled channel is outside its fixed generation")
    integer(worker["uid"], PROBE_UID, PROBE_UID, "probe UID")
    integer(worker["gid"], PROBE_UID, PROBE_UID, "probe GID")
    integer(worker["pid"], 2, 2**31 - 1, "probe PID")
    integer(worker["start_ticks"], 1, 2**63 - 1, "probe start")
    digest("sha256:" + str(worker["launch_nonce"]), "probe launch")
    namespaces(worker["namespaces"])
    digest(row["worker_source_digest"], "installed worker source")
    if row["limits"] != {
        "max_requests": MAX_REQUESTS,
        "max_read_bytes": MAX_BYTES,
        "per_request_ms": MAX_REQUEST_MS,
    }:
        raise FileAccessContractError("probe limits differ from the fixed enrollment")
    return dict(json_clone(row))


def _root_owned(path: Path, *, directory: bool) -> os.stat_result:
    value = path.lstat()
    if (
        not (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode))
        or value.st_uid != 0
        or value.st_gid != 0
        or stat.S_IMODE(value.st_mode) & 0o022
        or (not directory and (value.st_nlink != 1 or stat.S_IMODE(value.st_mode) != 0o444))
    ):
        raise FileAccessContractError("setup enrollment is not root-owned immutable state")
    return value


def read_file_access_enrollment(*, now_ms: int | None = None) -> dict[str, Any]:
    """Read only the fixed immutable setup file; callers persist its digest separately."""
    if sys.platform != "linux" or os.getuid() != OWNER_UID:
        raise FileAccessContractError("file-access setup is not enrolled on this platform")
    from .file_access_files import _identity
    from .linux_session_facts import isolation_facts

    current = isolation_facts()
    _root_owned(Path("/run"), directory=True)
    _root_owned(Path(ANCHOR), directory=True)
    path = Path(ENROLLMENT_PATH)
    before = _root_owned(path, directory=False)
    if not 1 <= before.st_size <= 16 * 1024:
        raise FileAccessContractError("enrollment exceeds its size bound")
    descriptor = os.open(
        path, os.O_RDONLY | linux_attr(os, "O_NOFOLLOW") | linux_attr(os, "O_CLOEXEC")
    )
    try:
        held = os.fstat(descriptor)
        payload = os.read(descriptor, 16 * 1024 + 1)
        if (
            _identity(held) != _identity(before)
            or _identity(os.fstat(descriptor)) != _identity(held)
            or _identity(path.lstat()) != _identity(before)
        ):
            raise FileAccessContractError("setup enrollment changed while reading")
    finally:
        os.close(descriptor)
    from .file_access_contract import _nonfinite, _pairs

    document = canonical_enrollment(
        json.loads(payload.decode(), object_pairs_hook=_pairs, parse_constant=_nonfinite)
    )
    now = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    integer(now, 1, 2**63 - 1, "current time")
    if (
        not document["issued_at_ms"] <= now < document["expires_at_ms"]
        or current["namespaces"] != document["worker"]["namespaces"]
    ):
        raise FileAccessContractError("file-access enrollment expired or changed namespace")
    source = Path(__file__).with_name("file_access_probe.py").read_bytes()
    if "sha256:" + hashlib.sha256(source).hexdigest() != document["worker_source_digest"]:
        raise FileAccessContractError("installed probe source changed")
    process = Path("/proc") / str(document["worker"]["pid"])
    before_process = (process / "stat").read_text().rsplit(")", 1)[1].split()
    status = dict(
        line.split(":", 1) for line in (process / "status").read_text().splitlines() if ":" in line
    )
    if (
        before_process[0] == "Z"
        or int(before_process[19]) != document["worker"]["start_ticks"]
        or any(status.get(key, "").split() != [str(PROBE_UID)] * 4 for key in ("Uid", "Gid"))
        or status.get("Groups", "").strip()
        or status.get("NoNewPrivs", "").strip() != "1"
        or any(
            int(status.get(key, "1"), 16)
            for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
        )
    ):
        raise FileAccessContractError("the enrolled reader process is unavailable")
    after_process = (process / "stat").read_text().rsplit(")", 1)[1].split()
    if after_process[0] == "Z" or after_process[19] != before_process[19]:
        raise FileAccessContractError("the enrolled reader process changed")
    return {"document": document, "document_digest": content_hash(document)}


def _acl_absent(descriptor: int) -> str:
    for name in ("system.posix_acl_access", "system.posix_acl_default"):
        try:
            linux_attr(os, "getxattr")(descriptor, name)
        except OSError as error:
            if error.errno != errno.ENODATA:
                raise FileAccessContractError(
                    "resource ACL state cannot be independently checked"
                ) from None
        else:
            raise FileAccessContractError("the fixed resource has an unexpected ACL")
    return ACL_ABSENT_DIGEST


def inspect_file_access_resource(
    *, expected_enrollment_digest: str, now_ms: int | None = None
) -> dict[str, Any]:
    """Fresh owner-side inspection; does not mutate, create or grant access."""
    current = read_file_access_enrollment(now_ms=now_ms)
    if current["document_digest"] != digest(expected_enrollment_digest, "stored enrollment"):
        raise FileAccessContractError("stored enrollment does not match live setup")
    from .file_access_files import _directory, _identity

    enrollment = current["document"]
    root = enrollment["root"]
    descriptors: list[int] = []
    try:
        root_fd = _directory(root["path"])
        descriptors.append(root_fd)
        # ACL queries require ordinary directory descriptors, opened by the owner.
        root_read = os.open(
            ".",
            os.O_RDONLY
            | linux_attr(os, "O_DIRECTORY")
            | linux_attr(os, "O_NOFOLLOW")
            | linux_attr(os, "O_CLOEXEC"),
            dir_fd=root_fd,
        )
        descriptors.append(root_read)
        parent_fd = os.open(
            "fixtures",
            os.O_RDONLY
            | linux_attr(os, "O_DIRECTORY")
            | linux_attr(os, "O_NOFOLLOW")
            | linux_attr(os, "O_CLOEXEC"),
            dir_fd=root_fd,
        )
        descriptors.append(parent_fd)
        data_fd = os.open(
            "transformed.jsonl",
            os.O_RDONLY
            | linux_attr(os, "O_NOFOLLOW")
            | linux_attr(os, "O_NONBLOCK")
            | linux_attr(os, "O_CLOEXEC"),
            dir_fd=parent_fd,
        )
        descriptors.append(data_fd)
        root_info, parent_info, before = (os.fstat(fd) for fd in (root_read, parent_fd, data_fd))
        for details, device, inode in (
            (root_info, root["device"], root["inode"]),
            (parent_info, root["parent_device"], root["parent_inode"]),
        ):
            if (
                details.st_dev,
                details.st_ino,
                details.st_uid,
                details.st_gid,
                stat.S_IMODE(details.st_mode),
            ) != (device, inode, OWNER_UID, PROBE_UID, 0o2710):
                raise FileAccessContractError("enrolled resource traversal changed")
        mode = f"{stat.S_IMODE(before.st_mode):04o}"
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != OWNER_UID
            or before.st_gid != PROBE_UID
            or before.st_dev != root["device"]
            or not 1 <= before.st_size <= MAX_BYTES
            or mode not in ("0600", "0640")
        ):
            raise FileAccessContractError("resource differs from the fixed generated-file scope")
        acl = _acl_absent(data_fd)
        parent_acl = _acl_absent(parent_fd)
        if _acl_absent(root_read) != parent_acl:
            raise FileAccessContractError("resource root ACL changed")
        chunks, size = [], 0
        while True:
            chunk = os.read(data_fd, min(65536, MAX_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_BYTES:
                raise FileAccessContractError("resource exceeds its read bound")
        payload = b"".join(chunks)
        rows = payload.decode().splitlines()
        if (
            not 1 <= len(rows) <= 100
            or any(not isinstance(json.loads(row), dict) for row in rows)
            or size != before.st_size
        ):
            raise FileAccessContractError("resource is not the bounded generated record set")
        if any(
            _identity(os.fstat(fd)) != _identity(original)
            for fd, original in (
                (root_read, root_info),
                (parent_fd, parent_info),
                (data_fd, before),
            )
        ):
            raise FileAccessContractError("resource changed during independent inspection")
        if _identity(
            os.stat("transformed.jsonl", dir_fd=parent_fd, follow_symlinks=False)
        ) != _identity(before):
            raise FileAccessContractError("resource pathname changed during independent inspection")
        return {
            "mode": mode,
            "resource": {
                "root": root["path"],
                "root_device": root_info.st_dev,
                "root_inode": root_info.st_ino,
                "parent_device": parent_info.st_dev,
                "parent_inode": parent_info.st_ino,
                "device": before.st_dev,
                "inode": before.st_ino,
                "owner_uid": before.st_uid,
                "group_gid": before.st_gid,
                "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
                "size": size,
                "record_count": len(rows),
                "acl_digest": acl,
                "parent_acl_digest": parent_acl,
            },
        }
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
