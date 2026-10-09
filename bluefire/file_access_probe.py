"""Fixed, pre-enrolled Linux reader. No process, path or identity selection API."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import socket
import stat
import struct
import sys
import time
from pathlib import Path
from typing import Any, Mapping

from .file_access_contract import (
    ANCHOR,
    MAX_BYTES,
    MAX_REPORT_BYTES,
    MAX_REQUEST_MS,
    MAX_REQUESTS,
    OWNER_UID,
    PROBE_UID,
    FileAccessContractError,
    canonical_file_access_binding,
    exact,
    identifier,
    integer,
    linux_attr,
    request_challenge,
)
from .file_access_contract import _nonfinite as _nonfinite
from .file_access_contract import _pairs as _pairs
from .file_access_files import _directory as _directory
from .file_access_files import _identity as _identity
from .util import canonical_json_bytes, content_hash

REQUEST_SCHEMA = "bluefire.file-access-probe-request.v1"
RESPONSE_SCHEMA = "bluefire.file-access-probe-response.v1"


def process_facts() -> dict[str, Any]:
    """Read actual post-drop credentials; never accept caller-supplied facts."""
    if sys.platform != "linux":
        raise FileAccessContractError("the fixed probe requires Linux")
    from .linux_session_facts import isolation_surface_facts, namespaces

    isolation_surface_facts()

    status = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    if (
        status.get("Uid", "").split() != [str(PROBE_UID)] * 4
        or status.get("Gid", "").split() != [str(PROBE_UID)] * 4
        or status.get("Groups", "").strip()
        or status.get("NoNewPrivs", "").strip() != "1"
        or any(
            int(status.get(key, "1"), 16)
            for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
        )
    ):
        raise FileAccessContractError(
            "probe credentials are not the enrolled unprivileged identity"
        )
    fields = Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()
    return {
        "uid": PROBE_UID,
        "gid": PROBE_UID,
        "pid": os.getpid(),
        "start_ticks": int(fields[19]),
        "namespaces": namespaces(),
    }


def fresh_read(binding: Mapping[str, Any]) -> dict[str, Any]:
    """Only an explicit final-file EACCES is an observed denial."""
    document = canonical_file_access_binding(binding)
    principal = process_facts()
    worker = document["worker"]
    if any(principal[key] != worker[key] for key in principal):
        raise FileAccessContractError("probe launch identity changed")
    resource = document["resource"]
    root_fd, parent_fd, data_fd = -1, -1, -1
    try:
        root_fd = _directory(resource["root"])
        root = os.fstat(root_fd)
        parent_fd = os.open(
            "fixtures",
            linux_attr(os, "O_PATH")
            | linux_attr(os, "O_DIRECTORY")
            | linux_attr(os, "O_NOFOLLOW")
            | linux_attr(os, "O_CLOEXEC"),
            dir_fd=root_fd,
        )
        parent = os.fstat(parent_fd)
        for details, prefix in ((root, "root"), (parent, "parent")):
            if (
                details.st_dev,
                details.st_ino,
                details.st_uid,
                details.st_gid,
                stat.S_IMODE(details.st_mode),
            ) != (
                resource[prefix + "_device"],
                resource[prefix + "_inode"],
                OWNER_UID,
                PROBE_UID,
                0o2710,
            ):
                raise FileAccessContractError("probe traversal identity or permissions changed")
        before = os.stat("transformed.jsonl", dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (
                before.st_dev,
                before.st_ino,
                before.st_uid,
                before.st_gid,
                before.st_size,
                stat.S_IMODE(before.st_mode),
            )
            != (
                resource["device"],
                resource["inode"],
                OWNER_UID,
                PROBE_UID,
                resource["size"],
                int(document["mode"], 8),
            )
        ):
            raise FileAccessContractError("probe resource identity changed")
        outcome, digest, count = "allowed", None, None
        try:
            data_fd = os.open(
                "transformed.jsonl",
                os.O_RDONLY
                | linux_attr(os, "O_NOFOLLOW")
                | linux_attr(os, "O_NONBLOCK")
                | linux_attr(os, "O_CLOEXEC"),
                dir_fd=parent_fd,
            )
        except OSError as error:
            if error.errno != errno.EACCES:
                raise
            outcome = "permission_denied"
        if data_fd >= 0:
            if _identity(os.fstat(data_fd)) != _identity(before):
                raise FileAccessContractError("probe resource changed while opening")
            parts, size = [], 0
            while True:
                chunk = os.read(data_fd, min(65536, MAX_BYTES + 1 - size))
                if not chunk:
                    break
                parts.append(chunk)
                size += len(chunk)
                if size > MAX_BYTES:
                    raise FileAccessContractError("probe read exceeds its byte allowance")
            payload = b"".join(parts)
            digest = "sha256:" + hashlib.sha256(payload).hexdigest()
            records = payload.decode("utf-8").splitlines()
            if not records or any(not isinstance(json.loads(line), dict) for line in records):
                raise FileAccessContractError("probe data is not the generated record set")
            count = len(records)
            if (digest, size, count) != (
                resource["sha256"],
                resource["size"],
                resource["record_count"],
            ):
                raise FileAccessContractError("probe content differs from the enrolled data")
            if _identity(os.fstat(data_fd)) != _identity(before):
                raise FileAccessContractError("probe data changed during the read")
        after = os.stat("transformed.jsonl", dir_fd=parent_fd, follow_symlinks=False)
        if (
            _identity(after) != _identity(before)
            or _identity(os.fstat(root_fd)) != _identity(root)
            or _identity(os.fstat(parent_fd)) != _identity(parent)
        ):
            raise FileAccessContractError("probe resource changed during the request")
        return {
            "outcome": outcome,
            "sha256": digest,
            "size": before.st_size,
            "record_count": count,
            "device": before.st_dev,
            "inode": before.st_ino,
            "mode": f"{stat.S_IMODE(before.st_mode):04o}",
            "principal": principal,
            "read_handles_closed": True,
        }
    finally:
        for descriptor in (data_fd, parent_fd, root_fd):
            if descriptor >= 0:
                os.close(descriptor)


def _receive(endpoint: socket.socket) -> Mapping[str, Any]:
    endpoint.setsockopt(socket.SOL_SOCKET, linux_attr(socket, "SO_PASSCRED"), 1)
    peer = struct.unpack(
        "3i", endpoint.getsockopt(socket.SOL_SOCKET, linux_attr(socket, "SO_PEERCRED"), 12)
    )
    payload, ancillary, flags, _ = linux_attr(endpoint, "recvmsg")(
        MAX_REPORT_BYTES + 1,
        linux_attr(socket, "CMSG_SPACE")(12) + linux_attr(socket, "CMSG_SPACE")(16),
        linux_attr(socket, "MSG_CMSG_CLOEXEC"),
    )
    credentials = []
    unexpected = False
    for level, kind, data in ancillary:
        if (
            level == socket.SOL_SOCKET
            and kind == linux_attr(socket, "SCM_CREDENTIALS")
            and len(data) == 12
        ):
            credentials.append(struct.unpack("3i", data))
        else:
            unexpected = True
            if level == socket.SOL_SOCKET and kind == linux_attr(socket, "SCM_RIGHTS"):
                import array

                descriptors = array.array("i")
                descriptors.frombytes(data[: len(data) - len(data) % descriptors.itemsize])
                for descriptor in descriptors:
                    os.close(descriptor)
    if (
        flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
        or unexpected
        or credentials != [peer]
        or peer[0] <= 1
        or peer[1:] != (OWNER_UID, OWNER_UID)
        or not 1 <= len(payload) <= MAX_REPORT_BYTES
    ):
        raise FileAccessContractError("probe request peer or framing is invalid")
    value = json.loads(payload.decode(), object_pairs_hook=_pairs, parse_constant=_nonfinite)
    return exact(
        value,
        {"schema_version", "operation", "launch_nonce", "request_hash", "challenge", "binding"},
        "probe request",
    )


def serve(listener: socket.socket, definition: Mapping[str, Any]) -> None:
    """Serve only the setup-bound resource, with finite lifetime and no retries."""
    facts = process_facts()
    expires = definition["expires_at_ms"]
    deadline = time.monotonic() + max(0, min(900_000, expires - time.time_ns() // 1_000_000)) / 1000
    listener.settimeout(0.25)
    seen: set[str] = set()
    completed: dict[str, dict[str, Any]] = {}
    for _ in range(MAX_REQUESTS):
        while True:
            if time.monotonic() >= deadline:
                return
            try:
                endpoint, _ = listener.accept()
                break
            except socket.timeout:
                continue
        with endpoint:
            request_deadline = min(deadline, time.monotonic() + MAX_REQUEST_MS / 1000)
            endpoint.settimeout(max(0.001, request_deadline - time.monotonic()))
            try:
                request = _receive(endpoint)
                binding = canonical_file_access_binding(request["binding"])
                expected_worker = facts | {
                    "socket_path": definition["socket_path"],
                    "launch_nonce": definition["launch_nonce"],
                }
                if (
                    request["schema_version"] != REQUEST_SCHEMA
                    or request["operation"] not in ("read", "closure")
                    or request["launch_nonce"] != definition["launch_nonce"]
                    or binding["worker"] != expected_worker
                    or any(
                        binding[key] != definition[key]
                        for key in ("enrollment_id", "resource_id", "resource_generation")
                    )
                    or binding["resource"]["root"] != definition["root"]
                    or binding["expires_at_ms"] > expires
                    or binding["expires_at_ms"] <= time.time_ns() // 1_000_000
                    or not isinstance(request["request_hash"], str)
                    or not isinstance(request["challenge"], str)
                    or len(request["challenge"]) != 64
                    or any(c not in "0123456789abcdef" for c in request["challenge"])
                ):
                    raise FileAccessContractError("probe request is outside the enrolled resource")
                from .file_access_contract import digest as checked_digest

                checked_digest(request["request_hash"], "probe request hash")
                if request["challenge"] != request_challenge(binding, request["request_hash"]):
                    raise FileAccessContractError("probe challenge differs from its exact request")
                if request["operation"] == "closure":
                    cached = completed.get(request["request_hash"])
                    if (
                        cached is None
                        or cached["binding_digest"] != content_hash(binding)
                        or cached["challenge"] != request["challenge"]
                    ):
                        raise FileAccessContractError("no completed exact request is retained")
                    response = cached
                else:
                    if request["request_hash"] in seen:
                        raise FileAccessContractError("a read request cannot be replayed")
                    seen.add(request["request_hash"])
                    result = fresh_read(binding)
                    if time.monotonic() >= request_deadline:
                        raise FileAccessContractError("probe enrollment expired during the read")
                    response = {
                        "schema_version": RESPONSE_SCHEMA,
                        "request_hash": request["request_hash"],
                        "challenge": request["challenge"],
                        "binding_digest": content_hash(binding),
                        "result": result,
                    }
                    completed[request["request_hash"]] = response
            except (OSError, ValueError, TypeError, KeyError):
                response = {"schema_version": RESPONSE_SCHEMA, "error": "probe_unavailable"}
            payload = canonical_json_bytes(response)
            if len(payload) > MAX_REPORT_BYTES or linux_attr(endpoint, "sendmsg")([payload]) != len(
                payload
            ):
                return


def main() -> None:
    """Entry only for the setup-owned fixed launch; never a general command API."""
    from .ai_broker_bootstrap import (
        adopt_bootstrap,
        protect_process,
        receive_bootstrap,
        send_bootstrap,
    )

    if len(sys.argv) != 5:
        raise FileAccessContractError("probe needs its exact setup launch")
    bootstrap_fd, listener_fd, parent = map(int, sys.argv[1:4])
    launch = sys.argv[4]
    if (
        bootstrap_fd <= 2
        or listener_fd <= 2
        or bootstrap_fd == listener_fd
        or parent != os.getppid()
    ):
        raise FileAccessContractError("probe launch descriptors are invalid")
    keep = {0, 1, 2, bootstrap_fd, listener_fd}
    for entry in list(Path("/proc/self/fd").iterdir()):
        descriptor = int(entry.name)
        if descriptor not in keep:
            try:
                os.close(descriptor)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
    if parent != 1 or any(os.readlink(f"/proc/self/fd/{fd}") != "/dev/null" for fd in (0, 1, 2)):
        raise FileAccessContractError(
            "probe requires its fixed namespace init and null standard streams"
        )
    # Namespace PID1 teardown kills this finite worker. Arming parent-death here
    # would also kill it when setup intentionally drops PID1's root credentials.
    protect_process(PROBE_UID)
    with adopt_bootstrap(bootstrap_fd) as bootstrap, socket.socket(fileno=listener_fd) as listener:
        definition, inherited = receive_bootstrap(bootstrap, expected_uid=0, expected_pid=parent)
        exact(
            definition,
            {
                "enrollment_id",
                "resource_id",
                "resource_generation",
                "expires_at_ms",
                "root",
                "socket_path",
                "launch_nonce",
            },
            "fixed setup definition",
        )
        identifier(definition["enrollment_id"], "file-enrollment")
        identifier(definition["resource_id"], "file-resource")
        generation = identifier(definition["resource_generation"], "file-generation").rsplit(
            "-", 1
        )[1]
        now = time.time_ns() // 1_000_000
        integer(definition["expires_at_ms"], now + 1, now + 900_000, "setup expiry")
        if (
            definition["root"] != f"{ANCHOR}/data/{generation}"
            or definition["socket_path"] != f"{ANCHOR}/control/{generation}/probe.sock"
        ):
            raise FileAccessContractError("setup paths differ from the fixed generation")
        if (
            inherited is not None
            or definition.get("launch_nonce") != launch
            or listener.family != linux_attr(socket, "AF_UNIX")
            or listener.type != socket.SOCK_SEQPACKET
            or listener.getsockname() != definition.get("socket_path")
        ):
            raise FileAccessContractError("probe setup binding is invalid")
        listener.set_inheritable(False)
        listener.setsockopt(socket.SOL_SOCKET, linux_attr(socket, "SO_PASSCRED"), 1)
        listener.listen(1)
        send_bootstrap(
            bootstrap, {"kind": "ready", "launch_nonce": launch, "principal": process_facts()}
        )
        admitted, _ = receive_bootstrap(bootstrap, expected_uid=0, expected_pid=parent)
        if admitted != {"kind": "admit", "launch_nonce": launch}:
            raise FileAccessContractError("probe setup was not admitted")
        serve(listener, definition)


if __name__ == "__main__":
    main()
