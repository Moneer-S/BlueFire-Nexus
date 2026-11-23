"""Read-only reconciliation of one already completed fixed worker request."""

from __future__ import annotations

import array
import json
import socket
import struct
import time
from typing import Any, Mapping

from .file_access_contract import (
    MAX_REPORT_BYTES,
    MAX_REQUEST_MS,
    FileAccessContractError,
    VerifiedFileAccessBinding,
    digest,
    exact,
    linux_attr,
    request_challenge,
)
from .file_access_probe import REQUEST_SCHEMA, RESPONSE_SCHEMA, _nonfinite, _pairs
from .util import canonical_json_bytes, content_hash


def validate_closed_response(
    value: Any, *, binding: Mapping[str, Any], request_hash: str
) -> dict[str, Any]:
    row = exact(
        value,
        {"schema_version", "request_hash", "challenge", "binding_digest", "result"},
        "worker closure response",
    )
    challenge = request_challenge(binding, request_hash)
    result = exact(
        row["result"],
        {
            "outcome",
            "sha256",
            "size",
            "record_count",
            "device",
            "inode",
            "mode",
            "principal",
            "read_handles_closed",
        },
        "closed worker result",
    )
    expected_principal = {
        key: binding["worker"][key] for key in ("uid", "gid", "pid", "start_ticks", "namespaces")
    }
    if (
        row["schema_version"] != RESPONSE_SCHEMA
        or row["request_hash"] != request_hash
        or row["challenge"] != challenge
        or row["binding_digest"] != content_hash(binding)
        or result["principal"] != expected_principal
        or result["read_handles_closed"] is not True
    ):
        raise FileAccessContractError("worker closure differs from the exact recorded request")
    resource = binding["resource"]
    if (
        any(result[key] != resource[key] for key in ("size", "device", "inode"))
        or result["mode"] != binding["mode"]
    ):
        raise FileAccessContractError("closed read differs from the recorded resource")
    if result["outcome"] == "allowed":
        if (result["sha256"], result["record_count"]) != (
            resource["sha256"],
            resource["record_count"],
        ):
            raise FileAccessContractError("closed read content differs from the recorded resource")
    elif (
        result["outcome"] != "permission_denied"
        or result["sha256"] is not None
        or result["record_count"] is not None
    ):
        raise FileAccessContractError("closed read outcome is unsupported")
    return {
        "schema_version": "bluefire.file-access-worker-closure.v1",
        "request_hash": request_hash,
        "challenge": challenge,
        "binding_digest": content_hash(binding),
        "principal": expected_principal,
        "read_handles_closed": True,
        "worker_response_digest": content_hash(row),
    }


def recover_file_access_closure(
    binding: VerifiedFileAccessBinding, *, request_hash: str
) -> dict[str, Any]:
    """Never dispatch a read. A missing cache entry remains unresolved."""
    from .file_access_enrollment import read_file_access_enrollment

    if not isinstance(binding, VerifiedFileAccessBinding):
        raise FileAccessContractError("closure recovery requires independently stored provenance")
    document = binding.to_dict()
    digest(request_hash, "original registered request hash")
    enrollment = read_file_access_enrollment()
    if (
        enrollment["document_digest"] != document["enrollment_digest"]
        or enrollment["document"]["worker"] != document["worker"]
    ):
        raise FileAccessContractError("worker generation changed before closure recovery")
    remaining = min(MAX_REQUEST_MS, document["expires_at_ms"] - time.time_ns() // 1_000_000)
    if remaining <= 0:
        raise FileAccessContractError("worker closure recovery expired")
    request = {
        "schema_version": REQUEST_SCHEMA,
        "operation": "closure",
        "launch_nonce": document["worker"]["launch_nonce"],
        "request_hash": request_hash,
        "challenge": request_challenge(document, request_hash),
        "binding": document,
    }
    with socket.socket(linux_attr(socket, "AF_UNIX"), socket.SOCK_SEQPACKET) as channel:
        channel.settimeout(remaining / 1000)
        channel.setsockopt(socket.SOL_SOCKET, linux_attr(socket, "SO_PASSCRED"), 1)
        channel.connect(document["worker"]["socket_path"])
        payload = canonical_json_bytes(request)
        if linux_attr(channel, "sendmsg")([payload]) != len(payload):
            raise FileAccessContractError("closure query did not send completely")
        response, ancillary, flags, _ = linux_attr(channel, "recvmsg")(
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
                import os

                descriptors = array.array("i")
                descriptors.frombytes(data[: len(data) - len(data) % descriptors.itemsize])
                for descriptor in descriptors:
                    os.close(descriptor)
    worker = document["worker"]
    if (
        unexpected
        or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
        or credentials != [(worker["pid"], worker["uid"], worker["gid"])]
        or not 1 <= len(response) <= MAX_REPORT_BYTES
    ):
        raise FileAccessContractError("closure response lacks exact post-drop worker credentials")
    after = read_file_access_enrollment()
    if after != enrollment:
        raise FileAccessContractError("worker generation changed during closure recovery")
    value = json.loads(response.decode(), object_pairs_hook=_pairs, parse_constant=_nonfinite)
    return validate_closed_response(value, binding=document, request_hash=request_hash)
