"""Pure synthetic metadata; no UID creation or native probe execution."""

from bluefire.file_access_contract import ACL_ABSENT_DIGEST, request_challenge
from bluefire.util import content_hash


def binding():
    generation = "a" * 32
    return {
        "schema_version": "bluefire.file-access-execution.v1",
        "enrollment_id": "file-enrollment-" + "b" * 32,
        "enrollment_digest": "sha256:" + "c" * 64,
        "expires_at_ms": 1_800_000,
        "resource_id": "file-resource-" + "d" * 32,
        "resource_generation": "file-generation-" + generation,
        "control_revision": 1,
        "mode": "0640",
        "resource": {
            "root": "/run/bluefire-file-access/data/" + generation,
            "root_device": 3,
            "root_inode": 101,
            "parent_device": 3,
            "parent_inode": 102,
            "device": 3,
            "inode": 103,
            "owner_uid": 1000,
            "group_gid": 1002,
            "sha256": "sha256:" + "e" * 64,
            "size": 100,
            "record_count": 6,
            "acl_digest": ACL_ABSENT_DIGEST,
            "parent_acl_digest": ACL_ABSENT_DIGEST,
        },
        "worker": {
            "socket_path": "/run/bluefire-file-access/control/" + generation + "/probe.sock",
            "uid": 1002,
            "gid": 1002,
            "pid": 23,
            "start_ticks": 42,
            "launch_nonce": "f" * 64,
            "namespaces": {kind: kind + ":[123]" for kind in ("mnt", "net", "pid", "ipc")},
        },
    }


def observation(document=None, *, owner=False, denied=False):
    document = document or binding()
    request_hash = "sha256:" + ("9" if owner else "8") * 64
    principal = {
        key: document["worker"][key] for key in ("uid", "gid", "pid", "start_ticks", "namespaces")
    }
    if owner:
        principal = {**principal, "uid": 1000, "gid": 1000, "pid": 24}
    challenge = request_challenge(document, request_hash)
    return {
        "schema_version": "bluefire.file-access-observation.v1",
        "reader": "owner" if owner else "non_owner",
        "request_hash": request_hash,
        "challenge": challenge,
        "binding_digest": content_hash(document),
        **{
            key: document[key]
            for key in ("resource_id", "resource_generation", "control_revision", "mode")
        },
        "observed_at_ms": 1_000_001 if owner else 1_000_000,
        "outcome": "permission_denied" if denied else "allowed",
        "sha256": None if denied else document["resource"]["sha256"],
        "size": document["resource"]["size"],
        "record_count": None if denied else document["resource"]["record_count"],
        "principal": principal,
        "resource": {key: value for key, value in document["resource"].items() if key != "root"}
        | {"mode": document["mode"]},
        "closure": {
            "state": "verified_closed",
            "request_hash": request_hash,
            "challenge": challenge,
            "principal_digest": content_hash(principal),
        },
    }
