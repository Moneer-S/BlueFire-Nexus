"""Bounded private frames and immutable review bindings for owned receivers."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Mapping

from .receiver_auth import validate_receiver_task_id
from .receiver_policy import ReceiverContentPolicy
from .util import canonical_json_bytes, content_hash, file_hash

FRAME_LIMIT = 8192
SESSION_SECONDS = 240
_HEX = re.compile(r"[0-9a-f]{64}")
_HASH = re.compile(r"sha256:[0-9a-f]{64}")
_GENERATION_FILES = (
    "receiver_session_worker.py",
    "receiver_session_contract.py",
    "receiver_session_channel.py",
    "receiver.py",
    "receiver_policy.py",
    "collection_semantics.py",
    "receiver_auth.py",
)


class ReceiverSessionError(ValueError):
    """A secret-free, path-free session refusal."""


def _require(value: bool) -> None:
    if not value:
        raise ReceiverSessionError("owned receiver session binding is invalid")


def exact(value: Any, fields: set[str]) -> Mapping[str, Any]:
    _require(isinstance(value, Mapping) and set(value) == fields)
    return dict(value)


def _pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in rows:
        _require(key not in result)
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise ReceiverSessionError("owned receiver frame has a nonfinite value")


def decode_frame(payload: bytes) -> Mapping[str, Any]:
    _require(
        type(payload) is bytes and 1 <= len(payload) <= FRAME_LIMIT and payload.endswith(b"\n")
    )
    try:
        value = json.loads(payload, object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ReceiverSessionError("owned receiver frame is malformed") from None
    _require(isinstance(value, dict))
    return dict(value)


def encode_frame(value: Mapping[str, Any]) -> bytes:
    payload = canonical_json_bytes(dict(value)) + b"\n"
    _require(len(payload) <= FRAME_LIMIT)
    return payload


def worker_generation() -> str:
    root = Path(__file__).resolve(strict=True).parent
    hashes: dict[str, str] = {}
    for name in _GENERATION_FILES:
        path = root / name
        details = path.lstat()
        _require(
            path.is_file()
            and not path.is_symlink()
            and details.st_nlink == 1
            and 0 < details.st_size <= 1024 * 1024
        )
        hashes[name] = file_hash(path)
    return content_hash(hashes)


def prepare_frame(
    *,
    launch_id: str,
    policy_id: str,
    port: int,
    generation: str,
    deadline_ns: int,
    expires_at_ms: int,
) -> dict[str, Any]:
    policy = ReceiverContentPolicy(policy_id)
    _require(isinstance(launch_id, str) and _HEX.fullmatch(launch_id) is not None)
    _require(type(port) is int and 1024 <= port <= 65535)
    _require(isinstance(generation, str) and _HASH.fullmatch(generation) is not None)
    _require(
        type(deadline_ns) is int
        and deadline_ns > 0
        and type(expires_at_ms) is int
        and expires_at_ms > 0
    )
    return {
        "kind": "prepare",
        "launch_id": launch_id,
        "policy": policy.to_dict(),
        "policy_digest": policy.digest,
        "port": port,
        "worker_generation": generation,
        "deadline_ns": deadline_ns,
        "expires_at_ms": expires_at_ms,
    }


def validate_prepare(
    value: Any, *, launch_id: str, generation: str, now_ns: int
) -> Mapping[str, Any]:
    value = exact(
        value,
        {
            "kind",
            "launch_id",
            "policy",
            "policy_digest",
            "port",
            "worker_generation",
            "deadline_ns",
            "expires_at_ms",
        },
    )
    policy = value["policy"]
    _require(isinstance(policy, Mapping))
    expected = prepare_frame(
        launch_id=launch_id,
        policy_id=policy.get("policy_id"),
        port=value["port"],
        generation=generation,
        deadline_ns=value["deadline_ns"],
        expires_at_ms=value["expires_at_ms"],
    )
    _require(
        canonical_json_bytes(dict(value)) == canonical_json_bytes(expected)
        and now_ns < value["deadline_ns"] <= now_ns + SESSION_SECONDS * 1_000_000_000
    )
    now_ms = time.time_ns() // 1_000_000
    _require(now_ms < value["expires_at_ms"] <= now_ms + SESSION_SECONDS * 1000)
    return dict(value)


def ready_binding(
    prepared: Mapping[str, Any], *, session_id: str, process_id: int, creation_identity: str
) -> dict[str, Any]:
    _require(isinstance(session_id, str) and _HEX.fullmatch(session_id) is not None)
    _require(type(process_id) is int and process_id > 1)
    _require(
        isinstance(creation_identity, str)
        and re.fullmatch(r"[1-9][0-9]{0,31}", creation_identity) is not None
    )
    value = {
        "schema_version": "bluefire.owned-receiver-session.v1",
        "launch_id": prepared["launch_id"],
        "worker_generation": prepared["worker_generation"],
        "policy": dict(prepared["policy"]),
        "policy_digest": prepared["policy_digest"],
        "host": "127.0.0.1",
        "port": prepared["port"],
        "receiver_session_id": session_id,
        "receiver_process_id": process_id,
        "creation_identity": creation_identity,
        "deadline_ns": prepared["deadline_ns"],
        "expires_at_ms": prepared["expires_at_ms"],
        "maximum_bytes": 1024 * 1024,
        "maximum_decisions": 1,
        "storage": "memory_only",
    }
    return {**value, "review_digest": content_hash(value)}


def validate_ready(
    value: Any, prepared: Mapping[str, Any], *, process_id: int, creation_identity: str
) -> dict[str, Any]:
    frame = exact(value, {"kind", "binding"})
    _require(frame["kind"] == "ready" and isinstance(frame["binding"], Mapping))
    received = frame["binding"]
    expected = ready_binding(
        prepared,
        session_id=received.get("receiver_session_id"),
        process_id=process_id,
        creation_identity=creation_identity,
    )
    _require(canonical_json_bytes(dict(received)) == canonical_json_bytes(expected))
    return expected


def task_frame(
    binding: Mapping[str, Any],
    *,
    task_id: str,
    digest: str,
    size: int,
    review_digest: str,
    now_ns: int,
) -> dict[str, Any]:
    validate_receiver_task_id(task_id)
    _require(review_digest == binding["review_digest"] and now_ns < binding["deadline_ns"])
    _require(
        isinstance(digest, str)
        and _HEX.fullmatch(digest) is not None
        and type(size) is int
        and 1 <= size <= 1024 * 1024
    )
    return {
        "kind": "bind",
        "review_digest": review_digest,
        "task_id": task_id,
        "sha256": digest,
        "size_bytes": size,
    }


def validate_task(value: Any, binding: Mapping[str, Any], *, now_ns: int) -> dict[str, Any]:
    value = exact(value, {"kind", "review_digest", "task_id", "sha256", "size_bytes"})
    expected = task_frame(
        binding,
        task_id=value["task_id"],
        digest=value["sha256"],
        size=value["size_bytes"],
        review_digest=value["review_digest"],
        now_ns=now_ns,
    )
    _require(dict(value) == expected)
    return expected


def validate_terminal(
    value: Any, binding: Mapping[str, Any], task: Mapping[str, Any]
) -> Mapping[str, Any]:
    value = exact(value, {"kind", "review_digest", "task_digest", "summary", "decision"})
    _require(
        value["kind"] == "terminal"
        and value["review_digest"] == binding["review_digest"]
        and value["task_digest"] == content_hash(task)
    )
    summary = exact(
        value["summary"],
        {
            "schema_version",
            "reason",
            "connections_handled",
            "challenges_issued",
            "requests_accepted",
            "requests_refused",
        },
    )
    _require(
        summary["schema_version"] == "bluefire.loopback-receiver-summary.v1"
        and summary["reason"]
        in {
            "content_policy_decision",
            "explicit_stop",
            "lifecycle_timeout",
            "idle_timeout",
            "max_connections",
        }
    )
    _require(
        all(
            type(summary[key]) is int and 0 <= summary[key] <= 8
            for key in (
                "connections_handled",
                "challenges_issued",
                "requests_accepted",
                "requests_refused",
            )
        )
    )
    _require(summary["requests_accepted"] <= 1)
    decision = value["decision"]
    if decision is None:
        _require(
            summary["requests_accepted"] == 0 and summary["reason"] != "content_policy_decision"
        )
        return dict(value)
    decision = exact(
        decision,
        {
            "schema_version",
            "task_id",
            "receiver_session_id",
            "receiver_process_id",
            "authenticated",
            "policy_id",
            "policy_digest",
            "sha256",
            "bytes_received",
            "decision",
            "reason",
            "semantics",
        },
    )
    _require(
        decision["schema_version"] == "bluefire.receiver-content-decision.v1"
        and decision["authenticated"] is True
    )
    _require(
        type(decision["bytes_received"]) is int and type(decision["receiver_process_id"]) is int
    )
    _require(
        all(
            decision[key] == expected
            for key, expected in {
                "task_id": task["task_id"],
                "sha256": task["sha256"],
                "bytes_received": task["size_bytes"],
                "receiver_session_id": binding["receiver_session_id"],
                "receiver_process_id": binding["receiver_process_id"],
                "policy_id": binding["policy"]["policy_id"],
                "policy_digest": binding["policy_digest"],
            }.items()
        )
    )
    _require(
        summary["reason"] == "content_policy_decision"
        and summary["connections_handled"] >= 2
        and summary["challenges_issued"] >= 1
    )
    kind = decision["decision"]
    _require(kind in {"accepted", "policy_refused", "invalid_content"})
    _require(summary["requests_accepted"] == int(kind == "accepted"))
    if kind != "accepted":
        _require(summary["requests_refused"] >= 1)
    if kind == "invalid_content":
        _require(
            decision["semantics"] is None
            and decision["reason"] == "malformed_unsupported_or_incomplete"
        )
        return dict(value)
    counts = exact(
        decision["semantics"],
        {
            "container",
            "record_count",
            "retained_record_count",
            "redacted_record_count",
            "empty_record_count",
        },
    )
    _require(
        counts["container"] == "jsonl"
        and type(counts["record_count"]) is int
        and 1 <= counts["record_count"] <= 100
    )
    dimensions = [
        counts[key]
        for key in ("retained_record_count", "redacted_record_count", "empty_record_count")
    ]
    _require(
        all(type(count) is int and 0 <= count <= 100 for count in dimensions)
        and sum(dimensions) == counts["record_count"]
    )
    from .receiver_policy import REVIEWED_RECORDS_POLICY

    accepted = (
        decision["policy_id"] == REVIEWED_RECORDS_POLICY
        or counts["redacted_record_count"] == counts["record_count"]
    )
    _require(
        kind == ("accepted" if accepted else "policy_refused")
        and decision["reason"] == ("reviewed_content" if accepted else "records_not_all_redacted")
    )
    return dict(value)
