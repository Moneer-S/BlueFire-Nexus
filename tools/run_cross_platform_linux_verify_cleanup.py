"""Independently verify one exact Gate 11 Linux cleanup publication."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import time
from pathlib import Path
from typing import Any, Mapping

_WORKSPACE = re.compile(r"^bluefire-gate11-[0-9a-f]{16}$")
_PROBES = (0, 100, 250)


class VerificationError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _read(path: Path, maximum: int) -> tuple[Mapping[str, Any], bytes]:
    before = path.lstat()
    _require(
        stat.S_ISREG(before.st_mode)
        and not stat.S_ISLNK(before.st_mode)
        and before.st_nlink == 1
        and 1 <= before.st_size <= maximum,
        "unsafe cleanup verification input",
    )
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        _require(
            stat.S_ISREG(opened.st_mode)
            and opened.st_nlink == 1
            and (opened.st_dev, opened.st_ino, opened.st_size)
            == (before.st_dev, before.st_ino, before.st_size),
            "cleanup verification input identity changed",
        )
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(maximum + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = path.lstat()
    _require(
        len(payload) == opened.st_size
        and stat.S_ISREG(after.st_mode)
        and after.st_nlink == 1
        and (after.st_dev, after.st_ino, after.st_size)
        == (opened.st_dev, opened.st_ino, opened.st_size)
        and (current.st_dev, current.st_ino, current.st_size)
        == (opened.st_dev, opened.st_ino, opened.st_size)
        and stat.S_ISREG(current.st_mode)
        and not stat.S_ISLNK(current.st_mode)
        and current.st_nlink == 1,
        "cleanup verification input changed",
    )
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise VerificationError("cleanup verification input is not strict JSON") from exc
    _require(isinstance(value, Mapping), "cleanup verification input is not an object")
    return value, payload


def _identity(value: Any, label: str) -> Mapping[str, int]:
    fields = {"process_id", "process_group_id", "session_id", "start_time_ticks"}
    _require(isinstance(value, Mapping) and set(value) == fields, f"invalid {label}")
    _require(
        all(type(value.get(field)) is int and 0 < int(value[field]) < 2**63 for field in fields),
        f"invalid {label}",
    )
    return {field: int(value[field]) for field in sorted(fields)}


def _process_identity(process_id: int) -> Mapping[str, int] | None:
    try:
        raw = (Path("/proc") / str(process_id) / "stat").read_text(encoding="ascii")
    except FileNotFoundError:
        return None
    close = raw.rfind(")")
    fields = raw[close + 2 :].split() if close >= 0 else []
    _require(len(fields) >= 20, "live process identity is malformed")
    return {
        "process_id": process_id,
        "process_group_id": int(fields[2]),
        "session_id": int(fields[3]),
        "start_time_ticks": int(fields[19]),
    }


def _workspace_absent(workspace: Path) -> bool:
    try:
        workspace.lstat()
    except FileNotFoundError:
        return True
    return False


def _exact_identities_absent(identities: tuple[Mapping[str, int], ...]) -> bool:
    for expected in identities:
        observed = _process_identity(int(expected["process_id"]))
        if observed is None or observed["start_time_ticks"] != expected["start_time_ticks"]:
            continue
        _require(
            observed["process_group_id"] == expected["process_group_id"]
            and observed["session_id"] == expected["session_id"],
            "a retained Linux process identity changed",
        )
        return False
    return True


def run() -> Mapping[str, Any]:
    staging = Path.cwd().resolve(strict=True)
    request, _request_payload = _read(staging / "request.json", 64 * 1024)
    supervisor, _supervisor_payload = _read(staging / "supervisor.json", 4096)
    cleanup, cleanup_payload = _read(staging / "cleanup-proof.json", 2 * 1024 * 1024)
    workspace_name = request.get("workspace_name")
    _require(
        isinstance(workspace_name, str)
        and _WORKSPACE.fullmatch(workspace_name) is not None
        and supervisor.get("workspace_name") == workspace_name
        and cleanup.get("workspace_name") == workspace_name,
        "cleanup workspace identity is invalid",
    )
    _require(
        set(supervisor)
        == {
            "schema_version",
            "workspace_name",
            "process_id",
            "process_group_id",
            "session_id",
            "start_time_ticks",
        }
        and supervisor.get("schema_version") == "bluefire.cross-platform-linux-supervisor.v1",
        "cleanup supervisor identity is invalid",
    )
    supervisor_identity = _identity(
        {
            key: supervisor[key]
            for key in supervisor
            if key not in {"schema_version", "workspace_name"}
        },
        "supervisor identity",
    )
    _require(
        supervisor_identity["process_id"]
        == supervisor_identity["process_group_id"]
        == supervisor_identity["session_id"],
        "cleanup supervisor containment is invalid",
    )
    _require(
        set(cleanup)
        == {
            "schema_version",
            "workspace_name",
            "process_absent",
            "workspace_absent",
            "process_identities",
            "survivor_probes",
        }
        and cleanup.get("schema_version") == "bluefire.cross-platform-linux-cleanup.v1"
        and cleanup.get("process_absent") is True
        and cleanup.get("workspace_absent") is True
        and cleanup.get("survivor_probes")
        == [
            {"delay_ms": 0, "running": False},
            {"delay_ms": 100, "running": False},
            {"delay_ms": 250, "running": False},
        ]
        and cleanup_payload == _canonical(cleanup) + b"\n",
        "cleanup publication is invalid",
    )
    raw_identities = cleanup.get("process_identities")
    _require(
        isinstance(raw_identities, list) and 1 <= len(raw_identities) <= 65536,
        "cleanup identity inventory is invalid",
    )
    identities = tuple(_identity(item, "cleanup process identity") for item in raw_identities)
    _require(
        list(identities) == sorted(identities, key=lambda item: item["process_id"])
        and len({item["process_id"] for item in identities}) == len(identities)
        and supervisor_identity in identities,
        "cleanup identity inventory is invalid",
    )
    workspace = Path("/tmp") / workspace_name
    for delay_ms in _PROBES:
        if delay_ms:
            time.sleep(delay_ms / 1000)
        _require(_workspace_absent(workspace), "the exact Linux workspace survived cleanup")
        _require(
            _exact_identities_absent(identities),
            "an exact Linux process identity survived cleanup",
        )
    identity_material = {
        "schema_version": "bluefire.cross-platform-linux-cleanup-identities.v1",
        "workspace_name": workspace_name,
        "process_identities": list(identities),
    }
    source_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return {
        "schema_version": "bluefire.cross-platform-linux-cleanup-verification.v1",
        "workspace_name": workspace_name,
        "workspace_absent": True,
        "process_identities_absent": True,
        "process_identity_count": len(identities),
        "identity_material_sha256": "sha256:"
        + hashlib.sha256(_canonical(identity_material)).hexdigest(),
        "verifier_sha256": "sha256:" + source_digest,
        "probe_delays_ms": list(_PROBES),
    }


def main() -> int:
    if len(sys.argv) != 1:
        return 2
    try:
        result = run()
    except BaseException:
        return 1
    sys.stdout.write(_canonical(result).decode("utf-8") + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
