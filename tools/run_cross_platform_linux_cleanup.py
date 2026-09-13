"""Fixed no-argument fail-closed cleanup for the Gate 11 WSL process group."""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import stat
import sys
import time
from pathlib import Path
from typing import Any, Mapping, cast

_WORKSPACE = re.compile(r"^bluefire-gate11-[0-9a-f]{16}$")


class CleanupError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CleanupError(message)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return cast(Mapping[str, Any], value)


def _payload(path: Path, maximum: int, *, minimum: int = 1) -> bytes:
    before = path.lstat()
    _require(
        stat.S_ISREG(before.st_mode)
        and not stat.S_ISLNK(before.st_mode)
        and before.st_nlink == 1
        and minimum <= before.st_size <= maximum,
        "unsafe control file",
    )
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        _require(
            stat.S_ISREG(opened.st_mode)
            and opened.st_nlink == 1
            and (opened.st_dev, opened.st_ino, opened.st_size)
            == (before.st_dev, before.st_ino, before.st_size),
            "control file identity changed",
        )
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(maximum + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = path.lstat()
    _require(
        len(payload) == opened.st_size
        and minimum <= len(payload) <= maximum
        and (after.st_dev, after.st_ino, after.st_size)
        == (opened.st_dev, opened.st_ino, opened.st_size)
        and (current.st_dev, current.st_ino, current.st_size)
        == (opened.st_dev, opened.st_ino, opened.st_size)
        and stat.S_ISREG(current.st_mode)
        and not stat.S_ISLNK(current.st_mode)
        and current.st_nlink == 1,
        "control file changed during reading",
    )
    return payload


def _read(path: Path, maximum: int) -> Mapping[str, Any]:
    payload = _payload(path, maximum)
    value = json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_object)
    _require(isinstance(value, Mapping), "invalid control document")
    return value


def _ready(path: Path) -> bool:
    try:
        payload = _payload(path, 0, minimum=0)
    except FileNotFoundError:
        return False
    _require(not payload, "invalid supervisor ready marker")
    return True


def _process_row(pid: int) -> Mapping[str, Any] | None:
    try:
        raw = (Path("/proc") / str(pid) / "stat").read_text(encoding="ascii")
    except FileNotFoundError:
        return None
    close = raw.rfind(")")
    fields = raw[close + 2 :].split() if close >= 0 else []
    _require(len(fields) >= 20, "process identity is malformed")
    return {
        "state": fields[0],
        "parent_process_id": int(fields[1]),
        "process_group_id": int(fields[2]),
        "session_id": int(fields[3]),
        "start_time_ticks": int(fields[19]),
    }


def _scoped_processes(
    record: Mapping[str, Any] | None,
    staging: Path,
    workspace: Path,
) -> tuple[Mapping[str, int], ...]:
    snapshot: dict[int, tuple[Mapping[str, Any], bytes, int]] = {}
    entries = [path for path in Path("/proc").iterdir() if path.name.isdigit()]
    _require(len(entries) <= 65536, "the Linux process scan exceeded its bound")
    for entry in entries:
        pid = int(entry.name)
        try:
            row = _process_row(pid)
            if row is None:
                continue
            command = (entry / "cmdline").read_bytes()
            owner = entry.stat().st_uid
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        snapshot[pid] = row, command, owner

    descendants: set[int] = set()
    if record is not None:
        descendants.add(int(record["process_id"]))
        changed = True
        while changed:
            changed = False
            for pid, (row, _command, _owner) in snapshot.items():
                if pid not in descendants and int(row["parent_process_id"]) in descendants:
                    descendants.add(pid)
                    changed = True

    members: list[Mapping[str, int]] = []
    allowed = (os.fsencode(staging / "worker.py"), os.fsencode(workspace))
    for pid, (row, command, owner) in snapshot.items():
        supervisor_member = bool(
            record is not None
            and row["process_group_id"] == record["process_group_id"]
            and row["session_id"] == record["session_id"]
        )
        path_bound = any(token in command for token in allowed)
        lineage_bound = pid in descendants
        if not supervisor_member and not path_bound and not lineage_bound:
            continue
        _require(owner == os.getuid(), "a foreign process entered the Linux runtime")
        if record is not None and not path_bound:
            _require(
                row["start_time_ticks"] >= record["start_time_ticks"],
                "a pre-existing process collided with the Linux runtime identity",
            )
        if record is not None and pid == record["process_id"]:
            _require(
                row["start_time_ticks"] == record["start_time_ticks"],
                "the Linux supervisor process identity was reused",
            )
        members.append(
            {
                "process_id": pid,
                "process_group_id": int(row["process_group_id"]),
                "session_id": int(row["session_id"]),
                "start_time_ticks": int(row["start_time_ticks"]),
            }
        )
    return tuple(sorted(members, key=lambda item: item["process_id"]))


def _signal_processes(members: tuple[Mapping[str, int], ...], signal_number: int) -> None:
    pidfd_open = getattr(os, "pidfd_open", None)
    pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
    _require(
        callable(pidfd_open) and callable(pidfd_send_signal),
        "identity-bound Linux process signalling is unavailable",
    )
    for member in reversed(members):
        process_id = int(member["process_id"])
        try:
            descriptor = pidfd_open(process_id, 0)
        except ProcessLookupError:
            continue
        try:
            current = _process_row(process_id)
            if current is None:
                continue
            _require(
                int(current["start_time_ticks"]) == int(member["start_time_ticks"]),
                "a Linux process identity changed before cleanup",
            )
            pidfd_send_signal(descriptor, signal_number, None, 0)
        except ProcessLookupError:
            pass
        finally:
            os.close(descriptor)


def _identity_processes(
    members: tuple[Mapping[str, int], ...],
) -> tuple[Mapping[str, int], ...]:
    live: list[Mapping[str, int]] = []
    for member in members:
        process_id = int(member["process_id"])
        row = _process_row(process_id)
        if row is None:
            continue
        _require(
            int(row["start_time_ticks"]) == int(member["start_time_ticks"]),
            "a retained Linux process identity was reused",
        )
        live.append(member)
    return tuple(live)


def _merge_processes(
    *groups: tuple[Mapping[str, int], ...],
) -> tuple[Mapping[str, int], ...]:
    merged: dict[int, Mapping[str, int]] = {}
    for group in groups:
        for member in group:
            process_id = int(member["process_id"])
            prior = merged.get(process_id)
            _require(
                prior is None or int(prior["start_time_ticks"]) == int(member["start_time_ticks"]),
                "a Linux process identity collided during cleanup",
            )
            merged[process_id] = member
    return tuple(merged[key] for key in sorted(merged))


def _terminate_scope(
    record: Mapping[str, Any] | None,
    staging: Path,
    workspace: Path,
) -> tuple[list[Mapping[str, Any]], tuple[Mapping[str, int], ...]]:
    retained = (
        (
            {
                "process_id": int(record["process_id"]),
                "process_group_id": int(record["process_group_id"]),
                "session_id": int(record["session_id"]),
                "start_time_ticks": int(record["start_time_ticks"]),
            },
        )
        if record is not None
        else ()
    )
    known = _merge_processes(retained, _scoped_processes(record, staging, workspace))
    if known:
        _signal_processes(known, signal.SIGTERM)
    deadline = time.monotonic() + 5
    current = known
    while time.monotonic() < deadline:
        scoped = _scoped_processes(record, staging, workspace)
        current = _merge_processes(_identity_processes(known), scoped)
        known = _merge_processes(known, current)
        if not current:
            break
        time.sleep(0.025)
    if current:
        _signal_processes(current, signal.SIGKILL)
    probes: list[Mapping[str, Any]] = []
    for delay_ms in (0, 100, 250):
        if delay_ms:
            time.sleep(delay_ms / 1000)
        scoped = _scoped_processes(record, staging, workspace)
        current = _merge_processes(_identity_processes(known), scoped)
        known = _merge_processes(known, current)
        probes.append({"delay_ms": delay_ms, "running": bool(current)})
    _require(not any(item["running"] for item in probes), "Linux worker process survived")
    return probes, known


def _remove_workspace(workspace: Path) -> None:
    try:
        details = workspace.lstat()
    except FileNotFoundError:
        return
    _require(
        workspace.parent == Path("/tmp")
        and _WORKSPACE.fullmatch(workspace.name) is not None
        and stat.S_ISDIR(details.st_mode)
        and not stat.S_ISLNK(details.st_mode)
        and details.st_uid == os.getuid()
        and stat.S_IMODE(details.st_mode) == 0o700,
        "the Linux workspace ownership boundary changed",
    )
    shutil.rmtree(workspace)
    _require(not workspace.exists(), "the Linux workspace survived removal")


def _supervisor_record(staging: Path, workspace_name: str) -> Mapping[str, Any] | None:
    try:
        if not _ready(staging / "supervisor.ready"):
            return None
        record = _read(staging / "supervisor.json", 4096)
        fields = ("process_id", "process_group_id", "session_id", "start_time_ticks")
        _require(
            set(record)
            == {
                "schema_version",
                "workspace_name",
                *fields,
            }
            and record.get("schema_version") == "bluefire.cross-platform-linux-supervisor.v1"
            and record.get("workspace_name") == workspace_name
            and all(
                type(record.get(field)) is int and 0 < int(record[field]) < 2**63
                for field in fields
            )
            and record.get("process_id") == record.get("process_group_id")
            and record.get("process_id") == record.get("session_id"),
            "invalid Linux supervisor record",
        )
    except (OSError, UnicodeError, ValueError):
        return None
    return record


def run() -> Mapping[str, Any]:
    staging = Path.cwd().resolve(strict=True)
    request = _read(staging / "request.json", 64 * 1024)
    workspace_name = request.get("workspace_name")
    _require(
        isinstance(workspace_name, str) and _WORKSPACE.fullmatch(workspace_name) is not None,
        "invalid workspace identity",
    )
    workspace = Path("/tmp") / workspace_name
    probes: list[Mapping[str, Any]]
    identities: tuple[Mapping[str, int], ...]
    record = _supervisor_record(staging, workspace_name)
    if record is not None:
        probes, identities = _terminate_scope(record, staging, workspace)
    else:
        probes, identities = _terminate_scope(None, staging, workspace)
    _remove_workspace(workspace)
    return {
        "schema_version": "bluefire.cross-platform-linux-cleanup.v1",
        "workspace_name": workspace_name,
        "process_absent": True,
        "workspace_absent": True,
        "process_identities": list(identities),
        "survivor_probes": probes,
    }


def main() -> int:
    if len(sys.argv) != 1:
        return 2
    try:
        result = run()
    except BaseException:
        return 1
    sys.stdout.write(json.dumps(result, separators=(",", ":"), sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
