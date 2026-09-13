"""Strict report and bundle primitives for GATE-03 validation."""

from __future__ import annotations

import hashlib
import json
import re
import stat
from pathlib import Path
from typing import Any, Mapping, Sequence, cast

from .util import content_hash

_MAX_REPORT_BYTES = 4 * 1024 * 1024
_MAX_RUNTIME_BYTES = 256 * 1024 * 1024
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


class DeepBehaviorGateValidationError(ValueError):
    """Persisted GATE-03 evidence is absent, unsafe, stale, or semantically false."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DeepBehaviorGateValidationError(message)


def _is_unsafe(details: Any) -> bool:
    return stat.S_ISLNK(details.st_mode) or bool(
        int(getattr(details, "st_file_attributes", 0)) & _REPARSE_POINT
    )


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        _require(key not in value, "a GATE-03 report contains duplicate keys")
        value[key] = item
    return value


def _read_report(root: Path, name: str) -> Mapping[str, Any]:
    path = root / name
    try:
        before = path.lstat()
        _require(
            stat.S_ISREG(before.st_mode)
            and not _is_unsafe(before)
            and before.st_nlink == 1
            and 1 <= before.st_size <= _MAX_REPORT_BYTES,
            f"{name} is not a safe bounded report",
        )
        payload = path.read_bytes()
        after = path.lstat()
    except DeepBehaviorGateValidationError:
        raise
    except OSError as exc:
        raise DeepBehaviorGateValidationError(f"{name} is unavailable") from exc

    def identity(row: Any) -> tuple[int, int, int, int, int]:
        return (
            int(row.st_dev),
            int(row.st_ino),
            int(row.st_size),
            int(row.st_mtime_ns),
            int(row.st_nlink),
        )

    _require(
        identity(before) == identity(after) and len(payload) == before.st_size,
        f"{name} changed while it was read",
    )
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _raw: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise DeepBehaviorGateValidationError(f"{name} is not strict UTF-8 JSON") from exc
    _require(isinstance(value, Mapping), f"{name} must contain one JSON object")
    canonical = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    _require(payload == canonical, f"{name} is not canonical GATE-03 JSON")
    return cast(Mapping[str, Any], value)


def _mapping(value: Any, keys: set[str], label: str) -> Mapping[str, Any]:
    _require(isinstance(value, Mapping) and set(value) == keys, f"{label} fields are not exact")
    return cast(Mapping[str, Any], value)


def _digest(value: Any, label: str) -> str:
    _require(isinstance(value, str) and _SHA256.fullmatch(value) is not None, f"{label} is invalid")
    return str(value)


def _run_reference(value: Any, label: str) -> Mapping[str, str]:
    row = _mapping(value, {"run_id", "path"}, label)
    run_id = row.get("run_id")
    _require(
        isinstance(run_id, str)
        and _RUN_ID.fullmatch(run_id) is not None
        and row.get("path") == f"runs/{run_id}",
        f"{label} is not canonical",
    )
    run_id = cast(str, run_id)
    return {"run_id": run_id, "path": str(row["path"])}


def _bundle_stats(bundle: Path) -> Mapping[str, int | bool]:
    files = 0
    total = 0
    for path in sorted(bundle.rglob("*"), key=lambda item: item.as_posix()):
        if not path.is_file():
            continue
        details = path.lstat()
        _require(
            stat.S_ISREG(details.st_mode) and not _is_unsafe(details) and details.st_nlink == 1,
            "a run bundle contains an unsafe file",
        )
        files += 1
        total += details.st_size
        _require(total <= _MAX_RUNTIME_BYTES, "run bundle evidence is unbounded")
    return {"passed": True, "files_scanned": files, "bytes_scanned": total}


def _runtime_inventory(bundle_paths: Sequence[Path]) -> Mapping[str, Any]:
    files = 0
    total = 0
    digests: list[str] = []
    for bundle in bundle_paths:
        root = bundle.resolve(strict=True)
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
            if not path.is_file():
                continue
            details = path.lstat()
            _require(
                stat.S_ISREG(details.st_mode)
                and not _is_unsafe(details)
                and details.st_nlink == 1
                and 0 < details.st_size <= _MAX_RUNTIME_BYTES,
                "a runtime scan artifact is unsafe",
            )
            payload = path.read_bytes()
            _require(len(payload) == details.st_size, "a runtime scan artifact changed")
            files += 1
            total += len(payload)
            _require(total <= _MAX_RUNTIME_BYTES, "runtime scan inventory is unbounded")
            digests.append(hashlib.sha256(payload).hexdigest())
    return {
        "files_scanned": files,
        "bytes_scanned": total,
        "artifact_digest_set_sha256": content_hash(sorted(digests)),
    }


__all__ = [
    "DeepBehaviorGateValidationError",
    "_RUN_ID",
    "_bundle_stats",
    "_digest",
    "_is_unsafe",
    "_mapping",
    "_read_report",
    "_require",
    "_run_reference",
    "_runtime_inventory",
    "_strict_object",
]
