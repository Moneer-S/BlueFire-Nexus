"""Exact wheel validation and reconstruction for the Strix runtime closure."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import re
import stat
import zipfile
from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import default as email_policy
from pathlib import Path, PurePosixPath

from tools.strix_runtime_closure_common import (
    MAX_FILE_BYTES,
    MAX_TOTAL_BYTES,
    StrixRuntimeClosurePreparationError,
    _copy_payload,
    _digest_bytes,
    _normalized_distribution,
    _read_regular,
    _require_digest,
    _safe_relative,
)

MAX_WHEEL_MEMBERS = 100_000
_WHEEL_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]{0,254}$")
FORBIDDEN_NAMES = {"sitecustomize.py", "usercustomize.py"}
FORBIDDEN_PARTS = {
    ".aws",
    ".azure",
    ".config",
    ".docker",
    ".git",
    ".gnupg",
    ".kube",
    ".ssh",
    "__pycache__",
    "auth.json",
    "credentials",
    "docker.sock",
    "id_ed25519",
    "id_rsa",
    "shadow",
}


@dataclass(frozen=True, slots=True)
class WheelEntry:
    archive_path: str
    destination: str
    size: int
    digest: str


@dataclass(frozen=True, slots=True)
class WheelPlan:
    path: Path
    name: str
    normalized_name: str
    version: str
    wheel_digest: str
    metadata_digest: str
    record_digest: str
    requires_dist: tuple[str, ...]
    requires_python: str | None
    wheel_tags: tuple[str, ...]
    root_is_purelib: bool | None
    entries: tuple[WheelEntry, ...]


def _wheel_member_destination(path: PurePosixPath) -> str:
    parts = path.parts
    data_indexes = [index for index, part in enumerate(parts) if part.endswith(".data")]
    if not data_indexes:
        return path.as_posix()
    if len(data_indexes) != 1:
        raise StrixRuntimeClosurePreparationError("wheel data root is ambiguous")
    index = data_indexes[0]
    if index != 0 or len(parts) < 3 or parts[1] not in {"purelib", "platlib"}:
        raise StrixRuntimeClosurePreparationError(
            "wheel contains unsupported scripts, headers, or data"
        )
    return PurePosixPath(*parts[2:]).as_posix()


def _record_digest(value: str, payload: bytes, size: int, label: str) -> None:
    if not value.startswith("sha256="):
        raise StrixRuntimeClosurePreparationError(f"{label} RECORD hash is not SHA-256")
    encoded = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
    if value != f"sha256={encoded}" or str(size) != str(len(payload)):
        raise StrixRuntimeClosurePreparationError(f"{label} RECORD does not match member bytes")


def _plan_wheel(path: Path, expected_digest: str | None = None) -> WheelPlan:
    payload = _read_regular(path, MAX_FILE_BYTES, allow_empty=False)
    wheel_digest = _digest_bytes(payload)
    if (
        expected_digest is not None
        and wheel_digest != f"sha256:{_require_digest(expected_digest, 'wheel')}"
    ):
        raise StrixRuntimeClosurePreparationError("wheel digest differs from its receipt")
    try:
        archive = zipfile.ZipFile(io.BytesIO(payload))
    except zipfile.BadZipFile as exc:
        raise StrixRuntimeClosurePreparationError("wheel is not a valid ZIP archive") from exc
    with archive:
        members = archive.infolist()
        if not members or len(members) > MAX_WHEEL_MEMBERS:
            raise StrixRuntimeClosurePreparationError("wheel member count is invalid")
        files: dict[str, zipfile.ZipInfo] = {}
        casefolded: set[str] = set()
        expanded = 0
        for member in members:
            raw = member.filename.rstrip("/")
            member_path = _safe_relative(raw, "wheel member")
            folded = member_path.as_posix().casefold()
            if folded in casefolded:
                raise StrixRuntimeClosurePreparationError("wheel member identity is ambiguous")
            casefolded.add(folded)
            mode = (member.external_attr >> 16) & 0xFFFF
            kind = stat.S_IFMT(mode)
            if (
                member.flag_bits & 0x1
                or member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                or kind not in {0, stat.S_IFREG, stat.S_IFDIR}
            ):
                raise StrixRuntimeClosurePreparationError(
                    "wheel contains encrypted or special content"
                )
            expanded += member.file_size
            if member.file_size > MAX_FILE_BYTES or expanded > MAX_TOTAL_BYTES:
                raise StrixRuntimeClosurePreparationError(
                    "wheel expanded content exceeds its bound"
                )
            if not member.is_dir():
                files[member_path.as_posix()] = member
        metadata_names = [name for name in files if name.endswith(".dist-info/METADATA")]
        wheel_names = [name for name in files if name.endswith(".dist-info/WHEEL")]
        record_names = [name for name in files if name.endswith(".dist-info/RECORD")]
        if len(metadata_names) != 1 or len(wheel_names) != 1 or len(record_names) != 1:
            raise StrixRuntimeClosurePreparationError("wheel metadata set is ambiguous")
        dist_root = metadata_names[0].removesuffix("/METADATA")
        if (
            wheel_names[0].removesuffix("/WHEEL") != dist_root
            or record_names[0].removesuffix("/RECORD") != dist_root
        ):
            raise StrixRuntimeClosurePreparationError("wheel metadata roots disagree")
        metadata_payload = archive.read(metadata_names[0])
        wheel_payload = archive.read(wheel_names[0])
        record_payload = archive.read(record_names[0])
        metadata = BytesParser(policy=email_policy).parsebytes(metadata_payload)
        name = metadata.get("Name")
        version = metadata.get("Version")
        if (
            not isinstance(name, str)
            or not isinstance(version, str)
            or _WHEEL_SAFE.fullmatch(name) is None
            or _WHEEL_SAFE.fullmatch(version) is None
        ):
            raise StrixRuntimeClosurePreparationError("wheel name or version is invalid")
        wheel_metadata = BytesParser(policy=email_policy).parsebytes(wheel_payload)
        if wheel_metadata.get("Wheel-Version") is None:
            raise StrixRuntimeClosurePreparationError("wheel identity metadata is incomplete")
        root_is_purelib_value = wheel_metadata.get("Root-Is-Purelib")
        if root_is_purelib_value is None:
            root_is_purelib = None
        elif root_is_purelib_value.lower() == "true":
            root_is_purelib = True
        elif root_is_purelib_value.lower() == "false":
            root_is_purelib = False
        else:
            raise StrixRuntimeClosurePreparationError(
                "wheel purelib identity is invalid"
            )
        records: dict[str, tuple[str, str]] = {}
        try:
            for row in csv.reader(io.StringIO(record_payload.decode("utf-8"), newline="")):
                if len(row) != 3:
                    raise StrixRuntimeClosurePreparationError("wheel RECORD row is malformed")
                record_path = _safe_relative(row[0], "wheel RECORD").as_posix()
                if record_path in records:
                    raise StrixRuntimeClosurePreparationError(
                        "wheel RECORD contains duplicates"
                    )
                records[record_path] = (row[1], row[2])
        except (UnicodeDecodeError, csv.Error) as exc:
            raise StrixRuntimeClosurePreparationError("wheel RECORD cannot be parsed") from exc
        if set(records) != set(files):
            raise StrixRuntimeClosurePreparationError(
                "wheel RECORD does not cover every member"
            )
        entries: list[WheelEntry] = []
        destination_casefold: set[str] = set()
        for member_name in sorted(files):
            member_payload = archive.read(files[member_name])
            hash_value, size_value = records[member_name]
            if member_name == record_names[0]:
                if hash_value or size_value:
                    raise StrixRuntimeClosurePreparationError(
                        "wheel RECORD self-row must be empty"
                    )
            else:
                try:
                    recorded_size = int(size_value)
                except ValueError as exc:
                    raise StrixRuntimeClosurePreparationError(
                        "wheel RECORD size is invalid"
                    ) from exc
                _record_digest(hash_value, member_payload, recorded_size, member_name)
            destination = _wheel_member_destination(PurePosixPath(member_name))
            destination_path = _safe_relative(destination, "installed wheel member")
            if (
                destination_path.name in FORBIDDEN_NAMES
                or destination_path.suffix == ".pth"
                or any(part.casefold() in FORBIDDEN_PARTS for part in destination_path.parts)
                or destination_path.suffix in {".pyc", ".pyo"}
            ):
                raise StrixRuntimeClosurePreparationError(
                    "wheel contains an unsafe startup hook"
                )
            folded = destination_path.as_posix().casefold()
            if folded in destination_casefold:
                raise StrixRuntimeClosurePreparationError("wheel remap collides")
            destination_casefold.add(folded)
            entries.append(
                WheelEntry(
                    archive_path=member_name,
                    destination=destination_path.as_posix(),
                    size=len(member_payload),
                    digest=_digest_bytes(member_payload),
                )
            )
        return WheelPlan(
            path=path,
            name=name,
            normalized_name=_normalized_distribution(name),
            version=version,
            wheel_digest=wheel_digest,
            metadata_digest=_digest_bytes(metadata_payload),
            record_digest=_digest_bytes(record_payload),
            requires_dist=tuple(sorted(metadata.get_all("Requires-Dist", []))),
            requires_python=metadata.get("Requires-Python"),
            wheel_tags=tuple(sorted(wheel_metadata.get_all("Tag", []))),
            root_is_purelib=root_is_purelib,
            entries=tuple(entries),
        )


def _read_plan_member(plan: WheelPlan, suffix: str) -> bytes:
    matches = [entry for entry in plan.entries if entry.archive_path.endswith(suffix)]
    if len(matches) != 1:
        raise StrixRuntimeClosurePreparationError("wheel manifest member is ambiguous")
    payload = _read_regular(plan.path, MAX_FILE_BYTES, allow_empty=False)
    if _digest_bytes(payload) != plan.wheel_digest:
        raise StrixRuntimeClosurePreparationError("wheel changed before member read")
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        member_payload = archive.read(matches[0].archive_path)
    if _digest_bytes(member_payload) != matches[0].digest:
        raise StrixRuntimeClosurePreparationError("wheel manifest member digest drifted")
    return member_payload


def _install_wheel(
    plan: WheelPlan,
    site_packages: Path,
    *,
    destinations: dict[str, str],
    source_site_packages: Path | None,
) -> list[dict[str, object]]:
    payload = _read_regular(plan.path, MAX_FILE_BYTES, allow_empty=False)
    if _digest_bytes(payload) != plan.wheel_digest:
        raise StrixRuntimeClosurePreparationError(
            "wheel changed between planning and assembly"
        )
    installed: list[dict[str, object]] = []
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        for entry in plan.entries:
            member_payload = archive.read(entry.archive_path)
            if len(member_payload) != entry.size or _digest_bytes(member_payload) != entry.digest:
                raise StrixRuntimeClosurePreparationError(
                    "wheel member changed during extraction"
                )
            if (
                source_site_packages is not None
                and not entry.destination.endswith(".dist-info/RECORD")
            ):
                source = source_site_packages.joinpath(*PurePosixPath(entry.destination).parts)
                source_payload = _read_regular(source, MAX_FILE_BYTES)
                if source_payload != member_payload:
                    raise StrixRuntimeClosurePreparationError(
                        "qualified installed package differs from its exact wheel"
                    )
            relative = (
                PurePosixPath("runtime/lib/python3.12/site-packages")
                / PurePosixPath(entry.destination)
            ).as_posix()
            installed.append(
                _copy_payload(
                    site_packages.parents[3],
                    relative,
                    member_payload,
                    destinations=destinations,
                )
            )
    return installed
