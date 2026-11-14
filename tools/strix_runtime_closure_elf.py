"""Bounded ELF dependency closure without executing target bytes."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Sequence

from tools.strix_runtime_closure_common import (
    StrixRuntimeClosurePreparationError,
    _copy_payload,
    _digest_bytes,
    _read_regular,
)

ELF_SCHEMA = "bluefire.strix-linux-runtime-elf-dependencies.v1"
LOADER_DESTINATION = "lib64/ld-linux-x86-64.so.2"
MAX_ELF_PROGRAM_HEADERS = 128
MAX_ELF_DYNAMIC_ENTRIES = 4096
MAX_ELF_NEEDED = 256


@dataclass(frozen=True, slots=True)
class ElfIdentity:
    interpreter: str | None
    needed: tuple[str, ...]
    runpaths: tuple[str, ...]


def _elf_identity(payload: bytes) -> ElfIdentity | None:
    if not payload.startswith(b"\x7fELF"):
        return None
    if len(payload) < 64 or payload[4:7] != b"\x02\x01\x01":
        raise StrixRuntimeClosurePreparationError(
            "runtime contains unsupported ELF identity"
        )
    try:
        (
            _identity,
            elf_type,
            machine,
            version,
            _entry,
            program_offset,
            _section_offset,
            _flags,
            header_size,
            program_size,
            program_count,
            _section_size,
            _section_count,
            _section_names,
        ) = struct.unpack_from("<16sHHIQQQIHHHHHH", payload, 0)
    except struct.error as exc:
        raise StrixRuntimeClosurePreparationError("ELF header is truncated") from exc
    if (
        elf_type not in {2, 3}
        or machine != 62
        or version != 1
        or header_size != 64
        or program_size != 56
        or not 1 <= program_count <= MAX_ELF_PROGRAM_HEADERS
        or program_offset > len(payload)
        or program_count * program_size > len(payload) - program_offset
    ):
        raise StrixRuntimeClosurePreparationError(
            "ELF header is outside the reviewed profile"
        )
    loads: list[tuple[int, int, int]] = []
    dynamics: list[tuple[int, int]] = []
    interpreters: list[str] = []
    for index in range(program_count):
        offset = program_offset + index * program_size
        try:
            (
                kind,
                _flags,
                file_offset,
                virtual,
                _physical,
                file_size,
                memory_size,
                _align,
            ) = struct.unpack_from("<IIQQQQQQ", payload, offset)
        except struct.error as exc:
            raise StrixRuntimeClosurePreparationError(
                "ELF program header is truncated"
            ) from exc
        if (
            file_offset > len(payload)
            or file_size > len(payload) - file_offset
            or file_size > memory_size
        ):
            raise StrixRuntimeClosurePreparationError(
                "ELF segment is outside file bounds"
            )
        if kind == 1:
            loads.append((virtual, file_offset, file_size))
        elif kind == 2:
            dynamics.append((file_offset, file_size))
        elif kind == 3:
            raw = payload[file_offset : file_offset + file_size]
            if not raw.endswith(b"\x00") or raw.count(b"\x00") != 1:
                raise StrixRuntimeClosurePreparationError("ELF interpreter is invalid")
            try:
                interpreters.append(raw[:-1].decode("ascii"))
            except UnicodeDecodeError as exc:
                raise StrixRuntimeClosurePreparationError(
                    "ELF interpreter is not ASCII"
                ) from exc
    if tuple(interpreters) not in {(), ("/lib64/ld-linux-x86-64.so.2",)}:
        raise StrixRuntimeClosurePreparationError(
            "ELF interpreter is outside the fixed profile"
        )
    if len(dynamics) > 1:
        raise StrixRuntimeClosurePreparationError("ELF dynamic table is ambiguous")
    if not dynamics:
        return ElfIdentity(interpreters[0] if interpreters else None, (), ())
    dynamic_offset, dynamic_size = dynamics[0]
    if dynamic_size % 16 or dynamic_size // 16 > MAX_ELF_DYNAMIC_ENTRIES:
        raise StrixRuntimeClosurePreparationError("ELF dynamic table is invalid")
    values: list[tuple[int, int]] = []
    terminated = False
    for offset in range(dynamic_offset, dynamic_offset + dynamic_size, 16):
        tag, value = struct.unpack_from("<qQ", payload, offset)
        if tag == 0:
            terminated = True
            break
        values.append((tag, value))
    if not terminated:
        raise StrixRuntimeClosurePreparationError("ELF dynamic table is unterminated")
    string_addresses = [value for tag, value in values if tag == 5]
    string_sizes = [value for tag, value in values if tag == 10]
    if (
        len(string_addresses) != 1
        or len(string_sizes) != 1
        or string_sizes[0] > 16 * 1024 * 1024
    ):
        raise StrixRuntimeClosurePreparationError("ELF string table identity is invalid")
    string_address, string_size = string_addresses[0], string_sizes[0]
    mappings = [
        file_offset + (string_address - virtual)
        for virtual, file_offset, file_size in loads
        if virtual <= string_address
        and string_size <= file_size - (string_address - virtual)
    ]
    if (
        len(mappings) != 1
        or mappings[0] > len(payload)
        or string_size > len(payload) - mappings[0]
    ):
        raise StrixRuntimeClosurePreparationError(
            "ELF string table cannot be mapped uniquely"
        )
    strings = payload[mappings[0] : mappings[0] + string_size]

    def text(offset: int) -> str:
        if offset >= len(strings):
            raise StrixRuntimeClosurePreparationError("ELF string offset is invalid")
        end = strings.find(b"\x00", offset)
        if end < 0:
            raise StrixRuntimeClosurePreparationError("ELF string is unterminated")
        try:
            return strings[offset:end].decode("ascii")
        except UnicodeDecodeError as exc:
            raise StrixRuntimeClosurePreparationError("ELF string is not ASCII") from exc

    needed = tuple(text(value) for tag, value in values if tag == 1)
    safe = __import__("re").compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]{0,254}$")
    if len(needed) > MAX_ELF_NEEDED or any(safe.fullmatch(item) is None for item in needed):
        raise StrixRuntimeClosurePreparationError("ELF dependency name is unsafe")
    runpath_values = [text(value) for tag, value in values if tag in {15, 29}]
    if len(runpath_values) > 1:
        raise StrixRuntimeClosurePreparationError("ELF search path is ambiguous")
    runpaths: tuple[str, ...] = ()
    if runpath_values:
        items = runpath_values[0].split(":")
        if any(
            not item or (item != "$ORIGIN" and not item.startswith("$ORIGIN/"))
            for item in items
        ):
            raise StrixRuntimeClosurePreparationError(
                "ELF search path is not origin-relative"
            )
        runpaths = tuple(items)
    return ElfIdentity(interpreters[0] if interpreters else None, needed, runpaths)


def _lexical_join(base: PurePosixPath, suffix: str) -> PurePosixPath:
    parts: list[str] = list(base.parts)
    for part in PurePosixPath(suffix).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                raise StrixRuntimeClosurePreparationError(
                    "ELF origin path escapes closure"
                )
            parts.pop()
        else:
            parts.append(part)
    if not parts:
        raise StrixRuntimeClosurePreparationError(
            "ELF origin path resolves to closure root"
        )
    return PurePosixPath(*parts)


def _close_elf_dependencies(
    root: Path,
    *,
    base_library_root: Path,
    system_library_roots: Sequence[Path],
    loader_source: Path,
    destinations: dict[str, str],
) -> dict[str, Any]:
    allowed_sources = (base_library_root, loader_source.parent, *system_library_roots)
    loader_payload = _read_regular(
        loader_source,
        allow_empty=False,
        allow_symlink=True,
        allowed_roots=allowed_sources,
    )
    loader_row = _copy_payload(
        root,
        LOADER_DESTINATION,
        loader_payload,
        mode=0o555,
        destinations=destinations,
    )
    source_roots = tuple(path.resolve(strict=True) for path in system_library_roots)
    base_root = base_library_root.resolve(strict=True)
    objects: dict[str, dict[str, Any]] = {}
    pending: list[str] = []

    def add_elf_paths() -> None:
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix()
            if relative in objects or relative in pending:
                continue
            with path.open("rb") as handle:
                if handle.read(4) == b"\x7fELF":
                    pending.append(relative)

    add_elf_paths()
    while pending:
        relative = pending.pop(0)
        payload = _read_regular(root.joinpath(*PurePosixPath(relative).parts))
        identity = _elf_identity(payload)
        if identity is None:
            continue
        origin = PurePosixPath(relative).parent
        dependency_rows: list[dict[str, str]] = []
        for needed in identity.needed:
            staged_candidates: list[PurePosixPath] = []
            for runpath in identity.runpaths:
                suffix = runpath.removeprefix("$ORIGIN").lstrip("/")
                directory = _lexical_join(origin, suffix) if suffix else origin
                candidate_path = directory / needed
                if root.joinpath(*candidate_path.parts).is_file():
                    staged_candidates.append(candidate_path)
            for directory in (
                PurePosixPath("runtime/lib"),
                PurePosixPath("lib/x86_64-linux-gnu"),
                PurePosixPath("lib64"),
            ):
                candidate_path = directory / needed
                if root.joinpath(*candidate_path.parts).is_file():
                    staged_candidates.append(candidate_path)
            staged_unique = sorted({item.as_posix() for item in staged_candidates})
            if len(staged_unique) > 1:
                raise StrixRuntimeClosurePreparationError(
                    "ELF dependency resolves ambiguously"
                )
            if staged_unique:
                destination = staged_unique[0]
            else:
                source_candidates: list[tuple[Path, str]] = []
                base_candidate = base_root / needed
                if base_candidate.exists():
                    source_candidates.append((base_candidate, f"runtime/lib/{needed}"))
                for source_root in source_roots:
                    source_candidate = source_root / needed
                    if source_candidate.exists():
                        source_candidates.append(
                            (source_candidate, f"lib/x86_64-linux-gnu/{needed}")
                        )
                unique_sources: dict[tuple[int, int], tuple[Path, str]] = {}
                for source, destination_value in source_candidates:
                    resolved = source.resolve(strict=True)
                    details = resolved.stat()
                    unique_sources[(details.st_dev, details.st_ino)] = (
                        source,
                        destination_value,
                    )
                if len(unique_sources) != 1:
                    raise StrixRuntimeClosurePreparationError(
                        f"ELF dependency is unresolved or ambiguous: {needed}"
                    )
                source, destination = next(iter(unique_sources.values()))
                source_payload = _read_regular(
                    source,
                    allow_empty=False,
                    allow_symlink=True,
                    allowed_roots=(base_root, *source_roots),
                )
                _copy_payload(
                    root,
                    destination,
                    source_payload,
                    destinations=destinations,
                )
                add_elf_paths()
            dependency_payload = _read_regular(
                root.joinpath(*PurePosixPath(destination).parts), allow_empty=False
            )
            dependency_rows.append(
                {
                    "name": needed,
                    "destination": destination,
                    "content_digest": _digest_bytes(dependency_payload),
                }
            )
        objects[relative] = {
            "path": relative,
            "content_digest": _digest_bytes(payload),
            "interpreter": identity.interpreter,
            "needed": list(identity.needed),
            "runpaths": list(identity.runpaths),
            "resolved_dependencies": dependency_rows,
        }
    return {
        "schema_version": ELF_SCHEMA,
        "parser": {
            "implementation": "bounded-stdlib-elf64-x86_64",
            "version": 1,
            "target_execution": False,
            "ldd_used": False,
        },
        "loader": loader_row,
        "objects": [objects[path] for path in sorted(objects)],
        "recursive_dt_needed_closed": True,
        "dlopen_only_resources_startup_qualified_separately": True,
        "source_paths_redacted": True,
    }
