from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import stat
import struct
import zipfile
from pathlib import Path
from typing import Any

import pytest

from bluefire import strix_worker_fixed_bootstrap as bootstrap
from bluefire import strix_worker_seccomp_bootstrap as lockdown
from tools import prepare_strix_linux_runtime_closure as closure
from tools.strix_runtime_closure_prepare_core import runtime_inventory_digest


def _record_hash(payload: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
    return f"sha256={encoded}"


def _wheel(
    path: Path,
    *,
    name: str = "demo-package",
    version: str = "1.2.3",
    files: dict[str, bytes] | None = None,
    platform_package: bool = False,
) -> bytes:
    normalized = name.replace("-", "_")
    dist_info = f"{normalized}-{version}.dist-info"
    package_root = (
        f"{normalized}-{version}.data/platlib/{normalized}"
        if platform_package
        else normalized
    )
    members = {
        f"{package_root}/__init__.py": b"VALUE = 1\n",
        f"{dist_info}/METADATA": (
            f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n\n"
        ).encode(),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            f"Root-Is-Purelib: {'false' if platform_package else 'true'}\n"
            "Tag: py3-none-any\n"
        ).encode(),
        **(files or {}),
    }
    record_name = f"{dist_info}/RECORD"
    rows = [
        (member, _record_hash(payload), str(len(payload)))
        for member, payload in sorted(members.items())
    ]
    rows.append((record_name, "", ""))
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerows(rows)
    members[record_name] = output.getvalue().encode()
    with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for member, payload in members.items():
            archive.writestr(member, payload)
    return path.read_bytes()


def _elf64(
    *,
    needed: tuple[str, ...] = ("libc.so.6",),
    runpath: str = "$ORIGIN/../lib",
    interpreter: str = "/lib64/ld-linux-x86-64.so.2",
) -> bytes:
    strings = bytearray(b"\x00")

    def add(value: str) -> int:
        offset = len(strings)
        strings.extend(value.encode("ascii") + b"\x00")
        return offset

    needed_offsets = [add(value) for value in needed]
    runpath_offset = add(runpath)
    program_offset = 64
    program_count = 3
    interpreter_offset = 0x100
    string_offset = 0x200
    dynamic_offset = 0x300
    virtual_base = 0x400000
    dynamic_rows = [(5, virtual_base + string_offset), (10, len(strings))]
    dynamic_rows.extend((1, value) for value in needed_offsets)
    dynamic_rows.extend(((29, runpath_offset), (0, 0)))
    dynamic = b"".join(struct.pack("<qQ", *row) for row in dynamic_rows)
    total = dynamic_offset + len(dynamic)
    payload = bytearray(total)
    identity = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        payload,
        0,
        identity,
        3,
        62,
        1,
        0,
        program_offset,
        0,
        0,
        64,
        56,
        program_count,
        0,
        0,
        0,
    )
    struct.pack_into(
        "<IIQQQQQQ", payload, program_offset, 1, 5, 0, virtual_base, 0, total, total, 0x1000
    )
    encoded_interpreter = interpreter.encode("ascii") + b"\x00"
    struct.pack_into(
        "<IIQQQQQQ",
        payload,
        program_offset + 56,
        3,
        4,
        interpreter_offset,
        0,
        0,
        len(encoded_interpreter),
        len(encoded_interpreter),
        1,
    )
    struct.pack_into(
        "<IIQQQQQQ",
        payload,
        program_offset + 112,
        2,
        4,
        dynamic_offset,
        virtual_base + dynamic_offset,
        0,
        len(dynamic),
        len(dynamic),
        8,
    )
    payload[interpreter_offset : interpreter_offset + len(encoded_interpreter)] = encoded_interpreter
    payload[string_offset : string_offset + len(strings)] = strings
    payload[dynamic_offset : dynamic_offset + len(dynamic)] = dynamic
    return bytes(payload)


def test_platform_wheel_maps_only_platlib_into_site_packages(tmp_path: Path) -> None:
    wheel = tmp_path / "bluefire_nexus-3.0-py3-none-any.whl"
    payload = _wheel(
        wheel,
        name="bluefire-nexus",
        version="3.0",
        platform_package=True,
    )
    plan = closure._plan_wheel(wheel, hashlib.sha256(payload).hexdigest())
    destinations = {entry.destination for entry in plan.entries}
    assert "bluefire_nexus/__init__.py" in destinations
    assert not any(".data/" in destination for destination in destinations)
    assert plan.record_digest.startswith("sha256:")


def test_wheel_rejects_unrecorded_and_script_content(tmp_path: Path) -> None:
    scripted = tmp_path / "demo_package-1.2.3-py3-none-any.whl"
    _wheel(
        scripted,
        files={"demo_package-1.2.3.data/scripts/demo": b"#!/bin/sh\n"},
    )
    with pytest.raises(
        closure.StrixRuntimeClosurePreparationError,
        match="unsupported scripts",
    ):
        closure._plan_wheel(scripted)

    broken = tmp_path / "broken_package-1.2.3-py3-none-any.whl"
    payload = _wheel(broken, name="broken-package")
    source = io.BytesIO(payload)
    rewritten = tmp_path / "rewritten.whl"
    with zipfile.ZipFile(source) as archive, zipfile.ZipFile(rewritten, "x") as output:
        for member in archive.infolist():
            data = archive.read(member)
            if member.filename.endswith("/__init__.py"):
                data = b"TAMPERED = True\n"
            output.writestr(member, data)
    with pytest.raises(
        closure.StrixRuntimeClosurePreparationError,
        match="RECORD does not match",
    ):
        closure._plan_wheel(rewritten)


def test_wheel_rejects_traversal_links_and_startup_hooks(tmp_path: Path) -> None:
    traversal = tmp_path / "traversal.whl"
    with zipfile.ZipFile(traversal, "x") as archive:
        archive.writestr("../escape", b"no")
    with pytest.raises(closure.StrixRuntimeClosurePreparationError, match="path is unsafe"):
        closure._plan_wheel(traversal)

    linked = tmp_path / "linked.whl"
    with zipfile.ZipFile(linked, "x") as archive:
        info = zipfile.ZipInfo("linked")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "target")
    with pytest.raises(closure.StrixRuntimeClosurePreparationError, match="special content"):
        closure._plan_wheel(linked)

    hooked = tmp_path / "hooked_package-1.2.3-py3-none-any.whl"
    _wheel(hooked, name="hooked-package", files={"sitecustomize.py": b"raise SystemExit\n"})
    with pytest.raises(closure.StrixRuntimeClosurePreparationError, match="startup hook"):
        closure._plan_wheel(hooked)


def test_elf_parser_accepts_exact_loader_needed_and_origin_path() -> None:
    identity = closure._elf_identity(_elf64(needed=("libpython3.12.so.1.0", "libc.so.6")))
    assert identity == closure.ElfIdentity(
        interpreter="/lib64/ld-linux-x86-64.so.2",
        needed=("libpython3.12.so.1.0", "libc.so.6"),
        runpaths=("$ORIGIN/../lib",),
    )


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"needed": ("../libc.so.6",)}, "dependency name"),
        ({"runpath": "/usr/lib"}, "not origin-relative"),
        ({"interpreter": "/lib/evil-loader.so"}, "outside the fixed profile"),
    ],
)
def test_elf_parser_rejects_unsafe_identity(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(closure.StrixRuntimeClosurePreparationError, match=message):
        closure._elf_identity(_elf64(**changes))


def test_elf_parser_rejects_header_and_segment_bounds() -> None:
    invalid_class = bytearray(_elf64())
    invalid_class[4] = 1
    with pytest.raises(closure.StrixRuntimeClosurePreparationError, match="unsupported ELF"):
        closure._elf_identity(bytes(invalid_class))

    invalid_segment = bytearray(_elf64())
    struct.pack_into("Q", invalid_segment, 64 + 32, len(invalid_segment) + 1)
    with pytest.raises(closure.StrixRuntimeClosurePreparationError, match="outside file bounds"):
        closure._elf_identity(bytes(invalid_segment))


def test_copy_payload_is_exclusive_standalone_and_immutable(tmp_path: Path) -> None:
    root = tmp_path / closure.ROOT_NAME
    root.mkdir()
    destinations: dict[str, str] = {}
    row = closure._copy_payload(
        root,
        "runtime/lib/example.py",
        b"VALUE = 1\n",
        destinations=destinations,
    )
    output = root / "runtime/lib/example.py"
    assert row["content_digest"] == "sha256:" + hashlib.sha256(b"VALUE = 1\n").hexdigest()
    assert output.stat().st_nlink == 1
    if stat.S_IMODE(output.stat().st_mode):
        assert stat.S_IMODE(output.stat().st_mode) & 0o222 == 0
    with pytest.raises(closure.StrixRuntimeClosurePreparationError, match="collides"):
        closure._copy_payload(
            root,
            "RUNTIME/lib/example.py",
            b"different",
            destinations=destinations,
        )


def test_runtime_inventory_digest_changes_with_non_bootstrap_file(tmp_path: Path) -> None:
    root = tmp_path / closure.ROOT_NAME
    root.mkdir()
    closure._copy_payload(
        root,
        "runtime/lib/example.py",
        b"VALUE = 1\n",
        destinations={},
    )
    runtime = root / "runtime"
    library = runtime / "lib"
    library.chmod(0o555)
    runtime.chmod(0o555)
    source = library / "example.py"
    try:
        original = runtime_inventory_digest(root)
        source.chmod(0o644)
        source.write_bytes(b"VALUE = 2\n")
        source.chmod(0o444)
        assert runtime_inventory_digest(root) != original
    finally:
        library.chmod(0o700)
        runtime.chmod(0o700)


def test_bootstrap_and_policy_sources_are_exact_and_site_independent() -> None:
    bootstrap_payload = Path(bootstrap.__file__).read_bytes()
    lockdown_payload = Path(lockdown.__file__).read_bytes()
    assert bootstrap.LOCKDOWN_SOURCE_DIGEST == (
        "sha256:" + hashlib.sha256(lockdown_payload).hexdigest()
    )
    assert bootstrap.POLICY_DIGEST == lockdown.POLICY_DIGEST
    assert b"sys.path.append(RUNTIME_SITE_PACKAGES)" in bootstrap_payload
    assert b"def arm(" in lockdown_payload
    assert closure.PRIVATE_DIRECTORIES == tuple(sorted(set(closure.PRIVATE_DIRECTORIES)))
    assert "workspace" in closure.PRIVATE_MOUNTPOINTS


def test_prep_contract_has_no_circular_startup_or_tls_claim() -> None:
    source = Path(closure.__file__).read_text(encoding="utf-8")
    assert "startup_qualification_ref" not in source
    assert "ca_bundle" not in source
    assert "runtime/share" not in source
    assert '"-S"' in source
    assert '"/bootstrap/worker.py"' in source


def test_manifest_serialization_is_canonical_and_path_redacted() -> None:
    document = {
        "schema_version": closure.PREPARATION_SCHEMA,
        "source_paths_redacted": True,
        "closure": {"root_name": closure.ROOT_NAME},
    }
    first = closure._document_bytes(document)
    second = closure._document_bytes(json.loads(first))
    assert first == second
    assert first.endswith(b"\n")
    assert b"C:\\" not in first
    synthetic_home = b"/".join((b"", b"home", b"runner"))
    assert synthetic_home not in first
    assert closure._digest_bytes(first).startswith("sha256:")
