"""Stage one verified Rust runner for a platform-specific BlueFire wheel.

This helper is intentionally explicit: release automation supplies the native
binary, target platform, and architecture, and the helper writes generated
package resources.  It never downloads or builds executable content.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import platform
import re
import secrets
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bluefire import __version__
from bluefire.runner_bootstrap import (
    MANIFEST_FILENAME,
    RunnerBootstrapError,
    RunnerPackageManifest,
    build_runner_manifest,
    validate_runner_inventory,
)
from bluefire.runner_client import RunnerTransportError, SubprocessRustRunner
from bluefire.util import canonical_json_bytes

_REPLACED_NAMES = frozenset({"bluefire-runner", "bluefire-runner.exe", MANIFEST_FILENAME})
_MAX_PRESERVED_ENTRIES = 4_096
_MAX_PRESERVED_BYTES = 256 * 1024 * 1024
_MAX_PRESERVED_DEPTH = 16
_SAFE_TRANSPORT_DIAGNOSTICS = frozenset(
    {
        "Linux exit identity is invalid",
        "Linux private process containment is unavailable",
        "Linux process was reaped before containment",
        "Linux unreaped process observation is unavailable",
        "Packaged runner watchdog is unavailable.",
        "Runner identity could not be verified.",
        "Runner process exit status is unavailable",
        "Runner process tree could not be stopped safely",
        "Runner process tree state could not be released",
        "Rust runner could not be started",
        "Rust runner exceeded the transport output limit",
        "Rust runner transport timed out",
        "Windows process containment is unavailable",
        "Windows process control is unavailable",
        "runner binary must be an existing absolute file",
        "runner inventory is not valid UTF-8 JSON",
        "runner inventory must be a JSON object",
        "runner transport bounds are invalid",
        "verified launch input is unavailable",
    }
)
_SAFE_UNEXPECTED_STATUS = re.compile(r"^Rust runner exited with unexpected status -?[0-9]+$")


@dataclass(frozen=True)
class _TreeEntry:
    relative: Path
    status: os.stat_result
    payload: bytes | None


def stage_native_runner(
    runner_binary: str | Path,
    output_root: str | Path,
    *,
    platform_name: str,
    architecture: str,
    product_version: str = __version__,
    inventory: Mapping[str, Any] | None = None,
) -> RunnerPackageManifest:
    """Verify and atomically stage an artifact and its strict manifest.

    The complete directory is published in one no-replace rename.  Keeping the
    temporary directory beside the destination makes that rename atomic and
    prevents a process that wins a late destination race from being replaced.
    """

    source = Path(runner_binary).expanduser()
    destination_root = Path(output_root).expanduser()
    try:
        if not source.is_absolute() or source.is_symlink() or not source.is_file():
            raise RunnerBootstrapError("The native runner staging input is invalid.")
        source = source.resolve(strict=True)
        destination_root.mkdir(parents=True, exist_ok=True)
        if destination_root.is_symlink():
            raise RunnerBootstrapError("The native runner staging location is unavailable.")
        destination_root = destination_root.resolve(strict=True)
        destination_identity = destination_root.stat(follow_symlinks=False)
        destination_parent = destination_root.parent
        destination_parent_identity = destination_parent.stat(follow_symlinks=False)
        destination_snapshot = _capture_tree(destination_root, destination_identity)
    except RunnerBootstrapError:
        raise
    except OSError as exc:
        raise RunnerBootstrapError("The native runner staging location is unavailable.") from exc

    source_manifest = build_runner_manifest(
        source,
        product_version=product_version,
        platform_name=platform_name,
        architecture=architecture,
    )

    publication_root, publication_identity = _create_publication_directory(
        destination_parent,
        destination_root.name,
    )
    artifact_temporary = publication_root / source_manifest.filename
    manifest_temporary = publication_root / MANIFEST_FILENAME
    reservation_root = destination_parent / (
        f".{destination_root.name}.bluefire-native-previous-{secrets.token_hex(16)}"
    )
    owned_files: dict[Path, os.stat_result] = {}
    owned_directories: dict[Path, os.stat_result] = {}
    published = False
    destination_claimed = False
    try:
        _copy_preserved_tree(
            publication_root,
            destination_snapshot,
            owned_files,
            owned_directories,
        )
        _copy_owned_file(source, artifact_temporary, owned_files)
        if os.name != "nt":
            os.chmod(artifact_temporary, 0o700)
        manifest = build_runner_manifest(
            artifact_temporary,
            product_version=product_version,
            platform_name=platform_name,
            architecture=architecture,
        )
        if manifest != source_manifest:
            raise RunnerBootstrapError("The staged native runner failed integrity verification.")
        observed_inventory = (
            inventory if inventory is not None else _probe_inventory(artifact_temporary)
        )
        validate_runner_inventory(observed_inventory, manifest)
        _write_owned_file(
            manifest_temporary,
            canonical_json_bytes(manifest.to_dict()) + b"\n",
            owned_files,
        )
        _sync_directory(publication_root)

        _require_unchanged_tree(
            destination_root,
            destination_identity,
            destination_snapshot,
        )
        _atomic_rename_no_replace(destination_root, reservation_root)
        destination_claimed = True
        _require_unchanged_tree(
            reservation_root,
            destination_identity,
            destination_snapshot,
        )
        _atomic_rename_no_replace(publication_root, destination_root)
        published = True
    except RunnerBootstrapError:
        raise
    except OSError as exc:
        raise RunnerBootstrapError("The native runner could not be staged safely.") from exc
    finally:
        if not published:
            _remove_owned_publication(
                publication_root,
                publication_identity,
                owned_files,
                owned_directories,
            )
            if destination_claimed:
                _restore_claimed_destination(
                    destination_root,
                    reservation_root,
                    destination_parent,
                    destination_parent_identity,
                    destination_identity,
                    destination_snapshot,
                )
        elif destination_claimed:
            if not _remove_snapshot_tree(
                reservation_root,
                destination_identity,
                destination_snapshot,
            ):
                raise RunnerBootstrapError(
                    "The superseded native runner tree could not be removed safely."
                )
    return manifest


def _create_publication_directory(
    parent: Path,
    destination_name: str,
) -> tuple[Path, os.stat_result]:
    publication_root: Path | None = None
    try:
        publication_root = Path(
            tempfile.mkdtemp(
                prefix=f".{destination_name}.bluefire-native-stage-",
                dir=parent,
            )
        )
        return publication_root, publication_root.stat(follow_symlinks=False)
    except OSError as exc:
        if publication_root is not None:
            try:
                publication_root.rmdir()
            except OSError:
                pass
        raise RunnerBootstrapError("The native runner could not be staged safely.") from exc


def _capture_tree(root: Path, expected_root: os.stat_result) -> tuple[_TreeEntry, ...]:
    entries: list[_TreeEntry] = []
    total_bytes = 0

    def walk(directory: Path, relative_root: Path, depth: int) -> None:
        nonlocal total_bytes
        if depth > _MAX_PRESERVED_DEPTH:
            raise OSError("the native resource tree is too deep")
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda item: item.name)
        for child in children:
            relative = relative_root / child.name
            child_path = Path(child.path)
            observed = child_path.stat(follow_symlinks=False)
            if stat.S_ISLNK(observed.st_mode):
                raise OSError("the native resource tree contains a link")
            if relative.parts[0] in _REPLACED_NAMES and (
                len(relative.parts) != 1 or not stat.S_ISREG(observed.st_mode)
            ):
                raise OSError("a generated native resource path is not a regular file")
            if stat.S_ISDIR(observed.st_mode):
                entries.append(_TreeEntry(relative, observed, None))
                walk(child_path, relative, depth + 1)
            elif stat.S_ISREG(observed.st_mode):
                payload, final_status = _read_exact_regular(child_path, observed)
                total_bytes += len(payload)
                if total_bytes > _MAX_PRESERVED_BYTES:
                    raise OSError("the native resource tree is too large")
                entries.append(_TreeEntry(relative, final_status, payload))
            else:
                raise OSError("the native resource tree contains a special file")
            if len(entries) > _MAX_PRESERVED_ENTRIES:
                raise OSError("the native resource tree contains too many entries")

    try:
        observed_root = root.stat(follow_symlinks=False)
        if (
            root.is_symlink()
            or not stat.S_ISDIR(observed_root.st_mode)
            or not os.path.samestat(observed_root, expected_root)
        ):
            raise OSError("the native resource root changed")
        walk(root, Path(), 0)
        final_root = root.stat(follow_symlinks=False)
        if not os.path.samestat(final_root, expected_root):
            raise OSError("the native resource root changed")
        return tuple(entries)
    except OSError as exc:
        raise RunnerBootstrapError(
            "The native runner staging destination is not a bounded regular tree."
        ) from exc


def _read_exact_regular(
    path: Path,
    expected: os.stat_result,
) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not _status_matches(before, expected):
            raise OSError("the native resource file changed")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            payload = handle.read(_MAX_PRESERVED_BYTES + 1)
            after = os.fstat(handle.fileno())
        if len(payload) > _MAX_PRESERVED_BYTES or not _status_matches(after, before):
            raise OSError("the native resource file changed")
        return payload, after
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _status_matches(observed: os.stat_result, expected: os.stat_result) -> bool:
    return (
        os.path.samestat(observed, expected)
        and observed.st_size == expected.st_size
        and observed.st_mtime_ns == expected.st_mtime_ns
        and observed.st_nlink == expected.st_nlink
        # Windows path and handle metadata can disagree on synthetic mode bits
        # and creation-time aliases for the same NTFS file identity.
        and (
            os.name == "nt"
            or (
                observed.st_mode == expected.st_mode
                and observed.st_ctime_ns == expected.st_ctime_ns
            )
        )
    )


def _copy_preserved_tree(
    publication_root: Path,
    snapshot: Sequence[_TreeEntry],
    owned_files: dict[Path, os.stat_result],
    owned_directories: dict[Path, os.stat_result],
) -> None:
    preserved = [entry for entry in snapshot if entry.relative.parts[0] not in _REPLACED_NAMES]
    for entry in preserved:
        destination = publication_root / entry.relative
        if entry.payload is None:
            destination.mkdir(mode=0o700)
            owned_directories[destination] = destination.stat(follow_symlinks=False)
        else:
            _write_owned_file(destination, entry.payload, owned_files)
            os.chmod(destination, stat.S_IMODE(entry.status.st_mode))
    for entry in reversed(preserved):
        if entry.payload is None:
            os.chmod(
                publication_root / entry.relative,
                stat.S_IMODE(entry.status.st_mode),
            )


def _copy_owned_file(
    source: Path,
    destination: Path,
    owned_files: dict[Path, os.stat_result],
) -> None:
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        owned_files[destination] = os.fstat(descriptor)
        with source.open("rb") as source_handle, os.fdopen(descriptor, "wb") as destination_handle:
            descriptor = -1
            identity = os.fstat(destination_handle.fileno())
            shutil.copyfileobj(source_handle, destination_handle)
            destination_handle.flush()
            os.fsync(destination_handle.fileno())
        owned_files[destination] = identity
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_owned_file(
    destination: Path,
    payload: bytes,
    owned_files: dict[Path, os.stat_result],
) -> None:
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        owned_files[destination] = os.fstat(descriptor)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _require_unchanged_tree(
    path: Path,
    expected_root: os.stat_result,
    expected_entries: Sequence[_TreeEntry],
) -> None:
    """Recheck every retained identity and byte before claiming the tree."""

    try:
        observed_entries = _capture_tree(path, expected_root)
        if len(observed_entries) != len(expected_entries) or any(
            observed.relative != expected.relative
            or observed.payload != expected.payload
            or not _status_matches(observed.status, expected.status)
            for observed, expected in zip(observed_entries, expected_entries, strict=True)
        ):
            raise OSError("the native resource tree changed")
    except (OSError, RunnerBootstrapError) as exc:
        raise RunnerBootstrapError(
            "The native runner staging destination changed during publication."
        ) from exc


def _atomic_rename_no_replace(source: Path, destination: Path) -> None:
    """Atomically rename ``source`` while refusing every existing destination."""

    if os.name == "nt":
        # Python maps os.rename to the non-replacing Windows move operation.
        os.rename(source, destination)
        return
    if sys.platform.startswith("linux"):
        _linux_rename_no_replace(source, destination)
        return
    if sys.platform == "darwin":
        _macos_rename_no_replace(source, destination)
        return
    raise OSError(errno.ENOTSUP, "Atomic no-replace publication is unavailable.")


def _linux_rename_no_replace(source: Path, destination: Path) -> None:
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError:
        _linux_rename_no_replace_syscall(libc, source, destination)
        return
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    at_fdcwd = -100
    rename_noreplace = 1
    if (
        renameat2(
            at_fdcwd,
            os.fsencode(source),
            at_fdcwd,
            os.fsencode(destination),
            rename_noreplace,
        )
        != 0
    ):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), destination)


def _linux_rename_no_replace_syscall(
    libc: Any,
    source: Path,
    destination: Path,
) -> None:
    import ctypes

    syscall_numbers = {"x86_64": 316, "amd64": 316, "aarch64": 276, "arm64": 276}
    number = syscall_numbers.get(platform.machine().lower())
    if number is None:
        raise OSError(errno.ENOTSUP, "renameat2 is unavailable.")
    syscall = libc.syscall
    syscall.restype = ctypes.c_long
    result = syscall(
        ctypes.c_long(number),
        ctypes.c_int(-100),
        ctypes.c_char_p(os.fsencode(source)),
        ctypes.c_int(-100),
        ctypes.c_char_p(os.fsencode(destination)),
        ctypes.c_uint(1),
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), destination)


def _macos_rename_no_replace(source: Path, destination: Path) -> None:
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renamex_np = libc.renamex_np
    except AttributeError as exc:
        raise OSError(errno.ENOTSUP, "renamex_np is unavailable.") from exc
    renamex_np.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
    renamex_np.restype = ctypes.c_int
    rename_excl = 0x00000004
    if renamex_np(os.fsencode(source), os.fsencode(destination), rename_excl) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), destination)


def _sync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _remove_owned_publication(
    publication_root: Path,
    expected: os.stat_result,
    owned_files: Mapping[Path, os.stat_result],
    owned_directories: Mapping[Path, os.stat_result],
) -> None:
    """Remove only our private files, retaining any foreign race content."""

    try:
        observed = publication_root.stat(follow_symlinks=False)
    except OSError:
        return
    if (
        publication_root.is_symlink()
        or not stat.S_ISDIR(observed.st_mode)
        or not os.path.samestat(observed, expected)
    ):
        return
    for path, expected_file in owned_files.items():
        try:
            observed_file = path.stat(follow_symlinks=False)
            if stat.S_ISREG(observed_file.st_mode) and os.path.samestat(
                observed_file, expected_file
            ):
                os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
                path.unlink()
        except OSError:
            pass
    for path, expected_directory in sorted(
        owned_directories.items(),
        key=lambda item: len(item[0].parts),
        reverse=True,
    ):
        try:
            observed_directory = path.stat(follow_symlinks=False)
            if stat.S_ISDIR(observed_directory.st_mode) and os.path.samestat(
                observed_directory, expected_directory
            ):
                os.chmod(path, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)
                path.rmdir()
        except OSError:
            pass
    try:
        publication_root.rmdir()
    except OSError:
        # A concurrent foreign entry is deliberately preserved.
        pass


def _restore_claimed_destination(
    destination: Path,
    reservation: Path,
    parent: Path,
    expected_parent: os.stat_result,
    expected_destination: os.stat_result,
    expected_entries: Sequence[_TreeEntry],
) -> None:
    """Restore the exact claimed directory without replacing a race winner."""

    try:
        observed_parent = parent.stat(follow_symlinks=False)
        observed_reservation = reservation.stat(follow_symlinks=False)
        if (
            parent.is_symlink()
            or not stat.S_ISDIR(observed_parent.st_mode)
            or not os.path.samestat(observed_parent, expected_parent)
            or not stat.S_ISDIR(observed_reservation.st_mode)
            or not os.path.samestat(observed_reservation, expected_destination)
        ):
            return
        _atomic_rename_no_replace(reservation, destination)
    except OSError:
        # A race winner at the destination is preserved.  The claimed tree can
        # only be removed when the original destination was provably empty.
        if not expected_entries:
            _remove_owned_empty_directory(reservation, expected_destination)


def _remove_snapshot_tree(
    path: Path,
    expected_root: os.stat_result,
    expected_entries: Sequence[_TreeEntry],
) -> bool:
    """Remove the exact superseded tree, never an entry introduced by a race."""

    try:
        _require_unchanged_tree(path, expected_root, expected_entries)
    except RunnerBootstrapError:
        return False
    for entry in reversed(expected_entries):
        target = path / entry.relative
        try:
            observed = target.stat(follow_symlinks=False)
            if entry.payload is None:
                if not stat.S_ISDIR(observed.st_mode) or not os.path.samestat(
                    observed, entry.status
                ):
                    return False
                os.chmod(target, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)
                target.rmdir()
            else:
                if not _status_matches(observed, entry.status):
                    return False
                os.chmod(target, stat.S_IREAD | stat.S_IWRITE)
                target.unlink()
        except OSError:
            return False
    try:
        observed_root = path.stat(follow_symlinks=False)
        if not os.path.samestat(observed_root, expected_root):
            return False
        path.rmdir()
    except OSError:
        return False
    return True


def _remove_owned_empty_directory(path: Path, expected: os.stat_result) -> None:
    try:
        observed = path.stat(follow_symlinks=False)
        if stat.S_ISDIR(observed.st_mode) and os.path.samestat(observed, expected):
            path.rmdir()
    except OSError:
        # Foreign content makes rmdir fail and is intentionally retained.
        pass


def _probe_inventory(binary: Path) -> Mapping[str, Any]:
    try:
        with tempfile.TemporaryDirectory(prefix="bluefire-native-stage-") as work_root:
            return SubprocessRustRunner(
                binary,
                work_root,
                timeout_seconds=10.0,
                output_limit_bytes=2 * 1024 * 1024,
            ).inventory()
    except RunnerTransportError as exc:
        detail = str(exc)
        if (
            detail not in _SAFE_TRANSPORT_DIAGNOSTICS
            and _SAFE_UNEXPECTED_STATUS.fullmatch(detail) is None
        ):
            detail = "runner transport failed without a safe diagnostic"
        raise RunnerBootstrapError(f"The native runner inventory probe failed: {detail}") from None
    except Exception:
        raise RunnerBootstrapError(
            "The native runner inventory probe failed without a safe diagnostic."
        ) from None


def _load_inventory(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RunnerBootstrapError("The supplied runner inventory is invalid.") from exc
    if not isinstance(value, Mapping):
        raise RunnerBootstrapError("The supplied runner inventory is invalid.")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--platform", required=True, choices=("windows", "linux", "macos"))
    parser.add_argument("--architecture", required=True, choices=("x86_64", "aarch64"))
    parser.add_argument("--product-version", default=__version__)
    parser.add_argument("--inventory-json", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        manifest = stage_native_runner(
            args.runner,
            args.output_root,
            platform_name=args.platform,
            architecture=args.architecture,
            product_version=args.product_version,
            inventory=(
                _load_inventory(args.inventory_json) if args.inventory_json is not None else None
            ),
        )
    except RunnerBootstrapError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(manifest.to_dict(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
