"""Verify a prepared transfer and record its ref after process-boundary exit."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
from pathlib import Path

from bluefire import strix_runtime_transfer as transfer
from tools.package_strix_runtime_admission_input import _append_output

_LINE = re.compile(rb"bundle_ref=(sha256:[0-9a-f]{64})\n")


def record_bundle_ref(
    *,
    stage_root: Path,
    reference_file: Path,
    source_bundle: Path,
    trusted_bundle: Path,
    github_output: Path,
) -> str:
    """Copy verified bytes out of the isolated stage, clean it, then emit the ref."""

    stage = stage_root.resolve(strict=True)
    reference = Path(os.path.abspath(reference_file))
    source = Path(os.path.abspath(source_bundle))
    trusted = Path(os.path.abspath(trusted_bundle))
    github_output_path = Path(os.path.abspath(github_output))
    if (
        stage.name != "bluefire-strix-preparation-stage"
        or reference.parent != stage
        or source.parent != stage
        or trusted.parent != stage.parent
        or stage == github_output_path
        or stage in github_output_path.parents
        or trusted.exists()
        or trusted.is_symlink()
    ):
        raise transfer.StrixRuntimeTransferError("boundary staging paths are not fixed and new")
    completed = False
    primary_error: BaseException | None = None
    observed = ""
    try:
        expected_inventory = {
            "bluefire-strix-candidate-work",
            transfer.CANDIDATE_DIRECTORY,
            transfer.WORK_DIRECTORY,
            transfer.PREPARATION_DIRECTORY,
            reference.name,
            source.name,
        }
        if {path.name for path in stage.iterdir()} != expected_inventory:
            raise transfer.StrixRuntimeTransferError("boundary staging inventory is not exact")
        reference_handle, _reference_metadata = transfer._open_regular(reference, 256)
        with reference_handle:
            payload = reference_handle.read(257)
        matched = _LINE.fullmatch(payload)
        if matched is None:
            raise transfer.StrixRuntimeTransferError("boundary bundle reference is invalid")
        expected = matched.group(1).decode("ascii")

        digest = hashlib.sha256()
        source_handle, before = transfer._open_regular(source, transfer.MAX_BUNDLE_BYTES)
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            destination_descriptor = os.open(trusted, flags, 0o400)
        except BaseException:
            source_handle.close()
            raise
        try:
            with source_handle:
                while chunk := source_handle.read(1024 * 1024):
                    digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        count = os.write(destination_descriptor, view)
                        if count <= 0:
                            raise transfer.StrixRuntimeTransferError(
                                "trusted transfer copy could not be written"
                            )
                        view = view[count:]
                after = os.fstat(source_handle.fileno())
            os.fsync(destination_descriptor)
        finally:
            os.close(destination_descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise transfer.StrixRuntimeTransferError("boundary bundle changed during copy")
        observed = f"sha256:{digest.hexdigest()}"
        if observed != expected:
            raise transfer.StrixRuntimeTransferError("boundary bundle reference does not match")
        final_handle, final_metadata = transfer._open_regular(trusted, transfer.MAX_BUNDLE_BYTES)
        final_digest = hashlib.sha256()
        with final_handle:
            while chunk := final_handle.read(1024 * 1024):
                final_digest.update(chunk)
        if (
            not stat.S_ISREG(final_metadata.st_mode)
            or final_metadata.st_size != before.st_size
            or f"sha256:{final_digest.hexdigest()}" != observed
        ):
            raise transfer.StrixRuntimeTransferError("trusted transfer copy identity drifted")
        transfer._remove_root(stage)
        if stage.exists() or stage.is_symlink():
            raise transfer.StrixRuntimeTransferError("boundary staging tree remains")
        _append_output(github_output_path, observed)
        completed = True
        return observed
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        if not completed:
            cleanup_errors: list[str] = []
            try:
                transfer._remove_root(stage)
            except BaseException as exc:
                cleanup_errors.append(f"stage: {exc}")
            try:
                if trusted.is_symlink() or trusted.exists():
                    if not trusted.is_symlink():
                        os.chmod(trusted, 0o600)  # nosec B103
                    trusted.unlink()
            except BaseException as exc:
                cleanup_errors.append(f"trusted bundle: {exc}")
            if cleanup_errors:
                raise transfer.StrixRuntimeTransferError(
                    "boundary cleanup failed: " + "; ".join(cleanup_errors)
                ) from primary_error


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage-root", type=Path, required=True)
    parser.add_argument("--reference-file", type=Path, required=True)
    parser.add_argument("--source-bundle", type=Path, required=True)
    parser.add_argument("--trusted-bundle", type=Path, required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        reference = record_bundle_ref(
            stage_root=args.stage_root,
            reference_file=args.reference_file,
            source_bundle=args.source_bundle,
            trusted_bundle=args.trusted_bundle,
            github_output=args.github_output,
        )
    except (OSError, ValueError) as exc:
        print(f"Strix boundary bundle recording refused: {exc}", file=sys.stderr)
        return 2
    print(f"Recorded exact post-boundary Strix transfer ref: {reference}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
