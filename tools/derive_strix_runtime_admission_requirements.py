"""Derive the frozen Strix dependency requirements before artifact download.

This controller-side step runs only the exact pinned ``uv export`` against the
reconstructed reviewed source. It does not import or execute Strix, resolve a
target or model, or consume any bytes from the preparation artifact.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

from tools import qualify_strix_runtime_admission as admission
from tools import qualify_strix_runtime_candidate as preparation


def derive_requirements(
    *,
    source_root: Path,
    work_root: Path,
    output_file: Path,
    inherited_environment: dict[str, str],
) -> dict[str, object]:
    """Export one exact hash-bound requirements file from the reviewed lock."""

    source = source_root.resolve(strict=True)
    work = work_root.resolve(strict=False)
    output = output_file.resolve(strict=False)
    if work.exists() or output.exists() or output.parent != work:
        raise admission.StrixRuntimeAdmissionQualificationError(
            "controller requirements paths must be new and fixed"
        )
    work.mkdir(mode=0o700)
    succeeded = False
    try:
        environment = admission._safe_environment(work / "controller")
        path_value = inherited_environment.get("PATH", "")
        if not path_value or any(
            not entry or not Path(entry).is_absolute() for entry in path_value.split(os.pathsep)
        ):
            raise admission.StrixRuntimeAdmissionQualificationError(
                "controller tool PATH is unavailable or contains a relative entry"
            )
        environment["PATH"] = path_value
        for name in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"):
            value = inherited_environment.get(name)
            if value:
                environment[name] = value
        receipt = preparation._export_requirements(source, output, environment)
        succeeded = True
        return receipt
    finally:
        controller = work / "controller"
        if controller.exists():
            shutil.rmtree(controller, ignore_errors=False)
        if not succeeded:
            shutil.rmtree(work, ignore_errors=False)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--output-file", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        receipt = derive_requirements(
            source_root=args.source_root,
            work_root=args.work_root,
            output_file=args.output_file,
            inherited_environment=dict(os.environ),
        )
    except (OSError, ValueError) as exc:
        print(f"Strix controller requirements derivation refused: {exc}", file=sys.stderr)
        return 2
    print(
        "Derived frozen Strix dependency requirements without using the preparation artifact: "
        f"{receipt['requirements_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
