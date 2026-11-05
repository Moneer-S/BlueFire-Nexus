"""Fetch and reconstruct the reviewed Strix source before artifact download."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

from tools import build_strix_engine_candidate as candidate


def reconstruct_source(
    *, work_root: Path, source_root: Path, inherited_environment: dict[str, str]
) -> None:
    """Create one clean pinned source checkout with both reviewed overlays."""

    work = work_root.resolve(strict=False)
    source = source_root.resolve(strict=False)
    if work.exists() or source.exists() or source.parent != work:
        raise candidate.StrixCandidateBuildError(
            "source reconstruction requires a new work/source path"
        )
    work.mkdir(mode=0o700)
    succeeded = False
    try:
        environment = candidate.build_sanitized_environment(work, inherited_environment)
        candidate.clone_reviewed_source(source, environment)
        candidate.validate_source_checkout(source, environment)
        candidate.apply_reviewed_overlay(source, environment)
        candidate.apply_reviewed_startup_overlay(source, environment)
        succeeded = True
    finally:
        if not succeeded:
            shutil.rmtree(work, ignore_errors=False)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        reconstruct_source(
            work_root=args.work_root,
            source_root=args.source_root,
            inherited_environment=dict(os.environ),
        )
    except (OSError, ValueError) as exc:
        print(f"Strix source reconstruction refused: {exc}", file=sys.stderr)
        return 2
    print("Reconstructed the exact reviewed Strix source and two overlays.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
