"""Validate and package exact Strix preparation inputs for a fresh runner.

This packaging step never imports or executes Strix, starts its sidecar or
container, supplies a target, or contacts a model. The fresh admission job
must independently repeat every validation after transfer.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

from bluefire.strix_runtime_transfer import create_transfer_bundle
from tools import qualify_strix_runtime_admission as admission
from tools import qualify_strix_runtime_candidate as preparation


def package_input(
    *,
    candidate_root: Path,
    source_root: Path,
    preparation_root: Path,
    preparation_work_root: Path,
    output_file: Path,
    bluefire_source_revision: str,
    threat_review_ref: str,
    inherited_environment: dict[str, str],
) -> str:
    """Revalidate the first-job preparation and create one transfer tar."""

    controller = output_file.resolve(strict=False).parent / ".strix-transfer-controller"
    if controller.exists():
        raise admission.StrixRuntimeAdmissionQualificationError(
            "transfer controller work root already exists"
        )
    controller.mkdir(mode=0o700)
    try:
        environment = admission._safe_environment(controller)
        environment.update(
            {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "safe.directory",
                "GIT_CONFIG_VALUE_0": os.fspath(source_root.resolve(strict=True)),
            }
        )
        for name in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"):
            value = inherited_environment.get(name)
            if value:
                environment[name] = value
        identity = preparation.validate_candidate(
            candidate_root,
            source_root,
            bluefire_source_revision,
            environment,
        )
        _prep, runtime, _refs = admission._validate_preparation(
            preparation_root.resolve(strict=True),
            revision=bluefire_source_revision,
            candidate_identity=identity,
        )
        inspected = admission._inspect_runtime(
            (preparation_work_root / "runtime").resolve(strict=True),
            runtime,
            prompt_sha256=str(identity["prompt_sha256"]),
        )
        if inspected.get("imported") is not False or inspected.get("executed") is not False:
            raise admission.StrixRuntimeAdmissionQualificationError(
                "transfer input unexpectedly records Strix execution"
            )
        return create_transfer_bundle(
            output_file,
            candidate_root=candidate_root,
            preparation_root=preparation_root,
            preparation_work_root=preparation_work_root,
            bluefire_source_revision=bluefire_source_revision,
            threat_review_ref=threat_review_ref,
        )
    finally:
        shutil.rmtree(controller, ignore_errors=False)


def _append_output(path: Path, reference: str) -> None:
    flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        os.write(descriptor, f"bundle_ref={reference}\n".encode("ascii"))
    finally:
        os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--preparation-root", type=Path, required=True)
    parser.add_argument("--preparation-work-root", type=Path, required=True)
    parser.add_argument("--output-file", type=Path, required=True)
    parser.add_argument("--bluefire-source-revision", required=True)
    parser.add_argument("--threat-review-ref", required=True)
    parser.add_argument("--github-output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        reference = package_input(
            candidate_root=args.candidate_root,
            source_root=args.source_root,
            preparation_root=args.preparation_root,
            preparation_work_root=args.preparation_work_root,
            output_file=args.output_file,
            bluefire_source_revision=args.bluefire_source_revision,
            threat_review_ref=args.threat_review_ref,
            inherited_environment=dict(os.environ),
        )
        if args.github_output is not None:
            _append_output(args.github_output, reference)
    except (OSError, ValueError) as exc:
        print(f"Strix runtime transfer packaging refused: {exc}", file=sys.stderr)
        return 2
    print(f"Prepared one non-executed Strix runtime transfer: {reference}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
