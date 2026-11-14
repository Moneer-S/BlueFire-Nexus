"""Build, qualify, and clean one runner-private BlueFire Strix test sandbox image."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from tools import strix_test_sandbox_image_build as _build
from tools import strix_test_sandbox_qualification as _qualification

TestSandboxQualificationError = _build.TestSandboxQualificationError
provider_source_digest = _build.provider_source_digest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare-inputs")
    prepare.add_argument("--package-root", type=Path, required=True)
    prepare.add_argument("--tool-root", type=Path, required=True)
    qualify_parser = commands.add_parser("qualify")
    qualify_parser.add_argument("--bluefire-source-revision", required=True)
    qualify_parser.add_argument("--qualifier-revision", required=True)
    qualify_parser.add_argument("--runtime-root", type=Path, required=True)
    qualify_parser.add_argument("--runtime-composite-manifest", type=Path, required=True)
    qualify_parser.add_argument("--runtime-composite-ref", required=True)
    qualify_parser.add_argument("--provider-source", type=Path, action="append", required=True)
    qualify_parser.add_argument("--provider-source-digest", required=True)
    qualify_parser.add_argument("--package-root", type=Path, required=True)
    qualify_parser.add_argument("--output-root", type=Path, required=True)
    qualify_parser.add_argument("--work-root", type=Path, required=True)
    qualify_parser.add_argument("--docker-socket", required=True)
    qualify_parser.add_argument("--syft", type=Path, required=True)
    cleanup_parser = commands.add_parser("cleanup")
    cleanup_parser.add_argument("--manifest", type=Path, required=True)
    cleanup_parser.add_argument("--ledger", type=Path, required=True)
    cleanup_parser.add_argument("--output-root", type=Path, required=True)
    cleanup_parser.add_argument("--docker-socket", required=True)
    partial_cleanup_parser = commands.add_parser("cleanup-partial")
    partial_cleanup_parser.add_argument("--ledger", type=Path, required=True)
    partial_cleanup_parser.add_argument("--output-root", type=Path, required=True)
    partial_cleanup_parser.add_argument("--docker-socket", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "prepare-inputs":
            result = _qualification.prepare_inputs(
                package_root=args.package_root, tool_root=args.tool_root
            )
        elif args.command == "qualify":
            qualified = _qualification.qualify(
                bluefire_revision=args.bluefire_source_revision,
                qualifier_revision=args.qualifier_revision,
                runtime_root=args.runtime_root,
                runtime_composite_manifest=args.runtime_composite_manifest,
                runtime_composite_ref=args.runtime_composite_ref,
                provider_sources=args.provider_source,
                expected_provider_digest=args.provider_source_digest,
                package_root=args.package_root,
                output_root=args.output_root,
                work_root=args.work_root,
                docker_socket=args.docker_socket,
                syft_path=args.syft,
            )
            result = qualified.contract_digest
        elif args.command == "cleanup":
            receipt = _qualification.cleanup(
                manifest_path=args.manifest,
                ledger_path=args.ledger,
                output_root=args.output_root,
                docker_socket=args.docker_socket,
            )
            result = receipt.receipt_digest
        else:
            result = _qualification.cleanup_partial(
                ledger_path=args.ledger,
                output_root=args.output_root,
                docker_socket=args.docker_socket,
            )
    except TestSandboxQualificationError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
