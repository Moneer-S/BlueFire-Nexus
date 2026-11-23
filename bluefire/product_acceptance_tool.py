"""Developer command wrapper for the product acceptance library."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from .product_acceptance import (
    AcceptanceContractError,
    AcceptanceFailure,
    run_release_acceptance,
    verify_release_result,
)
from .product_acceptance_schema import result_schema_document, write_result_schema


def tool_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="product_acceptance.py")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="Run the locked product acceptance contract")
    run.add_argument("--release", action="store_true", required=True)
    run.add_argument("--repository-root", type=Path)
    run.add_argument("--output-dir", type=Path)
    verify = commands.add_parser("verify", help="Verify a persisted release result and artifacts")
    verify.add_argument("--result", type=Path, required=True)
    schema = commands.add_parser("schema", help="Generate the acceptance result JSON Schema")
    schema.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.command == "schema":
        if args.output is None:
            print(
                json.dumps(result_schema_document(), ensure_ascii=False, indent=2, sort_keys=True)
            )
        else:
            write_result_schema(args.output)
        return 0
    try:
        if args.command == "verify":
            result = verify_release_result(args.result)
        else:
            result = run_release_acceptance(
                repository_root=args.repository_root,
                output_dir=args.output_dir,
            )
    except AcceptanceFailure as exc:
        print(json.dumps(exc.result, ensure_ascii=False, indent=2, sort_keys=True))
        return 1
    except (AcceptanceContractError, OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False, indent=2, sort_keys=True))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


__all__ = ["tool_main"]
