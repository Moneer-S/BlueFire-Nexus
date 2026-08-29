"""Fixed-argument helper for producing GATE-04 release evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bluefire.defense_frontier import (
    HELPER_SCHEMA,
    REPORT_PATHS,
    DefenseFrontierError,
    produce_defense_frontier_evidence,
)


def _failure(code: str, message: str) -> dict[str, object]:
    return {
        "schema_version": HELPER_SCHEMA,
        "status": "failed",
        "error_code": code,
        "message": message,
    }


def run_defense_frontier_journey(
    repository: Path,
    evidence_dir: Path,
) -> Mapping[str, object]:
    root = repository.resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    summary = produce_defense_frontier_evidence(root, destination)
    if any(not (destination / name).is_file() for name in REPORT_PATHS):
        raise DefenseFrontierError("GATE-04 evidence producer omitted a required report")
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_defense_frontier_journey.py")
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        summary = run_defense_frontier_journey(args.repository, args.evidence_dir)
        exit_code = 0
    except DefenseFrontierError as exc:
        summary = _failure("defense_frontier_unproven", str(exc))
        exit_code = 1
    except (OSError, RuntimeError, ValueError):
        summary = _failure(
            "defense_frontier_internal_failure",
            "GATE-04 evidence production failed",
        )
        exit_code = 1
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["main", "run_defense_frontier_journey"]
