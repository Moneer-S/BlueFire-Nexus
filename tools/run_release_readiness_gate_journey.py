"""Fixed-argument helper for fresh GATE-12 product journeys."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bluefire.release_readiness_journey import (
    HELPER_SCHEMA,
    REPORT_PATHS,
    ReleaseReadinessJourneyError,
    produce_release_readiness_evidence,
)


def run_release_readiness_gate_journey(
    repository: Path,
    evidence_dir: Path,
) -> Mapping[str, object]:
    destination = evidence_dir.resolve(strict=True)
    summary = produce_release_readiness_evidence(repository, destination)
    if any(not (destination / name).is_file() for name in REPORT_PATHS):
        raise ReleaseReadinessJourneyError("GATE-12 evidence producer omitted a required report")
    return summary


def _failure(code: str, message: str) -> dict[str, object]:
    return {
        "schema_version": HELPER_SCHEMA,
        "status": "failed",
        "error_code": code,
        "message": message,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_release_readiness_gate_journey.py")
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        summary = run_release_readiness_gate_journey(args.repository, args.evidence_dir)
        exit_code = 0 if summary.get("status") == "passed" else 1
    except ReleaseReadinessJourneyError as exc:
        summary = _failure("release_readiness_journey_unproven", str(exc))
        exit_code = 1
    except (OSError, RuntimeError, TypeError, ValueError):
        summary = _failure(
            "release_readiness_journey_internal_failure",
            "GATE-12 evidence production failed",
        )
        exit_code = 1
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main", "run_release_readiness_gate_journey"]
