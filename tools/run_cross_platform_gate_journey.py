"""Fixed-argument helper for producing GATE-11 cross-platform evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bluefire.cross_platform_journey import (
    HELPER_SCHEMA,
    LINUX_CHECK,
    LINUX_REPORT,
    REPORT_PATHS,
    CrossPlatformJourneyError,
    produce_cross_platform_evidence,
)


def _failure() -> dict[str, object]:
    return {
        "schema_version": HELPER_SCHEMA,
        "status": "failed",
        "blocking_check": None,
        "reports": list(REPORT_PATHS),
        "run_count": 0,
    }


def run_cross_platform_gate_journey(
    repository: Path,
    evidence_dir: Path,
) -> Mapping[str, object]:
    root = repository.resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    summary = produce_cross_platform_evidence(root, destination)
    if summary.get("status") == "passed":
        if any(not (destination / name).is_file() for name in REPORT_PATHS):
            raise CrossPlatformJourneyError("GATE-11 evidence producer omitted a report")
    elif summary.get("blocking_check") == LINUX_CHECK:
        if not (destination / LINUX_REPORT).is_file():
            raise CrossPlatformJourneyError("GATE-11 Linux report was not published")
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_cross_platform_gate_journey.py")
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        summary = run_cross_platform_gate_journey(args.repository, args.evidence_dir)
        exit_code = (
            0
            if summary.get("status") == "passed" or summary.get("blocking_check") == LINUX_CHECK
            else 1
        )
    except (CrossPlatformJourneyError, OSError, RuntimeError, TypeError, ValueError):
        summary = _failure()
        exit_code = 1
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main", "run_cross_platform_gate_journey"]
