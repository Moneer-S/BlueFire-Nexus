"""Fixed-argument helper for producing GATE-11 cross-platform evidence."""

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from pathlib import Path
from typing import Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bluefire.application_errors import APIError
from bluefire.cross_platform_journey import (
    HELPER_SCHEMA,
    LINUX_CHECK,
    LINUX_REPORT,
    REPORT_PATHS,
    CrossPlatformJourneyError,
    produce_cross_platform_evidence,
)
from bluefire.gate_helper_diagnostics import exception_diagnostic
from bluefire.gate_private_diagnostics import PRIVATE_DIAGNOSTICS_ENV, retain_private_output


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
    except (
        APIError,
        CrossPlatformJourneyError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as exc:
        diagnostic = dict(exception_diagnostic(exc))
        if os.environ.get(PRIVATE_DIAGNOSTICS_ENV):
            try:
                retain_private_output(
                    repository=args.repository,
                    evidence_dir=args.evidence_dir,
                    stdout=b"",
                    stderr="".join(
                        traceback.format_exception(type(exc), exc, exc.__traceback__)
                    ).encode("utf-8"),
                    source={"kind": "cross_platform_exception", **exception_diagnostic(exc)},
                )
                diagnostic["private_exception_capture"] = "retained"
            except (OSError, RuntimeError, ValueError):
                # Preserve the original failure classification even if storage itself failed.
                diagnostic["private_exception_capture"] = "unavailable"
        print(json.dumps(diagnostic, sort_keys=True), file=sys.stderr)
        summary = _failure()
        exit_code = 1
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main", "run_cross_platform_gate_journey"]
