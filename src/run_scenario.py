#!/usr/bin/env python3
"""Scenario runner CLI for BlueFire-Nexus."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict

from rich.console import Console
from rich.table import Table

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import config


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run BlueFire-Nexus scenario")
    parser.add_argument(
        "--profile",
        type=str,
        required=False,
        default="apt29_credential_access",
        help="Scenario profile name from scenarios/<profile>.yaml",
    )
    parser.add_argument(
        "--scenario-file",
        type=str,
        default="",
        help="Direct path to a scenario YAML file",
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Enable AI copilot for this run (config override only for current process)",
    )
    parser.add_argument(
        "--run-id",
        type=str,
        default="",
        help="Optional explicit run id",
    )
    parser.add_argument(
        "--output-json",
        action="store_true",
        help="Print full JSON result payload",
    )
    return parser


def _resolve_scenario_path(profile: str, scenario_file: str) -> str:
    if scenario_file:
        return scenario_file
    candidate = Path("scenarios") / f"{profile}.yaml"
    return str(candidate)


def _print_summary(result: Dict[str, Any]) -> None:
    console = Console()
    table = Table(title=f"BlueFire Run Summary ({result.get('run_id', 'unknown')})")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Status", str(result.get("status")))
    table.add_row("Scenario", str(result.get("scenario")))
    table.add_row("Output", str(result.get("output_dir")))
    table.add_row("Report", str(result.get("report_path")))
    steps = result.get("steps", [])
    table.add_row("Steps", str(len(steps)))
    console.print(table)


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    log_level = config.get("general.log_level", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    logger = logging.getLogger(__name__)

    try:
        nexus = BlueFireNexus()
        if args.ai:
            nexus.config_manager.set("modules.ai.enabled", True)
            nexus.config_manager.set("copilot.enabled", True)
            nexus.config = nexus.config_manager.to_dict()
            nexus._configure_modules()

        scenario_path = _resolve_scenario_path(args.profile, args.scenario_file)
        result = nexus.run_scenario_file(scenario_path, run_id=args.run_id or None)

        _print_summary(result)
        if args.output_json:
            print(json.dumps(result, indent=2, sort_keys=True))

        if result.get("status") in {"error", "blocked"}:
            sys.exit(1)
    except Exception as exc:
        logger.critical("Fatal scenario runner failure: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
