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
from src.core.legacy_controls import (
    legacy_preset_overrides,
    normalize_capability_name,
    normalize_pack_name,
    resolve_legacy_preset_name,
    summarize_legacy_controls,
)


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
    parser.add_argument(
        "--legacy-all",
        action="store_true",
        help="Enable all safety-gated legacy capability packs in simulate mode for this run",
    )
    parser.add_argument(
        "--legacy-preset",
        type=str,
        default="",
        help=(
            "Apply a legacy preset profile "
            "(safe-baseline/full-simulate/full-emulate/actor-simulate/c2-simulate/stealth-simulate)"
        ),
    )
    parser.add_argument(
        "--legacy-ack",
        action="store_true",
        help="Acknowledge lab-only legacy capability execution for this run",
    )
    parser.add_argument(
        "--legacy-mode",
        type=str,
        choices=["simulate", "emulate"],
        default="simulate",
        help="Override legacy capability mode for this run",
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
    legacy = result.get("legacy_controls")
    if legacy:
        table.add_row("Legacy preset", str(legacy.get("active_preset") or "none"))
        table.add_row(
            "Legacy Packs",
            ", ".join(
                f"{pack}={cfg.get('mode')}"
                for pack, cfg in (legacy.get("packs") or {}).items()
                if cfg.get("enabled") or cfg.get("enabled_capabilities")
            )
            or "disabled",
        )
    console.print(table)


def _apply_legacy_overrides(nexus: BlueFireNexus, args: argparse.Namespace) -> None:
    """Apply per-run legacy toggle overrides from CLI arguments."""
    if getattr(args, "legacy_preset", "").strip():
        preset_name = resolve_legacy_preset_name(args.legacy_preset)
        for key, value in legacy_preset_overrides(preset_name).items():
            nexus.config_manager.set(key, value)
    if args.legacy_all:
        nexus.config_manager.set("modules.legacy.enable_all_lab_capabilities", True)
        nexus.config_manager.set("modules.legacy.global_mode", args.legacy_mode)
    if args.legacy_ack:
        nexus.config_manager.set("modules.legacy.global_lab_acknowledged", True)
        nexus.config_manager.set("modules.legacy.lab_confirmation", True)

    pack = str(getattr(args, "legacy_pack", "") or "").strip().lower()
    capability = str(getattr(args, "legacy_capability", "") or "").strip().lower()
    if pack:
        pack = normalize_pack_name(pack)
    if pack and capability:
        capability = normalize_capability_name(pack, capability)
    if pack:
        nexus.config_manager.set(f"modules.legacy.{pack}.enabled", True)
        nexus.config_manager.set(f"modules.legacy.{pack}.mode", args.legacy_mode)
        if args.legacy_ack:
            nexus.config_manager.set(f"modules.legacy.{pack}.lab_confirmation", True)
    if pack and capability:
        nexus.config_manager.set(
            f"modules.legacy.{pack}.capabilities.{capability}.enabled",
            True,
        )
        nexus.config_manager.set(
            f"modules.legacy.{pack}.capabilities.{capability}.mode",
            args.legacy_mode,
        )
        if args.legacy_ack:
            nexus.config_manager.set(
                f"modules.legacy.{pack}.capabilities.{capability}.lab_confirmation",
                True,
            )
    nexus.config = nexus.config_manager.to_dict()
    nexus._configure_modules()


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

        _apply_legacy_overrides(nexus, args)

        legacy_summary = summarize_legacy_controls(nexus.config)
        if legacy_summary.get("enable_all_lab_capabilities") or any(
            pack.get("enabled") or pack.get("enabled_capabilities")
            for pack in (legacy_summary.get("packs") or {}).values()
        ):
            Console().print(
                "[yellow]Legacy capability activation[/]: "
                + json.dumps(legacy_summary, indent=2)
            )

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
