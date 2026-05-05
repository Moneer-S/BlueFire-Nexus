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

from src.core.ai.mutation import mutate_step_params
from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import config
from src.core.legacy_controls import (
    capability_aliases,
    legacy_preset_overrides,
    normalize_capability_name,
    normalize_pack_name,
    recommend_legacy_preset_for_objective,
    render_manual_preset_name,
    resolve_legacy_preset_name,
    summarize_legacy_controls,
)
from src.core.scenario import load_scenario

# Mutation strategies recognized by `src.core.ai.mutation`. Listed here so
# argparse can validate `--mutate` and the operator gets a clear error on
# unknown values rather than silent fallback to a generic marker.
_MUTATE_STRATEGIES = ("low_noise", "evasion-lite", "protocol_shift", "protocol-shift")


def _normalize_legacy_mode(value: str) -> str:
    mode = str(value).strip().lower()
    if mode not in {"simulate", "emulate"}:
        raise ValueError("legacy mode must be either 'simulate' or 'emulate'")
    return mode


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
    parser.add_argument(
        "--legacy-pack",
        type=str,
        default="",
        help="Granular legacy pack override (actor_pack/c2_pack/stealth_pack)",
    )
    parser.add_argument(
        "--legacy-capability",
        type=str,
        default="",
        help="Granular capability override within --legacy-pack (aliases accepted)",
    )
    parser.add_argument(
        "--legacy-guided",
        action="store_true",
        help="Auto-apply recommended preset based on scenario objective before other overrides",
    )
    parser.add_argument(
        "--mutate",
        type=str,
        default="",
        choices=("",) + _MUTATE_STRATEGIES,
        help=(
            "Apply an AI mutation strategy to every step's params before dispatch. "
            "Implies explicit lab opt-in (mutation requires `allowed=True`). "
            "Default empty = no mutation. Strategies: "
            f"{', '.join(_MUTATE_STRATEGIES)}."
        ),
    )
    return parser


def _build_mutation_overrides(
    scenario_path: str, strategy: str
) -> Dict[str, Dict[str, Any]]:
    """Compute per-step mutated params for `nexus.run_scenario_file`.

    Returns a mapping of `step_id -> mutated params dict`. Loads the
    scenario file using the same loader the runtime uses, then applies
    `mutate_step_params(..., allowed=True, strategy=...)` to each step.

    The operator must explicitly choose `--mutate <strategy>` for this to
    fire; the mutation engine itself still requires `allowed=True`, which
    is satisfied here because the operator chose the strategy on the CLI.
    Mutation is recorded in the summary so it is never silent.
    """
    scenario = load_scenario(scenario_path)
    overrides: Dict[str, Dict[str, Any]] = {}
    for step in scenario.steps:
        result = mutate_step_params(step.params, allowed=True, strategy=strategy)
        overrides[step.step_id] = result.mutated
    return overrides


def _resolve_scenario_path(profile: str, scenario_file: str) -> str:
    if scenario_file:
        return scenario_file
    candidate = Path("scenarios") / f"{profile}.yaml"
    return str(candidate)


def _apply_guided_preset_recommendation(
    nexus: BlueFireNexus,
    *,
    scenario_path: str,
    apply_recommendation: bool,
) -> Dict[str, str]:
    """Apply objective-driven preset recommendation and return recommendation details."""
    scenario = load_scenario(scenario_path)
    objective = scenario.objective.strip().lower() or "safe-evaluation"
    recommendation = recommend_legacy_preset_for_objective(
        objective,
        modules=[step.module for step in scenario.steps],
    )
    if apply_recommendation:
        recommended_preset = str(recommendation.get("recommended_preset", "safe-baseline"))
        for key, value in legacy_preset_overrides(recommended_preset).items():
            nexus.config_manager.set(key, value)
    return {
        "objective": str(recommendation.get("objective", objective)),
        "recommended_preset": str(recommendation.get("recommended_preset", "safe-baseline")),
    }


def _print_summary(result: Dict[str, Any]) -> None:
    console = Console()
    table = Table(title=f"BlueFire Run Summary ({result.get('run_id', 'unknown')})")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Status", str(result.get("status")))
    table.add_row("Scenario", str(result.get("scenario")))
    table.add_row("Output", str(result.get("output_dir")))
    table.add_row("Report", str(result.get("report_path")))
    if result.get("risk_summary_path"):
        table.add_row("Risk summary", str(result.get("risk_summary_path")))
    if result.get("mutation_strategy"):
        table.add_row("Mutation strategy", str(result.get("mutation_strategy")))
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
        enabled_caps: list[str] = []
        for pack, cfg in (legacy.get("packs") or {}).items():
            for capability in cfg.get("enabled_capabilities") or []:
                aliases = capability_aliases(pack, capability)
                if aliases:
                    enabled_caps.append(f"{pack}:{capability} ({', '.join(aliases)})")
                else:
                    enabled_caps.append(f"{pack}:{capability}")
        if enabled_caps:
            table.add_row("Legacy capabilities", ", ".join(enabled_caps))
    console.print(table)


def _apply_legacy_overrides(nexus: BlueFireNexus, args: argparse.Namespace) -> None:
    """Apply per-run legacy toggle overrides from CLI arguments."""
    legacy_mode = _normalize_legacy_mode(args.legacy_mode)
    if getattr(args, "legacy_preset", "").strip():
        preset_name = resolve_legacy_preset_name(args.legacy_preset)
        for key, value in legacy_preset_overrides(preset_name).items():
            nexus.config_manager.set(key, value)
    if args.legacy_all:
        nexus.config_manager.set("modules.legacy.enable_all_lab_capabilities", True)
        nexus.config_manager.set("modules.legacy.global_mode", legacy_mode)
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
        nexus.config_manager.set(f"modules.legacy.{pack}.mode", legacy_mode)
        if args.legacy_ack:
            nexus.config_manager.set(f"modules.legacy.{pack}.lab_confirmation", True)
    if pack and capability:
        nexus.config_manager.set(
            f"modules.legacy.{pack}.capabilities.{capability}.enabled",
            True,
        )
        nexus.config_manager.set(
            f"modules.legacy.{pack}.capabilities.{capability}.mode",
            legacy_mode,
        )
        if args.legacy_ack:
            nexus.config_manager.set(
                f"modules.legacy.{pack}.capabilities.{capability}.lab_confirmation",
                True,
            )
    if pack and not capability:
        active_preset = str(
            nexus.config_manager.get("modules.legacy.active_preset", "")
        ).strip()
        if not active_preset:
            nexus.config_manager.set(
                "modules.legacy.active_preset",
                render_manual_preset_name(pack),
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

        scenario_path = _resolve_scenario_path(args.profile, args.scenario_file)
        if args.legacy_guided:
            guided_recommendation = _apply_guided_preset_recommendation(
                nexus,
                scenario_path=scenario_path,
                apply_recommendation=True,
            )
            nexus.config = nexus.config_manager.to_dict()
            nexus._configure_modules()
            Console().print(
                "[cyan]Applied guided preset recommendation[/]: "
                f"{guided_recommendation['objective']} -> "
                f"{guided_recommendation['recommended_preset']}"
            )

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

        step_overrides = None
        if args.mutate:
            step_overrides = _build_mutation_overrides(scenario_path, args.mutate)
            Console().print(
                "[magenta]Applying AI mutation strategy[/]: "
                f"{args.mutate} (lab opt-in implied by --mutate)"
            )

        result = nexus.run_scenario_file(
            scenario_path,
            run_id=args.run_id or None,
            step_param_overrides=step_overrides,
        )
        if args.mutate:
            result["mutation_strategy"] = args.mutate

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
