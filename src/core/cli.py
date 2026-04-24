"""Rich/Typer CLI for BlueFire-Nexus."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.tree import Tree

from .bluefire_nexus import BlueFireNexus
from .legacy_controls import CAPABILITY_ALIASES

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()
CONFIG_OPTION = typer.Option(Path("config.yaml"), "--config")  # noqa: B008
SCENARIO_ARG = typer.Argument(..., exists=True, readable=True)  # noqa: B008
MODULE_OPTION = typer.Option(..., "--module")  # noqa: B008
PAYLOAD_OPTION = typer.Option("{}", "--payload", help="JSON payload")  # noqa: B008
GOAL_ARG = typer.Argument(...)  # noqa: B008
RUN_ID_ARG = typer.Argument(...)  # noqa: B008
STRATEGY_OPTION = typer.Option("evasion-lite", "--strategy")  # noqa: B008
LAB_ALL_OPTION = typer.Option(False, "--enable-all-lab-capabilities")  # noqa: B008
LAB_CONFIRM_OPTION = typer.Option(False, "--lab-confirmation")  # noqa: B008
LEGACY_PACK_OPTION = typer.Option("", "--legacy-pack")  # noqa: B008
LEGACY_CAPABILITY_OPTION = typer.Option("", "--legacy-capability")  # noqa: B008
LEGACY_MODE_OPTION = typer.Option("simulate", "--legacy-mode")  # noqa: B008


def _canonical_legacy_capability(pack: str, capability: str) -> str:
    if not capability:
        return ""
    alias_map = CAPABILITY_ALIASES.get(pack, {})
    return alias_map.get(capability.lower().strip(), capability.lower().strip())


def _apply_legacy_overrides(
    nexus: BlueFireNexus,
    *,
    enable_all: bool,
    lab_confirmation: bool,
    legacy_pack: str,
    legacy_capability: str,
    legacy_mode: str,
) -> None:
    normalized_pack = legacy_pack.strip()
    normalized_capability = _canonical_legacy_capability(normalized_pack, legacy_capability)
    if enable_all:
        nexus.config_manager.set("modules.legacy.enable_all_lab_capabilities", True)
    if lab_confirmation:
        nexus.config_manager.set("modules.legacy.lab_confirmation", True)
        nexus.config_manager.set("modules.legacy.global_lab_acknowledged", True)
    if normalized_pack:
        nexus.config_manager.set(f"modules.legacy.{normalized_pack}.enabled", True)
        nexus.config_manager.set(f"modules.legacy.{normalized_pack}.mode", legacy_mode)
        if lab_confirmation:
            nexus.config_manager.set(
                f"modules.legacy.{normalized_pack}.lab_confirmation",
                True,
            )
    if normalized_pack and normalized_capability:
        nexus.config_manager.set(
            f"modules.legacy.{normalized_pack}.capabilities.{normalized_capability}.enabled",
            True,
        )
        nexus.config_manager.set(
            f"modules.legacy.{normalized_pack}.capabilities.{normalized_capability}.mode",
            legacy_mode,
        )
        if lab_confirmation:
            nexus.config_manager.set(
                f"modules.legacy.{normalized_pack}.capabilities."
                f"{normalized_capability}.lab_confirmation",
                True,
            )
    nexus.config = nexus.config_manager.to_dict()
    nexus._configure_modules()


def _render_legacy_activation(nexus: BlueFireNexus) -> None:
    summary = nexus.legacy_activation_summary()
    tree = Tree("[bold yellow]Legacy capability controls[/]")
    tree.add(
        f"All lab capabilities: {summary.get('enable_all_lab_capabilities')} | "
        f"Global mode: {summary.get('global_mode')} | "
        f"Global confirmation: {summary.get('global_lab_acknowledged')}"
    )
    for pack_name, pack_summary in summary.get("packs", {}).items():
        node = tree.add(
            f"{pack_name}: enabled={pack_summary.get('enabled')} "
            f"mode={pack_summary.get('mode')} "
            f"confirmed={pack_summary.get('acknowledged')}"
        )
        enabled_caps = pack_summary.get("enabled_capabilities") or []
        if enabled_caps:
            node.add("Capabilities: " + ", ".join(enabled_caps))
    console.print(tree)


def _print_scenario_result(result: dict) -> None:
    tree = Tree(f"[bold cyan]Scenario[/]: {result.get('scenario', 'unknown')}")
    tree.add(f"[green]Status[/]: {result.get('status')}")
    tree.add(f"Run ID: {result.get('run_id')}")
    tree.add(f"Output: {result.get('output_dir')}")
    for step in result.get("steps", []):
        step_node = tree.add(f"[magenta]{step.get('step_id', '?')}[/] {step.get('module')}")
        step_node.add(f"Status: {step.get('status')}")
        if step.get("message"):
            step_node.add(step["message"])
    console.print(tree)


@app.command("run-scenario")
def run_scenario_cmd(
    scenario: Path = SCENARIO_ARG,
    config: Path = CONFIG_OPTION,
    enable_all_lab_capabilities: bool = LAB_ALL_OPTION,
    lab_confirmation: bool = LAB_CONFIRM_OPTION,
    legacy_pack: str = LEGACY_PACK_OPTION,
    legacy_capability: str = LEGACY_CAPABILITY_OPTION,
    legacy_mode: str = LEGACY_MODE_OPTION,
) -> None:
    """Run a YAML scenario and print a run summary."""
    nexus = BlueFireNexus(str(config))
    _apply_legacy_overrides(
        nexus,
        enable_all=enable_all_lab_capabilities,
        lab_confirmation=lab_confirmation,
        legacy_pack=legacy_pack,
        legacy_capability=legacy_capability,
        legacy_mode=legacy_mode,
    )
    _render_legacy_activation(nexus)
    result = nexus.run_scenario_file(str(scenario))
    _print_scenario_result(result)


@app.command("run-operation")
def run_operation_cmd(
    module: str = MODULE_OPTION,
    payload: str = PAYLOAD_OPTION,
    config: Path = CONFIG_OPTION,
    enable_all_lab_capabilities: bool = LAB_ALL_OPTION,
    lab_confirmation: bool = LAB_CONFIRM_OPTION,
    legacy_pack: str = LEGACY_PACK_OPTION,
    legacy_capability: str = LEGACY_CAPABILITY_OPTION,
    legacy_mode: str = LEGACY_MODE_OPTION,
) -> None:
    """Run one module operation from inline JSON payload."""
    nexus = BlueFireNexus(str(config))
    _apply_legacy_overrides(
        nexus,
        enable_all=enable_all_lab_capabilities,
        lab_confirmation=lab_confirmation,
        legacy_pack=legacy_pack,
        legacy_capability=legacy_capability,
        legacy_mode=legacy_mode,
    )
    _render_legacy_activation(nexus)
    data = json.loads(payload)
    result = nexus.execute_operation(module, data)
    console.print(Panel.fit(json.dumps(result, indent=2), title="Operation Result"))


@app.command("plan")
def plan_cmd(goal: str = GOAL_ARG, config: Path = CONFIG_OPTION) -> None:
    """Use the AI copilot to propose a scenario plan."""
    nexus = BlueFireNexus(str(config))
    plan = nexus.generate_plan(goal)
    console.print(Panel.fit(json.dumps(plan, indent=2), title="Copilot Plan"))


@app.command("suggest-detections")
def suggest_detections_cmd(
    run_id: str = RUN_ID_ARG,
    config: Path = CONFIG_OPTION,
) -> None:
    """Use AI copilot to suggest detections for a run."""
    nexus = BlueFireNexus(str(config))
    suggestions = nexus.suggest_detections(run_id)
    console.print(Panel.fit(json.dumps(suggestions, indent=2), title="Detection Suggestions"))


@app.command("mutate-technique")
def mutate_technique_cmd(
    module: str = MODULE_OPTION,
    payload: str = PAYLOAD_OPTION,
    strategy: str = STRATEGY_OPTION,
    config: Path = CONFIG_OPTION,
) -> None:
    """Mutate a technique payload for lab-only research experiments."""
    nexus = BlueFireNexus(str(config))
    data = json.loads(payload)
    mutated = nexus.mutate_technique(module_name=module, base_params=data, strategy=strategy)
    console.print(Panel.fit(json.dumps(mutated, indent=2), title="Technique Mutation"))


@app.command("legacy-controls")
def legacy_controls_cmd(config: Path = CONFIG_OPTION) -> None:
    """Show current master and granular legacy safety toggles."""
    nexus = BlueFireNexus(str(config))
    _render_legacy_activation(nexus)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
