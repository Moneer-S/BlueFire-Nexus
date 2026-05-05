"""Rich/Typer CLI for BlueFire-Nexus."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from .bluefire_nexus import BlueFireNexus
from .legacy_controls import (
    CAPABILITY_ALIASES,
    capability_aliases,
    guided_legacy_profile_catalog,
    legacy_preset_catalog,
    legacy_preset_overrides,
    normalize_capability_name,
    normalize_pack_name,
    recommend_legacy_preset_for_objective,
    render_manual_preset_name,
    resolve_legacy_preset_name,
    summarize_legacy_risk_posture,
)

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()
CONFIG_OPTION = typer.Option(Path("config.yaml"), "--config")  # noqa: B008
SCENARIO_ARG = typer.Argument(..., exists=True, readable=True)  # noqa: B008
MODULE_OPTION = typer.Option(..., "--module")  # noqa: B008
PAYLOAD_OPTION = typer.Option("{}", "--payload", help="JSON payload")  # noqa: B008
GOAL_ARG = typer.Argument(...)  # noqa: B008
RUN_ID_ARG = typer.Argument(...)  # noqa: B008
STRATEGY_OPTION = typer.Option("evasion-lite", "--strategy")  # noqa: B008
PRESET_ARG = typer.Argument(...)  # noqa: B008
LAB_ALL_OPTION = typer.Option(False, "--enable-all-lab-capabilities")  # noqa: B008
LAB_CONFIRM_OPTION = typer.Option(False, "--lab-confirmation")  # noqa: B008
LEGACY_PACK_OPTION = typer.Option("", "--legacy-pack")  # noqa: B008
LEGACY_CAPABILITY_OPTION = typer.Option("", "--legacy-capability")  # noqa: B008
LEGACY_MODE_OPTION = typer.Option("simulate", "--legacy-mode")  # noqa: B008
LEGACY_PRESET_OPTION = typer.Option(
    "",
    "--legacy-preset",
    help=(
        "Preset profile "
        "(safe-baseline/full-simulate/full-emulate/"
        "actor-simulate/c2-simulate/stealth-simulate)"
    ),
)  # noqa: B008


def _canonical_legacy_capability(pack: str, capability: str) -> str:
    if not capability or not pack:
        return ""
    try:
        return normalize_capability_name(pack, capability)
    except ValueError:
        alias_map = CAPABILITY_ALIASES.get(pack, {})
        return alias_map.get(capability.lower().strip(), capability.lower().strip())


def _apply_legacy_preset(nexus: BlueFireNexus, preset_name: str) -> None:
    if not preset_name.strip():
        return
    canonical = resolve_legacy_preset_name(preset_name)
    for key, value in legacy_preset_overrides(canonical).items():
        nexus.config_manager.set(key, value)


def _normalize_legacy_mode(value: str) -> str:
    mode = str(value).strip().lower()
    if mode not in {"simulate", "emulate"}:
        raise typer.BadParameter(
            "legacy mode must be either 'simulate' or 'emulate'",
            param_hint="--legacy-mode",
        )
    return mode


def _apply_legacy_overrides(
    nexus: BlueFireNexus,
    *,
    legacy_preset: str,
    enable_all: bool,
    lab_confirmation: bool,
    legacy_pack: str,
    legacy_capability: str,
    legacy_mode: str,
) -> None:
    _apply_legacy_preset(nexus, legacy_preset)
    legacy_mode = _normalize_legacy_mode(legacy_mode)
    normalized_pack = legacy_pack.strip().lower()
    if normalized_pack:
        try:
            normalized_pack = normalize_pack_name(normalized_pack)
        except ValueError as exc:
            raise typer.BadParameter(str(exc), param_hint="--legacy-pack") from exc
    normalized_capability = _canonical_legacy_capability(normalized_pack, legacy_capability)
    if normalized_pack and normalized_capability:
        try:
            normalized_capability = normalize_capability_name(
                normalized_pack,
                normalized_capability,
            )
        except ValueError as exc:
            raise typer.BadParameter(str(exc), param_hint="--legacy-capability") from exc
    if enable_all:
        nexus.config_manager.set("modules.legacy.enable_all_lab_capabilities", True)
        nexus.config_manager.set("modules.legacy.global_mode", legacy_mode)
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
    if normalized_pack and not normalized_capability:
        active_preset = str(
            nexus.config_manager.get("modules.legacy.active_preset", "")
        ).strip()
        if not active_preset:
            nexus.config_manager.set(
                "modules.legacy.active_preset",
                render_manual_preset_name(normalized_pack),
            )
    nexus.config = nexus.config_manager.to_dict()
    nexus._configure_modules()


def _render_legacy_activation(nexus: BlueFireNexus) -> None:
    summary = nexus.legacy_activation_summary()
    active_preset = summary.get("active_preset") or "none"
    tree = Tree("[bold yellow]Legacy capability controls[/]")
    tree.add(
        f"Active preset: {active_preset} | "
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
            caps_node = node.add("Capabilities")
            for capability in enabled_caps:
                aliases = capability_aliases(pack_name, capability)
                if aliases:
                    caps_node.add(f"{capability} (aliases: {', '.join(aliases)})")
                else:
                    caps_node.add(capability)
    console.print(tree)


def _print_scenario_result(result: dict) -> None:
    tree = Tree(f"[bold cyan]Scenario[/]: {result.get('scenario', 'unknown')}")
    tree.add(f"[green]Status[/]: {result.get('status')}")
    tree.add(f"Run ID: {result.get('run_id')}")
    tree.add(f"Output: {result.get('output_dir')}")
    legacy = result.get("legacy_controls") or {}
    if legacy:
        tree.add(f"Legacy preset: {legacy.get('active_preset') or 'none'}")
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
    legacy_preset: str = LEGACY_PRESET_OPTION,
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
        legacy_preset=legacy_preset,
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
    legacy_preset: str = LEGACY_PRESET_OPTION,
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
        legacy_preset=legacy_preset,
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


@app.command("risk-summary")
def risk_summary_cmd(
    run_target: str = PRESET_ARG,
    top: int = typer.Option(10, "--top", min=1, max=100),
) -> None:
    """Show risk summary from run id, run dir, or risk_summary.json path."""
    candidate = Path(run_target)
    if candidate.exists():
        summary_path = candidate / "risk_summary.json" if candidate.is_dir() else candidate
    else:
        summary_path = Path("output") / run_target / "risk_summary.json"
    if not summary_path.exists():
        raise typer.BadParameter(
            f"Risk summary file not found: {summary_path}",
            param_hint="run_target",
        )
    payload = json.loads(summary_path.read_text(encoding="utf-8"))
    _render_risk_summary_payload(payload, title=f"Risk summary ({summary_path})", top=top)


def _render_risk_summary_payload(payload: Mapping[str, Any], *, title: str, top: int) -> None:
    risk = payload.get("risk_summary", {})
    summary_table = Table(title=title)
    summary_table.add_column("Metric")
    summary_table.add_column("Value")
    summary_table.add_row("critical", str(risk.get("critical", 0)))
    summary_table.add_row("high", str(risk.get("high", 0)))
    summary_table.add_row("medium", str(risk.get("medium", 0)))
    summary_table.add_row("low", str(risk.get("low", 0)))
    summary_table.add_row("average_score", str(payload.get("average_score", 0)))
    summary_table.add_row("max_score", str(payload.get("max_score", 0)))
    summary_table.add_row("min_score", str(payload.get("min_score", 0)))
    summary_table.add_row("module_count", str(payload.get("module_count", 0)))
    console.print(summary_table)

    modules = payload.get("modules", [])
    detail_table = Table(title="Top risky modules")
    detail_table.add_column("Module")
    detail_table.add_column("Severity")
    detail_table.add_column("Score")
    detail_table.add_column("Pack")
    detail_table.add_column("Capability")
    detail_table.add_column("Mode")
    ordered_modules = sorted(
        modules,
        key=lambda item: int(item.get("score", 0)),
        reverse=True,
    )
    for item in ordered_modules[:top]:
        detail_table.add_row(
            str(item.get("module", "")),
            str(item.get("severity", "")),
            str(item.get("score", "")),
            str(item.get("pack", "")),
            str(item.get("capability", "")),
            str(item.get("mode", "")),
        )
    console.print(detail_table)


@app.command("legacy-presets")
def legacy_presets_cmd() -> None:
    """List preset profiles for quickly enabling legacy capability packs."""
    table = Table(title="Legacy capability preset profiles")
    table.add_column("Preset")
    table.add_column("Aliases")
    table.add_column("Risk")
    table.add_column("Description")
    for preset, details in legacy_preset_catalog().items():
        aliases = ", ".join(details.get("aliases", [])) or "-"
        risk = str(details.get("risk", "n/a"))
        description = str(details.get("description", ""))
        table.add_row(preset, aliases, risk, description)
    console.print(table)


@app.command("legacy-guided-presets")
def legacy_guided_presets_cmd() -> None:
    """List objective-driven recommendations mapped to legacy presets."""
    table = Table(title="Legacy guided objective recommendations")
    table.add_column("Objective")
    table.add_column("Aliases")
    table.add_column("Recommended preset")
    table.add_column("Risk")
    table.add_column("Notes")
    for objective, details in guided_legacy_profile_catalog().items():
        aliases = ", ".join(details.get("aliases", [])) or "-"
        table.add_row(
            objective,
            aliases,
            str(details.get("recommended_preset", "safe-baseline")),
            str(details.get("risk", "n/a")),
            str(details.get("notes", "")),
        )
    console.print(table)


@app.command("legacy-recommend-preset")
def legacy_recommend_preset_cmd(
    objective: str = PRESET_ARG,
    config: Path = CONFIG_OPTION,
    apply_recommendation: bool = typer.Option(
        False,
        "--apply",
        help="Apply recommended preset to runtime config for this command invocation",
    ),
    save: bool = typer.Option(
        False,
        "--save",
        help="Persist recommended preset to config file (implies --apply)",
    ),
) -> None:
    """Recommend (and optionally apply) the best preset for an objective."""
    try:
        recommendation = recommend_legacy_preset_for_objective(objective)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="objective") from exc

    canonical_objective = str(recommendation.get("objective"))
    recommended_preset = str(recommendation.get("recommended_preset"))
    aliases = ", ".join(recommendation.get("aliases", [])) or "-"
    console.print(
        Panel.fit(
            "\n".join(
                [
                    f"Objective: {canonical_objective}",
                    f"Aliases: {aliases}",
                    f"Recommended preset: {recommended_preset}",
                    f"Risk: {recommendation.get('risk', 'n/a')}",
                    f"Notes: {recommendation.get('notes', '')}",
                ]
            ),
            title="Legacy preset recommendation",
        )
    )

    if not apply_recommendation and not save:
        return

    nexus = BlueFireNexus(str(config))
    if save:
        apply_recommendation = True
    for key, value in legacy_preset_overrides(recommended_preset).items():
        nexus.config_manager.set(key, value)
    if save:
        nexus.config_manager.save()
    nexus.config = nexus.config_manager.to_dict()
    nexus._configure_modules()
    action = "Applied and saved" if save else "Applied"
    console.print(f"[green]{action} recommended preset[/]: {recommended_preset}")
    _render_legacy_activation(nexus)


@app.command("legacy-risk-ladder")
def legacy_risk_ladder_cmd() -> None:
    """Show presets ordered by declared risk level."""
    rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    presets = legacy_preset_catalog()
    ordered = sorted(
        presets.items(),
        key=lambda entry: (
            rank.get(str(entry[1].get("risk", "low")).lower(), 99),
            entry[0],
        ),
    )
    table = Table(title="Legacy preset risk ladder")
    table.add_column("Risk")
    table.add_column("Preset")
    table.add_column("Aliases")
    table.add_column("Description")
    for preset, details in ordered:
        aliases = ", ".join(details.get("aliases", [])) or "-"
        table.add_row(
            str(details.get("risk", "n/a")),
            preset,
            aliases,
            str(details.get("description", "")),
        )
    console.print(table)


@app.command("legacy-scenario-recommendation")
def legacy_scenario_recommendation_cmd(
    scenario: Path = SCENARIO_ARG,
    apply_recommendation: bool = typer.Option(
        False,
        "--apply",
        help="Apply recommended preset to runtime config for this command invocation",
    ),
    save: bool = typer.Option(
        False,
        "--save",
        help="Persist recommended preset to config file (implies --apply)",
    ),
    config: Path = CONFIG_OPTION,
) -> None:
    """Recommend preset using scenario objective + module composition."""
    from .scenario import load_scenario

    scenario_data = load_scenario(scenario)
    recommendation = recommend_legacy_preset_for_objective(
        scenario_data.objective,
        modules=[step.module for step in scenario_data.steps],
    )
    recommended_preset = str(recommendation.get("recommended_preset", "safe-baseline"))
    objective = str(recommendation.get("objective", "safe-evaluation"))
    aliases = ", ".join(recommendation.get("aliases", [])) or "-"
    console.print(
        Panel.fit(
            "\n".join(
                [
                    f"Scenario: {scenario_data.name}",
                    f"Resolved objective: {objective}",
                    f"Objective aliases: {aliases}",
                    f"Recommended preset: {recommended_preset}",
                    f"Risk: {recommendation.get('risk', 'n/a')}",
                    f"Notes: {recommendation.get('notes', '')}",
                ]
            ),
            title="Legacy scenario recommendation",
        )
    )
    if not apply_recommendation and not save:
        return
    nexus = BlueFireNexus(str(config))
    if save:
        apply_recommendation = True
    for key, value in legacy_preset_overrides(recommended_preset).items():
        nexus.config_manager.set(key, value)
    if save:
        nexus.config_manager.save()
    nexus.config = nexus.config_manager.to_dict()
    nexus._configure_modules()
    action = "Applied and saved" if save else "Applied"
    console.print(f"[green]{action} scenario recommendation[/]: {recommended_preset}")
    _render_legacy_activation(nexus)


@app.command("legacy-operator-guide")
def legacy_operator_guide_cmd() -> None:
    """Render quick-start workflow from objective to persistent preset."""
    lines = [
        "1) List objective mappings:",
        "   python -m src.core.cli legacy-guided-presets",
        "",
        "2) Get recommendation for an objective:",
        "   python -m src.core.cli legacy-recommend-preset detection",
        "   or from a scenario file:",
        (
            "   python -m src.core.cli legacy-scenario-recommendation "
            "scenarios/apt29_credential_access.yaml"
        ),
        "",
        "3) Apply recommendation for one run:",
        "   python -m src.core.cli legacy-recommend-preset detection --apply",
        "",
        "4) Persist recommendation to config:",
        "   python -m src.core.cli legacy-recommend-preset detection --save --config config.yaml",
        "",
        "5) Verify resulting controls:",
        "   python -m src.core.cli legacy-controls --config config.yaml",
        "   python -m src.core.cli legacy-posture --config config.yaml",
        "",
        "6) Inspect run risk summary:",
        "   python -m src.core.cli risk-summary output/<run-id>/risk_summary.json",
    ]
    console.print(Panel.fit("\n".join(lines), title="Legacy operator guide"))


@app.command("show-risk-summary")
def show_risk_summary_cmd(
    risk_summary_path: str = PRESET_ARG,
    top: int = typer.Option(10, "--top", min=1, max=100),
) -> None:
    """Show a risk summary from a run risk_summary.json file."""
    path = Path(risk_summary_path)
    if not path.exists():
        raise typer.BadParameter(
            f"Risk summary file not found: {path}",
            param_hint="risk_summary_path",
        )
    payload = json.loads(path.read_text(encoding="utf-8"))
    _render_risk_summary_payload(payload, title=f"Risk summary ({path})", top=top)


@app.command("legacy-run-risk")
def legacy_run_risk_cmd(
    run_id: str = RUN_ID_ARG,
    top: int = typer.Option(10, "--top", min=1, max=100),
) -> None:
    """Show summarized risk posture for an existing run."""
    target = Path("output") / run_id / "risk_summary.json"
    if not target.exists():
        raise typer.BadParameter(
            f"Risk summary not found for run '{run_id}'. Expected: {target}",
            param_hint="run_id",
        )
    payload = json.loads(target.read_text(encoding="utf-8"))
    _render_risk_summary_payload(payload, title=f"Run risk summary ({run_id})", top=top)


@app.command("legacy-risk-posture")
def legacy_risk_posture_cmd(config: Path = CONFIG_OPTION) -> None:
    """Show current config risk posture based on active legacy controls."""
    nexus = BlueFireNexus(str(config))
    summary = nexus.legacy_activation_summary()
    posture = summarize_legacy_risk_posture(summary)
    table = Table(title="Legacy activation risk posture")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("severity", str(posture.get("risk_level", "low")))
    table.add_row("enabled_capabilities", str(posture.get("enabled_capability_count", 0)))
    table.add_row("emulate_capabilities", str(posture.get("emulate_capability_count", 0)))
    table.add_row("active_preset", str(summary.get("active_preset") or "none"))
    table.add_row(
        "master_toggle",
        str(bool(summary.get("enable_all_lab_capabilities", False))),
    )
    console.print(table)


@app.command("legacy-apply-preset")
def legacy_apply_preset_cmd(
    preset: str = PRESET_ARG,
    config: Path = CONFIG_OPTION,
    preview_only: bool = typer.Option(False, "--preview-only"),
) -> None:
    """Apply a legacy preset profile and optionally persist to config."""
    try:
        canonical = resolve_legacy_preset_name(preset)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="preset") from exc

    nexus = BlueFireNexus(str(config))
    for key, value in legacy_preset_overrides(canonical).items():
        nexus.config_manager.set(key, value)
    if not preview_only:
        nexus.config_manager.save()
    nexus.config = nexus.config_manager.to_dict()
    nexus._configure_modules()

    action = "Previewed" if preview_only else "Applied and saved"
    console.print(f"[green]{action} legacy preset[/]: {canonical} ({config})")
    _render_legacy_activation(nexus)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
