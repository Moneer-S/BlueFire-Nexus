"""Rich/Typer CLI for BlueFire-Nexus."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from .bluefire_nexus import BlueFireNexus, resolve_output_root
from .configuration import (
    apply_simple_preset,
    simple_preset_catalog,
    simple_preset_names,
)
from .reporting import (
    find_run_dir as _find_run_dir,
    latest_run as _latest_run,
    list_runs as _list_runs,
    validate_run_bundle as _validate_run_bundle,
    write_output_index as _write_output_index,
    write_viewer_for_run,
)
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
        # Honour `general.output_root` / `BLUEFIRE_OUTPUT_ROOT` so this
        # command finds runs in non-default output roots (test
        # harnesses, production deployments that pin a custom location).
        summary_path = resolve_output_root() / run_target / "risk_summary.json"
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
    # Mirrors the static viewer's ``why`` column added in PR #114.
    # ``rationale`` is a list of short markers (``pack=tactic_pack``,
    # ``tactic_base=impact``, ``mode=emulate``, ...) explaining why
    # the score landed where it did. Surface it in the CLI so an
    # operator triaging from a terminal doesn't need to open
    # risk_summary.json to see the reasoning.
    detail_table.add_column("Why")
    ordered_modules = sorted(
        modules,
        key=lambda item: int(item.get("score", 0)),
        reverse=True,
    )
    for item in ordered_modules[:top]:
        rationale = item.get("rationale") or []
        why = (
            ", ".join(str(r) for r in rationale)
            if isinstance(rationale, (list, tuple))
            else ""
        )
        detail_table.add_row(
            str(item.get("module", "")),
            str(item.get("severity", "")),
            str(item.get("score", "")),
            str(item.get("pack", "")),
            str(item.get("capability", "")),
            str(item.get("mode", "")),
            why,
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


@app.command("simple-presets")
def simple_presets_cmd() -> None:
    """List cross-cutting simple-mode presets (general / legacy / AI)."""
    table = Table(title="Simple-mode config presets")
    table.add_column("Preset")
    table.add_column("Description")
    for name, entry in simple_preset_catalog().items():
        table.add_row(name, str(entry.get("description", "")))
    console.print(table)


@app.command("apply-simple-preset")
def apply_simple_preset_cmd(
    preset: str = typer.Argument(..., help="Simple-mode preset name."),
    config: Path = typer.Option(
        Path("config.yaml"),
        "--config",
        "-c",
        help="Path to the config file to update.",
    ),
    preview_only: bool = typer.Option(
        False,
        "--preview-only",
        help="Print the dot-path overrides without writing the config file.",
    ),
) -> None:
    """Apply a simple-mode preset (general / legacy / AI) to the config."""
    canonical = preset.strip().lower()
    if canonical not in simple_preset_names():
        raise typer.BadParameter(
            f"Unknown simple-mode preset {preset!r}. Available: "
            f"{', '.join(sorted(simple_preset_names()))}"
        )
    nexus = BlueFireNexus(str(config))
    overrides = apply_simple_preset(nexus.config_manager, canonical)
    table = Table(title=f"Simple preset overrides: {canonical}")
    table.add_column("Key")
    table.add_column("Value")
    for path, value in overrides.items():
        table.add_row(path, str(value))
    console.print(table)
    if preview_only:
        console.print(
            "[yellow]preview-only:[/] preset overrides not persisted to config."
        )
        return
    nexus.config_manager.save()
    console.print(f"[green]Persisted preset {canonical!r} to[/] {config}")


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
    # Honour `general.output_root` / `BLUEFIRE_OUTPUT_ROOT` so this
    # command finds runs that did NOT land under the default `output/`.
    target = resolve_output_root() / run_id / "risk_summary.json"
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


# ---------------------------------------------------------------------------
# Local report viewer CLI
# ---------------------------------------------------------------------------
#
# These commands operate on the local output directory only. No
# server is started, no browser is auto-opened (operators can use
# their OS's native ``open`` / ``xdg-open`` / ``start`` if they
# want to). Output root resolution honours
# ``general.output_root`` and ``BLUEFIRE_OUTPUT_ROOT``.


def _render_run_table(runs: list[dict]) -> Table:
    # Plain ASCII separator. Em-dash (U+2014) renders as the
    # Unicode replacement glyph on Windows terminals using cp1252
    # / cp437, which surfaced as garbled output in fresh-clone
    # smoke runs.
    table = Table(title=f"BlueFire runs ({len(runs)} total - newest first)")
    table.add_column("run_id", overflow="fold")
    table.add_column("scenario")
    table.add_column("status")
    # Same severity tier the dashboard header badge surfaces;
    # rendered inline so a defender skimming ``list-runs`` sees
    # which prior runs ended at critical without opening each
    # dashboard separately.
    table.add_column("severity")
    table.add_column("steps", justify="right")
    table.add_column("started")
    table.add_column("viewer")
    for run in runs:
        table.add_row(
            run.get("run_id", ""),
            run.get("scenario_name", "") or "-",
            run.get("overall_status", "") or "-",
            run.get("highest_severity") or "-",
            str(run.get("module_count", 0)),
            run.get("started_at") or "-",
            "yes" if run.get("has_viewer") else "no",
        )
    return table


def _file_uri(path: Path) -> str:
    """Return ``file://...`` for a path, resolving to absolute first.

    ``Path.as_uri()`` raises ``ValueError`` on relative paths.
    The default output root is ``Path("output")`` (a relative
    path), so paths that originate from ``list_runs`` are
    relative whenever the operator runs from the project
    directory. Resolve to absolute before formatting so the
    file:// URI is always valid. Closes the Codex P1 from
    PR #79 sweep.
    """
    return path.resolve().as_uri()


def _load_config_for_console_preview() -> Optional[Dict[str, Any]]:
    """Read ``config.yaml`` for the operator-console mode-diff render.

    The ``operator-console`` CLI is documented as a read-only
    generator and must not mutate on-disk state. ``ConfigManager()``
    cannot be used here because its ``_load_config`` writes the
    default ``config.yaml`` when the file is missing (Codex P1 on
    PR #183) -- a stray ``operator-console`` invocation in a clean
    directory would silently create a config file just by previewing
    the page.

    This helper delegates to :meth:`ConfigManager.load_readonly`,
    which mirrors the load + default-merge + alias-normalisation +
    env-template-resolution pipeline that the runtime
    ``apply-mode-profile`` path uses (via ``ConfigManager().to_dict()``)
    but skips the default-file-creation side effect when the file is
    missing. The console diff is therefore computed against the same
    merged shape that ``apply-mode-profile`` would actually compare
    against -- a partial config (e.g. only ``general.dry_run`` set)
    no longer over-reports ``(write)`` rows that would in fact be
    no-ops on disk (Codex P2 on PR #183).

    When the file is missing, unreadable, or doesn't parse to a
    mapping, the helper returns ``None`` so the console falls back to
    the static-only render path. No file is ever created or modified.
    """

    from .config import ConfigManager

    config_path = Path("config.yaml")
    if not config_path.is_file():
        console.print(
            "[dim]config.yaml not found; rendering mode cards with "
            "static target overrides only.[/]"
        )
        return None
    merged = ConfigManager.load_readonly(str(config_path))
    if merged is None:
        # Either malformed YAML or a non-mapping top-level value.
        # ``load_readonly`` already swallowed the parse error; here we
        # just surface a single warning to the operator and fall back
        # to the static render.
        console.print(
            "[yellow]Warning: could not load config.yaml for mode "
            "diff (malformed YAML or non-mapping value); rendering "
            "static target overrides only.[/]"
        )
        return None
    return merged


def _print_next_steps_hint(run: dict) -> None:
    """Print next-step hints to stdout, file:// URI on its own line.

    The viewer URL prints on its own line so an operator can copy
    or click it without rich wrapping the URL across two terminal
    rows (which breaks copy-paste). The label sits above the URL
    line so the structure is "label, then standalone URL". Em-dash
    avoided in messages since Windows non-UTF-8 terminals render
    it as a Unicode replacement glyph.
    """
    run_dir = run.get("run_dir") or ""
    if not run_dir:
        return
    viewer = Path(run_dir) / "index.html"
    manifest = Path(run_dir) / "manifest.json"
    if viewer.exists():
        # ``Path.as_uri`` returns ``file:///...`` so the operator
        # can copy or click it. Resolve first because the path may
        # be relative.
        console.print("[green]Open viewer (copy or click below):[/]")
        console.print(_file_uri(viewer), no_wrap=True, overflow="ignore")
    elif manifest.exists():
        run_id = run.get("run_id", "")
        console.print("[yellow]Viewer missing - regenerate it with:[/]")
        console.print(f"  python -m src.core.cli build-report-view {run_id}")
    if manifest.exists():
        console.print(f"[cyan]Manifest:[/] {manifest}")


def _next_steps_hint(run: dict) -> str:
    """Backwards-compatible string form for callers that captured the
    string return value. Newer call sites should call
    :func:`_print_next_steps_hint` directly so URLs land on their own
    line with ``no_wrap=True``.
    """
    run_dir = run.get("run_dir") or ""
    if not run_dir:
        return ""
    viewer = Path(run_dir) / "index.html"
    manifest = Path(run_dir) / "manifest.json"
    bullets: list[str] = []
    if viewer.exists():
        bullets.append(
            "[green]Open viewer (copy or click below):[/]\n"
            f"{_file_uri(viewer)}"
        )
    elif manifest.exists():
        run_id = run.get("run_id", "")
        bullets.append(
            "[yellow]Viewer missing - regenerate it with:[/]\n"
            f"  python -m src.core.cli build-report-view {run_id}"
        )
    if manifest.exists():
        bullets.append(f"[cyan]Manifest:[/] {manifest}")
    return "\n".join(bullets)


def _render_run_detail(run: dict) -> None:
    """Print one run's metadata + a next-steps hint."""
    rows = [
        ("run_id", str(run.get("run_id", ""))),
        ("scenario_name", str(run.get("scenario_name") or "-")),
        ("overall_status", str(run.get("overall_status") or "-")),
        # Same severity tier the dashboard header badge renders;
        # rendered inline so a defender running ``latest-run`` /
        # ``show-run`` after the fact sees whether that run ended
        # at low or critical without opening the dashboard. Empty
        # string falls through as a dash.
        ("highest_severity", str(run.get("highest_severity") or "-")),
        ("started_at", str(run.get("started_at") or "-")),
        ("module_count", str(run.get("module_count", 0))),
        ("run_dir", str(run.get("run_dir", ""))),
        ("has_manifest", "yes" if run.get("has_manifest") else "no"),
        ("has_viewer", "yes" if run.get("has_viewer") else "no"),
    ]
    table = Table(title=f"Run detail: {run.get('run_id', '')}")
    table.add_column("field")
    table.add_column("value", overflow="fold")
    for key, value in rows:
        table.add_row(key, value)
    console.print(table)
    # Direct-print path keeps the file:// URI on its own line with
    # ``no_wrap=True`` so terminals don't break it across rows.
    _print_next_steps_hint(run)


@app.command("list-runs")
def list_runs_cmd(
    output_root: Path = typer.Option(  # noqa: B008
        None,
        "--output-root",
        help=(
            "Override BLUEFIRE_OUTPUT_ROOT / general.output_root for "
            "discovery. Defaults to the runtime's resolved output root."
        ),
    ),
    limit: int = typer.Option(  # noqa: B008
        20,
        "--limit",
        min=1,
        max=500,
        help="Maximum number of runs to display (newest first).",
    ),
) -> None:
    """List recent BlueFire runs in the configured output directory.

    Reads each run's ``manifest.json`` (when present) for the
    metadata. Runs without a manifest fall back to filesystem
    ctime so partial / errored runs still surface.

    Examples:

        # List 20 newest runs in the default output root.
        python -m src.core.cli list-runs

        # Inspect a different output directory.
        python -m src.core.cli list-runs --output-root /tmp/lab-output

        # Show only the 5 newest runs.
        python -m src.core.cli list-runs --limit 5
    """
    root = output_root if output_root else resolve_output_root()
    runs = _list_runs(Path(root))[:limit]
    if not runs:
        console.print(
            f"[yellow]No runs found under[/] {root}.\n"
            "Run a scenario first, e.g.\n"
            "  python -m src.run_scenario --profile apt29_credential_access"
        )
        return
    console.print(_render_run_table(runs))
    console.print(
        "[dim]Tip: `python -m src.core.cli show-run <run_id>` for details, "
        "or `latest-run` for a shortcut to the newest entry.[/]"
    )
    aggregator = Path(root) / "index.html"
    if aggregator.exists():
        console.print(
            f"[dim]Aggregate index:[/] {_file_uri(aggregator)}"
        )


@app.command("latest-run")
def latest_run_cmd(
    output_root: Path = typer.Option(  # noqa: B008
        None,
        "--output-root",
        help=(
            "Override BLUEFIRE_OUTPUT_ROOT / general.output_root. "
            "Defaults to the runtime's resolved output root."
        ),
    ),
) -> None:
    """Show the most recent BlueFire run in the configured output directory.

    Useful as a one-shot "what just happened" command after a
    scenario run, especially right after the README's quickstart
    invocation.

    Examples:

        # Show details + a file:// link to the viewer.
        python -m src.core.cli latest-run

        # Pin a non-default output root.
        python -m src.core.cli latest-run --output-root /tmp/lab-output
    """
    root = output_root if output_root else resolve_output_root()
    run = _latest_run(Path(root))
    if not run:
        console.print(
            f"[yellow]No runs found under[/] {root}.\n"
            "Run a scenario first, e.g.\n"
            "  python -m src.run_scenario --profile apt29_credential_access"
        )
        return
    _render_run_detail(run)
    aggregator = Path(root) / "index.html"
    if aggregator.exists():
        console.print(
            f"[dim]Aggregate index:[/] {_file_uri(aggregator)}"
        )


@app.command("show-run")
def show_run_cmd(
    run_id: str = RUN_ID_ARG,
    output_root: Path = typer.Option(  # noqa: B008
        None,
        "--output-root",
        help=(
            "Override BLUEFIRE_OUTPUT_ROOT / general.output_root. "
            "Defaults to the runtime's resolved output root."
        ),
    ),
) -> None:
    """Show metadata for a single run by ``run_id``.

    Resolves first by directory name, then by manifest's
    ``run.run_id`` field (the directory name may be sanitised
    differently from the original id). Prints a file:// link to
    the static HTML viewer when one is available.

    Examples:

        # Look up a known run id.
        python -m src.core.cli show-run run-20260507120000-abc123

        # Inspect a run from an alternate output root.
        python -m src.core.cli show-run my-run-id --output-root /tmp/lab-output
    """
    root = output_root if output_root else resolve_output_root()
    run_dir = _find_run_dir(Path(root), run_id)
    if not run_dir:
        raise typer.BadParameter(
            f"Run not found: {run_id!r} (searched under {root}). "
            "List available runs with `python -m src.core.cli list-runs`.",
            param_hint="run_id",
        )
    # Re-resolve through list_runs so the rendered detail uses the
    # same shape as list-runs / latest-run.
    matches = [r for r in _list_runs(Path(root)) if Path(r["run_dir"]) == run_dir]
    if not matches:
        # The run dir is partial (no manifest). Render a minimal entry.
        console.print(
            f"[yellow]Run directory {run_dir} has no manifest yet.[/] "
            "Use `build-report-view` to render after the run finishes."
        )
        return
    _render_run_detail(matches[0])


@app.command("build-report-view")
def build_report_view_cmd(
    run_id: str = RUN_ID_ARG,
    output_root: Path = typer.Option(  # noqa: B008
        None,
        "--output-root",
        help=(
            "Override BLUEFIRE_OUTPUT_ROOT / general.output_root. "
            "Defaults to the runtime's resolved output root."
        ),
    ),
) -> None:
    """Generate / refresh ``index.html`` for an existing run.

    Useful when the orchestrator wrote a manifest but the viewer
    step failed, after a manifest was edited manually, or after
    the viewer template (this code) changed and you want every
    historical run rebuilt.

    The command never starts a server and never opens a browser.
    Output prints a ``file://`` link the operator can copy into
    their browser of choice.

    Examples:

        # Regenerate the viewer for the latest run id you got
        # from `latest-run` or `list-runs`.
        python -m src.core.cli build-report-view run-20260507120000-abc123

        # Rebuild a viewer for a run sitting under an alternate
        # output root.
        python -m src.core.cli build-report-view my-run --output-root /tmp/lab-output
    """
    root = output_root if output_root else resolve_output_root()
    run_dir = _find_run_dir(Path(root), run_id)
    if not run_dir:
        raise typer.BadParameter(
            f"Run not found: {run_id!r} (searched under {root}). "
            "List available runs with `python -m src.core.cli list-runs`.",
            param_hint="run_id",
        )
    try:
        target = write_viewer_for_run(run_dir)
    except FileNotFoundError as exc:
        raise typer.BadParameter(
            f"{exc}. Run the scenario first, then re-run "
            "`build-report-view <run_id>`.",
            param_hint="run_id",
        ) from exc
    console.print(f"[green]Wrote viewer:[/] {target}")
    console.print("[cyan]Open in browser (copy or click below):[/]")
    # URI on its own line with ``no_wrap=True`` so terminals don't
    # break it. ASCII separator below; em-dash renders as a
    # Unicode replacement glyph on Windows non-UTF-8 terminals.
    console.print(_file_uri(target), no_wrap=True, overflow="ignore")
    console.print(
        "[dim]No server required - the page is fully self-contained.[/]"
    )


@app.command("operator-console")
def operator_console_cmd(
    output_root: Path = typer.Option(  # noqa: B008
        None,
        "--output-root",
        help=(
            "Override BLUEFIRE_OUTPUT_ROOT / general.output_root. "
            "Defaults to the runtime's resolved output root."
        ),
    ),
    scenarios: Path = typer.Option(  # noqa: B008
        None,
        "--scenarios",
        help=(
            "Override the scenarios directory the console scrapes for "
            "name / description / objective summaries. Defaults to "
            "the repo's ``scenarios/`` directory when present."
        ),
    ),
) -> None:
    """Generate the local-only operator console.

    Writes a single self-contained ``index.html`` at
    ``<output_root>/operator-console/index.html`` listing every
    registered module, its capability IO contract (produces /
    consumes / discriminator), the typed chain pairs the registry
    knows about, and the shipped scenarios. The page is read-only
    planning context - it never starts a server, opens a browser,
    or makes a network call.

    Use this to decide which modules to chain BEFORE running a
    scenario. The actual runner is ``run-scenario`` /
    ``run-operation``; this command does not execute anything.

    Examples:

        python -m src.core.cli operator-console

        python -m src.core.cli operator-console --output-root /tmp/lab

        python -m src.core.cli operator-console --scenarios /work/custom-scenarios
    """

    from .operator_console import build_operator_console

    root = output_root if output_root else resolve_output_root()
    # Load the current config so each mode card renders a real
    # ``current -> target`` diff against what's on disk, not just the
    # static target overrides. The console is documented as a
    # read-only generator -- "never writes anywhere outside
    # ``output_root/operator-console/``" -- so the load path MUST NOT
    # mutate on-disk state. ``ConfigManager()`` constructs the default
    # ``config.yaml`` when the file is missing (Codex P1 on PR #183),
    # so we cannot use ConfigManager here. Read ``config.yaml``
    # directly via ``yaml.safe_load`` only when the file already
    # exists; if it is missing or unreadable the console falls back to
    # the static-only render and the operator gets a
    # current-config-not-loaded notice. Either way no file is created.
    current_config: Optional[Dict[str, Any]] = _load_config_for_console_preview()
    target = build_operator_console(
        Path(root),
        scenarios_dir=scenarios,
        current_config=current_config,
    )
    console.print(f"[green]Wrote operator console:[/] {target}")
    console.print("[cyan]Open in browser (copy or click below):[/]")
    console.print(_file_uri(target), no_wrap=True, overflow="ignore")
    console.print(
        "[dim]No server required - the page is fully self-contained.[/]"
    )


# ---------------------------------------------------------------------------
# Scenario-planner CLI surfaces (PR5 in the chain-graph loop)
#
# Wraps :mod:`src.core.scenario_planner` so an operator can interrogate
# the planner from the terminal without writing Python. Each command
# loads a scenario YAML, computes the static chain state from it via
# :func:`src.core.chain_graph.build_scenario_graph`, then calls into
# the planner. Outputs are pure-Python rich tables / panels -- no
# remote calls, no LLM.


def _chain_state_from_scenario(scenario_path: Path):
    """Load a scenario YAML and return a :class:`ChainState` for it.

    The state's produced-types frozenset is the union of every step's
    ``produces`` declaration -- the planner uses it to rank what could
    plausibly run AFTER this scenario completes (i.e. "given this is
    the chain so far, what's the natural extension?").

    Warnings forwarded into ``ChainState`` are restricted to the
    ``missing_required`` severity. The runtime ``ChainContext.warnings``
    surface that the planner's ``explain_chain`` reads carries
    consumer-side warnings only ("required input not produced
    upstream"); ``ChainGraph`` also emits producer-side warnings
    (``unused_emission`` / ``high_value_unused``) that aren't in the
    same category. Forwarding all severities into the planner state
    would surface dangling-emission warnings as if they were
    unsatisfied consumer inputs and mislead JSON consumers reading
    the ``missing_type`` field. (Codex P2 on PR #168.)
    """

    from .chain_graph import build_scenario_graph
    from .scenario import load_scenario
    from .scenario_planner import ChainState

    scenario = load_scenario(scenario_path)
    graph = build_scenario_graph(scenario.steps)
    produced_types: set[str] = set()
    for node in graph.nodes:
        for produced_type in node.produces:
            produced_types.add(produced_type)
    warnings = tuple(
        {
            "step_id": w.step_id,
            "module": (
                next(
                    (n.module for n in graph.nodes if n.step_id == w.step_id),
                    "",
                )
            ),
            "missing_type": w.artifact_type,
            "severity": w.severity,
        }
        for w in graph.warnings
        if w.severity == "missing_required"
    )
    return scenario, ChainState(
        produced_types=frozenset(produced_types), warnings=warnings
    )


@app.command("planner-suggest")
def planner_suggest_cmd(
    scenario: Path = SCENARIO_ARG,
    limit: int = typer.Option(  # noqa: B008
        10, "--limit", min=1, max=50, help="Max suggestions to render."
    ),
    json_output: bool = typer.Option(  # noqa: B008
        False, "--json", help="Print the suggestions as JSON instead of a table."
    ),
) -> None:
    """Rank next-step suggestions for a scenario's chain state.

    Loads the scenario, computes the union of typed artifacts every
    step would produce, and asks the planner what could run NEXT
    given that chain state. Useful for deciding how to extend an
    existing scenario without grepping for compatible modules.

    Examples:

        python -m src.core.cli planner-suggest scenarios/fin7_initial_access_to_c2.yaml
        python -m src.core.cli planner-suggest scenarios/apt29_credential_access.yaml --limit 5
        python -m src.core.cli planner-suggest scenarios/insider_exfil_dns.yaml --json
    """

    from .scenario_planner import offer_next_steps

    scenario_obj, state = _chain_state_from_scenario(scenario)
    suggestions = offer_next_steps(state, limit=limit)
    if json_output:
        payload = [
            {
                "module": s.module,
                "rank": s.rank,
                "score": s.score,
                "required_satisfied": list(s.required_satisfied),
                "optional_satisfied": list(s.optional_satisfied),
                "required_missing": list(s.required_missing),
                "produces": list(s.produces),
                "rationale": s.rationale,
            }
            for s in suggestions
        ]
        # Bypass rich's wrap/highlight to keep the JSON byte-stable so
        # automation can pipe stdout straight into ``json.loads``.
        typer.echo(json.dumps(payload, indent=2))
        return

    table = Table(title=f"Next-step suggestions for {scenario_obj.name}")
    table.add_column("Rank tier")
    table.add_column("Module")
    table.add_column("Score", justify="right")
    table.add_column("Required satisfied")
    table.add_column("Required missing")
    table.add_column("Produces")
    for suggestion in suggestions:
        table.add_row(
            suggestion.rank,
            suggestion.module,
            f"{suggestion.score:.2f}",
            ", ".join(suggestion.required_satisfied) or "-",
            ", ".join(suggestion.required_missing) or "-",
            ", ".join(suggestion.produces) or "-",
        )
    console.print(table)


@app.command("planner-explain")
def planner_explain_cmd(
    scenario: Path = SCENARIO_ARG,
    json_output: bool = typer.Option(  # noqa: B008
        False, "--json", help="Print the explanation as JSON instead of a panel."
    ),
) -> None:
    """Summarise a scenario's chain coherence in plain text.

    Surfaces produced types, dangling producer types (emitted but no
    registered consumer would pick them up), and unsatisfied
    consumer warnings. Reads from the static chain graph so the
    explanation is available before any execution.

    Examples:

        python -m src.core.cli planner-explain scenarios/healthcare_ransomware.yaml
        python -m src.core.cli planner-explain scenarios/insider_exfil_dns.yaml --json
    """

    from .scenario_planner import explain_chain

    scenario_obj, state = _chain_state_from_scenario(scenario)
    explanation = explain_chain(state)
    if json_output:
        payload = {
            "produced_types": list(explanation.produced_types),
            "unused_emissions": list(explanation.unused_emissions),
            "unsatisfied_warnings": [dict(w) for w in explanation.unsatisfied_warnings],
            "narrative": explanation.narrative,
        }
        typer.echo(json.dumps(payload, indent=2))
        return

    lines = [explanation.narrative]
    if explanation.produced_types:
        lines.append("")
        lines.append(f"Produced types: {', '.join(explanation.produced_types)}")
    if explanation.unused_emissions:
        lines.append("")
        lines.append(
            f"Dangling producer types: {', '.join(explanation.unused_emissions)}"
        )
    if explanation.unsatisfied_warnings:
        lines.append("")
        lines.append("Unsatisfied warnings:")
        for warning in explanation.unsatisfied_warnings:
            lines.append(
                f"  - {warning.get('step_id', '?')} ({warning.get('module', '?')}): "
                f"{warning.get('missing_type', '?')}"
            )
    console.print(
        Panel.fit("\n".join(lines), title=f"Chain explanation: {scenario_obj.name}")
    )


@app.command("planner-variants")
def planner_variants_cmd(
    scenario: Path = SCENARIO_ARG,
    count: int = typer.Option(  # noqa: B008
        3, "--count", min=1, max=20, help="How many mutated variants to generate."
    ),
    seed: int = typer.Option(  # noqa: B008
        None, "--seed", help="Optional RNG seed for reproducible variant generation."
    ),
    json_output: bool = typer.Option(  # noqa: B008
        False, "--json", help="Print the variants as JSON instead of a per-variant tree."
    ),
) -> None:
    """Generate mutated variants of a scenario via the capability mutation catalog.

    Each variant is a fresh list of step dicts with one or more steps
    swapped via the catalog (technique / channel / method / vector
    etc.). The planner never writes the variants to disk and never
    triggers execution -- the operator copies the variant they want
    into a new scenario YAML and runs it via ``run-scenario``.

    Examples:

        python -m src.core.cli planner-variants scenarios/fin7_initial_access_to_c2.yaml
        python -m src.core.cli planner-variants scenarios/apt29_credential_access.yaml --count 5 --seed 42
        python -m src.core.cli planner-variants scenarios/healthcare_ransomware.yaml --json
    """

    from .scenario import load_scenario
    from .scenario_planner import suggest_scenario_variants

    scenario_obj = load_scenario(scenario)
    step_dicts = [
        {
            "step_id": step.step_id,
            "name": step.name,
            "module": step.module,
            "params": dict(step.params),
            "objective": step.objective,
        }
        for step in scenario_obj.steps
    ]
    variants = suggest_scenario_variants(step_dicts, count=count, seed=seed)
    if json_output:
        typer.echo(json.dumps(variants, indent=2, default=str))
        return

    if not variants:
        console.print(
            "[yellow]No variants generated[/]: scenario has no steps that "
            "match a mutation catalog slot."
        )
        return

    for index, variant in enumerate(variants, start=1):
        tree = Tree(f"[bold cyan]Variant {index}[/] (of {scenario_obj.name})")
        for step_idx, step in enumerate(variant, start=1):
            step_node = tree.add(
                f"[magenta]{step.get('step_id', '?')}[/] "
                f"{step.get('module', '?')}"
            )
            params = step.get("params") or {}
            if params:
                for key, value in sorted(params.items()):
                    step_node.add(f"{key}: {value}")
        console.print(tree)


# ---------------------------------------------------------------------------
# Mode-selection CLI surfaces (PR6 in the chain-graph loop)
#
# Wraps :mod:`src.core.modes` so an operator can preview what each
# execution mode (simulate / emulate / live-lab) implies before
# running anything. The commands are purely declarative -- they
# never mutate config, never enable a mode, never start execution.
# Operators apply mode overrides themselves via the ordinary
# config-writer path after reviewing the plan.


@app.command("explain-mode")
def explain_mode_cmd(
    mode: str = typer.Argument(  # noqa: B008
        ...,
        help="Mode name: simulate / emulate / live-lab (aliases: sim / em / live / lab).",
    ),
    json_output: bool = typer.Option(  # noqa: B008
        False, "--json", help="Print the mode metadata as JSON instead of a panel."
    ),
) -> None:
    """Describe what a given execution mode entails.

    Prints the mode's description, the gates it requires, the config
    overrides a config writer would apply, the categories of real-
    world side effects it permits, and (for non-default modes) the
    operator-facing warnings.

    The command is read-only -- no config write, no execution,
    no network call. Use it to decide whether a mode is appropriate
    for the target environment BEFORE configuring the run.

    Examples:

        python -m src.core.cli explain-mode simulate
        python -m src.core.cli explain-mode emulate --json
        python -m src.core.cli explain-mode live-lab
    """

    from .modes import resolve_mode

    try:
        definition = resolve_mode(mode)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="mode") from exc

    if json_output:
        payload = {
            "name": definition.name,
            "description": definition.description,
            "required_gates": list(definition.required_gates),
            "config_overrides": [
                {"key": key, "value": value}
                for key, value in definition.config_overrides
            ],
            "side_effects": list(definition.side_effects),
            "warnings": list(definition.warnings),
            "safe_for_unattended": definition.safe_for_unattended,
        }
        typer.echo(json.dumps(payload, indent=2))
        return

    title = f"Mode: {definition.name}"
    if not definition.safe_for_unattended:
        title = f"{title} -- requires explicit confirmation"
    body_lines: List[str] = [definition.description, ""]
    body_lines.append("Config overrides:")
    if definition.config_overrides:
        for key, value in definition.config_overrides:
            body_lines.append(f"  {key}: {value}")
    else:
        body_lines.append("  (none)")
    body_lines.append("")
    body_lines.append("Required gates:")
    if definition.required_gates:
        for gate in definition.required_gates:
            body_lines.append(f"  - {gate}")
    else:
        body_lines.append("  (none)")
    body_lines.append("")
    body_lines.append("Side effects:")
    for effect in definition.side_effects:
        body_lines.append(f"  - {effect}")
    if definition.warnings:
        body_lines.append("")
        body_lines.append("Warnings:")
        for warning in definition.warnings:
            body_lines.append(f"  - {warning}")
    console.print(Panel.fit("\n".join(body_lines), title=title))


@app.command("mode-plan")
def mode_plan_cmd(
    scenario: Path = SCENARIO_ARG,
    mode: str = typer.Option(  # noqa: B008
        "simulate",
        "--mode",
        help="Target mode: simulate / emulate / live-lab.",
    ),
    json_output: bool = typer.Option(  # noqa: B008
        False, "--json", help="Print the mode plan as JSON instead of a tree."
    ),
) -> None:
    """Project what running a scenario in a given mode would mean.

    Loads the scenario, walks its module list to surface any legacy
    packs it references, and composes a per-scenario mode plan
    showing the config patch the operator would apply, every
    required gate (mode-level + per-pack), and the operator-facing
    warnings.

    The command is read-only -- it does NOT write the config patch,
    does NOT enable any mode, and does NOT start execution.
    Operators apply mode overrides via the ordinary config-writer
    path after reviewing the plan.

    Examples:

        python -m src.core.cli mode-plan scenarios/fin7_initial_access_to_c2.yaml
        python -m src.core.cli mode-plan scenarios/apt29_credential_access.yaml --mode emulate
        python -m src.core.cli mode-plan scenarios/insider_exfil_dns.yaml --mode live-lab --json
    """

    from .modes import build_mode_plan
    from .scenario import load_scenario

    try:
        scenario_obj = load_scenario(scenario)
    except Exception as exc:
        raise typer.BadParameter(
            f"failed to load scenario: {exc.__class__.__name__}",
            param_hint="scenario",
        ) from exc
    try:
        plan = build_mode_plan(scenario_obj, mode)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--mode") from exc

    if json_output:
        typer.echo(json.dumps(plan.to_dict(), indent=2, default=str))
        return

    tree = Tree(
        f"[bold cyan]Mode plan:[/] {plan.mode} -- {plan.scenario_name}"
    )
    tree.add(f"Scenario id: {plan.scenario_id or '(none)'}")
    tree.add(f"Step count: {plan.step_count}")
    if not plan.safe_for_unattended:
        tree.add(
            "[bold yellow]NOT safe for unattended use[/] -- "
            "requires explicit confirmation."
        )

    overrides_node = tree.add("Config overrides")
    if plan.config_overrides:
        for key, value in plan.config_overrides:
            overrides_node.add(f"{key}: {value}")
    else:
        overrides_node.add("(none)")

    gates_node = tree.add(
        f"Required gates ({len(plan.required_gates)})"
    )
    if plan.required_gates:
        for gate in plan.required_gates:
            gates_node.add(gate)
    else:
        gates_node.add("(none)")

    if plan.legacy_packs:
        packs_node = tree.add(
            f"Legacy packs referenced ({len(plan.legacy_packs)})"
        )
        for pack in plan.legacy_packs:
            packs_node.add(pack)

    side_effects_node = tree.add("Side effects")
    for effect in plan.side_effects:
        side_effects_node.add(effect)

    if plan.warnings:
        warnings_node = tree.add(
            f"[bold red]Warnings ({len(plan.warnings)})[/]"
        )
        for warning in plan.warnings:
            warnings_node.add(warning)

    console.print(tree)


@app.command("apply-mode-profile")
def apply_mode_profile_cmd(
    mode: str = typer.Argument(..., help="Target mode: simulate / emulate / live-lab."),  # noqa: B008
    write: bool = typer.Option(  # noqa: B008
        False,
        "--write",
        help=(
            "Persist the mode's config overrides to disk via "
            "ConfigManager.save(). Without this flag the command is "
            "preview-only and never mutates config."
        ),
    ),
    i_understand_this_is_a_lab: bool = typer.Option(  # noqa: B008
        False,
        "--i-understand-this-is-a-lab",
        help=(
            "Operator confirmation required to write a non-simulate "
            "mode. Has no effect in preview mode."
        ),
    ),
    allowed_subnets: Optional[List[str]] = typer.Option(  # noqa: B008
        None,
        "--allowed-subnets",
        help=(
            "Comma-separated CIDR ranges. Required (along with "
            "--i-understand-this-is-a-lab) when applying live-lab "
            "with --write."
        ),
    ),
    json_output: bool = typer.Option(  # noqa: B008
        False, "--json", help="Print the apply plan as JSON instead of a tree."
    ),
) -> None:
    """Preview or apply a mode's config overrides to ``config.yaml``.

    Without ``--write`` the command is preview-only: it loads the
    current config, computes the per-key diff between the current
    state and the target mode's overrides, and renders the diff
    plus the required gates and warnings. **Nothing on disk
    changes.**

    With ``--write`` (and the matching gate flags for non-simulate
    modes) the command applies the overrides via
    ``ConfigManager.set(...)`` for each non-no-op change and calls
    ``ConfigManager.save()``. The operator MUST opt in twice for
    non-simulate modes -- once with ``--write`` and once with the
    mode-specific confirmation flags -- so a stray ``--write`` on
    its own cannot silently turn on emulate or live-lab.

    Examples:

        # Preview only -- the safe default.
        python -m src.core.cli apply-mode-profile simulate
        python -m src.core.cli apply-mode-profile emulate
        python -m src.core.cli apply-mode-profile live-lab

        # Apply simulate (no extra gates).
        python -m src.core.cli apply-mode-profile simulate --write

        # Apply emulate (lab-confirmation required).
        python -m src.core.cli apply-mode-profile emulate --write \\
            --i-understand-this-is-a-lab

        # Apply live-lab (lab-confirmation + bounded subnets required).
        python -m src.core.cli apply-mode-profile live-lab --write \\
            --i-understand-this-is-a-lab \\
            --allowed-subnets 10.10.0.0/24,192.168.50.0/24

        # Same, JSON output.
        python -m src.core.cli apply-mode-profile emulate --json
    """

    from .config import ConfigManager
    from .modes import (
        apply_mode_to_config_manager,
        check_apply_gates,
        compute_apply_plan,
    )

    config_manager = ConfigManager()
    try:
        plan = compute_apply_plan(mode, config_manager.to_dict())
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="mode") from exc

    parsed_subnets: List[str] = []
    if allowed_subnets:
        # typer "List[str]" with comma-separated values arrives as a
        # single-element list; split each element on commas to support
        # ``--allowed-subnets a,b,c`` and ``--allowed-subnets a
        # --allowed-subnets b`` interchangeably.
        for entry in allowed_subnets:
            for part in str(entry).split(","):
                stripped = part.strip()
                if stripped:
                    parsed_subnets.append(stripped)

    unmet_gates = (
        check_apply_gates(
            plan.mode,
            i_understand_this_is_a_lab=i_understand_this_is_a_lab,
            allowed_subnets=parsed_subnets,
        )
        if write
        else ()
    )

    applied_changes: Tuple[Any, ...] = ()
    if write and not unmet_gates:
        applied_changes = apply_mode_to_config_manager(
            config_manager, plan, save=True
        )
        if plan.mode == "live-lab" and parsed_subnets:
            # live-lab also needs allowed_subnets populated. The mode
            # catalog deliberately doesn't pin a value (the operator's
            # lab subnets are theirs to declare); write the user-
            # supplied list here so a single ``--write`` run lands a
            # complete live-lab config.
            #
            # The subnets write must show up in ``applied_changes``
            # alongside the catalog-driven mode overrides so:
            #   1. ``changes_applied_count`` in the JSON output is
            #      accurate, and
            #   2. the "No changes were needed" message never fires
            #      while we just persisted a safety-critical config
            #      value (Codex P1 on PR #180).
            from .modes import ConfigChange as _ConfigChange

            current_subnets = config_manager.get(
                "general.safeties.allowed_subnets", default=None
            )
            target_subnets = list(parsed_subnets)
            subnets_change = _ConfigChange(
                key="general.safeties.allowed_subnets",
                current=current_subnets,
                target=target_subnets,
                no_op=current_subnets == target_subnets,
            )
            config_manager.set(
                "general.safeties.allowed_subnets", target_subnets
            )
            config_manager.save()
            if not subnets_change.no_op:
                applied_changes = applied_changes + (subnets_change,)

    if json_output:
        payload = plan.to_dict()
        payload["write_requested"] = bool(write)
        payload["unmet_gates"] = list(unmet_gates)
        payload["applied"] = bool(write and not unmet_gates)
        payload["changes_applied_count"] = len(applied_changes)
        payload["allowed_subnets_supplied"] = list(parsed_subnets)
        typer.echo(json.dumps(payload, indent=2, default=str))
        # Refusal exit code MUST be preserved across output modes.
        # An automation harness that runs
        # ``apply-mode-profile emulate --write --json`` without the
        # confirmation flag is relying on the process status code to
        # detect a blocked apply (the docstring promises exit code 2
        # on unmet gates). The early ``return`` here previously
        # short-circuited the refusal exit and let unmet-gate runs
        # exit 0, breaking the contract (Codex P1 on PR #180).
        if write and unmet_gates:
            raise typer.Exit(code=2)
        return

    header = (
        f"[bold cyan]Apply plan:[/] mode={plan.mode} "
        f"({'WRITE' if write else 'preview-only'})"
    )
    tree = Tree(header)
    tree.add(f"Description: {plan.description}")
    tree.add(
        f"Changes pending write: {len(plan.changes_to_write)} "
        f"(of {len(plan.changes)} total)"
    )

    if plan.changes:
        changes_node = tree.add("Per-key diff")
        for change in plan.changes:
            tag = "[dim](no-op)[/]" if change.no_op else "[bold yellow](write)[/]"
            changes_node.add(
                f"{change.key}: {change.current!r} -> "
                f"{change.target!r} {tag}"
            )

    if plan.required_gates:
        gates_node = tree.add(
            f"Required gates ({len(plan.required_gates)})"
        )
        for gate in plan.required_gates:
            gates_node.add(gate)

    if plan.warnings:
        warnings_node = tree.add(
            f"[bold red]Warnings ({len(plan.warnings)})[/]"
        )
        for warning in plan.warnings:
            warnings_node.add(warning)

    if write and unmet_gates:
        gate_block = tree.add("[bold red]Refusing to write -- unmet gates[/]")
        for gate in unmet_gates:
            gate_block.add(gate)
        console.print(tree)
        raise typer.Exit(code=2)

    if write and not unmet_gates:
        if applied_changes:
            tree.add(
                f"[bold green]Applied {len(applied_changes)} change(s) "
                f"to config.yaml.[/]"
            )
        else:
            tree.add(
                "[bold green]No changes were needed -- config "
                "already matches the target mode.[/]"
            )

    console.print(tree)


@app.command("build-output-index")
def build_output_index_cmd(
    output_root: Path = typer.Option(  # noqa: B008
        None,
        "--output-root",
        help=(
            "Override BLUEFIRE_OUTPUT_ROOT / general.output_root. "
            "Defaults to the runtime's resolved output root."
        ),
    ),
) -> None:
    """Generate / refresh the top-level ``index.html`` aggregator.

    Writes a single static page at ``<output_root>/index.html``
    listing every run on disk newest-first, with quick links into
    each run's per-run viewer / manifest / report. Useful when
    the orchestrator wrote individual runs but the aggregator
    step failed, or after a manifest was edited manually.

    The command never starts a server, never auto-opens a
    browser, and never makes a network call. Output prints a
    ``file://`` link the operator can copy into their browser.

    Examples:

        # Refresh aggregator for the default output root.
        python -m src.core.cli build-output-index

        # Pin a non-default output root.
        python -m src.core.cli build-output-index --output-root /tmp/lab-output
    """
    root = output_root if output_root else resolve_output_root()
    target = _write_output_index(Path(root))
    console.print(f"[green]Wrote aggregator:[/] {target}")
    console.print("[cyan]Open in browser (copy or click below):[/]")
    console.print(_file_uri(target), no_wrap=True, overflow="ignore")
    console.print(
        "[dim]No server required - the page is fully self-contained.[/]"
    )


@app.command("validate-run")
def validate_run_cmd(
    run_id: str = RUN_ID_ARG,
    output_root: Path = typer.Option(  # noqa: B008
        None,
        "--output-root",
        help=(
            "Override BLUEFIRE_OUTPUT_ROOT / general.output_root. "
            "Defaults to the runtime's resolved output root."
        ),
    ),
    json_output: bool = typer.Option(  # noqa: B008
        False,
        "--json",
        help="Print the validation report as JSON instead of a rich table.",
    ),
) -> None:
    """Validate that a run produced a complete demo bundle.

    Checks the run directory against the canonical demo
    artifact set (manifest.json / index.html / report.md /
    report.json / risk_summary.json / telemetry.jsonl), confirms
    the manifest's detection-draft count matches the on-disk
    ``detections/`` directory, and walks every ``<a href>`` in
    ``index.html`` to ensure each link resolves to a real file
    or directory under the run dir. Useful before sharing a
    run-output zip with someone else, or as a CI check after a
    scenario refactor.

    Exit code is non-zero when any required artifact is missing
    OR any link in the viewer is broken.

    Examples:

        # Validate the latest run.
        python -m src.core.cli validate-run "$(python -m src.core.cli latest-run | grep run_id | awk '{print $4}')"

        # Or by explicit run_id.
        python -m src.core.cli validate-run run-20260507120000-abc123

        # Machine-readable form for CI / scripting.
        python -m src.core.cli validate-run my-run --json
    """
    root = output_root if output_root else resolve_output_root()
    run_dir = _find_run_dir(Path(root), run_id)
    if not run_dir:
        raise typer.BadParameter(
            f"Run not found: {run_id!r} (searched under {root}). "
            "List available runs with `python -m src.core.cli list-runs`.",
            param_hint="run_id",
        )
    report = _validate_run_bundle(run_dir)
    if json_output:
        console.print_json(data=report)
    else:
        if report["ok"]:
            console.print(
                f"[green]OK[/]: run {run_id} bundle is complete "
                "(no missing artifacts, no broken links)."
            )
        else:
            console.print(f"[red]FAIL[/]: run {run_id} bundle has issues.")
            if report["missing"]:
                console.print("[red]Missing artifacts:[/]")
                for artifact in report["missing"]:
                    console.print(f"  - {artifact}")
            if report["broken_links"]:
                console.print("[red]Broken viewer links:[/]")
                for link in report["broken_links"]:
                    console.print(f"  - {link}")
        if report["warnings"]:
            console.print("[yellow]Warnings:[/]")
            for warning in report["warnings"]:
                console.print(f"  - {warning}")
    if not report["ok"]:
        raise typer.Exit(code=1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
