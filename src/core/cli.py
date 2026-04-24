"""Rich/Typer CLI for BlueFire-Nexus."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.tree import Tree

from .bluefire_nexus import BlueFireNexus

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()
CONFIG_OPTION = typer.Option(Path("config.yaml"), "--config")  # noqa: B008
SCENARIO_ARG = typer.Argument(..., exists=True, readable=True)  # noqa: B008
MODULE_OPTION = typer.Option(..., "--module")  # noqa: B008
PAYLOAD_OPTION = typer.Option("{}", "--payload", help="JSON payload")  # noqa: B008
GOAL_ARG = typer.Argument(...)  # noqa: B008
RUN_ID_ARG = typer.Argument(...)  # noqa: B008


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
) -> None:
    """Run a YAML scenario and print a run summary."""
    nexus = BlueFireNexus(str(config))
    result = nexus.run_scenario_file(str(scenario))
    _print_scenario_result(result)


@app.command("run-operation")
def run_operation_cmd(
    module: str = MODULE_OPTION,
    payload: str = PAYLOAD_OPTION,
    config: Path = CONFIG_OPTION,
) -> None:
    """Run one module operation from inline JSON payload."""
    nexus = BlueFireNexus(str(config))
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


def main() -> None:
    app()


if __name__ == "__main__":
    main()
