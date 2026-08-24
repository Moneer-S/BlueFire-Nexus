"""Canonical ``bluefire`` command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from .api import APIError, serve
from .config import AutonomyLevel, RunnerProfile
from .contracts import ExecutionMode, load_scenario
from .service import BlueFireService


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bluefire",
        description="Evidence-first sandbox research and validation platform.",
    )
    parser.add_argument("--config", type=Path, help="Canonical YAML configuration path")
    parser.add_argument("--runs-dir", type=Path, help="Run-bundle directory")
    commands = parser.add_subparsers(dest="command", required=True)

    scenario = commands.add_parser("scenario", help="Validate, preview, or run a scenario")
    scenario_commands = scenario.add_subparsers(dest="scenario_command", required=True)
    validate = scenario_commands.add_parser("validate", help="Validate a scenario graph")
    _scenario_reference_arguments(validate)
    preview = scenario_commands.add_parser("preview", help="Resolve a scenario preflight")
    _scenario_request_arguments(preview, include_approval=True)
    run = scenario_commands.add_parser("run", help="Run a scenario")
    _scenario_request_arguments(run, include_approval=True)

    ui = commands.add_parser("ui", help="Serve the local experiment console")
    ui.add_argument("--host", default="127.0.0.1")
    ui.add_argument("--port", type=int, default=8765)

    runner = commands.add_parser("runner", help="Inspect the Rust runner")
    runner_commands = runner.add_subparsers(dest="runner_command", required=True)
    runner_status = runner_commands.add_parser("status", help="Read runner inventory")
    runner_status.add_argument("--profile")

    runs = commands.add_parser("runs", help="Inspect immutable run bundles")
    runs_commands = runs.add_subparsers(dest="runs_command", required=True)
    runs_commands.add_parser("list", help="List runs")
    run_detail = runs_commands.add_parser("detail", help="Show one run")
    run_detail.add_argument("run_id")

    replay = commands.add_parser("replay", help="Replay an immutable prior run")
    replay.add_argument("run_id")
    replay.add_argument("--exact", action="store_true")
    replay.add_argument("--from-step-id")
    replay.add_argument("--swap-step-id")
    replay.add_argument("--swap-behavior-id")
    replay.add_argument("--profile")
    replay.add_argument("--autonomy", choices=[level.value for level in AutonomyLevel])
    replay.add_argument("--ai-provider")
    replay.add_argument("--ai-enabled", action=argparse.BooleanOptionalAction, default=None)
    replay.add_argument("--scope-ref", action="append", default=[])
    replay.add_argument("--defense-change")
    replay.add_argument(
        "--action-implementation",
        action="append",
        default=[],
        metavar="STEP_ID=ACTION_ID",
    )
    replay.add_argument("--approve", action="store_true")
    replay.add_argument("--approved-by", default="local-operator")

    compare = commands.add_parser("compare", help="Compare two or more runs")
    compare.add_argument("run_ids", nargs="+")

    bundle = commands.add_parser("bundle", help="Validate run-bundle integrity")
    bundle_commands = bundle.add_subparsers(dest="bundle_command", required=True)
    bundle_validate = bundle_commands.add_parser("validate", help="Validate a bundle manifest")
    bundle_validate.add_argument("run_id")

    plugins = commands.add_parser("plugins", help="Inspect declarative plugin support")
    plugins_commands = plugins.add_subparsers(dest="plugins_command", required=True)
    plugins_commands.add_parser("inventory", help="Show plugin trust boundary")

    research = commands.add_parser("research", help="Inspect restricted research metadata")
    research_commands = research.add_subparsers(dest="research_command", required=True)
    research_commands.add_parser("status", help="Show metadata-only research entries")
    return parser


def _scenario_request_arguments(
    parser: argparse.ArgumentParser,
    *,
    include_approval: bool,
) -> None:
    _scenario_reference_arguments(parser)
    parser.add_argument(
        "--mode", choices=[mode.value for mode in ExecutionMode], default="simulate"
    )
    parser.add_argument("--profile")
    parser.add_argument("--autonomy", choices=[level.value for level in AutonomyLevel])
    parser.add_argument("--ai-provider")
    parser.add_argument(
        "--ai-enabled",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Legacy alias: true maps to assist and false maps to off",
    )
    parser.add_argument("--scope-ref", action="append", default=["sandbox.workspace"])
    parser.add_argument(
        "--action-implementation",
        action="append",
        default=[],
        metavar="STEP_ID=ACTION_ID",
    )
    if include_approval:
        parser.add_argument("--approve", action="store_true")
        parser.add_argument("--approved-by", default="local-operator")


def _service(args: argparse.Namespace) -> BlueFireService:
    return BlueFireService(config_path=args.config, runs_dir=args.runs_dir)


def _scenario_payload(args: argparse.Namespace) -> dict[str, Any]:
    payload: dict[str, Any] = {
        **_scenario_reference_payload(args),
        "mode": args.mode,
        "runner_profile_id": args.profile,
        "target_scope": {"scope_refs": list(dict.fromkeys(args.scope_ref))},
    }
    if args.autonomy is not None:
        payload["autonomy"] = args.autonomy
    if args.ai_enabled is not None:
        payload["ai_enabled"] = args.ai_enabled
    if args.ai_provider is not None:
        payload["ai_provider_id"] = args.ai_provider
    action_implementations = _action_implementation_arguments(args.action_implementation)
    if action_implementations:
        payload["action_implementations"] = action_implementations
    if args.approve:
        payload["approval"] = {"confirmed": True, "approved_by": args.approved_by}
    return payload


def _scenario_reference_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("path", type=Path, nargs="?")
    parser.add_argument(
        "--scenario-id",
        help="Canonical ID of a scenario bundled with BlueFire",
    )


def _scenario_reference_payload(args: argparse.Namespace) -> dict[str, Any]:
    path = args.path
    scenario_id = args.scenario_id
    if (path is None) == (scenario_id is None):
        raise ValueError("select exactly one scenario path or --scenario-id")
    if scenario_id is not None:
        return {"scenario_id": scenario_id}
    return {"scenario": load_scenario(path).to_dict()}


def _json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def _execute(args: argparse.Namespace) -> Mapping[str, Any] | Sequence[Any] | None:
    service = _service(args)
    if args.command == "scenario":
        if args.scenario_command == "validate":
            return service.validate(_scenario_reference_payload(args))
        payload = _scenario_payload(args)
        if args.scenario_command == "preview":
            return service.preflight(payload)
        return service.run(payload)
    if args.command == "ui":
        print(f"BlueFire local console: http://{args.host}:{args.port}", file=sys.stderr)
        serve(service, host=args.host, port=args.port)
        return None
    if args.command == "runner":
        profile = _execute_profile(service, args.profile)
        runner, sandbox = service.runner_factory(profile)
        return {
            "schema_version": "bluefire.runner-status.v1",
            "profile_id": profile.id,
            "sandbox_ready": sandbox.is_dir(),
            "inventory": runner.inventory(),
        }
    if args.command == "runs":
        return service.list() if args.runs_command == "list" else service.detail(args.run_id)
    if args.command == "replay":
        replay_payload: dict[str, Any] = {
            "exact": args.exact,
            "from_step_id": args.from_step_id,
            "swap_step_id": args.swap_step_id,
            "swap_behavior_id": args.swap_behavior_id,
            "runner_profile_id": args.profile,
            "defense_change": args.defense_change,
        }
        if args.autonomy is not None:
            replay_payload["autonomy"] = args.autonomy
        if args.ai_enabled is not None:
            replay_payload["ai_enabled"] = args.ai_enabled
        if args.ai_provider is not None:
            replay_payload["ai_provider_id"] = args.ai_provider
        if args.scope_ref:
            replay_payload["target_scope"] = {"scope_refs": list(dict.fromkeys(args.scope_ref))}
        action_implementations = _action_implementation_arguments(args.action_implementation)
        if action_implementations:
            replay_payload["action_implementations"] = action_implementations
        if args.approve:
            replay_payload["approval"] = {
                "confirmed": True,
                "approved_by": args.approved_by,
            }
        return service.replay(args.run_id, replay_payload)
    if args.command == "compare":
        return service.compare({"run_ids": args.run_ids})
    if args.command == "bundle":
        return service.store.validate_bundle(args.run_id)
    if args.command == "plugins":
        return {
            "schema_version": "bluefire.plugin-inventory.v1",
            "loading_model": "declarative-manifest-only",
            "python_entry_points_enabled": False,
            "installed": [],
        }
    if args.command == "research":
        rows = []
        for behavior_id in service.registry.behavior_ids:
            behavior = service.registry.get_behavior(behavior_id)
            if behavior.execution_state.value == "metadata_only":
                rows.append(
                    {
                        "id": behavior.id,
                        "title": behavior.title,
                        "execution_state": behavior.execution_state.value,
                        "safety_tier": behavior.safety_tier.value,
                        "limitations": list(behavior.limitations),
                    }
                )
        return {"schema_version": "bluefire.research-status.v1", "items": rows}
    raise AssertionError("argparse returned an unknown command")


def _execute_profile(service: BlueFireService, profile_id: str | None) -> RunnerProfile:
    profiles = [
        profile
        for profile in service.config.runner_profiles
        if profile.mode is ExecutionMode.EXECUTE
    ]
    if profile_id is not None:
        profiles = [profile for profile in profiles if profile.id == profile_id]
    if len(profiles) != 1:
        choices = ", ".join(profile.id for profile in service.config.runner_profiles)
        raise ValueError(f"select one Execute profile with --profile; available: {choices}")
    return profiles[0]


def _action_implementation_arguments(values: Sequence[str]) -> Mapping[str, str]:
    result: dict[str, str] = {}
    for value in values:
        step_id, separator, action_id = value.partition("=")
        if not separator or not step_id or not action_id or step_id in result:
            raise ValueError("--action-implementation requires unique STEP_ID=ACTION_ID values")
        result[step_id] = action_id
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        result = _execute(args)
    except APIError as exc:
        _json(
            {
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "details": exc.details,
                }
            }
        )
        return 2
    except (OSError, RuntimeError, ValueError) as exc:
        _json({"error": {"code": "command_failed", "message": str(exc)}})
        return 2
    except KeyboardInterrupt:
        return 130
    if result is not None:
        _json(result)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["main"]
