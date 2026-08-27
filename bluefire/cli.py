"""Canonical ``bluefire`` command-line interface."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from .api import (
    APIError,
    browser_console_url,
    generate_browser_bootstrap_capability,
    serve,
)
from .config import AutonomyLevel, RunnerProfile
from .contracts import ExecutionMode, load_scenario
from .product_acceptance import AcceptanceFailure, run_release_acceptance, verify_release_result
from .receiver import (
    DEFAULT_IDLE_TIMEOUT_SECONDS,
    DEFAULT_MAX_BODY_BYTES,
    ReceiverConfig,
    run_loopback_receiver,
)
from .runner_bootstrap import managed_product_root
from .runner_trust import RunnerTrustError, load_local_enrollment
from .service import BlueFireService

_RESOURCE_KINDS = (
    "action",
    "collector",
    "comparison",
    "detection_backend",
    "model_provider",
    "plugin",
    "research_source",
    "runner",
    "runner_profile",
)

_MAX_CLI_JSON_BYTES = 256 * 1024
_MAX_PUBLIC_KEY_TEXT_BYTES = 128


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
    scenario_commands.add_parser("list", help="List active durable scenarios")
    scenario_commands.add_parser("versions", help="List active scenario versions")
    scenario_version = scenario_commands.add_parser(
        "version", help="Read one active or exact scenario version"
    )
    scenario_version.add_argument("scenario_id")
    scenario_version.add_argument("--version", type=int)
    scenario_save = scenario_commands.add_parser(
        "save", help="Validate and save a durable scenario version"
    )
    scenario_save.add_argument("path", type=Path)

    ui = commands.add_parser("ui", help="Serve the local experiment console")
    ui.add_argument("--host", default="127.0.0.1")
    ui.add_argument("--port", type=int, default=8765)

    receiver = commands.add_parser(
        "receiver", help="Receive bounded artifacts on a literal loopback socket"
    )
    receiver.add_argument("--host", default="127.0.0.1")
    receiver.add_argument("--port", type=int, default=4317)
    receiver.add_argument(
        "--max-requests",
        type=int,
        default=1,
        help="Verified accepted artifacts before exit",
    )
    receiver.add_argument(
        "--max-connections",
        type=int,
        default=16,
        help="All TCP connections before exit; at least twice --max-requests",
    )
    receiver.add_argument("--max-body-bytes", type=int, default=DEFAULT_MAX_BODY_BYTES)
    receiver.add_argument("--request-timeout", type=float, default=5.0)
    receiver.add_argument("--idle-timeout", type=float, default=DEFAULT_IDLE_TIMEOUT_SECONDS)
    receiver.add_argument(
        "--storage-dir",
        type=Path,
        help="Explicit receiver-owned directory for content-addressed artifact storage",
    )

    runner = commands.add_parser("runner", help="Manage the authenticated local runner")
    runner_commands = runner.add_subparsers(dest="runner_command", required=True)
    runner_status = runner_commands.add_parser("status", help="Read managed lifecycle status")
    runner_status.add_argument("--profile")
    runner_bootstrap = runner_commands.add_parser(
        "bootstrap", help="Install, verify, and enroll the packaged runner"
    )
    runner_bootstrap.add_argument("--profile")
    runner_bootstrap.add_argument(
        "--allow-upgrade",
        action="store_true",
        help="Confirm a clean compatible runner upgrade",
    )
    runner_start = runner_commands.add_parser(
        "start", help="Start the separately hosted authenticated runner"
    )
    runner_start.add_argument("--profile")
    runner_stop = runner_commands.add_parser("stop", help="Request authenticated runner shutdown")
    runner_stop.add_argument("--profile")
    runner_commands.add_parser("revoke", help="Revoke stopped runner trust")
    runner_remove = runner_commands.add_parser(
        "remove", help="Remove revoked trust and reconciled runner state"
    )
    runner_remove.add_argument(
        "--confirm-runner-id",
        required=True,
        help="Exact runner ID required for destructive removal",
    )

    packages = commands.add_parser("packages", help="Manage signed declarative action packages")
    package_commands = packages.add_subparsers(dest="package_command", required=True)
    package_commands.add_parser(
        "inventory", help="Show installed packages, publisher trust, and active catalog"
    )
    package_detail = package_commands.add_parser("detail", help="Show one installed action package")
    package_detail.add_argument("package_id")

    package_trust = package_commands.add_parser(
        "trust-publisher", help="Enroll one exact local publisher key binding"
    )
    package_trust.add_argument("--publisher-id", required=True)
    package_trust.add_argument("--key-id", required=True)
    package_trust.add_argument("--public-key-file", type=Path, required=True)
    package_trust.add_argument("--provenance-file", type=Path, required=True)
    package_trust.add_argument("--trusted-by", required=True)

    for command in ("suspend-publisher", "revoke-publisher"):
        package_transition = package_commands.add_parser(
            command,
            help=f"{command.split('-', 1)[0].capitalize()} one publisher key binding",
        )
        package_transition.add_argument("publisher_id")
        package_transition.add_argument("key_id")
        package_transition.add_argument("--actor", required=True)
        package_transition.add_argument("--reason", required=True)

    package_install = package_commands.add_parser(
        "install", help="Verify and install one signed package envelope"
    )
    package_install.add_argument("envelope_file", type=Path)
    package_install.add_argument("--installed-by", required=True)

    package_activate = package_commands.add_parser(
        "activate", help="Activate one exact package version against a live runner"
    )
    package_activate.add_argument("package_id")
    package_activate.add_argument("version")
    package_activate.add_argument("--profile", required=True)
    package_activate.add_argument("--activated-by", required=True)
    package_activate.add_argument("--reason", required=True)

    for command, actor_option in (
        ("deactivate", "deactivated-by"),
        ("remove", "removed-by"),
    ):
        package_transition = package_commands.add_parser(
            command, help=f"{command.capitalize()} one exact package version"
        )
        package_transition.add_argument("package_id")
        package_transition.add_argument("version")
        package_transition.add_argument("--package-digest", required=True)
        package_transition.add_argument("--catalog-generation", type=int, required=True)
        package_transition.add_argument("--catalog-digest", required=True)
        package_transition.add_argument(f"--{actor_option}", required=True)
        package_transition.add_argument("--reason", required=True)

    runs = commands.add_parser("runs", help="Inspect immutable run bundles")
    runs_commands = runs.add_subparsers(dest="runs_command", required=True)
    runs_commands.add_parser("list", help="List runs")
    run_detail = runs_commands.add_parser("detail", help="Show one run")
    run_detail.add_argument("run_id")
    run_events = runs_commands.add_parser("events", help="Read one run event stream")
    run_events.add_argument("run_id")
    run_events.add_argument("--after-sequence", type=int, default=0)
    run_events.add_argument("--limit", type=int, default=200)

    detections = commands.add_parser(
        "detections", help="Manage the immutable Detection Lab lifecycle"
    )
    detection_commands = detections.add_subparsers(dest="detection_command", required=True)
    detection_commands.add_parser(
        "health", help="Report parser, compiler, and persistence readiness"
    )
    detection_commands.add_parser("list", help="List persisted detection candidates")
    detection_detail = detection_commands.add_parser("detail", help="Show one detection candidate")
    detection_detail.add_argument("candidate_id")
    detection_create = detection_commands.add_parser(
        "create", help="Create an immutable hypothesis from a JSON request"
    )
    detection_create.add_argument("document", type=Path)
    for operation in (
        "parse",
        "exercise-fixtures",
        "exercise-observed",
        "evaluate-benign",
        "reject",
        "clone",
        "tune",
        "compare",
    ):
        detection_action = detection_commands.add_parser(
            operation,
            help=f"{operation.replace('-', ' ').capitalize()} using a JSON request",
        )
        detection_action.add_argument("candidate_id")
        detection_action.add_argument(
            "document",
            type=Path,
            nargs="?" if operation == "parse" else None,
            help="JSON request object; parse defaults to an empty request",
        )

    settings = commands.add_parser("settings", help="Manage durable secret-safe settings")
    settings_commands = settings.add_subparsers(dest="settings_command", required=True)
    settings_commands.add_parser("list", help="List durable settings")
    setting_set = settings_commands.add_parser("set", help="Save one JSON setting value")
    setting_set.add_argument("key")
    setting_set.add_argument("document", type=Path)

    resources = commands.add_parser("resources", help="Manage typed durable resources")
    resource_commands = resources.add_subparsers(dest="resource_command", required=True)
    resource_list = resource_commands.add_parser("list", help="List one resource kind")
    resource_list.add_argument("kind", choices=_RESOURCE_KINDS)
    resource_get = resource_commands.add_parser("get", help="Read one resource")
    resource_get.add_argument("kind", choices=_RESOURCE_KINDS)
    resource_get.add_argument("resource_id")
    resource_save = resource_commands.add_parser("save", help="Save one JSON resource document")
    resource_save.add_argument("kind", choices=_RESOURCE_KINDS)
    resource_save.add_argument("resource_id")
    resource_save.add_argument("document", type=Path)
    resource_save.add_argument(
        "--status",
        help="Explicit lifecycle status; omitted uses the resource contract's safe default",
    )
    for operation in ("activate", "deactivate", "probe"):
        resource_action = resource_commands.add_parser(
            operation, help=f"{operation.capitalize()} one supported runtime resource"
        )
        resource_action.add_argument("kind", choices=_RESOURCE_KINDS)
        resource_action.add_argument("resource_id")

    jobs = commands.add_parser("jobs", help="Inspect and control durable run jobs")
    job_commands = jobs.add_subparsers(dest="job_command", required=True)
    job_detail = job_commands.add_parser("detail", help="Show one durable job")
    job_detail.add_argument("job_id")
    job_approval = job_commands.add_parser("approve", help="Approve one reviewed Execute job")
    job_approval.add_argument("job_id")
    job_approval.add_argument("--approved-by", required=True)
    for operation in ("pause", "resume", "cancel", "retry"):
        job_action = job_commands.add_parser(operation, help=f"{operation.capitalize()} one job")
        job_action.add_argument("job_id")
    proposal_list = job_commands.add_parser(
        "proposals", help="List durable AI proposal reviews for one job"
    )
    proposal_list.add_argument("job_id")
    proposal_detail = job_commands.add_parser("proposal", help="Show one AI proposal review")
    proposal_detail.add_argument("job_id")
    proposal_detail.add_argument("proposal_record_id")
    for operation in ("proposal-accept", "proposal-reject"):
        proposal_action = job_commands.add_parser(
            operation, help=f"{operation.replace('-', ' ').capitalize()} with a JSON decision"
        )
        proposal_action.add_argument("job_id")
        proposal_action.add_argument("proposal_record_id")
        proposal_action.add_argument("document", type=Path)

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

    acceptance = commands.add_parser(
        "acceptance", help="Run the locked machine-verifiable release contract"
    )
    acceptance_commands = acceptance.add_subparsers(dest="acceptance_command", required=True)
    acceptance_run = acceptance_commands.add_parser(
        "run", help="Execute every required product release gate"
    )
    acceptance_run.add_argument("--release", action="store_true", required=True)
    acceptance_run.add_argument("--repository-root", type=Path)
    acceptance_run.add_argument("--output-dir", type=Path)
    acceptance_verify = acceptance_commands.add_parser(
        "verify", help="Verify a persisted release result and all referenced artifacts"
    )
    acceptance_verify.add_argument("--result", type=Path, required=True)
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
    if args.command == "receiver":
        return run_loopback_receiver(
            ReceiverConfig(
                authentication_key=_managed_receiver_authentication_key(),
                host=args.host,
                port=args.port,
                max_requests=args.max_requests,
                max_connections=args.max_connections,
                max_body_bytes=args.max_body_bytes,
                request_timeout_seconds=args.request_timeout,
                idle_timeout_seconds=args.idle_timeout,
                storage_dir=args.storage_dir,
            )
        )
    if args.command == "acceptance":
        if args.acceptance_command == "verify":
            return verify_release_result(args.result)
        return run_release_acceptance(
            repository_root=args.repository_root,
            output_dir=args.output_dir,
        )
    service = _service(args)
    if args.command == "scenario":
        if args.scenario_command == "list":
            return service.scenarios()
        if args.scenario_command == "versions":
            return service.scenario_versions()
        if args.scenario_command == "version":
            return service.scenario_version(args.scenario_id, version=args.version)
        if args.scenario_command == "save":
            return service.save_scenario_version({"scenario": load_scenario(args.path).to_dict()})
        if args.scenario_command == "validate":
            return service.validate(_scenario_reference_payload(args))
        payload = _scenario_payload(args)
        if args.scenario_command == "preview":
            return service.preflight(payload)
        return service.run(payload)
    if args.command == "ui":
        browser_capability = generate_browser_bootstrap_capability()

        def announce_ready(server: Any) -> None:
            address = server.server_address
            if not isinstance(address, tuple) or len(address) < 2:
                raise RuntimeError("The local console listener address is unavailable.")
            launch_url = browser_console_url(
                str(address[0]),
                int(address[1]),
                browser_capability,
            )
            print(f"BlueFire local console: {launch_url}", file=sys.stderr)
            sys.stderr.flush()

        serve(
            service,
            host=args.host,
            port=args.port,
            browser_bootstrap_capability=browser_capability,
            on_ready=announce_ready,
        )
        return None
    if args.command == "runner":
        if args.runner_command == "status":
            return service.runner_status(profile_id=args.profile)
        if args.runner_command == "bootstrap":
            return service.bootstrap_runner(
                profile_id=args.profile,
                allow_upgrade=args.allow_upgrade,
            )
        if args.runner_command == "start":
            return service.start_runner(profile_id=args.profile)
        if args.runner_command == "stop":
            return service.stop_runner(profile_id=args.profile)
        if args.runner_command == "revoke":
            return service.revoke_runner()
        return service.remove_runner(confirm_runner_id=args.confirm_runner_id)
    if args.command == "packages":
        if args.package_command == "inventory":
            return service.action_packages()
        if args.package_command == "detail":
            return service.action_package(args.package_id)
        if args.package_command == "trust-publisher":
            return service.trust_action_package_publisher(
                {
                    "publisher_id": args.publisher_id,
                    "key_id": args.key_id,
                    "public_key": _public_key_bytes(args.public_key_file),
                    "provenance": _json_object(args.provenance_file),
                    "trusted_by": args.trusted_by,
                }
            )
        if args.package_command in {"suspend-publisher", "revoke-publisher"}:
            action = args.package_command.removesuffix("-publisher")
            return service.transition_action_package_publisher(
                args.publisher_id,
                args.key_id,
                action,
                {"actor": args.actor, "reason": args.reason},
            )
        if args.package_command == "install":
            return service.install_action_package(
                {
                    "envelope": _json_object(args.envelope_file),
                    "installed_by": args.installed_by,
                }
            )
        if args.package_command == "activate":
            return service.activate_action_package(
                args.package_id,
                args.version,
                {
                    "runner_profile_id": args.profile,
                    "activated_by": args.activated_by,
                    "reason": args.reason,
                },
            )
        package_lifecycle_request = {
            "package_digest": args.package_digest,
            "expected_catalog_generation": args.catalog_generation,
            "expected_catalog_digest": args.catalog_digest,
            f"{args.package_command}d_by": getattr(args, f"{args.package_command}d_by"),
            "reason": args.reason,
        }
        if args.package_command == "deactivate":
            return service.deactivate_action_package(
                args.package_id,
                args.version,
                package_lifecycle_request,
            )
        return service.remove_action_package(
            args.package_id,
            args.version,
            package_lifecycle_request,
        )
    if args.command == "runs":
        if args.runs_command == "list":
            return service.list()
        if args.runs_command == "events":
            return service.events(
                args.run_id,
                after_sequence=args.after_sequence,
                limit=args.limit,
            )
        return service.detail(args.run_id)
    if args.command == "detections":
        if args.detection_command == "health":
            return service.detection_health()
        if args.detection_command == "list":
            return service.detection_candidates()
        if args.detection_command == "detail":
            return service.detection_candidate(args.candidate_id)
        if args.detection_command == "create":
            return service.upsert_detection_hypothesis(_json_object(args.document))
        detection_request = _json_object(args.document) if args.document is not None else {}
        operations = {
            "parse": service.parse_detection_candidate,
            "exercise-fixtures": service.exercise_detection_fixtures,
            "exercise-observed": service.exercise_detection_observed,
            "evaluate-benign": service.evaluate_detection_benign,
            "reject": service.reject_detection_candidate,
            "clone": service.clone_detection_candidate,
            "tune": service.tune_detection_candidate,
            "compare": service.compare_detection_candidates,
        }
        return operations[args.detection_command](args.candidate_id, detection_request)
    if args.command == "settings":
        if args.settings_command == "list":
            return service.settings()
        return service.upsert_setting(args.key, {"value": _json_object(args.document)})
    if args.command == "resources":
        if args.resource_command == "list":
            return service.resources(args.kind)
        if args.resource_command == "get":
            return service.resource(args.kind, args.resource_id)
        if args.resource_command == "save":
            resource_request: dict[str, Any] = {"document": _json_object(args.document)}
            if args.status is not None:
                resource_request["status"] = args.status
            return service.save_resource(
                args.kind,
                args.resource_id,
                resource_request,
            )
        if args.resource_command == "activate":
            return service.activate_resource(args.kind, args.resource_id, {})
        if args.resource_command == "deactivate":
            return service.deactivate_resource(args.kind, args.resource_id, {})
        if args.resource_command == "probe":
            if args.kind != "runner_profile":
                raise ValueError("resource probe currently supports runner_profile only")
            return service.probe_runner_profile(args.resource_id, {})
    if args.command == "jobs":
        if args.job_command == "detail":
            return service.job(args.job_id)
        if args.job_command == "approve":
            return service.approve_job(args.job_id, {"approved_by": args.approved_by})
        if args.job_command == "pause":
            return service.pause_job(args.job_id)
        if args.job_command == "resume":
            return service.resume_job(args.job_id)
        if args.job_command == "cancel":
            return service.cancel_job(args.job_id)
        if args.job_command == "retry":
            return service.retry_job(args.job_id)
        if args.job_command == "proposals":
            return service.proposal_reviews(args.job_id)
        if args.job_command == "proposal":
            return service.proposal_review(args.job_id, args.proposal_record_id)
        proposal_review_request = _json_object(args.document)
        if args.job_command == "proposal-accept":
            return service.accept_proposal_review(
                args.job_id,
                args.proposal_record_id,
                proposal_review_request,
            )
        if args.job_command == "proposal-reject":
            return service.reject_proposal_review(
                args.job_id,
                args.proposal_record_id,
                proposal_review_request,
            )
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


def _managed_receiver_authentication_key() -> bytes:
    """Load only active enrollment material without exposing its managed path."""

    try:
        enrollment = load_local_enrollment(
            managed_product_root() / "enrollment",
            require_active=True,
        )
        key = enrollment.hmac_key()
    except (OSError, RunnerTrustError):
        raise RuntimeError(
            "Managed receiver authentication is unavailable; bootstrap and start an active runner enrollment first."
        ) from None
    if type(key) is not bytes or len(key) != 32:
        raise RuntimeError("Managed receiver authentication is unavailable.")
    return key


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


def _json_object(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(
            _bounded_utf8_text(
                path,
                maximum_bytes=_MAX_CLI_JSON_BYTES,
                description="JSON object",
            )
        )
    except json.JSONDecodeError as exc:
        raise ValueError("unable to read JSON object") from exc
    if not isinstance(value, Mapping):
        raise ValueError("JSON document must contain an object")
    return dict(value)


def _public_key_bytes(path: Path) -> bytes:
    encoded = _bounded_utf8_text(
        path,
        maximum_bytes=_MAX_PUBLIC_KEY_TEXT_BYTES,
        description="publisher public key",
    ).strip()
    if not encoded or "=" in encoded:
        raise ValueError("publisher public key must be canonical unpadded base64url text")
    try:
        padded = encoded + "=" * (-len(encoded) % 4)
        raw = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ValueError("publisher public key must be canonical unpadded base64url text") from exc
    canonical = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    if len(raw) != 32 or canonical != encoded:
        raise ValueError("publisher public key must encode exactly 32 raw bytes")
    return raw


def _bounded_utf8_text(
    path: Path,
    *,
    maximum_bytes: int,
    description: str,
) -> str:
    try:
        with path.open("rb") as source:
            payload = source.read(maximum_bytes + 1)
    except OSError as exc:
        raise ValueError(f"unable to read {description}") from exc
    if len(payload) > maximum_bytes:
        raise ValueError(f"{description} exceeds the {maximum_bytes}-byte CLI limit")
    try:
        return payload.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError(f"{description} must contain UTF-8 text") from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        result = _execute(args)
    except AcceptanceFailure as exc:
        _json(exc.result)
        return 1
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
