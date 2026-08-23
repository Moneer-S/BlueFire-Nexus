"""Shared application service for the CLI and loopback web console."""

from __future__ import annotations

from http import HTTPStatus
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .api import APIError
from .comparison import ComparisonError, compare_runs
from .config import BlueFireConfig, RunnerProfile, load_config
from .contracts import ContractError, ExecutionMode, ScenarioDefinition, load_scenario
from .orchestrator import OrchestrationError, Orchestrator
from .registry import BehaviorRegistry, RegistryError, load_builtin_registry
from .replay import ReplayError, ReplayRequest, prepare_replay
from .run_store import RunStore, RunStoreError
from .runner_client import RunnerTransport, RunnerTransportError, SubprocessRustRunner
from .runner_contracts import RunnerContractError, resolve_environment_path

RunnerFactory = Callable[[RunnerProfile], tuple[RunnerTransport, Path]]


class BlueFireService:
    """Synchronous, JSON-only product boundary used by every frontend."""

    def __init__(
        self,
        *,
        project_root: str | Path | None = None,
        config_path: str | Path | None = None,
        runs_dir: str | Path | None = None,
        registry: BehaviorRegistry | None = None,
        config: BlueFireConfig | None = None,
        runner_factory: RunnerFactory | None = None,
    ) -> None:
        root = (
            Path(project_root) if project_root is not None else Path(__file__).resolve().parents[1]
        )
        self.project_root = root.resolve()
        self.registry = registry or load_builtin_registry()
        self.config = config or self._load_default_config(config_path)
        self.store = RunStore(runs_dir or Path.cwd() / ".bluefire-runs")
        self.runner_factory = runner_factory or self._environment_runner
        self._scenarios = (self._load_default_scenario(),)

    def catalog(self) -> Mapping[str, Any]:
        behaviors = [
            self.registry.get_behavior(behavior_id).to_dict()
            for behavior_id in self.registry.behavior_ids
        ]
        actions = [
            self.registry.get_action(action_id).to_dict() for action_id in self.registry.action_ids
        ]
        return {
            "schema_version": "bluefire.catalog-response.v1",
            "modes": [mode.value for mode in ExecutionMode],
            "ai": {
                "enabled": self.config.ai_enabled,
                "independent_of_mode": True,
                "authority": "proposal_only",
            },
            "behaviors": behaviors,
            "actions": actions,
            "runner_profiles": [profile.to_dict() for profile in self.config.runner_profiles],
        }

    def scenarios(self) -> Mapping[str, Any]:
        scenarios = []
        for scenario in self._scenarios:
            self.registry.validate_scenario(scenario)
            scenarios.append(scenario.to_dict())
        return {"schema_version": "bluefire.scenario-list.v1", "scenarios": scenarios}

    def validate(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            scenario = self._scenario(request)
            self.registry.validate_scenario(scenario)
        except (ContractError, RegistryError, KeyError, TypeError, ValueError) as exc:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "scenario_invalid",
                "Scenario validation failed.",
                [str(exc)],
            ) from exc
        return {
            "schema_version": "bluefire.validation.v1",
            "valid": True,
            "issues": [],
            "scenario": scenario.to_dict(),
            "graph": {
                "nodes": [
                    {
                        "id": step.id,
                        "behavior_id": step.behavior_id,
                        "alternates": list(step.alternates),
                    }
                    for step in scenario.steps
                ],
                "edges": [edge.to_dict() for edge in scenario.edges],
            },
        }

    def preflight(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        scenario = self._scenario_or_api_error(request)
        mode = self._mode(request)
        profile = self._profile(request.get("runner_profile_id"), mode)
        approval = self._approval(request, required=False)
        runner: RunnerTransport | None = None
        runner_problem: str | None = None
        if mode is ExecutionMode.EXECUTE:
            try:
                if profile is None:
                    raise RunnerContractError("an Execute runner profile must be selected")
                runner, _sandbox = self.runner_factory(profile)
            except (RunnerContractError, RunnerTransportError, OSError) as exc:
                runner_problem = str(exc)
        orchestrator = Orchestrator(self.registry, self.store, runner=runner)
        try:
            report = orchestrator.preflight(
                scenario,
                mode=mode,
                profile=profile,
                ai_enabled=self._ai_enabled(request),
                approval_present=approval is not None,
            ).to_dict()
        except OrchestrationError as exc:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "preflight_invalid",
                "The scenario cannot be planned.",
                [str(exc)],
            ) from exc
        problems = list(report["problems"])
        if runner_problem:
            problems = [item for item in problems if "Rust runner transport" not in item]
            problems.append(runner_problem)
        scope_problems = self._scope_problems(request, profile, mode)
        problems.extend(scope_problems)
        report["problems"] = problems
        report["findings"] = problems
        if problems:
            only_approval = problems == ["Explicit operator approval is required."]
            report["status"] = "approval_required" if only_approval else "refused"
            report["ready"] = False
        report["runner_profile"] = profile.id if profile else None
        report["scope"] = request.get("target_scope", {"scope_refs": []})
        report["capabilities"] = report["required_capabilities"]
        report["safety_tier"] = self._maximum_tier(scenario)
        report["approval"] = (
            "present"
            if approval
            else ("required" if report["approval_required"] else "not_required")
        )
        report["cleanup"] = {
            "policy": profile.cleanup_policy.value if profile else "simulate_only",
            "action_id": "sandbox.cleanup.v1",
        }
        return report

    def run(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        scenario = self._scenario_or_api_error(request)
        mode = self._mode(request)
        profile = self._profile(request.get("runner_profile_id"), mode)
        approved_by = self._approval(request, required=mode is ExecutionMode.EXECUTE)
        scope_problems = self._scope_problems(request, profile, mode)
        if scope_problems:
            raise APIError(
                HTTPStatus.CONFLICT,
                "scope_refused",
                "Target scope is not authorized.",
                scope_problems,
            )
        runner: RunnerTransport | None = None
        sandbox: Path | None = None
        if mode is ExecutionMode.EXECUTE:
            if profile is None:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "profile_required",
                    "Execute requires an explicit runner profile.",
                )
            try:
                runner, sandbox = self.runner_factory(profile)
            except (RunnerContractError, RunnerTransportError, OSError) as exc:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "runner_unavailable",
                    "The selected Rust runner is unavailable.",
                    [str(exc)],
                ) from exc
        orchestrator = Orchestrator(self.registry, self.store, runner=runner)
        try:
            return orchestrator.run(
                scenario,
                mode=mode,
                profile=profile,
                sandbox_root=sandbox,
                approved_by=approved_by,
                ai_enabled=self._ai_enabled(request),
            )
        except (OrchestrationError, RunnerContractError, RunnerTransportError) as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "run_refused",
                "The run was refused before it could complete.",
                [str(exc)],
            ) from exc

    def list(self) -> Mapping[str, Any]:
        return {"schema_version": "bluefire.run-list.v1", "runs": self.store.list_runs()}

    def detail(self, run_id: str) -> Mapping[str, Any]:
        try:
            return self.store.get_run(run_id)
        except RunStoreError as exc:
            raise APIError(HTTPStatus.NOT_FOUND, "run_not_found", "Run was not found.") from exc

    def replay(self, run_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            prepared = prepare_replay(
                self.store,
                self.registry,
                ReplayRequest(
                    source_run_id=run_id,
                    exact=bool(request.get("exact", False)),
                    from_step_id=self._optional_string(request.get("from_step_id")),
                    swap_step_id=self._optional_string(request.get("swap_step_id")),
                    swap_behavior_id=self._optional_string(request.get("swap_behavior_id")),
                    ai_enabled=(
                        request.get("ai_enabled")
                        if isinstance(request.get("ai_enabled"), bool)
                        else None
                    ),
                    runner_profile_id=self._optional_string(request.get("runner_profile_id")),
                    defense_change=self._optional_string(request.get("defense_change")),
                ),
            )
            source = self.store.get_run(run_id)
            mode = ExecutionMode(str(source.get("mode", "simulate")))
            profile = self._profile(prepared.runner_profile_id, mode)
            approved_by = self._approval(request, required=mode is ExecutionMode.EXECUTE)
            runner: RunnerTransport | None = None
            sandbox: Path | None = None
            if mode is ExecutionMode.EXECUTE:
                if profile is None:
                    raise ReplayError("Execute replay requires an explicit runner profile")
                runner, sandbox = self.runner_factory(profile)
            orchestrator = Orchestrator(self.registry, self.store, runner=runner)
            return orchestrator.run(
                prepared.scenario,
                mode=mode,
                profile=profile,
                sandbox_root=sandbox,
                approved_by=approved_by,
                ai_enabled=prepared.ai_enabled,
                replay=prepared.lineage,
                resume_from_step_id=prepared.resume_from_step_id,
                seed_artifacts=prepared.seed_artifacts,
            )
        except APIError:
            raise
        except (
            ReplayError,
            RunStoreError,
            OrchestrationError,
            RunnerContractError,
            RunnerTransportError,
            ValueError,
        ) as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "replay_refused",
                "Replay could not be prepared safely.",
                [str(exc)],
            ) from exc

    def compare(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        run_ids = request.get("run_ids")
        if not isinstance(run_ids, list) or not all(isinstance(item, str) for item in run_ids):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "run_ids_required",
                "Comparison requires a list of run IDs.",
            )
        try:
            return compare_runs(self.store, run_ids)
        except (ComparisonError, RunStoreError) as exc:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "comparison_invalid",
                "Runs could not be compared.",
                [str(exc)],
            ) from exc

    def _environment_runner(self, profile: RunnerProfile) -> tuple[RunnerTransport, Path]:
        binary = resolve_environment_path(profile.runner_binary, must_exist=True)
        sandbox = resolve_environment_path(profile.sandbox_root, must_exist=False)
        transport_root = self.store.root / ".runner-requests"
        runner = SubprocessRustRunner(
            binary,
            transport_root,
            timeout_seconds=float(profile.budgets.max_seconds + 5),
            output_limit_bytes=min(max(profile.budgets.max_bytes, 4096), 4 * 1024 * 1024),
        )
        return runner, sandbox

    def _scenario(self, request: Mapping[str, Any]) -> ScenarioDefinition:
        value = request.get("scenario")
        if isinstance(value, Mapping):
            return ScenarioDefinition.from_mapping(value)
        scenario_id = request.get("scenario_id")
        if isinstance(scenario_id, str):
            for candidate in self._scenarios:
                if candidate.id == scenario_id:
                    return candidate
        raise ContractError("request must include a scenario object or known scenario_id")

    def _load_default_config(self, configured: str | Path | None) -> BlueFireConfig:
        if configured is not None:
            return load_config(configured)
        checkout_path = self.project_root / "config" / "bluefire.example.yaml"
        if checkout_path.is_file():
            return load_config(checkout_path)
        resource = files("bluefire.data").joinpath("bluefire.example.yaml")
        with as_file(resource) as resource_path:
            return load_config(resource_path)

    def _load_default_scenario(self) -> ScenarioDefinition:
        checkout_path = self.project_root / "scenarios" / "sandbox_research_chain.yaml"
        if checkout_path.is_file():
            return load_scenario(checkout_path)
        resource = files("bluefire.data").joinpath("sandbox_research_chain.yaml")
        with as_file(resource) as resource_path:
            return load_scenario(resource_path)

    def _scenario_or_api_error(self, request: Mapping[str, Any]) -> ScenarioDefinition:
        try:
            scenario = self._scenario(request)
            self.registry.validate_scenario(scenario)
            return scenario
        except (ContractError, RegistryError, KeyError, ValueError, TypeError) as exc:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "scenario_invalid",
                "Scenario validation failed.",
                [str(exc)],
            ) from exc

    @staticmethod
    def _mode(request: Mapping[str, Any]) -> ExecutionMode:
        try:
            return ExecutionMode(request.get("mode", "simulate"))
        except ValueError as exc:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "mode_invalid",
                "Mode must be simulate or execute.",
            ) from exc

    def _profile(self, value: Any, mode: ExecutionMode) -> RunnerProfile | None:
        if value is None or value == "":
            if mode is ExecutionMode.EXECUTE:
                return None
            return next(
                (profile for profile in self.config.runner_profiles if profile.mode is mode),
                None,
            )
        if not isinstance(value, str):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "profile_invalid",
                "runner_profile_id must be a string or null.",
            )
        for profile in self.config.runner_profiles:
            if profile.id == value:
                if profile.mode is not mode:
                    raise APIError(
                        HTTPStatus.CONFLICT,
                        "profile_mode_mismatch",
                        "Runner profile mode does not match the requested mode.",
                    )
                return profile
        raise APIError(HTTPStatus.NOT_FOUND, "profile_not_found", "Runner profile was not found.")

    @staticmethod
    def _approval(request: Mapping[str, Any], *, required: bool) -> str | None:
        value = request.get("approval")
        if value is None:
            if required:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "approval_required",
                    "Execute requires explicit operator approval.",
                )
            return None
        if not isinstance(value, Mapping) or set(value) - {"confirmed", "approved_by"}:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "approval_invalid",
                "Approval must contain only confirmed and approved_by.",
            )
        confirmed = value.get("confirmed") is True
        identity = value.get("approved_by")
        if not confirmed or not isinstance(identity, str) or not identity.strip():
            if required:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "approval_required",
                    "Execute requires an unchecked-by-default explicit approval and identity.",
                )
            return None
        return identity.strip()

    @staticmethod
    def _ai_enabled(request: Mapping[str, Any]) -> bool:
        value = request.get("ai_enabled", False)
        if not isinstance(value, bool):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "ai_flag_invalid",
                "ai_enabled must be a boolean.",
            )
        return value

    @staticmethod
    def _scope_problems(
        request: Mapping[str, Any],
        profile: RunnerProfile | None,
        mode: ExecutionMode,
    ) -> Sequence[str]:
        value = request.get("target_scope", {"scope_refs": ["sandbox.workspace"]})
        if not isinstance(value, Mapping) or set(value) != {"scope_refs"}:
            return ["target_scope must contain only scope_refs"]
        references = value.get("scope_refs")
        if (
            not isinstance(references, list)
            or not references
            or not all(isinstance(item, str) and item for item in references)
        ):
            return ["target_scope.scope_refs must be a non-empty string list"]
        if mode is ExecutionMode.EXECUTE:
            if profile is None:
                return ["an Execute runner profile is required before scope can be resolved"]
            extra = sorted(set(references) - set(profile.scope))
            if extra:
                return ["target scope is outside the selected profile: " + ", ".join(extra)]
        return []

    def _maximum_tier(self, scenario: ScenarioDefinition) -> str:
        ranks = {"safe": 1, "controlled": 2, "restricted": 3}
        tiers = [
            self.registry.get_behavior(step.behavior_id).safety_tier.value
            for step in scenario.steps
        ]
        return max(tiers, key=ranks.__getitem__) if tiers else "safe"

    @staticmethod
    def _optional_string(value: Any) -> str | None:
        return value if isinstance(value, str) and value else None


__all__ = ["BlueFireService", "RunnerFactory"]
