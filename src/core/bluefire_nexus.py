"""Main orchestration runtime for BlueFire-Nexus."""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from .ai import mutate_technique as ai_mutate_technique
from .ai.copilot import AICopilot
from .config import ConfigManager
from .detections import write_detection_artifacts
from .legacy_controls import build_legacy_summary
from .models import ModuleResult, RunContext
from .modules.registry import build_runtime_modules
from .reporting import write_json_report, write_markdown_report, write_risk_summary
from .safety import SafetyGate, SafetyViolation
from .scenario import load_scenario
from .telemetry import TelemetryBus


class BlueFireNexus:
    """Coordinates scenario execution across registered modules."""

    def __init__(self, config_path: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        self.config_manager = ConfigManager(config_path or "config.yaml")
        self.config = self.config_manager.to_dict()
        self.modules = build_runtime_modules()
        self._configure_modules()
        self.logger.info("BlueFire-Nexus initialized with %d modules.", len(self.modules))

    def _configure_modules(self) -> None:
        modules_cfg = self.config.get("modules", {})
        for name, module in self.modules.items():
            module_cfg = dict(modules_cfg.get(name, {}))
            module_cfg["config_root"] = self.config
            module.update_config(module_cfg)

    def legacy_activation_summary(self) -> Dict[str, Any]:
        """Return effective master and granular legacy capability activation state."""
        return build_legacy_summary(self.config)

    def reload_config(self) -> None:
        self.config_manager = ConfigManager(str(self.config_manager.config_path))
        self.config = self.config_manager.to_dict()
        self._configure_modules()

    def configure_module(self, module_name: str, config_data: Dict[str, Any]) -> None:
        modules_cfg = self.config.setdefault("modules", {})
        existing = modules_cfg.setdefault(module_name, {})
        existing.update(config_data)
        if module_name in self.modules:
            self.modules[module_name].update_config(existing)

    def _output_root(self) -> Path:
        """Return the configured runtime output root (default ``output``).

        Resolution order (first non-empty wins):

        1. ``general.output_root`` in the loaded config — for explicit
           per-config control (production deployments, scenarios that
           pin a specific output location).
        2. ``BLUEFIRE_OUTPUT_ROOT`` env var — for ambient test
           isolation (the test harness sets this once per session so
           tests that do not pass an explicit config still produce
           artifacts under a tmp directory rather than the project-
           root ``output/``).
        3. ``output`` — default, preserves existing CLI behaviour.
        """
        general = self.config.get("general", {}) if isinstance(self.config, Mapping) else {}
        if isinstance(general, Mapping):
            configured = str(general.get("output_root", "")).strip()
            if configured:
                return Path(configured)
        env_root = os.environ.get("BLUEFIRE_OUTPUT_ROOT", "").strip()
        if env_root:
            return Path(env_root)
        return Path("output")

    def _make_run_context(self, run_id: Optional[str] = None) -> RunContext:
        run_identifier = run_id or (
            f"run-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"
        )
        out_dir = self._output_root() / run_identifier
        out_dir.mkdir(parents=True, exist_ok=True)

        safeties = self.config.get("general", {}).get("safeties", {})
        dry_run = bool(self.config.get("general", {}).get("dry_run", True))
        max_runtime = int(safeties.get("max_runtime", 3600))
        allowed_subnets = list(safeties.get("allowed_subnets", []))

        return RunContext(
            run_id=run_identifier,
            output_dir=out_dir,
            config=self.config,
            dry_run=dry_run,
            max_runtime=max_runtime,
            allowed_subnets=allowed_subnets,
        )

    @staticmethod
    def _module_context(
        run_context: RunContext,
        step: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "run_context": run_context,
            "run_id": run_context.run_id,
            "dry_run": run_context.dry_run,
            "allowed_subnets": run_context.allowed_subnets,
            "max_runtime": run_context.max_runtime,
            "config": run_context.config,
        }
        if step is not None:
            payload["step"] = step
        return payload

    def execute_operation(
        self,
        module_name: str,
        operation_data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        context = self._make_run_context()
        telemetry = TelemetryBus(self.config, context.output_dir)
        safety = SafetyGate(context)
        copilot = AICopilot(context.config, context.output_dir)

        if module_name not in self.modules:
            return {"status": "error", "message": f"Unknown module: {module_name}"}

        module = self.modules[module_name]

        try:
            validation_error = module.validate(operation_data)
            if validation_error:
                return {"status": "error", "message": validation_error, "module": module_name}

            safety.ensure_safe(operation_data)
            result: ModuleResult = module.execute(operation_data, self._module_context(context))
            telemetry.emit_many(result.telemetry)

            if result.status == "success":
                module_results = {module_name: result}
                detection_paths = write_detection_artifacts(
                    context.output_dir, context.run_id, module_results
                )
                detection_summary = {
                    module_name: {
                        key: values[0]
                        for key, values in detection_paths.items()
                        if values
                    }
                }
                report_path = write_markdown_report(
                    context.output_dir,
                    module_name,
                    module_results,
                    detection_summary,
                )
                write_json_report(context.output_dir, module_results)
                risk_summary_path = write_risk_summary(context.output_dir, module_results)
                copilot_artifacts = copilot.narrate(context.run_id)
            else:
                detection_paths = {}
                report_path = None
                risk_summary_path = None
                copilot_artifacts = {}

            return {
                "status": result.status,
                "module": module_name,
                "message": result.message,
                "techniques": result.techniques,
                "artifacts": result.artifacts,
                "detection_hints": result.detection_hints,
                "run_id": context.run_id,
                "output_dir": str(context.output_dir),
                "detection_artifacts": detection_paths,
                "report_path": str(report_path) if report_path else None,
                "risk_summary_path": str(risk_summary_path) if risk_summary_path else None,
                "copilot": copilot_artifacts,
                "legacy_controls": self.legacy_activation_summary(),
                "timestamp": result.timestamp,
            }
        except SafetyViolation as exc:
            self.logger.warning("Safety gate blocked operation: %s", exc)
            return {
                "status": "blocked",
                "module": module_name,
                "message": str(exc),
                "run_id": context.run_id,
                "output_dir": str(context.output_dir),
            }
        except Exception as exc:
            self.logger.exception("Unhandled execution failure in module %s", module_name)
            return {
                "status": "error",
                "module": module_name,
                "message": str(exc),
                "run_id": context.run_id,
                "output_dir": str(context.output_dir),
            }
        finally:
            telemetry.close()

    def run_scenario_file(
        self,
        scenario_path: str,
        run_id: Optional[str] = None,
        step_param_overrides: Optional[Mapping[str, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        context = self._make_run_context(run_id=run_id)
        telemetry = TelemetryBus(self.config, context.output_dir)
        safety = SafetyGate(context)
        copilot = AICopilot(context.config, context.output_dir)

        scenario = load_scenario(scenario_path)
        module_results: Dict[str, ModuleResult] = {}
        steps_results: list[Dict[str, Any]] = []
        overall_status = "success"

        try:
            overrides = step_param_overrides or {}
            for step in scenario.steps:
                module = self.modules.get(step.module)
                if not module:
                    overall_status = "error"
                    steps_results.append(
                        {
                            "status": "error",
                            "module": step.module,
                            "message": f"Unknown module '{step.module}'",
                            "step_id": step.step_id,
                        }
                    )
                    if scenario.fail_fast:
                        break
                    continue

                try:
                    step_params = dict(step.params)
                    scoped_overrides = overrides.get(step.step_id) or overrides.get(step.module) or {}
                    if scoped_overrides:
                        step_params.update(dict(scoped_overrides))
                    safety.ensure_safe(step_params)
                    validation_error = module.validate(step_params)
                    if validation_error:
                        raise ValueError(validation_error)

                    result = module.execute(step_params, self._module_context(context, step=step))
                    telemetry.emit_many(result.telemetry)

                    module_results[f"{step.module}:{step.step_id}"] = result
                    detection_paths = write_detection_artifacts(
                        context.output_dir,
                        context.run_id,
                        {f"{step.module}:{step.step_id}": result},
                    )
                    step_result = {
                        "status": result.status,
                        "module": step.module,
                        "step_id": step.step_id,
                        "name": step.name,
                        "message": result.message,
                        "techniques": result.techniques,
                        "artifacts": result.artifacts,
                        "detections": detection_paths,
                    }
                    steps_results.append(step_result)

                    if result.status != "success":
                        if overall_status == "success":
                            overall_status = "partial_success"
                        if scenario.fail_fast:
                            break
                except Exception as exc:
                    overall_status = "error"
                    steps_results.append(
                        {
                            "status": "error",
                            "module": step.module,
                            "step_id": step.step_id,
                            "name": step.name,
                            "message": str(exc),
                        }
                    )
                    if scenario.fail_fast:
                        break

            detection_summary: Dict[str, Dict[str, str]] = {}
            for step_result in steps_results:
                module_name = step_result.get("module")
                step_id = step_result.get("step_id")
                detections = step_result.get("detections") or {}
                if not module_name:
                    continue
                # Key the per-step detections by `module:step_id` so multi-step
                # scenarios that re-use a single module no longer overwrite
                # each other in the rendered report. Falls back to the bare
                # module name when no step_id is present.
                step_key = f"{module_name}:{step_id}" if step_id else str(module_name)
                if isinstance(detections, dict):
                    summarized = {
                        key: values[0] if isinstance(values, list) and values else str(values)
                        for key, values in detections.items()
                    }
                    detection_summary[step_key] = summarized

            report_path = write_markdown_report(
                context.output_dir,
                scenario.name,
                module_results,
                detection_summary,
            )
            write_json_report(context.output_dir, module_results)
            risk_summary_path = write_risk_summary(
                context.output_dir,
                module_results,
                scenario_name=scenario.name,
            )
            copilot_summary = copilot.narrate(context.run_id)

            return {
                "status": overall_status,
                "scenario": scenario.name,
                "run_id": context.run_id,
                "output_dir": str(context.output_dir),
                "steps": steps_results,
                "report_path": str(report_path),
                "risk_summary_path": str(risk_summary_path),
                "copilot": copilot_summary,
                "legacy_controls": self.legacy_activation_summary(),
            }
        finally:
            telemetry.close()

    def generate_plan(self, goal: str) -> Dict[str, str]:
        context = self._make_run_context()
        copilot = AICopilot(self.config, context.output_dir)
        return copilot.plan(goal)

    def suggest_detections(self, run_id: str) -> Dict[str, str]:
        run_dir = self._output_root() / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        copilot = AICopilot(self.config, run_dir)
        return copilot.suggest_detections(run_id)

    def mutate_technique(
        self,
        module_name: str,
        base_params: Mapping[str, Any],
        strategy: str = "evasion-lite",
    ) -> Dict[str, Any]:
        """Apply AI-assisted technique mutation for lab research workflows."""
        run_context = self._make_run_context()
        mutated = ai_mutate_technique(
            module_name=module_name,
            base_params=base_params,
            strategy=strategy,
            run_id=run_context.run_id,
        )
        return mutated
