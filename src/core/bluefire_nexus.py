"""Main orchestration runtime for BlueFire-Nexus."""

from __future__ import annotations

import copy
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from .ai import mutate_technique as ai_mutate_technique
from .ai.copilot import AICopilot, summarise_run_state
from .config import ConfigManager
from .configuration import resolve_output_root
from .detections import write_detection_artifacts
from .legacy_controls import build_legacy_summary
from .models import ModuleResult, RunContext
from .modules.chain import ChainContext
from .modules.registry import build_runtime_modules
from .reporting import (
    build_risk_summary,
    compute_propagation_edges,
    highest_risk_tier,
    write_json_report,
    write_markdown_report,
    write_output_index,
    write_risk_summary,
    write_run_manifest,
    write_viewer_for_run,
)
from .safety import SafetyGate, SafetyViolation
from .scenario import load_scenario
from .telemetry import TelemetryBus


__all__ = ["BlueFireNexus", "resolve_output_root"]


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
        """Instance proxy for :func:`resolve_output_root` against ``self.config``."""
        return resolve_output_root(self.config)

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
        previous_step_results: Optional[Mapping[str, Mapping[str, Any]]] = None,
        chain: Optional[ChainContext] = None,
    ) -> Dict[str, Any]:
        """Build the per-step runtime context dict passed to ``module.execute``.

        The optional ``previous_step_results`` mapping carries upstream
        steps' results keyed by step_id, so downstream modules can opt
        into reading prior outputs (e.g. a later credential-access step
        consuming a discovery step's host list). The mapping is always
        present in the returned context (possibly empty) — modules that
        do not opt in simply ignore the key.

        The optional ``chain`` argument is the typed view over the
        accumulated chain artifacts (PR for chaining engine v2). When
        present, its serialisable snapshot lands under
        ``context["chain"]`` so consumers can ask "give me the latest
        credential" / "do we have a host?" without hard-coding the
        upstream step_id. Modules that don't opt in keep using
        ``previous_step_results``; the chain view is additive.

        The mapping is a defensive **deep** copy: nested values like
        ``artifacts``, ``techniques``, and any further-nested
        dicts/lists must remain immune to in-place mutation by the
        receiving module, otherwise downstream steps would see leaked
        state from earlier steps. ``dict(record)`` (shallow copy) is
        not enough — it leaves nested mutables shared with the
        accumulator.
        """
        payload: Dict[str, Any] = {
            "run_context": run_context,
            "run_id": run_context.run_id,
            "dry_run": run_context.dry_run,
            "allowed_subnets": run_context.allowed_subnets,
            "max_runtime": run_context.max_runtime,
            "config": run_context.config,
            "previous_step_results": {
                str(step_id): copy.deepcopy(record)
                for step_id, record in (previous_step_results or {}).items()
            },
            # Always include a chain snapshot so consumers don't need
            # to defensively check for the key. An empty chain has empty
            # by-type / by-step / warnings sub-mappings.
            "chain": chain.snapshot() if chain is not None else {
                "artifacts_by_type": {},
                "artifacts_by_step": {},
                "warnings": [],
            },
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
        started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
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
            # Single-module ``execute_operation`` path: no scenario step
            # to annotate, but the run_id is still useful so a defender
            # concatenating multiple ``telemetry.jsonl`` streams across
            # runs can still trace each event back to its origin.
            telemetry.emit_many(result.telemetry, run_id=context.run_id)

            module_results: Dict[str, ModuleResult] = {}
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
                run_summary = summarise_run_state(
                    run_id=context.run_id,
                    module_results=module_results,
                    detection_summary=detection_summary,
                )
                copilot_artifacts = copilot.narrate(
                    context.run_id, run_summary=run_summary
                )
            else:
                detection_paths = {}
                report_path = None
                risk_summary_path = None
                copilot_artifacts = {}

            # Manifest is written for every run that reaches this point —
            # success or otherwise — so the static viewer always has a
            # consistent shape to render.
            manifest_steps: list[Dict[str, Any]] = [
                {
                    "step_id": module_name,
                    "module": module_name,
                    "name": module_name,
                    "status": result.status,
                    "message": result.message,
                    "techniques": list(result.techniques or []),
                    "artifacts": dict(result.artifacts or {}),
                    "detections": dict(detection_paths or {}),
                }
            ]
            risk_payload = (
                build_risk_summary(module_results) if result.status == "success" else None
            )
            # Track whether the manifest / viewer writes actually
            # succeeded. Closes Codex P2 from PR #71 sweep: returning
            # ``manifest_path``/``viewer_path`` on a failed write
            # turned a handled I/O hiccup into a later, harder-to-
            # diagnose "file not found" for downstream consumers.
            manifest_written: Optional[Path] = None
            viewer_written: Optional[Path] = None
            try:
                manifest_written = write_run_manifest(
                    run_id=context.run_id,
                    run_dir=context.output_dir,
                    scenario_name=module_name,
                    overall_status=result.status,
                    started_at=started_at,
                    config=self.config,
                    steps=manifest_steps,
                    module_results=module_results if result.status == "success" else None,
                    report_path=report_path,
                    risk_summary_path=risk_summary_path,
                    risk_summary_payload=risk_payload,
                    copilot=copilot_artifacts if isinstance(copilot_artifacts, Mapping) else None,
                    legacy_controls=self.legacy_activation_summary(),
                )
            except OSError as manifest_exc:  # pragma: no cover - I/O safety net
                self.logger.warning("manifest write failed: %s", manifest_exc)
            if manifest_written is not None:
                try:
                    viewer_written = write_viewer_for_run(context.output_dir)
                except (OSError, FileNotFoundError, ValueError) as viewer_exc:  # pragma: no cover - I/O safety net
                    self.logger.warning("viewer write failed: %s", viewer_exc)
                # Refresh the top-level run aggregator so the operator
                # gets a current ``output/index.html`` listing every
                # run on disk. A failure here is non-fatal — per-run
                # artifacts are already written by this point.
                try:
                    write_output_index(self._output_root())
                except OSError as index_exc:  # pragma: no cover - I/O safety net
                    self.logger.warning(
                        "output index aggregator write failed: %s", index_exc
                    )

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
                "manifest_path": str(manifest_written) if manifest_written else None,
                "viewer_path": str(viewer_written) if viewer_written else None,
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
        started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        telemetry = TelemetryBus(self.config, context.output_dir)
        safety = SafetyGate(context)
        copilot = AICopilot(context.config, context.output_dir)

        scenario = load_scenario(scenario_path)
        module_results: Dict[str, ModuleResult] = {}
        steps_results: list[Dict[str, Any]] = []
        # Accumulator for step-to-step artifact propagation. Built
        # incrementally after each step completes; passed read-only into
        # subsequent steps' module.execute via _module_context. Modules
        # that don't opt in simply ignore the context key.
        previous_step_results: Dict[str, Dict[str, Any]] = {}
        # Typed view over the chain (PR for chaining engine v2). Indexes
        # every upstream step's artifacts by canonical artifact type and
        # by step_id so consumers can ask "give me the latest credential"
        # without hard-coding the upstream step_id. Built incrementally
        # alongside ``previous_step_results``; both views are passed
        # into the per-step context.
        chain = ChainContext()
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
                            "name": step.name,
                            "objective": step.objective,
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

                    # Record consumer warnings before execution so the
                    # warning timeline reflects "the chain knew this step
                    # was missing X" rather than "the step ran and then
                    # we noticed". Warnings are advisory only - the step
                    # still runs against the consumer's documented
                    # default for the optional / missing slot.
                    chain.record_consumer_warning(
                        step_id=step.step_id,
                        module=step.module,
                        contract=getattr(module, "io_contract", None),
                    )
                    result = module.execute(
                        step_params,
                        self._module_context(
                            context,
                            step=step,
                            previous_step_results=previous_step_results,
                            chain=chain,
                        ),
                    )
                    # Annotate each telemetry event with the scenario
                    # step_id + run_id so a defender concatenating
                    # multiple runs' ``telemetry.jsonl`` files can
                    # trace every event back to the specific step
                    # that produced it (PR #147). Modules typically
                    # leave both fields empty; the bus fills them in
                    # on the way out.
                    telemetry.emit_many(
                        result.telemetry,
                        step_id=step.step_id,
                        run_id=context.run_id,
                    )

                    module_results[f"{step.module}:{step.step_id}"] = result
                    # Record this step's outcome for downstream steps.
                    # Modules that opt into chained inputs read this via
                    # ``context["previous_step_results"][<step_id>]``.
                    # Deep-copy the artifacts so neither the accumulator
                    # nor the receiving module can mutate them through
                    # the ModuleResult instance held by `result`.
                    previous_step_results[step.step_id] = {
                        "status": result.status,
                        "module": step.module,
                        "techniques": list(result.techniques),
                        "artifacts": copy.deepcopy(result.artifacts),
                    }
                    # Index the step's typed emissions into the chain so
                    # downstream steps can ask "latest credential / host
                    # / staged_file" without hard-coding upstream ids.
                    # Skipped when the result is non-success: a failed
                    # step's artifacts are not authoritative chain input.
                    if result.status == "success":
                        chain.record_step(
                            step_id=step.step_id,
                            module=step.module,
                            contract=getattr(module, "io_contract", None),
                            artifacts=result.artifacts or {},
                        )
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
                        "objective": step.objective,
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
                            "objective": step.objective,
                            "message": str(exc),
                        }
                    )
                    # Record the error for downstream steps so they can
                    # decide whether to abort, retry, or proceed without
                    # the upstream output.
                    previous_step_results[step.step_id] = {
                        "status": "error",
                        "module": step.module,
                        "techniques": [],
                        "artifacts": {},
                        "error": str(exc),
                    }
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

            # Compute propagation edges from the per-step results
            # before writing the markdown report so the report's
            # new "Propagation narrative" section reads from the
            # same canonical edge list the manifest builder will
            # surface a moment later. Same shape (kind / from_step
            # / to_step / from_module / to_module / narrative).
            scenario_propagation_edges = compute_propagation_edges(steps_results)
            # Build the per-step objective map keyed by ``module:step_id``
            # so the report.md writer can render a defender-facing
            # ``- Objective: ...`` line in each per-step section. The
            # orchestrator owns this map (not the writer) because the
            # writer takes ``module_results`` keyed by the same
            # composite key — keeping the lookup-shape symmetry here
            # avoids re-deriving step ids inside the renderer.
            step_objectives_by_key: Dict[str, str] = {}
            for step in scenario.steps:
                if step.objective:
                    step_objectives_by_key[f"{step.module}:{step.step_id}"] = (
                        step.objective
                    )
            report_path = write_markdown_report(
                context.output_dir,
                scenario.name,
                module_results,
                detection_summary,
                scenario_objective=scenario.objective,
                propagation_edges=scenario_propagation_edges,
                step_objectives=step_objectives_by_key,
            )
            write_json_report(context.output_dir, module_results)
            risk_summary_path = write_risk_summary(
                context.output_dir,
                module_results,
                scenario_name=scenario.name,
            )
            run_summary = summarise_run_state(
                run_id=context.run_id,
                scenario_name=scenario.name,
                scenario_objective=scenario.objective,
                module_results=module_results,
                detection_summary=detection_summary,
                step_objectives=step_objectives_by_key,
            )
            copilot_summary = copilot.narrate(
                context.run_id, run_summary=run_summary
            )

            # Track whether the manifest / viewer writes actually
            # succeeded; only return the path keys when the file
            # is real on disk. See the matching guard in
            # ``execute_operation``.
            manifest_written: Optional[Path] = None
            viewer_written: Optional[Path] = None
            try:
                manifest_written = write_run_manifest(
                    run_id=context.run_id,
                    run_dir=context.output_dir,
                    scenario_name=scenario.name,
                    scenario_path=str(scenario_path),
                    scenario_objective=scenario.objective,
                    overall_status=overall_status,
                    started_at=started_at,
                    config=self.config,
                    steps=steps_results,
                    module_results=module_results,
                    report_path=report_path,
                    risk_summary_path=risk_summary_path,
                    risk_summary_payload=build_risk_summary(
                        module_results, scenario_name=scenario.name
                    ),
                    copilot=copilot_summary,
                    legacy_controls=self.legacy_activation_summary(),
                    # Surface the typed chain context summary in the
                    # manifest so the static viewer / report layer can
                    # flag consumer steps that ran without an upstream
                    # emission. Snapshot is built incrementally during
                    # the scenario loop above.
                    chain=chain.snapshot(),
                    # Pass the loaded scenario's typed step list so
                    # the manifest writer can compute the static chain
                    # graph (``chain.graph``) alongside the runtime
                    # snapshot. Defenders pivoting on a run bundle
                    # then see both the predicted propagation graph
                    # (from YAML) and the actual runtime chain — the
                    # gap between them is a coverage signal.
                    scenario_steps=scenario.steps,
                )
            except OSError as manifest_exc:  # pragma: no cover - I/O safety net
                self.logger.warning("manifest write failed: %s", manifest_exc)
            if manifest_written is not None:
                try:
                    viewer_written = write_viewer_for_run(context.output_dir)
                except (OSError, FileNotFoundError, ValueError) as viewer_exc:  # pragma: no cover - I/O safety net
                    self.logger.warning("viewer write failed: %s", viewer_exc)
                # Refresh the top-level run aggregator so the operator
                # gets a current ``output/index.html`` listing every
                # run on disk. A failure here is non-fatal — per-run
                # artifacts are already written by this point.
                try:
                    write_output_index(self._output_root())
                except OSError as index_exc:  # pragma: no cover - I/O safety net
                    self.logger.warning(
                        "output index aggregator write failed: %s", index_exc
                    )

            # Compute the highest non-zero severity tier from the
            # same risk-summary payload the manifest carries so the
            # CLI summary table, dashboard header badge, and any
            # external tooling reading the result dict converge on
            # the same "severity arc highest point" answer. Empty
            # string when no tier has any non-zero count (e.g. a
            # blocked-only run with no scored module).
            risk_summary_payload_for_tier = build_risk_summary(
                module_results, scenario_name=scenario.name
            )
            highest_severity = highest_risk_tier(risk_summary_payload_for_tier)
            return {
                "status": overall_status,
                "scenario": scenario.name,
                "run_id": context.run_id,
                "output_dir": str(context.output_dir),
                "steps": steps_results,
                "report_path": str(report_path),
                "risk_summary_path": str(risk_summary_path),
                "manifest_path": str(manifest_written) if manifest_written else None,
                "viewer_path": str(viewer_written) if viewer_written else None,
                "highest_severity": highest_severity,
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
