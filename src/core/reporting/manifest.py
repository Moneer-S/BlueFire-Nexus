"""Run manifest: a single JSON view of every artifact a run produced.

Why this exists
---------------

A scenario run scatters output across the run directory:
``report.md``, ``report.json``, ``risk_summary.json``,
``telemetry.jsonl``, per-engine detection drafts under
``detections/<sigma|yara_l|spl>/``, and (when AI is enabled)
copilot artifacts (``copilot_plan.txt`` /
``copilot_narrative.md`` / ``copilot_detections.md``). Each is
written by a different writer and pointed to by a different
return-dict key.

The manifest is the **single machine-readable index** of those
artifacts. A downstream consumer (the static HTML viewer in
``src/core/reporting/viewer.py``, an external tooling pipeline,
the operator's own scripts) only needs to load
``output/<run_id>/manifest.json`` to discover everything the run
produced — no need to walk the directory or know which writer
emitted which file.

Design rules
------------

1. **Local-only.** No network calls, no remote URLs, no SIEM
   exporter shape. The manifest is a local artifact like every
   other run output.
2. **Paths relative to the run directory.** Every path written
   into the manifest is relative to the run dir (resolved when
   present, kept as-is when missing). A run dir can be moved
   around without invalidating the manifest. Absolute paths leak
   environment specifics (home directories, mount points) and
   make the file less reproducible.
3. **No duplication of large content.** The manifest references
   files; it does NOT inline ``report.md`` body text or
   ``telemetry.jsonl`` events. Counts and small metadata only.
4. **Deterministic shape.** Same set of keys regardless of which
   optional artifacts are present; missing artifacts get
   ``null`` or empty defaults rather than silently dropping the
   key. Stable shape simplifies test assertions and viewer
   rendering.
5. **Schema versioned.** ``manifest.schema_version`` is an
   integer that increments on breaking shape changes so the
   viewer / external tools can fail loudly on an unknown
   version rather than reading a stale layout.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Mapping
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import ModuleResult


# Schema version for the manifest. Bump on any breaking change to
# the on-disk shape so consumers can detect drift.
MANIFEST_SCHEMA_VERSION = 1


def _relative_path(path: Optional[str | Path], run_dir: Path) -> Optional[str]:
    """Render an absolute or relative path as run-dir-relative.

    Returns ``None`` when ``path`` is missing / empty so the
    manifest's optional fields stay consistently nullable.
    Falls back to the raw string when ``Path.relative_to`` fails
    (the run dir was moved, the path is on a different drive on
    Windows, etc.). The fallback never raises — the manifest is
    best-effort attribution, not a strict typed schema.
    """
    if path is None or path == "":
        return None
    try:
        candidate = Path(path)
    except (TypeError, ValueError):
        return str(path)
    run_dir_abs = Path(run_dir).resolve()
    try:
        relative = candidate.resolve().relative_to(run_dir_abs)
    except ValueError:
        # On Windows, two different drives raise ValueError. Fall back
        # to a posix-style relative attempt via os.path.relpath, which
        # is more permissive but still reasonable for sibling paths.
        try:
            return Path(os.path.relpath(str(candidate), str(run_dir_abs))).as_posix()
        except ValueError:
            return str(candidate)
    return relative.as_posix()


def _utc_now_isoformat() -> str:
    """Manifest-side UTC timestamp helper. Centralised so tests can monkey-patch."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safety_summary(config: Mapping[str, Any] | None) -> Dict[str, Any]:
    """Surface the run's effective safety / mode settings.

    Only reads what is documented to live under ``general`` /
    ``general.safeties``; never reaches into module-specific
    config blocks. Defaults match the local-first baseline.
    """
    general = (config or {}).get("general") if isinstance(config, Mapping) else None
    if not isinstance(general, Mapping):
        general = {}
    safeties = general.get("safeties") if isinstance(general.get("safeties"), Mapping) else {}
    return {
        "dry_run": bool(general.get("dry_run", True)),
        "max_runtime": int(safeties.get("max_runtime", 3600)),
        "allowed_subnets": list(safeties.get("allowed_subnets", [])),
        "allowed_domains": list(safeties.get("allowed_domains", [])),
    }


def _module_status_summary(steps: Iterable[Mapping[str, Any]]) -> Dict[str, int]:
    """Aggregate per-step status counts so the viewer header has a glance."""
    counts: Dict[str, int] = {}
    for step in steps:
        status = str(step.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    return counts


_PROPAGATION_NARRATIVE_TEMPLATES: Dict[str, str] = {
    # Each template is rendered against four substitution slots:
    #   {to_module}    — downstream module name (e.g. ``credential_access``)
    #   {from_module}  — upstream module name (or ``"upstream"`` if unknown)
    #   {to_step}      — downstream step id
    #   {from_step}    — upstream step id
    # Templates are written in defender-facing prose. The verb
    # patterns ("targets" / "pivots from" / "beacons to") are
    # specific to each propagation kind so a defender can tell the
    # axes apart at a glance; the upstream verb is the
    # module-agnostic ``"produced by"`` so the prose reads
    # correctly whether the upstream step was discovery
    # (enumerated targets), collection (staged data), or
    # resource_development (registered domain). The viewer
    # surfaces the rendered string as a story column so the
    # propagation table reads as a chain narrative, not a graph.
    "target_from_step": (
        "{to_module} targets the host produced by the "
        "{from_module} step '{from_step}'"
    ),
    "source_from_step": (
        "{to_module} pivots from the host produced by the "
        "{from_module} step '{from_step}'"
    ),
    "c2_endpoint_from_step": (
        "{to_module} beacons to the endpoint produced by the "
        "{from_module} step '{from_step}'"
    ),
}


def _render_propagation_narrative(
    *,
    kind: str,
    from_step: str,
    from_module: str,
    to_step: str,
    to_module: str,
) -> str:
    """Render a one-sentence prose description for a propagation edge.

    Returns a defender-facing line such as ``"credential_access
    targets the host the discovery step 'enumerate-files'
    enumerated"``. The kind drives the template; missing module
    names degrade to empty strings rather than ``None`` so the
    rendered text never carries the literal ``None``.
    """
    template = _PROPAGATION_NARRATIVE_TEMPLATES.get(kind)
    if not template:
        return ""
    return template.format(
        kind=kind,
        from_step=from_step or "",
        from_module=from_module or "upstream",
        to_step=to_step or "",
        to_module=to_module or "downstream",
    )


def _propagation_edges(steps: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Extract the propagation graph from per-step artifacts.

    Modules that consume ``previous_step_results`` record the
    upstream step under one of three keys in their result's
    ``artifacts``:

    - ``target_propagated_from_step`` for the standard
      ``target_from_step`` slot (discovery → credential_access,
      collection → exfiltration, collection → impact, lateral
      destination, ...).
    - ``source_propagated_from_step`` for the lateral_movement
      ``source_from_step`` slot.
    - ``c2_endpoint_propagated_from_step`` for the
      ``command_control`` ``c2_endpoint_from_step`` slot
      (resource_development → command_control endpoint axis).

    The viewer renders these as edges in a propagation graph
    so operators can see how data flowed between steps without
    cross-referencing scenario YAML. Adding a new propagation
    axis means adding the slot here AND in
    ``_PROPAGATION_KEYS`` of
    ``tests/test_enterprise_intrusion_chain_quality.py`` AND
    in the viewer's propagation-section legend, so the new
    axis surfaces at every layer (manifest, viewer, tests).

    Each edge dict carries five fields:

    - ``kind`` — the propagation slot name.
    - ``from_step`` / ``to_step`` — step ids.
    - ``from_module`` / ``to_module`` — module names. ``from_module``
      is resolved by looking the upstream step up in the same
      ``steps`` iterable (single forward pass keeps complexity
      O(n)). When the upstream step is missing from the iterable
      ``from_module`` is the empty string.
    - ``narrative`` — a one-sentence defender-facing description of
      what flowed between the two steps, derived from
      ``_PROPAGATION_NARRATIVE_TEMPLATES``. The viewer renders this
      as a story column; consumers that don't care about prose can
      ignore the field.
    """
    steps_list = list(steps)
    module_by_step: Dict[str, str] = {}
    for step in steps_list:
        step_id = str(step.get("step_id") or "")
        if step_id:
            module_by_step[step_id] = str(step.get("module") or "")

    edges: List[Dict[str, Any]] = []
    for step in steps_list:
        artifacts = step.get("artifacts") or {}
        if not isinstance(artifacts, Mapping):
            continue
        downstream_id = str(step.get("step_id") or "")
        downstream_module = str(step.get("module") or "")
        for kind, key in (
            ("target_from_step", "target_propagated_from_step"),
            ("source_from_step", "source_propagated_from_step"),
            ("c2_endpoint_from_step", "c2_endpoint_propagated_from_step"),
        ):
            upstream = artifacts.get(key)
            if not upstream:
                continue
            upstream_id = str(upstream)
            upstream_module = module_by_step.get(upstream_id, "")
            edges.append(
                {
                    "kind": kind,
                    "from_step": upstream_id,
                    "to_step": downstream_id,
                    "from_module": upstream_module,
                    "to_module": downstream_module,
                    "narrative": _render_propagation_narrative(
                        kind=kind,
                        from_step=upstream_id,
                        from_module=upstream_module,
                        to_step=downstream_id,
                        to_module=downstream_module,
                    ),
                }
            )
    return edges


def _detection_summary(steps: Iterable[Mapping[str, Any]], run_dir: Path) -> Dict[str, Any]:
    """Build a per-engine detection summary from per-step outputs.

    Reports counts and relative paths per engine (``sigma`` /
    ``yara_l`` / ``spl``). Paths are normalised to run-dir-
    relative form so the manifest is portable.
    """
    engine_counts: Dict[str, int] = {}
    per_step: List[Dict[str, Any]] = []
    for step in steps:
        detections = step.get("detections")
        if not isinstance(detections, Mapping):
            continue
        engines: Dict[str, List[str]] = {}
        for engine, paths in detections.items():
            if isinstance(paths, list):
                normalised = [
                    _relative_path(path, run_dir) for path in paths if path
                ]
                normalised = [p for p in normalised if p]
            elif paths:
                rel = _relative_path(str(paths), run_dir)
                normalised = [rel] if rel else []
            else:
                normalised = []
            if normalised:
                engines[str(engine)] = normalised
                engine_counts[str(engine)] = engine_counts.get(str(engine), 0) + len(normalised)
        if engines:
            per_step.append(
                {
                    "step_id": str(step.get("step_id") or ""),
                    "module": str(step.get("module") or ""),
                    "engines": engines,
                }
            )
    return {
        "engine_counts": engine_counts,
        "total": sum(engine_counts.values()),
        "per_step": per_step,
    }


def _attack_coverage(steps: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Build a sorted [{technique, steps[]}] table from emitted runtime techniques."""
    technique_to_steps: Dict[str, List[str]] = {}
    for step in steps:
        for technique in step.get("techniques") or []:
            if not technique:
                continue
            key = str(technique)
            step_id = str(step.get("step_id") or step.get("module") or "")
            technique_to_steps.setdefault(key, []).append(step_id)
    return [
        {"technique": tech, "steps": sorted(set(technique_to_steps[tech]))}
        for tech in sorted(technique_to_steps)
    ]


def _telemetry_summary(run_dir: Path) -> Dict[str, Any]:
    """Surface telemetry-event counts without inlining the whole stream.

    Reads ``telemetry.jsonl`` line-by-line so a large telemetry
    file does not blow out memory. Counts events by ``event_type``
    and by emitting module. The manifest references the file by
    path; consumers that need raw events read it directly.
    """
    telemetry_path = run_dir / "telemetry.jsonl"
    if not telemetry_path.exists():
        return {
            "path": None,
            "event_count": 0,
            "events_by_type": {},
            "events_by_module": {},
        }
    events_by_type: Dict[str, int] = {}
    events_by_module: Dict[str, int] = {}
    event_count = 0
    try:
        with telemetry_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(event, dict):
                    continue
                event_count += 1
                event_type = str(event.get("event_type") or event.get("type") or "")
                if event_type:
                    events_by_type[event_type] = events_by_type.get(event_type, 0) + 1
                module = str(event.get("module") or "")
                if module:
                    events_by_module[module] = events_by_module.get(module, 0) + 1
    except OSError:
        # File exists but is unreadable — surface a manifest entry
        # that says so rather than failing the whole manifest write.
        return {
            "path": _relative_path(str(telemetry_path), run_dir),
            "event_count": 0,
            "events_by_type": {},
            "events_by_module": {},
            "error": "telemetry file present but unreadable",
        }
    return {
        "path": _relative_path(str(telemetry_path), run_dir),
        "event_count": event_count,
        "events_by_type": events_by_type,
        "events_by_module": events_by_module,
    }


def _normalise_steps(steps: Iterable[Mapping[str, Any]], run_dir: Path) -> List[Dict[str, Any]]:
    """Render the per-step list with manifest-friendly relative paths.

    The full ``ModuleResult.artifacts`` dict can carry arbitrary
    nested content; the manifest preserves it as-is for now (it's
    bounded by what each module emits) but normalises path-shaped
    values to run-dir-relative form when they look like paths.
    Conservative: only string values that resolve to existing
    paths under ``run_dir`` are rewritten.
    """
    normalised: List[Dict[str, Any]] = []
    for step in steps:
        artifacts = step.get("artifacts") or {}
        if not isinstance(artifacts, Mapping):
            artifacts = {}
        detections = step.get("detections") or {}
        rendered_detections: Dict[str, Any] = {}
        if isinstance(detections, Mapping):
            for engine, paths in detections.items():
                if isinstance(paths, list):
                    rendered_detections[str(engine)] = [
                        _relative_path(path, run_dir) for path in paths if path
                    ]
                elif paths:
                    rel = _relative_path(str(paths), run_dir)
                    if rel:
                        rendered_detections[str(engine)] = [rel]
        normalised.append(
            {
                "step_id": str(step.get("step_id") or ""),
                "module": str(step.get("module") or ""),
                "name": str(step.get("name") or ""),
                "status": str(step.get("status") or ""),
                "message": str(step.get("message") or ""),
                "techniques": list(step.get("techniques") or []),
                "artifacts": dict(artifacts),
                "detections": rendered_detections,
            }
        )
    return normalised


def _copilot_summary(
    copilot_dict: Mapping[str, Any] | None, run_dir: Path
) -> Dict[str, Any]:
    """Render the copilot's returned dict in manifest form.

    Captures provider attribution, fallback / network state,
    relative path to the artifact, and the run summary if
    present. Body text is NOT inlined — consumers open the file.
    """
    if not isinstance(copilot_dict, Mapping):
        return {
            "present": False,
            "provider": None,
            "model": None,
            "generated_at": None,
            "network_disabled": None,
            "fallback_used": None,
            "error": None,
            "path": None,
            "run_summary": None,
        }
    return {
        "present": True,
        "provider": copilot_dict.get("provider"),
        "model": copilot_dict.get("model"),
        "generated_at": copilot_dict.get("generated_at"),
        "network_disabled": copilot_dict.get("network_disabled"),
        "fallback_used": copilot_dict.get("fallback_used"),
        "error": copilot_dict.get("error"),
        "path": _relative_path(copilot_dict.get("path"), run_dir),
        "run_summary": copilot_dict.get("run_summary"),
    }


def build_manifest(
    *,
    run_id: str,
    run_dir: Path,
    scenario_name: str = "",
    scenario_path: str = "",
    scenario_objective: str = "",
    overall_status: str = "",
    started_at: Optional[str] = None,
    finished_at: Optional[str] = None,
    config: Optional[Mapping[str, Any]] = None,
    steps: Optional[Iterable[Mapping[str, Any]]] = None,
    module_results: Optional[Mapping[str, ModuleResult]] = None,
    report_path: Optional[str | Path] = None,
    risk_summary_path: Optional[str | Path] = None,
    risk_summary_payload: Optional[Mapping[str, Any]] = None,
    copilot: Optional[Mapping[str, Any]] = None,
    legacy_controls: Optional[Mapping[str, Any]] = None,
    warnings: Optional[Iterable[str]] = None,
    errors: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Assemble the full manifest dict for a single run.

    The keys are stable across runs even when an artifact is
    absent — consumers can rely on every documented key being
    present (with ``null`` or empty defaults). Use
    :func:`write_manifest` to persist the result; this function
    is pure so tests can assert on shape without touching disk.
    """
    steps_list = list(steps or [])
    normalised_steps = _normalise_steps(steps_list, run_dir)

    json_report_path = run_dir / "report.json"

    manifest: Dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "run": {
            "run_id": str(run_id),
            "scenario_name": str(scenario_name or ""),
            "scenario_path": str(scenario_path or ""),
            "scenario_objective": str(scenario_objective or "").strip(),
            "started_at": started_at,
            "finished_at": finished_at or _utc_now_isoformat(),
            "overall_status": str(overall_status or ""),
            "module_count": len(steps_list),
            "step_status_counts": _module_status_summary(steps_list),
        },
        "safety": _safety_summary(config),
        "steps": normalised_steps,
        "propagation_edges": _propagation_edges(steps_list),
        "attack_coverage": _attack_coverage(steps_list),
        "telemetry": _telemetry_summary(run_dir),
        "detections": _detection_summary(steps_list, run_dir),
        "reports": {
            "report_md": _relative_path(report_path, run_dir),
            "report_json": (
                _relative_path(str(json_report_path), run_dir)
                if json_report_path.exists()
                else None
            ),
            "risk_summary_json": _relative_path(risk_summary_path, run_dir),
        },
        "risk": dict(risk_summary_payload) if isinstance(risk_summary_payload, Mapping) else None,
        "copilot": _copilot_summary(copilot, run_dir),
        "legacy_controls": (
            dict(legacy_controls) if isinstance(legacy_controls, Mapping) else None
        ),
        "warnings": list(warnings or []),
        "errors": list(errors or []),
    }

    # Roll blocked / failed / error step ids into the top-level
    # warnings + errors lists so consumers don't have to scan
    # ``steps`` to surface them. Counts already live under
    # ``run.step_status_counts``.
    blocked: List[str] = []
    error_ids: List[str] = []
    for step in steps_list:
        status = str(step.get("status") or "")
        step_id = str(step.get("step_id") or step.get("module") or "")
        if status == "blocked" and step_id:
            blocked.append(step_id)
        elif status == "error" and step_id:
            error_ids.append(step_id)
    if blocked:
        manifest["blocked_steps"] = blocked
    else:
        manifest["blocked_steps"] = []
    if error_ids:
        # Auto-extend errors with ids when the caller didn't pass any.
        existing = set(manifest["errors"])
        for ident in error_ids:
            label = f"step {ident} reported error status"
            if label not in existing:
                manifest["errors"].append(label)

    # Module results are not inlined as full ModuleResult objects
    # (the per-step entries already cover that surface) but we
    # surface the keys so the viewer has a stable handle on what
    # ran when ``steps`` is shallow (e.g. single-module
    # ``execute_operation`` calls).
    if module_results:
        manifest["module_keys"] = sorted(str(k) for k in module_results.keys())
    else:
        manifest["module_keys"] = []

    return manifest


def write_manifest(
    run_dir: Path,
    manifest: Mapping[str, Any],
    *,
    filename: str = "manifest.json",
) -> Path:
    """Persist a manifest to ``run_dir/<filename>`` as pretty-printed JSON."""
    target = Path(run_dir) / filename
    target.write_text(json.dumps(dict(manifest), indent=2, default=str), encoding="utf-8")
    return target


def write_run_manifest(
    *,
    run_id: str,
    run_dir: Path,
    scenario_name: str = "",
    scenario_path: str = "",
    scenario_objective: str = "",
    overall_status: str = "",
    started_at: Optional[str] = None,
    finished_at: Optional[str] = None,
    config: Optional[Mapping[str, Any]] = None,
    steps: Optional[Iterable[Mapping[str, Any]]] = None,
    module_results: Optional[Mapping[str, ModuleResult]] = None,
    report_path: Optional[str | Path] = None,
    risk_summary_path: Optional[str | Path] = None,
    risk_summary_payload: Optional[Mapping[str, Any]] = None,
    copilot: Optional[Mapping[str, Any]] = None,
    legacy_controls: Optional[Mapping[str, Any]] = None,
    warnings: Optional[Iterable[str]] = None,
    errors: Optional[Iterable[str]] = None,
) -> Path:
    """Convenience wrapper: build + write in one call.

    The orchestrator calls this; tests can call ``build_manifest``
    directly when they want shape assertions without touching
    disk.
    """
    manifest = build_manifest(
        run_id=run_id,
        run_dir=run_dir,
        scenario_name=scenario_name,
        scenario_path=scenario_path,
        scenario_objective=scenario_objective,
        overall_status=overall_status,
        started_at=started_at,
        finished_at=finished_at,
        config=config,
        steps=steps,
        module_results=module_results,
        report_path=report_path,
        risk_summary_path=risk_summary_path,
        risk_summary_payload=risk_summary_payload,
        copilot=copilot,
        legacy_controls=legacy_controls,
        warnings=warnings,
        errors=errors,
    )
    return write_manifest(run_dir, manifest)


def _serialise_module_result(result: ModuleResult) -> Dict[str, Any]:
    """Reusable helper: render a ModuleResult as a manifest-shaped dict."""
    return asdict(result)


def compute_propagation_edges(
    steps: Iterable[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    """Public wrapper around the propagation-edge extractor.

    The orchestrator (and any external tooling) needs the same
    edge list the manifest carries — including the ``narrative``
    field — so the report writer can surface a "Propagation
    narrative" section without re-implementing the walk. Exposing
    a public alias keeps the underscore-prefixed implementation
    free to evolve while still pinning the contract via tests.
    """
    return _propagation_edges(steps)


def highest_risk_tier(manifest_or_risk_summary: Mapping[str, Any]) -> str:
    """Return the highest non-zero severity tier in a manifest / risk block.

    Accepts either:

    - a full manifest dict (the function looks up
      ``manifest["risk"]["risk_summary"]``), OR
    - a risk-summary dict built by ``build_risk_summary`` (the
      function looks up the ``risk_summary`` sub-key directly).

    Returns one of ``"critical"`` / ``"high"`` / ``"medium"`` /
    ``"low"`` or empty when the input carries no risk data or
    every tier is zero. Surfaces the same single tier the static
    dashboard renders as a top-level header badge so the CLI
    summary, manifest consumers, and dashboard agree on the
    "severity arc highest point" answer for a given run.
    """
    if not isinstance(manifest_or_risk_summary, Mapping):
        return ""
    # Try manifest shape first ({risk: {risk_summary: {...}}}).
    risk = manifest_or_risk_summary.get("risk")
    summary: Mapping[str, Any]
    if isinstance(risk, Mapping):
        candidate = risk.get("risk_summary")
        summary = candidate if isinstance(candidate, Mapping) else {}
    else:
        # Fall back to the build_risk_summary shape ({risk_summary: {...}, ...}).
        candidate = manifest_or_risk_summary.get("risk_summary")
        summary = candidate if isinstance(candidate, Mapping) else {}

    for tier in ("critical", "high", "medium", "low"):
        try:
            count = int(summary.get(tier, 0) or 0)
        except (TypeError, ValueError):
            count = 0
        if count > 0:
            return tier
    return ""


__all__ = [
    "MANIFEST_SCHEMA_VERSION",
    "build_manifest",
    "compute_propagation_edges",
    "highest_risk_tier",
    "write_manifest",
    "write_run_manifest",
]
