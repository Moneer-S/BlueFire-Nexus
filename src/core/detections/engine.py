"""Detection generation orchestrator."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import yaml

from ..models import ModuleResult
from ..risk import score_module_result
from .sigma import build_sigma_rule
from .spl import render_spl
from .yara_l import generate_yara_l


# Characters that are invalid (or troublesome) in NTFS filenames.
# ``:`` is the worst offender — Windows interprets it as the
# Alternate Data Stream separator, so ``foo:bar.yml`` writes to
# the ``bar.yml`` ADS of the file ``foo``, leaving an empty
# main-stream file behind. The orchestrator builds module-result
# dict keys as ``f"{module}:{step_id}"`` to disambiguate steps
# that reuse the same module; that worked on POSIX but broke
# detection writes on Windows. Sanitise *only* the filename
# component — manifest / coverage records keep the original
# colon-separated key so report tooling can still parse it.
_FILENAME_UNSAFE_CHARS = ':*?"<>|/\\'


def _safe_filename_component(value: str) -> str:
    """Return a filename-safe form of ``value``.

    Replaces every NTFS-unsafe character with ``__`` (double
    underscore — distinct from the single underscore the engine
    uses to glue ``module`` and ``run_id`` so a reader can still
    decode the original ``module:step_id`` -> ``module__step_id``
    swap visually). Trailing whitespace and dots are stripped
    too because Windows resolves ``foo.`` and ``foo `` to ``foo``,
    creating subtle collisions.
    """
    if not value:
        return ""
    result = value
    for ch in _FILENAME_UNSAFE_CHARS:
        result = result.replace(ch, "__")
    return result.rstrip(" .")


def _merge_legacy_hint(result: ModuleResult) -> Dict[str, Any]:
    """Augment detection hint with normalized legacy metadata."""
    hint: Dict[str, Any] = dict(result.detection_hints or {})
    legacy = result.artifacts.get("legacy") if isinstance(result.artifacts, dict) else None
    payload = legacy.get("payload", {}) if isinstance(legacy, dict) else {}
    if isinstance(payload, dict):
        for key in (
            "protocol",
            "endpoint",
            "transport",
            "cadence_seconds",
            "dns_record_type",
            "chunk_size",
            "entropy_signal",
            "actor",
            "tactic",
            "technique",
            "command",
            "target_process",
            "api_hash",
            "capability",
            "legacy_subtype",
            "runtime_warning",
        ):
            value = payload.get(key)
            if value not in (None, "") and key not in hint:
                hint[key] = value
    if isinstance(legacy, dict):
        hint.setdefault("legacy_pack", legacy.get("pack"))
        hint.setdefault("legacy_capability", legacy.get("capability"))
        hint.setdefault("legacy_mode", legacy.get("mode"))
    return hint


def _sigma_doc_to_yaml(rule: Dict[str, Any]) -> str:
    """Render YAML with stable key order for readability."""
    ordered: Dict[str, Any] = {}
    for key in (
        "title",
        "id",
        "status",
        "description",
        "logsource",
        "detection",
        "fields",
        "tags",
        "level",
    ):
        if key in rule:
            ordered[key] = rule[key]
    for key, value in rule.items():
        if key not in ordered:
            ordered[key] = value
    return yaml.safe_dump(ordered, sort_keys=False)


def write_detection_artifacts(
    output_dir: Path,
    run_id: str,
    module_results: Dict[str, ModuleResult],
) -> Dict[str, list[str]]:
    """Write Sigma, YARA-L and SPL detections for each successful module result."""
    detections_dir = output_dir / "detections"
    sigma_dir = detections_dir / "sigma"
    yaral_dir = detections_dir / "yara_l"
    spl_dir = detections_dir / "spl"
    sigma_dir.mkdir(parents=True, exist_ok=True)
    yaral_dir.mkdir(parents=True, exist_ok=True)
    spl_dir.mkdir(parents=True, exist_ok=True)

    generated: Dict[str, list[str]] = {"sigma": [], "yara_l": [], "spl": []}
    telemetry_summary_rows: List[Dict[str, Any]] = []
    for module_name, result in module_results.items():
        if result.status not in {"success", "partial_success"}:
            continue

        hint = _merge_legacy_hint(result)
        risk = score_module_result(result)
        hint.setdefault("risk_score", risk["score"])
        hint.setdefault("risk_severity", risk["severity"])
        technique = (
            hint.get("mitre_technique")
            or hint.get("mitre_technique_id")
            or (result.techniques[0] if result.techniques else "T0000")
        )

        # ``module_name`` is the orchestrator's module-result dict
        # key. For scenario steps that's ``f"{module}:{step_id}"``,
        # which contains a colon — invalid in NTFS filenames and
        # interpreted as an ADS separator. Sanitise for the
        # filesystem path while preserving the original
        # colon-separated form for the rule body / Sigma id /
        # YARA-L meta so tooling that parses those still gets the
        # canonical key.
        safe_module = _safe_filename_component(module_name)
        safe_run_id = _safe_filename_component(run_id)
        stem = f"{safe_module}_{safe_run_id}"

        sigma_rule = build_sigma_rule(run_id, module_name, hint)
        sigma_path = sigma_dir / f"{stem}.yml"
        sigma_path.write_text(_sigma_doc_to_yaml(sigma_rule), encoding="utf-8")
        generated["sigma"].append(str(sigma_path))

        yaral = generate_yara_l(module_name, technique, hint, run_id=run_id)
        yaral_path = yaral_dir / f"{stem}.yaral"
        yaral_path.write_text(yaral, encoding="utf-8")
        generated["yara_l"].append(str(yaral_path))

        spl_path = spl_dir / f"{stem}.spl"
        spl_path.write_text(render_spl(result, run_id, hint_override=hint), encoding="utf-8")
        generated["spl"].append(str(spl_path))

        telemetry_summary_rows.append(
            {
                "module": module_name,
                "technique": technique,
                "legacy_pack": hint.get("legacy_pack", ""),
                "legacy_capability": hint.get("legacy_capability", ""),
                "legacy_mode": hint.get("legacy_mode", ""),
                "legacy_subtype": hint.get("legacy_subtype", ""),
                "risk_score": risk.get("score"),
                "risk_severity": risk.get("severity"),
                "risk_rationale": list(risk.get("rationale", [])),
                "sigma": str(sigma_path),
                "yara_l": str(yaral_path),
                "spl": str(spl_path),
            }
        )

    if telemetry_summary_rows:
        # Same sanitisation applies to the coverage filename — the
        # default run-id format ``run-YYYYMMDDHHMMSS-<hex>`` has no
        # unsafe chars but a future operator-chosen ``run_id``
        # could.
        summary_path = detections_dir / f"coverage_{_safe_filename_component(run_id)}.json"
        summary_path.write_text(
            json.dumps({"detections": telemetry_summary_rows}, indent=2),
            encoding="utf-8",
        )

    return generated
