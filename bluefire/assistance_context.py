"""Read-only, authoritative selected-object context for reusable assistance turns."""

from __future__ import annotations

from typing import Any, Mapping, Protocol
from urllib.parse import urlencode

from .ai_assistance import COMPARE, REVISE
from .ai_provider_access import AIProviderAccess
from .config import AIConfig
from .contracts import ScenarioDefinition
from .detection_ai_jobs import DetectionAIJobs
from .detection_evaluations import _source, _source_binding
from .detection_lab import DetectionLabService
from .job_runtime import RunJobController
from .method_comparison_jobs import MethodComparisonJobs
from .product_store import ProductStore
from .registry import BehaviorRegistry
from .util import content_hash


class AssistanceContext(Protocol):
    """Existing capability services borrowed without importing the composition facade."""

    detection_lab: DetectionLabService
    detection_ai: DetectionAIJobs
    method_comparison: MethodComparisonJobs
    product_store: ProductStore
    registry: BehaviorRegistry
    job_controller: RunJobController
    _provider_access: AIProviderAccess

    def _runtime_ai(self) -> AIConfig: ...


LIMITATIONS = [
    "Assistance selects existing product capabilities; a suggestion is not a successful experiment.",
    "Rule revisions remain in native review. Execute replay requires a separate fresh approval.",
    "Selected observations are development input, not independent held-out validation or deployed prevention evidence.",
    "A committed rule revision advances automatically when this process remains available; reopening can recover an interrupted handoff without repeating completed work.",
]


def detection_path(run_id: str, candidate_id: str, job_id: str | None = None) -> str:
    values = {"run": run_id, "candidate": candidate_id, "candidate_scope": "registry"}
    if job_id:
        values["ai_job"] = job_id
    return "/detection-lab?" + urlencode(values)


def context(service: AssistanceContext, run_id: str, candidate_id: str) -> Mapping[str, Any]:
    with service.detection_lab._lock:
        resource = service.detection_lab._resource(candidate_id)
        candidate = service.detection_lab._candidate_from_resource(resource)
        run, records, observed = _source(service.detection_lab, run_id)
        source = _source_binding(run, records, observed)
        language = candidate.target_language in {"sqlite", "sigma"}
        evidence = 1 <= len(observed) <= 128
        scenario = ScenarioDefinition.from_mapping(run["scenario"])
        compatible = any(
            any(
                alternate in service.registry.compatible_behaviors(step.behavior_id)
                for alternate in step.alternates
            )
            or step.behavior_id
            in {"sandbox.collection.records.v1", "sandbox.collection.archive.v1"}
            for step in scenario.steps
        )
        selected = {
            "run_id": run_id,
            "candidate_id": candidate_id,
            "candidate_resource_digest": resource["digest"],
            "title": candidate.title,
            "definition_digest": candidate.definition_digest,
            "target_language": candidate.target_language,
            "source_binding": source,
        }
        eligible = language and evidence and bool(candidate.rule_source)
        capabilities = [
            {
                "id": REVISE,
                "title": "Revise and evaluate the saved rule",
                "available": eligible,
                "supported_autonomy": ["assist"],
                "reason": (
                    "Requires native review before creating an immutable revision and evaluating it on this source."
                    if eligible
                    else "Select an existing SQLite or Sigma rule and 1–128 independently observed records."
                ),
                "native_path": detection_path(run_id, candidate_id),
            },
            {
                "id": COMPARE,
                "title": "Try the other method with the same detector",
                "available": eligible and compatible,
                "supported_autonomy": ["assist"],
                "reason": (
                    "Requires a compatible registered method, preserved source authority, ready runner for Execute, and fresh native approval."
                    if eligible and compatible
                    else "This source and detector have no supported observed method comparison."
                ),
                "native_path": "/compare?" + urlencode({"source": run_id}),
            },
        ]
        document = {
            "schema_version": "bluefire.assistance-context.v1",
            "selected": selected,
            "capabilities": capabilities,
            "limitations": LIMITATIONS,
        }
        return {**document, "context_digest": content_hash(document)}
