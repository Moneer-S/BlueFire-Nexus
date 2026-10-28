"""Read-only, authoritative selected-object context for reusable assistance turns."""

from __future__ import annotations

from http import HTTPStatus
from typing import TYPE_CHECKING, Any, Callable, Mapping, Protocol
from urllib.parse import urlencode

from .ai_assistance import COMPARE, REVISE
from .ai_provider_access import AIProviderAccess
from .application_errors import APIError
from .assistance_audit_context import KIND as AUDIT_KIND
from .assistance_audit_context import context as audit_context
from .assistance_audit_context import selection as audit_selection
from .assistance_comparison_context import KIND as COMPARISON_KIND
from .assistance_comparison_context import context as comparison_context
from .assistance_comparison_context import selection as comparison_selection
from .assistance_file_access_context import KIND as FILE_ACCESS_KIND
from .assistance_file_access_context import context as file_access_context
from .assistance_file_access_context import selection as file_access_selection
from .assistance_file_access_retest_context import KIND as FILE_ACCESS_RETEST_KIND
from .assistance_file_access_retest_context import context as file_access_retest_context
from .assistance_file_access_retest_context import selection as file_access_retest_selection
from .assistance_receiver_context import KINDS as RECEIVER_KINDS
from .assistance_runs import AssistanceRunJobs
from .collection_methods import COLLECTION_METHODS
from .config import AIConfig
from .contracts import ScenarioDefinition
from .detection_ai_jobs import DetectionAIJobs
from .detection_create_jobs import DetectionCreateJobs
from .detection_evaluations import _source, _source_binding
from .detection_lab import DetectionLabService
from .graph_ai_jobs import GraphAIJobs
from .job_runtime import RunJobController
from .method_comparison_jobs import MethodComparisonJobs
from .product_store import ProductStore
from .product_store_errors import ProductStoreError
from .registry import BehaviorRegistry
from .util import content_hash

if TYPE_CHECKING:
    from .file_access_control import FileAccessControl

_ANALYSIS_ADAPTERS: dict[
    str,
    tuple[
        Callable[[Mapping[str, Any]], Mapping[str, Any]],
        Callable[[AssistanceContext, Mapping[str, Any]], Mapping[str, Any]],
    ],
] = {
    AUDIT_KIND: (audit_selection, audit_context),
    FILE_ACCESS_KIND: (file_access_selection, file_access_context),
    FILE_ACCESS_RETEST_KIND: (file_access_retest_selection, file_access_retest_context),
    COMPARISON_KIND: (comparison_selection, comparison_context),
}
ANALYSIS_KINDS = frozenset(_ANALYSIS_ADAPTERS)


class AssistanceContext(Protocol):
    """Existing capability services borrowed without importing the composition facade."""

    detection_lab: DetectionLabService
    detection_ai: DetectionAIJobs
    detection_create: DetectionCreateJobs
    graph_ai: GraphAIJobs
    assistance_runs: AssistanceRunJobs
    assistance_receiver: Any
    receiver_defense: Any
    s3_access: Any
    method_comparison: MethodComparisonJobs
    product_store: ProductStore
    registry: BehaviorRegistry
    job_controller: RunJobController
    _provider_access: AIProviderAccess

    def _runtime_ai(self) -> AIConfig: ...

    def comparison_snapshot(self, snapshot_id: str) -> Mapping[str, Any]: ...

    def file_access_composed_retest_linkage(
        self, owner_id: str, attempt_id: str
    ) -> Mapping[str, Any]: ...

    @property
    def file_access(self) -> FileAccessControl: ...


LIMITATIONS = [
    "Assistance selects existing product capabilities; a suggestion is not a successful experiment.",
    "Rule revisions remain in native review. Execute replay requires a separate fresh approval.",
    "Selected observations are development input, not independent held-out validation or deployed prevention evidence.",
    "A committed rule revision advances automatically when this process remains available; reopening can recover an interrupted handoff without repeating completed work.",
]


def submitted(request: Mapping[str, Any]) -> Mapping[str, Any]:
    """Normalize additive selection syntax without changing the durable wire request."""
    chosen = request.get("selection")
    if chosen is None or chosen.get("kind") in {
        "graph",
        "saved_graph",
        "saved_scenario",
        "run_detection",
        *ANALYSIS_KINDS,
        *RECEIVER_KINDS,
    }:
        return request
    return {
        **{key: value for key, value in request.items() if key != "selection"},
        **{key: value for key, value in chosen.items() if key != "kind"},
    }


def is_graph(request: Mapping[str, Any]) -> bool:
    return bool(
        request.get("selection", {}).get("kind")
        in {
            "graph",
            "saved_graph",
            "saved_scenario",
            "run_detection",
            *ANALYSIS_KINDS,
            *RECEIVER_KINDS,
        }
    )


def is_receiver(request):
    return request.get("selection", {}).get("kind") in RECEIVER_KINDS


def is_audit(request):
    return request.get("selection", {}).get("kind") == AUDIT_KIND


def is_file_access(request):
    return request.get("selection", {}).get("kind") in {FILE_ACCESS_KIND, FILE_ACCESS_RETEST_KIND}


def is_analysis_only(request):
    return request.get("selection", {}).get("kind") in ANALYSIS_KINDS


def analysis_selection(value):
    """Validate the exact saved binding without flattening the durable selection."""
    adapter = _ANALYSIS_ADAPTERS.get(value.get("kind"))
    if adapter is None:
        raise ProductStoreError("Select an exact saved analysis context.")
    return adapter[0](value)


def analysis_context(service: AssistanceContext, chosen: Mapping[str, Any]) -> Mapping[str, Any]:
    """Reuse the read-only source adapters for capability-free explanations."""
    kind = chosen.get("kind")
    adapter = _ANALYSIS_ADAPTERS.get(kind) if isinstance(kind, str) else None
    if adapter is None:
        raise ProductStoreError("Select an exact saved analysis context.")
    return adapter[1](service, chosen)


def fresh_analysis_context(
    service: AssistanceContext, chosen: Mapping[str, Any], captured: Mapping[str, Any]
) -> Mapping[str, Any]:
    """Revalidate before provider use/publication while preserving the captured document."""
    current = analysis_context(service, chosen)
    if current != captured:
        raise APIError(
            HTTPStatus.CONFLICT,
            "assistance_turn_refused",
            "The selected saved analysis context changed.",
        )
    return current


def is_creation(request: Mapping[str, Any]) -> bool:
    return bool(request.get("selection", {}).get("kind") == "run_detection")


def is_saved_run(request: Mapping[str, Any]) -> bool:
    return bool(request.get("selection", {}).get("kind") in {"saved_graph", "saved_scenario"})


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
            or step.behavior_id in COLLECTION_METHODS
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
