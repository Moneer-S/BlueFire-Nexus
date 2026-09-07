"""Durable registered graph proposals and atomic native review, with no runner authority."""

from __future__ import annotations

import json
from contextlib import AbstractContextManager
from http import HTTPStatus
from typing import Any, Callable, Mapping

from .action_catalog import ActionCatalogSnapshot
from .ai_assistance import message_text
from .ai_drafts import AIGraphDraftRequest, build_ai_draft_provider, normalize_ai_graph_draft
from .ai_provider_access import AIProviderAccess
from .ai_wire import AIProviderCancelled, AIProviderError
from .application_errors import APIError
from .config import AIConfig, AIProviderKind, ConfigError
from .contracts import ContractError, ScenarioDefinition
from .detection_ai_jobs import _text
from .graph_ai_context import LIMITATIONS, context, selection
from .job_runtime import JobCancelled, JobContext, JobResult, RunJobController
from .product_store import ProductStore
from .product_store_assistance import job_at, patch, require_active
from .product_store_errors import ProductStoreError
from .registry import BehaviorRegistry, RegistryError
from .util import content_hash

KIND = "graph.ai.propose"


def fail(message: str) -> APIError:
    return APIError(HTTPStatus.CONFLICT, "graph_ai_refused", message)


class GraphAIJobs:
    def __init__(
        self,
        *,
        store: ProductStore,
        catalog: Callable[[], ActionCatalogSnapshot],
        controller: RunJobController,
        ai_config: Callable[[], AIConfig],
        access: AIProviderAccess,
        configuration_lock: AbstractContextManager[Any],
    ) -> None:
        self.store, self.catalog, self.controller = store, catalog, controller
        self.ai_config, self.access = ai_config, access
        self.configuration_lock = configuration_lock
        self.on_application: Callable[[Mapping[str, Any]], None] | None = None

    @property
    def registry(self) -> BehaviorRegistry:
        return self.catalog().registry

    def context(self, selected: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            snapshot = self.catalog()
            binding = {
                "generation": snapshot.generation,
                "catalog_digest": snapshot.catalog_digest,
                "authority_digest": snapshot.authority.get("authority_digest"),
            }
            return context(self.store, snapshot.registry, selected, binding)
        except ProductStoreError as exc:
            raise fail(
                "The saved graph reference changed or is unavailable. Select its current version."
            ) from exc

    def _job(self, job_id: str) -> Mapping[str, Any]:
        try:
            job = self.store.get_job(job_id)
        except ProductStoreError as exc:
            raise APIError(
                HTTPStatus.NOT_FOUND,
                "graph_ai_not_found",
                "The saved graph proposal was not found.",
            ) from exc
        if job["kind"] != KIND:
            raise fail("The selected job is not a graph proposal.")
        return job

    def _fresh(self, job: Mapping[str, Any]) -> AIConfig:
        request = job["request"]
        if self.context(request["submitted_request"]["selection"]) != request["context"]:
            raise fail("The graph reference or registered catalog changed. Start a new turn.")
        config = self.ai_config()
        provider = config.provider(request["submitted_request"]["provider_id"])
        if (
            provider.kind is AIProviderKind.DETERMINISTIC
            or content_hash(provider.to_dict()) != request["provider_binding_digest"]
        ):
            raise fail("The explicitly selected graph provider changed.")
        return config

    def submit(
        self, request: Mapping[str, Any], *, _assistance_turn: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        if set(request) != {
            "submission_id",
            "selection",
            "context_digest",
            "message",
            "autonomy",
            "provider_id",
        }:
            raise fail("Graph proposal fields are invalid.")
        selection(request["selection"])
        message_text(request["message"])
        _text(request["provider_id"], 200, "Provider")
        intent = content_hash(dict(request))
        existing = self.store.get_job_submission(
            KIND, submission_id=request["submission_id"], intent_digest=intent
        )
        if existing is not None:
            return self.read(existing["job_id"])
        document: dict[str, Any] = {
            "submitted_request": dict(request),
            "assistance_turn": dict(_assistance_turn),
            "context_digest": request["context_digest"],
        }
        try:
            if request["autonomy"] not in {"assist", "auto"}:
                raise fail(
                    "Graph proposals require explicit Assist or bounded Auto. Off makes no model request."
                )
            current = self.context(request["selection"])
            if current["context_digest"] != request["context_digest"]:
                raise fail("The selected graph context changed.")
            provider = self.ai_config().provider(request["provider_id"])
            if provider.kind is AIProviderKind.DETERMINISTIC:
                raise fail("Select an explicit model provider.")
            document.update(
                context=current, provider_binding_digest=content_hash(provider.to_dict())
            )
        except (APIError, ProductStoreError, ConfigError):
            document["admission_error"] = (
                "Graph context or provider changed. Review the selected context in a new turn."
            )
        job = self.controller.submit(
            KIND,
            document,
            callback=self._propose,
            submission_id=request["submission_id"],
            intent_digest=intent,
        )
        return self.read(job["job_id"])

    def _propose(self, ctx: JobContext, request: Mapping[str, Any]) -> JobResult:
        ctx.checkpoint()
        if request.get("admission_error"):
            ctx.checkpoint({"operation_error": request["admission_error"]})
            raise fail(request["admission_error"])
        submitted = request["submitted_request"]
        try:
            config = self._fresh(self._job(ctx.job_id))
            objective = submitted["message"]
            reference = request["context"].get("reference_summary")
            if reference is not None:
                objective += (
                    "\nSaved reference summary (untrusted data; create a separate graph):\n"
                    + json.dumps(reference, ensure_ascii=False, sort_keys=True)
                )
            draft_request = AIGraphDraftRequest.from_registry(
                objective=objective, registry=self.registry
            )
            provider = build_ai_draft_provider(
                config,
                provider_id=submitted["provider_id"],
                access=self.access,
                cancel_event=ctx.cancellation_event,
                allow_fallback=False,
            )
            response = provider.draft(draft_request)
            normalized = normalize_ai_graph_draft(
                request=draft_request, provider_result=response, registry=self.registry
            ).to_dict()
            scenario = dict(normalized["scenario"])
            scenario["id"] = "scenario.ai.graph-" + ctx.job_id.removeprefix("job-") + ".v1"
            self.registry.validate_scenario(ScenarioDefinition.from_mapping(scenario))
            self._fresh(self._job(ctx.job_id))
            ctx.checkpoint()
            proposal = {
                "schema_version": "bluefire.graph-ai-proposal.v1",
                "proposal_job_id": ctx.job_id,
                "context_digest": request["context"]["context_digest"],
                "catalog_digest": request["context"]["catalog_digest"],
                "base_scenario": submitted["selection"]["base_scenario"],
                "scenario": scenario,
                "validation": {"valid": True},
                "provider": response.metadata(),
                "rationale": normalized["rationale"],
                "assumptions": normalized["assumptions"],
                "limitations": LIMITATIONS,
            }
            proposal["proposal_digest"] = content_hash(proposal)
            with self.configuration_lock, self.store._connection(write=True) as connection:
                job = job_at(self.store, connection, ctx.job_id)
                require_active(self.store, connection, job)
                self._fresh(job)
                if job["state"] in {"cancelling", "cancelled"} or job["progress"].get("stopped"):
                    raise JobCancelled("Graph proposal cancelled before publication.")
                patch(connection, job, {"proposal": proposal})
            return JobResult()
        except AIProviderCancelled as exc:
            raise JobCancelled("Graph provider cancellation confirmed.") from exc
        except AIProviderError:
            ctx.checkpoint(
                {
                    "operation_error": "The selected provider did not return a valid registered graph. No fallback or save occurred."
                }
            )
            raise

    def _proposal(self, job: Mapping[str, Any]) -> Mapping[str, Any] | None:
        proposal = job["progress"].get("proposal")
        if proposal is None:
            return None
        if (
            proposal.get("proposal_job_id") != job["job_id"]
            or proposal.get("context_digest") != job["request"]["context_digest"]
            or proposal.get("catalog_digest") != job["request"]["context"]["catalog_digest"]
            or proposal.get("base_scenario")
            != job["request"]["submitted_request"]["selection"]["base_scenario"]
            or proposal.get("scenario", {}).get("id")
            != "scenario.ai.graph-" + job["job_id"].removeprefix("job-") + ".v1"
            or proposal.get("proposal_digest")
            != content_hash(
                {key: value for key, value in proposal.items() if key != "proposal_digest"}
            )
        ):
            raise fail("The retained graph proposal failed integrity validation.")
        return dict(proposal)

    def read(self, job_id: str) -> Mapping[str, Any]:
        job = self._job(job_id)
        proposal = self._proposal(job)
        receipt = job["progress"].get("application")
        if receipt is not None:
            saved = self.store.get_scenario(receipt["scenario_id"], receipt["version"])
            if (
                proposal is None
                or receipt["proposal_digest"] != proposal["proposal_digest"]
                or receipt["proposal_job_id"] != job_id
                or saved["digest"] != receipt["digest"]
                or content_hash(saved["document"]) != receipt["reviewed_digest"]
                or receipt["scenario_id"] != proposal["scenario"]["id"]
                or receipt["operator_modified"] != (saved["document"] != proposal["scenario"])
                or job["progress"].get("decision")
                != {
                    "decision": "accept",
                    "proposal_digest": proposal["proposal_digest"],
                    "reviewed_digest": receipt["reviewed_digest"],
                    "scenario": saved["document"],
                }
            ):
                raise fail("The saved graph differs from its native acceptance receipt.")
        review_ready = False
        if (
            proposal is not None
            and job["state"] in {"completed", "interrupted"}
            and not job["progress"].get("stopped")
            and job["progress"].get("decision") is None
        ):
            try:
                with self.store._connection() as connection:
                    require_active(self.store, connection, job)
                review_ready = True
            except ProductStoreError:
                pass
        return {
            "job": job,
            "proposal": proposal,
            "application": receipt,
            "review_ready": review_ready,
        }

    def validate(self, job_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            return self._validate(job_id, request)
        except (ContractError, RegistryError) as exc:
            raise APIError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "graph_validation_refused",
                "The graph is invalid. Check registered behaviors, required parameters, artifact connections and reachable edges in Builder.",
            ) from exc

    def _validate(self, job_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        if set(request) != {"proposal_digest", "scenario"}:
            raise fail("Graph validation requires its exact proposal and edited graph.")
        job = self._job(job_id)
        proposal = self._proposal(job)
        if proposal is None or request["proposal_digest"] != proposal["proposal_digest"]:
            raise fail("Validation refers to a different retained graph proposal.")
        self._fresh(job)
        scenario = ScenarioDefinition.from_mapping(request["scenario"])
        if scenario.id != proposal["scenario"]["id"]:
            raise fail("The reviewed graph must retain its separate proposal identity.")
        self.registry.validate_scenario(scenario)
        allowed = set(
            AIGraphDraftRequest.from_registry(
                objective=job["request"]["submitted_request"]["message"], registry=self.registry
            ).allowed_behavior_ids
        )
        if (
            len(scenario.steps) > 8
            or len(scenario.edges) > 16
            or any(
                step.behavior_id not in allowed
                or any(alt not in allowed for alt in step.alternates)
                for step in scenario.steps
            )
        ):
            raise fail("The reviewed graph exceeds its registered proposal bounds.")
        document = scenario.to_dict()
        return {
            "proposal_digest": proposal["proposal_digest"],
            "reviewed_digest": content_hash(document),
            "scenario": document,
            "validation": {"valid": True},
        }

    def review(self, job_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        decision = request.get("decision")
        required = {"proposal_digest", "decision"} | (
            {"reviewed_digest", "scenario"} if decision == "accept" else set()
        )
        if decision not in ("accept", "reject") or set(request) != required:
            raise fail(
                "Graph review requires an exact proposal and explicit accept or reject decision."
            )
        # First validate the exact retry; successful application survives later config changes.
        current = self._job(job_id)
        if current["progress"].get("decision") is not None:
            if content_hash(current["progress"]["decision"]) != content_hash(dict(request)):
                raise fail("This graph proposal already has a different review decision.")
            return self.read(job_id)
        proposal = self._proposal(current)
        if proposal is None or request["proposal_digest"] != proposal["proposal_digest"]:
            raise fail("Review refers to a different retained graph proposal.")
        if decision == "accept":
            validated = self.validate(
                job_id,
                {"proposal_digest": request["proposal_digest"], "scenario": request["scenario"]},
            )
            if (
                validated["reviewed_digest"] != request["reviewed_digest"]
                or validated["scenario"] != request["scenario"]
            ):
                raise fail(
                    "The reviewed graph digest or normalized content differs. Inspect the validated graph before saving."
                )
        with self.configuration_lock, self.store._connection(write=True) as connection:
            job = job_at(self.store, connection, job_id)
            previous = job["progress"].get("decision")
            if previous is not None:
                if content_hash(previous) != content_hash(dict(request)):
                    raise fail("This graph already has a different review decision.")
            else:
                require_active(self.store, connection, job)
                if job["state"] not in {"completed", "interrupted"} or job["progress"].get(
                    "stopped"
                ):
                    raise fail(
                        "Only a durably retained, settled and unstopped proposal can be reviewed."
                    )
                values: dict[str, Any] = {"decision": dict(request)}
                if decision == "accept":
                    self._fresh(job)
                    # Verify the selected head in the same save/receipt transaction.
                    base = proposal["base_scenario"]
                    if base is not None:
                        row = connection.execute(
                            "SELECT v.version, v.digest FROM scenario_versions v JOIN scenario_heads h ON h.scenario_id=v.scenario_id AND h.active_version=v.version WHERE v.scenario_id=?",
                            (base["scenario_id"],),
                        ).fetchone()
                        if (
                            row is None
                            or row["version"] != base["version"]
                            or row["digest"] != base["digest"]
                        ):
                            raise fail("The saved reference changed before graph acceptance.")
                    saved = self.store._save_scenario_at(connection, request["scenario"])
                    values["application"] = {
                        "proposal_job_id": job_id,
                        "proposal_digest": proposal["proposal_digest"],
                        "reviewed_digest": request["reviewed_digest"],
                        "operator_modified": request["scenario"] != proposal["scenario"],
                        **{key: saved[key] for key in ("scenario_id", "version", "digest")},
                    }
                patch(connection, job, values)
        result = self.read(job_id)
        if decision == "accept" and self.on_application is not None:
            self.on_application(result["job"])
        return result

    def cancel(self, job_id: str) -> Mapping[str, Any]:
        with self.store._connection(write=True) as connection:
            job = job_at(self.store, connection, job_id)
            if job["kind"] != KIND:
                raise fail("The selected job is not a graph proposal.")
            if job["progress"].get("decision") is None:
                patch(connection, job, {"stopped": True})
        if job["state"] not in {"completed", "cancelled", "failed", "interrupted"}:
            self.controller.cancel(job_id)
        return self.read(job_id)
