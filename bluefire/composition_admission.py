"""Durable delegation admission, with no runner or model dispatch."""

from . import composition_context
from .capability_grant import create_grant
from .capability_packs import review_pack
from .capability_resources import CapabilityContractError
from .product_store_contracts import safe_document
from .product_store_errors import ProductStoreError
from .receiver_defense_jobs import fields
from .util import content_hash

REFUSAL_SCHEMA = "bluefire.composition-objective-refusal.v1"
_MESSAGES = {
    "composition_review_changed": "The reviewed context changed. Review the current delegation again.",
    "composition_admission_unavailable": "The delegation prerequisites are unavailable. Review the current environment again.",
    "composition_admission_interrupted": "The saved delegation was interrupted before authority was established. Review a new delegation.",
}


def _saved_grant(jobs, identifier):
    with jobs.store._connection() as connection:
        present = connection.execute(
            "SELECT 1 FROM capability_grants WHERE grant_id=?", (identifier,)
        ).fetchone()
    return (
        None
        if present is None
        else jobs.store.get_capability_grant(identifier, now_ms=jobs.clock())
    )


def _finish(jobs, owner, *, accepted, problem=None):
    jobs.store.finish_capability_objective_submission(
        owner["job_id"],
        expected_state=owner["state"],
        admission={
            "accepted": accepted,
            "problem": (
                None if problem is None else {"code": problem, "message": _MESSAGES[problem]}
            ),
        },
    )
    return jobs.read(owner["job_id"])


def _replay(jobs, previous, request):
    if (
        previous["kind"] != "composition.objective"
        or previous["progress"].get("submitted_request") != request
    ):
        raise ProductStoreError("This submission already belongs to another exact operation.")
    if previous["state"] in {"completed", "failed", "cancelled"}:
        return jobs.read(previous["job_id"])
    if previous["state"] != "interrupted":
        return jobs.read(previous["job_id"])
    marker = previous["request"]
    grant = None
    if marker.get("schema_version") != REFUSAL_SCHEMA:
        grant = _saved_grant(jobs, marker["grant_id"])
        if grant is not None and grant["document"]["grant_digest"] != marker["grant_digest"]:
            raise ProductStoreError("The saved delegation binding is inconsistent.")
    return _finish(
        jobs,
        previous,
        accepted=grant is not None,
        problem=None if grant is not None else "composition_admission_interrupted",
    )


def authorize(jobs, request):
    fields(request, {"submission_id", "review", "reviewed_by", "review_digest"})
    pack = review_pack(request["review"])
    request = safe_document(request, context="composition authorization submission")
    if (
        not isinstance(request["reviewed_by"], str)
        or not 1 <= len(request["reviewed_by"].strip()) <= 200
    ):
        raise ProductStoreError("A bounded operator identity is required.")
    job_id, _ = jobs.store._job_submission_binding(request["submission_id"], content_hash(request))
    try:
        previous = jobs.store.get_job(job_id)
    except ProductStoreError:
        previous = None
    if previous is not None:
        return _replay(jobs, previous, request)
    retained = _saved_grant(jobs, "grant-" + job_id[4:])
    problem = None
    grant = None
    existing = None if retained is None else retained["document"]
    current = None
    created = jobs.clock()
    try:
        reviewed = jobs.review(request["review"])
        if request["review_digest"] != reviewed["review_digest"]:
            problem = "composition_review_changed"
        else:
            current = composition_context.resolve(
                jobs.service,
                reviewed["environment"]["control_owner_id"],
                pack=pack,
            )
            grant = create_grant(
                registry=current["registry"],
                implementation_digests=current["implementation_digests"],
                objective=reviewed["objective"],
                environment=reviewed["environment"],
                limits=reviewed["limits"],
                grant_id="grant-" + job_id[4:],
                approved_by=request["reviewed_by"],
                created_at_ms=created,
                expires_at_ms=min(
                    created + 900_000, current.get("expires_at_ms", created + 900_000)
                ),
                pack=pack,
            )
            if existing is not None:
                if any(
                    existing[key] != grant[key]
                    for key in ("objective", "environment", "limits", "snapshot", "approved_by")
                ):
                    raise ProductStoreError("The retained delegation differs from this review.")
                grant = existing
    except (ProductStoreError, CapabilityContractError):
        problem = "composition_admission_unavailable"
    if problem is not None and existing is not None:
        raise ProductStoreError("The retained delegation needs exact admission reconciliation.")
    marker = (
        {
            "schema_version": REFUSAL_SCHEMA,
            "control_owner_id": request["review"]["control_owner_id"],
            "submitted_request_digest": content_hash(request),
        }
        if problem
        else {
            "schema_version": "bluefire.composition-objective-request.v1",
            "grant_id": grant["grant_id"],
            "grant_digest": grant["grant_digest"],
        }
    )
    owner, inserted = jobs.store.create_capability_objective_submission(marker, request)
    if not inserted:
        return _replay(jobs, owner, request)
    if problem is not None:
        return _finish(jobs, owner, accepted=False, problem=problem)
    lineage = (
        "lineage-"
        + content_hash(
            {
                "control": grant["environment"]["control_owner_id"],
                "environment": grant["environment"]["environment_id"],
                "runner": grant["environment"]["runner_id"],
                "target": grant["environment"]["target_scope_digest"],
                "predicate": grant["objective"]["predicate"],
            }
        )[7:]
    )
    try:
        if existing is None:
            jobs.store.save_capability_grant(
                grant,
                lineage_id=lineage,
                registry=current["registry"],
                implementation_digests=current["implementation_digests"],
                current_environment=current["current_environment"],
                now_ms=created,
                objective_job_id=owner["job_id"],
            )
        return _finish(jobs, owner, accepted=True)
    except Exception:
        interrupted = jobs.store.get_job(owner["job_id"])
        if interrupted["state"] == "queued":
            interrupted = jobs.store.transition_job(owner["job_id"], "planning")
        if interrupted["state"] == "planning":
            interrupted = jobs.store.transition_job(owner["job_id"], "running")
        if interrupted["state"] == "running":
            jobs.store.transition_job(owner["job_id"], "interrupted")
        raise
