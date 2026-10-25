"""Saved-only, minimized file-access explanation; no native or recovery contact."""

import re

from .product_store_errors import ProductStoreError
from .util import canonical_json_bytes, content_hash

KIND = "file_access_control"
SUMMARY_SCHEMA = "bluefire.file-access-assistance-summary.v1"
LIMITATIONS = [
    "This explains one exact saved file-access control revision; it is not an execution or recovery plan.",
    "Saved baseline reads, protection metadata and verified fresh task observations are separate evidence; a mode or policy change alone does not prove denied access.",
    "Task-access settlement is not current endpoint readiness. Readiness is not assessed and no native channel or enrollment is contacted by this context.",
    "Recorded reads concern only the originally enrolled generated resource and principals; they are not independent detection telemetry or a general host-access claim.",
    "Missing or unresolved evidence remains unreported. No file read, permission change, recovery, run or grant is available from this context.",
]
_OWNER = re.compile(
    r"(?:job-[0-9a-f]{32}|win-file-control-[0-9a-f]{32}|file-control-[0-9a-f]{64})\Z"
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_STATES = {
    "created",
    "baseline_verified",
    "hardened",
    "rolled_back",
    "reset",
    "uncertain",
    "recovery_required",
    "setup_verified",
}
_JOB_STATES = {
    "queued",
    "planning",
    "running",
    "awaiting_approval",
    "cancelling",
    "completed",
    "failed",
    "cancelled",
    "interrupted",
}
_OPERATIONS = {"create", "baseline", "harden", "rollback", "reset"}
_OUTCOMES = {"complete", "unknown", "refused_no_effect", "settled_partial"}


def _require(condition):
    if not condition:
        raise ProductStoreError("The saved file-access source is unavailable or changed.")


def selection(value):
    _require(
        isinstance(value, dict)
        and set(value) == {"kind", "control_owner_id", "control_revision", "control_digest"}
    )
    _require(
        value["kind"] == KIND
        and isinstance(value["control_owner_id"], str)
        and _OWNER.fullmatch(value["control_owner_id"])
    )
    _require(type(value["control_revision"]) is int and 1 <= value["control_revision"] <= 2**31 - 1)
    _require(
        isinstance(value["control_digest"], str) and _DIGEST.fullmatch(value["control_digest"])
    )
    return dict(value)


def _chosen(view):
    return selection(
        {
            "kind": KIND,
            "control_owner_id": view["control_owner_id"],
            "control_revision": view["revision"],
            "control_digest": view["control_digest"],
        }
    )


def _latest(service, owner_id, control_digest):
    # operation() may settle interrupted obligations. Read the durable journal only.
    store = service.product_store
    with store._connection() as connection:
        row = connection.execute(
            "SELECT job_id FROM file_access_operations WHERE control_owner_id=? ORDER BY rowid DESC LIMIT 1",
            (owner_id,),
        ).fetchone()
    if row is None:
        return None, None
    job = store.get_job(row["job_id"])
    records = store.file_access_operation_records(row["job_id"])
    document, outcome = records["document"], records["outcome"]
    operation = document["review"]["operation"]
    _require(records["control_owner_id"] == owner_id and job["kind"] == "file_access.operation")
    _require(operation in _OPERATIONS and job["state"] in _JOB_STATES)
    _require(
        document["review"]["control_owner_id"] in (owner_id, None)
        and (document["review"]["control_owner_id"] is not None or operation == "create")
    )
    _require(outcome is None or outcome["state"] in _OUTCOMES)
    latest = {
        "operation": operation,
        "state": job["state"],
        "outcome": outcome["state"] if outcome is not None else "not_recorded",
        "record_digest": content_hash(
            {
                "job_id": job["job_id"],
                "state": job["state"],
                "document": document,
                "outcome_digest": records["outcome_digest"],
            }
        ),
    }
    observation = None
    if (
        outcome is not None
        and outcome["state"] == "complete"
        and outcome.get("verified_observation") is not None
    ):
        observation = outcome["verified_observation"]
        _require(outcome["control_digest"] == control_digest)
        _require(observation["schema_version"] == "bluefire.file-access-control-observation.v1")
        _require(observation["operation"] == operation and operation in {"baseline", "rollback"})
        _require(observation["non_owner"] == observation["owner"] == "allowed")
    return latest, observation


def _summary(service, view):
    schema = view["schema_version"]
    _require(
        schema
        in {
            "bluefire.file-access-control.v1",
            "bluefire.windows-file-access-control.v1",
            "bluefire.windows-file-access-control.v2",
            "bluefire.windows-file-access-control.v3",
        }
    )
    platform = view.get("platform", "linux")
    _require(platform in {"linux", "macos", "windows"} and view["status"] in _STATES)
    _require((platform == "windows") == schema.startswith("bluefire.windows-"))
    baseline = view["baseline"]
    baseline_summary = {"recorded": False}
    if baseline is not None:
        _require(baseline["non_owner"] == baseline["owner"] == "allowed")
        _require(
            isinstance(baseline["baseline_digest"], str)
            and _DIGEST.fullmatch(baseline["baseline_digest"])
        )
        baseline_summary = {"recorded": True, "non_owner": "allowed", "owner": "allowed"}
    resource = view["resource"]
    protection = (
        "not_recorded"
        if resource is None
        else resource["protection" if platform == "windows" else "mode"]
    )
    _require(
        protection
        in (
            {"reader_readable", "metadata_only", "unknown", "not_recorded"}
            if platform == "windows"
            else {"0640", "0600", "not_recorded"}
        )
    )
    usage = view["task_usage_state" if platform == "windows" else "usage_state"]
    _require(
        usage
        in ({"none", "settled", "unresolved"} if platform == "windows" else {"pending", "settled"})
    )
    latest, observation = _latest(service, view["control_owner_id"], view["control_digest"])
    fresh = {"recorded": False}
    if observation is not None:
        fresh = {
            "recorded": True,
            "operation": observation["operation"],
            "non_owner": observation["non_owner"],
            "owner": observation["owner"],
            "source": "verified_saved_task_observation",
            "independent_observation": False,
        }
    retest = view.get("retest")
    if retest is not None:
        _require(
            schema == "bluefire.windows-file-access-control.v3"
            and retest["schema_version"] == "bluefire.windows-file-correction-observation.v3"
            and retest["non_owner"] == "data_access_denied"
            and retest["owner"] == "allowed"
            and retest["native_cleanup"] == retest["owned_job_cleanup"] == "verified"
            and retest["independent_observation"] is False
        )
        fresh = {
            "recorded": True,
            "operation": "harden",
            "non_owner": "data_access_denied",
            "owner": "allowed",
            "source": "verified_saved_paired_read",
            "independent_observation": False,
        }
    summary = {
        "schema_version": SUMMARY_SCHEMA,
        "platform": platform,
        "control_status": view["status"],
        "baseline": baseline_summary,
        "protection": {
            "kind": "windows_metadata" if platform == "windows" else "posix_mode",
            "value": protection,
            "effective_access_proven": False,
        },
        "fresh_result": fresh,
        "latest_operation": latest,
        "task_access": {"usage_state": usage},
        "readiness": "not_assessed",
    }
    _require(len(canonical_json_bytes(summary)) <= 8192)
    return summary


def context(service, value=None, *, owner_id=None):
    """Use the ordinary saved projection, with its native-readiness probe disabled internally."""
    try:
        chosen = selection(value) if value is not None else None
        identifier = chosen["control_owner_id"] if chosen is not None else owner_id
        _require(isinstance(identifier, str) and _OWNER.fullmatch(identifier))
        view = service.file_access.control(identifier, _saved_only=True)
        current = _chosen(view)
        _require(chosen is None or current == chosen)
        summary = _summary(service, view)
        # Refuse a revision/obligation change during this multi-record read.
        confirmed = service.file_access.control(identifier, _saved_only=True)
        _require(confirmed == view)
        document = {
            "schema_version": "bluefire.assistance-context.v1",
            "selected": current,
            "analysis_only": True,
            "capabilities": [],
            "reference_summary": summary,
            "limitations": list(LIMITATIONS),
        }
        return {**document, "context_digest": content_hash(document)}
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise ProductStoreError("The saved file-access source is unavailable or changed.") from exc
