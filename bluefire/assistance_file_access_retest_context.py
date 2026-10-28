"""Bounded explanation context for one historical Linux file-access retest."""

from __future__ import annotations

import re
from typing import Any, Mapping

from .product_store_errors import ProductStoreError
from .util import canonical_json_bytes, content_hash

KIND = "file_access_retest_comparison"
SUMMARY_SCHEMA = "bluefire.file-access-retest-assistance-summary.v1"
LIMITATIONS = [
    "This explains one exact saved Linux baseline, reviewed hardening, and selected composed retest; it does not read files, change permissions, rerun work, or recover an attempt.",
    "Baseline and retest are recorded reads of the same originally enrolled generated resource; they are not independent telemetry or a general host-access claim.",
    "The reviewed mode change alone does not prove denied access. Only a verified fresh retest can establish its recorded objective.",
    "Unknown or incomplete retest evidence remains unknown; a verified false objective is not successful prevention.",
    "The historical linkage is rechecked before explanation. Later control revisions cannot replace this selected comparison; changed or unavailable evidence refuses a new explanation.",
]
_OWNER = re.compile(r"job-[0-9a-f]{32}\Z")
_ATTEMPT = re.compile(r"attempt-[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LINKAGE_KEYS = {
    "schema_version",
    "objective_owner_id",
    "attempt_id",
    "control_owner_id",
    "baseline",
    "change",
    "retest",
    "comparison",
    "linkage_digest",
}


def _require(condition: bool) -> None:
    if not condition:
        raise ProductStoreError(
            "The selected saved file-access comparison is unavailable or changed."
        )


def _count(value: Any) -> bool:
    return type(value) is int and 1 <= value <= 100


def _revision(value: Any) -> bool:
    return type(value) is int and 1 <= value <= 2_147_483_647


def selection(value: Any) -> dict[str, Any]:
    _require(
        isinstance(value, dict)
        and set(value)
        == {"kind", "objective_owner_id", "attempt_id", "control_owner_id", "linkage_digest"}
    )
    _require(
        value["kind"] == KIND
        and isinstance(value["objective_owner_id"], str)
        and _OWNER.fullmatch(value["objective_owner_id"]) is not None
        and isinstance(value["attempt_id"], str)
        and _ATTEMPT.fullmatch(value["attempt_id"]) is not None
        and isinstance(value["control_owner_id"], str)
        and _OWNER.fullmatch(value["control_owner_id"]) is not None
        and isinstance(value["linkage_digest"], str)
        and _DIGEST.fullmatch(value["linkage_digest"]) is not None
    )
    return dict(value)


def _chosen(linkage: Mapping[str, Any]) -> dict[str, Any]:
    _require(
        isinstance(linkage, dict)
        and set(linkage) == _LINKAGE_KEYS
        and linkage["schema_version"] == "bluefire.file-access-composed-retest-linkage.v1"
        and isinstance(linkage["linkage_digest"], str)
        and linkage["linkage_digest"]
        == content_hash({key: value for key, value in linkage.items() if key != "linkage_digest"})
    )
    return selection(
        {
            "kind": KIND,
            "objective_owner_id": linkage["objective_owner_id"],
            "attempt_id": linkage["attempt_id"],
            "control_owner_id": linkage["control_owner_id"],
            "linkage_digest": linkage["linkage_digest"],
        }
    )


def _summary(linkage: Mapping[str, Any]) -> dict[str, Any]:
    baseline, change, retest, comparison = (
        linkage["baseline"],
        linkage["change"],
        linkage["retest"],
        linkage["comparison"],
    )
    _require(all(isinstance(row, dict) for row in (baseline, change, retest, comparison)))
    _require(
        _revision(baseline.get("control_revision"))
        and _revision(change.get("control_revision"))
        and change["control_revision"] > baseline["control_revision"]
        and baseline.get("mode") == "0640"
        and change.get("mode") == "0600"
        and baseline.get("non_owner") == baseline.get("owner") == "allowed"
        and _count(baseline.get("record_count"))
        and retest.get("state") in {"verified", "unknown"}
        and comparison.get("state") in {"established", "not_established", "unknown"}
        and comparison.get("non_owner_change") in {"allowed_to_denied", "still_allowed", "unknown"}
    )
    if retest["state"] == "unknown":
        _require(
            all(
                retest.get(key) is None
                for key in (
                    "non_owner_decision",
                    "owner_decision",
                    "record_count",
                    "run_cleanup",
                    "request_cleanup",
                    "objective_established",
                )
            )
            and comparison["state"] == comparison["non_owner_change"] == "unknown"
            and all(
                comparison.get(key) is None
                for key in ("owner_preserved", "content_preserved", "cleanup_verified")
            )
        )
    else:
        _require(
            retest.get("non_owner_decision") in {"allowed", "permission_denied", "unknown"}
            and retest.get("owner_decision") in {"allowed", "unknown"}
            and _count(retest.get("record_count"))
            and retest.get("run_cleanup") in {"complete", "incomplete"}
            and retest.get("request_cleanup") == "verified_closed"
            and type(retest.get("objective_established")) is bool
            and comparison["state"]
            == ("established" if retest["objective_established"] else "not_established")
            and comparison["non_owner_change"]
            == {
                "permission_denied": "allowed_to_denied",
                "allowed": "still_allowed",
                "unknown": "unknown",
            }[retest["non_owner_decision"]]
            and comparison.get("owner_preserved")
            is (True if retest["owner_decision"] == "allowed" else None)
            and comparison.get("cleanup_verified") is (retest["run_cleanup"] == "complete")
            and (comparison.get("content_preserved") is None)
            == (retest["owner_decision"] == "unknown")
        )
        _require(
            comparison.get("content_preserved") is None
            or type(comparison["content_preserved"]) is bool
        )
    summary = {
        "schema_version": SUMMARY_SCHEMA,
        "proof_scope": "historical_saved_linkage_only",
        "baseline": {
            "source": "verified_saved_baseline_operation",
            "control_revision": baseline["control_revision"],
            "mode": "0640",
            "non_owner": "allowed",
            "owner": "allowed",
            "record_count": baseline["record_count"],
        },
        "change": {
            "source": "reviewed_saved_hardening_operation",
            "control_revision": change["control_revision"],
            "mode": "0600",
        },
        "retest": {
            "source": "saved_composed_attempt",
            "state": retest["state"],
            "non_owner_decision": retest["non_owner_decision"],
            "owner_decision": retest["owner_decision"],
            "record_count": retest["record_count"],
            "run_cleanup": retest["run_cleanup"],
            "request_cleanup": retest["request_cleanup"],
            "objective_established": retest["objective_established"],
        },
        "comparison": {
            "state": comparison["state"],
            "non_owner_change": comparison["non_owner_change"],
            "owner_preserved": comparison["owner_preserved"],
            "content_preserved": comparison["content_preserved"],
            "cleanup_verified": comparison["cleanup_verified"],
        },
    }
    _require(len(canonical_json_bytes(summary)) <= 8192)
    return summary


def context(
    service: Any,
    value: Any = None,
    *,
    owner_id: str | None = None,
    attempt_id: str | None = None,
) -> dict[str, Any]:
    """Capture and recheck the selected saved linkage without native or current-control reads."""
    try:
        chosen = selection(value) if value is not None else None
        owner = chosen["objective_owner_id"] if chosen is not None else owner_id
        attempt = chosen["attempt_id"] if chosen is not None else attempt_id
        _require(
            isinstance(owner, str)
            and _OWNER.fullmatch(owner) is not None
            and isinstance(attempt, str)
            and _ATTEMPT.fullmatch(attempt) is not None
        )
        linkage = service.file_access_composed_retest_linkage(owner, attempt)
        current = _chosen(linkage)
        _require(chosen is None or current == chosen)
        summary = _summary(linkage)
        _require(service.file_access_composed_retest_linkage(owner, attempt) == linkage)
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
        raise ProductStoreError(
            "The selected saved file-access comparison is unavailable or changed."
        ) from exc
