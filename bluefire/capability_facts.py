"""Small provenance-aware fact sets for fresh composition attempts."""

from __future__ import annotations

from typing import Any, Mapping

from .capability_grant import authority_id, digest, identifier
from .capability_resources import CapabilityContractError, exact, integer
from .util import content_hash, json_clone

SCHEMA = "bluefire.composition-facts.v1"
_FIELDS = {
    "schema_version",
    "environment_digest",
    "control_digest",
    "prior_attempt_id",
    "prior_graph_digest",
    "facts",
    "facts_digest",
}
_FACT_FIELDS = {
    "fact_id",
    "kind",
    "provenance",
    "source",
    "observed_at_ms",
    "valid_until_ms",
    "environment_digest",
    "control_digest",
    "attempt_id",
    "value",
}
_COUNTS = {"record_count", "redacted_record_count", "retained_record_count", "empty_record_count"}


def seal_facts(body: Mapping[str, Any]) -> dict[str, Any]:
    """Create a detached record; hashing is not verification or authority."""
    exact(body, _FIELDS - {"facts_digest"}, "composition fact body")
    return {**dict(json_clone(body)), "facts_digest": content_hash(body)}


def validate_facts(
    value: Any,
    *,
    expected_digest: str,
    grant: Mapping[str, Any],
    now_ms: int,
    require_prior_result: bool,
) -> dict[str, Any]:
    """Expected digest belongs to the store/controller, never to model output."""
    integer(now_ms, 1, 2**63 - 1, "current time")
    if type(require_prior_result) is not bool:
        raise CapabilityContractError("fact admission kind is invalid")
    row = exact(value, _FIELDS, "composition facts")
    digest(expected_digest, "trusted facts digest")
    body = {key: item for key, item in row.items() if key != "facts_digest"}
    environment = grant["environment"]
    environment_digest = content_hash(environment)
    if (
        row["schema_version"] != SCHEMA
        or content_hash(body) != expected_digest
        or row["facts_digest"] != expected_digest
        or row["environment_digest"] != environment_digest
        or row["control_digest"] != environment["control_digest"]
    ):
        raise CapabilityContractError("fact set changed or belongs to another environment/control")
    prior = row["prior_attempt_id"]
    if require_prior_result:
        authority_id(prior, "attempt")
        digest(row["prior_graph_digest"], "prior semantic graph")
    elif prior is not None or row["prior_graph_digest"] is not None:
        raise CapabilityContractError("initial admission cannot borrow a previous attempt")
    facts = row["facts"]
    if not isinstance(facts, list) or not 1 <= len(facts) <= 64:
        raise CapabilityContractError("composition facts have an invalid count")
    seen: set[str] = set()
    usable: dict[str, Mapping[str, Any]] = {}
    for raw in facts:
        fact = exact(raw, _FACT_FIELDS, "composition fact")
        identity = identifier(fact["fact_id"], "fact ID")
        if identity in seen:
            raise CapabilityContractError("composition fact IDs must be unique")
        seen.add(identity)
        kind = fact["kind"]
        if kind not in ("retained_policy", "receiver_result", "cleanup"):
            raise CapabilityContractError("fact kind is outside the reviewed pack")
        if fact["provenance"] not in ("observed", "operator_declared", "model_hypothesis"):
            raise CapabilityContractError("fact provenance is invalid")
        source = exact(fact["source"], {"kind", "id", "digest"}, "fact source")
        if source["kind"] not in ("run_evidence", "control_record", "declaration", "hypothesis"):
            raise CapabilityContractError("fact source kind is invalid")
        identifier(source["id"], "fact source ID")
        digest(source["digest"], "fact source digest")
        if fact["provenance"] == "observed" and source["kind"] not in (
            "run_evidence",
            "control_record",
        ):
            raise CapabilityContractError("observed facts require independently verified records")
        observed = integer(fact["observed_at_ms"], 1, now_ms, "fact observation time")
        integer(fact["valid_until_ms"], observed + 1, grant["expires_at_ms"], "fact expiry")
        if (
            fact["environment_digest"] != environment_digest
            or fact["control_digest"] != environment["control_digest"]
            or fact["attempt_id"] != (None if kind == "retained_policy" else prior)
        ):
            raise CapabilityContractError("fact resource context or attempt identity changed")
        detail = fact["value"]
        if kind == "retained_policy":
            exact(detail, {"status", "policy_digest"}, "retained policy fact")
            if detail["status"] not in ("retained", "rolled_back", "unknown"):
                raise CapabilityContractError("retained policy fact status is invalid")
            digest(detail["policy_digest"], "observed policy digest")
        elif kind == "receiver_result":
            exact(detail, {"decision", "policy_digest", *_COUNTS}, "receiver result fact")
            digest(detail["policy_digest"], "observed policy digest")
            if detail["decision"] not in ("accepted", "policy_refused", "unknown"):
                raise CapabilityContractError("receiver decision is invalid")
            for key in _COUNTS:
                integer(detail[key], 0, 100, key)
            if detail["record_count"] != sum(detail[key] for key in _COUNTS - {"record_count"}):
                raise CapabilityContractError("receiver semantic counts are inconsistent")
        else:
            exact(detail, {"run", "receiver"}, "cleanup fact")
            if detail["run"] not in ("complete", "incomplete", "unknown") or detail[
                "receiver"
            ] not in ("verified_closed", "uncertain", "unknown"):
                raise CapabilityContractError("cleanup fact is invalid")
        if fact["provenance"] == "observed" and now_ms < fact["valid_until_ms"]:
            if kind in usable:
                raise CapabilityContractError(
                    "ambiguous current facts cannot establish prerequisites"
                )
            usable[kind] = fact
    policy = usable.get("retained_policy")
    if (
        policy is None
        or policy["source"]["kind"] != "control_record"
        or policy["value"] != {"status": "retained", "policy_digest": environment["policy_digest"]}
    ):
        raise CapabilityContractError("current retained policy is not established")
    if require_prior_result:
        result, cleanup = usable.get("receiver_result"), usable.get("cleanup")
        if (
            result is None
            or cleanup is None
            or result["source"]["kind"] != "run_evidence"
            or cleanup["source"]["kind"] != "run_evidence"
            or result["value"]["decision"] != "policy_refused"
            or result["value"]["policy_digest"] != environment["policy_digest"]
            or result["value"]["record_count"] != grant["objective"]["predicate"]["record_count"]
            or cleanup["value"] != {"run": "complete", "receiver": "verified_closed"}
        ):
            raise CapabilityContractError(
                "revision requires observed refusal and settled prior cleanup"
            )
    elif any(fact["kind"] != "retained_policy" for fact in facts):
        raise CapabilityContractError("initial admission accepts only current policy facts")
    return dict(json_clone(row))
