"""Exact receiver history data boundary for its separately authorized provider purpose."""

from __future__ import annotations

import re

from .ai_composition_contract import EVIDENCE_MODEL_SCHEMA, RECORD_REF_SCHEMA, RETAINED_MODEL_SCHEMA
from .capability_grant import authority_id, digest, identifier, text
from .capability_resources import METHODS, CapabilityContractError, exact, integer, semantic_ports
from .util import content_hash

_NODE = re.compile(r"[a-z][a-z0-9_]{0,99}\Z")
_SUMMARY = {
    "observed_filesystem": {
        "size_bytes",
        "sha256",
        "permission_status",
        "effective_access",
        "permission_mode_octal",
        "group_write_bit",
        "other_write_bit",
        "non_owner_write_bit",
    },
    "observed_collection": {
        "size_bytes",
        "sha256",
        "container",
        "record_count",
        "redacted_record_count",
        "retained_record_count",
        "empty_record_count",
    },
    "observed_process_snapshot": {"process_id", "parent_process_id", "platform"},
    "observed_receiver_binding": {"sha256", "bytes_received", "receiver_process_id"},
    "runner_result": {"runner_status"},
    "evidence_gap": {"observation_available"},
    "record_metadata": set(),
}
_ENUMS = {
    "permission_status": {"available", "unavailable_windows", "unsupported_platform"},
    "effective_access": {"not_evaluated"},
    "container": {"jsonl", "ustar", "gzip"},
    "platform": {"linux", "windows", "macos"},
    "runner_status": {"success", "partial", "failed", "refused", "control_blocked", "cancelled"},
}


def _node(value):
    if not isinstance(value, str) or not _NODE.fullmatch(value):
        raise CapabilityContractError("historical graph node is invalid")


def _array(value, low, high):
    if not isinstance(value, list) or not low <= len(value) <= high:
        raise CapabilityContractError("historical model context array exceeds its bound")
    return value


def _parameters(value, method, count):
    from .retained_artifacts import METHOD

    if method == METHOD:
        exact(value, {"source_ref"}, "retained method parameters")
        digest(value["source_ref"], "retained source")
        return
    domains = {
        METHODS[0]: {"record_count": [count]},
        METHODS[1]: {"redact_values": [False, True]},
        METHODS[2]: {},
        METHODS[3]: {},
        METHODS[4]: {"bundle_format": ["jsonl"]},
        METHODS[5]: {"port": None},
        METHODS[6]: {"verify_removal": [True]},
    }[method]
    exact(value, set(domains), "historical method parameters")
    for key, allowed in domains.items():
        if allowed is None:
            integer(value[key], 1024, 65535, "reviewed receiver port")
        elif not any(content_hash(value[key]) == content_hash(item) for item in allowed):
            raise CapabilityContractError("historical method expanded its closed parameter domain")


def _record_ref(value):
    exact(value, set(RECORD_REF_SCHEMA["properties"]), "historical record reference")
    for key in ("owner_id", "job_id"):
        if not isinstance(value[key], str) or not re.fullmatch(r"job-[0-9a-f]{32}", value[key]):
            raise CapabilityContractError("historical record job identity is invalid")
    authority_id(value["attempt_id"], "attempt")
    for key in ("run_id", "evidence_id"):
        identifier(value[key], key)
    for key in ("record_hash", "source_binding_digest"):
        digest(value[key], key)


def _finding(row, attempt_id, source_digest):
    exact(
        row,
        {
            "finding_id",
            "evidence_id",
            "step_id",
            "behavior_id",
            "action_id",
            "provenance",
            "semantic_kind",
            "observed_at",
            "content_hash",
            "record_hash",
            "summary",
            "applicability",
            "record_ref",
        },
        "historical finding",
    )
    _record_ref(row["record_ref"])
    ref = row["record_ref"]
    if (
        row["finding_id"] != "finding-" + content_hash(ref).removeprefix("sha256:")
        or ref["attempt_id"] != attempt_id
        or ref["source_binding_digest"] != source_digest
        or ref["record_hash"] != row["record_hash"]
        or ref["evidence_id"] != row["evidence_id"]
        or row["applicability"]
        != {"status": "historical_only", "reason": "current_state_not_verified"}
        or not isinstance(row["provenance"], str)
        or row["provenance"]
        not in {"observed", "executed", "control_blocked", "unknown", "synthetic", "counterfactual"}
    ):
        raise CapabilityContractError("historical finding provenance or identity is invalid")
    for key in ("step_id", "behavior_id"):
        identifier(row[key], key)
    if row["action_id"] is not None:
        identifier(row["action_id"], "action_id")
    text(row["observed_at"], "historical observation time", 100)
    digest(row["content_hash"], "historical content hash")
    kind = row["semantic_kind"]
    summary = row["summary"]
    if (
        not isinstance(kind, str)
        or kind not in _SUMMARY
        or not isinstance(summary, dict)
        or set(summary) - _SUMMARY[kind]
    ):
        raise CapabilityContractError("historical finding summary is not a fixed projection")
    for key, value in summary.items():
        if key == "sha256":
            if not isinstance(value, str) or not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", value):
                raise CapabilityContractError("historical summary hash is invalid")
        elif key in _ENUMS:
            if not isinstance(value, str) or value not in _ENUMS[key]:
                raise CapabilityContractError("historical summary enum is invalid")
        elif key == "permission_mode_octal":
            if not isinstance(value, str) or not re.fullmatch(r"0[0-7]{3}", value):
                raise CapabilityContractError("historical mode is invalid")
        elif key.endswith("_bit") or key == "observation_available":
            if type(value) is not bool or key == "observation_available" and value is not False:
                raise CapabilityContractError("historical summary boolean is invalid")
        else:
            integer(value, 0, 2**53 - 1, "historical summary count")


def validate_model_context(value, *, retained=False):
    """Reject raw content and field expansion even with the new purpose authorized."""
    fields = {
        "schema_version",
        "objective",
        "revision",
        "methods",
        "facts",
        "initial_proposal",
        "historical_context",
    }
    if retained:
        fields.add("retained_artifacts")
    exact(value, fields, "historical receiver model context")
    if (
        value["schema_version"] != (RETAINED_MODEL_SCHEMA if retained else EVIDENCE_MODEL_SCHEMA)
        or type(value["revision"]) is not bool
        or not retained
        and (value["revision"] is not True or value["initial_proposal"] is not None)
    ):
        raise CapabilityContractError("historical model context requires a receiver revision")
    objective = exact(value["objective"], {"question", "predicate"}, "receiver objective")
    text(objective["question"], "receiver objective question", 4000)
    predicate = exact(
        objective["predicate"], {"kind", "record_count", "data_class"}, "receiver predicate"
    )
    if (
        predicate["kind"] != "redacted_delivery_preserves_records"
        or predicate["data_class"] != "generated_public_jsonl"
    ):
        raise CapabilityContractError("historical purpose cannot expand the receiver objective")
    count = integer(predicate["record_count"], 1, 100, "receiver record count")
    from .retained_artifacts import METHOD, POLICY, source_reference

    methods = (*METHODS, METHOD) if retained else METHODS
    if retained:
        custody = exact(
            value["retained_artifacts"],
            {"policy", "available_sources", "availability"},
            "retained custody",
        )
        if custody["policy"] != POLICY:
            raise CapabilityContractError("retention policy changed")
        sources = _array(custody["available_sources"], 0, 32)
        refs = [source_reference(row)["source_ref"] for row in sources]
        if len(set(refs)) != len(refs) or custody["availability"] != (
            "available" if refs else "none_available"
        ):
            raise CapabilityContractError("retained availability changed")
    seen = set()
    for method in _array(value["methods"], len(methods), len(methods)):
        exact(method, {"behavior_id", "inputs", "outputs", "parameter_domains"}, "receiver method")
        identity = method["behavior_id"]
        if not isinstance(identity, str) or identity not in methods or identity in seen:
            raise CapabilityContractError("historical purpose selected a foreign method")
        seen.add(identity)
        for key, ports in zip(
            ("inputs", "outputs"),
            semantic_ports(
                identity,
                pack=(
                    "bluefire.receiver-composition-pack.v2"
                    if retained
                    else "bluefire.receiver-composition-pack.v1"
                ),
            ),
            strict=True,
        ):
            actual = _array(method[key], len(ports), len(ports))
            for port, expected in zip(actual, ports, strict=True):
                exact(
                    port,
                    {"name", "type", "required", "multiple", "description"},
                    "receiver semantic port",
                )
                if (
                    (port["name"], port["type"], port["multiple"]) != expected[:3]
                    or type(port["required"]) is not bool
                    or type(port["multiple"]) is not bool
                    or key == "inputs"
                    and port["required"] != expected[3]
                ):
                    raise CapabilityContractError("receiver semantic port changed")
                if not isinstance(port["description"], str):
                    raise CapabilityContractError("receiver port description must be text")
                text(port["description"] or "empty", "port description", 2000)
        domains = method["parameter_domains"]
        if identity == METHOD:
            if domains != {"source_ref": {"kind": "sealed_same_lineage_generated_jsonl"}}:
                raise CapabilityContractError("retained source domain changed")
            continue
        if not isinstance(domains, dict) or any(
            not isinstance(items, list) or not 1 <= len(items) <= 2 for items in domains.values()
        ):
            raise CapabilityContractError("receiver parameter domains are invalid")
        _parameters({key: items[0] for key, items in domains.items()}, identity, count)
        if identity == METHODS[1] and domains != {"redact_values": [False, True]}:
            raise CapabilityContractError("receiver transform domain changed")
        if identity != METHODS[1] and any(len(items) != 1 for items in domains.values()):
            raise CapabilityContractError("receiver fixed domain changed")
    for fact in _array(value["facts"], 1 if retained else 3, 3):
        exact(fact, {"evidence_ref", "kind", "provenance", "value"}, "receiver fact")
        identifier(fact["evidence_ref"], "current fact reference")
        if (
            fact["provenance"] != "observed"
            or not isinstance(fact["kind"], str)
            or fact["kind"]
            not in (
                {"retained_policy", "receiver_result", "cleanup", "retained_artifact_result"}
                if retained
                else {"retained_policy", "receiver_result", "cleanup"}
            )
        ):
            raise CapabilityContractError(
                "historical context cannot promote historical findings to facts"
            )
        if fact["kind"] == "retained_artifact_result":
            result = exact(
                fact["value"],
                {"source", "prior_run_id", "later_failure", "receiver_decision"},
                "retained result",
            )
            source_reference(result["source"])
            if not isinstance(result["prior_run_id"], str) or not re.fullmatch(
                r"run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}", result["prior_run_id"]
            ):
                raise CapabilityContractError("retained prior run is invalid")
            failure = exact(result["later_failure"], {"step_id", "outcome"}, "later failure")
            identifier(failure["step_id"], "failed step")
            if (
                failure["outcome"] not in {"blocked", "failed", "partial"}
                or result["receiver_decision"] != "unknown"
            ):
                raise CapabilityContractError("retained failure cannot invent a receiver decision")
            continue
        allowed = {
            "retained_policy": {"status", "policy_digest"},
            "receiver_result": {
                "decision",
                "policy_digest",
                "record_count",
                "redacted_record_count",
                "retained_record_count",
                "empty_record_count",
            },
            "cleanup": {"run", "receiver"},
        }[fact["kind"]]
        detail = exact(fact["value"], allowed, "current receiver fact value")
        for key, item in detail.items():
            if key.endswith("_count"):
                integer(item, 0, 100, key)
            elif key.endswith("_digest"):
                digest(item, key)
            elif not isinstance(item, str) or item not in {
                "retained",
                "rolled_back",
                "unknown",
                "accepted",
                "policy_refused",
                "complete",
                "incomplete",
                "verified_closed",
                "uncertain",
            }:
                raise CapabilityContractError("current receiver fact value is invalid")
    if retained:
        kinds = [row["kind"] for row in value["facts"]]
        expected = {"retained_policy", "cleanup"} if value["revision"] else {"retained_policy"}
        if (
            len(set(kinds)) != len(kinds)
            or not expected <= set(kinds)
            or value["revision"]
            and len(set(kinds) & {"receiver_result", "retained_artifact_result"}) != 1
            or not value["revision"]
            and set(kinds) != expected
        ):
            raise CapabilityContractError("retained current facts do not match the revision")
        if value["initial_proposal"] is not None:
            # Reuse the closed proposal parser and exact parameter/port validator.
            from .ai_runtime_composition import validate_candidate

            validate_candidate(
                value["initial_proposal"],
                {
                    "snapshot": {
                        "pack": "bluefire.receiver-composition-pack.v2",
                        "methods": [
                            {**row, "behavior": {"inputs": row["inputs"]}}
                            for row in value["methods"]
                        ],
                    },
                    "facts": {
                        "facts": [{"fact_id": row["evidence_ref"]} for row in value["facts"]]
                    },
                    "retained_artifacts": value["retained_artifacts"],
                },
            )
    if retained and value["historical_context"] is None:
        return
    if retained and (value["revision"] is not True or value["initial_proposal"] is not None):
        raise CapabilityContractError("selected history requires a revision")
    history = exact(
        value["historical_context"],
        {"knowledge_digest", "attempt_ids", "attempts", "choices"},
        "selected history",
    )
    digest(history["knowledge_digest"], "historical knowledge")
    ids = _array(history["attempt_ids"], 1, 8)
    for item in ids:
        authority_id(item, "attempt")
    if len(set(ids)) != len(ids):
        raise CapabilityContractError("historical attempt selection contains duplicates")
    attempts = _array(history["attempts"], len(ids), len(ids))
    for attempt, attempt_id in zip(attempts, ids, strict=True):
        exact(attempt, {"attempt_id", "source_binding_digest", "findings"}, "historical source")
        if attempt["attempt_id"] != attempt_id:
            raise CapabilityContractError("historical source selection changed")
        digest(attempt["source_binding_digest"], "historical source")
        for row in _array(attempt["findings"], 0, 32):
            _finding(row, attempt_id, attempt["source_binding_digest"])
    choice_ids = set()
    for choice in _array(history["choices"], 1, 512):
        exact(
            choice,
            {
                "attempt_id",
                "compiled_digest",
                "semantic_digest",
                "step_id",
                "behavior_id",
                "parameters",
                "inputs",
            },
            "historical choice",
        )
        if choice["attempt_id"] not in ids or choice["behavior_id"] not in methods:
            raise CapabilityContractError(
                "historical choice is outside the selected receiver attempts"
            )
        for key in ("compiled_digest", "semantic_digest"):
            digest(choice[key], key)
        _node(choice["step_id"])
        identity = (choice["attempt_id"], choice["step_id"])
        if identity in choice_ids:
            raise CapabilityContractError("historical choice is duplicated")
        choice_ids.add(identity)
        _parameters(choice["parameters"], choice["behavior_id"], count)
        ports = {
            port[0]
            for port in semantic_ports(
                choice["behavior_id"],
                pack=(
                    "bluefire.receiver-composition-pack.v2"
                    if retained
                    else "bluefire.receiver-composition-pack.v1"
                ),
            )[0]
        }
        inputs = choice["inputs"]
        if not isinstance(inputs, dict) or set(inputs) - ports:
            raise CapabilityContractError("historical choice input ports are invalid")
        for ref in inputs.values():
            exact(ref, {"from_step", "artifact"}, "historical producer reference")
            _node(ref["from_step"])
            identifier(ref["artifact"], "historical artifact")


def validate_retained_model_context(value):
    """Exact metadata-only boundary for the separate retained-result purpose."""
    validate_model_context(value, retained=True)
