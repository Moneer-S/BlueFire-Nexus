"""Closed collector consistency messages, never enrollment or native authority."""

from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import Any, Mapping
from urllib.parse import quote

from . import s3_audit_collection_contract as audit
from .s3_access_contract import S3AccessError, S3AccessScope, digest, document, exact, timestamp
from .util import canonical_json_bytes, content_hash

REQUEST_SCHEMA = "bluefire.s3-worker-request.v3"
RESULT_SCHEMA = "bluefire.s3-worker-result.v3"
OBSERVATION_SCHEMA = "bluefire.s3-audit-collection-observation.v1"
MAX_SEND_FRAME_BYTES = 2048
_BASE_FIELDS = {
    "schema_version",
    "launch_id",
    "request_id",
    "worker_generation",
    "runtime_digest",
    "scope",
    "scope_digest",
    "operation",
    "policy_change",
    "deadline",
    "max_sends",
    "exclusive_writer_digest",
    "audit",
    "audit_authority_digest",
}


def _require(value: bool, message: str) -> None:
    if not value:
        raise S3AccessError(message)


def request(value: Any) -> dict[str, Any]:
    row = document(value, limit=audit.MAX_REQUEST_BYTES)
    exact(row, _BASE_FIELDS, "audit worker request")
    scope = S3AccessScope.from_mapping(row["scope"])
    collection = audit.collection(scope, row["audit"])
    future = audit.budget(scope, collection["source"])["workflow"]
    _require(
        row["schema_version"] == REQUEST_SCHEMA
        and row["operation"] == "collect_audit"
        and row["policy_change"] is None
        and row["exclusive_writer_digest"] is None
        and type(row["max_sends"]) is int
        and row["max_sends"] == 9
        and row["scope_digest"] == scope.digest
        and row["launch_id"] == collection["launch_id"]
        and row["request_id"] == collection["request_id"]
        and row["runtime_digest"] == collection["source"]["protected_runtime_digest"]
        and row["worker_generation"] == collection["source"]["worker_generation"]
        and row["audit_authority_digest"] == content_hash(collection["source"])
        and row["deadline"] == collection["deadline"],
        "audit worker request differs from its exact collection",
    )
    _require(
        row["scope"]["limits"]["sessions"] >= 4 + future["sessions"]
        and row["scope"]["limits"]["business_attempts"] >= 6,
        "audit request cannot drop either batch or four original read holds",
    )
    row["scope"], row["audit"] = scope.to_dict(), collection
    _require(
        len(canonical_json_bytes(row)) + 1 <= audit.MAX_REQUEST_BYTES,
        "complete audit request exceeds its unchanged frame bound",
    )
    return row


def operation_plan(value: Any, *, selected_count: int = 0) -> list[tuple[str, str, str]]:
    row = request(value)
    return audit.operation_plan(
        S3AccessScope.from_mapping(row["scope"]), row["audit"], selected_count=selected_count
    )


def planned_send(value: Any, sequence: int, *, committed_discovery: Any = None) -> dict[str, Any]:
    """Exact descriptive SDK preview. A native debit, not this helper, permits sends."""
    row = request(value)
    scope = S3AccessScope.from_mapping(row["scope"])
    parameters = audit.list_parameters(scope, row["audit"])
    _require(type(sequence) is int and 1 <= sequence <= 9, "audit send sequence differs")
    resource: dict[str, Any]
    selected: list[Any] = []
    if sequence >= 4 + len(parameters):
        _require(
            isinstance(committed_discovery, Mapping)
            and committed_discovery.get("request_digest") == content_hash(row)
            and committed_discovery.get("collection_digest") == content_hash(row["audit"]),
            "audit GetObject requires the original committed Discovery",
        )
        selected = committed_discovery.get("selected")
        _require(
            isinstance(selected, list) and sequence - 4 - len(parameters) < len(selected),
            "audit selected file is absent",
        )
        item = selected[sequence - 4 - len(parameters)]
        resource = {
            "Bucket": row["audit"]["source"]["audit_bucket"],
            "ExpectedBucketOwner": row["scope"]["account_id"],
            "Key": item["key"],
            "IfMatch": item["etag"],
            "size_bytes": item["size_bytes"],
            "discovery_digest": content_hash(committed_discovery),
        }
    elif sequence >= 4:
        resource = parameters[sequence - 4]
    elif sequence == 2:
        resource = {
            "role_arn": row["audit"]["source"]["collector_role_arn"],
            "session_name": "bf-" + row["request_id"][:32] + "-collector",
        }
    else:
        resource = {}
    plan = operation_plan(row, selected_count=len(selected))
    _require(sequence <= len(plan), "audit send exceeds actual operation plan")
    service, operation, role = plan[sequence - 1]
    body = ""
    if operation == "GetCallerIdentity":
        body = "Action=GetCallerIdentity&Version=2011-06-15"
    elif operation == "AssumeRole":
        body = (
            "Action=AssumeRole&Version=2011-06-15&RoleArn="
            + quote(resource["role_arn"], safe="-._~")
            + "&RoleSessionName="
            + resource["session_name"]
            + "&DurationSeconds=900"
        )
    return {
        "service": service,
        "operation": operation,
        "role": role,
        "method": "POST" if service == "sts" else "GET",
        "host": service
        + "."
        + (
            row["audit"]["source"]["audit_bucket_region"]
            if service == "s3"
            else row["scope"]["region"]
        )
        + ".amazonaws.com",
        "resource": resource,
        "payload_digest": "sha256:" + hashlib.sha256(body.encode("ascii")).hexdigest(),
    }


def validate_send(
    value: Any, frame: Any, *, sequence: int, committed_discovery: Any = None
) -> dict[str, Any]:
    row = request(value)
    checked = document(frame, limit=MAX_SEND_FRAME_BYTES - 1)
    expected = {
        "kind": "send",
        "request_digest": content_hash(row),
        "sequence": sequence,
        "send": planned_send(row, sequence, committed_discovery=committed_discovery),
    }
    expected["send_digest"] = content_hash(expected)
    _require(
        canonical_json_bytes(checked) == canonical_json_bytes(expected),
        "audit send preview differs from exact original sequence and resource",
    )
    return checked


def validate_discovery_ack(value: Any, durable: Any, ack: Any) -> None:
    row = request(value)
    checked = document(ack, limit=MAX_SEND_FRAME_BYTES - 1)
    _require(
        checked
        == {
            "kind": "discovery_committed",
            "request_digest": content_hash(row),
            "reservation_digest": durable["reservation_digest"],
            "discovery_digest": content_hash(durable),
            "frame_digest": durable["frame_digest"],
            "next_send_sequence": durable["next_send_sequence"],
        }
        and type(checked["next_send_sequence"]) is int,
        "native Discovery ACK differs from original committed frame",
    )


def discovery(value: Any, frame: Any, *, reservation_digest: str) -> dict[str, Any]:
    """Reconstruct every list projection; native commit/ACK remains a separate step."""
    row = request(value)
    scope = S3AccessScope.from_mapping(row["scope"])
    checked = document(frame, limit=audit.MAX_FRAME_BYTES - 1)
    exact(
        checked,
        {
            "kind",
            "request_digest",
            "collection_digest",
            "pair_digest",
            "reservation_digest",
            "audit_source_digest",
            "prefixes",
            "listings",
            "candidates",
            "selected",
            "truncated",
            "completed_list_count",
            "next_send_sequence",
        },
        "audit discovery frame",
    )
    parameters = audit.list_parameters(scope, row["audit"])
    listings, candidates = checked["listings"], checked["candidates"]
    _require(
        isinstance(listings, list)
        and len(listings) == len(parameters)
        and isinstance(candidates, list)
        and len(candidates) <= 32,
        "audit discovery list accounting differs",
    )
    objects: list[list[dict[str, Any]]] = [[] for _ in parameters]
    previous = -1
    for candidate in candidates:
        _require(
            isinstance(candidate, list) and len(candidate) == 4,
            "audit discovery candidate shape differs",
        )
        index, suffix, size, etag = candidate
        _require(
            type(index) is int and previous <= index < len(parameters) and isinstance(suffix, str),
            "audit candidate prefix order differs",
        )
        previous = index
        objects[index].append(
            {"key": parameters[index]["Prefix"] + suffix, "size_bytes": size, "etag": etag}
        )
    raw = []
    for index, listing in enumerate(listings):
        exact(
            listing,
            {"request_id", "body_sha256", "projection_digest", "key_count", "is_truncated"},
            "audit listing provenance",
        )
        raw.append(
            {
                "prefix": parameters[index]["Prefix"],
                "start_after": parameters[index]["StartAfter"],
                "request_id": listing["request_id"],
                "body_sha256": listing["body_sha256"],
                "http_status": 200,
                "retry_attempts": 0,
                "key_count": listing["key_count"],
                "is_truncated": listing["is_truncated"],
                "objects": objects[index],
            }
        )
    rebuilt = audit.discovery(
        scope,
        row["audit"],
        request_digest=content_hash(row),
        reservation_digest=reservation_digest,
        listings=raw,
    )
    _require(
        canonical_json_bytes(checked) == canonical_json_bytes(rebuilt["frame"]),
        "audit discovery differs from the exact deterministic projection",
    )
    return rebuilt["durable"]


def _read_correlation(
    original: Mapping[str, Any], value: Any, *, delivery_state: str, event_count: int
) -> None:
    from .s3_access_audit import _ERROR_OUTCOMES, _EVENT_ID

    row = exact(
        value,
        {
            "schema_version",
            "request_digest",
            "worker_result_digest",
            "reads",
            "authorized_request_window",
            "independent_collection_proven",
            "effective_access_claim",
        },
        "audit read correlation",
    )
    raw = original["request"]
    end = timestamp(raw["deadline"])
    start = max(
        timestamp(raw["scope"]["created_at"]),
        end - timedelta(seconds=raw["scope"]["limits"]["request_seconds"]),
    )
    _require(
        row["schema_version"] == "bluefire.s3-audit-correlation.v1"
        and row["request_digest"] == original["request_digest"]
        and row["worker_result_digest"] == original["worker_result_digest"]
        and row["independent_collection_proven"] is False
        and row["effective_access_claim"] is False
        and row["authorized_request_window"]
        == {"from": start.isoformat(), "through": end.isoformat()},
        "audit correlation original identity or window differs",
    )
    expected = raw["scope"]["objects"][: 1 if original["reader"] == "probe" else 2]
    reads = row["reads"]
    _require(
        isinstance(reads, list) and len(reads) == len(expected),
        "audit correlation read count differs",
    )
    for index, (observed, obj) in enumerate(zip(reads, expected, strict=True)):
        exact(
            observed,
            {
                "purpose",
                "reader",
                "status",
                "worker_outcome",
                "worker_request_id",
                "audit_event_ids",
                "audit_outcomes",
                "full_object_bytes_proven",
            },
            "audit correlation read",
        )
        calls = original["result"]["calls"]
        call = calls[index + 3] if len(calls) > index + 3 else None
        outcome = (
            "unreported"
            if call is None
            else (
                _ERROR_OUTCOMES.get(call["error_code"], "other_service_error")
                if "error_code" in call
                else "service_success"
            )
        )
        ids, outcomes = observed["audit_event_ids"], observed["audit_outcomes"]
        _require(
            observed["purpose"] == obj["purpose"]
            and observed["reader"] == original["reader"]
            and observed["worker_outcome"] == outcome
            and observed["worker_request_id"] == (call["request_id"] if call else None)
            and observed["full_object_bytes_proven"] is False
            and isinstance(ids, list)
            and len(ids) <= event_count
            and all(
                isinstance(item, str)
                and _EVENT_ID.fullmatch(item) is not None
                and item == item.lower()
                for item in ids
            )
            and len(ids) == len(set(ids))
            and isinstance(outcomes, list)
            and all(isinstance(item, str) for item in outcomes)
            and outcomes == sorted(set(outcomes))
            and all(
                item
                in {
                    "service_success",
                    "service_denied",
                    "object_missing",
                    "bucket_missing",
                    "credential_error",
                    "other_service_error",
                }
                for item in outcomes
            ),
            "audit read correlation projection differs",
        )
        status = observed["status"]
        _require(isinstance(status, str), "audit correlation status differs")
        if ids:
            _require(
                call is not None
                and status in {"matched", "conflict"}
                and bool(outcomes)
                and (status != "matched" or outcomes == [outcome]),
                "audit match lacks an exact original request",
            )
        else:
            allowed = (
                {"worker_unreported"}
                if call is None
                else (
                    {"truncated"}
                    if delivery_state == "truncated"
                    else (
                        {"unknown"}
                        if delivery_state == "unknown"
                        else {"awaiting_delivery", "unknown"}
                    )
                )
            )
            _require(not outcomes and status in allowed, "audit absence cannot establish access")


def validate_result(value: Any, result: Any) -> dict[str, Any]:
    from .s3_access_wire import SAFE_ERROR_CODES, SAFE_REQUEST_ID

    row = request(value)
    checked = document(result, limit=audit.MAX_FRAME_BYTES - 1)
    audit.result_frame(checked)
    exact(
        checked,
        {
            "schema_version",
            "request_digest",
            "outcome",
            "data",
            "problem",
            "send_permits_consumed",
            "calls",
            "runtime_isolation_proven",
        },
        "audit worker result",
    )
    _require(
        checked["schema_version"] == RESULT_SCHEMA
        and checked["request_digest"] == content_hash(row)
        and checked["runtime_isolation_proven"] is False
        and checked["outcome"] in ("observed", "failed"),
        "audit result binding differs",
    )
    consumed, calls = checked["send_permits_consumed"], checked["calls"]
    _require(
        type(consumed) is int
        and 0 <= consumed <= 9
        and isinstance(calls, list)
        and len(calls) <= consumed,
        "audit result call accounting differs",
    )
    data = checked["data"]
    count = 0
    if checked["outcome"] == "observed":
        exact(
            data,
            {
                "schema_version",
                "collection_digest",
                "pair_digest",
                "audit_source_digest",
                "reservation_digest",
                "discovery",
                "objects",
                "usage",
                "normalized_digest",
                "correlations",
                "delivery_state",
                "effective_access_claim",
                "log_integrity_proven",
            },
            "audit collection observation",
        )
        digest(data["reservation_digest"])
        durable = data["discovery"]
        exact(
            durable,
            {
                "schema_version",
                "request_digest",
                "collection_digest",
                "pair_digest",
                "reservation_digest",
                "audit_source_digest",
                "resource_key",
                "phase",
                "frame_digest",
                "prefixes",
                "listings",
                "completed_list_count",
                "next_send_sequence",
                "candidate_count",
                "selected",
                "truncated",
            },
            "audit durable discovery",
        )
        # Raw frame must have been checked at the native ACK boundary; result alone cannot prove that.
        parameters = audit.list_parameters(S3AccessScope.from_mapping(row["scope"]), row["audit"])
        _require(
            data["schema_version"] == OBSERVATION_SCHEMA
            and data["collection_digest"] == content_hash(row["audit"])
            and data["pair_digest"] == content_hash(row["audit"]["original_pair"])
            and data["audit_source_digest"] == row["audit_authority_digest"]
            and data["effective_access_claim"] is False
            and data["log_integrity_proven"] is False
            and data["delivery_state"] in ("incomplete", "truncated", "unknown")
            and len(canonical_json_bytes(durable)) <= audit.MAX_DURABLE_BYTES
            and durable["schema_version"] == audit.DISCOVERY_SCHEMA
            and durable["request_digest"] == content_hash(row)
            and all(
                durable[name] == data[name]
                for name in (
                    "collection_digest",
                    "pair_digest",
                    "audit_source_digest",
                    "reservation_digest",
                )
            )
            and durable["resource_key"]
            == content_hash(
                {name: row["scope"][name] for name in ("account_id", "region", "bucket")}
            )
            and durable["phase"] == row["audit"]["original_pair"]["phase"]
            and durable["prefixes"] == [[item["Prefix"], item["StartAfter"]] for item in parameters]
            and type(durable["completed_list_count"]) is int
            and durable["completed_list_count"] == len(parameters)
            and type(durable["next_send_sequence"]) is int
            and durable["next_send_sequence"] == 4 + len(parameters)
            and type(durable["candidate_count"]) is int
            and 0 <= durable["candidate_count"] <= 32
            and type(durable["truncated"]) is bool,
            "audit observation discovery identity differs",
        )
        digest(durable["frame_digest"])
        digest(data["normalized_digest"])
        listings = durable["listings"]
        _require(
            isinstance(listings, list) and len(listings) == len(parameters),
            "audit listing provenance count differs",
        )
        for listing in listings:
            exact(
                listing,
                {"request_id", "body_sha256", "projection_digest", "key_count", "is_truncated"},
                "audit listing provenance",
            )
            digest(listing["body_sha256"])
            digest(listing["projection_digest"])
            audit._integer(listing["key_count"], 16)
            _require(type(listing["is_truncated"]) is bool, "audit listing truncation differs")
        _require(
            sum(listing["key_count"] for listing in listings) == durable["candidate_count"]
            and len(
                canonical_json_bytes(
                    {key: item for key, item in durable.items() if key != "selected"}
                )
            )
            <= 4096,
            "audit durable candidate count or provenance bound differs",
        )
        selected, objects = durable["selected"], data["objects"]
        _require(
            isinstance(selected, list)
            and len(selected) <= 4
            and isinstance(objects, list)
            and len(objects) == len(selected) <= durable["candidate_count"],
            "audit object count differs",
        )
        count = len(selected)
        totals = {"files": count, "compressed_bytes": 0, "expanded_bytes": 0, "events": 0}
        previous = ""
        for index, (item, observed) in enumerate(zip(selected, objects, strict=True)):
            exact(item, {"key", "etag", "size_bytes"}, "selected audit object")
            _require(
                len(canonical_json_bytes(item)) <= 896, "selected audit object exceeds its bound"
            )
            matching = [
                p
                for p in parameters
                if isinstance(item["key"], str) and item["key"].startswith(p["Prefix"])
            ]
            _require(len(matching) == 1, "selected audit key escapes its original prefixes")
            audit._key(S3AccessScope.from_mapping(row["scope"]), item["key"], matching[0]["Prefix"])
            _require(
                previous < item["key"]
                and item["key"] > matching[0]["StartAfter"]
                and isinstance(item["etag"], str)
                and audit._ETAG.fullmatch(item["etag"]) is not None,
                "selected audit object identity differs",
            )
            previous = item["key"]
            audit._integer(item["size_bytes"], audit.MAX_RESPONSE_BYTES, minimum=1)
            exact(
                observed,
                {
                    "selected_index",
                    "compressed_sha256",
                    "expanded_sha256",
                    "expanded_bytes",
                    "event_count",
                },
                "audit object observation",
            )
            _require(
                type(observed["selected_index"]) is int and observed["selected_index"] == index,
                "audit object read identity differs",
            )
            for name in ("compressed_sha256", "expanded_sha256"):
                digest(observed[name])
            totals["compressed_bytes"] += item["size_bytes"]
            totals["expanded_bytes"] += audit._integer(
                observed["expanded_bytes"], 1048576, minimum=1
            )
            totals["events"] += audit._integer(observed["event_count"], 500)
        limits = audit.budget(S3AccessScope.from_mapping(row["scope"]), row["audit"]["source"])[
            "per_batch"
        ]
        usage = exact(data["usage"], {"sdk_body_bytes", *totals}, "audit collection usage")
        for name, amount in usage.items():
            audit._integer(amount, limits[name])
        _require(
            all(usage[name] == amount for name, amount in totals.items())
            and usage["sdk_body_bytes"] >= totals["compressed_bytes"]
            and (not durable["truncated"] or data["delivery_state"] == "truncated"),
            "audit aggregate usage or truncation differs",
        )
        exact(data["correlations"], {"probe", "legitimate"}, "audit pair correlations")
        for original in row["audit"]["original_pair"]["reads"]:
            _read_correlation(
                original,
                data["correlations"][original["reader"]],
                delivery_state=data["delivery_state"],
                event_count=totals["events"],
            )
    else:
        _require(
            data is None and checked["problem"] == "scoped_operation_failed",
            "failed audit cannot claim observations",
        )
    plan = operation_plan(
        row,
        selected_count=(
            count if data is not None else row["audit"]["source"]["audit_limits"]["files"]
        ),
    )
    _require(consumed <= len(plan), "audit result exceeds actual call sequence")
    for index, (call, (_, operation, role)) in enumerate(zip(calls, plan, strict=False)):
        exact(
            call,
            {"operation", "role", "request_id", "http_status"}
            | ({"error_code"} if "error_code" in call else set()),
            "audit response projection",
        )
        _require(
            call["operation"] == operation
            and call["role"] == role
            and isinstance(call["request_id"], str)
            and SAFE_REQUEST_ID.fullmatch(call["request_id"]) is not None
            and type(call["http_status"]) is int,
            "audit response identity differs",
        )
        _require(
            "error_code" not in call or (index + 1 == len(calls) == consumed),
            "audit service failure must end its consumed send sequence",
        )
        _require(
            (
                (
                    isinstance(call["error_code"], str)
                    and call["error_code"] in SAFE_ERROR_CODES
                    and 400 <= call["http_status"] <= 599
                )
                if "error_code" in call
                else call["http_status"] == 200
            ),
            "audit response status differs",
        )
    _require(len({call["request_id"] for call in calls}) == len(calls), "audit response IDs repeat")
    if data is not None:
        _require(
            checked["problem"] is None
            and consumed == len(plan) == len(calls)
            and not any("error_code" in call for call in calls),
            "audit observations lack complete sends",
        )
        listings = data["discovery"]["listings"]
        _require(
            isinstance(listings, list) and len(listings) == len(plan) - 3 - count,
            "audit listing receipt count differs",
        )
        for call, listing in zip(calls[3 : 3 + len(listings)], listings, strict=True):
            exact(
                listing,
                {"request_id", "body_sha256", "projection_digest", "key_count", "is_truncated"},
                "audit listing provenance",
            )
            digest(listing["body_sha256"])
            digest(listing["projection_digest"])
            audit._integer(listing["key_count"], 16)
            _require(type(listing["is_truncated"]) is bool, "audit listing truncation differs")
            _require(
                listing["request_id"] == call["request_id"], "audit listing response ID differs"
            )
    audit.result_frame(checked)
    return checked
