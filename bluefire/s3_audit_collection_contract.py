"""Pure bounded S3 audit collection data, never enrollment or send authority."""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any, Mapping

from .s3_access_contract import (
    S3AccessError,
    S3AccessScope,
    digest,
    document,
    exact,
    role_arn,
    text,
    timestamp,
)
from .util import canonical_json_bytes, content_hash

SOURCE_SCHEMA = "bluefire.s3-audit-source.v1"
WORKFLOW_SCHEMA = "bluefire.s3-audit-workflow.v1"
APPROVAL_SCHEMA = "bluefire.s3-workflow-approval.v3"
PAIR_SCHEMA = "bluefire.s3-audit-read-pair.v1"
COLLECTION_SCHEMA = "bluefire.s3-audit-collection.v1"
DISCOVERY_SCHEMA = "bluefire.s3-audit-discovery.v1"
MAX_REQUEST_BYTES = 80 * 1024
MAX_FRAME_BYTES = 16 * 1024
MAX_PROJECTION_BYTES = 15 * 1024
MAX_DURABLE_BYTES = 8 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_LIST_KEYS = 16
MAX_BATCHES = 2
LIMIT_CEILINGS = {
    "api_calls": 9,
    "sessions": 1,
    "files": 4,
    "sdk_body_bytes": 393216,
    "compressed_bytes": 262144,
    "expanded_bytes": 1048576,
    "events": 500,
    "seconds": 30,
}
_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", re.ASCII)
_HEX = re.compile(r"[0-9a-f]{64}", re.ASCII)
_JOB = re.compile(r"job-[0-9a-f]{32}", re.ASCII)
_RUN = re.compile(r"run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}", re.ASCII)
_REGION = re.compile(
    r"(?:af|ap|ca|eu|il|me|mx|sa|us)-"
    r"(?:central|east|north|northeast|northwest|south|southeast|southwest|west)-[1-9][0-9]?",
    re.ASCII,
)
_BUCKET = re.compile(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", re.ASCII)
_PATH = re.compile(r"[A-Za-z0-9/_.-]+", re.ASCII)
_ETAG = re.compile(r'"[A-Za-z0-9._+-]{1,128}"', re.ASCII)
_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9+/=_:.-]{0,127}", re.ASCII)


def _require(value: bool, message: str) -> None:
    if not value:
        raise S3AccessError(message)


def _integer(value: Any, maximum: int, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise S3AccessError("audit collection integer exceeds its bound")
    return value


def _utc(value: Any) -> str:
    result = timestamp(value)
    _require(result.year >= 1000, "audit collection UTC date is unsupported")
    return result.isoformat().replace("+00:00", "Z")


def _scope(scope: S3AccessScope) -> dict[str, Any]:
    return S3AccessScope.from_mapping(scope.to_dict()).to_dict()


def source(scope: S3AccessScope, value: Any) -> dict[str, Any]:
    """Check an explicit source descriptor without reading it or granting access."""
    bound = _scope(scope)
    row = document(value)
    exact(
        row,
        {
            "schema_version",
            "audit_source_id",
            "experiment_scope_digest",
            "trail_arn",
            "source_account_id",
            "event_region",
            "audit_bucket",
            "audit_bucket_owner_account_id",
            "audit_bucket_region",
            "exact_delivery_root_prefix",
            "collector_role_arn",
            "managed_profile_digest",
            "protected_runtime_digest",
            "worker_generation",
            "expires_at",
            "audit_limits",
        },
        "audit source",
    )
    _require(
        row["schema_version"] == SOURCE_SCHEMA
        and row["experiment_scope_digest"] == scope.digest
        and row["source_account_id"] == bound["account_id"]
        and row["audit_bucket_owner_account_id"] == bound["account_id"]
        and row["event_region"] == bound["region"],
        "audit source differs from its experiment account or region",
    )
    text(row["audit_source_id"], _REFERENCE, "audit source identity")
    text(row["audit_bucket_region"], _REGION, "audit bucket region")
    bucket = text(row["audit_bucket"], _BUCKET, "audit bucket")
    _require(
        not bucket.startswith(("xn--", "sthree-", "amzn-s3-demo-"))
        and not bucket.endswith(("-s3alias", "--ol-s3", "--x-s3", "--table-s3")),
        "audit bucket family is unsupported",
    )
    trail = re.compile(
        re.escape(f"arn:aws:cloudtrail:{bound['region']}:{bound['account_id']}:trail/")
        + r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}",
        re.ASCII,
    )
    text(row["trail_arn"], trail, "same-account trail")
    prefix = text(row["exact_delivery_root_prefix"], _PATH, "audit delivery prefix")
    suffix = f"AWSLogs/{bound['account_id']}/CloudTrail/{bound['region']}/"
    _require(
        len(prefix.encode("ascii")) <= 256
        and not prefix.startswith("/")
        and prefix.endswith(suffix)
        and all(part not in {"", ".", ".."} for part in prefix[:-1].split("/"))
        and (prefix == suffix or prefix[: -len(suffix)].endswith("/")),
        "audit delivery prefix is not the exact ordinary trail path",
    )
    collector = role_arn(row["collector_role_arn"], bound["account_id"])
    _require(collector not in bound["roles"].values(), "audit collector role must be distinct")
    for name in ("managed_profile_digest", "protected_runtime_digest", "worker_generation"):
        digest(row[name])
    row["expires_at"] = _utc(row["expires_at"])
    _require(
        timestamp(bound["created_at"])
        < timestamp(row["expires_at"])
        <= timestamp(bound["expires_at"]),
        "audit source expiry is outside the original scope",
    )
    limits = exact(row["audit_limits"], set(LIMIT_CEILINGS), "audit limits")
    for name, ceiling in LIMIT_CEILINGS.items():
        _integer(limits[name], ceiling, minimum=1)
    _require(
        limits["api_calls"] == 9 and limits["sessions"] == 1,
        "audit source must cover the complete call and session reservation",
    )
    return row


def budget(scope: S3AccessScope, value: Any) -> dict[str, dict[str, int]]:
    """Return finite minima; remaining balances and future holds need admission."""
    bound = _scope(scope)["limits"]
    configured = source(scope, value)["audit_limits"]
    per = {name: min(configured[name], cap) for name, cap in LIMIT_CEILINGS.items()}
    per["api_calls"] = min(per["api_calls"], bound["api_calls"] // MAX_BATCHES)
    per["sessions"] = min(per["sessions"], bound["sessions"] // MAX_BATCHES)
    per["events"] = min(per["events"], bound["audit_events"] // MAX_BATCHES)
    per["seconds"] = min(
        per["seconds"], bound["request_seconds"], bound["audit_seconds"] // MAX_BATCHES
    )
    per["sdk_body_bytes"] = min(per["sdk_body_bytes"], bound["audit_bytes"] // MAX_BATCHES)
    per["expanded_bytes"] = min(per["expanded_bytes"], bound["audit_bytes"] // MAX_BATCHES)
    per["compressed_bytes"] = min(
        per["compressed_bytes"], per["sdk_body_bytes"], per["files"] * MAX_RESPONSE_BYTES
    )
    _require(
        per["api_calls"] == 9
        and per["sessions"] == 1
        and all(per.values())
        and MAX_BATCHES * (per["sdk_body_bytes"] + per["expanded_bytes"]) <= bound["audit_bytes"],
        "original scope cannot cover both audit batch reservations",
    )
    workflow = {name: MAX_BATCHES * amount for name, amount in per.items()}
    workflow["batches"] = MAX_BATCHES
    workflow["wire_plus_expansion_bytes"] = workflow["sdk_body_bytes"] + workflow["expanded_bytes"]
    return {"per_batch": per, "workflow": workflow}


def workflow(scope: S3AccessScope, value: Any) -> dict[str, Any]:
    """Check two audit batches and four future reads; native admission owns holds."""
    bound = _scope(scope)
    row = document(value)
    exact(
        row,
        {
            "schema_version",
            "workflow_job_id",
            "environment_id",
            "resource_key",
            "scope_digest",
            "source",
            "budget",
        },
        "audit workflow",
    )
    _require(row["schema_version"] == WORKFLOW_SCHEMA, "audit workflow schema is unsupported")
    text(row["workflow_job_id"], _JOB, "audit workflow identity")
    text(row["environment_id"], _REFERENCE, "audit environment identity")
    _require(
        row["scope_digest"] == scope.digest
        and row["resource_key"]
        == content_hash({name: bound[name] for name in ("account_id", "region", "bucket")}),
        "audit workflow differs from its original experiment resource or scope",
    )
    checked_source = source(scope, row["source"])
    derived = budget(scope, checked_source)
    _require(
        canonical_json_bytes(row["budget"]) == canonical_json_bytes(derived),
        "audit workflow budget differs from its derived reservations",
    )
    _require(
        bound["limits"]["sessions"] >= 2 * MAX_BATCHES + derived["workflow"]["sessions"]
        and bound["limits"]["business_attempts"] >= (1 + 2) * MAX_BATCHES,
        "original scope cannot cover the four business reads and both audit batches",
    )
    row["source"] = checked_source
    row["budget"] = derived
    return row


def build_workflow(
    scope: S3AccessScope,
    source_value: Any,
    *,
    workflow_job_id: str,
    environment_id: str,
) -> dict[str, Any]:
    """Construct checked commitment data, never an enrollment or reservation."""
    bound = _scope(scope)
    checked_source = source(scope, source_value)
    return workflow(
        scope,
        {
            "schema_version": WORKFLOW_SCHEMA,
            "workflow_job_id": workflow_job_id,
            "environment_id": environment_id,
            "resource_key": content_hash(
                {name: bound[name] for name in ("account_id", "region", "bucket")}
            ),
            "scope_digest": scope.digest,
            "source": checked_source,
            "budget": budget(scope, checked_source),
        },
    )


def original_pair(scope: S3AccessScope, value: Any) -> dict[str, Any]:
    """Validate raw read consistency; authenticated store/native joins are separate."""
    from .s3_access_wire_contract import request as ordinary_request
    from .s3_audit_read_contract import validated_read

    row = document(value, limit=MAX_REQUEST_BYTES)
    exact(
        row,
        {
            "schema_version",
            "workflow_job_id",
            "operation_job_id",
            "phase",
            "outcome_digest",
            "review_digest",
            "reads",
        },
        "original audit read pair",
    )
    _require(
        row["schema_version"] == PAIR_SCHEMA
        and isinstance(row["phase"], str)
        and row["phase"] in {"baseline", "retest"},
        "audit source phase pair is unsupported",
    )
    text(row["workflow_job_id"], _JOB, "original workflow")
    text(row["operation_job_id"], _JOB, "original operation")
    _require(
        row["workflow_job_id"] != row["operation_job_id"], "original operation is not a workflow"
    )
    digest(row["outcome_digest"])
    digest(row["review_digest"])
    reads = row["reads"]
    _require(isinstance(reads, list) and len(reads) == 2, "audit requires both original reads")
    for entry, reader in zip(reads, ("probe", "legitimate"), strict=True):
        exact(
            entry,
            {
                "reader",
                "run_id",
                "manifest_digest",
                "request_digest",
                "worker_result_digest",
                "reservation_digest",
                "cleanup",
                "request",
                "result",
            },
            "original audit read",
        )
        _require(
            entry["reader"] == reader and entry["cleanup"] == "verified",
            "original read order or native cleanup is unresolved",
        )
        run_id = text(entry["run_id"], _RUN, "original run")
        try:
            datetime.strptime(run_id[4:20], "%Y%m%dT%H%M%SZ")
        except ValueError:
            raise S3AccessError("original run UTC identity is invalid") from None
        for name in (
            "manifest_digest",
            "request_digest",
            "worker_result_digest",
            "reservation_digest",
        ):
            digest(entry[name])
        original = document(entry["request"], limit=MAX_REQUEST_BYTES)
        _require(
            original.get("schema_version") == "bluefire.s3-worker-request.v1"
            and original.get("operation") == reader + "_read",
            "audit requires an original business read request",
        )
        raw = ordinary_request(original)
        checked = validated_read(raw, entry["result"])
        _require(
            raw["schema_version"] == "bluefire.s3-worker-request.v1"
            and raw["operation"] == reader + "_read"
            and raw["scope"] == scope.to_dict()
            and content_hash(raw) == entry["request_digest"]
            and content_hash(checked) == entry["worker_result_digest"],
            "original audit read request or result differs",
        )
        entry["request"], entry["result"] = raw, checked
    for name in ("run_id", "manifest_digest", "request_digest", "reservation_digest"):
        _require(
            reads[0][name] != reads[1][name], "original audit read identities must be distinct"
        )
    for name in ("launch_id", "request_id"):
        _require(
            reads[0]["request"][name] != reads[1]["request"][name],
            "original audit worker identities must be distinct",
        )
    _require(
        reads[0]["request"]["runtime_digest"] == reads[1]["request"]["runtime_digest"]
        and reads[0]["request"]["worker_generation"] == reads[1]["request"]["worker_generation"],
        "original audit read runtime differs within the pair",
    )
    return row


def collection(scope: S3AccessScope, value: Any) -> dict[str, Any]:
    """Check one original collection intent, without consulting clocks or stores."""
    row = document(value, limit=MAX_REQUEST_BYTES)
    exact(
        row,
        {
            "schema_version",
            "launch_id",
            "request_id",
            "source",
            "workflow_job_id",
            "operation_job_id",
            "issued_at",
            "deadline",
            "original_pair",
        },
        "audit collection",
    )
    _require(row["schema_version"] == COLLECTION_SCHEMA, "audit collection schema is unsupported")
    for name in ("launch_id", "request_id"):
        text(row[name], _HEX, "collection worker identity")
    for name in ("workflow_job_id", "operation_job_id"):
        text(row[name], _JOB, "collection job identity")
    row["source"] = source(scope, row["source"])
    pair = original_pair(scope, row["original_pair"])
    row["original_pair"] = pair
    _require(
        row["workflow_job_id"] == pair["workflow_job_id"]
        and row["operation_job_id"] not in {row["workflow_job_id"], pair["operation_job_id"]},
        "collection does not bind a distinct original workflow operation",
    )
    for entry in pair["reads"]:
        raw = entry["request"]
        _require(
            raw["runtime_digest"] == row["source"]["protected_runtime_digest"]
            and raw["worker_generation"] == row["source"]["worker_generation"]
            and row["launch_id"] != raw["launch_id"]
            and row["request_id"] != raw["request_id"],
            "collection source runtime or worker identity differs",
        )
    row["issued_at"], row["deadline"] = _utc(row["issued_at"]), _utc(row["deadline"])
    issued, end = timestamp(row["issued_at"]), timestamp(row["deadline"])
    bound = _scope(scope)
    starts = [
        max(
            timestamp(bound["created_at"]),
            timestamp(entry["request"]["deadline"])
            - timedelta(seconds=bound["limits"]["request_seconds"]),
        )
        for entry in pair["reads"]
    ]
    seconds = budget(scope, row["source"])["per_batch"]["seconds"]
    _require(
        max(starts)
        <= issued
        < end
        <= min(
            timestamp(row["source"]["expires_at"]),
            issued + timedelta(seconds=seconds),
            min(starts) + timedelta(seconds=bound["limits"]["audit_seconds"]),
        ),
        "collection deadline is outside its original bounded audit interval",
    )
    _listed(scope, row)
    _require(
        len(canonical_json_bytes(row)) <= MAX_REQUEST_BYTES,
        "audit collection exceeds request bound",
    )
    return row


def _listed(scope: S3AccessScope, row: Mapping[str, Any]) -> list[dict[str, Any]]:
    bound = _scope(scope)
    lower = min(
        max(
            timestamp(bound["created_at"]),
            timestamp(entry["request"]["deadline"])
            - timedelta(seconds=bound["limits"]["request_seconds"]),
        )
        for entry in row["original_pair"]["reads"]
    )
    lower = lower.replace(second=0, microsecond=0)
    upper = timestamp(row["issued_at"])
    day = lower.replace(hour=0, minute=0)
    last = upper.replace(hour=0, minute=0, second=0, microsecond=0)
    _require(0 <= (last - day).days < 2, "audit discovery exceeds its two dated prefixes")
    answer = []
    while day <= last:
        prefix = row["source"]["exact_delivery_root_prefix"] + day.strftime("%Y/%m/%d/")
        start = max(day, lower)
        cursor = prefix + bound["account_id"] + "_CloudTrail_" + bound["region"] + "_"
        cursor += start.strftime("%Y%m%dT%H%MZ") + "_"
        _require(len(prefix) <= 267 and len(cursor) <= 512, "audit listing path exceeds its bound")
        answer.append(
            {
                "Bucket": row["source"]["audit_bucket"],
                "ExpectedBucketOwner": bound["account_id"],
                "Prefix": prefix,
                "StartAfter": cursor,
                "MaxKeys": MAX_LIST_KEYS,
            }
        )
        if day == last:
            break
        day += timedelta(days=1)
    return answer


def list_parameters(scope: S3AccessScope, value: Any) -> list[dict[str, Any]]:
    return _listed(scope, collection(scope, value))


def operation_plan(
    scope: S3AccessScope, value: Any, *, selected_count: int = 0
) -> list[tuple[str, str, str]]:
    """A consistency plan, not permission to read a caller-selected resource."""
    row = collection(scope, value)
    _integer(selected_count, budget(scope, row["source"])["per_batch"]["files"])
    return (
        [
            ("sts", "GetCallerIdentity", "controller"),
            ("sts", "AssumeRole", "controller"),
            ("sts", "GetCallerIdentity", "collector"),
        ]
        + [("s3", "ListObjectsV2", "collector") for _ in _listed(scope, row)]
        + [("s3", "GetObject", "collector")] * selected_count
    )


def _key(scope: S3AccessScope, key: Any, prefix: str) -> str:
    bound = _scope(scope)
    validated_key = text(key, _PATH, "audit log key")
    _require(
        len(validated_key) <= 512 and validated_key.startswith(prefix),
        "audit key escapes its dated prefix",
    )
    filename = validated_key[len(prefix) :]
    grammar = re.compile(
        re.escape(bound["account_id"] + "_CloudTrail_" + bound["region"] + "_")
        + r"([0-9]{8}T[0-9]{4}Z)_[A-Za-z0-9]{16}\.json\.gz",
        re.ASCII,
    )
    match = grammar.fullmatch(filename)
    if match is None:
        raise S3AccessError("audit key is not a supported CloudTrail delivery filename")
    try:
        delivered = datetime.strptime(match.group(1), "%Y%m%dT%H%MZ")
    except ValueError:
        raise S3AccessError("audit filename delivery time is invalid") from None
    _require(
        prefix.endswith(delivered.strftime("%Y/%m/%d/")), "audit filename date differs from prefix"
    )
    return validated_key


def discovery(
    scope: S3AccessScope, value: Any, *, request_digest: str, reservation_digest: str, listings: Any
) -> dict[str, dict[str, Any]]:
    """Build bounded descriptive frames; only native commit/ACK authorizes keys."""
    row = collection(scope, value)
    digest(request_digest)
    digest(reservation_digest)
    expected = _listed(scope, row)
    raw = document({"listings": listings}, limit=128 * 1024)["listings"]
    _require(
        isinstance(raw, list) and len(raw) == len(expected),
        "audit discovery lacks exact list responses",
    )
    candidates, provenance = [], []
    for index, (listing, parameters) in enumerate(zip(raw, expected, strict=True)):
        exact(
            listing,
            {
                "prefix",
                "start_after",
                "request_id",
                "body_sha256",
                "http_status",
                "retry_attempts",
                "key_count",
                "is_truncated",
                "objects",
            },
            "audit listing",
        )
        _require(
            listing["prefix"] == parameters["Prefix"]
            and listing["start_after"] == parameters["StartAfter"]
            and type(listing["http_status"]) is int
            and listing["http_status"] == 200
            and type(listing["retry_attempts"]) is int
            and listing["retry_attempts"] == 0
            and type(listing["is_truncated"]) is bool,
            "audit listing source or status differs",
        )
        text(listing["request_id"], _REQUEST_ID, "audit listing request ID")
        digest(listing["body_sha256"])
        count = _integer(listing["key_count"], MAX_LIST_KEYS)
        objects = listing["objects"]
        _require(
            isinstance(objects, list) and len(objects) == count, "audit listing key count differs"
        )
        previous = parameters["StartAfter"]
        for obj in objects:
            exact(obj, {"key", "etag", "size_bytes"}, "discovered audit object")
            key = _key(scope, obj["key"], parameters["Prefix"])
            _require(previous < key, "audit listing keys are not unique lexical successors")
            previous = key
            text(obj["etag"], _ETAG, "audit conditional identity")
            _integer(obj["size_bytes"], 5 * 1024**4)
            candidates.append(
                [index, key[len(parameters["Prefix"]) :], obj["size_bytes"], obj["etag"]]
            )
        provenance.append(
            {
                "request_id": listing["request_id"],
                "body_sha256": listing["body_sha256"],
                "projection_digest": content_hash(listing),
                "key_count": count,
                "is_truncated": listing["is_truncated"],
            }
        )
    _require(
        len({entry["request_id"] for entry in provenance}) == len(provenance),
        "audit listings reuse an AWS request identity",
    )
    limits = budget(scope, row["source"])["per_batch"]
    selected: list[int] = []
    selected_rows, total = [], 0
    for index, candidate in enumerate(candidates):
        prefix_index, suffix, size, observed_etag = candidate
        if (
            0 < size <= MAX_RESPONSE_BYTES
            and len(selected) < limits["files"]
            and total + size <= limits["compressed_bytes"]
        ):
            selected.append(index)
            selected_rows.append(
                {
                    "key": expected[prefix_index]["Prefix"] + suffix,
                    "size_bytes": size,
                    "etag": observed_etag,
                }
            )
            total += size
    truncated = any(entry["is_truncated"] for entry in provenance) or len(selected) < len(
        candidates
    )
    projection = {
        "prefixes": [[item["Prefix"], item["StartAfter"]] for item in expected],
        "listings": provenance,
        "candidates": candidates,
        "selected": selected,
        "truncated": truncated,
        "completed_list_count": len(expected),
        "next_send_sequence": 4 + len(expected),
    }
    _require(
        len(canonical_json_bytes(projection)) <= MAX_PROJECTION_BYTES,
        "audit discovery projection exceeds its bounded frame",
    )
    frame = {
        "kind": "discovery",
        "request_digest": request_digest,
        "collection_digest": content_hash(row),
        "pair_digest": content_hash(row["original_pair"]),
        "reservation_digest": reservation_digest,
        "audit_source_digest": content_hash(row["source"]),
        **projection,
    }
    _require(
        len(canonical_json_bytes(frame)) + 1 <= MAX_FRAME_BYTES,
        "complete audit discovery frame exceeds its unchanged line bound",
    )
    durable = {
        "schema_version": DISCOVERY_SCHEMA,
        "request_digest": frame["request_digest"],
        "collection_digest": frame["collection_digest"],
        "pair_digest": frame["pair_digest"],
        "reservation_digest": reservation_digest,
        "audit_source_digest": frame["audit_source_digest"],
        "resource_key": content_hash(
            {key: scope.to_dict()[key] for key in ("account_id", "region", "bucket")}
        ),
        "phase": row["original_pair"]["phase"],
        "frame_digest": content_hash(frame),
        "prefixes": projection["prefixes"],
        "listings": provenance,
        "completed_list_count": projection["completed_list_count"],
        "next_send_sequence": projection["next_send_sequence"],
        "candidate_count": len(candidates),
        "selected": selected_rows,
        "truncated": truncated,
    }
    _require(
        all(len(canonical_json_bytes(item)) <= 896 for item in selected_rows),
        "selected audit row exceeds its durable bound",
    )
    other = {key: item for key, item in durable.items() if key != "selected"}
    _require(
        len(canonical_json_bytes(other)) <= 4096
        and len(canonical_json_bytes(durable)) <= MAX_DURABLE_BYTES,
        "audit discovery payload exceeds its durable bound",
    )
    return {"frame": frame, "durable": durable}


def result_frame(value: Any) -> bytes:
    """Size an already validated result; this does not validate its provenance."""
    row = document(value, limit=MAX_PROJECTION_BYTES)
    payload = canonical_json_bytes({"kind": "result", "result": row}) + b"\n"
    _require(len(payload) <= MAX_FRAME_BYTES, "complete audit result frame exceeds its line bound")
    return payload
