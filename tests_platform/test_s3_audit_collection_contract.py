"""Pure synthetic audit collection contracts, not AWS or installed-worker proof."""

from copy import deepcopy

import pytest

from bluefire import s3_audit_collection_contract as audit
from bluefire.s3_access_contract import S3AccessError, S3AccessScope
from bluefire.s3_access_wire import S3WorkerRequest, validate_result
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_s3_access_audit import result as read_result
from tests_platform.test_s3_access_wire import request_row


def source_row(scope):
    """Nonsecret synthetic source for configuration and parity fixture reuse."""
    bound = scope.to_dict()
    return {
        "schema_version": audit.SOURCE_SCHEMA,
        "audit_source_id": "synthetic-trail-delivery",
        "experiment_scope_digest": scope.digest,
        "trail_arn": f"arn:aws:cloudtrail:{bound['region']}:{bound['account_id']}:trail/synthetic",
        "source_account_id": bound["account_id"],
        "event_region": bound["region"],
        "audit_bucket": "bluefire-audit-fixture",
        "audit_bucket_owner_account_id": bound["account_id"],
        "audit_bucket_region": "us-west-2",
        "exact_delivery_root_prefix": f"AWSLogs/{bound['account_id']}/CloudTrail/{bound['region']}/",
        "collector_role_arn": f"arn:aws:iam::{bound['account_id']}:role/bluefire-audit-reader",
        "managed_profile_digest": "sha256:" + "6" * 64,
        "protected_runtime_digest": "sha256:" + "d" * 64,
        "worker_generation": "sha256:" + "c" * 64,
        "expires_at": bound["expires_at"],
        "audit_limits": dict(audit.LIMIT_CEILINGS),
    }


def collection_row(scope=None, *, phase="baseline", read_deadline="2026-10-09T00:00:30Z"):
    scope = scope or S3AccessScope.from_mapping(request_row()["scope"])
    reads = []
    for index, reader in enumerate(("probe", "legitimate"), start=1):
        raw = request_row(reader + "_read")
        raw.update(
            scope=scope.to_dict(),
            scope_digest=scope.digest,
            deadline=read_deadline,
            request_id=str(index) * 64,
            launch_id=str(index + 2) * 64,
        )
        request = S3WorkerRequest.from_mapping(raw)
        result = read_result(request, "AccessDenied" if phase == "retest" and index == 1 else None)
        for number, call in enumerate(result["calls"]):
            call["request_id"] = f"{reader}-request-{number}"
        reads.append(
            {
                "reader": reader,
                "run_id": "run-20261009T000010Z-" + str(index) * 16,
                "manifest_digest": "sha256:" + str(index + 2) * 64,
                "request_digest": request.digest,
                "worker_result_digest": content_hash(result),
                "reservation_digest": "sha256:" + str(index + 4) * 64,
                "cleanup": "verified",
                "request": request.to_dict(),
                "result": result,
            }
        )
    return {
        "schema_version": audit.COLLECTION_SCHEMA,
        "launch_id": "9" * 64,
        "request_id": "a" * 64,
        "source": source_row(scope),
        "workflow_job_id": "job-" + "1" * 32,
        "operation_job_id": "job-" + "3" * 32,
        "issued_at": "2026-10-09T00:01:00Z",
        "deadline": "2026-10-09T00:01:30Z",
        "original_pair": {
            "schema_version": audit.PAIR_SCHEMA,
            "workflow_job_id": "job-" + "1" * 32,
            "operation_job_id": "job-" + "2" * 32,
            "phase": phase,
            "outcome_digest": "sha256:" + "7" * 64,
            "review_digest": "sha256:" + "8" * 64,
            "reads": reads,
        },
    }


def workflow_row(scope):
    bound = scope.to_dict()
    source = source_row(scope)
    return {
        "schema_version": audit.WORKFLOW_SCHEMA,
        "workflow_job_id": "job-" + "1" * 32,
        "environment_id": "synthetic-audited-environment",
        "resource_key": content_hash(
            {name: bound[name] for name in ("account_id", "region", "bucket")}
        ),
        "scope_digest": scope.digest,
        "source": source,
        "budget": audit.budget(scope, source),
    }


def fixture():
    scope = S3AccessScope.from_mapping(request_row()["scope"])
    return scope, collection_row(scope)


def listing_rows(scope, row, *, count=1, size=100, truncated=False):
    listings = []
    for index, parameters in enumerate(audit.list_parameters(scope, row)):
        objects = [
            {
                "key": parameters["StartAfter"] + f"{number:016d}.json.gz",
                "etag": '"synthetic-etag"',
                "size_bytes": size,
            }
            for number in range(count)
        ]
        listings.append(
            {
                "prefix": parameters["Prefix"],
                "start_after": parameters["StartAfter"],
                "request_id": f"list-request-{index}",
                "body_sha256": "sha256:" + str(index + 1) * 64,
                "http_status": 200,
                "retry_attempts": 0,
                "key_count": len(objects),
                "is_truncated": truncated,
                "objects": objects,
            }
        )
    return listings


def discovered(scope, row, listings=None):
    return audit.discovery(
        scope,
        row,
        request_digest="sha256:" + "e" * 64,
        reservation_digest="sha256:" + "b" * 64,
        listings=listing_rows(scope, row) if listings is None else listings,
    )


def test_source_is_explicit_detached_and_allows_a_distinct_bucket_region():
    scope, row = fixture()
    before = deepcopy(row["source"])
    checked = audit.source(scope, before)
    checked["audit_limits"]["events"] = 1
    assert before == row["source"]
    assert audit.source(scope, before)["audit_bucket_region"] == "us-west-2"
    assert scope.to_dict()["region"] == "us-east-1"


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "bluefire.s3-host-environments.v3"),
        ("experiment_scope_digest", "sha256:" + "f" * 64),
        ("audit_source_id", "../source"),
        ("source_account_id", "999999999999"),
        ("event_region", "us-west-2"),
        ("audit_bucket_owner_account_id", "999999999999"),
        ("audit_bucket_region", "us-gov-west-1"),
        ("audit_bucket", "bucket--x-s3"),
        ("trail_arn", "arn:aws:cloudtrail:us-east-1:999999999999:trail/synthetic"),
        ("collector_role_arn", "arn:aws:iam::123456789012:role/bluefire-controller"),
        ("exact_delivery_root_prefix", "AWSLogs/123456789012/CloudTrail/us-west-2/"),
        ("exact_delivery_root_prefix", "../AWSLogs/123456789012/CloudTrail/us-east-1/"),
        ("exact_delivery_root_prefix", "x//AWSLogs/123456789012/CloudTrail/us-east-1/"),
        ("exact_delivery_root_prefix", "x%2f/AWSLogs/123456789012/CloudTrail/us-east-1/"),
        ("managed_profile_digest", "unsealed"),
        ("expires_at", "2026-10-09T02:00:00Z"),
    ],
)
def test_source_rejects_unbound_or_unsupported_values(field, value):
    scope, row = fixture()
    row["source"][field] = value
    with pytest.raises(S3AccessError):
        audit.source(scope, row["source"])


def test_source_refuses_unknown_fields_and_duplicate_json_keys():
    scope, row = fixture()
    value = row["source"]
    with pytest.raises(S3AccessError):
        audit.source(scope, {**value, "credential": "not-accepted"})
    raw = canonical_json_bytes(value)
    with pytest.raises(S3AccessError):
        audit.source(scope, b'{"schema_version":"duplicate",' + raw[1:])


@pytest.mark.parametrize(
    "field,value",
    [
        ("api_calls", 8),
        ("sessions", 2),
        ("files", True),
        ("files", 5),
        ("sdk_body_bytes", 393217),
        ("compressed_bytes", 262145),
        ("expanded_bytes", 1048577),
        ("events", 501),
        ("seconds", 31),
    ],
)
def test_source_limits_are_closed_finite_and_non_boolean(field, value):
    scope, row = fixture()
    row["source"]["audit_limits"][field] = value
    with pytest.raises(S3AccessError):
        audit.source(scope, row["source"])


def test_budget_holds_both_batches_and_counts_compressed_as_shared_wire_subset():
    scope, row = fixture()
    per, whole = (audit.budget(scope, row["source"])[name] for name in ("per_batch", "workflow"))
    assert per == audit.LIMIT_CEILINGS
    assert whole["batches"] == whole["sessions"] == 2
    assert whole["api_calls"] == 18 and whole["files"] == 8 and whole["events"] == 1000
    assert whole["wire_plus_expansion_bytes"] == 2 * (393216 + 1048576)
    assert per["compressed_bytes"] <= per["sdk_body_bytes"] < 9 * audit.MAX_RESPONSE_BYTES
    assert scope.to_dict()["limits"]["sessions"] == 6


def test_budget_uses_original_scope_event_and_time_minima_without_raising_any_ceiling():
    scope, _ = fixture()
    raw = scope.to_dict()
    raw["limits"].update(audit_events=90, audit_seconds=40, request_seconds=25)
    raw["expires_at"] = "2026-10-09T00:30:00Z"
    scope = S3AccessScope.from_mapping(raw)
    limits = audit.budget(scope, source_row(scope))
    assert limits["per_batch"]["events"] == 45
    assert limits["per_batch"]["seconds"] == 20
    assert limits["workflow"]["events"] == 90
    assert limits["workflow"]["seconds"] == 40


@pytest.mark.parametrize(
    "field,value", [("api_calls", 17), ("sessions", 1), ("audit_events", 1), ("audit_bytes", 1000)]
)
def test_budget_refuses_an_unfunded_pair_without_refund_or_implicit_increase(field, value):
    scope, _ = fixture()
    raw = scope.to_dict()
    raw["limits"][field] = value
    scope = S3AccessScope.from_mapping(raw)
    with pytest.raises(S3AccessError):
        audit.budget(scope, source_row(scope))
    assert scope.to_dict()["limits"][field] == value


def test_workflow_is_canonical_detached_and_covers_four_reads_plus_two_audit_sessions():
    scope, _ = fixture()
    row = workflow_row(scope)
    row["source"]["expires_at"] = "2026-10-09T01:00:00.000000Z"
    before = deepcopy(row)
    checked = audit.workflow(scope, row)
    assert checked["source"] == audit.source(scope, row["source"])
    assert checked["budget"] == audit.budget(scope, checked["source"])
    assert checked["budget"]["workflow"]["batches"] == 2
    assert 4 + checked["budget"]["workflow"]["sessions"] == 6
    assert scope.to_dict()["limits"]["sessions"] == 6
    assert scope.to_dict()["limits"]["business_attempts"] == 2 * (1 + 2)
    checked["source"]["audit_limits"]["events"] = 1
    checked["budget"]["per_batch"]["events"] = 1
    checked["budget"]["workflow"]["events"] = 2
    assert row == before
    assert audit.workflow(scope, row)["budget"]["workflow"]["events"] == 1000


@pytest.mark.parametrize("change", ["missing", "extra", "duplicate_json"])
def test_workflow_has_closed_fields_and_rejects_duplicate_json(change):
    scope, _ = fixture()
    row = workflow_row(scope)
    if change == "missing":
        row.pop("budget")
    elif change == "extra":
        row["authority"] = "not-accepted"
    else:
        row = b'{"schema_version":"duplicate",' + canonical_json_bytes(row)[1:]
    with pytest.raises(S3AccessError):
        audit.workflow(scope, row)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", audit.SOURCE_SCHEMA),
        ("workflow_job_id", "operation-" + "1" * 32),
        ("workflow_job_id", "job-" + "A" * 32),
        ("environment_id", "../environment"),
        ("scope_digest", "sha256:" + "0" * 64),
        ("resource_key", "sha256:" + "0" * 64),
    ],
)
def test_workflow_rejects_changed_schema_identity_scope_or_resource(field, value):
    scope, _ = fixture()
    row = workflow_row(scope)
    row[field] = value
    with pytest.raises(S3AccessError):
        audit.workflow(scope, row)


def test_workflow_resource_key_is_the_experiment_not_the_audit_bucket():
    scope, _ = fixture()
    row = workflow_row(scope)
    bound = scope.to_dict()
    row["resource_key"] = content_hash(
        {
            "account_id": bound["account_id"],
            "region": row["source"]["audit_bucket_region"],
            "bucket": row["source"]["audit_bucket"],
        }
    )
    assert row["resource_key"] != workflow_row(scope)["resource_key"]
    with pytest.raises(S3AccessError, match="original experiment resource or scope"):
        audit.workflow(scope, row)


@pytest.mark.parametrize("change", ["source_scope", "source_account", "stale_budget"])
def test_workflow_revalidates_nested_source_and_its_derived_budget(change):
    scope, _ = fixture()
    row = workflow_row(scope)
    if change == "source_scope":
        row["source"]["experiment_scope_digest"] = "sha256:" + "0" * 64
    elif change == "source_account":
        row["source"]["source_account_id"] = "999999999999"
    else:
        row["source"]["audit_limits"]["events"] = 250
        assert audit.source(scope, row["source"]) == row["source"]
    with pytest.raises(S3AccessError):
        audit.workflow(scope, row)


@pytest.mark.parametrize(
    "part,field,value",
    [
        ("per_batch", "sessions", True),
        ("per_batch", "sessions", 1.0),
        ("workflow", "batches", 2.0),
        ("workflow", "api_calls", 19),
    ],
)
def test_workflow_requires_exact_canonical_derived_budget(part, field, value):
    scope, _ = fixture()
    row = workflow_row(scope)
    row["budget"][part][field] = value
    with pytest.raises(S3AccessError, match="derived reservations"):
        audit.workflow(scope, row)


@pytest.mark.parametrize("field", ["sessions", "business_attempts"])
def test_workflow_refuses_five_sessions_or_business_attempts_without_raising_limits(field):
    scope, _ = fixture()
    raw = scope.to_dict()
    raw["limits"][field] = 5
    scope = S3AccessScope.from_mapping(raw)
    row = workflow_row(scope)
    assert row["budget"]["workflow"]["sessions"] == 2
    with pytest.raises(S3AccessError, match="four business reads and both audit batches"):
        audit.workflow(scope, row)
    assert scope.to_dict()["limits"][field] == 5


def test_workflow_uses_both_phase_minima_without_changing_source_ceilings():
    scope, _ = fixture()
    raw = scope.to_dict()
    raw["limits"].update(audit_events=90, audit_seconds=40, request_seconds=25)
    raw["expires_at"] = "2026-10-09T00:30:00Z"
    scope = S3AccessScope.from_mapping(raw)
    row = workflow_row(scope)
    checked = audit.workflow(scope, canonical_json_bytes(row))
    assert checked["budget"]["per_batch"]["events"] == 45
    assert checked["budget"]["workflow"]["events"] == 90
    assert checked["budget"]["workflow"]["seconds"] == 40
    assert checked["source"]["audit_limits"] == audit.LIMIT_CEILINGS
    assert checked["budget"]["workflow"]["sessions"] == 2


def test_workflow_builder_matches_checked_commitment_without_sharing_nested_source():
    scope, _ = fixture()
    expected = workflow_row(scope)
    raw_source = expected["source"]
    before = deepcopy(raw_source)
    built = audit.build_workflow(
        scope,
        raw_source,
        workflow_job_id=expected["workflow_job_id"],
        environment_id=expected["environment_id"],
    )
    assert canonical_json_bytes(built) == canonical_json_bytes(audit.workflow(scope, expected))
    built["source"]["audit_limits"]["events"] = 1
    built["budget"]["workflow"]["events"] = 2
    assert raw_source == before


@pytest.mark.parametrize(
    "field,value", [("workflow_job_id", "job-invalid"), ("environment_id", "../invalid")]
)
def test_workflow_builder_does_not_bypass_identity_validation(field, value):
    scope, _ = fixture()
    arguments = {"workflow_job_id": "job-" + "1" * 32, "environment_id": "synthetic-environment"}
    arguments[field] = value
    with pytest.raises(S3AccessError):
        audit.build_workflow(scope, source_row(scope), **arguments)


@pytest.mark.parametrize("phase", ["baseline", "retest"])
def test_collection_binds_both_original_reads_and_accepts_real_denial_shape(phase):
    scope, _ = fixture()
    row = collection_row(scope, phase=phase)
    assert audit.collection(scope, row) == row
    if phase == "retest":
        assert (
            row["original_pair"]["reads"][0]["result"]["calls"][3]["error_code"] == "AccessDenied"
        )
    assert row["original_pair"]["reads"][1]["request"]["operation"] == "legitimate_read"


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "reverse",
        "run",
        "request_digest",
        "result_digest",
        "reservation",
        "cleanup",
        "request_id",
        "runtime",
        "raw_result",
    ],
)
def test_pair_rejects_missing_replaced_or_inconsistent_original_evidence(change):
    scope, row = fixture()
    reads = row["original_pair"]["reads"]
    if change == "missing":
        reads.pop()
    elif change == "reverse":
        reads.reverse()
    elif change == "run":
        reads[1]["run_id"] = reads[0]["run_id"]
    elif change == "request_digest":
        reads[0]["request_digest"] = "sha256:" + "0" * 64
    elif change == "result_digest":
        reads[0]["worker_result_digest"] = "sha256:" + "0" * 64
    elif change == "reservation":
        reads[1]["reservation_digest"] = reads[0]["reservation_digest"]
    elif change == "cleanup":
        reads[0]["cleanup"] = "unknown"
    elif change == "request_id":
        reads[1]["request"]["request_id"] = reads[0]["request"]["request_id"]
    elif change == "runtime":
        reads[0]["request"]["runtime_digest"] = "sha256:" + "0" * 64
    else:
        reads[0]["result"]["calls"][3]["request_id"] = "substituted"
    with pytest.raises(S3AccessError):
        audit.collection(scope, row)


@pytest.mark.parametrize("change", ["duplicate_get_object_id", "read_after_failed_sts"])
def test_pair_rejects_impossible_read_history_even_with_recomputed_result_digest(change):
    scope, row = fixture()
    entry = row["original_pair"]["reads"][1]
    calls = entry["result"]["calls"]
    if change == "duplicate_get_object_id":
        calls[4]["request_id"] = calls[3]["request_id"]
    else:
        calls[0].update(http_status=403, error_code="AccessDenied")
        entry["result"].update(outcome="failed", data=None, problem="scoped_operation_failed")
    entry["worker_result_digest"] = content_hash(entry["result"])
    assert (
        validate_result(S3WorkerRequest.from_mapping(entry["request"]), entry["result"])
        == entry["result"]
    )
    with pytest.raises(S3AccessError, match="unique request mapping"):
        audit.collection(scope, row)


def test_pair_preserves_unreported_read_when_initial_sts_failed_without_any_object_call():
    scope, row = fixture()
    entry = row["original_pair"]["reads"][0]
    result = entry["result"]
    result["calls"] = result["calls"][:1]
    result["calls"][0].update(http_status=403, error_code="AccessDenied")
    result.update(
        outcome="failed", data=None, problem="scoped_operation_failed", send_permits_consumed=1
    )
    entry["worker_result_digest"] = content_hash(result)
    checked = audit.collection(scope, row)
    assert checked["original_pair"]["reads"][0]["result"] == result
    assert all(call["operation"] != "GetObject" for call in result["calls"])


@pytest.mark.parametrize(
    "field,value",
    [
        ("workflow_job_id", "job-" + "4" * 32),
        ("operation_job_id", "job-" + "2" * 32),
        ("launch_id", "3" * 64),
        ("request_id", "1" * 64),
        ("issued_at", "2026-10-08T23:59:00Z"),
        ("deadline", "2026-10-09T00:01:31Z"),
    ],
)
def test_collection_keeps_original_distinct_identity_and_deadline(field, value):
    scope, row = fixture()
    row[field] = value
    with pytest.raises(S3AccessError):
        audit.collection(scope, row)


def test_collection_cannot_mint_a_later_audit_window_or_accept_caller_cursor():
    scope, row = fixture()
    row.update(issued_at="2026-10-09T00:31:00Z", deadline="2026-10-09T00:31:30Z")
    with pytest.raises(S3AccessError):
        audit.collection(scope, row)
    _, row = fixture()
    row["StartAfter"] = "caller-cursor"
    with pytest.raises(S3AccessError):
        audit.collection(scope, row)


@pytest.mark.parametrize("phase", ["cleanup", 1, ["baseline"]])
def test_phase_discriminant_is_closed_even_for_non_string_json(phase):
    scope, row = fixture()
    row["original_pair"]["phase"] = phase
    with pytest.raises(S3AccessError):
        audit.collection(scope, row)


def test_new_collection_requests_cannot_recursively_replace_original_business_reads():
    scope, row = fixture()
    row["original_pair"]["reads"][0]["request"]["schema_version"] = "bluefire.s3-worker-request.v3"
    with pytest.raises(S3AccessError, match="original business read"):
        audit.collection(scope, row)


def test_cursor_uses_original_start_minute_not_event_end_or_collection_time():
    scope, row = fixture()
    params = audit.list_parameters(scope, row)
    assert len(params) == 1
    assert params[0]["StartAfter"].endswith("_20261009T0000Z_")
    assert params[0]["MaxKeys"] == 16
    assert set(params[0]) == {"Bucket", "ExpectedBucketOwner", "Prefix", "StartAfter", "MaxKeys"}
    assert params[0]["StartAfter"] + "0000000000000000.json.gz" > params[0]["StartAfter"]


def test_midnight_cursor_derives_two_exact_dated_prefixes_without_a_fake_second_list():
    scope, _ = fixture()
    raw = scope.to_dict()
    raw.update(created_at="2026-10-08T23:59:00Z", expires_at="2026-10-09T00:59:00Z")
    scope = S3AccessScope.from_mapping(raw)
    row = collection_row(scope, read_deadline="2026-10-09T00:00:20Z")
    params = audit.list_parameters(scope, row)
    assert [entry["Prefix"].split("/")[-4:] for entry in params] == [
        ["2026", "10", "08", ""],
        ["2026", "10", "09", ""],
    ]
    assert [entry["StartAfter"].rsplit("_", 2)[1] for entry in params] == [
        "20261008T2359Z",
        "20261009T0000Z",
    ]
    assert len(audit.operation_plan(scope, row, selected_count=4)) == 9
    assert len(audit.operation_plan(*fixture(), selected_count=4)) == 8
    assert audit.budget(scope, row["source"])["per_batch"]["api_calls"] == 9


def test_discovery_binds_exact_compact_frame_and_original_experiment_resource_key():
    scope, row = fixture()
    value = discovered(scope, row)
    frame, durable = value["frame"], value["durable"]
    assert frame["kind"] == "discovery" and frame["request_digest"] == "sha256:" + "e" * 64
    assert frame["collection_digest"] == content_hash(row)
    assert frame["pair_digest"] == durable["pair_digest"] == content_hash(row["original_pair"])
    assert frame["completed_list_count"] == durable["completed_list_count"] == 1
    assert frame["next_send_sequence"] == durable["next_send_sequence"] == 5
    assert durable["frame_digest"] == content_hash(frame)
    assert durable["resource_key"] == content_hash(
        {key: scope.to_dict()[key] for key in ("account_id", "region", "bucket")}
    )
    assert durable["resource_key"] != content_hash({"bucket": row["source"]["audit_bucket"]})
    assert "candidates" not in durable
    assert len(frame["candidates"]) == len(durable["selected"]) == 1
    assert durable["selected"][0]["key"] == frame["prefixes"][0][0] + frame["candidates"][0][1]
    assert len(canonical_json_bytes(frame)) + 1 <= 16384
    assert len(canonical_json_bytes(durable)) <= 8192


def test_first_listed_files_are_selected_not_reversed_into_latest_and_truncation_is_visible():
    scope, row = fixture()
    listings = listing_rows(scope, row, count=16, truncated=True)
    value = discovered(scope, row, listings)
    assert value["frame"]["selected"] == [0, 1, 2, 3]
    assert [entry["key"] for entry in value["durable"]["selected"]] == [
        entry["key"] for entry in listings[0]["objects"][:4]
    ]
    assert value["frame"]["truncated"] is value["durable"]["truncated"] is True
    assert value["durable"]["candidate_count"] == 16


def test_two_prefixes_keep_32_candidates_ephemeral_and_only_four_full_keys_durable():
    scope, _ = fixture()
    raw = scope.to_dict()
    raw.update(created_at="2026-10-08T23:59:00Z", expires_at="2026-10-09T00:59:00Z")
    scope = S3AccessScope.from_mapping(raw)
    row = collection_row(scope, read_deadline="2026-10-09T00:00:20Z")
    value = discovered(scope, row, listing_rows(scope, row, count=16))
    assert len(value["frame"]["candidates"]) == value["durable"]["candidate_count"] == 32
    assert len(value["durable"]["selected"]) == 4
    assert value["frame"]["completed_list_count"] == value["durable"]["completed_list_count"] == 2
    assert value["frame"]["next_send_sequence"] == value["durable"]["next_send_sequence"] == 6
    assert "candidates" not in value["durable"] and value["durable"]["truncated"] is True
    assert len(canonical_json_bytes(value["frame"])) + 1 <= audit.MAX_FRAME_BYTES
    assert len(canonical_json_bytes(value["durable"])) <= audit.MAX_DURABLE_BYTES


@pytest.mark.parametrize("field", ["request_digest", "reservation_digest"])
def test_discovery_requires_explicit_well_formed_original_outer_channel_identities(field):
    scope, row = fixture()
    kwargs = {
        "request_digest": "sha256:" + "e" * 64,
        "reservation_digest": "sha256:" + "b" * 64,
        "listings": listing_rows(scope, row),
    }
    kwargs[field] = "unbound"
    with pytest.raises(S3AccessError):
        audit.discovery(scope, row, **kwargs)


def test_zero_or_oversized_objects_do_not_gain_get_authority():
    scope, row = fixture()
    for size in (0, 65537):
        value = discovered(scope, row, listing_rows(scope, row, size=size))
        assert value["frame"]["selected"] == value["durable"]["selected"] == []
        assert value["durable"]["truncated"] is True


@pytest.mark.parametrize(
    "change",
    [
        "prefix",
        "cursor",
        "owner_key",
        "same_minute_before_cursor",
        "invalid_date",
        "duplicate",
        "reverse",
        "count",
        "etag",
        "negative_size",
        "boolean_size",
        "status",
        "retry",
        "boolean_truncated",
    ],
)
def test_discovery_refuses_changed_listing_boundaries_and_invalid_sdk_projection(change):
    scope, row = fixture()
    if change == "same_minute_before_cursor":
        row = collection_row(scope, read_deadline="2026-10-09T00:05:30Z")
        row.update(issued_at="2026-10-09T00:06:00Z", deadline="2026-10-09T00:06:30Z")
    listings = listing_rows(scope, row, count=2)
    listing = listings[0]
    obj = listing["objects"][0]
    if change == "prefix":
        listing["prefix"] = "AWSLogs/"
    elif change == "cursor":
        listing["start_after"] += "substituted"
    elif change == "owner_key":
        obj["key"] = obj["key"].replace("123456789012", "999999999999")
    elif change == "same_minute_before_cursor":
        obj["key"] = obj["key"].replace("T0005Z_", "T0004Z_")
        assert obj["key"].startswith(listing["prefix"])
        assert "_20261009T0004Z_" in obj["key"]
        assert obj["key"] < listing["start_after"]
    elif change == "invalid_date":
        obj["key"] = obj["key"].replace("20261009", "20260230")
    elif change == "duplicate":
        listing["objects"][1] = deepcopy(obj)
    elif change == "reverse":
        listing["objects"].reverse()
    elif change == "count":
        listing["key_count"] = True
    elif change == "etag":
        obj["etag"] = '"invalid\\etag"'
    elif change == "negative_size":
        obj["size_bytes"] = -1
    elif change == "boolean_size":
        obj["size_bytes"] = True
    elif change == "status":
        listing["http_status"] = True
    elif change == "retry":
        listing["retry_attempts"] = 1
    else:
        listing["is_truncated"] = 1
    message = "lexical successors" if change == "same_minute_before_cursor" else None
    with pytest.raises(S3AccessError, match=message):
        discovered(scope, row, listings)


def test_prefix_and_full_frame_caps_are_measured_without_transport_widening(monkeypatch):
    scope, row = fixture()
    suffix = row["source"]["exact_delivery_root_prefix"]
    row["source"]["exact_delivery_root_prefix"] = "p" * (255 - len(suffix)) + "/" + suffix
    assert len(row["source"]["exact_delivery_root_prefix"]) == 256
    assert audit.collection(scope, row)
    row["source"]["exact_delivery_root_prefix"] = "p" + row["source"]["exact_delivery_root_prefix"]
    with pytest.raises(S3AccessError):
        audit.collection(scope, row)
    scope, row = fixture()
    frame = discovered(scope, row)["frame"]
    monkeypatch.setattr(audit, "MAX_FRAME_BYTES", len(canonical_json_bytes(frame)))
    with pytest.raises(S3AccessError, match="complete audit discovery frame"):
        discovered(scope, row)


def test_result_limit_counts_the_complete_wrapper_and_newline(monkeypatch):
    size = audit.MAX_PROJECTION_BYTES - len(canonical_json_bytes({"data": ""}))
    value = {"data": "x" * size}
    assert len(canonical_json_bytes(value)) == audit.MAX_PROJECTION_BYTES
    payload = audit.result_frame(value)
    assert payload == canonical_json_bytes({"kind": "result", "result": value}) + b"\n"
    assert len(payload) <= 16384
    with pytest.raises(S3AccessError):
        audit.result_frame({"data": "x" * (size + 1)})
    monkeypatch.setattr(audit, "MAX_FRAME_BYTES", len(payload) - 1)
    with pytest.raises(S3AccessError, match="complete audit result frame"):
        audit.result_frame(value)


def test_collection_and_discovery_do_not_mutate_supplied_evidence():
    scope, row = fixture()
    listings = listing_rows(scope, row)
    before = deepcopy((row, listings))
    discovered(scope, row, listings)
    assert (row, listings) == before
