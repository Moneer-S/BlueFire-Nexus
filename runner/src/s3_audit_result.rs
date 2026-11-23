//! Pure collector-result accounting and original-read correlations.

use chrono::{Duration, SecondsFormat};
use serde_json::{json, Value};

use crate::canonical::{canonical_hash, canonical_json};
use crate::s3_access_policy::encoded;
use crate::s3_access_scope::{digest, require, utc_time, Checked};
use crate::s3_audit_binding::checked_source;

use super::{
    fields, request_id, text, Discovery, OriginalRead, S3WorkerBinding, MAX_LINE, RESULT_SCHEMA,
};

fn event_id(value: &str) -> bool {
    value.len() == 36
        && value.is_ascii()
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

pub(super) fn worker_outcome(call: Option<&Value>) -> &'static str {
    let Some(call) = call else {
        return "unreported";
    };
    match call.get("error_code").and_then(Value::as_str) {
        None => "service_success",
        Some("AccessDenied") => "service_denied",
        Some("NoSuchKey") => "object_missing",
        Some("NoSuchBucket") => "bucket_missing",
        Some(
            "ExpiredToken"
            | "InvalidToken"
            | "InvalidAccessKeyId"
            | "SignatureDoesNotMatch"
            | "RequestExpired"
            | "AuthorizationHeaderMalformed",
        ) => "credential_error",
        Some(_) => "other_service_error",
    }
}

fn correlation(read: &OriginalRead, value: &Value, delivery: &str, events: u64) -> Checked<()> {
    fields(value, "schema_version request_digest worker_result_digest reads authorized_request_window independent_collection_proven effective_access_claim")?;
    let end = utc_time(text(&read.request["deadline"])?)?;
    let start = utc_time(text(&read.request["scope"]["created_at"])?)?.max(
        end - Duration::seconds(
            read.request["scope"]["limits"]["request_seconds"]
                .as_i64()
                .ok_or("invalid original duration")?,
        ),
    );
    let iso = |value: chrono::DateTime<chrono::FixedOffset>| {
        value.to_rfc3339_opts(
            if value.timestamp_subsec_micros() == 0 {
                SecondsFormat::Secs
            } else {
                SecondsFormat::Micros
            },
            false,
        )
    };
    require(
        value["schema_version"] == "bluefire.s3-audit-correlation.v1"
            && value["request_digest"] == read.request_digest
            && value["worker_result_digest"] == read.worker_result_digest
            && value["independent_collection_proven"] == false
            && value["effective_access_claim"] == false
            && value["authorized_request_window"] == json!({"from":iso(start),"through":iso(end)}),
    )?;
    let rows = value["reads"]
        .as_array()
        .ok_or("invalid audit correlation reads")?;
    let objects = read.request["scope"]["objects"]
        .as_array()
        .ok_or("invalid original objects")?;
    let calls = read.result["calls"]
        .as_array()
        .ok_or("invalid original calls")?;
    require(rows.len() == if read.reader == "probe" { 1 } else { 2 })?;
    for (index, row) in rows.iter().enumerate() {
        fields(row, "purpose reader status worker_outcome worker_request_id audit_event_ids audit_outcomes full_object_bytes_proven")?;
        let call = calls.get(index + 3);
        let outcome = worker_outcome(call);
        require(
            row["purpose"] == objects[index]["purpose"]
                && row["reader"] == read.reader
                && row["worker_outcome"] == outcome
                && row["full_object_bytes_proven"] == false
                && row["worker_request_id"]
                    == call
                        .map(|value| value["request_id"].clone())
                        .unwrap_or(Value::Null),
        )?;
        let ids = row["audit_event_ids"]
            .as_array()
            .ok_or("invalid audit event IDs")?;
        require(ids.len() as u64 <= events)?;
        let mut unique = std::collections::BTreeSet::new();
        for id in ids {
            require(event_id(text(id)?) && unique.insert(text(id)?))?;
        }
        let outcomes = row["audit_outcomes"]
            .as_array()
            .ok_or("invalid audit outcomes")?;
        let mut previous = "";
        for value in outcomes {
            let value = text(value)?;
            require(
                previous < value
                    && [
                        "service_success",
                        "service_denied",
                        "object_missing",
                        "bucket_missing",
                        "credential_error",
                        "other_service_error",
                    ]
                    .contains(&value),
            )?;
            previous = value;
        }
        let status = text(&row["status"])?;
        if ids.is_empty() {
            require(
                outcomes.is_empty()
                    && if call.is_none() {
                        status == "worker_unreported"
                    } else if delivery == "truncated" {
                        status == "truncated"
                    } else if delivery == "unknown" {
                        status == "unknown"
                    } else {
                        ["awaiting_delivery", "unknown"].contains(&status)
                    },
            )?;
        } else {
            require(
                call.is_some()
                    && ["matched", "conflict"].contains(&status)
                    && !outcomes.is_empty()
                    && (status != "matched" || *outcomes == vec![json!(outcome)]),
            )?;
        }
    }
    Ok(())
}

pub(crate) fn validate_result(
    binding: &S3WorkerBinding,
    row: &Value,
    debits: u64,
    committed: Option<&Discovery>,
) -> Checked<bool> {
    fields(row, "schema_version request_digest outcome data problem send_permits_consumed calls runtime_isolation_proven")?;
    require(
        canonical_json(&json!({"kind":"result","result":row})).len() < MAX_LINE
            && canonical_json(row).len() <= 15 * 1024
            && row["schema_version"] == RESULT_SCHEMA
            && row["request_digest"] == binding.digest()
            && row["runtime_isolation_proven"] == false
            && ["observed", "failed"].contains(&text(&row["outcome"])?),
    )?;
    let consumed = row["send_permits_consumed"]
        .as_u64()
        .ok_or("invalid audit send count")?;
    let calls = row["calls"].as_array().ok_or("invalid audit calls")?;
    require(consumed <= debits && debits <= 9 && calls.len() as u64 <= consumed)?;
    let collection = binding.audit().ok_or("audit collection absent")?;
    let observed = row["outcome"] == "observed";
    let mut count = if let Some(discovery) = committed {
        discovery.document["selected"]
            .as_array()
            .ok_or("invalid audit selection")?
            .len()
    } else {
        collection.source["audit_limits"]["files"]
            .as_u64()
            .ok_or("invalid audit files")? as usize
    };
    if observed {
        let committed = committed.ok_or("audit result lacks original committed Discovery")?;
        let data = &row["data"];
        fields(data, "schema_version collection_digest pair_digest audit_source_digest reservation_digest discovery objects usage normalized_digest correlations delivery_state effective_access_claim log_integrity_proven")?;
        require(
            data["schema_version"] == "bluefire.s3-audit-collection-observation.v1"
                && data["collection_digest"] == canonical_hash(&encoded(collection)?)
                && data["pair_digest"] == canonical_hash(&encoded(&collection.original_pair)?)
                && data["audit_source_digest"] == collection.source_digest()
                && data["reservation_digest"] == committed.document["reservation_digest"]
                && data["discovery"] == committed.document
                && digest(text(&data["normalized_digest"])?)
                && data["effective_access_claim"] == false
                && data["log_integrity_proven"] == false,
        )?;
        let delivery = text(&data["delivery_state"])?;
        require(
            ["incomplete", "truncated", "unknown"].contains(&delivery)
                && (committed.document["truncated"] != true || delivery == "truncated"),
        )?;
        let selected = committed.document["selected"]
            .as_array()
            .ok_or("invalid audit selection")?;
        let objects = data["objects"].as_array().ok_or("invalid audit objects")?;
        require(objects.len() == selected.len())?;
        count = objects.len();
        let mut compressed = 0u64;
        let mut expanded = 0u64;
        let mut events = 0u64;
        let (limits, _) = checked_source(
            &collection.source,
            binding.scope(),
            binding.runtime_digest(),
            binding.worker_generation(),
        )?;
        for (index, object) in objects.iter().enumerate() {
            fields(
                object,
                "selected_index compressed_sha256 expanded_sha256 expanded_bytes event_count",
            )?;
            require(
                object["selected_index"].as_u64() == Some(index as u64)
                    && digest(text(&object["compressed_sha256"])?)
                    && digest(text(&object["expanded_sha256"])?),
            )?;
            compressed = compressed
                .checked_add(
                    selected[index]["size_bytes"]
                        .as_u64()
                        .ok_or("invalid compressed size")?,
                )
                .ok_or("audit size overflow")?;
            let size = object["expanded_bytes"]
                .as_u64()
                .ok_or("invalid expanded size")?;
            require(size > 0)?;
            expanded = expanded.checked_add(size).ok_or("audit size overflow")?;
            events = events
                .checked_add(
                    object["event_count"]
                        .as_u64()
                        .ok_or("invalid event count")?,
                )
                .ok_or("audit event overflow")?;
        }
        let usage = &data["usage"];
        fields(
            usage,
            "sdk_body_bytes compressed_bytes expanded_bytes events files",
        )?;
        let wire = usage["sdk_body_bytes"]
            .as_u64()
            .ok_or("invalid SDK bytes")?;
        require(
            wire >= compressed
                && wire <= limits.sdk_body_bytes
                && compressed <= limits.compressed_bytes
                && expanded <= limits.expanded_bytes
                && events <= limits.events
                && count as u64 <= limits.files
                && usage["files"].as_u64() == Some(count as u64)
                && usage["compressed_bytes"].as_u64() == Some(compressed)
                && usage["expanded_bytes"].as_u64() == Some(expanded)
                && usage["events"].as_u64() == Some(events),
        )?;
        fields(&data["correlations"], "probe legitimate")?;
        for read in &collection.original_pair.reads {
            correlation(read, &data["correlations"][&read.reader], delivery, events)?;
        }
    } else {
        require(row["data"].is_null() && row["problem"] == "scoped_operation_failed")?;
    }
    let plan = collection.operation_plan(binding.scope(), count)?;
    require(consumed <= plan.len() as u64)?;
    let mut ids = std::collections::BTreeSet::new();
    for (index, call) in calls.iter().enumerate() {
        fields(
            call,
            if call.get("error_code").is_some() {
                "operation role request_id http_status error_code"
            } else {
                "operation role request_id http_status"
            },
        )?;
        let identifier = text(&call["request_id"])?;
        require(
            call["operation"] == plan[index].operation
                && call["role"] == plan[index].role
                && request_id(identifier)
                && ids.insert(identifier),
        )?;
        let status = call["http_status"]
            .as_u64()
            .ok_or("invalid audit HTTP status")?;
        if let Some(code) = call.get("error_code") {
            require(
                crate::s3_worker_result_contract::valid_error(text(code)?)
                    && (400..=599).contains(&status)
                    && index + 1 == calls.len()
                    && calls.len() as u64 == consumed,
            )?;
        } else {
            require(status == 200)?;
        }
    }
    if observed {
        require(
            row["problem"].is_null()
                && consumed == plan.len() as u64
                && consumed == debits
                && calls.len() == plan.len()
                && calls.iter().all(|call| call.get("error_code").is_none()),
        )?;
        let listings = committed.ok_or("audit Discovery absent")?.document["listings"]
            .as_array()
            .ok_or("invalid listings")?;
        for (index, listing) in listings.iter().enumerate() {
            require(listing["request_id"] == calls[index + 3]["request_id"])?;
        }
    }
    Ok(observed)
}
