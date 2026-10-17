use super::*;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../tests/fixtures/s3_audit_wire_v3.json")).unwrap()
}

pub(crate) fn request(phase: &str) -> Value {
    let corpus: Value =
        serde_json::from_str(include_str!("../tests/fixtures/s3_access_binding_v1.json")).unwrap();
    let scope = corpus["cases"][0]["request"]["scope"].clone();
    let mut reads = Vec::new();
    for (index, reader) in ["probe", "legitimate"].into_iter().enumerate() {
        let operation = format!("{reader}_read");
        let mut raw = corpus["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["request"]["operation"] == operation)
            .unwrap()["request"]
            .clone();
        raw["request_id"] = json!((index + 1).to_string().repeat(64));
        raw["launch_id"] = json!((index + 3).to_string().repeat(64));
        let binding = S3WorkerBinding::from_json(canonical_json(&raw).as_bytes()).unwrap();
        let calls: Vec<_> = binding.operation_plan().iter().enumerate().map(|(number, call)| {
            let mut row = json!({"operation":call.operation,"role":call.role,"request_id":format!("{reader}-request-{number}"),"http_status":200});
            if phase == "retest" && reader == "probe" && number == 3 {
                row["http_status"] = json!(403);
                row["error_code"] = json!("AccessDenied");
            }
            row
        }).collect();
        let objects: Vec<_> = scope["objects"].as_array().unwrap().iter().take(if reader == "probe" {1} else {2}).map(|object| {
            if phase == "retest" && reader == "probe" { json!({"purpose":object["purpose"],"result":"service_denied"}) }
            else { json!({"purpose":object["purpose"],"result":"read","sha256":object["sha256"],"size_bytes":object["size_bytes"]}) }
        }).collect();
        let result = json!({"schema_version":"bluefire.s3-worker-result.v1","request_digest":binding.digest(),
            "outcome":"observed","data":{"reader":reader,"objects":objects,"effective_access_claim":false},
            "problem":null,"send_permits_consumed":calls.len(),"calls":calls,"runtime_isolation_proven":false});
        reads.push(json!({"reader":reader,"run_id":format!("run-20261009T000010Z-{}",(index+1).to_string().repeat(16)),
            "manifest_digest":format!("sha256:{}",(index+3).to_string().repeat(64)),
            "request_digest":binding.digest(),"worker_result_digest":canonical_hash(&result),
            "reservation_digest":format!("sha256:{}",(index+5).to_string().repeat(64)),
            "cleanup":"verified","request":raw,"result":result}));
    }
    let source = json!({"schema_version":"bluefire.s3-audit-source.v1","audit_source_id":"synthetic-trail-delivery",
        "experiment_scope_digest":canonical_hash(&scope),"trail_arn":"arn:aws:cloudtrail:us-east-1:123456789012:trail/synthetic",
        "source_account_id":"123456789012","event_region":"us-east-1","audit_bucket":"bluefire-audit-fixture",
        "audit_bucket_owner_account_id":"123456789012","audit_bucket_region":"us-west-2",
        "exact_delivery_root_prefix":"AWSLogs/123456789012/CloudTrail/us-east-1/",
        "collector_role_arn":"arn:aws:iam::123456789012:role/bluefire-audit-reader",
        "managed_profile_digest":format!("sha256:{}","6".repeat(64)),
        "protected_runtime_digest":format!("sha256:{}","d".repeat(64)),"worker_generation":format!("sha256:{}","c".repeat(64)),
        "expires_at":scope["expires_at"],"audit_limits":{"api_calls":9,"sessions":1,"files":4,
            "sdk_body_bytes":393216,"compressed_bytes":262144,"expanded_bytes":1048576,"events":500,"seconds":30}});
    let collection = json!({"schema_version":"bluefire.s3-audit-collection.v1","launch_id":"9".repeat(64),"request_id":"a".repeat(64),
        "source":source,"workflow_job_id":format!("job-{}","1".repeat(32)),"operation_job_id":format!("job-{}","3".repeat(32)),
        "issued_at":"2026-10-09T00:01:00Z","deadline":"2026-10-09T00:01:30Z",
        "original_pair":{"schema_version":"bluefire.s3-audit-read-pair.v1","workflow_job_id":format!("job-{}","1".repeat(32)),
            "operation_job_id":format!("job-{}","2".repeat(32)),"phase":phase,"outcome_digest":format!("sha256:{}","7".repeat(64)),
            "review_digest":format!("sha256:{}","8".repeat(64)),"reads":reads}});
    json!({"schema_version":REQUEST_SCHEMA,"launch_id":collection["launch_id"],"request_id":collection["request_id"],
        "worker_generation":collection["source"]["worker_generation"],"runtime_digest":collection["source"]["protected_runtime_digest"],
        "scope":scope,"scope_digest":canonical_hash(&scope),"operation":"collect_audit","policy_change":null,
        "deadline":collection["deadline"],"max_sends":9,"exclusive_writer_digest":null,
        "audit_authority_digest":canonical_hash(&source),"audit":collection})
}

fn binding(value: &Value) -> Checked<S3WorkerBinding> {
    S3WorkerBinding::from_json(canonical_json(value).as_bytes())
}

pub(crate) fn discovered(binding: &S3WorkerBinding, case: &Value) -> (Value, Discovery) {
    let vectors = vectors();
    let collection = binding.audit().unwrap();
    let prefix = vectors["prefix"].as_str().unwrap();
    let cursor = vectors["start_after"].as_str().unwrap();
    let count = case["candidate_count"].as_u64().unwrap() as usize;
    let size = case["size_bytes"].as_u64().unwrap();
    let objects: Vec<_> = (0..count)
        .map(|index| {
            json!({"key":format!("{cursor}{index:016}.json.gz"),
        "size_bytes":size,"etag":"\"synthetic-etag\""})
        })
        .collect();
    let listing = json!({"prefix":prefix,"start_after":cursor,"request_id":"list-request-0",
        "body_sha256":format!("sha256:{}","1".repeat(64)),"http_status":200,"retry_attempts":0,
        "key_count":count,"is_truncated":false,"objects":objects});
    let candidates: Vec<_> = objects
        .iter()
        .map(|object| {
            json!([
                0,
                object["key"]
                    .as_str()
                    .unwrap()
                    .strip_prefix(prefix)
                    .unwrap(),
                size,
                object["etag"]
            ])
        })
        .collect();
    let selected: Vec<_> = (0..case["selected_count"].as_u64().unwrap()).collect();
    let frame = json!({"kind":"discovery","request_digest":binding.digest(),"collection_digest":canonical_hash(&encoded(collection).unwrap()),
        "pair_digest":canonical_hash(&encoded(&collection.original_pair).unwrap()),"reservation_digest":vectors["reservation_digest"],
        "audit_source_digest":collection.source_digest(),"prefixes":[[prefix,cursor]],
        "listings":[{"request_id":"list-request-0","body_sha256":listing["body_sha256"],"projection_digest":canonical_hash(&listing),
            "key_count":count,"is_truncated":false}],"candidates":candidates,"selected":selected,
        "truncated":case["truncated"],"completed_list_count":1,"next_send_sequence":5});
    let bytes = format!("{}\n", canonical_json(&frame));
    let discovery = Discovery::from_frame(
        binding,
        bytes.as_bytes(),
        vectors["reservation_digest"].as_str().unwrap(),
        4,
    )
    .unwrap();
    (frame, discovery)
}

pub(crate) fn result(binding: &S3WorkerBinding, case: &Value, discovery: &Discovery) -> Value {
    let collection = binding.audit().unwrap();
    let count = case["selected_count"].as_u64().unwrap() as usize;
    let plan = collection.operation_plan(binding.scope(), count).unwrap();
    let mut calls: Vec<_> = plan
        .iter()
        .enumerate()
        .map(|(index, call)| {
            json!({"operation":call.operation,"role":call.role,
        "request_id":format!("audit-request-{index}"),"http_status":200})
        })
        .collect();
    calls[3]["request_id"] = json!("list-request-0");
    let mut correlations = serde_json::Map::new();
    for read in &collection.original_pair.reads {
        let rows: Vec<_> = read.request["scope"]["objects"].as_array().unwrap().iter().take(if read.reader == "probe" {1} else {2})
            .enumerate().map(|(index, object)| {
                let call = &read.result["calls"][index+3];
                json!({"purpose":object["purpose"],"reader":read.reader,"status":if case["truncated"] == true {"truncated"} else {"awaiting_delivery"},
                    "worker_outcome":worker_outcome(Some(call)),"worker_request_id":call["request_id"],
                    "audit_event_ids":[],"audit_outcomes":[],"full_object_bytes_proven":false})
            }).collect();
        correlations.insert(read.reader.clone(),json!({"schema_version":"bluefire.s3-audit-correlation.v1",
            "request_digest":read.request_digest,"worker_result_digest":read.worker_result_digest,"reads":rows,
            "authorized_request_window":{"from":"2026-10-09T00:00:00+00:00","through":"2026-10-09T00:00:30+00:00"},
            "independent_collection_proven":false,"effective_access_claim":false}));
    }
    let objects: Vec<_> = (0..count)
        .map(|index| {
            json!({"selected_index":index,"compressed_sha256":format!("sha256:{}","1".repeat(64)),
        "expanded_sha256":format!("sha256:{}","2".repeat(64)),"expanded_bytes":14,"event_count":0})
        })
        .collect();
    json!({"schema_version":RESULT_SCHEMA,"request_digest":binding.digest(),"outcome":"observed","problem":null,
        "send_permits_consumed":plan.len(),"calls":calls,"runtime_isolation_proven":false,
        "data":{"schema_version":"bluefire.s3-audit-collection-observation.v1","collection_digest":canonical_hash(&encoded(collection).unwrap()),
            "pair_digest":canonical_hash(&encoded(&collection.original_pair).unwrap()),"audit_source_digest":collection.source_digest(),
            "reservation_digest":discovery.document()["reservation_digest"],"discovery":discovery.document(),"objects":objects,
            "usage":{"sdk_body_bytes":1000+100*count,"compressed_bytes":100*count,"expanded_bytes":14*count,"events":0,"files":count},
            "normalized_digest":format!("sha256:{}","3".repeat(64)),"correlations":correlations,
            "delivery_state":if case["truncated"] == true {"truncated"} else {"incomplete"},
            "effective_access_claim":false,"log_integrity_proven":false}})
}

#[test]
fn shared_collector_vectors_bind_requests_discovery_resources_and_results_without_activation() {
    let vectors = vectors();
    assert_eq!(vectors["request_bytes"], super::super::MAX_DOCUMENT_BYTES);
    assert_eq!(vectors["line_bytes"], MAX_LINE);
    for case in vectors["cases"].as_array().unwrap() {
        let raw = request(case["phase"].as_str().unwrap());
        let binding = binding(&raw).unwrap();
        assert!(binding.assert_dispatch_supported().is_err());
        let (frame, discovery) = discovered(&binding, case);
        assert_eq!(
            frame["prefixes"],
            json!([[vectors["prefix"], vectors["start_after"]]])
        );
        assert_eq!(
            discovery.document()["selected"].as_array().unwrap().len(),
            case["selected_count"].as_u64().unwrap() as usize
        );
        let result = result(&binding, case, &discovery);
        let count = case["actual_sends"].as_u64().unwrap();
        assert!(validate_result(&binding, &result, count, Some(&discovery)).unwrap());
        assert!(validate_result(&binding, &result, count, None).is_err());
        assert!(canonical_json(&json!({"kind":"result","result":result})).len() < MAX_LINE);
        assert_eq!(
            discovery.journal_record().unwrap()["kind"],
            "audit_discovery"
        );
        for sequence in 1..=count {
            let send = binding
                .audit()
                .unwrap()
                .planned_send(&binding, sequence as usize, Some(&discovery))
                .unwrap();
            if sequence >= 4 {
                assert_eq!(send["host"], vectors["sdk_s3_host"]);
            }
            let mut frame = json!({"kind":"send","request_digest":binding.digest(),"sequence":sequence,"send":send});
            frame["send_digest"] = json!(canonical_hash(&frame));
            let bytes = format!("{}\n", canonical_json(&frame));
            crate::s3_access_send::S3SendPreview::from_audit_frame(
                &binding,
                bytes.as_bytes(),
                sequence,
                Some(&discovery),
            )
            .unwrap();
        }
    }
    assert!(
        9 * MAX_SEND + 2 * MAX_LINE + 2048
            < vectors["conversation_bytes"].as_u64().unwrap() as usize
    );
}

#[test]
fn shared_request_refusal_vectors_remain_closed_and_numeric_strict() {
    for vector in vectors()["request_refusals"].as_array().unwrap() {
        let mut raw = request("baseline");
        *raw.pointer_mut(vector["pointer"].as_str().unwrap())
            .unwrap() = vector["value"].clone();
        assert!(binding(&raw).is_err(), "{}", vector["pointer"]);
    }
    let raw = canonical_json(&request("baseline"));
    assert!(S3WorkerBinding::from_json(
        format!("{{\"schema_version\":\"duplicate\",{}", &raw[1..]).as_bytes()
    )
    .is_err());
}

#[test]
fn original_pair_refuses_digest_rebinding_duplicate_read_ids_and_reads_after_failed_sts() {
    for change in [
        "digest",
        "duplicate",
        "failed_sts",
        "scope",
        "manifest",
        "runtime",
    ] {
        let mut raw = request("baseline");
        let read = &mut raw["audit"]["original_pair"]["reads"][0];
        match change {
            "digest" => read["worker_result_digest"] = json!(format!("sha256:{}", "f".repeat(64))),
            "duplicate" => {
                // Legitimate has two read calls; preserve a valid result digest after mutation.
                let read = &mut raw["audit"]["original_pair"]["reads"][1];
                read["result"]["calls"][4]["request_id"] =
                    read["result"]["calls"][3]["request_id"].clone();
                read["worker_result_digest"] = json!(canonical_hash(&read["result"]));
            }
            "failed_sts" => {
                read["result"]["calls"][0]["http_status"] = json!(403);
                read["result"]["calls"][0]["error_code"] = json!("AccessDenied");
                read["result"]["outcome"] = json!("failed");
                read["result"]["data"] = Value::Null;
                read["result"]["problem"] = json!("scoped_operation_failed");
                read["worker_result_digest"] = json!(canonical_hash(&read["result"]));
            }
            "scope" => {
                read["request"]["scope_digest"] = json!(format!("sha256:{}", "f".repeat(64)))
            }
            "manifest" => read["manifest_digest"] = json!("malformed"),
            _ => read["request"]["runtime_digest"] = json!(format!("sha256:{}", "f".repeat(64))),
        }
        assert!(binding(&raw).is_err(), "{change}");
    }
}

#[test]
fn discovery_requires_exact_original_debits_ordered_selection_and_unmodified_projection() {
    let binding = binding(&request("baseline")).unwrap();
    let (frame, _) = discovered(&binding, &vectors()["cases"][0]);
    for change in ["debits", "reservation", "selection", "float", "key", "hash"] {
        let mut frame = frame.clone();
        match change {
            "reservation" => {
                frame["reservation_digest"] = json!(format!("sha256:{}", "e".repeat(64)))
            }
            "selection" => frame["selected"] = json!([]),
            "float" => frame["completed_list_count"] = json!(1.0),
            "key" => frame["candidates"][0][1] = json!("outside.json.gz"),
            "hash" => {
                frame["listings"][0]["projection_digest"] =
                    json!(format!("sha256:{}", "e".repeat(64)))
            }
            _ => (),
        }
        let bytes = format!("{}\n", canonical_json(&frame));
        assert!(Discovery::from_frame(
            &binding,
            bytes.as_bytes(),
            vectors()["reservation_digest"].as_str().unwrap(),
            if change == "debits" { 3 } else { 4 }
        )
        .is_err());
    }
}

#[test]
fn get_before_checked_discovery_and_extra_get_refuse_without_mutation_authority() {
    let binding = binding(&request("baseline")).unwrap();
    let (_, discovery) = discovered(&binding, &vectors()["cases"][0]);
    let collection = binding.audit().unwrap();
    assert!(collection.planned_send(&binding, 5, None).is_err());
    assert!(collection
        .planned_send(&binding, 6, Some(&discovery))
        .is_err());
    let send = collection
        .planned_send(&binding, 5, Some(&discovery))
        .unwrap();
    assert_eq!(send["resource"]["IfMatch"], "\"synthetic-etag\"");
    assert_eq!(
        send["resource"]["discovery_digest"],
        canonical_hash(discovery.document())
    );
}

#[test]
fn result_requires_checked_discovery_exact_original_correlations_and_all_budgets() {
    let binding = binding(&request("baseline")).unwrap();
    let (_, discovery) = discovered(&binding, &vectors()["cases"][0]);
    for change in [
        "index",
        "wire",
        "expanded",
        "events",
        "original",
        "coverage",
        "access",
        "oversized",
    ] {
        let mut result = result(&binding, &vectors()["cases"][0], &discovery);
        match change {
            "index" => result["data"]["objects"][0]["selected_index"] = json!(true),
            "wire" => result["data"]["usage"]["sdk_body_bytes"] = json!(393217),
            "expanded" => result["data"]["usage"]["expanded_bytes"] = json!(1048577),
            "events" => result["data"]["usage"]["events"] = json!(501),
            "original" => {
                result["data"]["correlations"]["probe"]["request_digest"] =
                    json!(format!("sha256:{}", "e".repeat(64)))
            }
            "coverage" => result["data"]["delivery_state"] = json!("complete"),
            "access" => result["data"]["effective_access_claim"] = json!(true),
            _ => result["data"]["normalized_digest"] = json!("x".repeat(MAX_LINE)),
        }
        assert!(
            validate_result(&binding, &result, 5, Some(&discovery)).is_err(),
            "{change}"
        );
    }
}

#[test]
fn failed_collector_has_no_observations_or_policy_reconciliation_claim() {
    let binding = binding(&request("baseline")).unwrap();
    let mut result = json!({"schema_version":RESULT_SCHEMA,"request_digest":binding.digest(),"outcome":"failed",
        "data":null,"problem":"scoped_operation_failed","send_permits_consumed":0,"calls":[],"runtime_isolation_proven":false});
    assert!(!validate_result(&binding, &result, 0, None).unwrap());
    result["outcome"] = json!("reconcile_required");
    result["problem"] = json!("write_outcome_unsettled");
    assert!(validate_result(&binding, &result, 0, None).is_err());
}

#[test]
fn legacy_shared_binding_bytes_and_digests_are_unchanged() {
    let corpus: Value =
        serde_json::from_str(include_str!("../tests/fixtures/s3_access_binding_v1.json")).unwrap();
    for case in corpus["cases"].as_array().unwrap() {
        let binding = binding(&case["request"]).unwrap();
        assert_eq!(binding.canonical_json(), canonical_json(&case["request"]));
        assert_eq!(binding.digest(), case["request_digest"].as_str().unwrap());
    }
}

#[test]
fn failed_result_preserves_smaller_configured_file_ceiling_without_fake_gets() {
    let mut raw = request("baseline");
    raw["audit"]["source"]["audit_limits"]["files"] = json!(1);
    raw["audit_authority_digest"] = json!(canonical_hash(&raw["audit"]["source"]));
    let binding = binding(&raw).unwrap();
    let failed = json!({"schema_version":RESULT_SCHEMA,"request_digest":binding.digest(),"outcome":"failed",
        "data":null,"problem":"scoped_operation_failed","send_permits_consumed":0,"calls":[],"runtime_isolation_proven":false});
    assert!(!validate_result(&binding, &failed, 0, None).unwrap());
}

#[test]
fn current_collection_interval_cannot_start_early_or_extend_narrow_source_deadline() {
    let mut raw = request("baseline");
    raw["audit"]["source"]["audit_limits"]["seconds"] = json!(5);
    raw["audit"]["deadline"] = json!("2026-10-09T00:01:02Z");
    raw["deadline"] = raw["audit"]["deadline"].clone();
    raw["audit_authority_digest"] = json!(canonical_hash(&raw["audit"]["source"]));
    let binding = binding(&raw).unwrap();
    for (instant, accepted) in [
        ("2026-10-09T00:00:59.500000Z", false),
        ("2026-10-09T00:01:00Z", true),
        ("2026-10-09T00:01:01Z", true),
        ("2026-10-09T00:01:02Z", false),
    ] {
        assert_eq!(
            binding.assert_current(utc_time(instant).unwrap()).is_ok(),
            accepted
        );
    }
}

#[test]
fn policy_position_serialization_preserves_retained_ledger_labels() {
    use crate::s3_worker_result::PolicyPosition;

    for (position, label) in [
        (PolicyPosition::Before, "before"),
        (PolicyPosition::After, "after"),
        (PolicyPosition::Drift, "drift"),
        (PolicyPosition::Unknown, "unknown"),
    ] {
        let encoded = json!(label);
        assert_eq!(serde_json::to_value(position).unwrap(), encoded);
        assert_eq!(
            serde_json::from_value::<PolicyPosition>(encoded).unwrap(),
            position
        );
    }
    assert!(serde_json::from_value::<PolicyPosition>(json!("verified")).is_err());
}
