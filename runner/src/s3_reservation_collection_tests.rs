//! Real journal transitions using synthetic original-task results, without AWS.

use super::*;
use crate::s3_access_binding::{
    audit::{CollectionContext, Discovery},
    S3WorkerBinding,
};

#[path = "s3_reservation_collection_protocol_tests.rs"]
mod protocol;

fn prepared() -> (Ledger, Vec<u8>, Value, AuditedReservation) {
    prepared_case(false)
}

fn prepared_case(fixtures: bool) -> (Ledger, Vec<u8>, Value, AuditedReservation) {
    prepared_with(fixtures, ENROLLMENT, &profile())
}

fn prepared_with(
    fixtures: bool,
    enrollment: &str,
    profile_digest: &str,
) -> (Ledger, Vec<u8>, Value, AuditedReservation) {
    prepared_with_limit(fixtures, fixtures, None, enrollment, profile_digest)
}

fn prepared_with_limit(
    fixtures: bool,
    cleanup_fixtures: bool,
    api_limit: Option<u64>,
    enrollment: &str,
    profile_digest: &str,
) -> (Ledger, Vec<u8>, Value, AuditedReservation) {
    let mut request = crate::s3_access_binding::audit::tests::request("baseline");
    let mut scope: Scope = serde_json::from_value(request["scope"].clone()).unwrap();
    if let Some(limit) = api_limit {
        scope.limits.api_calls = limit;
    }
    let authority = fixtures.then(|| format!("sha256:{}", "9".repeat(64)));
    if fixtures {
        for object in &mut scope.objects {
            let bytes = crate::s3_fixture_binding::payload(&scope.scope_id, &object.purpose);
            object.sha256 = format!("sha256:{}", crate::canonical::sha256_hex(&bytes));
            object.size_bytes = bytes.len() as u64;
        }
    }
    if fixtures || api_limit.is_some() {
        request["scope"] = encoded(&scope).unwrap();
        request["scope_digest"] = json!(canonical_hash(&request["scope"]));
        request["audit"]["source"]["experiment_scope_digest"] = request["scope_digest"].clone();
        request["audit_authority_digest"] = json!(canonical_hash(&request["audit"]["source"]));
        for read in request["audit"]["original_pair"]["reads"]
            .as_array_mut()
            .unwrap()
        {
            read["request"]["scope"] = encoded(&scope).unwrap();
            read["request"]["scope_digest"] = json!(canonical_hash(&encoded(&scope).unwrap()));
            read["request_digest"] = json!(canonical_hash(&read["request"]));
            read["result"]["request_digest"] = read["request_digest"].clone();
            for (index, object) in read["result"]["data"]["objects"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .enumerate()
            {
                object["sha256"] = json!(scope.objects[index].sha256);
                object["size_bytes"] = json!(scope.objects[index].size_bytes);
            }
            read["worker_result_digest"] = json!(canonical_hash(&read["result"]));
        }
    }
    let mut commitment = workflow(&scope);
    commitment["source"] = request["audit"]["source"].clone();
    let mut ledger = Ledger::load(&[], enrollment).unwrap();
    let mut bytes = Vec::new();
    if fixtures {
        fixture_stage(
            &mut ledger,
            &mut bytes,
            &scope,
            &commitment,
            authority.clone(),
            profile_digest,
            false,
        );
    }
    let mut inspect = reservation(&scope, 10, "inspect", "inspect_policy");
    inspect.audit_workflow = commitment.clone();
    inspect.profile_digest = profile_digest.into();
    inspect.operation.fixture_authority_digest = authority.clone();
    let hash = reserve(&mut ledger, &mut bytes, &inspect);
    complete(
        &mut ledger,
        &mut bytes,
        &hash,
        true,
        PolicyPosition::Before,
        true,
    );
    for index in 0..2 {
        let reader = if index == 0 { "probe" } else { "legitimate" };
        let read = &request["audit"]["original_pair"]["reads"][index];
        let binding =
            S3WorkerBinding::from_json(canonical_json(&read["request"]).as_bytes()).unwrap();
        let mut raw = reservation(
            &scope,
            index as u64 + 11,
            "baseline",
            &format!("{reader}_read"),
        );
        raw.audit_workflow = commitment.clone();
        raw.profile_digest = profile_digest.into();
        raw.operation.fixture_authority_digest = authority.clone();
        raw.operation.operation_id = request["audit"]["original_pair"]["operation_job_id"]
            .as_str()
            .unwrap()
            .into();
        raw.operation.request_digest = binding.digest().into();
        raw.operation.request_id = binding.request_id().into();
        raw.operation.launch_id = binding.launch_id().into();
        raw.task = TaskIdentity {
            run_id: read["run_id"].as_str().unwrap().into(),
            manifest_digest: read["manifest_digest"].as_str().unwrap().into(),
            deadline: read["request"]["deadline"].as_str().unwrap().into(),
        };
        let hash = reserve(&mut ledger, &mut bytes, &raw);
        for sequence in 1..=raw.operation.max_sends {
            append(
                &mut ledger,
                &mut bytes,
                Record::Debit {
                    reservation_digest: hash.clone(),
                    sequence,
                    preview_digest: canonical_hash(&json!({"synthetic_preview":sequence})),
                    is_write: false,
                },
            );
        }
        append(
            &mut ledger,
            &mut bytes,
            Record::Completion {
                reservation_digest: hash.clone(),
                result_digest: canonical_hash(&read["result"]),
                observed: true,
                policy_position: PolicyPosition::Unknown,
                cleanup_verified: true,
                fixture_position: None,
            },
        );
        request["audit"]["original_pair"]["reads"][index]["reservation_digest"] = json!(hash);
    }
    if cleanup_fixtures {
        fixture_stage(
            &mut ledger,
            &mut bytes,
            &scope,
            &commitment,
            authority.clone(),
            profile_digest,
            true,
        );
    }
    let binding = S3WorkerBinding::from_json(canonical_json(&request).as_bytes()).unwrap();
    let mut collector = reservation(&scope, 20, "audit_baseline", "collect_audit");
    collector.audit_workflow = commitment;
    collector.profile_digest = profile_digest.into();
    collector.operation.operation_id = request["audit"]["operation_job_id"]
        .as_str()
        .unwrap()
        .into();
    collector.operation.request_digest = binding.digest().into();
    collector.operation.request_id = binding.request_id().into();
    collector.operation.launch_id = binding.launch_id().into();
    collector.operation.fixture_authority_digest = authority;
    collector.task.deadline = request["deadline"].as_str().unwrap().into();
    collector.collection = Some(binding.audit().unwrap().context().unwrap());
    (ledger, bytes, request, collector)
}

fn fixture_stage(
    ledger: &mut Ledger,
    bytes: &mut Vec<u8>,
    scope: &Scope,
    commitment: &Value,
    authority: Option<String>,
    profile_digest: &str,
    cleanup: bool,
) {
    for (index, purpose) in ["primary", "health"].into_iter().enumerate() {
        let name = if cleanup {
            "cleanup_fixture"
        } else {
            "prepare_fixture"
        };
        let phase = if cleanup { "cleanup" } else { "prepare" };
        let mut raw = reservation(
            scope,
            (if cleanup { 40 } else { 1 }) + index as u64,
            phase,
            name,
        );
        raw.audit_workflow = commitment.clone();
        raw.profile_digest = profile_digest.into();
        raw.operation.operation_id =
            format!("job-{}", (if cleanup { "e" } else { "f" }).repeat(32));
        raw.operation.fixture_authority_digest = authority.clone();
        raw.operation.fixture = Some(crate::s3_fixture_binding::FixtureOperation {
            schema_version: "bluefire.s3-fixture-operation.v2".into(),
            intent_id: "a".repeat(64),
            purpose: purpose.into(),
            expected_etag: cleanup.then(|| "\"owned\"".into()),
        });
        let hash = reserve(ledger, bytes, &raw);
        for sequence in 1..=raw.operation.max_sends {
            append(
                ledger,
                bytes,
                Record::Debit {
                    reservation_digest: hash.clone(),
                    sequence,
                    preview_digest: canonical_hash(&json!({"synthetic_fixture":sequence})),
                    is_write: sequence == 5,
                },
            );
        }
        append(
            ledger,
            bytes,
            Record::Completion {
                reservation_digest: hash.clone(),
                result_digest: canonical_hash(&json!({"synthetic_fixture_result":hash})),
                observed: true,
                policy_position: PolicyPosition::Unknown,
                cleanup_verified: true,
                fixture_position: Some(crate::s3_reservation::state::FixturePosition {
                    state: (if cleanup { "absent" } else { "owned" }).into(),
                    etag: (!cleanup).then(|| "\"owned\"".into()),
                }),
            },
        );
    }
}

fn debit_record(reservation: &str, sequence: u64) -> Record {
    Record::Debit {
        reservation_digest: reservation.into(),
        sequence,
        preview_digest: canonical_hash(&json!({"synthetic_preview":sequence})),
        is_write: false,
    }
}

fn selection(binding: &S3WorkerBinding, reservation: &str) -> (Vec<u8>, Discovery) {
    let case = json!({"candidate_count":1,"selected_count":1,"size_bytes":100,"truncated":false});
    let (mut frame, _) = crate::s3_access_binding::audit::tests::discovered(binding, &case);
    frame["reservation_digest"] = json!(reservation);
    let bytes = format!("{}\n", canonical_json(&frame)).into_bytes();
    let discovery = Discovery::from_frame(binding, &bytes, reservation, 4).unwrap();
    (bytes, discovery)
}

#[test]
fn collection_joins_actual_original_task_manifest_request_result_and_reservation_rows() {
    let (ledger, bytes, _, collector) = prepared();
    let replayed = Ledger::load(&bytes, ENROLLMENT).unwrap();
    assert!(ledger.check_audited(&collector).is_ok());
    assert!(replayed.check_audited(&collector).is_ok());
    assert_eq!(
        Ledger::load(&[], ENROLLMENT)
            .unwrap()
            .check_reserve(&collector.operation),
        Err(Error::Conflict)
    );
    for change in [
        "run",
        "manifest",
        "request",
        "result",
        "reservation",
        "deadline",
        "operation",
        "source",
        "collector_run",
        "collector_manifest",
    ] {
        let mut changed = collector.clone();
        let context = changed.collection.as_mut().unwrap();
        let read = &mut context.reads[0];
        match change {
            "run" => read.run_id = format!("run-20261009T000010Z-{}", "f".repeat(16)),
            "manifest" => read.manifest_digest = format!("sha256:{}", "f".repeat(64)),
            "request" => read.request_digest = format!("sha256:{}", "f".repeat(64)),
            "result" => read.worker_result_digest = format!("sha256:{}", "f".repeat(64)),
            "reservation" => read.reservation_digest = format!("sha256:{}", "f".repeat(64)),
            "deadline" => read.deadline = "2026-10-09T00:00:29Z".into(),
            "operation" => context.original_operation_id = format!("job-{}", "f".repeat(32)),
            "source" => context.audit_source_digest = format!("sha256:{}", "f".repeat(64)),
            "collector_run" => changed.task.run_id = read.run_id.clone(),
            _ => changed.task.manifest_digest = read.manifest_digest.clone(),
        }
        assert!(replayed.check_audited(&changed).is_err(), "{change}");
    }
    let mut missing = collector;
    missing.collection = None;
    assert_eq!(replayed.check_audited(&missing), Err(Error::Conflict));
}

#[test]
fn original_cleanup_and_missing_result_never_gain_collection_authority() {
    let (ledger, _, _, collector) = prepared();
    let original = collector.collection.as_ref().unwrap().reads[0]
        .request_digest
        .clone();
    for completion in [None, Some((true, PolicyPosition::Unknown, false))] {
        let mut changed = ledger.clone();
        changed.requests.get_mut(&original).unwrap().completion = completion;
        assert_eq!(
            changed.check_audited(&collector),
            Err(Error::RecoveryRequired)
        );
    }
    for (result, expected) in [
        (None, Error::RecoveryRequired),
        (Some(canonical_hash(&Value::Null)), Error::Conflict),
    ] {
        let mut changed = ledger.clone();
        changed
            .requests
            .get_mut(&original)
            .unwrap()
            .completion_result_digest = result;
        assert_eq!(changed.check_audited(&collector), Err(expected));
    }
}

#[test]
fn exact_collection_can_follow_fixture_cleanup_without_reopening_business_or_adopting_authority() {
    let (ledger, bytes, _, collector) = prepared_case(true);
    let replayed = Ledger::load(&bytes, ENROLLMENT).unwrap();
    assert!(replayed.check_audited(&collector).is_ok());
    let mut substituted = collector.clone();
    substituted.operation.fixture_authority_digest = Some(format!("sha256:{}", "f".repeat(64)));
    assert_eq!(ledger.check_audited(&substituted), Err(Error::Conflict));
    let mut business = reservation(&collector.scope, 50, "inspect", "inspect_policy");
    business.audit_workflow = collector.audit_workflow.clone();
    business.operation.fixture_authority_digest =
        collector.operation.fixture_authority_digest.clone();
    assert_eq!(ledger.check_audited(&business), Err(Error::Lifecycle));
    let mut unknown = replayed;
    let last = unknown.order.last().unwrap().clone();
    unknown.requests.get_mut(&last).unwrap().completion =
        Some((true, PolicyPosition::Unknown, false));
    assert_eq!(
        unknown.check_audited(&collector),
        Err(Error::RecoveryRequired)
    );
}

#[test]
fn low_cap_collection_preserves_outstanding_policy_and_fixture_recovery_holds() {
    for limit in [109, 110] {
        let (mut ledger, mut bytes, _, collector) =
            prepared_with_limit(true, false, Some(limit), ENROLLMENT, &profile());
        let mut apply = reservation(&collector.scope, 60, "apply", "apply_policy");
        apply.audit_workflow = collector.audit_workflow.clone();
        apply.operation.fixture_authority_digest =
            collector.operation.fixture_authority_digest.clone();
        assert_eq!(ledger.required_calls(&apply.operation).unwrap(), 69);
        if limit == 109 {
            let before = bytes.clone();
            assert_eq!(ledger.check_audited(&apply), Err(Error::Budget));
            assert_eq!(bytes, before);
            assert!(ledger
                .requests
                .values()
                .all(|row| row.reserved.operation != "apply_policy"));
            continue;
        }
        let write = reserve(&mut ledger, &mut bytes, &apply);
        for sequence in 1..=3 {
            append(
                &mut ledger,
                &mut bytes,
                Record::Debit {
                    reservation_digest: write.clone(),
                    sequence,
                    preview_digest: canonical_hash(&json!({"synthetic_write":sequence})),
                    is_write: sequence == 3,
                },
            );
        }
        complete(
            &mut ledger,
            &mut bytes,
            &write,
            false,
            PolicyPosition::Unknown,
            true,
        );
        let mut ledger = Ledger::load(&bytes, ENROLLMENT).unwrap();
        assert!(ledger.requests[&apply.operation.request_digest].write_debited);
        assert_eq!(
            ledger.requests[&apply.operation.request_digest].completion,
            Some((false, PolicyPosition::Unknown, true))
        );
        // A failed collection still converts its full nine-call hold; neither
        // the unknown policy position nor the owned fixtures are cleared.
        let collection = reserve(&mut ledger, &mut bytes, &collector);
        for sequence in 1..=4 {
            append(&mut ledger, &mut bytes, debit_record(&collection, sequence));
        }
        complete(
            &mut ledger,
            &mut bytes,
            &collection,
            false,
            PolicyPosition::Unknown,
            true,
        );
        let mut ledger = Ledger::load(&bytes, ENROLLMENT).unwrap();
        assert_eq!(
            ledger.requests[&collector.operation.request_digest]
                .reserved
                .max_sends,
            9
        );
        assert_eq!(
            ledger.requests[&collector.operation.request_digest].debits,
            4
        );
        assert_eq!(
            ledger.requests[&apply.operation.request_digest].completion,
            Some((false, PolicyPosition::Unknown, true))
        );
        assert_eq!(
            ledger
                .requests
                .values()
                .filter(|row| row.reserved.operation == "prepare_fixture"
                    && row
                        .fixture_position
                        .as_ref()
                        .is_some_and(|position| position.state == "owned"))
                .count(),
            2
        );
        let mut reconcile = reservation(&collector.scope, 61, "reconcile", "reconcile_policy");
        reconcile.audit_workflow = collector.audit_workflow.clone();
        reconcile.operation.fixture_authority_digest =
            collector.operation.fixture_authority_digest.clone();
        let historical: u64 = ledger
            .requests
            .values()
            .map(|row| row.reserved.max_sends)
            .sum();
        let floor = ledger.required_calls(&reconcile.operation).unwrap();
        assert_eq!((historical, floor), (36, 65));
        assert_eq!(historical + floor + 9, limit);
        let recovery = reserve(&mut ledger, &mut bytes, &reconcile);
        complete(
            &mut ledger,
            &mut bytes,
            &recovery,
            true,
            PolicyPosition::After,
            true,
        );
        fixture_stage(
            &mut ledger,
            &mut bytes,
            &collector.scope,
            &collector.audit_workflow,
            collector.operation.fixture_authority_digest.clone(),
            &profile(),
            true,
        );
        let replayed = Ledger::load(&bytes, ENROLLMENT).unwrap();
        assert_eq!(
            replayed
                .requests
                .values()
                .filter(|row| row.reserved.operation == "cleanup_fixture"
                    && row
                        .fixture_position
                        .as_ref()
                        .is_some_and(|position| position.state == "absent")
                    && row.completion == Some((true, PolicyPosition::Unknown, true)))
                .count(),
            2
        );
        assert_eq!(
            replayed.check_audited(&collector),
            Err(Error::AlreadyReserved)
        );
    }
}

#[test]
fn discovery_replay_requires_exact_list_debits_and_precedes_any_selected_get() {
    let (mut ledger, mut bytes, request, collector) = prepared();
    let binding = S3WorkerBinding::from_json(canonical_json(&request).as_bytes()).unwrap();
    let hash = reserve(&mut ledger, &mut bytes, &collector);
    let (frame, discovery) = selection(&binding, &hash);
    let record = Record::AuditDiscovery {
        reservation_digest: hash.clone(),
        discovery: discovery.document().clone(),
    };
    assert!(ledger
        .clone()
        .apply(record.clone(), canonical_hash(&Value::Null))
        .is_err());
    for sequence in 1..=4 {
        append(&mut ledger, &mut bytes, debit_record(&hash, sequence));
    }
    assert!(ledger
        .clone()
        .apply(debit_record(&hash, 5), canonical_hash(&Value::Null))
        .is_err());
    let checked = ledger.audit_reservation(binding.digest()).unwrap();
    let context: &CollectionContext = checked.raw().collection.as_ref().unwrap();
    let from_saved = Discovery::from_context(
        &checked.raw().scope,
        checked.workflow(),
        context,
        binding.digest(),
        &hash,
        4,
        &frame,
    )
    .unwrap();
    assert_eq!(from_saved.document(), discovery.document());
    append(&mut ledger, &mut bytes, record.clone());
    assert!(ledger
        .clone()
        .apply(record, canonical_hash(&Value::Null))
        .is_err());
    let mut ledger = Ledger::load(&bytes, ENROLLMENT).unwrap();
    assert_eq!(
        ledger.requests[binding.digest()]
            .discovery
            .as_ref()
            .unwrap()
            .document(),
        discovery.document()
    );
    append(&mut ledger, &mut bytes, debit_record(&hash, 5));
    assert!(ledger
        .clone()
        .apply(debit_record(&hash, 6), canonical_hash(&Value::Null))
        .is_err());
    let case = json!({"candidate_count":1,"selected_count":1,"size_bytes":100,"truncated":false});
    let result = crate::s3_access_binding::audit::tests::result(&binding, &case, &discovery);
    let frame = format!(
        "{}\n",
        canonical_json(&json!({"kind":"result","result":result}))
    );
    assert!(
        crate::s3_worker_result::WorkerResult::from_frame(&binding, frame.as_bytes(), 5).is_err()
    );
    assert!(
        crate::s3_worker_result::WorkerResult::from_frame_with_discovery(
            &binding,
            frame.as_bytes(),
            5,
            ledger.requests[binding.digest()].discovery.as_ref()
        )
        .unwrap()
        .observed
    );
    append(
        &mut ledger,
        &mut bytes,
        Record::Completion {
            reservation_digest: hash,
            result_digest: canonical_hash(&result),
            observed: true,
            policy_position: PolicyPosition::Unknown,
            cleanup_verified: true,
            fixture_position: None,
        },
    );
    let replayed = Ledger::load(&bytes, ENROLLMENT).unwrap();
    assert_eq!(
        replayed.requests[binding.digest()].completion_result_digest,
        Some(canonical_hash(&result))
    );
    assert!(!replayed.requests[binding.digest()].write_debited);
}

#[test]
fn discovery_and_collection_completion_cannot_rebind_authority_or_change_positions() {
    let (mut ledger, mut bytes, request, collector) = prepared();
    let binding = S3WorkerBinding::from_json(canonical_json(&request).as_bytes()).unwrap();
    let hash = reserve(&mut ledger, &mut bytes, &collector);
    for sequence in 1..=4 {
        append(&mut ledger, &mut bytes, debit_record(&hash, sequence));
    }
    let (_, discovery) = selection(&binding, &hash);
    for field in [
        "request_digest",
        "collection_digest",
        "pair_digest",
        "reservation_digest",
        "audit_source_digest",
        "frame_digest",
    ] {
        let mut changed = discovery.document().clone();
        changed[field] = if field == "frame_digest" {
            json!("malformed")
        } else {
            json!(format!("sha256:{}", "f".repeat(64)))
        };
        assert!(
            ledger
                .clone()
                .apply(
                    Record::AuditDiscovery {
                        reservation_digest: hash.clone(),
                        discovery: changed
                    },
                    canonical_hash(&Value::Null)
                )
                .is_err(),
            "{field}"
        );
    }
    append(
        &mut ledger,
        &mut bytes,
        Record::AuditDiscovery {
            reservation_digest: hash.clone(),
            discovery: discovery.document().clone(),
        },
    );
    for position in [
        PolicyPosition::Before,
        PolicyPosition::After,
        PolicyPosition::Drift,
    ] {
        assert!(ledger
            .clone()
            .apply(
                Record::Completion {
                    reservation_digest: hash.clone(),
                    result_digest: canonical_hash(&Value::Null),
                    observed: false,
                    policy_position: position,
                    cleanup_verified: true,
                    fixture_position: None
                },
                canonical_hash(&Value::Null)
            )
            .is_err());
    }
    assert!(ledger
        .clone()
        .apply(
            Record::Completion {
                reservation_digest: hash.clone(),
                result_digest: canonical_hash(&Value::Null),
                observed: true,
                policy_position: PolicyPosition::Unknown,
                cleanup_verified: true,
                fixture_position: None
            },
            canonical_hash(&Value::Null)
        )
        .is_err());
    append(
        &mut ledger,
        &mut bytes,
        Record::Completion {
            reservation_digest: hash,
            result_digest: canonical_hash(&Value::Null),
            observed: false,
            policy_position: PolicyPosition::Unknown,
            cleanup_verified: false,
            fixture_position: None,
        },
    );
    let mut next = reservation(&collector.scope, 30, "reconcile", "reconcile_policy");
    next.audit_workflow = collector.audit_workflow;
    assert_eq!(
        Ledger::load(&bytes, ENROLLMENT)
            .unwrap()
            .check_audited(&next),
        Err(Error::RecoveryRequired)
    );
}
