use super::*;
use crate::canonical::sha256_hex;
use crate::s3_access_policy::encoded;
use crate::s3_fixture_binding::{payload, FixtureOperation};
use serde_json::json;

#[path = "s3_reservation_audit_replay_tests.rs"]
mod replay;

fn profile() -> String {
    format!("sha256:{}", "8".repeat(64))
}

fn scope() -> Scope {
    let corpus: Value =
        serde_json::from_str(include_str!("../tests/fixtures/s3_access_binding_v1.json")).unwrap();
    serde_json::from_value(corpus["cases"][0]["request"]["scope"].clone()).unwrap()
}

fn workflow(scope: &Scope) -> Value {
    let scope_digest = canonical_hash(&encoded(scope).unwrap());
    json!({
        "schema_version":"bluefire.s3-audit-workflow.v1",
        "workflow_job_id":format!("job-{}", "1".repeat(32)),"environment_id":"synthetic-audit-environment",
        "scope_digest":scope_digest,
        "resource_key":canonical_hash(&json!({"account_id":scope.account_id,"region":scope.region,"bucket":scope.bucket})),
        "source":{
            "schema_version":"bluefire.s3-audit-source.v1","audit_source_id":"synthetic-trail",
            "experiment_scope_digest":scope_digest,
            "trail_arn":format!("arn:aws:cloudtrail:{}:{}:trail/synthetic",scope.region,scope.account_id),
            "source_account_id":scope.account_id,"event_region":scope.region,
            "audit_bucket":"synthetic-audit-delivery","audit_bucket_owner_account_id":scope.account_id,
            "audit_bucket_region":"us-west-2",
            "exact_delivery_root_prefix":format!("AWSLogs/{}/CloudTrail/{}/",scope.account_id,scope.region),
            "collector_role_arn":format!("arn:aws:iam::{}:role/audit-collector",scope.account_id),
            "managed_profile_digest":format!("sha256:{}","6".repeat(64)),
            "protected_runtime_digest":format!("sha256:{}","d".repeat(64)),
            "worker_generation":format!("sha256:{}","c".repeat(64)),"expires_at":scope.expires_at,
            "audit_limits":{"api_calls":9,"sessions":1,"files":4,"sdk_body_bytes":393216,
                "compressed_bytes":262144,"expanded_bytes":1048576,"events":500,"seconds":30},
        },
        "budget":{
            "per_batch":{"api_calls":9,"sessions":1,"files":4,"sdk_body_bytes":393216,
                "compressed_bytes":262144,"expanded_bytes":1048576,"events":500,"seconds":30},
            "workflow":{"api_calls":18,"sessions":2,"files":8,"sdk_body_bytes":786432,
                "compressed_bytes":524288,"expanded_bytes":2097152,"events":1000,"seconds":60,
                "batches":2,"wire_plus_expansion_bytes":2883584},
        },
    })
}

fn reservation(scope: &Scope, index: u64, phase: &str, name: &str) -> AuditedReservation {
    let workflow = workflow(scope);
    let operation_id = match phase {
        "baseline" => format!("job-{}", "b".repeat(32)),
        "retest" => format!("job-{}", "c".repeat(32)),
        "audit_baseline" => format!("job-{}", "d".repeat(32)),
        "audit_retest" => format!("job-{}", "e".repeat(32)),
        _ => format!("job-{index:032x}"),
    };
    let max_sends = match name {
        "inspect_policy" | "reconcile_policy" => 2,
        "probe_read" | "apply_policy" | "rollback_policy" => 4,
        "legitimate_read" | "reconcile_fixture" => 5,
        "prepare_fixture" => 6,
        "cleanup_fixture" => 7,
        "collect_audit" => 9,
        _ => panic!("unsupported synthetic operation"),
    };
    AuditedReservation {
        operation: Reserved {
            workflow_id: workflow["workflow_job_id"].as_str().unwrap().into(),
            operation_id,
            environment_id: "synthetic-audit-environment".into(),
            resource_key: workflow["resource_key"].as_str().unwrap().into(),
            scope_digest: workflow["scope_digest"].as_str().unwrap().into(),
            request_digest: format!("sha256:{index:064x}"),
            request_id: format!("{:064x}", index + 1000),
            launch_id: format!("{:064x}", index + 2000),
            approval_digest: format!("sha256:{}", "f".repeat(64)),
            runtime_digest: format!("sha256:{}", "d".repeat(64)),
            worker_generation: format!("sha256:{}", "c".repeat(64)),
            phase: phase.into(),
            operation: name.into(),
            revision: 1,
            max_sends,
            api_limit: scope.limits.api_calls,
            session_limit: scope.limits.sessions,
            business_attempt_limit: scope.limits.business_attempts,
            fixture_authority_digest: None,
            fixture: None,
        },
        scope: scope.clone(),
        audit_workflow: workflow,
        profile_digest: profile(),
        task: TaskIdentity {
            run_id: format!("run-20261009T000010Z-{index:016x}"),
            manifest_digest: format!("sha256:{:064x}", index + 3000),
            deadline: (crate::s3_access_scope::utc_time(&scope.created_at).unwrap()
                + chrono::Duration::seconds(scope.limits.request_seconds as i64))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        },
        collection: None,
    }
}

fn refs(history: &[Retained]) -> Vec<&Retained> {
    history.iter().collect()
}

fn retained(record: &AuditedReservation) -> Retained {
    Retained {
        digest: canonical_hash(&json!({"synthetic_reservation":record.operation.request_digest})),
        reserved: record.operation.clone(),
        debits: 0,
        write_debited: false,
        completion: Some((false, PolicyPosition::Unknown, true)),
        completion_result_digest: Some(format!("sha256:{}", "a".repeat(64))),
        fixture_position: None,
        discovery: None,
    }
}

fn retain_in_memory(
    scope: &Scope,
    state: &mut AuditState,
    history: &mut Vec<Retained>,
    record: &AuditedReservation,
    floor: u64,
) -> AuditHolds {
    let checked = record.checked(scope, &profile()).unwrap();
    let holds = state
        .apply_reservation(&refs(history), checked, floor)
        .unwrap();
    history.push(retained(record));
    holds
}

fn read_pair(
    scope: &Scope,
    state: &mut AuditState,
    history: &mut Vec<Retained>,
    phase: &str,
    first: u64,
) {
    retain_in_memory(
        scope,
        state,
        history,
        &reservation(scope, first, phase, "probe_read"),
        15,
    );
    retain_in_memory(
        scope,
        state,
        history,
        &reservation(scope, first + 1, phase, "legitimate_read"),
        11,
    );
}

#[test]
fn first_reservation_holds_both_batches_and_all_four_business_reads() {
    let scope = scope();
    let next = reservation(&scope, 1, "inspect", "inspect_policy")
        .checked(&scope, &profile())
        .unwrap();
    let state = AuditState::default();
    let holds = state.check_reserve(&[], &next, 2).unwrap();
    assert_eq!(holds.total_api_commitment, 38);
    assert_eq!(holds.total_session_commitment, 6);
    assert_eq!(holds.total_business_commitment, 6);
    assert_eq!(holds.unbound_original_reads, 4);
    assert_eq!(holds.unbound_audit_batches, 2);
    assert_eq!(holds.audit_budget.files, 8);
    assert_eq!(holds.audit_budget.events, 1000);
    assert_eq!(holds.audit_budget.sdk_body_bytes, 786432);
    assert_eq!(holds.audit_budget.compressed_bytes, 524288);
    assert_eq!(holds.audit_budget.expanded_bytes, 2097152);
    assert_eq!(holds.audit_budget.wire_plus_expansion_bytes, 2883584);
    assert_eq!(holds.audit_budget.seconds, 60);
    assert!(holds.original_pair.is_none());
    for (limit, accepted) in [(37, false), (38, true)] {
        let mut scope = scope.clone();
        scope.limits.api_calls = limit;
        let next = reservation(&scope, 1, "inspect", "inspect_policy")
            .checked(&scope, &profile())
            .unwrap();
        assert_eq!(state.check_reserve(&[], &next, 2).is_ok(), accepted);
    }
}

#[test]
fn first_original_read_holds_both_pairs_plus_eighteen_audit_calls() {
    for (limit, accepted) in [(35, false), (36, true)] {
        let mut scope = scope();
        scope.limits.api_calls = limit;
        let next = reservation(&scope, 1, "baseline", "probe_read")
            .checked(&scope, &profile())
            .unwrap();
        let result = AuditState::default().check_reserve(&[], &next, 9);
        assert_eq!(result.is_ok(), accepted);
        if accepted {
            assert_eq!(result.unwrap().total_api_commitment, 36);
        }
    }
}

#[test]
fn native_fixture_recovery_floor_is_added_not_replaced_by_audit_holds() {
    for (limit, accepted) in [(87, false), (88, true)] {
        let mut scope = scope();
        scope.limits.api_calls = limit;
        for object in &mut scope.objects {
            let raw = payload(&scope.scope_id, &object.purpose);
            object.sha256 = format!("sha256:{}", sha256_hex(&raw));
            object.size_bytes = raw.len() as u64;
        }
        let mut raw = reservation(&scope, 1, "prepare", "prepare_fixture");
        raw.operation.fixture_authority_digest = Some(format!("sha256:{}", "7".repeat(64)));
        raw.operation.fixture = Some(FixtureOperation {
            schema_version: "bluefire.s3-fixture-operation.v2".into(),
            intent_id: "a".repeat(64),
            purpose: "primary".into(),
            expected_etag: None,
        });
        let floor = super::super::fixture::required_calls(&[], &raw.operation).unwrap();
        assert_eq!(floor, 70);
        let next = raw.checked(&scope, &profile()).unwrap();
        let result = AuditState::default().check_reserve(&[], &next, floor);
        assert_eq!(result.is_ok(), accepted);
        if accepted {
            assert_eq!(result.unwrap().total_api_commitment, 88);
        }
    }
}

#[test]
fn actual_native_profile_never_uses_the_host_managed_profile_digest_as_authority() {
    let scope = scope();
    let mut raw = reservation(&scope, 1, "inspect", "inspect_policy");
    assert!(raw.checked(&scope, &profile()).is_ok());
    raw.profile_digest = raw.audit_workflow["source"]["managed_profile_digest"]
        .as_str()
        .unwrap()
        .into();
    assert!(raw.checked(&scope, &profile()).is_err());
}

#[test]
fn changed_workflow_source_profile_runtime_generation_budget_and_limits_refuse() {
    let scope = scope();
    let first = reservation(&scope, 1, "inspect", "inspect_policy");
    let mut state = AuditState::default();
    let mut history = Vec::new();
    retain_in_memory(&scope, &mut state, &mut history, &first, 2);
    for field in [
        "source",
        "workflow",
        "profile",
        "runtime",
        "generation",
        "budget",
        "limits",
    ] {
        let mut next = reservation(&scope, 2, "baseline", "probe_read");
        let mut actual_profile = profile();
        match field {
            "source" => {
                next.audit_workflow["source"]["audit_bucket"] = json!("different-audit-delivery")
            }
            "workflow" => {
                next.operation.workflow_id = format!("job-{}", "2".repeat(32));
                next.audit_workflow["workflow_job_id"] = json!(next.operation.workflow_id);
            }
            "profile" => {
                actual_profile = format!("sha256:{}", "9".repeat(64));
                next.profile_digest = actual_profile.clone();
            }
            "runtime" => next.operation.runtime_digest = format!("sha256:{}", "0".repeat(64)),
            "generation" => next.operation.worker_generation = format!("sha256:{}", "0".repeat(64)),
            "budget" => next.audit_workflow["budget"]["workflow"]["files"] = json!(7),
            _ => next.operation.api_limit -= 1,
        }
        let refused = match next.checked(&scope, &actual_profile) {
            Err(_) => true,
            Ok(checked) => state.check_reserve(&refs(&history), &checked, 9).is_err(),
        };
        assert!(refused, "{field}");
    }
}

#[test]
fn legacy_history_cannot_be_adopted_and_audited_history_cannot_be_stripped() {
    let scope = scope();
    let first = reservation(&scope, 1, "inspect", "inspect_policy");
    let history = vec![retained(&first)];
    let next = reservation(&scope, 2, "baseline", "probe_read")
        .checked(&scope, &profile())
        .unwrap();
    assert_eq!(
        AuditState::default()
            .check_reserve(&refs(&history), &next, 9)
            .err(),
        Some(Error::Conflict)
    );
    let mut state = AuditState::default();
    let mut history = Vec::new();
    retain_in_memory(&scope, &mut state, &mut history, &first, 2);
    assert_eq!(
        state.check_legacy(&refs(&history), next.operation()),
        Err(Error::Conflict)
    );
}

#[test]
fn zero_send_failed_read_is_one_use_and_its_phase_cannot_be_replaced() {
    let scope = scope();
    let mut state = AuditState::default();
    let mut history = Vec::new();
    let first = reservation(&scope, 1, "baseline", "probe_read");
    retain_in_memory(&scope, &mut state, &mut history, &first, 9);
    history[0].completion_result_digest = Some(canonical_hash(&Value::Null));
    let mut retry = reservation(&scope, 2, "baseline", "probe_read");
    retry.operation.operation_id = format!("job-{}", "4".repeat(32));
    let retry = retry.checked(&scope, &profile()).unwrap();
    assert_eq!(
        state.check_reserve(&refs(&history), &retry, 9).err(),
        Some(Error::AlreadyReserved)
    );
    let mut partner = reservation(&scope, 3, "baseline", "legitimate_read");
    partner.operation.operation_id = format!("job-{}", "3".repeat(32));
    let partner = partner.checked(&scope, &profile()).unwrap();
    assert_eq!(
        state.check_reserve(&refs(&history), &partner, 5).err(),
        Some(Error::Conflict)
    );
    assert_eq!(history[0].debits, 0);
}

#[test]
fn audit_converts_only_its_original_hold_without_double_charge_or_refund() {
    let scope = scope();
    let mut state = AuditState::default();
    let mut history = Vec::new();
    read_pair(&scope, &mut state, &mut history, "baseline", 1);
    let next = reservation(&scope, 3, "audit_baseline", "collect_audit");
    let audit = retain_in_memory(&scope, &mut state, &mut history, &next, 0);
    assert_eq!(audit.total_api_commitment, 9 + 9 + 18);
    assert_eq!(audit.total_session_commitment, 6);
    assert_eq!(audit.total_business_commitment, 6);
    assert_eq!(audit.unbound_audit_batches, 1);
    assert_eq!(
        audit.original_pair.as_ref().unwrap()[0].reservation_digest,
        history[0].digest
    );
    assert_eq!(
        audit.original_pair.as_ref().unwrap()[1].worker_result_digest,
        history[1].completion_result_digest.clone().unwrap()
    );
    history[2].completion_result_digest = Some(canonical_hash(&Value::Null));
    let mut repeat = reservation(&scope, 4, "audit_baseline", "collect_audit");
    repeat.operation.operation_id = format!("job-{}", "4".repeat(32));
    let repeat = repeat.checked(&scope, &profile()).unwrap();
    assert_eq!(
        state.check_reserve(&refs(&history), &repeat, 0).err(),
        Some(Error::AlreadyReserved)
    );
    let reconcile = reservation(&scope, 5, "reconcile", "reconcile_policy")
        .checked(&scope, &profile())
        .unwrap();
    let holds = state
        .check_reserve(&refs(&history), &reconcile, 17)
        .unwrap();
    assert_eq!(holds.total_api_commitment, 9 + 9 + 17 + 9);
    assert_eq!(holds.audit_budget, audit.audit_budget);
}

#[test]
fn original_read_and_audit_conversion_conserve_all_future_calls() {
    let scope = scope();
    let mut state = AuditState::default();
    let mut history = Vec::new();
    let records = [
        ("inspect", "inspect_policy", 2, 38),
        ("baseline", "probe_read", 9, 38),
        ("baseline", "legitimate_read", 5, 38),
        ("audit_baseline", "collect_audit", 0, 38),
        ("retest", "probe_read", 15, 44),
        ("retest", "legitimate_read", 11, 44),
        ("audit_retest", "collect_audit", 0, 38),
    ];
    for (index, (phase, operation, floor, expected)) in records.into_iter().enumerate() {
        let raw = reservation(&scope, index as u64 + 1, phase, operation);
        let holds = retain_in_memory(&scope, &mut state, &mut history, &raw, floor);
        assert_eq!(holds.total_api_commitment, expected, "{phase}/{operation}");
        assert_eq!(holds.total_session_commitment, 6);
        assert_eq!(holds.total_business_commitment, 6);
    }
}

#[test]
fn both_audit_slots_and_all_read_slots_remain_charged_in_reconstructed_state() {
    let scope = scope();
    let records = [
        (reservation(&scope, 1, "baseline", "probe_read"), 9),
        (reservation(&scope, 2, "baseline", "legitimate_read"), 5),
        (reservation(&scope, 3, "audit_baseline", "collect_audit"), 0),
        (reservation(&scope, 4, "retest", "probe_read"), 15),
        (reservation(&scope, 5, "retest", "legitimate_read"), 11),
        (reservation(&scope, 6, "audit_retest", "collect_audit"), 0),
    ];
    for _ in 0..2 {
        let mut state = AuditState::default();
        let mut history = Vec::new();
        let mut last = None;
        for (record, floor) in &records {
            let serialized = serde_json::to_value(record).unwrap();
            let restored: AuditedReservation = serde_json::from_value(serialized).unwrap();
            last = Some(retain_in_memory(
                &scope,
                &mut state,
                &mut history,
                &restored,
                *floor,
            ));
        }
        let holds = last.unwrap();
        assert_eq!(holds.unbound_original_reads, 0);
        assert_eq!(holds.unbound_audit_batches, 0);
        assert_eq!(holds.total_api_commitment, 36);
        assert_eq!(holds.total_session_commitment, 6);
        assert_eq!(holds.total_business_commitment, 6);
        let mut repeat = reservation(&scope, 7, "retest", "legitimate_read");
        repeat.operation.operation_id = format!("job-{}", "7".repeat(32));
        let repeat = repeat.checked(&scope, &profile()).unwrap();
        assert_eq!(
            state.check_reserve(&refs(&history), &repeat, 5).err(),
            Some(Error::AlreadyReserved)
        );
    }
}

#[test]
fn unknown_worker_cleanup_blocks_audit_ordinary_and_legacy_paths() {
    let scope = scope();
    let mut state = AuditState::default();
    let mut history = Vec::new();
    read_pair(&scope, &mut state, &mut history, "baseline", 1);
    for completion in [None, Some((true, PolicyPosition::Unknown, false))] {
        history[1].completion = completion;
        for (phase, operation, floor) in [
            ("audit_baseline", "collect_audit", 0),
            ("reconcile", "reconcile_policy", 17),
        ] {
            let next = reservation(&scope, 3, phase, operation)
                .checked(&scope, &profile())
                .unwrap();
            assert_eq!(
                state.check_reserve(&refs(&history), &next, floor).err(),
                Some(Error::RecoveryRequired)
            );
            assert_eq!(
                state.check_legacy(&refs(&history), next.operation()),
                Err(Error::RecoveryRequired)
            );
        }
    }
}

#[test]
fn original_pair_requires_both_retained_nonnull_result_digests_without_fabrication() {
    let scope = scope();
    let audit = reservation(&scope, 3, "audit_baseline", "collect_audit")
        .checked(&scope, &profile())
        .unwrap();
    assert_eq!(
        AuditState::default().check_reserve(&[], &audit, 0).err(),
        Some(Error::Lifecycle)
    );
    let mut state = AuditState::default();
    let mut history = Vec::new();
    read_pair(&scope, &mut state, &mut history, "baseline", 1);
    for digest in [
        None,
        Some(canonical_hash(&Value::Null)),
        Some("malformed".into()),
    ] {
        history[0].completion_result_digest = digest;
        assert!(state.check_reserve(&refs(&history), &audit, 0).is_err());
    }
}

#[test]
fn audit_evidence_cannot_supply_policy_write_or_fixture_position() {
    let scope = scope();
    let mut state = AuditState::default();
    let mut history = Vec::new();
    read_pair(&scope, &mut state, &mut history, "baseline", 1);
    retain_in_memory(
        &scope,
        &mut state,
        &mut history,
        &reservation(&scope, 3, "audit_baseline", "collect_audit"),
        0,
    );
    let next = reservation(&scope, 4, "reconcile", "reconcile_policy")
        .checked(&scope, &profile())
        .unwrap();
    for change in ["write", "policy", "fixture"] {
        let mut changed = history.clone();
        match change {
            "write" => changed[2].write_debited = true,
            "policy" => changed[2].completion = Some((true, PolicyPosition::After, true)),
            _ => {
                changed[2].fixture_position = Some(super::super::state::FixturePosition {
                    state: "absent".into(),
                    etag: None,
                })
            }
        }
        assert_eq!(
            state.check_reserve(&refs(&changed), &next, 17).err(),
            Some(Error::Conflict)
        );
    }
    assert!(history
        .iter()
        .all(|row| !row.write_debited && row.fixture_position.is_none()));
}

#[test]
fn undersized_ordinary_floor_and_audit_fallback_floor_refuse_without_state_change() {
    let scope = scope();
    let mut state = AuditState::default();
    let mut history = Vec::new();
    let read = reservation(&scope, 1, "baseline", "probe_read")
        .checked(&scope, &profile())
        .unwrap();
    assert!(state.apply_reservation(&[], read, 0).is_err());
    assert!(state.reservations.is_empty());
    read_pair(&scope, &mut state, &mut history, "baseline", 1);
    let audit = reservation(&scope, 3, "audit_baseline", "collect_audit")
        .checked(&scope, &profile())
        .unwrap();
    assert!(state.apply_reservation(&refs(&history), audit, 9).is_err());
    assert_eq!(state.reservations.len(), 2);
}
