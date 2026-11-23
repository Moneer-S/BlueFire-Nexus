//! Actual journal encode/apply/load with synthetic observations, no storage or permits.

use super::*;
use crate::s3_reservation::state::{Entry, Ledger, Record, SCHEMA};

const ENROLLMENT: &str = "synthetic-audit-enrollment";

#[path = "s3_reservation_collection_tests.rs"]
mod collection;

fn append(ledger: &mut Ledger, bytes: &mut Vec<u8>, record: Record) -> String {
    let entry = Entry {
        schema_version: SCHEMA.into(),
        sequence: ledger.entries + 1,
        previous_hash: ledger.previous_hash.clone(),
        record: record.clone(),
    };
    let (hash, encoded) = crate::s3_reservation::encode_entry(entry).unwrap();
    let mut candidate = ledger.clone();
    candidate.apply(record, hash.clone()).unwrap();
    candidate.entries += 1;
    candidate.previous_hash = hash.clone();
    candidate.bytes += encoded.len();
    bytes.extend(encoded);
    *ledger = candidate;
    hash
}

fn reserve(ledger: &mut Ledger, bytes: &mut Vec<u8>, raw: &AuditedReservation) -> String {
    append(
        ledger,
        bytes,
        Record::AuditedReservation {
            reservation: Box::new(raw.clone()),
        },
    )
}

fn complete(
    ledger: &mut Ledger,
    bytes: &mut Vec<u8>,
    reservation: &str,
    observed: bool,
    position: PolicyPosition,
    clean: bool,
) {
    if observed {
        let row = ledger
            .requests
            .values()
            .find(|row| row.digest == reservation)
            .unwrap()
            .reserved
            .clone();
        for sequence in 1..=row.max_sends {
            append(
                ledger,
                bytes,
                Record::Debit {
                    reservation_digest: reservation.into(),
                    sequence,
                    preview_digest: canonical_hash(
                        &json!({"synthetic_preview":sequence,"request":row.request_digest}),
                    ),
                    is_write: sequence == 3
                        && matches!(row.operation.as_str(), "apply_policy" | "rollback_policy"),
                },
            );
        }
    }
    append(
        ledger,
        bytes,
        Record::Completion {
            reservation_digest: reservation.into(),
            result_digest: if observed {
                canonical_hash(&json!({"synthetic_result":reservation}))
            } else {
                canonical_hash(&Value::Null)
            },
            observed,
            policy_position: position,
            cleanup_verified: clean,
            fixture_position: None,
        },
    );
}

#[test]
fn audited_full_scope_record_replays_through_real_entry_and_keeps_original_floors() {
    let scope = scope();
    let mut ledger = Ledger::load(&[], ENROLLMENT).unwrap();
    let mut bytes = Vec::new();
    for (index, phase, operation, position, floor) in [
        (1, "inspect", "inspect_policy", PolicyPosition::Before, 2),
        (2, "baseline", "probe_read", PolicyPosition::Unknown, 9),
        (3, "baseline", "legitimate_read", PolicyPosition::Unknown, 5),
        (4, "apply", "apply_policy", PolicyPosition::After, 21),
        (5, "retest", "probe_read", PolicyPosition::Unknown, 15),
        (6, "retest", "legitimate_read", PolicyPosition::Unknown, 11),
        (7, "rollback", "rollback_policy", PolicyPosition::Before, 6),
    ] {
        let raw = reservation(&scope, index, phase, operation);
        assert_eq!(ledger.required_calls(&raw.operation).unwrap(), floor);
        let hash = reserve(&mut ledger, &mut bytes, &raw);
        complete(&mut ledger, &mut bytes, &hash, true, position, true);
        ledger = Ledger::load(&bytes, ENROLLMENT).unwrap();
    }
    let first: Value =
        serde_json::from_slice(bytes.split_inclusive(|byte| *byte == b'\n').next().unwrap())
            .unwrap();
    assert_eq!(first["record"]["kind"], "audited_reservation");
    assert_eq!(
        first["record"]["reservation"]["scope"],
        encoded(&scope).unwrap()
    );
    let repeated = reservation(&scope, 8, "retest", "probe_read");
    assert!(ledger.check_audited(&repeated).is_err());
    let collect = reservation(&scope, 9, "audit_baseline", "collect_audit");
    assert_eq!(ledger.check_audited(&collect), Err(Error::Conflict));
}

#[test]
fn different_resource_scopes_and_native_profiles_replay_without_current_scope_adoption() {
    let scope = scope();
    let mut other = scope.clone();
    other.bucket = "synthetic-other-resource".into();
    let first = reservation(&scope, 1, "inspect", "inspect_policy");
    let mut second = reservation(&other, 2, "inspect", "inspect_policy");
    second.profile_digest = format!("sha256:{}", "9".repeat(64));
    assert!(second.checked(&scope, &profile()).is_err());
    assert!(second.checked(&other, &second.profile_digest).is_ok());
    let mut ledger = Ledger::load(&[], ENROLLMENT).unwrap();
    let mut bytes = Vec::new();
    let hash = reserve(&mut ledger, &mut bytes, &first);
    complete(
        &mut ledger,
        &mut bytes,
        &hash,
        true,
        PolicyPosition::Before,
        true,
    );
    let hash = reserve(&mut ledger, &mut bytes, &second);
    complete(
        &mut ledger,
        &mut bytes,
        &hash,
        true,
        PolicyPosition::Before,
        true,
    );
    let ledger = Ledger::load(&bytes, ENROLLMENT).unwrap();
    assert_eq!(ledger.requests.len(), 2);
    assert!(ledger
        .check_audited(&reservation(&scope, 3, "baseline", "probe_read"))
        .is_ok());
    let mut next = reservation(&other, 4, "baseline", "probe_read");
    next.profile_digest = second.profile_digest;
    assert!(ledger.check_audited(&next).is_ok());
}

#[test]
fn actual_current_scope_profile_and_full_saved_scope_substitutions_refuse() {
    let scope = scope();
    let first = reservation(&scope, 1, "inspect", "inspect_policy");
    let mut other = scope.clone();
    other.limits.api_calls -= 1;
    assert!(first.checked(&other, &profile()).is_err());
    assert!(first
        .checked(&scope, &format!("sha256:{}", "9".repeat(64)))
        .is_err());
    let mut corrupt = serde_json::to_value(&first).unwrap();
    corrupt["scope"]["limits"]["sessions"] = json!(true);
    assert!(serde_json::from_value::<AuditedReservation>(corrupt).is_err());
    let mut corrupt = first.clone();
    corrupt.scope.bucket = "synthetic-substituted-resource".into();
    assert!(corrupt.checked_historical().is_err());
}

#[test]
fn actual_mixed_history_refuses_same_resource_adoption_stripping_and_profile_drift() {
    let scope = scope();
    for audited in [false, true] {
        let first = reservation(&scope, 1, "inspect", "inspect_policy");
        let mut ledger = Ledger::load(&[], ENROLLMENT).unwrap();
        let mut bytes = Vec::new();
        let hash = if audited {
            reserve(&mut ledger, &mut bytes, &first)
        } else {
            append(
                &mut ledger,
                &mut bytes,
                Record::Reservation {
                    operation: Box::new(first.operation),
                },
            )
        };
        complete(
            &mut ledger,
            &mut bytes,
            &hash,
            true,
            PolicyPosition::Before,
            true,
        );
        let ledger = Ledger::load(&bytes, ENROLLMENT).unwrap();
        let next = reservation(&scope, 2, "baseline", "probe_read");
        if audited {
            assert_eq!(ledger.check_reserve(&next.operation), Err(Error::Conflict));
            let mut drift = next;
            drift.profile_digest = format!("sha256:{}", "9".repeat(64));
            assert_eq!(ledger.check_audited(&drift), Err(Error::Conflict));
        } else {
            assert_eq!(ledger.check_audited(&next), Err(Error::Conflict));
        }
    }
}

#[test]
fn actual_replay_zero_send_consumes_slot_and_unknown_cleanup_stays_blocking() {
    let scope = scope();
    for clean in [false, true] {
        let mut ledger = Ledger::load(&[], ENROLLMENT).unwrap();
        let mut bytes = Vec::new();
        let inspected = reservation(&scope, 1, "inspect", "inspect_policy");
        let hash = reserve(&mut ledger, &mut bytes, &inspected);
        complete(
            &mut ledger,
            &mut bytes,
            &hash,
            true,
            PolicyPosition::Before,
            true,
        );
        let probe = reservation(&scope, 2, "baseline", "probe_read");
        let hash = reserve(&mut ledger, &mut bytes, &probe);
        complete(
            &mut ledger,
            &mut bytes,
            &hash,
            false,
            PolicyPosition::Unknown,
            clean,
        );
        let ledger = Ledger::load(&bytes, ENROLLMENT).unwrap();
        assert_eq!(ledger.requests[&probe.operation.request_digest].debits, 0);
        let mut retry = reservation(&scope, 3, "baseline", "probe_read");
        retry.operation.operation_id = "replacement-probe".into();
        assert_eq!(
            ledger.check_audited(&retry),
            Err(if clean {
                Error::AlreadyReserved
            } else {
                Error::RecoveryRequired
            })
        );
    }
}

#[test]
fn malformed_completion_does_not_install_a_result_digest_on_original_retained_row() {
    let scope = scope();
    let mut ledger = Ledger::load(&[], ENROLLMENT).unwrap();
    let mut bytes = Vec::new();
    let raw = reservation(&scope, 1, "inspect", "inspect_policy");
    let hash = reserve(&mut ledger, &mut bytes, &raw);
    let result = ledger.apply(
        Record::Completion {
            reservation_digest: hash,
            result_digest: canonical_hash(&json!({"synthetic_result":true})),
            observed: true,
            policy_position: PolicyPosition::Before,
            cleanup_verified: true,
            fixture_position: None,
        },
        format!("sha256:{}", "5".repeat(64)),
    );
    assert_eq!(result, Err(Error::Corrupt)); // No original send was debited.
    let row = &ledger.requests[&raw.operation.request_digest];
    assert!(row.completion.is_none() && row.completion_result_digest.is_none());
}

#[test]
fn legacy_entry_bytes_and_hash_are_exactly_the_original_variant() {
    let scope = scope();
    let raw = reservation(&scope, 1, "inspect", "inspect_policy");
    let ledger = Ledger::load(&[], ENROLLMENT).unwrap();
    let old = json!({"schema_version":SCHEMA,"sequence":1,"previous_hash":ledger.previous_hash,
        "record":{"kind":"reservation","operation":raw.operation}});
    let entry: Entry = serde_json::from_value(old.clone()).unwrap();
    let (hash, bytes) = crate::s3_reservation::encode_entry(entry).unwrap();
    assert_eq!(bytes, format!("{}\n", canonical_json(&old)).into_bytes());
    assert_eq!(hash, canonical_hash(&old));
    assert!(Ledger::load(&bytes, ENROLLMENT).is_ok());
}

#[test]
fn connected_journal_first_inspect_rechecks_thirty_eight_call_bound() {
    for (limit, accepted) in [(37, false), (38, true)] {
        let mut scope = scope();
        scope.limits.api_calls = limit;
        let raw = reservation(&scope, 1, "inspect", "inspect_policy");
        let mut ledger = Ledger::load(&[], ENROLLMENT).unwrap();
        assert_eq!(ledger.check_audited(&raw).is_ok(), accepted);
        if !accepted {
            assert!(ledger
                .apply(
                    Record::AuditedReservation {
                        reservation: Box::new(raw)
                    },
                    format!("sha256:{}", "5".repeat(64))
                )
                .is_err());
            assert!(ledger.requests.is_empty() && ledger.order.is_empty());
        }
    }
}
