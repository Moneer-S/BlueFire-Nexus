use super::*;
use crate::s3_admission::tests::{checked, fixture, reseal};
use serde_json::json;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
pub(crate) struct Directory {
    pub(crate) path: PathBuf,
    identity: (u64, u64),
}
impl Directory {
    pub(crate) fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "bluefire-s3-ledger-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let meta = fs::symlink_metadata(&path).unwrap();
        assert_ne!(
            meta.uid(),
            0,
            "native storage tests need the owned non-root user"
        );
        Self {
            path,
            identity: (meta.dev(), meta.ino()),
        }
    }
    pub(crate) fn admission(&self) -> VerifiedS3Admission {
        let mut value = fixture();
        value["admission"]["host"]["ledger_root"] = json!(self.path);
        value["admission"]["host"]["owner_uid"] =
            json!(fs::symlink_metadata(&self.path).unwrap().uid());
        reseal(&mut value);
        checked(&value).unwrap()
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let meta = fs::symlink_metadata(&self.path).unwrap();
        assert_eq!((meta.dev(), meta.ino()), self.identity);
        assert!(meta.is_dir());
        fs::remove_dir_all(&self.path).unwrap();
    }
}
pub(crate) fn now() -> DateTime<FixedOffset> {
    DateTime::parse_from_rfc3339("2026-10-09T00:00:01Z").unwrap()
}
pub(crate) fn send(admission: &VerifiedS3Admission, sequence: u64) -> Vec<u8> {
    let mut row = json!({"kind":"send", "request_digest":admission.binding().digest(),
        "sequence":sequence,"send":admission.binding().planned_send(sequence as usize).unwrap()});
    row["send_digest"] = json!(canonical_hash(&row));
    let mut bytes = canonical_json(&row).into_bytes();
    bytes.push(b'\n');
    bytes
}

#[test]
fn exclusive_lease_and_replay_never_reissue_dispatch() {
    let directory = Directory::new();
    let admission = directory.admission();
    let store = S3ReservationStore::open(&admission).unwrap();
    let second = S3ReservationStore::open(&admission).unwrap();
    let reserved = store.reserve(&admission, now()).unwrap();
    assert!(second.reserve(&admission, now()).is_err());
    drop(reserved);
    assert_eq!(
        store.reserve(&admission, now()).err(),
        Some(Error::AlreadyReserved)
    );
}

#[test]
fn debit_is_on_disk_before_the_permit_and_is_not_refunded_on_drop() {
    let directory = Directory::new();
    let admission = directory.admission();
    let store = S3ReservationStore::open(&admission).unwrap();
    let mut reserved = store.reserve(&admission, now()).unwrap();
    let permit = reserved.debit(&send(&admission, 1), now()).unwrap();
    assert_eq!(permit["sequence"], 1);
    let bytes = fs::read(directory.path.join("reservations.jsonl")).unwrap();
    // The storage header is followed by the hash-chained entries.
    let header_end = bytes.iter().position(|byte| *byte == b'\n').unwrap() + 1;
    let ledger = Ledger::load(&bytes[header_end..], admission.enrollment_digest()).unwrap();
    assert_eq!(ledger.requests[admission.binding().digest()].debits, 1);
    assert!(reserved.debit(&send(&admission, 1), now()).is_err());
    drop(reserved); // Deliberately model losing the already-produced permit.
    assert_eq!(
        store.reserve(&admission, now()).err(),
        Some(Error::AlreadyReserved)
    );
}

#[test]
fn expired_send_never_appends_a_debit() {
    let directory = Directory::new();
    let admission = directory.admission();
    let store = S3ReservationStore::open(&admission).unwrap();
    let mut reserved = store.reserve(&admission, now()).unwrap();
    assert_eq!(
        reserved
            .debit(&send(&admission, 1), admission.expires_at())
            .err(),
        Some(Error::Expired)
    );
    assert_eq!(reserved.send_debits(), 0);
}

fn operation(index: u64, phase: &str, operation: &str) -> Reserved {
    Reserved {
        workflow_id: "workflow".into(),
        operation_id: format!("operation-{index}"),
        environment_id: "environment".into(),
        resource_key: format!("sha256:{}", "1".repeat(64)),
        scope_digest: format!("sha256:{}", "2".repeat(64)),
        request_digest: format!("sha256:{index:064x}"),
        request_id: format!("{index:064x}"),
        launch_id: format!("{:064x}", index + 100),
        approval_digest: format!("sha256:{}", "3".repeat(64)),
        runtime_digest: format!("sha256:{}", "4".repeat(64)),
        worker_generation: format!("sha256:{}", "5".repeat(64)),
        phase: phase.into(),
        operation: operation.into(),
        revision: index,
        max_sends: match operation {
            "inspect_policy" | "reconcile_policy" => 2,
            "legitimate_read" => 5,
            _ => 4,
        },
        api_limit: 300,
        session_limit: 6,
        business_attempt_limit: 6,
    }
}
fn reserve_state(ledger: &mut Ledger, row: Reserved) -> String {
    let hash = canonical_hash(&serde_json::to_value(&row).unwrap());
    ledger
        .apply(
            Record::Reservation {
                operation: Box::new(row),
            },
            hash.clone(),
        )
        .unwrap();
    hash
}

#[test]
fn boxed_reservation_preserves_canonical_journal_bytes_and_digest() {
    let operation = operation(1, "inspect", "inspect_policy");
    let before = json!({
        "schema_version": SCHEMA,
        "sequence": 1,
        "previous_hash": "",
        "record": {"kind": "reservation", "operation": operation}
    });
    let entry = Entry {
        schema_version: SCHEMA.into(),
        sequence: 1,
        previous_hash: String::new(),
        record: Record::Reservation {
            operation: Box::new(operation),
        },
    };
    let encoded = serde_json::to_value(&entry).unwrap();
    assert_eq!(canonical_json(&encoded), canonical_json(&before));
    assert_eq!(canonical_hash(&encoded), canonical_hash(&before));
    let restored: Entry = serde_json::from_str(&canonical_json(&before)).unwrap();
    let restored = serde_json::to_value(restored).unwrap();
    assert_eq!(canonical_json(&restored), canonical_json(&before));
    assert_eq!(canonical_hash(&restored), canonical_hash(&before));
}
fn complete_state(ledger: &mut Ledger, hash: &str, position: PolicyPosition) {
    ledger
        .apply(
            Record::Debit {
                reservation_digest: hash.into(),
                sequence: 1,
                preview_digest: format!("sha256:{}", "6".repeat(64)),
                is_write: false,
            },
            String::new(),
        )
        .unwrap();
    ledger
        .apply(
            Record::Completion {
                reservation_digest: hash.into(),
                result_digest: format!("sha256:{}", "7".repeat(64)),
                observed: true,
                policy_position: position,
                cleanup_verified: true,
            },
            String::new(),
        )
        .unwrap();
}

fn complete_failed(ledger: &mut Ledger, hash: &str, cleanup_verified: bool) {
    ledger
        .apply(
            Record::Completion {
                reservation_digest: hash.into(),
                result_digest: format!("sha256:{}", "7".repeat(64)),
                observed: false,
                policy_position: PolicyPosition::Unknown,
                cleanup_verified,
            },
            String::new(),
        )
        .unwrap();
}

#[test]
fn lost_write_ack_is_reconcile_only_and_cannot_be_replayed() {
    let mut ledger = Ledger::load(&[], &format!("sha256:{}", "e".repeat(64))).unwrap();
    for (index, phase, operation) in [
        (1, "inspect", "inspect_policy"),
        (2, "baseline", "probe_read"),
        (3, "baseline", "legitimate_read"),
    ] {
        let hash = reserve_state(&mut ledger, self::operation(index, phase, operation));
        complete_state(&mut ledger, &hash, PolicyPosition::Before);
    }
    let hash = reserve_state(&mut ledger, operation(4, "apply", "apply_policy"));
    for sequence in 1..=3 {
        ledger
            .apply(
                Record::Debit {
                    reservation_digest: hash.clone(),
                    sequence,
                    preview_digest: format!("sha256:{}", "6".repeat(64)),
                    is_write: sequence == 3,
                },
                String::new(),
            )
            .unwrap();
    }
    complete_failed(&mut ledger, &hash, true);
    assert_eq!(
        ledger.check_reserve(&operation(5, "apply", "apply_policy")),
        Err(Error::ReconcileRequired)
    );
    assert_eq!(
        ledger.check_reserve(&operation(5, "rollback", "rollback_policy")),
        Err(Error::ReconcileRequired)
    );
    assert_eq!(
        ledger.check_reserve(&operation(5, "retest", "probe_read")),
        Err(Error::ReconcileRequired)
    );
    let reconcile = reserve_state(&mut ledger, operation(5, "reconcile", "reconcile_policy"));
    complete_state(&mut ledger, &reconcile, PolicyPosition::After);
    assert!(ledger
        .check_reserve(&operation(6, "retest", "probe_read"))
        .is_ok());
    assert_eq!(
        ledger.check_reserve(&operation(6, "apply", "apply_policy")),
        Err(Error::Lifecycle)
    );
}

#[test]
fn resource_scope_rebinding_and_phase_skips_fail_closed() {
    let mut ledger = Ledger::load(&[], &format!("sha256:{}", "e".repeat(64))).unwrap();
    assert_eq!(
        ledger.check_reserve(&operation(1, "apply", "apply_policy")),
        Err(Error::Lifecycle)
    );
    let inspect = reserve_state(&mut ledger, operation(1, "inspect", "inspect_policy"));
    complete_state(&mut ledger, &inspect, PolicyPosition::Before);
    let mut changed = operation(2, "baseline", "probe_read");
    changed.scope_digest = format!("sha256:{}", "f".repeat(64));
    assert_eq!(ledger.check_reserve(&changed), Err(Error::Conflict));
}

#[test]
fn fresh_read_retry_uses_new_identity_and_never_refunds_old_reservation() {
    let mut ledger = Ledger::load(&[], &format!("sha256:{}", "e".repeat(64))).unwrap();
    for index in 1..=3 {
        let mut row = operation(index, "inspect", "inspect_policy");
        row.api_limit = 6;
        let hash = reserve_state(&mut ledger, row);
        ledger
            .apply(
                Record::Completion {
                    reservation_digest: hash,
                    result_digest: format!("sha256:{}", "7".repeat(64)),
                    observed: false,
                    policy_position: PolicyPosition::Unknown,
                    cleanup_verified: true,
                },
                String::new(),
            )
            .unwrap();
    }
    let mut next = operation(4, "inspect", "inspect_policy");
    next.api_limit = 6;
    assert_eq!(ledger.check_reserve(&next), Err(Error::Budget));
    assert!(ledger.requests.values().all(|old| old.debits == 0));
}

#[test]
fn apply_requires_complete_retest_and_recovery_budget_before_write() {
    let mut ledger = Ledger::load(&[], &format!("sha256:{}", "e".repeat(64))).unwrap();
    for (index, phase, name) in [
        (1, "inspect", "inspect_policy"),
        (2, "baseline", "probe_read"),
        (3, "baseline", "legitimate_read"),
    ] {
        let mut row = operation(index, phase, name);
        row.api_limit = 31;
        let hash = reserve_state(&mut ledger, row);
        complete_state(&mut ledger, &hash, PolicyPosition::Before);
    }
    let mut apply = operation(4, "apply", "apply_policy");
    apply.api_limit = 31;
    assert_eq!(ledger.check_reserve(&apply), Err(Error::Budget));
}

#[test]
fn reserved_write_without_send_can_only_be_reconciled_not_replayed() {
    let mut ledger = Ledger::load(&[], &format!("sha256:{}", "e".repeat(64))).unwrap();
    for (index, phase, name) in [
        (1, "inspect", "inspect_policy"),
        (2, "baseline", "probe_read"),
        (3, "baseline", "legitimate_read"),
    ] {
        let hash = reserve_state(&mut ledger, operation(index, phase, name));
        complete_state(&mut ledger, &hash, PolicyPosition::Before);
    }
    let hash = reserve_state(&mut ledger, operation(4, "apply", "apply_policy"));
    complete_failed(&mut ledger, &hash, true);
    assert!(ledger
        .check_reserve(&operation(5, "reconcile", "reconcile_policy"))
        .is_ok());
    assert_eq!(
        ledger.check_reserve(&operation(5, "apply", "apply_policy")),
        Err(Error::Lifecycle)
    );
}

#[test]
fn legitimate_health_read_counts_toward_business_attempts_and_apply_floor() {
    let mut ledger = Ledger::load(&[], &format!("sha256:{}", "e".repeat(64))).unwrap();
    for (index, phase, name) in [
        (1, "inspect", "inspect_policy"),
        (2, "baseline", "probe_read"),
        (3, "baseline", "legitimate_read"),
    ] {
        let mut row = operation(index, phase, name);
        row.business_attempt_limit = 5;
        let hash = reserve_state(&mut ledger, row);
        complete_state(&mut ledger, &hash, PolicyPosition::Before);
    }
    let mut apply = operation(4, "apply", "apply_policy");
    apply.business_attempt_limit = 5;
    assert_eq!(ledger.check_reserve(&apply), Err(Error::Budget));
}

#[test]
fn failed_legitimate_reservations_never_refund_either_business_attempt() {
    let mut ledger = Ledger::load(&[], &format!("sha256:{}", "e".repeat(64))).unwrap();
    let inspect = reserve_state(&mut ledger, operation(1, "inspect", "inspect_policy"));
    complete_state(&mut ledger, &inspect, PolicyPosition::Before);
    for index in 2..=4 {
        let hash = reserve_state(&mut ledger, operation(index, "baseline", "legitimate_read"));
        ledger
            .apply(
                Record::Completion {
                    reservation_digest: hash,
                    result_digest: format!("sha256:{}", "7".repeat(64)),
                    observed: false,
                    policy_position: PolicyPosition::Unknown,
                    cleanup_verified: true,
                },
                String::new(),
            )
            .unwrap();
    }
    assert_eq!(
        ledger.check_reserve(&operation(5, "baseline", "legitimate_read")),
        Err(Error::Budget)
    );
    assert_eq!(
        ledger.check_reserve(&operation(5, "baseline", "probe_read")),
        Err(Error::Budget)
    );
    assert_eq!(
        ledger
            .requests
            .values()
            .filter(|old| old.reserved.operation == "legitimate_read")
            .map(|old| old.debits)
            .sum::<u64>(),
        0
    );
}

#[test]
fn orphaned_or_cleanup_unknown_worker_blocks_even_read_only_reconciliation() {
    for unknown_completion in [false, true] {
        let mut ledger = Ledger::load(&[], &format!("sha256:{}", "e".repeat(64))).unwrap();
        for (index, phase, name) in [
            (1, "inspect", "inspect_policy"),
            (2, "baseline", "probe_read"),
            (3, "baseline", "legitimate_read"),
        ] {
            let hash = reserve_state(&mut ledger, operation(index, phase, name));
            complete_state(&mut ledger, &hash, PolicyPosition::Before);
        }
        let hash = reserve_state(&mut ledger, operation(4, "apply", "apply_policy"));
        if unknown_completion {
            complete_failed(&mut ledger, &hash, false);
        }
        for (phase, name) in [
            ("inspect", "inspect_policy"),
            ("reconcile", "reconcile_policy"),
            ("retest", "probe_read"),
            ("rollback", "rollback_policy"),
        ] {
            assert_eq!(
                ledger.check_reserve(&operation(5, phase, name)),
                Err(Error::RecoveryRequired)
            );
        }
    }
}
