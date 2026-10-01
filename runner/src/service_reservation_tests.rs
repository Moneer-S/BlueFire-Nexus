use super::*;

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_host_cannot_initialize_service_state() {
    let error = ServiceReservationStore::open(
        Path::new("unused-service-reservation-root"),
        &format!("sha256:{}", "1".repeat(64)),
        ReservationLimits::default(),
    )
    .err();
    assert_eq!(error, Some(ReservationError::UnsupportedPlatform));
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::service_admission::reservation_test_admission;
    use chrono::{Duration, SecondsFormat};
    use serde_json::{json, Value};
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::{symlink, DirBuilderExt, MetadataExt, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    struct Fixture {
        base: PathBuf,
        root: PathBuf,
        identity: (u64, u64),
        uid: u32,
    }
    impl Fixture {
        fn new() -> Self {
            let base = std::env::temp_dir().join(format!(
                "bluefire-reservation-test-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
            let root = base.join("trusted-state");
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            let metadata = fs::symlink_metadata(&base).unwrap();
            assert_ne!(
                metadata.uid(),
                0,
                "service tests require the owned non-root test user"
            );
            Self {
                base,
                root,
                identity: (metadata.dev(), metadata.ino()),
                uid: metadata.uid(),
            }
        }
        fn admission(
            &self,
            task: &str,
            binding: &ServiceOperationBinding,
        ) -> VerifiedServiceAdmission {
            reservation_test_admission(self.uid, task, binding.digest())
        }
        fn binding(&self, index: u8, operation: &str) -> ServiceOperationBinding {
            let admission = reservation_test_admission(self.uid, "fixture-task", &hash('a'));
            let identity = json!({
                "schema_version": "bluefire.owned-user-service.v1", "authorization_digest": admission.scope_digest(),
                "runner_profile_id": admission.runner_profile_id(), "workspace_id": admission.workspace_id(), "target_scope_digest": admission.target_scope_digest(),
                "owner_uid": admission.owner_uid(), "boot_id": admission.boot_id(), "manager_id": admission.manager_id(), "unit_nonce": admission.unit_nonce(),
                "unit_content_digest": admission.unit_content_digest(), "created_at": admission.created_at().to_rfc3339_opts(SecondsFormat::Micros, true),
                "cleanup_due_at": admission.cleanup_expires_at().to_rfc3339_opts(SecondsFormat::Micros, true),
            });
            parse(json!({
                "schema_version": crate::service_operation_binding::SCHEMA,
                "identity_digest": canonical_hash(&identity), "identity": identity,
                "journal_request_id": "journal-reservation-test", "journal_revision": index * 2 + 1,
                "journal_record_hash": hash('b'), "operation_id": format!("op-{:032x}", index + 1), "operation": operation,
                "reviewed_scope_digest": admission.scope_digest(), "manager_installation_digest": admission.manager_installation_digest(),
                "payload_installation_digest": admission.payload_installation_digest(),
            }))
        }
        fn open(&self, limits: ReservationLimits) -> ServiceReservationStore {
            let admission = reservation_test_admission(self.uid, "fixture-task", &hash('a'));
            ServiceReservationStore::open(&self.root, admission.enrollment_digest(), limits)
                .unwrap()
        }
        fn now(&self) -> DateTime<FixedOffset> {
            reservation_test_admission(self.uid, "fixture-task", &hash('a')).created_at()
                + Duration::seconds(1)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Ok(metadata) = fs::symlink_metadata(&self.base) {
                if metadata.is_dir() && (metadata.dev(), metadata.ino()) == self.identity {
                    fs::remove_dir_all(&self.base).unwrap();
                }
            }
        }
    }
    fn hash(letter: char) -> String {
        format!("sha256:{}", letter.to_string().repeat(64))
    }
    fn parse(value: Value) -> ServiceOperationBinding {
        ServiceOperationBinding::from_json(&serde_json::to_vec(&value).unwrap()).unwrap()
    }
    fn changed(
        binding: &ServiceOperationBinding,
        change: impl FnOnce(&mut Value),
    ) -> ServiceOperationBinding {
        let mut value: Value = serde_json::from_str(binding.canonical_json()).unwrap();
        change(&mut value);
        value["identity_digest"] = json!(canonical_hash(&value["identity"]));
        parse(value)
    }
    fn reserve(
        fixture: &Fixture,
        store: &ServiceReservationStore,
        index: u8,
        operation: &str,
    ) -> ServiceReservation {
        let binding = fixture.binding(index, operation);
        match store
            .reserve(
                &fixture.admission(&format!("task-{index}"), &binding),
                &binding,
                fixture.now(),
            )
            .unwrap()
        {
            ReservationDecision::Reserved(permit) => permit.into_record(),
            _ => panic!("expected a new durable reservation"),
        }
    }
    fn reconcile(
        store: &ServiceReservationStore,
        reservation: &ServiceReservation,
        disposition: ReconciledDisposition,
    ) {
        // Test-only independent-observation witness, never a production token
        // constructor or a claim that filesystem tests observed a real service.
        store
            .reconcile(
                reservation,
                VerifiedServiceReconciliation {
                    reservation_digest: reservation.digest.clone(),
                    disposition,
                    observation_digest: hash('c'),
                },
            )
            .unwrap();
    }

    #[test]
    fn restart_retains_uncertainty_and_never_reissues_a_dispatch_permit() {
        let fixture = Fixture::new();
        let store = fixture.open(ReservationLimits::default());
        let binding = fixture.binding(0, "create_unit");
        let admission = fixture.admission("task-0", &binding);
        let first = reserve(&fixture, &store, 0, "create_unit");
        drop(store); // interruption after fsync, before any effect or result
        let restarted = fixture.open(ReservationLimits::default());
        match restarted
            .reserve(&admission, &binding, fixture.now())
            .unwrap()
        {
            ReservationDecision::Existing { reservation, state } => {
                assert_eq!(reservation, first);
                assert_eq!(state, ReservationState::Uncertain);
            }
            _ => panic!("interruption must not replay setup"),
        }
        let next = fixture.binding(1, "reload");
        assert_eq!(
            restarted
                .reserve(&fixture.admission("task-1", &next), &next, fixture.now())
                .err(),
            Some(ReservationError::PriorUncertain)
        );
        assert_eq!(
            restarted.inspect(first.operation_id()).unwrap(),
            Some((first, ReservationState::Uncertain))
        );
    }

    #[test]
    fn concurrent_reservations_issue_exactly_one_permit() {
        let fixture = Fixture::new();
        let store = Arc::new(fixture.open(ReservationLimits::default()));
        let barrier = Arc::new(Barrier::new(8));
        let binding = fixture.binding(0, "create_unit");
        let now = fixture.now();
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let (store, barrier, binding, uid) =
                    (store.clone(), barrier.clone(), binding.clone(), fixture.uid);
                std::thread::spawn(move || {
                    let admission = reservation_test_admission(uid, "same-task", binding.digest());
                    barrier.wait();
                    match store.reserve(&admission, &binding, now) {
                        Ok(ReservationDecision::Reserved(_)) => 1,
                        Ok(ReservationDecision::Existing { .. }) | Err(ReservationError::Busy) => 0,
                        result => panic!("unexpected concurrent reservation result: {result:?}"),
                    }
                })
            })
            .collect();
        assert_eq!(
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .sum::<usize>(),
            1
        );
        assert_eq!(
            store
                .inspect("op-00000000000000000000000000000001")
                .unwrap()
                .unwrap()
                .1,
            ReservationState::Uncertain
        );
    }

    #[test]
    fn same_operation_refuses_changed_task_grant_or_journal_request() {
        let fixture = Fixture::new();
        let store = fixture.open(ReservationLimits::default());
        let binding = fixture.binding(0, "create_unit");
        reserve(&fixture, &store, 0, "create_unit");
        assert_eq!(
            store
                .reserve(
                    &fixture.admission("different-task", &binding),
                    &binding,
                    fixture.now()
                )
                .err(),
            Some(ReservationError::OperationConflict)
        );
        for field in ["journal_request_id", "journal_record_hash"] {
            let modified = changed(&binding, |value| {
                value[field] = json!(if field == "journal_record_hash" {
                    hash('f')
                } else {
                    "other-request".into()
                })
            });
            assert_eq!(
                store
                    .reserve(
                        &fixture.admission("task-0", &modified),
                        &modified,
                        fixture.now()
                    )
                    .err(),
                Some(ReservationError::OperationConflict)
            );
        }
    }

    #[test]
    fn manager_or_boot_change_cannot_rekey_a_retained_unit_name() {
        let fixture = Fixture::new();
        let store = fixture.open(ReservationLimits::default());
        let binding = fixture.binding(0, "create_unit");
        reserve(&fixture, &store, 0, "create_unit");
        let before = BindingProjection::parse(&binding).unwrap();
        let mut lease = store.storage.lease().unwrap();
        let ledger = Ledger::load(
            &lease.read().unwrap(),
            &store.enrollment_digest,
            store.limits.max_records,
        )
        .unwrap();
        for (field, value) in [
            ("manager_id", "f".repeat(32)),
            ("boot_id", "99999999-2222-3333-4444-555555555555".into()),
        ] {
            let modified = changed(&fixture.binding(1, "reload"), |document| {
                document["identity"][field] = json!(value)
            });
            let after = BindingProjection::parse(&modified).unwrap();
            assert_eq!(after.resource_key(), before.resource_key());
            assert_eq!(
                ledger.check_next(&after),
                Err(ReservationError::ResourceConflict)
            );
        }
    }

    #[test]
    fn all_reviewed_resource_and_installation_mismatches_refuse_before_reservation() {
        let fixture = Fixture::new();
        let store = fixture.open(ReservationLimits::default());
        let binding = fixture.binding(0, "create_unit");
        let before = fs::read(fixture.root.join("reservations.jsonl")).unwrap();
        for (field, value) in [
            ("authorization_digest", json!(hash('f'))),
            ("runner_profile_id", json!("other-profile")),
            ("workspace_id", json!("other-workspace")),
            ("target_scope_digest", json!(hash('f'))),
            ("owner_uid", json!(fixture.uid + 1)),
            ("boot_id", json!("99999999-2222-3333-4444-555555555555")),
            ("manager_id", json!("f".repeat(32))),
            ("unit_nonce", json!("e".repeat(32))),
            ("unit_content_digest", json!(hash('f'))),
        ] {
            let modified = changed(&binding, |document| document["identity"][field] = value);
            assert_eq!(
                store
                    .reserve(
                        &fixture.admission("task-0", &modified),
                        &modified,
                        fixture.now()
                    )
                    .err(),
                Some(ReservationError::AdmissionMismatch),
                "{field}"
            );
        }
        for field in [
            "reviewed_scope_digest",
            "manager_installation_digest",
            "payload_installation_digest",
        ] {
            let modified = changed(&binding, |document| document[field] = json!(hash('f')));
            assert_eq!(
                store
                    .reserve(
                        &fixture.admission("task-0", &modified),
                        &modified,
                        fixture.now()
                    )
                    .err(),
                Some(ReservationError::AdmissionMismatch),
                "{field}"
            );
        }
        for field in ["created_at", "cleanup_due_at"] {
            let modified = changed(&binding, |document| {
                let before =
                    DateTime::parse_from_rfc3339(document["identity"][field].as_str().unwrap())
                        .unwrap();
                let after = if field == "created_at" {
                    before + Duration::seconds(1)
                } else {
                    before - Duration::seconds(1)
                };
                document["identity"][field] =
                    json!(after.to_rfc3339_opts(SecondsFormat::Micros, true));
            });
            assert_eq!(
                store
                    .reserve(
                        &fixture.admission("task-0", &modified),
                        &modified,
                        fixture.now()
                    )
                    .err(),
                Some(ReservationError::AdmissionMismatch),
                "{field}"
            );
        }
        let modified = changed(&binding, |document| {
            document["journal_record_hash"] = json!(hash('f'))
        });
        assert_eq!(
            store
                .reserve(
                    &fixture.admission("task-0", &binding),
                    &modified,
                    fixture.now()
                )
                .err(),
            Some(ReservationError::AdmissionMismatch)
        );
        assert_eq!(
            fs::read(fixture.root.join("reservations.jsonl")).unwrap(),
            before
        );
    }

    #[test]
    fn process_results_do_not_clear_uncertainty_or_authorize_setup_retry() {
        for outcome in [
            ReportedOutcome::Succeeded,
            ReportedOutcome::Failed,
            ReportedOutcome::Unknown,
        ] {
            let fixture = Fixture::new();
            let store = fixture.open(ReservationLimits::default());
            let first = reserve(&fixture, &store, 0, "create_unit");
            store.record_outcome(&first, outcome, &hash('d')).unwrap();
            store.record_outcome(&first, outcome, &hash('d')).unwrap(); // exact metadata retry
            let next = fixture.binding(1, "reload");
            assert_eq!(
                store
                    .reserve(&fixture.admission("next", &next), &next, fixture.now())
                    .err(),
                Some(ReservationError::PriorUncertain)
            );
            reconcile(&store, &first, ReconciledDisposition::OperationFailed);
            assert_eq!(
                store
                    .reserve(&fixture.admission("next", &next), &next, fixture.now())
                    .err(),
                Some(ReservationError::LifecycleRefused)
            );
            let retry = fixture.binding(1, "create_unit");
            assert_eq!(
                store
                    .reserve(&fixture.admission("retry", &retry), &retry, fixture.now())
                    .err(),
                Some(ReservationError::LifecycleRefused)
            );
            reserve(&fixture, &store, 1, "stop");
        }
    }

    #[test]
    fn complete_lifecycle_retains_tombstones_and_distinguishes_cleanup_observation() {
        let fixture = Fixture::new();
        let store = fixture.open(ReservationLimits::default());
        let mut final_record = None;
        for (index, operation) in SETUP.into_iter().chain(CLEANUP).enumerate() {
            let reservation = reserve(&fixture, &store, index as u8, operation);
            store
                .record_outcome(&reservation, ReportedOutcome::Succeeded, &hash('d'))
                .unwrap();
            assert_eq!(
                store
                    .inspect(reservation.operation_id())
                    .unwrap()
                    .unwrap()
                    .1,
                ReservationState::Uncertain
            );
            if operation != "reload_after_cleanup" {
                reconcile(
                    &store,
                    &reservation,
                    ReconciledDisposition::OperationSucceeded,
                );
            } else {
                final_record = Some(reservation);
            }
        }
        let final_record = final_record.unwrap();
        reconcile(
            &store,
            &final_record,
            ReconciledDisposition::OperationSucceeded,
        );
        assert_eq!(
            store
                .inspect(final_record.operation_id())
                .unwrap()
                .unwrap()
                .1,
            ReservationState::Reconciled(ReconciledDisposition::OperationSucceeded)
        );
        reconcile(
            &store,
            &final_record,
            ReconciledDisposition::CleanupComplete,
        );
        drop(store);
        let store = fixture.open(ReservationLimits::default());
        assert_eq!(
            store
                .inspect(final_record.operation_id())
                .unwrap()
                .unwrap()
                .1,
            ReservationState::Reconciled(ReconciledDisposition::CleanupComplete)
        );
        let restart = fixture.binding(9, "create_unit");
        assert_eq!(
            store
                .reserve(
                    &fixture.admission("restart", &restart),
                    &restart,
                    fixture.now()
                )
                .err(),
            Some(ReservationError::LifecycleRefused)
        );
        let original = fixture.binding(0, "create_unit");
        assert!(matches!(
            store
                .reserve(
                    &fixture.admission("task-0", &original),
                    &original,
                    fixture.now()
                )
                .unwrap(),
            ReservationDecision::Existing { .. }
        ));
        assert_eq!(
            fs::read_to_string(fixture.root.join("reservations.jsonl"))
                .unwrap()
                .lines()
                .count(),
            29
        );
    }

    #[test]
    fn finite_setup_and_cleanup_expiry_are_independent_and_never_renewed() {
        let fixture = Fixture::new();
        let store = fixture.open(ReservationLimits::default());
        let create = fixture.binding(0, "create_unit");
        let admission = fixture.admission("task-0", &create);
        assert_eq!(
            store
                .reserve(
                    &admission,
                    &create,
                    admission.created_at() - Duration::microseconds(1)
                )
                .err(),
            Some(ReservationError::Expired)
        );
        assert_eq!(
            store
                .reserve(&admission, &create, admission.setup_expires_at())
                .err(),
            Some(ReservationError::Expired)
        );
        let created = reserve(&fixture, &store, 0, "create_unit");
        reconcile(&store, &created, ReconciledDisposition::OperationFailed);
        let cleanup = fixture.binding(1, "stop");
        let cleanup_admission = fixture.admission("cleanup", &cleanup);
        assert!(matches!(
            store
                .reserve(&cleanup_admission, &cleanup, admission.setup_expires_at())
                .unwrap(),
            ReservationDecision::Reserved(_)
        ));
        assert_eq!(
            store
                .reserve(&cleanup_admission, &cleanup, admission.cleanup_expires_at())
                .err(),
            Some(ReservationError::Expired)
        );
    }

    #[test]
    fn limits_fail_closed_without_eviction_or_reinitializing_tombstones() {
        let fixture = Fixture::new();
        let store = fixture.open(ReservationLimits {
            max_records: 1,
            ..ReservationLimits::default()
        });
        let first = reserve(&fixture, &store, 0, "create_unit");
        let before = fs::read(fixture.root.join("reservations.jsonl")).unwrap();
        assert_eq!(
            store.record_outcome(&first, ReportedOutcome::Succeeded, &hash('d')),
            Err(ReservationError::StorageFull)
        );
        assert_eq!(
            fs::read(fixture.root.join("reservations.jsonl")).unwrap(),
            before
        );
        drop(store);
        let store = fixture.open(ReservationLimits {
            max_records: 1,
            ..ReservationLimits::default()
        });
        assert_eq!(
            store.inspect(first.operation_id()).unwrap().unwrap().1,
            ReservationState::Uncertain
        );
        fs::OpenOptions::new()
            .append(true)
            .open(fixture.root.join("reservations.jsonl"))
            .unwrap()
            .write_all(&vec![b' '; 1024 * 1024])
            .unwrap();
        assert_eq!(
            store.inspect(first.operation_id()).err(),
            Some(ReservationError::StorageFull)
        );
    }

    #[test]
    fn interrupted_append_and_existing_empty_store_never_reinitialize() {
        for tail in [b"{".as_slice(), b"\n".as_slice()] {
            let fixture = Fixture::new();
            let store = fixture.open(ReservationLimits::default());
            let first = reserve(&fixture, &store, 0, "create_unit");
            fs::OpenOptions::new()
                .append(true)
                .open(fixture.root.join("reservations.jsonl"))
                .unwrap()
                .write_all(tail)
                .unwrap();
            assert_eq!(
                store.inspect(first.operation_id()).err(),
                Some(ReservationError::StorageCorrupt)
            );
            let before = fs::read(fixture.root.join("reservations.jsonl")).unwrap();
            let admission = fixture.admission("task", &fixture.binding(0, "create_unit"));
            assert_eq!(
                ServiceReservationStore::open(
                    &fixture.root,
                    admission.enrollment_digest(),
                    ReservationLimits::default()
                )
                .err(),
                Some(ReservationError::StorageCorrupt)
            );
            assert_eq!(
                fs::read(fixture.root.join("reservations.jsonl")).unwrap(),
                before
            );
        }
        let fixture = Fixture::new();
        fixture.open(ReservationLimits::default());
        fs::write(fixture.root.join("reservations.jsonl"), b"").unwrap();
        let admission = fixture.admission("task", &fixture.binding(0, "create_unit"));
        assert_eq!(
            ServiceReservationStore::open(
                &fixture.root,
                admission.enrollment_digest(),
                ReservationLimits::default()
            )
            .err(),
            Some(ReservationError::StorageCorrupt)
        );
    }

    #[test]
    fn canonical_but_unreconciled_next_operation_is_refused_during_recovery() {
        let fixture = Fixture::new();
        let store = fixture.open(ReservationLimits::default());
        let first = reserve(&fixture, &store, 0, "create_unit");
        let binding = fixture.binding(1, "reload");
        let admission = fixture.admission("task-1", &binding);
        // A syntactically valid append with a coherent hash chain must not
        // bypass the exact same uncertainty guard applied before live dispatch.
        let entry = LedgerEntry {
            schema_version: SCHEMA.into(),
            sequence: 2,
            previous_hash: first.digest.clone(),
            record: Record::Reservation {
                operation: ReservedOperation {
                    binding: binding.canonical_json().into(),
                    binding_digest: binding.digest().into(),
                    resource_key: first.resource_key().into(),
                    operation_id: BindingProjection::parse(&binding).unwrap().operation_id,
                    grant_digest: admission.grant_digest().into(),
                    task_id: admission.task_id().into(),
                    enrollment_digest: admission.enrollment_digest().into(),
                },
            },
        };
        let mut bytes = encoded(&entry).unwrap();
        bytes.push(b'\n');
        let ledger = fixture.root.join("reservations.jsonl");
        fs::OpenOptions::new()
            .append(true)
            .open(&ledger)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
        let before = fs::read(&ledger).unwrap();
        assert_eq!(
            store.inspect(first.operation_id()).err(),
            Some(ReservationError::StorageCorrupt)
        );
        drop(store);
        assert_eq!(
            ServiceReservationStore::open(
                &fixture.root,
                admission.enrollment_digest(),
                ReservationLimits::default()
            )
            .err(),
            Some(ReservationError::StorageCorrupt)
        );
        assert_eq!(fs::read(ledger).unwrap(), before);
    }

    #[test]
    fn storage_refuses_permissions_links_replacements_and_enrollment_changes() {
        let fixture = Fixture::new();
        let store = fixture.open(ReservationLimits::default());
        let binding = fixture.binding(0, "create_unit");
        let admission = fixture.admission("task", &binding);
        assert_eq!(
            ServiceReservationStore::open(&fixture.root, &hash('f'), ReservationLimits::default())
                .err(),
            Some(ReservationError::StorageCorrupt)
        );
        let alias = fixture.base.join("alias");
        symlink(&fixture.root, &alias).unwrap();
        assert_eq!(
            ServiceReservationStore::open(
                &alias,
                admission.enrollment_digest(),
                ReservationLimits::default()
            )
            .err(),
            Some(ReservationError::StorageUnsafe)
        );
        fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o750)).unwrap();
        assert_eq!(
            store.reserve(&admission, &binding, fixture.now()).err(),
            Some(ReservationError::StorageUnsafe)
        );
        fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o700)).unwrap();
        let ledger = fixture.root.join("reservations.jsonl");
        fs::set_permissions(&ledger, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            store.reserve(&admission, &binding, fixture.now()).err(),
            Some(ReservationError::StorageUnsafe)
        );
        fs::set_permissions(&ledger, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&ledger, fixture.base.join("hardlink")).unwrap();
        assert_eq!(
            store.reserve(&admission, &binding, fixture.now()).err(),
            Some(ReservationError::StorageUnsafe)
        );
        fs::remove_file(fixture.base.join("hardlink")).unwrap();
        fs::rename(&ledger, fixture.root.join("original.jsonl")).unwrap();
        fs::copy(fixture.root.join("original.jsonl"), &ledger).unwrap();
        assert_eq!(
            store.reserve(&admission, &binding, fixture.now()).err(),
            Some(ReservationError::StorageUnsafe)
        );
    }

    #[test]
    fn storage_refuses_swapped_root_and_symbolic_ledger_without_touching_replacements() {
        let fixture = Fixture::new();
        let store = fixture.open(ReservationLimits::default());
        let ledger = fixture.root.join("reservations.jsonl");
        let original = fixture.root.join("original.jsonl");
        fs::rename(&ledger, &original).unwrap();
        symlink(&original, &ledger).unwrap();
        assert_eq!(
            store.inspect("unused").err(),
            Some(ReservationError::StorageUnsafe)
        );
        fs::remove_file(&ledger).unwrap();
        fs::rename(&original, &ledger).unwrap();
        let previous = fixture.base.join("previous-root");
        fs::rename(&fixture.root, &previous).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&fixture.root)
            .unwrap();
        assert_eq!(
            store.inspect("unused").err(),
            Some(ReservationError::StorageUnsafe)
        );
        assert_eq!(fs::read_dir(&fixture.root).unwrap().count(), 0);
    }

    #[test]
    fn cleanup_cannot_claim_unreserved_resource_or_use_unrelated_reconciliation() {
        let fixture = Fixture::new();
        let store = fixture.open(ReservationLimits::default());
        let binding = fixture.binding(0, "stop");
        assert_eq!(
            store
                .reserve(
                    &fixture.admission("cleanup", &binding),
                    &binding,
                    fixture.now()
                )
                .err(),
            Some(ReservationError::LifecycleRefused)
        );
        let first = reserve(&fixture, &store, 0, "create_unit");
        assert_eq!(
            store.reconcile(
                &first,
                VerifiedServiceReconciliation {
                    reservation_digest: first.digest.clone(),
                    disposition: ReconciledDisposition::CleanupComplete,
                    observation_digest: hash('c')
                }
            ),
            Err(ReservationError::ReconciliationMismatch)
        );
        assert_eq!(
            store.reconcile(
                &first,
                VerifiedServiceReconciliation {
                    reservation_digest: hash('e'),
                    disposition: ReconciledDisposition::OperationSucceeded,
                    observation_digest: hash('c')
                }
            ),
            Err(ReservationError::ReconciliationMismatch)
        );
        assert_eq!(
            store.inspect(first.operation_id()).unwrap().unwrap().1,
            ReservationState::Uncertain
        );
    }
}
