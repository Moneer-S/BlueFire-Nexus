//! Test-only staged collector conversation; public dispatch remains closed.

use super::*;
use crate::reservation_storage::{JournalKind, Storage};
use crate::s3_admission::{
    tests::{checked, reseal},
    VerifiedS3Admission,
};
use crate::s3_reservation::{tests::Directory, S3Reservation, S3ReservationStore};
use crate::s3_worker_protocol::{Chunk, Driver};
use std::collections::VecDeque;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    AppendRefused,
    LostAck,
}

struct Fake<'a> {
    admission: &'a VerifiedS3Admission,
    directory: &'a Directory,
    started: Instant,
    elapsed: Duration,
    incoming: Vec<u8>,
    outgoing: VecDeque<u8>,
    phase: usize,
    reservation: String,
    discovery: Option<Discovery>,
    ended: bool,
    signalled: bool,
    reaped: bool,
    credentials_checked: bool,
    acknowledgement_checked: bool,
    premature_get: bool,
    cleanup_known: bool,
    fault: Fault,
    lost_ack_seen: bool,
}

impl Fake<'_> {
    fn emit(&mut self, value: Value) {
        self.outgoing.extend(canonical_json(&value).bytes());
        self.outgoing.push_back(b'\n');
    }

    fn send(&mut self, sequence: usize) {
        let binding = self.admission.binding();
        let resource = if self.premature_get && sequence == 5 {
            let (_, discovery) = selection(binding, &self.reservation);
            binding
                .audit()
                .unwrap()
                .planned_send(binding, sequence, Some(&discovery))
                .unwrap()
        } else {
            binding
                .audit()
                .unwrap()
                .planned_send(binding, sequence, self.discovery.as_ref())
                .unwrap()
        };
        let mut frame = json!({"kind":"send","request_digest":binding.digest(),"sequence":sequence,"send":resource});
        frame["send_digest"] = json!(canonical_hash(&frame));
        self.emit(frame);
    }

    fn retained(&self) -> (Value, Ledger) {
        let bytes = std::fs::read(self.directory.path.join("reservations.jsonl")).unwrap();
        let header = bytes.iter().position(|byte| *byte == b'\n').unwrap() + 1;
        let row = bytes
            .split(|byte| *byte == b'\n')
            .rfind(|line| !line.is_empty())
            .unwrap();
        (
            serde_json::from_slice(row).unwrap(),
            Ledger::load(&bytes[header..], self.admission.enrollment_digest()).unwrap(),
        )
    }

    fn receive(&mut self, frame: Value) {
        if self.phase == 0 {
            assert_eq!(
                canonical_json(&frame),
                self.admission.binding().canonical_json()
            );
            self.emit(
                json!({"kind":"ready","request_digest":self.admission.binding().digest(),
                "process_id":123,"creation_identity":"456","nonce":"a".repeat(64)}),
            );
            self.phase = 1;
        } else if self.phase == 1 {
            assert_eq!(frame["kind"], "contained");
            self.phase = 2;
        } else if self.phase == 2 {
            assert_eq!(frame["kind"], "credentials");
            assert_eq!(frame["reservation_digest"], self.reservation);
            let (last, ledger) = self.retained();
            assert_eq!(last["record"]["kind"], "audited_reservation");
            assert_eq!(
                ledger.requests[self.admission.binding().digest()].digest,
                self.reservation
            );
            assert_eq!(ledger.requests[self.admission.binding().digest()].debits, 0);
            self.credentials_checked = true;
            self.phase = 3;
            self.send(1);
        } else if frame["kind"] == "permit" {
            let sequence = frame["sequence"].as_u64().unwrap();
            let (last, _) = self.retained();
            assert_eq!(last["record"]["kind"], "debit");
            assert_eq!(last["record"]["sequence"], sequence);
            if sequence < 4 {
                self.send(sequence as usize + 1);
            } else if sequence == 4 {
                if self.premature_get {
                    self.send(5);
                } else {
                    let (bytes, discovery) = selection(self.admission.binding(), &self.reservation);
                    self.discovery = Some(discovery);
                    self.outgoing.extend(bytes);
                }
            } else {
                assert!(self.acknowledgement_checked);
                assert_eq!(sequence, 5);
                let case = json!({"candidate_count":1,"selected_count":1,"size_bytes":100,"truncated":false});
                let result = crate::s3_access_binding::audit::tests::result(
                    self.admission.binding(),
                    &case,
                    self.discovery.as_ref().unwrap(),
                );
                self.emit(json!({"kind":"result","result":result}));
                self.ended = true;
            }
        } else {
            let discovery = self.discovery.as_ref().unwrap();
            assert_eq!(frame, discovery.acknowledgement());
            let (last, ledger) = self.retained();
            assert_eq!(last["record"]["kind"], "audit_discovery");
            assert_eq!(last["record"]["discovery"], *discovery.document());
            assert_eq!(ledger.requests[self.admission.binding().digest()].debits, 4);
            assert_eq!(
                ledger.requests[self.admission.binding().digest()]
                    .discovery
                    .as_ref()
                    .unwrap()
                    .document(),
                discovery.document()
            );
            self.acknowledgement_checked = true;
            self.send(5);
        }
    }
}

impl Driver for Fake<'_> {
    fn now(&self) -> Instant {
        self.started + self.elapsed
    }
    fn wall(&self) -> chrono::DateTime<chrono::FixedOffset> {
        crate::s3_access_scope::utc_time("2026-10-09T00:01:00Z").unwrap()
            + chrono::Duration::from_std(self.elapsed).unwrap()
    }
    fn pause(&mut self, duration: Duration) {
        self.elapsed += duration;
    }
    fn read(&mut self, stderr: bool) -> std::result::Result<Chunk, ()> {
        if !stderr && !self.outgoing.is_empty() {
            Ok(Chunk::Bytes(
                (0..4096)
                    .filter_map(|_| self.outgoing.pop_front())
                    .collect(),
            ))
        } else if self.ended {
            Ok(Chunk::Eof)
        } else {
            Ok(Chunk::Pending)
        }
    }
    fn write(&mut self, bytes: &[u8]) -> std::result::Result<usize, ()> {
        let count = bytes.len().min(997);
        self.incoming.extend_from_slice(&bytes[..count]);
        while let Some(end) = self.incoming.iter().position(|byte| *byte == b'\n') {
            let frame: Vec<_> = self.incoming.drain(..=end).collect();
            let frame: Value = serde_json::from_slice(&frame).unwrap();
            if self.fault == Fault::LostAck && frame["kind"] == "discovery_committed" {
                let (last, ledger) = self.retained();
                assert_eq!(last["record"]["kind"], "audit_discovery");
                assert_eq!(ledger.requests[self.admission.binding().digest()].debits, 4);
                assert_eq!(
                    ledger.requests[self.admission.binding().digest()]
                        .discovery
                        .as_ref()
                        .unwrap()
                        .document(),
                    self.discovery.as_ref().unwrap().document()
                );
                self.lost_ack_seen = true;
                return Err(());
            }
            self.receive(frame);
        }
        Ok(count)
    }
    fn identity(&mut self) -> std::result::Result<(u32, u64), ()> {
        Ok((123, 456))
    }
    fn exited(&mut self) -> std::result::Result<bool, ()> {
        Ok(self.ended)
    }
    fn terminate_group(&mut self) -> bool {
        assert!(!self.reaped);
        self.signalled = true;
        self.ended = true;
        true
    }
    fn reap(&mut self) -> std::result::Result<Option<Option<i32>>, ()> {
        assert!(self.signalled);
        self.reaped = true;
        Ok(Some(Some(0)))
    }
    fn group_absent(&mut self) -> bool {
        self.cleanup_known
    }
}

#[test]
fn staged_native_conversation_commits_before_ack_and_preserves_original_cleanup_barriers() {
    for (premature_get, cleanup_known) in [(false, true), (true, true), (false, false)] {
        conversation_case(premature_get, cleanup_known, Fault::None);
    }
}

#[test]
fn discovery_journal_capacity_refusal_emits_no_ack_or_selected_get() {
    conversation_case(false, true, Fault::AppendRefused);
}

#[test]
fn lost_discovery_ack_retains_selection_without_get_or_replacement_reservation() {
    conversation_case(false, true, Fault::LostAck);
}

fn conversation_case(premature_get: bool, cleanup_known: bool, fault: Fault) {
    let directory = Directory::new();
    let mut value = crate::s3_admission::tests::audit_tests::fixture();
    value["admission"]["host"]["ledger_root"] = json!(directory.path);
    value["admission"]["host"]["owner_uid"] =
        json!(std::fs::symlink_metadata(&directory.path).unwrap().uid());
    reseal(&mut value);
    let initial = checked(&value).unwrap();
    let (ledger, history, request, mut raw) =
        prepared_with(false, initial.enrollment_digest(), initial.profile_digest());
    value["manifest"]["params"]["worker_request"] = request.clone();
    value["admission"]["host"]["audit_workflow"] = raw.audit_workflow.clone();
    value["admission"]["host"]["environment_id"] = json!(raw.operation.environment_id);
    let workflow = &mut value["manifest"]["params"]["workflow_approval"];
    workflow["phase"] = json!("audit_baseline");
    workflow["operation_job_id"] = request["audit"]["operation_job_id"].clone();
    workflow["environment_id"] = json!(raw.operation.environment_id);
    workflow["expected_workflow_revision"] = json!(raw.operation.revision);
    workflow["audit_workflow_digest"] = json!(canonical_hash(&raw.audit_workflow));
    workflow["prior_run_ids"] = json!(request["audit"]["original_pair"]["reads"]
        .as_array()
        .unwrap()
        .iter()
        .map(|read| read["run_id"].clone())
        .collect::<Vec<_>>());
    value["now"] = request["audit"]["issued_at"].clone();
    value["admission"]["issued_at"] = value["now"].clone();
    value["admission"]["expires_at"] = request["deadline"].clone();
    value["manifest"]["requested_at"] = value["now"].clone();
    value["manifest"]["expires_at"] = request["deadline"].clone();
    value["manifest"]["approval"]["approved_at"] = value["now"].clone();
    value["manifest"]["approval"]["expires_at"] = request["deadline"].clone();
    reseal(&mut value);
    let admission = checked(&value).unwrap();
    assert!(S3ReservationStore::open(&admission).is_err());
    raw.task.run_id = admission.manifest().run_id.clone();
    raw.task.manifest_digest = admission.manifest_digest().into();
    raw.operation.approval_digest = admission.approval_digest().into();
    raw.checked(admission.binding().scope(), admission.profile_digest())
        .unwrap();
    // Test-only construction exercises the staged code without opening dispatch.
    let storage = Storage::open(
        admission.ledger_root(),
        admission.enrollment_digest(),
        4 * 1024 * 1024,
        JournalKind::S3,
    )
    .unwrap();
    let storage = if fault == Fault::AppendRefused {
        let header_bytes = std::fs::metadata(directory.path.join("reservations.jsonl"))
            .unwrap()
            .len() as usize;
        drop(storage);
        let mut planned = ledger.clone();
        let mut planned_bytes = history.clone();
        let hash = reserve(&mut planned, &mut planned_bytes, &raw);
        for sequence in 1..=4 {
            append(
                &mut planned,
                &mut planned_bytes,
                debit_record(&hash, sequence),
            );
        }
        // The actual protected append has exactly enough room for the
        // reservation and listing debits, but none for Discovery.
        Storage::open(
            admission.ledger_root(),
            admission.enrollment_digest(),
            header_bytes + planned_bytes.len(),
            JournalKind::S3,
        )
        .unwrap()
    } else {
        storage
    };
    let mut lease = storage.lease().unwrap();
    assert!(lease.read().unwrap().is_empty());
    let mut history_bytes = 0;
    for entry in history.split_inclusive(|byte| *byte == b'\n') {
        lease.append(entry, history_bytes).unwrap();
        history_bytes += entry.len();
    }
    assert_eq!(history_bytes, history.len());
    let mut ledger = ledger;
    let reservation_digest = crate::s3_reservation::append(
        &mut lease,
        &mut ledger,
        Record::AuditedReservation {
            reservation: Box::new(raw.clone()),
        },
    )
    .unwrap();
    let reservation = S3Reservation {
        lease,
        ledger,
        admission: &admission,
        reservation_digest: reservation_digest.clone(),
    };
    let credentials = json!({"access_key":"SYNTHETICACCESSKEY","secret_key":"synthetic-secret-value",
            "token":"synthetic-session-token","expires_at":"2026-10-09T00:10:00Z"});
    let secret = crate::s3_worker_secret::WorkerSecret::from_bytes(
        canonical_json(&credentials).as_bytes(),
        &canonical_hash(&credentials),
        crate::s3_access_scope::utc_time(value["now"].as_str().unwrap()).unwrap(),
        admission.expires_at(),
    )
    .unwrap();
    let mut driver = Fake {
        admission: &admission,
        directory: &directory,
        started: Instant::now(),
        elapsed: Duration::ZERO,
        incoming: Vec::new(),
        outgoing: VecDeque::new(),
        phase: 0,
        reservation: reservation_digest,
        discovery: None,
        ended: false,
        signalled: false,
        reaped: false,
        credentials_checked: false,
        acknowledgement_checked: false,
        premature_get,
        cleanup_known,
        fault,
        lost_ack_seen: false,
    };
    let started = driver.started;
    let result = crate::s3_worker_protocol::supervise(
        &mut driver,
        reservation,
        secret,
        started + Duration::from_secs(20),
        started + Duration::from_secs(22),
        &AtomicBool::new(false),
    );
    assert!(driver.credentials_checked && driver.signalled && driver.reaped);
    let completed = !premature_get && fault == Fault::None;
    assert_eq!(driver.acknowledgement_checked, completed);
    assert_eq!(driver.lost_ack_seen, fault == Fault::LostAck);
    assert_eq!(result["send_debits"], if completed { 5 } else { 4 });
    assert_eq!(
        result["cleanup"],
        if cleanup_known && fault != Fault::AppendRefused {
            "verified"
        } else {
            "unknown"
        }
    );
    if !completed {
        assert!(result["result"].is_null());
    } else {
        assert_eq!(result["result"]["outcome"], "observed");
    }
    let (_, replayed) = driver.retained();
    let retained = &replayed.requests[admission.binding().digest()];
    if fault == Fault::AppendRefused {
        assert!(retained.discovery.is_none() && retained.completion.is_none());
        let mut next = raw;
        next.operation.request_digest = canonical_hash(&json!({"replacement":"refused"}));
        next.operation.request_id = "e".repeat(64);
        next.operation.launch_id = "f".repeat(64);
        assert_eq!(replayed.check_audited(&next), Err(Error::RecoveryRequired));
    } else {
        assert_eq!(retained.completion.unwrap().2, cleanup_known);
        if fault == Fault::LostAck {
            assert_eq!(
                retained.discovery.as_ref().unwrap().document(),
                driver.discovery.as_ref().unwrap().document()
            );
            assert_eq!(
                retained.completion,
                Some((false, PolicyPosition::Unknown, true))
            );
            assert_eq!(replayed.check_audited(&raw), Err(Error::AlreadyReserved));
            let mut replacement = raw;
            replacement.operation.request_digest =
                canonical_hash(&json!({"replacement":"lost-ack"}));
            replacement.operation.request_id = "e".repeat(64);
            replacement.operation.launch_id = "f".repeat(64);
            replacement.operation.operation_id = format!("job-{}", "f".repeat(32));
            assert_eq!(
                replayed.check_audited(&replacement),
                Err(Error::AlreadyReserved)
            );
        }
    }
}
