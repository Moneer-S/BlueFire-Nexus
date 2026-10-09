use super::*;
use crate::canonical::canonical_hash;
use crate::s3_admission::VerifiedS3Admission;
use crate::s3_reservation::{
    tests::{now, send, Directory},
    S3ReservationStore,
};
use std::collections::VecDeque;

struct Fake<'a> {
    admission: &'a VerifiedS3Admission,
    directory: &'a Directory,
    started: Instant,
    elapsed: Duration,
    outgoing: VecDeque<u8>,
    incoming: Vec<u8>,
    stage: usize,
    exited: bool,
    signalled: bool,
    reaped: bool,
    group_absent: bool,
    identity_good: bool,
    credentials_received: bool,
}
impl<'a> Fake<'a> {
    fn new(admission: &'a VerifiedS3Admission, directory: &'a Directory) -> Self {
        Self {
            admission,
            directory,
            started: Instant::now(),
            elapsed: Duration::ZERO,
            outgoing: VecDeque::new(),
            incoming: Vec::new(),
            stage: 0,
            exited: false,
            signalled: false,
            reaped: false,
            group_absent: true,
            identity_good: true,
            credentials_received: false,
        }
    }
    fn emit(&mut self, value: Value) {
        self.outgoing.extend(canonical_json(&value).bytes());
        self.outgoing.push_back(b'\n');
    }
    fn receive(&mut self, frame: Value) {
        match self.stage {
            0 => {
                assert_eq!(
                    canonical_json(&frame),
                    self.admission.binding().canonical_json()
                );
                self.emit(
                    json!({"kind":"ready","request_digest":self.admission.binding().digest(),
                    "process_id":123,"creation_identity":"456","nonce":"a".repeat(64)}),
                );
            }
            1 => assert_eq!(frame["kind"], "contained"),
            2 => {
                assert_eq!(frame["kind"], "credentials");
                self.credentials_received = true;
                self.outgoing.extend(send(self.admission, 1));
            }
            3 | 4 => {
                let sequence = (self.stage - 2) as u64;
                assert_eq!(frame["kind"], "permit");
                assert_eq!(frame["sequence"], sequence);
                let retained =
                    std::fs::read(self.directory.path.join("reservations.jsonl")).unwrap();
                let last: Value = serde_json::from_slice(
                    retained
                        .split(|b| *b == b'\n')
                        .rfind(|line| !line.is_empty())
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(last["record"]["kind"], "debit");
                assert_eq!(last["record"]["sequence"], sequence);
                if sequence == 1 {
                    self.outgoing.extend(send(self.admission, 2));
                } else {
                    let request: Value =
                        serde_json::from_str(self.admission.binding().canonical_json()).unwrap();
                    self.emit(json!({"kind":"result","result":{
                        "schema_version":"bluefire.s3-worker-result.v1", "request_digest":self.admission.binding().digest(),
                        "outcome":"observed", "data":{"policy_digest":request["scope"]["policy"]["baseline_digest"],"structural_review":"supported_baseline"},
                        "problem":null,"send_permits_consumed":2,"runtime_isolation_proven":false,
                        "calls":[{"operation":"GetCallerIdentity","role":"controller","request_id":"safe-1","http_status":200},
                            {"operation":"GetBucketPolicy","role":"controller","request_id":"safe-2","http_status":200}]
                    }}));
                    self.exited = true; // The final frame still needs many bounded reads.
                }
            }
            _ => panic!("unexpected native input"),
        }
        self.stage += 1;
    }
}
impl Driver for Fake<'_> {
    fn now(&self) -> Instant {
        self.started + self.elapsed
    }
    fn wall(&self) -> DateTime<FixedOffset> {
        now() + chrono::Duration::from_std(self.elapsed).unwrap()
    }
    fn pause(&mut self, duration: Duration) {
        self.elapsed += duration;
    }
    fn read(&mut self, stderr: bool) -> Result<Chunk, ()> {
        if !stderr && !self.outgoing.is_empty() {
            Ok(Chunk::Bytes(
                (0..7).filter_map(|_| self.outgoing.pop_front()).collect(),
            ))
        } else if self.exited {
            Ok(Chunk::Eof)
        } else {
            Ok(Chunk::Pending)
        }
    }
    fn write(&mut self, bytes: &[u8]) -> Result<usize, ()> {
        let count = bytes.len().min(37);
        self.incoming.extend_from_slice(&bytes[..count]);
        while let Some(end) = self.incoming.iter().position(|b| *b == b'\n') {
            let frame: Vec<_> = self.incoming.drain(..=end).collect();
            self.receive(serde_json::from_slice(&frame).unwrap());
        }
        Ok(count)
    }
    fn identity(&mut self) -> Result<(u32, u64), ()> {
        if self.identity_good {
            Ok((123, 456))
        } else {
            Err(())
        }
    }
    fn exited(&mut self) -> Result<bool, ()> {
        Ok(self.exited)
    }
    fn terminate_group(&mut self) -> bool {
        assert!(!self.reaped);
        self.signalled = true;
        self.exited = true;
        true
    }
    fn reap(&mut self) -> Result<Option<Option<i32>>, ()> {
        assert!(self.signalled);
        self.reaped = true;
        Ok(Some(Some(0)))
    }
    fn group_absent(&mut self) -> bool {
        self.group_absent
    }
}
fn secret(admission: &VerifiedS3Admission) -> WorkerSecret {
    let value = json!({"access_key":"SYNTHETICACCESSKEY", "secret_key":"synthetic-secret-value", "token":"synthetic-session-token", "expires_at":"2026-10-09T00:10:00Z"});
    WorkerSecret::from_bytes(
        canonical_json(&value).as_bytes(),
        &canonical_hash(&value),
        now(),
        admission.expires_at(),
    )
    .unwrap()
}

#[test]
fn real_ledger_and_fixed_protocol_debit_before_fake_worker_send() {
    let directory = Directory::new();
    let admission = directory.admission();
    let store = S3ReservationStore::open(&admission).unwrap();
    let reservation = store.reserve(&admission, now()).unwrap();
    let mut child = Fake::new(&admission, &directory);
    let start = child.started;
    let result = supervise(
        &mut child,
        reservation,
        secret(&admission),
        start + Duration::from_secs(20),
        start + Duration::from_secs(22),
        &AtomicBool::new(false),
    );
    assert_eq!(result["send_debits"], 2);
    assert_eq!(result["result"]["outcome"], "observed");
    assert_eq!(result["cleanup"], "verified");
    assert!(child.credentials_received && child.signalled && child.reaped);
}

#[test]
fn identity_failure_never_releases_credentials_or_send_authority() {
    let directory = Directory::new();
    let admission = directory.admission();
    let store = S3ReservationStore::open(&admission).unwrap();
    let reservation = store.reserve(&admission, now()).unwrap();
    let mut child = Fake::new(&admission, &directory);
    child.identity_good = false;
    let start = child.started;
    let result = supervise(
        &mut child,
        reservation,
        secret(&admission),
        start + Duration::from_secs(20),
        start + Duration::from_secs(22),
        &AtomicBool::new(false),
    );
    assert_eq!(result["send_debits"], 0);
    assert!(!child.credentials_received);
    assert_eq!(result["cleanup"], "verified");
}

#[test]
fn unproven_group_absence_keeps_observations_but_not_verified_cleanup() {
    let directory = Directory::new();
    let admission = directory.admission();
    let store = S3ReservationStore::open(&admission).unwrap();
    let reservation = store.reserve(&admission, now()).unwrap();
    let mut child = Fake::new(&admission, &directory);
    child.group_absent = false;
    let start = child.started;
    let result = supervise(
        &mut child,
        reservation,
        secret(&admission),
        start + Duration::from_secs(20),
        start + Duration::from_secs(22),
        &AtomicBool::new(false),
    );
    assert_eq!(result["result"]["outcome"], "observed");
    assert_eq!(result["cleanup"], "unknown");
}
