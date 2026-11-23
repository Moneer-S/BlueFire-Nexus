use super::*;
use std::cell::Cell;
use std::rc::Rc;

const OWNER: &str = "S-1-5-21-101-202-303-1001";
const READER: &str = "S-1-5-21-101-202-303-1002";
const GENERATION: &str = "0123456789abcdef0123456789abcdef";
const DATA: &[u8] = b"synthetic pair bytes\n";
fn identity(index: u8) -> FileIdentity {
    FileIdentity {
        volume_serial: u64::MAX - 4,
        file_id: [index; 16],
    }
}
fn resource() -> ResourceExpectation {
    ResourceExpectation::new(
        GENERATION,
        OWNER,
        READER,
        [identity(1), identity(2), identity(3), identity(4)],
        identity(5),
        DATA.len(),
        &format!("sha256:{}", hex::encode(Sha256::digest(DATA))),
        ResourceState::Readable,
    )
    .unwrap_or_else(|_| panic!("fixture"))
}
fn token(owner: bool) -> TokenFacts {
    TokenFacts {
        sid: if owner { OWNER } else { READER }.into(),
        instance: if owner { 10 } else { 30 },
        authentication: if owner { 20 } else { 40 },
        modified: 50,
        kind: if owner { 1 } else { 2 },
        level: if owner { 0 } else { 2 },
        elevated: false,
        dangerous_privileges: false,
    }
}
fn sid(value: &str) -> Vec<u8> {
    let mut bytes = vec![1, 5, 0, 0, 0, 0, 0, 5];
    bytes.extend_from_slice(&21u32.to_le_bytes());
    for value in account_sid(value).unwrap_or_else(|| panic!("fixture SID")) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}
fn descriptor_bytes(mask: u32) -> Vec<u8> {
    let owner = sid(OWNER);
    let reader = sid(READER);
    let mut raw = vec![1, 0, 4, 0x90];
    for offset in [20, 0, 0, 20 + owner.len() as u32] {
        raw.extend_from_slice(&offset.to_le_bytes());
    }
    raw.extend_from_slice(&owner);
    raw.extend_from_slice(&[2, 0]);
    raw.extend_from_slice(&(24u16 + owner.len() as u16 + reader.len() as u16).to_le_bytes());
    raw.extend_from_slice(&[2, 0, 0, 0]);
    for (mask, value) in [(OWNER_MASK, owner), (mask, reader)] {
        raw.extend_from_slice(&[0, 0]);
        raw.extend_from_slice(&(8u16 + value.len() as u16).to_le_bytes());
        raw.extend_from_slice(&mask.to_le_bytes());
        raw.extend_from_slice(&value);
    }
    raw
}
struct FakeClock {
    base: Instant,
    expired: Rc<Cell<bool>>,
    cancelled: Rc<Cell<bool>>,
}
impl Clock for FakeClock {
    fn now(&self) -> Instant {
        self.base
            + if self.expired.get() {
                Duration::from_secs(30)
            } else {
                Duration::ZERO
            }
    }
    fn cancelled(&self) -> bool {
        self.cancelled.get()
    }
}
struct Fake {
    state: ResourceState,
    expired: Rc<Cell<bool>>,
    cancelled: Rc<Cell<bool>>,
    late: &'static str,
    cancel_instead: bool,
    owner: bool,
    impersonating: bool,
    cleaned: bool,
    cleanup_failed: bool,
    fail_cleanup: usize,
    cleanup_count: usize,
    owner_entries: usize,
    owner_drift: bool,
    metadata_drift: bool,
    descriptor_drift: bool,
    identity_drift: bool,
    reader_denial: Option<(&'static str, u32)>,
    owner_denied: bool,
    extra_byte: bool,
    wrong_hash: bool,
    handles: Vec<(usize, bool)>,
    opens: [usize; 2],
    data_opens: [usize; 2],
    reads: [usize; 2],
    position: usize,
}
impl Fake {
    fn new() -> (Self, FakeClock) {
        let expired = Rc::new(Cell::new(false));
        let cancelled = Rc::new(Cell::new(false));
        let clock = FakeClock {
            base: Instant::now(),
            expired: expired.clone(),
            cancelled: cancelled.clone(),
        };
        (
            Self {
                state: ResourceState::Readable,
                expired,
                cancelled,
                late: "",
                cancel_instead: false,
                owner: false,
                impersonating: false,
                cleaned: false,
                cleanup_failed: false,
                fail_cleanup: 0,
                cleanup_count: 0,
                owner_entries: 0,
                owner_drift: false,
                metadata_drift: false,
                descriptor_drift: false,
                identity_drift: false,
                reader_denial: None,
                owner_denied: false,
                extra_byte: false,
                wrong_hash: false,
                handles: Vec::new(),
                opens: [0, 0],
                data_opens: [0, 0],
                reads: [0, 0],
                position: 0,
            },
            clock,
        )
    }
    fn tick(&self, stage: &str) {
        if self.late == stage {
            if self.cancel_instead {
                self.cancelled.set(true);
            } else {
                self.expired.set(true);
            }
        }
    }
    fn run(&mut self, clock: &FakeClock) -> PairReadProof {
        let read = PreparedRead::new(GENERATION, resource(), clock.base + Duration::from_secs(5))
            .unwrap_or_else(|_| panic!("fixture"));
        let secret = SecretCredential::from_private_delivery(GENERATION, &[65, 66, 67])
            .unwrap_or_else(|_| panic!("fixture"));
        read.read_pair_with(secret, self, clock)
    }
    fn run_correction(&mut self, clock: &FakeClock) -> PairReadProof {
        let mut expectation = resource();
        expectation.state = self.state;
        let read = PreparedRead::new(GENERATION, expectation, clock.base + Duration::from_secs(5))
            .unwrap_or_else(|_| panic!("fixture"));
        let secret = SecretCredential::from_private_delivery(GENERATION, &[65, 66, 67])
            .unwrap_or_else(|_| panic!("fixture"));
        read.read_pair_correction_with(secret, self, clock)
    }
}
impl Backend for Fake {
    fn caller(&mut self) -> Result<TokenFacts, Failure> {
        if self.impersonating {
            return Err(Failure::new("caller", "preexisting_impersonation_refused"));
        }
        self.tick(if self.owner {
            "owner_caller"
        } else {
            "reader_caller"
        });
        let mut value = token(true);
        if self.owner && self.owner_drift {
            value.instance += 1;
        }
        Ok(value)
    }
    fn logon(&mut self, _: &SecretCredential) -> Result<TokenFacts, Failure> {
        self.tick("logon");
        Ok(token(false))
    }
    fn impersonate(&mut self) -> Result<(), Failure> {
        self.impersonating = true;
        self.tick("impersonate");
        Ok(())
    }
    fn effective(&mut self) -> Result<TokenFacts, Failure> {
        if !self.owner && !self.impersonating {
            return Err(Failure::new("context", "owned_impersonation_missing"));
        }
        if self.owner {
            self.tick(if self.handles.len() == 5 {
                "owner_before_data"
            } else {
                "owner_effective"
            });
        } else {
            self.tick("reader_effective");
        }
        Ok(token(self.owner))
    }
    fn open(&mut self, path: &str, directory: bool, data: bool) -> Result<usize, Failure> {
        assert!(self.owner || self.impersonating);
        let index = resource()
            .paths()
            .iter()
            .position(|value| value == path)
            .unwrap_or_else(|| panic!("fixed path"));
        assert_eq!(directory, index < 4);
        let phase = usize::from(self.owner);
        self.opens[phase] += 1;
        if data {
            assert_eq!(index, 4);
            self.data_opens[phase] += 1;
            if self.owner && self.owner_denied {
                return Err(Failure::native("data_open", 5));
            }
        }
        if !self.owner {
            if let Some((stage, code)) = self.reader_denial {
                if data || stage == "metadata_open" {
                    return Err(Failure::native(stage, code));
                }
            }
        }
        self.tick(if self.owner {
            "owner_open"
        } else {
            "reader_open"
        });
        let handle = self.handles.len();
        self.handles.push((index, data));
        Ok(handle)
    }
    fn facts(&mut self, handle: usize) -> Result<FileFacts, Failure> {
        let index = self.handles[handle].0;
        let mut id = identity(index as u8 + 1);
        if self.owner && self.identity_drift && index == 4 {
            id.file_id[15] ^= 0x80;
        }
        self.tick(if self.owner {
            "owner_facts"
        } else {
            "reader_facts"
        });
        Ok(FileFacts {
            identity: id,
            final_path: format!("\\\\?\\{}", resource().paths()[index]),
            directory: index < 4,
            size: if index == 4 { DATA.len() as u64 } else { 0 },
            links: 1,
            attributes: if index < 4 { 0x10 } else { 0x80 },
            created: 1,
            written: 2,
            changed: if self.owner && self.metadata_drift {
                4
            } else {
                3
            },
        })
    }
    fn descriptor(&mut self, handle: usize) -> Result<Vec<u8>, Failure> {
        let mut raw = descriptor_bytes(if self.handles[handle].0 == 3 {
            DIRECTORY_MASK
        } else {
            self.state.mask()
        });
        if self.owner && self.descriptor_drift {
            raw[2] = 0;
        }
        self.tick(if self.owner {
            "owner_descriptor"
        } else {
            "reader_descriptor"
        });
        Ok(raw)
    }
    fn read(&mut self, handle: usize, output: &mut [u8]) -> Result<usize, Failure> {
        assert!(self.handles[handle].1);
        self.reads[usize::from(self.owner)] += 1;
        self.tick(if self.owner {
            "owner_read"
        } else {
            "reader_read"
        });
        if self.position == DATA.len() {
            if self.owner && self.extra_byte {
                output[0] = b'x';
                return Ok(1);
            }
            return Ok(0);
        }
        let count = output.len().min(DATA.len() - self.position);
        output[..count].copy_from_slice(&DATA[self.position..self.position + count]);
        if self.owner && self.wrong_hash {
            output[0] ^= 1;
        }
        self.position += count;
        Ok(count)
    }
    fn cleanup(&mut self) -> CleanupFacts {
        self.cleanup_count += 1;
        self.tick(if self.owner {
            "owner_cleanup"
        } else {
            "reader_cleanup"
        });
        self.cleanup_failed |= self.fail_cleanup == self.cleanup_count;
        self.impersonating = false;
        if !self.cleanup_failed {
            self.handles.clear();
            self.cleaned = true;
        }
        CleanupFacts {
            handles_released: !self.cleanup_failed,
            impersonation_reverted: true,
            controller_restored: !self.owner || !self.owner_drift,
            owned_process_exit_required: self.cleanup_failed || (self.owner && self.owner_drift),
        }
    }
    fn enter_owner_phase(&mut self, original: &TokenFacts) -> Result<(), Failure> {
        self.owner_entries += 1;
        assert!(
            self.cleaned
                && self.handles.is_empty()
                && !self.impersonating
                && !self.cleanup_failed
                && !self.owner
        );
        assert!(*original == token(true));
        self.owner = true;
        self.position = 0;
        self.tick("owner_enter");
        Ok(())
    }
}

#[test]
fn pair_uses_two_fresh_data_opens_and_real_owner_bytes_after_reader_cleanup() {
    let (mut backend, clock) = Fake::new();
    let proof = backend.run(&clock);
    assert_eq!(proof.outcome, ReadOutcome::Allowed);
    assert_eq!(backend.data_opens, [1, 1]);
    assert_eq!(backend.owner_entries, 1);
    assert!(proof.reader.cleanup.complete() && proof.cleanup.complete());
    assert!(proof.owner.original_owner_verified && proof.owner.no_thread_token_verified);
    assert!(proof.resource_pair_rechecked && !proof.independent_observation);
    assert_eq!(proof.reader.bytes_read, DATA.len());
    assert_eq!(proof.owner.bytes_read, DATA.len());
    assert_eq!(proof.reader.observed_sha256, proof.owner.observed_sha256);
    let text = serde_json::to_string(&proof).unwrap();
    assert!(!text.contains(OWNER) && !text.contains(READER) && !text.contains("C:\\"));
}

#[test]
fn late_or_cancelled_callback_never_starts_the_next_native_effect() {
    for cancel in [false, true] {
        for stage in [
            "reader_caller",
            "logon",
            "impersonate",
            "reader_effective",
            "reader_cleanup",
            "owner_enter",
            "owner_caller",
            "owner_effective",
            "owner_before_data",
            "owner_open",
            "owner_facts",
            "owner_descriptor",
            "owner_read",
            "owner_cleanup",
        ] {
            let (mut backend, clock) = Fake::new();
            backend.late = stage;
            backend.cancel_instead = cancel;
            let proof = backend.run(&clock);
            assert_eq!(proof.outcome, ReadOutcome::Unknown, "{stage}");
            if matches!(
                stage,
                "reader_caller" | "logon" | "impersonate" | "reader_effective"
            ) {
                assert_eq!(backend.opens, [0, 0], "{stage}");
            }
            if matches!(
                stage,
                "reader_cleanup" | "owner_enter" | "owner_caller" | "owner_effective"
            ) {
                assert_eq!(backend.opens[1], 0, "{stage}");
            }
            if stage == "owner_before_data" {
                assert_eq!(backend.data_opens[1], 0);
            }
            if stage == "owner_read" {
                assert_eq!(backend.reads[1], 1);
            }
        }
    }
}

#[test]
fn sticky_reader_cleanup_failure_forbids_owner_phase() {
    for earlier_failure in [false, true] {
        let (mut backend, clock) = Fake::new();
        backend.fail_cleanup = 1;
        if earlier_failure {
            backend.reader_denial = Some(("data_open", 2));
        }
        let proof = backend.run(&clock);
        assert_eq!(proof.outcome, ReadOutcome::Unknown);
        assert_eq!(proof.reader.issue, Some("cleanup_unknown"));
        assert_eq!(proof.reader.failed_stage, Some("cleanup"));
        assert_eq!(backend.owner_entries, 0);
        assert_eq!(backend.data_opens, [1, 0]);
        assert!(!proof.cleanup.complete());
    }
}

#[test]
fn owner_denial_or_drift_retains_true_reader_phase_without_baseline_success() {
    for failure in [
        "denied",
        "token",
        "identity",
        "metadata",
        "descriptor",
        "hash",
        "eof",
        "cleanup",
    ] {
        let (mut backend, clock) = Fake::new();
        backend.owner_denied = failure == "denied";
        backend.owner_drift = failure == "token";
        backend.identity_drift = failure == "identity";
        backend.metadata_drift = failure == "metadata";
        backend.descriptor_drift = failure == "descriptor";
        backend.wrong_hash = failure == "hash";
        backend.extra_byte = failure == "eof";
        backend.fail_cleanup = if failure == "cleanup" { 2 } else { 0 };
        let proof = backend.run(&clock);
        assert_eq!(proof.outcome, ReadOutcome::Unknown, "{failure}");
        assert_eq!(proof.reader.outcome, ReadOutcome::Allowed, "{failure}");
        if failure == "metadata" {
            assert_eq!(proof.issue, Some("resource_pair_drift"));
        }
    }
}

#[test]
fn only_reader_final_data_open_denial_can_be_a_complete_denied_pair() {
    for (stage, code) in [
        ("data_open", 5),
        ("metadata_open", 5),
        ("data_open", 2),
        ("read", 5),
    ] {
        let (mut backend, clock) = Fake::new();
        backend.reader_denial = Some((stage, code));
        let proof = backend.run(&clock);
        if stage == "data_open" && code == 5 {
            assert_eq!(proof.outcome, ReadOutcome::DataAccessDenied);
            assert_eq!(proof.owner.outcome, ReadOutcome::Allowed);
            assert!(proof.resource_pair_rechecked);
        } else {
            assert_eq!(proof.outcome, ReadOutcome::Unknown);
            assert_eq!(backend.owner_entries, 0);
        }
    }
}

#[test]
fn pair_rejects_hardened_resource_before_either_data_open() {
    let (mut backend, clock) = Fake::new();
    let mut expectation = resource();
    expectation.state = ResourceState::MetadataOnly;
    let read = PreparedRead::new(GENERATION, expectation, clock.base + Duration::from_secs(5))
        .unwrap_or_else(|_| panic!("fixture"));
    let credential = SecretCredential::from_private_delivery(GENERATION, &[65])
        .unwrap_or_else(|_| panic!("fixture"));
    let proof = read.read_pair_with(credential, &mut backend, &clock);
    assert_eq!(proof.outcome, ReadOutcome::Unknown);
    assert_eq!(backend.data_opens, [0, 0]);
}

#[test]
fn correction_metadata_only_denial_needs_fresh_owner_bytes_and_both_cleanups() {
    let (mut backend, clock) = Fake::new();
    backend.state = ResourceState::MetadataOnly;
    backend.reader_denial = Some(("data_open", 5));
    let proof = backend.run_correction(&clock);
    assert_eq!(
        proof.schema_version,
        "bluefire.windows-fixed-read-pair-correction.v3"
    );
    assert_eq!(proof.outcome, ReadOutcome::DataAccessDenied);
    assert_eq!(proof.reader.outcome, ReadOutcome::DataAccessDenied);
    assert_eq!(proof.reader.bytes_read, 0);
    assert_eq!(proof.reader.observed_sha256, None);
    assert_eq!(proof.owner.outcome, ReadOutcome::Allowed);
    assert_eq!(proof.owner.bytes_read, DATA.len());
    assert_eq!(
        proof.owner.observed_sha256,
        Some(format!("sha256:{}", hex::encode(Sha256::digest(DATA))))
    );
    assert_eq!(backend.data_opens, [1, 1]);
    assert!(proof.reader.cleanup.complete() && proof.cleanup.complete());
    assert!(proof.resource_pair_rechecked && !proof.independent_observation);
}

#[test]
fn correction_refuses_readable_resource_without_native_effects() {
    let (mut backend, clock) = Fake::new();
    let proof = backend.run_correction(&clock);
    assert_eq!(proof.outcome, ReadOutcome::Unknown);
    assert_eq!(proof.issue, Some("pair_resource_or_credential_invalid"));
    assert_eq!(backend.opens, [0, 0]);
    assert_eq!(backend.data_opens, [0, 0]);
    assert_eq!(backend.owner_entries, 0);
}

#[test]
fn correction_denial_never_hides_owner_drift_or_unknown_cleanup() {
    for failure in [
        "denied",
        "token",
        "identity",
        "metadata",
        "descriptor",
        "hash",
        "eof",
        "reader_cleanup",
        "owner_cleanup",
    ] {
        let (mut backend, clock) = Fake::new();
        backend.state = ResourceState::MetadataOnly;
        backend.reader_denial = Some(("data_open", 5));
        backend.owner_denied = failure == "denied";
        backend.owner_drift = failure == "token";
        backend.identity_drift = failure == "identity";
        backend.metadata_drift = failure == "metadata";
        backend.descriptor_drift = failure == "descriptor";
        backend.wrong_hash = failure == "hash";
        backend.extra_byte = failure == "eof";
        backend.fail_cleanup = match failure {
            "reader_cleanup" => 1,
            "owner_cleanup" => 2,
            _ => 0,
        };
        let proof = backend.run_correction(&clock);
        assert_eq!(proof.outcome, ReadOutcome::Unknown, "{failure}");
        if failure == "reader_cleanup" {
            assert_eq!(backend.owner_entries, 0);
            assert_eq!(backend.data_opens, [1, 0]);
        } else {
            assert_eq!(
                proof.reader.outcome,
                ReadOutcome::DataAccessDenied,
                "{failure}"
            );
        }
    }
}

#[test]
fn correction_original_deadline_and_cancellation_guard_each_owner_callback() {
    for cancel in [false, true] {
        for stage in [
            "reader_caller",
            "logon",
            "reader_cleanup",
            "owner_enter",
            "owner_before_data",
            "owner_read",
            "owner_cleanup",
        ] {
            let (mut backend, clock) = Fake::new();
            backend.state = ResourceState::MetadataOnly;
            backend.reader_denial = Some(("data_open", 5));
            backend.late = stage;
            backend.cancel_instead = cancel;
            let proof = backend.run_correction(&clock);
            assert_eq!(proof.outcome, ReadOutcome::Unknown, "{stage}");
            if matches!(stage, "reader_caller" | "logon") {
                assert_eq!(backend.opens, [0, 0]);
            }
            if matches!(
                stage,
                "reader_cleanup" | "owner_enter" | "owner_before_data"
            ) {
                assert_eq!(backend.data_opens[1], 0);
            }
        }
    }
}
