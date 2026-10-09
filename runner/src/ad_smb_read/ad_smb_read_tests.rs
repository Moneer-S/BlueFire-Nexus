//! All backends here are inert; no Win32 logon, file open, SMB or cleanup API runs.
use super::*;
use std::cell::Cell;
use std::rc::Rc;

const ID: &str = "0123456789abcdef0123456789abcdef";
const SID: &str = "S-1-5-21-1-2-3-1101";
const UPN: &str = "probe@lab.example";
const CONTENT: &[u8] = b"record\n";

struct FakeClock {
    time: Rc<Cell<u64>>,
    cancelled: Rc<Cell<bool>>,
}
impl Clock for FakeClock {
    fn elapsed(&self) -> Duration {
        Duration::from_secs(self.time.get())
    }
    fn cancelled(&self) -> bool {
        self.cancelled.get()
    }
}

struct Fake {
    calls: Vec<&'static str>,
    fail: Option<(&'static str, u32)>,
    time: Rc<Cell<u64>>,
    cancelled: Rc<Cell<bool>>,
    expire_after: Option<&'static str>,
    cancel_after: Option<&'static str>,
    logon: LocalLogon,
    facts: FileFacts,
    data: Vec<u8>,
    offset: usize,
    oversized_count: bool,
    cleanup: CleanupFacts,
    read_sizes: Vec<usize>,
}

impl Fake {
    fn step(&mut self, name: &'static str) -> Result<(), Failure> {
        self.calls.push(name);
        if self.expire_after == Some(name) {
            self.time.set(60);
        }
        if self.cancel_after == Some(name) {
            self.cancelled.set(true);
        }
        if let Some((stage, code)) = self.fail {
            if name == stage {
                return Err(Failure {
                    stage,
                    issue: "win32_failure",
                    win32: Some(code),
                });
            }
        }
        Ok(())
    }
}

impl Backend for Fake {
    fn caller(&mut self) -> Result<LocalLogon, Failure> {
        self.step("caller")?;
        Ok(LocalLogon {
            authentication_id: 1,
            local_token_user_sid: "S-1-5-21-8-9-10-1100".into(),
        })
    }
    fn logon(&mut self, _: &SecretCredential) -> Result<LocalLogon, Failure> {
        self.step("logon")?;
        Ok(self.logon.clone())
    }
    fn impersonate(&mut self) -> Result<(), Failure> {
        self.step("impersonate")
    }
    fn open(&mut self, path: &str) -> Result<(), Failure> {
        assert_eq!(
            path,
            format!("\\\\member.lab.example\\bf_{ID}\\records.jsonl")
        );
        self.step("open")
    }
    fn facts(&mut self) -> Result<FileFacts, Failure> {
        self.step("metadata")?;
        Ok(FileFacts {
            protocol: self.facts.protocol.clone(),
            file_id: self.facts.file_id,
            volume_serial: self.facts.volume_serial,
            size: self.facts.size,
            is_regular: self.facts.is_regular,
            final_path: self.facts.final_path.clone(),
        })
    }
    fn read(&mut self, output: &mut [u8]) -> Result<usize, Failure> {
        self.step("read")?;
        self.read_sizes.push(output.len());
        if self.oversized_count {
            return Ok(output.len() + 1);
        }
        let n = output.len().min(self.data.len() - self.offset);
        output[..n].copy_from_slice(&self.data[self.offset..self.offset + n]);
        self.offset += n;
        Ok(n)
    }
    fn cleanup(&mut self, share: &str) -> CleanupFacts {
        assert_eq!(share, format!("\\\\member.lab.example\\bf_{ID}"));
        self.calls.push("cleanup");
        self.cleanup.clone()
    }
}

fn fixtures() -> (PreparedRead, SecretCredential, Fake, FakeClock) {
    let target = ReadTarget::new(
        "member.lab.example",
        ID,
        FilePurpose::Primary,
        ID,
        42,
        &format!("sha256:{}", hex::encode(Sha256::digest(CONTENT))),
        CONTENT.len(),
    )
    .unwrap();
    let digest = format!("sha256:{}", "a".repeat(64));
    let bindings = ReadBindings::new(&digest, &digest, &digest, &digest).unwrap();
    let read = PreparedRead::new(ID, target, Reader::Probe, SID, UPN, bindings, &[], 60).unwrap();
    let secret = SecretCredential::new(UPN, &[71, 82, 69, 69, 78]).unwrap();
    let time = Rc::new(Cell::new(0));
    let cancelled = Rc::new(Cell::new(false));
    let fake = Fake {
        calls: vec![],
        fail: None,
        time: time.clone(),
        cancelled: cancelled.clone(),
        expire_after: None,
        cancel_after: None,
        logon: LocalLogon {
            authentication_id: 2,
            local_token_user_sid: "S-1-5-21-8-9-10-1100".into(),
        },
        facts: FileFacts {
            protocol: ProtocolFacts {
                version: 2,
                size: 116,
                protocol: 0x20000,
                major: 3,
                flags: 0x28,
            },
            file_id: hex_array(ID).unwrap(),
            volume_serial: 42,
            size: CONTENT.len() as u64,
            is_regular: true,
            final_path: format!("\\\\?\\UNC\\member.lab.example\\bf_{ID}\\records.jsonl"),
        },
        data: CONTENT.to_vec(),
        offset: 0,
        oversized_count: false,
        cleanup: CleanupFacts {
            file_closed: Some(true),
            exact_unc_cancel_status: Some(0),
            impersonation_reverted: Some(true),
            token_closed: Some(true),
            ..CleanupFacts::default()
        },
        read_sizes: vec![],
    };
    (read, secret, fake, FakeClock { time, cancelled })
}

#[test]
fn complete_read_does_not_claim_remote_identity_or_independence() {
    let (read, secret, mut fake, clock) = fixtures();
    let proof = read.read_with(secret, &mut fake, &clock);
    assert_eq!(proof.state, ReadState::BytesMatched);
    assert_eq!(proof.bytes_read, CONTENT.len());
    assert_eq!(proof.expected_volume_serial, 42);
    assert_eq!(proof.observed_volume_serial, Some(42));
    assert_eq!(proof.observed_file_id.as_deref(), Some(ID));
    assert_eq!(fake.read_sizes, [CONTENT.len(), 1]);
    assert_eq!(
        fake.calls,
        [
            "caller",
            "logon",
            "impersonate",
            "open",
            "metadata",
            "read",
            "read",
            "cleanup"
        ]
    );
    assert_ne!(
        proof.local_logon.as_ref().unwrap().local_token_user_sid,
        proof.expected_remote_sid
    );
    assert!(
        !proof.authenticated_remote_reader
            && !proof.fresh_server_logon
            && !proof.independent_observation
            && !proof.effective_access_claim
    );
    assert_eq!(proof.cleanup.server_session_closed, None);
    let projection = serde_json::to_string(&proof).unwrap();
    assert!(
        !projection.contains("GREEN")
            && !projection.contains(UPN)
            && !projection.contains("record\\n")
    );
}

#[test]
fn only_generated_exact_unc_and_bounded_identity_inputs() {
    let digest = format!("sha256:{}", "a".repeat(64));
    for member in [
        "127.0.0.1",
        "MEMBER.lab.example",
        "member",
        "member.lab.example.",
        "member\\x.lab.example",
        "-member.lab.example",
    ] {
        assert!(ReadTarget::new(member, ID, FilePurpose::Primary, ID, 42, &digest, 1).is_err());
    }
    for id in ["", "../x", "0123456789ABCDEF0123456789ABCDEF"] {
        assert!(ReadTarget::new(
            "member.lab.example",
            id,
            FilePurpose::Primary,
            ID,
            42,
            &digest,
            1
        )
        .is_err());
    }
    for size in [0, 65_537, usize::MAX] {
        assert!(ReadTarget::new(
            "member.lab.example",
            ID,
            FilePurpose::Primary,
            ID,
            42,
            &digest,
            size
        )
        .is_err());
    }
    assert!(ReadBindings::new("bad", &digest, &digest, &digest).is_err());
}

#[test]
fn closed_request_rejects_probe_health_reuse_and_lifetime() {
    for prior in [vec![0], vec![2, 2], vec![1, 2, 3, 4, 5, 6]] {
        let (read, _, _, _) = fixtures();
        assert!(PreparedRead::new(
            ID,
            read.target,
            Reader::Probe,
            SID,
            UPN,
            read.bindings,
            &prior,
            60
        )
        .is_err());
    }
    for seconds in [0, 61, u64::MAX] {
        let (read, _, _, _) = fixtures();
        assert!(PreparedRead::new(
            ID,
            read.target,
            Reader::Probe,
            SID,
            UPN,
            read.bindings,
            &[],
            seconds
        )
        .is_err());
    }
    for sid in [
        "S-1-5-32-544",
        "S-1-5-21-1-2-3-500",
        "S-1-5-21-01-2-3-1101",
        "S-1-5-21-1-2-3-4294967296",
    ] {
        let (read, _, _, _) = fixtures();
        assert!(PreparedRead::new(
            ID,
            read.target,
            Reader::Probe,
            sid,
            UPN,
            read.bindings,
            &[],
            60
        )
        .is_err());
    }
    let (mut read, _, _, _) = fixtures();
    read.target.purpose = FilePurpose::Health;
    assert!(PreparedRead::new(
        ID,
        read.target,
        Reader::Probe,
        SID,
        UPN,
        read.bindings,
        &[],
        60
    )
    .is_err());
}

#[test]
fn private_credential_format_and_upn_binding_fail_before_native_work() {
    for password in [vec![], vec![0], vec![0xd800], vec![65; 257]] {
        assert!(SecretCredential::new(UPN, &password).is_err());
    }
    for name in [
        "probe",
        "probe@127.0.0.1",
        "PROBE@lab.example",
        "probe@lab.example\0",
    ] {
        assert!(SecretCredential::new(name, &[65]).is_err());
    }
    let (read, _, mut fake, clock) = fixtures();
    let proof = read.read_with(
        SecretCredential::new("other@lab.example", &[65]).unwrap(),
        &mut fake,
        &clock,
    );
    assert_eq!(proof.state, ReadState::NotStarted);
    assert!(fake.calls.is_empty());
}

#[test]
fn fresh_luid_and_cloned_local_sid_required_before_impersonation() {
    for id in [0, 1, 3] {
        let (mut read, secret, mut fake, clock) = fixtures();
        read.prior_luids.push(3);
        fake.logon.authentication_id = id;
        let proof = read.read_with(secret, &mut fake, &clock);
        assert_eq!(proof.issue, Some("fresh_local_context_mismatch"));
        assert!(!fake.calls.contains(&"impersonate") && !proof.file_open_attempted);
        assert_eq!(fake.calls.last(), Some(&"cleanup"));
    }
    let (read, secret, mut fake, clock) = fixtures();
    fake.logon.local_token_user_sid = SID.into();
    assert_eq!(
        read.read_with(secret, &mut fake, &clock).issue,
        Some("fresh_local_context_mismatch")
    );
}

#[test]
fn errors_at_each_stage_never_retry_or_blur_open_denial() {
    for stage in ["caller", "logon", "impersonate", "open", "metadata", "read"] {
        for code in [5, 2, 53, 1326, 1219, 64] {
            let (read, secret, mut fake, clock) = fixtures();
            fake.fail = Some((stage, code));
            let proof = read.read_with(secret, &mut fake, &clock);
            assert_eq!(proof.failed_stage, Some(stage));
            assert_eq!(proof.win32_error, Some(code));
            assert_eq!(
                proof.state,
                if stage == "open" && code == 5 {
                    ReadState::OpenAccessDenied
                } else {
                    ReadState::Unknown
                }
            );
            assert_eq!(fake.calls.iter().filter(|call| **call == stage).count(), 1);
            assert_eq!(fake.calls.last(), Some(&"cleanup"));
            if ["caller", "logon", "impersonate"].contains(&stage) {
                assert!(!proof.file_open_attempted);
            }
            if stage == "open" {
                assert!(proof.protocol.is_none());
                assert!(proof.observed_file_id.is_none());
            }
            assert!(!proof.effective_access_claim);
        }
    }
}

#[test]
fn aggregate_deadline_and_cancellation_never_restart_between_stages() {
    for stage in ["caller", "logon", "impersonate", "open", "metadata", "read"] {
        for deadline in [true, false] {
            let (read, secret, mut fake, clock) = fixtures();
            if deadline {
                fake.expire_after = Some(stage);
            } else {
                fake.cancel_after = Some(stage);
            }
            let proof = read.read_with(secret, &mut fake, &clock);
            assert_eq!(
                proof.state,
                if deadline {
                    ReadState::Deadline
                } else {
                    ReadState::Cancelled
                }
            );
            assert_eq!(fake.calls.last(), Some(&"cleanup"));
            assert_eq!(fake.calls[fake.calls.len() - 2], stage);
        }
    }
    let (read, secret, mut fake, clock) = fixtures();
    clock.time.set(60);
    assert_eq!(
        read.read_with(secret, &mut fake, &clock).state,
        ReadState::Deadline
    );
    assert_eq!(fake.calls, ["cleanup"]);
}

#[test]
fn protection_flags_require_supported_smb3_privacy_and_mutual_auth() {
    for flags in [0, 0x10, 0x08, 0x20, 0x29, 0x2a, 0x68] {
        let (read, secret, mut fake, clock) = fixtures();
        fake.facts.protocol.flags = flags;
        assert_eq!(
            read.read_with(secret, &mut fake, &clock).issue,
            Some("smb_protection_unverified")
        );
        assert!(!fake.calls.contains(&"read"));
    }
    for flags in [0x28, 0x2c, 0x38] {
        let (read, secret, mut fake, clock) = fixtures();
        fake.facts.protocol.flags = flags;
        assert_eq!(
            read.read_with(secret, &mut fake, &clock).state,
            ReadState::BytesMatched
        );
    }
    for variation in 0..5 {
        let (read, secret, mut fake, clock) = fixtures();
        match variation {
            0 => fake.facts.protocol.version = 1,
            1 => fake.facts.protocol.version = 4,
            2 => fake.facts.protocol.size = 180,
            3 => fake.facts.protocol.protocol = 0,
            _ => fake.facts.protocol.major = 2,
        }
        assert_eq!(
            read.read_with(secret, &mut fake, &clock).issue,
            Some("smb_protection_unverified")
        );
    }
}

#[test]
fn metadata_drift_or_referral_refuses_payload_read() {
    for variation in 0..5 {
        let (read, secret, mut fake, clock) = fixtures();
        match variation {
            0 => fake.facts.file_id[0] ^= 1,
            1 => fake.facts.size += 1,
            2 => fake.facts.is_regular = false,
            3 => {
                fake.facts.final_path =
                    format!("\\\\?\\UNC\\other.lab.example\\bf_{ID}\\records.jsonl")
            }
            _ => fake.facts.final_path.push_str(":stream"),
        }
        assert_eq!(
            read.read_with(secret, &mut fake, &clock).issue,
            Some("file_identity_mismatch")
        );
        assert!(!fake.calls.contains(&"read"));
    }
}

#[test]
fn same_file_id_content_and_path_on_a_different_volume_refuses_payload() {
    let (read, secret, mut fake, clock) = fixtures();
    fake.facts.volume_serial = 43;
    let proof = read.read_with(secret, &mut fake, &clock);
    assert_eq!(proof.issue, Some("file_identity_mismatch"));
    assert_eq!(proof.expected_volume_serial, 42);
    assert_eq!(proof.observed_volume_serial, Some(43));
    assert_eq!(proof.bytes_read, 0);
    assert!(!fake.calls.contains(&"read"));
}

#[test]
fn observed_file_id_preserves_the_actual_mismatching_object() {
    let (read, secret, mut fake, clock) = fixtures();
    fake.facts.file_id[0] ^= 1;
    let actual = hex::encode(fake.facts.file_id);
    let proof = read.read_with(secret, &mut fake, &clock);
    assert_eq!(proof.observed_file_id.as_deref(), Some(actual.as_str()));
    assert_ne!(actual, ID);
    assert_eq!(proof.state, ReadState::Unknown);
    assert_eq!(proof.issue, Some("file_identity_mismatch"));
    assert_eq!(proof.bytes_read, 0);
    assert!(!fake.calls.contains(&"read"));
}

#[test]
fn only_exact_complete_bytes_and_eof_match() {
    for variation in 0..4 {
        let (read, secret, mut fake, clock) = fixtures();
        match variation {
            0 => {
                fake.data.pop();
            }
            1 => fake.data.push(1),
            2 => fake.data[0] ^= 1,
            _ => fake.oversized_count = true,
        }
        let proof = read.read_with(secret, &mut fake, &clock);
        assert_eq!(proof.state, ReadState::Unknown);
        assert!(proof.bytes_read <= CONTENT.len());
        assert!(fake.read_sizes.iter().all(|size| *size <= CONTENT.len()));
    }
}

#[test]
fn local_cleanup_failure_is_not_a_successful_completed_read() {
    for variation in 0..5 {
        let (read, secret, mut fake, clock) = fixtures();
        match variation {
            0 => fake.cleanup.file_closed = Some(false),
            1 => fake.cleanup.impersonation_reverted = Some(false),
            2 => fake.cleanup.token_closed = Some(false),
            3 => fake.cleanup.observation_tokens_closed = Some(false),
            _ => fake.cleanup.owned_process_exit_required = true,
        }
        let proof = read.read_with(secret, &mut fake, &clock);
        assert_eq!(proof.state, ReadState::Unknown);
        assert_eq!(proof.issue, Some("local_cleanup_unknown"));
        assert_eq!(proof.cleanup.server_session_closed, None);
    }
}

#[test]
fn connection_cancel_is_a_separate_fact_not_server_closure() {
    for status in [0, 2250, 2401, 5] {
        let (read, secret, mut fake, clock) = fixtures();
        fake.cleanup.exact_unc_cancel_status = Some(status);
        let proof = read.read_with(secret, &mut fake, &clock);
        assert_eq!(proof.state, ReadState::BytesMatched);
        assert_eq!(proof.cleanup.exact_unc_cancel_status, Some(status));
        assert_eq!(proof.cleanup.server_session_closed, None);
    }
}
