use super::*;
use std::cell::Cell;
use std::rc::Rc;

// Synthetic account-authority values only; never actual host identities.
const OWNER: &str = "S-1-5-21-101-202-303-1001";
const READER: &str = "S-1-5-21-101-202-303-1002";
const GENERATION: &str = "0123456789abcdef0123456789abcdef";
const PAYLOAD: &[u8] = b"{\"record\":1}\n";
fn identity(index: u8) -> FileIdentity {
    FileIdentity {
        volume_serial: u64::MAX - 4,
        file_id: [index; 16],
    }
}
fn resource(state: ResourceState) -> ResourceExpectation {
    ResourceExpectation::new(
        GENERATION,
        OWNER,
        READER,
        [identity(1), identity(2), identity(3), identity(4)],
        identity(5),
        PAYLOAD.len(),
        &format!("sha256:{}", hex::encode(Sha256::digest(PAYLOAD))),
        state,
    )
    .unwrap_or_else(|_| panic!("synthetic resource"))
}
fn prepared(state: ResourceState) -> PreparedRead {
    PreparedRead::new(
        GENERATION,
        resource(state),
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap_or_else(|_| panic!("synthetic admission"))
}
fn secret() -> SecretCredential {
    SecretCredential::from_private_delivery(GENERATION, &[65, 66, 67])
        .unwrap_or_else(|_| panic!("synthetic secret"))
}
fn token(sid: &str, kind: u32, instance: u64, auth: u64) -> TokenFacts {
    TokenFacts {
        sid: sid.into(),
        instance,
        authentication: auth,
        modified: 50,
        kind,
        level: if kind == 2 { 2 } else { 0 },
        elevated: false,
        dangerous_privileges: false,
    }
}
fn sid_bytes(value: &str) -> Vec<u8> {
    let parts = account_sid(value).unwrap_or_else(|| panic!("synthetic SID"));
    let mut bytes = vec![1, 5, 0, 0, 0, 0, 0, 5];
    bytes.extend_from_slice(&21u32.to_le_bytes());
    for part in parts {
        bytes.extend_from_slice(&part.to_le_bytes());
    }
    bytes
}
fn sd(mask: u32) -> Vec<u8> {
    let owner = sid_bytes(OWNER);
    let reader = sid_bytes(READER);
    let mut bytes = vec![1, 0, 4, 0x90];
    bytes.extend_from_slice(&20u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&(20u32 + owner.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&owner);
    bytes.extend_from_slice(&[2, 0]);
    bytes.extend_from_slice(&(8u16 + 16 + owner.len() as u16 + reader.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&[2, 0, 0, 0]);
    for (mask, sid) in [(OWNER_MASK, owner), (mask, reader)] {
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&(8u16 + sid.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&mask.to_le_bytes());
        bytes.extend_from_slice(&sid);
    }
    bytes
}
struct TestClock {
    base: Instant,
    expired: bool,
    cancelled: bool,
    calls: Cell<usize>,
    expire_at: usize,
    forced_expired: Rc<Cell<bool>>,
}
impl TestClock {
    fn live() -> Self {
        Self {
            base: Instant::now(),
            expired: false,
            cancelled: false,
            calls: Cell::new(0),
            expire_at: usize::MAX,
            forced_expired: Rc::new(Cell::new(false)),
        }
    }
}
impl Clock for TestClock {
    fn now(&self) -> Instant {
        let n = self.calls.get();
        self.calls.set(n + 1);
        self.base
            + if self.expired || self.forced_expired.get() || n >= self.expire_at {
                Duration::from_secs(30)
            } else {
                Duration::ZERO
            }
    }
    fn cancelled(&self) -> bool {
        self.cancelled
    }
}
struct Fake {
    state: ResourceState,
    caller: TokenFacts,
    logon: TokenFacts,
    effective: TokenFacts,
    fail_impersonate: bool,
    fail_logon: bool,
    deny_data: bool,
    metadata_denied: bool,
    metadata_drift: bool,
    descriptor_drift: bool,
    context_drift: bool,
    data_alias: bool,
    bad_hash: bool,
    extra_byte: bool,
    clean: bool,
    volume_high_bit_drift: bool,
    file_high_bit_drift: bool,
    read_access_denied: bool,
    expire_on_cleanup: Option<Rc<Cell<bool>>>,
    handles: Vec<(usize, bool)>,
    metadata_opens: usize,
    data_opens: usize,
    read_position: usize,
    effective_calls: usize,
    impersonated: bool,
    cleaned: bool,
    received_account: Vec<u16>,
    wrong_path: bool,
    denied_code: u32,
}
impl Fake {
    fn new(state: ResourceState) -> Self {
        Self {
            state,
            caller: token(OWNER, 1, 10, 20),
            logon: token(READER, 2, 30, 40),
            // A duplicated effective token has a distinct instance and modified ID.
            effective: {
                let mut value = token(READER, 2, 31, 40);
                value.modified = 51;
                value
            },
            fail_impersonate: false,
            fail_logon: false,
            deny_data: false,
            metadata_denied: false,
            metadata_drift: false,
            descriptor_drift: false,
            context_drift: false,
            data_alias: false,
            bad_hash: false,
            extra_byte: false,
            clean: true,
            handles: Vec::new(),
            volume_high_bit_drift: false,
            file_high_bit_drift: false,
            read_access_denied: false,
            expire_on_cleanup: None,
            metadata_opens: 0,
            data_opens: 0,
            read_position: 0,
            effective_calls: 0,
            impersonated: false,
            cleaned: false,
            received_account: Vec::new(),
            wrong_path: false,
            denied_code: 5,
        }
    }
}
impl Backend for Fake {
    fn caller(&mut self) -> Result<TokenFacts, Failure> {
        Ok(self.caller.clone())
    }
    fn logon(&mut self, credential: &SecretCredential) -> Result<TokenFacts, Failure> {
        self.received_account = credential.account.clone();
        if self.fail_logon {
            return Err(Failure::native("logon", 5));
        }
        Ok(self.logon.clone())
    }
    fn impersonate(&mut self) -> Result<(), Failure> {
        if self.fail_impersonate {
            return Err(Failure::native("impersonate", 5));
        }
        self.impersonated = true;
        Ok(())
    }
    fn effective(&mut self) -> Result<TokenFacts, Failure> {
        self.effective_calls += 1;
        if !self.impersonated {
            return Err(Failure::new("context", "not_impersonated"));
        }
        let mut facts = self.effective.clone();
        if self.context_drift && self.effective_calls > 15 {
            facts.instance += 1;
        }
        Ok(facts)
    }
    fn open(&mut self, path: &str, directory: bool, data: bool) -> Result<usize, Failure> {
        if !self.impersonated {
            return Err(Failure::new("open", "not_impersonated"));
        }
        let paths = resource(self.state).paths();
        let index = paths
            .iter()
            .position(|p| p == path)
            .unwrap_or_else(|| panic!("fixed paths only"));
        assert_eq!(directory, index < 4);
        if data {
            self.data_opens += 1;
            assert_eq!(index, 4);
            if self.deny_data {
                return Err(Failure::native("data_open", self.denied_code));
            }
        } else {
            self.metadata_opens += 1;
            if self.metadata_denied {
                return Err(Failure::native("metadata_open", 5));
            }
        }
        let handle = self.handles.len();
        self.handles.push((index, data));
        Ok(handle)
    }
    fn facts(&mut self, handle: usize) -> Result<FileFacts, Failure> {
        let (index, data) = self.handles[handle];
        let mut id = identity(index as u8 + 1);
        if self.volume_high_bit_drift {
            id.volume_serial ^= 1u64 << 63;
        }
        if self.file_high_bit_drift {
            id.file_id[15] ^= 0x80;
        }
        if (self.metadata_drift && self.metadata_opens > 5 && index == 3)
            || (self.data_alias && data)
        {
            id.file_id[0] ^= 1;
        }
        let mut final_path = format!("\\\\?\\{}", resource(self.state).paths()[index]);
        if self.wrong_path {
            final_path.push_str(".alias");
        }
        Ok(FileFacts {
            identity: id,
            final_path,
            directory: index < 4,
            size: if index == 4 { PAYLOAD.len() as u64 } else { 0 },
            links: 1,
            attributes: if index < 4 { 0x10 } else { 0x80 },
            created: 1,
            written: 2,
            changed: 3,
        })
    }
    fn descriptor(&mut self, handle: usize) -> Result<Vec<u8>, Failure> {
        let (index, _) = self.handles[handle];
        let mut bytes = sd(if index == 3 {
            DIRECTORY_MASK
        } else {
            self.state.mask()
        });
        if self.descriptor_drift && self.metadata_opens > 5 {
            bytes[2] = 0;
        }
        Ok(bytes)
    }
    fn read(&mut self, _: usize, output: &mut [u8]) -> Result<usize, Failure> {
        if self.read_access_denied {
            return Err(Failure::native("read", 5));
        }
        if self.read_position == PAYLOAD.len() {
            if self.extra_byte {
                output[0] = b'x';
                return Ok(1);
            }
            return Ok(0);
        }
        let count = output.len().min(PAYLOAD.len() - self.read_position);
        output[..count].copy_from_slice(&PAYLOAD[self.read_position..self.read_position + count]);
        if self.bad_hash {
            output[0] ^= 1;
        }
        self.read_position += count;
        Ok(count)
    }
    fn cleanup(&mut self) -> CleanupFacts {
        self.cleaned = true;
        self.impersonated = false;
        if let Some(expired) = &self.expire_on_cleanup {
            expired.set(true);
        }
        CleanupFacts {
            handles_released: self.clean,
            impersonation_reverted: true,
            controller_restored: true,
            owned_process_exit_required: !self.clean,
        }
    }
}
fn run(fake: &mut Fake) -> ReadProof {
    prepared(fake.state).read_with(secret(), fake, &TestClock::live())
}

#[test]
fn allowed_matches_real_bytes_and_duplicated_effective_instance() {
    let mut fake = Fake::new(ResourceState::Readable);
    let proof = run(&mut fake);
    assert_eq!(proof.outcome, ReadOutcome::Allowed);
    assert_eq!(proof.bytes_read, PAYLOAD.len());
    assert!(proof.resource_rechecked && proof.effective_reader_verified && fake.cleaned);
    assert!(!proof.independent_observation);
    assert_eq!(fake.metadata_opens, 10);
    assert_eq!(fake.data_opens, 1);
    assert_eq!(
        String::from_utf16(&fake.received_account[..19])
            .ok()
            .as_deref(),
        Some("bf_0123456789abcdef")
    );
    let encoded = serde_json::to_string(&proof).unwrap_or_default();
    assert!(!encoded.contains(OWNER) && !encoded.contains(READER) && !encoded.contains("token_id"));
}
#[test]
fn only_fresh_data_open_access_denied_can_produce_denied() {
    let mut fake = Fake::new(ResourceState::MetadataOnly);
    fake.deny_data = true;
    let proof = run(&mut fake);
    assert_eq!(proof.outcome, ReadOutcome::DataAccessDenied);
    assert!(proof.resource_rechecked && fake.cleaned);
    assert_eq!(fake.metadata_opens, 10);
    assert_eq!(proof.bytes_read, 0);
    assert!(proof.observed_sha256.is_none());
    for stage in ["metadata", "logon", "other_code"] {
        let mut fake = Fake::new(ResourceState::Readable);
        match stage {
            "metadata" => fake.metadata_denied = true,
            "logon" => fake.fail_logon = true,
            _ => {
                fake.deny_data = true;
                fake.denied_code = 32;
            }
        }
        assert_eq!(run(&mut fake).outcome, ReadOutcome::Unknown);
        assert!(fake.cleaned);
    }
}
#[test]
fn access_denied_during_read_is_unknown_not_data_open_denial() {
    let mut fake = Fake::new(ResourceState::Readable);
    fake.read_access_denied = true;
    let proof = run(&mut fake);
    assert_eq!(proof.outcome, ReadOutcome::Unknown);
    assert_eq!(proof.failed_stage, Some("read"));
    assert!(proof.data_open_attempted && fake.cleaned);
}
#[test]
fn impersonation_failure_never_opens_or_reads() {
    let mut fake = Fake::new(ResourceState::Readable);
    fake.fail_impersonate = true;
    let proof = run(&mut fake);
    assert_eq!(proof.outcome, ReadOutcome::Unknown);
    assert_eq!(proof.failed_stage, Some("impersonate"));
    assert_eq!(
        fake.metadata_opens + fake.data_opens + fake.read_position,
        0
    );
    assert!(fake.cleaned);
}
#[test]
fn both_read_outcomes_require_identity_descriptor_and_effective_rechecks() {
    for denied in [false, true] {
        for drift in 0..3 {
            let mut fake = Fake::new(ResourceState::Readable);
            fake.deny_data = denied;
            match drift {
                0 => fake.metadata_drift = true,
                1 => fake.descriptor_drift = true,
                _ => fake.context_drift = true,
            }
            assert_eq!(run(&mut fake).outcome, ReadOutcome::Unknown);
            assert!(fake.cleaned);
        }
    }
}
#[test]
fn unresolved_cleanup_overrides_allowed_and_denied() {
    for denied in [false, true] {
        let mut fake = Fake::new(ResourceState::Readable);
        fake.deny_data = denied;
        fake.clean = false;
        let proof = run(&mut fake);
        assert_eq!(proof.outcome, ReadOutcome::Unknown);
        assert_eq!(proof.issue, Some("cleanup_unknown"));
        assert!(proof.cleanup.owned_process_exit_required);
    }
}
#[test]
fn deadline_cancellation_and_original_expiry_are_unknown() {
    for cancelled in [false, true] {
        let mut fake = Fake::new(ResourceState::Readable);
        let mut clock = TestClock::live();
        clock.expired = !cancelled;
        clock.cancelled = cancelled;
        let proof = prepared(fake.state).read_with(secret(), &mut fake, &clock);
        assert_eq!(proof.outcome, ReadOutcome::Unknown);
        assert_eq!(fake.metadata_opens + fake.data_opens, 0);
        assert!(fake.cleaned);
    }
    assert!(PreparedRead::new(
        GENERATION,
        resource(ResourceState::Readable),
        Instant::now() - Duration::from_secs(1)
    )
    .is_err());
    let mut fake = Fake::new(ResourceState::Readable);
    let mut clock = TestClock::live();
    clock.expire_at = 20;
    assert_eq!(
        prepared(fake.state)
            .read_with(secret(), &mut fake, &clock)
            .outcome,
        ReadOutcome::Unknown
    );
}
#[test]
fn deadline_expiring_during_cleanup_overrides_both_outcomes() {
    for denied in [false, true] {
        let mut fake = Fake::new(ResourceState::Readable);
        fake.deny_data = denied;
        let clock = TestClock::live();
        fake.expire_on_cleanup = Some(clock.forced_expired.clone());
        let proof = prepared(fake.state).read_with(secret(), &mut fake, &clock);
        assert_eq!(proof.outcome, ReadOutcome::Unknown);
        assert_eq!(proof.issue, Some("deadline"));
        assert_eq!(proof.failed_stage, Some("complete"));
        assert!(proof.resource_rechecked && proof.cleanup.complete());
    }
    let original = Instant::now() + Duration::from_secs(2);
    let read = PreparedRead::new(GENERATION, resource(ResourceState::Readable), original)
        .unwrap_or_else(|_| panic!("synthetic deadline"));
    assert_eq!(read.deadline, original);
}
#[test]
fn path_alias_data_handle_hash_and_eof_mismatches_are_unknown() {
    for fault in 0..4 {
        let mut fake = Fake::new(ResourceState::Readable);
        match fault {
            0 => fake.wrong_path = true,
            1 => fake.data_alias = true,
            2 => fake.bad_hash = true,
            _ => fake.extra_byte = true,
        }
        assert_eq!(run(&mut fake).outcome, ReadOutcome::Unknown);
        assert!(fake.cleaned);
    }
}
#[test]
fn actual_token_facts_bind_controller_logon_and_effective_reader() {
    for fault in 0..10 {
        let mut fake = Fake::new(ResourceState::Readable);
        match fault {
            0 => fake.caller.sid = READER.into(),
            1 => fake.caller.elevated = true,
            2 => fake.logon.sid = OWNER.into(),
            3 => fake.logon.authentication = fake.caller.authentication,
            4 => fake.logon.kind = 1,
            5 => fake.logon.level = 1,
            6 => fake.effective.authentication += 1,
            7 => fake.effective.elevated = true,
            8 => fake.effective.dangerous_privileges = true,
            _ => fake.effective.instance = 0,
        }
        assert_eq!(run(&mut fake).outcome, ReadOutcome::Unknown);
        assert_eq!(fake.metadata_opens + fake.data_opens, 0);
    }
}
#[test]
fn credential_is_fixed_generation_bound_and_rejects_malformed_utf16() {
    let wrong = SecretCredential::from_private_delivery("abcdef0123456789abcdef0123456789", &[65])
        .unwrap_or_else(|_| panic!("synthetic credential"));
    let mut fake = Fake::new(ResourceState::Readable);
    let proof = prepared(fake.state).read_with(wrong, &mut fake, &TestClock::live());
    assert_eq!(proof.issue, Some("credential_generation_mismatch"));
    assert!(fake.received_account.is_empty());
    for password in [vec![], vec![0], vec![0xd800], vec![65; 257]] {
        assert!(SecretCredential::from_private_delivery(GENERATION, &password).is_err());
    }
}
#[test]
fn constructor_rejects_noncanonical_sid_alias_identity_and_path_injection() {
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(PAYLOAD)));
    for generation in ["", "../resource", "ABCDEF0123456789ABCDEF0123456789"] {
        assert!(ResourceExpectation::new(
            generation,
            OWNER,
            READER,
            [identity(1), identity(2), identity(3), identity(4)],
            identity(5),
            PAYLOAD.len(),
            &digest,
            ResourceState::Readable
        )
        .is_err());
    }
    for reader in [
        OWNER,
        "S-1-5-21-101-202-304-1002",
        "S-1-5-21-0101-202-303-1002",
        "S-1-5-21-101-202-303-999",
        "S-1-5-21-101-202-303-4294967296",
    ] {
        assert!(ResourceExpectation::new(
            GENERATION,
            OWNER,
            reader,
            [identity(1), identity(2), identity(3), identity(4)],
            identity(5),
            PAYLOAD.len(),
            &digest,
            ResourceState::Readable
        )
        .is_err());
    }
    let mut cross_volume = identity(5);
    cross_volume.volume_serial -= 1;
    for file in [
        identity(1),
        cross_volume,
        FileIdentity {
            volume_serial: identity(1).volume_serial,
            file_id: [0; 16],
        },
    ] {
        assert!(ResourceExpectation::new(
            GENERATION,
            OWNER,
            READER,
            [identity(1), identity(2), identity(3), identity(4)],
            file,
            PAYLOAD.len(),
            &digest,
            ResourceState::Readable
        )
        .is_err());
    }
    for size in [0, MAX_BYTES + 1] {
        assert!(ResourceExpectation::new(
            GENERATION,
            OWNER,
            READER,
            [identity(1), identity(2), identity(3), identity(4)],
            identity(5),
            size,
            &digest,
            ResourceState::Readable
        )
        .is_err());
    }
}
#[test]
fn identities_preserve_all_volume_and_file_id_bits() {
    let mut a = identity(1);
    let mut b = a;
    b.volume_serial ^= 1u64 << 63;
    assert!(a != b);
    a.file_id[15] ^= 0x80;
    assert!(a != identity(1));
    for volume in [false, true] {
        let mut fake = Fake::new(ResourceState::Readable);
        fake.volume_high_bit_drift = volume;
        fake.file_high_bit_drift = !volume;
        let proof = run(&mut fake);
        assert_eq!(proof.outcome, ReadOutcome::Unknown);
        assert_eq!(proof.failed_stage, Some("metadata"));
        assert_eq!(fake.data_opens, 0);
    }
    // Distinct identities which differ ONLY in their high 128-bit ID bytes are
    // legitimate distinct objects, not truncated aliases in constructor checks.
    let mut file = identity(1);
    file.file_id[15] ^= 0x80;
    let expected = resource(ResourceState::Readable);
    assert!(ResourceExpectation::new(
        GENERATION,
        OWNER,
        READER,
        [identity(1), identity(2), identity(3), identity(4)],
        file,
        expected.size,
        &format!("sha256:{}", hex::encode(expected.digest)),
        ResourceState::Readable
    )
    .is_ok());
}
#[test]
fn exact_selected_descriptor_rejects_wrong_masks_flags_and_hidden_aces() {
    for mask in [
        DIRECTORY_MASK,
        ResourceState::Readable.mask(),
        ResourceState::MetadataOnly.mask(),
    ] {
        assert!(descriptor::verify(&sd(mask), OWNER, READER, mask).is_ok());
    }
    assert!(descriptor::verify(
        &sd(ResourceState::Readable.mask()),
        OWNER,
        READER,
        ResourceState::MetadataOnly.mask()
    )
    .is_err());
    for fault in 0..7 {
        let mut bytes = sd(ResourceState::Readable.mask());
        let acl_at = 48;
        match fault {
            0 => bytes[3] = 0x80,
            1 => bytes[acl_at + 4] = 3,
            2 => bytes[acl_at + 8 + 1] = 0x10,
            3 => bytes[acl_at + 8] = 1,
            4 => bytes[20 + 8] = 22,
            5 => {
                bytes[acl_at + 2] += 4;
                bytes.extend_from_slice(&[0; 4]);
            }
            _ => bytes[16..20].copy_from_slice(&u32::MAX.to_le_bytes()),
        }
        assert!(descriptor::verify(&bytes, OWNER, READER, ResourceState::Readable.mask()).is_err());
    }
}
#[test]
fn selected_descriptor_refuses_broader_offsets_gaps_and_trailing_bytes() {
    for field in [8, 12] {
        for offset in [20u32, 48, u32::MAX] {
            let mut bytes = sd(ResourceState::Readable.mask());
            bytes[field..field + 4].copy_from_slice(&offset.to_le_bytes());
            assert!(
                descriptor::verify(&bytes, OWNER, READER, ResourceState::Readable.mask()).is_err()
            );
        }
    }
    let mut trailing = sd(ResourceState::Readable.mask());
    trailing.extend_from_slice(&[0; 4]);
    assert!(descriptor::verify(&trailing, OWNER, READER, ResourceState::Readable.mask()).is_err());
    let original = sd(ResourceState::Readable.mask());
    let mut gap = original[..48].to_vec();
    gap.extend_from_slice(&[0; 4]);
    gap.extend_from_slice(&original[48..]);
    gap[16..20].copy_from_slice(&52u32.to_le_bytes());
    assert!(descriptor::verify(&gap, OWNER, READER, ResourceState::Readable.mask()).is_err());
    let mut sacl_flag = original.clone();
    sacl_flag[2] |= 0x10;
    assert!(descriptor::verify(&sacl_flag, OWNER, READER, ResourceState::Readable.mask()).is_err());
    // The supported components may appear in either self-relative order.
    let mut reordered = original[..20].to_vec();
    reordered.extend_from_slice(&original[48..]);
    reordered.extend_from_slice(&original[20..48]);
    reordered[4..8].copy_from_slice(&100u32.to_le_bytes());
    reordered[16..20].copy_from_slice(&20u32.to_le_bytes());
    assert!(descriptor::verify(&reordered, OWNER, READER, ResourceState::Readable.mask()).is_ok());
}
