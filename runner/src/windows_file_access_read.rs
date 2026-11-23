//! Fixed native Windows endpoint READ component, deliberately not registered as
//! an action or worker verb. Enrollment and trusted one-use private credential
//! delivery remain external premises, not facts established by SID syntax.
//!
//! Run only in a disposable worker already owned by the supervisor's Windows
//! Job. The supervisor must enforce the ORIGINAL hard deadline and drain all
//! owned processes after failure: synchronous Win32 calls can block beyond our
//! cooperative five-second bound. Reversion failure aborts that worker.
//! Observations are bounded snapshots, not independent audit or continuing access.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::atomic::{compiler_fence, Ordering};
use std::time::{Duration, Instant};

#[cfg(target_os = "windows")]
#[path = "windows_file_access_read/windows_file_access_read_ffi.rs"]
mod ffi;
#[path = "windows_file_access_read/windows_file_access_read_pair.rs"]
mod pair;
#[cfg(test)]
#[path = "windows_file_access_read/windows_file_access_read_tests.rs"]
mod tests;
#[cfg(target_os = "windows")]
#[path = "windows_file_access_read/windows_file_access_read_windows.rs"]
mod windows;
pub use pair::{OwnerReadProof, PairReadProof};
#[cfg(test)]
#[path = "windows_file_access_read/windows_file_access_read_pair_tests.rs"]
mod pair_tests;

const MAX_BYTES: usize = 1_048_576;
const OWNER_MASK: u32 = 0x001f_01ff;
const DIRECTORY_MASK: u32 = 0x0012_00a0;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FileIdentity {
    pub volume_serial: u64,
    pub file_id: [u8; 16],
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ResourceState {
    Readable,
    MetadataOnly,
}
impl ResourceState {
    fn mask(self) -> u32 {
        match self {
            Self::Readable => 0x0012_0089,
            Self::MetadataOnly => 0x0012_0080,
        }
    }
}

/// Private enrolled resource facts; callers cannot supply paths, SDDL or domains.
/// This value validates shape and consistency; it does not enroll an account.
pub struct ResourceExpectation {
    generation: String,
    owner: String,
    reader: String,
    identities: [FileIdentity; 5],
    size: usize,
    digest: [u8; 32],
    state: ResourceState,
}
impl ResourceExpectation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        generation: &str,
        enrolled_owner_sid: &str,
        enrolled_reader_sid: &str,
        ancestors: [FileIdentity; 4],
        file: FileIdentity,
        size: usize,
        sha256: &str,
        state: ResourceState,
    ) -> Result<Self, &'static str> {
        let owner = account_sid(enrolled_owner_sid).ok_or("owner_sid_invalid")?;
        let reader = account_sid(enrolled_reader_sid).ok_or("reader_sid_invalid")?;
        if owner[..3] != reader[..3] || owner == reader {
            return Err("distinct_same_authority_accounts_required");
        }
        if !lower_hex(generation, 32) || !(1..=MAX_BYTES).contains(&size) {
            return Err("resource_recipe_invalid");
        }
        let digest = sha256
            .strip_prefix("sha256:")
            .filter(|s| lower_hex(s, 64))
            .and_then(|s| hex::decode(s).ok())
            .and_then(|v| v.try_into().ok())
            .ok_or("resource_digest_invalid")?;
        let identities = [ancestors[0], ancestors[1], ancestors[2], ancestors[3], file];
        for (index, identity) in identities.iter().enumerate() {
            if identity.file_id == [0; 16]
                || identity.volume_serial != file.volume_serial
                || identities[..index].contains(identity)
            {
                return Err("resource_identity_invalid");
            }
        }
        Ok(Self {
            generation: generation.into(),
            owner: enrolled_owner_sid.into(),
            reader: enrolled_reader_sid.into(),
            identities,
            size,
            digest,
            state,
        })
    }
    fn paths(&self) -> [String; 5] {
        let root = format!("C:\\BlueFire\\EndpointAccess\\{}", self.generation);
        [
            "C:\\".into(),
            "C:\\BlueFire".into(),
            "C:\\BlueFire\\EndpointAccess".into(),
            root.clone(),
            format!("{root}\\records.jsonl"),
        ]
    }
}

/// Owned private-channel credential. Never Debug, Clone or Serialize. Its caller
/// must erase the source delivery buffer; this type erases only its owned copies.
pub struct SecretCredential {
    generation: String,
    account: Vec<u16>,
    password: Vec<u16>,
}
impl SecretCredential {
    pub fn from_private_delivery(generation: &str, password: &[u16]) -> Result<Self, &'static str> {
        if !lower_hex(generation, 32)
            || password.is_empty()
            || password.len() > 256
            || password.contains(&0)
            || std::char::decode_utf16(password.iter().copied()).any(|v| v.is_err())
        {
            return Err("private_credential_invalid");
        }
        let account = format!("bf_{}", &generation[..16])
            .encode_utf16()
            .chain([0])
            .collect();
        let password = password.iter().copied().chain([0]).collect();
        Ok(Self {
            generation: generation.into(),
            account,
            password,
        })
    }
}
impl Drop for SecretCredential {
    fn drop(&mut self) {
        for unit in self.account.iter_mut().chain(self.password.iter_mut()) {
            unsafe { std::ptr::write_volatile(unit, 0) };
        }
        let mut generation = std::mem::take(&mut self.generation).into_bytes();
        for byte in &mut generation {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

pub struct PreparedRead {
    request_id: String,
    resource: ResourceExpectation,
    deadline: Instant,
}
impl PreparedRead {
    /// The deadline is the original admission deadline, never a renewed budget.
    pub fn new(
        request_id: &str,
        resource: ResourceExpectation,
        original_deadline: Instant,
    ) -> Result<Self, &'static str> {
        let now = Instant::now();
        if !lower_hex(request_id, 32) || original_deadline <= now {
            return Err("read_admission_invalid");
        }
        Ok(Self {
            request_id: request_id.into(),
            resource,
            deadline: original_deadline.min(now + Duration::from_secs(5)),
        })
    }
    /// Requires externally owned disposable Job/deadline supervision.
    pub fn read(self, credential: SecretCredential, cancelled: &dyn Fn() -> bool) -> ReadProof {
        let clock = SystemClock { cancelled };
        #[cfg(target_os = "windows")]
        return self.read_with(credential, &mut windows::WindowsBackend::default(), &clock);
        #[cfg(not(target_os = "windows"))]
        self.read_with(credential, &mut Unsupported, &clock)
    }
    fn read_with(
        self,
        credential: SecretCredential,
        backend: &mut impl Backend,
        clock: &impl Clock,
    ) -> ReadProof {
        let mut proof = ReadProof {
            schema_version: "bluefire.windows-fixed-read.v1",
            request_id: self.request_id.clone(),
            outcome: ReadOutcome::Unknown,
            issue: None,
            failed_stage: None,
            data_open_attempted: false,
            bytes_read: 0,
            observed_sha256: None,
            effective_reader_verified: false,
            resource_rechecked: false,
            independent_observation: false,
            cleanup: CleanupFacts::default(),
        };
        let result = if credential.generation != self.resource.generation {
            Err(Failure::new("credential", "credential_generation_mismatch"))
        } else {
            read_once(&self, &credential, backend, clock, &mut proof)
        };
        drop(credential);
        if let Err(error) = result {
            proof.outcome = ReadOutcome::Unknown;
            proof.failed_stage = Some(error.stage);
            proof.issue = Some(error.issue);
        }
        proof.cleanup = backend.cleanup();
        if !proof.cleanup.complete() {
            proof.outcome = ReadOutcome::Unknown;
            proof.failed_stage = Some("cleanup");
            proof.issue = Some("cleanup_unknown");
        } else if let Err(error) = current(&self, clock, "complete") {
            proof.outcome = ReadOutcome::Unknown;
            proof.failed_stage = Some(error.stage);
            proof.issue = Some(error.issue);
        }
        proof
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadOutcome {
    Allowed,
    DataAccessDenied,
    Unknown,
}
#[derive(Clone, Copy, Default, Debug, Serialize)]
pub struct CleanupFacts {
    pub handles_released: bool,
    pub impersonation_reverted: bool,
    pub controller_restored: bool,
    pub owned_process_exit_required: bool,
}
impl CleanupFacts {
    fn complete(&self) -> bool {
        self.handles_released
            && self.impersonation_reverted
            && self.controller_restored
            && !self.owned_process_exit_required
    }
}
/// Bounded, path/SID/token/credential-free proof. No fabricated parsed-record or
/// independent-observer claim; a matched hash is the actual byte observation.
#[derive(Debug, Serialize)]
pub struct ReadProof {
    pub schema_version: &'static str,
    pub request_id: String,
    pub outcome: ReadOutcome,
    pub issue: Option<&'static str>,
    pub failed_stage: Option<&'static str>,
    pub data_open_attempted: bool,
    pub bytes_read: usize,
    pub observed_sha256: Option<String>,
    pub effective_reader_verified: bool,
    pub resource_rechecked: bool,
    pub independent_observation: bool,
    pub cleanup: CleanupFacts,
}

#[derive(Clone, Eq, PartialEq)]
struct TokenFacts {
    sid: String,
    instance: u64,
    authentication: u64,
    modified: u64,
    kind: u32,
    level: u32,
    elevated: bool,
    dangerous_privileges: bool,
}
impl TokenFacts {
    fn valid(&self, sid: &str, kind: u32) -> bool {
        self.sid == sid
            && self.instance != 0
            && self.authentication != 0
            && self.modified != 0
            && self.kind == kind
            && !self.elevated
            && !self.dangerous_privileges
            && (kind == 1 || self.level == 2)
    }
}
#[derive(Clone, Eq, PartialEq)]
struct FileFacts {
    identity: FileIdentity,
    final_path: String,
    directory: bool,
    size: u64,
    links: u32,
    attributes: u32,
    created: i64,
    written: i64,
    changed: i64,
}
struct Failure {
    stage: &'static str,
    issue: &'static str,
    win32: Option<u32>,
}
impl Failure {
    fn new(stage: &'static str, issue: &'static str) -> Self {
        Self {
            stage,
            issue,
            win32: None,
        }
    }
    #[cfg(any(target_os = "windows", test))]
    fn native(stage: &'static str, code: u32) -> Self {
        Self {
            stage,
            issue: "native_failure",
            win32: Some(code),
        }
    }
}
trait Clock {
    fn now(&self) -> Instant;
    fn cancelled(&self) -> bool;
}
struct SystemClock<'a> {
    cancelled: &'a dyn Fn() -> bool,
}
impl Clock for SystemClock<'_> {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn cancelled(&self) -> bool {
        (self.cancelled)()
    }
}
trait Backend {
    fn caller(&mut self) -> Result<TokenFacts, Failure>;
    fn logon(&mut self, credential: &SecretCredential) -> Result<TokenFacts, Failure>;
    fn impersonate(&mut self) -> Result<(), Failure>;
    fn effective(&mut self) -> Result<TokenFacts, Failure>;
    fn open(&mut self, exact_path: &str, directory: bool, data: bool) -> Result<usize, Failure>;
    fn facts(&mut self, handle: usize) -> Result<FileFacts, Failure>;
    fn descriptor(&mut self, handle: usize) -> Result<Vec<u8>, Failure>;
    fn read(&mut self, handle: usize, output: &mut [u8]) -> Result<usize, Failure>;
    fn cleanup(&mut self) -> CleanupFacts;
    fn enter_owner_phase(&mut self, _original: &TokenFacts) -> Result<(), Failure> {
        Err(Failure::new("owner_context", "owner_phase_unsupported"))
    }
}
fn current(read: &PreparedRead, clock: &impl Clock, stage: &'static str) -> Result<(), Failure> {
    if clock.cancelled() {
        return Err(Failure::new(stage, "cancelled"));
    }
    if clock.now() >= read.deadline {
        return Err(Failure::new(stage, "deadline"));
    }
    Ok(())
}
fn effective(
    read: &PreparedRead,
    backend: &mut impl Backend,
    clock: &impl Clock,
    expected: &TokenFacts,
) -> Result<(), Failure> {
    current(read, clock, "context")?;
    if backend.effective()? != *expected {
        return Err(Failure::new("context", "effective_token_drift"));
    }
    Ok(())
}
type ResourceInspection = ([usize; 5], Vec<FileFacts>, [Vec<u8>; 2]);

fn inspect(
    read: &PreparedRead,
    backend: &mut impl Backend,
    clock: &impl Clock,
    token: &TokenFacts,
) -> Result<ResourceInspection, Failure> {
    let resource = &read.resource;
    let paths = resource.paths();
    let mut held = [0; 5];
    let mut facts = Vec::with_capacity(5);
    for index in 0..5 {
        effective(read, backend, clock, token)?;
        held[index] = backend.open(&paths[index], index < 4, false)?;
        effective(read, backend, clock, token)?;
        let observed = backend.facts(held[index])?;
        if observed.identity != resource.identities[index]
            || observed.final_path != format!("\\\\?\\{}", paths[index])
            || observed.directory != (index < 4)
            || observed.attributes & (0x400 | 0x1000) != 0
            || (index == 4 && (observed.size != resource.size as u64 || observed.links != 1))
        {
            return Err(Failure::new(
                "metadata",
                "resource_identity_or_metadata_mismatch",
            ));
        }
        facts.push(observed);
    }
    let mut descriptors = [Vec::new(), Vec::new()];
    for (slot, index, mask) in [(0, 3, DIRECTORY_MASK), (1, 4, resource.state.mask())] {
        effective(read, backend, clock, token)?;
        descriptors[slot] = backend.descriptor(held[index])?;
        descriptor::verify(&descriptors[slot], &resource.owner, &resource.reader, mask)?;
    }
    Ok((held, facts, descriptors))
}
fn read_once(
    read: &PreparedRead,
    credential: &SecretCredential,
    backend: &mut impl Backend,
    clock: &impl Clock,
    proof: &mut ReadProof,
) -> Result<(), Failure> {
    current(read, clock, "caller")?;
    let caller = backend.caller()?;
    if !caller.valid(&read.resource.owner, 1) {
        return Err(Failure::new("caller", "controller_identity_mismatch"));
    }
    current(read, clock, "logon")?;
    let logon = backend.logon(credential)?;
    if !logon.valid(&read.resource.reader, 2) || logon.authentication == caller.authentication {
        return Err(Failure::new("logon", "reader_identity_mismatch"));
    }
    current(read, clock, "impersonate")?;
    if backend.caller()? != caller {
        return Err(Failure::new("caller", "controller_token_drift"));
    }
    backend.impersonate()?;
    current(read, clock, "context")?;
    // Bind the observed effective instance: Windows may duplicate the logon token.
    let token = backend.effective()?;
    if !token.valid(&read.resource.reader, 2) || token.authentication != logon.authentication {
        return Err(Failure::new("context", "effective_reader_mismatch"));
    }
    proof.effective_reader_verified = true;
    let (held, before, descriptors) = inspect(read, backend, clock, &token)?;
    effective(read, backend, clock, &token)?;
    proof.data_open_attempted = true;
    let data = match backend.open(&read.resource.paths()[4], false, true) {
        Ok(handle) => Some(handle),
        Err(error) if error.stage == "data_open" && error.win32 == Some(5) => None,
        Err(error) => return Err(error),
    };
    if let Some(data) = data {
        effective(read, backend, clock, &token)?;
        if backend.facts(data)? != before[4] {
            return Err(Failure::new("metadata", "data_handle_mismatch"));
        }
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 8192];
        while proof.bytes_read < read.resource.size {
            effective(read, backend, clock, &token)?;
            let limit = buffer.len().min(read.resource.size - proof.bytes_read);
            let count = backend.read(data, &mut buffer[..limit])?;
            if count == 0 || count > limit {
                return Err(Failure::new("read", "read_length_mismatch"));
            }
            hash.update(&buffer[..count]);
            buffer[..count].fill(0);
            proof.bytes_read += count;
        }
        effective(read, backend, clock, &token)?;
        if backend.read(data, &mut buffer[..1])? != 0 {
            return Err(Failure::new("read", "read_eof_mismatch"));
        }
        let digest: [u8; 32] = hash.finalize().into();
        proof.observed_sha256 = Some(format!("sha256:{}", hex::encode(digest)));
        if digest != read.resource.digest {
            return Err(Failure::new("read", "read_digest_mismatch"));
        }
        effective(read, backend, clock, &token)?;
        if backend.facts(data)? != before[4] {
            return Err(Failure::new("metadata", "data_metadata_drift"));
        }
    }
    // Both outcomes require fresh pathname opens plus held-object reinspection.
    let (_, after, after_descriptors) = inspect(read, backend, clock, &token)?;
    if after != before || after_descriptors != descriptors {
        return Err(Failure::new("recheck", "resource_drift"));
    }
    for index in 0..5 {
        effective(read, backend, clock, &token)?;
        if backend.facts(held[index])? != before[index] {
            return Err(Failure::new("recheck", "held_metadata_drift"));
        }
    }
    for (slot, index) in [(0, 3), (1, 4)] {
        effective(read, backend, clock, &token)?;
        if backend.descriptor(held[index])? != descriptors[slot] {
            return Err(Failure::new("recheck", "held_descriptor_drift"));
        }
    }
    effective(read, backend, clock, &token)?;
    proof.resource_rechecked = true;
    proof.outcome = if data.is_some() {
        ReadOutcome::Allowed
    } else {
        ReadOutcome::DataAccessDenied
    };
    Ok(())
}
fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn account_sid(value: &str) -> Option<[u32; 4]> {
    let parts: Vec<_> = value.strip_prefix("S-1-5-21-")?.split('-').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut output = [0; 4];
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() || part.starts_with('0') || !part.bytes().all(|v| v.is_ascii_digit()) {
            return None;
        }
        output[index] = part.parse().ok()?;
    }
    (output[3] >= 1000).then_some(output)
}

/// Bounded self-relative OWNER+DACL parser for the exact two-ACE recipe.
mod descriptor {
    use super::{account_sid, Failure, OWNER_MASK};
    fn invalid() -> Failure {
        Failure::new("descriptor", "selected_descriptor_mismatch")
    }
    fn u16_at(bytes: &[u8], at: usize) -> Result<u16, Failure> {
        let end = at.checked_add(2).ok_or_else(invalid)?;
        Ok(u16::from_le_bytes(
            bytes
                .get(at..end)
                .ok_or_else(invalid)?
                .try_into()
                .map_err(|_| invalid())?,
        ))
    }
    fn u32_at(bytes: &[u8], at: usize) -> Result<u32, Failure> {
        let end = at.checked_add(4).ok_or_else(invalid)?;
        Ok(u32::from_le_bytes(
            bytes
                .get(at..end)
                .ok_or_else(invalid)?
                .try_into()
                .map_err(|_| invalid())?,
        ))
    }
    pub(super) fn sid(bytes: &[u8]) -> Result<(String, usize), Failure> {
        if bytes.len() < 8 || bytes[0] != 1 || bytes[1] > 15 {
            return Err(invalid());
        }
        let length = 8 + bytes[1] as usize * 4;
        if bytes.len() < length {
            return Err(invalid());
        }
        let authority = bytes[2..8]
            .iter()
            .fold(0u64, |v, byte| (v << 8) | *byte as u64);
        let mut value = format!("S-1-{authority}");
        for at in (8..length).step_by(4) {
            value.push_str(&format!("-{}", u32_at(bytes, at)?));
        }
        Ok((value, length))
    }
    pub(super) fn verify(
        bytes: &[u8],
        owner: &str,
        reader: &str,
        reader_mask: u32,
    ) -> Result<(), Failure> {
        if !(20..=65_536).contains(&bytes.len())
            || bytes[0] != 1
            || bytes[1] != 0
            || account_sid(owner).is_none()
            || account_sid(reader).is_none()
        {
            return Err(invalid());
        }
        let control = u16_at(bytes, 2)?;
        // This selected OWNER+DACL recipe admits no group, SACL or other control
        // semantics. Reject broader fields rather than interpreting their offsets.
        if control != 0x9004 || u32_at(bytes, 8)? != 0 || u32_at(bytes, 12)? != 0 {
            return Err(invalid());
        }
        let owner_at = u32_at(bytes, 4)? as usize;
        let acl_at = u32_at(bytes, 16)? as usize;
        if owner_at < 20 || acl_at < 20 || !owner_at.is_multiple_of(4) || !acl_at.is_multiple_of(4)
        {
            return Err(invalid());
        }
        let (observed_owner, owner_length) = sid(bytes.get(owner_at..).ok_or_else(invalid)?)?;
        if observed_owner != owner {
            return Err(invalid());
        }
        let acl_length = u16_at(bytes, acl_at.checked_add(2).ok_or_else(invalid)?)? as usize;
        let acl = bytes
            .get(acl_at..acl_at.checked_add(acl_length).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        if acl.len() < 8
            || acl[0] != 2
            || acl[1] != 0
            || u16_at(acl, 4)? != 2
            || u16_at(acl, 6)? != 0
            || (owner_at < acl_at + acl.len() && acl_at < owner_at + owner_length)
        {
            return Err(invalid());
        }
        // Account for the complete returned descriptor, allowing either ordinary
        // self-relative component order but no unparsed gaps or trailing data.
        let owner_end = owner_at + owner_length;
        let acl_end = acl_at + acl.len();
        if !((owner_at == 20 && acl_at == owner_end && acl_end == bytes.len())
            || (acl_at == 20 && owner_at == acl_end && owner_end == bytes.len()))
        {
            return Err(invalid());
        }
        let mut offset = 8;
        for (mask, expected_sid) in [(OWNER_MASK, owner), (reader_mask, reader)] {
            let length = u16_at(acl, offset + 2)? as usize;
            let ace = acl
                .get(offset..offset.checked_add(length).ok_or_else(invalid)?)
                .ok_or_else(invalid)?;
            if ace.len() < 16 || ace[0] != 0 || ace[1] != 0 || u32_at(ace, 4)? != mask {
                return Err(invalid());
            }
            let (observed, sid_length) = sid(&ace[8..])?;
            if observed != expected_sid || ace.len() != 8 + sid_length {
                return Err(invalid());
            }
            offset += length;
        }
        if offset != acl.len() {
            return Err(invalid());
        }
        Ok(())
    }
}
#[cfg(not(target_os = "windows"))]
struct Unsupported;
#[cfg(not(target_os = "windows"))]
impl Backend for Unsupported {
    fn caller(&mut self) -> Result<TokenFacts, Failure> {
        Err(Failure::new("caller", "windows_required"))
    }
    fn logon(&mut self, _: &SecretCredential) -> Result<TokenFacts, Failure> {
        Err(Failure::new("logon", "windows_required"))
    }
    fn impersonate(&mut self) -> Result<(), Failure> {
        Err(Failure::new("impersonate", "windows_required"))
    }
    fn effective(&mut self) -> Result<TokenFacts, Failure> {
        Err(Failure::new("context", "windows_required"))
    }
    fn open(&mut self, _: &str, _: bool, _: bool) -> Result<usize, Failure> {
        Err(Failure::new("metadata", "windows_required"))
    }
    fn facts(&mut self, _: usize) -> Result<FileFacts, Failure> {
        Err(Failure::new("metadata", "windows_required"))
    }
    fn descriptor(&mut self, _: usize) -> Result<Vec<u8>, Failure> {
        Err(Failure::new("descriptor", "windows_required"))
    }
    fn read(&mut self, _: usize, _: &mut [u8]) -> Result<usize, Failure> {
        Err(Failure::new("read", "windows_required"))
    }
    fn cleanup(&mut self) -> CleanupFacts {
        CleanupFacts {
            handles_released: true,
            impersonation_reverted: true,
            controller_restored: true,
            owned_process_exit_required: false,
        }
    }
}
